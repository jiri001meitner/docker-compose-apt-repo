"""Accounts and tokens in SQLite, and the export built from them.

The SQLite database is the source of truth. After every change the CLI
rewrites the export (``clients.json``) atomically; the auth service only
reads that file. Tokens are stored only as SHA-256.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from repo_common.fsio import atomic_write, exclusive_lock
from repo_common.timeutil import format_utc, parse_optional_utc, parse_utc, utcnow

from .model import (
    ExportError,
    TokenEntry,
    normalize_scope,
    parse_export,
    render_export,
    valid_name,
    valid_token,
)

EXPORT_MODE = 0o644
EXPORT_LOCK = ".clients.lock"
SYNC_LABEL = "managed"  # tokens owned by `token sync`
DATE_ONLY_LENGTH = len("YYYY-MM-DD")
SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    email       TEXT,
    scopes      TEXT NOT NULL,
    valid_until TEXT,
    blocked     INTEGER NOT NULL DEFAULT 0 CHECK (blocked IN (0, 1)),
    note        TEXT,
    created     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    login      TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    sha256     TEXT NOT NULL,
    label      TEXT,
    created    TEXT NOT NULL,
    revoked    TEXT
);
CREATE INDEX IF NOT EXISTS tokens_account ON tokens(account_id);
"""
EXPORT_QUERY = (
    "SELECT t.login, t.sha256, a.id AS account, a.scopes, a.valid_until, a.blocked"
    " FROM tokens t JOIN accounts a ON a.id = t.account_id WHERE t.revoked IS NULL"
)


class AdminError(Exception):
    """Usage or validation error (exit code 1)."""

    exit_code = 1


class NotFoundError(AdminError):
    """The account or login does not exist (exit code 2)."""

    exit_code = 2


def token_digest(token: str) -> str:
    """Hex SHA-256 of a token, the only form that is stored."""
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def parse_valid_until(value: str) -> datetime:
    """``YYYY-MM-DD`` means the end of that day (UTC); full ISO 8601 also works."""
    try:
        if len(value) == DATE_ONLY_LENGTH:
            day = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=UTC)
            return day + timedelta(days=1) - timedelta(seconds=1)
        return parse_utc(value)
    except ValueError as exc:
        raise AdminError(f"invalid date {value!r}: {exc}") from exc


def check_name(kind: str, value: str) -> str:
    """Return ``value`` when it is a valid login or account id."""
    if not valid_name(value):
        raise AdminError(
            f"invalid {kind} {value!r}: use 3-63 of [a-z0-9-], starting with a letter or digit"
        )
    return value


def canonical_scopes(values: Sequence[str]) -> list[str]:
    """Sorted canonical scopes; ``/`` swallows all others."""
    if not values:
        raise AdminError("at least one --scope is required ('/' means everything)")
    try:
        scopes = sorted({normalize_scope(v) for v in values})
    except ValueError as exc:
        raise AdminError(str(exc)) from exc
    return ["/"] if "/" in scopes else scopes


def _optional_time(value: datetime | None) -> str | None:
    return format_utc(value) if value else None


@dataclass(frozen=True, slots=True)
class AccountSpec:
    """A new account (``account add``)."""

    name: str
    scopes: list[str]
    valid_until: datetime | None
    email: str | None = None
    note: str | None = None


@dataclass(frozen=True, slots=True)
class AccountChanges:
    """Fields to change (``account set``); None leaves a field as it is.

    An empty string clears ``email`` or ``note``; ``unlimited`` clears the
    end of the subscription.
    """

    name: str | None = None
    email: str | None = None
    scopes: list[str] | None = None
    valid_until: datetime | None = None
    unlimited: bool = False
    note: str | None = None

    def columns(self) -> dict[str, Any]:
        """Column -> new value for every field that changes."""
        changes: dict[str, Any] = {}
        if self.name is not None:
            changes["name"] = self.name
        if self.email is not None:
            changes["email"] = self.email or None
        if self.scopes is not None:
            changes["scopes"] = json.dumps(self.scopes)
        if self.unlimited:
            changes["valid_until"] = None
        elif self.valid_until is not None:
            changes["valid_until"] = format_utc(self.valid_until)
        if self.note is not None:
            changes["note"] = self.note or None
        return changes


# One fixed statement per column: no SQL is ever built from input.
_UPDATE_COLUMN = {
    "name": "UPDATE accounts SET name = ? WHERE id = ?",
    "email": "UPDATE accounts SET email = ? WHERE id = ?",
    "scopes": "UPDATE accounts SET scopes = ? WHERE id = ?",
    "valid_until": "UPDATE accounts SET valid_until = ? WHERE id = ?",
    "note": "UPDATE accounts SET note = ? WHERE id = ?",
}


@dataclass(frozen=True, slots=True)
class NewToken:
    """A row for the tokens table."""

    login: str
    account_id: str
    sha256: str
    label: str | None


def _insert_token(c: sqlite3.Connection, token: NewToken) -> None:
    c.execute(
        "INSERT INTO tokens (login, account_id, sha256, label, created) VALUES (?, ?, ?, ?, ?)",
        (token.login, token.account_id, token.sha256, token.label, format_utc(utcnow())),
    )


class Admin:
    """Account and token operations on the SQLite database."""

    def __init__(self, db_path: str, export_path: str) -> None:
        self.export_path = Path(export_path)
        os.makedirs(os.path.dirname(db_path) or ".", mode=0o700, exist_ok=True)
        old_umask = os.umask(0o077)
        try:
            self.conn = sqlite3.connect(db_path, isolation_level=None, timeout=10)
        finally:
            os.umask(old_umask)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        """Close the database."""
        self.conn.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """One write transaction, rolled back on any exception."""
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        self.conn.execute("COMMIT")

    # --- accounts ---------------------------------------------------------

    def _account(self, account_id: str) -> sqlite3.Row:
        row = self.conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
        if row is None:
            raise NotFoundError(f"account {account_id!r} not found")
        return cast(sqlite3.Row, row)

    def account_add(self, account_id: str, spec: AccountSpec) -> None:
        """Create a new account; an existing id is an error."""
        check_name("account id", account_id)
        with self.tx() as c:
            if c.execute("SELECT 1 FROM accounts WHERE id = ?", (account_id,)).fetchone():
                raise AdminError(f"account {account_id!r} already exists")
            c.execute(
                "INSERT INTO accounts (id, name, email, scopes, valid_until, note, created)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    account_id,
                    spec.name,
                    spec.email,
                    json.dumps(spec.scopes),
                    _optional_time(spec.valid_until),
                    spec.note,
                    format_utc(utcnow()),
                ),
            )

    def account_ensure(self, account_id: str, spec: AccountSpec) -> bool:
        """Create or update an account to name, scopes and end; True if changed."""
        check_name("account id", account_id)
        wanted = (spec.name, json.dumps(spec.scopes), _optional_time(spec.valid_until))
        with self.tx() as c:
            row = c.execute(
                "SELECT name, scopes, valid_until FROM accounts WHERE id = ?", (account_id,)
            ).fetchone()
            if row is None:
                c.execute(
                    "INSERT INTO accounts (id, name, scopes, valid_until, created)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (account_id, *wanted, format_utc(utcnow())),
                )
                return True
            if tuple(row) == wanted:
                return False
            c.execute(
                "UPDATE accounts SET name = ?, scopes = ?, valid_until = ? WHERE id = ?",
                (*wanted, account_id),
            )
            return True

    def account_set(self, account_id: str, changes: AccountChanges) -> None:
        """Change the given fields of an existing account."""
        with self.tx() as c:
            self._account(account_id)
            for column, value in changes.columns().items():
                c.execute(_UPDATE_COLUMN[column], (value, account_id))

    def account_extend(self, account_id: str, days: int) -> datetime:
        """Extend from the later of now and the current end (no lost days)."""
        if days <= 0:
            raise AdminError("--days must be positive")
        with self.tx() as c:
            row = self._account(account_id)
            if row["valid_until"] is None:
                raise AdminError(f"account {account_id!r} is unlimited")
            new_end = max(utcnow(), parse_utc(row["valid_until"])) + timedelta(days=days)
            c.execute(
                "UPDATE accounts SET valid_until = ? WHERE id = ?",
                (format_utc(new_end), account_id),
            )
            return new_end

    def account_block(self, account_id: str, blocked: bool) -> None:
        """Block or unblock all tokens of the account."""
        with self.tx() as c:
            self._account(account_id)
            c.execute("UPDATE accounts SET blocked = ? WHERE id = ?", (int(blocked), account_id))

    def account_delete(self, account_id: str) -> None:
        """Delete the account and its tokens."""
        with self.tx() as c:
            self._account(account_id)
            c.execute("DELETE FROM accounts WHERE id = ?", (account_id,))

    def accounts(self) -> list[sqlite3.Row]:
        """All accounts, by id."""
        return list(self.conn.execute("SELECT * FROM accounts ORDER BY id"))

    # --- tokens -----------------------------------------------------------

    def token_add(self, account_id: str, login: str, label: str | None) -> str:
        """Create a token for a new login; returns the token (shown once)."""
        check_name("login", login)
        token = secrets.token_urlsafe(32)
        with self.tx() as c:
            self._account(account_id)
            if c.execute("SELECT 1 FROM tokens WHERE login = ?", (login,)).fetchone():
                raise AdminError(f"login {login!r} already exists (revoke it or pick another)")
            _insert_token(c, NewToken(login, account_id, token_digest(token), label))
        return token

    def token_rotate(self, login: str) -> str:
        """Replace the token of a login (also revives a revoked one)."""
        token = secrets.token_urlsafe(32)
        with self.tx() as c:
            if not c.execute("SELECT 1 FROM tokens WHERE login = ?", (login,)).fetchone():
                raise NotFoundError(f"login {login!r} not found")
            c.execute(
                "UPDATE tokens SET sha256 = ?, revoked = NULL WHERE login = ?",
                (token_digest(token), login),
            )
        return token

    def token_revoke(self, login: str) -> bool:
        """Revoke a login; False when it already was revoked."""
        with self.tx() as c:
            row = c.execute("SELECT revoked FROM tokens WHERE login = ?", (login,)).fetchone()
            if row is None:
                raise NotFoundError(f"login {login!r} not found")
            if row["revoked"] is not None:
                return False
            c.execute(
                "UPDATE tokens SET revoked = ? WHERE login = ?", (format_utc(utcnow()), login)
            )
            return True

    def token_sync(self, account_id: str, wanted: dict[str, str]) -> bool:
        """Make the account's managed tokens exactly ``wanted`` (login -> token).

        Used by automation for derived per-host tokens: adds and updates the
        given ones and revokes the other tokens it manages (label ``managed``).
        Tokens added by hand to the same account are left alone.
        """
        for login, token in wanted.items():
            check_name("login", login)
            if not valid_token(token):
                raise AdminError(f"token for {login!r} is not a valid token")
        with self.tx() as c:
            self._account(account_id)
            rows = {
                r["login"]: r
                for r in c.execute("SELECT * FROM tokens WHERE account_id = ?", (account_id,))
            }
            changed = [
                _sync_token(c, NewToken(login, account_id, token_digest(token), SYNC_LABEL), rows)
                for login, token in wanted.items()
            ]
            for login, row in rows.items():
                if login not in wanted and row["revoked"] is None and row["label"] == SYNC_LABEL:
                    c.execute(
                        "UPDATE tokens SET revoked = ? WHERE login = ?",
                        (format_utc(utcnow()), login),
                    )
                    changed.append(True)
        return any(changed)

    def tokens(self, account_id: str | None = None) -> list[sqlite3.Row]:
        """Tokens of one account, or all of them."""
        if account_id is None:
            return list(self.conn.execute("SELECT * FROM tokens ORDER BY account_id, login"))
        return list(
            self.conn.execute(
                "SELECT * FROM tokens WHERE account_id = ? ORDER BY login", (account_id,)
            )
        )

    # --- export -----------------------------------------------------------

    def build_export(self) -> bytes:
        """The export for the current database content."""
        entries = [
            TokenEntry(
                login=row["login"],
                account=row["account"],
                sha256=row["sha256"],
                scopes=tuple(json.loads(row["scopes"])),
                valid_until=parse_optional_utc(row["valid_until"]),
                blocked=bool(row["blocked"]),
            )
            for row in self.conn.execute(EXPORT_QUERY)
        ]
        return render_export(utcnow(), entries)

    def write_export(self) -> bool:
        """Atomically replace the export when its content changed; True if written.

        Serialised by a lock file next to the export and built under that lock,
        so two concurrent repo-admin runs can never put an older snapshot of the
        database over a newer one. The data is validated with the same parser
        repo-auth uses: an export it would reject is never written (repo-auth
        would silently keep the previous one, e.g. without a fresh block).
        """
        try:
            with exclusive_lock(self.export_path.parent / EXPORT_LOCK, wait=True):
                return self._write_export_locked()
        except OSError as exc:
            raise AdminError(f"cannot write export {self.export_path}: {exc}") from exc

    def _write_export_locked(self) -> bool:
        data = self.build_export()
        try:
            parse_export(data)
        except ExportError as exc:
            raise AdminError(f"database produces an invalid export, not written: {exc}") from exc
        try:
            if _without_generated(self.export_path.read_bytes()) == _without_generated(data):
                return False
        except FileNotFoundError:
            pass
        atomic_write(self.export_path, data, EXPORT_MODE)
        return True


def _sync_token(c: sqlite3.Connection, token: NewToken, rows: dict[str, sqlite3.Row]) -> bool:
    """Bring one managed token to its digest; True if it changed."""
    row = rows.get(token.login)
    if row is None:
        other = c.execute(
            "SELECT account_id FROM tokens WHERE login = ?", (token.login,)
        ).fetchone()
        if other is not None:
            raise AdminError(f"login {token.login!r} belongs to account {other['account_id']!r}")
        _insert_token(c, token)
        return True
    if (row["sha256"], row["revoked"], row["label"]) == (token.sha256, None, token.label):
        return False
    c.execute(
        "UPDATE tokens SET sha256 = ?, revoked = NULL, label = ? WHERE login = ?",
        (token.sha256, token.label, token.login),
    )
    return True


def _without_generated(data: bytes) -> Any:
    """The export without its timestamp, for comparing content."""
    try:
        parsed = json.loads(data)
    except ValueError:
        return None
    if isinstance(parsed, dict):
        parsed.pop("generated", None)
    return parsed
