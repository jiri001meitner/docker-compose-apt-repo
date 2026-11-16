"""repo-admin: manage accounts and tokens, publish the export for repo-auth.

The SQLite database is the source of truth. After every change the export
(``clients.json``) is rewritten atomically; the auth service only reads it.
Tokens are shown exactly once (``token add``) and stored only as SHA-256.

Exit codes: 0 ok, 1 usage or validation error, 2 not found.
Commands meant for automation print ``OK`` or ``CHANGED`` on the last line.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import secrets
import sqlite3
import sys
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from .model import (
    ExportError,
    TokenEntry,
    format_utc,
    normalize_scope,
    parse_export,
    parse_utc,
    render_export,
    valid_name,
    valid_token,
)

DEFAULT_DB = "/data/db/repo.sqlite3"
DEFAULT_EXPORT = "/data/export/clients.json"
EXPORT_MODE = 0o644
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


SYNC_LABEL = "managed"  # tokens owned by `token sync`
EXPORT_LOCK = ".clients.lock"


class AdminError(Exception):
    exit_code = 1


class NotFoundError(AdminError):
    exit_code = 2


def now_utc() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def parse_valid_until(value: str) -> datetime:
    """``YYYY-MM-DD`` means the end of that day (UTC); full ISO 8601 also works."""
    try:
        if len(value) == 10:
            day = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=UTC)
            return day + timedelta(days=1) - timedelta(seconds=1)
        return parse_utc(value)
    except ValueError as exc:
        raise AdminError(f"invalid date {value!r}: {exc}") from exc


def check_name(kind: str, value: str) -> str:
    if not valid_name(value):
        raise AdminError(f"invalid {kind} {value!r}: use 3-63 of [a-z0-9-], starting with a letter or digit")
    return value


def canonical_scopes(values: Sequence[str]) -> list[str]:
    if not values:
        raise AdminError("at least one --scope is required ('/' means everything)")
    try:
        scopes = sorted({normalize_scope(v) for v in values})
    except ValueError as exc:
        raise AdminError(str(exc)) from exc
    return ["/"] if "/" in scopes else scopes


class Admin:
    def __init__(self, db_path: str, export_path: str) -> None:
        self.db_path = db_path
        self.export_path = export_path
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
        self.conn.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
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

    def account_add(
        self,
        account_id: str,
        *,
        name: str,
        email: str | None,
        scopes: list[str],
        valid_until: datetime | None,
        note: str | None,
    ) -> None:
        check_name("account id", account_id)
        with self.tx() as c:
            if c.execute("SELECT 1 FROM accounts WHERE id = ?", (account_id,)).fetchone():
                raise AdminError(f"account {account_id!r} already exists")
            c.execute(
                "INSERT INTO accounts (id, name, email, scopes, valid_until, note, created)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    account_id,
                    name,
                    email,
                    json.dumps(scopes),
                    format_utc(valid_until) if valid_until else None,
                    note,
                    format_utc(now_utc()),
                ),
            )

    def account_ensure(self, account_id: str, name: str, scopes: list[str], valid_until: datetime | None) -> bool:
        """Create or update an account to the given state; True if changed."""
        check_name("account id", account_id)
        wanted = (name, json.dumps(scopes), format_utc(valid_until) if valid_until else None)
        with self.tx() as c:
            row = c.execute("SELECT name, scopes, valid_until FROM accounts WHERE id = ?", (account_id,)).fetchone()
            if row is None:
                c.execute(
                    "INSERT INTO accounts (id, name, scopes, valid_until, created) VALUES (?, ?, ?, ?, ?)",
                    (account_id, *wanted, format_utc(now_utc())),
                )
                return True
            if tuple(row) == wanted:
                return False
            c.execute("UPDATE accounts SET name = ?, scopes = ?, valid_until = ? WHERE id = ?", (*wanted, account_id))
            return True

    def account_set(
        self,
        account_id: str,
        *,
        name: str | None = None,
        email: str | None = None,
        scopes: list[str] | None = None,
        valid_until: datetime | None = None,
        unlimited: bool = False,
        note: str | None = None,
    ) -> None:
        with self.tx() as c:
            self._account(account_id)
            if name is not None:
                c.execute("UPDATE accounts SET name = ? WHERE id = ?", (name, account_id))
            if email is not None:
                c.execute("UPDATE accounts SET email = ? WHERE id = ?", (email or None, account_id))
            if scopes is not None:
                c.execute("UPDATE accounts SET scopes = ? WHERE id = ?", (json.dumps(scopes), account_id))
            if unlimited:
                c.execute("UPDATE accounts SET valid_until = NULL WHERE id = ?", (account_id,))
            elif valid_until is not None:
                c.execute("UPDATE accounts SET valid_until = ? WHERE id = ?", (format_utc(valid_until), account_id))
            if note is not None:
                c.execute("UPDATE accounts SET note = ? WHERE id = ?", (note or None, account_id))

    def account_extend(self, account_id: str, days: int) -> datetime:
        """Extend from the later of now and the current end (no lost days)."""
        if days <= 0:
            raise AdminError("--days must be positive")
        with self.tx() as c:
            row = self._account(account_id)
            if row["valid_until"] is None:
                raise AdminError(f"account {account_id!r} is unlimited")
            base = max(now_utc(), parse_utc(row["valid_until"]))
            new_end = base + timedelta(days=days)
            c.execute("UPDATE accounts SET valid_until = ? WHERE id = ?", (format_utc(new_end), account_id))
            return new_end

    def account_block(self, account_id: str, blocked: bool) -> None:
        with self.tx() as c:
            self._account(account_id)
            c.execute("UPDATE accounts SET blocked = ? WHERE id = ?", (int(blocked), account_id))

    def account_delete(self, account_id: str) -> None:
        with self.tx() as c:
            self._account(account_id)
            c.execute("DELETE FROM accounts WHERE id = ?", (account_id,))

    def accounts(self) -> list[sqlite3.Row]:
        return list(self.conn.execute("SELECT * FROM accounts ORDER BY id"))

    # --- tokens -----------------------------------------------------------

    def token_add(self, account_id: str, login: str, label: str | None) -> str:
        check_name("login", login)
        token = secrets.token_urlsafe(32)
        with self.tx() as c:
            self._account(account_id)
            if c.execute("SELECT 1 FROM tokens WHERE login = ?", (login,)).fetchone():
                raise AdminError(f"login {login!r} already exists (revoke it or pick another)")
            c.execute(
                "INSERT INTO tokens (login, account_id, sha256, label, created) VALUES (?, ?, ?, ?, ?)",
                (login, account_id, token_digest(token), label, format_utc(now_utc())),
            )
        return token

    def token_rotate(self, login: str) -> str:
        token = secrets.token_urlsafe(32)
        with self.tx() as c:
            if not c.execute("SELECT 1 FROM tokens WHERE login = ?", (login,)).fetchone():
                raise NotFoundError(f"login {login!r} not found")
            c.execute("UPDATE tokens SET sha256 = ?, revoked = NULL WHERE login = ?", (token_digest(token), login))
        return token

    def token_revoke(self, login: str) -> bool:
        with self.tx() as c:
            row = c.execute("SELECT revoked FROM tokens WHERE login = ?", (login,)).fetchone()
            if row is None:
                raise NotFoundError(f"login {login!r} not found")
            if row["revoked"] is not None:
                return False
            c.execute("UPDATE tokens SET revoked = ? WHERE login = ?", (format_utc(now_utc()), login))
            return True

    def token_sync(self, account_id: str, wanted: dict[str, str]) -> bool:
        """Make the account's active tokens exactly ``wanted`` (login -> token).

        Used by automation for derived per-host tokens: adds and updates the
        given ones and revokes the other tokens it manages (label ``managed``).
        Tokens added by hand to the same account are left alone.
        """
        for login, token in wanted.items():
            check_name("login", login)
            if not valid_token(token):
                raise AdminError(f"token for {login!r} is not a valid token")
        changed = False
        with self.tx() as c:
            self._account(account_id)
            rows = {r["login"]: r for r in c.execute("SELECT * FROM tokens WHERE account_id = ?", (account_id,))}
            for login, token in wanted.items():
                digest = token_digest(token)
                row = rows.get(login)
                if row is None:
                    other = c.execute("SELECT account_id FROM tokens WHERE login = ?", (login,)).fetchone()
                    if other is not None:
                        raise AdminError(f"login {login!r} belongs to account {other['account_id']!r}")
                    c.execute(
                        "INSERT INTO tokens (login, account_id, sha256, label, created) VALUES (?, ?, ?, ?, ?)",
                        (login, account_id, digest, SYNC_LABEL, format_utc(now_utc())),
                    )
                    changed = True
                elif row["sha256"] != digest or row["revoked"] is not None or row["label"] != SYNC_LABEL:
                    c.execute(
                        "UPDATE tokens SET sha256 = ?, revoked = NULL, label = ? WHERE login = ?",
                        (digest, SYNC_LABEL, login),
                    )
                    changed = True
            for login, row in rows.items():
                if login not in wanted and row["revoked"] is None and row["label"] == SYNC_LABEL:
                    c.execute("UPDATE tokens SET revoked = ? WHERE login = ?", (format_utc(now_utc()), login))
                    changed = True
        return changed

    def tokens(self, account_id: str | None = None) -> list[sqlite3.Row]:
        if account_id is None:
            return list(self.conn.execute("SELECT * FROM tokens ORDER BY account_id, login"))
        return list(self.conn.execute("SELECT * FROM tokens WHERE account_id = ? ORDER BY login", (account_id,)))

    # --- export -----------------------------------------------------------

    def build_export(self) -> bytes:
        entries: list[TokenEntry] = []
        query = (
            "SELECT t.login, t.sha256, a.id AS account, a.scopes, a.valid_until, a.blocked"
            " FROM tokens t JOIN accounts a ON a.id = t.account_id WHERE t.revoked IS NULL"
        )
        for row in self.conn.execute(query):
            entries.append(
                TokenEntry(
                    login=row["login"],
                    account=row["account"],
                    sha256=row["sha256"],
                    scopes=tuple(json.loads(row["scopes"])),
                    valid_until=parse_utc(row["valid_until"]) if row["valid_until"] else None,
                    blocked=bool(row["blocked"]),
                )
            )
        return render_export(now_utc(), entries)

    def write_export(self) -> bool:
        """Atomically replace the export when its content changed; True if written.

        Serialised by a lock file next to the export and built under that lock,
        so two concurrent repo-admin runs can never put an older snapshot of the
        database over a newer one. The data is validated with the same parser
        repo-auth uses: an export it would reject is never written (repo-auth
        would silently keep the previous one, e.g. without a fresh block).
        """
        directory = os.path.dirname(self.export_path) or "."
        try:
            os.makedirs(directory, exist_ok=True)
            with open(os.path.join(directory, EXPORT_LOCK), "a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                return self._write_export_locked(directory)
        except OSError as exc:
            raise AdminError(f"cannot write export {self.export_path}: {exc}") from exc

    def _write_export_locked(self, directory: str) -> bool:
        data = self.build_export()
        try:
            parse_export(data)
        except ExportError as exc:
            raise AdminError(f"database produces an invalid export, not written: {exc}") from exc
        try:
            with open(self.export_path, "rb") as fh:
                current = fh.read()
            if _strip_generated(current) == _strip_generated(data):
                return False
        except FileNotFoundError:
            pass
        fd, tmp = tempfile.mkstemp(prefix=".clients.", dir=directory)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, EXPORT_MODE)
            os.replace(tmp, self.export_path)
        except BaseException:
            with suppress(FileNotFoundError):
                os.unlink(tmp)
            raise
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        return True


def _strip_generated(data: bytes) -> Any:
    try:
        parsed = json.loads(data)
    except ValueError:
        return None
    if isinstance(parsed, dict):
        parsed.pop("generated", None)
    return parsed


# --- CLI --------------------------------------------------------------------


def _print_rows(rows: list[sqlite3.Row], columns: list[str]) -> None:
    print("\t".join(columns))
    for row in rows:
        print("\t".join("" if row[c] is None else str(row[c]) for c in columns))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="repo-admin", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--db", default=os.environ.get("REPO_ADMIN_DB", DEFAULT_DB))
    p.add_argument("--export", default=os.environ.get("REPO_AUTH_EXPORT", DEFAULT_EXPORT))
    sub = p.add_subparsers(dest="area", required=True)

    acc = sub.add_parser("account").add_subparsers(dest="cmd", required=True)
    a = acc.add_parser("add")
    a.add_argument("id")
    a.add_argument("--name", required=True)
    a.add_argument("--email")
    a.add_argument("--scope", action="append", default=[])
    a.add_argument("--note")
    g = a.add_mutually_exclusive_group(required=True)
    g.add_argument("--valid-until")
    g.add_argument("--unlimited", action="store_true")
    a = acc.add_parser("ensure", help="create or update (automation); prints OK/CHANGED")
    a.add_argument("id")
    a.add_argument("--name", required=True)
    a.add_argument("--scope", action="append", default=[])
    g = a.add_mutually_exclusive_group(required=True)
    g.add_argument("--valid-until")
    g.add_argument("--unlimited", action="store_true")
    a = acc.add_parser("set")
    a.add_argument("id")
    a.add_argument("--name")
    a.add_argument("--email")
    a.add_argument("--scope", action="append")
    a.add_argument("--note")
    g = a.add_mutually_exclusive_group()
    g.add_argument("--valid-until")
    g.add_argument("--unlimited", action="store_true")
    a = acc.add_parser("extend")
    a.add_argument("id")
    a.add_argument("--days", type=int, required=True)
    for name in ("block", "unblock", "delete"):
        acc.add_parser(name).add_argument("id")
    acc.add_parser("list")

    tok = sub.add_parser("token").add_subparsers(dest="cmd", required=True)
    t = tok.add_parser("add", help="new token, printed once")
    t.add_argument("account")
    t.add_argument("--login", required=True)
    t.add_argument("--label")
    tok.add_parser("rotate", help="new token for an existing login, printed once").add_argument("login")
    tok.add_parser("revoke").add_argument("login")
    t = tok.add_parser("sync", help="set the account's tokens from JSON {login: token} on stdin")
    t.add_argument("account")
    t = tok.add_parser("list")
    t.add_argument("account", nargs="?")

    sub.add_parser("export", help="rewrite the export now; prints OK/CHANGED")
    return p


def run(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    admin = Admin(args.db, args.export)
    try:
        changed_marker: bool | None = None
        secret_line: str | None = None  # printed only after the export is written
        if args.area == "account":
            if args.cmd == "add":
                admin.account_add(
                    args.id,
                    name=args.name,
                    email=args.email,
                    scopes=canonical_scopes(args.scope),
                    valid_until=None if args.unlimited else parse_valid_until(args.valid_until),
                    note=args.note,
                )
            elif args.cmd == "ensure":
                changed_marker = admin.account_ensure(
                    args.id,
                    args.name,
                    canonical_scopes(args.scope),
                    None if args.unlimited else parse_valid_until(args.valid_until),
                )
            elif args.cmd == "set":
                admin.account_set(
                    args.id,
                    name=args.name,
                    email=args.email,
                    scopes=canonical_scopes(args.scope) if args.scope is not None else None,
                    valid_until=parse_valid_until(args.valid_until) if args.valid_until else None,
                    unlimited=args.unlimited,
                    note=args.note,
                )
            elif args.cmd == "extend":
                print(format_utc(admin.account_extend(args.id, args.days)))
            elif args.cmd in ("block", "unblock"):
                admin.account_block(args.id, args.cmd == "block")
            elif args.cmd == "delete":
                admin.account_delete(args.id)
            elif args.cmd == "list":
                _print_rows(admin.accounts(), ["id", "name", "email", "scopes", "valid_until", "blocked", "note"])
        elif args.area == "token":
            if args.cmd == "add":
                secret_line = f"{args.login} {admin.token_add(args.account, args.login, args.label)}"
            elif args.cmd == "rotate":
                secret_line = f"{args.login} {admin.token_rotate(args.login)}"
            elif args.cmd == "revoke":
                admin.token_revoke(args.login)
            elif args.cmd == "sync":
                try:
                    wanted = json.loads(sys.stdin.read())
                except ValueError as exc:
                    raise AdminError(f"stdin is not JSON: {exc}") from exc
                if not isinstance(wanted, dict) or not all(
                    isinstance(k, str) and isinstance(v, str) for k, v in wanted.items()
                ):
                    raise AdminError("stdin must be a JSON object {login: token}")
                changed_marker = admin.token_sync(args.account, wanted)
            elif args.cmd == "list":
                _print_rows(admin.tokens(args.account), ["login", "account_id", "label", "created", "revoked"])
        export_changed = admin.write_export()
        if secret_line is not None:
            print(secret_line)
        if args.area == "export":
            changed_marker = export_changed
        if changed_marker is not None:
            print("CHANGED" if changed_marker else "OK")
        return 0
    except AdminError as exc:
        print(f"repo-admin: {exc}", file=sys.stderr)
        return exc.exit_code
    finally:
        admin.close()


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
