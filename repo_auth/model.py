"""Shared validation rules and the export format read by the auth service.

The export (``clients.json``) is the only thing the auth service reads. It is
written atomically by ``repo-admin`` from its SQLite database, so a broken or
half-written database can never open the repository.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from repo_common.timeutil import format_utc, parse_utc

EXPORT_VERSION = 1

# Logins and account ids: lowercase, digits, dash; 3-63 characters.
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")
# Hex SHA-256 of the token.
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# Tokens: printable ASCII without space and colon, 32-256 characters.
TOKEN_RE = re.compile(r"^[\x21-\x39\x3b-\x7e]{32,256}$")
# Scope segments: what aptly prefixes and distributions may contain.
SEGMENT_RE = re.compile(r"^[A-Za-z0-9._+~-]+$")
ENTRY_KEYS = frozenset({"account", "sha256", "scopes", "valid_until", "blocked"})
TOP_LEVEL_KEYS = frozenset({"version", "generated", "tokens"})


class ExportError(ValueError):
    """The export file is not valid; the whole file is rejected."""


def valid_name(value: str) -> bool:
    """True for a valid login or account id."""
    return NAME_RE.fullmatch(value) is not None


def valid_token(value: str) -> bool:
    """True for a token that can be sent in a Basic header (no space, no colon)."""
    return TOKEN_RE.fullmatch(value) is not None


def normalize_scope(scope: str) -> str:
    """Return the canonical form ``/a/b/`` (or ``/`` for everything).

    Raises ValueError for anything that is not a plain absolute path made of
    safe segments.
    """
    if scope == "/":
        return "/"
    if not scope.startswith("/"):
        raise ValueError(f"scope must start with '/': {scope!r}")
    segments = scope.strip("/").split("/")
    for segment in segments:
        if segment in ("", ".", "..") or SEGMENT_RE.fullmatch(segment) is None:
            raise ValueError(f"invalid scope segment in {scope!r}")
    return "/" + "/".join(segments) + "/"


@dataclass(frozen=True, slots=True)
class TokenEntry:
    """One active token as the auth service sees it."""

    login: str
    account: str
    sha256: str
    scopes: tuple[str, ...]
    valid_until: datetime | None
    blocked: bool


@dataclass(frozen=True, slots=True)
class Export:
    """The whole client list, keyed by login."""

    generated: datetime
    tokens: dict[str, TokenEntry]


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise ExportError(message)


def _parse_scopes(login: str, raw: Any) -> tuple[str, ...]:
    _require(isinstance(raw, list) and len(raw) > 0, f"{login}: scopes must be a non-empty list")
    scopes: list[str] = []
    for scope in raw:
        _require(isinstance(scope, str), f"{login}: scope is not a string")
        try:
            canonical = normalize_scope(scope)
        except ValueError as exc:
            raise ExportError(f"{login}: {exc}") from exc
        _require(canonical == scope, f"{login}: scope {scope!r} is not canonical")
        scopes.append(scope)
    return tuple(scopes)


def _parse_timestamp(context: str, raw: Any) -> datetime:
    _require(isinstance(raw, str), f"{context}: timestamp is not a string")
    try:
        return parse_utc(raw)
    except ValueError as exc:
        raise ExportError(f"{context}: {exc}") from exc


def _parse_entry(login: str, raw: Any) -> TokenEntry:
    _require(valid_name(login), f"invalid login {login!r}")
    _require(isinstance(raw, dict), f"{login}: entry is not an object")
    _require(set(raw) == ENTRY_KEYS, f"{login}: unexpected keys {sorted(set(raw) ^ ENTRY_KEYS)}")
    account, digest, blocked = raw["account"], raw["sha256"], raw["blocked"]
    _require(isinstance(account, str) and valid_name(account), f"{login}: invalid account")
    _require(
        isinstance(digest, str) and SHA256_RE.fullmatch(digest) is not None,
        f"{login}: invalid sha256",
    )
    _require(isinstance(blocked, bool), f"{login}: blocked is not a boolean")
    valid_until = raw["valid_until"]
    return TokenEntry(
        login=login,
        account=account,
        sha256=digest,
        scopes=_parse_scopes(login, raw["scopes"]),
        valid_until=None if valid_until is None else _parse_timestamp(login, valid_until),
        blocked=blocked,
    )


def parse_export(data: bytes) -> Export:
    """Parse and strictly validate the export; any defect rejects the file."""
    try:
        raw = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExportError(f"not valid JSON: {exc}") from exc
    _require(isinstance(raw, dict), "export is not an object")
    version = raw.get("version")
    _require(version == EXPORT_VERSION, f"unsupported export version {version!r}")
    _require(set(raw) == TOP_LEVEL_KEYS, "unexpected top-level keys")
    tokens_raw = raw["tokens"]
    _require(isinstance(tokens_raw, dict), "tokens is not an object")
    return Export(
        generated=_parse_timestamp("generated", raw["generated"]),
        tokens={login: _parse_entry(login, entry) for login, entry in tokens_raw.items()},
    )


def render_export(generated: datetime, tokens: list[TokenEntry]) -> bytes:
    """Serialise the client list (sorted, stable output)."""
    payload = {
        "version": EXPORT_VERSION,
        "generated": format_utc(generated),
        "tokens": {
            t.login: {
                "account": t.account,
                "sha256": t.sha256,
                "scopes": list(t.scopes),
                "valid_until": format_utc(t.valid_until) if t.valid_until else None,
                "blocked": t.blocked,
            }
            for t in sorted(tokens, key=lambda t: t.login)
        },
    }
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
