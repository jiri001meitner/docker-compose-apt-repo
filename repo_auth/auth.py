"""Access decision for one forwarded request (pure logic, no I/O)."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import unquote

from .model import Export, valid_name, valid_token

MAX_AUTHORIZATION_LENGTH = 1024
MAX_URI_LENGTH = 4096
ALLOWED_METHODS = frozenset({"GET", "HEAD"})
# Compared against when the login is unknown, so both paths cost the same.
_DUMMY_DIGEST = hashlib.sha256(b"repo-auth dummy token").hexdigest()


@dataclass(frozen=True, slots=True)
class Decision:
    status: int  # 200, 401, 403 or 503
    reason: str
    login: str | None = None
    account: str | None = None


def _deny(reason: str, login: str | None = None) -> Decision:
    """401. ``login`` is only for the log; it is never sent back to the client."""
    return Decision(401, reason, login)


def parse_basic(header: str | None) -> tuple[str, str] | None:
    """Return (login, token) from a Basic Authorization header, or None."""
    if header is None or len(header) > MAX_AUTHORIZATION_LENGTH:
        return None
    scheme, _, encoded = header.strip().partition(" ")
    if scheme.lower() != "basic" or not encoded:
        return None
    try:
        raw = base64.b64decode(encoded.strip(), validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError):
        return None
    login, sep, token = text.partition(":")
    if not sep or not valid_name(login) or not valid_token(token):
        return None
    return login, token


_BAD_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def normalize_path(uri: str | None) -> str | None:
    """Canonical request path, or None when the path is suspicious.

    Rejects traversal (``.``/``..`` segments, also percent-encoded), empty
    segments (``//``), backslashes, control characters and double encoding.
    A trailing slash (directory listing) is kept.
    """
    if not uri or len(uri) > MAX_URI_LENGTH:
        return None
    path = uri.split("?", 1)[0].split("#", 1)[0]
    if not path.startswith("/") or _BAD_ESCAPE.search(path):
        return None  # Go's URL parser rejects invalid escapes too; never guess
    try:
        decoded = unquote(path, errors="strict")
        if unquote(decoded, errors="strict") != decoded:
            return None  # double encoding (%252e...)
    except UnicodeDecodeError:
        return None
    if "\\" in decoded or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in decoded):
        return None
    if decoded == "/":
        return "/"
    body = decoded[1:]
    trailing = body.endswith("/")
    if trailing:
        body = body[:-1]
    segments = body.split("/")
    if any(seg in ("", ".", "..") for seg in segments):
        return None
    return "/" + "/".join(segments) + ("/" if trailing else "")


def in_scope(path: str, scopes: tuple[str, ...]) -> bool:
    return any(scope == "/" or path.startswith(scope) or path == scope[:-1] for scope in scopes)


def decide(
    export: Export | None,
    *,
    method: str | None,
    uri: str | None,
    authorization: str | None,
    now: datetime,
) -> Decision:
    if export is None:
        return Decision(503, "client list not loaded")

    credentials = parse_basic(authorization)
    if credentials is None:
        return _deny("missing or malformed credentials")
    login, token = credentials

    entry = export.tokens.get(login)
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    expected = entry.sha256 if entry is not None else _DUMMY_DIGEST
    if not hmac.compare_digest(digest, expected) or entry is None:
        return _deny("unknown login or wrong token", login)

    if entry.blocked:
        return Decision(403, "account blocked", login, entry.account)
    if entry.valid_until is not None and now >= entry.valid_until:
        return Decision(403, "subscription expired", login, entry.account)
    if (method or "").upper() not in ALLOWED_METHODS:
        return Decision(403, "method not allowed", login, entry.account)
    path = normalize_path(uri)
    if path is None:
        return Decision(403, "invalid path", login, entry.account)
    if not in_scope(path, entry.scopes):
        return Decision(403, "path outside scope", login, entry.account)
    return Decision(200, "ok", login, entry.account)
