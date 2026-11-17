"""Access decision for one forwarded request (pure logic, no I/O).

Order matters: the service answers 503 while it has no client list, then
checks credentials (401) before anything else, so a wrong token never reveals
whether an account exists, is blocked or expired. Only an authenticated
client gets a 403 from the policy rules.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import unquote

from .model import Export, TokenEntry, valid_name, valid_token

MAX_AUTHORIZATION_LENGTH = 1024
MAX_URI_LENGTH = 4096
ALLOWED_METHODS = frozenset({"GET", "HEAD"})
FIRST_PRINTABLE = 0x20
DELETE_CHAR = 0x7F
# Compared against when the login is unknown, so both paths cost the same.
_DUMMY_DIGEST = hashlib.sha256(b"repo-auth dummy token").hexdigest()
_BAD_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


@dataclass(frozen=True, slots=True)
class Decision:
    """Outcome: 200, 401, 403 or 503 with a reason for the log.

    ``login`` and ``account`` are for the log and, on 200 only, for the
    headers Caddy copies into its access log.
    """

    status: int
    reason: str
    login: str | None = None
    account: str | None = None


@dataclass(frozen=True, slots=True)
class Request:
    """The forwarded request as described by Caddy's X-Forwarded-* headers."""

    method: str | None
    uri: str | None
    now: datetime


def parse_basic(header: str | None) -> tuple[str, str] | None:
    """Return (login, token) from a Basic Authorization header, or None."""
    if header is None or len(header) > MAX_AUTHORIZATION_LENGTH:
        return None
    scheme, _, encoded = header.strip().partition(" ")
    if scheme.lower() != "basic" or not encoded:
        return None
    try:
        text = base64.b64decode(encoded.strip(), validate=True).decode("utf-8")
    except (binascii.Error, ValueError):
        return None
    login, sep, token = text.partition(":")
    if not sep or not valid_name(login) or not valid_token(token):
        return None
    return login, token


def _decode(path: str) -> str | None:
    """Percent-decode once; None for invalid or double encoding and control chars."""
    if _BAD_ESCAPE.search(path):
        return None  # Go's URL parser rejects invalid escapes too; never guess
    try:
        decoded = unquote(path, errors="strict")
        if unquote(decoded, errors="strict") != decoded:
            return None  # double encoding (%252e...)
    except UnicodeDecodeError:
        return None
    if "\\" in decoded or any(
        ord(ch) < FIRST_PRINTABLE or ord(ch) == DELETE_CHAR for ch in decoded
    ):
        return None
    return decoded


def _canonical(decoded: str) -> str | None:
    """Reject ``.``, ``..`` and empty segments; keep a trailing slash."""
    if decoded == "/":
        return "/"
    body = decoded[1:]
    trailing = body.endswith("/")
    segments = (body[:-1] if trailing else body).split("/")
    if any(seg in ("", ".", "..") for seg in segments):
        return None
    return "/" + "/".join(segments) + ("/" if trailing else "")


def normalize_path(uri: str | None) -> str | None:
    """Canonical request path, or None when the path is suspicious.

    Rejects traversal (``.``/``..`` segments, also percent-encoded), empty
    segments (``//``), backslashes, control characters and double or invalid
    encoding. Query and fragment are ignored.
    """
    if not uri or len(uri) > MAX_URI_LENGTH:
        return None
    path = uri.split("?", 1)[0].split("#", 1)[0]
    decoded = _decode(path) if path.startswith("/") else None
    return None if decoded is None else _canonical(decoded)


def in_scope(path: str, scopes: tuple[str, ...]) -> bool:
    """True when ``path`` lies under one of the canonical ``scopes``."""
    return any(scope == "/" or path.startswith(scope) or path == scope[:-1] for scope in scopes)


def _blocked(entry: TokenEntry, _request: Request) -> str | None:
    return "account blocked" if entry.blocked else None


def _expired(entry: TokenEntry, request: Request) -> str | None:
    expired = entry.valid_until is not None and request.now >= entry.valid_until
    return "subscription expired" if expired else None


def _method(_entry: TokenEntry, request: Request) -> str | None:
    allowed = (request.method or "").upper() in ALLOWED_METHODS
    return None if allowed else "method not allowed"


def _path(entry: TokenEntry, request: Request) -> str | None:
    path = normalize_path(request.uri)
    if path is None:
        return "invalid path"
    return None if in_scope(path, entry.scopes) else "path outside scope"


# Policy rules for an authenticated client, in order; the first reason wins.
POLICY: tuple[Callable[[TokenEntry, Request], str | None], ...] = (
    _blocked,
    _expired,
    _method,
    _path,
)


def authenticate(export: Export, authorization: str | None) -> TokenEntry | Decision:
    """The token entry for valid credentials, otherwise a 401 decision.

    Unknown logins are compared against a dummy digest, so the time taken does
    not tell whether a login exists. The login is kept in the decision for the
    log only (rate limiting); it is never sent back.
    """
    credentials = parse_basic(authorization)
    if credentials is None:
        return Decision(401, "missing or malformed credentials")
    login, token = credentials
    entry = export.tokens.get(login)
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    expected = entry.sha256 if entry is not None else _DUMMY_DIGEST
    if not hmac.compare_digest(digest, expected) or entry is None:
        return Decision(401, "unknown login or wrong token", login)
    return entry


def decide(
    export: Export | None,
    *,
    method: str | None,
    uri: str | None,
    authorization: str | None,
    now: datetime,
) -> Decision:
    """Decide one forwarded request."""
    if export is None:
        return Decision(503, "client list not loaded")
    entry = authenticate(export, authorization)
    if isinstance(entry, Decision):
        return entry
    request = Request(method=method, uri=uri, now=now)
    for rule in POLICY:
        reason = rule(entry, request)
        if reason is not None:
            return Decision(403, reason, entry.login, entry.account)
    return Decision(200, "ok", entry.login, entry.account)
