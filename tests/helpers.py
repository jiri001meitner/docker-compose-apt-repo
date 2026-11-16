from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta

from repo_auth.model import Export, TokenEntry

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
TOKEN = "t" * 43
OTHER_TOKEN = "u" * 43


def basic(login: str, token: str) -> str:
    return "Basic " + base64.b64encode(f"{login}:{token}".encode()).decode()


def entry(
    login: str = "client-one",
    *,
    token: str = TOKEN,
    scopes: tuple[str, ...] = ("/caddy/",),
    valid_until: datetime | None = None,
    blocked: bool = False,
    account: str = "acme",
) -> TokenEntry:
    return TokenEntry(
        login=login,
        account=account,
        sha256=hashlib.sha256(token.encode()).hexdigest(),
        scopes=scopes,
        valid_until=valid_until,
        blocked=blocked,
    )


def export(*entries: TokenEntry) -> Export:
    return Export(generated=NOW, tokens={e.login: e for e in entries})


def future(days: int = 30) -> datetime:
    return NOW + timedelta(days=days)
