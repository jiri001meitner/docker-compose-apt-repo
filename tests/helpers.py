"""Fixtures shared by the repo-auth tests."""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import hashlib
import io
import os
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock

from repo_auth.admin import run
from repo_auth.auth import decide
from repo_auth.model import Export, TokenEntry, parse_export

from .tempdirs import temp_dir

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
TOKEN = "t" * 43
OTHER_TOKEN = "u" * 43


def basic(login: str, token: str) -> str:
    """Value of a Basic Authorization header."""
    return "Basic " + base64.b64encode(f"{login}:{token}".encode()).decode()


def entry(login: str = "client-one", *, token: str = TOKEN, **fields: Any) -> TokenEntry:
    """A token entry for ``login``; ``fields`` override the TokenEntry defaults."""
    base = TokenEntry(
        login=login,
        account="acme",
        sha256=hashlib.sha256(token.encode()).hexdigest(),
        scopes=("/caddy/",),
        valid_until=None,
        blocked=False,
    )
    return dataclasses.replace(base, **fields)


def export(*entries: TokenEntry) -> Export:
    """An export containing ``entries``."""
    return Export(generated=NOW, tokens={e.login: e for e in entries})


def future(days: int = 30) -> datetime:
    """A time ``days`` after NOW."""
    return NOW + timedelta(days=days)


class AdminCliCase(unittest.TestCase):
    """Runs repo-admin commands against a database and export in a temporary directory."""

    def setUp(self) -> None:
        """Paths in a fresh temporary directory (created by repo-admin itself)."""
        tmp = temp_dir(self)
        self.dir = tmp
        self.db = os.path.join(tmp, "db", "repo.sqlite3")
        self.export = os.path.join(tmp, "export", "clients.json")

    def cli(self, *argv: str, stdin: str = "") -> tuple[int, str, str]:
        """Run repo-admin; returns (exit code, stdout, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        with (
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
            mock.patch("sys.stdin", io.StringIO(stdin)),
        ):
            code = run(["--db", self.db, "--export", self.export, *argv])
        return code, out.getvalue(), err.getvalue()

    def marker(self, *argv: str, stdin: str = "") -> str:
        """The OK/CHANGED line an automation command prints last."""
        return self.cli(*argv, stdin=stdin)[1].split()[-1]

    def exported(self) -> Export:
        """The export as repo-auth would read it."""
        return parse_export(Path(self.export).read_bytes())

    def active(self) -> set[str]:
        """Logins in the export."""
        return set(self.exported().tokens)

    def check(self, login: str, token: str, uri: str = "/caddy/x") -> int:
        """HTTP status repo-auth would answer for these credentials now."""
        return decide(
            self.exported(),
            method="GET",
            uri=uri,
            authorization=basic(login, token),
            now=datetime.now(UTC),
        ).status
