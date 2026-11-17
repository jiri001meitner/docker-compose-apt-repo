"""Export format and the export store."""

from __future__ import annotations

import json
import os
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

from repo_auth.model import ExportError, normalize_scope, parse_export, render_export
from repo_auth.store import ExportStore

from .helpers import NOW, entry, future
from .tempdirs import temp_dir


def token_count(store: ExportStore) -> int:
    """Number of tokens in the store's current export (fails when none is loaded)."""
    exp = store.get()
    if exp is None:
        raise AssertionError("no export loaded")
    return len(exp.tokens)


GOOD = render_export(NOW, [entry(), entry("client-two", valid_until=future(), scopes=("/",))])


class ModelTest(unittest.TestCase):
    """The export format."""

    def test_roundtrip(self) -> None:
        """render_export output parses back to the same entries."""
        exp = parse_export(GOOD)
        self.assertEqual(set(exp.tokens), {"client-one", "client-two"})
        self.assertEqual(exp.tokens["client-two"].valid_until, future())

    def test_rejects_defects(self) -> None:
        """Any defect anywhere rejects the whole file."""
        base = json.loads(GOOD)

        def mutate(fn: Callable[[Any], object]) -> bytes:
            """A copy of the good export changed by ``fn``."""
            data = json.loads(json.dumps(base))
            fn(data)
            return json.dumps(data).encode()

        cases = {
            "not json": b"{",
            "not utf8": b"\xff",
            "list": b"[]",
            "version": mutate(lambda d: d.update(version=2)),
            "extra key": mutate(lambda d: d.update(extra=1)),
            "bad login": mutate(
                lambda d: d["tokens"].update({"Bad Login": d["tokens"]["client-one"]})
            ),
            "bad sha": mutate(lambda d: d["tokens"]["client-one"].update(sha256="xyz")),
            "empty scopes": mutate(lambda d: d["tokens"]["client-one"].update(scopes=[])),
            "traversal scope": mutate(
                lambda d: d["tokens"]["client-one"].update(scopes=["/caddy/../"])
            ),
            "non-canonical scope": mutate(
                lambda d: d["tokens"]["client-one"].update(scopes=["/caddy"])
            ),
            "naive date": mutate(
                lambda d: d["tokens"]["client-one"].update(valid_until="2030-01-01T00:00:00")
            ),
            "blocked not bool": mutate(lambda d: d["tokens"]["client-one"].update(blocked=0)),
            "missing key": mutate(lambda d: d["tokens"]["client-one"].pop("blocked")),
        }
        for name, data in cases.items():
            with self.subTest(name), self.assertRaises(ExportError):
                parse_export(data)

    def test_normalize_scope(self) -> None:
        """Scopes are canonicalised to /a/b/; unsafe ones are refused."""
        self.assertEqual(normalize_scope("/caddy"), "/caddy/")
        self.assertEqual(normalize_scope("/ppa/mozillateam/"), "/ppa/mozillateam/")
        self.assertEqual(normalize_scope("/"), "/")
        for bad in ["caddy", "//", "/a//b/", "/a/../b", "/a/./b", "/a b/", "/a%2e/"]:
            with self.subTest(bad), self.assertRaises(ValueError):
                normalize_scope(bad)


class StoreTest(unittest.TestCase):
    """Loading and reloading the export file."""

    def setUp(self) -> None:
        """An export path in a temporary directory."""
        self.path = os.path.join(temp_dir(self), "clients.json")

    def write(self, data: bytes) -> None:
        """Replace the export atomically."""
        tmp = self.path + ".tmp"
        Path(tmp).write_bytes(data)
        os.replace(tmp, self.path)

    def test_missing_at_start(self) -> None:
        """No file at start: nothing loaded."""
        self.assertIsNone(ExportStore(self.path).get())

    def test_invalid_at_start(self) -> None:
        """An invalid file at start: nothing loaded."""
        self.write(b"garbage")
        self.assertIsNone(ExportStore(self.path).get())

    def test_appears_later(self) -> None:
        """A file that appears later is picked up."""
        store = ExportStore(self.path)
        self.assertIsNone(store.get())
        self.write(GOOD)
        self.assertEqual(token_count(store), 2)

    def test_reload_and_keep_last_good(self) -> None:
        """Changes are reloaded; broken or deleted files keep the last good one."""
        self.write(GOOD)
        store = ExportStore(self.path)
        self.assertEqual(token_count(store), 2)
        self.write(render_export(NOW, [entry()]))
        self.assertEqual(token_count(store), 1)
        self.write(b"{broken")
        self.assertEqual(token_count(store), 1)
        os.unlink(self.path)
        self.assertEqual(token_count(store), 1)
        self.write(GOOD)
        self.assertEqual(token_count(store), 2)


if __name__ == "__main__":
    unittest.main()
