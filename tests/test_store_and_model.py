from __future__ import annotations

import json
import os
import tempfile
import unittest

from repo_auth.model import ExportError, normalize_scope, parse_export, render_export
from repo_auth.store import ExportStore

from .helpers import NOW, entry, future

GOOD = render_export(NOW, [entry(), entry("client-two", valid_until=future(), scopes=("/",))])


class ModelTest(unittest.TestCase):
    def test_roundtrip(self) -> None:
        exp = parse_export(GOOD)
        self.assertEqual(set(exp.tokens), {"client-one", "client-two"})
        self.assertEqual(exp.tokens["client-two"].valid_until, future())

    def test_rejects_defects(self) -> None:
        base = json.loads(GOOD)

        def mutate(fn: object) -> bytes:
            data = json.loads(json.dumps(base))
            fn(data)  # type: ignore[operator]
            return json.dumps(data).encode()

        cases = {
            "not json": b"{",
            "not utf8": b"\xff",
            "list": b"[]",
            "version": mutate(lambda d: d.update(version=2)),
            "extra key": mutate(lambda d: d.update(extra=1)),
            "bad login": mutate(lambda d: d["tokens"].update({"Bad Login": d["tokens"]["client-one"]})),
            "bad sha": mutate(lambda d: d["tokens"]["client-one"].update(sha256="xyz")),
            "empty scopes": mutate(lambda d: d["tokens"]["client-one"].update(scopes=[])),
            "traversal scope": mutate(lambda d: d["tokens"]["client-one"].update(scopes=["/caddy/../"])),
            "non-canonical scope": mutate(lambda d: d["tokens"]["client-one"].update(scopes=["/caddy"])),
            "naive date": mutate(lambda d: d["tokens"]["client-one"].update(valid_until="2030-01-01T00:00:00")),
            "blocked not bool": mutate(lambda d: d["tokens"]["client-one"].update(blocked=0)),
            "missing key": mutate(lambda d: d["tokens"]["client-one"].pop("blocked")),
        }
        for name, data in cases.items():
            with self.subTest(name):
                with self.assertRaises(ExportError):
                    parse_export(data)

    def test_normalize_scope(self) -> None:
        self.assertEqual(normalize_scope("/caddy"), "/caddy/")
        self.assertEqual(normalize_scope("/ppa/mozillateam/"), "/ppa/mozillateam/")
        self.assertEqual(normalize_scope("/"), "/")
        for bad in ["caddy", "//", "/a//b/", "/a/../b", "/a/./b", "/a b/", "/a%2e/"]:
            with self.subTest(bad), self.assertRaises(ValueError):
                normalize_scope(bad)


class StoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "clients.json")

    def tearDown(self) -> None:
        self.dir.cleanup()

    def write(self, data: bytes) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, self.path)

    def test_missing_at_start(self) -> None:
        self.assertIsNone(ExportStore(self.path).get())

    def test_invalid_at_start(self) -> None:
        self.write(b"garbage")
        self.assertIsNone(ExportStore(self.path).get())

    def test_appears_later(self) -> None:
        store = ExportStore(self.path)
        self.assertIsNone(store.get())
        self.write(GOOD)
        exp = store.get()
        assert exp is not None
        self.assertIn("client-one", exp.tokens)

    def test_reload_and_keep_last_good(self) -> None:
        self.write(GOOD)
        store = ExportStore(self.path)
        self.assertEqual(len(store.get().tokens), 2)  # type: ignore[union-attr]
        self.write(render_export(NOW, [entry()]))
        self.assertEqual(len(store.get().tokens), 1)  # type: ignore[union-attr]
        self.write(b"{broken")
        self.assertEqual(len(store.get().tokens), 1)  # type: ignore[union-attr]
        os.unlink(self.path)
        self.assertEqual(len(store.get().tokens), 1)  # type: ignore[union-attr]
        self.write(GOOD)
        self.assertEqual(len(store.get().tokens), 2)  # type: ignore[union-attr]


if __name__ == "__main__":
    unittest.main()
