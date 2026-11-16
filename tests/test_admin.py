from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from datetime import UTC, datetime
from unittest import mock

from repo_auth.admin import run
from repo_auth.auth import decide
from repo_auth.model import parse_export

from .helpers import basic


class AdminTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.dir.name, "db", "repo.sqlite3")
        self.export = os.path.join(self.dir.name, "export", "clients.json")

    def tearDown(self) -> None:
        self.dir.cleanup()

    def cli(self, *argv: str, stdin: str = "") -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with (
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
            mock.patch("sys.stdin", io.StringIO(stdin)),
        ):
            code = run(["--db", self.db, "--export", self.export, *argv])
        return code, out.getvalue(), err.getvalue()

    def exported(self) -> dict[str, object]:
        with open(self.export, "rb") as fh:
            return dict(parse_export(fh.read()).tokens)

    def check(self, login: str, token: str, uri: str = "/caddy/x") -> int:
        with open(self.export, "rb") as fh:
            exp = parse_export(fh.read())
        return decide(exp, method="GET", uri=uri, authorization=basic(login, token), now=datetime.now(UTC)).status

    def test_full_lifecycle(self) -> None:
        self.assertEqual(
            self.cli("account", "add", "acme", "--name", "ACME", "--scope", "/caddy", "--valid-until", "2099-12-31")[0],
            0,
        )
        code, out, _ = self.cli("token", "add", "acme", "--login", "acme-web1", "--label", "web1")
        self.assertEqual(code, 0)
        login, token = out.split()
        self.assertEqual(login, "acme-web1")
        self.assertEqual(self.check(login, token), 200)
        self.assertEqual(self.check(login, token, "/ppa/x/"), 403)

        # token is stored only as a hash
        with open(self.db, "rb") as fh:
            self.assertNotIn(token.encode(), fh.read())
        self.assertNotIn(token, open(self.export).read())

        self.cli("account", "block", "acme")
        self.assertEqual(self.check(login, token), 403)
        self.cli("account", "unblock", "acme")
        self.assertEqual(self.check(login, token), 200)

        code, out, _ = self.cli("token", "rotate", "acme-web1")
        new_token = out.split()[1]
        self.assertEqual(self.check(login, token), 401)
        self.assertEqual(self.check(login, new_token), 200)

        self.cli("token", "revoke", "acme-web1")
        self.assertEqual(self.exported(), {})

        self.cli("account", "set", "acme", "--valid-until", "2000-01-01")
        self.cli("token", "rotate", "acme-web1")
        self.assertEqual(len(self.exported()), 1)

    def test_expired_account(self) -> None:
        self.cli("account", "add", "old", "--name", "Old", "--scope", "/", "--valid-until", "2000-01-01")
        _, out, _ = self.cli("token", "add", "old", "--login", "old-one")
        self.assertEqual(self.check(*out.split()), 403)

    def test_extend_from_later_of_now_and_end(self) -> None:
        self.cli("account", "add", "ext", "--name", "E", "--scope", "/", "--valid-until", "2000-01-01")
        _, out, _ = self.cli("account", "extend", "ext", "--days", "30")
        end = datetime.fromisoformat(out.strip())
        self.assertGreater(end, datetime.now(UTC))
        self.cli("account", "set", "ext", "--valid-until", "2099-01-01")
        _, out, _ = self.cli("account", "extend", "ext", "--days", "1")
        self.assertTrue(out.startswith("2099-01-02T23:59:59"))

    def test_validation_errors(self) -> None:
        cases = [
            ("account", "add", "Bad Id", "--name", "x", "--scope", "/", "--unlimited"),
            ("account", "add", "okid", "--name", "x", "--unlimited"),  # no scope
            ("account", "add", "okid", "--name", "x", "--scope", "/a/../b", "--unlimited"),
            ("account", "add", "okid", "--name", "x", "--scope", "/", "--valid-until", "zitra"),
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                self.assertEqual(self.cli(*argv)[0], 1)
        self.assertEqual(self.cli("token", "add", "missing", "--login", "abc")[0], 2)
        self.assertEqual(self.cli("token", "revoke", "missing")[0], 2)

    def test_duplicates(self) -> None:
        self.cli("account", "add", "a1x", "--name", "A", "--scope", "/", "--unlimited")
        self.assertEqual(self.cli("account", "add", "a1x", "--name", "A", "--scope", "/", "--unlimited")[0], 1)
        self.cli("token", "add", "a1x", "--login", "l1x")
        self.assertEqual(self.cli("token", "add", "a1x", "--login", "l1x")[0], 1)

    def test_sync_is_idempotent_and_revokes_others(self) -> None:
        self.assertEqual(
            self.cli("account", "ensure", "linuxadm", "--name", "Hosts", "--scope", "/", "--unlimited")[1].split()[-1],
            "CHANGED",
        )
        self.assertEqual(
            self.cli("account", "ensure", "linuxadm", "--name", "Hosts", "--scope", "/", "--unlimited")[1].split()[-1],
            "OK",
        )
        hosts = {"host-a1": "a" * 64, "host-b1": "b" * 64}
        self.assertEqual(self.cli("token", "sync", "linuxadm", stdin=json.dumps(hosts))[1].split()[-1], "CHANGED")
        self.assertEqual(self.cli("token", "sync", "linuxadm", stdin=json.dumps(hosts))[1].split()[-1], "OK")
        self.assertEqual(self.check("host-a1", "a" * 64), 200)
        del hosts["host-b1"]
        self.assertEqual(self.cli("token", "sync", "linuxadm", stdin=json.dumps(hosts))[1].split()[-1], "CHANGED")
        self.assertEqual(self.check("host-b1", "b" * 64), 401)
        self.assertEqual(self.cli("export")[1].split()[-1], "OK")

    def test_sync_rejects_bad_input_and_foreign_login(self) -> None:
        self.cli("account", "add", "other", "--name", "O", "--scope", "/", "--unlimited")
        self.cli("token", "add", "other", "--login", "taken-one")
        self.cli("account", "ensure", "linuxadm", "--name", "H", "--scope", "/", "--unlimited")
        for stdin in [
            "not json",
            "[]",
            '{"host-a1": 1}',
            '{"host-a1": "short"}',
            '{"Bad": "' + "a" * 64 + '"}',
            '{"taken-one": "' + "a" * 64 + '"}',
        ]:
            with self.subTest(stdin=stdin):
                self.assertEqual(self.cli("token", "sync", "linuxadm", stdin=stdin)[0], 1)

    def test_file_modes_and_atomic_export(self) -> None:
        self.cli("account", "add", "acme", "--name", "A", "--scope", "/", "--unlimited")
        self.assertEqual(stat.S_IMODE(os.stat(self.db).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(self.db)).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(self.export).st_mode), 0o644)
        leftovers = [
            n for n in os.listdir(os.path.dirname(self.export)) if n.startswith(".clients.") and n != ".clients.lock"
        ]
        self.assertEqual(leftovers, [])

    def test_export_unchanged_keeps_file(self) -> None:
        self.cli("account", "add", "acme", "--name", "A", "--scope", "/", "--unlimited")
        before = os.stat(self.export).st_ino
        self.cli("account", "list")
        self.assertEqual(os.stat(self.export).st_ino, before)


if __name__ == "__main__":
    unittest.main()
