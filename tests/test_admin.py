"""repo-admin through its command line, checked against the auth decision."""

from __future__ import annotations

import json
import os
import stat
import unittest
from datetime import UTC, datetime
from pathlib import Path

from .helpers import AdminCliCase

ACME_UNLIMITED = ("--name", "A", "--scope", "/", "--unlimited")
EXPIRED = ("--valid-until", "2000-01-01")


class AdminTest(AdminCliCase):
    """Account and token commands."""

    def test_full_lifecycle(self) -> None:
        """Add, block, unblock, rotate, revoke and revive a token."""
        add = ("account", "add", "acme", "--name", "ACME", "--scope", "/caddy")
        code = self.cli(*add, "--valid-until", "2099-12-31")[0]
        self.assertEqual(code, 0)
        code, out, _ = self.cli("token", "add", "acme", "--login", "acme-web1", "--label", "web1")
        self.assertEqual(code, 0)
        login, token = out.split()
        self.assertEqual(login, "acme-web1")
        self.assertEqual(self.check(login, token), 200)
        self.assertEqual(self.check(login, token, "/ppa/x/"), 403)

        # The token is stored only as a hash.
        self.assertNotIn(token.encode(), Path(self.db).read_bytes())
        self.assertNotIn(token, Path(self.export).read_text(encoding="utf-8"))

        self.cli("account", "block", "acme")
        self.assertEqual(self.check(login, token), 403)
        self.cli("account", "unblock", "acme")
        self.assertEqual(self.check(login, token), 200)

        new_token = self.cli("token", "rotate", "acme-web1")[1].split()[1]
        self.assertEqual(self.check(login, token), 401)
        self.assertEqual(self.check(login, new_token), 200)

        self.cli("token", "revoke", "acme-web1")
        self.assertEqual(self.active(), set())

        self.cli("account", "set", "acme", "--valid-until", "2000-01-01")
        self.cli("token", "rotate", "acme-web1")
        self.assertEqual(self.active(), {"acme-web1"})

    def test_expired_account(self) -> None:
        """A token of an account past its end gets 403."""
        self.cli("account", "add", "old", "--name", "Old", "--scope", "/", *EXPIRED)
        login, token = self.cli("token", "add", "old", "--login", "old-one")[1].split()
        self.assertEqual(self.check(login, token), 403)

    def test_extend_from_later_of_now_and_end(self) -> None:
        """Extending an expired account counts from now, an active one from its end."""
        self.cli("account", "add", "ext", "--name", "E", "--scope", "/", *EXPIRED)
        end = datetime.fromisoformat(
            self.cli("account", "extend", "ext", "--days", "30")[1].strip()
        )
        self.assertGreater(end, datetime.now(UTC))
        self.cli("account", "set", "ext", "--valid-until", "2099-01-01")
        out = self.cli("account", "extend", "ext", "--days", "1")[1]
        self.assertTrue(out.startswith("2099-01-02T23:59:59"))

    def test_validation_errors(self) -> None:
        """Invalid input exits 1, a missing account or login exits 2."""
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
        """An existing account id or login cannot be added again."""
        self.cli("account", "add", "a1x", *ACME_UNLIMITED)
        self.assertEqual(self.cli("account", "add", "a1x", *ACME_UNLIMITED)[0], 1)
        self.cli("token", "add", "a1x", "--login", "l1x")
        self.assertEqual(self.cli("token", "add", "a1x", "--login", "l1x")[0], 1)


class AutomationTest(AdminCliCase):
    """Idempotent commands used by Ansible (OK/CHANGED)."""

    def test_sync_is_idempotent_and_revokes_others(self) -> None:
        """ensure and sync report CHANGED once, then OK; dropped hosts lose access."""
        ensure = ("account", "ensure", "linuxadm", "--name", "Hosts", "--scope", "/", "--unlimited")
        self.assertEqual(self.marker(*ensure), "CHANGED")
        self.assertEqual(self.marker(*ensure), "OK")
        hosts = {"host-a1": "a" * 64, "host-b1": "b" * 64}
        sync = ("token", "sync", "linuxadm")
        self.assertEqual(self.marker(*sync, stdin=json.dumps(hosts)), "CHANGED")
        self.assertEqual(self.marker(*sync, stdin=json.dumps(hosts)), "OK")
        self.assertEqual(self.check("host-a1", "a" * 64), 200)
        del hosts["host-b1"]
        self.assertEqual(self.marker(*sync, stdin=json.dumps(hosts)), "CHANGED")
        self.assertEqual(self.check("host-b1", "b" * 64), 401)
        self.assertEqual(self.marker("export"), "OK")

    def test_sync_rejects_bad_input_and_foreign_login(self) -> None:
        """Malformed stdin and a login of another account are refused."""
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


class FilesTest(AdminCliCase):
    """Permissions and atomic replacement of the files repo-admin writes."""

    def test_file_modes_and_atomic_export(self) -> None:
        """Database 0600 in a 0700 directory, export 0644, no temporary files left."""
        self.cli("account", "add", "acme", *ACME_UNLIMITED)
        self.assertEqual(stat.S_IMODE(os.stat(self.db).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(self.db)).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(self.export).st_mode), 0o644)
        leftovers = [
            n
            for n in os.listdir(os.path.dirname(self.export))
            if n.startswith(".clients.") and n != ".clients.lock"
        ]
        self.assertEqual(leftovers, [])

    def test_export_unchanged_keeps_file(self) -> None:
        """A command that changes nothing does not replace the export."""
        self.cli("account", "add", "acme", *ACME_UNLIMITED)
        before = os.stat(self.export).st_ino
        self.cli("account", "list")
        self.assertEqual(os.stat(self.export).st_ino, before)


if __name__ == "__main__":
    unittest.main()
