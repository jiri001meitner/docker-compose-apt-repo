"""Edge cases from the security review (M1-M4, L4-L7)."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest import mock

from repo_auth import server as server_mod
from repo_auth.admin import Admin, run
from repo_auth.auth import decide, normalize_path, parse_basic
from repo_auth.model import parse_export, render_export
from repo_auth.server import make_server
from repo_auth.store import ExportStore

from .helpers import NOW, TOKEN, basic, entry, export


def raw_request(path: str, data: bytes, *, read: bool = True, timeout: float = 5) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(path)
        s.sendall(data)
        if not read:
            return b""
        chunks = []
        while chunk := s.recv(65536):
            chunks.append(chunk)
        return b"".join(chunks)


def fwd(auth: str | None, uri: str = "/caddy/x", method: str = "GET", extra: str = "") -> bytes:
    lines = [f"{method} /auth HTTP/1.1", "Host: x", "X-Forwarded-Method: GET", f"X-Forwarded-Uri: {uri}"]
    if auth:
        lines.append(f"Authorization: {auth}")
    return ("\r\n".join(lines) + "\r\n" + extra + "\r\n").encode()


class NormalizeAndParseExtraTest(unittest.TestCase):
    def test_paths(self) -> None:
        exp = export(entry(scopes=("/caddy/",)))
        auth = basic("client-one", TOKEN)

        def status(uri: str) -> int:
            return decide(exp, method="GET", uri=uri, authorization=auth, now=NOW).status

        self.assertEqual(status("/caddy%2Fx"), 200)  # Caddy file_server decodes %2F the same way
        self.assertEqual(status("/cad%2fdy/x"), 403)
        self.assertEqual(status("/caddyx/x"), 403)
        self.assertEqual(status("/caddy"), 200)
        self.assertEqual(normalize_path("/caddy/a%3Fb"), "/caddy/a?b")
        self.assertEqual(normalize_path("/caddy/a%23b"), "/caddy/a#b")
        for bad in ["/caddy/%E9", "/caddy/%C3", "/caddy/%zz"]:
            with self.subTest(bad):
                self.assertIsNone(normalize_path(bad))
        self.assertIsNotNone(normalize_path("/" + "a" * 4095))
        self.assertIsNone(normalize_path("/" + "a" * 4096))

    def test_basic_variants(self) -> None:
        good = base64.b64encode(f"client-one:{TOKEN}".encode()).decode()
        self.assertIsNone(parse_basic("Basic" + good))
        self.assertIsNone(parse_basic("Basic\t" + good))
        self.assertIsNone(parse_basic("Basic " + good.rstrip("=") if good.endswith("=") else "Basic " + good[:-1]))
        self.assertIsNone(parse_basic(basic("", TOKEN)))
        self.assertIsNone(parse_basic(basic("client-one", "")))
        self.assertIsNone(parse_basic("Basic " + base64.b64encode("klient-é:".encode() + b"x" * 40).decode()))


class StoreHealthTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = os.path.join(self.dir.name, "clients.json")

    def write(self, data: bytes) -> None:
        with open(self.path + ".tmp", "wb") as fh:
            fh.write(data)
        os.replace(self.path + ".tmp", self.path)

    def test_degraded_states(self) -> None:
        store = ExportStore(self.path)
        self.assertEqual(store.health()[0], False)
        self.write(render_export(NOW, [entry()]))
        self.assertTrue(store.health()[0])
        self.write(b"{broken")
        ok, reason = store.health()
        self.assertFalse(ok)
        self.assertIn("last good", reason)
        self.assertIsNotNone(store.get())
        os.unlink(self.path)
        self.assertFalse(store.health()[0])
        self.assertIsNotNone(store.get())
        self.write(render_export(NOW, [entry()]))
        self.assertTrue(store.health()[0])

    @unittest.skipIf(os.geteuid() == 0, "root ignores permissions")
    def test_unreadable_dir_keeps_last_good(self) -> None:
        self.write(render_export(NOW, [entry()]))
        store = ExportStore(self.path)
        self.assertIsNotNone(store.get())
        os.chmod(self.dir.name, 0)
        try:
            self.assertIsNotNone(store.get())
            self.assertFalse(store.health()[0])
        finally:
            os.chmod(self.dir.name, 0o700)


class ServerHardeningTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.sock = os.path.join(self.dir.name, "auth.sock")
        self.export = os.path.join(self.dir.name, "clients.json")
        with open(self.export, "wb") as fh:
            fh.write(render_export(NOW, [entry()]))

    def start(self, realm: str = "Repo") -> None:
        self.server = make_server(self.sock, self.export, realm)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def test_first_authorization_header_wins_and_head_has_no_body(self) -> None:
        self.start()
        good, bad = basic("client-one", TOKEN), basic("client-one", "z" * 43)
        resp = raw_request(self.sock, fwd(good, extra=f"Authorization: {bad}\r\n"))
        self.assertTrue(resp.startswith(b"HTTP/1.1 200"), resp[:40])
        self.assertIn(b"X-Repo-Client: client-one", resp)
        resp = raw_request(self.sock, fwd(bad, method="HEAD", extra=f"Authorization: {good}\r\n"))
        self.assertTrue(resp.startswith(b"HTTP/1.1 401"))
        self.assertTrue(resp.endswith(b"\r\n\r\n"))  # HEAD: no body
        self.assertNotIn(b"X-Repo-", resp)

    def test_body_does_not_become_next_request(self) -> None:
        self.start()
        smuggled = b"GET /auth HTTP/1.1\r\nHost: x\r\n\r\n"
        req = fwd(None, extra=f"Content-Length: {len(smuggled)}\r\n").rstrip(b"\r\n") + b"\r\n\r\n" + smuggled
        resp = raw_request(self.sock, req)
        self.assertEqual(resp.count(b"HTTP/1.1 "), 1)
        self.assertIn(b"Connection: close", resp)

    def test_realm_sanitised(self) -> None:
        self.start('Evil"\r\nX-Injected: 1')
        resp = raw_request(self.sock, fwd(None))
        self.assertNotIn(b"X-Injected: 1\r\n", resp)
        self.assertIn(b'WWW-Authenticate: Basic realm="EvilX-Injected: 1", charset="UTF-8"', resp)

    def test_healthz_reports_degraded(self) -> None:
        self.start()
        self.assertTrue(raw_request(self.sock, b"GET /healthz HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 200"))
        with open(self.export, "wb") as fh:
            fh.write(b"{broken")
        resp = raw_request(self.sock, b"GET /healthz HTTP/1.1\r\n\r\n")
        self.assertTrue(resp.startswith(b"HTTP/1.1 503"))
        self.assertTrue(raw_request(self.sock, fwd(basic("client-one", TOKEN))).startswith(b"HTTP/1.1 200"))

    def test_slow_client_is_cut_off(self) -> None:
        with (
            mock.patch.object(server_mod, "REQUEST_DEADLINE", 0.5),
            mock.patch.object(server_mod.Handler, "timeout", 0.3),
        ):
            self.start()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect(self.sock)
                start = time.monotonic()
                with contextlib.suppress(OSError):
                    for _ in range(20):
                        s.sendall(b"X")
                        time.sleep(0.2)  # each byte within the per-read timeout
                        if s.recv(1, socket.MSG_DONTWAIT | socket.MSG_PEEK) == b"":
                            break
                self.assertLess(time.monotonic() - start, 2.5)

    def test_concurrency_limit(self) -> None:
        with mock.patch.object(server_mod, "MAX_CONCURRENT", 2):
            self.start()
            idle = []
            for _ in range(2):
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(self.sock)
                idle.append(s)
            time.sleep(0.2)
            resp = raw_request(self.sock, fwd(basic("client-one", TOKEN)))
            self.assertTrue(resp.startswith(b"HTTP/1.1 503"), resp[:40])
            for s in idle:
                s.close()
            time.sleep(0.3)
            self.assertTrue(raw_request(self.sock, fwd(basic("client-one", TOKEN))).startswith(b"HTTP/1.1 200"))


class AdminReviewTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.db = os.path.join(self.dir.name, "db", "repo.sqlite3")
        self.export = os.path.join(self.dir.name, "export", "clients.json")

    def cli(self, *argv: str, stdin: str = "") -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with (
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
            mock.patch("sys.stdin", io.StringIO(stdin)),
        ):
            code = run(["--db", self.db, "--export", self.export, *argv])
        return code, out.getvalue(), err.getvalue()

    def active(self) -> set[str]:
        with open(self.export, "rb") as fh:
            return set(parse_export(fh.read()).tokens)

    def test_invalid_db_state_fails_loudly(self) -> None:
        self.cli("account", "add", "acme", "--name", "A", "--scope", "/caddy", "--unlimited")
        self.cli("token", "add", "acme", "--login", "acme-one")
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE accounts SET scopes = ? WHERE id = 'acme'", (json.dumps(["/caddy"]),))
        before = open(self.export, "rb").read()
        code, _, err = self.cli("account", "block", "acme")
        self.assertEqual(code, 1)
        self.assertIn("invalid export", err)
        self.assertEqual(open(self.export, "rb").read(), before)

    def test_token_printed_only_after_export(self) -> None:
        self.cli("account", "add", "acme", "--name", "A", "--scope", "/", "--unlimited")
        os.chmod(os.path.dirname(self.export), 0o500)
        try:
            if os.geteuid() == 0:
                self.skipTest("root ignores permissions")
            code, out, err = self.cli("token", "add", "acme", "--login", "acme-one")
        finally:
            os.chmod(os.path.dirname(self.export), 0o700)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("cannot write export", err)

    def test_sync_leaves_manual_tokens(self) -> None:
        self.cli("account", "ensure", "linuxadm", "--name", "H", "--scope", "/", "--unlimited")
        self.cli("token", "add", "linuxadm", "--login", "manual-one")
        self.cli("token", "sync", "linuxadm", stdin=json.dumps({"host-a1": "a" * 64}))
        self.assertEqual(self.active(), {"manual-one", "host-a1"})
        self.assertEqual(self.cli("token", "sync", "linuxadm", stdin="{}")[1].split()[-1], "CHANGED")
        self.assertEqual(self.active(), {"manual-one"})

    def test_ensure_keeps_block(self) -> None:
        self.cli("account", "ensure", "acme", "--name", "A", "--scope", "/", "--unlimited")
        self.cli("token", "add", "acme", "--login", "acme-one")
        self.cli("account", "block", "acme")
        self.assertEqual(
            self.cli("account", "ensure", "acme", "--name", "A", "--scope", "/", "--unlimited")[1].split()[-1], "OK"
        )
        with open(self.export, "rb") as fh:
            self.assertTrue(parse_export(fh.read()).tokens["acme-one"].blocked)

    def test_concurrent_admins_end_with_latest_state(self) -> None:
        self.cli("account", "add", "acme", "--name", "A", "--scope", "/", "--unlimited")
        logins = [f"acme-{i:02d}" for i in range(12)]
        errors: list[str] = []

        # run() swaps the global stdout, so drive the Admin API from threads instead.
        def worker(login: str) -> None:
            admin = Admin(self.db, self.export)
            try:
                admin.token_add("acme", login, None)
                admin.write_export()
            except Exception as exc:
                errors.append(repr(exc))
            finally:
                admin.close()

        threads = [threading.Thread(target=worker, args=(login,)) for login in logins]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(self.active(), set(logins))

    def test_wal_files_private(self) -> None:
        self.cli("account", "add", "acme", "--name", "A", "--scope", "/", "--unlimited")
        for name in os.listdir(os.path.dirname(self.db)):
            with self.subTest(name):
                self.assertEqual(os.stat(os.path.join(os.path.dirname(self.db), name)).st_mode & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
