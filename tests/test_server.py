from __future__ import annotations

import http.client
import io
import logging
import os
import socket
import stat
import tempfile
import threading
import unittest

from repo_auth.model import render_export
from repo_auth.server import make_server

from .helpers import NOW, TOKEN, basic, entry


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str) -> None:
        super().__init__("localhost", timeout=5)
        self._path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(self._path)
        self.sock = sock


class ServerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.sock = os.path.join(self.dir.name, "auth.sock")
        self.export = os.path.join(self.dir.name, "clients.json")
        self.log = io.StringIO()
        handler = logging.StreamHandler(self.log)
        logging.getLogger("repo_auth").addHandler(handler)
        logging.getLogger("repo_auth").setLevel(logging.DEBUG)
        self.addCleanup(logging.getLogger("repo_auth").removeHandler, handler)
        self.server = make_server(self.sock, self.export, 'Repo "x"')
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.dir.cleanup()

    def write_export(self) -> None:
        with open(self.export, "wb") as fh:
            fh.write(render_export(NOW.replace(year=2026), [entry()]))

    def request(
        self, path: str = "/auth", headers: dict[str, str] | None = None, method: str = "GET"
    ) -> http.client.HTTPResponse:
        conn = UnixHTTPConnection(self.sock)
        conn.request(method, path, headers=headers or {})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        return resp

    def fwd(self, auth: str | None, uri: str = "/caddy/dists/x/Release") -> dict[str, str]:
        h = {"X-Forwarded-Method": "GET", "X-Forwarded-Uri": uri}
        if auth is not None:
            h["Authorization"] = auth
        return h

    def test_socket_mode(self) -> None:
        self.assertEqual(stat.S_IMODE(os.stat(self.sock).st_mode), 0o660)

    def test_closed_without_export(self) -> None:
        self.assertEqual(self.request("/healthz").status, 503)
        self.assertEqual(self.request(headers=self.fwd(basic("client-one", TOKEN))).status, 503)

    def test_flow(self) -> None:
        self.write_export()
        self.assertEqual(self.request("/healthz").status, 200)
        ok = self.request(headers=self.fwd(basic("client-one", TOKEN)))
        self.assertEqual(ok.status, 200)
        self.assertEqual(ok.getheader("X-Repo-Client"), "client-one")
        self.assertEqual(ok.getheader("X-Repo-Account"), "acme")
        self.assertEqual(ok.getheader("Cache-Control"), "no-store")

        denied = self.request(headers=self.fwd(None))
        self.assertEqual(denied.status, 401)
        self.assertEqual(denied.getheader("WWW-Authenticate"), 'Basic realm="Repo x", charset="UTF-8"')
        self.assertIsNone(denied.getheader("X-Repo-Client"))

        self.assertEqual(self.request(headers=self.fwd(basic("client-one", TOKEN), "/ppa/x/")).status, 403)
        self.assertEqual(self.request(headers=self.fwd(basic("client-one", TOKEN)), method="HEAD").status, 200)
        self.assertEqual(self.request("/other").status, 404)

    def test_no_secret_in_log(self) -> None:
        self.write_export()
        self.request(headers=self.fwd(basic("client-one", TOKEN)))
        self.request(headers=self.fwd(basic("client-one", "w" * 43)))
        text = self.log.getvalue()
        self.assertNotIn(TOKEN, text)
        self.assertNotIn("w" * 43, text)
        self.assertNotIn(basic("client-one", TOKEN).split()[1], text)
        self.assertIn("login=client-one", text)

    def test_refuses_non_socket_path(self) -> None:
        path = os.path.join(self.dir.name, "file")
        with open(path, "w") as fh:
            fh.write("x")
        with self.assertRaises(SystemExit):
            make_server(path, self.export, "r")
        self.assertTrue(os.path.exists(path))

    def test_replaces_stale_socket(self) -> None:
        stale = os.path.join(self.dir.name, "stale.sock")
        s = socket.socket(socket.AF_UNIX)
        s.bind(stale)
        s.close()
        srv = make_server(stale, self.export, "r")
        srv.server_close()


if __name__ == "__main__":
    unittest.main()
