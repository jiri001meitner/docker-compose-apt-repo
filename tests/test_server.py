"""repo-auth over its UNIX socket, as Caddy forward_auth talks to it."""

from __future__ import annotations

import http.client
import io
import logging
import os
import socket
import stat
import threading
import unittest
from pathlib import Path
from typing import override

from repo_auth.model import render_export
from repo_auth.server import make_server

from .helpers import NOW, TOKEN, basic, entry
from .tempdirs import temp_dir


class UnixHTTPConnection(http.client.HTTPConnection):
    """http.client over a UNIX socket."""

    def __init__(self, path: str) -> None:
        super().__init__("localhost", timeout=5)
        self._path = path

    @override
    def connect(self) -> None:
        """Connect to the socket instead of a TCP host."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(self._path)
        self.sock = sock


def forwarded(auth: str | None, uri: str = "/caddy/dists/x/Release") -> dict[str, str]:
    """Headers Caddy sends for a client request."""
    headers = {"X-Forwarded-Method": "GET", "X-Forwarded-Uri": uri}
    if auth is not None:
        headers["Authorization"] = auth
    return headers


class ServerTest(unittest.TestCase):
    """Endpoints, headers, logging and socket handling."""

    def setUp(self) -> None:
        """Start a server on a socket in a temporary directory, capturing its log."""
        self.dir = temp_dir(self)
        self.sock = os.path.join(self.dir, "auth.sock")
        self.export = os.path.join(self.dir, "clients.json")
        self.log = io.StringIO()
        handler = logging.StreamHandler(self.log)
        logger = logging.getLogger("repo_auth")
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        self.addCleanup(logger.removeHandler, handler)
        self.server = make_server(self.sock, self.export, 'Repo "x"')
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def write_export(self) -> None:
        """Give the server a client list with one token."""
        Path(self.export).write_bytes(render_export(NOW, [entry()]))

    def request(
        self, path: str = "/auth", headers: dict[str, str] | None = None, method: str = "GET"
    ) -> http.client.HTTPResponse:
        """One request; the response with its body read."""
        conn = UnixHTTPConnection(self.sock)
        conn.request(method, path, headers=headers or {})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        return resp

    def test_socket_mode(self) -> None:
        """The socket is 0660: only the owner and the proxy group can connect."""
        self.assertEqual(stat.S_IMODE(os.stat(self.sock).st_mode), 0o660)

    def test_closed_without_export(self) -> None:
        """Without a client list everything is 503, health included."""
        self.assertEqual(self.request("/healthz").status, 503)
        self.assertEqual(self.request(headers=forwarded(basic("client-one", TOKEN))).status, 503)

    def test_flow(self) -> None:
        """200 with client headers, 401 with a challenge, 403 out of scope, 404 elsewhere."""
        self.write_export()
        self.assertEqual(self.request("/healthz").status, 200)
        ok = self.request(headers=forwarded(basic("client-one", TOKEN)))
        self.assertEqual(ok.status, 200)
        self.assertEqual(ok.getheader("X-Repo-Client"), "client-one")
        self.assertEqual(ok.getheader("X-Repo-Account"), "acme")
        self.assertEqual(ok.getheader("Cache-Control"), "no-store")

        denied = self.request(headers=forwarded(None))
        self.assertEqual(denied.status, 401)
        self.assertEqual(
            denied.getheader("WWW-Authenticate"), 'Basic realm="Repo x", charset="UTF-8"'
        )
        self.assertIsNone(denied.getheader("X-Repo-Client"))

        outside = forwarded(basic("client-one", TOKEN), "/ppa/x/")
        self.assertEqual(self.request(headers=outside).status, 403)
        head = self.request(headers=forwarded(basic("client-one", TOKEN)), method="HEAD")
        self.assertEqual(head.status, 200)
        self.assertEqual(self.request("/other").status, 404)

    def test_no_secret_in_log(self) -> None:
        """Neither a valid nor a wrong token appears in the log; the login does."""
        self.write_export()
        self.request(headers=forwarded(basic("client-one", TOKEN)))
        self.request(headers=forwarded(basic("client-one", "w" * 43)))
        text = self.log.getvalue()
        self.assertNotIn(TOKEN, text)
        self.assertNotIn("w" * 43, text)
        self.assertNotIn(basic("client-one", TOKEN).split()[1], text)
        self.assertIn("login=client-one", text)

    def test_refuses_non_socket_path(self) -> None:
        """A regular file at the socket path is never deleted."""
        path = os.path.join(self.dir, "file")
        Path(path).write_text("x", encoding="utf-8")
        with self.assertRaises(SystemExit):
            make_server(path, self.export, "r")
        self.assertTrue(os.path.exists(path))

    def test_replaces_stale_socket(self) -> None:
        """A socket left by a previous run is replaced."""
        stale = os.path.join(self.dir, "stale.sock")
        with socket.socket(socket.AF_UNIX) as s:
            s.bind(stale)
        make_server(stale, self.export, "r").server_close()


if __name__ == "__main__":
    unittest.main()
