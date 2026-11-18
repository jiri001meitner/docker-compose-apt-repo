"""Reachability probe of an upstream against local sockets."""

from __future__ import annotations

import http.server
import socket
import threading
import time
import unittest
from typing import Any, ClassVar, override

from repo_sync.config import Upstream
from repo_sync.probe import UpstreamUnreachableError, probe, release_url


class _Handler(http.server.BaseHTTPRequestHandler):
    """Records the path and answers every HEAD with ``status``."""

    status = 200
    paths: ClassVar[list[str]] = []  # replaced per server by _server

    def _reply(self) -> None:
        """Reply with ``status``."""
        self.paths.append(self.path)
        self.send_response(self.status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_HEAD = _reply

    @override
    def log_message(self, format: str, *args: Any) -> None:
        """Keep the test output quiet."""


def _server(status: int, paths: list[str]) -> http.server.HTTPServer:
    """HTTP server on a free local port answering every HEAD with ``status``."""
    handler = type("Handler", (_Handler,), {"status": status, "paths": paths})
    return http.server.HTTPServer(("127.0.0.1", 0), handler)


def upstream(port: int) -> Upstream:
    """An upstream on localhost:``port``."""
    return Upstream(f"http://127.0.0.1:{port}/ubuntu/", "resolute", "main", ("amd64",))


class ProbeTest(unittest.TestCase):
    """Any HTTP answer is reachable; no answer raises quickly."""

    def serve(self, status: int, paths: list[str]) -> http.server.HTTPServer:
        """A server answering ``status``, stopped after the test."""
        server = _server(status, paths)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def test_release_url(self) -> None:
        """The probed file is the distribution's InRelease, slash-normalised."""
        self.assertEqual(
            release_url(upstream(80)), "http://127.0.0.1:80/ubuntu/dists/resolute/InRelease"
        )

    def test_answer_is_reachable(self) -> None:
        """200 and also an error status count as an answer."""
        for status in (200, 404, 503):
            with self.subTest(status):
                paths: list[str] = []
                server = self.serve(status, paths)
                probe(upstream(server.server_port), 2)
                self.assertEqual(paths, ["/ubuntu/dists/resolute/InRelease"])

    def test_refused_is_unreachable(self) -> None:
        """A closed port raises UpstreamUnreachableError (an OSError)."""
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        with self.assertRaises(UpstreamUnreachableError) as ctx:
            probe(upstream(port), 2)
        self.assertIsInstance(ctx.exception, OSError)
        self.assertIn("unreachable", str(ctx.exception))

    def test_silent_server_times_out(self) -> None:
        """A server that accepts but never answers is given up after the timeout."""
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            sock.listen()
            started = time.monotonic()
            with self.assertRaises(UpstreamUnreachableError):
                probe(upstream(sock.getsockname()[1]), 0.3)
            self.assertLess(time.monotonic() - started, 5)


if __name__ == "__main__":
    unittest.main()
