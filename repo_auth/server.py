"""HTTP server for Caddy ``forward_auth`` on a UNIX socket.

Endpoints:
  GET|HEAD /auth     decision for the request described by X-Forwarded-* headers
  GET|HEAD /healthz  200 when the client list is loaded, else 503

The service never logs credentials. It is meant to run without any network
(``network_mode: none``); Caddy reaches it only through the socket.
"""

from __future__ import annotations

import contextlib
import logging
import os
import signal
import socket
import socketserver
import stat
import sys
import threading
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from types import FrameType

from .auth import decide
from .store import ExportStore

log = logging.getLogger("repo_auth")

DEFAULT_SOCKET = "/run/repo-auth/auth.sock"
DEFAULT_EXPORT = "/data/export/clients.json"
DEFAULT_REALM = "APT repository"
SOCKET_MODE = 0o660
REQUEST_TIMEOUT = 5.0  # per read on the socket
REQUEST_DEADLINE = 10.0  # whole connection, against slow-trickle clients
MAX_CONCURRENT = 32  # handler threads; above this the request gets 503 at once
_BUSY = (
    b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\n"
    b"Content-Length: 5\r\nCache-Control: no-store\r\nConnection: close\r\n\r\nbusy\n"
)


class _Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    block_on_close = False
    store: ExportStore
    realm: str

    def __init__(self, path: str, handler: type[BaseHTTPRequestHandler]) -> None:
        super().__init__(path, handler)
        self._slots = threading.BoundedSemaphore(MAX_CONCURRENT)

    def process_request(self, request: socket.socket, client_address: object) -> None:  # type: ignore[override]
        if not self._slots.acquire(blocking=False):
            log.warning("too many concurrent requests (%d), answering 503", MAX_CONCURRENT)
            with contextlib.suppress(OSError):
                # Read what the client already sent, so closing does not reset
                # the connection before it sees the 503.
                request.settimeout(0.2)
                request.recv(65536)
                request.sendall(_BUSY)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: object) -> None:  # type: ignore[override]
        deadline = threading.Timer(REQUEST_DEADLINE, _abort, args=(request,))
        deadline.daemon = True
        deadline.start()
        try:
            super().process_request_thread(request, client_address)
        finally:
            deadline.cancel()
            self._slots.release()


def _abort(request: socket.socket) -> None:
    with contextlib.suppress(OSError):
        request.shutdown(socket.SHUT_RDWR)


class Handler(BaseHTTPRequestHandler):
    server: _Server
    server_version = "repo-auth"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = REQUEST_TIMEOUT

    # UNIX sockets have no peer address; BaseHTTPRequestHandler expects one.
    def address_string(self) -> str:
        return "unix"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        log.debug("http: " + format, *args)

    def _reply(self, status: int, text: str, headers: dict[str, str] | None = None) -> None:
        body = (text + "\n").encode("utf-8")
        # One request per connection: bounds the time a thread is held, and a
        # request body (never sent by Caddy forward_auth) can't be misread as
        # the next request.
        self.close_connection = True
        self.send_response(status)
        self.send_header("Connection", "close")
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _handle(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            ok, reason = self.server.store.health()
            self._reply(200 if ok else 503, reason)
            return
        if path != "/auth":
            self._reply(404, "not found")
            return
        decision = decide(
            self.server.store.get(),
            method=self.headers.get("X-Forwarded-Method"),
            uri=self.headers.get("X-Forwarded-Uri"),
            authorization=self.headers.get("Authorization"),
            now=datetime.now(UTC),
        )
        log.info(
            "%d %s login=%s account=%s uri=%r",
            decision.status,
            decision.reason,
            decision.login or "-",
            decision.account or "-",
            (self.headers.get("X-Forwarded-Uri") or "")[:200],
        )
        headers: dict[str, str] = {}
        if decision.status == 401:
            headers["WWW-Authenticate"] = f'Basic realm="{self.server.realm}", charset="UTF-8"'
        if decision.status == 200 and decision.login and decision.account:
            headers["X-Repo-Client"] = decision.login
            headers["X-Repo-Account"] = decision.account
        self._reply(decision.status, HTTPStatus(decision.status).phrase, headers)

    def do_GET(self) -> None:
        self._handle()

    def do_HEAD(self) -> None:
        self._handle()


def _prepare_socket(path: str) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(st.st_mode):
        raise SystemExit(f"{path} exists and is not a socket, refusing to remove it")
    os.unlink(path)


def make_server(socket_path: str, export_path: str, realm: str) -> _Server:
    _prepare_socket(socket_path)
    old_umask = os.umask(0o117)  # socket created as 0660
    try:
        server = _Server(socket_path, Handler)
    finally:
        os.umask(old_umask)
    os.chmod(socket_path, SOCKET_MODE)
    server.store = ExportStore(export_path)
    server.realm = "".join(c for c in realm if c.isprintable() and c not in '"\\') or DEFAULT_REALM
    return server


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("REPO_AUTH_LOG_LEVEL", "INFO"),
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    socket_path = os.environ.get("REPO_AUTH_SOCKET", DEFAULT_SOCKET)
    export_path = os.environ.get("REPO_AUTH_EXPORT", DEFAULT_EXPORT)
    realm = os.environ.get("REPO_AUTH_REALM", DEFAULT_REALM)
    server = make_server(socket_path, export_path, realm)
    if server.store.get() is None:
        log.warning("no valid client list yet (%s), answering 503 until it appears", export_path)

    def _stop(signum: int, _frame: FrameType | None) -> None:
        log.info("signal %d, stopping", signum)
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _stop)
    log.info("listening on %s", socket_path)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        with contextlib.suppress(FileNotFoundError):
            os.unlink(socket_path)


if __name__ == "__main__":
    socket.setdefaulttimeout(REQUEST_TIMEOUT)
    main()
