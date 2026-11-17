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
from typing import Any, override

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


# What socketserver hands to process_request (a datagram server passes a tuple).
type _Request = socket.socket | tuple[bytes, socket.socket]


class Slots:
    """Counter of busy handler threads; taking a slot never blocks.

    A slot is taken in the accepting thread and released by the handler
    thread, so it cannot be a ``with`` block around one piece of code.
    """

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._busy = 0
        self._lock = threading.Lock()

    def take(self) -> bool:
        """Take a slot; False when all are busy."""
        with self._lock:
            if self._busy >= self._limit:
                return False
            self._busy += 1
            return True

    def release(self) -> None:
        """Give a slot back; releasing more than was taken is a bug."""
        with self._lock:
            if self._busy <= 0:
                raise RuntimeError("slot released twice")
            self._busy -= 1


def _stream(request: _Request) -> socket.socket:
    return request if isinstance(request, socket.socket) else request[1]


def _reject_busy(sock: socket.socket) -> None:
    """Answer 503 without a handler thread."""
    with contextlib.suppress(OSError):
        # Read what the client already sent, so closing does not reset the
        # connection before it sees the 503.
        sock.settimeout(0.2)
        sock.recv(65536)
        sock.sendall(_BUSY)


def _abort(sock: socket.socket) -> None:
    with contextlib.suppress(OSError):
        sock.shutdown(socket.SHUT_RDWR)


class _Server(socketserver.ThreadingUnixStreamServer):
    """Threaded UNIX socket server with a concurrency limit and a per-connection deadline."""

    daemon_threads = True
    block_on_close = False

    def __init__(
        self, path: str, handler: type[BaseHTTPRequestHandler], store: ExportStore, realm: str
    ) -> None:
        super().__init__(path, handler)
        self.store = store
        self.realm = realm
        self._slots = Slots(MAX_CONCURRENT)

    @override
    def process_request(self, request: _Request, client_address: Any) -> None:
        if not self._slots.take():
            log.warning("too many concurrent requests (%d), answering 503", MAX_CONCURRENT)
            _reject_busy(_stream(request))
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    @override
    def process_request_thread(self, request: _Request, client_address: Any) -> None:
        deadline = threading.Timer(REQUEST_DEADLINE, _abort, args=(_stream(request),))
        deadline.daemon = True
        deadline.start()
        try:
            super().process_request_thread(request, client_address)
        finally:
            deadline.cancel()
            self._slots.release()


class Handler(BaseHTTPRequestHandler):
    """One forward_auth request per connection."""

    server: _Server
    server_version = "repo-auth"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = REQUEST_TIMEOUT

    @override
    def address_string(self) -> str:
        """UNIX sockets have no peer address; BaseHTTPRequestHandler expects one."""
        return "unix"

    @override
    def log_message(self, format: str, *args: Any) -> None:
        """Route http.server's own messages to logging at debug level."""
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

    def _dispatch(self) -> None:
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
        if decision.status == HTTPStatus.UNAUTHORIZED:
            headers["WWW-Authenticate"] = f'Basic realm="{self.server.realm}", charset="UTF-8"'
        if decision.status == HTTPStatus.OK and decision.login and decision.account:
            headers["X-Repo-Client"] = decision.login
            headers["X-Repo-Account"] = decision.account
        self._reply(decision.status, HTTPStatus(decision.status).phrase, headers)

    # http.server looks the handlers up by these names.
    do_GET = _dispatch
    do_HEAD = _dispatch


def _prepare_socket(path: str) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(st.st_mode):
        raise SystemExit(f"{path} exists and is not a socket, refusing to remove it")
    os.unlink(path)


def safe_realm(realm: str) -> str:
    """Realm usable inside a quoted header value."""
    return "".join(c for c in realm if c.isprintable() and c not in '"\\') or DEFAULT_REALM


def make_server(socket_path: str, export_path: str, realm: str) -> _Server:
    """Bind the socket (0660) and attach the export store."""
    _prepare_socket(socket_path)
    old_umask = os.umask(0o117)  # socket created as 0660
    try:
        server = _Server(socket_path, Handler, ExportStore(export_path), safe_realm(realm))
    finally:
        os.umask(old_umask)
    os.chmod(socket_path, SOCKET_MODE)
    return server


def main() -> None:
    """Run the service until SIGTERM."""
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
