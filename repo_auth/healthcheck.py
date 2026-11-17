"""Container healthcheck: GET /healthz over the UNIX socket (exit 0 = healthy)."""

from __future__ import annotations

import os
import socket
import sys

from .server import DEFAULT_SOCKET


def main() -> int:
    """Exit status 0 when /healthz answers 200."""
    path = os.environ.get("REPO_AUTH_SOCKET", DEFAULT_SOCKET)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)
            sock.connect(path)
            sock.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            status_line = sock.recv(64).split(b"\r\n", 1)[0]
    except OSError as exc:
        print(f"unhealthy: {exc}", file=sys.stderr)
        return 1
    if status_line.startswith(b"HTTP/1.1 200"):
        return 0
    print(f"unhealthy: {status_line.decode(errors='replace')}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
