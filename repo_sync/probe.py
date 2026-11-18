"""Quick reachability check of an upstream before aptly is started.

aptly retries a dead upstream for minutes (connect timeouts, ``-max-tries``).
With frequent runs that would be most of every run during an outage, so a
mirror whose upstream does not answer at all is skipped after one short
request. Any HTTP answer counts as reachable: what is wrong with it (404,
redirect, bad signature) is aptly's job to find and report precisely.

The timeout is one deadline for the whole probe. ``http.client`` would apply
it to each resolved address in turn, and an upstream with three IPv4 and
three IPv6 addresses (Launchpad) then took six times as long.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
from collections.abc import Callable
from urllib.parse import urlsplit

from .config import Upstream

DEFAULT_PORTS = {"http": 80, "https": 443}


class UpstreamUnreachableError(OSError):
    """The upstream gave no HTTP answer within the timeout."""


def release_url(upstream: Upstream) -> str:
    """URL of the upstream's signed Release file."""
    return f"{upstream.url.rstrip('/')}/dists/{upstream.distribution}/InRelease"


def _remaining(deadline: float) -> float:
    """Seconds left until ``deadline``; TimeoutError when none are."""
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("timed out")
    return left


def _connect(host: str, port: int, deadline: float) -> socket.socket:
    """TCP connection to the first address of ``host`` that accepts before ``deadline``.

    Name resolution itself is bounded by the system resolver's timeouts.
    """
    error: OSError = TimeoutError("timed out")
    for family, kind, proto, _name, address in socket.getaddrinfo(
        host, port, type=socket.SOCK_STREAM
    ):
        sock = socket.socket(family, kind, proto)
        try:
            sock.settimeout(_remaining(deadline))
            sock.connect(address)
        except OSError as exc:
            sock.close()
            error = exc
            if isinstance(exc, TimeoutError):
                break  # the deadline is spent
            continue
        return sock
    raise error


def probe(upstream: Upstream, timeout: float) -> None:
    """Raise :class:`UpstreamUnreachableError` unless the upstream answers HTTP in ``timeout`` s.

    The scheme is http or https (validated in the configuration); https
    verifies the certificate like aptly does.
    """
    url = release_url(upstream)
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or DEFAULT_PORTS[parts.scheme]
    deadline = time.monotonic() + timeout
    conn = http.client.HTTPConnection(host, port)
    try:
        # request() uses conn.sock instead of connecting; close() closes it.
        conn.sock = _connect(host, port, deadline)
        if parts.scheme == "https":
            conn.sock.settimeout(_remaining(deadline))
            conn.sock = ssl.create_default_context().wrap_socket(conn.sock, server_hostname=host)
        conn.sock.settimeout(_remaining(deadline))
        conn.request("HEAD", parts.path or "/")
        conn.getresponse().close()
    except http.client.HTTPException:
        return  # a malformed answer is still an answer; aptly reports it
    except OSError as exc:  # DNS, refused, timeout, TLS
        raise UpstreamUnreachableError(f"upstream unreachable ({url}): {exc}") from exc
    finally:
        conn.close()


def run_probe() -> Callable[[Upstream, float], None]:
    """The probe for one run: a host that did not answer is not asked again.

    Several mirrors often share an upstream host (every PPA is on
    Launchpad); during its outage one timeout is enough for all of them.
    """
    dead: set[tuple[str, str]] = set()

    def checked(upstream: Upstream, timeout: float) -> None:
        parts = urlsplit(upstream.url)
        origin = (parts.scheme, parts.netloc)
        if origin in dead:
            raise UpstreamUnreachableError(
                f"upstream unreachable ({release_url(upstream)}): "
                f"{parts.netloc} did not answer earlier in this run"
            )
        try:
            probe(upstream, timeout)
        except UpstreamUnreachableError:
            dead.add(origin)
            raise

    return checked
