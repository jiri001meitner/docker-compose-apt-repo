"""Quick reachability check of an upstream before aptly is started.

aptly retries a dead upstream for minutes (connect timeouts, ``-max-tries``).
With frequent runs that would be most of every run during an outage, so a
mirror whose upstream does not answer at all is skipped after one short
request. Any HTTP answer counts as reachable: what is wrong with it (404,
redirect, bad signature) is aptly's job to find and report precisely.
"""

from __future__ import annotations

import http.client
from urllib.parse import urlsplit

from .config import Upstream


class UpstreamUnreachableError(OSError):
    """The upstream gave no HTTP answer within the timeout."""


def release_url(upstream: Upstream) -> str:
    """URL of the upstream's signed Release file."""
    return f"{upstream.url.rstrip('/')}/dists/{upstream.distribution}/InRelease"


def probe(upstream: Upstream, timeout: float) -> None:
    """Raise :class:`UpstreamUnreachableError` unless the upstream answers HTTP in ``timeout`` s.

    The scheme is http or https (validated in the configuration); https
    verifies the certificate like aptly does.
    """
    url = release_url(upstream)
    parts = urlsplit(url)
    host = parts.hostname or ""
    conn_class = (
        http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
    )
    conn = conn_class(host, parts.port, timeout=timeout)
    try:
        conn.request("HEAD", parts.path or "/")
        conn.getresponse().close()
    except http.client.HTTPException:
        return  # a malformed answer is still an answer; aptly reports it
    except OSError as exc:  # DNS, refused, timeout, TLS
        raise UpstreamUnreachableError(f"upstream unreachable ({url}): {exc}") from exc
    finally:
        conn.close()
