"""gpgv for aptly with apt's rule: one valid signature from the keyring is enough.

Launchpad signs a PPA's ``InRelease`` with the PPA's current key and also with
its legacy 1024-bit key. gpgv exits 2 when any signature cannot be checked
(``NO_PUBKEY``), and aptly fails on any non-zero exit, so a mirror whose
keyring holds only the current key never syncs. Trusting the legacy key would
lower verification to 1024-bit RSA, because gpgv accepts a file signed by that
key alone.

This program runs the real gpgv and keeps its exit status except in one case,
the one apt accepts too: at least one signature is valid (``VALIDSIG``, so made
by a key in the keyring given by aptly) and every other signature only lacks
its public key. The status may hold nothing else: a bad, expired or revoked
signature, an ``ERROR`` (e.g. a second clearsigned message appended to the
file) or any status keyword not listed here keeps the failure, so the rule
fails closed if gpgv ever reports something new.

The image installs it as ``/usr/local/bin/gpgv``, ahead of ``/usr/bin/gpgv``
in ``PATH``, which is where aptly looks for gpgv.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import TextIO

from repo_common.proc import run_program

GPGV = "/usr/bin/gpgv"
GPGV_TIMEOUT = 300
STATUS_PREFIX = "[GNUPG:] "
# gpgv's exit status when a signature could not be checked (missing key).
EXIT_CANNOT_CHECK = 2
# ERRSIG <keyid> <pkalgo> <hashalgo> <class> <time> <rc> [<fpr>]: the reason
# field and its value "No public key" (gpg doc/DETAILS).
ERRSIG_RC_FIELD = 6
ERRSIG_NO_PUBKEY = "9"
# Everything gpgv reports for a file signed by a known and an unknown key.
ALLOWED = frozenset(
    {"NEWSIG", "KEY_CONSIDERED", "SIG_ID", "GOODSIG", "VALIDSIG", "ERRSIG", "NO_PUBKEY"}
)


@dataclass(frozen=True)
class Verdict:
    """Decision over one gpgv run."""

    accepted: bool
    unknown_keys: tuple[str, ...] = ()


def _records(status: Iterable[str]) -> list[list[str]]:
    return [
        line[len(STATUS_PREFIX) :].split()
        for line in status
        if line.startswith(STATUS_PREFIX) and line[len(STATUS_PREFIX) :].split()
    ]


def judge(returncode: int, status: Iterable[str]) -> Verdict:
    """Apply apt's rule to gpgv's exit status and ``--status-fd`` lines."""
    if returncode == 0:
        return Verdict(accepted=True)
    if returncode != EXIT_CANNOT_CHECK:
        return Verdict(accepted=False)
    records = _records(status)
    keywords = [record[0] for record in records]
    if not ALLOWED.issuperset(keywords):
        return Verdict(accepted=False)
    errsigs = [record for record in records if record[0] == "ERRSIG"]
    if any(
        len(record) <= ERRSIG_RC_FIELD or record[ERRSIG_RC_FIELD] != ERRSIG_NO_PUBKEY
        for record in errsigs
    ):
        return Verdict(accepted=False)
    valid = keywords.count("VALIDSIG")
    unknown = len(errsigs)
    if (
        valid == 0
        or unknown == 0  # exit 2 without a missing key is some other failure
        or keywords.count("NO_PUBKEY") != unknown
        or keywords.count("GOODSIG") != valid
        or keywords.count("NEWSIG") != valid + unknown
    ):
        return Verdict(accepted=False)
    return Verdict(accepted=True, unknown_keys=tuple(record[1] for record in errsigs))


def split_status_fd(args: Sequence[str]) -> tuple[int | None, list[str]]:
    """Return the ``--status-fd`` descriptor and the remaining arguments."""
    rest: list[str] = []
    status_fd: int | None = None
    items = iter(args)
    for arg in items:
        if arg == "--status-fd":
            status_fd = int(next(items))
        elif arg.startswith("--status-fd="):
            status_fd = int(arg.split("=", 1)[1])
        else:
            rest.append(arg)
    return status_fd, rest


def _write_fd(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view) :]


def _forward(stream: TextIO, data: bytes) -> None:
    stream.flush()
    stream.buffer.write(data)
    stream.buffer.flush()


def main(args: Sequence[str]) -> int:
    """Run gpgv with ``args``; status goes to the caller's ``--status-fd``."""
    status_fd, rest = split_status_fd(args)
    if status_fd is None:
        proc = run_program([GPGV, *rest], timeout=GPGV_TIMEOUT)
        _forward(sys.stdout, proc.stdout)
        _forward(sys.stderr, proc.stderr)
        return proc.returncode
    # gpgv prints nothing else to stdout, so stdout carries the status lines.
    proc = run_program([GPGV, "--status-fd", "1", *rest], timeout=GPGV_TIMEOUT)
    _write_fd(status_fd, proc.stdout)
    _forward(sys.stderr, proc.stderr)
    verdict = judge(proc.returncode, proc.stdout.decode("utf-8", errors="replace").splitlines())
    if not verdict.accepted:
        return proc.returncode
    if verdict.unknown_keys:
        print(
            "gpgv (repo-sync): valid signature from the keyring; ignoring signatures by"
            f" keys not in it: {' '.join(verdict.unknown_keys)}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
