"""The only place that starts external programs."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping, Sequence


def run_program(
    argv: Sequence[str], *, timeout: float, env: Mapping[str, str] | None = None
) -> subprocess.CompletedProcess[bytes]:
    """Run ``argv`` without a shell and capture its output; never raises on exit status.

    ``argv[0]`` must be an absolute path, so ``PATH`` cannot select another
    program. Arguments are passed as a list, so no value is ever interpreted
    by a shell. Raises :class:`subprocess.TimeoutExpired` after ``timeout``.
    """
    if not argv or not os.path.isabs(argv[0]):
        raise ValueError(f"program must be an absolute path: {argv[:1]!r}")
    return subprocess.run(  # noqa: S603 - absolute program, argument list, no shell
        list(argv), capture_output=True, timeout=timeout, check=False, env=env
    )


def check_program(
    argv: Sequence[str], *, timeout: float, env: Mapping[str, str] | None = None
) -> subprocess.CompletedProcess[bytes]:
    """Like :func:`run_program`, but a non-zero exit raises CalledProcessError."""
    proc = run_program(argv, timeout=timeout, env=env)
    proc.check_returncode()
    return proc
