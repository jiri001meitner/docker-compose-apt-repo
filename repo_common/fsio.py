"""Crash-safe file updates and advisory locks."""

from __future__ import annotations

import contextlib
import fcntl
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path


def fsync_directory(directory: Path) -> None:
    """Persist a rename inside ``directory``."""
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes, mode: int = 0o644) -> None:
    """Replace ``path`` with ``data`` so readers see the old or the new file, never a mix.

    The data goes to a temporary file in the same directory, is flushed to
    disk, gets its final mode and is renamed over the target; the directory
    is synced so the rename survives a crash.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    fsync_directory(path.parent)


@contextlib.contextmanager
def exclusive_lock(path: Path, *, wait: bool) -> Iterator[None]:
    """Hold an exclusive ``flock`` on ``path`` (created 0600 if missing).

    With ``wait=False`` a held lock raises :class:`BlockingIOError` at once.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX if wait else fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)
