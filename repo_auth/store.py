"""Loads the export and reloads it when the file changes."""

from __future__ import annotations

import logging
import os
import threading
from typing import NamedTuple

from .model import Export, ExportError, parse_export

log = logging.getLogger(__name__)

MAX_EXPORT_SIZE = 16 * 1024 * 1024


class _Stamp(NamedTuple):
    inode: int
    size: int
    mtime_ns: int


class ExportStore:
    """Thread-safe view of the export file.

    A missing or invalid file at startup leaves the store empty (the service
    answers 503, i.e. closed). An invalid file later keeps the last good
    export, so a broken write never opens or closes the repository by itself.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._export: Export | None = None
        self._stamp: _Stamp | None = None
        self._failed_stamp: _Stamp | None = None
        self._degraded = False

    def _current_stamp(self) -> _Stamp | None:
        try:
            st = os.stat(self._path)
        except OSError:
            return None
        return _Stamp(st.st_ino, st.st_size, st.st_mtime_ns)

    def get(self) -> Export | None:
        """The current export, reloading it when the file changed."""
        stamp = self._current_stamp()
        with self._lock:
            if stamp is None:
                if self._export is not None and not self._degraded:
                    log.error("export %s disappeared, keeping the last good one", self._path)
                self._degraded = True
                return self._export
            if stamp == self._stamp:
                self._degraded = False
                return self._export
            if stamp == self._failed_stamp:
                return self._export
            try:
                if stamp.size > MAX_EXPORT_SIZE:
                    raise ExportError(f"export larger than {MAX_EXPORT_SIZE} bytes")
                with open(self._path, "rb") as fh:
                    data = fh.read(MAX_EXPORT_SIZE + 1)
                export = parse_export(data)
            except (OSError, ExportError) as exc:
                log.error(
                    "cannot load export %s: %s (keeping %s)",
                    self._path,
                    exc,
                    "the last good one" if self._export else "nothing, answering 503",
                )
                self._failed_stamp = stamp
                self._degraded = True
                return self._export
            self._export = export
            self._stamp = stamp
            self._failed_stamp = None
            self._degraded = False
            log.info("loaded export %s: %d tokens", self._path, len(export.tokens))
            return self._export

    def health(self) -> tuple[bool, str]:
        """Return (healthy, reason).

        Unhealthy also when the newest file is unusable and an older export is
        still being served: decisions keep working, but the last change made by
        repo-admin (a block, a revocation) is not in effect.
        """
        export = self.get()
        with self._lock:
            if export is None:
                return False, "client list not loaded"
            if self._degraded:
                return False, "newest client list unusable, serving the last good one"
            return True, f"ok, {len(export.tokens)} tokens"
