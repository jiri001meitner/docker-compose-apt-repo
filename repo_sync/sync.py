"""One synchronisation run: update mirrors, snapshot, publish, clean up.

Every mirror is independent: a failing upstream (Launchpad down, Cloudsmith
returning 402, a bad signature) leaves its last published snapshot in place
and the others continue. The run itself only fails on internal errors.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import logging
import os
import subprocess
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .aptly import SNAPSHOT_RE, Aptly, AptlyError
from .config import Config, Mirror

log = logging.getLogger(__name__)

STATE_FILE = "repo-sync-state.json"
LOCK_FILE = ".repo-sync.lock"


class LockedError(RuntimeError):
    pass


def utcnow() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def iso(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def from_iso(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


@dataclass
class MirrorState:
    mirror_hash: str | None = None
    prefix: str | None = None
    distribution: str | None = None
    snapshot: str | None = None
    packages: int = 0
    first_attempt: str | None = None
    last_attempt: str | None = None
    last_success: str | None = None
    last_error: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> MirrorState:
        known = {k: raw[k] for k in cls.__dataclass_fields__ if k in raw}
        return cls(**known)


@dataclass
class State:
    mirrors: dict[str, MirrorState] = field(default_factory=dict)
    last_run: str | None = None

    @classmethod
    def load(cls, path: Path) -> State:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return cls()
        return cls(
            mirrors={k: MirrorState.from_dict(v) for k, v in raw.get("mirrors", {}).items()},
            last_run=raw.get("last_run"),
        )

    def save(self, path: Path) -> None:
        data = {"last_run": self.last_run, "mirrors": {k: vars(v) for k, v in sorted(self.mirrors.items())}}
        atomic_write(path, (json.dumps(data, indent=2) + "\n").encode())


def atomic_write(path: Path, data: bytes, mode: int = 0o644) -> None:
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


@contextlib.contextmanager
def run_lock(root: Path) -> Iterator[None]:
    root.mkdir(parents=True, exist_ok=True)
    with open(root / LOCK_FILE, "w") as fh:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LockedError("another repo-sync run is in progress") from exc
        yield


def dearmor(key_file: str, out_dir: Path) -> str:
    """Convert an armored public key file into a keyring gpgv can read."""
    target = out_dir / (Path(key_file).name + ".gpg")
    subprocess.run(  # noqa: S603 - fixed argv
        ["gpg", "--batch", "--yes", "--dearmor", "-o", str(target), key_file],  # noqa: S607
        check=True,
        capture_output=True,
        timeout=60,
    )
    return str(target)


class Syncer:
    def __init__(self, config: Config, aptly: Aptly, root: Path, keyring_dir: Path) -> None:
        self.config = config
        self.aptly = aptly
        self.root = root
        self.keyring_dir = keyring_dir
        self.state_path = root / STATE_FILE
        self.state = State.load(self.state_path)

    def run(self) -> State:
        now = utcnow()
        self._prune_removed()
        mirrors = self.aptly.mirrors()
        published = self.aptly.published()
        for mirror in self.config.mirrors:
            st = self.state.mirrors.setdefault(mirror.name, MirrorState())
            st.first_attempt = st.first_attempt or iso(now)
            st.last_attempt = iso(now)
            try:
                self._sync_one(mirror, st, mirrors, published, now)
                st.last_success = iso(now)
                st.last_error = None
            except (AptlyError, subprocess.CalledProcessError, OSError) as exc:
                st.last_error = _short_error(exc)
                log.error("mirror %s: %s", mirror.name, st.last_error)
            self.state.save(self.state_path)
        try:
            self.aptly.db_cleanup()
        except AptlyError as exc:
            log.error("db cleanup failed: %s", exc)
        self.state.last_run = iso(utcnow())
        self.state.save(self.state_path)
        return self.state

    def _sync_one(
        self, mirror: Mirror, st: MirrorState, mirrors: set[str], published: set[tuple[str, str]], now: datetime
    ) -> None:
        keyring = dearmor(mirror.key_file, self.keyring_dir)
        if mirror.name in mirrors and st.mirror_hash != mirror.mirror_hash():
            log.info("mirror %s: definition changed, recreating", mirror.name)
            self.aptly.mirror_drop(mirror.name)
            mirrors.discard(mirror.name)
        if mirror.name not in mirrors:
            self.aptly.mirror_create(mirror, keyring)
            mirrors.add(mirror.name)
        st.mirror_hash = mirror.mirror_hash()

        self.aptly.mirror_update(mirror.name, keyring)

        new_snapshot = f"{mirror.name}-{now.strftime('%Y%m%dT%H%M%SZ')}"
        self.aptly.snapshot_create(new_snapshot, mirror.name)
        target = (mirror.prefix, mirror.distribution)
        existing = set(self.aptly.snapshots())
        if (
            st.snapshot
            and st.snapshot in existing
            and target in published
            and (st.prefix, st.distribution) == target
            and self.aptly.snapshots_identical(st.snapshot, new_snapshot)
        ):
            log.info("mirror %s: no change", mirror.name)
            self.aptly.snapshot_drop(new_snapshot)
        else:
            if target in published:
                self.aptly.publish_switch(new_snapshot, mirror.prefix, mirror.distribution)
            else:
                self.aptly.publish_snapshot(new_snapshot, mirror.prefix, mirror.distribution, mirror.architectures)
                published.add(target)
            old_target = (st.prefix, st.distribution)
            if st.prefix and old_target != target and old_target in published:
                self.aptly.publish_drop(st.prefix, st.distribution or "")
                published.discard(old_target)
            st.snapshot = new_snapshot
            st.prefix, st.distribution = target
            st.packages = self.aptly.snapshot_packages(new_snapshot)
            log.info("mirror %s: published %s (%d packages)", mirror.name, new_snapshot, st.packages)
        self._drop_old_snapshots(mirror.name, st.snapshot)

    def _drop_old_snapshots(self, mirror_name: str, keep: str | None) -> None:
        """Keep the published snapshot plus the newest keep_snapshots - 1 others (for rollback)."""
        others = sorted(
            (
                s
                for s in self.aptly.snapshots()
                if (m := SNAPSHOT_RE.match(s)) and m.group("mirror") == mirror_name and s != keep
            ),
            reverse=True,
        )
        for snap in others[self.config.keep_snapshots - 1 :]:
            self.aptly.snapshot_drop(snap)

    def _prune_removed(self) -> None:
        wanted = {m.name for m in self.config.mirrors}
        for name in sorted(set(self.state.mirrors) - wanted):
            st = self.state.mirrors[name]
            log.warning("mirror %s removed from config: dropping publish, snapshots and mirror", name)
            published = self.aptly.published()
            if st.prefix and (st.prefix, st.distribution) in published:
                self.aptly.publish_drop(st.prefix, st.distribution or "")
            for snap in self.aptly.snapshots():
                m = SNAPSHOT_RE.match(snap)
                if m and m.group("mirror") == name:
                    self.aptly.snapshot_drop(snap)
            if name in self.aptly.mirrors():
                self.aptly.mirror_drop(name)
            del self.state.mirrors[name]
        self.state.save(self.state_path)


def _short_error(exc: BaseException) -> str:
    text = str(exc)
    if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
        text += ": " + (exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr)
    return " ".join(text.split())[-500:]
