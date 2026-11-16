"""One synchronisation run: update mirrors, snapshot, publish, clean up.

Every mirror is independent: a failing upstream (Launchpad down, Cloudsmith
returning 402, a bad signature, a timeout) leaves its last published snapshot
in place and the others continue. Decisions are taken from what aptly really
has (``publish list -json``, ``snapshot list``), not from the state file; the
state file only records results for the catalogue and the report, so a crash
anywhere in a run heals on the next one.
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

from .aptly import Aptly, AptlyError, Publication, snapshot_owner
from .config import Config, Mirror

log = logging.getLogger(__name__)

STATE_FILE = "repo-sync-state.json"
LOCK_FILE = ".repo-sync.lock"
ARMORED_KEY = b"-----BEGIN PGP PUBLIC KEY BLOCK-----"

# Anything one mirror (or one cleanup step) can raise without the run being
# broken as a whole. TimeoutExpired is a SubprocessError.
SYNC_ERRORS = (AptlyError, subprocess.SubprocessError, OSError, ValueError)


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
            return cls(
                mirrors={k: MirrorState.from_dict(v) for k, v in raw.get("mirrors", {}).items()},
                last_run=raw.get("last_run"),
            )
        except FileNotFoundError:
            return cls()
        except (ValueError, TypeError, AttributeError) as exc:
            raise RuntimeError(f"state file {path} is corrupt ({exc}); remove it, the next sync rebuilds it") from exc

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
    with open(key_file, "rb") as fh:
        if ARMORED_KEY not in fh.read(1 << 20):
            # gpg --dearmor accepts binary input with rc 0 and writes garbage;
            # the mirror would then fail with a misleading "No public key".
            raise ValueError(f"{key_file} is not an armored OpenPGP public key")
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
        mirrors = self.aptly.mirrors()
        pubs = self.aptly.publications()
        for mirror in self.config.mirrors:
            st = self.state.mirrors.setdefault(mirror.name, MirrorState())
            st.first_attempt = st.first_attempt or iso(now)
            st.last_attempt = iso(now)
            try:
                self._sync_one(mirror, st, mirrors, pubs, now)
                st.last_success = iso(now)
                st.last_error = None
            except SYNC_ERRORS as exc:
                st.last_error = _short_error(exc)
                log.error("mirror %s: %s", mirror.name, st.last_error)
            self.state.save(self.state_path)
        # Removed mirrors are cleaned up after the configured ones had their
        # chance: a renamed mirror first takes over its prefix, and only then
        # is the old one dropped (never leaving the prefix empty meanwhile).
        self._prune_removed(pubs)
        try:
            self.aptly.db_cleanup()
        except SYNC_ERRORS as exc:
            log.error("db cleanup failed: %s", _short_error(exc))
        self.state.last_run = iso(utcnow())
        self.state.save(self.state_path)
        return self.state

    def _snapshot_name(self, mirror_name: str, now: datetime) -> str:
        base = f"{mirror_name}-{now.strftime('%Y%m%dT%H%M%SZ')}"
        existing = set(self.aptly.snapshots())
        name, n = base, 0
        while name in existing:
            n += 1
            name = f"{base}-{n}"
        return name

    def _layout_matches(self, pub: Publication, mirror: Mirror) -> bool:
        """`publish switch` keeps the original architectures, component and
        options; when they differ the publication has to be made again."""
        return (
            pub.component == mirror.component
            and set(pub.architectures) == set(mirror.architectures)
            and pub.acquire_by_hash
        )

    def _sync_one(
        self,
        mirror: Mirror,
        st: MirrorState,
        mirrors: set[str],
        pubs: dict[tuple[str, str], Publication],
        now: datetime,
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

        new_snapshot = self._snapshot_name(mirror.name, now)
        self.aptly.snapshot_create(new_snapshot, mirror.name)
        target = (mirror.prefix, mirror.distribution)
        current = pubs.get(target)
        if (
            current is not None
            and snapshot_owner(current.snapshot) == mirror.name
            and self._layout_matches(current, mirror)
            and self.aptly.snapshots_identical(current.snapshot, new_snapshot)
        ):
            log.info("mirror %s: no change", mirror.name)
            self.aptly.snapshot_drop(new_snapshot)
            published = current.snapshot
        else:
            if current is not None and self._layout_matches(current, mirror):
                self.aptly.publish_switch(new_snapshot, mirror.prefix, mirror.distribution)
            else:
                if current is not None:
                    log.warning(
                        "mirror %s: layout of %s/%s changed (%s %s -> %s %s), publishing again",
                        mirror.name,
                        mirror.prefix,
                        mirror.distribution,
                        current.component,
                        ",".join(current.architectures),
                        mirror.component,
                        ",".join(mirror.architectures),
                    )
                    self.aptly.publish_drop(mirror.prefix, mirror.distribution)
                self.aptly.publish_snapshot(new_snapshot, mirror)
            pubs[target] = Publication(new_snapshot, mirror.component, mirror.architectures, True)
            published = new_snapshot
            log.info("mirror %s: published %s", mirror.name, new_snapshot)
        # The mirror moved (prefix or distribution changed): drop where it was.
        for key, pub in list(pubs.items()):
            if key != target and snapshot_owner(pub.snapshot) == mirror.name:
                log.info("mirror %s: dropping old publication %s/%s", mirror.name, *key)
                self.aptly.publish_drop(*key)
                del pubs[key]
        st.snapshot = published
        st.prefix, st.distribution = target
        st.packages = self.aptly.snapshot_packages(published)
        self._drop_old_snapshots(mirror.name, {p.snapshot for p in pubs.values()})

    def _drop_old_snapshots(self, mirror_name: str, protected: set[str]) -> None:
        """Keep published snapshots plus the newest keep_snapshots - 1 others (rollback)."""
        others = sorted(
            (s for s in self.aptly.snapshots() if snapshot_owner(s) == mirror_name and s not in protected),
            reverse=True,
        )
        for snap in others[self.config.keep_snapshots - 1 :]:
            self.aptly.snapshot_drop(snap)

    def _prune_removed(self, pubs: dict[tuple[str, str], Publication]) -> None:
        """Drop what belongs to mirrors no longer in the config.

        Works from aptly's real content. A publication of a removed mirror at
        a place a configured mirror owns is kept until that mirror publishes
        there (e.g. renamed mirror whose upstream is down right now).
        """
        wanted = {m.name for m in self.config.mirrors}
        targets = {(m.prefix, m.distribution) for m in self.config.mirrors}
        try:
            snapshots = self.aptly.snapshots()
            mirrors = self.aptly.mirrors()
        except SYNC_ERRORS as exc:
            log.error("cleanup of removed mirrors skipped: %s", _short_error(exc))
            return
        for snap in snapshots:
            owner = snapshot_owner(snap)
            if owner is None or owner in wanted:
                continue
            try:
                places = [key for key, pub in pubs.items() if pub.snapshot == snap]
                if any(key in targets for key in places):
                    log.info("keeping %s: still served until its successor publishes", snap)
                    continue
                for key in places:
                    log.warning("removed mirror %s: dropping publication %s/%s", owner, *key)
                    self.aptly.publish_drop(*key)
                    del pubs[key]
                self.aptly.snapshot_drop(snap)
            except SYNC_ERRORS as exc:
                log.error("cleanup of %s failed: %s", snap, _short_error(exc))
        for name in sorted(mirrors - wanted):
            try:
                log.warning("mirror %s removed from config: dropping it", name)
                self.aptly.mirror_drop(name)
            except SYNC_ERRORS as exc:
                log.error("cleanup of mirror %s failed: %s", name, _short_error(exc))
        for name in sorted(set(self.state.mirrors) - wanted):
            del self.state.mirrors[name]


def _short_error(exc: BaseException) -> str:
    text = str(exc)
    if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
        text += ": " + (exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr)
    return " ".join(text.split())[-500:]
