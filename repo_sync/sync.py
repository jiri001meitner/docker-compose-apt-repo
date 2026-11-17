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
import dataclasses
import json
import logging
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from repo_common.fsio import atomic_write, exclusive_lock
from repo_common.timeutil import format_utc, utcnow

from .aptly import SOURCE_SUFFIX, AptlyError, Publication, is_source_snapshot, snapshot_owner
from .config import Config, Mirror
from .gpg import dearmor

log = logging.getLogger(__name__)

STATE_FILE = "repo-sync-state.json"
LOCK_FILE = ".repo-sync.lock"
MAX_ERROR_LENGTH = 500

# Anything one mirror (or one cleanup step) can raise without the run being
# broken as a whole. TimeoutExpired is a SubprocessError.
SYNC_ERRORS = (AptlyError, subprocess.SubprocessError, OSError, ValueError)

type Publications = dict[tuple[str, str], Publication]


class LockedError(RuntimeError):
    """Another run holds the lock."""


class AptlyOps(Protocol):
    """The aptly operations a run uses (:class:`repo_sync.aptly.Aptly`)."""

    def mirrors(self) -> set[str]:
        """Names of all mirrors."""

    def mirror_create(self, mirror: Mirror, keyring: str) -> None:
        """Create a mirror."""

    def mirror_drop(self, name: str) -> None:
        """Delete a mirror."""

    def mirror_update(self, name: str, keyring: str) -> None:
        """Download a mirror from upstream."""

    def snapshots(self) -> list[str]:
        """Names of all snapshots."""

    def snapshot_create(self, name: str, mirror: str) -> None:
        """Snapshot a mirror."""

    def snapshot_latest(self, name: str, source: str) -> None:
        """Snapshot of the newest versions in ``source``."""

    def snapshot_drop(self, name: str) -> None:
        """Delete a snapshot."""

    def snapshots_identical(self, a: str, b: str) -> bool:
        """True when both snapshots have the same packages."""

    def snapshot_packages(self, name: str) -> int:
        """Number of packages in a snapshot."""

    def publications(self) -> Publications:
        """Current publications by (prefix, distribution)."""

    def publish_snapshot(self, snapshot: str, mirror: Mirror) -> None:
        """Publish a snapshot at the mirror's target."""

    def publish_switch(self, snapshot: str, prefix: str, distribution: str) -> None:
        """Switch a publication to another snapshot."""

    def publish_drop(self, prefix: str, distribution: str) -> None:
        """Remove a publication."""

    def db_cleanup(self) -> None:
        """Remove unreferenced package files."""


@dataclass
class MirrorState:
    """Result of the last runs of one mirror, for the catalogue and the report."""

    mirror_hash: str | None = None
    snapshot: str | None = None
    packages: int = 0
    first_attempt: str | None = None
    last_attempt: str | None = None
    last_success: str | None = None
    last_error: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> MirrorState:
        """Build from the state file, ignoring unknown keys."""
        names = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in raw.items() if k in names})


@dataclass
class State:
    """The state file."""

    mirrors: dict[str, MirrorState] = field(default_factory=dict)
    last_run: str | None = None

    @classmethod
    def load(cls, path: Path) -> State:
        """Read the state file; missing means empty, corrupt raises RuntimeError."""
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            return cls(
                mirrors={k: MirrorState.from_dict(v) for k, v in raw.get("mirrors", {}).items()},
                last_run=raw.get("last_run"),
            )
        except FileNotFoundError:
            return cls()
        except (ValueError, TypeError, AttributeError) as exc:
            raise RuntimeError(
                f"state file {path} is corrupt ({exc}); remove it, the next sync rebuilds it"
            ) from exc

    def save(self, path: Path) -> None:
        """Write the state file atomically."""
        data = {
            "last_run": self.last_run,
            "mirrors": {k: dataclasses.asdict(v) for k, v in sorted(self.mirrors.items())},
        }
        atomic_write(path, (json.dumps(data, indent=2) + "\n").encode())


@contextlib.contextmanager
def run_lock(root: Path) -> Iterator[None]:
    """Only one run at a time; a second one raises LockedError at once."""
    with contextlib.ExitStack() as stack:
        try:
            stack.enter_context(exclusive_lock(root / LOCK_FILE, wait=False))
        except BlockingIOError as exc:
            raise LockedError("another repo-sync run is in progress") from exc
        yield


def _layout_matches(pub: Publication, mirror: Mirror) -> bool:
    """``publish switch`` keeps the original architectures, component and options.

    When they differ the publication has to be made again.
    """
    up = mirror.upstream
    return (
        pub.component == up.component
        and set(pub.architectures) == set(up.architectures)
        and pub.acquire_by_hash
    )


def _short_error(exc: BaseException) -> str:
    text = str(exc)
    if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
        stderr = exc.stderr
        text += ": " + (stderr.decode(errors="replace") if isinstance(stderr, bytes) else stderr)
    return " ".join(text.split())[-MAX_ERROR_LENGTH:]


class Syncer:
    """Runs one synchronisation of all configured mirrors."""

    def __init__(self, config: Config, aptly: AptlyOps, root: Path, keyring_dir: Path) -> None:
        self.config = config
        self.aptly = aptly
        self.keyring_dir = keyring_dir
        self.state_path = root / STATE_FILE
        self.state = State.load(self.state_path)
        self.started = utcnow()  # one timestamp for the whole run

    def run(self) -> State:
        """Sync every mirror, then clean up; returns the new state."""
        now = self.started
        mirrors = self.aptly.mirrors()
        pubs = self.aptly.publications()
        for mirror in self.config.mirrors:
            st = self.state.mirrors.setdefault(mirror.name, MirrorState())
            st.first_attempt = st.first_attempt or format_utc(now)
            st.last_attempt = format_utc(now)
            try:
                self._sync_one(mirror, st, mirrors, pubs)
                st.last_success = format_utc(now)
                st.last_error = None
            except SYNC_ERRORS as exc:
                st.last_error = _short_error(exc)
                log.error("mirror %s: %s", mirror.name, st.last_error)
            self.state.save(self.state_path)
        self.cleanup(pubs)
        self.state.last_run = format_utc(utcnow())
        self.state.save(self.state_path)
        return self.state

    def cleanup(self, pubs: Publications) -> None:
        """Drop what removed mirrors left behind, then unreferenced package files.

        Runs after the configured mirrors had their chance: a renamed mirror
        first takes over its prefix, and only then is the old one dropped
        (never leaving the prefix empty meanwhile).
        """
        self._prune_removed(pubs)
        try:
            self.aptly.db_cleanup()
        except SYNC_ERRORS as exc:
            log.error("db cleanup failed: %s", _short_error(exc))

    def _snapshot_name(self, mirror_name: str) -> str:
        base = f"{mirror_name}-{self.started.strftime('%Y%m%dT%H%M%SZ')}"
        existing = set(self.aptly.snapshots())
        name, n = base, 0
        while name in existing or name + SOURCE_SUFFIX in existing:
            n += 1
            name = f"{base}-{n}"
        return name

    def _ensure_mirror(self, mirror: Mirror, st: MirrorState, mirrors: set[str]) -> str:
        """Create (or recreate) the aptly mirror and update it; returns the keyring."""
        keyring = dearmor(mirror.key_file, self.keyring_dir)
        identity = mirror.upstream.identity()
        if mirror.name in mirrors and st.mirror_hash != identity:
            log.info("mirror %s: definition changed, recreating", mirror.name)
            self.aptly.mirror_drop(mirror.name)
            mirrors.discard(mirror.name)
        if mirror.name not in mirrors:
            self.aptly.mirror_create(mirror, keyring)
            mirrors.add(mirror.name)
        st.mirror_hash = identity
        self.aptly.mirror_update(mirror.name, keyring)
        return keyring

    def _publish(self, mirror: Mirror, snapshot: str, current: Publication | None) -> None:
        """Make ``snapshot`` the publication at the mirror's target."""
        if current is not None and _layout_matches(current, mirror):
            self.aptly.publish_switch(snapshot, *mirror.target)
            return
        if current is not None:
            up = mirror.upstream
            log.warning(
                "mirror %s: layout of %s/%s changed (%s %s -> %s %s), publishing again",
                mirror.name,
                *mirror.target,
                current.component,
                ",".join(current.architectures),
                up.component,
                ",".join(up.architectures),
            )
            self.aptly.publish_drop(*mirror.target)
        self.aptly.publish_snapshot(snapshot, mirror)

    def _sync_one(
        self, mirror: Mirror, st: MirrorState, mirrors: set[str], pubs: Publications
    ) -> None:
        self._ensure_mirror(mirror, st, mirrors)
        new_snapshot = self._snapshot_name(mirror.name)
        # Only the newest version of each package is published: older ones
        # lack security fixes, and nobody uses a PPA for an old version.
        source = new_snapshot + SOURCE_SUFFIX
        self.aptly.snapshot_create(source, mirror.name)
        self.aptly.snapshot_latest(new_snapshot, source)
        current = pubs.get(mirror.target)
        if (
            current is not None
            and snapshot_owner(current.snapshot) == mirror.name
            and _layout_matches(current, mirror)
            and self.aptly.snapshots_identical(current.snapshot, new_snapshot)
        ):
            log.info("mirror %s: no change", mirror.name)
            self._drop_with_source(new_snapshot)
            published = current.snapshot
        else:
            self._publish(mirror, new_snapshot, current)
            up = mirror.upstream
            pubs[mirror.target] = Publication(new_snapshot, up.component, up.architectures, True)
            published = new_snapshot
            log.info("mirror %s: published %s", mirror.name, new_snapshot)
        self._drop_moved(mirror, pubs)
        st.snapshot = published
        st.packages = self.aptly.snapshot_packages(published)
        self._drop_old_snapshots(mirror.name, {p.snapshot for p in pubs.values()})

    def _drop_moved(self, mirror: Mirror, pubs: Publications) -> None:
        """The mirror moved (prefix or distribution changed): drop where it was."""
        for key, pub in list(pubs.items()):
            if key != mirror.target and snapshot_owner(pub.snapshot) == mirror.name:
                log.info("mirror %s: dropping old publication %s/%s", mirror.name, *key)
                self.aptly.publish_drop(*key)
                del pubs[key]

    def _drop_with_source(self, snapshot: str) -> None:
        """Drop a snapshot, then the source snapshot it was merged from (if any).

        aptly refuses to drop a source while a snapshot made from it exists,
        and ``snapshot show`` of that snapshot needs the source, so both live
        and go together.
        """
        self.aptly.snapshot_drop(snapshot)
        source = snapshot + SOURCE_SUFFIX
        if source in self.aptly.snapshots():
            self.aptly.snapshot_drop(source)

    def _drop_old_snapshots(self, mirror_name: str, protected: set[str]) -> None:
        """Keep published snapshots plus the newest keep_snapshots - 1 others (rollback).

        A source snapshot without its merged snapshot (a run interrupted
        between the two steps) is dropped.
        """
        own = [s for s in self.aptly.snapshots() if snapshot_owner(s) == mirror_name]
        orphans = [
            s for s in own if is_source_snapshot(s) and s.removesuffix(SOURCE_SUFFIX) not in own
        ]
        others = sorted(
            (s for s in own if s not in protected and not is_source_snapshot(s)), reverse=True
        )
        for snap in orphans:
            self.aptly.snapshot_drop(snap)
        for snap in others[self.config.keep_snapshots - 1 :]:
            self._drop_with_source(snap)

    def _prune_removed(self, pubs: Publications) -> None:
        """Drop what belongs to mirrors no longer in the config.

        Works from aptly's real content. A publication of a removed mirror at
        a place a configured mirror owns is kept until that mirror publishes
        there (e.g. renamed mirror whose upstream is down right now).
        """
        wanted = {m.name for m in self.config.mirrors}
        try:
            snapshots = self.aptly.snapshots()
            mirrors = self.aptly.mirrors()
        except SYNC_ERRORS as exc:
            log.error("cleanup of removed mirrors skipped: %s", _short_error(exc))
            return
        targets = {m.target for m in self.config.mirrors}
        for snap in snapshots:
            owner = snapshot_owner(snap)
            if owner is not None and owner not in wanted:
                try:
                    self._prune_snapshot(snap, pubs, targets)
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

    def _prune_snapshot(self, snap: str, pubs: Publications, targets: set[tuple[str, str]]) -> None:
        """Drop a removed mirror's snapshot and its publications, unless still needed."""
        if is_source_snapshot(snap):
            # Goes with its merged snapshot; only an orphan is dropped here.
            current = self.aptly.snapshots()
            if snap in current and snap.removesuffix(SOURCE_SUFFIX) not in current:
                self.aptly.snapshot_drop(snap)
            return
        places = [key for key, pub in pubs.items() if pub.snapshot == snap]
        if any(key in targets for key in places):
            log.info("keeping %s: still served until its successor publishes", snap)
            return
        for key in places:
            log.warning("removed mirror %s: dropping publication %s/%s", snapshot_owner(snap), *key)
            self.aptly.publish_drop(*key)
            del pubs[key]
        self._drop_with_source(snap)
