"""Thin wrapper around the aptly CLI (argument lists only, never a shell)."""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from repo_common.proc import run_program

from .config import Mirror, Signing

log = logging.getLogger(__name__)

# <mirror>-<UTC timestamp>[-<n>][-src]; <n> only when two runs fall into the
# same second, -src for the full snapshot of the mirror that the published
# (latest versions only) snapshot is made from. The mirror name may contain
# dashes, the timestamp anchors it.
SOURCE_SUFFIX = "-src"
SNAPSHOT_RE = re.compile(
    r"^(?P<mirror>[a-z0-9][a-z0-9-]*?)-(?P<ts>\d{8}T\d{6}Z)(?:-\d+)?(?P<source>-src)?$"
)

APTLY = "/usr/bin/aptly"
DEFAULT_TIMEOUT = 3600
# The first download of a large PPA on a slow line may take hours; aptly
# itself gives up on a silent server after about a minute.
UPDATE_TIMEOUT = 6 * 3600


def snapshot_owner(snapshot: str) -> str | None:
    """Name of the mirror a repo-sync snapshot belongs to, None for foreign ones."""
    match = SNAPSHOT_RE.match(snapshot)
    return match.group("mirror") if match else None


def is_source_snapshot(snapshot: str) -> bool:
    """True for the intermediate full snapshot a published one is made from."""
    match = SNAPSHOT_RE.match(snapshot)
    return bool(match and match.group("source"))


class AptlyError(RuntimeError):
    """aptly exited with an error; the message ends with its output."""

    def __init__(self, args: list[str], returncode: int, output: str) -> None:
        self.output = output.strip()
        tail = self.output[-400:]
        super().__init__(f"aptly {' '.join(args[:2])} failed ({returncode}): {tail}")


@dataclass(frozen=True, slots=True)
class AptlySettings:
    """Where aptly keeps its data and how it signs."""

    root_dir: str
    signing: Signing


@dataclass(frozen=True, slots=True)
class Publication:
    """What aptly really publishes at (prefix, distribution)."""

    snapshot: str
    component: str
    architectures: tuple[str, ...]
    acquire_by_hash: bool


class Aptly:
    """The aptly operations repo-sync needs."""

    def __init__(self, settings: AptlySettings, config_path: str) -> None:
        self.settings = settings
        self.config_path = config_path
        self._write_config()

    def _write_config(self) -> None:
        conf = {
            "rootDir": self.settings.root_dir,
            "downloadConcurrency": 4,
            "downloadRetries": 3,
            "architectures": [],
            "dependencyFollowSuggests": False,
            "dependencyFollowRecommends": False,
            "dependencyFollowAllVariants": False,
            "dependencyFollowSource": False,
            "gpgDisableSign": False,
            "gpgDisableVerify": False,
            "gpgProvider": "gpg2",
            "skipContentsPublishing": True,
            "skipBz2Publishing": True,
            "FileSystemPublishEndpoints": {},
        }
        Path(self.config_path).write_text(json.dumps(conf, indent=2) + "\n", encoding="utf-8")

    def run(self, *args: str, timeout: int = DEFAULT_TIMEOUT) -> str:
        """Run one aptly command; its stdout and stderr together, AptlyError on failure."""
        cmd = [APTLY, f"-config={self.config_path}", *args]
        log.debug("run: %s", " ".join(cmd))
        proc = run_program(cmd, timeout=timeout, env={**os.environ, "LC_ALL": "C.UTF-8"})
        output = (proc.stdout + proc.stderr).decode("utf-8", errors="replace")
        if proc.returncode != 0:
            raise AptlyError(list(args), proc.returncode, output)
        return output

    def _json(self, *args: str) -> Any:
        out = self.run(*args)
        starts = [i for i in (out.find("["), out.find("{")) if i >= 0]
        if not starts:
            raise AptlyError(list(args), 0, f"no JSON in output: {out[:200]}")
        return json.loads(out[min(starts) :])

    # --- mirrors -----------------------------------------------------------

    def _names(self, *args: str) -> list[str]:
        return [line.strip() for line in self.run(*args).splitlines() if line.strip()]

    def mirrors(self) -> set[str]:
        """Names of all aptly mirrors."""
        return set(self._names("mirror", "list", "-raw"))

    def mirror_create(self, mirror: Mirror, keyring: str) -> None:
        """Create the aptly mirror; its upstream is verified with ``keyring`` only."""
        up = mirror.upstream
        args = [
            "mirror",
            "create",
            f"-architectures={','.join(up.architectures)}",
            f"-keyring={keyring}",
        ]
        if up.filter:
            args.append(f"-filter={up.filter}")
            if up.filter_with_deps:
                args.append("-filter-with-deps")
        self.run(*args, mirror.name, up.url, up.distribution, up.component)

    def mirror_drop(self, name: str) -> None:
        """Delete the aptly mirror (its snapshots stay)."""
        self.run("mirror", "drop", "-force", name)

    def mirror_update(self, name: str, keyring: str) -> None:
        """Download from upstream, verifying the signature with ``keyring``."""
        self.run(
            "mirror",
            "update",
            f"-keyring={keyring}",
            "-max-tries=3",
            name,
            timeout=UPDATE_TIMEOUT,
        )

    # --- snapshots ---------------------------------------------------------

    def snapshots(self) -> list[str]:
        """Names of all snapshots."""
        return self._names("snapshot", "list", "-raw")

    def snapshot_create(self, name: str, mirror: str) -> None:
        """Snapshot the current content of a mirror."""
        self.run("snapshot", "create", name, "from", "mirror", mirror)

    def snapshot_latest(self, name: str, source: str) -> None:
        """New snapshot with only the newest version of each package in ``source``."""
        self.run("snapshot", "merge", "-latest", name, source)

    def snapshot_drop(self, name: str) -> None:
        """Delete a snapshot (aptly refuses a published one)."""
        self.run("snapshot", "drop", name)

    def snapshots_identical(self, a: str, b: str) -> bool:
        """True when both snapshots contain the same packages."""
        return "Snapshots are identical." in self.run("snapshot", "diff", a, b)

    def snapshot_packages(self, name: str) -> int:
        """Number of packages in a snapshot."""
        match = re.search(r"Number of packages:\s*(\d+)", self.run("snapshot", "show", name))
        return int(match.group(1)) if match else 0

    # --- publishing --------------------------------------------------------

    def publications(self) -> dict[tuple[str, str], Publication]:
        """Single-component snapshot publications by (prefix, distribution)."""
        result: dict[tuple[str, str], Publication] = {}
        for item in self._json("publish", "list", "-json"):
            sources = item.get("Sources") or []
            if item.get("SourceKind") != "snapshot" or len(sources) != 1:
                log.warning("ignoring publication %s not made by repo-sync", item.get("Path"))
                continue
            result[(item["Prefix"], item["Distribution"])] = Publication(
                snapshot=sources[0]["Name"],
                component=sources[0]["Component"],
                architectures=tuple(item.get("Architectures") or ()),
                acquire_by_hash=bool(item.get("AcquireByHash")),
            )
        return result

    def _sign_args(self) -> list[str]:
        return ["-batch", f"-gpg-key={self.settings.signing.gpg_key}"]

    def publish_snapshot(self, snapshot: str, mirror: Mirror) -> None:
        """Publish a snapshot at the mirror's prefix and distribution, signed."""
        # Acquire-By-Hash: a client fetching indexes during a switch never
        # mixes a new InRelease with old Packages ("Hash Sum mismatch").
        up = mirror.upstream
        self.run(
            "publish",
            "snapshot",
            *self._sign_args(),
            "-acquire-by-hash",
            f"-distribution={up.distribution}",
            f"-component={up.component}",
            f"-architectures={','.join(up.architectures)}",
            f"-origin={self.settings.signing.origin}",
            f"-label={self.settings.signing.label}",
            snapshot,
            mirror.prefix,
        )

    def publish_switch(self, snapshot: str, prefix: str, distribution: str) -> None:
        """Point an existing publication to another snapshot (same layout)."""
        self.run("publish", "switch", *self._sign_args(), distribution, prefix, snapshot)

    def publish_drop(self, prefix: str, distribution: str) -> None:
        """Remove a publication."""
        self.run("publish", "drop", distribution, prefix)

    def db_cleanup(self) -> None:
        """Remove package files no snapshot or mirror references any more."""
        self.run("db", "cleanup")
