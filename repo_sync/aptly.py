"""Thin wrapper around the aptly CLI (argument lists only, never a shell)."""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Mirror

log = logging.getLogger(__name__)

# <mirror>-<UTC timestamp>[-<n>]; the suffix only when two runs fall into the
# same second. The mirror name may contain dashes, the timestamp anchors it.
SNAPSHOT_RE = re.compile(r"^(?P<mirror>[a-z0-9][a-z0-9-]*?)-(?P<ts>\d{8}T\d{6}Z)(?:-\d+)?$")

DEFAULT_TIMEOUT = 3600
# The first download of a large PPA on a slow line may take hours; aptly
# itself gives up on a silent server after about a minute.
UPDATE_TIMEOUT = 6 * 3600


def snapshot_owner(snapshot: str) -> str | None:
    match = SNAPSHOT_RE.match(snapshot)
    return match.group("mirror") if match else None


class AptlyError(RuntimeError):
    def __init__(self, args: list[str], returncode: int, output: str) -> None:
        self.output = output.strip()
        tail = self.output[-400:]
        super().__init__(f"aptly {' '.join(args[:2])} failed ({returncode}): {tail}")


@dataclass(frozen=True, slots=True)
class AptlySettings:
    root_dir: str
    gpg_key: str
    origin: str
    label: str


@dataclass(frozen=True, slots=True)
class Publication:
    """What aptly really publishes at (prefix, distribution)."""

    snapshot: str
    component: str
    architectures: tuple[str, ...]
    acquire_by_hash: bool


class Aptly:
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
        cmd = ["aptly", f"-config={self.config_path}", *args]
        log.debug("run: %s", " ".join(cmd))
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={**os.environ, "LC_ALL": "C.UTF-8"},
        )
        output = proc.stdout + proc.stderr
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

    def mirrors(self) -> set[str]:
        return {line.strip() for line in self.run("mirror", "list", "-raw").splitlines() if line.strip()}

    def mirror_create(self, mirror: Mirror, keyring: str) -> None:
        args = ["mirror", "create", f"-architectures={','.join(mirror.architectures)}", f"-keyring={keyring}"]
        if mirror.filter:
            args.append(f"-filter={mirror.filter}")
            if mirror.filter_with_deps:
                args.append("-filter-with-deps")
        self.run(*args, mirror.name, mirror.url, mirror.distribution, mirror.component)

    def mirror_drop(self, name: str) -> None:
        self.run("mirror", "drop", "-force", name)

    def mirror_update(self, name: str, keyring: str) -> None:
        self.run("mirror", "update", f"-keyring={keyring}", "-max-tries=3", name, timeout=UPDATE_TIMEOUT)

    # --- snapshots ---------------------------------------------------------

    def snapshots(self) -> list[str]:
        return [line.strip() for line in self.run("snapshot", "list", "-raw").splitlines() if line.strip()]

    def snapshot_create(self, name: str, mirror: str) -> None:
        self.run("snapshot", "create", name, "from", "mirror", mirror)

    def snapshot_drop(self, name: str) -> None:
        self.run("snapshot", "drop", name)

    def snapshots_identical(self, a: str, b: str) -> bool:
        return "Snapshots are identical." in self.run("snapshot", "diff", a, b)

    def snapshot_packages(self, name: str) -> int:
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
        return ["-batch", f"-gpg-key={self.settings.gpg_key}"]

    def publish_snapshot(self, snapshot: str, mirror: Mirror) -> None:
        # Acquire-By-Hash: a client fetching indexes during a switch never
        # mixes a new InRelease with old Packages ("Hash Sum mismatch").
        self.run(
            "publish",
            "snapshot",
            *self._sign_args(),
            "-acquire-by-hash",
            f"-distribution={mirror.distribution}",
            f"-component={mirror.component}",
            f"-architectures={','.join(mirror.architectures)}",
            f"-origin={self.settings.origin}",
            f"-label={self.settings.label}",
            snapshot,
            mirror.prefix,
        )

    def publish_switch(self, snapshot: str, prefix: str, distribution: str) -> None:
        self.run("publish", "switch", *self._sign_args(), distribution, prefix, snapshot)

    def publish_drop(self, prefix: str, distribution: str) -> None:
        self.run("publish", "drop", distribution, prefix)

    def db_cleanup(self) -> None:
        self.run("db", "cleanup")
