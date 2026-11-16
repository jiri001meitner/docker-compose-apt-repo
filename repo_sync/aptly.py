"""Thin wrapper around the aptly CLI (argument lists only, never a shell)."""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .config import Mirror

log = logging.getLogger(__name__)

SNAPSHOT_RE = re.compile(r"^(?P<mirror>[a-z0-9][a-z0-9-]*)-(?P<ts>\d{8}T\d{6}Z)$")


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


class Aptly:
    def __init__(self, settings: AptlySettings, config_path: str, timeout: int = 3600) -> None:
        self.settings = settings
        self.config_path = config_path
        self.timeout = timeout
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

    def run(self, *args: str, check: bool = True) -> str:
        cmd = ["aptly", f"-config={self.config_path}", *args]
        log.debug("run: %s", " ".join(cmd))
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
            env={**os.environ, "LC_ALL": "C.UTF-8"},
        )
        output = proc.stdout + proc.stderr
        if check and proc.returncode != 0:
            raise AptlyError(list(args), proc.returncode, output)
        return output

    # --- mirrors -----------------------------------------------------------

    def mirrors(self) -> set[str]:
        return {line.strip() for line in self.run("mirror", "list", "-raw").splitlines() if line.strip()}

    def mirror_create(self, mirror: Mirror, keyring: str) -> None:
        args = ["mirror", "create", f"-architectures={','.join(mirror.architectures)}", f"-keyring={keyring}"]
        if mirror.filter:
            args.append(f"-filter={mirror.filter}")
            if mirror.filter_with_deps:
                args.append("-filter-with-deps")
        self.run(*args, mirror.name, mirror.url, mirror.distribution, *mirror.components)

    def mirror_drop(self, name: str) -> None:
        self.run("mirror", "drop", "-force", name)

    def mirror_update(self, name: str, keyring: str) -> None:
        self.run("mirror", "update", f"-keyring={keyring}", "-max-tries=3", name)

    # --- snapshots ---------------------------------------------------------

    def snapshots(self) -> list[str]:
        return [
            line.strip() for line in self.run("snapshot", "list", "-raw", "-sort=time").splitlines() if line.strip()
        ]

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

    def published(self) -> set[tuple[str, str]]:
        """(prefix, distribution) pairs currently published."""
        result: set[tuple[str, str]] = set()
        for line in self.run("publish", "list", "-raw").splitlines():
            parts = line.split()
            if len(parts) == 2:
                result.add((parts[0], parts[1]))
        return result

    def _sign_args(self) -> list[str]:
        return ["-batch", f"-gpg-key={self.settings.gpg_key}"]

    def publish_snapshot(self, snapshot: str, prefix: str, distribution: str, architectures: tuple[str, ...]) -> None:
        self.run(
            "publish",
            "snapshot",
            *self._sign_args(),
            f"-distribution={distribution}",
            f"-architectures={','.join(architectures)}",
            f"-origin={self.settings.origin}",
            f"-label={self.settings.label}",
            snapshot,
            prefix,
        )

    def publish_switch(self, snapshot: str, prefix: str, distribution: str) -> None:
        self.run("publish", "switch", *self._sign_args(), distribution, prefix, snapshot)

    def publish_drop(self, prefix: str, distribution: str) -> None:
        self.run("publish", "drop", distribution, prefix)

    def db_cleanup(self) -> None:
        self.run("db", "cleanup")
