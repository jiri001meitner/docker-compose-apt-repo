"""An in-memory aptly and a sample configuration for the repo-sync unit tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from repo_sync.aptly import AptlyError, Publication
from repo_sync.config import Mirror

FPR = "A" * 40


def config_json(**over: Any) -> dict[str, Any]:
    """``mirrors.json`` with two mirrors; top-level keys can be overridden."""
    base: dict[str, Any] = {
        "gpg_key": FPR,
        "origin": "repo.test",
        "label": "repo.test",
        "keep_snapshots": 2,
        "stale_warning_hours": 48,
        "stale_critical_hours": 168,
        "site_title": "Repo <test>",
        "base_url": "https://repo.test",
        "mirrors": [
            {
                "name": "caddy",
                "title": "Caddy",
                "url": "https://up.test/caddy",
                "distribution": "any-version",
                "component": "main",
                "architectures": ["amd64"],
                "key_file": "/keys/caddy.asc",
                "prefix": "caddy",
            },
            {
                "name": "ppa-moz",
                "title": "Mozilla",
                "url": "https://up.test/moz",
                "distribution": "resolute",
                "component": "main",
                "architectures": ["amd64"],
                "key_file": "/keys/moz.asc",
                "prefix": "ppa/mozillateam",
            },
        ],
    }
    base.update(over)
    return base


def _check(condition: bool, message: str) -> None:
    """A FakeAptly invariant (what real aptly would refuse) fails the test."""
    if not condition:
        raise AssertionError(message)


@dataclass
class FakeMirror:
    """An aptly mirror: where it points, its keyring and the upstream version it holds."""

    url: str
    keyring: str
    content: int = 0


class FakeAptly:
    """Models mirrors (with an upstream 'version'), snapshots and publications.

    ``upstream`` is the version each upstream currently serves, ``fail`` makes
    ``mirror_update`` raise, ``fail_drop`` makes ``snapshot_drop`` refuse.
    """

    def __init__(self) -> None:
        self.upstream: dict[str, int] = {"caddy": 1, "ppa-moz": 1}
        self.fail: dict[str, BaseException] = {}
        self.fail_drop: set[str] = set()
        self.mirror: dict[str, FakeMirror] = {}
        self.snaps: dict[str, int] = {}  # in creation order
        self.pub: dict[tuple[str, str], Publication] = {}
        self.calls: list[tuple[Any, ...]] = []

    def mirrors(self) -> set[str]:
        """Names of all mirrors."""
        return set(self.mirror)

    def mirror_create(self, mirror: Mirror, keyring: str) -> None:
        """Create an empty mirror."""
        self.calls.append(("create", mirror.name))
        self.mirror[mirror.name] = FakeMirror(mirror.upstream.url, keyring)

    def mirror_drop(self, name: str) -> None:
        """Delete a mirror."""
        self.calls.append(("mirror_drop", name))
        del self.mirror[name]

    def mirror_update(self, name: str, keyring: str) -> None:
        """Fetch the upstream's current version (or raise the configured failure)."""
        _check(keyring == self.mirror[name].keyring, f"{name}: updated with another keyring")
        if name in self.fail:
            raise self.fail[name]
        self.mirror[name].content = self.upstream.get(name, 1)

    def snapshots(self) -> list[str]:
        """Snapshot names, oldest first."""
        return list(self.snaps)

    def snapshot_create(self, name: str, mirror: str) -> None:
        """Snapshot a mirror; a duplicate name fails like in aptly."""
        _check(name not in self.snaps, f"duplicate snapshot {name}")
        self.snaps[name] = self.mirror[mirror].content

    def snapshot_drop(self, name: str) -> None:
        """Delete a snapshot; a published one fails like in aptly."""
        if name in self.fail_drop:
            raise AptlyError(["snapshot", "drop"], 1, "ERROR: snapshot is published")
        published = {p.snapshot for p in self.pub.values()}
        _check(name not in published, f"dropping published snapshot {name}")
        self.calls.append(("snap_drop", name))
        del self.snaps[name]

    def snapshots_identical(self, a: str, b: str) -> bool:
        """True when both snapshots hold the same upstream version."""
        return self.snaps[a] == self.snaps[b]

    def snapshot_packages(self, name: str) -> int:
        """Package count derived from the version."""
        return 10 + self.snaps[name]

    def publications(self) -> dict[tuple[str, str], Publication]:
        """Current publications."""
        return dict(self.pub)

    def publish_snapshot(self, snapshot: str, mirror: Mirror) -> None:
        """Publish at a free target."""
        _check(mirror.target not in self.pub, f"already published at {mirror.target}")
        self.calls.append(("publish", mirror.prefix, snapshot))
        up = mirror.upstream
        self.pub[mirror.target] = Publication(snapshot, up.component, up.architectures, True)

    def publish_switch(self, snapshot: str, prefix: str, distribution: str) -> None:
        """Switch keeping the original layout, like aptly."""
        self.calls.append(("switch", prefix, snapshot))
        old = self.pub[(prefix, distribution)]
        self.pub[(prefix, distribution)] = Publication(
            snapshot, old.component, old.architectures, old.acquire_by_hash
        )

    def publish_drop(self, prefix: str, distribution: str) -> None:
        """Remove a publication."""
        self.calls.append(("pub_drop", prefix))
        del self.pub[(prefix, distribution)]

    def db_cleanup(self) -> None:
        """Nothing to clean in memory."""
