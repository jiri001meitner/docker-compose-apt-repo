"""Orchestration tests with an in-memory aptly (no network, no aptly binary)."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock

from repo_sync import sync as sync_mod
from repo_sync.aptly import AptlyError
from repo_sync.catalog import CRITICAL, OK, WARNING, render_index, render_status, report
from repo_sync.config import ConfigError, parse_config
from repo_sync.sync import State, Syncer

FPR = "A" * 40


def config_json(**over: Any) -> dict[str, Any]:
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
                "components": ["main"],
                "architectures": ["amd64"],
                "key_file": "/keys/caddy.asc",
                "prefix": "caddy",
            },
            {
                "name": "ppa-moz",
                "title": "Mozilla",
                "url": "https://up.test/moz",
                "distribution": "resolute",
                "components": ["main"],
                "architectures": ["amd64"],
                "key_file": "/keys/moz.asc",
                "prefix": "ppa/mozillateam",
            },
        ],
    }
    base.update(over)
    return base


class FakeAptly:
    """Models mirrors (with an upstream 'version'), snapshots and publishes."""

    def __init__(self) -> None:
        self.upstream: dict[str, int] = {"caddy": 1, "ppa-moz": 1}
        self.fail: set[str] = set()
        self.mirror_content: dict[str, int] = {}
        self.snaps: dict[str, int] = {}
        self.order: list[str] = []
        self.pub: dict[tuple[str, str], str] = {}
        self.calls: list[tuple[Any, ...]] = []

    def mirrors(self) -> set[str]:
        return set(self.mirror_content)

    def mirror_create(self, mirror: Any, keyring: str) -> None:
        self.calls.append(("create", mirror.name))
        self.mirror_content[mirror.name] = 0

    def mirror_drop(self, name: str) -> None:
        self.calls.append(("mirror_drop", name))
        del self.mirror_content[name]

    def mirror_update(self, name: str, keyring: str) -> None:
        if name in self.fail:
            raise AptlyError(["mirror", "update"], 1, "ERROR: unable to fetch: 504 Gateway Timeout")
        self.mirror_content[name] = self.upstream[name]

    def snapshots(self) -> list[str]:
        return list(self.order)

    def snapshot_create(self, name: str, mirror: str) -> None:
        assert name not in self.snaps
        self.snaps[name] = self.mirror_content[mirror]
        self.order.append(name)

    def snapshot_drop(self, name: str) -> None:
        assert name not in self.pub.values(), f"dropping published snapshot {name}"
        self.calls.append(("snap_drop", name))
        del self.snaps[name]
        self.order.remove(name)

    def snapshots_identical(self, a: str, b: str) -> bool:
        return self.snaps[a] == self.snaps[b]

    def snapshot_packages(self, name: str) -> int:
        return 10 + self.snaps[name]

    def published(self) -> set[tuple[str, str]]:
        return set(self.pub)

    def publish_snapshot(self, snap: str, prefix: str, dist: str, archs: Any) -> None:
        self.calls.append(("publish", prefix, snap))
        self.pub[(prefix, dist)] = snap

    def publish_switch(self, snap: str, prefix: str, dist: str) -> None:
        self.calls.append(("switch", prefix, snap))
        self.pub[(prefix, dist)] = snap

    def publish_drop(self, prefix: str, dist: str) -> None:
        self.calls.append(("pub_drop", prefix))
        del self.pub[(prefix, dist)]

    def db_cleanup(self) -> None:
        pass


class SyncTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.aptly = FakeAptly()
        self.clock = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
        patcher_now = mock.patch.object(sync_mod, "utcnow", side_effect=lambda: self.clock)
        patcher_key = mock.patch.object(sync_mod, "dearmor", side_effect=lambda f, d: f + ".gpg")
        patcher_now.start()
        patcher_key.start()
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(self.tmp.cleanup)

    def run_sync(self, cfg: dict[str, Any] | None = None) -> State:
        self.clock += timedelta(hours=6)
        config = parse_config(json.dumps(cfg or config_json()))
        return Syncer(config, self.aptly, self.root, self.root).run()  # type: ignore[arg-type]

    def test_first_run_publishes_all(self) -> None:
        state = self.run_sync()
        self.assertEqual(set(self.aptly.pub), {("caddy", "any-version"), ("ppa/mozillateam", "resolute")})
        self.assertEqual(state.mirrors["caddy"].packages, 11)
        self.assertIsNone(state.mirrors["caddy"].last_error)

    def test_unchanged_upstream_keeps_snapshot(self) -> None:
        self.run_sync()
        before = dict(self.aptly.pub)
        self.run_sync()
        self.assertEqual(self.aptly.pub, before)
        self.assertEqual(len(self.aptly.snaps), 2)

    def test_changed_upstream_switches_and_trims(self) -> None:
        self.run_sync()
        for version in (2, 3, 4):
            self.aptly.upstream["caddy"] = version
            self.run_sync()
        caddy_snaps = [s for s in self.aptly.order if s.startswith("caddy-")]
        self.assertEqual(len(caddy_snaps), 2)  # keep_snapshots = 2
        self.assertEqual(self.aptly.pub[("caddy", "any-version")], caddy_snaps[-1])
        self.assertEqual(self.aptly.snaps[caddy_snaps[-1]], 4)

    def test_failure_is_isolated_and_keeps_publish(self) -> None:
        self.run_sync()
        published = self.aptly.pub[("ppa/mozillateam", "resolute")]
        self.aptly.fail.add("ppa-moz")
        self.aptly.upstream["caddy"] = 2
        state = self.run_sync()
        self.assertEqual(self.aptly.pub[("ppa/mozillateam", "resolute")], published)
        self.assertIn("504", state.mirrors["ppa-moz"].last_error or "")
        self.assertIsNone(state.mirrors["caddy"].last_error)
        self.assertNotEqual(state.mirrors["ppa-moz"].last_attempt, state.mirrors["ppa-moz"].last_success)

    def test_never_succeeded_mirror_not_published(self) -> None:
        self.aptly.fail.add("ppa-moz")
        state = self.run_sync()
        self.assertNotIn(("ppa/mozillateam", "resolute"), self.aptly.pub)
        self.assertIsNone(state.mirrors["ppa-moz"].last_success)

    def test_definition_change_recreates_mirror(self) -> None:
        self.run_sync()
        cfg = config_json()
        cfg["mirrors"][0]["url"] = "https://up.test/caddy2"
        self.run_sync(cfg)
        self.assertIn(("mirror_drop", "caddy"), self.aptly.calls)
        self.assertEqual(self.aptly.calls.count(("create", "caddy")), 2)

    def test_prefix_change_moves_publish(self) -> None:
        self.run_sync()
        cfg = config_json()
        cfg["mirrors"][0]["prefix"] = "tools/caddy"
        self.run_sync(cfg)
        self.assertIn(("tools/caddy", "any-version"), self.aptly.pub)
        self.assertNotIn(("caddy", "any-version"), self.aptly.pub)

    def test_removed_mirror_is_pruned(self) -> None:
        self.run_sync()
        cfg = config_json()
        cfg["mirrors"] = cfg["mirrors"][:1]
        state = self.run_sync(cfg)
        self.assertNotIn("ppa-moz", state.mirrors)
        self.assertNotIn(("ppa/mozillateam", "resolute"), self.aptly.pub)
        self.assertNotIn("ppa-moz", self.aptly.mirrors())
        self.assertFalse(any(s.startswith("ppa-moz-") for s in self.aptly.order))

    def test_state_survives_restart(self) -> None:
        self.run_sync()
        self.assertEqual(State.load(self.root / "repo-sync-state.json").mirrors["caddy"].packages, 11)

    def test_lock(self) -> None:
        with sync_mod.run_lock(self.root), self.assertRaises(sync_mod.LockedError), sync_mod.run_lock(self.root):
            pass


class CatalogTest(unittest.TestCase):
    def test_report_levels(self) -> None:
        config = parse_config(json.dumps(config_json()))
        now = datetime(2026, 11, 20, 0, 0, tzinfo=UTC)
        state = State()
        self.assertEqual(report(config, state, now)[0], WARNING)  # never attempted
        fresh = sync_mod.iso(now - timedelta(hours=1))
        state.mirrors["caddy"] = sync_mod.MirrorState(first_attempt=fresh, last_success=fresh, packages=5)
        state.mirrors["ppa-moz"] = sync_mod.MirrorState(first_attempt=fresh, last_success=fresh)
        self.assertEqual(report(config, state, now)[0], OK)
        state.mirrors["ppa-moz"].last_success = sync_mod.iso(now - timedelta(hours=50))
        state.mirrors["ppa-moz"].last_error = "boom"
        level, output, perf = report(config, state, now)
        self.assertEqual(level, WARNING)
        self.assertIn("ppa-moz (50 h)", output)
        self.assertIn("last attempt failed: ppa-moz", output)
        self.assertIn("'caddy_packages'=5", perf)
        state.mirrors["ppa-moz"].last_success = None
        state.mirrors["ppa-moz"].first_attempt = sync_mod.iso(now - timedelta(hours=200))
        self.assertEqual(report(config, state, now)[0], CRITICAL)
        state.mirrors["ppa-moz"].first_attempt = fresh
        self.assertEqual(report(config, state, now)[0], WARNING)  # never synced, just added

    def test_html_escapes_and_status(self) -> None:
        config = parse_config(json.dumps(config_json()))
        now = datetime(2026, 11, 20, tzinfo=UTC)
        page = render_index(config, State(), now, "AAAA").decode()
        self.assertIn("Repo &lt;test&gt;", page)
        self.assertNotIn("<test>", page)
        self.assertNotIn("<script", page)
        status = json.loads(render_status(config, State(), now))
        self.assertEqual([m["path"] for m in status["mirrors"]], ["/caddy/", "/ppa/mozillateam/"])


class ConfigTest(unittest.TestCase):
    def test_rejects(self) -> None:
        def mutate(fn: Any) -> str:
            c = config_json()
            fn(c)
            return json.dumps(c)

        cases = {
            "unknown key": mutate(lambda c: c.update(x=1)),
            "bad fpr": mutate(lambda c: c.update(gpg_key="abc")),
            "dup name": mutate(lambda c: c["mirrors"].append(dict(c["mirrors"][0], prefix="other"))),
            "dup publish": mutate(lambda c: c["mirrors"].append(dict(c["mirrors"][0], name="caddy2"))),
            "traversal prefix": mutate(lambda c: c["mirrors"][0].update(prefix="../etc")),
            "reserved prefix": mutate(lambda c: c["mirrors"][0].update(prefix="index.html")),
            "relative key": mutate(lambda c: c["mirrors"][0].update(key_file="keys/x.asc")),
            "ftp url": mutate(lambda c: c["mirrors"][0].update(url="ftp://x")),
            "no arch": mutate(lambda c: c["mirrors"][0].update(architectures=[])),
            "crit < warn": mutate(lambda c: c.update(stale_critical_hours=10)),
            "keep 0": mutate(lambda c: c.update(keep_snapshots=0)),
            "base url slash": mutate(lambda c: c.update(base_url="https://repo.test/")),
            "bool as int": mutate(lambda c: c.update(keep_snapshots=True)),
        }
        for name, data in cases.items():
            with self.subTest(name), self.assertRaises(ConfigError):
                parse_config(data)


if __name__ == "__main__":
    unittest.main()
