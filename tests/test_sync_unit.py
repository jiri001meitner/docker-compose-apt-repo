"""Orchestration tests with an in-memory aptly (no network, no aptly binary)."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock

from repo_sync import gpg
from repo_sync import sync as sync_mod
from repo_sync.aptly import AptlyError, Publication, is_source_snapshot, snapshot_owner
from repo_sync.config import parse_config
from repo_sync.sync import STATE_FILE, State, Syncer

from .fake_aptly import FakeAptly, config_json
from .tempdirs import temp_dir

CADDY = ("caddy", "any-version")
MOZ = ("ppa/mozillateam", "resolute")


class SyncCase(unittest.TestCase):
    """A fake aptly, a controllable clock and a state directory."""

    def setUp(self) -> None:
        """Fresh fake aptly; the clock moves only when a test advances it."""
        self.root = Path(temp_dir(self))
        self.aptly = FakeAptly()
        self.clock = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
        self.enterContext(mock.patch.object(sync_mod, "utcnow", side_effect=lambda: self.clock))
        self.enterContext(
            mock.patch.object(sync_mod, "dearmor", side_effect=lambda f, d: f + ".gpg")
        )

    def run_sync(self, cfg: dict[str, Any] | None = None, advance: bool = True) -> State:
        """One run, by default 6 hours after the previous one."""
        if advance:
            self.clock += timedelta(hours=6)
        config = parse_config(json.dumps(cfg or config_json()))
        return Syncer(config, self.aptly, self.root, self.root).run()

    def published(self, target: tuple[str, str]) -> str:
        """The snapshot published at (prefix, distribution)."""
        return self.aptly.pub[target].snapshot

    def snapshots_of(self, mirror: str) -> list[str]:
        """Published-type snapshots of one mirror (no -src sources), oldest first."""
        return [
            s for s in self.aptly.snaps if s.startswith(f"{mirror}-") and not s.endswith("-src")
        ]

    def assert_sources_paired(self) -> None:
        """Every snapshot has its source and no source is left without one."""
        names = set(self.aptly.snaps)
        merged = {s for s in names if not s.endswith("-src")}
        self.assertEqual({s + "-src" for s in merged}, names - merged)


class PublishTest(SyncCase):
    """Publishing and keeping snapshots."""

    def test_first_run_publishes_all(self) -> None:
        """The first run publishes every mirror."""
        state = self.run_sync()
        self.assertEqual(set(self.aptly.pub), {CADDY, MOZ})
        self.assertEqual(state.mirrors["caddy"].packages, 11)
        self.assertIsNone(state.mirrors["caddy"].last_error)

    def test_unchanged_upstream_keeps_snapshot(self) -> None:
        """An identical new snapshot is dropped and the publication left alone."""
        self.run_sync()
        before = dict(self.aptly.pub)
        self.run_sync()
        self.assertEqual(self.aptly.pub, before)
        self.assertEqual(len(self.snapshots_of("caddy")) + len(self.snapshots_of("ppa-moz")), 2)
        self.assert_sources_paired()

    def test_changed_upstream_switches_and_trims(self) -> None:
        """A change is switched in; only keep_snapshots snapshots remain."""
        self.run_sync()
        for version in (2, 3, 4):
            self.aptly.upstream["caddy"] = version
            self.run_sync()
        caddy_snaps = self.snapshots_of("caddy")
        self.assertEqual(len(caddy_snaps), 2)  # keep_snapshots = 2
        self.assertEqual(self.published(CADDY), caddy_snaps[-1])
        self.assertEqual(self.aptly.snaps[caddy_snaps[-1]], 4)
        self.assert_sources_paired()

    def test_published_snapshot_has_latest_versions_only(self) -> None:
        """Each run publishes a -latest merge of a full source snapshot kept beside it."""
        self.run_sync()
        latest = [c for c in self.aptly.calls if c[0] == "latest"]
        self.assertEqual(len(latest), 2)
        self.assertEqual({c[2] for c in latest}, {c[1] + "-src" for c in latest})
        self.assertEqual(
            self.published(CADDY), next(c[1] for c in latest if c[1].startswith("caddy-"))
        )
        for merged in (c[1] for c in latest):
            self.assertIn(merged + "-src", self.aptly.snaps)

    def test_leftover_source_snapshot_is_dropped(self) -> None:
        """A source snapshot without its merged one (interrupted run) is removed."""
        self.run_sync()
        self.aptly.mirror["caddy"].content = 1
        self.aptly.snaps["caddy-20260101T000000Z-src"] = 1
        self.run_sync()
        self.assertNotIn("caddy-20260101T000000Z-src", self.aptly.snaps)
        self.assert_sources_paired()

    def test_two_runs_in_one_second(self) -> None:
        """Snapshot names stay unique within one second."""
        self.run_sync()
        self.aptly.upstream["caddy"] = 2
        self.run_sync(advance=False)
        self.aptly.upstream["caddy"] = 3
        state = self.run_sync(advance=False)
        self.assertIsNone(state.mirrors["caddy"].last_error)
        self.assertTrue(self.published(CADDY).endswith("-2"))


class FailureTest(SyncCase):
    """A failing upstream or cleanup step affects nothing else."""

    def test_failure_is_isolated_and_keeps_publish(self) -> None:
        """A failing mirror keeps its publication; the others are updated."""
        self.run_sync()
        published = self.published(MOZ)
        self.aptly.fail["ppa-moz"] = AptlyError(["mirror", "update"], 1, "ERROR: 504 Gateway")
        self.aptly.upstream["caddy"] = 2
        state = self.run_sync()
        self.assertEqual(self.published(MOZ), published)
        self.assertIn("504", state.mirrors["ppa-moz"].last_error or "")
        self.assertIsNone(state.mirrors["caddy"].last_error)

    def test_timeout_is_isolated(self) -> None:
        """A hanging upstream is recorded as an error; the run completes."""
        self.aptly.fail["caddy"] = subprocess.TimeoutExpired(["aptly"], 21600)
        state = self.run_sync()
        self.assertIn("timed out", state.mirrors["caddy"].last_error or "")
        self.assertIn(MOZ, self.aptly.pub)
        self.assertIsNotNone(state.last_run)

    def test_never_succeeded_mirror_not_published(self) -> None:
        """A mirror that never synced publishes nothing."""
        self.aptly.fail["ppa-moz"] = AptlyError(["mirror", "create"], 1, "connection refused")
        state = self.run_sync()
        self.assertNotIn(MOZ, self.aptly.pub)
        self.assertIsNone(state.mirrors["ppa-moz"].last_success)

    def test_prune_error_does_not_block_sync(self) -> None:
        """A cleanup failure does not stop the configured mirrors."""
        self.run_sync()
        cfg = config_json()
        cfg["mirrors"] = cfg["mirrors"][:1]
        self.aptly.fail_drop.add(self.published(MOZ))
        self.aptly.upstream["caddy"] = 2
        state = self.run_sync(cfg)
        self.assertIsNone(state.mirrors["caddy"].last_error)
        self.assertEqual(self.aptly.snaps[self.published(CADDY)], 2)


class ChangeTest(SyncCase):
    """Changes of the configuration."""

    def test_definition_change_recreates_mirror(self) -> None:
        """A new upstream URL recreates the aptly mirror."""
        self.run_sync()
        cfg = config_json()
        cfg["mirrors"][0]["url"] = "https://up.test/caddy2"
        self.run_sync(cfg)
        self.assertIn(("mirror_drop", "caddy"), self.aptly.calls)
        self.assertEqual(self.aptly.mirror["caddy"].url, "https://up.test/caddy2")

    def test_architecture_change_republishes(self) -> None:
        """publish switch keeps architectures, so a change publishes again."""
        self.run_sync()
        cfg = config_json()
        cfg["mirrors"][0]["architectures"] = ["amd64", "arm64"]
        self.run_sync(cfg)
        self.assertEqual(set(self.aptly.pub[CADDY].architectures), {"amd64", "arm64"})
        self.assertIn(("pub_drop", "caddy"), self.aptly.calls)

    def test_publication_without_acquire_by_hash_is_redone(self) -> None:
        """An old publication without Acquire-By-Hash is made again."""
        self.run_sync()
        old = self.aptly.pub[CADDY]
        self.aptly.pub[CADDY] = Publication(old.snapshot, old.component, old.architectures, False)
        self.aptly.upstream["caddy"] = 2
        self.run_sync()
        self.assertTrue(self.aptly.pub[CADDY].acquire_by_hash)

    def test_prefix_change_moves_publish(self) -> None:
        """A new prefix publishes there and drops the old place."""
        self.run_sync()
        cfg = config_json()
        cfg["mirrors"][0]["prefix"] = "tools/caddy"
        self.run_sync(cfg)
        self.assertIn(("tools/caddy", "any-version"), self.aptly.pub)
        self.assertNotIn(CADDY, self.aptly.pub)

    def test_removed_mirror_is_pruned(self) -> None:
        """A mirror removed from the config is dropped completely."""
        self.run_sync()
        cfg = config_json()
        cfg["mirrors"] = cfg["mirrors"][:1]
        state = self.run_sync(cfg)
        self.assertNotIn("ppa-moz", state.mirrors)
        self.assertNotIn(MOZ, self.aptly.pub)
        self.assertNotIn("ppa-moz", self.aptly.mirrors())
        self.assertFalse([s for s in self.aptly.snaps if s.startswith("ppa-moz-")])

    def test_rename_with_dead_upstream_keeps_prefix_served(self) -> None:
        """A renamed mirror whose upstream is down keeps the old content served."""
        self.run_sync()
        old = self.published(MOZ)
        cfg = config_json()
        cfg["mirrors"][1]["name"] = "mozilla"
        self.aptly.fail["mozilla"] = AptlyError(["mirror", "update"], 1, "Launchpad down")
        self.run_sync(cfg)
        self.assertEqual(self.published(MOZ), old)
        del self.aptly.fail["mozilla"]
        self.run_sync(cfg)
        self.assertTrue(self.published(MOZ).startswith("mozilla-"))
        self.assertFalse([s for s in self.aptly.snaps if s.startswith("ppa-moz-")])
        self.assertNotIn("ppa-moz", self.aptly.mirrors())


class StateTest(SyncCase):
    """The state file and the run lock."""

    def test_state_file_lost_heals(self) -> None:
        """Decisions come from aptly, so a lost state file does no harm."""
        self.run_sync()
        (self.root / STATE_FILE).unlink()
        self.aptly.upstream["caddy"] = 2
        state = self.run_sync()
        self.assertIsNone(state.mirrors["caddy"].last_error)
        self.assertEqual(self.aptly.snaps[self.published(CADDY)], 2)

    def test_corrupt_state_is_reported(self) -> None:
        """A corrupt state file raises instead of being silently replaced."""
        (self.root / STATE_FILE).write_text("{broken", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            State.load(self.root / STATE_FILE)

    def test_state_survives_restart(self) -> None:
        """The state is saved and loads back."""
        self.run_sync()
        self.assertEqual(State.load(self.root / STATE_FILE).mirrors["caddy"].packages, 11)

    def test_lock(self) -> None:
        """A second run while one holds the lock fails at once."""
        with (
            sync_mod.run_lock(self.root),
            self.assertRaises(sync_mod.LockedError),
            sync_mod.run_lock(self.root),
        ):
            pass


class SnapshotNameTest(unittest.TestCase):
    """Snapshot names tie snapshots to their mirror."""

    def test_owner_and_source(self) -> None:
        """Owner is parsed from published and source snapshots; foreign names have none."""
        self.assertEqual(snapshot_owner("ppa-moz-20261116T120000Z"), "ppa-moz")
        self.assertEqual(snapshot_owner("ppa-moz-20261116T120000Z-2-src"), "ppa-moz")
        self.assertTrue(is_source_snapshot("caddy-20261116T120000Z-src"))
        self.assertFalse(is_source_snapshot("caddy-20261116T120000Z-2"))
        self.assertIsNone(snapshot_owner("manual-snapshot"))


class DearmorTest(unittest.TestCase):
    """Upstream key files."""

    def test_binary_key_rejected(self) -> None:
        """A binary key file is refused (gpg --dearmor would write garbage)."""
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / "k.gpg"
            key.write_bytes(b"\x99\x01\x0d binary keyring")
            with self.assertRaises(ValueError):
                gpg.dearmor(str(key), Path(d))


if __name__ == "__main__":
    unittest.main()
