"""The Icinga report, status.json and index.html."""

from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime, timedelta

from repo_common.timeutil import format_utc
from repo_sync.catalog import CRITICAL, OK, WARNING, render_index, render_status, report
from repo_sync.config import parse_config
from repo_sync.sync import MirrorState, State

from .fake_aptly import config_json

NOW = datetime(2026, 11, 20, 0, 0, tzinfo=UTC)


def hours_ago(hours: int) -> str:
    """A state timestamp ``hours`` before NOW."""
    return format_utc(NOW - timedelta(hours=hours))


class CatalogTest(unittest.TestCase):
    """Freshness levels and rendering."""

    def setUp(self) -> None:
        """The sample configuration."""
        self.config = parse_config(json.dumps(config_json()))

    def test_report_levels(self) -> None:
        """OK when fresh, WARNING when stale or never synced, CRITICAL when long stale."""
        state = State()
        self.assertEqual(report(self.config, state, NOW)[0], WARNING)  # never attempted
        fresh = hours_ago(1)
        state.mirrors["caddy"] = MirrorState(first_attempt=fresh, last_success=fresh, packages=5)
        state.mirrors["ppa-moz"] = MirrorState(first_attempt=fresh, last_success=fresh)
        self.assertEqual(report(self.config, state, NOW)[0], OK)
        state.mirrors["ppa-moz"].last_success = hours_ago(50)
        state.mirrors["ppa-moz"].last_error = "boom"
        level, output, perf = report(self.config, state, NOW)
        self.assertEqual(level, WARNING)
        self.assertIn("ppa-moz (50 h)", output)
        self.assertIn("last attempt failed: ppa-moz", output)
        self.assertIn("'caddy_packages'=5", perf)
        state.mirrors["ppa-moz"].last_success = None
        state.mirrors["ppa-moz"].first_attempt = hours_ago(200)
        self.assertEqual(report(self.config, state, NOW)[0], CRITICAL)
        state.mirrors["ppa-moz"].first_attempt = fresh
        self.assertEqual(report(self.config, state, NOW)[0], WARNING)  # never synced, just added

    def test_html_escapes_and_status(self) -> None:
        """Configured texts are escaped; status.json lists the paths."""
        page = render_index(self.config, State(), NOW, "AAAA").decode()
        self.assertIn("Repo &lt;test&gt;", page)
        self.assertNotIn("<test>", page)
        self.assertNotIn("<script", page)
        self.assertNotIn("$", page)  # every template placeholder was filled
        status = json.loads(render_status(self.config, State(), NOW))
        self.assertEqual([m["path"] for m in status["mirrors"]], ["/caddy/", "/ppa/mozillateam/"])

    def test_html_client_setup(self) -> None:
        """The setup instructions name the host and a source for the first mirror."""
        page = render_index(self.config, State(), NOW, "AAAA BBBB").decode()
        self.assertIn("machine repo.test\\nlogin LOGIN", page)
        self.assertIn("URIs: https://repo.test/caddy/", page)
        self.assertIn("<code>AAAA BBBB</code>", page)
        self.assertIn('lang="en"', page)


if __name__ == "__main__":
    unittest.main()
