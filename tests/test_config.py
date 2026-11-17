"""Validation of mirrors.json."""

from __future__ import annotations

import json
import unittest
from collections.abc import Callable
from typing import Any

from repo_sync.config import ConfigError, parse_config

from .fake_aptly import config_json


def mutate(fn: Callable[[dict[str, Any]], object]) -> str:
    """The sample configuration changed by ``fn``, as JSON."""
    c = config_json()
    fn(c)
    return json.dumps(c)


def first(**changes: Any) -> str:
    """The sample configuration with the first mirror changed."""
    return mutate(lambda c: c["mirrors"][0].update(changes))


class ConfigTest(unittest.TestCase):
    """Every defect rejects the configuration."""

    def test_sample_is_valid(self) -> None:
        """The sample parses, with the upstream part grouped."""
        config = parse_config(json.dumps(config_json()))
        self.assertEqual(config.mirrors[0].target, ("caddy", "any-version"))
        self.assertEqual(config.mirrors[1].upstream.component, "main")
        self.assertEqual(config.signing.gpg_key, "A" * 40)

    def test_identity_follows_upstream(self) -> None:
        """Only upstream fields change the mirror identity (recreate), not the prefix."""
        base = parse_config(json.dumps(config_json())).mirrors[0]
        moved = parse_config(first(prefix="tools/caddy")).mirrors[0]
        refiltered = parse_config(first(filter="caddy (>= 2.11)")).mirrors[0]
        self.assertEqual(base.upstream.identity(), moved.upstream.identity())
        self.assertNotEqual(base.upstream.identity(), refiltered.upstream.identity())

    def test_rejects(self) -> None:
        """Unknown keys, bad values, duplicates, nesting and inconsistent limits."""
        cases = {
            "unknown key": mutate(lambda c: c.update(x=1)),
            "bad fpr": mutate(lambda c: c.update(gpg_key="abc")),
            "dup name": mutate(
                lambda c: c["mirrors"].append(dict(c["mirrors"][0], prefix="other"))
            ),
            "dup publish": mutate(
                lambda c: c["mirrors"].append(dict(c["mirrors"][0], name="caddy2"))
            ),
            "traversal prefix": first(prefix="../etc"),
            "reserved prefix": first(prefix="index.html"),
            "relative key": first(key_file="keys/x.asc"),
            "ftp url": first(url="ftp://x"),
            "no arch": first(architectures=[]),
            "component list": first(component=["main", "contrib"]),
            "old components key": first(components=["main"]),
            "empty filter": first(filter=" "),
            "filter deps not bool": first(filter_with_deps="yes"),
            "nested prefix": mutate(lambda c: c["mirrors"][1].update(prefix="caddy/sub")),
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
