"""Configuration of mirrors (``mirrors.json``), strictly validated."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
PREFIX_SEGMENT_RE = re.compile(r"^[a-z0-9][a-z0-9.+-]*$")
DIST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
ARCH_RE = re.compile(r"^[a-z0-9-]+$")
FPR_RE = re.compile(r"^[0-9A-F]{40}$")
# Public catalogue files live at the root of the publish directory.
RESERVED_PREFIXES = frozenset({"index.html", "status.json", "key.asc", "favicon.ico", "robots.txt"})
MIRROR_KEYS = frozenset(
    {
        "name",
        "title",
        "url",
        "distribution",
        "component",
        "architectures",
        "key_file",
        "prefix",
        "filter",
        "filter_with_deps",
    }
)
CONFIG_KEYS = frozenset(
    {
        "gpg_key",
        "origin",
        "label",
        "keep_snapshots",
        "stale_warning_hours",
        "stale_critical_hours",
        "sync_interval_hours",
        "probe_timeout_seconds",
        "site_title",
        "base_url",
        "mirrors",
    }
)


class ConfigError(ValueError):
    """The configuration is invalid; nothing is synchronised."""


@dataclass(frozen=True, slots=True)
class Upstream:
    """What is mirrored: one distribution and component of an upstream repository.

    The same distribution, component and architectures are published.
    """

    url: str
    distribution: str
    component: str
    architectures: tuple[str, ...]
    filter: str | None = None
    filter_with_deps: bool = False

    def identity(self) -> str:
        """Changes exactly when the aptly mirror must be recreated."""
        material = json.dumps(
            [
                self.url,
                self.distribution,
                self.component,
                self.architectures,
                self.filter,
                self.filter_with_deps,
            ]
        )
        return hashlib.sha256(material.encode()).hexdigest()[:16]


@dataclass(frozen=True, slots=True)
class Mirror:
    """One mirrored repository and where it is published."""

    name: str
    title: str
    upstream: Upstream
    key_file: str
    prefix: str

    @property
    def target(self) -> tuple[str, str]:
        """(prefix, distribution) of the publication."""
        return self.prefix, self.upstream.distribution


@dataclass(frozen=True, slots=True)
class Signing:
    """Repository signing key and the Release file fields."""

    gpg_key: str
    origin: str
    label: str


@dataclass(frozen=True, slots=True)
class Schedule:
    """When a mirror is synced, how long its upstream may take to answer, when it is stale."""

    sync_interval_hours: int
    probe_timeout_seconds: int
    stale_warning_hours: int
    stale_critical_hours: int


@dataclass(frozen=True, slots=True)
class Config:
    """The whole ``mirrors.json``."""

    signing: Signing
    keep_snapshots: int
    schedule: Schedule
    site_title: str
    base_url: str
    mirrors: tuple[Mirror, ...]


def _req(cond: bool, msg: str) -> None:
    if not cond:
        raise ConfigError(msg)


def _str(raw: dict[str, Any], key: str, ctx: str, pattern: re.Pattern[str] | None = None) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or value == "":
        raise ConfigError(f"{ctx}: '{key}' must be a non-empty string")
    if pattern is not None:
        _req(pattern.fullmatch(value) is not None, f"{ctx}: invalid '{key}': {value!r}")
    return value


def _str_list(raw: dict[str, Any], key: str, ctx: str, pattern: re.Pattern[str]) -> tuple[str, ...]:
    value = raw.get(key)
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{ctx}: '{key}' must be a non-empty list")
    for item in value:
        _req(
            isinstance(item, str) and pattern.fullmatch(item) is not None,
            f"{ctx}: invalid {key} item {item!r}",
        )
    return tuple(value)


def _int(raw: dict[str, Any], key: str, default: int, minimum: int) -> int:
    value = raw.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ConfigError(f"'{key}' must be an integer >= {minimum}")
    return value


def _upstream(raw: dict[str, Any], ctx: str) -> Upstream:
    url = _str(raw, "url", ctx)
    _req(
        url.startswith(("https://", "http://")) and not any(c.isspace() for c in url),
        f"{ctx}: url must be http(s) without spaces",
    )
    flt = raw.get("filter")
    _req(
        flt is None or (isinstance(flt, str) and flt.strip() != ""),
        f"{ctx}: filter must be a string or null",
    )
    fwd = raw.get("filter_with_deps", False)
    _req(isinstance(fwd, bool), f"{ctx}: filter_with_deps must be boolean")
    return Upstream(
        url=url,
        distribution=_str(raw, "distribution", ctx, DIST_RE),
        # One component per mirror: aptly merges several into one snapshot,
        # and every upstream here (Caddy, PPAs) has only `main`.
        component=_str(raw, "component", ctx, DIST_RE),
        architectures=_str_list(raw, "architectures", ctx, ARCH_RE),
        filter=flt,
        filter_with_deps=fwd,
    )


def _mirror(raw: Any, index: int) -> Mirror:
    ctx = f"mirrors[{index}]"
    _req(isinstance(raw, dict), f"{ctx}: not an object")
    _req(set(raw) <= MIRROR_KEYS, f"{ctx}: unknown keys {sorted(set(raw) - MIRROR_KEYS)}")
    prefix = _str(raw, "prefix", ctx)
    segments = prefix.split("/")
    _req(all(PREFIX_SEGMENT_RE.fullmatch(s) for s in segments), f"{ctx}: invalid prefix {prefix!r}")
    _req(segments[0] not in RESERVED_PREFIXES, f"{ctx}: prefix {prefix!r} is reserved")
    key_file = _str(raw, "key_file", ctx)
    _req(key_file.startswith("/"), f"{ctx}: key_file must be absolute")
    return Mirror(
        name=_str(raw, "name", ctx, NAME_RE),
        title=_str(raw, "title", ctx),
        upstream=_upstream(raw, ctx),
        key_file=key_file,
        prefix=prefix,
    )


def _check_layout(mirrors: tuple[Mirror, ...]) -> None:
    names = [m.name for m in mirrors]
    _req(len(names) == len(set(names)), "mirror names must be unique")
    targets = [m.target for m in mirrors]
    _req(len(targets) == len(set(targets)), "prefix + distribution must be unique")
    # A prefix nested in another (ppa vs ppa/x) would put one repository's
    # tree inside another's, and an access scope for the outer one would
    # silently cover the inner one.
    prefixes = sorted({m.prefix for m in mirrors})
    for outer in prefixes:
        for inner in prefixes:
            _req(not inner.startswith(outer + "/"), f"prefix {inner!r} is nested in {outer!r}")


def parse_config(data: str) -> Config:
    """Parse and validate ``mirrors.json``; any defect raises ConfigError."""
    try:
        raw = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"not valid JSON: {exc}") from exc
    _req(isinstance(raw, dict), "config is not an object")
    _req(set(raw) <= CONFIG_KEYS, f"unknown keys {sorted(set(raw) - CONFIG_KEYS)}")
    mirrors_raw = raw.get("mirrors")
    if not isinstance(mirrors_raw, list):
        raise ConfigError("'mirrors' must be a list")
    mirrors = tuple(_mirror(m, i) for i, m in enumerate(mirrors_raw))
    _check_layout(mirrors)
    warn = _int(raw, "stale_warning_hours", 48, 1)
    crit = _int(raw, "stale_critical_hours", 168, 1)
    _req(crit >= warn, "stale_critical_hours must be >= stale_warning_hours")
    base_url = _str(raw, "base_url", "config")
    _req(
        base_url.startswith("https://") and not base_url.endswith("/"),
        "base_url must be https:// without '/'",
    )
    return Config(
        signing=Signing(
            gpg_key=_str(raw, "gpg_key", "config", FPR_RE),
            origin=_str(raw, "origin", "config"),
            label=_str(raw, "label", "config"),
        ),
        keep_snapshots=_int(raw, "keep_snapshots", 3, 1),
        schedule=Schedule(
            sync_interval_hours=_int(raw, "sync_interval_hours", 6, 1),
            probe_timeout_seconds=_int(raw, "probe_timeout_seconds", 10, 1),
            stale_warning_hours=warn,
            stale_critical_hours=crit,
        ),
        site_title=_str(raw, "site_title", "config"),
        base_url=base_url,
        mirrors=mirrors,
    )


def load_config(path: str) -> Config:
    """Read and validate the configuration file."""
    return parse_config(Path(path).read_text(encoding="utf-8"))
