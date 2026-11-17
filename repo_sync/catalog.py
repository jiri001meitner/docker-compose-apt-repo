"""Public catalogue: ``status.json``, ``index.html`` (Czech + English), Icinga report."""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import datetime
from importlib import resources
from string import Template

from repo_common.timeutil import format_utc, parse_optional_utc

from .config import Config, Mirror
from .sync import MirrorState, State

OK, WARNING, CRITICAL, UNKNOWN = 0, 1, 2, 3
STATE_NAMES = {OK: "OK", WARNING: "WARNING", CRITICAL: "CRITICAL", UNKNOWN: "UNKNOWN"}
SECONDS_PER_HOUR = 3600
KEYRING_PATH = "/etc/apt/keyrings/repo-mordecai.asc"

# Texts of index.html: placeholder -> (Czech, English).
TEXTS = {
    "t_intro": (
        "Zrcadla APT repozitářů. Stahování vyžaduje přístupové údaje.",
        "APT repository mirrors. Downloads require credentials.",
    ),
    "t_updated": ("Aktualizováno", "Updated"),
    "t_mirrors": ("Zrcadla", "Mirrors"),
    "t_mirror": ("Zrcadlo", "Mirror"),
    "t_distribution": ("Distribuce", "Distribution"),
    "t_packages": ("Balíčky", "Packages"),
    "t_last_sync": ("Poslední synchronizace (UTC)", "Last sync (UTC)"),
    "t_failed": (
        "poslední pokus o stažení ze zdroje selhal, nabízí se poslední úspěšný stav",
        "the last attempt to fetch from upstream failed; the last good state is served",
    ),
    "t_client": ("Nastavení klienta", "Client setup"),
    "t_key": ("Klíč repozitáře", "Repository key"),
    "t_fingerprint": ("otisk", "fingerprint"),
    "t_credentials": ("Přístupové údaje (soubor jen pro root)", "Credentials (root-only file)"),
    "t_source": ("Zdroj (příklad)", "Source (example)"),
    "t_status": ("Stav strojově", "Machine-readable status"),
}
LEVEL_CLASSES = {OK: "ok", WARNING: "warning", CRITICAL: "critical"}


@dataclass(frozen=True, slots=True)
class MirrorHealth:
    """Freshness of one mirror."""

    mirror: Mirror
    state: MirrorState
    age_hours: float | None  # since last success; None = never succeeded
    level: int

    def describe(self) -> str:
        """``name (age)`` for the report."""
        age = "never synced" if self.age_hours is None else f"{self.age_hours:.0f} h"
        return f"{self.mirror.name} ({age})"


def _hours(now: datetime, since: datetime | None) -> float | None:
    return (now - since).total_seconds() / SECONDS_PER_HOUR if since else None


def assess(config: Config, state: State, now: datetime) -> list[MirrorHealth]:
    """Freshness of every configured mirror.

    Stale = no successful sync for N hours. Short upstream outages are
    tolerated (the last good snapshot is served); a mirror that never synced
    serves nothing, so it is at least WARNING right away and CRITICAL after
    stale_critical_hours.
    """
    result = []
    for mirror in config.mirrors:
        st = state.mirrors.get(mirror.name, MirrorState())
        success = parse_optional_utc(st.last_success)
        age = _hours(now, success or parse_optional_utc(st.first_attempt)) or 0.0
        if age >= config.stale_critical_hours:
            level = CRITICAL
        elif success is None or age >= config.stale_warning_hours:
            level = WARNING
        else:
            level = OK
        result.append(MirrorHealth(mirror, st, _hours(now, success), level))
    return result


def report(config: Config, state: State, now: datetime) -> tuple[int, str, str]:
    """Icinga check result: (exit status, plugin output, performance data)."""
    health = assess(config, state, now)
    level = max((h.level for h in health), default=OK)
    bad = [h for h in health if h.level != OK]
    failing = [h for h in health if h.state.last_error]
    parts = [f"{len(health)} mirrors"]
    if bad:
        parts.append("stale: " + ", ".join(h.describe() for h in bad))
    if failing:
        parts.append("last attempt failed: " + ", ".join(h.mirror.name for h in failing))
    output = f"REPO {STATE_NAMES[level]} - " + "; ".join(parts)
    perf = " ".join(f"'{h.mirror.name}_packages'={h.state.packages}" for h in health)
    return level, output, perf


def status_document(config: Config, state: State, now: datetime) -> dict[str, object]:
    """Content of ``status.json``."""
    return {
        "generated": format_utc(now),
        "last_run": state.last_run,
        "mirrors": [
            {
                "name": h.mirror.name,
                "title": h.mirror.title,
                "path": f"/{h.mirror.prefix}/",
                "distribution": h.mirror.upstream.distribution,
                "component": h.mirror.upstream.component,
                "architectures": list(h.mirror.upstream.architectures),
                "upstream": h.mirror.upstream.url,
                "packages": h.state.packages,
                "last_success": h.state.last_success,
                "last_attempt": h.state.last_attempt,
                "last_attempt_failed": h.state.last_error is not None,
                "status": STATE_NAMES[h.level].lower(),
            }
            for h in assess(config, state, now)
        ],
    }


def render_status(config: Config, state: State, now: datetime) -> bytes:
    """``status.json`` as bytes."""
    return (json.dumps(status_document(config, state, now), indent=2) + "\n").encode()


def _bilingual(cs: str, en: str) -> str:
    return f'<span lang="cs">{html.escape(cs)}</span> / <span lang="en">{html.escape(en)}</span>'


def _row(base_url: str, health: MirrorHealth) -> str:
    e = html.escape
    m, st, up = health.mirror, health.state, health.mirror.upstream
    css = LEVEL_CLASSES.get(health.level, "warning")
    failed = " ⚠" if st.last_error else ""
    return (
        "<tr>"
        f"<td><strong>{e(m.title)}</strong><br><code>{e(base_url)}/{e(m.prefix)}/</code></td>"
        f"<td><code>{e(up.distribution)}</code> · {e(up.component)}<br>"
        f"{e(', '.join(up.architectures))}</td>"
        f"<td>{st.packages}</td>"
        f'<td class="{css}">{e(st.last_success or "—")}{failed}</td>'
        "</tr>"
    )


def _sources_example(config: Config) -> str:
    """A deb822 source for the first mirror (empty without mirrors)."""
    if not config.mirrors:
        return ""
    m = config.mirrors[0]
    return (
        f"Types: deb\nURIs: {config.base_url}/{m.prefix}/\n"
        f"Suites: {m.upstream.distribution}\nComponents: {m.upstream.component}\n"
        f"Architectures: amd64\nSigned-By: {KEYRING_PATH}\n"
    )


def render_index(config: Config, state: State, now: datetime, key_fingerprint: str) -> bytes:
    """``index.html``: mirrors, their freshness and client setup (Czech and English)."""
    e = html.escape
    template = Template(
        resources.files("repo_sync").joinpath("templates/index.html").read_text(encoding="utf-8")
    )
    page = template.substitute(
        {name: _bilingual(cs, en) for name, (cs, en) in TEXTS.items()},
        title=e(config.site_title),
        updated=e(format_utc(now)),
        rows="".join(_row(config.base_url, h) for h in assess(config, state, now)),
        fingerprint=e(key_fingerprint),
        base_url=e(config.base_url),
        host=e(config.base_url.removeprefix("https://")),
        sources=e(_sources_example(config)),
    )
    return page.encode()
