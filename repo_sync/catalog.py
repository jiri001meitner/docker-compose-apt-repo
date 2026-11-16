"""Public catalogue: ``status.json``, ``index.html`` (Czech + English), Icinga report."""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import datetime

from .config import Config, Mirror
from .sync import MirrorState, State, from_iso, iso

OK, WARNING, CRITICAL, UNKNOWN = 0, 1, 2, 3
STATE_NAMES = {OK: "OK", WARNING: "WARNING", CRITICAL: "CRITICAL", UNKNOWN: "UNKNOWN"}


@dataclass(frozen=True, slots=True)
class MirrorHealth:
    mirror: Mirror
    state: MirrorState
    age_hours: float | None  # since last success; None = never succeeded
    level: int


def assess(config: Config, state: State, now: datetime) -> list[MirrorHealth]:
    """Stale = no successful sync for N hours. Short upstream outages are tolerated
    (the last good snapshot is served); a mirror that never synced serves nothing,
    so it is at least WARNING right away and CRITICAL after stale_critical_hours."""
    result = []
    for mirror in config.mirrors:
        st = state.mirrors.get(mirror.name, MirrorState())
        success = from_iso(st.last_success)
        reference = success or from_iso(st.first_attempt)
        age = (now - reference).total_seconds() / 3600 if reference else 0.0
        if age >= config.stale_critical_hours:
            level = CRITICAL
        elif success is None or age >= config.stale_warning_hours:
            level = WARNING
        else:
            level = OK
        result.append(MirrorHealth(mirror, st, (now - success).total_seconds() / 3600 if success else None, level))
    return result


def report(config: Config, state: State, now: datetime) -> tuple[int, str, str]:
    """Icinga check result: (exit status, plugin output, performance data)."""
    health = assess(config, state, now)
    level = max((h.level for h in health), default=OK)
    bad = [h for h in health if h.level != OK]
    failing = [h for h in health if h.state.last_error]
    parts = [f"{len(health)} mirrors"]
    if bad:
        parts.append(
            "stale: "
            + ", ".join(
                f"{h.mirror.name} ({'never synced' if h.age_hours is None else f'{h.age_hours:.0f} h'})" for h in bad
            )
        )
    if failing:
        parts.append("last attempt failed: " + ", ".join(h.mirror.name for h in failing))
    output = f"REPO {STATE_NAMES[level]} - " + "; ".join(parts)
    perf = " ".join(f"'{h.mirror.name}_packages'={h.state.packages}" for h in health)
    return level, output, perf


def status_document(config: Config, state: State, now: datetime) -> dict[str, object]:
    return {
        "generated": iso(now),
        "last_run": state.last_run,
        "mirrors": [
            {
                "name": h.mirror.name,
                "title": h.mirror.title,
                "path": f"/{h.mirror.prefix}/",
                "distribution": h.mirror.distribution,
                "component": h.mirror.component,
                "architectures": list(h.mirror.architectures),
                "upstream": h.mirror.url,
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
    return (json.dumps(status_document(config, state, now), indent=2) + "\n").encode()


_CSS = """
:root{--bg:#fff;--fg:#1d2433;--muted:#5b6475;--line:#d9dee7;--ok:#1a7f37;--warn:#9a6700;--crit:#cf222e;
--code:#f4f6f9}
@media (prefers-color-scheme:dark){:root{--bg:#11151c;--fg:#e6e9ef;--muted:#9aa3b2;--line:#2a313c;
--ok:#3fb950;--warn:#d29922;--crit:#f85149;--code:#1a2029}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:960px;margin:0 auto;padding:24px 16px 48px}h1{font-size:1.6rem;margin:0 0 4px}
h2{font-size:1.15rem;margin:32px 0 8px}p.muted,.muted{color:var(--muted)}
table{width:100%;border-collapse:collapse;font-size:.92rem}th,td{text-align:left;padding:8px 6px;
border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}
.wrap{overflow-x:auto}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.88rem}
pre{background:var(--code);padding:12px;border-radius:6px;overflow-x:auto}
.ok{color:var(--ok)}.warning{color:var(--warn)}.critical{color:var(--crit)}
"""


def _t(cs: str, en: str) -> str:
    return f'<span lang="cs">{html.escape(cs)}</span> / <span lang="en">{html.escape(en)}</span>'


def render_index(config: Config, state: State, now: datetime, key_fingerprint: str) -> bytes:
    e = html.escape
    rows = []
    for h in assess(config, state, now):
        m, st = h.mirror, h.state
        status_cls = {OK: "ok", WARNING: "warning", CRITICAL: "critical"}.get(h.level, "warning")
        rows.append(
            "<tr>"
            f"<td><strong>{e(m.title)}</strong><br><code>{e(config.base_url)}/{e(m.prefix)}/</code></td>"
            f"<td><code>{e(m.distribution)}</code> · {e(m.component)}<br>"
            f"{e(', '.join(m.architectures))}</td>"
            f"<td>{st.packages}</td>"
            f'<td class="{status_cls}">{e(st.last_success or "—")}'
            f"{' ⚠' if st.last_error else ''}</td>"
            "</tr>"
        )
    host = e(config.base_url.removeprefix("https://"))
    example = config.mirrors[0] if config.mirrors else None
    sources = (
        f"Types: deb\nURIs: {config.base_url}/{example.prefix}/\nSuites: {example.distribution}\n"
        f"Components: {example.component}\nArchitectures: amd64\n"
        "Signed-By: /etc/apt/keyrings/repo-mordecai.asc\n"
        if example
        else ""
    )
    page = f"""<!doctype html>
<html lang="cs"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(config.site_title)}</title><meta name="robots" content="noindex"><style>{_CSS}</style></head>
<body><main>
<h1>{e(config.site_title)}</h1>
<p class="muted">{
        _t(
            "Zrcadla APT repozitářů. Stahování vyžaduje přístupové údaje.",
            "APT repository mirrors. Downloads require credentials.",
        )
    }</p>
<p class="muted">{_t("Aktualizováno", "Updated")}: {e(iso(now))}</p>

<h2>{_t("Zrcadla", "Mirrors")}</h2>
<div class="wrap"><table>
<thead><tr><th>{_t("Zrcadlo", "Mirror")}</th><th>{_t("Distribuce", "Distribution")}</th>
<th>{_t("Balíčky", "Packages")}</th><th>{_t("Poslední synchronizace (UTC)", "Last sync (UTC)")}</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table></div>
<p class="muted">⚠ {
        _t(
            "poslední pokus o stažení ze zdroje selhal, nabízí se poslední úspěšný stav",
            "the last attempt to fetch from upstream failed; the last good state is served",
        )
    }</p>

<h2>{_t("Nastavení klienta", "Client setup")}</h2>
<p>1. {_t("Klíč repozitáře", "Repository key")}: <a href="/key.asc"><code>/key.asc</code></a>,
{_t("otisk", "fingerprint")} <code>{e(key_fingerprint)}</code></p>
<pre>sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL {e(config.base_url)}/key.asc | sudo tee /etc/apt/keyrings/repo-mordecai.asc &gt;/dev/null</pre>
<p>2. {_t("Přístupové údaje (soubor jen pro root)", "Credentials (root-only file)")}:</p>
<pre>sudo install -m 0600 /dev/null /etc/apt/auth.conf.d/repo-mordecai.conf
printf 'machine {
        host
    }\\nlogin LOGIN\\npassword TOKEN\\n' | sudo tee /etc/apt/auth.conf.d/repo-mordecai.conf &gt;/dev/null</pre>
<p>3. {_t("Zdroj (příklad)", "Source (example)")}: <code>/etc/apt/sources.list.d/repo-mordecai-*.sources</code></p>
<pre>{e(sources)}</pre>
<p class="muted">{
        _t("Stav strojově", "Machine-readable status")
    }: <a href="/status.json"><code>/status.json</code></a></p>
</main></body></html>
"""
    return page.encode()
