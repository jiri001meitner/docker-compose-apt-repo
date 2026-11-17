"""repo-sync CLI.

  repo-sync sync      update mirrors, publish, rebuild the catalogue
  repo-sync catalog   rebuild only the catalogue (no network)
  repo-sync report    print "<status>\\t<output>|<perfdata>" for Icinga

Exit codes: 0 done (individual mirrors may still have failed, see report),
1 configuration or internal error, 75 another run holds the lock.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from types import FrameType

from repo_common.fsio import atomic_write
from repo_common.timeutil import utcnow

from .aptly import Aptly, AptlySettings
from .catalog import UNKNOWN, render_index, render_status, report
from .config import Config, ConfigError, load_config
from .gpg import export_public_key, signing_keyring
from .sync import STATE_FILE, LockedError, State, Syncer, run_lock

DEFAULT_CONFIG = "/etc/repo-sync/mirrors.json"
DEFAULT_ROOT = "/var/lib/aptly"
EXIT_ERROR = 1
EXIT_LOCKED = 75  # EX_TEMPFAIL
FINGERPRINT_GROUP = 4

log = logging.getLogger("repo_sync")


def write_catalog(config: Config, root: Path) -> None:
    """Write ``key.asc``, ``status.json`` and ``index.html`` to ``root/site``.

    Kept apart from aptly's public/ so the web server can serve it without
    authentication from its own root, with no repository files reachable.
    """
    site = root / "site"
    now = utcnow()
    state = State.load(root / STATE_FILE)
    fpr = config.signing.gpg_key
    atomic_write(site / "key.asc", export_public_key(fpr))
    atomic_write(site / "status.json", render_status(config, state, now))
    grouped = " ".join(
        fpr[i : i + FINGERPRINT_GROUP] for i in range(0, len(fpr), FINGERPRINT_GROUP)
    )
    atomic_write(site / "index.html", render_index(config, state, now, grouped))


def sync(config: Config, root: Path) -> None:
    """Synchronise all mirrors with a throw-away keyring and aptly config."""
    with tempfile.TemporaryDirectory(prefix="repo-sync-keys-") as keyring_dir:
        aptly = Aptly(
            AptlySettings(root_dir=str(root), signing=config.signing),
            config_path=os.path.join(keyring_dir, "aptly.conf"),
        )
        Syncer(config, aptly, root, Path(keyring_dir)).run()


def print_report(config: Config, root: Path) -> int:
    """Print the Icinga check result; the status is in the output, not the exit code."""
    try:
        status, output, perf = report(config, State.load(root / STATE_FILE), utcnow())
    except RuntimeError as exc:
        print(f"{UNKNOWN}\tREPO UNKNOWN - {exc}|")
        return 0
    print(f"{status}\t{output}|{perf}")
    return 0


def update(command: str, config: Config, root: Path) -> int:
    """``sync`` or ``catalog``: change the published tree under the run lock."""
    # docker stop sends SIGTERM to PID 1: unwind so the lock is released, the
    # temporary GNUPGHOME removed and the running aptly child killed.
    signal.signal(signal.SIGTERM, _terminate)
    os.umask(0o022)  # published files must be readable by the web server
    try:
        with run_lock(root), signing_keyring(os.environ.get("REPO_SYNC_SIGNING_KEY")):
            if command == "sync":
                sync(config, root)
            write_catalog(config, root)
    except LockedError as exc:
        log.error("%s", exc)
        return EXIT_LOCKED
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        log.error("internal error: %s", exc)
        return EXIT_ERROR
    log.info("%s", report(config, State.load(root / STATE_FILE), utcnow())[1])
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run one command; returns the exit code."""
    parser = argparse.ArgumentParser(
        prog="repo-sync", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("command", choices=["sync", "catalog", "report"])
    parser.add_argument("--config", default=os.environ.get("REPO_SYNC_CONFIG", DEFAULT_CONFIG))
    parser.add_argument("--root", default=os.environ.get("REPO_SYNC_ROOT", DEFAULT_ROOT))
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        config = load_config(args.config)
    except (OSError, ConfigError) as exc:
        log.error("configuration: %s", exc)
        return EXIT_ERROR
    root = Path(args.root)
    if args.command == "report":
        return print_report(config, root)
    return update(args.command, config, root)


def _terminate(signum: int, _frame: FrameType | None) -> None:
    log.warning("signal %d, stopping", signum)
    raise SystemExit(128 + signum)


if __name__ == "__main__":
    raise SystemExit(main())
