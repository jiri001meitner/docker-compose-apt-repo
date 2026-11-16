"""repo-sync CLI.

  repo-sync sync      update mirrors, publish, rebuild the catalogue
  repo-sync catalog   rebuild only the catalogue (no network)
  repo-sync report    print "<status>\\t<output>|<perfdata>" for Icinga

Exit codes: 0 done (individual mirrors may still have failed, see report),
1 configuration or internal error, 75 another run holds the lock.
"""

from __future__ import annotations

import argparse
import contextlib
import logging
import os
import signal
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from types import FrameType

from .aptly import Aptly, AptlySettings
from .catalog import render_index, render_status, report
from .config import Config, ConfigError, load_config
from .sync import LockedError, State, Syncer, atomic_write, run_lock, utcnow

DEFAULT_CONFIG = "/etc/repo-sync/mirrors.json"
DEFAULT_ROOT = "/var/lib/aptly"


def export_public_key(fingerprint: str) -> bytes:
    proc = subprocess.run(  # noqa: S603 - fixed argv
        ["gpg", "--batch", "--armor", "--export", fingerprint],  # noqa: S607
        check=True,
        capture_output=True,
        timeout=60,
    )
    if b"BEGIN PGP PUBLIC KEY BLOCK" not in proc.stdout:
        raise RuntimeError(f"signing key {fingerprint} not found in GNUPGHOME")
    return proc.stdout


@contextlib.contextmanager
def signing_keyring(key_file: str | None) -> Iterator[None]:
    """Import the secret signing key into a throw-away GNUPGHOME for this run.

    The key file is mounted read-only from the host; nothing derived from it
    outlives the process. Without REPO_SYNC_SIGNING_KEY the inherited
    GNUPGHOME is used (tests, manual runs).
    """
    if not key_file:
        yield
        return
    with tempfile.TemporaryDirectory(prefix="repo-sync-gnupg-") as home:
        os.chmod(home, 0o700)
        imported = subprocess.run(  # noqa: S603 - fixed argv
            ["gpg", "--homedir", home, "--batch", "--import", key_file],  # noqa: S607
            check=False,
            capture_output=True,
            timeout=60,
        )
        if imported.returncode != 0:
            # gpg's messages name the key, never its material.
            detail = " ".join(imported.stderr.decode(errors="replace").split())[-300:]
            raise RuntimeError(f"cannot import signing key {key_file} (passphrase-less key required): {detail}")
        previous = os.environ.get("GNUPGHOME")
        os.environ["GNUPGHOME"] = home
        try:
            yield
        finally:
            if previous is None:
                del os.environ["GNUPGHOME"]
            else:
                os.environ["GNUPGHOME"] = previous
            subprocess.run(  # noqa: S603 - fixed argv
                ["gpgconf", "--homedir", home, "--kill", "all"],  # noqa: S607
                check=False,
                capture_output=True,
                timeout=30,
            )


def write_catalog(config: Config, root: Path) -> None:
    # Kept apart from aptly's public/ so the web server can serve it without
    # authentication from its own root, with no repository files reachable.
    public = root / "site"
    now = utcnow()
    state = State.load(root / "repo-sync-state.json")
    atomic_write(public / "key.asc", export_public_key(config.gpg_key))
    atomic_write(public / "status.json", render_status(config, state, now))
    fpr = " ".join(config.gpg_key[i : i + 4] for i in range(0, 40, 4))
    atomic_write(public / "index.html", render_index(config, state, now, fpr))


def main(argv: list[str] | None = None) -> int:
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
    log = logging.getLogger("repo_sync")
    root = Path(args.root)
    try:
        config = load_config(args.config)
    except (OSError, ConfigError) as exc:
        log.error("configuration: %s", exc)
        return 1

    if args.command == "report":
        try:
            status, output, perf = report(config, State.load(root / "repo-sync-state.json"), utcnow())
        except RuntimeError as exc:
            print(f"3\tREPO UNKNOWN - {exc}|")
            return 0
        print(f"{status}\t{output}|{perf}")
        return 0

    # docker stop sends SIGTERM to PID 1: unwind so the lock is released, the
    # temporary GNUPGHOME removed and the running aptly child killed.
    signal.signal(signal.SIGTERM, _terminate)

    os.umask(0o022)  # published files must be readable by the web server
    try:
        with run_lock(root), signing_keyring(os.environ.get("REPO_SYNC_SIGNING_KEY")):
            if args.command == "sync":
                with tempfile.TemporaryDirectory(prefix="repo-sync-keys-") as keyring_dir:
                    aptly = Aptly(
                        AptlySettings(
                            root_dir=str(root), gpg_key=config.gpg_key, origin=config.origin, label=config.label
                        ),
                        config_path=os.path.join(keyring_dir, "aptly.conf"),
                    )
                    Syncer(config, aptly, root, Path(keyring_dir)).run()
            write_catalog(config, root)
    except LockedError as exc:
        log.error("%s", exc)
        return 75
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        log.error("internal error: %s", exc)
        return 1
    status, output, _ = report(config, State.load(root / "repo-sync-state.json"), utcnow())
    log.info("%s", output)
    return 0


def _terminate(signum: int, _frame: FrameType | None) -> None:
    logging.getLogger("repo_sync").warning("signal %d, stopping", signum)
    raise SystemExit(128 + signum)


if __name__ == "__main__":
    raise SystemExit(main())
