"""GnuPG operations: upstream keyrings, the signing key and its public part."""

from __future__ import annotations

import contextlib
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path

from repo_common.proc import check_program, run_program

GPG = "/usr/bin/gpg"
GPGCONF = "/usr/bin/gpgconf"
GPG_TIMEOUT = 60
ARMORED_PUBLIC_KEY = b"-----BEGIN PGP PUBLIC KEY BLOCK-----"
MAX_KEY_FILE = 1 << 20


class SigningKeyError(RuntimeError):
    """The signing key cannot be imported or exported."""


def dearmor(key_file: str, out_dir: Path) -> str:
    """Convert an armored public key file into a keyring gpgv can read."""
    with open(key_file, "rb") as fh:
        if ARMORED_PUBLIC_KEY not in fh.read(MAX_KEY_FILE):
            # gpg --dearmor accepts binary input with rc 0 and writes garbage;
            # the mirror would then fail with a misleading "No public key".
            raise ValueError(f"{key_file} is not an armored OpenPGP public key")
    target = out_dir / (Path(key_file).name + ".gpg")
    check_program(
        [GPG, "--batch", "--yes", "--dearmor", "-o", str(target), key_file], timeout=GPG_TIMEOUT
    )
    return str(target)


def export_public_key(fingerprint: str) -> bytes:
    """Armored public part of the signing key from the current GNUPGHOME."""
    proc = check_program([GPG, "--batch", "--armor", "--export", fingerprint], timeout=GPG_TIMEOUT)
    if ARMORED_PUBLIC_KEY not in proc.stdout:
        raise SigningKeyError(f"signing key {fingerprint} not found in GNUPGHOME")
    return proc.stdout


@contextlib.contextmanager
def _gnupghome(home: str) -> Iterator[None]:
    previous = os.environ.get("GNUPGHOME")
    os.environ["GNUPGHOME"] = home
    try:
        yield
    finally:
        if previous is None:
            del os.environ["GNUPGHOME"]
        else:
            os.environ["GNUPGHOME"] = previous
        run_program([GPGCONF, "--homedir", home, "--kill", "all"], timeout=GPG_TIMEOUT)


@contextlib.contextmanager
def signing_keyring(key_file: str | None) -> Iterator[None]:
    """Import the secret signing key into a throw-away GNUPGHOME for this run.

    The key file is mounted read-only from the host; nothing derived from it
    outlives the process. Without a key file the inherited GNUPGHOME is used
    (tests, manual runs).
    """
    if not key_file:
        yield
        return
    with tempfile.TemporaryDirectory(prefix="repo-sync-gnupg-") as home:
        os.chmod(home, 0o700)
        imported = run_program(
            [GPG, "--homedir", home, "--batch", "--import", key_file], timeout=GPG_TIMEOUT
        )
        if imported.returncode != 0:
            # gpg's messages name the key, never its material.
            detail = " ".join(imported.stderr.decode(errors="replace").split())[-300:]
            raise SigningKeyError(
                f"cannot import signing key {key_file} (passphrase-less key required): {detail}"
            )
        with _gnupghome(home):
            yield
