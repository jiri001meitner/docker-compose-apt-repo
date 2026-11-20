"""apt's signature rule in the gpgv used by aptly (repo_sync.gpgv)."""

from __future__ import annotations

import io
import os
import subprocess
import unittest
from unittest import mock

from repo_sync import gpgv

GOOD = [
    "[GNUPG:] NEWSIG",
    "[GNUPG:] KEY_CONSIDERED 738BEB9321D1AAEC13EA9391AEBDF4819BE21867 0",
    "[GNUPG:] GOODSIG AEBDF4819BE21867 Launchpad PPA for Test",
    "[GNUPG:] VALIDSIG 738BEB9321D1AAEC13EA9391AEBDF4819BE21867 2026-11-17 1794880763"
    " 0 4 0 1 10 01 738BEB9321D1AAEC13EA9391AEBDF4819BE21867",
]
UNKNOWN = [
    "[GNUPG:] NEWSIG",
    "[GNUPG:] ERRSIG 9BDB3D89CE49EC21 1 10 01 1794880763 9"
    " 0AB215679C571D1C8325275B9BDB3D89CE49EC21",
    "[GNUPG:] NO_PUBKEY 9BDB3D89CE49EC21",
]


def _sig(keyword: str) -> list[str]:
    """One signature ending with ``keyword`` (BADSIG, EXPKEYSIG, ...)."""
    return ["[GNUPG:] NEWSIG", f"[GNUPG:] {keyword} AEBDF4819BE21867 Launchpad PPA for Test"]


class JudgeTest(unittest.TestCase):
    """Only a valid signature plus signatures by unknown keys turns a failure into success."""

    def test_success_is_kept(self) -> None:
        """Exit 0 stays 0 whatever the status says."""
        self.assertTrue(gpgv.judge(0, GOOD).accepted)

    def test_valid_and_unknown_signature_is_accepted(self) -> None:
        """Launchpad's dual signature: current key in the keyring, legacy key not."""
        verdict = gpgv.judge(2, GOOD + UNKNOWN)
        self.assertTrue(verdict.accepted)
        self.assertEqual(verdict.unknown_keys, ("9BDB3D89CE49EC21",))

    def test_unknown_signature_first_is_accepted(self) -> None:
        """Order of the signatures does not matter."""
        self.assertTrue(gpgv.judge(2, UNKNOWN + GOOD).accepted)

    def test_only_unknown_signatures_are_rejected(self) -> None:
        """No signature from the keyring: rejected (a file signed by the legacy key alone)."""
        self.assertFalse(gpgv.judge(2, UNKNOWN).accepted)
        self.assertFalse(gpgv.judge(2, UNKNOWN + UNKNOWN).accepted)

    def test_bad_expired_or_revoked_signature_is_rejected(self) -> None:
        """A valid signature does not excuse a bad, expired or revoked one."""
        for keyword in ("BADSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG"):
            with self.subTest(keyword=keyword):
                self.assertFalse(gpgv.judge(2, GOOD + _sig(keyword)).accepted)
                self.assertFalse(gpgv.judge(1, GOOD + _sig(keyword)).accepted)

    def test_errsig_other_than_missing_key_is_rejected(self) -> None:
        """ERRSIG reason 4 (unsupported algorithm) is not a missing key."""
        errsig = ["[GNUPG:] NEWSIG", "[GNUPG:] ERRSIG 9BDB3D89CE49EC21 1 10 01 1794880763 4"]
        self.assertFalse(gpgv.judge(2, GOOD + errsig).accepted)

    def test_short_errsig_is_rejected(self) -> None:
        """An ERRSIG without the reason field cannot be judged."""
        errsig = ["[GNUPG:] NEWSIG", "[GNUPG:] ERRSIG 9BDB3D89CE49EC21 1 10"]
        self.assertFalse(gpgv.judge(2, GOOD + errsig).accepted)

    def test_error_status_is_rejected(self) -> None:
        """A second clearsigned message after a dual-signed one: gpgv reports ERROR."""
        status = [*GOOD, *UNKNOWN, "[GNUPG:] ERROR proc_pkt.plaintext 89_BAD_DATA"]
        self.assertFalse(gpgv.judge(2, status).accepted)

    def test_unknown_status_keyword_is_rejected(self) -> None:
        """Anything gpgv reports beyond the known set fails closed."""
        self.assertFalse(gpgv.judge(2, [*GOOD, *UNKNOWN, "[GNUPG:] FAILURE gpgv 1"]).accepted)

    def test_exit_two_without_missing_key_is_rejected(self) -> None:
        """Exit 2 with only valid signatures is some other failure."""
        self.assertFalse(gpgv.judge(2, GOOD).accepted)

    def test_errsig_without_no_pubkey_is_rejected(self) -> None:
        """ERRSIG reason 9 must come with its NO_PUBKEY line."""
        self.assertFalse(gpgv.judge(2, GOOD + UNKNOWN[:2]).accepted)

    def test_signature_without_verdict_is_rejected(self) -> None:
        """Every NEWSIG must end as VALIDSIG or a missing key."""
        self.assertFalse(gpgv.judge(2, [*GOOD, "[GNUPG:] NEWSIG"]).accepted)

    def test_other_exit_codes_are_kept(self) -> None:
        """Only exit 2 (cannot check) is ever turned into success."""
        self.assertFalse(gpgv.judge(1, GOOD + UNKNOWN).accepted)
        self.assertFalse(gpgv.judge(3, GOOD + UNKNOWN).accepted)

    def test_noise_is_ignored(self) -> None:
        """Lines without the status prefix and empty records do not count."""
        self.assertTrue(gpgv.judge(2, ["gpgv: noise", "[GNUPG:] ", *GOOD, *UNKNOWN]).accepted)


class SplitStatusFdTest(unittest.TestCase):
    """aptly passes ``--status-fd 3`` first; both spellings are understood."""

    def test_separate_value(self) -> None:
        """``--status-fd 3`` is removed from the arguments."""
        self.assertEqual(
            gpgv.split_status_fd(["--status-fd", "3", "--keyring", "k", "f"]),
            (3, ["--keyring", "k", "f"]),
        )

    def test_joined_value(self) -> None:
        """``--status-fd=3`` is removed from the arguments."""
        self.assertEqual(gpgv.split_status_fd(["--status-fd=3", "f"]), (3, ["f"]))

    def test_absent(self) -> None:
        """Without it the arguments are untouched."""
        self.assertEqual(gpgv.split_status_fd(["--version"]), (None, ["--version"]))


def _completed(returncode: int, stdout: bytes, stderr: bytes) -> subprocess.CompletedProcess[bytes]:
    """A finished gpgv run."""
    return subprocess.CompletedProcess(["gpgv"], returncode, stdout, stderr)


class MainTest(unittest.TestCase):
    """The status reaches the caller's descriptor and the exit code follows judge()."""

    def _run(
        self, args: list[str], result: subprocess.CompletedProcess[bytes]
    ) -> tuple[int, bytes, bytes, str, list[str]]:
        """Run main() with gpgv replaced by ``result``.

        Returns the exit code, what reached the status descriptor and stdout,
        stderr, and the command gpgv would have run.
        """
        read_fd, write_fd = os.pipe()
        out_bytes, err_bytes = io.BytesIO(), io.BytesIO()
        stdout, stderr = io.TextIOWrapper(out_bytes), io.TextIOWrapper(err_bytes)
        try:
            with (
                mock.patch.object(gpgv, "run_program", return_value=result) as run,
                mock.patch("sys.stdout", stdout),
                mock.patch("sys.stderr", stderr),
            ):
                code = gpgv.main([arg.replace("FD", str(write_fd)) for arg in args])
        finally:
            os.close(write_fd)
        with os.fdopen(read_fd, "rb") as fh:
            status = fh.read()
        stderr.flush()
        return (
            code,
            status,
            out_bytes.getvalue(),
            err_bytes.getvalue().decode(),
            run.call_args.args[0],
        )

    def test_dual_signature_succeeds_and_status_is_forwarded(self) -> None:
        """Exit 2 with a valid and an unknown signature becomes 0; status is passed on."""
        status = ("\n".join(GOOD + UNKNOWN) + "\n").encode()
        code, forwarded, _, message, called = self._run(
            ["--status-fd", "FD", "--keyring", "k.gpg", "InRelease"],
            _completed(2, status, b"gpgv: Can't check signature: No public key\n"),
        )
        self.assertEqual(code, 0)
        self.assertEqual(forwarded, status)
        self.assertEqual(called, [gpgv.GPGV, "--status-fd", "1", "--keyring", "k.gpg", "InRelease"])
        self.assertIn("No public key", message)
        self.assertIn("ignoring signatures by keys not in it: 9BDB3D89CE49EC21", message)

    def test_failure_keeps_exit_code(self) -> None:
        """Only unknown signatures: gpgv's exit code is returned unchanged."""
        status = ("\n".join(UNKNOWN) + "\n").encode()
        code, forwarded, _, message, _ = self._run(
            ["--status-fd=FD", "InRelease"], _completed(2, status, b"")
        )
        self.assertEqual((code, forwarded, message), (2, status, ""))

    def test_without_status_fd_is_passthrough(self) -> None:
        """``gpgv --version`` (aptly's probe) runs the real gpgv unchanged."""
        code, forwarded, out, _, called = self._run(
            ["--version"], _completed(0, b"gpgv (GnuPG) 2.4.8\n", b"")
        )
        self.assertEqual((code, forwarded, out), (0, b"", b"gpgv (GnuPG) 2.4.8\n"))
        self.assertEqual(called, [gpgv.GPGV, "--version"])


if __name__ == "__main__":
    unittest.main()
