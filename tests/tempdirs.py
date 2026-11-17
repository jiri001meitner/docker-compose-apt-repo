"""Temporary directories that live exactly as long as one test."""

from __future__ import annotations

import shutil
import tempfile
import unittest


def temp_dir(test: unittest.TestCase) -> str:
    """Create a private temporary directory, removed when ``test`` ends."""
    path = tempfile.mkdtemp(prefix="apt-repo-test-")
    test.addCleanup(shutil.rmtree, path, ignore_errors=True)
    return path
