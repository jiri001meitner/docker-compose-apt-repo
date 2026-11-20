#!/usr/bin/env bash
# gpgv for aptly: apt's rule (one valid signature from the keyring is enough).
# Installed as /usr/local/bin/gpgv, ahead of /usr/bin/gpgv in PATH; the logic
# and its reasons are in repo_sync/gpgv.py.
set -Eeuo pipefail
PYTHONPATH=/app exec /usr/bin/python3 -m repo_sync.gpgv "$@"
