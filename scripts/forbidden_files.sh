#!/usr/bin/env bash
# Reads NUL-separated paths (git ... -z) on stdin and reports those that must never be
# tracked: local configuration, keys, databases, sockets and caches.
# Exit 1 when at least one is found. Used by .githooks/pre-commit (staged
# files) and by the security workflow (all tracked files).
set -Eeuo pipefail

forbidden_reason() {
   local path="$1"
   case "${path}" in
      .env.example | .env.ci) return 1 ;;
      config/keys/.gitkeep | config/mirrors.json.example) return 1 ;;
   esac
   case "${path}" in
      .env | .env.* | */.env | */.env.*) echo "environment file" ;;
      config/mirrors.json) echo "local mirror configuration" ;;
      config/keys/*) echo "upstream or signing key" ;;
      *.pem | *.key | *.pfx | *.p12 | *.keystore | *.gpg | *.kbx | *.asc | *id_rsa* | *id_ed25519*)
         echo "key or keyring" ;;
      *.db | *.sqlite | *.sqlite3 | *.db-* | *.sqlite-* | *.sqlite3-*)
         echo "database" ;;
      *.sock) echo "socket" ;;
      *__pycache__/* | *.pyc | .mypy_cache/* | .ruff_cache/* | .pytest_cache/*) echo "cache" ;;
      *) return 1 ;;
   esac
}

main() {
   local path reason found=0
   while IFS= read -r -d '' path; do
      [[ -n "${path}" ]] || continue
      if reason="$(forbidden_reason "${path}")"; then
         printf 'forbidden file (%s): %s\n' "${reason}" "${path}" >&2
         found=1
      fi
   done
   return "${found}"
}

main "$@"
