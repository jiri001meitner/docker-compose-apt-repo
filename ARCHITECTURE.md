# Architecture

How the pieces fit, where the trust boundaries are and why. Operation and
commands are in [README.md](README.md); rules for contributors in
[AGENTS.md](AGENTS.md).

## Components

```
                       ┌──────────── host ──────────────────────────────────────┐
 apt client ──HTTPS──► │ Caddy ── forward_auth ──► repo-auth  (network: none)   │
 (auth.conf.d)         │   │      UNIX socket 0660   │ reads                     │
                       │   │                         ▼                           │
                       │   │                 export/clients.json ◄── repo-admin  │
                       │   │                   (atomic, validated)    │ (none)   │
                       │   │                                          ▼          │
                       │   │                                      db/ SQLite     │
                       │   ├─ file_server aptly/site   (public catalogue)        │
                       │   └─ file_server aptly/public (after 200 only)          │
                       │                    ▲ writes                             │
                       │ timer ──► repo-sync (aptly) ──br-aptrepo──► upstreams   │
                       └─────────────────────────────────────────────────────────┘
```

| Package | Image | Role |
|---|---|---|
| `repo_common/` | both | UTC timestamps, atomic writes and locks, the single program runner |
| `repo_auth/` | `repo-auth` | `model` (export format), `auth` (pure decision), `store` (reload), `server` (HTTP on the socket), `accounts` (SQLite), `admin` (CLI), `healthcheck` |
| `repo_sync/` | `aptly` | `config` (mirrors.json), `aptly` (CLI wrapper), `gpg`, `sync` (one run), `catalog` (status, index, Icinga report), `__main__` (CLI) |

## Data and state

| What | Where | Written by | Read by |
|---|---|---|---|
| accounts, token hashes | `DATA_DIR/db` (SQLite, 0700) | repo-admin | repo-admin |
| client list | `DATA_DIR/export/clients.json` | repo-admin (atomic, under `.clients.lock`) | repo-auth |
| mirrors, snapshots, publications | `DATA_DIR/aptly` | repo-sync | Caddy |
| run results | `aptly/repo-sync-state.json` | repo-sync | catalogue, report |
| signing key | `SIGNING_KEY_FILE` (0400, read-only mount) | operator | repo-sync (temporary GNUPGHOME) |

The source of truth for access is SQLite; repo-auth sees only the export,
so a broken database can never open the repository. The source of truth
for publishing is aptly itself (`publish list -json`); the state file only
feeds the catalogue, so a lost or stale state file heals on the next run.

## Trust boundaries

1. **Internet → Caddy.** Only GET/HEAD reach the repository; everything but
   the public catalogue (`/`, `/index.html`, `/status.json`, `/key.asc`)
   goes through `forward_auth` first. Caddy cleans the path before both
   the auth request and the file lookup, so they see the same path.
2. **Caddy → repo-auth.** UNIX socket, group of the proxy only; repo-auth has
   no network at all. It decides on `X-Forwarded-Method/Uri` and the Basic
   header: 503 without a client list, then credentials (401) before any
   policy (403), so a wrong token reveals nothing about the account.
   One request per connection, read timeout, connection deadline and a
   concurrency limit bound what a client can hold.
3. **Scopes = publish prefixes.** Prefixes may not be nested and packages
   are hardlinks; the only symlinks are aptly's `by-hash/` links inside one
   distribution. A path check on the request path therefore cannot be
   bypassed through the file system.
4. **repo-sync → upstreams.** Each mirror is verified with its own upstream
   key only; a tampered upstream is rejected and the last good snapshot
   stays published. The only container with network access, in its own
   bridge `br-aptrepo`.
5. **Signing key.** Imported per run into a throw-away GNUPGHOME; nothing
   derived from it outlives the process.

All containers are read-only, drop all capabilities, run with
`no-new-privileges` as non-root users and have memory and PID limits.

## Decisions

- **Standard library only** in the images: no third-party code in the
  authentication path, nothing to pin or audit.
- **One component per mirror**: aptly would merge several components into
  one snapshot.
- **Only the newest version of each package is published** (`snapshot merge
  -latest`): older versions lack security fixes and a mirror of a PPA is
  used for the newest version.
- **Acquire-By-Hash** on every publication; `publish switch` keeps the
  original layout, so a layout change publishes again.
- **Floating base images** (`python:3-slim`, `ubuntu:26.04`), rebuilt with
  `--pull`; `ubuntu:26.04` because older releases ship aptly 1.5.
