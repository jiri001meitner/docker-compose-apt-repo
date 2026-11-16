# docker-compose APT repository

A token-protected mirror of APT repositories (Caddy, Launchpad PPAs, …)
built on [aptly](https://www.aptly.info/), served by the host Caddy.

```
client (apt, auth.conf.d) ──HTTPS──> Caddy ──forward_auth (UNIX socket)──> repo-auth
                                        │                                      │ reads
                                        └── file_server: aptly/public          export/clients.json
                                                                                ▲ writes (atomic)
repo-sync (systemd timer) ── aptly mirror/snapshot/publish ──> aptly/        repo-admin ── db/ (SQLite)
```

| Service      | Runs                          | Network          | Writes                    |
|--------------|-------------------------------|------------------|---------------------------|
| `repo-auth`  | always (`up -d`)              | none             | only its socket           |
| `repo-admin` | on demand (`run --rm`)        | none             | `db/`, `export/`          |
| `repo-sync`  | timer (`run --rm repo-sync`)  | `br-aptrepo`     | `aptly/`                  |

All containers are `read_only`, drop all capabilities, `no-new-privileges`,
run as non-root users, have memory and PID limits.

## Access control (repo-auth)

Caddy `forward_auth` sends every repository request to `repo-auth`. The
answer is:

| Status | When |
|--------|------|
| 503 | the client list was never loaded (fail closed) |
| 401 | missing/malformed credentials, unknown login, wrong token (with `WWW-Authenticate`) |
| 403 | valid token, but account blocked, subscription expired, method other than GET/HEAD, suspicious path (`..`, `//`, `\`, control chars, double or invalid percent-encoding) or path outside the account's scopes |
| 200 | allowed; `X-Repo-Client` and `X-Repo-Account` are passed on for the access log |

Credentials are checked before anything else, so a wrong token never reveals
whether an account exists, is blocked or expired.

* **Tokens** are random 256-bit values (`repo-admin token add|rotate`) shown
  once. Only their SHA-256 is stored, compared in constant time.
* **Scopes** are path prefixes = publish prefixes (`/caddy/`,
  `/ppa/mozillateam/`, `/` for everything). Finer scopes make no sense:
  `pool/` is shared by the whole prefix, and prefixes may not be nested
  (`ppa` next to `ppa/x` is rejected). Scope is checked on the request path,
  so no symlink may lead across prefixes: packages are hardlinks, the only
  symlinks are aptly's `by-hash/` links to indexes of the same distribution
  (the integration test checks both).
* **Source of truth** is SQLite in `db/`, changed only by `repo-admin`. Every
  change writes `export/clients.json` atomically, under a lock, and only after
  validating it with the same parser `repo-auth` uses (an invalid state fails
  the command instead of being silently ignored).
* **Reload** happens on the next request after the file changes, no restart.
  A broken or deleted export keeps the last good one in effect, and
  `/healthz` returns 503 (container *unhealthy*) until it is fixed. Deleting
  the file therefore does **not** close access; to shut everyone out stop
  `repo-auth` (Caddy then answers 502) or block the accounts.
* **Robustness**: one request per connection, 5 s per read, 10 s per
  connection, at most 32 concurrent requests (then 503). The socket is 0660
  with the reverse proxy group.
* **Logs** never contain tokens; a 401 logs the attempted login (format
  checked) for rate limiting / fail2ban.

### repo-admin

```bash
alias dc="docker compose"
dc run --rm -T repo-admin account add acme --name "ACME s.r.o." --email it@acme.example \
   --scope /caddy --scope /ppa/mozillateam --valid-until 2027-12-31
dc run --rm -T repo-admin token add acme --login acme-web1 --label web1   # prints "login token" once
dc run --rm -T repo-admin account extend acme --days 365   # from max(now, current end)
dc run --rm -T repo-admin account block|unblock acme
dc run --rm -T repo-admin token rotate|revoke acme-web1
dc run --rm -T repo-admin account list ; dc run --rm -T repo-admin token list
```

Automation (own hosts with derived tokens) uses idempotent commands that
print `OK` or `CHANGED`:

```bash
dc run --rm -T repo-admin account ensure linuxadm --name "Own hosts" --scope / --unlimited
printf '%s' '{"host-a": "<token>", "host-b": "<token>"}' | dc run --rm -T repo-admin token sync linuxadm
```

`token sync` manages only tokens it created (label `managed`): it adds and
updates the given ones and revokes its other ones; hand-made tokens on the same
account stay. Its stdin and the output of `token add|rotate` contain secrets
(use `no_log` in Ansible).

Exit codes: 0 ok, 1 error, 2 not found.

## Mirrors (repo-sync)

`config/mirrors.json` (see `config/mirrors.json.example`) lists the mirrors,
each with one `component` (aptly would merge several into one); the
upstream public keys (armored) are in `config/keys/`. The repository signing
key must have no passphrase (it is imported with `--batch`). Decisions are
taken from aptly's real state (`publish list -json`), the state file only
feeds the catalogue and the report, so an interrupted run heals on the next.
One run:

1. `aptly mirror update`, verifying the upstream signature with the mirror's
   key only (a tampered upstream is rejected);
2. snapshot `<mirror>-<UTC timestamp>`; when identical to the published one it
   is dropped, otherwise the publication is switched. Indexes are published
   with `Acquire-By-Hash`, so a client updating during the switch never
   mixes old and new indexes;
3. published Release files are signed with the repository key, which is
   imported into a temporary `GNUPGHOME` for the run only;
4. `keep_snapshots` newest snapshots per mirror are kept for rollback;
5. the catalogue is written to `aptly/site/` (`index.html` in Czech and
   English, `status.json`, `key.asc`), separately from `aptly/public/`.

Mirrors are independent: an unreachable or hanging upstream (Launchpad
outage; `mirror update` may take up to 6 h) leaves its last good snapshot
published and the others continue. Changing a mirror's URL, distribution,
component, architectures or filter recreates the aptly mirror; a different
component or architecture set is published again (`publish switch` keeps
the original layout), with a short gap for that distribution. Changing the
prefix moves the publication. A mirror removed from the config (or renamed)
is dropped only after nothing configured needs its publication, so a
rename while the upstream is down keeps the old content served.

Only the listed architectures are mirrored (`amd64` also brings `all`).
Clients with a foreign architecture (`i386`) must set `Architectures: amd64`
in their source.

```bash
docker compose run --rm repo-sync            # sync + catalogue
docker compose run --rm repo-sync catalog    # catalogue only, no network
docker compose run --rm repo-sync report     # "<status>\t<text>|<perfdata>" for Icinga
```

`report` is WARNING when a mirror has never synced or has not synced for
`stale_warning_hours`, CRITICAL after `stale_critical_hours`. Exit codes of
`sync`: 0 done (see `report` for individual mirrors), 1 configuration or
internal error, 75 another run holds the lock.

## Deployment

1. `cp .env.example .env; chmod 600 .env`, fill in.
2. Directories: `DATA_DIR/db` (REPO_UID, 0700), `DATA_DIR/export` (REPO_UID,
   0755), `DATA_DIR/aptly` (SYNC_UID, 0755), `SOCKET_DIR` (REPO_UID, group
   SOCKET_GID, 2750; on tmpfs `/run` via tmpfiles.d).
3. Signing key (armored secret key) at `SIGNING_KEY_FILE`, owner SYNC_UID,
   mode 0400; `config/mirrors.json` and `config/keys/*.asc`.
4. `docker compose --profile tools build --pull && docker compose up -d repo-auth`
   (a plain `build` skips `repo-sync` and `repo-admin`, which are in the
   `tools` profile; rebuild like this to get base image updates).
5. Caddy site block from `caddy/repo.caddy.example`: catalogue served from
   `aptly/site` without auth, everything else through `forward_auth` from
   `aptly/public` (no `browse`).
6. Timer running `docker compose run --rm repo-sync`; the firewall must allow
   outbound traffic from `br-aptrepo`.

In the linuxadm repository this is done by the Ansible role `apt_repo`.

## Client

```bash
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://repo.example.org/key.asc | sudo tee /etc/apt/keyrings/repo-mordecai.asc >/dev/null
sudo install -m 0600 /dev/null /etc/apt/auth.conf.d/repo-mordecai.conf
printf 'machine repo.example.org\nlogin LOGIN\npassword TOKEN\n' | sudo tee /etc/apt/auth.conf.d/repo-mordecai.conf >/dev/null
```

```
# /etc/apt/sources.list.d/repo-mordecai-caddy.sources
Types: deb
URIs: https://repo.example.org/caddy/
Suites: any-version
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/repo-mordecai.asc
```

## Development and tests

```bash
python -m pytest -q && ruff check . && ruff format --check . && mypy   # unit tests, strict typing
docker build -f docker/aptly.Dockerfile -t apt-repo/aptly:test . \
  && docker build -t apt-repo/aptly-it:test tests/integration \
  && docker run --rm --network none apt-repo/aptly-it:test         # aptly + gpg + apt, offline
tests/e2e/run.sh                                                    # compose + real Caddy, curl matrix
```

CI runs all of them plus ShellCheck and `docker compose config`.
