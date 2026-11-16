#!/usr/bin/env bash
# End-to-end: compose repo-auth + repo-admin behind a real Caddy (container),
# request matrix with curl. Needs docker with compose; run from the project root.
set -Eeuo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

project="aptrepo-e2e-$$"
work="$(mktemp -d)"
chmod 0755 "${work}"
cleanup() {
   docker rm -f "${project}-caddy" >/dev/null 2>&1 || true
   docker compose -p "${project}" --env-file "${work}/.env" down -v >/dev/null 2>&1 || true
   rm -rf "${work}"
}
trap cleanup EXIT

data="${work}/data"
mkdir -p "${data}/db" "${data}/export" "${data}/aptly/public/caddy/dists/any-version" \
   "${data}/aptly/public/ppa/other/dists/resolute" "${data}/aptly/site" "${work}/run"
chmod 2750 "${work}/run"
echo release > "${data}/aptly/public/caddy/dists/any-version/Release"
echo secret > "${data}/aptly/public/ppa/other/dists/resolute/Release"
echo catalogue > "${data}/aptly/site/index.html"
echo key > "${data}/aptly/site/key.asc"
: > "${work}/signing.asc"

cat > "${work}/.env" <<ENV
DATA_DIR=${data}
REPO_UID=$(id -u)
SOCKET_GID=$(id -g)
SOCKET_DIR=${work}/run
SIGNING_KEY_FILE=${work}/signing.asc
ENV

dc() { docker compose -p "${project}" --env-file "${work}/.env" "$@"; }
dc build -q repo-auth
dc up -d repo-auth
admin() { dc run --rm -T repo-admin "$@"; }
admin account add acme --name ACME --scope /caddy --unlimited >/dev/null
read -r login token < <(admin token add acme --login acme-web1)
admin account add gone --name Gone --scope / --valid-until 2000-01-01 >/dev/null
read -r old_login old_token < <(admin token add gone --login gone-one)

for _ in $(seq 50); do [[ -S "${work}/run/auth.sock" ]] && break; sleep 0.2; done
[[ -S "${work}/run/auth.sock" ]] || { dc logs repo-auth; fail "socket not created"; }
[[ "$(stat -c '%a %g' "${work}/run/auth.sock")" == "660 $(id -g)" ]] || fail "socket mode/group"
pass "socket 0660 with the proxy group"

sed -e "s|repo.example.org|:8080|" -e "s|/srv/apt-repo|/data|g" -e "s|/run/repo-auth|/sock|" \
   caddy/repo.caddy.example > "${work}/Caddyfile"
printf '{\n\tadmin off\n\tauto_https off\n}\n' | cat - "${work}/Caddyfile" > "${work}/Caddyfile.full"
docker run -d --name "${project}-caddy" -p 127.0.0.1::8080 \
   -v "${work}/Caddyfile.full:/etc/caddy/Caddyfile:ro" -v "${data}:/data:ro" -v "${work}/run:/sock" \
   caddy:latest >/dev/null
port="$(docker port "${project}-caddy" 8080/tcp | head -1 | sed 's/.*://')"
base="http://127.0.0.1:${port}"
for _ in $(seq 50); do curl -s -o /dev/null "${base}/" && break; sleep 0.2; done

code() { curl -s -o /dev/null -w '%{http_code}' --path-as-is "$@"; }
expect() {
   local want="$1" name="$2"; shift 2
   local got; got="$(code "$@")"
   [[ "${got}" == "${want}" ]] || fail "${name}: expected ${want}, got ${got}"
   pass "${name} -> ${want}"
}
ok_auth=(-u "${login}:${token}")
expect 200 "catalogue without credentials" "${base}/"
expect 200 "key without credentials" "${base}/key.asc"
expect 401 "repository without credentials" "${base}/caddy/dists/any-version/Release"
expect 401 "wrong token" -u "${login}:$(printf 'x%.0s' {1..43})" "${base}/caddy/dists/any-version/Release"
expect 200 "valid token in scope" "${ok_auth[@]}" "${base}/caddy/dists/any-version/Release"
expect 403 "valid token outside scope" "${ok_auth[@]}" "${base}/ppa/other/dists/resolute/Release"
expect 403 "traversal" "${ok_auth[@]}" "${base}/caddy/../ppa/other/dists/resolute/Release"
expect 403 "encoded traversal" "${ok_auth[@]}" "${base}/caddy/%2e%2e/ppa/other/dists/resolute/Release"
expect 403 "encoded slash traversal" "${ok_auth[@]}" "${base}/caddy%2f..%2fppa/other/dists/resolute/Release"
expect 403 "POST" -X POST "${ok_auth[@]}" "${base}/caddy/dists/any-version/Release"
expect 403 "expired account" -u "${old_login}:${old_token}" "${base}/caddy/dists/any-version/Release"
expect 401 "spoofed X-Forwarded-Uri" -H "X-Forwarded-Uri: /caddy/x" "${base}/ppa/other/dists/resolute/Release"
expect 200 "dot segments are cleaned onto the public catalogue" "${base}/caddy/../index.html"
expect 404 "catalogue is not inside the repository root" "${ok_auth[@]}" "${base}/caddy/index.html"
expect 403 "other prefix outside scope" "${ok_auth[@]}" "${base}/ppa/other/x"

body="$(curl -s "${ok_auth[@]}" "${base}/caddy/dists/any-version/Release")"
[[ "${body}" == release ]] || fail "wrong body"
headers="$(curl -s -D - -o /dev/null "${base}/caddy/dists/any-version/Release")"
grep -qi '^www-authenticate: Basic realm=' <<<"${headers}" || fail "WWW-Authenticate missing"
grep -qi '^server:' <<<"${headers}" && fail "Server header leaks"
pass "401 carries WWW-Authenticate, no Server header"

admin account block acme >/dev/null
sleep 0.2
expect 403 "blocked account (export reload without restart)" "${ok_auth[@]}" "${base}/caddy/dists/any-version/Release"
admin account unblock acme >/dev/null
read -r _ new_token < <(admin token rotate acme-web1)
expect 401 "old token after rotate" "${ok_auth[@]}" "${base}/caddy/dists/any-version/Release"
expect 200 "new token after rotate" -u "${login}:${new_token}" "${base}/caddy/dists/any-version/Release"

docker logs "${project}-caddy" >"${work}/caddy.log" 2>&1
dc logs repo-auth >"${work}/auth.log" 2>&1
if grep -qF -e "${token}" -e "${new_token}" "${work}/auth.log" "${work}/caddy.log"; then fail "token in logs"; fi
pass "no token in logs"

[[ "$(docker inspect -f '{{.State.Health.Status}}' "$(dc ps -q repo-auth)")" == healthy ]] \
   || { sleep 31; [[ "$(docker inspect -f '{{.State.Health.Status}}' "$(dc ps -q repo-auth)")" == healthy ]]; } \
   || fail "repo-auth not healthy"
pass "repo-auth healthy"
echo "ALL OK"
