#!/usr/bin/env bash
# Offline integration test of repo-sync against real aptly and gpg.
# Runs as root in tests/integration/Dockerfile (aptly image + dpkg-dev):
#   docker build -f docker/aptly.Dockerfile -t apt-repo/aptly:test .
#   docker build -t apt-repo/aptly-it:test tests/integration
#   docker run --rm --network none apt-repo/aptly-it:test
set -Eeuo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

work="$(mktemp -d)"
chmod 0755 "${work}"  # the apt sandbox user (_apt) reads the file: repository
trap 'kill "${http_pid:-0}" 2>/dev/null || true; rm -rf "${work}"' EXIT

up="${work}/upstream"
root="${work}/aptly"
keys="${work}/keys"
mkdir -p "${up}" "${root}" "${keys}"

# --- keys: upstream signing key and our repository key --------------------
upstream_home="${work}/gnupg-upstream"
export GNUPGHOME="${upstream_home}"
install -d -m 0700 "${GNUPGHOME}"
gpg --batch -q --passphrase '' --quick-gen-key 'Upstream <up@test>' ed25519 sign never 2>/dev/null
gpg --batch -q --armor --export > "${keys}/upstream.asc"

repo_home="${work}/gnupg-repo"
install -d -m 0700 "${repo_home}"
GNUPGHOME="${repo_home}" gpg --batch -q --passphrase '' --quick-gen-key 'Repo <repo@test>' ed25519 sign never 2>/dev/null
repo_fpr="$(GNUPGHOME="${repo_home}" gpg --list-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')"
GNUPGHOME="${repo_home}" gpg --batch -q --armor --export-secret-keys "${repo_fpr}" > "${keys}/signing.asc"
chmod 0600 "${keys}/signing.asc"
GNUPGHOME="${repo_home}" gpg --batch -q --armor --export "${repo_fpr}" > "${keys}/repo-public.asc"

# --- fixture upstream: amd64 + i386 + all ----------------------------------
mkpkg() {
   local name="$1" version="$2" arch="$3" dir
   dir="${work}/build/${name}_${version}_${arch}"
   mkdir -p "${dir}/DEBIAN" "${up}/pool"
   printf 'Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: t <t@test>\nDescription: test\n' \
      "${name}" "${version}" "${arch}" > "${dir}/DEBIAN/control"
   dpkg-deb -b "${dir}" "${up}/pool/${name}_${version}_${arch}.deb" >/dev/null
}

publish_upstream() {
   local d="${up}/dists/resolute" arch
   rm -rf "${d}"
   for arch in amd64 i386; do
      mkdir -p "${d}/main/binary-${arch}"
      (cd "${up}" && apt-ftparchive --arch "${arch}" packages pool) > "${d}/main/binary-${arch}/Packages"
   done
   apt-ftparchive -o APT::FTPArchive::Release::Suite=resolute -o APT::FTPArchive::Release::Codename=resolute \
      -o APT::FTPArchive::Release::Architectures='amd64 i386' -o APT::FTPArchive::Release::Components=main \
      release "${d}" > "${work}/Release"
   mv "${work}/Release" "${d}/Release"
   GNUPGHOME="${upstream_home}" gpg --batch -q --yes --clearsign -o "${d}/InRelease" "${d}/Release"
}

mkpkg hello 1.0 amd64
mkpkg hello 1.0 i386
mkpkg hello-data 1.0 all
publish_upstream

python3 -m http.server 8080 --bind 127.0.0.1 -d "${up}" >/dev/null 2>&1 &
http_pid=$!
for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/8080) 2>/dev/null && break; sleep 0.1; done

cat > "${work}/mirrors.json" <<EOF
{
  "gpg_key": "${repo_fpr}",
  "origin": "repo.test", "label": "repo.test", "keep_snapshots": 2,
  "stale_warning_hours": 48, "stale_critical_hours": 168,
  "site_title": "Test <repo>", "base_url": "https://repo.test",
  "mirrors": [
    {"name": "fixture", "title": "Fixture", "url": "http://127.0.0.1:8080", "distribution": "resolute",
     "components": ["main"], "architectures": ["amd64"], "key_file": "${keys}/upstream.asc",
     "prefix": "ppa/fixture"},
    {"name": "dead", "title": "Dead upstream", "url": "http://127.0.0.1:9", "distribution": "resolute",
     "components": ["main"], "architectures": ["amd64"], "key_file": "${keys}/upstream.asc",
     "prefix": "dead"}
  ]
}
EOF

unset GNUPGHOME
export PYTHONPATH=/app REPO_SYNC_CONFIG="${work}/mirrors.json" REPO_SYNC_ROOT="${root}"
export REPO_SYNC_SIGNING_KEY="${keys}/signing.asc"
pub="${root}/public"
site="${root}/site"

# --- run 1 ------------------------------------------------------------------
python3 -m repo_sync sync 2>"${work}/sync1.log" || { cat "${work}/sync1.log"; fail "sync 1 exit code"; }
[[ -f "${pub}/ppa/fixture/dists/resolute/InRelease" ]] || fail "fixture not published"
pass "fixture published under nested prefix"
[[ ! -e "${pub}/dead" ]] || fail "dead mirror must not be published"
pass "unreachable upstream does not publish"
grep -q '^Architecture: i386' "${pub}/ppa/fixture/dists/resolute/main/binary-amd64/Packages" \
   && fail "i386 package leaked into mirror"
[[ -z "$(find "${pub}" -name '*_i386.deb')" ]] || fail "i386 .deb in pool"
grep -q '^Package: hello-data' "${pub}/ppa/fixture/dists/resolute/main/binary-amd64/Packages" \
   || fail "arch:all package missing"
pass "only amd64 + all mirrored"
# Scope is checked on the request path; a symlink could point across scopes.
[[ -z "$(find "${pub}" -type l)" ]] || fail "symlinks in the published tree"
pass "published tree has no symlinks"
grep -q '^Origin: repo.test' "${pub}/ppa/fixture/dists/resolute/Release" || fail "origin not set"
cmp -s <(gpg --dearmor < "${site}/key.asc") <(gpg --dearmor < "${keys}/repo-public.asc") || fail "key.asc differs"
gpg --dearmor < "${keys}/repo-public.asc" > "${keys}/repo-public.gpg"
gpgv --keyring "${keys}/repo-public.gpg" \
   "${pub}/ppa/fixture/dists/resolute/InRelease" 2>"${work}/gpgv.log" || { cat "${work}/gpgv.log"; echo "repo key ${repo_fpr}"; fail "InRelease not signed by repo key"; }
pass "Release signed by repository key, origin set"
for f in index.html status.json key.asc; do [[ -s "${site}/${f}" ]] || fail "missing ${f}"; done
[[ -z "$(find "${pub}" -maxdepth 1 -type f)" ]] || fail "catalogue files inside the repository root"
grep -q 'Test &lt;repo&gt;' "${site}/index.html" || fail "title not escaped"
python3 - "${site}/status.json" <<'PY' || fail "status.json content"
import json, sys
s = {m["name"]: m for m in json.load(open(sys.argv[1]))["mirrors"]}
assert s["fixture"]["packages"] == 2 and not s["fixture"]["last_attempt_failed"], s["fixture"]
assert s["dead"]["last_attempt_failed"] and s["dead"]["last_success"] is None, s["dead"]
PY
pass "catalogue written"
report="$(python3 -m repo_sync report)"
[[ "${report}" == 1$'\t'"REPO WARNING"* && "${report}" == *"last attempt failed: dead"* ]] \
   || fail "report: ${report}"
pass "report flags dead mirror as WARNING"
if compgen -G "/tmp/repo-sync-gnupg-*" >/dev/null || compgen -G "${root}/repo-sync-gnupg-*" >/dev/null; then
   fail "temporary GNUPGHOME left behind"
fi
pass "no signing key material left on disk"

# --- run 2: unchanged upstream ---------------------------------------------
before="$(sha256sum "${pub}/ppa/fixture/dists/resolute/InRelease")"
sleep 1
python3 -m repo_sync sync 2>"${work}/sync2.log" || fail "sync 2 exit code"
grep -q 'mirror fixture: no change' "${work}/sync2.log" || fail "expected no change"
[[ "$(sha256sum "${pub}/ppa/fixture/dists/resolute/InRelease")" == "${before}" ]] || fail "republished unchanged"
pass "unchanged upstream is not republished"

# --- run 3: new upstream version --------------------------------------------
mkpkg hello 1.1 amd64
publish_upstream
sleep 1
python3 -m repo_sync sync 2>"${work}/sync3.log" || fail "sync 3 exit code"
grep -q 'Version: 1.1' "${pub}/ppa/fixture/dists/resolute/main/binary-amd64/Packages" || fail "1.1 not published"
pass "new upstream version switched in"

# --- run 4: upstream breaks (bad signature) keeps last good ------------------
echo tampered >> "${up}/dists/resolute/Release"
sleep 1
python3 -m repo_sync sync 2>"${work}/sync4.log" || fail "sync 4 exit code"
grep -q 'mirror fixture:' "${work}/sync4.log" || fail "no error logged for tampered upstream"
grep -q 'Version: 1.1' "${pub}/ppa/fixture/dists/resolute/main/binary-amd64/Packages" || fail "last good lost"
pass "tampered upstream rejected, last good snapshot still served"

# --- concurrent run is refused ------------------------------------------------
exec 9>"${root}/.repo-sync.lock"
flock -n 9
rc=0; python3 -m repo_sync sync 2>/dev/null || rc=$?
[[ "${rc}" == 75 ]] || fail "locked run exit ${rc}"
exec 9>&-
pass "concurrent run refused with 75"

# --- apt client installs from the published repo -----------------------------
install -d -m 0755 /etc/apt/keyrings
cp "${keys}/repo-public.asc" /etc/apt/keyrings/repo-test.asc
cat > /etc/apt/sources.list.d/repo-test.sources <<EOF
Types: deb
URIs: file://${pub}/ppa/fixture/
Suites: resolute
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/repo-test.asc
EOF
mv /etc/apt/sources.list.d/ubuntu.sources /etc/apt/ubuntu.sources.off 2>/dev/null || true
apt-get -o Dir::Etc::SourceParts=/etc/apt/sources.list.d -q update >"${work}/apt.log" 2>&1 \
   || { cat "${work}/apt.log"; fail "apt update"; }
grep -qi 'not signed\|NO_PUBKEY\|insecure' "${work}/apt.log" && fail "apt signature warning"
apt-get install -y -q hello hello-data >>"${work}/apt.log" 2>&1 || { cat "${work}/apt.log"; fail "apt install"; }
[[ "$(dpkg-query -W -f='${Version}' hello)" == 1.1 ]] || fail "wrong version installed"
pass "apt verifies signature and installs hello 1.1"

echo "ALL OK"
