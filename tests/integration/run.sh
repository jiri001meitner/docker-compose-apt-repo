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
     "component": "main", "architectures": ["amd64"], "key_file": "${keys}/upstream.asc",
     "prefix": "ppa/fixture"},
    {"name": "dead", "title": "Dead upstream", "url": "http://127.0.0.1:9", "distribution": "resolute",
     "component": "main", "architectures": ["amd64"], "key_file": "${keys}/upstream.asc",
     "prefix": "dead"}
  ]
}
EOF

unset GNUPGHOME
export PYTHONPATH=/app REPO_SYNC_CONFIG="${work}/mirrors.json" REPO_SYNC_ROOT="${root}"
export REPO_SYNC_SIGNING_KEY="${keys}/signing.asc"
pub="${root}/public"
site="${root}/site"

# repo-sync runs as in production: uid 10200, and with a restrictive umask
# of the caller (it must still publish files the web server can read).
home="${work}/home"
install -d -o 10200 -g 10200 -m 0755 "${root}" "${home}"
chown 10200:10200 "${keys}/signing.asc"
repo_sync() {
   (umask 077; setpriv --reuid=10200 --regid=10200 --clear-groups env HOME="${home}" python3 -m repo_sync "$@")
}
set_mirror() {  # set_mirror <python expression on m (the fixture mirror)>
   python3 - "${work}/mirrors.json" "$1" <<'PY'
import json, sys
path, expr = sys.argv[1], sys.argv[2]
c = json.load(open(path))
m = c["mirrors"][0]
exec(expr)
json.dump(c, open(path, "w"), indent=1)
PY
}

# --- run 1 ------------------------------------------------------------------
repo_sync sync 2>"${work}/sync1.log" || { cat "${work}/sync1.log"; fail "sync 1 exit code"; }
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
# The only ones allowed are aptly's by-hash links to indexes of the same
# distribution (Acquire-By-Hash); packages are hardlinks.
while IFS= read -r link; do
   dist_dir="${link%%/main/*}"
   [[ "${link}" == */by-hash/* && "$(realpath "${link}")" == "${dist_dir}"/* ]] \
      || fail "symlink out of place: ${link} -> $(readlink "${link}")"
done < <(find "${pub}" -type l)
[[ -z "$(find "${pub}" -path '*/pool/*' -type l)" ]] || fail "symlink in pool"
pass "only by-hash symlinks, all inside their distribution"
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
report="$(repo_sync report)"
[[ "${report}" == 1$'\t'"REPO WARNING"* && "${report}" == *"last attempt failed: dead"* ]] \
   || fail "report: ${report}"
pass "report flags dead mirror as WARNING"
if compgen -G "/tmp/repo-sync-gnupg-*" >/dev/null || compgen -G "${root}/repo-sync-gnupg-*" >/dev/null; then
   fail "temporary GNUPGHOME left behind"
fi
pass "no signing key material left on disk"
[[ -z "$(find "${pub}" "${site}" ! -perm -o+r)" ]] || fail "files not readable by the web server"
[[ -z "$(find "${pub}" "${site}" -type d ! -perm -o+x)" ]] || fail "directories not traversable"
pass "published files world-readable despite umask 077"
[[ -z "$(ls -A "${home}")" ]] || fail "repo-sync wrote into HOME: $(ls -A "${home}")"
pass "nothing written to HOME"
grep -q '^Acquire-By-Hash: yes' "${pub}/ppa/fixture/dists/resolute/Release" || fail "no Acquire-By-Hash"
[[ -d "${pub}/ppa/fixture/dists/resolute/main/binary-amd64/by-hash" ]] || fail "no by-hash directory"
pass "indexes published by hash"

# --- run 2: unchanged upstream ---------------------------------------------
before="$(sha256sum "${pub}/ppa/fixture/dists/resolute/InRelease")"
sleep 1
repo_sync sync 2>"${work}/sync2.log" || fail "sync 2 exit code"
grep -q 'mirror fixture: no change' "${work}/sync2.log" || fail "expected no change"
[[ "$(sha256sum "${pub}/ppa/fixture/dists/resolute/InRelease")" == "${before}" ]] || fail "republished unchanged"
pass "unchanged upstream is not republished"

# --- run 3: new upstream version --------------------------------------------
mkpkg hello 1.1 amd64
publish_upstream
sleep 1
repo_sync sync 2>"${work}/sync3.log" || fail "sync 3 exit code"
grep -q 'Version: 1.1' "${pub}/ppa/fixture/dists/resolute/main/binary-amd64/Packages" || fail "1.1 not published"
pass "new upstream version switched in"

# --- run 4: upstream breaks (bad signature) keeps last good ------------------
echo tampered >> "${up}/dists/resolute/Release"
sleep 1
repo_sync sync 2>"${work}/sync4.log" || fail "sync 4 exit code"
grep -q 'mirror fixture:' "${work}/sync4.log" || fail "no error logged for tampered upstream"
grep -q 'Version: 1.1' "${pub}/ppa/fixture/dists/resolute/main/binary-amd64/Packages" || fail "last good lost"
pass "tampered upstream rejected, last good snapshot still served"
publish_upstream

# --- run 5: architectures added -------------------------------------------------
set_mirror 'm["architectures"] = ["amd64", "i386"]'
sleep 1
repo_sync sync 2>"${work}/sync5.log" || fail "sync 5 exit code"
grep -q '^Architectures: amd64 i386\|^Architectures: i386 amd64' "${pub}/ppa/fixture/dists/resolute/Release" \
   || { grep Architectures "${pub}/ppa/fixture/dists/resolute/Release"; fail "i386 not in Release"; }
grep -q '^Package: hello$' "${pub}/ppa/fixture/dists/resolute/main/binary-i386/Packages" || fail "no i386 index"
pass "added architecture is published"
set_mirror 'm["architectures"] = ["amd64"]'
sleep 1
repo_sync sync 2>"${work}/sync5b.log" || fail "sync 5b exit code"
[[ ! -e "${pub}/ppa/fixture/dists/resolute/main/binary-i386" ]] || fail "i386 index still published"
pass "removed architecture is unpublished"

# --- run 6: prefix moved ------------------------------------------------------------
set_mirror 'm["prefix"] = "ppa/moved"'
sleep 1
repo_sync sync 2>"${work}/sync6.log" || fail "sync 6 exit code"
[[ -f "${pub}/ppa/moved/dists/resolute/InRelease" ]] || fail "not published at new prefix"
[[ ! -e "${pub}/ppa/fixture/dists" ]] || fail "old prefix still published"
pass "prefix change moves the publication"

# --- run 7: renamed while upstream is down, then up ---------------------------------
set_mirror 'm["name"] = "renamed"; m["url"] = "http://127.0.0.1:9"'
sleep 1
repo_sync sync 2>"${work}/sync7.log" || fail "sync 7 exit code"
[[ -f "${pub}/ppa/moved/dists/resolute/InRelease" ]] || fail "prefix emptied while successor is down"
pass "renamed mirror with dead upstream keeps the prefix served"
set_mirror 'm["url"] = "http://127.0.0.1:8080"'
sleep 1
repo_sync sync 2>"${work}/sync7b.log" || fail "sync 7b exit code"
grep -q 'Version: 1.1' "${pub}/ppa/moved/dists/resolute/main/binary-amd64/Packages" || fail "successor not published"
grep -q 'mirror fixture removed from config' "${work}/sync7b.log" "${work}/sync7.log" || fail "old mirror not dropped"
pass "successor took over, old mirror dropped"

# --- concurrent run is refused ------------------------------------------------
exec 9>"${root}/.repo-sync.lock"
flock -n 9
rc=0; repo_sync sync 2>/dev/null || rc=$?
[[ "${rc}" == 75 ]] || fail "locked run exit ${rc}"
exec 9>&-
pass "concurrent run refused with 75"

# --- apt client installs from the published repo -----------------------------
install -d -m 0755 /etc/apt/keyrings
cp "${keys}/repo-public.asc" /etc/apt/keyrings/repo-test.asc
cat > /etc/apt/sources.list.d/repo-test.sources <<EOF
Types: deb
URIs: file://${pub}/ppa/moved/
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
