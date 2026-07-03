#!/usr/bin/env bash
#
# check-deb-install.sh — install-verify a built pam-nps-mfa .deb in a FRESH
# Ubuntu container of the matching series. Used for local validation and by
# the verify jobs in .github/workflows/release.yml.
#
#       docker run --rm \
#           -v "$PWD/dist-out":/pkg:ro \
#           -v "$(git rev-parse --show-toplevel)":/src:ro \
#           ubuntu:24.04 bash /src/packaging/check-deb-install.sh
#
# Verifies, fail-closed (any miss is a hard FAIL):
#   1. the .deb installs with its declared dependencies (apt resolves them)
#   2. on-disk modes match what the module enforces at runtime:
#      pam_nps.conf 0600, secret.d 0700, secret.d/README 0600, all root:root
#   3. every NEEDED library of pam_nps_mfa.so resolves (ldd, no "not found")
#   4. libpam actually loads the module: pamtester against a throwaway
#      service; missing config must deny with PAM_AUTHINFO_UNAVAIL
#
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive

PKGDIR="${PKG_DIR:-/pkg}"
fail() { echo "FAIL: $*" >&2; echo "==== INSTALL CHECK: FAIL ===="; exit 1; }
step() { echo; echo "### $*"; }

. /etc/os-release
SERIES="${ID}${VERSION_ID}"
DEB=$(ls "$PKGDIR"/pam-nps-mfa_*"+${SERIES}"_amd64.deb 2>/dev/null | head -1)
[ -n "$DEB" ] || fail "no pam-nps-mfa_*+${SERIES}_amd64.deb under $PKGDIR"
echo "checking: $DEB"

########################################
step "1/4 install the .deb via apt (resolves declared Depends)"
apt-get update -q || fail "apt-get update failed"
apt-get install -y -q --no-install-recommends "$DEB" pamtester \
    || fail "apt-get install of the .deb (or pamtester) failed"

########################################
step "2/4 verify on-disk modes (module enforces these at runtime)"
chk() { # path want_mode want_owner
    got=$(stat -c '%a %U:%G' "$1") || fail "stat $1 failed (not installed?)"
    [ "$got" = "$2 root:root" ] || fail "$1 is '$got', want '$2 root:root'"
    echo "OK: $1 = $got"
}
chk /etc/pam_nps 755
chk /etc/pam_nps/pam_nps.conf 600
chk /etc/pam_nps/secret.d 700
chk /etc/pam_nps/secret.d/README 600

########################################
step "3/4 verify the module's dynamic dependencies resolve"
SO=$(dpkg -L pam-nps-mfa | grep '/pam_nps_mfa\.so$') || fail "module .so not in package file list"
[ -f "$SO" ] || fail "$SO missing on disk"
echo "module: $SO"
ldd "$SO" || fail "ldd failed"
ldd "$SO" | grep -q 'not found' && fail "unresolved NEEDED library:
$(ldd "$SO" | grep 'not found')"

########################################
step "4/4 libpam load test (pamtester, throwaway service, fail-closed)"
# Missing config must deny with PAM_AUTHINFO_UNAVAIL — same assertion as the
# phase-5 dev smoke (packaging/dev/pamtester-smoke.sh). This proves dlopen,
# symbol resolution, and the fail-closed path with no RADIUS server involved.
printf 'auth required pam_nps_mfa.so config=/nonexistent/pam_nps.conf\n' \
    > /etc/pam.d/pam_nps_check
out=$(printf 'x\n' | pamtester -v pam_nps_check testuser authenticate 2>&1); rc=$?
rm -f /etc/pam.d/pam_nps_check
echo "$out"
[ "$rc" -ne 0 ] || fail "pamtester unexpectedly succeeded (fail-open!)"
grep -qi 'cannot retrieve authentication info\|information is unavailable' <<<"$out" \
    || fail "expected PAM_AUTHINFO_UNAVAIL wording, got rc=$rc: $out"

echo
echo "==== INSTALL CHECK: OK ($SERIES) ===="
