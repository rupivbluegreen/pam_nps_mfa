#!/usr/bin/env bash
#
# check-rpm-install.sh — install-verify a built pam_nps_mfa RPM in a FRESH
# EL-family container (CentOS Stream 9/10 in CI). Confirms the el9/el10
# artifacts install cleanly on CentOS Stream without stream-specific builds.
# Used for local validation and by the verify jobs in release.yml.
#
#       docker run --rm \
#           -v "$PWD/dist-out":/pkg:ro \
#           -v "$(git rev-parse --show-toplevel)":/src:ro \
#           quay.io/centos/centos:stream9 bash /src/packaging/check-rpm-install.sh
#
# Verifies, fail-closed:
#   1. dnf installs the RPM with its declared dependencies
#   2. rpm -V is clean (paths, modes, digests as packaged)
#   3. on-disk modes: pam_nps.conf 0600, secret.d 0700, README 0600, root:root
#   4. the module dlopens and its NEEDED libraries resolve
#
# In a container selinuxenabled is false, so the RPM %post semodule load is a
# deliberate no-op (same as the phase-8 gate); SELinux enforcement is a phase-9
# item on real hardware.
#
set -uo pipefail

PKGDIR="${PKG_DIR:-/pkg}"
DIST="${DIST_TAG:-}"     # e.g. el9 / el10; default: whatever single rpm is present
fail() { echo "FAIL: $*" >&2; echo "==== INSTALL CHECK: FAIL ===="; exit 1; }
step() { echo; echo "### $*"; }

if [ -n "$DIST" ]; then
    RPM=$(ls "$PKGDIR"/pam_nps_mfa-*."$DIST".x86_64.rpm 2>/dev/null | head -1)
else
    RPM=$(ls "$PKGDIR"/pam_nps_mfa-*.x86_64.rpm 2>/dev/null | head -1)
fi
[ -n "$RPM" ] || fail "no pam_nps_mfa binary rpm (dist='$DIST') under $PKGDIR"
echo "checking: $RPM"

########################################
step "1/4 dnf install (resolves declared Requires)"
dnf install -y "$RPM" python3 || fail "dnf install failed"

########################################
step "2/4 rpm -V (packaged paths, modes, digests)"
rpm -V pam_nps_mfa || fail "rpm -V reported deviations"
echo "OK: rpm -V clean"

########################################
step "3/4 verify on-disk modes (module enforces these at runtime)"
chk() { # path want_mode
    got=$(stat -c '%a %U:%G' "$1") || fail "stat $1 failed"
    [ "$got" = "$2 root:root" ] || fail "$1 is '$got', want '$2 root:root'"
    echo "OK: $1 = $got"
}
chk /etc/pam_nps 755
chk /etc/pam_nps/pam_nps.conf 600
chk /etc/pam_nps/secret.d 700
chk /etc/pam_nps/secret.d/README 600

########################################
step "4/4 module loads and NEEDED libraries resolve"
SO=/usr/lib64/security/pam_nps_mfa.so
[ -f "$SO" ] || fail "$SO missing"
ldd "$SO" || fail "ldd failed"
ldd "$SO" | grep -q 'not found' && fail "unresolved NEEDED library:
$(ldd "$SO" | grep 'not found')"
python3 -c "import ctypes; ctypes.CDLL('$SO')" \
    || fail "dlopen of $SO failed"
echo "OK: dlopen succeeded"

echo
echo "==== INSTALL CHECK: OK ($(. /etc/os-release; echo "$ID $VERSION_ID"), $RPM) ===="
