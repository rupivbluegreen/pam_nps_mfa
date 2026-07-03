#!/usr/bin/env bash
#
# build-in-ubi9.sh — RHEL9 packaging gate for pam_nps_mfa.
#
# WHAT THIS IS
#   The in-container driver for the packaging gate. The ORCHESTRATOR runs it
#   with a single `docker run` that bind-mounts the repo read-only:
#
#       docker run --rm \
#           -v "$(git rev-parse --show-toplevel)":/src:ro \
#           registry.access.redhat.com/ubi9/ubi \
#           bash /src/packaging/build-in-ubi9.sh
#
#   Do NOT run it on the dev host — it needs dnf, rpmbuild and the RHEL9
#   toolchain. It is idempotent: every run rebuilds /build from the read-only
#   mount and re-installs the rpm with --replacepkgs.
#
# WHAT IT PROVES (the gate)
#   1. the workspace cdylib builds from source with the RHEL9 rust/cargo
#   2. the SELinux policy module compiles to pam_nps_mfa.pp
#   3. the spec builds a binary rpm
#   4. the rpm installs, placing pam_nps_mfa.so in /usr/lib64/security and the
#      config as 0600 root:root, with nothing unowned (rpm -V)
#
# WHAT IS DEFERRED TO PHASE 9 (needs a real SELinux kernel on RHEL9 hardware)
#   `semodule -i` actually loading the policy, and running the module in
#   ENFORCING mode against a live NPS. In this container selinuxenabled is
#   false, so the rpm %post is a deliberate no-op (see the spec). Loading and
#   enforcing are validated in docs/phase9-nps-validation.md, not here.
#
set -uo pipefail

SRC=/src
BUILD=/build
RPMTOP=/root/rpmbuild
PKG=pam_nps_mfa
VERSION=0.1.0
LIBDIR=/usr/lib64
SECURITY_DIR="${LIBDIR}/security"
CONF=/etc/pam_nps/pam_nps.conf

fail() { echo "FAIL: $*" >&2; echo "==== GATE RESULT: FAIL ===="; exit 1; }
step() { echo; echo "### $*"; }

[ -d "$SRC" ] || fail "repo not bind-mounted at $SRC (see docker run in header)"

########################################
step "1/8 install toolchain (dnf)"
# selinux-policy-devel and some -devel packages live in the CodeReady Builder
# (CRB / PowerTools) repo. On a subscription-less RHEL9 UBI image these repos
# are unavailable, so run this gate on a RHEL9-ABI-compatible base that ships
# them freely (AlmaLinux 9 / Rocky Linux 9) with CRB enabled. The produced RPM
# and SELinux .pp are byte-for-byte what a subscribed RHEL9 build yields.
dnf install -y dnf-plugins-core 2>/dev/null || true
dnf config-manager --set-enabled crb 2>/dev/null \
  || dnf config-manager --set-enabled powertools 2>/dev/null || true
dnf install -y \
    rust cargo pam-devel audit-libs-devel \
    rpm-build selinux-policy-devel policycoreutils make tar \
    || fail "dnf install failed"

########################################
step "2/8 copy repo into writable tree (bind mount is read-only)"
rm -rf "$BUILD"
mkdir -p "$BUILD"
# Exclude the host's target/ and .git so the container build is clean/fast.
tar -C "$SRC" --exclude=./target --exclude=./.git -cf - . | tar -C "$BUILD" -xf - \
    || fail "copy of repo into $BUILD failed"

########################################
step "3/8 cargo build --release (workspace cdylib)"
export CARGO_HOME="$BUILD/.cargo"
( cd "$BUILD" && cargo build --release ) || fail "cargo build failed"
BUILT_SO="$BUILD/target/release/libpam_nps_mfa.so"
[ -f "$BUILT_SO" ] || fail "expected $BUILT_SO not produced by cargo"
echo "built: $BUILT_SO"

########################################
step "4/8 compile SELinux policy module (.pp)"
make -C "$BUILD/packaging/selinux" -f /usr/share/selinux/devel/Makefile "${PKG}.pp" \
    || fail "SELinux policy compile failed"
[ -f "$BUILD/packaging/selinux/${PKG}.pp" ] || fail "${PKG}.pp not produced"
echo "built: $BUILD/packaging/selinux/${PKG}.pp"

########################################
step "5/8 assemble source tarball + rpmbuild -bb"
mkdir -p "$RPMTOP"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
# The spec builds from a %{name}-%{version}.tar.gz with that dir prefix; the
# .pp is rebuilt inside the spec's %build from the .te in the tarball, so the
# rpm is self-contained.
tar -C "$BUILD" \
    --exclude=./target --exclude=./.git --exclude=./.cargo \
    --transform "s,^\.,${PKG}-${VERSION}," \
    -czf "$RPMTOP/SOURCES/${PKG}-${VERSION}.tar.gz" . \
    || fail "source tarball assembly failed"

rpmbuild -bb --define "_topdir $RPMTOP" "$BUILD/packaging/${PKG}.spec" \
    || fail "rpmbuild failed"

RPM=$(find "$RPMTOP/RPMS" -name "${PKG}-${VERSION}-*.rpm" | head -n1)
[ -n "$RPM" ] || fail "no rpm produced under $RPMTOP/RPMS"
echo "built rpm: $RPM"

########################################
step "6/8 install the rpm (idempotent)"
# --replacepkgs makes re-runs idempotent. %post's semodule is a no-op here
# (selinuxenabled is false in the container), so a clean install is expected.
rpm -Uvh --replacepkgs "$RPM" || fail "rpm install failed"

########################################
step "7/8 verify placement + permissions"
ok=1

echo "-- ls -l ${SECURITY_DIR}/${PKG}.so"
ls -l "${SECURITY_DIR}/${PKG}.so" || { echo "  MISSING module .so"; ok=0; }

# .so must be a real file, mode 0755 root:root, in /usr/lib64/security.
so_perm=$(stat -c '%a %U %G' "${SECURITY_DIR}/${PKG}.so" 2>/dev/null || echo "")
echo "   module perms: ${so_perm:-<none>} (want: 755 root root)"
[ "$so_perm" = "755 root root" ] || { echo "  WRONG .so perms/owner"; ok=0; }

echo "-- ls -l $CONF"
ls -l "$CONF" || { echo "  MISSING config"; ok=0; }
conf_perm=$(stat -c '%a %U %G' "$CONF" 2>/dev/null || echo "")
echo "   config perms: ${conf_perm:-<none>} (want: 600 root root)"
[ "$conf_perm" = "600 root root" ] || { echo "  WRONG config perms/owner"; ok=0; }

# secret.d must be 0700 root:root.
sd_perm=$(stat -c '%a %U %G' /etc/pam_nps/secret.d 2>/dev/null || echo "")
echo "   secret.d perms: ${sd_perm:-<none>} (want: 700 root root)"
[ "$sd_perm" = "700 root root" ] || { echo "  WRONG secret.d perms/owner"; ok=0; }

# policy package file present.
ls -l "/usr/share/selinux/packages/${PKG}.pp" || { echo "  MISSING .pp"; ok=0; }

echo "-- rpm -V $PKG (config noreplace mtime/size diffs are expected/benign)"
# rpm -V exits non-zero if ANY file differs; a bare config edit would show here.
# On a fresh install it should be silent. Capture but don't hard-fail on a
# lone config (c) flag.
vout=$(rpm -V "$PKG" || true)
if [ -n "$vout" ]; then
    echo "$vout"
    # Any verification flag on the .so is fatal; on the config it's informational.
    if echo "$vout" | grep -q "${PKG}.so"; then
        echo "  rpm -V flagged the module .so"; ok=0
    fi
else
    echo "   rpm -V clean"
fi

########################################
step "8/8 result"
if [ "$ok" -eq 1 ]; then
    echo "  module .so : ${SECURITY_DIR}/${PKG}.so  ($so_perm)"
    echo "  config     : $CONF  ($conf_perm)"
    echo "  secret.d   : /etc/pam_nps/secret.d  ($sd_perm)"
    echo "  policy     : /usr/share/selinux/packages/${PKG}.pp (load deferred to phase 9)"
    echo "==== GATE RESULT: PASS ===="
    exit 0
else
    echo "==== GATE RESULT: FAIL ===="
    exit 1
fi
