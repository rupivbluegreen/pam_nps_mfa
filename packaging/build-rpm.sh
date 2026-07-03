#!/usr/bin/env bash
#
# build-rpm.sh — container-agnostic RPM build driver for pam_nps_mfa.
#
# WHAT THIS IS
#   Builds the binary RPM + SRPM from packaging/pam_nps_mfa.spec inside any
#   RHEL9-family or Fedora container and copies the artifacts to /out. It is
#   the RELEASE build driver used by .github/workflows/release.yml; the
#   phase-8 packaging GATE (build + install + placement/permission verify)
#   remains packaging/build-in-ubi9.sh and is unchanged by this script.
#
#   Run it with the repo bind-mounted read-only at /src and an output dir
#   bind-mounted at /out:
#
#       docker run --rm \
#           -v "$(git rev-parse --show-toplevel)":/src:ro \
#           -v "$PWD/dist-out":/out \
#           almalinux:9 bash /src/packaging/build-rpm.sh
#
#   Validated bases: almalinux:9 (el9 — RHEL9/Alma9/Rocky9), almalinux:10
#   (el10), fedora:42 (fc42). On EL bases selinux-policy-devel lives in the
#   CRB repo, which subscription-less ubi images do NOT ship — use AlmaLinux
#   or Rocky, not ubi. Fedora needs no CRB; the enable step is a no-op there.
#
# WHAT IT PRODUCES in /out
#   pam_nps_mfa-<ver>-<rel><dist>.x86_64.rpm   (binary)
#   pam_nps_mfa-<ver>-<rel><dist>.src.rpm      (source)
#
set -uo pipefail

# Paths are overridable so the same script runs under docker (defaults) and
# inside a GitHub Actions container job (SRC_DIR=$GITHUB_WORKSPACE,
# OUT_DIR=$GITHUB_WORKSPACE/out — see .github/workflows/release.yml).
SRC="${SRC_DIR:-/src}"
BUILD="${BUILD_DIR:-/build}"
OUT="${OUT_DIR:-/out}"
RPMTOP=/root/rpmbuild
PKG=pam_nps_mfa

fail() { echo "FAIL: $*" >&2; exit 1; }
step() { echo; echo "### $*"; }

[ -d "$SRC" ] || fail "repo not bind-mounted at $SRC (see docker run in header)"

########################################
step "1/5 install toolchain (dnf)"
# CRB holds selinux-policy-devel on EL; harmless no-op elsewhere. dnf5
# (Fedora 41+) renamed the subcommand, so try both syntaxes.
dnf install -y dnf-plugins-core 2>/dev/null || true
dnf config-manager --set-enabled crb 2>/dev/null \
  || dnf config-manager setopt crb.enabled=1 2>/dev/null \
  || dnf config-manager --set-enabled powertools 2>/dev/null || true
dnf install -y \
    rust cargo pam-devel audit-libs-devel \
    rpm-build selinux-policy-devel policycoreutils make tar gzip \
    || fail "dnf install failed"

########################################
step "2/5 copy repo into writable tree (bind mount is read-only)"
rm -rf "$BUILD"
mkdir -p "$BUILD"
# Exclude build residue a local (non-CI) checkout may carry: the workspace
# target/, the nested fuzz workspace's target/corpus/artifacts, and any
# sockets — none belong in the source rpm.
TAR_EXCLUDES=(
    --exclude=./target --exclude=./.git --exclude=./.cargo
    --exclude=./fuzz/target --exclude=./fuzz/corpus --exclude=./fuzz/artifacts
)
tar -C "$SRC" "${TAR_EXCLUDES[@]}" -cf - . | tar -C "$BUILD" -xf - \
    || fail "copy of repo into $BUILD failed"

# Single source of truth for the version is the spec.
VERSION=$(awk '/^Version:/{print $2; exit}' "$BUILD/packaging/${PKG}.spec")
[ -n "$VERSION" ] || fail "could not read Version: from ${PKG}.spec"
echo "spec version: $VERSION"

########################################
step "3/5 assemble source tarball"
mkdir -p "$RPMTOP"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
# Same layout the phase-8 gate uses: %{name}-%{version}/ prefix, self-contained
# (the .pp is rebuilt inside %build from the .te in the tarball).
tar -C "$BUILD" "${TAR_EXCLUDES[@]}" \
    --transform "s,^\.,${PKG}-${VERSION}," \
    -czf "$RPMTOP/SOURCES/${PKG}-${VERSION}.tar.gz" . \
    || fail "source tarball assembly failed"

########################################
step "4/5 rpmbuild -ba (binary + source rpm)"
rpmbuild -ba --define "_topdir $RPMTOP" "$BUILD/packaging/${PKG}.spec" \
    || fail "rpmbuild failed"

########################################
step "5/5 collect artifacts into $OUT"
mkdir -p "$OUT"
found=0
while IFS= read -r rpm; do
    cp -v "$rpm" "$OUT/" || fail "copy of $rpm to $OUT failed"
    found=1
done < <(find "$RPMTOP/RPMS" "$RPMTOP/SRPMS" -name "${PKG}-${VERSION}-*.rpm")
[ "$found" -eq 1 ] || fail "no rpm produced under $RPMTOP/RPMS or $RPMTOP/SRPMS"

echo
echo "==== BUILD RESULT: OK ===="
ls -l "$OUT"
