#!/usr/bin/env bash
#
# build-deb.sh — container-agnostic .deb build driver for pam_nps_mfa.
#
# WHAT THIS IS
#   Builds the binary .deb inside an Ubuntu container and copies it to /out.
#   It is the Ubuntu counterpart of build-rpm.sh and is used by
#   .github/workflows/release.yml. The phase-8 packaging GATE remains
#   packaging/build-in-ubi9.sh (RPM/SELinux, RHEL9) and is unchanged.
#
#       docker run --rm \
#           -v "$(git rev-parse --show-toplevel)":/src:ro \
#           -v "$PWD/dist-out":/out \
#           ubuntu:24.04 bash /src/packaging/build-deb.sh
#
#   Validated bases: ubuntu:22.04, ubuntu:24.04.
#
# TOOLCHAIN NOTE
#   The workspace Cargo.lock is lockfile v4, which needs cargo >= 1.78. Both
#   the jammy and noble archives ship older cargo, so this driver installs a
#   PINNED rustup toolchain (RUST_VERSION below) instead of distro rust. It
#   never regenerates Cargo.lock: the build runs with --locked.
#
# PACKAGE LAYOUT (mirrors the RPM spec %install exactly — the module enforces
# these modes at runtime, so the package MUST install them correctly)
#   <pam-multiarch-dir>/pam_nps_mfa.so                 0755 root:root
#   /etc/pam_nps/pam_nps.conf   (conffile)             0600 root:root
#   /etc/pam_nps/secret.d/                             0700 root:root
#   /etc/pam_nps/secret.d/README                       0600 root:root
#   /usr/share/doc/pam-nps-mfa/  (snippets + copyright)
#   No SELinux content: not applicable on Ubuntu (no AppArmor profile either,
#   by design, for now).
#
# WHAT IT PRODUCES in /out
#   pam-nps-mfa_<ver>+<series>_amd64.deb    e.g. 0.1.0~alpha.1+ubuntu22.04
#
set -uo pipefail

SRC="${SRC_DIR:-/src}"
BUILD="${BUILD_DIR:-/build}"
OUT="${OUT_DIR:-/out}"
RUST_VERSION="${RUST_VERSION:-1.85.0}"
PKGNAME=pam-nps-mfa
export DEBIAN_FRONTEND=noninteractive

fail() { echo "FAIL: $*" >&2; exit 1; }
step() { echo; echo "### $*"; }

[ -d "$SRC" ] || fail "repo not bind-mounted at $SRC (see docker run in header)"

########################################
step "1/6 install build dependencies (apt)"
apt-get update -q || fail "apt-get update failed"
apt-get install -y -q --no-install-recommends \
    build-essential libpam0g-dev libaudit-dev \
    ca-certificates curl \
    || fail "apt-get install failed"
# Record why distro rust is not used (see TOOLCHAIN NOTE).
echo "archive cargo would have been:"
apt-cache policy cargo | sed -n '1,3p' || true

########################################
step "2/6 install pinned rust toolchain (rustup $RUST_VERSION)"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain "$RUST_VERSION" \
    || fail "rustup install failed"
export PATH="$HOME/.cargo/bin:$PATH"
cargo --version

########################################
step "3/6 copy repo into writable tree and cargo build --release --locked"
rm -rf "$BUILD"
mkdir -p "$BUILD"
tar -C "$SRC" \
    --exclude=./target --exclude=./.git --exclude=./.cargo \
    --exclude=./fuzz/target --exclude=./fuzz/corpus --exclude=./fuzz/artifacts \
    -cf - . | tar -C "$BUILD" -xf - \
    || fail "copy of repo into $BUILD failed"

( cd "$BUILD" && cargo build --release --locked ) || fail "cargo build failed"
BUILT_SO="$BUILD/target/release/libpam_nps_mfa.so"
[ -f "$BUILT_SO" ] || fail "expected $BUILT_SO after build"

########################################
step "4/6 determine version and PAM module directory"
# Version: CI passes the tag via PKG_VERSION (e.g. v0.1.0-alpha.1). Strip the
# leading v and translate hyphens to '~' (Debian pre-release ordering). If
# PKG_VERSION is unset or not version-shaped (workflow_dispatch passes a
# branch name), fall back to the RPM spec's Version: — single source of truth.
RAW="${PKG_VERSION:-}"
RAW="${RAW#v}"
case "$RAW" in
    [0-9]*) BASE_VERSION="${RAW//-/\~}" ;;
    *) BASE_VERSION=$(awk '/^Version:/{print $2; exit}' "$BUILD/packaging/pam_nps_mfa.spec")
       [ -n "$BASE_VERSION" ] || fail "could not read Version: from spec" ;;
esac
. /etc/os-release
SERIES="${ID}${VERSION_ID}"          # e.g. ubuntu22.04
DEB_VERSION="${BASE_VERSION}+${SERIES}"
echo "deb version: $DEB_VERSION"

# PAM module dir: ask dpkg where pam_unix.so lives instead of hardcoding the
# multiarch path (it moved to /usr/lib/... on usrmerged series).
PAMDIR=$(dirname "$(dpkg -L libpam-modules | grep -m1 '/pam_unix\.so$')") \
    || fail "could not locate pam_unix.so via dpkg -L libpam-modules"
[ -n "$PAMDIR" ] || fail "empty PAM module dir"
echo "PAM module dir: $PAMDIR"

# Runtime dependency package names must exist in this series.
for dep in libpam0g libaudit1; do
    apt-cache show "$dep" >/dev/null 2>&1 || fail "runtime dep $dep not found in $SERIES"
done

########################################
step "5/6 stage package tree and dpkg-deb --build"
PKGROOT="$BUILD/pkgroot"
rm -rf "$PKGROOT"
install -d -m 0755 "$PKGROOT/DEBIAN" "$PKGROOT$PAMDIR" \
    "$PKGROOT/etc" "$PKGROOT/usr/share/doc/$PKGNAME"

# Module (lib prefix stripped, as in the RPM), stripped of debug symbols.
install -m 0755 "$BUILT_SO" "$PKGROOT$PAMDIR/pam_nps_mfa.so"
strip --strip-unneeded "$PKGROOT$PAMDIR/pam_nps_mfa.so" || fail "strip failed"

# Live config tree — same files and modes as the RPM %install.
install -d -m 0755 "$PKGROOT/etc/pam_nps"
install -m 0600 "$BUILD/packaging/dist/pam_nps.conf.sample" \
    "$PKGROOT/etc/pam_nps/pam_nps.conf"
install -d -m 0700 "$PKGROOT/etc/pam_nps/secret.d"
install -m 0600 "$BUILD/packaging/dist/secret.d-README" \
    "$PKGROOT/etc/pam_nps/secret.d/README"

# Docs: deployment snippets + license + README.
install -m 0644 "$BUILD/packaging/dist/pam_nps.conf.sample" \
    "$BUILD/packaging/dist/pam.d-sshd.snippet" \
    "$BUILD/packaging/dist/sshd_config.snippet" \
    "$BUILD/README.md" \
    "$PKGROOT/usr/share/doc/$PKGNAME/"
install -m 0644 "$BUILD/LICENSE" "$PKGROOT/usr/share/doc/$PKGNAME/copyright"

printf '/etc/pam_nps/pam_nps.conf\n' > "$PKGROOT/DEBIAN/conffiles"

INSTALLED_SIZE=$(du -sk --exclude=DEBIAN "$PKGROOT" | cut -f1)
cat > "$PKGROOT/DEBIAN/control" <<EOF
Package: $PKGNAME
Version: $DEB_VERSION
Architecture: amd64
Maintainer: rupivbluegreen <arunbharadwaj13@gmail.com>
Installed-Size: $INSTALLED_SIZE
Depends: libpam0g, libaudit1, libc6
Section: admin
Priority: optional
Homepage: https://github.com/rupivbluegreen/pam_nps_mfa
Description: PAM RADIUS client for Microsoft NPS MFA (pre-release)
 PAM authentication module that turns a Linux host into a hardened RADIUS
 client for Microsoft NPS with the Entra MFA extension (MSCHAPv2 primary,
 PAP optional). Fails closed on every error path.
 .
 PRE-RELEASE: validation against a real NPS (phase 9) has not been
 completed. Do not deploy to production. Read the security notes in the
 README before wiring this into any PAM stack.
EOF

mkdir -p "$OUT"
DEB="$OUT/${PKGNAME}_${DEB_VERSION}_amd64.deb"
dpkg-deb --build --root-owner-group "$PKGROOT" "$DEB" || fail "dpkg-deb failed"

########################################
step "6/6 verify archive contents and modes"
dpkg-deb --info "$DEB"
LISTING=$(dpkg-deb --contents "$DEB")
echo "$LISTING"
echo "$LISTING" | grep -Eq -- '-rw-------.*root/root.*\./etc/pam_nps/pam_nps\.conf$' \
    || fail "pam_nps.conf is not 0600 root:root in the archive"
echo "$LISTING" | grep -Eq -- 'drwx------.*root/root.*\./etc/pam_nps/secret\.d/$' \
    || fail "secret.d/ is not 0700 root:root in the archive"
echo "$LISTING" | grep -Eq -- '-rw-------.*root/root.*\./etc/pam_nps/secret\.d/README$' \
    || fail "secret.d/README is not 0600 root:root in the archive"
echo "$LISTING" | grep -Eq -- "-rwxr-xr-x.*root/root.*\.$PAMDIR/pam_nps_mfa\.so$" \
    || fail "pam_nps_mfa.so is not 0755 root:root in the archive"

echo
echo "==== BUILD RESULT: OK ===="
ls -l "$OUT"
