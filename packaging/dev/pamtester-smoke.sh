#!/usr/bin/env bash
# Dev-only pamtester smoke test for pam_nps_mfa (phase 5 gate, richer than the
# in-tree dlopen symbol test: this drives the real pam_sm_authenticate through
# libpam with a real pam handle).
#
# MUST be run as root (it writes a DEDICATED service file under /etc/pam.d/).
# It NEVER touches common-auth, sshd, sudo, login, or any real stack — only a
# brand-new service named pam_nps_test — and removes it on exit. System auth is
# untouched.
#
#   sudo bash packaging/dev/pamtester-smoke.sh
#
# It exercises the return-code cases that need no live RADIUS server:
#   - missing config file        -> module denies with PAM_AUTHINFO_UNAVAIL
#   - group/other-readable config-> permissive file denies (PAM_AUTHINFO_UNAVAIL)
#   - empty password             -> PAM_AUTH_ERR
# Full accept/deny against a responder is the phase-6 loopback test.
set -u

if [[ $EUID -ne 0 ]]; then
  echo "must run as root (writes /etc/pam.d/pam_nps_test)" >&2
  exit 2
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SO="$REPO/target/release/libpam_nps_mfa.so"
SERVICE=pam_nps_test
SVC_FILE="/etc/pam.d/$SERVICE"
WORK="$(mktemp -d)"
STUB_CONF="$WORK/pam_nps.conf"

cleanup() { rm -f "$SVC_FILE"; rm -rf "$WORK"; }
trap cleanup EXIT

if [[ ! -f "$SO" ]]; then
  echo "build first: (cd $REPO && cargo build --release)" >&2
  exit 2
fi
if ! command -v pamtester >/dev/null; then
  echo "pamtester not installed (apt-get install -y pamtester)" >&2
  exit 2
fi

pass=0 fail=0
check() { # desc expected_substr actual_rc actual_out
  local desc="$1" want="$2" rc="$3" out="$4"
  if grep -qi "$want" <<<"$out"; then
    echo "PASS: $desc (pamtester: ${out##*$'\n'})"; ((pass++))
  else
    echo "FAIL: $desc — expected /$want/, got rc=$rc: $out"; ((fail++))
  fi
}

# The trailing pam_deny guarantees the stack denies if our module ever returns
# PAM_IGNORE/misbehaves, so a PASS reflects OUR module's decision, not a
# fallthrough accept.
write_service() { # config_path
  cat >"$SVC_FILE" <<EOF
auth     required  $SO  config=$1  debug
auth     required  pam_deny.so
account  required  pam_permit.so
EOF
}

# 1) missing config -> PAM_AUTHINFO_UNAVAIL (pamtester prints the pam_strerror)
write_service "$WORK/does-not-exist.conf"
out=$(printf 'x\n' | pamtester -v "$SERVICE" testuser authenticate 2>&1); rc=$?
check "missing config -> AUTHINFO_UNAVAIL" "information is unavailable\|authentication information" "$rc" "$out"

# 2) permissive (group/other-readable) config -> AUTHINFO_UNAVAIL
cat >"$STUB_CONF" <<EOF
server 127.0.0.1:1812 $WORK/secret
protocol pap
EOF
echo "s3cr3t-placeholder" > "$WORK/secret"
chmod 0644 "$STUB_CONF"; chmod 0600 "$WORK/secret"; chown root:root "$STUB_CONF" "$WORK/secret" 2>/dev/null
write_service "$STUB_CONF"
out=$(printf 'x\n' | pamtester -v "$SERVICE" testuser authenticate 2>&1); rc=$?
check "0644 config -> AUTHINFO_UNAVAIL" "information is unavailable\|authentication information" "$rc" "$out"

# 3) empty password with a valid (0600 root) config -> PAM_AUTH_ERR
#    (module rejects the empty authtok before any network I/O)
chmod 0600 "$STUB_CONF"
write_service "$STUB_CONF"
out=$(printf '\n' | pamtester -v "$SERVICE" testuser authenticate 2>&1); rc=$?
check "empty password -> AUTH_ERR" "authentication failure\|permission denied" "$rc" "$out"

echo "----"
echo "pamtester smoke: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
