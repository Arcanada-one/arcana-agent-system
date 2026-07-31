#!/usr/bin/env bash
# Arcana credential broker — install / verify / disable / rollback.
#
# Every path fails closed. `verify` is the gate the other verbs depend on: an
# install that cannot be verified is rolled back rather than left running, and
# a rollback target that cannot be verified is refused rather than activated.
#
# This script NEVER reads, prints or copies credential material. It checks
# ownership, modes and service state only. Provisioning the credential itself is
# a separate, operator-authorised act through the canonical secret channel.
#
# Usage: broker-lifecycle.sh {install|verify|disable|rollback <generation>}

set -euo pipefail

BROKER_USER="${BROKER_USER:-arcana-broker}"
EXECUTOR_GROUP="${EXECUTOR_GROUP:-arcana-executor}"
CRED_DIR="${CRED_DIR:-/etc/arcana/credential-broker}"
CRED_FILE="${CRED_FILE:-$CRED_DIR/provider.key}"
UNIT="arcana-credential-broker"
LIBEXEC="${LIBEXEC:-/usr/libexec/arcana}"
GEN_FILE="${GEN_FILE:-/var/lib/arcana-credential-broker/generation}"

die() { printf 'broker-lifecycle: FAIL: %s\n' "$*" >&2; exit 1; }
ok()  { printf 'broker-lifecycle: ok: %s\n' "$*"; }

platform() {
  case "$(uname -s)" in
    Linux)  echo linux ;;
    Darwin) echo macos ;;
    *)      die "unsupported platform: $(uname -s)" ;;
  esac
}

# --- verify ----------------------------------------------------------------
# Status-only. Emits no credential material, only ownership/mode/state facts.
verify_common() {
  [ -e "$CRED_FILE" ] || die "credential source absent: $CRED_FILE"
  [ -f "$CRED_FILE" ] || die "credential source is not a regular file: $CRED_FILE"
  [ -L "$CRED_FILE" ] && die "credential source is a symlink: $CRED_FILE"

  local mode owner
  if [ "$(platform)" = macos ]; then
    mode=$(stat -f '%Lp' "$CRED_FILE"); owner=$(stat -f '%Su' "$CRED_FILE")
  else
    mode=$(stat -c '%a' "$CRED_FILE"); owner=$(stat -c '%U' "$CRED_FILE")
  fi
  [ "$mode" = "600" ] || die "credential source mode is $mode, require 600"
  [ "$owner" = "$BROKER_USER" ] || die "credential source owner is $owner, require $BROKER_USER"
  ok "credential source: regular file, mode 600, owned by $BROKER_USER"

  # The executor must NOT be able to read the credential source.
  if id -u "${EXECUTOR_USER:-dev}" >/dev/null 2>&1; then
    if sudo -n -u "${EXECUTOR_USER:-dev}" test -r "$CRED_FILE" 2>/dev/null; then
      die "executor account can read the credential source — isolation is broken"
    fi
    ok "executor account cannot read the credential source"
  fi
}

verify_linux() {
  systemctl cat "$UNIT.service" >/dev/null 2>&1 || die "unit not installed: $UNIT.service"
  # The isolation directives must be present in the *effective* unit, not just
  # the shipped file — a drop-in could have weakened them.
  local eff; eff=$(systemctl show "$UNIT.service" 2>/dev/null || true)
  grep -q 'LimitCORE=0' <<<"$eff" || die "effective unit does not disable core dumps"
  grep -q 'NoNewPrivileges=yes' <<<"$eff" || die "effective unit allows privilege gain"
  grep -q "User=$BROKER_USER" <<<"$eff" || die "effective unit does not run as $BROKER_USER"
  grep -qE 'Environment=.*(KEY|TOKEN|SECRET)' <<<"$eff" \
    && die "effective unit injects a credential-shaped environment variable"
  ok "effective systemd unit retains required isolation"

  if systemctl is-active --quiet "$UNIT.socket"; then
    local sockmode
    sockmode=$(stat -c '%a' /run/arcana-credential-broker/broker.sock 2>/dev/null || echo missing)
    [ "$sockmode" = "660" ] || die "socket mode is $sockmode, require 660"
    ok "IPC socket present, mode 660"
  fi
}

verify_macos() {
  local plist="/Library/LaunchDaemons/one.arcanada.credential-broker.plist"
  [ -f "$plist" ] || die "launchd plist not installed: $plist"
  /usr/bin/plutil -lint "$plist" >/dev/null || die "launchd plist is malformed"
  grep -q 'EnvironmentVariables' "$plist" \
    && die "launchd plist passes an environment to the broker"
  ok "launchd plist installed, valid, environment-free"
}

verify() {
  verify_common
  case "$(platform)" in
    linux) verify_linux ;;
    macos) verify_macos ;;
  esac
  ok "verify PASSED"
}

# --- install ---------------------------------------------------------------
# Installs DISABLED. Enabling is a separate, explicit act after verification.
install_broker() {
  local here; here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  case "$(platform)" in
    linux)
      id -u "$BROKER_USER" >/dev/null 2>&1 || die "broker user $BROKER_USER does not exist"
      install -d -m 0700 -o "$BROKER_USER" -g "$BROKER_USER" "$CRED_DIR"
      install -m 0644 "$here/linux/$UNIT.service" "/etc/systemd/system/$UNIT.service"
      install -m 0644 "$here/linux/$UNIT.socket"  "/etc/systemd/system/$UNIT.socket"
      install -m 0644 "$here/linux/$UNIT.tmpfiles.conf" "/etc/tmpfiles.d/$UNIT.conf"
      systemd-tmpfiles --create "/etc/tmpfiles.d/$UNIT.conf"
      systemctl daemon-reload
      ok "installed (disabled by default; run 'verify' then enable explicitly)"
      ;;
    macos)
      install -d -m 0755 "$LIBEXEC"
      install -m 0644 "$here/macos/one.arcanada.credential-broker.plist" \
        /Library/LaunchDaemons/one.arcanada.credential-broker.plist
      ok "installed (Disabled=true in plist; enable explicitly after verify)"
      ;;
  esac
  install -d -m 0755 "$(dirname "$GEN_FILE")"
}

# --- disable ---------------------------------------------------------------
# The terminal safe state: credentialed execution stops. This is always a valid
# outcome — it never falls back to secret-bearing execution.
disable_broker() {
  case "$(platform)" in
    linux)
      systemctl disable --now "$UNIT.socket" 2>/dev/null || true
      systemctl disable --now "$UNIT.service" 2>/dev/null || true
      systemctl is-active --quiet "$UNIT.service" && die "broker still active after disable"
      ;;
    macos)
      launchctl bootout system/one.arcanada.credential-broker 2>/dev/null || true
      ;;
  esac
  ok "credentialed execution DISABLED (safe terminal state)"
}

# --- rollback --------------------------------------------------------------
# Roll back to a previously verified generation, or to disabled. Never to a
# generation that cannot be verified.
rollback() {
  local target="${1:-}"
  [ -n "$target" ] || die "rollback requires a target generation (or 'disabled')"

  if [ "$target" = disabled ]; then
    disable_broker
    return
  fi

  local bin="$LIBEXEC/arcana-credential-broker-$target"
  [ -x "$bin" ] || die "generation $target is not installed at $bin; refusing rollback"

  disable_broker
  ln -sfn "$bin" "$LIBEXEC/arcana-credential-broker"
  printf '%s\n' "$target" > "$GEN_FILE"

  # A rollback that cannot be verified is worse than no rollback: fall back to
  # the disabled state rather than leaving an unverified broker holding a key.
  if ! verify; then
    disable_broker
    die "generation $target failed verification; rolled back to disabled"
  fi
  ok "rolled back to verified generation $target"
}

case "${1:-}" in
  install)  install_broker ;;
  verify)   verify ;;
  disable)  disable_broker ;;
  rollback) shift; rollback "${1:-}" ;;
  *) printf 'usage: %s {install|verify|disable|rollback <generation|disabled>}\n' "$0" >&2; exit 2 ;;
esac
