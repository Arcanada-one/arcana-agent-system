#!/usr/bin/env bash
# Arcana credential broker lifecycle. No command reads, prints, copies, or
# accepts credential material; credential provisioning remains a separate gate.

set -euo pipefail

ARCANA_ROOT="${ARCANA_ROOT:-}"
SERVICE_MODE="${SERVICE_MODE:-auto}"
UNIT="arcana-credential-broker"

die() { printf 'broker-lifecycle: FAIL: %s\n' "$*" >&2; exit 1; }
ok() { printf 'broker-lifecycle: ok: %s\n' "$*"; }

platform() {
  if [ -n "${PLATFORM_OVERRIDE:-}" ]; then
    case "$PLATFORM_OVERRIDE" in linux|macos) printf '%s\n' "$PLATFORM_OVERRIDE"; return ;; esac
    die "invalid PLATFORM_OVERRIDE"
  fi
  case "$(uname -s)" in
    Linux) printf '%s\n' linux ;;
    Darwin) printf '%s\n' macos ;;
    *) die "unsupported platform" ;;
  esac
}

rooted() {
  local path="$1"
  case "$path" in /*) ;; *) die "internal path is not absolute" ;; esac
  if [ -n "$ARCANA_ROOT" ]; then
    case "$ARCANA_ROOT" in /*) ;; *) die "ARCANA_ROOT must be absolute" ;; esac
    [ "$ARCANA_ROOT" != "/" ] || die "ARCANA_ROOT=/ is ambiguous; use an empty value for production"
    printf '%s%s\n' "${ARCANA_ROOT%/}" "$path"
  else
    printf '%s\n' "$path"
  fi
}

if [ "$(platform)" = macos ]; then
  BROKER_USER="${BROKER_USER:-_arcanabroker}"
  BROKER_GROUP="${BROKER_GROUP:-_arcanabroker}"
  EXECUTOR_GROUP="${EXECUTOR_GROUP:-_arcanaexecutor}"
  LIBEXEC="${LIBEXEC:-$(rooted /usr/local/libexec/arcana)}"
  SOCKET_PATH="${SOCKET_PATH:-$(rooted /var/run/arcana-credential-broker/broker.sock)}"
  LOG_DIR="${LOG_DIR:-$(rooted /var/log/arcana)}"
else
  BROKER_USER="${BROKER_USER:-arcana-broker}"
  BROKER_GROUP="${BROKER_GROUP:-arcana-broker}"
  EXECUTOR_GROUP="${EXECUTOR_GROUP:-arcana-executor}"
  LIBEXEC="${LIBEXEC:-$(rooted /usr/libexec/arcana)}"
  SOCKET_PATH="${SOCKET_PATH:-$(rooted /run/arcana-credential-broker/broker.sock)}"
  LOG_DIR="${LOG_DIR:-}"
fi
CRED_DIR="${CRED_DIR:-$(rooted /etc/arcana/credential-broker)}"
CRED_FILE="${CRED_FILE:-$CRED_DIR/provider.key}"
POLICY_FILE="${POLICY_FILE:-$CRED_DIR/capability-policy.toml}"
STATE_DIR="${STATE_DIR:-$(rooted /var/lib/arcana-credential-broker)}"
GEN_FILE="${GEN_FILE:-$STATE_DIR/generation}"
PID_FILE="${PID_FILE:-$STATE_DIR/rehearsal.pid}"

validate_generation() {
  case "$1" in ''|*[!A-Za-z0-9._-]*) die "generation must be a non-empty filename token" ;; esac
}

current_binary() { printf '%s\n' "$LIBEXEC/arcana-credential-broker"; }
generation_binary() { printf '%s/arcana-credential-broker-%s\n' "$LIBEXEC" "$1"; }
generation_policy() { printf '%s/generations/%s/capability-policy.toml\n' "$STATE_DIR" "$1"; }

verify_credential() {
  [ "$SERVICE_MODE" = rehearsal ] && return
  [ -e "$CRED_FILE" ] || die "credential source absent: $CRED_FILE"
  [ -f "$CRED_FILE" ] || die "credential source is not a regular file"
  [ ! -L "$CRED_FILE" ] || die "credential source is a symlink"
  local mode owner
  if [ "$(platform)" = macos ]; then
    mode=$(stat -f '%Lp' "$CRED_FILE")
    owner=$(stat -f '%Su' "$CRED_FILE")
  else
    mode=$(stat -c '%a' "$CRED_FILE")
    owner=$(stat -c '%U' "$CRED_FILE")
  fi
  [ "$mode" = 600 ] || die "credential source mode is $mode, require 600"
  [ "$owner" = "$BROKER_USER" ] || die "credential source has the wrong owner"
  if id -u "${EXECUTOR_USER:-dev}" >/dev/null 2>&1; then
    if sudo -n -u "${EXECUTOR_USER:-dev}" test -r "$CRED_FILE" 2>/dev/null; then
      die "executor account can read the credential source"
    fi
  fi
  ok "credential source ownership and mode verified"
}

verify_installed_generation() {
  [ -s "$GEN_FILE" ] || die "installed generation is absent"
  local generation binary archived_policy
  generation=$(sed -n '1p' "$GEN_FILE")
  validate_generation "$generation"
  binary=$(generation_binary "$generation")
  archived_policy=$(generation_policy "$generation")
  [ -x "$binary" ] || die "generation binary is absent or not executable"
  [ -f "$archived_policy" ] || die "generation policy is absent"
  [ -f "$POLICY_FILE" ] || die "active policy is absent"
  [ ! -L "$POLICY_FILE" ] || die "active policy must not be a symlink"
  [ "$(readlink "$(current_binary)")" = "$binary" ] || die "current binary link does not match generation"
  cmp -s "$archived_policy" "$POLICY_FILE" || die "active policy differs from generation archive"
  ok "generation $generation binary and config are coherent"
}

verify_rehearsal() {
  [ -s "$PID_FILE" ] || die "rehearsal pid is absent"
  local pid
  pid=$(sed -n '1p' "$PID_FILE")
  case "$pid" in ''|*[!0-9]*) die "rehearsal pid is invalid" ;; esac
  kill -0 "$pid" 2>/dev/null || die "rehearsal broker is not running"
  [ -S "$SOCKET_PATH" ] || die "rehearsal IPC socket is absent"
  local mode
  if [ "$(platform)" = macos ]; then mode=$(stat -f '%Lp' "$SOCKET_PATH"); else mode=$(stat -c '%a' "$SOCKET_PATH"); fi
  [ "$mode" = 660 ] || die "rehearsal socket mode is $mode, require 660"
  ok "live rehearsal process and permissioned socket verified"
}

verify_linux() {
  systemctl cat "$UNIT.service" >/dev/null 2>&1 || die "broker service is not installed"
  local effective
  effective=$(systemctl show "$UNIT.service")
  grep -q '^LimitCORE=0$' <<<"$effective" || die "effective unit permits core dumps"
  grep -q '^NoNewPrivileges=yes$' <<<"$effective" || die "effective unit permits privilege gain"
  grep -q "^User=$BROKER_USER$" <<<"$effective" || die "effective unit has the wrong identity"
  if grep -Eqi '^Environment=.*(KEY|TOKEN|SECRET)' <<<"$effective"; then
    die "effective unit injects credential-shaped environment"
  fi
  systemctl is-active --quiet "$UNIT.socket" || die "broker socket unit is not active"
  ok "effective systemd isolation and socket activation verified"
}

verify_macos() {
  local plist
  plist=$(rooted /Library/LaunchDaemons/one.arcanada.credential-broker.plist)
  [ -f "$plist" ] || die "launchd plist is not installed"
  /usr/bin/plutil -lint "$plist" >/dev/null || die "launchd plist is malformed"
  if grep -q '<key>EnvironmentVariables</key>' "$plist"; then
    die "launchd plist injects environment variables"
  fi
  launchctl print system/one.arcanada.credential-broker >/dev/null || die "launchd job is not loaded"
  ok "launchd service is loaded and environment-free"
}

verify() {
  verify_installed_generation
  verify_credential
  if [ "$SERVICE_MODE" = rehearsal ]; then
    verify_rehearsal
  elif [ "$(platform)" = linux ]; then
    verify_linux
  else
    verify_macos
  fi
  ok "verify PASSED"
}

install_broker() {
  local generation="${1:-${GENERATION:-}}"
  local binary="${2:-${BROKER_BINARY:-}}"
  local policy="${3:-${POLICY_SOURCE:-}}"
  validate_generation "$generation"
  if [ -z "$binary" ] || [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
    die "install requires an executable broker binary"
  fi
  if [ -z "$policy" ] || [ ! -f "$policy" ] || [ -L "$policy" ]; then
    die "install requires a regular non-symlink policy"
  fi

  local here generation_dir target_binary
  here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  generation_dir="$STATE_DIR/generations/$generation"
  target_binary=$(generation_binary "$generation")
  install -d -m 0755 "$LIBEXEC"
  if [ "$SERVICE_MODE" = rehearsal ]; then
    install -d -m 0700 "$STATE_DIR" "$generation_dir" "$CRED_DIR"
  else
    id -u "$BROKER_USER" >/dev/null 2>&1 || die "broker user does not exist"
    getent group "$BROKER_GROUP" >/dev/null 2>&1 || {
      [ "$(platform)" = macos ] && dscl . -read "/Groups/$BROKER_GROUP" >/dev/null 2>&1
    } || die "broker group does not exist"
    getent group "$EXECUTOR_GROUP" >/dev/null 2>&1 || {
      [ "$(platform)" = macos ] && dscl . -read "/Groups/$EXECUTOR_GROUP" >/dev/null 2>&1
    } || die "executor group does not exist"
    install -d -m 0700 -o "$BROKER_USER" -g "$BROKER_GROUP" \
      "$STATE_DIR" "$generation_dir" "$CRED_DIR"
    if [ "$(platform)" = macos ]; then
      install -d -m 0750 -o "$BROKER_USER" -g "$EXECUTOR_GROUP" "$(dirname "$SOCKET_PATH")"
      install -d -m 0750 -o "$BROKER_USER" -g "$BROKER_GROUP" "$LOG_DIR"
    fi
  fi
  install -m 0755 "$binary" "$target_binary"
  if [ "$SERVICE_MODE" = rehearsal ]; then
    install -m 0644 "$policy" "$generation_dir/capability-policy.toml"
    install -m 0644 "$policy" "$POLICY_FILE"
  else
    install -m 0644 -o "$BROKER_USER" -g "$BROKER_GROUP" \
      "$policy" "$generation_dir/capability-policy.toml"
    install -m 0644 -o "$BROKER_USER" -g "$BROKER_GROUP" "$policy" "$POLICY_FILE"
  fi
  ln -sfn "$target_binary" "$(current_binary)"
  printf '%s\n' "$generation" > "$GEN_FILE"
  chmod 0600 "$GEN_FILE"

  if [ "$SERVICE_MODE" != rehearsal ]; then
    if [ "$(platform)" = linux ]; then
      install -m 0644 "$here/linux/$UNIT.service" "$(rooted /etc/systemd/system/$UNIT.service)"
      install -m 0644 "$here/linux/$UNIT.socket" "$(rooted /etc/systemd/system/$UNIT.socket)"
      install -m 0644 "$here/linux/$UNIT.tmpfiles.conf" "$(rooted /etc/tmpfiles.d/$UNIT.conf)"
      systemctl daemon-reload
    else
      install -m 0644 "$here/macos/one.arcanada.credential-broker.plist" \
        "$(rooted /Library/LaunchDaemons/one.arcanada.credential-broker.plist)"
    fi
  fi
  ok "installed generation $generation disabled"
}

disable_broker() {
  if [ "$SERVICE_MODE" = rehearsal ]; then
    if [ -s "$PID_FILE" ]; then
      local pid
      pid=$(sed -n '1p' "$PID_FILE")
      case "$pid" in *[!0-9]*) pid='' ;; esac
      if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null || true
        local attempts=0
        while kill -0 "$pid" 2>/dev/null && [ "$attempts" -lt 50 ]; do
          sleep 0.02
          attempts=$((attempts + 1))
        done
        if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid" 2>/dev/null || true; fi
      fi
      : > "$PID_FILE"
    fi
    if [ -S "$SOCKET_PATH" ]; then rm -f "$SOCKET_PATH"; fi
  elif [ "$(platform)" = linux ]; then
    systemctl disable --now "$UNIT.socket" "$UNIT.service" 2>/dev/null || true
    systemctl is-active --quiet "$UNIT.service" && die "broker remains active after disable"
  else
    launchctl bootout system/one.arcanada.credential-broker 2>/dev/null || true
  fi
  ok "credentialed execution DISABLED"
}

activate_broker() {
  verify_installed_generation
  if [ "$SERVICE_MODE" = rehearsal ]; then
    disable_broker >/dev/null
    install -d -m 0700 "$(dirname "$SOCKET_PATH")"
    "$(current_binary)" --mock-provider --policy "$POLICY_FILE" --socket "$SOCKET_PATH" \
      >"$STATE_DIR/rehearsal.log" 2>&1 &
    local pid=$!
    printf '%s\n' "$pid" > "$PID_FILE"
    chmod 0600 "$PID_FILE"
    local attempts=0
    while [ ! -S "$SOCKET_PATH" ] && kill -0 "$pid" 2>/dev/null && [ "$attempts" -lt 100 ]; do
      sleep 0.02
      attempts=$((attempts + 1))
    done
    kill -0 "$pid" 2>/dev/null || die "rehearsal broker exited during activation"
    [ -S "$SOCKET_PATH" ] || { disable_broker >/dev/null; die "rehearsal socket did not appear"; }
  elif [ "$(platform)" = linux ]; then
    systemctl enable --now "$UNIT.socket"
  else
    launchctl bootstrap system "$(rooted /Library/LaunchDaemons/one.arcanada.credential-broker.plist)"
    launchctl enable system/one.arcanada.credential-broker
    launchctl kickstart -k system/one.arcanada.credential-broker
  fi
  verify
  ok "broker activated"
}

rollback() {
  local target="${1:-}"
  [ -n "$target" ] || die "rollback requires a generation or disabled"
  if [ "$target" = disabled ]; then disable_broker; return; fi
  validate_generation "$target"
  local binary policy
  binary=$(generation_binary "$target")
  policy=$(generation_policy "$target")
  [ -x "$binary" ] || die "rollback binary is not installed"
  [ -f "$policy" ] || die "rollback policy is not installed"
  disable_broker >/dev/null
  ln -sfn "$binary" "$(current_binary)"
  install -m 0644 "$policy" "$POLICY_FILE"
  printf '%s\n' "$target" > "$GEN_FILE"
  chmod 0600 "$GEN_FILE"
  if ! activate_broker; then
    disable_broker
    die "rollback generation failed verification; terminal state is disabled"
  fi
  ok "rolled back binary and config to generation $target"
}

case "${1:-}" in
  install) shift; install_broker "${1:-}" "${2:-}" "${3:-}" ;;
  activate) activate_broker ;;
  verify) verify ;;
  disable) disable_broker ;;
  rollback) shift; rollback "${1:-}" ;;
  *) printf 'usage: %s {install <generation> <binary> <policy>|activate|verify|disable|rollback <generation|disabled>}\n' "$0" >&2; exit 2 ;;
esac
