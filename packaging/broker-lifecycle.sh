#!/usr/bin/env bash
# Arcana credential broker lifecycle. No command reads, prints, copies, or
# accepts credential material; credential provisioning remains a separate gate.

set -euo pipefail

ARCANA_ROOT="${ARCANA_ROOT:-}"
SERVICE_MODE="${SERVICE_MODE:-auto}"
UNIT="arcana-credential-broker"

die() { printf 'broker-lifecycle: FAIL: %s\n' "$*" >&2; exit 1; }
ok() { printf 'broker-lifecycle: ok: %s\n' "$*"; }

if [ -n "$ARCANA_ROOT" ] && [ "$SERVICE_MODE" != rehearsal ]; then
  die "ARCANA_ROOT is permitted only with SERVICE_MODE=rehearsal"
fi

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
  DEFAULT_STATE_DIR=$(rooted /var/db/arcana-credential-broker)
  DEFAULT_GENERATION_ROOT=$(rooted /var/db/arcana-credential-broker-generations)
  DEFAULT_CONTROL_DIR=$(rooted /var/db/arcana-credential-broker-control)
else
  BROKER_USER="${BROKER_USER:-arcana-broker}"
  BROKER_GROUP="${BROKER_GROUP:-arcana-broker}"
  EXECUTOR_GROUP="${EXECUTOR_GROUP:-arcana-executor}"
  LIBEXEC="${LIBEXEC:-$(rooted /usr/libexec/arcana)}"
  SOCKET_PATH="${SOCKET_PATH:-$(rooted /run/arcana-credential-broker/broker.sock)}"
  LOG_DIR="${LOG_DIR:-}"
  DEFAULT_STATE_DIR=$(rooted /var/lib/arcana-credential-broker)
  DEFAULT_GENERATION_ROOT=$(rooted /var/lib/arcana-credential-broker-generations)
  DEFAULT_CONTROL_DIR=$(rooted /var/lib/arcana-credential-broker-control)
fi
CRED_DIR="${CRED_DIR:-$(rooted /etc/arcana/credential-broker)}"
CRED_FILE="${CRED_FILE:-$CRED_DIR/provider.key}"
POLICY_FILE="${POLICY_FILE:-$CRED_DIR/capability-policy.toml}"
STATE_DIR="${STATE_DIR:-$DEFAULT_STATE_DIR}"
GENERATION_ROOT="${GENERATION_ROOT:-$DEFAULT_GENERATION_ROOT}"
CONTROL_DIR="${CONTROL_DIR:-$DEFAULT_CONTROL_DIR}"
RUNTIME_GENERATION_DIR="${RUNTIME_GENERATION_DIR:-$CONTROL_DIR/runtime-generations}"
GEN_FILE="${GEN_FILE:-$CONTROL_DIR/generation}"
PENDING_FILE="${PENDING_FILE:-$CONTROL_DIR/pending-generation}"
STATE_GENERATION_FILE="${STATE_GENERATION_FILE:-$CONTROL_DIR/runtime-state-generation}"
LIFECYCLE_LOCK_FILE="${LIFECYCLE_LOCK_FILE:-$CONTROL_DIR/lifecycle.lock}"
PID_FILE="${PID_FILE:-$STATE_DIR/rehearsal.pid}"
RUNTIME_STATE="${RUNTIME_STATE:-$STATE_DIR/broker-state.json}"
LOCK_OWNER_PID=''
LOCK_OWNER_TOKEN=''
LOCK_CANDIDATE=''
LOCK_OBSERVATION=''
OBSERVED_LOCK_OWNER=''

validate_generation() {
  case "$1" in ''|*[!A-Za-z0-9._-]*) die "generation must be a non-empty filename token" ;; esac
}

current_binary() { printf '%s\n' "$LIBEXEC/arcana-credential-broker"; }
generation_binary() { printf '%s/arcana-credential-broker-%s\n' "$LIBEXEC" "$1"; }
generation_policy() { printf '%s/%s/capability-policy.toml\n' "$GENERATION_ROOT" "$1"; }
generation_state() { printf '%s/%s-broker-state.json\n' "$RUNTIME_GENERATION_DIR" "$1"; }
generation_manifest() { printf '%s/%s/manifest.sha256\n' "$GENERATION_ROOT" "$1"; }

launchd_broker_disabled() {
  launchctl print-disabled system 2>/dev/null | awk '
    $1 == "\"one.arcanada.credential-broker\"" && $2 == "=>" && $3 == "true" { found = 1 }
    END { exit(found ? 0 : 1) }
  '
}

file_owner() {
  if [ "$(platform)" = macos ]; then stat -f '%Su' "$1"; else stat -c '%U' "$1"; fi
}

file_group() {
  if [ "$(platform)" = macos ]; then stat -f '%Sg' "$1"; else stat -c '%G' "$1"; fi
}

file_mode() {
  if [ "$(platform)" = macos ]; then stat -f '%Lp' "$1"; else stat -c '%a' "$1"; fi
}

file_digest() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  else
    shasum -a 256 "$path" | awk '{print $1}'
  fi
}

write_token_atomic() {
  local value="$1" target="$2"
  local temporary
  temporary=$(mktemp "${target}.tmp.XXXXXX")
  chmod 0600 "$temporary"
  printf '%s\n' "$value" > "$temporary"
  mv -f "$temporary" "$target"
}

release_lifecycle_lock() {
  [ -n "$LOCK_OWNER_PID" ] || return
  [ "${BASH_SUBSHELL:-0}" = 0 ] || return
  [ "$$" = "$LOCK_OWNER_PID" ] || return
  if [ -n "$LOCK_OBSERVATION" ]; then rm -f -- "$LOCK_OBSERVATION"; fi
  if [ -n "$LOCK_CANDIDATE" ]; then rm -f -- "$LOCK_CANDIDATE"; fi
  if [ -n "$LOCK_OWNER_TOKEN" ] && [ -f "$LIFECYCLE_LOCK_FILE" ] && \
    [ ! -L "$LIFECYCLE_LOCK_FILE" ] && \
    [ "$(sed -n '1p' "$LIFECYCLE_LOCK_FILE")" = "$LOCK_OWNER_TOKEN" ]; then
    rm -f -- "$LIFECYCLE_LOCK_FILE"
  fi
  LOCK_OWNER_PID=''
  LOCK_OWNER_TOKEN=''
  LOCK_CANDIDATE=''
  LOCK_OBSERVATION=''
  OBSERVED_LOCK_OWNER=''
}

observe_lifecycle_lock() {
  local observed=''
  OBSERVED_LOCK_OWNER=''
  LOCK_OBSERVATION="${LOCK_CANDIDATE}.observed"
  rm -f -- "$LOCK_OBSERVATION"

  [ ! -L "$LIFECYCLE_LOCK_FILE" ] || return 2
  if ! ln -P -- "$LIFECYCLE_LOCK_FILE" "$LOCK_OBSERVATION" 2>/dev/null; then
    LOCK_OBSERVATION=''
    [ ! -L "$LIFECYCLE_LOCK_FILE" ] || return 2
    # Absence, or a regular owner that appeared after link(2) failed, is a
    # transient generation transition. The bounded acquisition loop retries.
    return 1
  fi

  # The hard-link snapshot remains a stable inode even when its owner releases
  # the authoritative lock path while this process validates and reads it.
  [ ! -L "$LOCK_OBSERVATION" ] && [ -f "$LOCK_OBSERVATION" ] || return 2
  if [ "$SERVICE_MODE" != rehearsal ]; then
    [ "$(file_owner "$LOCK_OBSERVATION")" = root ] || return 2
    [ "$(file_mode "$LOCK_OBSERVATION")" = 600 ] || return 2
    verify_no_extended_acl "$LOCK_OBSERVATION"
  fi
  IFS= read -r observed < "$LOCK_OBSERVATION" || return 2
  rm -f -- "$LOCK_OBSERVATION"
  LOCK_OBSERVATION=''
  OBSERVED_LOCK_OWNER="$observed"
  return 0
}

acquire_lifecycle_lock() {
  local attempts=0 owner='' owner_pid='' current_owner='' observation_status=0
  if [ "$SERVICE_MODE" = rehearsal ]; then
    install -d -m 0700 "$CONTROL_DIR"
  else
    [ "$(id -u)" = 0 ] || die "lifecycle mutation requires root"
    install -d -m 0700 -o root -g root "$CONTROL_DIR"
    [ ! -L "$CONTROL_DIR" ] && [ -d "$CONTROL_DIR" ] || die "control directory is not trusted"
    [ "$(file_owner "$CONTROL_DIR")" = root ] || die "control directory is not root-owned"
    [ "$(file_mode "$CONTROL_DIR")" = 700 ] || die "control directory mode is not 0700"
    verify_no_extended_acl "$CONTROL_DIR"
  fi

  LOCK_OWNER_PID="$$"
  LOCK_OWNER_TOKEN="$$:${RANDOM}${RANDOM}"
  LOCK_CANDIDATE=$(mktemp "$CONTROL_DIR/.lifecycle-owner.XXXXXX")
  chmod 0600 "$LOCK_CANDIDATE"
  if [ "$SERVICE_MODE" != rehearsal ]; then chown root:root "$LOCK_CANDIDATE"; fi
  printf '%s\n' "$LOCK_OWNER_TOKEN" > "$LOCK_CANDIDATE"
  trap release_lifecycle_lock EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM

  # link(2) publishes the already-complete owner record and acquires the lock
  # in one atomic operation. No peer can observe an ownerless live lock.
  while ! ln -- "$LOCK_CANDIDATE" "$LIFECYCLE_LOCK_FILE" 2>/dev/null; do
    if [ "$SERVICE_MODE" = rehearsal ] && \
      [ -n "${LIFECYCLE_REHEARSAL_PRE_OWNER_READ_UNTIL_FILE:-}" ]; then
      case "$LIFECYCLE_REHEARSAL_PRE_OWNER_READ_UNTIL_FILE" in
        "$CONTROL_DIR"/*) ;;
        *) die "rehearsal owner-read release file must be inside the control directory" ;;
      esac
      : > "$CONTROL_DIR/rehearsal-pre-owner-read-ready"
      local owner_read_attempts=0
      while [ ! -f "$LIFECYCLE_REHEARSAL_PRE_OWNER_READ_UNTIL_FILE" ]; do
        owner_read_attempts=$((owner_read_attempts + 1))
        [ "$owner_read_attempts" -lt 500 ] || \
          die "timed out waiting for rehearsal owner-read release"
        sleep 0.02
      done
    fi
    if observe_lifecycle_lock; then
      owner="$OBSERVED_LOCK_OWNER"
    else
      observation_status=$?
      if [ "$observation_status" = 1 ]; then
        attempts=$((attempts + 1))
        [ "$attempts" -lt 500 ] || die "timed out observing a stable lifecycle lock"
        sleep 0.02
        continue
      fi
      die "lifecycle lock is not a trusted regular file"
    fi
    if [ "$SERVICE_MODE" = rehearsal ] && \
      [ -n "${LIFECYCLE_REHEARSAL_OBSERVED_OWNER_FILE:-}" ]; then
      case "$LIFECYCLE_REHEARSAL_OBSERVED_OWNER_FILE" in
        "$CONTROL_DIR"/*) ;;
        *) die "rehearsal observed-owner file must be inside the control directory" ;;
      esac
      write_token_atomic "$owner" "$LIFECYCLE_REHEARSAL_OBSERVED_OWNER_FILE"
    fi
    case "$owner" in
      [0-9]*:[0-9]*) owner_pid=${owner%%:*} ;;
      *) die "lifecycle lock owner record is invalid; manual root recovery required" ;;
    esac
    case "$owner_pid" in ''|*[!0-9]*) die "lifecycle lock owner pid is invalid" ;; esac
    if ! kill -0 "$owner_pid" 2>/dev/null; then
      # The observed owner may have released after the read. Only diagnose a
      # stale lock when the same token is still present; absence or a new owner
      # means another acquisition attempt is safe.
      if observe_lifecycle_lock; then
        current_owner="$OBSERVED_LOCK_OWNER"
      else
        observation_status=$?
        if [ "$observation_status" = 1 ]; then
          attempts=$((attempts + 1))
          [ "$attempts" -lt 500 ] || die "timed out observing a stable lifecycle lock"
          sleep 0.02
          continue
        fi
        die "lifecycle lock is not a trusted regular file"
      fi
      [ "$current_owner" != "$owner" ] || \
        die "stale lifecycle lock for pid $owner_pid requires explicit root recovery"
      continue
    fi
    attempts=$((attempts + 1))
    [ "$attempts" -lt 500 ] || die "timed out waiting for lifecycle lock held by pid $owner_pid"
    sleep 0.02
  done
  rm -f -- "$LOCK_CANDIDATE"
  LOCK_CANDIDATE=''

  if [ "$SERVICE_MODE" = rehearsal ] && [ -n "${LIFECYCLE_REHEARSAL_HOLD_LOCK_SECONDS:-}" ]; then
    case "$LIFECYCLE_REHEARSAL_HOLD_LOCK_SECONDS" in
      *[!0-9.]*|*.*.*|'') die "invalid rehearsal lock hold" ;;
    esac
    sleep "$LIFECYCLE_REHEARSAL_HOLD_LOCK_SECONDS"
  fi
  if [ "$SERVICE_MODE" = rehearsal ] && \
    [ -n "${LIFECYCLE_REHEARSAL_HOLD_LOCK_UNTIL_FILE:-}" ]; then
    [ -z "${LIFECYCLE_REHEARSAL_HOLD_LOCK_SECONDS:-}" ] || \
      die "rehearsal lock hold modes are mutually exclusive"
    case "$LIFECYCLE_REHEARSAL_HOLD_LOCK_UNTIL_FILE" in
      "$CONTROL_DIR"/*) ;;
      *) die "rehearsal lock release file must be inside the control directory" ;;
    esac
    local release_attempts=0
    while [ ! -f "$LIFECYCLE_REHEARSAL_HOLD_LOCK_UNTIL_FILE" ]; do
      release_attempts=$((release_attempts + 1))
      [ "$release_attempts" -lt 500 ] || die "timed out waiting for rehearsal lock release"
      sleep 0.02
    done
  fi
}

verify_no_extended_acl() {
  local path="$1"
  if [ "$(platform)" = macos ]; then
    [ "$(ls -lde "$path" | wc -l | tr -d ' ')" = 1 ] || \
      die "$path has an extended ACL"
  else
    local permission_word
    permission_word=$(LC_ALL=C ls -ld -- "$path" | awk '{print $1}')
    [ "${#permission_word}" = 10 ] || die "$path has an ACL or security-label marker"
  fi
}

clear_macos_acl() {
  local path="$1"
  [ "$(platform)" = macos ] || return
  chmod -N "$path"
  verify_no_extended_acl "$path"
}

validate_trusted_install_source() {
  local path="$1" current='/' component mode
  local -a components
  [ "$SERVICE_MODE" != rehearsal ] || return 0
  case "$path" in /*) ;; *) die "install sources must be absolute" ;; esac
  IFS='/' read -r -a components <<<"${path#/}"
  for component in "${components[@]}"; do
    case "$component" in ''|.|..) die "install source path is not canonical" ;; esac
    current="${current%/}/$component"
    [ -e "$current" ] || die "install source component is absent: $current"
    [ ! -L "$current" ] || die "install source component is a symlink: $current"
    [ "$(file_owner "$current")" = root ] || die "install source is not root-owned: $current"
    mode=$(file_mode "$current")
    [ $((8#$mode & 0022)) -eq 0 ] || die "install source is group/world writable: $current"
    verify_no_extended_acl "$current"
  done
}

write_generation_manifest() {
  local generation="$1" binary_digest="$2" policy_digest="$3"
  local target temporary
  target=$(generation_manifest "$generation")
  temporary="${target}.tmp.$$"
  (umask 077; printf 'binary_sha256=%s\npolicy_sha256=%s\n' "$binary_digest" "$policy_digest" > "$temporary")
  mv "$temporary" "$target"
  if [ "$SERVICE_MODE" != rehearsal ]; then
    chown root:"$BROKER_GROUP" "$target"
    chmod 0640 "$target"
  fi
}

manifest_digest() {
  local manifest="$1" key="$2"
  awk -F= -v key="$key" '$1 == key { print $2 }' "$manifest"
}

verify_generation_archive() {
  local generation="$1" binary policy manifest recorded_binary recorded_policy
  binary=$(generation_binary "$generation")
  policy=$(generation_policy "$generation")
  manifest=$(generation_manifest "$generation")
  if [ ! -x "$binary" ] || [ -L "$binary" ]; then
    die "generation binary is absent, non-executable, or a symlink"
  fi
  if [ ! -f "$policy" ] || [ -L "$policy" ]; then
    die "generation policy is absent or a symlink"
  fi
  if [ ! -f "$manifest" ] || [ -L "$manifest" ]; then
    die "generation manifest is absent or a symlink"
  fi
  [ "$(wc -l < "$manifest" | tr -d ' ')" = 2 ] || die "generation manifest has unexpected entries"
  recorded_binary=$(manifest_digest "$manifest" binary_sha256)
  recorded_policy=$(manifest_digest "$manifest" policy_sha256)
  case "$recorded_binary$recorded_policy" in *[!0-9a-f]*) die "generation manifest digest is malformed" ;; esac
  if [ "${#recorded_binary}" != 64 ] || [ "${#recorded_policy}" != 64 ]; then
    die "generation manifest digest has the wrong length"
  fi
  [ "$(file_digest "$binary")" = "$recorded_binary" ] || die "generation binary differs from immutable manifest"
  [ "$(file_digest "$policy")" = "$recorded_policy" ] || die "generation policy differs from immutable manifest"
  if [ "$SERVICE_MODE" != rehearsal ]; then
    local generation_dir
    generation_dir=$(dirname "$policy")
    for root_owned in "$GENERATION_ROOT" "$generation_dir" "$binary" "$policy" "$manifest"; do
      [ "$(file_owner "$root_owned")" = root ] || die "generation archive is not root-owned"
      local archive_mode
      archive_mode=$(file_mode "$root_owned")
      [ $((8#$archive_mode & 0022)) -eq 0 ] || die "generation archive is group/world writable"
    done
  fi
}

archive_runtime_state() {
  local owner="$1" snapshot quarantine
  validate_generation "$owner"
  if [ ! -e "$RUNTIME_STATE" ] && [ ! -L "$RUNTIME_STATE" ]; then return; fi
  snapshot=$(generation_state "$owner")
  if { [ -e "$snapshot" ] || [ -L "$snapshot" ]; } && \
    { [ -L "$snapshot" ] || [ ! -f "$snapshot" ]; }; then
    quarantine="${snapshot}.rejected.$$.${RANDOM}"
    mv -- "$snapshot" "$quarantine" || die "could not quarantine invalid existing state snapshot"
  fi
  rm -f -- "$snapshot"
  # rename(2) does not follow a broker-controlled source symlink. Moving the
  # object into this root-only directory freezes it before validation.
  mv -- "$RUNTIME_STATE" "$snapshot"
  if [ -L "$snapshot" ] || [ ! -f "$snapshot" ]; then
    quarantine="${snapshot}.rejected.$$.${RANDOM}"
    mv -- "$snapshot" "$quarantine" || die "could not quarantine invalid runtime state"
    die "runtime state is not a regular non-symlink file"
  fi
  chmod 0600 "$snapshot"
  if [ "$SERVICE_MODE" != rehearsal ]; then chown root:root "$snapshot"; fi
}

restore_generation_state() {
  local target="$1" snapshot
  validate_generation "$target"
  snapshot=$(generation_state "$target")
  # Publish state ownership before moving the object. If any later command
  # fails, the next rollback can reconcile runtime state independently from the
  # still-old selected binary generation.
  write_token_atomic "$target" "$STATE_GENERATION_FILE"
  if [ -e "$snapshot" ] || [ -L "$snapshot" ]; then
    [ ! -L "$snapshot" ] && [ -f "$snapshot" ] || \
      die "generation state snapshot is not a regular non-symlink file"
    if [ "$SERVICE_MODE" != rehearsal ]; then
      [ "$(file_owner "$snapshot")" = root ] || die "generation state snapshot is not root-owned"
      [ "$(file_mode "$snapshot")" = 600 ] || die "generation state snapshot mode is not 0600"
    fi
    rm -f -- "$RUNTIME_STATE"
    mv -- "$snapshot" "$RUNTIME_STATE"
    chmod 0600 "$RUNTIME_STATE"
    if [ "$SERVICE_MODE" != rehearsal ]; then
      chown "$BROKER_USER":"$BROKER_GROUP" "$RUNTIME_STATE"
    fi
  else
    rm -f -- "$RUNTIME_STATE"
  fi
}

select_generation() {
  local target="$1" old='' runtime_owner=''
  validate_generation "$target"
  verify_generation_archive "$target"
  if [ -s "$GEN_FILE" ]; then
    old=$(sed -n '1p' "$GEN_FILE")
    validate_generation "$old"
  fi
  if [ -s "$STATE_GENERATION_FILE" ]; then
    runtime_owner=$(sed -n '1p' "$STATE_GENERATION_FILE")
    validate_generation "$runtime_owner"
  elif [ -e "$RUNTIME_STATE" ] || [ -L "$RUNTIME_STATE" ]; then
    [ -n "$old" ] || die "runtime state has no generation identity"
    runtime_owner="$old"
  fi
  disable_broker >/dev/null
  if [ "$runtime_owner" != "$target" ]; then
    if [ -e "$RUNTIME_STATE" ] || [ -L "$RUNTIME_STATE" ]; then
      [ -n "$runtime_owner" ] || die "runtime state has no generation identity"
      archive_runtime_state "$runtime_owner"
    fi
    restore_generation_state "$target"
  elif { [ ! -e "$RUNTIME_STATE" ] && [ ! -L "$RUNTIME_STATE" ]; } && \
    { [ -e "$(generation_state "$target")" ] || [ -L "$(generation_state "$target")" ]; }; then
    restore_generation_state "$target"
  else
    write_token_atomic "$target" "$STATE_GENERATION_FILE"
  fi
  ln -sfn "$(generation_binary "$target")" "$(current_binary)"
  if [ "$SERVICE_MODE" = rehearsal ]; then
    install -m 0644 "$(generation_policy "$target")" "$POLICY_FILE"
  else
    install -m 0640 -o root -g "$BROKER_GROUP" \
      "$(generation_policy "$target")" "$POLICY_FILE"
  fi
  write_token_atomic "$target" "$GEN_FILE"
}

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
  verify_no_extended_acl "$CRED_DIR"
  verify_no_extended_acl "$CRED_FILE"
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
  verify_generation_archive "$generation"
  [ -f "$POLICY_FILE" ] || die "active policy is absent"
  [ ! -L "$POLICY_FILE" ] || die "active policy must not be a symlink"
  if [ "$SERVICE_MODE" != rehearsal ]; then
    [ "$(file_owner "$POLICY_FILE")" = root ] || die "active policy is not root-owned"
    [ "$(file_mode "$POLICY_FILE")" = 640 ] || die "active policy mode is not 0640"
  fi
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
  local mode expected_mode=660
  if [ "$(platform)" = macos ]; then mode=$(stat -f '%Lp' "$SOCKET_PATH"); else mode=$(stat -c '%a' "$SOCKET_PATH"); fi
  if [ "$(platform)" = macos ]; then expected_mode=666; fi
  [ "$mode" = "$expected_mode" ] || die "rehearsal socket mode is $mode, require $expected_mode"
  ok "live rehearsal process and permissioned socket verified"
}

verify_linux() {
  systemctl cat "$UNIT.service" >/dev/null 2>&1 || die "broker service is not installed"
  systemctl cat "$UNIT.socket" >/dev/null 2>&1 || die "broker socket is not installed"
  local effective fragment drop_ins socket_effective socket_fragment socket_drop_ins
  effective=$(systemctl show "$UNIT.service")
  grep -q '^LimitCORE=0$' <<<"$effective" || die "effective unit permits core dumps"
  grep -q '^NoNewPrivileges=yes$' <<<"$effective" || die "effective unit permits privilege gain"
  grep -q "^User=$BROKER_USER$" <<<"$effective" || die "effective unit has the wrong identity"
  grep -q "^Group=$BROKER_GROUP$" <<<"$effective" || die "effective unit has the wrong group"
  fragment=$(systemctl show --property FragmentPath --value "$UNIT.service")
  [ "$fragment" = "$(rooted /etc/systemd/system/$UNIT.service)" ] || \
    die "effective service fragment is not the lifecycle-installed unit"
  drop_ins=$(systemctl show --property DropInPaths --value "$UNIT.service")
  [ -z "$drop_ins" ] || die "service has unverified drop-in configuration"
  if grep -Eqi '^Environment=.*(KEY|TOKEN|SECRET)' <<<"$effective"; then
    die "effective unit injects credential-shaped environment"
  fi
  systemctl is-active --quiet "$UNIT.socket" || die "broker socket unit is not active"
  systemctl is-active --quiet "$UNIT.service" || die "broker service is not active"
  socket_effective=$(systemctl show "$UNIT.socket")
  grep -Fqx "Listen=$SOCKET_PATH (SequentialPacket)" <<<"$socket_effective" || \
    die "effective socket is not the expected sequential-packet listener"
  grep -q "^SocketUser=$BROKER_USER$" <<<"$socket_effective" || die "socket has the wrong owner contract"
  grep -q "^SocketGroup=$EXECUTOR_GROUP$" <<<"$socket_effective" || die "socket has the wrong group contract"
  grep -q '^SocketMode=0660$' <<<"$socket_effective" || die "socket has the wrong mode contract"
  grep -q '^Accept=no$' <<<"$socket_effective" || die "socket unexpectedly accepts per-connection services"
  grep -q '^RemoveOnStop=yes$' <<<"$socket_effective" || die "socket is not removed on stop"
  socket_fragment=$(systemctl show --property FragmentPath --value "$UNIT.socket")
  [ "$socket_fragment" = "$(rooted /etc/systemd/system/$UNIT.socket)" ] || \
    die "effective socket fragment is not the lifecycle-installed unit"
  socket_drop_ins=$(systemctl show --property DropInPaths --value "$UNIT.socket")
  [ -z "$socket_drop_ins" ] || die "socket has unverified drop-in configuration"
  [ -S "$SOCKET_PATH" ] || die "live broker socket inode is absent"
  [ "$(file_owner "$SOCKET_PATH")" = "$BROKER_USER" ] || die "live socket has the wrong owner"
  [ "$(file_group "$SOCKET_PATH")" = "$EXECUTOR_GROUP" ] || die "live socket has the wrong group"
  [ "$(file_mode "$SOCKET_PATH")" = 660 ] || die "live socket mode is not 0660"
  verify_no_extended_acl "$SOCKET_PATH"
  local pid live_executable expected_executable arg index
  local -a actual_argv=() expected_argv
  pid=$(systemctl show --property MainPID --value "$UNIT.service")
  case "$pid" in ''|0|*[!0-9]*) die "broker service has no live MainPID" ;; esac
  live_executable=$(readlink "/proc/$pid/exe")
  expected_executable=$(readlink -f "$(current_binary)")
  [ "$live_executable" = "$expected_executable" ] || die "live broker executable differs from selected generation"
  [ "$(file_digest "/proc/$pid/exe")" = "$(file_digest "$expected_executable")" ] || \
    die "live broker digest differs from selected generation"
  while IFS= read -r -d '' arg; do actual_argv+=("$arg"); done < "/proc/$pid/cmdline"
  expected_argv=(
    "$(current_binary)"
    --policy "$POLICY_FILE"
    --credential-source "$CRED_FILE"
    --state "$RUNTIME_STATE"
    --audit "$STATE_DIR/audit.log"
  )
  [ "${#actual_argv[@]}" = "${#expected_argv[@]}" ] || die "live broker argv length is unexpected"
  for index in "${!expected_argv[@]}"; do
    [ "${actual_argv[$index]}" = "${expected_argv[$index]}" ] || \
      die "live broker argv differs from the verified service contract"
  done
  ok "effective systemd isolation, live identity, and socket activation verified"
}

verify_macos() {
  local plist service pid identity live_executable expected_executable socket_mode socket_dir
  local index actual_argument live_command expected_command
  local -a expected_arguments
  plist=$(rooted /Library/LaunchDaemons/one.arcanada.credential-broker.plist)
  [ -f "$plist" ] || die "launchd plist is not installed"
  /usr/bin/plutil -lint "$plist" >/dev/null || die "launchd plist is malformed"
  if grep -q '<key>EnvironmentVariables</key>' "$plist"; then
    die "launchd plist injects environment variables"
  fi
  service=$(launchctl print system/one.arcanada.credential-broker) || die "launchd job is not loaded"
  grep -q 'state = running' <<<"$service" || die "launchd broker is not running"
  pid=$(sed -n 's/^[[:space:]]*pid = \([0-9][0-9]*\)$/\1/p' <<<"$service" | head -n 1)
  case "$pid" in ''|0|*[!0-9]*) die "launchd broker has no live pid" ;; esac
  identity=$(/bin/ps -p "$pid" -o user= -o group= | xargs)
  [ "$identity" = "$BROKER_USER $BROKER_GROUP" ] || die "launchd broker has the wrong identity"
  live_executable=$(/usr/sbin/lsof -a -p "$pid" -d txt -Fn 2>/dev/null | sed -n 's/^n//p' | head -n 1)
  expected_executable=$(generation_binary "$(sed -n '1p' "$GEN_FILE")")
  [ "$live_executable" = "$expected_executable" ] || die "live launchd executable differs from selected generation"
  [ "$(file_digest "$live_executable")" = "$(file_digest "$expected_executable")" ] || \
    die "live launchd digest differs from selected generation"
  [ -S "$SOCKET_PATH" ] || die "launchd broker socket is absent"
  socket_mode=$(stat -f '%Lp' "$SOCKET_PATH")
  [ "$socket_mode" = 666 ] || die "launchd broker socket mode is not 0666"
  socket_dir=$(dirname "$SOCKET_PATH")
  [ "$(stat -f '%Su' "$socket_dir")" = "$BROKER_USER" ] || die "socket directory has the wrong owner"
  [ "$(stat -f '%Sg' "$socket_dir")" = "$EXECUTOR_GROUP" ] || die "socket directory has the wrong executor group"
  [ "$(stat -f '%Lp' "$socket_dir")" = 750 ] || die "socket directory mode is not 0750"
  verify_no_extended_acl "$socket_dir"
  verify_no_extended_acl "$SOCKET_PATH"
  expected_arguments=(
    "$(current_binary)"
    --policy "$POLICY_FILE"
    --credential-source "$CRED_FILE"
    --state "$RUNTIME_STATE"
    --audit "$STATE_DIR/audit.log"
    --socket "$SOCKET_PATH"
  )
  for index in "${!expected_arguments[@]}"; do
    actual_argument=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:$index" "$plist") || \
      die "launchd ProgramArguments is incomplete"
    [ "$actual_argument" = "${expected_arguments[$index]}" ] || \
      die "launchd ProgramArguments differs from the lifecycle contract"
  done
  if /usr/libexec/PlistBuddy -c "Print :ProgramArguments:${#expected_arguments[@]}" "$plist" >/dev/null 2>&1; then
    die "launchd ProgramArguments has unverified trailing entries"
  fi
  expected_command="${expected_arguments[*]}"
  live_command=$(/bin/ps -ww -p "$pid" -o command= | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  [ "$live_command" = "$expected_command" ] || die "live launchd argv differs from the verified plist"
  ok "live launchd identity, executable, state, and permissioned socket verified"
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
  if [ -z "$binary" ] || [ ! -f "$binary" ] || [ ! -x "$binary" ] || [ -L "$binary" ]; then
    die "install requires an executable broker binary"
  fi
  if [ -z "$policy" ] || [ ! -f "$policy" ] || [ -L "$policy" ]; then
    die "install requires a regular non-symlink policy"
  fi
  validate_trusted_install_source "$binary"
  validate_trusted_install_source "$policy"

  local here generation_dir target_binary target_policy existing_generation=0
  here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  validate_trusted_install_source "$here/$(basename "${BASH_SOURCE[0]}")"
  if [ "$(platform)" = linux ]; then
    validate_trusted_install_source "$here/linux/$UNIT.service"
    validate_trusted_install_source "$here/linux/$UNIT.socket"
    validate_trusted_install_source "$here/linux/$UNIT.tmpfiles.conf"
  else
    validate_trusted_install_source "$here/macos/one.arcanada.credential-broker.plist"
  fi
  generation_dir="$GENERATION_ROOT/$generation"
  target_binary=$(generation_binary "$generation")
  target_policy=$(generation_policy "$generation")

  # Every install attempt is disable-first, including an identical-generation
  # retry after a prior crash. Service assets are repaired below on every run.
  disable_broker >/dev/null

  if [ -e "$generation_dir" ] || [ -e "$target_binary" ]; then
    if [ -f "$(generation_manifest "$generation")" ]; then
      verify_generation_archive "$generation"
      [ "$(file_digest "$binary")" = "$(file_digest "$target_binary")" ] || \
        die "generation name is immutable and already identifies a different binary"
      [ "$(file_digest "$policy")" = "$(file_digest "$target_policy")" ] || \
        die "generation name is immutable and already identifies a different policy"
      ok "generation $generation is already staged with identical immutable artifacts"
      existing_generation=1
    else
      # A generation becomes authoritative only when its root-owned manifest is
      # durable. Exact, validated-name debris from a pre-manifest crash is safe
      # to remove and restage; an existing manifest is never rewritten.
      if [ "$SERVICE_MODE" != rehearsal ]; then
        if [ -e "$generation_dir" ] && [ "$(file_owner "$generation_dir")" != root ]; then
          die "incomplete generation directory is not root-owned"
        fi
        if [ -e "$target_binary" ] && [ "$(file_owner "$target_binary")" != root ]; then
          die "incomplete generation binary is not root-owned"
        fi
      fi
      rm -rf -- "$generation_dir"
      rm -f -- "$target_binary"
      ok "removed incomplete pre-manifest staging for generation $generation"
    fi
  fi

  if [ "$SERVICE_MODE" = rehearsal ]; then
    install -d -m 0755 "$LIBEXEC"
  else
    install -d -m 0755 -o root -g root "$LIBEXEC"
  fi
  if [ "$SERVICE_MODE" = rehearsal ]; then
    install -d -m 0700 "$STATE_DIR" "$CONTROL_DIR" "$RUNTIME_GENERATION_DIR" \
      "$GENERATION_ROOT" "$CRED_DIR"
    if [ "$existing_generation" -eq 0 ]; then install -d -m 0700 "$generation_dir"; fi
  else
    id -u "$BROKER_USER" >/dev/null 2>&1 || die "broker user does not exist"
    getent group "$BROKER_GROUP" >/dev/null 2>&1 || {
      [ "$(platform)" = macos ] && dscl . -read "/Groups/$BROKER_GROUP" >/dev/null 2>&1
    } || die "broker group does not exist"
    getent group "$EXECUTOR_GROUP" >/dev/null 2>&1 || {
      [ "$(platform)" = macos ] && dscl . -read "/Groups/$EXECUTOR_GROUP" >/dev/null 2>&1
    } || die "executor group does not exist"
    install -d -m 0700 -o "$BROKER_USER" -g "$BROKER_GROUP" "$STATE_DIR" "$CRED_DIR"
    install -d -m 0700 -o root -g root "$CONTROL_DIR" "$RUNTIME_GENERATION_DIR"
    install -d -m 0750 -o root -g "$BROKER_GROUP" "$GENERATION_ROOT"
    if [ "$existing_generation" -eq 0 ]; then
      install -d -m 0750 -o root -g "$BROKER_GROUP" "$generation_dir"
    fi
    if [ "$(platform)" = macos ]; then
      install -d -m 0750 -o "$BROKER_USER" -g "$EXECUTOR_GROUP" "$(dirname "$SOCKET_PATH")"
      install -d -m 0750 -o "$BROKER_USER" -g "$BROKER_GROUP" "$LOG_DIR"
      clear_macos_acl "$(dirname "$SOCKET_PATH")"
      clear_macos_acl "$STATE_DIR"
      clear_macos_acl "$CONTROL_DIR"
      clear_macos_acl "$RUNTIME_GENERATION_DIR"
      clear_macos_acl "$CRED_DIR"
    fi
  fi
  if [ "$existing_generation" -eq 0 ]; then
    if [ "$SERVICE_MODE" = rehearsal ]; then
      install -m 0755 "$binary" "$target_binary"
      install -m 0644 "$policy" "$generation_dir/capability-policy.toml"
    else
      install -m 0755 -o root -g root "$binary" "$target_binary"
      install -m 0640 -o root -g "$BROKER_GROUP" \
        "$policy" "$generation_dir/capability-policy.toml"
    fi
    [ "$(file_digest "$binary")" = "$(file_digest "$target_binary")" ] || \
      die "staged binary digest differs from source"
    [ "$(file_digest "$policy")" = "$(file_digest "$generation_dir/capability-policy.toml")" ] || \
      die "staged policy digest differs from source"
    write_generation_manifest "$generation" "$(file_digest "$target_binary")" \
      "$(file_digest "$generation_dir/capability-policy.toml")"
    verify_generation_archive "$generation"
  fi

  if [ "$SERVICE_MODE" = rehearsal ]; then
    install -m 0644 "$target_policy" "$POLICY_FILE"
  else
    install -m 0640 -o root -g "$BROKER_GROUP" "$target_policy" "$POLICY_FILE"
  fi
  write_token_atomic "$generation" "$PENDING_FILE"

  if [ "$SERVICE_MODE" != rehearsal ]; then
    if [ "$(platform)" = linux ]; then
      install -m 0644 "$here/linux/$UNIT.service" "$(rooted /etc/systemd/system/$UNIT.service)"
      install -m 0644 "$here/linux/$UNIT.socket" "$(rooted /etc/systemd/system/$UNIT.socket)"
      install -m 0644 "$here/linux/$UNIT.tmpfiles.conf" "$(rooted /etc/tmpfiles.d/$UNIT.conf)"
      systemd-tmpfiles --create "$(rooted /etc/tmpfiles.d/$UNIT.conf)"
      systemctl daemon-reload
    else
      install -m 0644 "$here/macos/one.arcanada.credential-broker.plist" \
        "$(rooted /Library/LaunchDaemons/one.arcanada.credential-broker.plist)"
    fi
  fi
  ok "staged generation $generation; credentialed execution remains disabled"
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
    local managed load_state enabled active
    for managed in "$UNIT.socket" "$UNIT.service"; do
      load_state=$(systemctl show "$managed" --property=LoadState --value) \
        || die "systemd unit load state is unreadable: $managed"
      if [ "$load_state" = not-found ]; then
        continue
      fi
      [ "$load_state" = loaded ] || die "systemd unit load state is unsafe: $managed ($load_state)"
      systemctl disable --now "$managed" \
        || die "systemd failed to disable broker activation: $managed"
      enabled=$(systemctl is-enabled "$managed" 2>/dev/null || true)
      [ "$enabled" = disabled ] || die "systemd unit remains enabled after disable: $managed"
      active=$(systemctl show "$managed" --property=ActiveState --value) \
        || die "systemd unit state is unreadable after disable: $managed"
      [ "$active" = inactive ] || die "systemd unit is not inactive after disable: $managed"
    done
    [ ! -S "$SOCKET_PATH" ] || die "systemd broker socket remains after disable"
  else
    launchctl disable system/one.arcanada.credential-broker || die "launchd failed to persistently disable broker"
    if launchctl print system/one.arcanada.credential-broker >/dev/null 2>&1; then
      launchctl bootout system/one.arcanada.credential-broker || die "launchd failed to unload broker"
    fi
    if launchctl print system/one.arcanada.credential-broker >/dev/null 2>&1; then
      die "launchd broker remains loaded after disable"
    fi
    launchd_broker_disabled || die "launchd broker enable override remains after disable"
    [ ! -S "$SOCKET_PATH" ] || die "launchd broker socket remains after disable"
  fi
  ok "credentialed execution DISABLED"
}

activate_broker() {
  local target="${1:-}"
  if [ -z "$target" ]; then
    [ -s "$PENDING_FILE" ] || die "activate requires a staged generation"
    target=$(sed -n '1p' "$PENDING_FILE")
  fi
  select_generation "$target"
  verify_installed_generation
  if [ "$SERVICE_MODE" = rehearsal ]; then
    disable_broker >/dev/null
    install -d -m 0700 "$(dirname "$SOCKET_PATH")"
    "$(current_binary)" --mock-provider --policy "$POLICY_FILE" --socket "$SOCKET_PATH" \
      --state "$RUNTIME_STATE" \
      --audit "$STATE_DIR/audit.log" \
      >"$STATE_DIR/rehearsal.log" 2>&1 &
    local pid=$!
    printf '%s\n' "$pid" > "$PID_FILE"
    chmod 0600 "$PID_FILE"
    local attempts=0
    while [ ! -S "$SOCKET_PATH" ] && kill -0 "$pid" 2>/dev/null && [ "$attempts" -lt 100 ]; do
      sleep 0.02
      attempts=$((attempts + 1))
    done
    if ! kill -0 "$pid" 2>/dev/null; then
      # Rehearsal always uses the mock provider and starts before any request,
      # so bounded startup diagnostics cannot contain credential material.
      if [ -f "$STATE_DIR/rehearsal.log" ]; then
        sed -n '1,20p' "$STATE_DIR/rehearsal.log" >&2
      fi
      die "rehearsal broker exited during activation"
    fi
    [ -S "$SOCKET_PATH" ] || { disable_broker >/dev/null; die "rehearsal socket did not appear"; }
  elif [ "$(platform)" = linux ]; then
    systemctl enable --now "$UNIT.socket"
    systemctl restart "$UNIT.service"
  else
    launchctl bootstrap system "$(rooted /Library/LaunchDaemons/one.arcanada.credential-broker.plist)"
    launchctl enable system/one.arcanada.credential-broker
    launchctl kickstart -k system/one.arcanada.credential-broker
  fi
  verify
  rm -f -- "$PENDING_FILE"
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
  local result
  set +e
  (set -euo pipefail; activate_broker "$target")
  result=$?
  set -e
  if [ "$result" -ne 0 ]; then
    disable_broker
    die "rollback generation failed verification; terminal state is disabled"
  fi
  ok "rolled back binary and config to generation $target"
}

case "${1:-}" in
  install|activate|disable|rollback) acquire_lifecycle_lock ;;
esac

case "${1:-}" in
  install) shift; install_broker "${1:-}" "${2:-}" "${3:-}" ;;
  activate)
    set +e
    (set -euo pipefail; activate_broker)
    result=$?
    set -e
    if [ "$result" -ne 0 ]; then
      disable_broker
      die "activation failed verification; terminal state is disabled"
    fi
    ;;
  verify) verify ;;
  disable) disable_broker ;;
  rollback) shift; rollback "${1:-}" ;;
  *) printf 'usage: %s {install <generation> <binary> <policy>|activate|verify|disable|rollback <generation|disabled>}\n' "$0" >&2; exit 2 ;;
esac
