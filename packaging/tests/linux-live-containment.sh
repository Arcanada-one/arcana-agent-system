#!/usr/bin/env bash
# Live Linux cgroup-v2 hostile-descendant negative control. This test creates
# only uniquely named user-manager transient units and credential-free fixtures.
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'SEC0030_LINUX_CONTAINMENT_FAIL: %s\n' "$1" >&2
  exit 1
}

[[ "$(uname -s)" == Linux ]] || fail 'Linux host required'
[[ -f /sys/fs/cgroup/cgroup.controllers ]] || fail 'unified cgroup v2 required'
command -v systemd-run >/dev/null 2>&1 || fail 'systemd-run required'
command -v systemctl >/dev/null 2>&1 || fail 'systemctl required'
command -v sudo >/dev/null 2>&1 || fail 'sudo required for the system-manager proof'
sudo -n true >/dev/null 2>&1 || fail 'non-interactive system-manager authority required'

script_dir=$(cd "$(dirname "$0")" && pwd)
fixture="$script_dir/fixtures/linux-hostile-descendant.py"
[[ -f "$fixture" ]] || fail 'hostile descendant fixture missing'

scratch=$(mktemp -d)
run_id="sec0030-containment-$(date +%s)-$$"
[[ "$run_id" =~ ^sec0030-containment-[0-9]+-[0-9]+$ ]] || fail 'unsafe run identifier'
units=()

cleanup() {
  local unit cleanup_status=0 pid expected observed
  for unit in "${units[@]}"; do
    [[ "$unit" =~ ^sec0030-containment-[0-9]+-[0-9]+-[1-5]\.service$ ]] || continue
    if sudo -n systemctl is-active --quiet "$unit"; then
      sudo -n systemctl stop "$unit" >/dev/null 2>&1 || cleanup_status=1
    fi
    if sudo -n systemctl is-active --quiet "$unit"; then
      cleanup_status=1
    fi
    sudo -n systemctl reset-failed "$unit" >/dev/null 2>&1 || true
  done
  while IFS=$'\t' read -r pid expected; do
    [[ "$pid" =~ ^[1-9][0-9]*$ && "$expected" =~ ^[1-9][0-9]*$ ]] || continue
    observed=$(start_time "$pid" 2>/dev/null || true)
    [[ -z "$observed" || "$observed" != "$expected" ]] || cleanup_status=1
  done < <(find "$scratch" -type f \( -name leader.json -o -name descendant.json \) \
    -exec jq -r '[.pid, .start_time] | @tsv' {} + 2>/dev/null || true)
  find "$scratch" -depth -mindepth 1 -delete || cleanup_status=1
  rmdir "$scratch" || cleanup_status=1
  if (( cleanup_status != 0 )); then
    printf '%s\n' 'SEC0030_LINUX_CONTAINMENT_CLEANUP_FAIL' >&2
    return 1
  fi
  printf '%s\n' 'SEC0030_LINUX_CONTAINMENT_CLEANUP_PASS units=inactive pids=absent scratch=absent'
}
on_exit() {
  local status=$?
  trap - EXIT
  cleanup || status=1
  exit "$status"
}
trap on_exit EXIT

wait_for_file() {
  local path="$1"
  for _ in {1..100}; do
    [[ -s "$path" ]] && return 0
    sleep 0.05
  done
  fail "timed out waiting for $(basename "$path")"
}

start_time() {
  local pid="$1"
  [[ -r "/proc/$pid/stat" ]] || return 1
  awk '{print $22}' "/proc/$pid/stat" 2>/dev/null
}

wait_for_pid_identity_to_end() {
  local pid="$1" expected="$2" observed
  for _ in {1..100}; do
    if ! observed=$(start_time "$pid"); then
      return 0
    fi
    if [[ "$observed" != "$expected" ]]; then
      printf 'start time changed for reused pid=%s\n' "$pid"
      return 0
    fi
    sleep 0.05
  done
  fail "pid $pid retained start time $expected after cgroup stop"
}

properties=(
  'Type=exec'
  'ExitType=cgroup'
  'KillMode=control-group'
  'Delegate=no'
  'ProtectControlGroups=yes'
  'SendSIGKILL=yes'
  'TimeoutStopSec=5s'
  'RuntimeMaxSec=30s'
  'TasksMax=32'
  'MemoryMax=64M'
  'NoNewPrivileges=yes'
  'RestrictSUIDSGID=yes'
  'CapabilityBoundingSet='
  'AmbientCapabilities='
)
run_user=$(id -un)
run_group=$(id -gn)

for iteration in 1 2 3 4 5; do
  unit="$run_id-$iteration.service"
  units+=("$unit")
  output="$scratch/$iteration"
  mkdir -m 0700 "$output"
  systemd_args=(--quiet --unit "$unit" --property "User=$run_user" --property "Group=$run_group")
  for property in "${properties[@]}"; do
    systemd_args+=(--property "$property")
  done
  sudo -n systemd-run "${systemd_args[@]}" /usr/bin/python3 "$fixture" "$output"

  wait_for_file "$output/leader.json"
  wait_for_file "$output/descendant.json"
  wait_for_file "$output/marker"
  leader_pid=$(jq -r '.pid' "$output/leader.json")
  leader_start=$(jq -r '.start_time' "$output/leader.json")
  descendant_pid=$(jq -r '.pid' "$output/descendant.json")
  descendant_start=$(jq -r '.start_time' "$output/descendant.json")
  recorded_cgroup=$(jq -r '.cgroup' "$output/descendant.json")
  control_group=$(sudo -n systemctl show "$unit" --property=ControlGroup --value)
  [[ "$recorded_cgroup" == "$control_group" ]] || fail 'detached descendant escaped the transient service cgroup'
  jq -e 'all(.escape_attempts[]; .result == "denied")' "$output/descendant.json" >/dev/null \
    || fail 'cgroup.procs write unexpectedly succeeded'

  [[ "$(sudo -n systemctl show "$unit" --property=Type --value)" == exec ]] || fail 'effective Type is not exec'
  [[ "$(sudo -n systemctl show "$unit" --property=ExitType --value)" == cgroup ]] || fail 'effective ExitType is not cgroup'
  [[ "$(sudo -n systemctl show "$unit" --property=KillMode --value)" == control-group ]] || fail 'effective KillMode is not control-group'
  [[ "$(sudo -n systemctl show "$unit" --property=Delegate --value)" == no ]] || fail 'effective Delegate is not no'
  [[ "$(sudo -n systemctl show "$unit" --property=ProtectControlGroups --value)" == yes ]] || fail 'effective ProtectControlGroups is not yes'
  cgroup_events="/sys/fs/cgroup${control_group}/cgroup.events"
  grep -qx 'populated 1' "$cgroup_events" || fail 'cgroup was not populated before the negative control'

  if [[ "$iteration" == 1 ]]; then
    marker_before=$(<"$output/marker")
    kill -- "-$leader_pid"
    wait_for_pid_identity_to_end "$leader_pid" "$leader_start"
    sleep 0.25
    marker_after=$(<"$output/marker")
    (( marker_after > marker_before )) || fail 'detached child did not survive the causal process-group kill'
    [[ "$(start_time "$descendant_pid")" == "$descendant_start" ]] || fail 'descendant identity changed before cgroup stop'
    printf 'marker advanced after process-group kill: before=%s after=%s\n' "$marker_before" "$marker_after"
  fi

  populated_receipt="$output/populated-zero"
  watcher_ready="$output/watcher-ready"
  python3 - "$cgroup_events" "$populated_receipt" "$watcher_ready" <<'PY' &
import os
import errno
from pathlib import Path
import sys
import time

fd = os.open(sys.argv[1], os.O_RDONLY)
Path(sys.argv[3]).write_text("ready\n", encoding="ascii")
try:
    for _ in range(200):
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            value = os.read(fd, 4096).decode("ascii")
        except OSError as error:
            if error.errno == errno.ENODEV and not Path(sys.argv[1]).exists():
                Path(sys.argv[2]).write_text(
                    "populated 0; cgroup removed by systemd after stop\n", encoding="ascii"
                )
                raise SystemExit(0)
            raise
        if "populated 0" in value.splitlines():
            Path(sys.argv[2]).write_text("populated 0\n", encoding="ascii")
            raise SystemExit(0)
        time.sleep(0.025)
finally:
    os.close(fd)
raise SystemExit(1)
PY
  watcher_pid=$!
  wait_for_file "$watcher_ready"
  sudo -n systemctl stop "$unit"
  wait "$watcher_pid" || fail 'cgroup.events did not report populated 0'
  grep -q '^populated 0' "$populated_receipt" || fail 'missing populated 0 receipt'
  wait_for_pid_identity_to_end "$leader_pid" "$leader_start"
  wait_for_pid_identity_to_end "$descendant_pid" "$descendant_start"
  marker_stopped=$(<"$output/marker")
  sleep 0.2
  [[ "$(<"$output/marker")" == "$marker_stopped" ]] || fail 'marker advanced after cgroup stop'
  sudo -n systemctl reset-failed "$unit" >/dev/null 2>&1 || true
done

printf 'SEC0030_LINUX_CONTAINMENT_PASS iterations=5 causal_process_group_escape=1 cgroup_escape_denied=1 populated_zero=5\n'
