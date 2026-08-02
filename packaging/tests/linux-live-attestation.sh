#!/usr/bin/env bash
# Native Linux negative control: per-message SCM credentials plus enforcing
# AppArmor denial after a connected seqpacket descriptor changes hands.
set -euo pipefail
IFS=$'\n\t'
umask 077

fail() {
  printf 'SEC0030_LINUX_ATTESTATION_FAIL: %s\n' "$1" >&2
  exit 1
}

[[ "$(uname -s)" == Linux ]] || fail 'Linux host required'
for tool in aa-enabled aa-exec apparmor_parser gcc python3 sudo; do
  command -v "$tool" >/dev/null 2>&1 || fail "required tool unavailable: $tool"
done
aa-enabled >/dev/null 2>&1 || fail 'AppArmor is not enabled'
sudo -n true >/dev/null 2>&1 || fail 'non-interactive AppArmor load authority required'

script_dir=$(cd "$(dirname "$0")" && pwd)
fixture_dir="$script_dir/fixtures"
scratch=$(mktemp -d)
run_id="sec0030-attestation-$(date +%s)-$$"
[[ "$run_id" =~ ^sec0030-attestation-[0-9]+-[0-9]+$ ]] || fail 'unsafe run identifier'
trusted_profile="$run_id.trusted"
denied_profile="$run_id.denied"
profile_file="$scratch/apparmor.profile"
helper="$scratch/seqpacket-sender"
profile_loaded=0

cleanup() {
  local cleanup_status=0
  if (( profile_loaded == 1 )); then
    sudo -n apparmor_parser -R "$profile_file" >/dev/null 2>&1 || cleanup_status=1
    if sudo -n grep -Eq "^(${trusted_profile}|${denied_profile}) \(" \
      /sys/kernel/security/apparmor/profiles; then
      cleanup_status=1
    fi
  fi
  find "$scratch" -depth -mindepth 1 -delete || cleanup_status=1
  rmdir "$scratch" || cleanup_status=1
  if (( cleanup_status != 0 )); then
    printf '%s\n' 'SEC0030_LINUX_ATTESTATION_CLEANUP_FAIL' >&2
    return 1
  fi
  printf '%s\n' 'SEC0030_LINUX_ATTESTATION_CLEANUP_PASS profiles=absent scratch=absent'
}
on_exit() {
  local status=$?
  trap - EXIT
  cleanup || status=1
  exit "$status"
}
trap on_exit EXIT

gcc -O2 -Wall -Wextra -Werror -o "$helper" "$fixture_dir/linux-seqpacket-sender.c"
sed \
  -e "s|@@TRUSTED_PROFILE@@|$trusted_profile|g" \
  -e "s|@@DENIED_PROFILE@@|$denied_profile|g" \
  -e "s|@@HELPER@@|$helper|g" \
  "$fixture_dir/sec0030-apparmor.profile.in" > "$profile_file"
sudo -n apparmor_parser -r "$profile_file"
profile_loaded=1

profiles=$(sudo -n sh -c 'exec sed -n "s/ (enforce)$//p" /sys/kernel/security/apparmor/profiles')
grep -Fxq "$trusted_profile" <<<"$profiles" || fail 'trusted AppArmor profile is not loaded (enforce)'
grep -Fxq "$denied_profile" <<<"$profiles" || fail 'denied AppArmor profile is not loaded (enforce)'
# Keep the literal kernel status in the tracked proof contract.
sudo -n grep -Fq '(enforce)' /sys/kernel/security/apparmor/profiles || fail 'AppArmor profile status is unavailable'

python3 "$fixture_dir/linux-seqpacket-attestation.py" \
  --helper "$helper" \
  --trusted-profile "$trusted_profile" \
  --denied-profile "$denied_profile" \
  --address "$run_id"
