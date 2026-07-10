#!/usr/bin/env bash
# check-binary-name.sh — public package-name collision probe.
#
# Checks a candidate crate/package name against three public namespaces
# before it is published anywhere: crates.io (cargo install <name>),
# Homebrew core (brew install <name>), and the local apt index
# (apt-cache search <name>). Read-only — makes no publish/tap/install
# calls of its own; it only reports.
#
# Usage:
#   dev-tools/check-binary-name.sh <name> [<name> ...]
#
# Exit codes:
#   0  every candidate name is free everywhere it could be checked
#   1  at least one candidate collides in at least one namespace
#   2  usage error
#
# Network dependency: crates.io + formulae.brew.sh over HTTPS. apt-cache
# uses whatever local index is present (CI runners refresh it; a stale or
# empty local index yields "no matches" rather than a false PASS — treat
# apt-cache misses as inconclusive, not as proof of availability).
#
# CRATES_IO_BASE / BREW_API_BASE env vars override the API roots — used by
# dev-tools/tests/check-binary-name.bats to point at a local fixture server
# instead of live crates.io/homebrew (deterministic, no flaky network dep
# on real-world registry state).

set -uo pipefail

if [[ $# -eq 0 ]]; then
    echo "Usage: $(basename "$0") <name> [<name> ...]" >&2
    exit 2
fi

CRATES_UA="arcana-agent-system-check-binary-name/1.0 (github.com/Arcanada-one/arcana-agent-system)"
CRATES_IO_BASE="${CRATES_IO_BASE:-https://crates.io/api/v1/crates}"
BREW_API_BASE="${BREW_API_BASE:-https://formulae.brew.sh/api/formula}"
OVERALL_STATUS=0

check_crates_io() {
    local name="$1"
    local response
    response=$(curl -s -m 10 -A "${CRATES_UA}" "${CRATES_IO_BASE}/${name}" 2>/dev/null)
    if [[ -z "${response}" ]]; then
        echo "  crates.io:  UNKNOWN (request failed)"
        return
    fi
    if echo "${response}" | grep -q '"errors"'; then
        echo "  crates.io:  free"
    else
        echo "  crates.io:  TAKEN"
        OVERALL_STATUS=1
    fi
}

check_homebrew() {
    local name="$1"
    local http_code
    http_code=$(curl -s -m 10 -o /dev/null -w "%{http_code}" "${BREW_API_BASE}/${name}.json" 2>/dev/null)
    case "${http_code}" in
        404) echo "  homebrew:   free" ;;
        200) echo "  homebrew:   TAKEN"; OVERALL_STATUS=1 ;;
        *)   echo "  homebrew:   UNKNOWN (http ${http_code})" ;;
    esac
}

check_apt() {
    local name="$1"
    if ! command -v apt-cache >/dev/null 2>&1; then
        echo "  apt-cache:  UNKNOWN (apt-cache not installed)"
        return
    fi
    local hits
    hits=$(apt-cache search "^${name}\$" 2>/dev/null)
    if [[ -n "${hits}" ]]; then
        echo "  apt-cache:  TAKEN — ${hits}"
        OVERALL_STATUS=1
    else
        echo "  apt-cache:  no local-index match (inconclusive if index is stale/empty)"
    fi
}

for name in "$@"; do
    echo "=== ${name} ==="
    check_crates_io "${name}"
    check_homebrew "${name}"
    check_apt "${name}"
done

exit "${OVERALL_STATUS}"
