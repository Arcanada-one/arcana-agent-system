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
    local http_code
    # Decided on the HTTP status, as `check_homebrew` below already does.
    #
    # This used to grep the body for `"errors"` and report "free" when it found
    # it. That string is in a 404 body, so it agreed with the truth for as long
    # as crates.io only ever answered 200 or 404 — and it is in EVERY error
    # body. Under a 429, a 500, or a maintenance page, every name checked reads
    # "free". Verified against a local server returning
    # `429 {"errors":[...]}`: `serde` came back free.
    #
    # The direction matters. "Free" is the permissive answer here — it is what
    # licenses an attempt to publish, and a crates.io version that fails is
    # burned permanently. An outage must produce UNKNOWN, never an all-clear.
    http_code=$(curl -s -m 10 -o /dev/null -w "%{http_code}" \
        -A "${CRATES_UA}" "${CRATES_IO_BASE}/${name}" 2>/dev/null)
    case "${http_code}" in
        404) echo "  crates.io:  free" ;;
        200) echo "  crates.io:  TAKEN"; OVERALL_STATUS=1 ;;
        000) echo "  crates.io:  UNKNOWN (request failed)" ;;
        *)   echo "  crates.io:  UNKNOWN (http ${http_code})" ;;
    esac
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
