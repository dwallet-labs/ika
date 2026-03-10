#!/usr/bin/env bash
# run_all.sh — Run all Ika CLI integration tests.
#
# Prerequisites:
#   1. Local Ika network running:  ika start --force-reinitiation
#   2. CLI binary built:           cargo build --release -p ika
#   3. Config at default path or set IKA_SUI_CONFIG
#
# Usage:
#   ./crates/ika/tests/integration/run_all.sh                    # run all
#   ./crates/ika/tests/integration/run_all.sh creation presign   # run specific suites
#
# Environment variables:
#   IKA_BIN           Path to ika binary (default: ./target/release/ika)
#   SUI_RPC_URL       Sui fullnode RPC (default: http://127.0.0.1:9000)
#   IKA_SUI_CONFIG    Path to ika_sui_config.yaml
#   POLL_INTERVAL     Seconds between polls (default: 3)
#   POLL_TIMEOUT      Max seconds to wait (default: 300)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

export IKA_BIN="${IKA_BIN:-./target/release/ika}"
export SUI_RPC_URL="${SUI_RPC_URL:-http://127.0.0.1:9000}"
export IKA_SUI_CONFIG="${IKA_SUI_CONFIG:-./ika_sui_config.yaml}"

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
echo "Ika CLI Integration Tests"
echo "========================="
echo "  Binary:  $IKA_BIN"
echo "  RPC:     $SUI_RPC_URL"
echo "  Config:  $IKA_SUI_CONFIG"
echo ""

if [[ ! -x "$IKA_BIN" ]]; then
    echo "ERROR: ika binary not found at $IKA_BIN"
    echo "       Run: cargo build --release -p ika"
    exit 1
fi

if [[ ! -f "$IKA_SUI_CONFIG" ]]; then
    echo "ERROR: config not found at $IKA_SUI_CONFIG"
    echo "       Run: ika start --force-reinitiation"
    exit 1
fi

# Check that Sui RPC is reachable
if ! curl -s "$SUI_RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"sui_getLatestCheckpointSequenceNumber","params":[]}' \
    | grep -q '"result"'; then
    echo "ERROR: Sui RPC not reachable at $SUI_RPC_URL"
    echo "       Start local network: ika start --force-reinitiation"
    exit 1
fi

echo "Preflight checks passed."
echo ""

# ---------------------------------------------------------------------------
# Test suite registry (name:script pairs)
# ---------------------------------------------------------------------------
suite_script() {
    case "$1" in
        creation)     echo "test_dwallet_creation.sh" ;;
        queries)      echo "test_dwallet_get_and_pricing.sh" ;;
        presign)      echo "test_global_presign.sh" ;;
        combinations) echo "test_all_combinations.sh" ;;
        imported)     echo "test_imported_key.sh" ;;
        public-share) echo "test_make_public_share.sh" ;;
        *) echo "" ;;
    esac
}

ALL_SUITES="creation queries presign combinations imported public-share"

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if [[ $# -gt 0 ]]; then
    SELECTED="$*"
else
    SELECTED="$ALL_SUITES"
fi

TOTAL_FAIL=0
TOTAL_RUN=0
SUMMARY=""

for suite in $SELECTED; do
    script=$(suite_script "$suite")
    if [[ -z "$script" ]]; then
        echo "Unknown suite: $suite"
        echo "Available: $ALL_SUITES"
        exit 1
    fi

    echo ""
    echo "######################################################################"
    echo "# Suite: $suite"
    echo "######################################################################"

    set +e
    bash "$SCRIPT_DIR/$script"
    rc=$?
    set -e

    if [[ $rc -eq 0 ]]; then
        SUMMARY="${SUMMARY}  PASS  ${suite}\n"
    else
        SUMMARY="${SUMMARY}  FAIL  ${suite} (exit ${rc})\n"
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
    fi
    TOTAL_RUN=$((TOTAL_RUN + 1))
done

echo ""
echo "======================================================================"
echo " ALL SUITES SUMMARY"
echo "======================================================================"
printf "%b" "$SUMMARY"
echo ""
echo "Suites: $TOTAL_RUN total, $((TOTAL_RUN - TOTAL_FAIL)) passed, $TOTAL_FAIL failed"
echo "======================================================================"

exit "$TOTAL_FAIL"
