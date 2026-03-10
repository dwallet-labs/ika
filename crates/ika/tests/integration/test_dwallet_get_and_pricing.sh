#!/usr/bin/env bash
# test_dwallet_get_and_pricing.sh — Test read-only query commands.
#
# Tests: dwallet get, dwallet pricing, dwallet get-encryption-key.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

setup_test_tmpdir
trap cleanup_test_tmpdir EXIT

echo "=========================================="
echo " Query Command Tests"
echo "=========================================="

test_dwallet_get() {
    local encryption_key_id
    encryption_key_id=$(ensure_encryption_key "secp256k1")
    local create_result
    create_result=$(create_dwallet "secp256k1" "$encryption_key_id")
    local dwallet_id
    dwallet_id=$(json_field "$create_result" "dwallet_id")

    local get_result
    get_result=$(ika_json dwallet get --dwallet-id "$dwallet_id")
    json_has_field "$get_result" "dwallet"
    local curve
    curve=$(python3 -c "import json,sys; d=json.loads(sys.argv[1]); print(d['dwallet']['fields']['curve'])" "$get_result")
    [[ "$curve" == "0" ]]
}

test_dwallet_pricing() {
    local result
    result=$(ika_json dwallet pricing)
    json_has_field "$result" "pricing"
}

test_get_encryption_key() {
    local encryption_key_id
    encryption_key_id=$(ensure_encryption_key "secp256k1")
    local result
    result=$(ika_json dwallet get-encryption-key --encryption-key-id "$encryption_key_id")
    json_has_field "$result" "dwallet"
}

run_test "dwallet get"              test_dwallet_get
run_test "dwallet pricing"          test_dwallet_pricing
run_test "dwallet get-encryption-key" test_get_encryption_key

print_summary
