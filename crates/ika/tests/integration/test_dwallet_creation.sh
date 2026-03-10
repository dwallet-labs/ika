#!/usr/bin/env bash
# test_dwallet_creation.sh — dWallet creation for all curves (mirrors dwallet-creation.test.ts).
#
# Tests zero-trust dWallet creation via DKG for all 4 curves.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

setup_test_tmpdir
trap cleanup_test_tmpdir EXIT

echo "=========================================="
echo " dWallet Creation Tests"
echo "=========================================="

# --- Zero-trust creation for each curve ---

test_create_secp256k1() {
    local encryption_key_id
    encryption_key_id=$(ensure_encryption_key "secp256k1")
    local result
    result=$(create_dwallet "secp256k1" "$encryption_key_id")
    local dwallet_id
    dwallet_id=$(json_field "$result" "dwallet_id")
    [[ -n "$dwallet_id" && "$dwallet_id" != "null" ]]
    local fields
    fields=$(fetch_object_fields "$dwallet_id")
    local curve
    curve=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['curve'])" "$fields")
    [[ "$curve" == "0" ]]
}

test_create_secp256r1() {
    local encryption_key_id
    encryption_key_id=$(ensure_encryption_key "secp256r1")
    local result
    result=$(create_dwallet "secp256r1" "$encryption_key_id")
    local dwallet_id
    dwallet_id=$(json_field "$result" "dwallet_id")
    [[ -n "$dwallet_id" && "$dwallet_id" != "null" ]]
    local fields
    fields=$(fetch_object_fields "$dwallet_id")
    local curve
    curve=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['curve'])" "$fields")
    [[ "$curve" == "1" ]]
}

test_create_ed25519() {
    local encryption_key_id
    encryption_key_id=$(ensure_encryption_key "ed25519")
    local result
    result=$(create_dwallet "ed25519" "$encryption_key_id")
    local dwallet_id
    dwallet_id=$(json_field "$result" "dwallet_id")
    [[ -n "$dwallet_id" && "$dwallet_id" != "null" ]]
    local fields
    fields=$(fetch_object_fields "$dwallet_id")
    local curve
    curve=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['curve'])" "$fields")
    [[ "$curve" == "2" ]]
}

test_create_ristretto() {
    local encryption_key_id
    encryption_key_id=$(ensure_encryption_key "ristretto")
    local result
    result=$(create_dwallet "ristretto" "$encryption_key_id")
    local dwallet_id
    dwallet_id=$(json_field "$result" "dwallet_id")
    [[ -n "$dwallet_id" && "$dwallet_id" != "null" ]]
    local fields
    fields=$(fetch_object_fields "$dwallet_id")
    local curve
    curve=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['curve'])" "$fields")
    [[ "$curve" == "3" ]]
}

run_test "Create secp256k1 dWallet"  test_create_secp256k1
run_test "Create secp256r1 dWallet"  test_create_secp256r1
run_test "Create ed25519 dWallet"    test_create_ed25519
run_test "Create ristretto dWallet"  test_create_ristretto

print_summary
