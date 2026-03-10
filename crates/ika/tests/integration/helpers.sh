#!/usr/bin/env bash
# helpers.sh — Shared utilities for Ika CLI integration tests.
#
# Source this file from test scripts:
#   source "$(dirname "$0")/helpers.sh"
#
# Requires: IKA_BIN, SUI_RPC_URL, IKA_SUI_CONFIG environment variables.

set -euo pipefail

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
IKA_BIN="${IKA_BIN:-./target/release/ika}"
SUI_RPC_URL="${SUI_RPC_URL:-http://127.0.0.1:9000}"
IKA_SUI_CONFIG="${IKA_SUI_CONFIG:-./ika_sui_config.yaml}"
POLL_INTERVAL="${POLL_INTERVAL:-3}"
POLL_TIMEOUT="${POLL_TIMEOUT:-300}"  # seconds

# Counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
FAIL_NAMES=()

# ---------------------------------------------------------------------------
# Curve / algorithm / hash numeric IDs
#   Matches: crates/dwallet-mpc-types/src/mpc_protocol_configuration.rs
# ---------------------------------------------------------------------------
CURVE_SECP256K1=0
CURVE_SECP256R1=1
CURVE_ED25519=2
CURVE_RISTRETTO=3

# Signature algorithms (per-curve relative)
SIG_ECDSA_SECP256K1=0   # curve 0
SIG_TAPROOT=1            # curve 0
SIG_ECDSA_SECP256R1=0   # curve 1
SIG_EDDSA=0              # curve 2
SIG_SCHNORRKEL=0         # curve 3

# Hash schemes (per curve+algo)
HASH_KECCAK256=0    # secp256k1 + ECDSA
HASH_SHA256=1       # secp256k1 + ECDSA
HASH_DOUBLE_SHA256=2 # secp256k1 + ECDSA
HASH_TAPROOT_SHA256=0 # secp256k1 + Taproot
HASH_SECP256R1_SHA256=0
HASH_ED25519_SHA512=0
HASH_RISTRETTO_MERLIN=0

# Imported key test vectors (matching TS SDK tests)
IMPORTED_KEY_SECP256K1="20255a048b64a9930517e91a2ee6b3aa6ea78131a4ad88f20cb3d351f28d6fe653"
IMPORTED_KEY_SECP256R1="20c53afc96882df03726eba161dcddfc4a44c08dea525700692b99db108125ed5f"
IMPORTED_KEY_ED25519="7aca0549f93cc4a2052a23f10fc8577d1aba9058766eeebdaa0a7f39bbe91606"
IMPORTED_KEY_RISTRETTO="1ac94bd6e52bc134b6d482f6443d3c61bd987366dffc2c717bcb35dc62e5650b"

# Temp directory for test artifacts
TEST_TMPDIR=""

# ---------------------------------------------------------------------------
# Setup / teardown
# ---------------------------------------------------------------------------
setup_test_tmpdir() {
    TEST_TMPDIR="$(mktemp -d /tmp/ika_cli_e2e.XXXXXX)"
}

cleanup_test_tmpdir() {
    if [[ -n "${TEST_TMPDIR}" && -d "${TEST_TMPDIR}" ]]; then
        rm -rf "${TEST_TMPDIR}"
    fi
}

# ---------------------------------------------------------------------------
# Test runner helpers
# ---------------------------------------------------------------------------
test_pass() {
    local name="$1"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo "  PASS  $name"
}

test_fail() {
    local name="$1"
    local reason="${2:-}"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_FAILED=$((TESTS_FAILED + 1))
    FAIL_NAMES+=("$name")
    echo "  FAIL  $name"
    if [[ -n "$reason" ]]; then
        echo "        $reason"
    fi
}

# Run a test function; catches failures.
# Usage: run_test "test name" test_function arg1 arg2 ...
run_test() {
    local name="$1"; shift
    echo ""
    echo "--- $name ---"
    if "$@" 2>&1; then
        test_pass "$name"
    else
        test_fail "$name" "exit code $?"
    fi
}

print_summary() {
    echo ""
    echo "============================================"
    echo " RESULTS: $TESTS_PASSED/$TESTS_RUN passed"
    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo " FAILED ($TESTS_FAILED):"
        for n in "${FAIL_NAMES[@]}"; do
            echo "   - $n"
        done
    fi
    echo "============================================"
    return "$TESTS_FAILED"
}

# ---------------------------------------------------------------------------
# CLI wrappers (always use --json and suppress stderr unless debugging)
# ---------------------------------------------------------------------------
ika_json() {
    "$IKA_BIN" --json --yes "$@" --ika-sui-config "$IKA_SUI_CONFIG" 2>/dev/null
}

# Like ika_json but passes stderr through (for debugging).
ika_verbose() {
    "$IKA_BIN" --json --yes "$@" --ika-sui-config "$IKA_SUI_CONFIG"
}

# ---------------------------------------------------------------------------
# JSON helpers (using python3 for portability)
# ---------------------------------------------------------------------------
json_field() {
    # json_field '{"a":"b"}' a  ->  b
    python3 -c "import json,sys; d=json.loads(sys.argv[1]); print(d['$2'])" "$1"
}

json_field_nested() {
    # json_field_nested '{"a":{"b":"c"}}' 'a' 'b'  ->  c
    python3 -c "
import json, sys
d = json.loads(sys.argv[1])
keys = sys.argv[2:]
for k in keys:
    d = d[k]
print(d)
" "$@"
}

json_has_field() {
    python3 -c "import json,sys; d=json.loads(sys.argv[1]); sys.exit(0 if '$2' in d else 1)" "$1"
}

# ---------------------------------------------------------------------------
# Sui RPC helpers
# ---------------------------------------------------------------------------
sui_rpc() {
    local method="$1"; shift
    curl -s "$SUI_RPC_URL" -X POST -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":[$*]}"
}

# Fetch object fields as JSON string.
fetch_object_fields() {
    local object_id="$1"
    sui_rpc "sui_getObject" "\"$object_id\", {\"showContent\": true}" | \
        python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)['result']['data']['content']['fields']))"
}

# Get transaction object changes.
tx_created_objects() {
    local digest="$1"
    sui_rpc "sui_getTransactionBlock" "\"$digest\", {\"showObjectChanges\": true}" | \
        python3 -c "
import json, sys
data = json.load(sys.stdin)
for c in data['result'].get('objectChanges', []):
    if c.get('type') == 'created':
        short_type = c['objectType'].split('::')[-1]
        print(f\"{short_type} {c['objectId']}\")
"
}

# Find a specific created object type from a tx digest.
tx_find_created() {
    local digest="$1"
    local type_suffix="$2"
    tx_created_objects "$digest" | grep "$type_suffix" | head -1 | awk '{print $2}'
}

# ---------------------------------------------------------------------------
# Polling helpers
# ---------------------------------------------------------------------------

# Poll a dWallet until its state has public_output (Active).
poll_dwallet_active() {
    local dwallet_id="$1"
    local timeout="${2:-$POLL_TIMEOUT}"
    local start=$SECONDS
    while (( SECONDS - start < timeout )); do
        local fields
        fields=$(fetch_object_fields "$dwallet_id" 2>/dev/null) || true
        local has_output
        has_output=$(python3 -c "
import json, sys
f = json.loads(sys.argv[1])
state = f.get('state', {}).get('fields', {})
print('yes' if state.get('public_output') else 'no')
" "$fields" 2>/dev/null) || true
        if [[ "$has_output" == "yes" ]]; then
            return 0
        fi
        sleep "$POLL_INTERVAL"
    done
    echo "Timeout waiting for dWallet $dwallet_id to become Active" >&2
    return 1
}

# Poll a presign session until it has presign output (Completed).
poll_presign_completed() {
    local presign_session_id="$1"
    local timeout="${2:-$POLL_TIMEOUT}"
    local start=$SECONDS
    while (( SECONDS - start < timeout )); do
        local fields
        fields=$(fetch_object_fields "$presign_session_id" 2>/dev/null) || true
        local has_presign
        has_presign=$(python3 -c "
import json, sys
f = json.loads(sys.argv[1])
state = f.get('state', {}).get('fields', {})
print('yes' if state.get('presign') else 'no')
" "$fields" 2>/dev/null) || true
        if [[ "$has_presign" == "yes" ]]; then
            return 0
        fi
        sleep "$POLL_INTERVAL"
    done
    echo "Timeout waiting for presign $presign_session_id to complete" >&2
    return 1
}

# ---------------------------------------------------------------------------
# Encryption key management
# ---------------------------------------------------------------------------
# Register an encryption key for a curve. Returns the encryption_key_id.
register_encryption_key() {
    local curve_name="$1"
    local result
    result=$(ika_json dwallet register-encryption-key --curve "$curve_name")
    json_field "$result" "encryption_key_id"
}

# Register encryption key only if not already cached in $TEST_TMPDIR.
ensure_encryption_key() {
    local curve_name="$1"
    local cache_file="${TEST_TMPDIR}/enc_key_${curve_name}"
    if [[ -f "$cache_file" ]]; then
        cat "$cache_file"
        return 0
    fi
    local enc_key_id
    enc_key_id=$(register_encryption_key "$curve_name")
    echo "$enc_key_id" > "$cache_file"
    echo "$enc_key_id"
}

# ---------------------------------------------------------------------------
# dWallet creation flow
# ---------------------------------------------------------------------------

# Create a dWallet via DKG. Outputs JSON with dwallet_id, dwallet_cap_id, secret_share_path.
create_dwallet() {
    local curve_name="$1"
    local enc_key_id="$2"
    local output_path="${3:-${TEST_TMPDIR}/secret_${curve_name}_$RANDOM.bin}"
    ika_json dwallet create \
        --curve "$curve_name" \
        --encryption-key-id "$enc_key_id" \
        --output-secret "$output_path"
}

# ---------------------------------------------------------------------------
# Presign flow
# ---------------------------------------------------------------------------

# Request a presign for a dWallet. Returns JSON with digest, status.
request_presign() {
    local dwallet_id="$1"
    local sig_algo="$2"
    ika_json dwallet presign \
        --dwallet-id "$dwallet_id" \
        --signature-algorithm "$sig_algo"
}

# Request a global presign.
request_global_presign() {
    local curve_num="$1"
    local sig_algo="$2"
    ika_json dwallet global-presign \
        --curve "$curve_num" \
        --signature-algorithm "$sig_algo"
}

# Full presign flow: request → wait for completion → verify → return verified cap ID.
do_presign_and_verify() {
    local dwallet_id="$1"
    local sig_algo="$2"

    # Request presign
    local presign_result
    presign_result=$(request_presign "$dwallet_id" "$sig_algo")
    local presign_digest
    presign_digest=$(json_field "$presign_result" "digest")

    # Find UnverifiedPresignCap and PresignSession
    local unverified_cap
    unverified_cap=$(tx_find_created "$presign_digest" "UnverifiedPresignCap")
    local presign_session
    presign_session=$(tx_find_created "$presign_digest" "PresignSession")

    # Wait for completion
    poll_presign_completed "$presign_session"

    # Verify
    local verify_result
    verify_result=$(ika_json dwallet verify-presign --presign-cap-id "$unverified_cap")
    local verify_digest
    verify_digest=$(json_field "$verify_result" "digest")

    # Return verified cap ID
    tx_find_created "$verify_digest" "VerifiedPresignCap"
}

# Full global presign flow: request → wait → verify → return verified cap ID.
do_global_presign_and_verify() {
    local curve_num="$1"
    local sig_algo="$2"

    local presign_result
    presign_result=$(request_global_presign "$curve_num" "$sig_algo")
    local presign_digest
    presign_digest=$(json_field "$presign_result" "digest")

    local unverified_cap
    unverified_cap=$(tx_find_created "$presign_digest" "UnverifiedPresignCap")
    local presign_session
    presign_session=$(tx_find_created "$presign_digest" "PresignSession")

    poll_presign_completed "$presign_session"

    local verify_result
    verify_result=$(ika_json dwallet verify-presign --presign-cap-id "$unverified_cap")
    local verify_digest
    verify_digest=$(json_field "$verify_result" "digest")

    tx_find_created "$verify_digest" "VerifiedPresignCap"
}

# ---------------------------------------------------------------------------
# Sign flow
# ---------------------------------------------------------------------------

# Sign a message with a dWallet. Returns JSON with digest, status.
sign_message() {
    local dwallet_cap_id="$1"
    local dwallet_id="$2"
    local message_hex="$3"
    local sig_algo="$4"
    local hash_scheme="$5"
    local secret_share="$6"
    local presign_cap_id="$7"

    ika_json dwallet sign \
        --dwallet-cap-id "$dwallet_cap_id" \
        --dwallet-id "$dwallet_id" \
        --message "$message_hex" \
        --signature-algorithm "$sig_algo" \
        --hash-scheme "$hash_scheme" \
        --secret-share "$secret_share" \
        --presign-cap-id "$presign_cap_id"
}

# ---------------------------------------------------------------------------
# Import flow
# ---------------------------------------------------------------------------

# Import a key as a dWallet. Returns JSON with dwallet_id, dwallet_cap_id.
import_dwallet() {
    local curve_name="$1"
    local secret_key_hex="$2"
    local enc_key_id="$3"
    local output_path="${4:-${TEST_TMPDIR}/imported_${curve_name}_$RANDOM.bin}"

    # Write the secret key bytes to a temp file
    local key_file="${TEST_TMPDIR}/import_key_$RANDOM.bin"
    echo -n "$secret_key_hex" | xxd -r -p > "$key_file"

    ika_json dwallet import \
        --curve "$curve_name" \
        --centralized-message "$key_file" \
        --encryption-key-id "$enc_key_id" \
        --output-secret "$output_path"
}

# ---------------------------------------------------------------------------
# Full end-to-end flows
# ---------------------------------------------------------------------------

# Complete create → presign → verify → sign flow.
# Returns sign result JSON on success.
full_create_and_sign() {
    local curve_name="$1"
    local sig_algo="$2"
    local hash_scheme="$3"
    local message_hex="${4:-48656c6c6f}"  # "Hello" in hex

    local enc_key_id
    enc_key_id=$(ensure_encryption_key "$curve_name")

    # Create
    local create_result
    create_result=$(create_dwallet "$curve_name" "$enc_key_id")
    local dwallet_id dwallet_cap_id secret_path
    dwallet_id=$(json_field "$create_result" "dwallet_id")
    dwallet_cap_id=$(json_field "$create_result" "dwallet_cap_id")
    secret_path=$(json_field "$create_result" "secret_share_path")

    echo "  Created dWallet: $dwallet_id" >&2

    # Presign + verify
    local verified_cap
    verified_cap=$(do_presign_and_verify "$dwallet_id" "$sig_algo")
    echo "  Verified presign: $verified_cap" >&2

    # Sign
    local sign_result
    sign_result=$(sign_message "$dwallet_cap_id" "$dwallet_id" "$message_hex" "$sig_algo" "$hash_scheme" "$secret_path" "$verified_cap")
    local sign_status
    sign_status=$(json_field "$sign_result" "status")

    if [[ "$sign_status" != "Success" ]]; then
        echo "Sign failed with status: $sign_status" >&2
        return 1
    fi
    echo "  Sign succeeded: $(json_field "$sign_result" "digest")" >&2
}

# Complete import → presign → verify → sign flow.
full_import_and_sign() {
    local curve_name="$1"
    local sig_algo="$2"
    local hash_scheme="$3"
    local secret_key_hex="$4"
    local message_hex="${5:-48656c6c6f}"

    local enc_key_id
    enc_key_id=$(ensure_encryption_key "$curve_name")

    local output_path="${TEST_TMPDIR}/imported_${curve_name}_$RANDOM.bin"

    # Import
    local import_result
    import_result=$(import_dwallet "$curve_name" "$secret_key_hex" "$enc_key_id" "$output_path")
    local dwallet_id dwallet_cap_id
    dwallet_id=$(json_field "$import_result" "dwallet_id")
    dwallet_cap_id=$(json_field "$import_result" "dwallet_cap_id")

    echo "  Imported dWallet: $dwallet_id" >&2

    # Presign + verify (targeted for imported keys)
    local verified_cap
    verified_cap=$(do_presign_and_verify "$dwallet_id" "$sig_algo")
    echo "  Verified presign: $verified_cap" >&2

    # Sign
    local sign_result
    sign_result=$(sign_message "$dwallet_cap_id" "$dwallet_id" "$message_hex" "$sig_algo" "$hash_scheme" "$output_path" "$verified_cap")
    local sign_status
    sign_status=$(json_field "$sign_result" "status")

    if [[ "$sign_status" != "Success" ]]; then
        echo "Sign failed with status: $sign_status" >&2
        return 1
    fi
    echo "  Sign succeeded: $(json_field "$sign_result" "digest")" >&2
}

# Complete create → global-presign → verify → sign flow (for algos requiring global presign).
full_create_and_sign_global_presign() {
    local curve_name="$1"
    local curve_num="$2"
    local sig_algo="$3"
    local hash_scheme="$4"
    local message_hex="${5:-48656c6c6f}"

    local enc_key_id
    enc_key_id=$(ensure_encryption_key "$curve_name")

    # Create
    local create_result
    create_result=$(create_dwallet "$curve_name" "$enc_key_id")
    local dwallet_id dwallet_cap_id secret_path
    dwallet_id=$(json_field "$create_result" "dwallet_id")
    dwallet_cap_id=$(json_field "$create_result" "dwallet_cap_id")
    secret_path=$(json_field "$create_result" "secret_share_path")

    echo "  Created dWallet: $dwallet_id" >&2

    # Global presign + verify
    local verified_cap
    verified_cap=$(do_global_presign_and_verify "$curve_num" "$sig_algo")
    echo "  Verified global presign: $verified_cap" >&2

    # Sign
    local sign_result
    sign_result=$(sign_message "$dwallet_cap_id" "$dwallet_id" "$message_hex" "$sig_algo" "$hash_scheme" "$secret_path" "$verified_cap")
    local sign_status
    sign_status=$(json_field "$sign_result" "status")

    if [[ "$sign_status" != "Success" ]]; then
        echo "Sign failed with status: $sign_status" >&2
        return 1
    fi
    echo "  Sign succeeded: $(json_field "$sign_result" "digest")" >&2
}

# Import with global presign (for EdDSA, SchnorrkelSubstrate, Taproot).
full_import_and_sign_global_presign() {
    local curve_name="$1"
    local curve_num="$2"
    local sig_algo="$3"
    local hash_scheme="$4"
    local secret_key_hex="$5"
    local message_hex="${6:-48656c6c6f}"

    local enc_key_id
    enc_key_id=$(ensure_encryption_key "$curve_name")

    local output_path="${TEST_TMPDIR}/imported_${curve_name}_$RANDOM.bin"

    # Import
    local import_result
    import_result=$(import_dwallet "$curve_name" "$secret_key_hex" "$enc_key_id" "$output_path")
    local dwallet_id dwallet_cap_id
    dwallet_id=$(json_field "$import_result" "dwallet_id")
    dwallet_cap_id=$(json_field "$import_result" "dwallet_cap_id")

    echo "  Imported dWallet: $dwallet_id" >&2

    # Global presign + verify
    local verified_cap
    verified_cap=$(do_global_presign_and_verify "$curve_num" "$sig_algo")
    echo "  Verified global presign: $verified_cap" >&2

    # Sign
    local sign_result
    sign_result=$(sign_message "$dwallet_cap_id" "$dwallet_id" "$message_hex" "$sig_algo" "$hash_scheme" "$output_path" "$verified_cap")
    local sign_status
    sign_status=$(json_field "$sign_result" "status")

    if [[ "$sign_status" != "Success" ]]; then
        echo "Sign failed with status: $sign_status" >&2
        return 1
    fi
    echo "  Sign succeeded: $(json_field "$sign_result" "digest")" >&2
}

# Make user shares public and sign.
full_create_make_public_and_sign() {
    local curve_name="$1"
    local sig_algo="$2"
    local hash_scheme="$3"
    local message_hex="${4:-48656c6c6f}"

    local enc_key_id
    enc_key_id=$(ensure_encryption_key "$curve_name")

    # Create
    local create_result
    create_result=$(create_dwallet "$curve_name" "$enc_key_id")
    local dwallet_id dwallet_cap_id secret_path
    dwallet_id=$(json_field "$create_result" "dwallet_id")
    dwallet_cap_id=$(json_field "$create_result" "dwallet_cap_id")
    secret_path=$(json_field "$create_result" "secret_share_path")

    echo "  Created dWallet: $dwallet_id" >&2

    # Make shares public
    local make_public_result
    make_public_result=$(ika_json dwallet share make-public \
        --dwallet-id "$dwallet_id" \
        --secret-share "$secret_path")
    echo "  Made shares public" >&2

    # Presign + verify
    local verified_cap
    verified_cap=$(do_presign_and_verify "$dwallet_id" "$sig_algo")
    echo "  Verified presign: $verified_cap" >&2

    # Sign
    local sign_result
    sign_result=$(sign_message "$dwallet_cap_id" "$dwallet_id" "$message_hex" "$sig_algo" "$hash_scheme" "$secret_path" "$verified_cap")
    local sign_status
    sign_status=$(json_field "$sign_result" "status")

    if [[ "$sign_status" != "Success" ]]; then
        echo "Sign failed with status: $sign_status" >&2
        return 1
    fi
    echo "  Sign succeeded: $(json_field "$sign_result" "digest")" >&2
}
