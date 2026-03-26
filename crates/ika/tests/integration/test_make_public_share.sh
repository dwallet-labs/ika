#!/usr/bin/env bash
# test_make_public_share.sh — Make user shares public and sign
# (mirrors make-public-share-and-sign.test.ts).
#
# Tests: create → make-public → presign → verify → sign for all combos.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

setup_test_tmpdir
trap cleanup_test_tmpdir EXIT

echo "=========================================="
echo " Make Public Share & Sign Tests"
echo "=========================================="

# --- secp256k1 + ECDSA ---

test_public_secp256k1_ecdsa_keccak256() {
    full_create_make_public_and_sign "secp256k1" "$SIG_ECDSA_SECP256K1" "$HASH_KECCAK256"
}

test_public_secp256k1_ecdsa_sha256() {
    full_create_make_public_and_sign "secp256k1" "$SIG_ECDSA_SECP256K1" "$HASH_SHA256"
}

test_public_secp256k1_ecdsa_double_sha256() {
    full_create_make_public_and_sign "secp256k1" "$SIG_ECDSA_SECP256K1" "$HASH_DOUBLE_SHA256"
}

# --- secp256k1 + Taproot ---

test_public_secp256k1_taproot_sha256() {
    # make-public uses regular create, Taproot needs global presign
    ensure_encryption_key "secp256k1" > /dev/null
    local create_result
    create_result=$(create_dwallet "secp256k1")
    local dwallet_id dwallet_cap_id secret_path
    dwallet_id=$(json_field "$create_result" "dwallet_id")
    dwallet_cap_id=$(json_field "$create_result" "dwallet_cap_id")
    secret_path=$(json_field "$create_result" "secret_share_path")
    echo "  Created dWallet: $dwallet_id" >&2

    # Make public
    ika_json dwallet share make-public \
        --dwallet-id "$dwallet_id" \
        --secret-share "$secret_path" > /dev/null
    echo "  Made shares public" >&2

    # Global presign for Taproot
    local verified_cap
    verified_cap=$(do_global_presign_and_verify "$CURVE_SECP256K1" "$SIG_TAPROOT")
    echo "  Verified global presign: $verified_cap" >&2

    local sign_result
    sign_result=$(sign_message "$dwallet_cap_id" "$dwallet_id" "48656c6c6f" "$SIG_TAPROOT" "$HASH_TAPROOT_SHA256" "$secret_path" "$verified_cap")
    [[ "$(json_field "$sign_result" "status")" == "Success" ]]
    echo "  Sign succeeded" >&2
}

# --- secp256r1 + ECDSA ---

test_public_secp256r1_ecdsa_sha256() {
    full_create_make_public_and_sign "secp256r1" "$SIG_ECDSA_SECP256R1" "$HASH_SECP256R1_SHA256"
}

# --- ed25519 + EdDSA ---

test_public_ed25519_eddsa_sha512() {
    ensure_encryption_key "ed25519" > /dev/null
    local create_result
    create_result=$(create_dwallet "ed25519")
    local dwallet_id dwallet_cap_id secret_path
    dwallet_id=$(json_field "$create_result" "dwallet_id")
    dwallet_cap_id=$(json_field "$create_result" "dwallet_cap_id")
    secret_path=$(json_field "$create_result" "secret_share_path")
    echo "  Created dWallet: $dwallet_id" >&2

    ika_json dwallet share make-public \
        --dwallet-id "$dwallet_id" \
        --secret-share "$secret_path" > /dev/null
    echo "  Made shares public" >&2

    local verified_cap
    verified_cap=$(do_global_presign_and_verify "$CURVE_ED25519" "$SIG_EDDSA")
    echo "  Verified global presign: $verified_cap" >&2

    local sign_result
    sign_result=$(sign_message "$dwallet_cap_id" "$dwallet_id" "48656c6c6f" "$SIG_EDDSA" "$HASH_ED25519_SHA512" "$secret_path" "$verified_cap")
    [[ "$(json_field "$sign_result" "status")" == "Success" ]]
    echo "  Sign succeeded" >&2
}

# --- ristretto + SchnorrkelSubstrate ---

test_public_ristretto_schnorrkel_merlin() {
    ensure_encryption_key "ristretto" > /dev/null
    local create_result
    create_result=$(create_dwallet "ristretto")
    local dwallet_id dwallet_cap_id secret_path
    dwallet_id=$(json_field "$create_result" "dwallet_id")
    dwallet_cap_id=$(json_field "$create_result" "dwallet_cap_id")
    secret_path=$(json_field "$create_result" "secret_share_path")
    echo "  Created dWallet: $dwallet_id" >&2

    ika_json dwallet share make-public \
        --dwallet-id "$dwallet_id" \
        --secret-share "$secret_path" > /dev/null
    echo "  Made shares public" >&2

    local verified_cap
    verified_cap=$(do_global_presign_and_verify "$CURVE_RISTRETTO" "$SIG_SCHNORRKEL")
    echo "  Verified global presign: $verified_cap" >&2

    local sign_result
    sign_result=$(sign_message "$dwallet_cap_id" "$dwallet_id" "48656c6c6f" "$SIG_SCHNORRKEL" "$HASH_RISTRETTO_MERLIN" "$secret_path" "$verified_cap")
    [[ "$(json_field "$sign_result" "status")" == "Success" ]]
    echo "  Sign succeeded" >&2
}

run_test "Public share: secp256k1 + ECDSA + KECCAK256"            test_public_secp256k1_ecdsa_keccak256
run_test "Public share: secp256k1 + ECDSA + SHA256"                test_public_secp256k1_ecdsa_sha256
run_test "Public share: secp256k1 + ECDSA + DoubleSHA256"          test_public_secp256k1_ecdsa_double_sha256
run_test "Public share: secp256k1 + Taproot + SHA256"              test_public_secp256k1_taproot_sha256
run_test "Public share: secp256r1 + ECDSA + SHA256"                test_public_secp256r1_ecdsa_sha256
run_test "Public share: ed25519 + EdDSA + SHA512"                  test_public_ed25519_eddsa_sha512
run_test "Public share: ristretto + SchnorrkelSubstrate + Merlin"  test_public_ristretto_schnorrkel_merlin

print_summary
