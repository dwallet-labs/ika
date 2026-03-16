#!/usr/bin/env bash
# test_all_combinations.sh — Full sign flow for all curve/algo/hash combinations
# (mirrors all-combinations.test.ts).
#
# Tests: create → presign → verify → sign for every supported combination.
# Uses targeted presign for ECDSA curves, global presign for others.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

setup_test_tmpdir
trap cleanup_test_tmpdir EXIT

echo "=========================================="
echo " All Combinations Sign Tests"
echo "=========================================="

# --- secp256k1 + ECDSA ---

test_secp256k1_ecdsa_keccak256() {
    full_create_and_sign "secp256k1" "$SIG_ECDSA_SECP256K1" "$HASH_KECCAK256"
}

test_secp256k1_ecdsa_sha256() {
    full_create_and_sign "secp256k1" "$SIG_ECDSA_SECP256K1" "$HASH_SHA256"
}

test_secp256k1_ecdsa_double_sha256() {
    full_create_and_sign "secp256k1" "$SIG_ECDSA_SECP256K1" "$HASH_DOUBLE_SHA256"
}

# --- secp256k1 + Taproot ---

test_secp256k1_taproot_sha256() {
    full_create_and_sign_global_presign "secp256k1" "$CURVE_SECP256K1" "$SIG_TAPROOT" "$HASH_TAPROOT_SHA256"
}

# --- secp256r1 + ECDSA ---

test_secp256r1_ecdsa_sha256() {
    full_create_and_sign "secp256r1" "$SIG_ECDSA_SECP256R1" "$HASH_SECP256R1_SHA256"
}

# --- ed25519 + EdDSA ---

test_ed25519_eddsa_sha512() {
    full_create_and_sign_global_presign "ed25519" "$CURVE_ED25519" "$SIG_EDDSA" "$HASH_ED25519_SHA512"
}

# --- ristretto + SchnorrkelSubstrate ---

test_ristretto_schnorrkel_merlin() {
    full_create_and_sign_global_presign "ristretto" "$CURVE_RISTRETTO" "$SIG_SCHNORRKEL" "$HASH_RISTRETTO_MERLIN"
}

run_test "secp256k1 + ECDSA + KECCAK256"        test_secp256k1_ecdsa_keccak256
run_test "secp256k1 + ECDSA + SHA256"            test_secp256k1_ecdsa_sha256
run_test "secp256k1 + ECDSA + DoubleSHA256"      test_secp256k1_ecdsa_double_sha256
run_test "secp256k1 + Taproot + SHA256"           test_secp256k1_taproot_sha256
run_test "secp256r1 + ECDSA + SHA256"             test_secp256r1_ecdsa_sha256
run_test "ed25519 + EdDSA + SHA512"               test_ed25519_eddsa_sha512
run_test "ristretto + SchnorrkelSubstrate + Merlin" test_ristretto_schnorrkel_merlin

print_summary
