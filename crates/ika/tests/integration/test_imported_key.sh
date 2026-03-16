#!/usr/bin/env bash
# test_imported_key.sh — Imported key dWallet creation and signing
# (mirrors imported-key.test.ts).
#
# Tests: import → presign → verify → sign for all curve/algo combos.
# Uses targeted presign for ECDSA, global for EdDSA/Taproot/Schnorrkel.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

setup_test_tmpdir
trap cleanup_test_tmpdir EXIT

echo "=========================================="
echo " Imported Key Sign Tests"
echo "=========================================="

# --- secp256k1 + ECDSA (targeted presign) ---

test_imported_secp256k1_ecdsa_keccak256() {
    full_import_and_sign "secp256k1" "$SIG_ECDSA_SECP256K1" "$HASH_KECCAK256" "$IMPORTED_KEY_SECP256K1"
}

test_imported_secp256k1_ecdsa_sha256() {
    full_import_and_sign "secp256k1" "$SIG_ECDSA_SECP256K1" "$HASH_SHA256" "$IMPORTED_KEY_SECP256K1"
}

# --- secp256k1 + Taproot (global presign) ---

test_imported_secp256k1_taproot_sha256() {
    full_import_and_sign_global_presign "secp256k1" "$CURVE_SECP256K1" "$SIG_TAPROOT" "$HASH_TAPROOT_SHA256" "$IMPORTED_KEY_SECP256K1"
}

# --- secp256r1 + ECDSA (targeted presign) ---

test_imported_secp256r1_ecdsa_sha256() {
    full_import_and_sign "secp256r1" "$SIG_ECDSA_SECP256R1" "$HASH_SECP256R1_SHA256" "$IMPORTED_KEY_SECP256R1"
}

# --- ed25519 + EdDSA (global presign) ---

test_imported_ed25519_eddsa_sha512() {
    full_import_and_sign_global_presign "ed25519" "$CURVE_ED25519" "$SIG_EDDSA" "$HASH_ED25519_SHA512" "$IMPORTED_KEY_ED25519"
}

# --- ristretto + SchnorrkelSubstrate (global presign) ---

test_imported_ristretto_schnorrkel_merlin() {
    full_import_and_sign_global_presign "ristretto" "$CURVE_RISTRETTO" "$SIG_SCHNORRKEL" "$HASH_RISTRETTO_MERLIN" "$IMPORTED_KEY_RISTRETTO"
}

run_test "Imported secp256k1 + ECDSA + KECCAK256"            test_imported_secp256k1_ecdsa_keccak256
run_test "Imported secp256k1 + ECDSA + SHA256"                test_imported_secp256k1_ecdsa_sha256
run_test "Imported secp256k1 + Taproot + SHA256"              test_imported_secp256k1_taproot_sha256
run_test "Imported secp256r1 + ECDSA + SHA256"                test_imported_secp256r1_ecdsa_sha256
run_test "Imported ed25519 + EdDSA + SHA512"                  test_imported_ed25519_eddsa_sha512
run_test "Imported ristretto + SchnorrkelSubstrate + Merlin"  test_imported_ristretto_schnorrkel_merlin

print_summary
