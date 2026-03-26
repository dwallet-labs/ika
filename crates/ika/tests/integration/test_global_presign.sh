 #!/usr/bin/env bash
# test_global_presign.sh — Global presign completion for all curve/algo combos
# (mirrors global-presign.test.ts).
#
# Tests that global presigns complete successfully (no dWallet needed).

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

setup_test_tmpdir
trap cleanup_test_tmpdir EXIT

echo "=========================================="
echo " Global Presign Tests"
echo "=========================================="

test_global_presign() {
    local curve_num="$1"
    local sig_algo="$2"

    local presign_result
    presign_result=$(request_global_presign "$curve_num" "$sig_algo")
    local presign_digest
    presign_digest=$(json_field "$presign_result" "digest")
    local presign_status
    presign_status=$(json_field "$presign_result" "status")
    [[ "$presign_status" == "Success" ]]

    local presign_session
    presign_session=$(tx_find_created "$presign_digest" "PresignSession")
    [[ -n "$presign_session" ]]

    poll_presign_completed "$presign_session"
}

test_secp256k1_ecdsa()       { test_global_presign "$CURVE_SECP256K1"  "$SIG_ECDSA_SECP256K1"; }
test_secp256k1_taproot()     { test_global_presign "$CURVE_SECP256K1"  "$SIG_TAPROOT"; }
test_secp256r1_ecdsa()       { test_global_presign "$CURVE_SECP256R1"  "$SIG_ECDSA_SECP256R1"; }
test_ed25519_eddsa()         { test_global_presign "$CURVE_ED25519"    "$SIG_EDDSA"; }
test_ristretto_schnorrkel()  { test_global_presign "$CURVE_RISTRETTO"  "$SIG_SCHNORRKEL"; }

run_test "Global presign: secp256k1 + ECDSA"          test_secp256k1_ecdsa
run_test "Global presign: secp256k1 + Taproot"         test_secp256k1_taproot
run_test "Global presign: secp256r1 + ECDSA"           test_secp256r1_ecdsa
run_test "Global presign: ed25519 + EdDSA"             test_ed25519_eddsa
run_test "Global presign: ristretto + SchnorrkelSubstrate" test_ristretto_schnorrkel

print_summary
