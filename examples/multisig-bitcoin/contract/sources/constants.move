// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_btc_multisig::constants;

// === Constants ===

/// Returns the default signer public key for multisig wallet initialization.
/// This compressed public key serves as a placeholder during distributed key generation.
/// The actual wallet key is derived from the collective DKG process.
public(package) macro fun signer_public_key(): vector<u8> {
    b"020202020202020202020202020202020202020202020202020202020202020202"
}

/// Returns the corresponding Sui address for the default signer public key.
/// This zero address acts as a temporary identifier during wallet setup.
/// The actual wallet address is determined after successful DKG completion.
public(package) macro fun signer_public_key_address(): address {
    @0x0000000000000000000000000000000000000000000000000000000000000000
}

/// Returns the elliptic curve identifier for Bitcoin signature generation.
/// Uses secp256k1 (curve ID: 0) which is the standard curve for Bitcoin.
/// This curve provides the cryptographic foundation for all multisig operations.
public(package) macro fun curve(): u32 {
    0
}

/// Returns the signature algorithm identifier for Bitcoin signature generation.
/// Uses the standard Bitcoin signature algorithm (ECDSA) which is the standard algorithm for Bitcoin.
/// This algorithm provides the cryptographic foundation for all multisig operations.
public(package) macro fun signature_algorithm(): u32 {
    0
}

/// Returns the hash scheme identifier for Bitcoin signature generation.
/// Uses the standard Bitcoin hash scheme (SHA256) which is the standard hash scheme for Bitcoin.
/// This hash scheme provides the cryptographic foundation for all multisig operations.
public(package) macro fun hash_scheme(): u32 {
    0
}
