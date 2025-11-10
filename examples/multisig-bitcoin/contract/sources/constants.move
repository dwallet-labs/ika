// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_btc_multisig::constants;

// === Constants ===

/// Returns the default signer public key for multisig wallet initialization.
public(package) macro fun signer_public_key(): vector<u8> {
  b"505d0309553b7e66dbf0cca5b33706d78c2ce8809dd8dc03248559024f70ba6f"
}

/// Returns the corresponding Sui address for the default signer public key.
public(package) macro fun signer_public_key_address(): address {
  @0xf4ad8e7b218ea98312739b3312b5e500627ca252790a046ab95c8a8ddf38c546
}

/// Returns the elliptic curve identifier for Bitcoin signature generation.
/// Uses secp256k1 (curve ID: 0) which is the standard curve for Bitcoin.
/// This curve provides the cryptographic foundation for all multisig operations.
public(package) macro fun curve(): u32 {
  0
}

/// Returns the signature algorithm identifier for Bitcoin signature generation.
/// Uses the standard Bitcoin signature algorithm (Taproot) which is the standard algorithm for Bitcoin.
/// This algorithm provides the cryptographic foundation for all multisig operations.
public(package) macro fun signature_algorithm(): u32 {
  1
}

/// Returns the hash scheme identifier for Bitcoin signature generation.
/// Uses the standard Bitcoin hash scheme (SHA256) which is the standard hash scheme for Bitcoin.
/// This hash scheme provides the cryptographic foundation for all multisig operations.
public(package) macro fun hash_scheme(): u32 {
  0
}
