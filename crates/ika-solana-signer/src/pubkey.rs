// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Extract the 32-byte Ed25519 public key from a dWallet's `public_output`.

use dwallet_mpc_centralized_party::public_key_from_dwallet_output_by_curve;

use crate::error::IkaSignerError;

const ED25519_CURVE_ID: u32 = 2;

/// Decode the dWallet's BCS-encoded `public_output` into a Solana-compatible
/// 32-byte Ed25519 public key.
pub fn extract_ed25519_pubkey(
    dwallet_id: &str,
    public_output: &[u8],
) -> Result<[u8; 32], IkaSignerError> {
    let curve = dwallet_mpc_types::dwallet_mpc::DWalletCurve::Curve25519;
    let bytes = public_key_from_dwallet_output_by_curve(curve, public_output)
        .map_err(|_| IkaSignerError::InvalidPublicOutput(dwallet_id.to_string()))?;
    if bytes.len() != 32 {
        return Err(IkaSignerError::InvalidPublicOutput(dwallet_id.to_string()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// The numeric curve ID for Ed25519/Curve25519 dWallets in the on-chain encoding.
pub const fn ed25519_curve_id() -> u32 {
    ED25519_CURVE_ID
}
