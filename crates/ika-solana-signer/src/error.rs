// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use thiserror::Error;

/// Errors surfaced by [`crate::IkaSigner`].
#[derive(Debug, Error)]
pub enum IkaSignerError {
    #[error("dWallet {0} is not in Active state; cannot sign yet")]
    DWalletNotActive(String),

    #[error("dWallet {dwallet_id} curve is {actual} (expected ed25519/{expected})")]
    UnsupportedCurve {
        dwallet_id: String,
        actual: u32,
        expected: u32,
    },

    #[error("Could not extract Ed25519 public key from dWallet {0}'s public_output")]
    InvalidPublicOutput(String),

    #[error("Sign session was rejected by the network")]
    SignRejected,

    #[error(
        "Provided presign cap has already been consumed; reconstruct IkaSigner with a fresh cap or PresignMode::PerSignGlobal"
    )]
    PresignCapConsumed,

    #[error("MPC centralized signing failed: {0}")]
    Crypto(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
