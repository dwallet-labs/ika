// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use group::secp256k1;
use k256::ecdsa::hazmat::bits2field;
use k256::elliptic_curve::ops::Reduce;
use k256::{U256, elliptic_curve};
use sha3::Digest;
use sha3::digest::FixedOutput;

/// Supported hash functions for message digest.
#[derive(strum_macros::Display, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Hash {
    #[strum(to_string = "KECCAK256")]
    KECCAK256 = 0,
    #[strum(to_string = "SHA256")]
    SHA256 = 1,
}

impl TryFrom<u32> for Hash {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Hash::KECCAK256),
            1 => Ok(Hash::SHA256),
            _ => Err(anyhow::Error::msg(format!(
                "invalid value for Hash enum: {value}"
            ))),
        }
    }
}
