// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use group::secp256k1;
use k256::ecdsa::hazmat::bits2field;
use k256::elliptic_curve::ops::Reduce;
use k256::{U256, elliptic_curve};
use sha3::Digest;
use sha3::digest::FixedOutput;

/// Supported hash functions for message digest.
#[derive(Clone, Debug)]
pub enum Hash {
    KECCAK256 = 0,
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

/// Computes the message digest of a given message using the specified hash function.
pub fn message_digest(message: &[u8], hash_type: &Hash) -> anyhow::Result<secp256k1::Scalar> {
    let hash = match hash_type {
        Hash::KECCAK256 => bits2field::<k256::Secp256k1>(
            &sha3::Keccak256::new_with_prefix(message).finalize_fixed(),
        )
        .map_err(|e| anyhow::Error::msg(format!("KECCAK256 bits2field error: {e:?}")))?,

        Hash::SHA256 => {
            bits2field::<k256::Secp256k1>(&sha2::Sha256::new_with_prefix(message).finalize_fixed())
                .map_err(|e| anyhow::Error::msg(format!("SHA256 bits2field error: {e:?}")))?
        }
    };
    #[allow(clippy::useless_conversion)]
    let m = <elliptic_curve::Scalar<k256::Secp256k1> as Reduce<U256>>::reduce_bytes(&hash.into());
    Ok(U256::from(m).into())
}
