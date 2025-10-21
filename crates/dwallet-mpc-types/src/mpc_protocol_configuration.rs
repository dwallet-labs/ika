// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::{DWalletCurve, DWalletSignatureAlgorithm, DwalletNetworkMPCError};
use group::HashType;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Protocol flags for DKG and signing operations
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtocolFlag {
    DkgFirstRound = 0,
    DkgSecondRound = 1,
    ReEncryptUserShare = 2,
    MakeDWalletUserSecretKeySharePublic = 3,
    ImportedKeyDWalletVerification = 4,
    Presign = 5,
    Sign = 6,
    FutureSign = 7,
    SignWithPartialUserSignature = 8,
    DWalletDkg = 9,
    DWalletDkgWithSign = 10,
}

#[deprecated]
pub const DKG_FIRST_ROUND_PROTOCOL_FLAG: u32 = 0;
#[deprecated]
pub const DKG_SECOND_ROUND_PROTOCOL_FLAG: u32 = 1;
pub const RE_ENCRYPT_USER_SHARE_PROTOCOL_FLAG: u32 = 2;
pub const MAKE_DWALLET_USER_SECRET_KEY_SHARE_PUBLIC_PROTOCOL_FLAG: u32 = 3;
pub const IMPORTED_KEY_DWALLET_VERIFICATION_PROTOCOL_FLAG: u32 = 4;
pub const PRESIGN_PROTOCOL_FLAG: u32 = 5;
pub const SIGN_PROTOCOL_FLAG: u32 = 6;
pub const FUTURE_SIGN_PROTOCOL_FLAG: u32 = 7;
pub const SIGN_WITH_PARTIAL_USER_SIGNATURE_PROTOCOL_FLAG: u32 = 8;
pub const DWALLET_DKG_PROTOCOL_FLAG: u32 = 9;
pub const DWALLET_DKG_WITH_SIGN_PROTOCOL_FLAG: u32 = 10;

lazy_static! {
    /// Supported curves to signature algorithms to hash schemes
    pub static ref SUPPORTED_CURVES_TO_SIGNATURE_ALGORITHMS_TO_HASH_SCHEMES: HashMap<u32, HashMap<u32, Vec<u32>>> = {
        vec![
            (
                0, // Curve: Secp256k1
                vec![
                    (
                        0, // Signature Algorithm: ECDSA
                        vec![
                            0, // Hash: Keccak256
                            1, // Hash: SHA256
                            2, // Hash: DoubleSHA256
                        ],
                    ),
                    (
                        1, // Signature Algorithm: Taproot
                        vec![
                            0, // Hash: SHA256
                        ],
                    ),
                ]
                .into_iter()
                .collect(),
            ),
            (
                1, // Curve: Secp256r1)
                vec![(
                    0, // Signature Algorithm: ECDSA
                    vec![
                        0, // Hash: SHA256
                        1, // Hash: DoubleSHA256
                    ],
                )]
                .into_iter()
                .collect(),
            ),
            (
                2, // Curve: Curve25519
                vec![(
                    0, // Signature Algorithm: EdDSA
                    vec![
                        0, // Hash: SHA512
                    ],
                )]
                    .into_iter()
                    .collect(),
            ),
            (
                3, // Curve: Ristretto
                vec![(
                    0, // Signature Algorithm: SchnorrkelSubstrate
                    vec![
                        0, // Hash: Merlin
                    ],
                )]
                .into_iter()
                .collect(),
            ),
        ]
        .into_iter()
        .collect()
    };

    /// Global presign supported curves to signature algorithms for DKG
    pub static ref GLOBAL_PRESIGN_SUPPORTED_CURVE_TO_SIGNATURE_ALGORITHMS_FOR_DKG: HashMap<u32, Vec<u32>> = {
        let mut config = HashMap::new();
        config.insert(0, vec![0, 1]); // Secp256k1: ECDSA, Taproot
        config.insert(1, vec![0]); // Secp256r1: ECDSA
        config.insert(2, vec![0]); // Curve25519: EdDSA
        config.insert(3, vec![0]); // Ristretto: SchnorrkelSubstrate
        config
    };

    /// Global presign supported curves to signature algorithms for imported keys
    pub static ref GLOBAL_PRESIGN_SUPPORTED_CURVE_TO_SIGNATURE_ALGORITHMS_FOR_IMPORTED_KEY: HashMap<u32, Vec<u32>> = {
        let mut config = HashMap::new();
        config.insert(0, vec![1]); // Secp256k1: Taproot (ECDSA not supported for imported keys)
        // Secp256r1 (1): ECDSA not supported for imported keys
        config.insert(2, vec![0]); // Curve25519: EdDSA
        config.insert(3, vec![0]); // Ristretto: SchnorrkelSubstrate
        config
    };

    /// MPC Protocols without signature algorithm
    pub static ref MPC_PROTOCOLS_WITHOUT_SIGNATURE_ALGORITHM: Vec<u32> = {
        vec![
            DKG_FIRST_ROUND_PROTOCOL_FLAG,
            DKG_SECOND_ROUND_PROTOCOL_FLAG,
            RE_ENCRYPT_USER_SHARE_PROTOCOL_FLAG,
            MAKE_DWALLET_USER_SECRET_KEY_SHARE_PUBLIC_PROTOCOL_FLAG,
            IMPORTED_KEY_DWALLET_VERIFICATION_PROTOCOL_FLAG,
            DWALLET_DKG_PROTOCOL_FLAG,
        ]
    };

    /// MPC Protocols with signature algorithm
    pub static ref MPC_PROTOCOLS_WITH_SIGNATURE_ALGORITHM: Vec<u32> = {
        vec![
            PRESIGN_PROTOCOL_FLAG,
            SIGN_PROTOCOL_FLAG,
            FUTURE_SIGN_PROTOCOL_FLAG,
            SIGN_WITH_PARTIAL_USER_SIGNATURE_PROTOCOL_FLAG,
            DWALLET_DKG_WITH_SIGN_PROTOCOL_FLAG,
        ]
    };
}

/// Convert curve u32 to DWalletCurve enum
pub fn try_into_curve(curve: u32) -> Result<DWalletCurve, DwalletNetworkMPCError> {
    if !SUPPORTED_CURVES_TO_SIGNATURE_ALGORITHMS_TO_HASH_SCHEMES.contains_key(&curve) {
        return Err(DwalletNetworkMPCError::InvalidDWalletMPCCurve(curve));
    }
    match curve {
        0 => Ok(DWalletCurve::Secp256k1),
        1 => Ok(DWalletCurve::Secp256r1),
        2 => Ok(DWalletCurve::Curve25519),
        3 => Ok(DWalletCurve::Ristretto),
        v => Err(DwalletNetworkMPCError::InvalidDWalletMPCCurve(v)),
    }
}

/// Convert curve and signature algorithm numbers to (DWalletCurve, DWalletSignatureScheme)
/// Example: (0, 0) -> (Secp256k1, ECDSA)
pub fn try_into_signature_algorithm(
    curve: u32,
    signature_algorithm: u32,
) -> Result<DWalletSignatureAlgorithm, DwalletNetworkMPCError> {
    let signature_algorithms_to_hash_scheme =
        SUPPORTED_CURVES_TO_SIGNATURE_ALGORITHMS_TO_HASH_SCHEMES.get(&curve);

    signature_algorithms_to_hash_scheme
        .and_then(|signature_algorithms_to_hash_scheme| {
            signature_algorithms_to_hash_scheme
                .get(&signature_algorithm)
                .and({
                    match curve {
                        0 => match signature_algorithm {
                            // Secp256k1
                            0 => Some(DWalletSignatureAlgorithm::ECDSASecp256k1),
                            1 => Some(DWalletSignatureAlgorithm::Taproot),
                            _ => None,
                        },
                        1 => match signature_algorithm {
                            // Secp256r1
                            0 => Some(DWalletSignatureAlgorithm::ECDSASecp256r1),
                            _ => None,
                        },
                        2 => match signature_algorithm {
                            // Curve25519
                            0 => Some(DWalletSignatureAlgorithm::EdDSA),
                            _ => None,
                        },
                        3 => match signature_algorithm {
                            // Ristretto
                            0 => Some(DWalletSignatureAlgorithm::SchnorrkelSubstrate),
                            _ => None,
                        },
                        _ => None,
                    }
                })
        })
        .ok_or(DwalletNetworkMPCError::InvalidDWalletMPCSignatureAlgorithm(
            curve,
            signature_algorithm,
        ))
}

pub fn try_into_hash_scheme(
    curve: u32,
    signature_algorithm: u32,
    hash_scheme: u32,
) -> Result<HashType, DwalletNetworkMPCError> {
    let signature_algorithms_to_hash_scheme =
        SUPPORTED_CURVES_TO_SIGNATURE_ALGORITHMS_TO_HASH_SCHEMES.get(&curve);

    signature_algorithms_to_hash_scheme
        .and_then(|signature_algorithms_to_hash_scheme| {
            signature_algorithms_to_hash_scheme
                .get(&signature_algorithm)
                .and_then(|hash_schemes| {
                    hash_schemes.contains(&hash_scheme).then_some({
                        match curve {
                            0 => match signature_algorithm {
                                // Secp256k1
                                0 => {
                                    // ECDSA
                                    match hash_scheme {
                                        0 => Some(HashType::Keccak256),
                                        1 => Some(HashType::SHA256),
                                        2 => Some(HashType::DoubleSHA256),
                                        _ => None,
                                    }
                                }
                                1 => {
                                    // Taproot
                                    match hash_scheme {
                                        0 => Some(HashType::SHA256),
                                        _ => None,
                                    }
                                }
                                _ => None,
                            },
                            1 => match signature_algorithm {
                                // Secp256r1
                                0 => {
                                    // ECDSA
                                    match hash_scheme {
                                        0 => Some(HashType::SHA256),
                                        1 => Some(HashType::DoubleSHA256),
                                        _ => None,
                                    }
                                }
                                _ => None,
                            },
                            2 => match signature_algorithm {
                                // Curve25519
                                0 => {
                                    // EdDSA
                                    match hash_scheme {
                                        0 => Some(HashType::SHA512),
                                        _ => None,
                                    }
                                }
                                _ => None,
                            },
                            3 => match signature_algorithm {
                                // Ristretto
                                0 => {
                                    // SchnorrkelSubstrate},
                                    match hash_scheme {
                                        0 => Some(HashType::Merlin),
                                        _ => None,
                                    }
                                }
                                _ => None,
                            },
                            _ => None,
                        }
                    })
                })
                .flatten()
        })
        .ok_or(DwalletNetworkMPCError::InvalidDWalletMPCHashScheme(
            curve,
            signature_algorithm,
            hash_scheme,
        ))
}
