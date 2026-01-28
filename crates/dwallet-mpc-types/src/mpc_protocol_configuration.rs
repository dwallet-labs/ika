// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(deprecated)]

use crate::dwallet_mpc::{DWalletCurve, DWalletSignatureAlgorithm, DwalletNetworkMPCError};
use group::HashScheme;
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
) -> Result<HashScheme, DwalletNetworkMPCError> {
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
                                        0 => Some(HashScheme::Keccak256),
                                        1 => Some(HashScheme::SHA256),
                                        2 => Some(HashScheme::DoubleSHA256),
                                        _ => None,
                                    }
                                }
                                1 => {
                                    // Taproot
                                    match hash_scheme {
                                        0 => Some(HashScheme::SHA256),
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
                                        0 => Some(HashScheme::SHA256),
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
                                        0 => Some(HashScheme::SHA512),
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
                                        0 => Some(HashScheme::Merlin),
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

#[cfg(test)]
mod tests {
    #[test]
    fn validate_all_supported_curves_to_signature_algorithms_to_hash_schemes_are_correct() {
        // Validate Secp256k1 curve
        let secp256k1_entry = super::SUPPORTED_CURVES_TO_SIGNATURE_ALGORITHMS_TO_HASH_SCHEMES
            .get(&0)
            .expect("Secp256k1 entry should exist");

        // Validate Secp256k1 curve / ECDSA signature algorithm
        let ecdsa_entry = secp256k1_entry
            .get(&0)
            .expect("ECDSA entry should exist for Secp256k1");

        assert_eq!(
            ecdsa_entry,
            &vec![0, 1, 2],
            "Secp256k1 ECDSA should support Keccak256, SHA256, DoubleSHA256"
        );

        // Validate Secp256k1 curve / Taproot signature algorithm
        let taproot_entry = secp256k1_entry
            .get(&1)
            .expect("Taproot entry should exist for Secp256k1");

        assert_eq!(
            taproot_entry,
            &vec![0],
            "Secp256k1 Taproot should support SHA256"
        );

        // Validate Secp256k1 curve / no invalid signature algorithm
        let mut all_signature_algorithm_keys: Vec<_> = secp256k1_entry.keys().copied().collect();
        all_signature_algorithm_keys.sort();
        assert_eq!(
            all_signature_algorithm_keys,
            vec![0, 1],
            "Secp256k1 have only ECDSA and Taproot signature algorithms"
        );

        // Validate Secp256r1 curve
        let secp256r1_entry = super::SUPPORTED_CURVES_TO_SIGNATURE_ALGORITHMS_TO_HASH_SCHEMES
            .get(&1)
            .expect("Secp256r1 entry should exist");

        // Validate Secp256r1 curve / ECDSA signature algorithm
        let ecdsa_secp256r1_entry = secp256r1_entry
            .get(&0)
            .expect("ECDSA entry should exist for Secp256r1");

        assert_eq!(
            ecdsa_secp256r1_entry,
            &vec![0],
            "Secp256r1 ECDSA should support SHA256"
        );

        // Validate Secp256r1 curve / no invalid signature algorithm
        let all_secp256r1_signature_algorithm_keys: Vec<_> =
            secp256r1_entry.keys().copied().collect();
        assert_eq!(
            all_secp256r1_signature_algorithm_keys,
            vec![0],
            "Secp256r1 have only ECDSA signature algorithm"
        );

        // Validate Curve25519 curve
        let curve25519_entry = super::SUPPORTED_CURVES_TO_SIGNATURE_ALGORITHMS_TO_HASH_SCHEMES
            .get(&2)
            .expect("Curve25519 entry should exist");

        // Validate Curve25519 curve / EdDSA signature algorithm
        let eddsa_entry = curve25519_entry
            .get(&0)
            .expect("EdDSA entry should exist for Curve25519");

        assert_eq!(
            eddsa_entry,
            &vec![0],
            "Curve25519 EdDSA should support SHA512"
        );

        // Validate Curve25519 curve / no invalid signature algorithm
        let all_curve25519_signature_algorithm_keys: Vec<_> =
            curve25519_entry.keys().copied().collect();
        assert_eq!(
            all_curve25519_signature_algorithm_keys,
            vec![0],
            "Curve25519 have only EdDSA signature algorithm"
        );

        // Validate Ristretto curve
        let ristretto_entry = super::SUPPORTED_CURVES_TO_SIGNATURE_ALGORITHMS_TO_HASH_SCHEMES
            .get(&3)
            .expect("Ristretto entry should exist");

        // Validate Ristretto curve / SchnorrkelSubstrate signature algorithm
        let schnorrkel_entry = ristretto_entry
            .get(&0)
            .expect("SchnorrkelSubstrate entry should exist for Ristretto");

        assert_eq!(
            schnorrkel_entry,
            &vec![0],
            "Ristretto SchnorrkelSubstrate should support Merlin"
        );

        // Validate Ristretto curve / no invalid signature algorithm
        let all_ristretto_signature_algorithm_keys: Vec<_> =
            ristretto_entry.keys().copied().collect();
        assert_eq!(
            all_ristretto_signature_algorithm_keys,
            vec![0],
            "Ristretto have only SchnorrkelSubstrate signature algorithm"
        );
    }
}
