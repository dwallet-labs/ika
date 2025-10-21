// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::{DWalletCurve, DWalletSignatureScheme};
use group::HashType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Error types for MPC protocol configuration
#[derive(Debug, thiserror::Error, Clone)]
pub enum MpcProtocolConfigurationError {
    #[error("invalid HashType value: {0}")]
    InvalidHashType(u32),

    #[error("invalid curve value: {0}")]
    InvalidCurve(u32),

    #[error("invalid signature algorithm value: {0}")]
    InvalidSignatureAlgorithm(u32),

    #[error("curve {0:?} not found in configuration")]
    CurveNotFound(DWalletCurve),

    #[error("signature algorithm {0:?} not found for curve {1:?}")]
    SignatureAlgorithmNotFound(DWalletSignatureScheme, DWalletCurve),

    #[error("hash algorithm {0:?} not found for curve {1:?} and signature {2:?}")]
    HashTypeNotFound(HashType, DWalletCurve, DWalletSignatureScheme),
}

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

/// Configuration entry: (Curve u32, SignatureAlgorithm u32, Vec<Hash u32>)
///
/// # Curve Values:
/// - 0: Secp256k1
/// - 1: Ristretto
/// - 2: Curve25519
/// - 3: Secp256r1
///
/// # Signature Algorithm Values:
/// - 0: ECDSASecp256k1
/// - 1: Taproot
/// - 2: ECDSASecp256r1
/// - 3: EdDSA
/// - 4: SchnorrkelSubstrate
///
/// # Hash Algorithm Values:
/// - 0: Keccak256
/// - 1: SHA256
/// - 2: DoubleSHA256
/// - 3: SHA512
/// - 4: Merlin
pub type CurveSignatureHashConfig = Vec<(u32, u32, Vec<u32>)>;

/// MPC Protocol Configuration
///
/// Vector-based structure using raw u32 numbers: Vec<(Curve, SignatureAlgo, Vec<Hash>)>
pub struct MpcProtocolConfiguration {
    /// Vector of (curve u32, signature algorithm u32, supported hash algorithms Vec<u32>) tuples
    curve_to_signature_to_hash: CurveSignatureHashConfig,

    /// Curves and their supported signature algorithms for DKG (using u32 values)
    dkg_curve_to_signature_algorithms: HashMap<u32, Vec<u32>>,

    /// Curves and their supported signature algorithms for imported keys (non-ECDSA only, using u32 values)
    imported_key_curve_to_signature_algorithms: HashMap<u32, Vec<u32>>,

    /// Protocol flags that don't require signature algorithms
    protocols_without_signature_algorithm: Vec<ProtocolFlag>,

    /// Protocol flags that require signature algorithms
    protocols_with_signature_algorithm: Vec<ProtocolFlag>,
}

impl MpcProtocolConfiguration {
    /// Creates the default MPC protocol configuration
    pub fn default_config() -> Self {
        Self {
            curve_to_signature_to_hash: Self::default_curve_signature_hash_config(),
            dkg_curve_to_signature_algorithms: Self::default_dkg_config(),
            imported_key_curve_to_signature_algorithms: Self::default_imported_key_config(),
            protocols_without_signature_algorithm: Self::default_protocols_without_sig_algo(),
            protocols_with_signature_algorithm: Self::default_protocols_with_sig_algo(),
        }
    }

    /// Default DKG configuration: curves to signature algorithms (as u32)
    fn default_dkg_config() -> HashMap<u32, Vec<u32>> {
        let mut config = HashMap::new();
        config.insert(0, vec![0, 1]); // Secp256k1: ECDSASecp256k1, Taproot
        config.insert(3, vec![2]); // Secp256r1: ECDSASecp256r1
        config.insert(1, vec![4]); // Ristretto: SchnorrkelSubstrate
        config.insert(2, vec![3]); // Curve25519: EdDSA
        config
    }

    /// Default imported key configuration: curves to signature algorithms (non-ECDSA only, as u32)
    fn default_imported_key_config() -> HashMap<u32, Vec<u32>> {
        let mut config = HashMap::new();
        config.insert(0, vec![1]); // Secp256k1: Taproot
        config.insert(3, vec![]); // Secp256r1: (empty)
        config.insert(1, vec![4]); // Ristretto: SchnorrkelSubstrate
        config.insert(2, vec![3]); // Curve25519: EdDSA
        config
    }

    /// Get protocols that don't require signature algorithms
    fn default_protocols_without_sig_algo() -> Vec<ProtocolFlag> {
        vec![
            ProtocolFlag::DkgFirstRound,
            ProtocolFlag::DkgSecondRound,
            ProtocolFlag::ReEncryptUserShare,
            ProtocolFlag::MakeDWalletUserSecretKeySharePublic,
            ProtocolFlag::ImportedKeyDWalletVerification,
            ProtocolFlag::DWalletDkg,
        ]
    }

    /// Get protocols that require signature algorithms
    fn default_protocols_with_sig_algo() -> Vec<ProtocolFlag> {
        vec![
            ProtocolFlag::Presign,
            ProtocolFlag::Sign,
            ProtocolFlag::FutureSign,
            ProtocolFlag::SignWithPartialUserSignature,
            ProtocolFlag::DWalletDkgWithSign,
        ]
    }

    /// Default configuration for curve -> signature algorithm -> hash algorithms
    /// Static vector-based configuration using raw u32 values
    fn default_curve_signature_hash_config() -> CurveSignatureHashConfig {
        vec![
            // (0, 0, [0, 1, 2]): Secp256k1 + ECDSASecp256k1 -> [Keccak256, SHA256, DoubleSHA256]
            (0, 0, vec![0, 1, 2]),
            // (0, 1, [1]): Secp256k1 + Taproot -> [SHA256]
            (0, 1, vec![1]),
            // (3, 2, [1, 2]): Secp256r1 + ECDSASecp256r1 -> [SHA256, DoubleSHA256]
            (3, 2, vec![1, 2]),
            // (1, 4, [4]): Ristretto + SchnorrkelSubstrate -> [Merlin]
            (1, 4, vec![4]),
            // (2, 3, [3]): Curve25519 + EdDSA -> [SHA512]
            (2, 3, vec![3]),
        ]
    }

    // ============= Conversion Functions: Number -> Enum =============

    /// Convert u32 to DWalletCurve
    pub fn number_to_curve(curve: u32) -> Result<DWalletCurve, MpcProtocolConfigurationError> {
        match curve {
            0 => Ok(DWalletCurve::Secp256k1),
            1 => Ok(DWalletCurve::Ristretto),
            2 => Ok(DWalletCurve::Curve25519),
            3 => Ok(DWalletCurve::Secp256r1),
            _ => Err(MpcProtocolConfigurationError::InvalidCurve(curve)),
        }
    }

    /// Convert u32 to DWalletSignatureScheme
    pub fn number_to_signature_algorithm(
        sig_algo: u32,
    ) -> Result<DWalletSignatureScheme, MpcProtocolConfigurationError> {
        match sig_algo {
            0 => Ok(DWalletSignatureScheme::ECDSASecp256k1),
            1 => Ok(DWalletSignatureScheme::Taproot),
            2 => Ok(DWalletSignatureScheme::ECDSASecp256r1),
            3 => Ok(DWalletSignatureScheme::EdDSA),
            4 => Ok(DWalletSignatureScheme::SchnorrkelSubstrate),
            _ => Err(MpcProtocolConfigurationError::InvalidSignatureAlgorithm(
                sig_algo,
            )),
        }
    }

    /// Convert u32 to HashType
    pub fn number_to_hash_algorithm(hash: u32) -> Result<HashType, MpcProtocolConfigurationError> {
        match hash {
            0 => Ok(HashType::Keccak256),
            1 => Ok(HashType::SHA256),
            2 => Ok(HashType::DoubleSHA256),
            3 => Ok(HashType::SHA512),
            4 => Ok(HashType::Merlin),
            _ => Err(MpcProtocolConfigurationError::InvalidHashType(hash)),
        }
    }

    // ============= Combined Conversion Functions =============

    /// Convert curve number to DWalletCurve
    /// Example: 0 -> Secp256k1
    pub fn from_curve_number(curve: u32) -> Result<DWalletCurve, MpcProtocolConfigurationError> {
        Self::number_to_curve(curve)
    }

    /// Convert curve and signature algorithm numbers to (DWalletCurve, DWalletSignatureScheme)
    /// Example: (0, 0) -> (Secp256k1, ECDSASecp256k1)
    pub fn from_curve_signature_numbers(
        curve: u32,
        sig_algo: u32,
    ) -> Result<(DWalletCurve, DWalletSignatureScheme), MpcProtocolConfigurationError> {
        let curve_enum = Self::number_to_curve(curve)?;
        let sig_algo_enum = Self::number_to_signature_algorithm(sig_algo)?;
        Ok((curve_enum, sig_algo_enum))
    }

    /// Convert curve, signature algorithm, and hash numbers to (DWalletCurve, DWalletSignatureScheme, HashType)
    /// Example: (0, 0, 1) -> (Secp256k1, ECDSASecp256k1, SHA256)
    pub fn from_curve_signature_hash_numbers(
        curve: u32,
        sig_algo: u32,
        hash: u32,
    ) -> Result<(DWalletCurve, DWalletSignatureScheme, HashType), MpcProtocolConfigurationError>
    {
        let curve_enum = Self::number_to_curve(curve)?;
        let sig_algo_enum = Self::number_to_signature_algorithm(sig_algo)?;
        let hash_enum = Self::number_to_hash_algorithm(hash)?;
        Ok((curve_enum, sig_algo_enum, hash_enum))
    }

    // ============= Query Functions =============

    /// Get all supported curves
    pub const fn get_supported_curves() -> [DWalletCurve; 4] {
        [
            DWalletCurve::Secp256k1,
            DWalletCurve::Secp256r1,
            DWalletCurve::Ristretto,
            DWalletCurve::Curve25519,
        ]
    }

    /// Get all signature algorithms
    pub const fn get_all_signature_algorithms() -> [DWalletSignatureScheme; 5] {
        [
            DWalletSignatureScheme::ECDSASecp256k1,
            DWalletSignatureScheme::ECDSASecp256r1,
            DWalletSignatureScheme::SchnorrkelSubstrate,
            DWalletSignatureScheme::EdDSA,
            DWalletSignatureScheme::Taproot,
        ]
    }

    /// Get all hash algorithms
    pub const fn get_all_hash_algorithms() -> [HashType; 5] {
        [
            HashType::Keccak256,
            HashType::SHA256,
            HashType::DoubleSHA256,
            HashType::SHA512,
            HashType::Merlin,
        ]
    }

    /// Get signature algorithms supported by a specific curve (as u32)
    pub fn get_signature_algorithms_for_curve(&self, curve: u32) -> Vec<u32> {
        let mut sig_algos: Vec<u32> = self
            .curve_to_signature_to_hash
            .iter()
            .filter(|(c, _, _)| *c == curve)
            .map(|(_, sig_algo, _)| *sig_algo)
            .collect();
        sig_algos.sort();
        sig_algos.dedup();
        sig_algos
    }

    /// Get signature algorithms supported by a specific curve for DKG (as u32)
    pub fn get_dkg_signature_algorithms_for_curve(&self, curve: u32) -> Option<&Vec<u32>> {
        self.dkg_curve_to_signature_algorithms.get(&curve)
    }

    /// Get signature algorithms supported by a specific curve for imported keys (as u32)
    pub fn get_imported_key_signature_algorithms_for_curve(&self, curve: u32) -> Option<&Vec<u32>> {
        self.imported_key_curve_to_signature_algorithms.get(&curve)
    }

    /// Get all protocol flags that don't require signature algorithms
    pub fn get_protocols_without_signature_algorithm(&self) -> &Vec<ProtocolFlag> {
        &self.protocols_without_signature_algorithm
    }

    /// Get all protocol flags that require signature algorithms
    pub fn get_protocols_with_signature_algorithm(&self) -> &Vec<ProtocolFlag> {
        &self.protocols_with_signature_algorithm
    }

    /// Get hash algorithms supported by a specific curve and signature algorithm (as u32)
    pub fn get_hash_algorithms_for_curve_and_signature(
        &self,
        curve: u32,
        sig_algo: u32,
    ) -> Option<&Vec<u32>> {
        self.curve_to_signature_to_hash
            .iter()
            .find(|(c, s, _)| *c == curve && *s == sig_algo)
            .map(|(_, _, hashes)| hashes)
    }

    /// Get all hash algorithms supported by a specific curve (across all signature algorithms, as u32)
    pub fn get_hash_algorithms_for_curve(&self, curve: u32) -> Option<Vec<u32>> {
        let mut hashes: Vec<u32> = self
            .curve_to_signature_to_hash
            .iter()
            .filter(|(c, _, _)| *c == curve)
            .flat_map(|(_, _, hashes)| hashes.iter().copied())
            .collect();

        if hashes.is_empty() {
            return None;
        }

        hashes.sort();
        hashes.dedup();
        Some(hashes)
    }

    /// Validate if a combination of curve, signature algorithm, and hash is supported (using u32)
    pub fn is_combination_supported(&self, curve: u32, sig_algo: u32, hash: u32) -> bool {
        self.get_hash_algorithms_for_curve_and_signature(curve, sig_algo)
            .map(|hashes| hashes.contains(&hash))
            .unwrap_or(false)
    }

    // ============= U32 Conversion Methods for Serialization =============

    /// Get all supported curves as u32 values
    pub fn get_supported_curves_u32() -> Vec<u32> {
        Self::get_supported_curves()
            .iter()
            .map(|c| *c as u32)
            .collect()
    }

    /// Get all signature algorithms as u32 values
    pub fn get_all_signature_algorithms_u32() -> Vec<u32> {
        Self::get_all_signature_algorithms()
            .iter()
            .map(|s| *s as u32)
            .collect()
    }

    /// Get all hash algorithms as u32 values
    pub fn get_all_hash_algorithms_u32() -> Vec<u32> {
        Self::get_all_hash_algorithms()
            .iter()
            .map(|h| *h as u32)
            .collect()
    }

    /// Get the full configuration as reference (already in u32 format)
    pub fn get_curve_to_signature_to_hash(&self) -> &Vec<(u32, u32, Vec<u32>)> {
        &self.curve_to_signature_to_hash
    }

    /// Get DKG curve to signature algorithms map (already in u32 format)
    pub fn get_dkg_curve_to_signature_algorithms(&self) -> &HashMap<u32, Vec<u32>> {
        &self.dkg_curve_to_signature_algorithms
    }

    /// Get imported key curve to signature algorithms map (already in u32 format)
    pub fn get_imported_key_curve_to_signature_algorithms(&self) -> &HashMap<u32, Vec<u32>> {
        &self.imported_key_curve_to_signature_algorithms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_number_conversions() {
        // Test curve conversion
        assert_eq!(
            MpcProtocolConfiguration::number_to_curve(0).unwrap(),
            DWalletCurve::Secp256k1
        );

        // Test signature algorithm conversion
        assert_eq!(
            MpcProtocolConfiguration::number_to_signature_algorithm(0).unwrap(),
            DWalletSignatureScheme::ECDSASecp256k1
        );

        // Test hash algorithm conversion
        assert_eq!(
            MpcProtocolConfiguration::number_to_hash_algorithm(1).unwrap(),
            HashType::SHA256
        );
    }

    #[test]
    fn test_combined_conversions() {
        // Test curve number conversion
        let curve = MpcProtocolConfiguration::from_curve_number(0).unwrap();
        assert_eq!(curve, DWalletCurve::Secp256k1);

        // Test curve + signature conversion
        let (curve, sig_algo) =
            MpcProtocolConfiguration::from_curve_signature_numbers(0, 0).unwrap();
        assert_eq!(curve, DWalletCurve::Secp256k1);
        assert_eq!(sig_algo, DWalletSignatureScheme::ECDSASecp256k1);

        // Test curve + signature + hash conversion (0, 0, 1 -> Secp256k1, ECDSASecp256k1, SHA256)
        let (curve, sig_algo, hash) =
            MpcProtocolConfiguration::from_curve_signature_hash_numbers(0, 0, 1).unwrap();
        assert_eq!(curve, DWalletCurve::Secp256k1);
        assert_eq!(sig_algo, DWalletSignatureScheme::ECDSASecp256k1);
        assert_eq!(hash, HashType::SHA256);
    }

    #[test]
    fn test_default_config() {
        let config = MpcProtocolConfiguration::default_config();

        // Test Secp256k1 (0) + ECDSASecp256k1 (0)
        let hashes = config
            .get_hash_algorithms_for_curve_and_signature(0, 0)
            .unwrap();
        assert_eq!(hashes.len(), 3);
        assert!(hashes.contains(&0)); // Keccak256
        assert!(hashes.contains(&1)); // SHA256
        assert!(hashes.contains(&2)); // DoubleSHA256

        // Test Secp256k1 (0) + Taproot (1)
        let hashes = config
            .get_hash_algorithms_for_curve_and_signature(0, 1)
            .unwrap();
        assert_eq!(hashes.len(), 1);
        assert!(hashes.contains(&1)); // SHA256
    }

    #[test]
    fn test_is_combination_supported() {
        let config = MpcProtocolConfiguration::default_config();

        // Valid combination: 0, 0, 1 -> Secp256k1, ECDSASecp256k1, SHA256
        assert!(config.is_combination_supported(0, 0, 1));

        // Invalid combination: 0, 0, 4 -> Secp256k1, ECDSASecp256k1, Merlin (not supported)
        assert!(!config.is_combination_supported(0, 0, 4));
    }

    #[test]
    fn test_get_signature_algorithms_for_curve() {
        let config = MpcProtocolConfiguration::default_config();

        // Test Secp256k1 (0)
        let sig_algos = config.get_signature_algorithms_for_curve(0);
        assert_eq!(sig_algos.len(), 2);
        assert!(sig_algos.contains(&0)); // ECDSASecp256k1
        assert!(sig_algos.contains(&1)); // Taproot
    }

    #[test]
    fn test_config_structure() {
        let config = MpcProtocolConfiguration::default_config();

        // Test full config as vector
        let config_vec = config.get_curve_to_signature_to_hash();
        assert_eq!(config_vec.len(), 5); // 5 combinations total

        // Check that Secp256k1 (0) is present
        assert!(config_vec.iter().any(|(c, _, _)| *c == 0));
        // Check that Secp256r1 (3) is present
        assert!(config_vec.iter().any(|(c, _, _)| *c == 3));

        // Test signature algorithms for curve
        let sig_algos = config.get_signature_algorithms_for_curve(0);
        assert_eq!(sig_algos.len(), 2);

        // Test hash algorithms for curve and signature
        let hashes = config
            .get_hash_algorithms_for_curve_and_signature(0, 0)
            .unwrap();
        assert_eq!(hashes.len(), 3);

        // Test DKG config
        let dkg_config = config.get_dkg_curve_to_signature_algorithms();
        assert!(dkg_config.contains_key(&0)); // Secp256k1
        assert_eq!(dkg_config.get(&0).unwrap().len(), 2);
    }
}
