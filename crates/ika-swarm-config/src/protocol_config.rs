use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, DWalletSignatureScheme};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Hash algorithms supported by the protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum HashAlgorithm {
    Keccak256 = 0,
    SHA256 = 1,
    DoubleSHA256 = 2,
    SHA512 = 3,
    Merlin = 4,
}

/// Protocol flags for DKG and signing operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
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

/// Protocol types for MPC operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolType {
    /// Protocols that don't require signature algorithms
    WithoutSignatureAlgorithm,
    /// Protocols that require signature algorithms
    WithSignatureAlgorithm,
}

/// Configuration for curve-to-signature-algorithm mappings
///
/// Uses strongly-typed enums instead of raw u32 for type safety and better API ergonomics.
pub struct ProtocolConfiguration {
    /// Curves and their supported signature algorithms for DKG
    dkg_curve_to_signature_algorithms: HashMap<DWalletCurve, HashSet<DWalletSignatureScheme>>,

    /// Curves and their supported signature algorithms for imported keys (non-ECDSA only)
    imported_key_curve_to_signature_algorithms:
        HashMap<DWalletCurve, HashSet<DWalletSignatureScheme>>,

    /// Curves and their supported hash algorithms
    curve_to_hash_algorithms: HashMap<DWalletCurve, HashSet<HashAlgorithm>>,

    /// Protocol flags that don't require signature algorithms
    protocols_without_signature_algorithm: HashSet<ProtocolFlag>,

    /// Protocol flags that require signature algorithms
    protocols_with_signature_algorithm: HashSet<ProtocolFlag>,
}

impl ProtocolConfiguration {
    /// Creates the default protocol configuration
    pub fn default_config() -> Self {
        Self {
            dkg_curve_to_signature_algorithms: Self::default_dkg_config(),
            imported_key_curve_to_signature_algorithms: Self::default_imported_key_config(),
            curve_to_hash_algorithms: Self::default_hash_config(),
            protocols_without_signature_algorithm: Self::default_protocols_without_sig_algo(),
            protocols_with_signature_algorithm: Self::default_protocols_with_sig_algo(),
        }
    }

    /// Get protocols that don't require signature algorithms
    ///
    /// These protocols work independently of signature schemes:
    /// - DKG first and second rounds
    /// - Re-encryption of user shares
    /// - Making user secret key shares public
    /// - Imported key verification
    /// - DWallet DKG
    fn default_protocols_without_sig_algo() -> HashSet<ProtocolFlag> {
        [
            ProtocolFlag::DkgFirstRound,
            ProtocolFlag::DkgSecondRound,
            ProtocolFlag::ReEncryptUserShare,
            ProtocolFlag::MakeDWalletUserSecretKeySharePublic,
            ProtocolFlag::ImportedKeyDWalletVerification,
            ProtocolFlag::DWalletDkg,
        ]
        .into_iter()
        .collect()
    }

    /// Get protocols that require signature algorithms
    ///
    /// These protocols depend on specific signature schemes:
    /// - Presign operations
    /// - Sign operations
    /// - Future sign operations
    /// - Sign with partial user signature
    /// - DWallet DKG with sign
    fn default_protocols_with_sig_algo() -> HashSet<ProtocolFlag> {
        [
            ProtocolFlag::Presign,
            ProtocolFlag::Sign,
            ProtocolFlag::FutureSign,
            ProtocolFlag::SignWithPartialUserSignature,
            ProtocolFlag::DWalletDkgWithSign,
        ]
        .into_iter()
        .collect()
    }

    /// Default DKG configuration: curves to signature algorithms
    ///
    /// Each curve supports specific signature algorithms including ECDSA variants
    fn default_dkg_config() -> HashMap<DWalletCurve, HashSet<DWalletSignatureScheme>> {
        [
            // secp256k1 supports ECDSASecp256k1 and Taproot
            (
                DWalletCurve::Secp256k1,
                [
                    DWalletSignatureScheme::ECDSASecp256k1,
                    DWalletSignatureScheme::Taproot,
                ]
                .into_iter()
                .collect(),
            ),
            // secp256r1 supports ECDSASecp256r1
            (
                DWalletCurve::Secp256r1,
                [DWalletSignatureScheme::ECDSASecp256r1]
                    .into_iter()
                    .collect(),
            ),
            // ristretto supports SchnorrkelSubstrate
            (
                DWalletCurve::Ristretto,
                [DWalletSignatureScheme::SchnorrkelSubstrate]
                    .into_iter()
                    .collect(),
            ),
            // curve25519 supports EdDSA
            (
                DWalletCurve::Curve25519,
                [DWalletSignatureScheme::EdDSA].into_iter().collect(),
            ),
        ]
        .into_iter()
        .collect()
    }

    /// Default imported key configuration: curves to signature algorithms
    ///
    /// Each curve supports specific non-ECDSA signature algorithms only
    fn default_imported_key_config() -> HashMap<DWalletCurve, HashSet<DWalletSignatureScheme>> {
        [
            // secp256k1 supports Taproot (non-ECDSA)
            (
                DWalletCurve::Secp256k1,
                [DWalletSignatureScheme::Taproot].into_iter().collect(),
            ),
            // secp256r1 supports no non-ECDSA algorithms (empty set)
            (DWalletCurve::Secp256r1, HashSet::new()),
            // ristretto supports SchnorrkelSubstrate
            (
                DWalletCurve::Ristretto,
                [DWalletSignatureScheme::SchnorrkelSubstrate]
                    .into_iter()
                    .collect(),
            ),
            // curve25519 supports EdDSA
            (
                DWalletCurve::Curve25519,
                [DWalletSignatureScheme::EdDSA].into_iter().collect(),
            ),
        ]
        .into_iter()
        .collect()
    }

    /// Default hash algorithm configuration: curves to hash algorithms
    ///
    /// Each curve supports specific hash algorithms for signing operations
    fn default_hash_config() -> HashMap<DWalletCurve, HashSet<HashAlgorithm>> {
        [
            // secp256k1: supports SHA256, Keccak256, and DoubleSHA256
            (
                DWalletCurve::Secp256k1,
                [
                    HashAlgorithm::Keccak256,
                    HashAlgorithm::SHA256,
                    HashAlgorithm::DoubleSHA256,
                ]
                .into_iter()
                .collect(),
            ),
            // secp256r1: supports SHA256 and DoubleSHA256
            (
                DWalletCurve::Secp256r1,
                [HashAlgorithm::SHA256, HashAlgorithm::DoubleSHA256]
                    .into_iter()
                    .collect(),
            ),
            // ristretto: supports Merlin
            (
                DWalletCurve::Ristretto,
                [HashAlgorithm::Merlin].into_iter().collect(),
            ),
            // curve25519 (EdDSA): supports SHA512
            (
                DWalletCurve::Curve25519,
                [HashAlgorithm::SHA512].into_iter().collect(),
            ),
        ]
        .into_iter()
        .collect()
    }

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

    /// Get signature algorithms supported by a specific curve for DKG
    pub fn get_dkg_signature_algorithms_for_curve(
        &self,
        curve: DWalletCurve,
    ) -> Option<&HashSet<DWalletSignatureScheme>> {
        self.dkg_curve_to_signature_algorithms.get(&curve)
    }

    /// Get signature algorithms supported by a specific curve for imported keys
    pub fn get_imported_key_signature_algorithms_for_curve(
        &self,
        curve: DWalletCurve,
    ) -> Option<&HashSet<DWalletSignatureScheme>> {
        self.imported_key_curve_to_signature_algorithms.get(&curve)
    }

    /// Get hash algorithms supported by a specific curve
    pub fn get_hash_algorithms_for_curve(
        &self,
        curve: DWalletCurve,
    ) -> Option<&HashSet<HashAlgorithm>> {
        self.curve_to_hash_algorithms.get(&curve)
    }

    /// Get all protocol flags that don't require signature algorithms
    pub fn get_protocols_without_signature_algorithm(&self) -> &HashSet<ProtocolFlag> {
        &self.protocols_without_signature_algorithm
    }

    /// Get all protocol flags that require signature algorithms
    pub fn get_protocols_with_signature_algorithm(&self) -> &HashSet<ProtocolFlag> {
        &self.protocols_with_signature_algorithm
    }

    // Conversion methods for backward compatibility with u32 APIs

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

    /// Get signature algorithms supported by a specific curve for DKG (as u32)
    pub fn get_dkg_signature_algorithms_for_curve_u32(&self, curve: u32) -> Option<Vec<u32>> {
        let curve_enum = match curve {
            0 => DWalletCurve::Secp256k1,
            1 => DWalletCurve::Ristretto,
            2 => DWalletCurve::Curve25519,
            3 => DWalletCurve::Secp256r1,
            _ => return None,
        };

        self.dkg_curve_to_signature_algorithms
            .get(&curve_enum)
            .map(|set| set.iter().map(|s| *s as u32).collect())
    }

    /// Get signature algorithms supported by a specific curve for imported keys (as u32)
    pub fn get_imported_key_signature_algorithms_for_curve_u32(
        &self,
        curve: u32,
    ) -> Option<Vec<u32>> {
        let curve_enum = match curve {
            0 => DWalletCurve::Secp256k1,
            1 => DWalletCurve::Ristretto,
            2 => DWalletCurve::Curve25519,
            3 => DWalletCurve::Secp256r1,
            _ => return None,
        };

        self.imported_key_curve_to_signature_algorithms
            .get(&curve_enum)
            .map(|set| set.iter().map(|s| *s as u32).collect())
    }

    /// Get hash algorithms supported by a specific curve (as u32)
    pub fn get_hash_algorithms_for_curve_u32(&self, curve: u32) -> Option<Vec<u32>> {
        let curve_enum = match curve {
            0 => DWalletCurve::Secp256k1,
            1 => DWalletCurve::Ristretto,
            2 => DWalletCurve::Curve25519,
            3 => DWalletCurve::Secp256r1,
            _ => return None,
        };

        self.curve_to_hash_algorithms
            .get(&curve_enum)
            .map(|set| set.iter().map(|h| *h as u32).collect())
    }

    /// Get all protocol flags that don't require signature algorithms (as u32)
    pub fn get_protocols_without_signature_algorithm_u32(&self) -> Vec<u32> {
        self.protocols_without_signature_algorithm
            .iter()
            .map(|p| *p as u32)
            .collect()
    }

    /// Get all protocol flags that require signature algorithms (as u32)
    pub fn get_protocols_with_signature_algorithm_u32(&self) -> Vec<u32> {
        self.protocols_with_signature_algorithm
            .iter()
            .map(|p| *p as u32)
            .collect()
    }

    /// Get DKG curve to signature algorithms map as u32 values (for serialization)
    pub fn get_dkg_curve_to_signature_algorithms_u32(&self) -> HashMap<u32, Vec<u32>> {
        self.dkg_curve_to_signature_algorithms
            .iter()
            .map(|(curve, sig_algos)| {
                let curve_u32 = *curve as u32;
                let sig_algos_vec: Vec<u32> = sig_algos.iter().map(|s| *s as u32).collect();
                (curve_u32, sig_algos_vec)
            })
            .collect()
    }

    /// Get imported key curve to signature algorithms map as u32 values (for serialization)
    pub fn get_imported_key_curve_to_signature_algorithms_u32(&self) -> HashMap<u32, Vec<u32>> {
        self.imported_key_curve_to_signature_algorithms
            .iter()
            .map(|(curve, sig_algos)| {
                let curve_u32 = *curve as u32;
                let sig_algos_vec: Vec<u32> = sig_algos.iter().map(|s| *s as u32).collect();
                (curve_u32, sig_algos_vec)
            })
            .collect()
    }

    /// Get curve to hash algorithms map as u32 values (for serialization)
    pub fn get_curve_to_hash_algorithms_u32(&self) -> HashMap<u32, Vec<u32>> {
        self.curve_to_hash_algorithms
            .iter()
            .map(|(curve, hash_algos)| {
                let curve_u32 = *curve as u32;
                let hash_algos_vec: Vec<u32> = hash_algos.iter().map(|h| *h as u32).collect();
                (curve_u32, hash_algos_vec)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_has_all_curves() {
        let config = ProtocolConfiguration::default_config();
        let curves = ProtocolConfiguration::get_supported_curves();

        for curve in curves {
            assert!(
                config
                    .dkg_curve_to_signature_algorithms
                    .contains_key(&curve),
                "DKG config missing curve: {:?}",
                curve
            );
            assert!(
                config
                    .imported_key_curve_to_signature_algorithms
                    .contains_key(&curve),
                "Imported key config missing curve: {:?}",
                curve
            );
            assert!(
                config.curve_to_hash_algorithms.contains_key(&curve),
                "Hash config missing curve: {:?}",
                curve
            );
        }
    }

    #[test]
    fn test_secp256k1_dkg_supports_ecdsa_and_taproot() {
        let config = ProtocolConfiguration::default_config();
        let sig_algos = config
            .get_dkg_signature_algorithms_for_curve(DWalletCurve::Secp256k1)
            .unwrap();

        assert_eq!(sig_algos.len(), 2);
        assert!(sig_algos.contains(&DWalletSignatureScheme::ECDSASecp256k1));
        assert!(sig_algos.contains(&DWalletSignatureScheme::Taproot));
    }

    #[test]
    fn test_secp256r1_imported_key_has_no_non_ecdsa() {
        let config = ProtocolConfiguration::default_config();
        let sig_algos = config
            .get_imported_key_signature_algorithms_for_curve(DWalletCurve::Secp256r1)
            .unwrap();

        assert_eq!(sig_algos.len(), 0);
    }

    #[test]
    fn test_secp256k1_hash_algorithms() {
        let config = ProtocolConfiguration::default_config();
        let hash_algos = config
            .get_hash_algorithms_for_curve(DWalletCurve::Secp256k1)
            .unwrap();

        assert_eq!(hash_algos.len(), 3);
        assert!(hash_algos.contains(&HashAlgorithm::Keccak256));
        assert!(hash_algos.contains(&HashAlgorithm::SHA256));
        assert!(hash_algos.contains(&HashAlgorithm::DoubleSHA256));
    }

    #[test]
    fn test_protocols_without_sig_algo() {
        let config = ProtocolConfiguration::default_config();
        let protocols = config.get_protocols_without_signature_algorithm();

        assert_eq!(protocols.len(), 6);
        assert!(protocols.contains(&ProtocolFlag::DkgFirstRound));
        assert!(protocols.contains(&ProtocolFlag::DkgSecondRound));
        assert!(protocols.contains(&ProtocolFlag::ReEncryptUserShare));
        assert!(protocols.contains(&ProtocolFlag::MakeDWalletUserSecretKeySharePublic));
        assert!(protocols.contains(&ProtocolFlag::ImportedKeyDWalletVerification));
        assert!(protocols.contains(&ProtocolFlag::DWalletDkg));
    }

    #[test]
    fn test_protocols_with_sig_algo() {
        let config = ProtocolConfiguration::default_config();
        let protocols = config.get_protocols_with_signature_algorithm();

        assert_eq!(protocols.len(), 5);
        assert!(protocols.contains(&ProtocolFlag::Presign));
        assert!(protocols.contains(&ProtocolFlag::Sign));
        assert!(protocols.contains(&ProtocolFlag::FutureSign));
        assert!(protocols.contains(&ProtocolFlag::SignWithPartialUserSignature));
        assert!(protocols.contains(&ProtocolFlag::DWalletDkgWithSign));
    }

    #[test]
    fn test_u32_conversion_apis() {
        let config = ProtocolConfiguration::default_config();

        // Test curve u32 conversion
        let curves_u32 = ProtocolConfiguration::get_supported_curves_u32();
        assert_eq!(curves_u32.len(), 4);

        // Test signature algorithm u32 conversion
        let sig_algos_u32 = ProtocolConfiguration::get_all_signature_algorithms_u32();
        assert_eq!(sig_algos_u32.len(), 5);

        // Test DKG signature algorithms for curve (u32 API)
        let secp256k1_sig_algos = config
            .get_dkg_signature_algorithms_for_curve_u32(DWalletCurve::Secp256k1 as u32)
            .unwrap();
        assert_eq!(secp256k1_sig_algos.len(), 2);
        assert!(secp256k1_sig_algos.contains(&(DWalletSignatureScheme::ECDSASecp256k1 as u32)));
        assert!(secp256k1_sig_algos.contains(&(DWalletSignatureScheme::Taproot as u32)));

        // Test hash algorithms for curve (u32 API)
        let secp256k1_hashes = config
            .get_hash_algorithms_for_curve_u32(DWalletCurve::Secp256k1 as u32)
            .unwrap();
        assert_eq!(secp256k1_hashes.len(), 3);

        // Test protocols without sig algo (u32 API)
        let protocols_without = config.get_protocols_without_signature_algorithm_u32();
        assert_eq!(protocols_without.len(), 6);

        // Test protocols with sig algo (u32 API)
        let protocols_with = config.get_protocols_with_signature_algorithm_u32();
        assert_eq!(protocols_with.len(), 5);
    }
}
