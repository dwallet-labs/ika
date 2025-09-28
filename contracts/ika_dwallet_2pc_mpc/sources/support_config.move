// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_dwallet_2pc_mpc::support_config;

use sui::vec_map::VecMap;

// === Errors ===

/// Specified hash scheme is not supported
const EInvalidHashScheme: u64 = 1;
/// Specified cryptographic curve is not supported
const EInvalidCurve: u64 = 2;
/// Specified signature algorithm is not supported
const EInvalidSignatureAlgorithm: u64 = 3;
/// Cryptographic curve is temporarily paused
const ECurvePaused: u64 = 4;
/// Signature algorithm is temporarily paused
const ESignatureAlgorithmPaused: u64 = 5;
/// Hash scheme is temporarily paused
const EHashSchemePaused: u64 = 6;

// === Structs ===

/// Support data for the dWallet coordinator, including curve and algorithm configurations.
public struct SupportConfig has store {
    /// A nested map of supported curves to signature algorithms to hash schemes.
    /// e.g. secp256k1 -> [(ecdsa -> [sha256, keccak256]), (schnorr -> [sha256])]
    supported_curves_to_signature_algorithms_to_hash_schemes: VecMap<u32, VecMap<u32, vector<u32>>>,
    /// List of paused curves in case of emergency (e.g. [secp256k1, ristretto])
    paused_curves: vector<u32>,
    /// List of paused signature algorithms in case of emergency (e.g. [ecdsa, schnorr])
    paused_signature_algorithms: vector<u32>,
    /// List of paused hash schemes in case of emergency (e.g. [sha256, keccak256])
    paused_hash_schemes: vector<u32>,
    /// Signature algorithms that are allowed for global presign
    /// Deprecated: Use GlobalPresignConfig instead.
    signature_algorithms_allowed_global_presign: vector<u32>,
}

/// Global presign config
///
/// This config is used to determine if a presign is global or not.
/// If a presign is global, it can be used by any dWallet.
/// If a presign is not global, it can only be used by the dWallet it was created for.
public struct GlobalPresignConfig has store {
    /// Map of curves to signature algorithms for dWallets that are created via DKG.
    /// This means for this curve and this signature algorithm, it is only allowed to use global presign.
    /// e.g. secp256k1 -> [(ecdsa -> [sha256, keccak256]), (schnorr -> [sha256])]
    curve_to_signature_algorithms_for_dkg: VecMap<u32, vector<u32>>,
    /// Map of curves to signature algorithms for dWallets that are created via imported key.
    /// This means for this curve and this signature algorithm, it is only allowed to use global presign.
    /// e.g. secp256k1 -> [(ecdsa -> [sha256, keccak256]), (schnorr -> [sha256])]
    curve_to_signature_algorithms_for_imported_key: VecMap<u32, vector<u32>>,
}

/// === Package Functions ===

public(package) fun create(
    supported_curves_to_signature_algorithms_to_hash_schemes: VecMap<u32, VecMap<u32, vector<u32>>>,
): SupportConfig {
    SupportConfig {
        supported_curves_to_signature_algorithms_to_hash_schemes,
        paused_curves: vector[],
        paused_signature_algorithms: vector[],
        paused_hash_schemes: vector[],
        signature_algorithms_allowed_global_presign: vector[],
    }
}

/// Validates that a curve is supported and not paused.
///
/// ### Parameters
/// - `self`: Reference to the coordinator
/// - `curve`: Curve identifier to validate
///
/// ### Aborts
/// - `EInvalidCurve`: If the curve is not supported
/// - `ECurvePaused`: If the curve is currently paused
public(package) fun validate_curve(self: &SupportConfig, curve: u32) {
    assert!(
        self.supported_curves_to_signature_algorithms_to_hash_schemes.contains(&curve),
        EInvalidCurve,
    );
    assert!(!self.paused_curves.contains(&curve), ECurvePaused);
}

/// Validates that a curve and signature algorithm combination is supported and not paused.
///
/// ### Parameters
/// - `self`: Reference to the coordinator
/// - `curve`: Curve identifier to validate
/// - `signature_algorithm`: Signature algorithm to validate
///
/// ### Aborts
/// - `EInvalidCurve`: If the curve is not supported
/// - `ECurvePaused`: If the curve is currently paused
/// - `EInvalidSignatureAlgorithm`: If the signature algorithm is not supported for this curve
/// - `ESignatureAlgorithmPaused`: If the signature algorithm is currently paused
public(package) fun validate_curve_and_signature_algorithm(
    self: &SupportConfig,
    curve: u32,
    signature_algorithm: u32,
) {
    self.validate_curve(curve);
    let supported_curve_to_signature_algorithms = self.supported_curves_to_signature_algorithms_to_hash_schemes[
        &curve,
    ];
    assert!(
        supported_curve_to_signature_algorithms.contains(&signature_algorithm),
        EInvalidSignatureAlgorithm,
    );
    assert!(
        !self.paused_signature_algorithms.contains(&signature_algorithm),
        ESignatureAlgorithmPaused,
    );
}

/// Validates that a curve, signature algorithm, and hash scheme combination is supported and not paused.
///
/// ### Parameters
/// - `self`: Reference to the coordinator
/// - `curve`: Curve identifier to validate
/// - `signature_algorithm`: Signature algorithm to validate
/// - `hash_scheme`: Hash scheme to validate
///
/// ### Aborts
/// - `EInvalidCurve`: If the curve is not supported
/// - `ECurvePaused`: If the curve is currently paused
/// - `EInvalidSignatureAlgorithm`: If the signature algorithm is not supported for this curve
/// - `ESignatureAlgorithmPaused`: If the signature algorithm is currently paused
/// - `EInvalidHashScheme`: If the hash scheme is not supported for this combination
/// - `EHashSchemePaused`: If the hash scheme is currently paused
public(package) fun validate_curve_and_signature_algorithm_and_hash_scheme(
    self: &SupportConfig,
    curve: u32,
    signature_algorithm: u32,
    hash_scheme: u32,
) {
    self.validate_curve_and_signature_algorithm(curve, signature_algorithm);
    let supported_hash_schemes = self.supported_curves_to_signature_algorithms_to_hash_schemes[
        &curve,
    ][
        &signature_algorithm,
    ];
    assert!(supported_hash_schemes.contains(&hash_scheme), EInvalidHashScheme);
    assert!(!self.paused_hash_schemes.contains(&hash_scheme), EHashSchemePaused);
}

/// Checks if only global presign is allowed for a dWallet that is created via DKG.
///
/// ### Parameters
/// - `self`: Reference to the global presign config
/// - `curve`: Curve identifier to check
/// - `signature_algorithm`: Signature algorithm to check
/// ### Returns
/// True if only global presign is allowed for the dWallet that is created via DKG, false otherwise
public(package) fun is_global_presign_for_dkg(
    self: & GlobalPresignConfig,
    curve: u32,
    signature_algorithm: u32,
): bool {
    self.curve_to_signature_algorithms_for_dkg.contains(&curve) && self.curve_to_signature_algorithms_for_dkg[&curve].contains(&signature_algorithm)
}

/// Checks if only global presign is allowed for a dWallet that is created via imported key.
///
/// ### Parameters
/// - `self`: Reference to the global presign config
/// - `curve`: Curve identifier to check
/// - `signature_algorithm`: Signature algorithm to check
/// ### Returns
/// True if only global presign is allowed for the dWallet that is created via imported key, false otherwise
public(package) fun is_global_presign_for_imported_key(
    self: & GlobalPresignConfig,
    curve: u32,
    signature_algorithm: u32,
): bool {
    self.curve_to_signature_algorithms_for_imported_key.contains(&curve) && self.curve_to_signature_algorithms_for_imported_key[&curve].contains(&signature_algorithm)
}

public(package) fun set_supported_curves_to_signature_algorithms_to_hash_schemes(
    self: &mut SupportConfig,
    supported_curves_to_signature_algorithms_to_hash_schemes: VecMap<u32, VecMap<u32, vector<u32>>>,
) {
    self.supported_curves_to_signature_algorithms_to_hash_schemes =
        supported_curves_to_signature_algorithms_to_hash_schemes;
}

public(package) fun set_paused(
    self: &mut SupportConfig,
    paused_curves: vector<u32>,
    paused_signature_algorithms: vector<u32>,
    paused_hash_schemes: vector<u32>,
) {
    self.paused_curves = paused_curves;
    self.paused_signature_algorithms = paused_signature_algorithms;
    self.paused_hash_schemes = paused_hash_schemes;
}

public(package) fun create_global_presign_config(
    curve_to_signature_algorithms_for_dkg: VecMap<u32, vector<u32>>,
    curve_to_signature_algorithms_for_imported_key: VecMap<u32, vector<u32>>,
): GlobalPresignConfig {
    GlobalPresignConfig {
        curve_to_signature_algorithms_for_dkg,
        curve_to_signature_algorithms_for_imported_key,
    }
}

public(package) fun set_global_presign_config(
    self: &mut GlobalPresignConfig,
    curve_to_signature_algorithms_for_dkg: VecMap<u32, vector<u32>>,
    curve_to_signature_algorithms_for_imported_key: VecMap<u32, vector<u32>>,
) {
    self.curve_to_signature_algorithms_for_dkg = curve_to_signature_algorithms_for_dkg;
    self.curve_to_signature_algorithms_for_imported_key = curve_to_signature_algorithms_for_imported_key;
}