// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_system::validator_info;

use ika_common::extended_field::{Self, ExtendedField};
use ika_common::multiaddr;
use ika_system::validator_metadata::ValidatorMetadata;
use std::string::String;
use sui::bcs;
use sui::bls12381::{UncompressedG1, g1_from_bytes, g1_to_uncompressed_g1, bls12381_min_pk_verify};
use sui::group_ops::Element;
use sui::table_vec::TableVec;

// === Constants ===

/// Maximum allowed length for validator names
const MAX_VALIDATOR_NAME_LENGTH: u64 = 100;
/// Maximum allowed length for validator text fields (addresses, etc.)
const MAX_VALIDATOR_TEXT_FIELD_LENGTH: u64 = 259;
/// Intent bytes used for proof of possession verification
const PROOF_OF_POSSESSION_INTENT: vector<u8> = vector[0, 0, 0];
/// Default epoch identifier used for initial validation
const DEFAULT_EPOCH_ID: u64 = 0;
/// Expected length of BLS public keys in bytes
const BLS_KEY_LEN: u64 = 48;
/// Expected length of Ed25519 public keys in bytes
const ED25519_KEY_LEN: u64 = 32;

// === Errors ===

/// Invalid proof_of_possession_bytes field in ValidatorMetadata.
const EInvalidProofOfPossession: u64 = 0;
/// Validator name length exceeds maximum allowed length.
const EInvalidNameLength: u64 = 1;
/// Invalid protocol_pubkey_bytes field in ValidatorMetadata.
const EMetadataInvalidProtocolPubkey: u64 = 2;
/// Invalid network_pubkey_bytes field in ValidatorMetadata.
const EMetadataInvalidNetworkPubkey: u64 = 3;
/// Invalid consensus_pubkey_bytes field in ValidatorMetadata.
const EMetadataInvalidConsensusPubkey: u64 = 4;
/// Invalid network_address field in ValidatorMetadata.
const EMetadataInvalidNetworkAddress: u64 = 5;
/// Invalid p2p_address field in ValidatorMetadata.
const EMetadataInvalidP2pAddress: u64 = 6;
/// Invalid consensus_address field in ValidatorMetadata.
const EMetadataInvalidConsensusAddress: u64 = 7;
/// Validator Metadata is too long.
const EValidatorMetadataExceedingLengthLimit: u64 = 8;

// === Structs ===

/// Represents a validator info in the system.
/// Contains all validator-specific data including public keys, network addresses,
/// and metadata for both current and next epoch configurations.
public struct ValidatorInfo has store {
    /// Human-readable name of the validator
    name: String,
    /// Unique identifier for this validator
    validator_id: ID,
    /// The network address of the validator (could also contain extra info such as port, DNS and etc.)
    network_address: String,
    /// The address of the validator used for p2p activities such as state sync (could also contain extra info such as port, DNS and etc.)
    p2p_address: String,
    /// The address of the consensus
    consensus_address: String,
    /// Current epoch public keys
    /// The public key bytes corresponding to the private key that the validator
    /// holds to sign checkpoint messages
    protocol_pubkey_bytes: vector<u8>,
    /// The protocol public key element for cryptographic operations
    protocol_pubkey: Element<UncompressedG1>,
    /// The public key bytes corresponding to the private key that the validator
    /// uses to establish TLS connections
    network_pubkey_bytes: vector<u8>,
    /// The public key bytes corresponding to the consensus
    consensus_pubkey_bytes: vector<u8>,
    /// The validator's MPC public data.
    /// This key is used for the network DKG process and for resharing the network MPC key
    /// Must always contain value 
    mpc_data_bytes: Option<TableVec<vector<u8>>>,
    /// Next epoch configurations - only take effect in the next epoch
    /// If none, current value will stay unchanged.
    next_epoch_protocol_pubkey_bytes: Option<vector<u8>>,
    next_epoch_network_pubkey_bytes: Option<vector<u8>>,
    next_epoch_consensus_pubkey_bytes: Option<vector<u8>>,
    next_epoch_mpc_data_bytes: Option<TableVec<vector<u8>>>,
    next_epoch_network_address: Option<String>,
    next_epoch_p2p_address: Option<String>,
    next_epoch_consensus_address: Option<String>,

    previous_mpc_data_bytes: Option<TableVec<vector<u8>>>,
    /// Extended metadata field for additional validator information
    metadata: ExtendedField<ValidatorMetadata>,
}

// === Package Functions ===

/// Creates a new ValidatorInfo instance with the provided parameters.
/// Validates all inputs and verifies proof of possession for the protocol key.
public(package) fun new(
    name: String,
    validator_id: ID,
    protocol_pubkey_bytes: vector<u8>,
    network_pubkey_bytes: vector<u8>,
    consensus_pubkey_bytes: vector<u8>,
    mpc_data_bytes: TableVec<vector<u8>>,
    proof_of_possession_bytes: vector<u8>,
    network_address: String,
    p2p_address: String,
    consensus_address: String,
    metadata: ValidatorMetadata,
    ctx: &mut TxContext,
): ValidatorInfo {
    let protocol_pubkey = g1_to_uncompressed_g1(&g1_from_bytes(&protocol_pubkey_bytes));

    // Verify proof of possession for protocol public key
    assert!(
        verify_proof_of_possession(
            DEFAULT_EPOCH_ID,
            ctx.sender(),
            protocol_pubkey_bytes,
            proof_of_possession_bytes,
        ),
        EInvalidProofOfPossession,
    );

    let validator_info = ValidatorInfo {
        validator_id,
        name,
        protocol_pubkey_bytes,
        protocol_pubkey,
        network_pubkey_bytes,
        consensus_pubkey_bytes,
        mpc_data_bytes: option::some(mpc_data_bytes),
        network_address,
        p2p_address,
        consensus_address,
        next_epoch_protocol_pubkey_bytes: option::none(),
        next_epoch_network_pubkey_bytes: option::none(),
        next_epoch_consensus_pubkey_bytes: option::none(),
        next_epoch_mpc_data_bytes: option::none(),
        next_epoch_network_address: option::none(),
        next_epoch_p2p_address: option::none(),
        next_epoch_consensus_address: option::none(),
        previous_mpc_data_bytes: option::none(),
        metadata: extended_field::new(metadata, ctx),
    };
    validator_info.validate();
    validator_info
}

/// Sets the name of the validator.
public(package) fun set_name(self: &mut ValidatorInfo, name: String) {
    self.name = name;
    self.validate();
}

/// Sets the network address of the validator.
public(package) fun set_network_address(self: &mut ValidatorInfo, network_address: String) {
    self.network_address = network_address;
    self.validate();
}

/// Sets the metadata of the validator.
public(package) fun set_validator_metadata(self: &mut ValidatorInfo, metadata: ValidatorMetadata) {
    self.metadata.swap(metadata);
}

/// Sets network address for next epoch.
public(package) fun set_next_epoch_network_address(
    self: &mut ValidatorInfo,
    network_address: String,
) {
    self.next_epoch_network_address = option::some(network_address);
    self.validate();
}

/// Sets P2P address for next epoch.
public(package) fun set_next_epoch_p2p_address(self: &mut ValidatorInfo, p2p_address: String) {
    self.next_epoch_p2p_address = option::some(p2p_address);
    self.validate();
}

/// Sets consensus address for next epoch.
public(package) fun set_next_epoch_consensus_address(
    self: &mut ValidatorInfo,
    consensus_address: String,
) {
    self.next_epoch_consensus_address = option::some(consensus_address);
    self.validate();
}

/// Sets protocol public key for next epoch with proof of possession verification.
public(package) fun set_next_epoch_protocol_pubkey_bytes(
    self: &mut ValidatorInfo,
    protocol_pubkey_bytes: vector<u8>,
    proof_of_possession_bytes: vector<u8>,
    ctx: &TxContext,
) {
    assert!(
        verify_proof_of_possession(
            DEFAULT_EPOCH_ID,
            ctx.sender(),
            protocol_pubkey_bytes,
            proof_of_possession_bytes,
        ),
        EInvalidProofOfPossession,
    );
    self.next_epoch_protocol_pubkey_bytes = option::some(protocol_pubkey_bytes);
    self.validate();
}

/// Sets network public key for next epoch.
public(package) fun set_next_epoch_network_pubkey_bytes(
    self: &mut ValidatorInfo,
    network_pubkey_bytes: vector<u8>,
) {
    self.next_epoch_network_pubkey_bytes = option::some(network_pubkey_bytes);
    self.validate();
}

/// Sets consensus public key for next epoch.
public(package) fun set_next_epoch_consensus_pubkey_bytes(
    self: &mut ValidatorInfo,
    consensus_pubkey_bytes: vector<u8>,
) {
    self.next_epoch_consensus_pubkey_bytes = option::some(consensus_pubkey_bytes);
    self.validate();
}

/// Sets the MPC public data for the next epoch.
/// 
/// - If `next_epoch_mpc_data_bytes` is already set, 
///   this function returns its stored value and replaces it with the new value.
/// - If it is not set, but `previous_mpc_data_bytes` is set, 
///   this function returns the value from the previous field and replaces it with the new value.
/// - If neither is set, the new value is simply stored, and the function returns `None`.
/// 
/// The validator must drop the returned value if it is not `None`.
/// 
/// Using `Option` for the MPC data helps avoid latency issues due to large data sizes.
public(package) fun set_next_epoch_mpc_data_bytes(
    self: &mut ValidatorInfo,
    mpc_data: TableVec<vector<u8>>,
): Option<TableVec<vector<u8>>> {
    if (self.next_epoch_mpc_data_bytes.is_some()) {
        let next_epoch_mpc_data_bytes =
            self.next_epoch_mpc_data_bytes.extract();
        self.next_epoch_mpc_data_bytes.fill(mpc_data);
        self.validate();
        option::some(next_epoch_mpc_data_bytes)
    } else if (self.previous_mpc_data_bytes.is_some()) {
        let previous_mpc_data_bytes =
            self.previous_mpc_data_bytes.extract();
        self.next_epoch_mpc_data_bytes.fill(mpc_data);
        self.validate();
        option::some(previous_mpc_data_bytes)
    } else {
        self.next_epoch_mpc_data_bytes.fill(mpc_data);
        self.validate();
        option::none()
    }
}

/// Effectuate all staged next epoch metadata for this validator.
/// NOTE: this function SHOULD ONLY be called by validator_set when
/// advancing an epoch.
public(package) fun rotate_next_epoch_info(self: &mut ValidatorInfo) {
    if (self.next_epoch_network_address.is_some()) {
        self.network_address = self.next_epoch_network_address.extract();
        self.next_epoch_network_address = option::none();
    };

    if (self.next_epoch_p2p_address.is_some()) {
        self.p2p_address = self.next_epoch_p2p_address.extract();
        self.next_epoch_p2p_address = option::none();
    };

    if (self.next_epoch_consensus_address.is_some()) {
        self.consensus_address = self.next_epoch_consensus_address.extract();
        self.next_epoch_consensus_address = option::none();
    };

    if (self.next_epoch_protocol_pubkey_bytes.is_some()) {
        self.protocol_pubkey_bytes = self.next_epoch_protocol_pubkey_bytes.extract();
        self.next_epoch_protocol_pubkey_bytes = option::none();
        self.protocol_pubkey = g1_to_uncompressed_g1(&g1_from_bytes(&self.protocol_pubkey_bytes));
    };

    if (self.next_epoch_network_pubkey_bytes.is_some()) {
        self.network_pubkey_bytes = self.next_epoch_network_pubkey_bytes.extract();
        self.next_epoch_network_pubkey_bytes = option::none();
    };

    if (self.next_epoch_consensus_pubkey_bytes.is_some()) {
        self.consensus_pubkey_bytes = self.next_epoch_consensus_pubkey_bytes.extract();
        self.next_epoch_consensus_pubkey_bytes = option::none();
    };

    // `previous_mpc_data_bytes` cannot be set if `next_epoch_mpc_data_bytes` is already set.
    // This situation should never occur. If it does, it is considered an error,
    // so we ignore `next_epoch_mpc_data_bytes` and retain the current one.
    if (self.next_epoch_mpc_data_bytes.is_some() 
        && self.previous_mpc_data_bytes.is_none()
    ) {
        let next_epoch_mpc_data_bytes =
            self.next_epoch_mpc_data_bytes.extract();

        // At this point, we can assume that the current MPC public data bytes
        // are set set, so we can safely swap them.
        let previous_mpc_data_bytes = self.mpc_data_bytes
            .swap(
                next_epoch_mpc_data_bytes
            );

        // At this point, we can assume that the previous MPC public data bytes
        // are not set, so we can safely fill them.
        self.previous_mpc_data_bytes.fill(previous_mpc_data_bytes);
    };
}

public(package) fun proof_of_possession_intent_bytes(
    epoch: u64,
    sender_address: address,
    bls_key: vector<u8>,
): vector<u8> {
    let mut intent_bytes = PROOF_OF_POSSESSION_INTENT;
    let mut message = vector<u8>[];
    message.append(bls_key);
    message.append(sui::address::to_bytes(sender_address));
    intent_bytes.append(bcs::to_bytes(&message));
    intent_bytes.append(bcs::to_bytes(&epoch));
    intent_bytes
}

/// Verify the provided proof of possession using the contained public key and the provided
/// signature.
public(package) fun verify_proof_of_possession(
    epoch: u64,
    sender_address: address,
    bls_key: vector<u8>,
    pop_signature: vector<u8>,
): bool {
    let intent_bytes = proof_of_possession_intent_bytes(epoch, sender_address, bls_key);
    bls12381_min_pk_verify(
        &pop_signature,
        &bls_key,
        &intent_bytes,
    )
}

/// Aborts if validator info is invalid
public(package) fun validate(self: &ValidatorInfo) {
    // Verify name length.
    assert!(self.name.length() <= MAX_VALIDATOR_NAME_LENGTH, EInvalidNameLength);

    // Verify address length.
    assert!(
        self.network_address.length() <= MAX_VALIDATOR_TEXT_FIELD_LENGTH
                && self.p2p_address.length() <= MAX_VALIDATOR_TEXT_FIELD_LENGTH
                && self.consensus_address.length() <= MAX_VALIDATOR_TEXT_FIELD_LENGTH
                && self.name.length() <= MAX_VALIDATOR_TEXT_FIELD_LENGTH,
        EValidatorMetadataExceedingLengthLimit,
    );

    assert!(multiaddr::validate_tcp(&self.network_address), EMetadataInvalidNetworkAddress);
    if (self.next_epoch_network_address.is_some()) {
        assert!(
            self.next_epoch_network_address.borrow().length() <= MAX_VALIDATOR_TEXT_FIELD_LENGTH,
            EValidatorMetadataExceedingLengthLimit,
        );
        assert!(
            multiaddr::validate_tcp(self.next_epoch_network_address.borrow()),
            EMetadataInvalidNetworkAddress,
        );
    };

    assert!(multiaddr::validate_udp(&self.p2p_address), EMetadataInvalidP2pAddress);
    if (self.next_epoch_p2p_address.is_some()) {
        assert!(
            self.next_epoch_p2p_address.borrow().length() <= MAX_VALIDATOR_TEXT_FIELD_LENGTH,
            EValidatorMetadataExceedingLengthLimit,
        );
        assert!(
            multiaddr::validate_udp(self.next_epoch_p2p_address.borrow()),
            EMetadataInvalidP2pAddress,
        );
    };

    assert!(multiaddr::validate_udp(&self.consensus_address), EMetadataInvalidConsensusAddress);
    if (self.next_epoch_consensus_address.is_some()) {
        assert!(
            self.next_epoch_consensus_address.borrow().length() <= MAX_VALIDATOR_TEXT_FIELD_LENGTH,
            EValidatorMetadataExceedingLengthLimit,
        );
        assert!(
            multiaddr::validate_udp(self.next_epoch_consensus_address.borrow()),
            EMetadataInvalidConsensusAddress,
        );
    };

    assert!(self.network_pubkey_bytes.length() == ED25519_KEY_LEN, EMetadataInvalidNetworkPubkey);
    if (self.next_epoch_network_pubkey_bytes.is_some()) {
        assert!(
            self.next_epoch_network_pubkey_bytes.borrow().length() == ED25519_KEY_LEN,
            EMetadataInvalidNetworkPubkey,
        );
    };
    assert!(
        self.consensus_pubkey_bytes.length() == ED25519_KEY_LEN,
        EMetadataInvalidConsensusPubkey,
    );
    if (self.next_epoch_consensus_pubkey_bytes.is_some()) {
        assert!(
            self.next_epoch_consensus_pubkey_bytes.borrow().length() == ED25519_KEY_LEN,
            EMetadataInvalidConsensusPubkey,
        );
    };

    assert!(self.protocol_pubkey_bytes.length() == BLS_KEY_LEN, EMetadataInvalidProtocolPubkey);
    if (self.next_epoch_protocol_pubkey_bytes.is_some()) {
        assert!(
            self.next_epoch_protocol_pubkey_bytes.borrow().length() == BLS_KEY_LEN,
            EMetadataInvalidProtocolPubkey,
        );
    };

    // TODO(omersadika): add test for next epoch
}

/// Destroy the validator info.
public(package) fun destroy(self: ValidatorInfo) {
    let ValidatorInfo {
        metadata,
        mpc_data_bytes,
        next_epoch_mpc_data_bytes,
        previous_mpc_data_bytes,
        ..,
    } = self;
    metadata.destroy();
        mpc_data_bytes.destroy!(|mut mpc_data_bytes| {
        while (mpc_data_bytes.length() != 0) {
            mpc_data_bytes.pop_back();
        };
        mpc_data_bytes.destroy_empty();
    });

    next_epoch_mpc_data_bytes.destroy!(|mut next_epoch_mpc_data_bytes| {
        while (next_epoch_mpc_data_bytes.length() != 0) {
            next_epoch_mpc_data_bytes.pop_back();
        };
        next_epoch_mpc_data_bytes.destroy_empty();
    });

    previous_mpc_data_bytes.destroy!(|mut previous_mpc_data_bytes| {
        while (previous_mpc_data_bytes.length() != 0) {
            previous_mpc_data_bytes.pop_back();
        };
        previous_mpc_data_bytes.destroy_empty();
    });
}

public(package) fun is_duplicate(self: &ValidatorInfo, other: &ValidatorInfo): bool {
    self.name == other.name
    || self.network_address == other.network_address
    || self.p2p_address == other.p2p_address
    || self.protocol_pubkey_bytes == other.protocol_pubkey_bytes
    || self.network_pubkey_bytes == other.network_pubkey_bytes
    || self.network_pubkey_bytes == other.consensus_pubkey_bytes
    || self.consensus_pubkey_bytes == other.consensus_pubkey_bytes
    || self.consensus_pubkey_bytes == other.network_pubkey_bytes
    // All next epoch parameters.
    || is_equal_some(&self.next_epoch_network_address, &other.next_epoch_network_address)
    || is_equal_some(&self.next_epoch_p2p_address, &other.next_epoch_p2p_address)
    || is_equal_some(&self.next_epoch_protocol_pubkey_bytes, &other.next_epoch_protocol_pubkey_bytes)
    || is_equal_some(&self.next_epoch_network_pubkey_bytes, &other.next_epoch_network_pubkey_bytes)
    || is_equal_some(&self.next_epoch_network_pubkey_bytes, &other.next_epoch_consensus_pubkey_bytes)
    || is_equal_some(&self.next_epoch_consensus_pubkey_bytes, &other.next_epoch_consensus_pubkey_bytes)
    || is_equal_some(&self.next_epoch_consensus_pubkey_bytes, &other.next_epoch_network_pubkey_bytes)
    // My next epoch parameters with other current epoch parameters.
    || is_equal_some_and_value(&self.next_epoch_network_address, &other.network_address)
    || is_equal_some_and_value(&self.next_epoch_p2p_address, &other.p2p_address)
    || is_equal_some_and_value(&self.next_epoch_protocol_pubkey_bytes, &other.protocol_pubkey_bytes)
    || is_equal_some_and_value(&self.next_epoch_network_pubkey_bytes, &other.network_pubkey_bytes)
    || is_equal_some_and_value(&self.next_epoch_network_pubkey_bytes, &other.consensus_pubkey_bytes)
    || is_equal_some_and_value(&self.next_epoch_consensus_pubkey_bytes, &other.consensus_pubkey_bytes)
    || is_equal_some_and_value(&self.next_epoch_consensus_pubkey_bytes, &other.network_pubkey_bytes)
    // Other next epoch parameters with my current epoch parameters.
    || is_equal_some_and_value(&other.next_epoch_network_address, &self.network_address)
    || is_equal_some_and_value(&other.next_epoch_p2p_address, &self.p2p_address)
    || is_equal_some_and_value(&other.next_epoch_protocol_pubkey_bytes, &self.protocol_pubkey_bytes)
    || is_equal_some_and_value(&other.next_epoch_network_pubkey_bytes, &self.network_pubkey_bytes)
    || is_equal_some_and_value(&other.next_epoch_network_pubkey_bytes, &self.consensus_pubkey_bytes)
    || is_equal_some_and_value(&other.next_epoch_consensus_pubkey_bytes, &self.consensus_pubkey_bytes)
    || is_equal_some_and_value(&other.next_epoch_consensus_pubkey_bytes, &self.network_pubkey_bytes)
}

// === View Functions ===

/// Returns the validator metadata
public(package) fun metadata(self: &ValidatorInfo): ValidatorMetadata {
    *self.metadata.borrow()
}

/// Returns the validator ID
public fun validator_id(self: &ValidatorInfo): ID {
    self.validator_id
}

/// Returns the network address
public fun network_address(self: &ValidatorInfo): &String {
    &self.network_address
}

/// Returns the P2P address
public fun p2p_address(self: &ValidatorInfo): &String {
    &self.p2p_address
}

/// Returns the consensus address
public fun consensus_address(self: &ValidatorInfo): &String {
    &self.consensus_address
}

/// Returns the protocol public key bytes
public fun protocol_pubkey_bytes(self: &ValidatorInfo): &vector<u8> {
    &self.protocol_pubkey_bytes
}

/// Returns the protocol public key element
public fun protocol_pubkey(self: &ValidatorInfo): &Element<UncompressedG1> {
    &self.protocol_pubkey
}

/// Returns the network public key bytes
public fun network_pubkey_bytes(self: &ValidatorInfo): &vector<u8> {
    &self.network_pubkey_bytes
}

/// Returns the consensus public key bytes
public fun consensus_pubkey_bytes(self: &ValidatorInfo): &vector<u8> {
    &self.consensus_pubkey_bytes
}

/// Returns the MPC public data bytes
public fun mpc_data_bytes(self: &ValidatorInfo): &Option<TableVec<vector<u8>>> {
    &self.mpc_data_bytes
}

/// Returns the next epoch network address
public fun next_epoch_network_address(self: &ValidatorInfo): &Option<String> {
    &self.next_epoch_network_address
}

/// Returns the next epoch P2P address
public fun next_epoch_p2p_address(self: &ValidatorInfo): &Option<String> {
    &self.next_epoch_p2p_address
}

/// Returns the next epoch consensus address
public fun next_epoch_consensus_address(self: &ValidatorInfo): &Option<String> {
    &self.next_epoch_consensus_address
}

/// Returns the next epoch protocol public key bytes
public fun next_epoch_protocol_pubkey_bytes(self: &ValidatorInfo): &Option<vector<u8>> {
    &self.next_epoch_protocol_pubkey_bytes
}

/// Returns the next epoch network public key bytes
public fun next_epoch_network_pubkey_bytes(self: &ValidatorInfo): &Option<vector<u8>> {
    &self.next_epoch_network_pubkey_bytes
}

/// Returns the next epoch consensus public key bytes
public fun next_epoch_consensus_pubkey_bytes(self: &ValidatorInfo): &Option<vector<u8>> {
    &self.next_epoch_consensus_pubkey_bytes
}

/// Returns the next epoch MPC public data
public fun next_epoch_mpc_data_bytes(
    self: &ValidatorInfo,
): &Option<TableVec<vector<u8>>> {
    &self.next_epoch_mpc_data_bytes
}


/// Returns the previous MPC public data
public fun previous_mpc_data_bytes(
    self: &ValidatorInfo,
): &Option<TableVec<vector<u8>>> {
    &self.previous_mpc_data_bytes
}

// === Private Functions ===

/// Checks if an Option contains a value equal to the provided value.
fun is_equal_some_and_value<T>(a: &Option<T>, b: &T): bool {
    if (a.is_none()) {
        false
    } else {
        a.borrow() == b
    }
}

/// Checks if two Options both contain values and those values are equal.
fun is_equal_some<T>(a: &Option<T>, b: &Option<T>): bool {
    if (a.is_none() || b.is_none()) {
        false
    } else {
        a.borrow() == b.borrow()
    }
}

// === Test Functions ===

#[test_only]
use sui::table_vec;

#[test_only]
use ika_system::validator_metadata;

#[test_only]
/// Create a validator info with dummy name & address for testing purposes
public fun new_for_testing(public_key: vector<u8>): ValidatorInfo {
    let ctx = &mut tx_context::dummy();
    let validator_id = ctx.fresh_object_address().to_id();
    let protocol_pubkey = g1_to_uncompressed_g1(&g1_from_bytes(&public_key));
    let mpc_data_bytes = option::some(table_vec::empty<vector<u8>>(ctx));

    ValidatorInfo {
        validator_id,
        name: b"node".to_string(),
        network_address: b"127.0.0.1".to_string(),
        p2p_address: b"127.0.0.1".to_string(),
        consensus_address: b"127.0.0.1".to_string(),
        protocol_pubkey_bytes: public_key,
        protocol_pubkey,
        network_pubkey_bytes: vector[],
        consensus_pubkey_bytes: vector[],
        mpc_data_bytes: mpc_data_bytes,
        next_epoch_protocol_pubkey_bytes: option::none(),
        next_epoch_network_pubkey_bytes: option::none(),
        next_epoch_consensus_pubkey_bytes: option::none(),
        next_epoch_mpc_data_bytes: option::none(),
        next_epoch_network_address: option::none(),
        next_epoch_p2p_address: option::none(),
        next_epoch_consensus_address: option::none(),
        previous_mpc_data_bytes: option::none(),
        metadata: extended_field::new(validator_metadata::default(), ctx),
    }
}
