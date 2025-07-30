// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_common::bls_committee;

use sui::bls12381::{Self, G1, UncompressedG1};
use sui::event;
use sui::group_ops::{Self, Element};

// === Constants ===

const BLS_SIGNATURE_LEN: u64 = 96;

// === Errors ===

/// The signers bitmap is invalid.
const EInvalidBitmap: u64 = 0;
/// The length of the provided bls signature is incorrect.
const EInvalidSignatureLength: u64 = 1;
/// Invalid certificate signature.
const EInvalidSignature: u64 = 2;
/// Not enough stake of signers for the bls signature.
const ENotEnoughStake: u64 = 3;

// === Structs ===

/// Represents a single member of the BLS committee with their validator ID and protocol public key
public struct BlsCommitteeMember has copy, drop, store {
    validator_id: ID,
    protocol_pubkey: Element<UncompressedG1>,
}

/// Represents the current committee in the system with aggregated public keys and voting thresholds
public struct BlsCommittee has copy, drop, store {
    members: vector<BlsCommitteeMember>,
    /// The aggregation of public keys for all members of the committee
    aggregated_protocol_pubkey: Element<G1>,
    /// Minimum signatures required for quorum (2n/3 + 1)
    quorum_threshold: u64,
    /// Minimum signatures required for validity (n/3 + 1)
    validity_threshold: u64,
}

// === Events ===

/// Event emitted after verifying quorum of signature
public struct CommitteeQuorumVerifiedEvent has copy, drop {
    epoch: u64,
    signer_count: u64,
}

// === Public Functions ===

/// Returns the total voting power (number of members in the committee)
public fun total_voting_power(self: &BlsCommittee): u64 {
    self.members.length()
}

/// Returns the quorum threshold (2n/3 + 1) for the committee
public fun quorum_threshold(self: &BlsCommittee): u64 {
    self.quorum_threshold
}

/// Returns the validity threshold (n/3 + 1) for the committee
public fun validity_threshold(self: &BlsCommittee): u64 {
    self.validity_threshold
}

/// Creates a new BLS committee member with the given validator ID and protocol public key
public fun new_bls_committee_member(
    validator_id: ID,
    protocol_pubkey: Element<UncompressedG1>,
): BlsCommitteeMember {
    BlsCommitteeMember {
        validator_id,
        protocol_pubkey,
    }
}

/// Returns the validator ID of the committee member
public fun validator_id(member: &BlsCommitteeMember): ID {
    member.validator_id
}

/// Creates a new BLS committee from a vector of members
/// Each member has equal voting power of 1, total voting power equals number of members
/// Calculates quorum threshold (2n/3 + 1) and validity threshold (n/3 + 1)
public fun new_bls_committee(members: vector<BlsCommitteeMember>): BlsCommittee {
    // Compute the total aggregated key, e.g. the sum of all public keys in the committee
    let aggregated_protocol_pubkey = bls12381::uncompressed_g1_to_g1(
        &bls12381::uncompressed_g1_sum(
            &members.map!(|member| member.protocol_pubkey),
        ),
    );

    let quorum_threshold = (2 * (members.length() / 3)) + 1;
    let validity_threshold = (members.length() / 3) + 1;

    BlsCommittee {
        members,
        aggregated_protocol_pubkey,
        quorum_threshold,
        validity_threshold,
    }
}

/// Creates an empty committee with zero thresholds
/// Only relevant for initialization phase
public fun empty(): BlsCommittee {
    BlsCommittee {
        members: vector[],
        aggregated_protocol_pubkey: bls12381::g1_identity(),
        quorum_threshold: 0,
        validity_threshold: 0,
    }
}

/// Returns an immutable reference to committee members
public fun members(self: &BlsCommittee): &vector<BlsCommitteeMember> {
    &self.members
}

/// Returns a vector of all validator IDs in the committee
public fun validator_ids(self: &BlsCommittee): vector<ID> {
    self.members().map_ref!(|m| m.validator_id())
}

/// Checks if the committee contains a specific validator ID
public fun contains(self: &BlsCommittee, validator_id: &ID): bool {
    self.members().any!(|m| m.validator_id() == validator_id)
}

/// Verifies an aggregate BLS signature is a certificate in the epoch
/// The `signers_bitmap` represents which validators signed the certificate
/// Returns successfully if signature is valid and meets quorum threshold, otherwise aborts
public fun verify_certificate(
    self: &BlsCommittee,
    epoch: u64,
    signature: &vector<u8>,
    signers_bitmap: &vector<u8>,
    intent_bytes: &vector<u8>,
) {
    assert!(signature.length() == BLS_SIGNATURE_LEN, EInvalidSignatureLength);
    let members = &self.members;

    // Count non-signers instead of summing their voting powers
    let mut non_signer_count = 0;
    let mut non_signer_public_keys: vector<Element<UncompressedG1>> = vector::empty();
    let mut offset: u64 = 0;
    let n_members = members.length();
    let max_bitmap_len_bytes = n_members.divide_and_round_up(8);

    // The signers bitmap must not be longer than necessary to hold all members
    // It may be shorter, in which case the excluded members are treated as non-signers
    assert!(signers_bitmap.length() == max_bitmap_len_bytes, EInvalidBitmap);

    // Iterate over the signers bitmap and check if each member is a signer
    max_bitmap_len_bytes.do!(|i| {
        // Get the current byte or 0 if we've reached the end of the bitmap
        let byte = if (i < signers_bitmap.length()) {
            signers_bitmap[i]
        } else {
            0
        };

        (8u8).do!(|i| {
            let index = offset + (i as u64);
            let is_signer = (byte >> i) & 1 == 1;

            // If the index is out of bounds, the bit must be 0 to ensure
            // uniqueness of the signers_bitmap
            if (index >= n_members) {
                assert!(!is_signer, EInvalidBitmap);
                return
            };

            // There will be fewer non-signers than signers, so we handle
            // non-signers here
            if (!is_signer) {
                let member = &members[index];
                non_signer_count = non_signer_count + 1;
                non_signer_public_keys.push_back(member.protocol_pubkey);
            };
        });
        offset = offset + 8;
    });

    // Compute the aggregate voting power as the number of signers
    let signer_count = n_members - non_signer_count;

    assert!(is_quorum_threshold(self, signer_count), ENotEnoughStake);

    // Compute the aggregate public key as the difference between the total
    // aggregated key and the sum of the non-signer public keys
    let aggregate_key = bls12381::g1_sub(
        &self.aggregated_protocol_pubkey,
        &bls12381::uncompressed_g1_to_g1(
            &bls12381::uncompressed_g1_sum(&non_signer_public_keys),
        ),
    );

    // Verify the signature
    let pub_key_bytes = group_ops::bytes(&aggregate_key);
    assert!(
        bls12381::bls12381_min_pk_verify(
            signature,
            pub_key_bytes,
            intent_bytes,
        ),
        EInvalidSignature,
    );

    event::emit(CommitteeQuorumVerifiedEvent {
        epoch,
        signer_count,
    });
}

/// Returns true if the voting power meets or exceeds the quorum threshold
public fun is_quorum_threshold(self: &BlsCommittee, signer_count: u64): bool {
    signer_count >= self.quorum_threshold
}

/// Returns true if the voting power meets or exceeds the validity threshold
public fun is_validity_threshold(self: &BlsCommittee, signer_count: u64): bool {
    signer_count >= self.validity_threshold
}
