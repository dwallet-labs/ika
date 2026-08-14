// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::committee::EpochId;
use crate::crypto::keccak256_digest;
use crate::message::DWalletCheckpointMessageKind;
use crate::messages_system_checkpoints::SystemCheckpointMessageKind;
use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, DWalletHashScheme, DWalletSignatureAlgorithm};
use mpc::WeightedThresholdAccessStructure;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::hash::Hash;

/// Identifies which counterparty chain a session belongs to.
/// Events come from this chain, checkpoint results go back to it.
#[derive(
    Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, strum::Display,
)]
pub enum CounterpartyChainKind {
    Sui,
}

// === CounterpartyChain ===

/// Encapsulates chain-specific configuration for checkpoint submission.
pub trait CounterpartyChain: Clone + Debug + Send + Sync + 'static {
    /// Which variant of `CounterpartyChainKind` this implementor corresponds to.
    const KIND: CounterpartyChainKind;

    /// The curve used for NOA MPC signing on this chain.
    const CURVE: DWalletCurve;

    /// The signature algorithm for NOA signing on this chain.
    const SIGNATURE_ALGORITHM: DWalletSignatureAlgorithm;

    /// The hash scheme for NOA signing on this chain.
    const HASH_SCHEME: DWalletHashScheme;

    /// Chain context needed at runtime to build signable transaction bytes.
    type Context: Clone + Debug + Send + Sync + 'static;

    /// A validator's local observation of chain state, submitted through consensus.
    type Observation: Clone
        + Debug
        + Serialize
        + DeserializeOwned
        + PartialEq
        + Eq
        + Hash
        + Send
        + Sync
        + 'static;

    /// Compute chain context from all validators' latest observations.
    ///
    /// Uses the `access_structure` to verify that agreeing parties form an authorized
    /// subset (weighted 2f+1 threshold), not just a majority of respondents.
    /// Returns `Some(context)` when agreement is reached,
    /// `None` to keep `current_context` unchanged.
    fn context_from_observations(
        observations: &HashMap<u16, Self::Observation>,
        current_context: Option<&Self::Context>,
        access_structure: &WeightedThresholdAccessStructure,
    ) -> Option<Self::Context>;
}

/// Sui counterparty chain — carries Sui object IDs, module info, etc.
#[derive(Clone, Debug)]
pub struct SuiCounterpartyChain;

/// Runtime context for building Sui transactions.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SuiChainContext {
    pub reference_gas_price: u64,
    pub sui_epoch: u64,
}

/// A validator's locally observed Sui chain state for context agreement.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SuiChainObservation {
    pub reference_gas_price: u64,
    pub sui_epoch: u64,
}

impl CounterpartyChain for SuiCounterpartyChain {
    const KIND: CounterpartyChainKind = CounterpartyChainKind::Sui;
    const CURVE: DWalletCurve = DWalletCurve::Curve25519;
    const SIGNATURE_ALGORITHM: DWalletSignatureAlgorithm = DWalletSignatureAlgorithm::EdDSA;
    const HASH_SCHEME: DWalletHashScheme = DWalletHashScheme::SHA512;
    type Context = SuiChainContext;
    type Observation = SuiChainObservation;

    fn context_from_observations(
        observations: &HashMap<u16, SuiChainObservation>,
        current_context: Option<&SuiChainContext>,
        access_structure: &WeightedThresholdAccessStructure,
    ) -> Option<SuiChainContext> {
        if observations.is_empty() {
            return None;
        }

        // Group party IDs by their observation value.
        let mut votes: HashMap<&SuiChainObservation, HashSet<u16>> = HashMap::new();
        for (&party_id, observation) in observations {
            votes.entry(observation).or_default().insert(party_id);
        }

        let min_epoch = current_context.map(|c| c.sui_epoch).unwrap_or(0);

        // Collect all observations that reach quorum and don't regress.
        let mut best: Option<SuiChainContext> = None;
        for (observation, parties) in &votes {
            if observation.sui_epoch < min_epoch {
                continue;
            }
            if access_structure.is_authorized_subset(parties).is_ok() {
                let candidate = SuiChainContext {
                    reference_gas_price: observation.reference_gas_price,
                    sui_epoch: observation.sui_epoch,
                };
                best = Some(match best {
                    Some(prev) if prev.sui_epoch >= candidate.sui_epoch => prev,
                    _ => candidate,
                });
            }
        }

        best
    }
}

// === NOACheckpointKind ===

/// Enum identifying a checkpoint kind. Used in `NOACheckpointTxRef` for type-safe,
/// serialization-stable identification instead of raw strings.
#[derive(
    Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, strum::Display,
)]
pub enum NOACheckpointKindName {
    SuiDWallet,
    SuiSystem,
}

impl NOACheckpointKindName {
    /// The signature algorithm a demand for this checkpoint kind must use.
    ///
    /// Read from the same counterparty-chain constant the producer reads, so
    /// the two cannot drift: the handler builds a request with
    /// `<K::Counterparty as CounterpartyChain>::SIGNATURE_ALGORITHM` and a
    /// demand id carrying `K::KIND_NAME`, and this maps the second back to the
    /// first. The match is exhaustive, so a new checkpoint kind cannot be
    /// added without deciding its answer here.
    ///
    /// This is what lets a consumer DERIVE the algorithm from the demand
    /// identity instead of trusting the value an announcement carries
    /// alongside it — see `NOAPresignDemandId::expected_signature_algorithm`.
    pub fn signature_algorithm(self) -> DWalletSignatureAlgorithm {
        match self {
            Self::SuiDWallet => {
                <<SuiDWalletCheckpoint as NOACheckpointKind>::Counterparty as CounterpartyChain>::SIGNATURE_ALGORITHM
            }
            Self::SuiSystem => {
                <<SuiSystemCheckpoint as NOACheckpointKind>::Counterparty as CounterpartyChain>::SIGNATURE_ALGORITHM
            }
        }
    }
}

/// Defines a kind of NOA-signed checkpoint (e.g., DWallet or System).
pub trait NOACheckpointKind: Clone + Debug + Send + Sync + 'static {
    /// The type of individual messages within a checkpoint.
    type MessageKind: Clone
        + Debug
        + Serialize
        + DeserializeOwned
        + PartialEq
        + Eq
        + Send
        + Sync
        + 'static;

    /// The counterparty chain this checkpoint targets.
    type Counterparty: CounterpartyChain;

    /// Typed identifier for this checkpoint kind, used in `NOACheckpointTxRef`.
    const KIND_NAME: NOACheckpointKindName;

    /// Split checkpoint messages into per-tx groups.
    /// Pure function of messages + size limits.
    fn split_messages(messages: &[Self::MessageKind]) -> Vec<Vec<Self::MessageKind>>;

    /// Build tx bytes for a single message group. Context-dependent.
    /// `retry_round` acts as a nonce for uniqueness across retries.
    fn build_tx_bytes(
        epoch: EpochId,
        sequence_number: u64,
        tx_index: u32,
        messages: &[Self::MessageKind],
        context: &<Self::Counterparty as CounterpartyChain>::Context,
        noa_public_key: &[u8],
        retry_round: u32,
    ) -> Vec<u8>;
}

// === Marker types implementing NOACheckpointKind ===

/// Sui DWallet checkpoint kind — carries MPC session results.
#[derive(Clone, Debug)]
pub struct SuiDWalletCheckpoint;

/// Sui System checkpoint kind — carries governance/config updates.
#[derive(Clone, Debug)]
pub struct SuiSystemCheckpoint;

impl NOACheckpointKind for SuiDWalletCheckpoint {
    type MessageKind = DWalletCheckpointMessageKind;
    type Counterparty = SuiCounterpartyChain;

    const KIND_NAME: NOACheckpointKindName = NOACheckpointKindName::SuiDWallet;

    fn split_messages(messages: &[Self::MessageKind]) -> Vec<Vec<Self::MessageKind>> {
        // Single tx for now; future: split by 128KB limit.
        vec![messages.to_vec()]
    }

    fn build_tx_bytes(
        epoch: EpochId,
        sequence_number: u64,
        tx_index: u32,
        messages: &[Self::MessageKind],
        _context: &SuiChainContext,
        _noa_public_key: &[u8],
        retry_round: u32,
    ) -> Vec<u8> {
        // TODO: Build actual Sui TransactionData bytes using context + NOA public key.
        // Currently BCS-serializes the components as a placeholder.
        bcs::to_bytes(&(epoch, sequence_number, tx_index, messages, retry_round))
            .expect("BCS serialization of NOA DWallet tx bytes should not fail")
    }
}

impl NOACheckpointKind for SuiSystemCheckpoint {
    type MessageKind = SystemCheckpointMessageKind;
    type Counterparty = SuiCounterpartyChain;

    const KIND_NAME: NOACheckpointKindName = NOACheckpointKindName::SuiSystem;

    fn split_messages(messages: &[Self::MessageKind]) -> Vec<Vec<Self::MessageKind>> {
        // Single tx for now; future: split by 128KB limit.
        vec![messages.to_vec()]
    }

    fn build_tx_bytes(
        epoch: EpochId,
        sequence_number: u64,
        tx_index: u32,
        messages: &[Self::MessageKind],
        _context: &SuiChainContext,
        _noa_public_key: &[u8],
        retry_round: u32,
    ) -> Vec<u8> {
        // TODO: Build actual Sui TransactionData bytes using context + NOA public key.
        // Currently BCS-serializes the components as a placeholder.
        bcs::to_bytes(&(epoch, sequence_number, tx_index, messages, retry_round))
            .expect("BCS serialization of NOA System tx bytes should not fail")
    }
}

// === NOA Checkpoint Message ===

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NOACheckpointMessage<K: NOACheckpointKind> {
    pub epoch: EpochId,
    pub sequence_number: u64,
    pub messages: Vec<K::MessageKind>,
}

// === Certified NOA Checkpoint (NOA-signed) ===

/// A checkpoint certified by NOA MPC signature (not BLS).
/// A single checkpoint may span multiple Sui transactions, so we store
/// one signature and one signed-bytes entry per transaction, in order.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertifiedNOACheckpointMessage<K: NOACheckpointKind> {
    pub checkpoint: NOACheckpointMessage<K>,
    /// One signature per transaction (ordered, matching `signed_bytes`).
    pub signatures: Vec<Vec<u8>>,
    /// The transaction bytes that were signed (ordered, output of `signable_bytes`).
    pub signed_bytes: Vec<Vec<u8>>,
    pub curve: DWalletCurve,
    pub signature_algorithm: DWalletSignatureAlgorithm,
}

// === NOA Checkpoint Finalization Types ===

/// Status of an individual NOA checkpoint's on-chain transaction.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum NOACheckpointTxStatus {
    /// Signed and submitted, awaiting on-chain confirmation.
    Pending,
    /// Chain submission failed; will be re-attempted on next poll.
    SubmitFailed,
    /// On-chain execution confirmed by this validator; consensus vote submitted.
    ConfirmedLocally,
    /// 2f+1 validators confirmed on-chain execution.
    Finalized,
    /// 2f+1 failure votes received; awaiting MPC re-signing.
    RetryPending,
}

/// Identifies a specific NOA checkpoint transaction for finalization voting.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NOACheckpointTxRef {
    /// Which checkpoint kind.
    pub kind_name: NOACheckpointKindName,
    /// Checkpoint sequence number within the epoch.
    pub sequence_number: u64,
    /// Index within the checkpoint's transaction set (for multi-tx checkpoints).
    pub tx_index: u32,
    /// The epoch this checkpoint belongs to.
    pub epoch: EpochId,
}

/// Network-uniform identity of a single NOA sign demand, used to assign it a
/// presign deterministically in consensus order. Two arms cover all three
/// demand sources: checkpoint signs (and their per-tx retries) carry the
/// checkpoint tx coordinate + a retry round (0 for the first attempt); gRPC
/// attestation signs carry their gRPC session identifier.
///
/// Every arm COMMITS to the signature algorithm the demand will use — the
/// checkpoint arm implicitly (its `kind_name` determines it), the attestation
/// arm explicitly. That is what lets a consumer derive the algorithm rather
/// than trust the announcement carrying it; see
/// [`Self::expected_signature_algorithm`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NOAPresignDemandId {
    Checkpoint {
        tx_ref: NOACheckpointTxRef,
        retry_round: u32,
    },
    GrpcAttestation {
        /// The gRPC session identifier the attestation belongs to.
        session_identifier: [u8; 32],
        /// The algorithm this demand's presign must be drawn for. Part of the
        /// IDENTITY, not payload: a demand announced with a different
        /// algorithm is a DIFFERENT demand — a distinct digest that no honest
        /// consumer ever looks up — rather than a competing answer for this
        /// one. The session identifier alone could not carry that, so an
        /// announcer could otherwise pick the algorithm (and with it the
        /// presign pool) for any attestation whose identifier it can predict.
        signature_algorithm: DWalletSignatureAlgorithm,
    },
}

impl NOAPresignDemandId {
    /// Deterministic digest of the demand identity. Used network-wide as the
    /// consensus dedup key and the per-epoch presign-assignment table key, so
    /// every validator maps the same demand to the same presign.
    pub fn digest(&self) -> [u8; 32] {
        keccak256_digest(&bcs::to_bytes(self).expect("NOAPresignDemandId is BCS-serializable"))
    }

    /// The signature algorithm this demand must use, derived from its
    /// IDENTITY.
    ///
    /// The consensus dedup key for a presign-demand announcement is the digest
    /// of this identity alone — deliberately, so several validators announcing
    /// the same demand collapse into one transaction. The consequence is that
    /// the first announcement sequenced for a demand supplies the payload
    /// fields the drain then uses for everyone. Deriving this one from the
    /// identity removes the announcer's say in the matter entirely, which is
    /// stronger than validating what it sent: there is no divergent value left
    /// to prefer, and no honest demand can be dropped for carrying one.
    ///
    /// Total by construction — every arm commits to its algorithm.
    pub fn expected_signature_algorithm(&self) -> DWalletSignatureAlgorithm {
        match self {
            Self::Checkpoint { tx_ref, .. } => tx_ref.kind_name.signature_algorithm(),
            Self::GrpcAttestation {
                signature_algorithm,
                ..
            } => *signature_algorithm,
        }
    }
}

/// A single validator's observation of a checkpoint tx's on-chain status.
/// Sent via `ConsensusNOAObservation` consensus messages for quorum resolution
/// in the same consensus round as chain context agreement.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum NOACheckpointTxObservation {
    Finalized(NOACheckpointTxRef),
    Failed(NOACheckpointTxRef, u32), // (tx_ref, retry_round)
}

/// Consensus quorum resolution for an NOA checkpoint transaction.
#[derive(Clone, Debug)]
pub enum NOACheckpointResolution<C: CounterpartyChain> {
    Finalized(NOACheckpointTxRef),
    RetryWithContext {
        tx_ref: NOACheckpointTxRef,
        context: C::Context,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::DWalletCheckpointMessageKind;
    use crate::messages_system_checkpoints::SystemCheckpointMessageKind;

    /// The algorithm a consumer DERIVES from a demand identity must equal the
    /// one the producer puts in the request. The producer reads
    /// `<K::Counterparty>::SIGNATURE_ALGORITHM` and stamps the demand id with
    /// `K::KIND_NAME`; the consumer maps that name back. If the two ever
    /// disagreed, deriving would hand honest demands the wrong presign pool —
    /// the failure would look like a stuck NOA sign, not a wrong constant.
    ///
    /// Written generically over the kind so it pins the LINK between the two
    /// constants rather than restating either.
    fn assert_derived_matches_producer<K: NOACheckpointKind>() {
        assert_eq!(
            K::KIND_NAME.signature_algorithm(),
            <K::Counterparty as CounterpartyChain>::SIGNATURE_ALGORITHM,
            "{} derives an algorithm its producer does not use",
            K::KIND_NAME,
        );
    }

    /// EVERY checkpoint kind belongs in this list. A new kind is forced to add
    /// a `signature_algorithm` match arm by the compiler, but nothing forces it
    /// to be asserted here — so add it when you add the arm.
    #[test]
    fn derived_signature_algorithm_matches_every_producer() {
        assert_derived_matches_producer::<SuiDWalletCheckpoint>();
        assert_derived_matches_producer::<SuiSystemCheckpoint>();
    }

    /// EVERY demand's identity determines its algorithm — the checkpoint arm
    /// through its `kind_name`, the attestation arm by carrying it — so the
    /// drain always derives and never consults the announced value.
    #[test]
    fn every_demand_identity_determines_its_own_algorithm() {
        let checkpoint = NOAPresignDemandId::Checkpoint {
            tx_ref: NOACheckpointTxRef {
                kind_name: NOACheckpointKindName::SuiDWallet,
                sequence_number: 7,
                tx_index: 0,
                epoch: 3,
            },
            retry_round: 0,
        };
        assert_eq!(
            checkpoint.expected_signature_algorithm(),
            NOACheckpointKindName::SuiDWallet.signature_algorithm(),
        );
        assert_eq!(
            NOAPresignDemandId::GrpcAttestation {
                session_identifier: [1u8; 32],
                signature_algorithm: DWalletSignatureAlgorithm::ECDSASecp256r1,
            }
            .expected_signature_algorithm(),
            DWalletSignatureAlgorithm::ECDSASecp256r1,
        );
    }

    /// The algorithm is part of the attestation demand's IDENTITY: announcing
    /// the same session with a different algorithm yields a DIFFERENT digest,
    /// so it cannot compete with the honest demand for the same consensus
    /// dedup key — it is a demand no honest consumer ever looks up. This is
    /// what closes the substitution hole at the source rather than at the
    /// consumer.
    #[test]
    fn a_different_algorithm_is_a_different_attestation_demand() {
        let session_identifier = [9u8; 32];
        let honest = NOAPresignDemandId::GrpcAttestation {
            session_identifier,
            signature_algorithm: DWalletSignatureAlgorithm::ECDSASecp256k1,
        };
        let substituted = NOAPresignDemandId::GrpcAttestation {
            session_identifier,
            signature_algorithm: DWalletSignatureAlgorithm::ECDSASecp256r1,
        };
        assert_ne!(
            honest.digest(),
            substituted.digest(),
            "the algorithm must be part of the demand identity, not payload \
             beside it"
        );
    }

    /// The retry round is not part of what fixes the algorithm: a per-tx retry
    /// is a distinct demand (distinct id, distinct presign) for the same
    /// checkpoint tx, and must still derive the same algorithm.
    #[test]
    fn a_retry_derives_the_same_algorithm_as_its_first_attempt() {
        let tx_ref = NOACheckpointTxRef {
            kind_name: NOACheckpointKindName::SuiSystem,
            sequence_number: 11,
            tx_index: 2,
            epoch: 4,
        };
        let first = NOAPresignDemandId::Checkpoint {
            tx_ref: tx_ref.clone(),
            retry_round: 0,
        };
        let retry = NOAPresignDemandId::Checkpoint {
            tx_ref,
            retry_round: 3,
        };
        assert_ne!(
            first.digest(),
            retry.digest(),
            "a retry is a distinct demand"
        );
        assert_eq!(
            first.expected_signature_algorithm(),
            retry.expected_signature_algorithm(),
        );
    }

    #[test]
    fn test_dwallet_build_tx_bytes_roundtrip() {
        let ctx = SuiChainContext {
            reference_gas_price: 1000,
            sui_epoch: 1,
        };
        let bytes = SuiDWalletCheckpoint::build_tx_bytes(1, 0, 0, &[], &ctx, &[], 0);
        assert!(!bytes.is_empty());

        let decoded: (u64, u64, u32, Vec<DWalletCheckpointMessageKind>, u32) =
            bcs::from_bytes(&bytes).expect("BCS round-trip should succeed");
        assert_eq!(decoded, (1, 0, 0, vec![], 0));
    }

    #[test]
    fn test_system_build_tx_bytes_roundtrip() {
        let ctx = SuiChainContext {
            reference_gas_price: 1000,
            sui_epoch: 1,
        };
        let bytes = SuiSystemCheckpoint::build_tx_bytes(2, 5, 1, &[], &ctx, &[], 3);
        assert!(!bytes.is_empty());

        let decoded: (u64, u64, u32, Vec<SystemCheckpointMessageKind>, u32) =
            bcs::from_bytes(&bytes).expect("BCS round-trip should succeed");
        assert_eq!(decoded, (2, 5, 1, vec![], 3));
    }

    #[test]
    fn test_build_tx_bytes_retry_produces_different_output() {
        let ctx = SuiChainContext {
            reference_gas_price: 1000,
            sui_epoch: 1,
        };
        let first = SuiDWalletCheckpoint::build_tx_bytes(1, 0, 0, &[], &ctx, &[], 0);
        let retry = SuiDWalletCheckpoint::build_tx_bytes(1, 0, 0, &[], &ctx, &[], 1);
        assert_ne!(
            first, retry,
            "different retry_round should produce different bytes"
        );
    }
}
