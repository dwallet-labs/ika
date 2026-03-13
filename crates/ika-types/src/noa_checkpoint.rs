// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::committee::EpochId;
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
#[strum(serialize_all = "lowercase")]
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
        _current_context: Option<&SuiChainContext>,
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

        // Check if any observation value is supported by an authorized subset.
        for (observation, parties) in &votes {
            if access_structure.is_authorized_subset(parties).is_ok() {
                return Some(SuiChainContext {
                    reference_gas_price: observation.reference_gas_price,
                    sui_epoch: observation.sui_epoch,
                });
            }
        }

        // No authorized subset agrees — keep current context unchanged.
        None
    }
}

// === NOACheckpointKind ===

/// Enum identifying a checkpoint kind. Used in `NOACheckpointTxRef` for type-safe,
/// serialization-stable identification instead of raw strings.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NOACheckpointKindName {
    SuiDWallet,
    SuiSystem,
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

    /// Human-readable name for logging/metrics.
    const NAME: &'static str;

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
pub struct SuiDWallet;

/// Sui System checkpoint kind — carries governance/config updates.
#[derive(Clone, Debug)]
pub struct SuiSystem;

impl NOACheckpointKind for SuiDWallet {
    type MessageKind = DWalletCheckpointMessageKind;
    type Counterparty = SuiCounterpartyChain;
    const NAME: &'static str = "noa_dwallet_checkpoint";

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

impl NOACheckpointKind for SuiSystem {
    type MessageKind = SystemCheckpointMessageKind;
    type Counterparty = SuiCounterpartyChain;
    const NAME: &'static str = "noa_system_checkpoint";

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

/// A single validator's observation of a checkpoint tx's on-chain status.
/// Piggybacked on `InternalSessionsStatusUpdate` so that quorum resolution
/// happens in the same consensus round as chain context agreement.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum NOACheckpointTxObservation {
    Finalized(NOACheckpointTxRef),
    Failed(NOACheckpointTxRef, u32), // (tx_ref, retry_round)
}

/// Command from MPC service to finalizer after consensus quorum resolution.
#[derive(Clone, Debug)]
pub enum NOACheckpointCommand<C: CounterpartyChain> {
    MarkFinalized(NOACheckpointTxRef),
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

    #[test]
    fn test_dwallet_build_tx_bytes_roundtrip() {
        let ctx = SuiChainContext {
            reference_gas_price: 1000,
            sui_epoch: 1,
        };
        let bytes = SuiDWallet::build_tx_bytes(1, 0, 0, &[], &ctx, &[], 0);
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
        let bytes = SuiSystem::build_tx_bytes(2, 5, 1, &[], &ctx, &[], 3);
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
        let first = SuiDWallet::build_tx_bytes(1, 0, 0, &[], &ctx, &[], 0);
        let retry = SuiDWallet::build_tx_bytes(1, 0, 0, &[], &ctx, &[], 1);
        assert_ne!(
            first, retry,
            "different retry_round should produce different bytes"
        );
    }
}
