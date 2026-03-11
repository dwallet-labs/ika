// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::committee::EpochId;
use crate::message::DWalletCheckpointMessageKind;
use crate::messages_system_checkpoints::SystemCheckpointMessageKind;
use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, DWalletHashScheme, DWalletSignatureAlgorithm};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::hash::Hash;

// === ChainDestination ===

/// Encapsulates chain-specific configuration for checkpoint submission.
pub trait ChainDestination: Clone + Debug + Send + Sync + 'static {
    /// Chain context needed at runtime to build signable transaction bytes.
    type Context: Send + Sync;

    /// Human-readable chain name (e.g., "sui", "solana").
    const CHAIN_NAME: &'static str;
}

/// Sui chain destination — carries Sui object IDs, module info, etc.
#[derive(Clone, Debug)]
pub struct SuiDestination;

/// Runtime context for building Sui transactions.
/// Fields TBD when implementing actual tx building.
pub struct SuiChainContext;

impl ChainDestination for SuiDestination {
    type Context = SuiChainContext;
    const CHAIN_NAME: &'static str = "sui";
}

// === NOACheckpointKind ===

/// Enum identifying a checkpoint kind. Used in `NOACheckpointTxRef` for type-safe,
/// serialization-stable identification instead of raw strings.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NOACheckpointKindName {
    DWallet,
    System,
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

    /// The chain this checkpoint targets.
    type Destination: ChainDestination;

    /// Human-readable name for logging/metrics.
    const NAME: &'static str;

    /// Typed identifier for this checkpoint kind, used in `NOACheckpointTxRef`.
    fn kind_name() -> NOACheckpointKindName;

    /// The curve used for NOA MPC signing.
    fn curve() -> DWalletCurve;

    /// The signature algorithm for NOA signing.
    fn signature_algorithm() -> DWalletSignatureAlgorithm;

    /// The hash scheme for NOA signing.
    fn hash_scheme() -> DWalletHashScheme;

    /// Convert checkpoint data + chain context into transaction bytes for NOA signing.
    /// Returns one `Vec<u8>` per transaction — a single checkpoint may need multiple
    /// transactions when the message set exceeds Sui's 128 KB tx size limit.
    /// Crypto params (curve, sig algo, hash) come from Self::curve() etc.
    /// `noa_public_key` is runtime data from the current network key.
    fn signable_bytes(
        checkpoint: &NOACheckpointMessage<Self>,
        context: &<Self::Destination as ChainDestination>::Context,
        noa_public_key: &[u8],
    ) -> Vec<Vec<u8>>;
}

// === Marker types implementing NOACheckpointKind ===

/// DWallet checkpoint kind — carries MPC session results.
#[derive(Clone, Debug)]
pub struct DWallet;

/// System checkpoint kind — carries governance/config updates.
#[derive(Clone, Debug)]
pub struct System;

impl NOACheckpointKind for DWallet {
    type MessageKind = DWalletCheckpointMessageKind;
    type Destination = SuiDestination;
    const NAME: &'static str = "noa_dwallet_checkpoint";

    fn kind_name() -> NOACheckpointKindName {
        NOACheckpointKindName::DWallet
    }

    fn curve() -> DWalletCurve {
        DWalletCurve::Curve25519
    }

    fn signature_algorithm() -> DWalletSignatureAlgorithm {
        DWalletSignatureAlgorithm::EdDSA
    }

    fn hash_scheme() -> DWalletHashScheme {
        DWalletHashScheme::SHA512
    }

    fn signable_bytes(
        checkpoint: &NOACheckpointMessage<Self>,
        _context: &SuiChainContext,
        _noa_public_key: &[u8],
    ) -> Vec<Vec<u8>> {
        // TODO: Build actual Sui TransactionData bytes using context + NOA public key.
        // Currently BCS-serializes the checkpoint as a single transaction placeholder.
        vec![
            bcs::to_bytes(checkpoint)
                .expect("BCS serialization of NOA DWallet checkpoint should not fail"),
        ]
    }
}

impl NOACheckpointKind for System {
    type MessageKind = SystemCheckpointMessageKind;
    type Destination = SuiDestination;
    const NAME: &'static str = "noa_system_checkpoint";

    fn kind_name() -> NOACheckpointKindName {
        NOACheckpointKindName::System
    }

    fn curve() -> DWalletCurve {
        DWalletCurve::Curve25519
    }

    fn signature_algorithm() -> DWalletSignatureAlgorithm {
        DWalletSignatureAlgorithm::EdDSA
    }

    fn hash_scheme() -> DWalletHashScheme {
        DWalletHashScheme::SHA512
    }

    fn signable_bytes(
        checkpoint: &NOACheckpointMessage<Self>,
        _context: &SuiChainContext,
        _noa_public_key: &[u8],
    ) -> Vec<Vec<u8>> {
        // TODO: Build actual Sui TransactionData bytes using context + NOA public key.
        // Currently BCS-serializes the checkpoint as a single transaction placeholder.
        vec![
            bcs::to_bytes(checkpoint)
                .expect("BCS serialization of NOA System checkpoint should not fail"),
        ]
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
