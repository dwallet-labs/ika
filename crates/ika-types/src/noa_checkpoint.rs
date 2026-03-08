// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::committee::EpochId;
use crate::message::DWalletCheckpointMessageKind;
use crate::messages_system_checkpoints::SystemCheckpointMessageKind;
use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, DWalletHashScheme, DWalletSignatureAlgorithm};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

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

    /// The curve used for NOA MPC signing.
    fn curve() -> DWalletCurve;

    /// The signature algorithm for NOA signing.
    fn signature_algorithm() -> DWalletSignatureAlgorithm;

    /// The hash scheme for NOA signing.
    fn hash_scheme() -> DWalletHashScheme;

    /// Convert checkpoint data + chain context into transaction bytes for NOA signing.
    /// Crypto params (curve, sig algo, hash) come from Self::curve() etc.
    /// `noa_public_key` is runtime data from the current network key.
    fn to_signable_bytes(
        checkpoint: &NOACheckpointMessage<Self>,
        context: &<Self::Destination as ChainDestination>::Context,
        noa_public_key: &[u8],
    ) -> Vec<u8>;
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

    fn curve() -> DWalletCurve {
        DWalletCurve::Curve25519
    }

    fn signature_algorithm() -> DWalletSignatureAlgorithm {
        DWalletSignatureAlgorithm::EdDSA
    }

    fn hash_scheme() -> DWalletHashScheme {
        DWalletHashScheme::SHA512
    }

    fn to_signable_bytes(
        _checkpoint: &NOACheckpointMessage<Self>,
        _context: &SuiChainContext,
        _noa_public_key: &[u8],
    ) -> Vec<u8> {
        // TODO: Build actual Sui TransactionData bytes using context + NOA public key.
        todo!("Sui TransactionData construction for DWallet checkpoints")
    }
}

impl NOACheckpointKind for System {
    type MessageKind = SystemCheckpointMessageKind;
    type Destination = SuiDestination;
    const NAME: &'static str = "noa_system_checkpoint";

    fn curve() -> DWalletCurve {
        DWalletCurve::Curve25519
    }

    fn signature_algorithm() -> DWalletSignatureAlgorithm {
        DWalletSignatureAlgorithm::EdDSA
    }

    fn hash_scheme() -> DWalletHashScheme {
        DWalletHashScheme::SHA512
    }

    fn to_signable_bytes(
        _checkpoint: &NOACheckpointMessage<Self>,
        _context: &SuiChainContext,
        _noa_public_key: &[u8],
    ) -> Vec<u8> {
        // TODO: Build actual Sui TransactionData bytes using context + NOA public key.
        todo!("Sui TransactionData construction for System checkpoints")
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertifiedNOACheckpointMessage<K: NOACheckpointKind> {
    pub checkpoint: NOACheckpointMessage<K>,
    /// The raw NOA signature bytes.
    pub signature: Vec<u8>,
    /// The bytes that were signed (the output of to_signable_bytes).
    pub signed_bytes: Vec<u8>,
    pub curve: DWalletCurve,
    pub signature_algorithm: DWalletSignatureAlgorithm,
}
