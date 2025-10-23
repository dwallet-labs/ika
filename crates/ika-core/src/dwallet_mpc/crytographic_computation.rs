// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub(super) mod mpc_computations;
pub(super) mod native_computations;
mod orchestrator;
pub mod protocol_cryptographic_data;
pub(crate) mod protocol_public_parameters;
mod request;

use derivative::Derivative;
use ika_types::messages_dwallet_mpc::SessionIdentifier;
pub(crate) use orchestrator::CryptographicComputationsOrchestrator;
pub(crate) use request::Request as ComputationRequest;

const MPC_SIGN_SECOND_ROUND: u64 = 2;

/// A unique key for a computation request.
#[derive(Derivative)]
#[derivative(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub(crate) struct ComputationId {
    pub(crate) session_identifier: SessionIdentifier,
    // TODO(Scaly): remove it?
    pub(crate) mpc_round: Option<u64>,
    // TODO(Scaly): remove it? make option?
    pub(crate) attempt_number: u64,

    /// Do not include the consensus round in the equality check. A new computation is created
    /// every few consensus rounds when
    /// [`crate::dwallet_mpc::mpc_manager::DWalletMPCManager::perform_cryptographic_computation`]
    /// is called. Then, the chain checks if this computation has already been spawned.
    /// If the consensus round were part of the equality check, the chain would always treat it
    /// as a new computation and spawn one unnecessarily.
    #[derivative(Hash = "ignore")]
    #[derivative(PartialEq = "ignore")]
    pub(crate) consensus_round: u64,
}
