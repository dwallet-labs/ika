// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub(super) mod mpc_computations;
pub(super) mod native_computations;
mod orchestrator;
pub mod protocol_cryptographic_data;
mod request;

use ika_types::messages_dwallet_mpc::SessionIdentifier;
pub(crate) use orchestrator::CryptographicComputationsOrchestrator;
pub(crate) use request::Request as ComputationRequest;
use std::hash::Hash;

const MPC_SIGN_SECOND_ROUND: u64 = 2;

/// A unique key for a computation request.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ComputationId {
    pub(crate) session_identifier: SessionIdentifier,
    pub(crate) consensus_round: u64,
    pub(crate) mpc_round: u64,
    pub(crate) attempt_number: u64,
}

/// Do not include the consensus round in the equality check. A new computation is created
/// every few consensus rounds when
/// [`crate::dwallet_mpc::mpc_manager::DWalletMPCManager::perform_cryptographic_computation`]
/// is called. Then, the chain checks if this computation has already been spawned.
/// If the consensus round were part of the equality check, the chain would always treat it
/// as a new computation and spawn one unnecessarily.
impl PartialEq for ComputationId {
    fn eq(&self, other: &Self) -> bool {
        self.session_identifier == other.session_identifier
            && self.mpc_round == other.mpc_round
            && self.attempt_number == other.attempt_number
    }
}

impl Eq for ComputationId {}

/// Do not include the consensus round in the hash. A new computation is created
/// every few consensus rounds when
/// [`crate::dwallet_mpc::mpc_manager::DWalletMPCManager::perform_cryptographic_computation`]
/// is called. Then, the chain checks if this computation has already been spawned.
/// If the consensus round were part of the hash, the chain would always treat it
/// as a new computation and spawn one unnecessarily.
impl Hash for ComputationId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.session_identifier.hash(state);
        self.mpc_round.hash(state);
        self.attempt_number.hash(state);
    }
}
