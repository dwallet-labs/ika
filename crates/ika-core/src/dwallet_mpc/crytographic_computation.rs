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

const MPC_SIGN_SECOND_ROUND: u64 = 2;

/// A unique key for a computation request.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub(crate) struct ComputationId {
    pub(crate) session_identifier: SessionIdentifier,
    pub(crate) consensus_round: u64,
    pub(crate) current_round: u64,
    pub(crate) attempt_number: u64,
}
