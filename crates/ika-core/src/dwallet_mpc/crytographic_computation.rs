// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub(super) mod mpc_computations;
pub(super) mod native_computations;
mod orchestrator;
mod request;

use ika_types::messages_dwallet_mpc::SessionIdentifier;
pub(crate) use orchestrator::CryptographicComputationsOrchestrator;
pub(crate) use request::Request as ComputationRequest;

const MPC_SIGN_SECOND_ROUND: u64 = 2;

/// A unique key for a computation request.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub(crate) struct ComputationId {
    pub(crate) session_identifier: SessionIdentifier,
    /// The consensus round at which this computation executed (if it is synced with the consensus).
    /// The first MPC round will be `None`, since it isn't synced — it is launched when the
    /// event is received from Sui.
    /// All other MPC rounds will set this to `Some()` with the value being the last consensus
    /// round from which we gathered messages to advance.
    pub(crate) consensus_round: u64,
    pub(crate) mpc_round: u64,
    pub(crate) attempt_number: u64,
}
