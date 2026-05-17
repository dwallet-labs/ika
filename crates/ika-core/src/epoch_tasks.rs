// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Per-epoch background tasks that submit `ConsensusTransaction`s
//! and/or install per-epoch state on the `AuthorityPerEpochStore`.
//! None of these touch Sui RPC directly — for chain-reads, see
//! `sui_connector::sui_syncer` and the chain-driven updaters that
//! live alongside it (e.g. `consensus_pubkey_provider_updater`).

pub mod announcement_relay;
pub mod end_of_publish_sender;
pub mod handoff_signature_sender;
pub mod joiner_pubkey_provider_updater;
pub mod mpc_data_announcement_sender;
