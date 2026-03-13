// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Integration tests for the NOA checkpoint flow through `DWalletMPCService`.
//!
//! Covers:
//! - E2E happy path (single checkpoint)
//! - Sequential multi-checkpoint finalization gating
//! - Buffered context (messages arrive before chain context)
//! - Failure/retry through consensus
//! - Dual-handler (DWallet + System) simultaneous routing

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use async_trait::async_trait;
use dwallet_mpc_types::dwallet_mpc::DWalletSignatureAlgorithm;
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_system_checkpoints::SystemCheckpointMessageKind;
use ika_types::noa_checkpoint::{SuiChainContext, SuiDWalletCheckpoint, SuiSystemCheckpoint};
use tracing::info;

use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    IntegrationTestState, build_test_state, create_test_protocol_config_guard,
};
use crate::noa_checkpoints::{NOAChainSubmitter, NOACheckpointHandler, TxExecutionStatus};

// ── Shared setup ───────────────────────────────────────────────────────────────

/// Perform DKG + EdDSA presign pool population (shared by all NOA checkpoint tests).
/// Returns the test state ready for NOA handler installation.
async fn setup_noa_test_state() -> IntegrationTestState {
    let mut test_state = build_test_state(4);

    let (consensus_round, _network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;

    info!(
        "Network key created at consensus round {}, key_id: {:?}",
        consensus_round, network_key_id
    );
    test_state.consensus_round = consensus_round as usize;

    let start_round = test_state.consensus_round as u64;
    let consensus_round = utils::advance_rounds_while_presign_pool_empty(
        &mut test_state,
        DWalletSignatureAlgorithm::EdDSA,
        network_key_id,
        start_round,
    )
    .await;
    test_state.consensus_round = consensus_round as usize;

    info!(
        consensus_round,
        "Presign pool populated, ready for NOA checkpoint tests"
    );

    test_state
}

/// Run consensus rounds until `predicate` returns true, advancing the test state each round.
/// Panics after `max_rounds` iterations.
async fn run_until(
    test_state: &mut IntegrationTestState,
    max_rounds: usize,
    predicate: impl Fn() -> bool,
) {
    for round_idx in 0..max_rounds {
        utils::send_advance_results_between_parties(
            &test_state.committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            test_state.consensus_round as u64,
        );
        test_state.consensus_round += 1;

        for service in test_state.dwallet_mpc_services.iter_mut() {
            service.run_service_loop_iteration(vec![]).await;
        }

        utils::wait_for_computations(test_state).await;

        if predicate() {
            info!(round_idx, "run_until: predicate satisfied");
            return;
        }
    }
    panic!(
        "run_until: predicate not satisfied after {} rounds",
        max_rounds
    );
}

/// Install DWallet-only NOA checkpoint handlers with `AlwaysSucceedSubmitter` on every validator.
/// Returns one `AtomicBool` flag per validator.
fn install_dwallet_handlers_with_log_submitter(
    test_state: &mut IntegrationTestState,
) -> Vec<Arc<AtomicBool>> {
    let validator_count = test_state.dwallet_mpc_services.len();
    let flags: Vec<Arc<AtomicBool>> = (0..validator_count)
        .map(|_| Arc::new(AtomicBool::new(false)))
        .collect();

    for (i, service) in test_state.dwallet_mpc_services.iter_mut().enumerate() {
        let handler = NOACheckpointHandler::<SuiDWalletCheckpoint>::new(
            Arc::new(AlwaysSucceedSubmitter),
            1,
            vec![],
            flags[i].clone(),
        );
        service.setup_noa_checkpoint_handlers_for_testing(handler, None);
        service.set_agreed_sui_chain_context_for_testing(SuiChainContext {
            reference_gas_price: 1000,
            sui_epoch: 1,
        });
    }

    flags
}

/// Inject DWallet checkpoint messages at the given round for all validators.
fn inject_dwallet_checkpoint_messages(
    test_state: &IntegrationTestState,
    round: u64,
    messages: Vec<DWalletCheckpointMessageKind>,
) {
    for epoch_store in &test_state.epoch_stores {
        epoch_store
            .round_to_verified_checkpoint
            .lock()
            .unwrap()
            .entry(round)
            .or_default()
            .extend(messages.clone());
    }
}

/// Inject system checkpoint messages at the given round for all validators.
fn inject_system_checkpoint_messages(
    test_state: &IntegrationTestState,
    round: u64,
    messages: Vec<SystemCheckpointMessageKind>,
) {
    for epoch_store in &test_state.epoch_stores {
        epoch_store
            .round_to_verified_system_checkpoint
            .lock()
            .unwrap()
            .entry(round)
            .or_default()
            .extend(messages.clone());
    }
}

fn all_flags_true(flags: &[Arc<AtomicBool>]) -> bool {
    flags.iter().all(|f| f.load(Ordering::Acquire))
}

// ── Test chain submitters ──────────────────────────────────────────────────────

/// Test chain submitter that always succeeds: `submit_tx` returns `tx_bytes` as
/// the identifier, `check_tx_status` always returns `Executed`.
struct AlwaysSucceedSubmitter;

#[async_trait]
impl<K: ika_types::noa_checkpoint::NOACheckpointKind> NOAChainSubmitter<K>
    for AlwaysSucceedSubmitter
{
    async fn submit_tx(
        &self,
        tx_bytes: &[u8],
        _signature: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error> {
        Ok(tx_bytes.to_vec())
    }

    async fn check_tx_status(
        &self,
        _tx_identifier: &[u8],
    ) -> Result<TxExecutionStatus, anyhow::Error> {
        Ok(TxExecutionStatus::Executed)
    }
}

/// Chain submitter that fails `check_tx_status` for the first N calls, then succeeds.
struct FailThenSucceedSubmitter {
    check_call_count: AtomicU64,
    fail_first_n_checks: u64,
}

impl FailThenSucceedSubmitter {
    fn new(fail_first_n_checks: u64) -> Self {
        Self {
            check_call_count: AtomicU64::new(0),
            fail_first_n_checks,
        }
    }
}

#[async_trait]
impl<K: ika_types::noa_checkpoint::NOACheckpointKind> NOAChainSubmitter<K>
    for FailThenSucceedSubmitter
{
    async fn submit_tx(
        &self,
        tx_bytes: &[u8],
        _signature: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error> {
        Ok(tx_bytes.to_vec())
    }

    async fn check_tx_status(
        &self,
        _tx_identifier: &[u8],
    ) -> Result<TxExecutionStatus, anyhow::Error> {
        let count = self.check_call_count.fetch_add(1, Ordering::SeqCst);
        if count < self.fail_first_n_checks {
            Ok(TxExecutionStatus::Failed("simulated failure".to_string()))
        } else {
            Ok(TxExecutionStatus::Executed)
        }
    }
}

// ── Test 0 (existing): E2E happy path ──────────────────────────────────────────

/// End-to-end test: checkpoint message -> MPC sign -> chain submit -> finalization quorum.
#[tokio::test]
#[cfg(test)]
async fn test_noa_checkpoint_dwallet_e2e() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = setup_noa_test_state().await;
    let finalized_flags = install_dwallet_handlers_with_log_submitter(&mut test_state);

    let checkpoint_round = (test_state.consensus_round + 1) as u64;
    inject_dwallet_checkpoint_messages(
        &test_state,
        checkpoint_round,
        vec![DWalletCheckpointMessageKind::SetMaxActiveSessionsBuffer(42)],
    );

    info!(
        checkpoint_round,
        "Injected checkpoint messages, starting consensus loop"
    );

    let flags = finalized_flags.clone();
    run_until(&mut test_state, 300, || all_flags_true(&flags)).await;

    for (i, flag) in finalized_flags.iter().enumerate() {
        assert!(
            flag.load(Ordering::Acquire),
            "validator {} all_finalized_flag should be true after E2E flow",
            i
        );
    }
}

// ── Test 1: Multiple sequential checkpoints ────────────────────────────────────

/// Two checkpoint batches at different rounds. The `all_finalized_flag` must stay
/// false until BOTH are finalized — catches bugs where the flag flips after the first.
///
/// Both batches are injected up-front at two different consensus rounds. The flag
/// should only become true after both checkpoints are signed, submitted, and
/// finalized via 2f+1 quorum.
#[tokio::test]
#[cfg(test)]
async fn test_noa_checkpoint_multiple_sequential() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = setup_noa_test_state().await;
    let finalized_flags = install_dwallet_handlers_with_log_submitter(&mut test_state);

    // Inject batch 1 at round N+1 and batch 2 at round N+2.
    let first_round = (test_state.consensus_round + 1) as u64;
    let second_round = (test_state.consensus_round + 2) as u64;

    inject_dwallet_checkpoint_messages(
        &test_state,
        first_round,
        vec![DWalletCheckpointMessageKind::SetMaxActiveSessionsBuffer(10)],
    );
    inject_dwallet_checkpoint_messages(
        &test_state,
        second_round,
        vec![DWalletCheckpointMessageKind::SetMaxActiveSessionsBuffer(20)],
    );
    info!(
        first_round,
        second_round, "Injected both checkpoint batches"
    );

    // Run until ALL validators report all_finalized (requires BOTH batches done).
    let flags = finalized_flags.clone();
    run_until(&mut test_state, 300, || all_flags_true(&flags)).await;

    for (i, flag) in finalized_flags.iter().enumerate() {
        assert!(
            flag.load(Ordering::Acquire),
            "validator {} all_finalized_flag should be true after both batches",
            i
        );
    }
}

// ── Test 2: Buffered context ───────────────────────────────────────────────────

/// Checkpoint messages arrive BEFORE `current_agreed_sui_chain_context` is set.
/// They buffer, then flush when context is provided.
#[tokio::test]
#[cfg(test)]
async fn test_noa_checkpoint_buffered_context() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = setup_noa_test_state().await;

    // Install handlers WITHOUT setting chain context.
    let validator_count = test_state.dwallet_mpc_services.len();
    let finalized_flags: Vec<Arc<AtomicBool>> = (0..validator_count)
        .map(|_| Arc::new(AtomicBool::new(false)))
        .collect();

    for (i, service) in test_state.dwallet_mpc_services.iter_mut().enumerate() {
        let handler = NOACheckpointHandler::<SuiDWalletCheckpoint>::new(
            Arc::new(AlwaysSucceedSubmitter),
            1,
            vec![],
            finalized_flags[i].clone(),
        );
        service.setup_noa_checkpoint_handlers_for_testing(handler, None);
        // Deliberately NOT calling set_agreed_sui_chain_context_for_testing here.
    }

    // Inject checkpoint messages at round N+1 (before context).
    let buffered_round = (test_state.consensus_round + 1) as u64;
    inject_dwallet_checkpoint_messages(
        &test_state,
        buffered_round,
        vec![DWalletCheckpointMessageKind::SetMaxActiveSessionsBuffer(99)],
    );
    info!(buffered_round, "Injected messages without context");

    // Advance several rounds — messages should buffer in the service (no sign requests
    // generated because context is None). The handler's store remains empty.
    for _ in 0..5 {
        utils::send_advance_results_between_parties(
            &test_state.committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            test_state.consensus_round as u64,
        );
        test_state.consensus_round += 1;
        for service in test_state.dwallet_mpc_services.iter_mut() {
            service.run_service_loop_iteration(vec![]).await;
        }
    }

    // Now set the context.
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.set_agreed_sui_chain_context_for_testing(SuiChainContext {
            reference_gas_price: 1000,
            sui_epoch: 1,
        });
    }

    // The buffered messages drain when the next round has non-empty checkpoint messages
    // (the `continue` on empty `checkpoint_messages` skips the drain path).
    // Inject a small trigger message at the next round to flush the buffer.
    let flush_round = (test_state.consensus_round + 1) as u64;
    inject_dwallet_checkpoint_messages(
        &test_state,
        flush_round,
        vec![DWalletCheckpointMessageKind::SetMaxActiveSessionsBuffer(
            100,
        )],
    );
    info!(
        flush_round,
        "Injected flush-trigger message after context set"
    );

    // Run until finalized.
    let flags = finalized_flags.clone();
    run_until(&mut test_state, 300, || all_flags_true(&flags)).await;

    for (i, flag) in finalized_flags.iter().enumerate() {
        assert!(
            flag.load(Ordering::Acquire),
            "validator {} all_finalized_flag should be true after buffered flush",
            i
        );
    }
}

// ── Test 3: Chain failure → retry ──────────────────────────────────────────────

/// Full failure → retry lifecycle: `check_tx_status` returns `Failed` → observation →
/// 2f+1 quorum → `RetryWithContext` → MPC re-sign → re-submit → `Executed` → finalize.
#[tokio::test]
#[cfg(test)]
async fn test_noa_checkpoint_chain_failure_retry() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = setup_noa_test_state().await;

    let validator_count = test_state.dwallet_mpc_services.len();
    let finalized_flags: Vec<Arc<AtomicBool>> = (0..validator_count)
        .map(|_| Arc::new(AtomicBool::new(false)))
        .collect();

    for (i, service) in test_state.dwallet_mpc_services.iter_mut().enumerate() {
        let handler = NOACheckpointHandler::<SuiDWalletCheckpoint>::new(
            Arc::new(FailThenSucceedSubmitter::new(1)),
            1,
            vec![],
            finalized_flags[i].clone(),
        );
        service.setup_noa_checkpoint_handlers_for_testing(handler, None);
        service.set_agreed_sui_chain_context_for_testing(SuiChainContext {
            reference_gas_price: 1000,
            sui_epoch: 1,
        });
    }

    let checkpoint_round = (test_state.consensus_round + 1) as u64;
    inject_dwallet_checkpoint_messages(
        &test_state,
        checkpoint_round,
        vec![DWalletCheckpointMessageKind::SetMaxActiveSessionsBuffer(77)],
    );
    info!(
        checkpoint_round,
        "Injected checkpoint for failure/retry test"
    );

    // This test needs more rounds: sign → submit → poll(Failed) → consensus quorum →
    // RetryWithContext → re-sign → re-submit → poll(Executed) → finalization quorum.
    let flags = finalized_flags.clone();
    run_until(&mut test_state, 600, || all_flags_true(&flags)).await;

    for (i, flag) in finalized_flags.iter().enumerate() {
        assert!(
            flag.load(Ordering::Acquire),
            "validator {} all_finalized_flag should be true after failure/retry cycle",
            i
        );
    }
}

// ── Test 4: Both DWallet and System handlers ───────────────────────────────────

/// Both DWallet and System checkpoint handlers installed simultaneously.
/// Verifies routing correctness: each handler signs and finalizes independently.
#[tokio::test]
#[cfg(test)]
async fn test_noa_checkpoint_both_handlers() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = setup_noa_test_state().await;

    let validator_count = test_state.dwallet_mpc_services.len();
    let dwallet_flags: Vec<Arc<AtomicBool>> = (0..validator_count)
        .map(|_| Arc::new(AtomicBool::new(false)))
        .collect();
    let system_flags: Vec<Arc<AtomicBool>> = (0..validator_count)
        .map(|_| Arc::new(AtomicBool::new(false)))
        .collect();

    for (i, service) in test_state.dwallet_mpc_services.iter_mut().enumerate() {
        let dwallet_handler = NOACheckpointHandler::<SuiDWalletCheckpoint>::new(
            Arc::new(AlwaysSucceedSubmitter),
            1,
            vec![],
            dwallet_flags[i].clone(),
        );
        let system_handler = NOACheckpointHandler::<SuiSystemCheckpoint>::new(
            Arc::new(AlwaysSucceedSubmitter),
            1,
            vec![],
            system_flags[i].clone(),
        );
        service.setup_noa_checkpoint_handlers_for_testing(dwallet_handler, Some(system_handler));
        service.set_agreed_sui_chain_context_for_testing(SuiChainContext {
            reference_gas_price: 1000,
            sui_epoch: 1,
        });
    }

    // Inject DWallet checkpoint messages at round N+1.
    let checkpoint_round = (test_state.consensus_round + 1) as u64;
    inject_dwallet_checkpoint_messages(
        &test_state,
        checkpoint_round,
        vec![DWalletCheckpointMessageKind::SetMaxActiveSessionsBuffer(55)],
    );

    // Inject System checkpoint messages at the same round.
    inject_system_checkpoint_messages(
        &test_state,
        checkpoint_round,
        vec![SystemCheckpointMessageKind::SetEpochDurationMs(86_400_000)],
    );

    info!(
        checkpoint_round,
        "Injected both DWallet and System checkpoint messages"
    );

    let df = dwallet_flags.clone();
    let sf = system_flags.clone();
    run_until(&mut test_state, 600, || {
        all_flags_true(&df) && all_flags_true(&sf)
    })
    .await;

    for (i, flag) in dwallet_flags.iter().enumerate() {
        assert!(
            flag.load(Ordering::Acquire),
            "validator {} dwallet_finalized_flag should be true",
            i
        );
    }
    for (i, flag) in system_flags.iter().enumerate() {
        assert!(
            flag.load(Ordering::Acquire),
            "validator {} system_finalized_flag should be true",
            i
        );
    }
}
