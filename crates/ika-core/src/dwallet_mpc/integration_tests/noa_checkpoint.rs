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

use std::slice::from_ref;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use async_trait::async_trait;
use dwallet_mpc_types::dwallet_mpc::DWalletSignatureAlgorithm;
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_consensus::ConsensusTransactionKind;
use ika_types::messages_dwallet_mpc::{ConsensusNOAPresignDemand, SessionIdentifier, SessionType};
use ika_types::messages_system_checkpoints::SystemCheckpointMessageKind;
use ika_types::noa_checkpoint::{
    NOACheckpointKindName, NOACheckpointTxObservation, NOACheckpointTxRef, NOAPresignDemandId,
    SuiChainContext, SuiDWalletCheckpoint, SuiSystemCheckpoint,
};
use tracing::info;

use crate::authority::authority_per_epoch_store::{
    AuthorityPerEpochStoreTrait, NoaPresignDemandResolution,
};
use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    IntegrationTestState, build_test_state, create_test_protocol_config_guard,
    create_test_protocol_config_guard_with_noa_checkpoints,
};
use crate::noa_checkpoints::{NOAChainSubmitter, NOACheckpointHandler, TxExecutionStatus};

// ── Shared setup ───────────────────────────────────────────────────────────────

/// Perform DKG + EdDSA presign pool population (shared by all NOA checkpoint tests).
/// Returns the test state ready for NOA handler installation.
async fn setup_noa_test_state() -> IntegrationTestState {
    let mut test_state = build_test_state(4);

    let (consensus_round, network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;

    info!(
        "Network key created at consensus round {}, key_id: {:?}",
        consensus_round, network_key_id
    );
    test_state.consensus_round = consensus_round as usize;
    // The NOA signing key derives from the prior epoch's handoff certificate;
    // hand every validator one naming the key.
    utils::certify_network_key_for_noa_signing(&test_state, network_key_id, &network_key_bytes);

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
        )
        .await;
        test_state.consensus_round += 1;

        for service in test_state.dwallet_mpc_services.iter_mut() {
            service.run_service_loop_iteration().await;
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

/// Hand every validator ONE round carrying these checkpoint messages — the
/// fold's own output, which now reaches the drain in the round payload rather
/// than through a table.
///
/// Both kinds go in the same payload because a round is now one message. The
/// tables this replaced were keyed by round, so writing the dWallet kind and
/// the system kind for round N was two writes the drain read back as one
/// round; sending two payloads for round N instead is a duplicate round, and
/// the drain rejects it.
async fn inject_checkpoint_messages(
    test_state: &IntegrationTestState,
    round: u64,
    dwallet_messages: Vec<DWalletCheckpointMessageKind>,
    system_messages: Vec<SystemCheckpointMessageKind>,
) {
    for epoch_store in &test_state.epoch_stores {
        let mut payload = utils::empty_round_payload(round);
        payload.verified_dwallet_checkpoint_messages = dwallet_messages.clone();
        payload.verified_system_checkpoint_messages = system_messages.clone();
        epoch_store.deliver_round(payload).await;
    }
}

async fn inject_dwallet_checkpoint_messages(
    test_state: &IntegrationTestState,
    round: u64,
    messages: Vec<DWalletCheckpointMessageKind>,
) {
    inject_checkpoint_messages(test_state, round, messages, Vec::new()).await;
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
    )
    .await;
    // Delivery order IS the round sequence now that rounds cross a channel
    // instead of being written to round-keyed tables, so the counter has to
    // move past anything injected ahead of it or the next distribution would
    // hand the drain a round it has already consumed.
    test_state.consensus_round = checkpoint_round as usize + 1;

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
    )
    .await;
    inject_dwallet_checkpoint_messages(
        &test_state,
        second_round,
        vec![DWalletCheckpointMessageKind::SetMaxActiveSessionsBuffer(20)],
    )
    .await;
    // Delivery order IS the round sequence now that rounds cross a channel
    // instead of being written to round-keyed tables, so the counter has to
    // move past anything injected ahead of it or the next distribution would
    // hand the drain a round it has already consumed.
    test_state.consensus_round = second_round as usize + 1;
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
    )
    .await;
    // Delivery order IS the round sequence now that rounds cross a channel
    // instead of being written to round-keyed tables, so the counter has to
    // move past anything injected ahead of it or the next distribution would
    // hand the drain a round it has already consumed.
    test_state.consensus_round = buffered_round as usize + 1;
    info!(buffered_round, "Injected messages without context");

    // Advance several rounds — messages should buffer in the service (no sign requests
    // generated because context is None). The handler's store remains empty.
    for _ in 0..5 {
        utils::send_advance_results_between_parties(
            &test_state.committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            test_state.consensus_round as u64,
        )
        .await;
        test_state.consensus_round += 1;
        for service in test_state.dwallet_mpc_services.iter_mut() {
            service.run_service_loop_iteration().await;
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
    )
    .await;
    // Delivery order IS the round sequence now that rounds cross a channel
    // instead of being written to round-keyed tables, so the counter has to
    // move past anything injected ahead of it or the next distribution would
    // hand the drain a round it has already consumed.
    test_state.consensus_round = flush_round as usize + 1;
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
    )
    .await;
    // Delivery order IS the round sequence now that rounds cross a channel
    // instead of being written to round-keyed tables, so the counter has to
    // move past anything injected ahead of it or the next distribution would
    // hand the drain a round it has already consumed.
    test_state.consensus_round = checkpoint_round as usize + 1;
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
    // Both kinds ride the SAME round payload: one round is one message.
    inject_checkpoint_messages(
        &test_state,
        checkpoint_round,
        vec![DWalletCheckpointMessageKind::SetMaxActiveSessionsBuffer(55)],
        vec![SystemCheckpointMessageKind::SetEpochDurationMs(86_400_000)],
    )
    .await;
    test_state.consensus_round = checkpoint_round as usize + 1;

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

// ── Test 5: consensus submit failure → re-buffer ───────────────────────────────

/// A failed consensus submission must not drop buffered NOA observations or
/// presign demands. Their producers are one-shot — the checkpoint handler marks
/// a tx confirmed-locally / voted-failed BEFORE emitting its observation, and a
/// presign demand is announced at most once per epoch — so a dropped item is
/// never re-emitted and this validator's finalization vote (or demand
/// announcement) would be silently lost. The service must re-buffer failed
/// items and resend them once consensus submission recovers.
#[tokio::test]
#[cfg(test)]
async fn test_noa_status_update_rebuffers_on_submit_failure() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard_with_noa_checkpoints();

    let mut test_state = build_test_state(1);
    let authority = *test_state.committee.names().next().unwrap();
    let collector = test_state.sent_consensus_messages_collectors[0].clone();
    let service = &mut test_state.dwallet_mpc_services[0];

    let tx_ref = NOACheckpointTxRef {
        kind_name: NOACheckpointKindName::SuiDWallet,
        sequence_number: 1,
        tx_index: 0,
        epoch: 1,
    };
    let observation = NOACheckpointTxObservation::Finalized(tx_ref.clone());
    let demand = ConsensusNOAPresignDemand {
        authority,
        demand_id: NOAPresignDemandId::Checkpoint {
            tx_ref,
            retry_round: 0,
        },
    };
    service.buffer_noa_observation_for_testing(observation.clone());
    service.buffer_noa_presign_demand_for_testing(demand.clone());

    // While consensus submission fails, both items must survive in their buffers.
    collector.fail_submissions.store(true, Ordering::SeqCst);
    service
        .send_status_update_to_consensus_for_testing(false)
        .await;

    assert_eq!(
        service.buffered_noa_observations_for_testing(),
        from_ref(&observation),
        "failed observation submission must re-buffer the observation"
    );
    assert_eq!(
        service.buffered_noa_presign_demands_for_testing(),
        from_ref(&demand),
        "failed presign demand submission must re-buffer the demand"
    );
    assert!(
        collector.submitted_messages.lock().unwrap().is_empty(),
        "no message reaches consensus while submission fails"
    );

    // Once submission recovers, the retained items drain exactly once.
    collector.fail_submissions.store(false, Ordering::SeqCst);
    service
        .send_status_update_to_consensus_for_testing(false)
        .await;

    assert!(
        service.buffered_noa_observations_for_testing().is_empty(),
        "observation buffer must drain after a successful submission"
    );
    assert!(
        service
            .buffered_noa_presign_demands_for_testing()
            .is_empty(),
        "presign demand buffer must drain after a successful submission"
    );

    let submitted = collector.submitted_messages.lock().unwrap();
    let submitted_observations: Vec<_> = submitted
        .iter()
        .filter_map(|message| match &message.kind {
            ConsensusTransactionKind::NOAObservation(msg) => Some(msg.observation.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(submitted_observations, vec![observation]);
    let submitted_demands: Vec<_> = submitted
        .iter()
        .filter_map(|message| match &message.kind {
            ConsensusTransactionKind::NOAPresignDemand(msg) => Some(msg.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(submitted_demands, vec![demand]);
}

// ── Test 6: a demand sequenced before the signing key is derived ─────────────

/// Runs `rounds` consensus rounds through the services at `indices`, then one
/// final iteration so the last round created is actually drained.
async fn flow_consensus_rounds_on(
    test_state: &mut IntegrationTestState,
    indices: [usize; 2],
    rounds: usize,
) {
    for _ in 0..rounds {
        for index in indices {
            test_state.dwallet_mpc_services[index]
                .run_service_loop_iteration()
                .await;
        }
        utils::send_advance_results_between_parties(
            &test_state.committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            test_state.consensus_round as u64,
        )
        .await;
        test_state.consensus_round += 1;
    }
    for index in indices {
        test_state.dwallet_mpc_services[index]
            .run_service_loop_iteration()
            .await;
    }
}

/// A demand sequenced while a validator has not yet derived the epoch's
/// network-owned-address signing key parks, and once the derivation resolves
/// it is assigned the SAME presign a peer that derived the key immediately
/// assigned it.
///
/// Two validators receive the same demand in the same round over identical
/// pools. The peer holds the prior epoch's handoff certificate from the start
/// and assigns at delivery; the target holds none, parks, and assigns once it
/// is handed the certificate. Their assignment tables must then match entry
/// for entry: same presign, same blending index, same session, same key.
#[tokio::test]
#[cfg(test)]
async fn test_noa_presign_demand_parked_on_an_underived_key_matches_the_peer_assignment() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard_with_noa_checkpoints();

    let mut test_state = build_test_state(4);
    let (consensus_round, network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    const TARGET: usize = 0;
    const PEER: usize = 1;
    let demand_id = NOAPresignDemandId::Checkpoint {
        tx_ref: NOACheckpointTxRef {
            kind_name: NOACheckpointKindName::SuiDWallet,
            sequence_number: 7,
            tx_index: 0,
            epoch: 1,
        },
        retry_round: 0,
    };
    let algorithm = demand_id.expected_signature_algorithm();

    // Identical pools with two slots each, so WHICH slot the drain takes is
    // observable, seeded before any top-up batch can complete.
    for index in [TARGET, PEER] {
        for (slot, marker) in [(0u64, 0x3Au8), (1, 0x3B)] {
            test_state.epoch_stores[index]
                .insert_presigns(
                    algorithm,
                    network_key_id,
                    slot,
                    SessionIdentifier::new(SessionType::InternalPresign, [marker; 32]),
                    vec![vec![marker; 16]],
                )
                .expect("seed the presign pool");
        }
    }

    // Only the peer can derive the signing key from the start.
    let (prior_epoch, certificate) =
        utils::noa_signing_certificate(&test_state, network_key_id, &network_key_bytes);
    test_state.epoch_stores[PEER]
        .certified_handoff_attestations
        .lock()
        .unwrap()
        .insert(prior_epoch, certificate.clone());

    // The same demand reaches both validators in the same round: this round
    // goes to everyone the usual way, then both get one more round carrying
    // the demand.
    let announcing_authority = test_state
        .committee
        .names()
        .nth(2)
        .copied()
        .expect("committee has a third member");
    let round = test_state.consensus_round as u64;
    utils::send_advance_results_between_parties(
        &test_state.committee,
        &mut test_state.sent_consensus_messages_collectors,
        &mut test_state.epoch_stores,
        round,
    )
    .await;
    for index in [TARGET, PEER] {
        let mut payload = utils::empty_round_payload(round + 1);
        payload.noa_presign_demands.push(ConsensusNOAPresignDemand {
            authority: announcing_authority,
            demand_id: demand_id.clone(),
        });
        test_state.epoch_stores[index].deliver_round(payload).await;
    }
    test_state.consensus_round += 2;

    flow_consensus_rounds_on(&mut test_state, [TARGET, PEER], 3).await;

    let peer_resolution = test_state.epoch_stores[PEER]
        .noa_presign_demand_resolution(&demand_id)
        .expect("read the peer's resolution");
    assert!(
        matches!(
            peer_resolution,
            Some(NoaPresignDemandResolution::Assigned { .. })
        ),
        "the peer derived the key at once and assigns at delivery, found {peer_resolution:?}"
    );
    assert_eq!(
        test_state.epoch_stores[TARGET]
            .noa_presign_demand_resolution(&demand_id)
            .expect("read the target's resolution"),
        None,
        "the target cannot derive the key yet, so its demand parks"
    );
    assert_eq!(
        test_state.dwallet_mpc_services[TARGET].parked_noa_presign_demand_count(),
        1,
        "the parked demand stays in the target's queue"
    );

    // The target's derivation input lands.
    test_state.epoch_stores[TARGET]
        .certified_handoff_attestations
        .lock()
        .unwrap()
        .insert(prior_epoch, certificate);
    flow_consensus_rounds_on(&mut test_state, [TARGET, PEER], 3).await;

    let target_resolution = test_state.epoch_stores[TARGET]
        .noa_presign_demand_resolution(&demand_id)
        .expect("read the target's resolution");
    assert_eq!(
        target_resolution, peer_resolution,
        "the parked demand must be assigned exactly what the peer assigned it"
    );
    assert!(
        matches!(
            target_resolution,
            Some(NoaPresignDemandResolution::Assigned { network_encryption_key_id, .. })
                if network_encryption_key_id == network_key_id
        ),
        "the assignment records the certificate-derived key, found {target_resolution:?}"
    );
    for index in [TARGET, PEER] {
        assert_eq!(
            test_state.dwallet_mpc_services[index].parked_noa_presign_demand_count(),
            0,
            "an assigned demand leaves the queue on validator {index}"
        );
        assert_eq!(
            test_state.epoch_stores[index]
                .presign_pool_size(algorithm, network_key_id)
                .expect("pool size"),
            1,
            "exactly one slot is consumed on validator {index}"
        );
    }
}
