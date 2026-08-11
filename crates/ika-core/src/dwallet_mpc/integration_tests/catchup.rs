//! Integration coverage for the MPC catch-up gate (issue #2023).
//!
//! The production trap: a validator re-entering MPC processing far behind the
//! consensus tip keeps computing sessions that already completed
//! network-wide, and that dead-on-arrival crypto pins its round drain just
//! below tip rate — a stable non-contributing equilibrium. The gate breaks
//! it by withholding NEW internal-presign and user-session computations while
//! the per-iteration round gap exceeds the enter threshold, and resuming once
//! it falls below the exit threshold.
//!
//! The harness expresses the entry condition directly: planting a dense
//! backlog of empty consensus rounds into every validator's epoch store makes
//! the next service iteration observe `tip - cursor = backlog` at its drain
//! entry — the exact signal a mid-epoch restart replay produces.

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStoreTrait;
use crate::dwallet_mpc::catchup_gate::{CATCH_UP_ENTER_GAP_ROUNDS, CATCH_UP_EXIT_GAP_ROUNDS};
use crate::dwallet_mpc::dwallet_mpc_metrics::session_type_label;
use crate::dwallet_mpc::dwallet_mpc_service::DWalletMPCService;
use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{IntegrationTestState, build_test_state};
use crate::dwallet_mpc::mpc_session::SessionStatus;
use dwallet_mpc_types::dwallet_mpc::DWalletSignatureAlgorithm;
use ika_types::messages_dwallet_mpc::SessionType;
use sui_types::base_types::ObjectID;
use tracing::info;

/// Comfortably above [`CATCH_UP_ENTER_GAP_ROUNDS`], mirroring the observed
/// production entry gaps (a replay landing thousands of rounds behind).
const BACKLOG_ROUNDS: u64 = CATCH_UP_ENTER_GAP_ROUNDS + 1_000;

/// Plants `count` dense empty consensus rounds starting at `start_round`
/// into every validator's epoch store. Only the two per-round streams the
/// service treats as mandatory-dense (MPC messages and MPC outputs) need
/// entries; every other stream tolerates a missing round. Also advances the
/// harness round counter past the planted range.
fn plant_empty_round_backlog(test_state: &mut IntegrationTestState, start_round: u64, count: u64) {
    for store in &test_state.epoch_stores {
        let mut messages = store.round_to_messages.lock().unwrap();
        let mut outputs = store.round_to_outputs.lock().unwrap();
        for round in start_round..start_round + count {
            messages.entry(round).or_default();
            outputs.entry(round).or_default();
        }
    }
    test_state.consensus_round = (start_round + count) as usize;
}

/// The shared drain cursor of all services (asserting they agree, since the
/// backlog must start exactly one past it on every validator).
fn common_last_read_consensus_round(test_state: &IntegrationTestState) -> u64 {
    let cursor = test_state.dwallet_mpc_services[0]
        .last_read_consensus_round()
        .expect("services must have processed at least one consensus round");
    for (index, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        assert_eq!(
            service.last_read_consensus_round(),
            Some(cursor),
            "validator {index}: drain cursor diverged from validator 0"
        );
    }
    cursor
}

/// Session types of every computation currently running on a service's
/// orchestrator.
fn running_computation_session_types(service: &DWalletMPCService) -> Vec<SessionType> {
    service
        .dwallet_mpc_manager()
        .cryptographic_computations_orchestrator
        .currently_running_cryptographic_computations
        .iter()
        .map(|computation_id| computation_id.session_identifier.session_type())
        .collect()
}

/// Count of Active sessions of the suppressible types (internal presign /
/// user) on a service — the suppression assertions are vacuous without them.
fn active_suppressible_session_count(service: &DWalletMPCService) -> usize {
    service
        .dwallet_mpc_manager()
        .sessions
        .values()
        .filter(|session| {
            matches!(session.status, SessionStatus::Active { .. })
                && matches!(
                    session.session_type,
                    Some(SessionType::InternalPresign | SessionType::User)
                )
        })
        .count()
}

/// The catch-up gap gauge must follow EVERY observation, not just the
/// enter/exit transitions.
///
/// That is the whole point of the metric: the gate logs only on transitions,
/// so during a long catch-up (the production case is hours) the transitions
/// have already happened and nothing further is emitted. A gauge that only
/// updated on transitions would freeze at the entry gap and report a draining
/// validator as indistinguishable from a stuck one.
///
/// Driven by feeding the manager gap observations directly, so the assertion
/// is about the gauge and nothing else — the end-to-end path through the
/// service loop is covered by the test below.
#[tokio::test]
#[cfg(test)]
async fn test_catchup_gap_gauge_tracks_every_observation() {
    let _guard = utils::create_test_protocol_config_guard();
    let mut test_state = build_test_state(1);
    let manager = test_state.dwallet_mpc_services[0].dwallet_mpc_manager_mut();
    let gap_gauge = manager.dwallet_mpc_metrics.catchup_gap_rounds.clone();
    let mode_gauge = manager.dwallet_mpc_metrics.catchup_mode.clone();

    // Below the enter threshold: no transition, but the gap is still reported.
    manager.observe_consensus_round_gap(1_200, Some(200));
    assert_eq!(mode_gauge.get(), 0, "no transition: the gate stays out");
    assert_eq!(gap_gauge.get(), 1_000);

    // Still no transition, different gap — the gauge must move anyway.
    manager.observe_consensus_round_gap(1_500, Some(200));
    assert_eq!(mode_gauge.get(), 0, "still no transition");
    assert_eq!(
        gap_gauge.get(),
        1_300,
        "the gauge must track a non-transition update"
    );

    // Enter catch-up.
    let entry_gap = CATCH_UP_ENTER_GAP_ROUNDS + 3_000;
    manager.observe_consensus_round_gap(entry_gap, None);
    assert_eq!(mode_gauge.get(), 1);
    assert_eq!(gap_gauge.get(), entry_gap as i64);

    // The draining span: every one of these is inside the hysteresis band, so
    // the gate never transitions and never logs — the gauge is the only
    // signal that the backlog is shrinking.
    let mut previous = gap_gauge.get();
    for gap in [
        CATCH_UP_ENTER_GAP_ROUNDS,
        CATCH_UP_ENTER_GAP_ROUNDS / 2,
        CATCH_UP_EXIT_GAP_ROUNDS + 1,
    ] {
        manager.observe_consensus_round_gap(gap, Some(0));
        assert_eq!(
            mode_gauge.get(),
            1,
            "gap {gap} is inside the hysteresis band: still no transition"
        );
        assert_eq!(
            gap_gauge.get(),
            gap as i64,
            "the gauge must follow the gap while the gate holds its state"
        );
        assert!(
            gap_gauge.get() < previous,
            "a draining backlog must show as a falling gauge"
        );
        previous = gap_gauge.get();
    }

    // And it reaches zero when the cursor catches the tip.
    manager.observe_consensus_round_gap(9_000, Some(9_000));
    assert_eq!(mode_gauge.get(), 0, "a zero gap exits catch-up");
    assert_eq!(gap_gauge.get(), 0);
}

/// End-to-end exercise of the catch-up gate against the real service loop:
///
/// 1. **Engage + suppress**: plant a `BACKLOG_ROUNDS` backlog; the next
///    iteration drains it, the gate engages (gauge = 1), internal presign
///    batches instantiated during the drain go computation-less, and the
///    suppressed-computations counter advances.
/// 2. **Disengage + resume**: the following iteration observes a zero gap;
///    the gate exits (gauge = 0) and the withheld sessions immediately spawn
///    their computations, which then run to completion and fill the presign
///    pool — proving suppression withheld work without losing it.
/// 3. **Exemption**: with a fresh backlog AND a live network DKG request, the
///    re-engaged gate still lets the System session compute while every
///    running computation remains of an exempt type.
#[tokio::test]
#[cfg(test)]
async fn test_catchup_gate_suppresses_and_resumes_computations() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = utils::create_test_protocol_config_guard();

    let mut test_state = build_test_state(4);
    let (consensus_round, _network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // Settle: nothing in flight, gate disengaged everywhere.
    utils::wait_for_computations(&mut test_state).await;
    for (index, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        let manager = service.dwallet_mpc_manager();
        assert_eq!(
            manager.dwallet_mpc_metrics.catchup_mode.get(),
            0,
            "validator {index}: gate must start disengaged"
        );
        assert!(
            manager
                .cryptographic_computations_orchestrator
                .currently_running_cryptographic_computations
                .is_empty(),
            "validator {index}: no computation may be in flight before the backlog"
        );
    }

    // === Phase 1: backlog beyond the enter threshold — engage and suppress ===
    let cursor = common_last_read_consensus_round(&test_state);
    plant_empty_round_backlog(&mut test_state, cursor + 1, BACKLOG_ROUNDS);
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration().await;
    }

    for (index, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        let manager = service.dwallet_mpc_manager();
        assert_eq!(
            manager.dwallet_mpc_metrics.catchup_mode.get(),
            1,
            "validator {index}: gate must engage on a {BACKLOG_ROUNDS}-round entry gap"
        );
        // The drain itself must have instantiated suppressible work
        // (internal presign top-up batches), otherwise the suppression
        // assertion below proves nothing.
        assert!(
            active_suppressible_session_count(service) > 0,
            "validator {index}: the backlog drain should have instantiated internal \
             presign sessions"
        );
        let running = running_computation_session_types(service);
        assert!(
            running.is_empty(),
            "validator {index}: no computation may spawn while catching up, found {running:?}"
        );
        assert!(
            manager
                .dwallet_mpc_metrics
                .catchup_suppressed_computations_total
                .with_label_values(&[session_type_label(SessionType::InternalPresign)])
                .get()
                > 0,
            "validator {index}: the suppressed-computations counter must record the \
             withheld internal presign spawns"
        );
    }
    info!("Phase 1 passed: gate engaged and computations suppressed on every validator");

    // === Phase 2: the backlog is drained — disengage and resume ===
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration().await;
    }
    for (index, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        assert_eq!(
            service
                .dwallet_mpc_manager()
                .dwallet_mpc_metrics
                .catchup_mode
                .get(),
            0,
            "validator {index}: gate must disengage once the gap is back under the \
             exit threshold"
        );
        assert!(
            !service
                .dwallet_mpc_manager()
                .cryptographic_computations_orchestrator
                .currently_running_cryptographic_computations
                .is_empty(),
            "validator {index}: the withheld sessions must spawn computations as soon \
             as catch-up ends"
        );
    }
    info!("Phase 2 passed: gate disengaged and computations resumed on every validator");

    // Run the resumed sessions to completion: the EdDSA presign pool filling
    // proves the suppressed batches were deferred, not lost.
    utils::wait_for_computations(&mut test_state).await;
    let mut pool_filled = false;
    for _ in 0..40 {
        utils::send_advance_results_between_parties(
            &test_state.committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            test_state.consensus_round as u64,
        );
        test_state.consensus_round += 1;
        for service in test_state.dwallet_mpc_services.iter_mut() {
            service.run_service_loop_iteration().await;
        }
        utils::wait_for_computations(&mut test_state).await;
        if test_state.epoch_stores[0]
            .presign_pool_size(DWalletSignatureAlgorithm::EdDSA, network_key_id)
            .unwrap_or(0)
            > 0
        {
            pool_filled = true;
            break;
        }
    }
    assert!(
        pool_filled,
        "after catch-up ends, the previously suppressed presign sessions must complete \
         and fill the pool"
    );
    info!("Resumption proof passed: presign pool filled after the gate disengaged");

    // === Phase 3: system sessions are exempt from suppression ===
    // Start a second network DKG (a System session) and re-enter catch-up in
    // the same iteration: the DKG computation must spawn anyway, while no
    // suppressible-type computation does. The request/activation pipeline may
    // take more than one iteration, so keep re-planting a fresh backlog (each
    // iteration then re-observes an above-threshold entry gap and the gate
    // stays engaged) until the System computation appears.
    utils::wait_for_computations(&mut test_state).await;
    let epoch_id = test_state
        .dwallet_mpc_services
        .first()
        .expect("at least one service must exist")
        .epoch;
    let second_dkg_key_id = ObjectID::random();
    let all_parties: Vec<usize> = (0..test_state.sui_data_senders.len()).collect();
    utils::send_configurable_start_network_dkg_event(
        epoch_id,
        &mut test_state.sui_data_senders,
        [7u8; 32],
        2,
        &all_parties,
        second_dkg_key_id,
    );

    let mut system_computation_spawned_during_catchup = false;
    for attempt in 0..5 {
        let cursor = common_last_read_consensus_round(&test_state);
        plant_empty_round_backlog(&mut test_state, cursor + 1, BACKLOG_ROUNDS);
        for service in test_state.dwallet_mpc_services.iter_mut() {
            service.run_service_loop_iteration().await;
        }

        for (index, service) in test_state.dwallet_mpc_services.iter().enumerate() {
            assert_eq!(
                service
                    .dwallet_mpc_manager()
                    .dwallet_mpc_metrics
                    .catchup_mode
                    .get(),
                1,
                "validator {index}: gate must be engaged while the DKG backlog drains \
                 (attempt {attempt})"
            );
            let running = running_computation_session_types(service);
            assert!(
                running.iter().all(|session_type| matches!(
                    session_type,
                    SessionType::System | SessionType::NetworkOwnedAddressSign
                )),
                "validator {index}: only exempt session types may compute during \
                 catch-up, found {running:?}"
            );
        }

        system_computation_spawned_during_catchup =
            test_state.dwallet_mpc_services.iter().all(|service| {
                running_computation_session_types(service).contains(&SessionType::System)
            });
        if system_computation_spawned_during_catchup {
            break;
        }
    }
    assert!(
        system_computation_spawned_during_catchup,
        "the network DKG (System session) must spawn its computation on every validator \
         even while the gate is engaged"
    );
    info!("Phase 3 passed: System session computed during catch-up; suppressible types did not");

    // Let the in-flight computations drain so the test tears down cleanly.
    utils::wait_for_computations(&mut test_state).await;
}
