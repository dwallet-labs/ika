// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Literal v1.2.5 -> current PROTOCOL upgrade rehearsal: the gate for
//! activating protocol v6, where a validator's `AuthorityName` (its committee
//! identity) switches from the BLS protocol key to the Ed25519 consensus key.
//!
//! Its sibling `v125_rollout` is a pure BINARY swap that stays at protocol v5
//! throughout; this scenario is the counterpart that deliberately crosses the
//! VERSION boundary, because that crossing is the one thing the identity flip
//! cannot be assumed safe across:
//!
//! - The next-epoch committee is assembled MID-epoch, under the current
//!   epoch's protocol version, while the next epoch rebuilds that same
//!   committee under its OWN version. At the single activation boundary the
//!   producing and consuming sides therefore disagree about the name basis
//!   (BLS vs consensus key) of one and the same committee. An earlier,
//!   version-gated flip attempt wedged reconfiguration on exactly this
//!   asymmetry and was reverted; see
//!   `dev-docs/plans/authority-name-consensus-key.md` and the
//!   `consensus_key_authority_names` flag definition.
//! - Every `AuthorityName`-keyed structure crosses with it: committee maps,
//!   handoff attestation items, the off-chain mpc_data announcement/freeze
//!   pipeline, consensus-message attribution.
//!
//! What a green run proves, and a wedge would deny:
//!
//! 1. **The upgrade actually happens.** `expect_protocol_version_at_least(6)`
//!    after the boundary — without it a silent stay-at-v5 would make every
//!    later assertion pass while testing nothing (the flip never occurs).
//! 2. **The boundary reshare converges.** The epoch that activates v6 must
//!    complete its network-key reconfiguration, with byte-identical outputs
//!    and zero malicious reports — a name-basis disagreement across the
//!    boundary shows up first as a stuck or diverging reshare.
//! 3. **The committee survives intact.** No member is dropped by failing to
//!    resolve under the other basis (`expect_committee_size(4)`).
//! 4. **Users keep being served** across the flip, on state (RocksDB, network
//!    key) created by the literal v1.2.5 release under BLS-basis names.
//!
//! Genesis is protocol v5 (`ProtocolVersion::MIN`), which the deployed
//! v1.2.5 release supports; the current build advertises `MIN..=MAX` = 5..=6,
//! so once the whole committee runs it, the capability vote carries the
//! network to v6.
//!
//! Opt-in (real binaries + long-running), via `RUN_V125_V6_UPGRADE=1`:
//!
//! ```bash
//! # OLD_BIN: an ika-validator built at the release/mainnet-v1.2.5 tag
//! RUN_V125_V6_UPGRADE=1 \
//!   OLD_BIN=/path/to/ika-validator-v1.2.5 \
//!   NEW_BIN=target/release/ika-validator \
//!   NOTIFIER_BIN=target/release/ika-notifier \
//!   IKA_BIN=target/release/ika \
//!   SUI_BIN=$(which sui) \
//!   cargo test --release -p ika-upgrade-test --test v125_v6_upgrade -- --nocapture
//! ```

use std::path::PathBuf;
use std::time::Duration;

use ika_swarm_config::sui_client::GenesisGlobalPresignConfig;
use ika_upgrade_test::binary::BinarySpec;
use ika_upgrade_test::scenario::Scenario;

fn bin_from_env(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

#[tokio::test(flavor = "multi_thread")]
async fn v125_upgrade_activates_v6_and_flips_authority_names() {
    if std::env::var("RUN_V125_V6_UPGRADE").is_err() {
        eprintln!(
            "skipping: set RUN_V125_V6_UPGRADE=1 \
             (needs OLD_BIN/NEW_BIN/NOTIFIER_BIN/IKA_BIN/SUI_BIN)"
        );
        return;
    }
    let _guard = telemetry_subscribers::TelemetryConfig::new()
        .with_log_level("info")
        .with_env()
        .init();

    let old = BinarySpec::Path(bin_from_env(
        "OLD_BIN",
        "/tmp/ika-v125/target/release/ika-validator",
    ));
    let current = BinarySpec::Path(bin_from_env("NEW_BIN", "target/release/ika-validator"));
    let notifier = bin_from_env("NOTIFIER_BIN", "target/release/ika-notifier");
    let ika_cli = bin_from_env("IKA_BIN", "target/release/ika");
    let sui = bin_from_env("SUI_BIN", "sui");
    let repo = std::env::current_dir()
        .expect("cwd")
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf();
    let base = PathBuf::from(
        std::env::var("UPGRADE_TEST_DIR")
            .unwrap_or_else(|_| "/mnt/nvme0n1p1/tmp/ika-v125-v6-upgrade".to_string()),
    );
    let _ = std::fs::remove_dir_all(&base);
    let epoch_duration_ms = std::env::var("EPOCH_DURATION_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(600_000);
    assert!(
        epoch_duration_ms >= 480_000,
        "the v6 upgrade rehearsal requires an epoch of at least 480000ms so the bounded \
         sequential restarts complete before the mid-epoch reconfiguration"
    );

    // Validator 0 observes output-digest convergence: it records every
    // authority's consensus-submitted reconfiguration output, so a peer whose
    // bytes diverge across the name-basis boundary is caught, not just a
    // local failure.
    let observer = [0];

    Scenario::new(4, repo, sui, notifier)
        .with_base_dir(base)
        .with_epoch_duration_ms(epoch_duration_ms)
        .with_epoch_timeout(Duration::from_secs(1200))
        .with_genesis_global_presign_config(GenesisGlobalPresignConfig::Full)
        .with_ika_cli(ika_cli)
        .start_all(old)
        // Epoch 2 guarantees the all-v1.2.5 committee completed the genesis
        // network DKG at v5 and crossed a reconfiguration boundary, so the
        // state the current build inherits was written under BLS-basis names.
        .wait_for_epoch(2)
        .wait_for_all_validators_local_epoch(2)
        .expect_all_validators_healthy()
        .expect_protocol_version_at_most(5)
        // A user lifecycle on the literal v1.2.5 release, leaving behind
        // dWallets created while identities were BLS-derived.
        .run_workload("v125-at-v5-pre-flip")
        // Prove the reshare has not started, so the swap is not racing MPC.
        .expect_network_key_reconfiguration_not_started(2)
        // ── Full committee swap: every validator moves to the current build. ─
        .stop_and_swap(&[0, 1, 2, 3], current)
        .expect_all_validators_healthy()
        .wait_for_all_validators_local_epoch(2)
        // With n=4 the default 50% buffer stake requires all four capability
        // votes at the tally, and a fresh capability can land just after it;
        // drop to a bare quorum so the upgrade is not left to timing.
        .set_buffer_stake(0)
        // The pre-activation window: the whole committee runs the current
        // build but the network is still at v5, so names are still BLS-basis.
        // Pinning it makes an early vote fail loudly instead of silently
        // voiding this window's purpose.
        .expect_protocol_version_at_most(5)
        .run_workload("current-build-pre-activation-at-v5")
        .expect_protocol_version_at_most(5)
        // ── The boundary: capability vote carries the network v5 -> v6, and
        //    with it every validator's committee identity flips from the BLS
        //    protocol key to the zero-padded Ed25519 consensus key. ──────────
        .wait_for_epoch(3)
        .wait_for_all_validators_local_epoch(3)
        .expect_all_validators_healthy()
        // THE load-bearing assertion: without it the whole scenario passes
        // vacuously if the network simply stays at v5 and never flips.
        .expect_protocol_version_at_least(6)
        // No member may be lost to a name that fails to resolve under the
        // other basis.
        .expect_committee_size(4)
        // The reshare executed ACROSS the flip must converge byte-identically
        // with zero malicious reports — the first thing a producer/consumer
        // name-basis disagreement would break.
        .wait_for_network_key_reconfiguration_started(3)
        .wait_for_network_key_reconfiguration_completed(3)
        .expect_all_validators_healthy()
        .wait_for_all_validators_local_epoch(3)
        .expect_network_key_output_converged(&observer)
        .expect_malicious_actors_exactly(&observer, 0)
        .expect_no_pending_network_key_reconfiguration(3, &observer)
        .expect_network_dkg_output_version_at_least(4)
        .expect_reconfiguration_output_version_at_least(4)
        .expect_log_line_absent("node recognized itself as malicious")
        .expect_log_line_absent("recognized_self_as_malicious")
        // Users must keep being served immediately after the flip, on the
        // v1.2.5-origin network key.
        .run_workload("post-flip-at-v6")
        // A second boundary entirely inside v6: proves the first crossing was
        // not a one-off and that steady-state reconfiguration works with
        // consensus-key identities on both sides.
        .wait_for_epoch(4)
        .wait_for_all_validators_local_epoch(4)
        .expect_all_validators_healthy()
        .expect_protocol_version_at_least(6)
        .expect_committee_size(4)
        .wait_for_network_key_reconfiguration_started(4)
        .wait_for_network_key_reconfiguration_completed(4)
        .expect_all_validators_healthy()
        .wait_for_all_validators_local_epoch(4)
        .expect_network_key_output_converged(&observer)
        .expect_malicious_actors_exactly(&observer, 0)
        .expect_no_pending_network_key_reconfiguration(4, &observer)
        .run_workload("steady-state-at-v6")
        // Whole-run backstops: a late diverging output or a consensus
        // submission failure is a hard failure even if every polled gate
        // above happened to pass.
        .expect_log_line_absent("late network-key reconfiguration output DIVERGES")
        .expect_log_line_absent("failed to submit an MPC output message to consensus")
        .run()
        .await
        .expect(
            "literal v1.2.5 committee must upgrade to protocol v6, flip authority names to \
             the consensus key, and keep converging and serving across the boundary",
        );

    tracing::info!(
        "v125 -> v6 upgrade PASSED: literal v1.2.5 committee crossed v5 -> v6, authority \
         names flipped to the consensus key, both boundary and steady-state reshares \
         converged, and users were served throughout"
    );
}
