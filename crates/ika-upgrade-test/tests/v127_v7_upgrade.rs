// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Literal v1.2.7 -> current PROTOCOL upgrade rehearsal: the gate for
//! activating protocol v7, where `AuthorityName` stops being serialized as
//! the Ed25519 consensus key zero-padded into a 48-byte container and starts
//! being serialized as the raw 32 bytes (`short_authority_names`).
//!
//! Its sibling `v127_rollout` is a pure BINARY swap that stays at protocol v6
//! throughout; this scenario is the counterpart that deliberately crosses the
//! VERSION boundary, because that crossing is the one thing the width flip
//! cannot be assumed safe across. Decode tolerance does not make it safe:
//! every deployed binary has accepted BOTH widths since v1.2.7, yet signature
//! and digest bytes are reconstructed by RE-SERIALIZING locally, so what
//! matters is that all validators EMIT the same width — which is precisely
//! what the version boundary coordinates and what this test exercises.
//!
//! Everything `AuthorityName`-keyed crosses with it: the capability messages
//! that carry the vote itself, handoff attestation items, the off-chain
//! mpc_data announcement/freeze pipeline, consensus-message attribution, and
//! ten MPC message types that must reach byte-identical quorum.
//!
//! This is the OUT-OF-PROCESS half of the gate, and the half that matters
//! most for this particular flip: the emitted width is process-wide state
//! (`AUTHORITY_NAME_SHORT_ENCODING`), so only real, separately-compiled
//! validator processes flip independently the way a fleet does. The
//! in-process `protocol_version_transition` cluster test shares one global
//! across all four simulated validators and therefore cannot show a genuine
//! per-validator disagreement.
//!
//! What a green run proves, and a wedge would deny:
//!
//! 1. **The upgrade actually happens.** `expect_protocol_version_at_least(7)`
//!    after the boundary — without it a silent stay-at-v6 would make every
//!    later assertion pass while testing nothing (the flip never occurs).
//! 2. **The boundary reshare converges.** The epoch that activates v7 must
//!    complete its network-key reconfiguration, with byte-identical outputs
//!    and zero malicious reports — a width disagreement across the boundary
//!    shows up first as a stuck or diverging reshare.
//! 3. **The committee survives intact** (`expect_committee_size(4)`): no
//!    member is dropped because its name failed to resolve.
//! 4. **The cross-epoch handoff cert survives the flip.** The cert is signed
//!    at the end of the last v6 epoch, under the padded encoding, and
//!    verified by the first v7 epoch, which emits the short one. This is the
//!    single most likely place for the flip to wedge, and the dual-width
//!    retry in `verify_certified_handoff_attestation` is what makes it work.
//! 5. **Users keep being served** across the flip, on state (RocksDB, network
//!    key) created by the literal v1.2.7 release.
//! 6. **A restart after the flip re-joins as a member.** One validator is
//!    rebooted after activation, so it derives its startup identity and
//!    reads its persisted state under the new width, then carries its duties
//!    across the next epoch boundary.
//!
//! Genesis is protocol v6 (`ProtocolVersion::MIN`), which the deployed
//! v1.2.7 release supports (it advertises 5..=6); the current build
//! advertises 6..=7, so once the whole committee runs it, the capability vote
//! carries the network to v7.
//!
//! Opt-in (real binaries + long-running), via `RUN_V127_V7_UPGRADE=1`:
//!
//! ```bash
//! # OLD_BIN: an ika-validator built at the release/mainnet-v1.2.7 tag
//! RUN_V127_V7_UPGRADE=1 \
//!   OLD_BIN=/path/to/ika-validator-v1.2.7 \
//!   NEW_BIN=target/release/ika-validator \
//!   NOTIFIER_BIN=target/release/ika-notifier \
//!   IKA_BIN=target/release/ika \
//!   SUI_BIN=$(which sui) \
//!   cargo test --release -p ika-upgrade-test --test v127_v7_upgrade -- --nocapture
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
async fn v127_upgrade_activates_v7_and_shortens_authority_names() {
    if std::env::var("RUN_V127_V7_UPGRADE").is_err() {
        eprintln!(
            "skipping: set RUN_V127_V7_UPGRADE=1 \
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
        "/tmp/ika-v127/target/release/ika-validator",
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
            .unwrap_or_else(|_| "/mnt/nvme0n1p1/tmp/ika-v127-v7-upgrade".to_string()),
    );
    let _ = std::fs::remove_dir_all(&base);
    let epoch_duration_ms = std::env::var("EPOCH_DURATION_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(600_000);
    assert!(
        epoch_duration_ms >= 480_000,
        "the v7 upgrade rehearsal requires an epoch of at least 480000ms so the bounded \
         sequential restarts complete before the mid-epoch reconfiguration"
    );

    // Validator 0 observes output-digest convergence: it records every
    // authority's consensus-submitted reconfiguration output, so a peer whose
    // bytes diverge across the encoding-width boundary is caught, not just a
    // local failure.
    let observer = [0];

    Scenario::new(4, repo, sui, notifier)
        .with_base_dir(base)
        .with_epoch_duration_ms(epoch_duration_ms)
        .with_epoch_timeout(Duration::from_secs(1200))
        .with_genesis_global_presign_config(GenesisGlobalPresignConfig::Full)
        .with_ika_cli(ika_cli)
        .start_all(old)
        // Epoch 2 guarantees the all-v1.2.7 committee completed the genesis
        // network DKG at v6 and crossed a reconfiguration boundary, so the
        // state the current build inherits was written at the padded width.
        .wait_for_epoch(2)
        .wait_for_all_validators_local_epoch(2)
        .expect_all_validators_healthy()
        .expect_protocol_version_at_most(6)
        // Checked BEFORE the workload below: the reshare must not have
        // started when the swap begins, and a workload takes minutes, so
        // asserting this after it would race the epoch's own reconfiguration.
        .expect_network_key_reconfiguration_not_started(2)
        // A user lifecycle on the literal v1.2.7 release, leaving behind
        // dWallets created while names were emitted padded — the state that
        // must survive the flip.
        .run_workload("v127-at-v6-pre-flip")
        // ── Full committee swap: every validator moves to the current build. ─
        .stop_and_swap(&[0, 1, 2, 3], current.clone())
        .expect_all_validators_healthy()
        // With n=4 the default 50% buffer stake requires all four capability
        // votes at the tally, and a fresh capability can land just after it;
        // drop to a bare quorum so the upgrade is not left to timing.
        .set_buffer_stake(0)
        // ── The boundary. The capability vote is tallied at an epoch close,
        //    so the exact epoch v7 activates in depends on how much of epoch 2
        //    the sequential restarts consumed. Deliberately NOT asserting a
        //    version at epoch 3: pinning the activation to one specific epoch
        //    would make this gate fail on timing rather than on behavior.
        //    What must hold is that the network gets there and keeps working.
        .wait_for_epoch(3)
        .wait_for_all_validators_local_epoch(3)
        .expect_all_validators_healthy()
        .wait_for_epoch(4)
        .wait_for_all_validators_local_epoch(4)
        .expect_all_validators_healthy()
        // THE load-bearing assertion: by now the vote has been tallied with a
        // bare-quorum buffer and every validator supports v7, so the network
        // MUST have crossed. Without this the whole scenario would pass
        // vacuously on a network that quietly stayed at v6 and never flipped.
        .expect_protocol_version_at_least(7)
        // No member may be lost to a name that fails to resolve at the
        // other width — a silent quorum shrink is the subtle failure here,
        // distinct from an outright wedge (which surfaces as the epoch waits
        // above timing out).
        .expect_committee_size(4)
        // A reshare executed with the short encoding on both sides must
        // converge byte-identically with zero malicious reports. The handoff
        // cert anchoring this epoch was signed at the PADDED width by the
        // outgoing v6 epoch, so this also exercises the dual-width retry in
        // `verify_certified_handoff_attestation`.
        .wait_for_network_key_reconfiguration_started(4)
        .wait_for_network_key_reconfiguration_completed(4)
        .expect_all_validators_healthy()
        .wait_for_all_validators_local_epoch(4)
        .expect_network_key_output_converged(&observer)
        .expect_malicious_actors_exactly(&observer, 0)
        .expect_no_pending_network_key_reconfiguration(4, &observer)
        .expect_network_dkg_output_version_at_least(4)
        .expect_reconfiguration_output_version_at_least(4)
        .expect_log_line_absent("node recognized itself as malicious")
        .expect_log_line_absent("recognized_self_as_malicious")
        // ── Restart-after-flip: reboot one validator (same binary) after
        //    activation. Startup must set the process-wide encoding width
        //    from the epoch it re-enters and read its persisted state back
        //    under it; getting that wrong leaves the node's own name absent
        //    from the committee, booting state-sync in pull mode as a
        //    non-member ("notifier").
        .stop_and_swap(&[1], current)
        .expect_all_validators_healthy()
        // The restarted validator's boot-identity line (its log truncates on
        // restart, so only the post-flip boot is visible) must show it
        // recognized its own committee membership.
        .expect_log_line_present_on_validator(1, "is_state_sync_notifier=false")
        // Users must still be served after the flip, on the v1.2.7-origin
        // network key and against dWallets created before it — with the
        // restarted member back in the committee.
        .run_workload("post-flip-at-v7")
        // Re-joining means carrying duties across the NEXT boundary
        // (mpc_data announcement, freeze, reshare), not merely reporting
        // membership at boot: the epoch cannot advance without the restarted
        // member's participation converging.
        .wait_for_epoch(5)
        .wait_for_all_validators_local_epoch(5)
        .expect_all_validators_healthy()
        // Whole-run backstops: a late diverging output or a consensus
        // submission failure is a hard failure even if every polled gate
        // above happened to pass.
        .expect_log_line_absent("late network-key reconfiguration output DIVERGES")
        .expect_log_line_absent("failed to submit an MPC output message to consensus")
        .run()
        .await
        .expect(
            "literal v1.2.7 committee must upgrade to protocol v7, flip authority names to \
             the consensus key, keep converging and serving across the boundary, and \
             re-admit a restarted validator as a committee member",
        );

    tracing::info!(
        "v125 -> v7 upgrade PASSED: literal v1.2.7 committee crossed v6 -> v7, authority \
         names flipped to the consensus key, both boundary and steady-state reshares \
         converged, users were served throughout, and a validator restarted after the \
         flip re-joined as a committee member (not a notifier) and crossed the next \
         epoch boundary"
    );
}
