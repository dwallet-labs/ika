// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Literal mainnet-v1.1.8 upgrade rehearsal **with post-upgrade committee
//! churn**: boot a 4-validator committee on the actual `mainnet-v1.1.8`
//! `ika-node` binary at protocol v3, swap **all validators atomically** to the
//! local build and confirm the upgrade to v4 — then, on the now all-local
//! committee, **join a brand-new validator** (candidate → stake → activate) so
//! the v4 reshare encrypts the network key (originally DKG'd by 1.1.8's crypto)
//! to a 5-member committee that includes a party which never held it.
//!
//! This combines what `v118_upgrade` and `cross_binary` cover separately: the
//! real 1.1.8 → v4 on-disk + crypto continuity (`v118_upgrade`) AND a
//! committee-churn reshare that exercises the OCS joiner trust-anchor path
//! (`cross_binary`'s `add_joiner_validator`, which seeds the joiner's
//! `sui_unsafe_genesis_committee` so a v4/OCS validator boots).
//!
//! The churn runs **only after** the atomic swap, so every validator is the
//! local build — there is never a mixed 1.1.8/local committee. That is
//! required: this branch single-pins `cryptography-private`, so mixed
//! committees can't exchange MPC messages; the swap must be atomic, and any
//! churn must follow it. (A *rolling* 1.1.8 swap — `cross_binary` from 1.1.8 —
//! is therefore invalid; this scenario is how to get churn from a 1.1.8
//! origin.)
//!
//! Opt-in, via `RUN_V118_CHURN=1` (same binaries as `v118_upgrade`):
//!
//! ```bash
//! RUN_V118_CHURN=1 \
//!   OLD_BIN=/tmp/ika-v118/target/release/ika-node \
//!   NEW_BIN=target/release/ika-validator \
//!   NOTIFIER_BIN=target/release/ika-notifier \
//!   IKA_BIN=target/release/ika \
//!   SUI_BIN=$(which sui) \
//!   cargo test --release -p ika-upgrade-test --test v118_churn -- --nocapture
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
async fn v118_atomic_upgrade_then_committee_churn() {
    if std::env::var("RUN_V118_CHURN").is_err() {
        eprintln!(
            "skipping: set RUN_V118_CHURN=1 (needs OLD_BIN/NEW_BIN/NOTIFIER_BIN/IKA_BIN/SUI_BIN)"
        );
        return;
    }
    let _guard = telemetry_subscribers::TelemetryConfig::new()
        .with_log_level("info")
        .with_env()
        .init();

    let old = BinarySpec::Path(bin_from_env(
        "OLD_BIN",
        "/tmp/ika-v118/target/release/ika-node",
    ));
    let new = BinarySpec::Path(bin_from_env("NEW_BIN", "target/release/ika-validator"));
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
            .unwrap_or_else(|_| "/mnt/nvme0n1p1/tmp/ika-v118-churn".to_string()),
    );
    let _ = std::fs::remove_dir_all(&base);

    // Longer epochs give a loaded CI runner slack to finish each epoch's crypto
    // before the boundary; override via `EPOCH_DURATION_MS`.
    let epoch_duration_ms = std::env::var("EPOCH_DURATION_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300_000);

    Scenario::new(4, repo, sui, notifier)
        .with_base_dir(base)
        .with_epoch_duration_ms(epoch_duration_ms)
        .with_epoch_timeout(Duration::from_secs(1200))
        .with_ika_cli(ika_cli)
        // OCS read topology: keep validators 0 and 1 on the direct gRPC path
        // (serving the SuiStateMirror relay); flip validators 2 and 3 to
        // peer-only SuiStateMirrored at the atomic swap and bring the joiner up
        // mirrored, all reading verified Sui state through 0 and 1. The split
        // materializes at the 1.1.8->local swap (the 1.1.8 phase stays direct on
        // legacy JSON-RPC), giving a stable 5-member committee of 2 direct + 3
        // mirrored. SUI_STATE_DIRECT_COUNT=1 narrows the relay set to validator 0.
        .with_direct_validators(&[0, 1])
        // Mainnet-faithful on-chain state (populated global-presign config).
        .with_genesis_global_presign_config(GenesisGlobalPresignConfig::Full)
        // Boot the literal 1.1.8 committee at v3; epoch 2 guarantees the genesis
        // network DKG (1.1.8 crypto) completed before the swap.
        .start_all(old)
        .wait_for_epoch(2)
        // ATOMIC swap every validator to the local build (rolling is impossible
        // on this branch's single crypto pin). The local v4 binaries inherit
        // and reshare the completed 1.1.8-crypto network key.
        .stop_and_swap(&[0, 1, 2, 3], new.clone())
        // n=4: drop the buffer to a bare quorum so the capability vote tallies.
        .set_buffer_stake(0)
        .wait_for_epoch(3)
        .expect_protocol_version_at_least(4)
        .expect_committee_size(4)
        // The churn under test: all validators are now the local build (no mixed
        // committee), so a brand-new local validator can join. The v4 reshare
        // encrypts the 1.1.8-origin network key to a 5-member committee that
        // includes a party which never held it, and the joiner boots on the OCS
        // gRPC path — which refuses to start without a Sui trust anchor; the
        // harness seeds it in `add_joiner_validator` (the path this scenario
        // exists to exercise from a real 1.1.8 origin). The joiner comes up
        // peer-only mirrored, reading verified Sui state through 0 and 1.
        .join_validator_mirrored(new.clone())
        .wait_for_epoch(4)
        .expect_committee_size(5)
        // The new 5-member committee runs a full lifecycle against the reshared
        // 1.1.8-origin network key.
        .run_workload("v4-with-joiner")
        .record_mpc_timings("v4-with-joiner")
        .run()
        .await
        .expect("v1.1.8 -> local atomic upgrade + committee churn");

    tracing::info!(
        "v118 churn rehearsal PASSED: mainnet-v1.1.8 -> local, v3 -> v4, joiner added to a \
         5-member committee resharing the 1.1.8-origin network key"
    );
}
