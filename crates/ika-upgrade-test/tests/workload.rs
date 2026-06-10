// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! End-to-end workload check: bring up a single-binary cluster at protocol v3,
//! upgrade it to v4 through the capability vote, then drive a full
//! **DKG → Presign → Sign** dWallet lifecycle (via the `ika` CLI) and confirm
//! a signature is produced on-chain. Proves the session-lifecycle invariant
//! the upgrade harness depends on — sessions started in an epoch actually
//! complete — independently of the cross-binary scenario.
//!
//! Genesis is v3, never v4: at v4 the network DKG needs PVSS keys which only
//! arrive through the off-chain assembly, and that assembly is
//! next-committee-only — so a v4 *genesis* DKG is rejected forever (4/4
//! class-groups keys, 0/4 PVSS). The supported path is genesis v3 → upgrade
//! into v4, which is also the path mainnet takes.
//!
//! Opt-in via `RUN_WORKLOAD_TEST=1`:
//!
//! ```bash
//! RUN_WORKLOAD_TEST=1 \
//!   IKA_VALIDATOR_BIN=target/release/ika-validator \
//!   IKA_NOTIFIER_BIN=target/release/ika-notifier \
//!   IKA_BIN=target/release/ika \
//!   SUI_BIN=$(which sui) \
//!   cargo test --release -p ika-upgrade-test --test workload -- --nocapture
//! ```

use std::path::PathBuf;
use std::time::Duration;

use ika_protocol_config::ProtocolVersion;
use ika_upgrade_test::cluster::ClusterBuilder;
use ika_upgrade_test::workload::WorkloadDriver;

fn bin_from_env(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

#[tokio::test(flavor = "multi_thread")]
async fn workload_dkg_presign_sign() {
    if std::env::var("RUN_WORKLOAD_TEST").is_err() {
        eprintln!("skipping: set RUN_WORKLOAD_TEST=1 to run the workload driver test");
        return;
    }
    let _guard = telemetry_subscribers::TelemetryConfig::new()
        .with_log_level("info")
        .with_env()
        .init();

    let validator = bin_from_env("IKA_VALIDATOR_BIN", "target/release/ika-validator");
    let notifier = bin_from_env("IKA_NOTIFIER_BIN", "target/release/ika-notifier");
    let ika_cli = bin_from_env("IKA_BIN", "target/release/ika");
    let sui = bin_from_env("SUI_BIN", "sui");
    let base = PathBuf::from(
        std::env::var("UPGRADE_TEST_DIR")
            .unwrap_or_else(|_| "/mnt/nvme0n1p1/tmp/ika-workload-test".to_string()),
    );
    let _ = std::fs::remove_dir_all(&base);

    let cluster = ClusterBuilder::new(validator, notifier, sui)
        .with_num_validators(4)
        // Genesis at v3 (MIN), never v4 — see module docs. The binary supports
        // v3..=v4 and advertises v4 capability from the start, so the vote
        // advances the version at an epoch boundary once the buffer-stake
        // override below lets it tally at bare quorum.
        .with_genesis_protocol_version(ProtocolVersion::MIN)
        // 3-minute epoch: at v3 the genesis network DKG is not gated on the
        // off-chain mpc_data freeze (that gating is v4-only), so the epoch
        // only needs to clear validator bring-up + announcement recording
        // (~90s) plus the DKG itself; the dWallet lifecycle must fit inside
        // a post-upgrade epoch before its own reconfiguration window.
        .with_epoch_duration_ms(180_000)
        .with_base_dir(base)
        .build()
        .await
        .expect("cluster bring-up");

    // Wait for epoch 2, not 1. Epoch 1 is genesis and is reached immediately,
    // *before* the network DKG runs — so the DKG output isn't on-chain yet and
    // the CLI can't derive protocol parameters. The epoch counter advancing to
    // 2 is itself the completion signal: reconfiguration into epoch 2 reshares
    // the genesis key, which can't happen until the genesis DKG finished. So
    // reaching epoch 2 guarantees the v3 network key is readable.
    cluster
        .wait_for_epoch(2, Duration::from_secs(900))
        .await
        .expect("reach epoch 2 (genesis network DKG + reshare done at v3)");

    // With n=4 the default 50% buffer stake rounds the capability-vote
    // threshold up to all four validators; a single lagging capability
    // registration then blocks the upgrade forever. Drop the buffer to a bare
    // quorum (the realistic behavior on larger committees) so the v3->v4 vote
    // tallies at the next epoch boundary.
    let epoch = cluster.current_epoch().await.expect("read current epoch");
    for proc in &cluster.validators {
        proc.set_buffer_stake(epoch, 0)
            .await
            .unwrap_or_else(|e| panic!("set buffer stake on validator {}: {e}", proc.index));
    }

    cluster
        .wait_for_epoch(3, Duration::from_secs(600))
        .await
        .expect("reach epoch 3 (crossing the v3->v4 upgrade boundary)");

    let protocol_version = cluster
        .current_protocol_version()
        .await
        .expect("read protocol version");
    assert!(
        protocol_version >= 4,
        "expected protocol v4 after the upgrade boundary, got v{protocol_version}"
    );

    let driver = WorkloadDriver::new(
        ika_cli,
        cluster.rpc_url().to_string(),
        cluster.faucet_url().to_string(),
        cluster.network_config().clone(),
        cluster.publisher_keypair().copy(),
    )
    .await
    .expect("build workload driver");

    // Debug aid: hold the cluster up and print config paths so `ika dwallet`
    // can be driven manually (fast iteration vs. ~6-min test cycles).
    if std::env::var("HOLD_CLUSTER").is_ok() {
        eprintln!("HOLD_CLUSTER: cluster up. Run e.g.:");
        eprintln!(
            "  ika --json --client.config {} --ika-config {} dwallet create --curve secp256k1 --output-secret /tmp/s.bin",
            driver.client_config_path().display(),
            driver.ika_config_path().display(),
        );
        eprintln!("user_address={}", driver.user_address());
        tokio::time::sleep(Duration::from_secs(3600)).await;
        return;
    }

    let outcome = driver
        .run_dwallet_lifecycle()
        .await
        .expect("DKG -> Presign -> Sign lifecycle completes on-chain");

    assert!(
        !outcome.sign_digest.is_empty(),
        "sign produced a transaction digest"
    );
    tracing::info!(
        dwallet_id = %outcome.dwallet_id,
        sign_digest = %outcome.sign_digest,
        "workload PASSED: DKG -> Presign -> Sign completed on-chain"
    );
}
