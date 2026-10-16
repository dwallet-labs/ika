// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Upgrade one validator during an identified network-key reconfiguration.
//! OLD must have contributed rounds one and two, but not round three. NEW
//! reopens the same database and must contribute to that same session. The
//! fourth validator stays suspended until completion, preventing an OLD-only
//! quorum from hiding an upgraded spectator. See the cross-binary-upgrade spec.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use ika_protocol_config::ProtocolVersion;
use ika_types::supported_protocol_versions::SupportedProtocolVersions;
use ika_upgrade_test::cluster::ClusterBuilder;
use ika_upgrade_test::mid_session_upgrade::verify_mid_session_upgrade;

fn binary_from_env(name: &str) -> Result<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .with_context(|| format!("{name} must identify the separately built binary"))
}

#[tokio::test(flavor = "multi_thread")]
async fn old_to_new_validator_participates_in_the_same_running_session() -> Result<()> {
    if std::env::var("RUN_V141_MID_SESSION").is_err() {
        eprintln!("skipping: set RUN_V141_MID_SESSION=1 to run the real-crypto upgrade test");
        return Ok(());
    }
    let _guard = telemetry_subscribers::TelemetryConfig::new()
        .with_log_level("info")
        .with_env()
        .init();
    ensure!(
        std::env::var("USE_MOCKS").as_deref() != Ok("true"),
        "mid-session binary upgrades require real cryptography"
    );
    let old = binary_from_env("OLD_BIN")?;
    let new = binary_from_env("NEW_BIN")?;
    ensure!(old != new, "OLD and NEW must be separate binary paths");
    let base = PathBuf::from(
        std::env::var("UPGRADE_TEST_DIR")
            .unwrap_or_else(|_| "/tmp/ika-v141-mid-session".to_string()),
    );
    if base.exists() {
        std::fs::remove_dir_all(&base).context("clear previous scenario data")?;
    }
    let epoch_duration_ms = std::env::var("EPOCH_DURATION_MS")
        .ok()
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(600_000);
    ensure!(
        epoch_duration_ms == 600_000,
        "mid-session upgrade uses 600000ms epochs to keep bounded process pauses below the watchdog"
    );
    let timeout = Duration::from_secs(600);
    let mut cluster = ClusterBuilder::new(
        old,
        binary_from_env("NOTIFIER_BIN")?,
        binary_from_env("SUI_BIN")?,
    )
    .with_num_validators(4)
    .with_base_dir(base)
    .with_epoch_duration_ms(epoch_duration_ms)
    .with_genesis_protocol_version(ProtocolVersion::new(7))
    .with_supported_protocol_versions(SupportedProtocolVersions::new_for_testing(7, 7))
    .build()
    .await?;

    cluster.wait_for_epoch(2, Duration::from_secs(1200)).await?;
    cluster
        .wait_for_all_validators_local_epoch(2, timeout)
        .await?;
    cluster.expect_all_validators_healthy().await?;
    ensure!(
        cluster.current_protocol_version().await? == 7,
        "expected protocol v7"
    );
    cluster
        .expect_network_key_reconfiguration_not_started(2)
        .await?;

    // The negative control deliberately withholds NEW and lets the three OLD
    // peers finish. The same-session participation assertion must reject it.
    let participation_control =
        std::env::var("MID_SESSION_PARTICIPATION_CONTROL").as_deref() == Ok("true");
    verify_mid_session_upgrade(&mut cluster, new, 2, timeout, participation_control).await?;
    cluster
        .wait_for_network_key_reconfiguration_completed(2, timeout)
        .await?;
    cluster
        .wait_for_all_validators_local_epoch(2, timeout)
        .await?;
    cluster.expect_all_validators_healthy().await?;
    cluster
        .expect_malicious_actors_exactly(&[0, 1, 2, 3], 0)
        .await?;
    tracing::info!(
        "v141_mid_session PASSED: OLD rounds one/two and NEW round three completed the same \
         session with the upgraded validator's accepted output required for quorum"
    );
    Ok(())
}
