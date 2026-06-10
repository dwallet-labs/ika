// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Cross-binary rolling upgrade **with per-epoch committee churn**: boot a
//! 4-validator committee on an OLD binary that supports only protocol v3,
//! then across consecutive epochs (committee size 4 → 3 → 5 → 4):
//!
//! - remove a validator and swap every remaining one to the NEW binary
//!   (`dev`, supports v3..=v4) — the capability vote advances v3 -> v4 at the
//!   same boundary the committee shrinks to 3;
//! - join two brand-new validators (full candidate → stake → activate flow,
//!   their class-groups keys registered on-chain) — the v4 reshare encrypts
//!   shares to a 5-member committee that includes parties which never held
//!   the key;
//! - remove one of the original validators — a final reshare from 5 back
//!   down to 4 members.
//!
//! Every epoch boundary after the first is therefore a *real* reshare to a
//! different party set, which is the strongest exercise of reconfiguration:
//! mixed-binary committees process each other's consensus + MPC messages
//! (wire compat), a validator restarts on a new binary against its old
//! RocksDB (on-disk compat), the vote fires at the right moment, and
//! committee membership changes land at every boundary.
//!
//! A full DKG → Presign → Sign dWallet lifecycle runs once on the OLD binary
//! at v3 and once on the NEW binary at v4 (5-member committee), and the MPC
//! duration metrics are snapshotted after each so the run ends with a rough
//! per-protocol timing comparison (see `mpc_timings`; informational, flagged
//! not asserted — wall-clock on a loaded developer machine is noisy).
//!
//! Genesis is v3 — the only version both binaries support, and the only
//! supported path anyway (a v4 *genesis* DKG is rejected forever; the network
//! must upgrade into v4).
//!
//! On the OLD binary: the literal `mainnet-v1.1.8` ika-node is **not** usable
//! here — it links `class_groups` from `dwallet-labs/inkrypto` while `dev` links
//! `dwallet-labs/cryptography-private`, and v4 changed the on-chain
//! validator-key shape, so a v1.1.8 node cannot parse dev-registered keys (it
//! panics in `verify_validator_keys`). That incompatibility is itself a finding:
//! the real v1.1.8 -> dev upgrade is not a naive binary swap (it needs the
//! dual-pin / backward-compatible handling from `docs/plan-update-crypto-latest.md`).
//! To exercise a *successful* heterogeneous upgrade we use an OLD binary that
//! shares dev's crypto but is pinned to `MAX_PROTOCOL_VERSION = 3` (a one-line
//! build of dev) — genuinely a different compiled binary, differing only in the
//! protocol version it advertises, which is the realistic minimal upgrade.
//!
//! Opt-in (real binaries + long-running), via `RUN_CROSS_BINARY=1`:
//!
//! ```bash
//! # OLD_BIN: a dev build with MAX_PROTOCOL_VERSION patched to 3
//! RUN_CROSS_BINARY=1 \
//!   OLD_BIN=/path/to/ika-validator-max3 \
//!   NEW_BIN=target/release/ika-validator \
//!   NOTIFIER_BIN=target/release/ika-notifier \
//!   IKA_BIN=target/release/ika \
//!   SUI_BIN=$(which sui) \
//!   cargo test --release -p ika-upgrade-test --test cross_binary -- --nocapture
//! ```

use std::path::PathBuf;

use std::time::Duration;

use ika_upgrade_test::binary::BinarySpec;
use ika_upgrade_test::scenario::Scenario;

fn bin_from_env(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

#[tokio::test(flavor = "multi_thread")]
async fn cross_binary_rolling_upgrade_with_committee_churn() {
    if std::env::var("RUN_CROSS_BINARY").is_err() {
        eprintln!(
            "skipping: set RUN_CROSS_BINARY=1 (needs OLD_BIN/NEW_BIN/NOTIFIER_BIN/IKA_BIN/SUI_BIN)"
        );
        return;
    }
    let _guard = telemetry_subscribers::TelemetryConfig::new()
        .with_log_level("info")
        .with_env()
        .init();

    let old = BinarySpec::Path(bin_from_env("OLD_BIN", "target/release/ika-node"));
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
            .unwrap_or_else(|_| "/mnt/nvme0n1p1/tmp/ika-cross-binary".to_string()),
    );
    let _ = std::fs::remove_dir_all(&base);

    // 5-minute epochs: long enough that a swap-all + joiner registrations +
    // a dWallet lifecycle each fit comfortably before their epoch's
    // mid-epoch reconfiguration MPC window, short enough that the 5-epoch
    // run stays tractable. (The notifier stale-gas wedge that once forced
    // 10-minute epochs is fixed on this branch; the 3-minute workload test
    // is the floor evidence.)
    Scenario::new(4, repo, sui, notifier)
        .with_base_dir(base)
        .with_epoch_duration_ms(300_000)
        .with_epoch_timeout(Duration::from_secs(1200))
        // The committee dips to 3 after the first removal; the protocol
        // default min_validator_count = 4 would reject it at genesis.
        .with_min_validator_count(3)
        .with_ika_cli(ika_cli)
        .start_all(old)
        // The genesis network DKG runs *during* epoch 1; the epoch cannot
        // advance to 2 until it completes (reconfiguration into epoch 2
        // reshares that key). Waiting for epoch 2 therefore guarantees the
        // OLD binary finished the genesis DKG — the NEW binaries will inherit
        // a completed key and exercise a *reshare*, not an interrupted DKG.
        .wait_for_epoch(2)
        // dWallet lifecycle on the OLD binary at v3 — the timing baseline.
        .run_workload("old-binary-v3")
        .record_mpc_timings("old-binary-v3")
        // Validator 3 leaves the committee at the epoch-3 boundary...
        .remove_validator(3)
        // ...and everyone (including 3, which is still a committee member
        // until the boundary) swaps to the NEW binary.
        .stop_and_swap(&[0, 1, 2, 3], new.clone())
        // With n=4 the default 50% buffer stake rounds up to requiring all
        // four votes; the swap can leave one validator's fresh capability
        // uncommitted at the epoch-boundary tally, so drop the buffer to a
        // bare quorum (the realistic behavior on larger committees).
        .set_buffer_stake(0)
        // Boundary 2->3: protocol v3 -> v4 AND committee 4 -> 3 in one
        // reconfiguration.
        .wait_for_epoch(3)
        .expect_protocol_version_at_least(4)
        .expect_committee_size(3)
        // Out of the committee since the boundary; now safe to stop.
        .stop_validator(3)
        // Two brand-new validators join: candidate -> stake -> activate, node
        // spawned on the NEW binary. Active at the epoch-4 boundary — the
        // reshare into epoch 4 must encrypt shares to a 5-member committee
        // including two parties that never held the key.
        .join_validator(new.clone())
        .join_validator(new)
        .wait_for_epoch(4)
        .expect_committee_size(5)
        // dWallet lifecycle on the NEW binary at v4 with the churned
        // committee, then the comparison snapshot.
        .run_workload("new-binary-v4")
        .record_mpc_timings("new-binary-v4")
        // One more boundary with churn: an original validator leaves, the
        // committee reshapes 5 -> 4 (both joiners stay).
        .remove_validator(0)
        .wait_for_epoch(5)
        .expect_committee_size(4)
        .stop_validator(0)
        .run()
        .await
        .expect("cross-binary rolling upgrade with committee churn");

    tracing::info!(
        "cross-binary PASSED: v3 -> v4 with committee churn 4 -> 3 -> 5 -> 4 and timing report"
    );
}
