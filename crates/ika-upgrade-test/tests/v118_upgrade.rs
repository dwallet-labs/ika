// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Literal mainnet-v1.1.8 upgrade rehearsal: boot a 4-validator committee on
//! the **actual `mainnet-v1.1.8` `ika-node` binary** (built from the tag),
//! run the mainnet user flow at protocol v3, swap **all validators
//! atomically** to the local build, and verify the network upgrades to v4
//! and keeps serving — including through the rollout's presign stall window.
//!
//! ## The mainnet state this reproduces (verified on-chain at epoch 315)
//!
//! - `GlobalPresignConfig` is **populated** — identical to the harness
//!   `GenesisGlobalPresignConfig::Full` maps: every production curve routes
//!   DKG-dWallet presigns to *global* presign (`request_presign` aborts with
//!   `EOnlyGlobalPresignAllowed`; the current `ika` CLI falls back to
//!   `request_global_presign` on that abort). All live mainnet presign
//!   sessions have `dwallet_id: None`.
//! - Regular (DKG) dWallets carry **`UniversalPublicDKGOutput`** (sampled
//!   epochs 129-301); launch-era dWallets (epochs 1-4) carry the legacy
//!   **V1** outer format; **`TargetedPublicDKGOutput`** appears only on
//!   imported-key dWallets.
//! - 1.1.8 validators never see a Universal output in a presign request:
//!   global presigns don't bind a dWallet. (1.1.8 *rejects* Universal
//!   per-dWallet presigns — "Universal DKG output is not supported for v2
//!   non-global presign" — a combination mainnet's config makes unreachable.
//!   An earlier revision of this test genesis'd an *empty* config on the
//!   false premise that that was the mainnet state, which forced the
//!   workload's presign per-dWallet and wedged on exactly that rejection.)
//!
//! ## The pre-activation window (the production-critical moment)
//!
//! At 1.1.8, a global presign request is served as a user-requested MPC
//! session — works at protocol v3. On this branch, global presigns are
//! served from the validators' internal presign pool, which only fills once
//! `internal_presign_sessions` activates at protocol v4. Mainnet upgrades
//! with the config already populated, so the local build *must* keep
//! serving global presigns the 1.1.8 way until v4 activates — which it
//! does: pre-activation, session intake falls through to a user-requested
//! MPC session instead of diverting to the (nonexistent) pool (see
//! `handle_mpc_request` in `mpc_session.rs`). Without that fallback this
//! window is a hard deadlock, not a stall: the diverted request can never
//! complete at v3, `advance_epoch` requires
//! `all_current_epoch_sessions_completed`, so the epoch can never end and
//! v4 can never activate — one in-flight presign at restart would wedge
//! mainnet permanently (an earlier revision of the binary did exactly
//! this, and this test caught it). The rehearsal probes the window
//! directly: a workload launched immediately after the swap, while the
//! network is still at v3 on the local build, must complete its global
//! presign *before* the epoch boundary.
//!
//! What it answers that the `cross_binary` churn test (whose OLD binary is a
//! v3-pin of *this* branch) cannot:
//!
//! - the local binary boots against RocksDB state **written by 1.1.8**
//!   (on-disk format continuity);
//! - the local binary reshares a network key whose DKG output bytes were
//!   **produced by 1.1.8's crypto** — state continuity of the V1 serialized
//!   MPC data, the core mainnet risk;
//! - dWallets created under 1.1.8 remain usable after the swap;
//! - global presigns requested at v3 on the local build are served via the
//!   pre-activation fallback (no deadlock in the upgrade window).
//!
//! The swap is **atomic** (all validators at once), not rolling: this branch
//! single-pins `cryptography-private`, and mixed 1.1.8/local committees
//! cannot exchange MPC messages. The rehearsal mirrors a coordinated
//! full-network restart.
//!
//! Per-component binary choices (each verified against the tag):
//!
//! - **Validators**: 1.1.8 `ika-node` pre-swap. Same `--config-path` CLI,
//!   identical `NodeConfig` YAML (zero field changes since the tag),
//!   identical admin routes, and the harness registers the bare-1.1.8
//!   class-groups key shape on-chain, which 1.1.8 parses. Must be built
//!   `--no-default-features`: the tag's default `enforce-minimum-cpu`
//!   feature panics on <16 cores.
//! - **Notifier**: the *current* `ika-notifier` throughout. At 1.1.8 the
//!   notifier role was `ika-node` + `notifier_client_key_pair`; the wire
//!   surfaces it shares with validators (checkpoint messages, intent scopes
//!   0-3, discovery) are unchanged since the tag, and the harness spawns a
//!   single non-swappable notifier. Not a committee member, so not part of
//!   what the rehearsal exercises.
//! - **Workload CLI**: the *current* `ika` throughout (the 1.1.8 CLI has no
//!   `dwallet` subcommands). Its DKG produces Universal outputs and its
//!   presign falls back to global on `EOnlyGlobalPresignAllowed` — the same
//!   shape mainnet's current user population produces.
//!
//! Opt-in, via `RUN_V118_UPGRADE=1`:
//!
//! ```bash
//! # OLD_BIN: built from the mainnet-v1.1.8 tag with --no-default-features
//! RUN_V118_UPGRADE=1 \
//!   OLD_BIN=/tmp/ika-v118/target/release/ika-node \
//!   NEW_BIN=target/release/ika-validator \
//!   NOTIFIER_BIN=target/release/ika-notifier \
//!   IKA_BIN=target/release/ika \
//!   SUI_BIN=$(which sui) \
//!   cargo test --release -p ika-upgrade-test --test v118_upgrade -- --nocapture
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
async fn v118_atomic_upgrade_to_local_build() {
    if std::env::var("RUN_V118_UPGRADE").is_err() {
        eprintln!(
            "skipping: set RUN_V118_UPGRADE=1 (needs OLD_BIN/NEW_BIN/NOTIFIER_BIN/IKA_BIN/SUI_BIN)"
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
            .unwrap_or_else(|_| "/mnt/nvme0n1p1/tmp/ika-v118-upgrade".to_string()),
    );
    let _ = std::fs::remove_dir_all(&base);

    Scenario::new(4, repo, sui, notifier)
        .with_base_dir(base)
        .with_epoch_duration_ms(300_000)
        .with_epoch_timeout(Duration::from_secs(1200))
        .with_ika_cli(ika_cli)
        // The verified mainnet on-chain state: the config is populated, so
        // ECDSA presigns route to global presign on both binaries.
        .with_genesis_global_presign_config(GenesisGlobalPresignConfig::Full)
        .start_all(old)
        // Epoch 2 guarantees the 1.1.8 binaries finished the genesis network
        // DKG — the swapped binaries will inherit a *completed* 1.1.8-crypto
        // key and reshare it, which is the state-continuity moment under
        // test.
        .wait_for_epoch(2)
        // The mainnet user flow on literal 1.1.8 at v3: DKG (Universal
        // output), *global* presign served as a user-requested MPC session,
        // sign. Also the timing baseline, and it leaves 1.1.8-created
        // on-chain artifacts behind.
        .run_workload("v118-v3")
        .record_mpc_timings("v118-v3")
        // ATOMIC swap: every validator stops on 1.1.8 and restarts on the
        // local build against its existing RocksDB. Mirrors the coordinated
        // mainnet restart (rolling is impossible on this branch's single
        // crypto pin).
        .stop_and_swap(&[0, 1, 2, 3], new)
        // With n=4 the default 50% buffer stake requires all four capability
        // votes at the tally; a fresh capability can land just after it, so
        // drop the buffer to a bare quorum.
        .set_buffer_stake(0)
        // The pre-activation-window probe: launched right after the swap,
        // while the network is still at v3 on the local build. Its global
        // presign must be served by the pre-pool fallback (a user-requested
        // MPC session, the 1.1.8 way) and complete *within* this epoch — a
        // global presign session left pending would block `advance_epoch`
        // (`all_current_epoch_sessions_completed`) and wedge the network at
        // v3 forever, since the pool that could otherwise serve it only
        // fills at v4.
        .run_workload("pre-activation-window")
        .record_mpc_timings("pre-activation-window")
        // Boundary 2->3: the local binaries reshare the 1.1.8-created key
        // and the capability vote advances v3 -> v4.
        .wait_for_epoch(3)
        .expect_protocol_version_at_least(4)
        .expect_committee_size(4)
        // Steady-state lifecycle on the local build at v4: fresh DKG,
        // pool-served global presign, sign — all on top of state a 1.1.8
        // network created. (No `set_global_presign_config` step: the config
        // has been the mainnet-shape Full since genesis.)
        .run_workload("local-v4")
        .record_mpc_timings("local-v4")
        // One more boundary: a clean reshare executed end-to-end by the
        // local build alone — and the first one run *at protocol v4*, i.e.
        // with the v4 reconfiguration math (`reconfiguration_message_version
        // = 3`, PVSS HPKE; the epoch 2->3 reshare above still ran the v3
        // protocol). The snapshot's *window* vs `local-v4` isolates that
        // v4-math reshare from the cumulative averages.
        .wait_for_epoch(4)
        .record_mpc_timings("v4-reshare")
        // Settled v4 lifecycle: pools were filled during epoch 3, the
        // boundary work is done, so this window prices v4 DKG / pool-served
        // presign / sign without the pool-fill contention that loaded the
        // `local-v4` numbers.
        .run_workload("local-v4-settled")
        .record_mpc_timings("local-v4-settled")
        .run()
        .await
        .expect("v1.1.8 -> local atomic upgrade rehearsal");

    tracing::info!(
        "v118 upgrade rehearsal PASSED: literal mainnet-v1.1.8 -> local build, v3 -> v4, \
         pre-activation global presign served"
    );
}
