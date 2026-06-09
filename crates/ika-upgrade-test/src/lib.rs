// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Out-of-process cross-binary upgrade test harness.
//!
//! Runs an Ika cluster on one machine with validators executing *real,
//! separately-compiled* `ika-validator` binaries (e.g. `mainnet-v1.1.8` vs
//! `dev`), drives them across epoch boundaries, swaps binaries on individual
//! validators mid-run, and asserts the upgrade invariants (protocol-version
//! vote, reconfiguration MPC, session lifecycle, wire compat, on-disk compat).
//!
//! This is deliberately a separate crate from `ika-swarm`: `ika-swarm` links a
//! single `IkaNode` in-process (one OS thread per validator) and cannot host
//! two different compiled binaries. The harness here owns a small surface —
//! start / stop / swap_binary / wait_for_epoch / capabilities — and drives
//! real child processes via the existing admin HTTP RPC
//! (`ika-node/src/admin.rs`) and the coordinator Move contract on Sui.
//!
//! See `docs/cross-binary-upgrade-testing*.md` for the design.

pub mod binary;
pub mod cluster;
pub mod process;
pub mod scenario;
pub mod sui;
pub mod workload;

pub use binary::BinarySpec;
pub use cluster::ClusterOfProcesses;
pub use process::ValidatorProcess;
pub use scenario::Scenario;
pub use sui::SuiLocalnet;

/// Ika epoch duration used by the harness, in milliseconds. Short enough that
/// epochs advance on a wall-clock cadence the harness can wait on, long enough
/// that an MPC session started early in an epoch can complete within it. The
/// harness drives boundaries purely by this genesis duration (there is no
/// `force-close-epoch` admin endpoint — it is a dead constant in `admin.rs`).
pub const DEFAULT_EPOCH_DURATION_MS: u64 = 60_000;

/// Number of validators in a harness cluster. Capped at 4: msim/ika node-id
/// accounting aside, the project convention is never to exceed four ika
/// validators in a test cluster.
pub const DEFAULT_NUM_VALIDATORS: usize = 4;
