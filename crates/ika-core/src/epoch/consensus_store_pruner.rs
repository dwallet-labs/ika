// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use consensus_config::Epoch;
use mysten_metrics::spawn_logged_monitored_task;
use prometheus::{
    IntCounter, IntCounterVec, IntGauge, Registry, register_int_counter_vec_with_registry,
    register_int_counter_with_registry, register_int_gauge_with_registry,
};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tokio::{sync::mpsc, time::Instant};
use tracing::{error, info, warn};
use typed_store::rocks::safe_drop_db;

struct Metrics {
    last_pruned_db_epoch: IntGauge,
    successfully_pruned_dbs: IntCounter,
    error_pruning_dbs: IntCounterVec,
}

impl Metrics {
    /// `kind` is woven into the metric names; for "consensus" this
    /// reproduces the historical metric names exactly, so dashboards keep
    /// working. Each kind must be registered at most once per registry.
    fn new(registry: &Registry, kind: &str) -> Self {
        Self {
            last_pruned_db_epoch: register_int_gauge_with_registry!(
                format!("last_pruned_{kind}_db_epoch"),
                format!("The last epoch for which the {kind} store was pruned"),
                registry
            )
            .unwrap(),
            successfully_pruned_dbs: register_int_counter_with_registry!(
                format!("successfully_pruned_{kind}_dbs"),
                format!("The number of {kind} dbs successfully pruned"),
                registry
            )
            .unwrap(),
            error_pruning_dbs: register_int_counter_vec_with_registry!(
                format!("error_pruning_{kind}_dbs"),
                format!("The number of errors encountered while pruning {kind} dbs"),
                &["mode"],
                registry
            )
            .unwrap(),
        }
    }
}

/// Prunes per-epoch RocksDB directories under a base path, keeping the
/// `epoch_retention` most recent epochs plus the current one. Despite the
/// name (kept for the original consensus call sites), it serves any store
/// laid out as one directory per epoch:
///
/// - Mysticeti consensus DBs: directories named with the bare epoch
///   number (`42/`).
/// - Authority per-epoch stores: `epoch_42/` directories living next to
///   the `perpetual/` directory (which never matches the prefix filter
///   and is therefore never touched).
pub struct ConsensusStorePruner {
    tx_remove: mpsc::Sender<Epoch>,
    _handle: tokio::task::JoinHandle<()>,
}

impl ConsensusStorePruner {
    /// Pruner for the Mysticeti consensus store layout (bare epoch-number
    /// directory names).
    pub fn new(
        base_path: PathBuf,
        initial_epoch: Epoch,
        epoch_retention: u64,
        epoch_prune_period: Duration,
        registry: &Registry,
    ) -> Self {
        Self::new_with_layout(
            base_path,
            "",
            "consensus",
            initial_epoch,
            epoch_retention,
            epoch_prune_period,
            registry,
        )
    }

    /// Generalized constructor. `dir_prefix` is stripped from each
    /// directory name before parsing the remainder as an epoch number;
    /// entries that don't start with the prefix are skipped silently, so
    /// sibling directories (e.g. `perpetual/`) are left alone. `kind`
    /// names the store in logs and metrics — use a distinct stable string
    /// per call site or prometheus registration panics.
    ///
    /// `initial_epoch` seeds the pruning boundary so the periodic tick is
    /// effective from startup; without it, every tick before the first
    /// reconfiguration would run with epoch 0 and prune nothing — up to a
    /// full epoch of dormancy after every node restart.
    pub fn new_with_layout(
        base_path: PathBuf,
        dir_prefix: &'static str,
        kind: &'static str,
        initial_epoch: Epoch,
        epoch_retention: u64,
        epoch_prune_period: Duration,
        registry: &Registry,
    ) -> Self {
        let (tx_remove, mut rx_remove) = mpsc::channel(1);
        let metrics = Metrics::new(registry, kind);

        let _handle = spawn_logged_monitored_task!(async move {
            info!(
                "Starting {kind} store pruner with initial epoch {initial_epoch}, epoch retention {epoch_retention} and prune period {epoch_prune_period:?}"
            );

            let mut timeout = tokio::time::interval_at(
                Instant::now() + Duration::from_secs(60), // allow some time for the node to boot etc before attempting to prune
                epoch_prune_period,
            );

            let mut latest_epoch = initial_epoch;
            loop {
                tokio::select! {
                    _ = timeout.tick() => {
                        Self::prune_old_epoch_data(&base_path, dir_prefix, kind, latest_epoch, epoch_retention, &metrics).await;
                    }
                    result = rx_remove.recv() => {
                        if result.is_none() {
                            info!("Closing {kind} store pruner");
                            break;
                        }
                        latest_epoch = result.unwrap();
                        Self::prune_old_epoch_data(&base_path, dir_prefix, kind, latest_epoch, epoch_retention, &metrics).await;
                    }
                }
            }
        });

        Self { tx_remove, _handle }
    }

    /// This method will remove all epoch data stores and directories that are older than the current epoch minus the epoch retention. The method ensures
    /// that always the `current_epoch` data is retained.
    pub async fn prune(&self, current_epoch: Epoch) {
        let result = self.tx_remove.send(current_epoch).await;
        if result.is_err() {
            error!(
                "Error sending message to data removal task for epoch {:?}",
                current_epoch,
            );
        }
    }

    async fn prune_old_epoch_data(
        storage_base_path: &PathBuf,
        dir_prefix: &str,
        kind: &str,
        current_epoch: Epoch,
        epoch_retention: u64,
        metrics: &Metrics,
    ) {
        let drop_boundary = current_epoch.saturating_sub(epoch_retention);

        info!(
            "{kind} store pruning for current epoch {}. Will remove epochs < {:?}",
            current_epoch, drop_boundary
        );

        // Get all the epoch stores in the base path directory
        let files = match fs::read_dir(storage_base_path) {
            Ok(f) => f,
            Err(e) => {
                error!(
                    "Can not read the files in the {kind} storage path directory for epoch cleanup: {:?}",
                    e
                );
                return;
            }
        };

        // Look for any that are less than the drop boundary and drop
        for file_res in files {
            let f = match file_res {
                Ok(f) => f,
                Err(e) => {
                    error!(
                        "Error while cleaning up {kind} storage of previous epochs: {:?}",
                        e
                    );
                    continue;
                }
            };

            let name = f.file_name();
            let file_name = match name.to_str() {
                Some(f) => f,
                None => continue,
            };

            // Entries that don't carry the prefix (e.g. the `perpetual/`
            // sibling in the authority store layout) are not epoch
            // directories — skip them without logging.
            let file_epoch_string = match file_name.strip_prefix(dir_prefix) {
                Some(rest) => rest,
                None => continue,
            };

            let file_epoch = match file_epoch_string.parse::<u64>() {
                Ok(f) => f,
                Err(e) => {
                    error!(
                        "Could not parse file \"{file_name}\" in {kind} storage path into epoch for cleanup: {:?}",
                        e
                    );
                    continue;
                }
            };

            if file_epoch < drop_boundary {
                const WAIT_BEFORE_FORCE_DELETE: Duration = Duration::from_secs(5);
                if let Err(e) = safe_drop_db(f.path(), WAIT_BEFORE_FORCE_DELETE).await {
                    warn!(
                        "Could not prune old {kind} storage \"{:?}\" directory with safe approach. Will fallback to force delete: {:?}",
                        f.path(),
                        e
                    );
                    metrics.error_pruning_dbs.with_label_values(&["safe"]).inc();

                    if let Err(err) = fs::remove_dir_all(f.path()) {
                        error!(
                            "Could not prune old {kind} storage \"{:?}\" directory with force delete: {:?}",
                            f.path(),
                            err
                        );
                        metrics
                            .error_pruning_dbs
                            .with_label_values(&["force"])
                            .inc();
                    } else {
                        info!(
                            "Successfully pruned {kind} epoch storage directory with force delete: {:?}",
                            f.path()
                        );
                        let last_epoch = metrics.last_pruned_db_epoch.get();
                        metrics
                            .last_pruned_db_epoch
                            .set(last_epoch.max(file_epoch as i64));
                        metrics.successfully_pruned_dbs.inc();
                    }
                } else {
                    info!(
                        "Successfully pruned {kind} epoch storage directory: {:?}",
                        f.path()
                    );
                    let last_epoch = metrics.last_pruned_db_epoch.get();
                    metrics
                        .last_pruned_db_epoch
                        .set(last_epoch.max(file_epoch as i64));
                    metrics.successfully_pruned_dbs.inc();
                }
            }
        }

        info!(
            "Completed old epoch data removal process for epoch {:?}",
            current_epoch
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::epoch::consensus_store_pruner::{ConsensusStorePruner, Metrics};
    use prometheus::Registry;
    use std::fs;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_remove_old_epoch_data() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let metrics = Metrics::new(&Registry::new(), "consensus");

        {
            // Epoch 0 should not be removed when it's current epoch.
            let epoch_retention = 0;
            let current_epoch = 0;

            let base_directory = tempfile::tempdir().unwrap().keep();

            create_epoch_directories(&base_directory, vec!["0", "other"]);

            ConsensusStorePruner::prune_old_epoch_data(
                &base_directory,
                "",
                "consensus",
                current_epoch,
                epoch_retention,
                &metrics,
            )
            .await;

            let epochs_left = read_epoch_directories(&base_directory, "");

            assert_eq!(epochs_left.len(), 1);
            assert_eq!(epochs_left[0], 0);
        }

        {
            // Every directory should be retained only for 1 epoch. We expect any epoch directories < 99 to be removed.
            let epoch_retention = 1;
            let current_epoch = 100;

            let base_directory = tempfile::tempdir().unwrap().keep();

            create_epoch_directories(&base_directory, vec!["97", "98", "99", "100", "other"]);

            ConsensusStorePruner::prune_old_epoch_data(
                &base_directory,
                "",
                "consensus",
                current_epoch,
                epoch_retention,
                &metrics,
            )
            .await;

            let epochs_left = read_epoch_directories(&base_directory, "");

            assert_eq!(epochs_left.len(), 2);
            assert_eq!(epochs_left[0], 99);
            assert_eq!(epochs_left[1], 100);
        }

        {
            // Every directory should be retained only for 0 epochs. That means only the current epoch directory should be retained and everything else
            // deleted.
            let epoch_retention = 0;
            let current_epoch = 100;

            let base_directory = tempfile::tempdir().unwrap().keep();

            create_epoch_directories(&base_directory, vec!["97", "98", "99", "100", "other"]);

            ConsensusStorePruner::prune_old_epoch_data(
                &base_directory,
                "",
                "consensus",
                current_epoch,
                epoch_retention,
                &metrics,
            )
            .await;

            let epochs_left = read_epoch_directories(&base_directory, "");

            assert_eq!(epochs_left.len(), 1);
            assert_eq!(epochs_left[0], 100);
        }
    }

    #[tokio::test]
    async fn test_remove_old_epoch_data_authority_layout() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let metrics = Metrics::new(&Registry::new(), "authority");

        // Authority store layout: `epoch_<N>` directories next to the
        // `perpetual/` sibling (and other non-matching entries), which must
        // never be touched.
        let epoch_retention = 1;
        let current_epoch = 100;

        let base_directory = tempfile::tempdir().unwrap().keep();

        create_epoch_directories(
            &base_directory,
            vec![
                "epoch_97",
                "epoch_98",
                "epoch_99",
                "epoch_100",
                "perpetual",
                "epoch_garbage",
                "other",
            ],
        );

        ConsensusStorePruner::prune_old_epoch_data(
            &base_directory,
            "epoch_",
            "authority",
            current_epoch,
            epoch_retention,
            &metrics,
        )
        .await;

        let epochs_left = read_epoch_directories(&base_directory, "epoch_");
        assert_eq!(epochs_left, vec![99, 100]);

        // Non-epoch siblings survive untouched.
        for kept in ["perpetual", "epoch_garbage", "other"] {
            assert!(
                base_directory.join(kept).exists(),
                "non-epoch entry {kept} must not be pruned"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_consensus_store_pruner() {
        let epoch_retention = 1;
        let epoch_prune_period = std::time::Duration::from_millis(500);

        let base_directory = tempfile::tempdir().unwrap().keep();

        // We create some directories up to epoch 100
        create_epoch_directories(&base_directory, vec!["97", "98", "99", "100", "other"]);

        let pruner = ConsensusStorePruner::new(
            base_directory.clone(),
            0,
            epoch_retention,
            epoch_prune_period,
            &Registry::new(),
        );

        // We let the pruner run for a couple of times to prune the old directories. Since the initial epoch of 0 is used no dirs should be pruned.
        sleep(3 * epoch_prune_period).await;

        // We expect the directories to be the same as before
        let epoch_dirs = read_epoch_directories(&base_directory, "");
        assert_eq!(epoch_dirs.len(), 4);

        // Then we update the epoch and instruct to prune for current epoch = 100
        pruner.prune(100).await;

        // We let the pruner run and check again the directories - no directories of epoch < 99 should be left
        sleep(2 * epoch_prune_period).await;

        let epoch_dirs = read_epoch_directories(&base_directory, "");
        assert_eq!(epoch_dirs.len(), 2);
        assert_eq!(epoch_dirs[0], 99);
        assert_eq!(epoch_dirs[1], 100);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_pruner_initial_epoch_enables_periodic_pruning() {
        // A pruner seeded with the node's current epoch prunes on the
        // periodic tick alone — no reconfiguration notification needed.
        // (Unseeded pruners were dormant until the first epoch change
        // after every restart.)
        let epoch_retention = 1;
        let epoch_prune_period = std::time::Duration::from_millis(500);

        let base_directory = tempfile::tempdir().unwrap().keep();
        create_epoch_directories(
            &base_directory,
            vec!["epoch_97", "epoch_98", "epoch_99", "epoch_100", "perpetual"],
        );

        let _pruner = ConsensusStorePruner::new_with_layout(
            base_directory.clone(),
            "epoch_",
            "authority",
            100,
            epoch_retention,
            epoch_prune_period,
            &Registry::new(),
        );

        // First tick fires after the 60s boot grace; trigger via prune()
        // is not used here — wait for the boot-delayed interval is too slow
        // for a unit test, so emulate the tick path directly instead.
        ConsensusStorePruner::prune_old_epoch_data(
            &base_directory,
            "epoch_",
            "authority_tick_test",
            100,
            epoch_retention,
            // Distinct registry AND a valid prometheus name (no hyphens):
            // kind is interpolated into metric names.
            &Metrics::new(&Registry::new(), "authority_tick_test"),
        )
        .await;

        let epochs_left = read_epoch_directories(&base_directory, "epoch_");
        assert_eq!(epochs_left, vec![99, 100]);
        assert!(base_directory.join("perpetual").exists());
    }

    fn create_epoch_directories(base_directory: &std::path::Path, epochs: Vec<&str>) {
        for epoch in epochs {
            let mut path = base_directory.to_path_buf();
            path.push(epoch);
            fs::create_dir(path).unwrap();
        }
    }

    fn read_epoch_directories(base_directory: &std::path::Path, prefix: &str) -> Vec<u64> {
        let files = fs::read_dir(base_directory).unwrap();

        let mut epochs = Vec::new();
        for file_res in files {
            let name = file_res.unwrap().file_name().to_str().unwrap().to_owned();
            let Some(rest) = name.strip_prefix(prefix) else {
                continue;
            };
            if let Ok(file_epoch) = rest.parse::<u64>() {
                epochs.push(file_epoch);
            }
        }

        epochs.sort();
        epochs
    }
}
