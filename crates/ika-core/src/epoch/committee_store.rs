// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use ika_types::committee::{Committee, EpochId, LegacyCommittee};
use ika_types::error::IkaResult;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use sui_types::base_types::ObjectID;
use tracing::{info, warn};
use typed_store::rocks::{DBMap, DBOptions, MetricConf, ReadWriteOptions, default_db_options};
use typed_store::rocksdb::Options;

use typed_store::DBMapUtils;
use typed_store::Map;

use sui_macros::nondeterministic;

pub struct CommitteeStore {
    tables: CommitteeStoreTables,
    cache: RwLock<HashMap<EpochId, Arc<Committee>>>,
}

#[derive(DBMapUtils)]
pub struct CommitteeStoreTables {
    /// Map from each epoch ID to the committee information.
    #[default_options_override_fn = "committee_table_default_config"]
    committee_map: DBMap<EpochId, Committee>,
    /// Singleton marker: the `committee_map` value-schema generation this
    /// store was last opened under (see `COMMITTEE_SCHEMA_VERSION_CURRENT`).
    /// Present-and-current ⇒ every record is current-layout and the legacy
    /// migration scan is skipped at open. Absent ⇒ the CF may hold
    /// mainnet-v1.1.8 records (or is brand new) and the one-time scan runs.
    /// Its own column family, so consulting it never decodes a committee
    /// value under a possibly-mismatched schema.
    committee_schema_version: DBMap<(), u64>,
}

/// `committee_map` value-schema generations: the mainnet-v1.1.8 layout
/// (pre-`consensus_keys`) is generation 1; the 48-byte-`AuthorityName` layout
/// is 2; generation 3 narrows `AuthorityName` to the raw 32-byte consensus
/// key. Only the current value is ever written; the constant exists so the
/// marker is self-describing when inspected.
///
/// **Records from epochs below protocol v6 do not survive generation 3 and are
/// not meant to.** Their `voting_rights` are keyed by 48-byte BLS-basis names,
/// which have no consensus-key representation — the deserializer rejects them
/// rather than truncating to a wrong identity. Nothing live reads them: the
/// only consumers of `get_committee` are the insert-time dedup (current epoch),
/// joiner bootstrap (`prior_epoch = current - 1`, always v6+ since
/// `MIN_PROTOCOL_VERSION = 6`), and a `ReadStore` impl whose callers are
/// blanket forwarding impls. `ReadStore::get_committee` already propagates
/// decode errors instead of panicking, precisely for old-layout records.
const COMMITTEE_SCHEMA_VERSION_CURRENT: u64 = 3;

// These functions are used to initialize the DB tables
fn committee_table_default_config() -> DBOptions {
    default_db_options().optimize_for_point_lookup(64)
}

impl CommitteeStore {
    pub fn new(path: PathBuf, db_options: Option<Options>) -> Self {
        let tables = CommitteeStoreTables::open_tables_read_write(
            path,
            MetricConf::new("committee"),
            db_options,
            None,
        );

        Self::migrate_legacy_records(&tables);

        Self {
            tables,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// One-time migration: rewrite `committee_map` records persisted by
    /// mainnet-v1.1.8 (pre-`consensus_keys` layout, which the current
    /// `Committee` cannot decode — bcs is positional) in the current layout,
    /// so every later read is a plain decode. Runs at most once per data
    /// dir, guarded by the schema-version marker; crash-safe (a crash
    /// before the marker re-scans on the next open, and re-migrating a
    /// legacy record is a no-op rewrite). Remove together with
    /// `LegacyCommittee` once no fleet upgrades directly from 1.1.8 data
    /// dirs.
    fn migrate_legacy_records(tables: &CommitteeStoreTables) {
        // Marker present: this store was already opened (and, if needed,
        // migrated) by a current-schema binary, so every record decodes
        // under the current layout — skip the scan. The skip is what makes
        // REOPENS safe under debug assertions: the pinned typed-store
        // `debug_fatal!`s — a PANIC in debug/msim builds — on any record
        // that fails the reading view's schema, so scanning a
        // current-layout CF under the LEGACY view (as every reopen did
        // before the marker) panicked every msim node restart (issue
        // #1836). Release builds log-and-skip instead, which is why the
        // real-binary upgrade rehearsal never saw it.
        match tables.committee_schema_version.get(&()) {
            Ok(Some(version)) if version >= COMMITTEE_SCHEMA_VERSION_CURRENT => return,
            Ok(_) => {}
            Err(e) => {
                // A marker read error must NOT skip the migration: a
                // genuine 1.1.8 data dir would then fail its first
                // committee read. Fall through and scan — idempotent.
                warn!(
                    error = ?e,
                    "failed to read the committee schema-version marker; \
                     running the legacy-migration scan"
                );
            }
        }
        let legacy_view: DBMap<EpochId, LegacyCommittee> = DBMap::reopen(
            &tables.committee_map.db,
            Some("committee_map"),
            &ReadWriteOptions::default(),
            false,
        )
        .expect("reopening committee_map under the legacy schema cannot fail — same cf");
        // A record that decodes under the legacy schema IS legacy: the two
        // layouts are mutually exclusive on decode success (a current
        // record leaves trailing bytes under the legacy schema; a legacy
        // record exhausts its input under the current one), so no
        // current-decode probe is needed before rewriting — and probing
        // would `debug_fatal!` on every genuine 1.1.8 record in debug
        // builds. Current-layout records yield `Err` items here and are
        // skipped. (Residual corner: a marker-less MIXED CF — reachable
        // only by crashing mid-scan on a real 1.1.8 upgrade and reopening
        // in a debug-assertions build — panics in the iterator; the
        // release re-scan handles it.)
        for item in legacy_view.safe_iter() {
            let Ok((epoch, legacy)) = item else { continue };
            let committee = Committee::from(legacy);
            tables
                .committee_map
                .insert(&epoch, &committee)
                .expect("failed to rewrite a legacy committee record");
            info!(
                epoch,
                "migrated a pre-consensus-keys (mainnet-1.1.8) committee record; \
                 consensus_keys is empty for this epoch"
            );
        }
        // Written AFTER the scan completes, so a crash mid-migration
        // re-scans on the next open instead of stranding unmigrated rows
        // behind the marker.
        tables
            .committee_schema_version
            .insert(&(), &COMMITTEE_SCHEMA_VERSION_CURRENT)
            .expect("failed to write the committee schema-version marker");
    }

    pub fn new_for_testing(_genesis_committee: &Committee) -> Self {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("DB_{:?}", nondeterministic!(ObjectID::random())));
        Self::new(path, None)
    }

    pub fn init_genesis_committee(&self, genesis_committee: Committee) -> IkaResult {
        assert_eq!(genesis_committee.epoch, 0);
        self.tables.committee_map.insert(&0, &genesis_committee)?;
        self.cache.write().insert(0, Arc::new(genesis_committee));
        Ok(())
    }

    pub fn insert_new_committee(&self, new_committee: &Committee) -> IkaResult {
        if let Some(old_committee) = self.get_committee(&new_committee.epoch)? {
            // If somehow we already have this committee in the store, they must be the same.
            assert_eq!(&*old_committee, new_committee);
        } else {
            self.tables
                .committee_map
                .insert(&new_committee.epoch, new_committee)?;
            self.cache
                .write()
                .insert(new_committee.epoch, Arc::new(new_committee.clone()));
        }
        Ok(())
    }

    pub fn get_committee(&self, epoch_id: &EpochId) -> IkaResult<Option<Arc<Committee>>> {
        if let Some(committee) = self.cache.read().get(epoch_id) {
            return Ok(Some(committee.clone()));
        }
        // Legacy (mainnet-v1.1.8) records were rewritten in the current
        // layout by `migrate_legacy_records` at store open, so a decode
        // error here is genuine corruption and is propagated.
        let committee = self.tables.committee_map.get(epoch_id)?;
        let committee = committee.map(Arc::new);
        if let Some(committee) = committee.as_ref() {
            self.cache.write().insert(*epoch_id, committee.clone());
        }
        Ok(committee)
    }

    pub fn checkpoint_db(&self, path: &Path) -> IkaResult {
        self.tables
            .committee_map
            .checkpoint_db(path)
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ika_types::committee::LegacyCommittee;

    fn fresh_path() -> PathBuf {
        std::env::temp_dir().join(format!("DB_{:?}", nondeterministic!(ObjectID::random())))
    }

    fn legacy_view(store: &CommitteeStore) -> DBMap<EpochId, LegacyCommittee> {
        DBMap::reopen(
            &store.tables.committee_map.db,
            Some("committee_map"),
            &ReadWriteOptions::default(),
            false,
        )
        .unwrap()
    }

    /// A genuine 1.1.8 data dir: legacy records, NO marker. The first open
    /// migrates every record and writes the marker; the second open is a
    /// pure marker-skip and the records still read fine.
    #[tokio::test]
    async fn legacy_records_migrate_at_open() {
        let path = fresh_path();
        let (legacy_committee, _keys) = Committee::new_simple_test_committee_of_size(4);
        {
            let store = CommitteeStore::new(path.clone(), None);
            legacy_view(&store)
                .insert(
                    &legacy_committee.epoch,
                    &LegacyCommittee::mirror_of(&legacy_committee),
                )
                .unwrap();
            // A 1.1.8 dir has no marker; the fresh open above wrote one, so
            // remove it to simulate the real upgrade state.
            store.tables.committee_schema_version.remove(&()).unwrap();
        }
        for reopen in 0..2 {
            let store = CommitteeStore::new(path.clone(), None);
            let migrated = store
                .get_committee(&legacy_committee.epoch)
                .unwrap()
                .unwrap();
            assert_eq!(migrated.epoch, legacy_committee.epoch);
            assert_eq!(migrated.voting_rights, legacy_committee.voting_rights);
            assert_eq!(migrated.quorum_threshold, legacy_committee.quorum_threshold);
            assert_eq!(
                store.tables.committee_schema_version.get(&()).unwrap(),
                Some(COMMITTEE_SCHEMA_VERSION_CURRENT),
                "reopen {reopen}: the marker must be present after migration"
            );
        }
    }

    /// The marker actually gates the scan: with the marker present, a
    /// reopen must NOT touch the CF — proven by planting a legacy record
    /// AFTER the marker and observing it still legacy-encoded after the
    /// reopen (the migration would have rewritten it to the current
    /// layout, which no longer decodes under the legacy schema). This is
    /// the property that keeps msim node restarts panic-free (#1836): a
    /// marker-skipped open never iterates records under a mismatched
    /// schema.
    #[tokio::test]
    async fn marker_skips_the_scan_on_reopen() {
        let path = fresh_path();
        let (legacy_committee, _keys) = Committee::new_simple_test_committee_of_size(4);
        {
            let store = CommitteeStore::new(path.clone(), None);
            assert_eq!(
                store.tables.committee_schema_version.get(&()).unwrap(),
                Some(COMMITTEE_SCHEMA_VERSION_CURRENT),
                "a fresh open must write the marker"
            );
            legacy_view(&store)
                .insert(
                    &legacy_committee.epoch,
                    &LegacyCommittee::mirror_of(&legacy_committee),
                )
                .unwrap();
        }
        let store = CommitteeStore::new(path.clone(), None);
        // Still decodes under the LEGACY schema ⇒ the scan did not run and
        // did not rewrite it. (Probing it under the current schema would
        // debug_fatal-panic in debug builds — exactly what the marker skip
        // avoids — so the negative is asserted through the legacy view.)
        assert!(
            legacy_view(&store)
                .get(&legacy_committee.epoch)
                .unwrap()
                .is_some(),
            "the marker-guarded reopen must not have rewritten the record"
        );
    }

    /// Mixed marker-less CF (legacy + current + corrupt): the scan migrates
    /// the legacy record, leaves the current one untouched, and skips the
    /// corrupt one. Release-only: iterating a schema-mismatched record
    /// `debug_fatal!`s (panics) under debug assertions inside the pinned
    /// typed-store — this mixed state is only reachable in production by
    /// crashing mid-scan during a real 1.1.8 upgrade, where the re-scan
    /// runs on a release binary.
    #[cfg(not(debug_assertions))]
    #[tokio::test]
    async fn mixed_markerless_cf_migrates_legacy_and_skips_the_rest() {
        let path = fresh_path();
        let (legacy_committee, _keys) = Committee::new_simple_test_committee_of_size(4);
        let (mut current_committee, _keys) = Committee::new_simple_test_committee_of_size(4);
        current_committee.epoch = legacy_committee.epoch + 1;
        let corrupt_epoch = legacy_committee.epoch + 2;
        {
            let store = CommitteeStore::new(path.clone(), None);
            legacy_view(&store)
                .insert(
                    &legacy_committee.epoch,
                    &LegacyCommittee::mirror_of(&legacy_committee),
                )
                .unwrap();
            store
                .tables
                .committee_map
                .insert(&current_committee.epoch, &current_committee)
                .unwrap();
            let raw_view: DBMap<EpochId, Vec<u8>> = DBMap::reopen(
                &store.tables.committee_map.db,
                Some("committee_map"),
                &ReadWriteOptions::default(),
                false,
            )
            .unwrap();
            raw_view.insert(&corrupt_epoch, &vec![0xde, 0xad]).unwrap();
            store.tables.committee_schema_version.remove(&()).unwrap();
        }
        for _ in 0..2 {
            let store = CommitteeStore::new(path.clone(), None);
            let migrated = store
                .get_committee(&legacy_committee.epoch)
                .unwrap()
                .unwrap();
            assert_eq!(migrated.voting_rights, legacy_committee.voting_rights);
            // The current-layout record is untouched by the migration.
            let untouched = store
                .get_committee(&current_committee.epoch)
                .unwrap()
                .unwrap();
            assert_eq!(*untouched, current_committee);
            // The corrupt record is skipped by the migration and surfaces as
            // a propagated read error, not a panic.
            assert!(store.get_committee(&corrupt_epoch).is_err());
        }
    }
}
