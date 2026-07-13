// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use ika_types::committee::{Committee, EpochId, LegacyCommittee};
use ika_types::error::IkaResult;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use sui_types::base_types::ObjectID;
use tracing::info;
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
}

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
    /// so every later read is a plain decode. Idempotent and crash-safe: a
    /// record is rewritten only if it fails the current decode AND succeeds
    /// the legacy one, so re-running skips already-migrated records. Remove
    /// together with `LegacyCommittee` once no fleet upgrades directly from
    /// 1.1.8 data dirs.
    fn migrate_legacy_records(tables: &CommitteeStoreTables) {
        let legacy_view: DBMap<EpochId, LegacyCommittee> = DBMap::reopen(
            &tables.committee_map.db,
            Some("committee_map"),
            &ReadWriteOptions::default(),
            false,
        )
        .expect("reopening committee_map under the legacy schema cannot fail — same cf");
        // Current-layout records fail the legacy decode (trailing bytes) and
        // are yielded as Err items; skip them. For each legacy-decodable
        // record, confirm the current decode really fails before rewriting,
        // so a current record can never be misread as legacy.
        for item in legacy_view.safe_iter() {
            let Ok((epoch, legacy)) = item else { continue };
            if tables.committee_map.get(&epoch).is_ok() {
                continue;
            }
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

    #[tokio::test]
    async fn legacy_records_migrate_at_open() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("DB_{:?}", nondeterministic!(ObjectID::random())));
        let (committee, _keys) = Committee::new_simple_test_committee_of_size(4);
        {
            let store = CommitteeStore::new(path.clone(), None);
            // Plant a 1.1.8-layout record, as a pre-upgrade binary would have
            // written it.
            let legacy_view: DBMap<EpochId, LegacyCommittee> = DBMap::reopen(
                &store.tables.committee_map.db,
                Some("committee_map"),
                &ReadWriteOptions::default(),
                false,
            )
            .unwrap();
            legacy_view
                .insert(&committee.epoch, &LegacyCommittee::mirror_of(&committee))
                .unwrap();
            // The record does not decode under the current schema — this is
            // the state an upgraded binary opens the store in.
            assert!(store.tables.committee_map.get(&committee.epoch).is_err());
        }
        // Reopen: migration rewrites the record; reads are plain decodes.
        let store = CommitteeStore::new(path, None);
        let migrated = store.get_committee(&committee.epoch).unwrap().unwrap();
        assert_eq!(migrated.epoch, committee.epoch);
        assert_eq!(migrated.voting_rights, committee.voting_rights);
        assert_eq!(migrated.quorum_threshold, committee.quorum_threshold);
    }
}
