// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use ika_types::committee::{Committee, EpochId};
use ika_types::error::{IkaError, IkaResult};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use sui_types::base_types::ObjectID;
use typed_store::rocks::{DBMap, DBOptions, MetricConf, default_db_options};
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

        Self {
            tables,
            cache: RwLock::new(HashMap::new()),
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
        let committee = self.tables.committee_map.get(epoch_id)?;
        let committee = committee.map(Arc::new);
        if let Some(committee) = committee.as_ref() {
            self.cache.write().insert(*epoch_id, committee.clone());
        }
        Ok(committee)
    }

    // todo - make use of cache or remove this method
    pub fn get_latest_committee(&self) -> IkaResult<Committee> {
        Ok(self
            .tables
            .committee_map
            .reversed_safe_iter_with_bounds(None, None)?
            .next()
            .transpose()?
            // unwrap safe because we guarantee there is at least a genesis epoch
            // when initializing the store.
            .unwrap()
            .1)
    }
    /// Return the committee specified by `epoch`. If `epoch` is `None`, return the latest committee.
    // todo - make use of cache or remove this method
    pub fn get_or_latest_committee(&self, epoch: Option<EpochId>) -> IkaResult<Committee> {
        Ok(match epoch {
            Some(epoch) => self
                .get_committee(&epoch)?
                .ok_or(IkaError::MissingCommitteeAtEpoch(epoch))
                .map(|c| Committee::clone(&*c))?,
            None => self.get_latest_committee()?,
        })
    }

    pub fn checkpoint_db(&self, path: &Path) -> IkaResult {
        self.tables
            .committee_map
            .checkpoint_db(path)
            .map_err(Into::into)
    }
}
