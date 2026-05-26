// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Per-epoch task that P2P-fetches peer validators' `mpc_data` blobs
//! into the local perpetual + in-memory blob stores so the off-chain
//! class-groups assembler can resolve every committee member without
//! a chain read.
//!
//! Each validator publishes its own `ValidatorMpcDataAnnouncement`
//! via consensus carrying only the Blake2b256 digest of its
//! `mpc_data` blob. The producer side
//! (`mpc_data_announcement_sender`) caches its own blob locally on
//! submit, but **peer blobs are not carried on the wire** — by design,
//! the blob bytes flow over P2P. Without this fetcher every validator
//! would only ever hold its own blob, the off-chain assembler would
//! return `Incomplete` for every peer, and `sync_next_committee`
//! would fall back to reading `get_mpc_data_from_validators_pool`
//! from chain — which is exactly what the off_chain_validator_metadata
//! mode is supposed to eliminate.
//!
//! The task runs every few seconds: it iterates the per-epoch
//! `validator_mpc_data_announcements` table, skips authorities whose
//! blob is already in the local perpetual store (own producer cache,
//! prior fetch, or restart hydration), maps the announcer's
//! `AuthorityName` to its Anemo `PeerId` via the live committee
//! snapshot, calls `fetch_blob` over Anemo, hash-verifies the bytes
//! against the announcement digest, and inserts the blob into both
//! the perpetual table and the in-memory cache backing the local
//! Anemo server. The in-memory write is what lets *other* peers
//! fetch the blob from this validator without a node restart.

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
use anemo::{Network, PeerId};
use ika_network::mpc_artifacts::{InMemoryBlobStore, fetch_blob, mpc_data_blob_hash};
use ika_types::committee::EpochId;
use ika_types::crypto::AuthorityName;
use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tracing::{debug, info, warn};
use typed_store::Map;

pub struct PeerBlobFetcher {
    epoch_store: Weak<AuthorityPerEpochStore>,
    epoch_id: EpochId,
    own_authority: AuthorityName,
    perpetual_tables: Arc<AuthorityPerpetualTables>,
    in_memory_blob_store: Arc<InMemoryBlobStore>,
    p2p_network: Network,
    authority_names_to_peer_ids: HashMap<AuthorityName, PeerId>,
}

impl PeerBlobFetcher {
    pub fn new(
        epoch_store: Weak<AuthorityPerEpochStore>,
        epoch_id: EpochId,
        own_authority: AuthorityName,
        perpetual_tables: Arc<AuthorityPerpetualTables>,
        in_memory_blob_store: Arc<InMemoryBlobStore>,
        p2p_network: Network,
        authority_names_to_peer_ids: HashMap<AuthorityName, PeerId>,
    ) -> Self {
        Self {
            epoch_store,
            epoch_id,
            own_authority,
            perpetual_tables,
            in_memory_blob_store,
            p2p_network,
            authority_names_to_peer_ids,
        }
    }

    pub async fn run(self: Arc<Self>) {
        if let Some(epoch_store) = self.epoch_store.upgrade()
            && !epoch_store
                .protocol_config()
                .off_chain_validator_metadata_enabled()
        {
            info!(
                epoch = self.epoch_id,
                "off-chain validator metadata disabled; peer blob fetcher exiting"
            );
            return;
        }
        loop {
            self.fetch_missing_blobs_once().await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Single pass over the per-epoch announcement table. Fetches any
    /// blob we don't already have locally. Errors are logged at
    /// `warn` and the loop continues — the next tick retries.
    async fn fetch_missing_blobs_once(&self) {
        let Some(epoch_store) = self.epoch_store.upgrade() else {
            // Epoch ended — the spawning task is about to drop us.
            return;
        };
        let pending: Vec<(AuthorityName, [u8; 32])> = {
            let mut out = Vec::new();
            let Ok(tables) = epoch_store.tables() else {
                return;
            };
            for entry in tables.validator_mpc_data_announcements.safe_iter() {
                let Ok((authority, signed)) = entry else {
                    continue;
                };
                if authority == self.own_authority {
                    // Our own announcement; the producer path inserted
                    // the blob into both stores at submission time.
                    continue;
                }
                let digest = signed.announcement.blob_hash;
                // If we have the blob in perpetual storage, we're
                // done fetching it. But we also want the in-memory
                // store backing the local Anemo server to have it,
                // so peers asking us for the blob get a hit. After
                // a restart, perpetual is populated by hydration
                // but the in-memory store starts empty until the
                // hydration pass runs — and even after hydration,
                // any blob inserted by a code path that bypasses
                // the in-memory mirror (e.g. a future caller) would
                // leave us serving misses. Backfill on the spot.
                if let Ok(Some(bytes)) = self.perpetual_tables.get_mpc_artifact_blob(&digest) {
                    if !self.in_memory_blob_store.contains(&digest) {
                        self.in_memory_blob_store.insert(digest, bytes);
                    }
                    continue;
                }
                out.push((authority, digest));
            }
            out
        };
        if pending.is_empty() {
            return;
        }
        debug!(
            epoch = self.epoch_id,
            pending = pending.len(),
            "peer blob fetcher: starting fetch pass"
        );
        for (authority, digest) in pending {
            let Some(peer_id) = self.authority_names_to_peer_ids.get(&authority).copied() else {
                debug!(
                    ?authority,
                    "peer blob fetcher: no PeerId mapping for announcer; skipping"
                );
                continue;
            };
            match fetch_blob(&self.p2p_network, peer_id, digest).await {
                Ok(Some(bytes)) => {
                    let observed = mpc_data_blob_hash(&bytes);
                    if observed != digest {
                        warn!(
                            ?authority,
                            ?peer_id,
                            expected = ?digest,
                            observed = ?observed,
                            "peer blob fetcher: peer served bytes that don't match the \
                             announcement digest; dropping"
                        );
                        continue;
                    }
                    if let Err(e) = self
                        .perpetual_tables
                        .insert_mpc_artifact_blob(digest, &bytes)
                    {
                        warn!(error = ?e, ?authority, "peer blob fetcher: perpetual insert failed");
                        continue;
                    }
                    // Mirror the perpetual insert into the in-memory
                    // cache backing the local Anemo server so peers
                    // that ask us for this blob get a hit too.
                    self.in_memory_blob_store.insert(digest, bytes);
                    info!(
                        ?authority,
                        ?peer_id,
                        "peer blob fetcher: fetched + cached peer mpc_data blob"
                    );
                }
                Ok(None) => {
                    debug!(
                        ?authority,
                        ?peer_id,
                        "peer blob fetcher: peer doesn't have the blob yet; will retry"
                    );
                }
                Err(e) => {
                    debug!(
                        ?authority,
                        ?peer_id,
                        error = ?e,
                        "peer blob fetcher: transport error; will retry"
                    );
                }
            }
        }
    }
}
