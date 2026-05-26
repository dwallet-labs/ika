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
//! prior fetch, or restart hydration), and for every missing blob
//! asks peers over Anemo until one of them serves bytes that
//! hash-verify against the announcement digest. The fetcher
//! deliberately does NOT only ask the originator: a byzantine
//! originator that signs an announcement but withholds the bytes
//! would otherwise win — once *any* honest peer has fetched the
//! blob, it can serve it on the originator's behalf
//! (`fetch_blob` is content-addressed by digest, so any holder is
//! authoritative). The valid bytes get inserted into both the
//! perpetual table and the in-memory cache backing the local
//! Anemo server — the in-memory write is what lets *other* peers
//! fetch the blob from this validator without a restart, turning
//! every honest receiver into a relay.

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
use anemo::{Network, PeerId};
use ika_network::mpc_artifacts::{InMemoryBlobStore, fetch_blob};
use ika_types::committee::EpochId;
use ika_types::crypto::AuthorityName;
use rand::seq::SliceRandom;
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
        // Build a shuffled candidate peer list once per pass.
        // Asking the originator first preserves the obvious-case
        // fast path; falling through to a randomized order over
        // the rest of the committee spreads load and prevents a
        // byzantine originator from winning by withholding (any
        // peer that already fetched the blob can serve it).
        let mut other_peers: Vec<(AuthorityName, PeerId)> = self
            .authority_names_to_peer_ids
            .iter()
            .filter(|(authority, _)| **authority != self.own_authority)
            .map(|(authority, peer_id)| (*authority, *peer_id))
            .collect();
        other_peers.shuffle(&mut rand::rng());

        for (announcer, digest) in pending {
            // Try the originator first, then every other peer in
            // shuffled order. Break as soon as one serves valid
            // bytes.
            let originator_peer = self.authority_names_to_peer_ids.get(&announcer).copied();
            let mut candidates: Vec<(AuthorityName, PeerId)> = Vec::new();
            if let Some(peer_id) = originator_peer {
                candidates.push((announcer, peer_id));
            }
            for entry in &other_peers {
                if Some(entry.1) == originator_peer {
                    continue;
                }
                candidates.push(*entry);
            }
            if candidates.is_empty() {
                debug!(
                    ?announcer,
                    "peer blob fetcher: no peers mapped at all; skipping"
                );
                continue;
            }

            let mut fetched = false;
            for (candidate_authority, peer_id) in candidates {
                match fetch_blob(&self.p2p_network, peer_id, digest).await {
                    Ok(Some(bytes)) => {
                        match crate::validator_metadata::verify_peer_blob_for_relay(&bytes, &digest)
                        {
                            crate::validator_metadata::PeerBlobVerdict::Accept => {}
                            crate::validator_metadata::PeerBlobVerdict::HashMismatch => {
                                warn!(
                                    ?announcer,
                                    ?candidate_authority,
                                    ?peer_id,
                                    expected = ?digest,
                                    "peer blob fetcher: candidate served bytes that don't \
                                     match the announcement digest; trying next peer"
                                );
                                continue;
                            }
                            crate::validator_metadata::PeerBlobVerdict::DecodeFailed => {
                                // Hash matched (so the announcer
                                // committed to exactly these bytes)
                                // but the bytes don't decode to
                                // valid mpc_data. Refuse to insert:
                                // the in-memory store backs the
                                // local Anemo serve endpoint, so
                                // anything we accept here we'd
                                // relay onward — poisoning every
                                // honest receiver's relay cache.
                                // The byzantine announcer is the
                                // only party who could produce
                                // hash-matching bad bytes (no one
                                // else has the signed digest's
                                // preimage), so dropping costs
                                // nothing useful.
                                warn!(
                                    ?announcer,
                                    ?candidate_authority,
                                    ?peer_id,
                                    "peer blob fetcher: candidate served hash-matching bytes \
                                     that fail structural decode; refusing to relay"
                                );
                                continue;
                            }
                        }
                        if let Err(e) = self
                            .perpetual_tables
                            .insert_mpc_artifact_blob(digest, &bytes)
                        {
                            warn!(
                                error = ?e,
                                ?announcer,
                                ?candidate_authority,
                                "peer blob fetcher: perpetual insert failed; trying next peer"
                            );
                            continue;
                        }
                        self.in_memory_blob_store.insert(digest, bytes);
                        info!(
                            ?announcer,
                            served_by = ?candidate_authority,
                            ?peer_id,
                            "peer blob fetcher: fetched + cached peer mpc_data blob"
                        );
                        fetched = true;
                        break;
                    }
                    Ok(None) => {
                        debug!(
                            ?announcer,
                            ?candidate_authority,
                            ?peer_id,
                            "peer blob fetcher: candidate doesn't have the blob; trying next"
                        );
                    }
                    Err(e) => {
                        debug!(
                            ?announcer,
                            ?candidate_authority,
                            ?peer_id,
                            error = ?e,
                            "peer blob fetcher: transport error; trying next peer"
                        );
                    }
                }
            }
            if !fetched {
                debug!(
                    ?announcer,
                    "peer blob fetcher: no candidate served the blob this pass; will retry"
                );
            }
        }
    }
}
