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
//! submit, but **peer blobs are not carried on the wire** — by
//! design, the blob bytes flow over P2P. Without this fetcher every
//! validator would only ever hold its own blob, the off-chain
//! assembler would return `Incomplete` for every peer, and (in
//! off-chain mode) `sync_next_committee` would loop on
//! `OffChainAssemblyIncomplete` indefinitely; the legacy chain-read
//! fallback only runs when off-chain mode is disabled.
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
//!
//! Each pass also repairs the prior epoch's handoff-cert
//! `ValidatorMpcData` blobs
//! ([`fetch_missing_prior_cert_mpc_data_blobs`]): carried-forward
//! members that have been dark for epochs never announce in the
//! current epoch, so the announcement-driven pass cannot cover
//! them, yet the MPC manager's current-epoch key ingestion needs
//! exactly their cert-pinned blobs (issue #1881).

use crate::authority::authority_per_epoch_store::{
    AuthorityPerEpochStore, AuthorityPerEpochStoreTrait,
};
use crate::blob_cache::BlobCache;
use crate::validator_metadata::{PeerBlobVerdict, verify_peer_blob_for_relay};
use anemo::{Network, PeerId};
use ika_network::mpc_artifacts::fetch_blob;
use ika_types::committee::EpochId;
use ika_types::crypto::AuthorityName;
use ika_types::handoff::{CertifiedHandoffAttestation, HandoffItemKey};
use prometheus::IntCounterVec;
use rand::seq::SliceRandom;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tracing::{debug, info, warn};
use typed_store::Map;

pub struct PeerBlobFetcher {
    epoch_store: Weak<AuthorityPerEpochStore>,
    epoch_id: EpochId,
    own_authority: AuthorityName,
    blob_cache: Arc<BlobCache>,
    p2p_network: Network,
    authority_names_to_peer_ids: HashMap<AuthorityName, PeerId>,
    /// P2P fetch outcomes by result (`ok` / `not_found` / `hash_mismatch` /
    /// `decode_failed` / `cache_insert_failed` / `transport_error`) — the
    /// byzantine-bad-bytes and transport-health signals that explain slow
    /// ready-signal coverage. Registered by the caller (ika-node).
    fetch_outcomes: IntCounterVec,
    /// `(announcer, candidate)` pairs already warned about serving bad
    /// bytes this epoch — the fetch pass re-runs every ~2s while a blob
    /// is unfetched, so a persistently-bad peer would otherwise re-warn
    /// per pass. Warn once per pair, debug thereafter (the
    /// `fetch_outcomes` counter still measures persistent offenders).
    /// Bounded by committee-size² and dropped with the per-epoch task.
    warned_bad_bytes_pairs: Mutex<HashSet<(AuthorityName, AuthorityName)>>,
}

impl PeerBlobFetcher {
    pub fn new(
        epoch_store: Weak<AuthorityPerEpochStore>,
        epoch_id: EpochId,
        own_authority: AuthorityName,
        blob_cache: Arc<BlobCache>,
        p2p_network: Network,
        authority_names_to_peer_ids: HashMap<AuthorityName, PeerId>,
        fetch_outcomes: IntCounterVec,
    ) -> Self {
        Self {
            epoch_store,
            epoch_id,
            own_authority,
            blob_cache,
            p2p_network,
            authority_names_to_peer_ids,
            fetch_outcomes,
            warned_bad_bytes_pairs: Mutex::new(HashSet::new()),
        }
    }

    /// Warn the first time a given `(announcer, candidate)` pair serves
    /// bad bytes this epoch; returns whether the caller should warn (vs
    /// log the repeat at debug).
    fn should_warn_bad_bytes(&self, announcer: AuthorityName, candidate: AuthorityName) -> bool {
        self.warned_bad_bytes_pairs
            .lock()
            .expect("mutex poisoned")
            .insert((announcer, candidate))
    }

    pub async fn run(self: Arc<Self>) {
        use ika_types::sui::epoch_start_system::EpochStartSystemTrait;
        let mut poll_interval = Duration::from_secs(2);
        if let Some(epoch_store) = self.epoch_store.upgrade() {
            if !epoch_store
                .protocol_config()
                .off_chain_validator_metadata_enabled()
            {
                info!(
                    epoch = self.epoch_id,
                    "off-chain validator metadata disabled; peer blob fetcher exiting"
                );
                return;
            }
            poll_interval = crate::validator_metadata::epoch_scaled_poll_interval(
                epoch_store.epoch_start_state().epoch_duration_ms(),
                poll_interval,
            );
        }
        loop {
            self.fetch_missing_blobs_once().await;
            self.fetch_missing_prior_cert_blobs_once().await;
            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Single prior-cert repair pass: read the prior epoch's handoff cert
    /// (if any) and fetch every cert-pinned `ValidatorMpcData` blob missing
    /// locally from committee peers — see
    /// [`fetch_missing_prior_cert_mpc_data_blobs`] for why the
    /// announcement-driven pass alone cannot cover these blobs.
    async fn fetch_missing_prior_cert_blobs_once(&self) {
        let Some(prior_epoch) = self.epoch_id.checked_sub(1) else {
            return;
        };
        let Some(epoch_store) = self.epoch_store.upgrade() else {
            return;
        };
        let cert = match epoch_store.get_certified_handoff_attestation(prior_epoch) {
            Ok(Some(cert)) => cert,
            // No cert (genesis, a pre-v4 prior epoch, or the bootstrap
            // anchor still fetching) — nothing to repair from; the next
            // pass re-checks.
            Ok(None) => return,
            Err(e) => {
                debug!(
                    prior_epoch,
                    error = ?e,
                    "peer blob fetcher: prior handoff cert read failed; retrying next pass"
                );
                return;
            }
        };
        fetch_missing_prior_cert_mpc_data_blobs(
            &cert,
            self.own_authority,
            &self.blob_cache,
            &self.p2p_network,
            &self.authority_names_to_peer_ids,
        )
        .await;
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
                let Ok((authority, announcement)) = entry else {
                    continue;
                };
                if authority == self.own_authority {
                    // Our own announcement; the producer path inserted
                    // the blob into both stores at submission time.
                    continue;
                }
                let digest = announcement.blob_hash;
                // Already hold the blob (either store)? Nothing to
                // fetch. The cache's read-through `get` means a
                // perpetual-only blob is still servable to peers
                // without an explicit in-memory backfill here.
                if self.blob_cache.contains(&digest) {
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
                                self.fetch_outcomes
                                    .with_label_values(&["hash_mismatch"])
                                    .inc();
                                if self.should_warn_bad_bytes(announcer, candidate_authority) {
                                    warn!(
                                        ?announcer,
                                        ?candidate_authority,
                                        ?peer_id,
                                        expected = ?digest,
                                        "peer blob fetcher: candidate served bytes that don't \
                                         match the announcement digest; trying next peer"
                                    );
                                } else {
                                    debug!(
                                        ?announcer,
                                        ?candidate_authority,
                                        ?peer_id,
                                        expected = ?digest,
                                        "peer blob fetcher: candidate again served \
                                         hash-mismatching bytes; trying next peer"
                                    );
                                }
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
                                self.fetch_outcomes
                                    .with_label_values(&["decode_failed"])
                                    .inc();
                                if self.should_warn_bad_bytes(announcer, candidate_authority) {
                                    warn!(
                                        ?announcer,
                                        ?candidate_authority,
                                        ?peer_id,
                                        "peer blob fetcher: candidate served hash-matching bytes \
                                         that fail structural decode; refusing to relay"
                                    );
                                } else {
                                    debug!(
                                        ?announcer,
                                        ?candidate_authority,
                                        ?peer_id,
                                        "peer blob fetcher: candidate again served \
                                         hash-matching undecodable bytes; refusing to relay"
                                    );
                                }
                                continue;
                            }
                        }
                        // Write-through: durable perpetual + in-memory
                        // mirror in one call, so the blob is both
                        // restart-safe and immediately P2P-servable.
                        if let Err(e) = self.blob_cache.insert(digest, bytes) {
                            self.fetch_outcomes
                                .with_label_values(&["cache_insert_failed"])
                                .inc();
                            warn!(
                                error = ?e,
                                ?announcer,
                                ?candidate_authority,
                                "peer blob fetcher: cache insert failed; trying next peer"
                            );
                            continue;
                        }
                        self.fetch_outcomes.with_label_values(&["ok"]).inc();
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
                        self.fetch_outcomes.with_label_values(&["not_found"]).inc();
                        debug!(
                            ?announcer,
                            ?candidate_authority,
                            ?peer_id,
                            "peer blob fetcher: candidate doesn't have the blob; trying next"
                        );
                    }
                    Err(e) => {
                        self.fetch_outcomes
                            .with_label_values(&["transport_error"])
                            .inc();
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

/// Fetch the prior handoff cert's `ValidatorMpcData` blobs (∩ current
/// committee) that are missing from the local stores, from committee peers.
///
/// The announcement-driven pass only covers blobs someone announced THIS
/// epoch. A carried-forward committee member that has been dark for epochs
/// never re-announces — its digest re-enters each epoch's cert via
/// carry-forward — so a validator whose perpetual store post-dates that
/// member's last announcement (binary upgraded to the blob-writing version
/// later, DB restored, writes lost in a crash window) holds no local copy
/// and has no announcement to fetch by. The MPC manager sources the CURRENT
/// epoch's validator key bundle from exactly these cert digests against the
/// perpetual store and correctly defers ingestion while any pinned blob is
/// missing (never falling back to the freeze channel); without this repair
/// the deferral retries the same local store forever and the validator is
/// MPC-dead for this and every following epoch (issue #1881).
///
/// Byte-safe by construction: the digests come from the quorum-signed cert
/// and blobs are content-addressed, so ANY holder is authoritative. The
/// blob's owner is asked first, but it is typically exactly the dark member,
/// so every other committee peer follows in shuffled order. Fetched bytes
/// are verified (digest + structural decode) before the write-through
/// insert into the perpetual + in-memory stores. Returns the number of
/// blobs fetched and persisted this pass; still-missing blobs are retried
/// on the next pass.
pub async fn fetch_missing_prior_cert_mpc_data_blobs(
    cert: &CertifiedHandoffAttestation,
    own_authority: AuthorityName,
    blob_cache: &BlobCache,
    p2p_network: &Network,
    authority_names_to_peer_ids: &HashMap<AuthorityName, PeerId>,
) -> usize {
    let missing: Vec<(AuthorityName, [u8; 32])> = cert
        .attestation
        .items
        .iter()
        .filter_map(|(key, digest)| match key {
            HandoffItemKey::ValidatorMpcData { validator } => Some((*validator, *digest)),
            _ => None,
        })
        // Only current committee members feed the manager's key bundle; a
        // departed validator's carried digest is dead weight here.
        .filter(|(validator, _)| {
            *validator == own_authority || authority_names_to_peer_ids.contains_key(validator)
        })
        .filter(|(_, digest)| !blob_cache.contains(digest))
        .collect();
    if missing.is_empty() {
        return 0;
    }
    let mut other_peers: Vec<(AuthorityName, PeerId)> = authority_names_to_peer_ids
        .iter()
        .filter(|(authority, _)| **authority != own_authority)
        .map(|(authority, peer_id)| (*authority, *peer_id))
        .collect();
    other_peers.shuffle(&mut rand::rng());

    let mut fetched_count = 0;
    for (owner, digest) in missing {
        let owner_peer = authority_names_to_peer_ids.get(&owner).copied();
        let candidates = owner_peer
            .map(|peer_id| (owner, peer_id))
            .into_iter()
            .chain(
                other_peers
                    .iter()
                    .filter(|(_, peer_id)| Some(*peer_id) != owner_peer)
                    .copied(),
            );
        let mut fetched = false;
        for (candidate_authority, peer_id) in candidates {
            match fetch_blob(p2p_network, peer_id, digest).await {
                Ok(Some(bytes)) => {
                    if !matches!(
                        verify_peer_blob_for_relay(&bytes, &digest),
                        PeerBlobVerdict::Accept
                    ) {
                        debug!(
                            ?owner,
                            ?candidate_authority,
                            ?peer_id,
                            expected = ?digest,
                            "prior-cert blob repair: candidate served bytes that fail \
                             digest/decode verification; trying next peer"
                        );
                        continue;
                    }
                    if let Err(e) = blob_cache.insert(digest, bytes) {
                        warn!(
                            error = ?e,
                            ?owner,
                            ?candidate_authority,
                            "prior-cert blob repair: cache insert failed; trying next peer"
                        );
                        continue;
                    }
                    info!(
                        ?owner,
                        served_by = ?candidate_authority,
                        ?peer_id,
                        "prior-cert blob repair: fetched + persisted missing mpc_data blob"
                    );
                    fetched = true;
                    fetched_count += 1;
                    break;
                }
                Ok(None) => {
                    debug!(
                        ?owner,
                        ?candidate_authority,
                        ?peer_id,
                        "prior-cert blob repair: candidate doesn't have the blob; trying next"
                    );
                }
                Err(e) => {
                    debug!(
                        ?owner,
                        ?candidate_authority,
                        ?peer_id,
                        error = ?e,
                        "prior-cert blob repair: transport error; trying next peer"
                    );
                }
            }
        }
        if !fetched {
            debug!(
                ?owner,
                "prior-cert blob repair: no candidate served the blob this pass; will retry"
            );
        }
    }
    fetched_count
}
