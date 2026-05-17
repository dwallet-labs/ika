// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Anemo service that serves validator MPC class-groups public material
//! blobs by Blake2b256 digest.
//!
//! The cert / announcement layer (consensus + local store) carries
//! digests; this layer carries the bytes. Each producer caches its own
//! blob locally and serves on request; consumers fetch by digest, hash-
//! verify, and cache.

use anemo::Network;
use anemo::PeerId;
use arc_swap::ArcSwapOption;
use fastcrypto::hash::{Blake2b256, HashFunction};
use ika_types::committee::EpochId;
use ika_types::validator_metadata::{
    CertifiedHandoffAttestation, SignedValidatorMpcDataAnnouncement,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

mod generated {
    include!(concat!(env!("OUT_DIR"), "/ika.ValidatorMetadata.rs"));
}
mod server;

pub use generated::{
    validator_metadata_client::ValidatorMetadataClient,
    validator_metadata_server::{ValidatorMetadata, ValidatorMetadataServer},
};
pub use server::Server;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct GetMpcDataBlobRequest {
    pub blob_hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MpcDataBlob {
    pub bytes: Vec<u8>,
}

/// Wrapped by a joining validator (not yet in the consensus committee)
/// to ask a current-committee peer to relay their `mpc_data`
/// announcement into consensus. The peer verifies the signature
/// against the `PendingActiveSet` before relaying (see step 6); for
/// transport here the wire format is just the signed announcement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitMpcDataAnnouncementRequest {
    pub announcement: SignedValidatorMpcDataAnnouncement,
}

/// Result of a relay attempt. `Accepted` means the relayer queued the
/// announcement for consensus submission; it does NOT guarantee
/// inclusion. `Rejected { reason }` means the relayer is unwilling
/// (e.g. no epoch store yet, signature didn't verify, etc.).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SubmitMpcDataAnnouncementResponse {
    Accepted,
    Rejected { reason: String },
}

/// Asks for the `CertifiedHandoffAttestation` covering `epoch` — i.e.,
/// the cert produced by the committee that was active *during*
/// `epoch`, attesting to the handoff into `epoch + 1`. Joiners walk
/// these in epoch order to bootstrap their off-chain artifact view.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct GetCertifiedHandoffAttestationRequest {
    pub epoch: EpochId,
}

/// Storage backing for the server: a content-addressed blob lookup.
/// Implementations are expected to be cheap (in-memory) — the server
/// is called on the request hot path.
pub trait MpcDataBlobStorage: Send + Sync + 'static {
    fn get(&self, blob_hash: &[u8; 32]) -> Option<Vec<u8>>;
    fn insert_blob(&self, blob_hash: [u8; 32], blob: Vec<u8>);
}

/// Read-only lookup of certified handoff attestations by the epoch
/// they attest. Backed at runtime by
/// `AuthorityPerpetualTables::certified_handoff_attestations`;
/// returning `None` is "I don't have this epoch's cert", which is a
/// normal response for joiners asking about epochs the server is
/// too new to cover.
pub trait HandoffCertStorage: Send + Sync + 'static {
    fn get(&self, epoch: EpochId) -> Option<CertifiedHandoffAttestation>;
}

/// Wraps the consensus-submission side of the relay. Implemented by
/// the node once the per-epoch store + consensus adapter are up;
/// before that, the server holds `None` and rejects requests.
///
/// Implementations are responsible for:
/// - verifying the announcement (sig against current committee OR
///   pending active set, depending on whether the signer is a member
///   of the current consensus committee or a joiner — see step 6),
/// - bouncing duplicates by the latest-by-timestamp rule,
/// - submitting the resulting `ConsensusTransaction` via the adapter.
#[async_trait::async_trait]
pub trait AnnouncementRelay: Send + Sync + 'static {
    async fn relay(&self, announcement: SignedValidatorMpcDataAnnouncement) -> Result<(), String>;
}

/// Late-bindable holder for the announcement relay. The Anemo server
/// is constructed at node startup, well before the first epoch store
/// exists; the node installs a relay impl once the epoch state is up
/// and re-installs across epoch transitions.
#[derive(Default)]
pub struct AnnouncementRelayHandle {
    inner: ArcSwapOption<Box<dyn AnnouncementRelay>>,
}

impl AnnouncementRelayHandle {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn install(&self, relay: Box<dyn AnnouncementRelay>) {
        self.inner.store(Some(Arc::new(relay)));
    }

    pub fn clear(&self) {
        self.inner.store(None);
    }

    pub fn is_installed(&self) -> bool {
        self.inner.load().is_some()
    }

    pub(crate) fn current(&self) -> Option<Arc<Box<dyn AnnouncementRelay>>> {
        self.inner.load_full()
    }
}

/// In-memory content-addressed cache of MPC data blobs. Producer
/// pre-populates with their own blob on announce; consumers populate
/// as they fetch from peers. Hydrated from `AuthorityPerpetualTables`
/// at node startup so cross-restart serves don't need a chain refresh.
#[derive(Default)]
pub struct InMemoryBlobStore {
    blobs: RwLock<HashMap<[u8; 32], Vec<u8>>>,
}

impl InMemoryBlobStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn insert(&self, blob_hash: [u8; 32], blob: Vec<u8>) {
        self.blobs.write().unwrap().insert(blob_hash, blob);
    }

    pub fn contains(&self, blob_hash: &[u8; 32]) -> bool {
        self.blobs.read().unwrap().contains_key(blob_hash)
    }

    pub fn len(&self) -> usize {
        self.blobs.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.blobs.read().unwrap().is_empty()
    }
}

impl MpcDataBlobStorage for InMemoryBlobStore {
    fn get(&self, blob_hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.blobs.read().unwrap().get(blob_hash).cloned()
    }

    fn insert_blob(&self, blob_hash: [u8; 32], blob: Vec<u8>) {
        self.insert(blob_hash, blob);
    }
}

/// Computes the Blake2b256 digest used to address `mpc_data` blobs in
/// the cache and announcements.
pub fn mpc_data_blob_hash(blob: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b256::default();
    hasher.update(blob);
    hasher.finalize().into()
}

/// Build a `ValidatorMetadataServer` backed by `storage`, an
/// announcement-relay handle, and a certified-handoff store. The
/// relay handle starts empty; the node installs a relay impl into
/// it once per-epoch state is up. The cert store is wired directly
/// to perpetual storage at construction time.
pub fn build_server<S: MpcDataBlobStorage, C: HandoffCertStorage>(
    storage: Arc<S>,
    relay: Arc<AnnouncementRelayHandle>,
    cert_storage: Arc<C>,
) -> ValidatorMetadataServer<Server<S, C>> {
    ValidatorMetadataServer::new(Server {
        storage,
        relay,
        cert_storage,
    })
}

/// Fetch a blob by hash from `peer`. Returns `Ok(None)` if the peer
/// doesn't have it; returns an `Err` only on transport failure.
/// Callers MUST hash-verify the returned bytes against the requested
/// digest before trusting them — the network layer doesn't.
pub async fn fetch_blob(
    network: &Network,
    peer_id: PeerId,
    blob_hash: [u8; 32],
) -> anyhow::Result<Option<Vec<u8>>> {
    let peer = network
        .peer(peer_id)
        .ok_or_else(|| anyhow::anyhow!("peer not connected: {peer_id}"))?;
    let mut client = ValidatorMetadataClient::new(peer);
    let response = client
        .get_mpc_data_blob(GetMpcDataBlobRequest { blob_hash })
        .await
        .map_err(|status| anyhow::anyhow!("get_mpc_data_blob failed: {status:?}"))?;
    Ok(response.into_inner().map(|b| b.bytes))
}

/// Ask `peer` to relay `announcement` into consensus on behalf of
/// the signer. Used by a joining validator that isn't yet a member of
/// the consensus committee: it fans this RPC out to every current-
/// committee peer it can reach, and one honest relayer is enough.
pub async fn submit_announcement_to_peer(
    network: &Network,
    peer_id: PeerId,
    announcement: SignedValidatorMpcDataAnnouncement,
) -> anyhow::Result<SubmitMpcDataAnnouncementResponse> {
    let peer = network
        .peer(peer_id)
        .ok_or_else(|| anyhow::anyhow!("peer not connected: {peer_id}"))?;
    let mut client = ValidatorMetadataClient::new(peer);
    let response = client
        .submit_mpc_data_announcement(SubmitMpcDataAnnouncementRequest { announcement })
        .await
        .map_err(|status| anyhow::anyhow!("submit_mpc_data_announcement failed: {status:?}"))?;
    Ok(response.into_inner())
}

/// Fetch a `CertifiedHandoffAttestation` for `epoch` from `peer`.
/// Returns `Ok(None)` if the peer doesn't have a cert for that
/// epoch (it may be too new); `Err` is reserved for transport
/// failures. Callers MUST re-verify the returned cert against the
/// committee that produced it before trusting it — the network
/// layer doesn't.
pub async fn fetch_certified_handoff_attestation(
    network: &Network,
    peer_id: PeerId,
    epoch: EpochId,
) -> anyhow::Result<Option<CertifiedHandoffAttestation>> {
    let peer = network
        .peer(peer_id)
        .ok_or_else(|| anyhow::anyhow!("peer not connected: {peer_id}"))?;
    let mut client = ValidatorMetadataClient::new(peer);
    let response = client
        .get_certified_handoff_attestation(GetCertifiedHandoffAttestationRequest { epoch })
        .await
        .map_err(|status| {
            anyhow::anyhow!("get_certified_handoff_attestation failed: {status:?}")
        })?;
    Ok(response.into_inner())
}

/// Fan out a single announcement to every supplied peer concurrently.
/// Returns the per-peer outcomes for telemetry; the joiner can stop
/// once it sees enough `Accepted`s. We never block reconfig on this
/// — the joiner is best-effort and current-committee validators
/// don't need every relay attempt to succeed.
pub async fn submit_announcement_to_committee(
    network: &Network,
    peers: &[PeerId],
    announcement: SignedValidatorMpcDataAnnouncement,
) -> Vec<(PeerId, anyhow::Result<SubmitMpcDataAnnouncementResponse>)> {
    let futures = peers.iter().map(|peer_id| {
        let peer_id = *peer_id;
        let announcement = announcement.clone();
        async move {
            let result = submit_announcement_to_peer(network, peer_id, announcement).await;
            (peer_id, result)
        }
    });
    futures::future::join_all(futures).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn in_memory_blob_store_roundtrip() {
        let store = InMemoryBlobStore::new();
        let bytes = b"hello mpc data".to_vec();
        let hash = mpc_data_blob_hash(&bytes);
        assert!(!store.contains(&hash));
        store.insert(hash, bytes.clone());
        assert!(store.contains(&hash));
        assert_eq!(store.get(&hash).as_ref(), Some(&bytes));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn mpc_data_blob_hash_is_deterministic() {
        let bytes = vec![1, 2, 3, 4, 5];
        let h1 = mpc_data_blob_hash(&bytes);
        let h2 = mpc_data_blob_hash(&bytes);
        assert_eq!(h1, h2);
        // Different input → different hash.
        let h3 = mpc_data_blob_hash(b"different");
        assert_ne!(h1, h3);
    }

    #[test]
    fn relay_handle_starts_empty_then_installs_and_clears() {
        let handle = AnnouncementRelayHandle::new();
        assert!(!handle.is_installed());
        assert!(handle.current().is_none());

        struct StubRelay;
        #[async_trait::async_trait]
        impl AnnouncementRelay for StubRelay {
            async fn relay(&self, _: SignedValidatorMpcDataAnnouncement) -> Result<(), String> {
                Ok(())
            }
        }

        handle.install(Box::new(StubRelay));
        assert!(handle.is_installed());
        assert!(handle.current().is_some());

        handle.clear();
        assert!(!handle.is_installed());
        assert!(handle.current().is_none());
    }

    #[test]
    fn relay_handle_install_drops_previous_relay() {
        // Re-installing replaces the previously-installed relay.
        // This is used at every epoch boundary to re-bind the
        // relay to the freshly-built epoch store. We verify by
        // observing that the first relay's Drop runs as soon as
        // the second one is installed.
        struct DropCounter(Arc<AtomicU32>);
        #[async_trait::async_trait]
        impl AnnouncementRelay for DropCounter {
            async fn relay(&self, _: SignedValidatorMpcDataAnnouncement) -> Result<(), String> {
                Ok(())
            }
        }
        impl Drop for DropCounter {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let first_drops = Arc::new(AtomicU32::new(0));
        let second_drops = Arc::new(AtomicU32::new(0));
        let handle = AnnouncementRelayHandle::new();

        handle.install(Box::new(DropCounter(first_drops.clone())));
        assert_eq!(first_drops.load(Ordering::SeqCst), 0);

        handle.install(Box::new(DropCounter(second_drops.clone())));
        assert_eq!(
            first_drops.load(Ordering::SeqCst),
            1,
            "first relay dropped on swap"
        );
        assert_eq!(second_drops.load(Ordering::SeqCst), 0);

        handle.clear();
        assert_eq!(
            second_drops.load(Ordering::SeqCst),
            1,
            "second relay dropped on clear"
        );
    }
}
