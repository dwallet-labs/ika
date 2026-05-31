// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Content-addressed MPC blob storage and fetch.

use anemo::{Network, PeerId};
use fastcrypto::hash::{Blake2b256, HashFunction};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};

use super::ValidatorMetadataClient;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct GetMpcDataBlobRequest {
    pub blob_hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MpcDataBlob {
    pub bytes: Vec<u8>,
}

/// Storage backing for the server: a content-addressed blob lookup.
/// Implementations are expected to be cheap (in-memory) — the server
/// is called on the request hot path.
pub trait MpcDataBlobStorage: Send + Sync + 'static {
    fn get(&self, blob_hash: &[u8; 32]) -> Option<Vec<u8>>;
    fn insert_blob(&self, blob_hash: [u8; 32], blob: Vec<u8>);
}

/// Default byte cap for the in-memory serve cache. Generous enough to
/// hold a few epochs of `mpc_data` + network-key output blobs; eviction
/// only bounds RAM, never availability (see [`InMemoryBlobStore`]).
const DEFAULT_MAX_BYTES: usize = 512 * 1024 * 1024;

/// In-memory content-addressed cache of MPC data blobs. Producer
/// pre-populates with their own blob on announce; consumers populate
/// as they fetch from peers. Hydrated from `AuthorityPerpetualTables`
/// at node startup so cross-restart serves don't need a chain refresh.
///
/// Bounded by a total-bytes cap with **FIFO** eviction of the
/// oldest-inserted blobs. Every blob cached here is also written to the
/// durable perpetual table (the only insert path is `BlobCache`'s
/// write-through), and the serving `BlobCache::get` reads through to
/// perpetual on an in-memory miss — so eviction is purely a RAM bound
/// and never makes a blob unservable. FIFO (not LRU) is deliberate:
/// `get` stays a cheap read-lock on the server hot path, where LRU
/// would force a write-lock to record recency.
pub struct InMemoryBlobStore {
    inner: RwLock<BlobStoreInner>,
}

struct BlobStoreInner {
    blobs: HashMap<[u8; 32], Vec<u8>>,
    /// Insertion order, for FIFO eviction. `get` does not touch this,
    /// keeping reads off the write lock.
    insertion_order: VecDeque<[u8; 32]>,
    total_bytes: usize,
    max_bytes: usize,
}

impl BlobStoreInner {
    fn insert(&mut self, blob_hash: [u8; 32], blob: Vec<u8>) {
        // Content-addressed: a digest we already hold maps to identical
        // bytes, so re-inserting must be a no-op — otherwise it would
        // double-count bytes and push a duplicate eviction entry.
        if self.blobs.contains_key(&blob_hash) {
            return;
        }
        self.total_bytes = self.total_bytes.saturating_add(blob.len());
        self.blobs.insert(blob_hash, blob);
        self.insertion_order.push_back(blob_hash);
        // Evict oldest-first until back under the cap, but always keep
        // the just-inserted blob (`len() > 1`): a single blob larger
        // than the whole cap is still servable, and evicting it
        // immediately would make the insert pointless. Evicted blobs
        // remain available via the perpetual read-through fallback.
        while self.total_bytes > self.max_bytes && self.insertion_order.len() > 1 {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            if let Some(evicted) = self.blobs.remove(&oldest) {
                self.total_bytes = self.total_bytes.saturating_sub(evicted.len());
            }
        }
    }
}

impl InMemoryBlobStore {
    pub fn new() -> Arc<Self> {
        Self::with_max_bytes(DEFAULT_MAX_BYTES)
    }

    /// Construct with an explicit byte cap (used by tests to exercise
    /// eviction without allocating the default's worth of blobs).
    pub fn with_max_bytes(max_bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: RwLock::new(BlobStoreInner {
                blobs: HashMap::new(),
                insertion_order: VecDeque::new(),
                total_bytes: 0,
                max_bytes,
            }),
        })
    }

    pub fn insert(&self, blob_hash: [u8; 32], blob: Vec<u8>) {
        self.inner.write().unwrap().insert(blob_hash, blob);
    }

    pub fn contains(&self, blob_hash: &[u8; 32]) -> bool {
        self.inner.read().unwrap().blobs.contains_key(blob_hash)
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().blobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().blobs.is_empty()
    }
}

impl MpcDataBlobStorage for InMemoryBlobStore {
    fn get(&self, blob_hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.inner.read().unwrap().blobs.get(blob_hash).cloned()
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn fifo_evicts_oldest_when_over_byte_cap() {
        // Cap holds ~2 of the 100-byte blobs below.
        let store = InMemoryBlobStore::with_max_bytes(250);
        let make = |n: u8| {
            let bytes = vec![n; 100];
            (mpc_data_blob_hash(&bytes), bytes)
        };
        let (h1, b1) = make(1);
        let (h2, b2) = make(2);
        let (h3, b3) = make(3);
        store.insert(h1, b1);
        store.insert(h2, b2);
        assert_eq!(store.len(), 2);
        // Third insert pushes total to 300 > 250 → evict the oldest (h1).
        store.insert(h3, b3.clone());
        assert_eq!(store.len(), 2);
        assert!(!store.contains(&h1), "oldest should be evicted");
        assert!(store.contains(&h2));
        assert!(store.contains(&h3));
        assert_eq!(store.get(&h3).as_ref(), Some(&b3));
    }

    #[test]
    fn duplicate_insert_is_noop_and_does_not_double_count() {
        // Cap holds exactly two 100-byte blobs.
        let store = InMemoryBlobStore::with_max_bytes(200);
        let make = |n: u8| {
            let bytes = vec![n; 100];
            (mpc_data_blob_hash(&bytes), bytes)
        };
        let (h1, b1) = make(1);
        let (h2, b2) = make(2);
        store.insert(h1, b1.clone());
        // Re-insert h1 (content-addressed no-op): must not double-count
        // bytes, else inserting h2 would spuriously evict h1.
        store.insert(h1, b1);
        store.insert(h2, b2);
        assert_eq!(store.len(), 2);
        assert!(store.contains(&h1));
        assert!(store.contains(&h2));
    }

    #[test]
    fn single_blob_larger_than_cap_is_kept() {
        let store = InMemoryBlobStore::with_max_bytes(50);
        let bytes = vec![7u8; 100];
        let hash = mpc_data_blob_hash(&bytes);
        store.insert(hash, bytes.clone());
        // Over cap, but evicting the only/just-inserted blob would make
        // the insert pointless — it stays and is servable.
        assert_eq!(store.len(), 1);
        assert_eq!(store.get(&hash).as_ref(), Some(&bytes));
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
}
