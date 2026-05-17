// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Content-addressed MPC blob storage and fetch.

use anemo::{Network, PeerId};
use fastcrypto::hash::{Blake2b256, HashFunction};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
