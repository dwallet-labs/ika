// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Write-through + read-through cache for content-addressed MPC
//! blobs.
//!
//! Two stores back the off-chain blob plane: the durable perpetual
//! `mpc_artifact_blobs` table and the in-memory cache that backs the
//! Anemo `GetMpcDataBlob` server. Keeping them in sync by hand at
//! every call site is error-prone — a forgotten in-memory mirror
//! leaves a durably-stored blob unservable until the next restart
//! re-hydrates the cache.
//!
//! `BlobCache` owns both and exposes a single `insert`/`get` so call
//! sites can't write one store and forget the other:
//! - `insert` is write-through: durable perpetual first, then the
//!   in-memory hot cache.
//! - `get` is read-through: in-memory first, durable perpetual on a
//!   miss. The fallback means a blob written only to perpetual (e.g.
//!   a network DKG / reconfiguration output cached by the per-epoch
//!   store) is still servable over P2P without waiting for a restart.

use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
use ika_network::mpc_artifacts::{InMemoryBlobStore, MpcDataBlobStorage};
use ika_types::error::IkaResult;
use std::sync::Arc;
use tracing::warn;

pub struct BlobCache {
    in_memory: Arc<InMemoryBlobStore>,
    perpetual: Arc<AuthorityPerpetualTables>,
}

impl BlobCache {
    pub fn new(
        in_memory: Arc<InMemoryBlobStore>,
        perpetual: Arc<AuthorityPerpetualTables>,
    ) -> Arc<Self> {
        Arc::new(Self {
            in_memory,
            perpetual,
        })
    }

    /// Write-through: durable perpetual first, then the in-memory hot
    /// cache. Returns `Err` only when the durable write fails (the
    /// in-memory write is infallible). On a durable-write error the
    /// in-memory cache is intentionally NOT populated — a blob that
    /// isn't durable shouldn't appear servable, since it wouldn't
    /// survive a restart.
    pub fn insert(&self, digest: [u8; 32], bytes: Vec<u8>) -> IkaResult<()> {
        self.perpetual.insert_mpc_artifact_blob(digest, &bytes)?;
        self.in_memory.insert(digest, bytes);
        Ok(())
    }

    /// Whether the blob is available in either store. Checks the
    /// cheap in-memory map first, then the durable table. Used by the
    /// peer-blob fetcher to skip digests it already holds without
    /// cloning the bytes.
    pub fn contains(&self, digest: &[u8; 32]) -> bool {
        self.in_memory.contains(digest)
            || matches!(self.perpetual.get_mpc_artifact_blob(digest), Ok(Some(_)))
    }

    /// The underlying in-memory store, exposed for startup hydration.
    pub fn in_memory(&self) -> &Arc<InMemoryBlobStore> {
        &self.in_memory
    }
}

impl MpcDataBlobStorage for BlobCache {
    /// Read-through: in-memory hot cache first, durable perpetual on
    /// a miss. The perpetual fallback is what makes a perpetual-only
    /// blob servable without a restart.
    fn get(&self, blob_hash: &[u8; 32]) -> Option<Vec<u8>> {
        if let Some(bytes) = self.in_memory.get(blob_hash) {
            return Some(bytes);
        }
        self.perpetual
            .get_mpc_artifact_blob(blob_hash)
            .ok()
            .flatten()
    }

    fn insert_blob(&self, blob_hash: [u8; 32], blob: Vec<u8>) {
        if let Err(e) = self.insert(blob_hash, blob) {
            warn!(error = ?e, "BlobCache durable insert failed; blob not cached");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
    use ika_network::mpc_artifacts::mpc_data_blob_hash;
    use tempfile::TempDir;

    fn test_cache() -> (Arc<BlobCache>, TempDir) {
        let dir = TempDir::new().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let in_memory = InMemoryBlobStore::new();
        (BlobCache::new(in_memory, perpetual), dir)
    }

    #[tokio::test]
    async fn insert_writes_both_stores_and_get_returns_it() {
        let (cache, _dir) = test_cache();
        let bytes = b"some mpc blob".to_vec();
        let digest = mpc_data_blob_hash(&bytes);
        cache.insert(digest, bytes.clone()).unwrap();
        // In-memory hot path returns it.
        assert_eq!(cache.in_memory().get(&digest).as_ref(), Some(&bytes));
        // Read-through returns it.
        assert_eq!(cache.get(&digest).as_ref(), Some(&bytes));
        assert!(cache.contains(&digest));
    }

    #[tokio::test]
    async fn get_reads_through_to_perpetual_on_memory_miss() {
        // Simulate the F2-2 scenario: a blob is written to perpetual
        // only (e.g. a DKG output cached by the per-epoch store,
        // which never touched the in-memory mirror). The server must
        // still serve it — read-through covers it without a restart.
        let (cache, _dir) = test_cache();
        let bytes = b"perpetual-only protocol output".to_vec();
        let digest = mpc_data_blob_hash(&bytes);
        // Write directly to perpetual, bypassing the in-memory mirror.
        cache
            .perpetual
            .insert_mpc_artifact_blob(digest, &bytes)
            .unwrap();
        assert!(
            cache.in_memory().get(&digest).is_none(),
            "precondition: not in the in-memory mirror"
        );
        // Read-through serves it from perpetual.
        assert_eq!(cache.get(&digest).as_ref(), Some(&bytes));
        assert!(cache.contains(&digest));
    }

    #[tokio::test]
    async fn get_returns_none_for_absent_digest() {
        let (cache, _dir) = test_cache();
        let absent = [0xAB; 32];
        assert!(cache.get(&absent).is_none());
        assert!(!cache.contains(&absent));
    }
}
