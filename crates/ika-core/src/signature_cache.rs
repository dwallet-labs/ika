// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::signature_store::{SignatureMetadata, StoredSignature};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Entry in the signature cache
#[derive(Clone)]
struct CacheEntry<T> {
    data: T,
    inserted_at: Instant,
    ttl: Duration,
}

impl<T> CacheEntry<T> {
    fn new(data: T, ttl: Duration) -> Self {
        Self {
            data,
            inserted_at: Instant::now(),
            ttl,
        }
    }

    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() > self.ttl
    }
}

/// LRU cache for signature data with TTL support
pub struct SignatureCache {
    signatures: Mutex<LruCache<Vec<u8>, CacheEntry<StoredSignature>>>,
    metadata: Mutex<LruCache<Vec<u8>, CacheEntry<SignatureMetadata>>>,
    dwallet_index: Mutex<LruCache<Vec<u8>, CacheEntry<Vec<Vec<u8>>>>>,
    default_ttl: Duration,
}

impl SignatureCache {
    /// Create a new signature cache with specified size in MB
    pub fn new(size_mb: usize) -> Self {
        // Estimate cache sizes based on MB allocation
        // Assume average signature entry is ~1KB, metadata ~500B
        let estimated_entries = (size_mb * 1024) / 2; // Split between signatures and metadata
        let cache_size = NonZeroUsize::new(estimated_entries).unwrap_or(NonZeroUsize::new(1000).unwrap());

        Self {
            signatures: Mutex::new(LruCache::new(cache_size)),
            metadata: Mutex::new(LruCache::new(cache_size)),
            dwallet_index: Mutex::new(LruCache::new(
                NonZeroUsize::new(estimated_entries / 10).unwrap_or(NonZeroUsize::new(100).unwrap()),
            )),
            default_ttl: Duration::from_secs(300), // 5 minutes default TTL
        }
    }

    /// Get a signature from cache
    pub fn get_signature(&self, sign_id: &[u8]) -> Option<StoredSignature> {
        let mut cache = self.signatures.lock().unwrap();
        if let Some(entry) = cache.get(sign_id) {
            if !entry.is_expired() {
                return Some(entry.data.clone());
            }
            // Remove expired entry
            cache.pop(sign_id);
        }
        None
    }

    /// Put a signature into cache
    pub fn put_signature(&self, sign_id: Vec<u8>, signature: StoredSignature) {
        let mut cache = self.signatures.lock().unwrap();
        cache.put(sign_id, CacheEntry::new(signature, self.default_ttl));
    }

    /// Get signature metadata from cache
    pub fn get_metadata(&self, sign_id: &[u8]) -> Option<SignatureMetadata> {
        let mut cache = self.metadata.lock().unwrap();
        if let Some(entry) = cache.get(sign_id) {
            if !entry.is_expired() {
                return Some(entry.data.clone());
            }
            cache.pop(sign_id);
        }
        None
    }

    /// Put signature metadata into cache
    pub fn put_metadata(&self, sign_id: Vec<u8>, metadata: SignatureMetadata) {
        let mut cache = self.metadata.lock().unwrap();
        cache.put(sign_id, CacheEntry::new(metadata, self.default_ttl));
    }

    /// Get dwallet signatures from cache
    pub fn get_dwallet_signatures(&self, dwallet_id: &[u8]) -> Option<Vec<Vec<u8>>> {
        let mut cache = self.dwallet_index.lock().unwrap();
        if let Some(entry) = cache.get(dwallet_id) {
            if !entry.is_expired() {
                return Some(entry.data.clone());
            }
            cache.pop(dwallet_id);
        }
        None
    }

    /// Put dwallet signatures into cache
    pub fn put_dwallet_signatures(&self, dwallet_id: Vec<u8>, sign_ids: Vec<Vec<u8>>) {
        let mut cache = self.dwallet_index.lock().unwrap();
        cache.put(
            dwallet_id,
            CacheEntry::new(sign_ids, Duration::from_secs(60)), // Shorter TTL for indexes
        );
    }

    /// Invalidate a specific signature in cache
    pub fn invalidate_signature(&self, sign_id: &[u8]) {
        let mut sig_cache = self.signatures.lock().unwrap();
        let mut meta_cache = self.metadata.lock().unwrap();
        sig_cache.pop(sign_id);
        meta_cache.pop(sign_id);
    }

    /// Invalidate all signatures for a dwallet
    pub fn invalidate_dwallet(&self, dwallet_id: &[u8]) {
        let mut cache = self.dwallet_index.lock().unwrap();
        cache.pop(dwallet_id);
    }

    /// Clear all caches
    pub fn clear(&self) {
        let mut sig_cache = self.signatures.lock().unwrap();
        let mut meta_cache = self.metadata.lock().unwrap();
        let mut dwallet_cache = self.dwallet_index.lock().unwrap();
        sig_cache.clear();
        meta_cache.clear();
        dwallet_cache.clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let sig_cache = self.signatures.lock().unwrap();
        let meta_cache = self.metadata.lock().unwrap();
        let dwallet_cache = self.dwallet_index.lock().unwrap();

        CacheStats {
            signature_entries: sig_cache.len(),
            metadata_entries: meta_cache.len(),
            dwallet_index_entries: dwallet_cache.len(),
            signature_capacity: sig_cache.cap().get(),
            metadata_capacity: meta_cache.cap().get(),
            dwallet_capacity: dwallet_cache.cap().get(),
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub signature_entries: usize,
    pub metadata_entries: usize,
    pub dwallet_index_entries: usize,
    pub signature_capacity: usize,
    pub metadata_capacity: usize,
    pub dwallet_capacity: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::SignOutput;
    use crate::signature_store::SignatureAlgorithm;

    #[test]
    fn test_cache_operations() {
        let cache = SignatureCache::new(10); // 10MB cache

        let sign_output = SignOutput {
            dwallet_id: vec![1, 2, 3],
            sign_id: vec![4, 5, 6],
            signature: vec![7, 8, 9],
            is_future_sign: false,
            rejected: false,
            session_sequence_number: 1,
        };

        let stored_sig = StoredSignature {
            sign_output,
            checkpoint_sequence: 100,
            epoch: 0,
            timestamp_ms: 1234567890,
            algorithm: SignatureAlgorithm::ECDSASecp256k1,
            verified: true,
        };

        // Test put and get
        cache.put_signature(vec![4, 5, 6], stored_sig.clone());
        let retrieved = cache.get_signature(&[4, 5, 6]).unwrap();
        assert_eq!(retrieved.sign_output.signature, vec![7, 8, 9]);

        // Test cache stats
        let stats = cache.stats();
        assert_eq!(stats.signature_entries, 1);

        // Test invalidation
        cache.invalidate_signature(&[4, 5, 6]);
        assert!(cache.get_signature(&[4, 5, 6]).is_none());
    }
}