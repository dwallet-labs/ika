// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::committee::EpochId;
use crate::error::{IkaError, IkaResult};
use crate::message::SignOutput;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use sui_types::base_types::TransactionDigest;
use typed_store::metrics::SamplingInterval;
use typed_store::rocks::{MetricConf, TypedStoreError};
use typed_store::traits::Map;
use typed_store::{reopen, DBMap, DBOptions};

/// Signature algorithms supported by the system
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    ECDSASecp256k1,
    ECDSASecp256r1,
    EdDSA,
    SchnorrkelSubstrate,
    Taproot,
}

/// Complete signature data stored in the index
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSignature {
    pub sign_output: SignOutput,
    pub checkpoint_sequence: u64,
    pub epoch: EpochId,
    pub timestamp_ms: u64,
    pub algorithm: SignatureAlgorithm,
    pub verified: bool,
}

/// Metadata associated with a signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureMetadata {
    pub dwallet_id: Vec<u8>,
    pub sign_id: Vec<u8>,
    pub message_hash: Option<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
    pub curve: Option<String>,
    pub created_at: u64,
    pub sui_tx_digest: Option<TransactionDigest>,
}

/// Query options for signature searches
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SignatureQueryOptions {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub from_timestamp: Option<u64>,
    pub to_timestamp: Option<u64>,
    pub include_metadata: bool,
    pub verify_signature: bool,
    pub algorithm: Option<SignatureAlgorithm>,
}

/// Response structure for signature queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureQueryResponse {
    pub signatures: Vec<StoredSignature>,
    pub metadata: Option<Vec<SignatureMetadata>>,
    pub total_count: usize,
    pub has_more: bool,
}

/// Store for efficient signature indexing and querying
pub struct SignatureStore {
    /// Primary index: sign_id -> signature data
    signatures_by_id: DBMap<Vec<u8>, StoredSignature>,

    /// Secondary index: dwallet_id -> set of sign_ids
    signatures_by_dwallet: DBMap<Vec<u8>, HashSet<Vec<u8>>>,

    /// Secondary index: checkpoint_sequence -> set of sign_ids
    signatures_by_checkpoint: DBMap<u64, HashSet<Vec<u8>>>,

    /// Secondary index: timestamp (bucketed by hour) -> set of sign_ids
    signatures_by_timestamp: DBMap<u64, HashSet<Vec<u8>>>,

    /// Metadata storage: sign_id -> metadata
    signature_metadata: DBMap<Vec<u8>, SignatureMetadata>,

    /// Track highest indexed checkpoint
    highest_indexed_checkpoint: DBMap<Vec<u8>, u64>,
}

impl SignatureStore {
    pub fn new(path: &Path, db_options: Option<DBOptions>) -> Result<Arc<Self>, TypedStoreError> {
        let rocks = reopen!(&path, db_options,
            "signatures_by_id", signatures_by_id: DBMap<Vec<u8>, StoredSignature>,
            "signatures_by_dwallet", signatures_by_dwallet: DBMap<Vec<u8>, HashSet<Vec<u8>>>,
            "signatures_by_checkpoint", signatures_by_checkpoint: DBMap<u64, HashSet<Vec<u8>>>,
            "signatures_by_timestamp", signatures_by_timestamp: DBMap<u64, HashSet<Vec<u8>>>,
            "signature_metadata", signature_metadata: DBMap<Vec<u8>, SignatureMetadata>,
            "highest_indexed_checkpoint", highest_indexed_checkpoint: DBMap<Vec<u8>, u64>
        )?;

        let store = Arc::new(SignatureStore {
            signatures_by_id: rocks.signatures_by_id,
            signatures_by_dwallet: rocks.signatures_by_dwallet,
            signatures_by_checkpoint: rocks.signatures_by_checkpoint,
            signatures_by_timestamp: rocks.signatures_by_timestamp,
            signature_metadata: rocks.signature_metadata,
            highest_indexed_checkpoint: rocks.highest_indexed_checkpoint,
        });

        Ok(store)
    }

    /// Index a new signature from a checkpoint
    pub fn index_signature(
        &self,
        sign_output: SignOutput,
        checkpoint_sequence: u64,
        epoch: EpochId,
        timestamp_ms: u64,
        algorithm: SignatureAlgorithm,
    ) -> IkaResult<()> {
        let sign_id = sign_output.sign_id.clone();
        let dwallet_id = sign_output.dwallet_id.clone();

        // Create stored signature
        let stored_sig = StoredSignature {
            sign_output: sign_output.clone(),
            checkpoint_sequence,
            epoch,
            timestamp_ms,
            algorithm,
            verified: false, // Will be set by verification process
        };

        // Store primary index
        self.signatures_by_id.insert(&sign_id, &stored_sig)?;

        // Update secondary indexes
        self.update_dwallet_index(&dwallet_id, &sign_id)?;
        self.update_checkpoint_index(checkpoint_sequence, &sign_id)?;
        self.update_timestamp_index(timestamp_ms, &sign_id)?;

        // Create metadata
        let metadata = SignatureMetadata {
            dwallet_id: dwallet_id.clone(),
            sign_id: sign_id.clone(),
            message_hash: None, // To be filled if available
            public_key: None,   // To be filled if available
            curve: None,        // To be filled based on algorithm
            created_at: timestamp_ms,
            sui_tx_digest: None, // To be filled when written to Sui
        };

        self.signature_metadata.insert(&sign_id, &metadata)?;

        Ok(())
    }

    /// Get a signature by its ID
    pub fn get_signature_by_id(&self, sign_id: &[u8]) -> IkaResult<Option<StoredSignature>> {
        Ok(self.signatures_by_id.get(sign_id)?)
    }

    /// Get all signatures for a dWallet
    pub fn get_signatures_by_dwallet(
        &self,
        dwallet_id: &[u8],
        options: &SignatureQueryOptions,
    ) -> IkaResult<SignatureQueryResponse> {
        let sign_ids = self.signatures_by_dwallet
            .get(dwallet_id)?
            .unwrap_or_default();

        self.build_response_from_ids(sign_ids, options)
    }

    /// Get signatures by checkpoint sequence
    pub fn get_signatures_by_checkpoint(
        &self,
        checkpoint_seq: u64,
        options: &SignatureQueryOptions,
    ) -> IkaResult<SignatureQueryResponse> {
        let sign_ids = self.signatures_by_checkpoint
            .get(&checkpoint_seq)?
            .unwrap_or_default();

        self.build_response_from_ids(sign_ids, options)
    }

    /// Search signatures with filters
    pub fn search_signatures(
        &self,
        options: &SignatureQueryOptions,
    ) -> IkaResult<SignatureQueryResponse> {
        let mut all_sign_ids = HashSet::new();

        // If timestamp range is specified, use timestamp index
        if let (Some(from), Some(to)) = (options.from_timestamp, options.to_timestamp) {
            let from_bucket = from / 3600000; // Hour buckets
            let to_bucket = to / 3600000;

            for bucket in from_bucket..=to_bucket {
                if let Some(ids) = self.signatures_by_timestamp.get(&bucket)? {
                    all_sign_ids.extend(ids);
                }
            }
        }

        self.build_response_from_ids(all_sign_ids, options)
    }

    /// Get metadata for a signature
    pub fn get_signature_metadata(&self, sign_id: &[u8]) -> IkaResult<Option<SignatureMetadata>> {
        Ok(self.signature_metadata.get(sign_id)?)
    }

    /// Update the Sui transaction reference for a signature
    pub fn update_sui_reference(
        &self,
        sign_id: &[u8],
        tx_digest: TransactionDigest,
    ) -> IkaResult<()> {
        if let Some(mut metadata) = self.signature_metadata.get(sign_id)? {
            metadata.sui_tx_digest = Some(tx_digest);
            self.signature_metadata.insert(sign_id, &metadata)?;
        }
        Ok(())
    }

    /// Mark a signature as verified
    pub fn mark_signature_verified(&self, sign_id: &[u8]) -> IkaResult<()> {
        if let Some(mut sig) = self.signatures_by_id.get(sign_id)? {
            sig.verified = true;
            self.signatures_by_id.insert(sign_id, &sig)?;
        }
        Ok(())
    }

    /// Get the highest indexed checkpoint
    pub fn get_highest_indexed_checkpoint(&self) -> IkaResult<Option<u64>> {
        let key = b"highest";
        Ok(self.highest_indexed_checkpoint.get(key)?)
    }

    /// Update the highest indexed checkpoint
    pub fn update_highest_indexed_checkpoint(&self, checkpoint_seq: u64) -> IkaResult<()> {
        let key = b"highest";
        self.highest_indexed_checkpoint.insert(key, &checkpoint_seq)?;
        Ok(())
    }

    // Helper methods

    fn update_dwallet_index(&self, dwallet_id: &[u8], sign_id: &[u8]) -> IkaResult<()> {
        let mut sign_ids = self.signatures_by_dwallet
            .get(dwallet_id)?
            .unwrap_or_default();
        sign_ids.insert(sign_id.to_vec());
        self.signatures_by_dwallet.insert(dwallet_id, &sign_ids)?;
        Ok(())
    }

    fn update_checkpoint_index(&self, checkpoint_seq: u64, sign_id: &[u8]) -> IkaResult<()> {
        let mut sign_ids = self.signatures_by_checkpoint
            .get(&checkpoint_seq)?
            .unwrap_or_default();
        sign_ids.insert(sign_id.to_vec());
        self.signatures_by_checkpoint.insert(&checkpoint_seq, &sign_ids)?;
        Ok(())
    }

    fn update_timestamp_index(&self, timestamp_ms: u64, sign_id: &[u8]) -> IkaResult<()> {
        let bucket = timestamp_ms / 3600000; // Hour buckets
        let mut sign_ids = self.signatures_by_timestamp
            .get(&bucket)?
            .unwrap_or_default();
        sign_ids.insert(sign_id.to_vec());
        self.signatures_by_timestamp.insert(&bucket, &sign_ids)?;
        Ok(())
    }

    fn build_response_from_ids(
        &self,
        sign_ids: HashSet<Vec<u8>>,
        options: &SignatureQueryOptions,
    ) -> IkaResult<SignatureQueryResponse> {
        let mut signatures = Vec::new();
        let mut metadata = Vec::new();

        let offset = options.offset.unwrap_or(0);
        let limit = options.limit.unwrap_or(100);

        // Convert to sorted vec for consistent ordering
        let mut sign_ids: Vec<_> = sign_ids.into_iter().collect();
        sign_ids.sort();

        let total_count = sign_ids.len();
        let end_idx = std::cmp::min(offset + limit, total_count);

        for sign_id in &sign_ids[offset..end_idx] {
            if let Some(sig) = self.signatures_by_id.get(sign_id)? {
                // Apply filters
                if let Some(algo) = options.algorithm {
                    if sig.algorithm != algo {
                        continue;
                    }
                }

                if let Some(from) = options.from_timestamp {
                    if sig.timestamp_ms < from {
                        continue;
                    }
                }

                if let Some(to) = options.to_timestamp {
                    if sig.timestamp_ms > to {
                        continue;
                    }
                }

                signatures.push(sig);

                if options.include_metadata {
                    if let Some(meta) = self.signature_metadata.get(sign_id)? {
                        metadata.push(meta);
                    }
                }
            }
        }

        Ok(SignatureQueryResponse {
            signatures,
            metadata: if options.include_metadata { Some(metadata) } else { None },
            total_count,
            has_more: end_idx < total_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_signature_store_creation() {
        let temp_dir = tempdir().unwrap();
        let store = SignatureStore::new(temp_dir.path(), None).unwrap();
        assert!(store.get_highest_indexed_checkpoint().unwrap().is_none());
    }

    #[test]
    fn test_signature_indexing_and_retrieval() {
        let temp_dir = tempdir().unwrap();
        let store = SignatureStore::new(temp_dir.path(), None).unwrap();

        let sign_output = SignOutput {
            dwallet_id: vec![1, 2, 3],
            sign_id: vec![4, 5, 6],
            signature: vec![7, 8, 9],
            is_future_sign: false,
            rejected: false,
            session_sequence_number: 1,
        };

        store.index_signature(
            sign_output.clone(),
            100,
            0,
            1234567890,
            SignatureAlgorithm::ECDSASecp256k1,
        ).unwrap();

        let retrieved = store.get_signature_by_id(&[4, 5, 6]).unwrap().unwrap();
        assert_eq!(retrieved.sign_output.signature, vec![7, 8, 9]);
        assert_eq!(retrieved.checkpoint_sequence, 100);
    }
}