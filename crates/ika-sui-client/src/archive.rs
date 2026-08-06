// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! OCS checkpoint **archive** — a verified-fallback source of Sui end-of-epoch
//! checkpoints over an object store.
//!
//! This is a thin ika-side wrapper over Sui's own free functions in
//! [`sui_storage::object_store::util`] (`build_object_store`,
//! `end_of_epoch_data`, `fetch_checkpoint`); it implements no fetch/decode logic
//! of its own. Sui exposes no reusable reader/client *type* for this — only
//! those functions (its own light client wraps them in a private struct, and
//! `state_sync`/`sui-tool` call them directly), so a small caller-side wrapper
//! is the idiomatic way to use the API. The wrapper only holds a pre-built
//! `ObjectStore` (reused across fetches), adds typed errors with `{url, seq}`
//! context, and carries the trust-model note below.
//!
//! Layout mirrors Sui's light-client / public Remote Store (and a local Sui
//! node's `data-ingestion-dir`): a root `epochs.json` listing the end-of-epoch
//! checkpoint sequence numbers, plus per-sequence `{seq}.binpb.zst` blobs
//! (zstd-compressed protobuf checkpoints). `https://`, `s3://`, `gs://`, and
//! `file://` URLs all work (the last is how localnet and tests exercise this).
//!
//! Trust placement: **everything fetched here is untrusted.** The caller
//! BLS-verifies each summary against the committee chain (rooted at the genesis
//! blob) before trusting any of it, and the `epochs.json` enumeration is only a
//! hint for *where to look* — omission/reorder is caught downstream by the
//! ratchet's epoch-monotonicity + per-end-of-epoch signature check, so a
//! malicious archive can stall but never forge. Hence "fallback": the relay is
//! the primary end-of-epoch source; this fills cold-bootstrap and pruning gaps.

use std::sync::Arc;

use async_trait::async_trait;
use object_store::ObjectStore;
use sui_storage::object_store::util::{build_object_store, end_of_epoch_data, fetch_checkpoint};
use sui_types::messages_checkpoint::{
    CertifiedCheckpointSummary, CheckpointContents, CheckpointSequenceNumber,
};

/// Error reading from the checkpoint archive.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("archive enumerate (epochs.json) at {url}: {source}")]
    Enumerate {
        url: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("archive fetch checkpoint {seq} at {url}: {source}")]
    Fetch {
        url: String,
        seq: CheckpointSequenceNumber,
        #[source]
        source: anyhow::Error,
    },
}

/// Read-only source of Sui end-of-epoch checkpoints over an object store. A
/// trait so the committee ratchet / cold-bootstrap can be unit-tested with an
/// in-memory archive. Everything returned is UNVERIFIED — the caller BLS-verifies
/// each summary against the committee chain (rooted at the genesis committee).
#[async_trait]
pub trait CheckpointArchive: Send + Sync {
    /// Enumerate the end-of-epoch checkpoint sequence numbers (`epochs.json`).
    /// An untrusted hint for *where* the end-of-epoch checkpoints are; the
    /// caller verifies each fetched checkpoint cryptographically.
    async fn enumerate_end_of_epoch_seqs(
        &self,
    ) -> Result<Vec<CheckpointSequenceNumber>, ArchiveError>;

    /// Fetch a checkpoint by sequence number, returning its (still-unverified)
    /// certified summary and contents.
    async fn fetch_checkpoint(
        &self,
        seq: CheckpointSequenceNumber,
    ) -> Result<(CertifiedCheckpointSummary, CheckpointContents), ArchiveError>;
}

/// A read-only client over a Sui checkpoint object store.
#[derive(Clone)]
pub struct SuiCheckpointArchive {
    url: String,
    options: Vec<(String, String)>,
    store: Arc<dyn ObjectStore>,
}

impl SuiCheckpointArchive {
    /// `url` is an object-store URL (`https://`, `s3://`, `gs://`, or
    /// `file://`); `options` are backend credentials/flags (e.g. an S3 region,
    /// or `no-sign-request`).
    pub fn new(url: impl Into<String>, options: Vec<(String, String)>) -> Self {
        let url = url.into();
        let store = build_object_store(&url, options.clone(), vec![]);
        Self {
            url,
            options,
            store,
        }
    }

    /// The object-store URL this archive reads from.
    pub fn url(&self) -> &str {
        &self.url
    }
}

#[async_trait]
impl CheckpointArchive for SuiCheckpointArchive {
    async fn enumerate_end_of_epoch_seqs(
        &self,
    ) -> Result<Vec<CheckpointSequenceNumber>, ArchiveError> {
        end_of_epoch_data(&self.url, self.options.clone())
            .await
            .map_err(|source| ArchiveError::Enumerate {
                url: self.url.clone(),
                source,
            })
    }

    async fn fetch_checkpoint(
        &self,
        seq: CheckpointSequenceNumber,
    ) -> Result<(CertifiedCheckpointSummary, CheckpointContents), ArchiveError> {
        let checkpoint =
            fetch_checkpoint(&self.store, seq)
                .await
                .map_err(|source| ArchiveError::Fetch {
                    url: self.url.clone(),
                    seq,
                    source,
                })?;
        Ok((checkpoint.summary, checkpoint.contents))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};

    // A unique temp dir for this test process (no external tempfile dep).
    fn temp_store_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ika_ocs_archive_{}_{}", std::process::id(), tag));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn file_url(dir: &Path) -> String {
        format!("file://{}", dir.display())
    }

    #[tokio::test]
    async fn enumerates_end_of_epoch_seqs_from_epochs_json() {
        let dir = temp_store_dir("enum_ok");
        fs::write(dir.join("epochs.json"), b"[100,250,410]").unwrap();

        let archive = SuiCheckpointArchive::new(file_url(&dir), vec![]);
        let seqs = archive.enumerate_end_of_epoch_seqs().await.unwrap();
        assert_eq!(seqs, vec![100, 250, 410]);

        fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn enumerate_errors_when_epochs_json_absent() {
        let dir = temp_store_dir("enum_missing");
        // No epochs.json written.
        let archive = SuiCheckpointArchive::new(file_url(&dir), vec![]);
        let err = archive.enumerate_end_of_epoch_seqs().await.unwrap_err();
        assert!(matches!(err, ArchiveError::Enumerate { .. }), "got {err:?}");

        fs::remove_dir_all(&dir).ok();
    }
}
