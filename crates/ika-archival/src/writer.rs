// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear
#![allow(dead_code)]

use crate::{
    CheckpointUpdates, DWALLET_CHECKPOINT_FILE_MAGIC, DWALLET_CHECKPOINT_FILE_SUFFIX,
    EPOCH_DIR_PREFIX, FileMetadata, FileType, MAGIC_BYTES, Manifest, SYSTEM_CHECKPOINT_FILE_MAGIC,
    SYSTEM_CHECKPOINT_FILE_SUFFIX, SystemCheckpointUpdates, create_file_metadata, read_manifest,
    write_manifest,
};
use anyhow::Result;
use anyhow::{Context, anyhow};
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use ika_config::object_storage_config::ObjectStoreConfig;
use ika_types::checkpoint::{
    CertifiedCheckpointMessage, CheckpointSequenceNumber, DWallet, System,
};
use ika_types::storage::WriteStore;
use object_store::DynObjectStore;
use prometheus::{IntGauge, Registry, register_int_gauge_with_registry};
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use sui_storage::blob::{Blob, BlobEncoding};
use sui_storage::object_store::util::{copy_file, path_to_filesystem};
use sui_storage::{FileCompression, StorageFormat, compress};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::Instant;
use tracing::{debug, info};

pub struct ArchiveMetrics {
    pub latest_dwallet_checkpoint_archived: IntGauge,
    pub latest_system_checkpoint_archived: IntGauge,
}

impl ArchiveMetrics {
    pub fn new(registry: &Registry) -> Arc<Self> {
        let this = Self {
            latest_dwallet_checkpoint_archived: register_int_gauge_with_registry!(
                "latest_dwallet_checkpoint_archived",
                "Latest dwallet checkpoint to have archived to the remote store",
                registry
            )
            .unwrap(),
            latest_system_checkpoint_archived: register_int_gauge_with_registry!(
                "latest_system_checkpoint_archived",
                "Latest system checkpoint to have archived to the remote store",
                registry
            )
            .unwrap(),
        };
        Arc::new(this)
    }
}

/// [`DWalletCheckpointWriter`] writes checkpoints and summaries.
/// It creates multiple *.chk and *.sum files
struct DWalletCheckpointWriter {
    root_dir_path: PathBuf,
    epoch_num: u64,
    dwallet_checkpoint_range: Range<u64>,
    wbuf: BufWriter<File>,
    sender: Sender<CheckpointUpdates>,
    dwallet_checkpoint_buf_offset: usize,
    file_compression: FileCompression,
    storage_format: StorageFormat,
    manifest: Manifest,
    last_commit_instant: Instant,
    commit_duration: Duration,
    commit_file_size: usize,
}

impl DWalletCheckpointWriter {
    pub fn new(
        root_dir_path: PathBuf,
        file_compression: FileCompression,
        storage_format: StorageFormat,
        sender: Sender<CheckpointUpdates>,
        manifest: Manifest,
        commit_duration: Duration,
        commit_file_size: usize,
    ) -> Result<Self> {
        let epoch_num = manifest.epoch_num();
        let checkpoint_sequence_num = manifest.next_dwallet_checkpoint_seq_num();
        let epoch_dir = root_dir_path.join(format!("{EPOCH_DIR_PREFIX}{epoch_num}"));
        if epoch_dir.exists() {
            fs::remove_dir_all(&epoch_dir)?;
        }
        fs::create_dir_all(&epoch_dir)?;
        let checkpoint_file = Self::next_file(
            &epoch_dir,
            checkpoint_sequence_num,
            DWALLET_CHECKPOINT_FILE_SUFFIX,
            DWALLET_CHECKPOINT_FILE_MAGIC,
            storage_format,
            file_compression,
        )?;
        Ok(DWalletCheckpointWriter {
            root_dir_path,
            epoch_num,
            dwallet_checkpoint_range: checkpoint_sequence_num..checkpoint_sequence_num,
            wbuf: BufWriter::new(checkpoint_file),
            dwallet_checkpoint_buf_offset: 0,
            sender,
            file_compression,
            storage_format,
            manifest,
            last_commit_instant: Instant::now(),
            commit_duration,
            commit_file_size,
        })
    }

    pub fn write(&mut self, checkpoint_message: CertifiedCheckpointMessage<DWallet>) -> Result<()> {
        match self.storage_format {
            StorageFormat::Blob => self.write_as_blob(checkpoint_message),
        }
    }

    pub fn write_as_blob(
        &mut self,
        checkpoint_message: CertifiedCheckpointMessage<DWallet>,
    ) -> Result<()> {
        assert_eq!(
            checkpoint_message.sequence_number,
            self.dwallet_checkpoint_range.end
        );

        if checkpoint_message.epoch()
            == self
                .epoch_num
                .checked_add(1)
                .context("Epoch num overflow")?
        {
            self.cut()?;
            self.update_to_next_epoch();
            if self.epoch_dir().exists() {
                fs::remove_dir_all(self.epoch_dir())?;
            }
            fs::create_dir_all(self.epoch_dir())?;
            self.reset()?;
        }

        assert_eq!(checkpoint_message.epoch, self.epoch_num);

        let contents_blob = Blob::encode(&checkpoint_message, BlobEncoding::Bcs)?;
        let blob_size = contents_blob.size();
        let cut_new_checkpoint_file = (self.dwallet_checkpoint_buf_offset + blob_size)
            > self.commit_file_size
            || (self.last_commit_instant.elapsed() > self.commit_duration);
        if cut_new_checkpoint_file {
            self.cut()?;
            self.reset()?;
        }

        self.dwallet_checkpoint_buf_offset += contents_blob.write(&mut self.wbuf)?;

        self.dwallet_checkpoint_range.end = self
            .dwallet_checkpoint_range
            .end
            .checked_add(1)
            .context("Checkpoint sequence num overflow")?;
        Ok(())
    }
    fn finalize(&mut self) -> Result<FileMetadata> {
        self.wbuf.flush()?;
        self.wbuf.get_ref().sync_data()?;
        let off = self.wbuf.get_ref().stream_position()?;
        self.wbuf.get_ref().set_len(off)?;
        let file_path = self.epoch_dir().join(format!(
            "{}.{DWALLET_CHECKPOINT_FILE_SUFFIX}",
            self.dwallet_checkpoint_range.start
        ));
        self.compress(&file_path)?;
        let file_metadata = create_file_metadata(
            &file_path,
            FileType::DWalletCheckpointMessage,
            self.epoch_num,
            self.dwallet_checkpoint_range.clone(),
        )?;
        Ok(file_metadata)
    }

    fn cut(&mut self) -> Result<()> {
        if !self.dwallet_checkpoint_range.is_empty() {
            let checkpoint_file_metadata = self.finalize()?;
            let checkpoint_updates = CheckpointUpdates::new(
                self.epoch_num,
                self.dwallet_checkpoint_range.end,
                checkpoint_file_metadata,
                &mut self.manifest,
            );
            info!("Checkpoint file cut for: {:?}", checkpoint_updates);
            self.sender.blocking_send(checkpoint_updates)?;
        }
        Ok(())
    }

    fn compress(&self, source: &Path) -> Result<()> {
        if self.file_compression == FileCompression::None {
            return Ok(());
        }
        let mut input = File::open(source)?;
        let tmp_file_name = source.with_extension("tmp");
        let mut output = File::create(&tmp_file_name)?;
        compress(&mut input, &mut output)?;
        fs::rename(tmp_file_name, source)?;
        Ok(())
    }

    fn next_file(
        dir_path: &Path,
        checkpoint_sequence_num: u64,
        suffix: &str,
        magic_bytes: u32,
        storage_format: StorageFormat,
        file_compression: FileCompression,
    ) -> Result<File> {
        let next_file_path = dir_path.join(format!("{checkpoint_sequence_num}.{suffix}"));
        let mut f = File::create(next_file_path.clone())?;
        let mut metab = [0u8; MAGIC_BYTES];
        BigEndian::write_u32(&mut metab, magic_bytes);
        let n = f.write(&metab)?;
        drop(f);
        f = OpenOptions::new().append(true).open(next_file_path)?;
        f.seek(SeekFrom::Start(n as u64))?;
        f.write_u8(storage_format.into())?;
        f.write_u8(file_compression.into())?;
        Ok(f)
    }

    fn create_new_files(&mut self) -> Result<()> {
        let f = Self::next_file(
            &self.epoch_dir(),
            self.dwallet_checkpoint_range.start,
            DWALLET_CHECKPOINT_FILE_SUFFIX,
            DWALLET_CHECKPOINT_FILE_MAGIC,
            self.storage_format,
            self.file_compression,
        )?;
        self.dwallet_checkpoint_buf_offset = MAGIC_BYTES;
        self.wbuf = BufWriter::new(f);
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        self.reset_checkpoint_range();
        self.create_new_files()?;
        self.reset_last_commit_ts();
        Ok(())
    }
    fn reset_last_commit_ts(&mut self) {
        self.last_commit_instant = Instant::now();
    }
    fn reset_checkpoint_range(&mut self) {
        self.dwallet_checkpoint_range =
            self.dwallet_checkpoint_range.end..self.dwallet_checkpoint_range.end
    }
    fn epoch_dir(&self) -> PathBuf {
        self.root_dir_path
            .join(format!("{}{}", EPOCH_DIR_PREFIX, self.epoch_num))
    }
    fn update_to_next_epoch(&mut self) {
        self.epoch_num = self.epoch_num.checked_add(1).unwrap();
    }
}

struct SystemCheckpointWriter {
    root_dir_path: PathBuf,
    epoch_num: u64,
    system_checkpoint_range: Range<u64>,
    wbuf: BufWriter<File>,
    sender: Sender<SystemCheckpointUpdates>,
    system_checkpoint_buf_offset: usize,
    file_compression: FileCompression,
    storage_format: StorageFormat,
    manifest: Manifest,
    last_commit_instant: Instant,
    commit_duration: Duration,
    commit_file_size: usize,
}

impl SystemCheckpointWriter {
    fn new(
        root_dir_path: PathBuf,
        file_compression: FileCompression,
        storage_format: StorageFormat,
        sender: Sender<SystemCheckpointUpdates>,
        manifest: Manifest,
        commit_duration: Duration,
        commit_file_size: usize,
    ) -> Result<Self> {
        let epoch_num = manifest.epoch_num();
        let system_checkpoint_sequence_num = manifest.next_system_checkpoint_seq_num();
        let epoch_dir = root_dir_path.join(format!("{EPOCH_DIR_PREFIX}{epoch_num}"));
        if epoch_dir.exists() {
            fs::remove_dir_all(&epoch_dir)?;
        }
        fs::create_dir_all(&epoch_dir)?;
        let system_checkpoint_file = Self::next_file(
            &epoch_dir,
            system_checkpoint_sequence_num,
            SYSTEM_CHECKPOINT_FILE_SUFFIX,
            SYSTEM_CHECKPOINT_FILE_MAGIC,
            storage_format,
            file_compression,
        )?;
        Ok(SystemCheckpointWriter {
            root_dir_path,
            epoch_num,
            system_checkpoint_range: system_checkpoint_sequence_num..system_checkpoint_sequence_num,
            wbuf: BufWriter::new(system_checkpoint_file),
            system_checkpoint_buf_offset: 0,
            sender,
            file_compression,
            storage_format,
            manifest,
            last_commit_instant: Instant::now(),
            commit_duration,
            commit_file_size,
        })
    }

    pub fn write(
        &mut self,
        system_checkpoint_message: CertifiedCheckpointMessage<System>,
    ) -> Result<()> {
        match self.storage_format {
            StorageFormat::Blob => self.write_as_blob(system_checkpoint_message),
        }
    }

    pub fn write_as_blob(
        &mut self,
        system_checkpoint_message: CertifiedCheckpointMessage<System>,
    ) -> Result<()> {
        assert_eq!(
            system_checkpoint_message.sequence_number,
            self.system_checkpoint_range.end
        );

        if system_checkpoint_message.epoch()
            == self
                .epoch_num
                .checked_add(1)
                .context("Epoch num overflow")?
        {
            self.cut()?;
            self.update_to_next_epoch();
            if self.epoch_dir().exists() {
                fs::remove_dir_all(self.epoch_dir())?;
            }
            fs::create_dir_all(self.epoch_dir())?;
            self.reset()?;
        }

        assert_eq!(system_checkpoint_message.epoch, self.epoch_num);

        let contents_blob = Blob::encode(&system_checkpoint_message, BlobEncoding::Bcs)?;
        let blob_size = contents_blob.size();
        let cut_new_system_checkpoint_file = (self.system_checkpoint_buf_offset + blob_size)
            > self.commit_file_size
            || (self.last_commit_instant.elapsed() > self.commit_duration);
        if cut_new_system_checkpoint_file {
            self.cut()?;
            self.reset()?;
        }

        self.system_checkpoint_buf_offset += contents_blob.write(&mut self.wbuf)?;

        self.system_checkpoint_range.end = self
            .system_checkpoint_range
            .end
            .checked_add(1)
            .context("System checkpoint sequence num overflow")?;
        Ok(())
    }
    fn finalize(&mut self) -> Result<FileMetadata> {
        self.wbuf.flush()?;
        self.wbuf.get_ref().sync_data()?;
        let off = self.wbuf.get_ref().stream_position()?;
        self.wbuf.get_ref().set_len(off)?;
        let file_path = self.epoch_dir().join(format!(
            "{}.{SYSTEM_CHECKPOINT_FILE_SUFFIX}",
            self.system_checkpoint_range.start
        ));
        self.compress(&file_path)?;
        let file_metadata = create_file_metadata(
            &file_path,
            FileType::SystemCheckpointMessage,
            self.epoch_num,
            self.system_checkpoint_range.clone(),
        )?;
        Ok(file_metadata)
    }

    fn cut(&mut self) -> Result<()> {
        if !self.system_checkpoint_range.is_empty() {
            let system_checkpoint_file_metadata = self.finalize()?;
            let system_checkpoint_updates = SystemCheckpointUpdates::new(
                self.epoch_num,
                self.system_checkpoint_range.end,
                system_checkpoint_file_metadata,
                &mut self.manifest,
            );
            info!(
                "System checkpoint file cut for: {:?}",
                system_checkpoint_updates
            );
            self.sender.blocking_send(system_checkpoint_updates)?;
        }
        Ok(())
    }

    fn compress(&self, source: &Path) -> Result<()> {
        if self.file_compression == FileCompression::None {
            return Ok(());
        }
        let mut input = File::open(source)?;
        let tmp_file_name = source.with_extension("tmp");
        let mut output = File::create(&tmp_file_name)?;
        compress(&mut input, &mut output)?;
        fs::rename(tmp_file_name, source)?;
        Ok(())
    }

    fn next_file(
        dir_path: &Path,
        system_checkpoint_sequence_num: u64,
        suffix: &str,
        magic_bytes: u32,
        storage_format: StorageFormat,
        file_compression: FileCompression,
    ) -> Result<File> {
        let next_file_path = dir_path.join(format!("{system_checkpoint_sequence_num}.{suffix}"));
        let mut f = File::create(next_file_path.clone())?;
        let mut metab = [0u8; MAGIC_BYTES];
        BigEndian::write_u32(&mut metab, magic_bytes);
        let n = f.write(&metab)?;
        drop(f);
        f = OpenOptions::new().append(true).open(next_file_path)?;
        f.seek(SeekFrom::Start(n as u64))?;
        f.write_u8(storage_format.into())?;
        f.write_u8(file_compression.into())?;
        Ok(f)
    }

    fn create_new_files(&mut self) -> Result<()> {
        let f = Self::next_file(
            &self.epoch_dir(),
            self.system_checkpoint_range.start,
            SYSTEM_CHECKPOINT_FILE_SUFFIX,
            SYSTEM_CHECKPOINT_FILE_MAGIC,
            self.storage_format,
            self.file_compression,
        )?;
        self.system_checkpoint_buf_offset = MAGIC_BYTES;
        self.wbuf = BufWriter::new(f);
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        self.reset_system_checkpoint_range();
        self.create_new_files()?;
        self.reset_last_commit_ts();
        Ok(())
    }
    fn reset_last_commit_ts(&mut self) {
        self.last_commit_instant = Instant::now();
    }
    fn reset_system_checkpoint_range(&mut self) {
        self.system_checkpoint_range =
            self.system_checkpoint_range.end..self.system_checkpoint_range.end
    }
    fn epoch_dir(&self) -> PathBuf {
        self.root_dir_path
            .join(format!("{}{}", EPOCH_DIR_PREFIX, self.epoch_num))
    }
    fn update_to_next_epoch(&mut self) {
        self.epoch_num = self.epoch_num.checked_add(1).unwrap();
    }
}

/// ArchiveWriter archives history by tailing checkpoints writing them to a local staging dir and
/// simultaneously uploading them to a remote object store
pub struct ArchiveWriter {
    file_compression: FileCompression,
    storage_format: StorageFormat,
    local_staging_dir_root: PathBuf,
    local_object_store: Arc<DynObjectStore>,
    remote_object_store: Arc<DynObjectStore>,
    commit_duration: Duration,
    commit_file_size: usize,
    archive_metrics: Arc<ArchiveMetrics>,
}

impl ArchiveWriter {
    pub async fn new(
        local_store_config: ObjectStoreConfig,
        remote_store_config: ObjectStoreConfig,
        file_compression: FileCompression,
        storage_format: StorageFormat,
        commit_duration: Duration,
        commit_file_size: usize,
        registry: &Registry,
    ) -> Result<Self> {
        Ok(ArchiveWriter {
            file_compression,
            storage_format,
            remote_object_store: remote_store_config.make()?,
            local_object_store: local_store_config.make()?,
            local_staging_dir_root: local_store_config.directory.context("Missing local dir")?,
            commit_duration,
            commit_file_size,
            archive_metrics: ArchiveMetrics::new(registry),
        })
    }

    pub async fn start<S>(&self, store: S) -> Result<tokio::sync::broadcast::Sender<()>>
    where
        S: Clone + WriteStore + Send + Sync + 'static,
    {
        let remote_archive_is_empty = self
            .remote_object_store
            .list_with_delimiter(None)
            .await
            .expect("Failed to read remote archive dir")
            .common_prefixes
            .is_empty();
        let manifest = if remote_archive_is_empty {
            // Start from genesis
            Manifest::new(0, 0, 0)
        } else {
            read_manifest(self.remote_object_store.clone())
                .await
                .expect("Failed to read manifest")
        };
        let start_checkpoint_sequence_number = manifest.next_dwallet_checkpoint_seq_num();
        let (sender, receiver) = mpsc::channel::<CheckpointUpdates>(100);
        let (sender_system_checkpoint, receiver_system_checkpoint) =
            mpsc::channel::<SystemCheckpointUpdates>(100);
        let checkpoint_writer = DWalletCheckpointWriter::new(
            self.local_staging_dir_root.clone(),
            self.file_compression,
            self.storage_format,
            sender,
            manifest.clone(),
            self.commit_duration,
            self.commit_file_size,
        )
        .expect("Failed to create checkpoint writer");
        let (kill_sender, kill_receiver) = tokio::sync::broadcast::channel::<()>(1);
        tokio::spawn(Self::start_syncing_with_remote(
            self.remote_object_store.clone(),
            self.local_object_store.clone(),
            self.local_staging_dir_root.clone(),
            receiver,
            receiver_system_checkpoint,
            kill_sender.subscribe(),
            self.archive_metrics.clone(),
        ));
        let store_clone = store.clone();
        let kill_receiver_clone = kill_receiver.resubscribe();
        tokio::task::spawn(async move {
            Self::start_tailing_checkpoints(
                start_checkpoint_sequence_number,
                checkpoint_writer,
                store_clone,
                kill_receiver_clone,
            )
            .await
        });

        let start_system_checkpoint_sequence_number = manifest.next_system_checkpoint_seq_num();
        let system_checkpoint_writer = SystemCheckpointWriter::new(
            self.local_staging_dir_root.clone(),
            self.file_compression,
            self.storage_format,
            sender_system_checkpoint,
            manifest,
            self.commit_duration,
            self.commit_file_size,
        )
        .expect("Failed to create system_checkpoint writer");
        tokio::task::spawn(async move {
            Self::start_tailing_system_checkpoints(
                start_system_checkpoint_sequence_number,
                system_checkpoint_writer,
                store,
                kill_receiver,
            )
            .await
        });

        Ok(kill_sender)
    }

    async fn start_tailing_checkpoints<S>(
        start_checkpoint_sequence_number: CheckpointSequenceNumber,
        mut checkpoint_writer: DWalletCheckpointWriter,
        store: S,
        mut kill: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<()>
    where
        S: WriteStore + Send + Sync + 'static,
    {
        let mut checkpoint_sequence_number = start_checkpoint_sequence_number;
        info!("Starting checkpoint tailing from sequence number: {checkpoint_sequence_number}");

        while kill.try_recv().is_err() {
            if let Some(checkpoint_message) = store
                .get_dwallet_checkpoint_by_sequence_number(checkpoint_sequence_number)
                .map_err(|_| anyhow!("Failed to read checkpoint message from store"))?
            {
                checkpoint_writer.write(checkpoint_message.into_inner())?;
                checkpoint_sequence_number = checkpoint_sequence_number
                    .checked_add(1)
                    .context("checkpoint seq number overflow")?;
                // There is more checkpoints to tail, so continue without sleeping
                continue;
            }
            // Checkpoint with `checkpoint_sequence_number` is not available to read from store yet,
            // sleep for sometime and then retry
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        Ok(())
    }

    async fn start_tailing_system_checkpoints<S>(
        start_system_checkpoint_sequence_number: CheckpointSequenceNumber,
        mut system_checkpoint_writer: SystemCheckpointWriter,
        store: S,
        mut kill: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<()>
    where
        S: WriteStore + Send + Sync + 'static,
    {
        let mut system_checkpoint_sequence_number = start_system_checkpoint_sequence_number;
        info!(
            "Starting system checkpoint tailing from sequence number: {system_checkpoint_sequence_number}"
        );

        while kill.try_recv().is_err() {
            if let Some(system_checkpoint_message) = store
                .get_system_checkpoint_by_sequence_number(system_checkpoint_sequence_number)
                .map_err(|_| anyhow!("Failed to read system checkpoint message from store"))?
            {
                system_checkpoint_writer.write(system_checkpoint_message.into_inner())?;
                system_checkpoint_sequence_number = system_checkpoint_sequence_number
                    .checked_add(1)
                    .context("System checkpoint seq number overflow")?;
                // There is more system checkpoints to tail, so continue without sleeping
                continue;
            }
            // System checkpoint with `system_checkpoint_sequence_number` is not available to read from store yet,
            // sleep for sometime and then retry
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        Ok(())
    }

    async fn start_syncing_with_remote(
        remote_object_store: Arc<DynObjectStore>,
        local_object_store: Arc<DynObjectStore>,
        local_staging_root_dir: PathBuf,
        mut update_receiver: Receiver<CheckpointUpdates>,
        mut update_receiver_system_checkpoint: Receiver<SystemCheckpointUpdates>,
        mut kill: tokio::sync::broadcast::Receiver<()>,
        metrics: Arc<ArchiveMetrics>,
    ) -> Result<()> {
        loop {
            tokio::select! {
                _ = kill.recv() => break,
                updates = update_receiver.recv() => {
                    if let Some(checkpoint_updates) = updates {
                        info!("Received checkpoint update: {:?}", checkpoint_updates);
                        let latest_checkpoint_seq_num = checkpoint_updates.manifest.next_dwallet_checkpoint_seq_num();
                        let summary_file_path = checkpoint_updates.summary_file_path();
                        Self::sync_file_to_remote(
                            local_staging_root_dir.clone(),
                            summary_file_path,
                            local_object_store.clone(),
                            remote_object_store.clone()
                        )
                        .await
                        .expect("Syncing checkpoint summary should not fail");

                        let content_file_path = checkpoint_updates.content_file_path();
                        Self::sync_file_to_remote(
                            local_staging_root_dir.clone(),
                            content_file_path,
                            local_object_store.clone(),
                            remote_object_store.clone()
                        )
                        .await
                        .expect("Syncing checkpoint content should not fail");

                        write_manifest(
                            checkpoint_updates.manifest,
                            remote_object_store.clone()
                        )
                        .await
                        .expect("Updating manifest should not fail");
                        metrics.latest_dwallet_checkpoint_archived.set(latest_checkpoint_seq_num as i64)
                    } else {
                        info!("Terminating archive sync loop");
                        break;
                    }
                },
                updates = update_receiver_system_checkpoint.recv() => {
                    if let Some(system_checkpoint_updates) = updates {
                        info!("Received system_checkpoint update: {:?}", system_checkpoint_updates);
                        let latest_system_checkpoint_seq_num = system_checkpoint_updates.manifest.next_system_checkpoint_seq_num();
                        let summary_file_path = system_checkpoint_updates.summary_file_path();
                        Self::sync_file_to_remote(
                            local_staging_root_dir.clone(),
                            summary_file_path,
                            local_object_store.clone(),
                            remote_object_store.clone()
                        )
                        .await
                        .expect("Syncing system_checkpoint summary should not fail");

                        let content_file_path = system_checkpoint_updates.content_file_path();
                        Self::sync_file_to_remote(
                            local_staging_root_dir.clone(),
                            content_file_path,
                            local_object_store.clone(),
                            remote_object_store.clone()
                        )
                        .await
                        .expect("Syncing system_checkpoint content should not fail");

                        write_manifest(
                            system_checkpoint_updates.manifest,
                            remote_object_store.clone()
                        )
                        .await
                        .expect("Updating manifest should not fail");
                        metrics.latest_system_checkpoint_archived.set(latest_system_checkpoint_seq_num as i64)
                    } else {
                        info!("Terminating archive sync loop");
                        break;
                    }
                },
            }
        }
        Ok(())
    }

    async fn sync_file_to_remote(
        dir: PathBuf,
        path: object_store::path::Path,
        from: Arc<DynObjectStore>,
        to: Arc<DynObjectStore>,
    ) -> Result<()> {
        debug!("Syncing archive file to remote: {:?}", path);
        copy_file(&path, &path, &from, &to).await?;
        fs::remove_file(path_to_filesystem(dir, &path)?)?;
        Ok(())
    }
}
