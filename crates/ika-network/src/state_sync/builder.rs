// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use super::{
    Handle, PeerHeights, StateSync, StateSyncEventLoop, StateSyncMessage, StateSyncServer,
    metrics::Metrics,
    server::{CheckpointMessageDownloadLimitLayer, Server},
};
use crate::state_sync::server::SystemCheckpointDownloadLimitLayer;
use anemo::codegen::InboundRequestLayer;
use anemo_tower::{inflight_limit, rate_limit};
use ika_archival::reader::ArchiveReaderBalancer;
use ika_config::p2p::StateSyncConfig;
use ika_types::checkpoint::{DWallet, System, VerifiedCheckpointMessage};
use ika_types::digests::ChainIdentifier;
use ika_types::storage::WriteStore;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tap::Pipe;
use tokio::{
    sync::{broadcast, mpsc},
    task::JoinSet,
};

pub struct Builder<S> {
    store: Option<S>,
    config: Option<StateSyncConfig>,
    metrics: Option<Metrics>,
    archive_readers: Option<ArchiveReaderBalancer>,
    chain_identifier: Option<ChainIdentifier>,
}

impl Builder<()> {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            store: None,
            config: None,
            metrics: None,
            archive_readers: None,
            chain_identifier: None,
        }
    }
}

impl<S> Builder<S> {
    pub fn store<NewStore>(self, store: NewStore) -> Builder<NewStore> {
        Builder {
            store: Some(store),
            config: self.config,
            metrics: self.metrics,
            archive_readers: self.archive_readers,
            chain_identifier: self.chain_identifier,
        }
    }

    pub fn config(mut self, config: StateSyncConfig) -> Self {
        self.config = Some(config);
        self
    }

    pub fn with_metrics(mut self, registry: &prometheus::Registry) -> Self {
        self.metrics = Some(Metrics::enabled(registry));
        self
    }

    pub fn archive_readers(mut self, archive_readers: ArchiveReaderBalancer) -> Self {
        self.archive_readers = Some(archive_readers);
        self
    }
}

impl<S> Builder<S>
where
    S: WriteStore + Clone + Send + Sync + 'static,
{
    pub fn build(self) -> (UnstartedStateSync<S>, StateSyncServer<impl StateSync>) {
        let state_sync_config = self.config.clone().unwrap_or_default();
        let (mut builder, server) = self.build_internal();
        let mut state_sync_server = StateSyncServer::new(server);

        // Apply rate limits from configuration as needed.
        if let Some(limit) = state_sync_config.push_dwallet_checkpoint_message_rate_limit {
            state_sync_server = state_sync_server.add_layer_for_push_dwallet_checkpoint_message(
                InboundRequestLayer::new(rate_limit::RateLimitLayer::new(
                    governor::Quota::per_second(limit),
                    rate_limit::WaitMode::Block,
                )),
            );
        }
        if let Some(limit) = state_sync_config.get_dwallet_checkpoint_message_rate_limit {
            state_sync_server = state_sync_server.add_layer_for_get_dwallet_checkpoint_message(
                InboundRequestLayer::new(rate_limit::RateLimitLayer::new(
                    governor::Quota::per_second(limit),
                    rate_limit::WaitMode::Block,
                )),
            );
        }
        if let Some(limit) = state_sync_config.get_dwallet_checkpoint_message_inflight_limit {
            state_sync_server = state_sync_server.add_layer_for_get_dwallet_checkpoint_message(
                InboundRequestLayer::new(inflight_limit::InflightLimitLayer::new(
                    limit,
                    inflight_limit::WaitMode::ReturnError,
                )),
            );
        }
        if let Some(limit) = state_sync_config.get_dwallet_checkpoint_message_per_checkpoint_limit {
            let layer = CheckpointMessageDownloadLimitLayer::new(limit);
            builder.download_limit_layer = Some(layer.clone());
            state_sync_server = state_sync_server
                .add_layer_for_get_dwallet_checkpoint_message(InboundRequestLayer::new(layer));
        }

        (builder, state_sync_server)
    }

    pub(super) fn build_internal(self) -> (UnstartedStateSync<S>, Server<S>) {
        let Builder {
            store,
            config,
            metrics,
            archive_readers,
            chain_identifier,
        } = self;
        let store = store.unwrap();
        let config = config.unwrap_or_default();
        let metrics = metrics.unwrap_or_else(Metrics::disabled);
        let archive_readers = archive_readers.unwrap_or_default();
        let chain_identifier = chain_identifier.unwrap_or_default();

        let (sender, mailbox) = mpsc::channel(config.mailbox_capacity());
        let (dwallet_checkpoint_event_sender, _receiver) =
            broadcast::channel(config.synced_dwallet_checkpoint_broadcast_channel_capacity());
        let (system_checkpoint_event_sender, _receiver) =
            broadcast::channel(config.synced_system_checkpoint_broadcast_channel_capacity());
        let weak_sender = sender.downgrade();
        let handle = Handle {
            sender,
            dwallet_checkpoint_event_sender: dwallet_checkpoint_event_sender.clone(),
            system_checkpoint_event_sender: system_checkpoint_event_sender.clone(),
        };
        let peer_heights = PeerHeights {
            peers: HashMap::new(),
            unprocessed_checkpoints: HashMap::new(),
            sequence_number_to_digest: HashMap::new(),
            unprocessed_system_checkpoint: HashMap::new(),
            sequence_number_to_digest_system_checkpoint: HashMap::new(),
            wait_interval_when_no_peer_to_sync_content: config
                .wait_interval_when_no_peer_to_sync_content(),
        }
        .pipe(RwLock::new)
        .pipe(Arc::new);

        let server = Server {
            store: store.clone(),
            peer_heights: peer_heights.clone(),
            sender: weak_sender,
            chain_identifier,
        };

        (
            UnstartedStateSync {
                config,
                handle,
                mailbox,
                store,
                download_limit_layer: None,
                peer_heights,
                checkpoint_event_sender: dwallet_checkpoint_event_sender,
                system_checkpoint_event_sender,
                metrics,
                archive_readers,
                chain_identifier,
                system_checkpoint_download_limit_layer: None,
            },
            server,
        )
    }
}

pub struct UnstartedStateSync<S> {
    pub(super) config: StateSyncConfig,
    pub(super) handle: Handle,
    pub(super) mailbox: mpsc::Receiver<StateSyncMessage>,
    pub(super) download_limit_layer: Option<CheckpointMessageDownloadLimitLayer>,
    pub(super) system_checkpoint_download_limit_layer: Option<SystemCheckpointDownloadLimitLayer>,
    pub(super) store: S,
    pub(super) peer_heights: Arc<RwLock<PeerHeights>>,
    pub(super) checkpoint_event_sender: broadcast::Sender<VerifiedCheckpointMessage<DWallet>>,
    pub(super) system_checkpoint_event_sender: broadcast::Sender<VerifiedCheckpointMessage<System>>,
    pub(super) metrics: Metrics,
    pub(super) archive_readers: ArchiveReaderBalancer,
    pub(crate) chain_identifier: ChainIdentifier,
}

impl<S> UnstartedStateSync<S>
where
    S: WriteStore + Clone + Send + Sync + 'static,
{
    pub(super) fn build(
        self,
        network: anemo::Network,
        is_notifier: bool,
    ) -> (StateSyncEventLoop<S>, Handle) {
        let Self {
            config,
            handle,
            mailbox,
            download_limit_layer,
            system_checkpoint_download_limit_layer,
            store,
            peer_heights,
            checkpoint_event_sender,
            system_checkpoint_event_sender,
            metrics,
            archive_readers,
            chain_identifier,
        } = self;

        (
            StateSyncEventLoop {
                is_notifier,
                config,
                mailbox,
                weak_sender: handle.sender.downgrade(),
                tasks: JoinSet::new(),
                sync_checkpoint_messages_task: None,
                download_limit_layer,
                system_checkpoint_event_sender,
                sync_system_checkpoints_task: None,
                system_checkpoint_download_limit_layer,
                store,
                peer_heights,
                checkpoint_event_sender,
                network,
                metrics,
                archive_readers,
                sync_checkpoint_from_archive_task: None,
                chain_identifier,
                sync_system_checkpoint_from_archive_task: None,
            },
            handle,
        )
    }

    pub fn start(self, network: anemo::Network, is_notifier: bool) -> Handle {
        let (event_loop, handle) = self.build(network, is_notifier);
        tokio::spawn(event_loop.start());

        handle
    }
}
