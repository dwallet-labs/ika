// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::{net::SocketAddr, num::NonZeroU32, time::Duration};

use ika_types::checkpoint::CheckpointSequenceNumber;
use ika_types::digests::DWalletCheckpointMessageDigest;
use ika_types::digests::SystemCheckpointMessageDigest;
use serde::{Deserialize, Serialize};
use sui_types::multiaddr::Multiaddr;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct P2pConfig {
    /// The address that the p2p network will bind on.
    #[serde(default = "default_listen_address")]
    pub listen_address: SocketAddr,
    /// The external address other nodes can use to reach this node.
    /// This will be shared with other peers through the discovery service
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_address: Option<Multiaddr>,
    /// SeedPeers are preferred and the node will always try to ensure a
    /// connection is established with these nodes.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub seed_peers: Vec<SeedPeer>,
    /// A list of fixed peers that the node will always try to connect to.
    /// If this field is set, the node will not find new peers through discovery.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_peers: Option<Vec<SeedPeer>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anemo_config: Option<anemo::Config>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_sync: Option<StateSyncConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery: Option<DiscoveryConfig>,
    /// Size in bytes above which network messages are considered excessively large. Excessively
    /// large messages will still be handled, but logged and reported in metrics for debugging.
    ///
    /// If unspecified, this will default to 8 MiB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excessive_message_size: Option<usize>,
}

fn default_listen_address() -> SocketAddr {
    "0.0.0.0:8080".parse().unwrap()
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            listen_address: default_listen_address(),
            external_address: Default::default(),
            seed_peers: Default::default(),
            fixed_peers: None,
            anemo_config: Default::default(),
            state_sync: None,
            discovery: None,
            excessive_message_size: None,
        }
    }
}

impl P2pConfig {
    pub fn excessive_message_size(&self) -> usize {
        const EXCESSIVE_MESSAGE_SIZE: usize = 32 << 20;

        self.excessive_message_size
            .unwrap_or(EXCESSIVE_MESSAGE_SIZE)
    }

    pub fn set_discovery_config(mut self, discovery_config: DiscoveryConfig) -> Self {
        self.discovery = Some(discovery_config);
        self
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct SeedPeer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_id: Option<anemo::PeerId>,
    pub address: Multiaddr,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct AllowlistedPeer {
    pub peer_id: anemo::PeerId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Multiaddr>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct StateSyncConfig {
    /// List of "known-good" dwallet checkpoints that state sync will be forced to use. State sync will
    /// skip verification of pinned dwallet checkpoints, and reject dwallet checkpoints with digests that don't
    /// match pinned values for a given sequence number.
    ///
    /// This can be used:
    /// - in case of a fork, to prevent the node from syncing to the wrong chain.
    /// - in case of a network stall, to force the node to proceed with a manually-injected
    ///   dwallet checkpoint.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub pinned_dwallet_checkpoints: Vec<(CheckpointSequenceNumber, DWalletCheckpointMessageDigest)>,

    /// Query peers for their latest dwallet checkpoint every interval period.
    ///
    /// If unspecified, this will default to `5,000` milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval_period_ms: Option<u64>,

    /// Size of the StateSync actor's mailbox.
    ///
    /// If unspecified, this will default to `1,024`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mailbox_capacity: Option<usize>,

    /// Size of the broadcast channel use for notifying other systems of newly sync'ed dwallet checkpoints.
    ///
    /// If unspecified, this will default to `1,024`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub synced_dwallet_checkpoint_broadcast_channel_capacity: Option<usize>,

    /// Set the upper bound on the number of dwallet checkpoint headers to be downloaded concurrently.
    ///
    /// If unspecified, this will default to `400`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dwallet_checkpoint_header_download_concurrency: Option<usize>,

    /// Set the upper bound on the number of dwallet checkpoint contents to be downloaded concurrently.
    ///
    /// If unspecified, this will default to `400`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dwallet_checkpoint_content_download_concurrency: Option<usize>,

    /// Set the upper bound on the number of individual transactions contained in dwallet checkpoint
    /// contents to be downloaded concurrently. If both this value and
    /// `dwallet_checkpoint_content_download_concurrency` are set, the lower of the two will apply.
    ///
    /// If unspecified, this will default to `50,000`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dwallet_checkpoint_content_download_tx_concurrency: Option<u64>,

    /// Set the timeout that should be used when sending most state-sync RPC requests.
    ///
    /// If unspecified, this will default to `10,000` milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,

    /// Set the timeout that should be used when sending RPC requests to sync dwallet checkpoint contents.
    ///
    /// If unspecified, this will default to `10,000` milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dwallet_checkpoint_content_timeout_ms: Option<u64>,

    /// Per-peer rate-limit (in requests/sec) for the PushDWalletCheckpointMessage RPC.
    ///
    /// If unspecified, this will default to no limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_dwallet_checkpoint_message_rate_limit: Option<NonZeroU32>,

    /// Per-peer rate-limit (in requests/sec) for the GetDWalletCheckpointMessage RPC.
    ///
    /// If unspecified, this will default to no limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_dwallet_checkpoint_message_rate_limit: Option<NonZeroU32>,

    /// Per-peer inflight limit for the GetDWalletCheckpointMessage RPC.
    ///
    /// If unspecified, this will default to no limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_dwallet_checkpoint_message_inflight_limit: Option<usize>,

    /// Per-dwallet checkpoint inflight limit for the GetDWalletCheckpointMessage RPC. This is enforced globally
    /// across all peers.
    ///
    /// If unspecified, this will default to no limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_dwallet_checkpoint_message_per_checkpoint_limit: Option<usize>,

    /// The amount of time to wait before retry if there are no peers to sync content from.
    /// If unspecified, this will set to default value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_interval_when_no_peer_to_sync_content_ms: Option<u64>,

    /// List of "known-good" system checkpoints that state sync will be forced to use. State sync will
    /// skip verification of pinned system checkpoints, and reject system checkpoints with digests that don't
    /// match pinned values for a given sequence number.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub pinned_system_checkpoints: Vec<(CheckpointSequenceNumber, SystemCheckpointMessageDigest)>,

    /// Size of the broadcast channel use for notifying other systems of newly sync'ed system checkpoints.
    ///
    /// If unspecified, this will default to `1,024`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub synced_system_checkpoint_broadcast_channel_capacity: Option<usize>,

    /// Set the upper bound on the number of system checkpoint headers to be downloaded concurrently.
    ///
    /// If unspecified, this will default to `400`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_checkpoint_header_download_concurrency: Option<usize>,

    /// Set the upper bound on the number of system checkpoint contents to be downloaded concurrently.
    ///
    /// If unspecified, this will default to `400`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_checkpoint_content_download_concurrency: Option<usize>,

    /// Set the upper bound on the number of individual transactions contained in system checkpoint
    /// contents to be downloaded concurrently.
    ///
    /// If unspecified, this will default to `50,000`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_checkpoint_content_download_tx_concurrency: Option<u64>,

    /// Set the timeout that should be used when sending RPC requests to sync system checkpoint contents.
    ///
    /// If unspecified, this will default to `10,000` milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_checkpoint_content_timeout_ms: Option<u64>,

    /// Per-peer rate-limit (in requests/sec) for the PushSystemCheckpointMessage RPC.
    ///
    /// If unspecified, this will default to no limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_system_checkpoint_message_rate_limit: Option<NonZeroU32>,

    /// Per-peer rate-limit (in requests/sec) for the GetSystemCheckpointMessage RPC.
    ///
    /// If unspecified, this will default to no limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_system_checkpoint_message_rate_limit: Option<NonZeroU32>,

    /// Per-peer inflight limit for the GetSystemCheckpointMessage RPC.
    ///
    /// If unspecified, this will default to no limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_system_checkpoint_message_inflight_limit: Option<usize>,

    /// Per-system checkpoint inflight limit for the GetSystemCheckpointMessage RPC. This is enforced globally
    /// across all peers.
    ///
    /// If unspecified, this will default to no limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_system_checkpoint_message_per_checkpoint_limit: Option<usize>,
}

impl StateSyncConfig {
    pub fn interval_period(&self) -> Duration {
        const INTERVAL_PERIOD_MS: u64 = 5_000; // 5 seconds

        Duration::from_millis(self.interval_period_ms.unwrap_or(INTERVAL_PERIOD_MS))
    }

    pub fn mailbox_capacity(&self) -> usize {
        const MAILBOX_CAPACITY: usize = 1_024;

        self.mailbox_capacity.unwrap_or(MAILBOX_CAPACITY)
    }

    pub fn synced_dwallet_checkpoint_broadcast_channel_capacity(&self) -> usize {
        const SYNCED_DWALLET_CHECKPOINT_BROADCAST_CHANNEL_CAPACITY: usize = 1_024;

        self.synced_dwallet_checkpoint_broadcast_channel_capacity
            .unwrap_or(SYNCED_DWALLET_CHECKPOINT_BROADCAST_CHANNEL_CAPACITY)
    }

    pub fn synced_system_checkpoint_broadcast_channel_capacity(&self) -> usize {
        const SYNCED_SYSTEM_CHECKPOINT_BROADCAST_CHANNEL_CAPACITY: usize = 1_024;

        self.synced_system_checkpoint_broadcast_channel_capacity
            .unwrap_or(SYNCED_SYSTEM_CHECKPOINT_BROADCAST_CHANNEL_CAPACITY)
    }

    pub fn dwallet_checkpoint_header_download_concurrency(&self) -> usize {
        const DWALLET_CHECKPOINT_HEADER_DOWNLOAD_CONCURRENCY: usize = 400;

        self.dwallet_checkpoint_header_download_concurrency
            .unwrap_or(DWALLET_CHECKPOINT_HEADER_DOWNLOAD_CONCURRENCY)
    }

    pub fn system_checkpoint_header_download_concurrency(&self) -> usize {
        const SYSTEM_CHECKPOINT_HEADER_DOWNLOAD_CONCURRENCY: usize = 400;

        self.system_checkpoint_header_download_concurrency
            .unwrap_or(SYSTEM_CHECKPOINT_HEADER_DOWNLOAD_CONCURRENCY)
    }

    pub fn dwallet_checkpoint_content_download_concurrency(&self) -> usize {
        const DWALLET_CHECKPOINT_CONTENT_DOWNLOAD_CONCURRENCY: usize = 400;

        self.dwallet_checkpoint_content_download_concurrency
            .unwrap_or(DWALLET_CHECKPOINT_CONTENT_DOWNLOAD_CONCURRENCY)
    }

    pub fn dwallet_checkpoint_content_download_tx_concurrency(&self) -> u64 {
        const DWALLET_CHECKPOINT_CONTENT_DOWNLOAD_TX_CONCURRENCY: u64 = 50_000;

        self.dwallet_checkpoint_content_download_tx_concurrency
            .unwrap_or(DWALLET_CHECKPOINT_CONTENT_DOWNLOAD_TX_CONCURRENCY)
    }

    pub fn timeout(&self) -> Duration {
        const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

        self.timeout_ms
            .map(Duration::from_millis)
            .unwrap_or(DEFAULT_TIMEOUT)
    }

    pub fn dwallet_checkpoint_content_timeout(&self) -> Duration {
        const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

        self.dwallet_checkpoint_content_timeout_ms
            .map(Duration::from_millis)
            .unwrap_or(DEFAULT_TIMEOUT)
    }

    pub fn wait_interval_when_no_peer_to_sync_content(&self) -> Duration {
        self.wait_interval_when_no_peer_to_sync_content_ms
            .map(Duration::from_millis)
            .unwrap_or(self.default_wait_interval_when_no_peer_to_sync_content())
    }

    fn default_wait_interval_when_no_peer_to_sync_content(&self) -> Duration {
        if cfg!(msim) {
            Duration::from_secs(5)
        } else {
            Duration::from_secs(10)
        }
    }
}

/// Access Type of a node.
/// AccessType info is shared in the discovery process.
/// * If the node marks itself as Public, other nodes may try to connect to it.
/// * If the node marks itself as Private, only nodes that have it in
///   their `allowlisted_peers` or `seed_peers` will try to connect to it.
/// * If not set, defaults to Public.
///
/// AccessType is useful when a network of nodes want to stay private. To achieve this,
/// mark every node in this network as `Private` and allowlist/seed them to each other.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AccessType {
    Public,
    Private,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct DiscoveryConfig {
    /// Query peers for their latest checkpoint every interval period.
    ///
    /// If unspecified, this will default to `5,000` milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval_period_ms: Option<u64>,

    /// Target number of concurrent connections to establish.
    ///
    /// If unspecified, this will default to `4`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_concurrent_connections: Option<usize>,

    /// Number of peers to query each interval.
    ///
    /// Sets the number of peers, to be randomly selected, that are queried for their known peers
    /// each interval.
    ///
    /// If unspecified, this will default to `1`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peers_to_query: Option<usize>,

    /// Per-peer rate-limit (in requests/sec) for the GetKnownPeers RPC.
    ///
    /// If unspecified, this will default to no limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_known_peers_rate_limit: Option<NonZeroU32>,

    /// See docstring for `AccessType`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_type: Option<AccessType>,

    /// Like `seed_peers` in `P2pConfig`, allowlisted peers will awlays be allowed to establish
    /// connection with this node regardless of the concurrency limit.
    /// Unlike `seed_peers`, a node does not reach out to `allowlisted_peers` preferentially.
    /// It is also used to determine if a peer is accessible when its AccessType is Private.
    /// For example, a node will ignore a peer with Private AccessType if the peer is not in
    /// its `allowlisted_peers`. Namely, the node will not try to establish connections
    /// to this peer, nor advertise this peer's info to other peers in the network.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub allowlisted_peers: Vec<AllowlistedPeer>,
}

impl DiscoveryConfig {
    pub fn interval_period(&self) -> Duration {
        const INTERVAL_PERIOD_MS: u64 = 5_000; // 5 seconds

        Duration::from_millis(self.interval_period_ms.unwrap_or(INTERVAL_PERIOD_MS))
    }

    pub fn target_concurrent_connections(&self) -> usize {
        const TARGET_CONCURRENT_CONNECTIONS: usize = 4;

        self.target_concurrent_connections
            .unwrap_or(TARGET_CONCURRENT_CONNECTIONS)
    }

    pub fn peers_to_query(&self) -> usize {
        const PEERS_TO_QUERY: usize = 1;

        self.peers_to_query.unwrap_or(PEERS_TO_QUERY)
    }

    pub fn access_type(&self) -> AccessType {
        // defaults None to Public
        self.access_type.unwrap_or(AccessType::Public)
    }
}
