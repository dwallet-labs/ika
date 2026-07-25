// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear
//
//! Orchestration entry point that assembles the OCS verifier stack.
//!
//! Two layers, two transports. The validator's role determines which
//! impl plugs into each:
//!
//! ```text
//!     OcsVerifiedReader            (consumer surface — verified reads)
//!         │
//!         ▼
//!     dyn ProofProvider
//!         │
//!     ┌───┴────────────────┐
//!     │ sui-state-direct   │ LocalProofProvider     →  SuiGrpcClient
//!     │ sui-state-mirrored │ SuiMirrorProofProvider → anemo to a direct peer
//!
//!     OcsVerifyingClient           (committee ratchet — uses raw transport)
//!         │
//!         ▼
//!     dyn SuiTransport
//!         │
//!     ┌───┴────────────────────────────────────────────┐
//!     │ sui-state-direct   │ SuiGrpcClient             │
//!     │ sui-state-mirrored │ SuiMirrorTransport (+opt. │
//!     │                    │   FallbackTransport for   │
//!     │                    │   directly-routed methods)│
//! ```
//!
//! A `sui-state-direct` validator also exposes a `SuiStateMirrorServer`
//! wrapping the same `LocalProofProvider`, so its local consumer and
//! remote `sui-state-mirrored` peers see the same view.

use std::sync::Arc;

use anemo::PeerId;
use ika_config::node::{SuiConnectorConfig, SuiDataSource, resolve_sui_checkpoint_archive};
use ika_network::proof_provider::{
    LocalProofProvider, ProofCacheConfig, ProofProvider, ProofProviderMetrics,
};
use ika_network::sui_state_mirror::{
    self, Server as SuiStateMirrorImpl, SuiMirrorPeers, SuiMirrorProofProvider, SuiMirrorTransport,
    SuiStateMirrorServer,
};
use ika_sui_client::genesis::load_and_verify_sui_genesis;
use ika_sui_client::grpc::SuiGrpcClient;
use ika_sui_client::transport::SuiTransport;
use tracing::{info, warn};
use typed_store::TypedStoreError;

use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
use crate::sui_connector::changeset_receiver::{ChangesetReceiver, SharedChangesetIndex};
use crate::sui_connector::committee_store::{CommitteeBootstrap, CommitteeStore};
use crate::sui_connector::fallback_transport::FallbackTransport;
use crate::sui_connector::ocs_currency::ChangesetIndex;
use crate::sui_connector::ocs_metrics::OcsMetrics;
use crate::sui_connector::ocs_verifier::{OcsError, OcsVerifyingClient};
use crate::sui_connector::retained_transport::RetainedFullnodeTransport;
use crate::sui_connector::verified_reader::OcsVerifiedReader;
use crate::sui_connector::verified_state_cache::{SharedVerifiedStateCache, VerifiedStateCache};
use parking_lot::RwLock;
use std::time::Duration;

pub struct SuiConnectorStack {
    /// Verified-read surface used by all consumers.
    pub reader: Arc<OcsVerifiedReader>,
    /// Committee ratchet (uses raw transport, not the verified reader).
    pub ratchet: Arc<OcsVerifyingClient>,
    /// `Some` when this validator runs as sui-state-direct with
    /// `serve_mirror = true`. Caller adds it to the anemo router at
    /// construction time.
    pub mirror_server: Option<SuiStateMirrorServer<SuiStateMirrorImpl>>,
    /// sui-state-direct only: a fresh raw [`SuiTransport`] the caller
    /// uses to spawn an
    /// [`crate::sui_connector::push_worker::IkaCheckpointPusher`] once
    /// the anemo network is up. `None` for sui-state-mirrored.
    pub raw_transport_for_pushing: Option<Arc<dyn SuiTransport>>,
    /// Per-validator verified state cache. On sui-state-direct the
    /// `IkaCheckpointPusher` folds every checkpoint's Ika-modified objects
    /// here and consumers read cache-first; on sui-state-mirrored it is a
    /// read-through memo of per-read-verified relay reads.
    pub state_cache: SharedVerifiedStateCache,
    pub metrics: Arc<OcsMetrics>,
    /// `Some` on a sui-state-mirrored / peer-only node: the changeset-stream
    /// receiver that keeps the reader's currency index caught up. The caller
    /// spawns `.run()` once the anemo network is up (like the pusher). `None`
    /// on sui-state-direct.
    pub changeset_receiver: Option<ChangesetReceiver>,
}

#[derive(thiserror::Error, Debug)]
pub enum SetupError {
    #[error("invalid Sui mirror peer id `{peer}`: {error}")]
    BadPeerId { peer: String, error: String },
    #[error("sui-state-mirrored configured but no anemo network handed in")]
    MirroredWithoutNetwork,
    #[error(
        "OCS stack requested but the node config has no `sui-data-source` section \
         (old-style JSON-RPC config); add a sui-data-source (gRPC) section"
    )]
    MissingDataSource,
    #[error(
        "the Sui chain at the configured endpoint does not advertise \
         CheckpointArtifactsDigest (requires protocol v122+ with \
         include_checkpoint_artifacts_digest_in_summary enabled)"
    )]
    ArtifactsDigestUnsupported,
    #[error(
        "persisted OCS committee state could not be deserialized ({0}); this usually \
         means a Sui version upgrade changed its on-disk format. Recovery is automatic \
         when a `sui_genesis` blob is configured (the committee tables are wiped and \
         the chain re-bootstraps from genesis); without one, clear the node's OCS \
         committee tables manually and configure `sui_genesis`."
    )]
    PersistedCommitteeUnreadable(String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("Sui genesis bootstrap: {0}")]
    Genesis(#[from] ika_sui_client::genesis::GenesisError),
    #[error("BootstrapPlan::Genesis resolved but no sui_genesis path is configured")]
    GenesisPathMissing,
    #[error(transparent)]
    Ocs(#[from] OcsError),
    #[error(transparent)]
    Ika(#[from] ika_types::error::IkaError),
}

/// What the operator gave us for OCS bootstrap, post-disambiguation:
///
/// - `Hydrated`: perpetual tables already have committees; ignore any
///   configured genesis blob (we've already verified past it).
/// - `Genesis`: bootstrap committee[0] from the verified `sui_genesis` blob.
pub enum BootstrapPlan {
    Hydrated,
    /// Genesis-rooted: load the configured `sui_genesis` blob, verify its
    /// genesis checkpoint digest against the compiled-in chain identifier, and
    /// install `committee[0]`. The caller does the I/O.
    Genesis,
}

pub fn resolve_bootstrap_plan(
    cfg: &SuiConnectorConfig,
    perpetual: &AuthorityPerpetualTables,
) -> Result<BootstrapPlan, SetupError> {
    if let Some(head) = perpetual
        .highest_sui_committee_epoch()
        .map_err(SetupError::Ika)?
    {
        // Perpetual committee state always wins over a configured genesis seed:
        // the seed is a first-boot bootstrap, and configs carry it forever, so
        // re-reading it on every restart would re-bootstrap the node each time.
        // To force a re-bootstrap, clear the OCS committee tables — say so out
        // loud instead of silently ignoring a config change.
        if cfg.sui_genesis.is_some() {
            tracing::info!(
                perpetual_head_epoch = head,
                "OCS bootstrap: using the perpetual committee chain; the configured \
                 genesis blob is only read on first boot. To re-bootstrap, clear the \
                 node's OCS committee tables so the next boot re-seeds from genesis."
            );
        }
        return Ok(BootstrapPlan::Hydrated);
    }
    // Genesis-rooted bootstrap: load + verify the configured genesis blob.
    if cfg.sui_genesis.is_some() {
        return Ok(BootstrapPlan::Genesis);
    }
    // Caller treats this as "no OCS configured; skip" only when the
    // node mode permits it. For validators we error in node startup.
    Ok(BootstrapPlan::Hydrated)
}

/// The role-dependent transports + provider resolved from the data source: the
/// raw ratchet transport, the read `ProofProvider`, whether this node can serve
/// the mirror (sui-state-direct), the optional raw transport for the pusher
/// (direct only), and the optional concrete mirror client for the changeset
/// receiver (mirrored / peer-only only).
type RawTransportSetup = (
    Arc<dyn SuiTransport>,
    Arc<dyn ProofProvider>,
    bool,
    Option<Arc<dyn SuiTransport>>,
    Option<Arc<SuiMirrorTransport>>,
);

pub async fn build_sui_connector_stack(
    cfg: &SuiConnectorConfig,
    perpetual: Arc<AuthorityPerpetualTables>,
    network: Option<anemo::Network>,
    proof_cache_cfg: ProofCacheConfig,
    metrics: Arc<OcsMetrics>,
    provider_metrics: Arc<ProofProviderMetrics>,
) -> Result<SuiConnectorStack, SetupError> {
    // 1. Build the *raw* transport used by the committee ratchet (and,
    //    on sui-state-direct nodes, by the LocalProofProvider
    //    underneath). Direct-gRPC for sui-state-direct;
    //    relay-or-fallback for sui-state-mirrored.
    let (raw_for_ratchet, proof_provider, mirror_capable, raw_for_pushing, changeset_source): RawTransportSetup = match cfg
        .sui_data_source
        .as_ref()
        .ok_or(SetupError::MissingDataSource)?
    {
        SuiDataSource::SuiStateDirect { url, .. } => {
            // Concrete `SuiGrpcClient`: the proof builder needs
            // `get_transaction_checkpoint`, an inherent gRPC method (not part of
            // the relay-able `SuiTransport` surface).
            let grpc = Arc::new(
                SuiGrpcClient::new(url)
                    .await
                    .map_err(|e| SetupError::Transport(format!("connect {url}: {e}")))?,
            );
            // Same provider instance used by the local reader and (via
            // the mirror server) by remote sui-state-mirrored peers.
            let provider: Arc<dyn ProofProvider> = Arc::new(LocalProofProvider::new(
                grpc.clone(),
                &proof_cache_cfg,
                provider_metrics.clone(),
            ));
            provider_metrics
                .role_info
                .with_label_values(&["sui_state_direct"])
                .set(1);
            let grpc: Arc<dyn SuiTransport> = grpc;
            (grpc.clone(), provider, true, Some(grpc), None)
        }
        SuiDataSource::SuiStateMirrored { fallback_grpc_url } => {
            let net = network.clone().ok_or(SetupError::MirroredWithoutNetwork)?;
            let mut peer_ids = Vec::with_capacity(cfg.sui_state_mirror_peers.len());
            for raw_id in &cfg.sui_state_mirror_peers {
                peer_ids.push(parse_peer_id(raw_id)?);
            }
            let peers = SuiMirrorPeers::new(net, peer_ids, provider_metrics.clone());

            let provider: Arc<dyn ProofProvider> = Arc::new(SuiMirrorProofProvider::new(
                peers.clone(),
                provider_metrics.clone(),
            ));
            provider_metrics
                .role_info
                .with_label_values(&["sui_state_mirrored"])
                .set(1);

            // Keep the concrete mirror client: the changeset receiver pulls
            // `changeset_page` from it (not part of the `SuiTransport` trait).
            let mirror = Arc::new(SuiMirrorTransport::new(peers));
            let relay: Arc<dyn SuiTransport> = mirror.clone();
            let raw: Arc<dyn SuiTransport> = match fallback_grpc_url {
                Some(url) => {
                    let fallback: Arc<dyn SuiTransport> =
                        Arc::new(SuiGrpcClient::new(url).await.map_err(|e| {
                            SetupError::Transport(format!("connect fallback {url}: {e}"))
                        })?);
                    Arc::new(FallbackTransport::new(relay, fallback))
                }
                None => relay,
            };
            (raw, provider, false, None, Some(mirror))
        }
    };

    // 2. Probe artifacts-digest support before doing anything else.
    probe_artifacts_digest(&raw_for_ratchet).await?;

    // 2b. Recover from a stale persisted committee format before resolving the
    //     bootstrap plan. A Sui version upgrade can change the on-disk BCS
    //     layout of the committee / summary columns; when a genesis blob is
    //     configured the recovery is automatic — wipe the committee tables and
    //     re-bootstrap the chain from genesis (worst case a full genesis→now
    //     re-ratchet; the public checkpoint stores retain every end-of-epoch
    //     checkpoint since epoch 0, so the walk always has a verified source).
    //     Without a genesis blob there is nothing to re-bootstrap from, so
    //     surface an actionable error instead of silently wiping the only
    //     anchor. The rebuildable verified-object cache recovers itself inside
    //     `VerifiedStateCache::open`; this handles the trust chain. (A
    //     transient RocksDB IO error is not format rot and still propagates.)
    if let Err(e) = perpetual.probe_head_committee_readable() {
        match e {
            TypedStoreError::SerializationError(reason) if cfg.sui_genesis.is_some() => {
                warn!(
                    reason,
                    "persisted Sui committee state could not be deserialized (likely a Sui \
                     version upgrade); wiping the committee tables and re-bootstrapping the \
                     committee chain from the configured genesis blob"
                );
                perpetual
                    .wipe_sui_committee_state_for_format_recovery()
                    .map_err(SetupError::Ika)?;
                // Cleared: `highest_sui_committee_epoch()` is now `None`, so the
                // bootstrap below takes the genesis-bootstrap path.
            }
            TypedStoreError::SerializationError(reason) => {
                return Err(SetupError::PersistedCommitteeUnreadable(reason));
            }
            other => return Err(SetupError::Ika(other.into())),
        }
    }

    // 3. Resolve the bootstrap plan → the genesis blob (verified against the
    //    compiled-in chain identifier) yields committee[0] → committee store →
    //    ratchet client.
    let plan = resolve_bootstrap_plan(cfg, &perpetual)?;
    let bootstrap = match plan {
        BootstrapPlan::Hydrated => None,
        BootstrapPlan::Genesis => {
            let path = cfg
                .sui_genesis
                .as_ref()
                .ok_or(SetupError::GenesisPathMissing)?;
            let boot = load_and_verify_sui_genesis(path, cfg.sui_chain_identifier)?;
            info!(
                epoch = boot.committee.epoch,
                chain_identifier = %boot.chain_identifier.base58_encode(),
                "OCS bootstrap: genesis-rooted committee[0] loaded; Sui chain identifier \
                 verified against the compiled-in constant"
            );
            Some(CommitteeBootstrap::Genesis(boot.committee))
        }
    };
    let committees = Arc::new(CommitteeStore::open(perpetual.clone(), bootstrap)?);
    // Verified-fallback end-of-epoch checkpoint archive (object store). Used by
    // the ratchet for cold bootstrap and when the upstream fullnode has pruned
    // an end-of-epoch checkpoint; every byte is BLS-verified, so the archive is
    // untrusted. An explicit config wins verbatim; with none, the known public
    // chains default to their public Sui checkpoint store (localnet gets none).
    let archive_config = resolve_sui_checkpoint_archive(
        cfg.sui_chain_identifier,
        cfg.sui_checkpoint_archive.as_ref(),
    );
    if cfg.sui_checkpoint_archive.is_none()
        && let Some(default_archive) = &archive_config
    {
        info!(
            url = %default_archive.url,
            chain = %cfg.sui_chain_identifier,
            "no sui-checkpoint-archive configured; using the network's public Sui \
             end-of-epoch checkpoint store as the verified fallback archive \
             (untrusted availability source — every checkpoint is BLS-verified \
             against the genesis-rooted committee chain)"
        );
    }
    let archive: Option<Arc<dyn ika_sui_client::archive::CheckpointArchive>> =
        archive_config.as_ref().map(|a| {
            Arc::new(ika_sui_client::archive::SuiCheckpointArchive::new(
                a.url.clone(),
                a.options.clone(),
            )) as Arc<dyn ika_sui_client::archive::CheckpointArchive>
        });
    let ratchet = Arc::new(
        OcsVerifyingClient::new(raw_for_ratchet, committees.clone(), metrics.clone())
            .with_archive(archive),
    );

    // Mirrored / peer-only currency: a changeset index the reader consults,
    // folded by a background `ChangesetReceiver` that pulls committee-signed
    // changesets from the relay. Direct nodes leave it `None` (their pusher-fed
    // cache is already a complete, contiguous fold). The receiver backfills from
    // the oldest committee-verifiable checkpoint — the anchor summary's seq + 1
    // (it can't verify earlier); if the serving peer has pruned below that,
    // currency stays dormant on those objects, a safe `Unknown` fallback.
    const CHANGESET_PAGE_LIMIT: u32 = 64;
    const CHANGESET_POLL_INTERVAL: Duration = Duration::from_secs(2);
    // Keep currency for objects modified within this many checkpoints of the
    // head; older entries are dropped (reads anchored below the floor fall back
    // to the per-read defenses). Must exceed a few epochs so idle Ika objects
    // (the System / Coordinator inner, modified at epoch boundaries) stay
    // covered — heuristic, tune per chain. On a busy chain the per-checkpoint
    // modified set still dominates; Ika-filtering the folded set is the
    // complementary bound (see the design doc).
    const CHANGESET_RETAIN_WINDOW: u64 = 432_000;
    let changeset_index: Option<SharedChangesetIndex> = changeset_source.is_some().then(|| {
        Arc::new(RwLock::new(
            ChangesetIndex::new().with_retain_window(Some(CHANGESET_RETAIN_WINDOW)),
        ))
    });
    let changeset_receiver = match (changeset_source, &changeset_index) {
        (Some(source), Some(index)) => {
            let bootstrap_from = perpetual
                .oldest_sui_committee_summary()
                .map_err(|e| SetupError::Transport(format!("oldest committee summary: {e}")))?
                .map(|summary| (*summary.sequence_number()).saturating_add(1))
                .unwrap_or(0);
            Some(ChangesetReceiver::new(
                index.clone(),
                source,
                committees.clone(),
                CHANGESET_PAGE_LIMIT,
                bootstrap_from,
                CHANGESET_POLL_INTERVAL,
            ))
        }
        _ => None,
    };

    // Durable cache: rehydrates from the perpetual `verified_object_cache`
    // column on boot and writes through every absorb, so a restart resumes
    // serving from DB instead of re-fetching from the (possibly pruned) Sui
    // fullnode.
    let state_cache: SharedVerifiedStateCache = Arc::new(
        VerifiedStateCache::open(perpetual.clone())?
            .with_retain_window(Some(cfg.verified_cache_retention_checkpoints())),
    );

    // 4. Verified-read surface for consumers. Freshness defense is
    //    version-monotonicity (per-object high-water mark in the
    //    reader); checkpoint-distance bounds were too fragile — even
    //    `System` only updates at epoch boundaries, so its proof can
    //    legitimately anchor far behind the relay's head.
    //
    //    Cache-first reads are enabled only on sui-state-direct
    //    (`mirror_capable`): there the local `IkaCheckpointPusher` folds
    //    every Ika-modified object of every checkpoint, in order, into
    //    `state_cache`, so a cache hit is the object's current state (up
    //    to the pusher's poll lag) and needs no re-verification. On
    //    sui-state-mirrored the cache is a read-through memo of an
    //    untrusted relay, so reads stay on the per-read-verified relay.
    let cache_first_reads = mirror_capable;
    // Cache-first staleness tripwire (direct only): if the cache head lags the
    // observed upstream head by more than this many checkpoints (e.g. a
    // stalled pusher), serve from the network instead of frozen cache state.
    // ~100 checkpoints is well above the normal pusher poll lag (a handful of
    // checkpoints) yet catches an unboundedly-falling-behind pusher.
    const CACHE_STALENESS_BOUND_CHECKPOINTS: u64 = 100;
    let staleness_bound = cache_first_reads.then_some(CACHE_STALENESS_BOUND_CHECKPOINTS);
    let reader = Arc::new(
        OcsVerifiedReader::new(
            proof_provider.clone(),
            committees.clone(),
            metrics.clone(),
            None,
            state_cache.clone(),
            cache_first_reads,
            staleness_bound,
        )
        .with_changeset_index(changeset_index),
    );

    // Publish the head epoch we booted at so dashboards can correlate
    // when this node started ratcheting.
    let anchor_epoch = ratchet.committees().head_epoch();
    provider_metrics
        .anchor_info
        .with_label_values(&[&anchor_epoch.to_string()])
        .set(1);

    // 5. sui-state-direct relay server (Some iff configured to serve): exposes
    //    the verified-read RPCs (VerifiedObject / BatchVerifiedObjects /
    //    VerifiedDynamicFieldsPage) to mirrored and peer-only peers.
    let mirror_server = if mirror_capable
        && matches!(
            cfg.sui_data_source,
            Some(SuiDataSource::SuiStateDirect {
                serve_mirror: true,
                ..
            })
        ) {
        // Front the relay server's transport with the retained-checkpoint
        // decorator: it serves the committee-ratchet primitives from this node's
        // persisted end-of-epoch checkpoints before reaching the (prune-prone)
        // fullnode, so a mirrored peer's ratchet advances without depending on
        // the fullnode still holding the end-of-epoch checkpoint.
        let mirror_transport: Arc<dyn SuiTransport> = Arc::new(RetainedFullnodeTransport::new(
            ratchet.transport().clone(),
            perpetual.clone(),
        ));
        Some(sui_state_mirror::make_server(
            mirror_transport,
            proof_provider,
            provider_metrics.clone(),
        ))
    } else {
        None
    };

    info!(
        data_source = ?cfg.sui_data_source,
        head_epoch = ratchet.committees().head_epoch(),
        "OCS connector stack built"
    );
    Ok(SuiConnectorStack {
        reader,
        ratchet,
        mirror_server,
        raw_transport_for_pushing: raw_for_pushing,
        state_cache,
        metrics,
        changeset_receiver,
    })
}

fn parse_peer_id(s: &str) -> Result<PeerId, SetupError> {
    let bytes: [u8; 32] =
        hex::FromHex::from_hex(s).map_err(|e: hex::FromHexError| SetupError::BadPeerId {
            peer: s.to_string(),
            error: e.to_string(),
        })?;
    Ok(PeerId(bytes))
}

/// Parse the configured `sui_state_mirror_peers` into anemo [`PeerId`]s,
/// warning on (and skipping) malformed entries. Lenient counterpart of the
/// strict per-entry [`parse_peer_id`] used at stack construction: callers of
/// this are deciding which peers to *wait for*, where a bad entry should not
/// abort boot.
pub fn configured_mirror_peer_ids(cfg: &SuiConnectorConfig) -> Vec<PeerId> {
    cfg.sui_state_mirror_peers
        .iter()
        .filter_map(|raw| match parse_peer_id(raw) {
            Ok(id) => Some(id),
            Err(e) => {
                tracing::warn!(
                    peer = %raw,
                    error = %e,
                    "skipping malformed sui_state_mirror_peers entry"
                );
                None
            }
        })
        .collect()
}

async fn probe_artifacts_digest(transport: &Arc<dyn SuiTransport>) -> Result<(), SetupError> {
    let summary = transport
        .get_latest_checkpoint()
        .await
        .map_err(|e| SetupError::Transport(format!("probe latest checkpoint: {e}")))?;
    let seq = *summary.sequence_number();
    let data = transport
        .get_full_checkpoint(seq)
        .await
        .map_err(|e| SetupError::Transport(format!("probe full checkpoint {seq}: {e}")))?;
    if data
        .checkpoint_summary
        .checkpoint_artifacts_digest()
        .is_err()
    {
        warn!(
            seq,
            "Sui chain does not advertise CheckpointArtifactsDigest"
        );
        return Err(SetupError::ArtifactsDigestUnsupported);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use ika_config::node::{SuiChainIdentifier, SuiDataSource};
    use sui_types::base_types::ObjectID;
    use sui_types::committee::Committee;

    /// Minimal `SuiConnectorConfig` for `resolve_bootstrap_plan`: only the
    /// genesis / chain-identifier fields it reads matter; the rest are filler.
    fn minimal_config(sui_genesis: Option<std::path::PathBuf>) -> SuiConnectorConfig {
        SuiConnectorConfig {
            sui_rpc_url: None,
            sui_data_source: Some(SuiDataSource::SuiStateDirect {
                url: "http://unused".to_string(),
                serve_mirror: false,
            }),
            sui_state_mirror_peers: vec![],
            sui_genesis,
            sui_checkpoint_archive: None,
            sui_chain_identifier: SuiChainIdentifier::Custom,
            ika_unsafe_identity_override: None,
            ika_package_id: ObjectID::random(),
            ika_common_package_id: ObjectID::random(),
            ika_dwallet_2pc_mpc_package_id: ObjectID::random(),
            ika_dwallet_2pc_mpc_package_id_v2: None,
            ika_system_package_id: ObjectID::random(),
            ika_system_object_id: ObjectID::random(),
            ika_dwallet_coordinator_object_id: ObjectID::random(),
            verified_cache_retention_checkpoints: None,
            notifier_client_key_pair: None,
            notifier_gas_from_address_balance: false,
            sui_ika_system_module_last_processed_event_id_override: None,
        }
    }

    /// A fresh node (no perpetual committees) with a configured `sui_genesis`
    /// blob resolves to the genesis-rooted bootstrap plan.
    #[tokio::test]
    async fn fresh_node_with_genesis_resolves_to_genesis_plan() {
        let dir = tempfile::tempdir().unwrap();
        let perpetual = AuthorityPerpetualTables::open(dir.path(), None);
        let cfg = minimal_config(Some(std::path::PathBuf::from("/unused/genesis.blob")));
        let plan = resolve_bootstrap_plan(&cfg, &perpetual).unwrap();
        assert!(
            matches!(plan, BootstrapPlan::Genesis),
            "a configured genesis blob must resolve to the genesis bootstrap"
        );
    }

    /// A fresh node without a genesis blob is `Hydrated` (the caller decides
    /// whether that's an error for its role).
    #[tokio::test]
    async fn fresh_node_without_bootstrap_is_hydrated() {
        let dir = tempfile::tempdir().unwrap();
        let perpetual = AuthorityPerpetualTables::open(dir.path(), None);
        let cfg = minimal_config(None);
        let plan = resolve_bootstrap_plan(&cfg, &perpetual).unwrap();
        assert!(matches!(plan, BootstrapPlan::Hydrated));
    }

    /// Invariant: perpetual committee state ALWAYS wins over a configured
    /// genesis seed. With a committee already installed, resolving the bootstrap
    /// plan returns `Hydrated` even with `sui_genesis` set — the seed is a
    /// first-boot bootstrap, ignored once the node has verified past it
    /// (re-bootstrapping requires wiping the tables).
    #[tokio::test]
    async fn perpetual_state_overrides_configured_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let perpetual = AuthorityPerpetualTables::open(dir.path(), None);
        // Install a committee -> head is set, so the node is "hydrated".
        let (committee, _keys) = Committee::new_simple_test_committee();
        perpetual.install_sui_committee(&committee).unwrap();
        assert_eq!(
            perpetual.highest_sui_committee_epoch().unwrap(),
            Some(committee.epoch)
        );

        // A configured genesis blob must NOT re-bootstrap.
        let cfg = minimal_config(Some(std::path::PathBuf::from("/unused/genesis.blob")));
        let plan = resolve_bootstrap_plan(&cfg, &perpetual).unwrap();
        assert!(
            matches!(plan, BootstrapPlan::Hydrated),
            "perpetual committee state must override the configured genesis"
        );
    }
}
