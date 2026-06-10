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
//!     │                    │   non-relayable methods)  │
//! ```
//!
//! A `sui-state-direct` validator also exposes a `SuiStateMirrorServer`
//! wrapping the same `LocalProofProvider`, so its local consumer and
//! remote `sui-state-mirrored` peers see the same view.

use std::sync::Arc;

use anemo::PeerId;
use ika_config::node::{
    SuiChainIdentifier, SuiConnectorConfig, SuiDataSource, compiled_in_trusted_anchor,
};
use ika_network::proof_provider::{
    LocalProofProvider, ProofCacheConfig, ProofProvider, ProofProviderMetrics,
};
use ika_network::sui_state_mirror::{
    self, Server as SuiStateMirrorImpl, SuiMirrorPeers, SuiMirrorProofProvider, SuiMirrorTransport,
    SuiStateMirrorServer,
};
use ika_sui_client::grpc::SuiGrpcClient;
use ika_sui_client::transport::SuiTransport;
use tracing::{info, warn};

use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
use crate::sui_connector::committee_store::{CommitteeBootstrap, CommitteeStore};
use crate::sui_connector::fallback_transport::FallbackTransport;
use crate::sui_connector::ocs_metrics::OcsMetrics;
use crate::sui_connector::ocs_verifier::{OcsError, OcsVerifyingClient};
use crate::sui_connector::push_handler::IkaPushHandler;
use crate::sui_connector::verified_reader::OcsVerifiedReader;
use crate::sui_connector::verified_state_cache::{SharedVerifiedStateCache, VerifiedStateCache};
use sui_types::digests::CheckpointDigest;

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
    /// Per-validator verified state cache. Both roles get one;
    /// the writer differs (direct: `IkaCheckpointPusher`; mirrored:
    /// `IkaPushHandler`). Step 1 only wires the direct-side writer.
    pub state_cache: SharedVerifiedStateCache,
    /// `Some` alongside `mirror_server`: the same push handler the server
    /// holds, so the caller can hand it the bound anemo network
    /// (`set_network`) for push-gap recovery once the network is up.
    pub push_handler: Option<Arc<IkaPushHandler>>,
    pub metrics: Arc<OcsMetrics>,
}

#[derive(thiserror::Error, Debug)]
pub enum SetupError {
    #[error("invalid Sui mirror peer id `{peer}`: {error}")]
    BadPeerId { peer: String, error: String },
    #[error("sui-state-mirrored configured but no anemo network handed in")]
    MirroredWithoutNetwork,
    #[error(
        "the Sui chain at the configured endpoint does not advertise \
         CheckpointArtifactsDigest (requires protocol v122+ with \
         include_checkpoint_artifacts_digest_in_summary enabled)"
    )]
    ArtifactsDigestUnsupported,
    #[error(
        "both `sui_trusted_anchor` and `sui_unsafe_genesis_committee` are set; \
         these are mutually exclusive"
    )]
    BothBootstrapsSet,
    #[error(
        "anchor digest mismatch: fetched summary at digest {fetched:?} but config pinned {pinned:?}"
    )]
    AnchorDigestMismatch {
        fetched: CheckpointDigest,
        pinned: CheckpointDigest,
    },
    #[error("anchor summary at digest {0:?} is not end-of-epoch (no end_of_epoch_data)")]
    AnchorNotEndOfEpoch(CheckpointDigest),
    #[error("transport: {0}")]
    Transport(String),
    #[error(transparent)]
    Ocs(#[from] OcsError),
    #[error(transparent)]
    Ika(#[from] ika_types::error::IkaError),
}

/// What the operator gave us for OCS bootstrap, post-disambiguation:
///
/// - `Hydrated`: perpetual tables already have committees; ignore the
///   anchor entirely (we've already verified past it).
/// - `Anchor(digest)`: fetch this digest's summary and bootstrap from
///   its `end_of_epoch_data`.
/// - `UnsafeGenesis(committee)`: install this committee[0] directly.
pub enum BootstrapPlan {
    Hydrated,
    Anchor(CheckpointDigest),
    UnsafeGenesis(sui_types::committee::Committee),
}

pub fn resolve_bootstrap_plan(
    cfg: &SuiConnectorConfig,
    chain: SuiChainIdentifier,
    perpetual: &AuthorityPerpetualTables,
) -> Result<BootstrapPlan, SetupError> {
    if let Some(head) = perpetual
        .highest_sui_committee_epoch()
        .map_err(SetupError::Ika)?
    {
        // Perpetual committee state always wins over a configured anchor:
        // the anchor is a first-boot seed, and configs carry it forever, so
        // re-reading it on every restart would re-anchor the node each time.
        // The flip side: an operator re-anchoring to recover from
        // ProofChainBroken must clear the OCS committee tables for the new
        // anchor to take effect — say so out loud instead of silently
        // ignoring their config change.
        if cfg.sui_trusted_anchor.is_some() || cfg.sui_unsafe_genesis_committee.is_some() {
            tracing::info!(
                perpetual_head_epoch = head,
                "OCS bootstrap: using the perpetual committee chain; the configured \
                 trust anchor is only read on first boot. To force a re-anchor \
                 (e.g. after ProofChainBroken), clear the node's OCS committee \
                 tables so the next boot re-seeds from the configured anchor."
            );
        }
        return Ok(BootstrapPlan::Hydrated);
    }
    let override_anchor = cfg.sui_trusted_anchor;
    let unsafe_genesis = cfg.sui_unsafe_genesis_committee.clone();
    if override_anchor.is_some() && unsafe_genesis.is_some() {
        return Err(SetupError::BothBootstrapsSet);
    }
    if let Some(digest) = override_anchor {
        return Ok(BootstrapPlan::Anchor(digest));
    }
    if let Some(committee) = unsafe_genesis {
        return Ok(BootstrapPlan::UnsafeGenesis(committee));
    }
    if let Some(digest) = compiled_in_trusted_anchor(chain) {
        return Ok(BootstrapPlan::Anchor(digest));
    }
    // Caller treats this as "no OCS configured; skip" only when the
    // node mode permits it. For validators we error in node startup.
    Ok(BootstrapPlan::Hydrated)
}

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
    let (raw_for_ratchet, proof_provider, mirror_capable, raw_for_pushing): (
        Arc<dyn SuiTransport>,
        Arc<dyn ProofProvider>,
        bool,
        Option<Arc<dyn SuiTransport>>,
    ) = match &cfg.sui_data_source {
        SuiDataSource::SuiStateDirect { url, .. } => {
            let grpc: Arc<dyn SuiTransport> = Arc::new(
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
            (grpc.clone(), provider, true, Some(grpc))
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

            let relay: Arc<dyn SuiTransport> = Arc::new(SuiMirrorTransport::new(peers));
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
            (raw, provider, false, None)
        }
    };

    // 2. Probe artifacts-digest support before doing anything else.
    probe_artifacts_digest(&raw_for_ratchet).await?;

    // 3. Resolve trust anchor → fetch + verify summary → committee
    //    store → ratchet client. The anchor digest is the trust gate;
    //    the fetched summary's digest must match exactly. If unset,
    //    the unsafe-genesis-committee path takes over (localnet only).
    let plan = resolve_bootstrap_plan(cfg, cfg.sui_chain_identifier, &perpetual)?;
    let bootstrap = match plan {
        BootstrapPlan::Hydrated => None,
        BootstrapPlan::Anchor(digest) => {
            let summary = raw_for_ratchet
                .get_checkpoint_summary_by_digest(digest)
                .await
                .map_err(|e| {
                    SetupError::Transport(format!("get_checkpoint_summary_by_digest: {e}"))
                })?;
            // The fetched summary's digest is the source of truth. The
            // upstream is untrusted; we only accept when the digest
            // matches the operator-pinned value byte-for-byte.
            let fetched_digest = sui_types::message_envelope::Message::digest(summary.data());
            if fetched_digest != digest {
                return Err(SetupError::AnchorDigestMismatch {
                    fetched: fetched_digest,
                    pinned: digest,
                });
            }
            if summary.data().end_of_epoch_data.is_none() {
                return Err(SetupError::AnchorNotEndOfEpoch(digest));
            }
            Some(CommitteeBootstrap::EndOfEpoch(summary))
        }
        BootstrapPlan::UnsafeGenesis(committee) => {
            warn!(
                epoch = committee.epoch,
                "USING `sui_unsafe_genesis_committee` — bypassing the digest-anchored \
                 trust model. This MUST NOT be used in production."
            );
            Some(CommitteeBootstrap::UnsafeGenesis(committee))
        }
    };
    let committees = Arc::new(CommitteeStore::open(perpetual.clone(), bootstrap)?);
    let ratchet = Arc::new(OcsVerifyingClient::new(
        raw_for_ratchet,
        committees.clone(),
        metrics.clone(),
        cfg.allow_unverified_committee_fallback,
    ));

    let state_cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());

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
    let reader = Arc::new(OcsVerifiedReader::new(
        proof_provider.clone(),
        committees.clone(),
        metrics.clone(),
        None,
        state_cache.clone(),
        cache_first_reads,
        staleness_bound,
    ));

    // Publish the head epoch we booted at so dashboards can correlate
    // when this node started ratcheting.
    let anchor_epoch = ratchet.committees().head_epoch();
    provider_metrics
        .anchor_info
        .with_label_values(&[&anchor_epoch.to_string()])
        .set(1);

    // 5. sui-state-direct relay server (Some iff configured to serve), with the push
    //    handler attached so peers can broadcast checkpoints to us.
    let (mirror_server, push_handler) = if mirror_capable
        && matches!(
            cfg.sui_data_source,
            SuiDataSource::SuiStateDirect {
                serve_mirror: true,
                ..
            }
        ) {
        let handler = Arc::new(IkaPushHandler::new(
            committees,
            ratchet.clone(),
            metrics.clone(),
            state_cache.clone(),
        ));
        let server = sui_state_mirror::make_server(
            ratchet.transport().clone(),
            proof_provider,
            Some(handler.clone()),
            Some(state_cache.clone()),
            provider_metrics.clone(),
        );
        (Some(server), Some(handler))
    } else {
        (None, None)
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
        push_handler,
        metrics,
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
