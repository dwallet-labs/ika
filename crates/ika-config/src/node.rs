// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::Config;
use crate::object_storage_config::ObjectStoreConfig;
use crate::p2p::P2pConfig;
use anyhow::{Result, anyhow};
use consensus_config::Parameters as ConsensusParameters;
use ika_types::committee::EpochId;
use once_cell::sync::OnceCell;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use sui_types::base_types::{ObjectID, SuiAddress};

use dwallet_rng::RootSeed;
use ika_types::crypto::AuthorityPublicKeyBytes;
use ika_types::crypto::KeypairTraits;
use ika_types::crypto::NetworkKeyPair;
use ika_types::messages_dwallet_checkpoint::DWalletCheckpointSequenceNumber;
use ika_types::supported_protocol_versions::SupportedProtocolVersions;
pub use sui_config::node::KeyPairWithPath;
use sui_types::crypto::SuiKeyPair;

use ika_types::crypto::{
    AccountKeyPair, AuthorityKeyPair, EncodeDecodeBase64, get_key_pair_from_rng,
};
use sui_types::event::EventID;
use sui_types::multiaddr::Multiaddr;

/// The mode in which an Ika node operates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeMode {
    /// Validator mode: participates in consensus and MPC operations.
    /// Requires `consensus_config` to be set in NodeConfig.
    Validator,
    /// Fullnode mode: syncs state via P2P but doesn't participate in consensus.
    /// Requires `consensus_config` to be None and `notifier_client_key_pair` to be None.
    Fullnode,
    /// Notifier mode: submits certified checkpoints to Sui chain.
    /// Requires `notifier_client_key_pair` to be set in SuiConnectorConfig.
    Notifier,
}

impl NodeMode {
    /// Detects the node mode from the configuration.
    /// Returns the appropriate mode based on the config settings.
    pub fn detect_from_config(config: &NodeConfig) -> Self {
        if config.consensus_config().is_some() {
            NodeMode::Validator
        } else if config
            .sui_connector_config
            .notifier_client_key_pair
            .is_some()
        {
            NodeMode::Notifier
        } else {
            NodeMode::Fullnode
        }
    }

    /// Validates that the configuration matches the expected mode.
    /// Returns an error if the configuration is incompatible with the mode.
    pub fn validate_config(&self, config: &NodeConfig) -> Result<()> {
        match self {
            NodeMode::Validator => {
                if config.consensus_config().is_none() {
                    return Err(anyhow!(
                        "Validator mode requires consensus_config to be set in NodeConfig"
                    ));
                }
                if config
                    .sui_connector_config
                    .notifier_client_key_pair
                    .is_some()
                {
                    return Err(anyhow!(
                        "Validator mode should not have notifier_client_key_pair set"
                    ));
                }
                Ok(())
            }
            NodeMode::Fullnode => {
                if config.consensus_config().is_some() {
                    return Err(anyhow!(
                        "Fullnode mode requires consensus_config to be None. \
                         Use ika-validator binary for validator nodes."
                    ));
                }
                if config
                    .sui_connector_config
                    .notifier_client_key_pair
                    .is_some()
                {
                    return Err(anyhow!(
                        "Fullnode mode should not have notifier_client_key_pair set. \
                         Use ika-notifier binary for notifier nodes."
                    ));
                }
                Ok(())
            }
            NodeMode::Notifier => {
                if config.consensus_config().is_some() {
                    return Err(anyhow!(
                        "Notifier mode requires consensus_config to be None. \
                         Notifiers should not participate in consensus."
                    ));
                }
                if config
                    .sui_connector_config
                    .notifier_client_key_pair
                    .is_none()
                {
                    return Err(anyhow!(
                        "Notifier mode requires notifier_client_key_pair to be set in SuiConnectorConfig"
                    ));
                }
                Ok(())
            }
        }
    }

    /// Returns true if this mode participates in consensus.
    pub fn is_validator(&self) -> bool {
        matches!(self, NodeMode::Validator)
    }

    /// Returns true if this mode is a notifier.
    pub fn is_notifier(&self) -> bool {
        matches!(self, NodeMode::Notifier)
    }

    /// Returns true if this mode is a fullnode.
    pub fn is_fullnode(&self) -> bool {
        matches!(self, NodeMode::Fullnode)
    }

    /// Returns the uptime metric label for this mode.
    pub fn uptime_metric_label(&self) -> &'static str {
        match self {
            NodeMode::Validator => "validator",
            NodeMode::Fullnode => "fullnode",
            NodeMode::Notifier => "notifier",
        }
    }
}

impl fmt::Display for NodeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeMode::Validator => write!(f, "validator"),
            NodeMode::Fullnode => write!(f, "fullnode"),
            NodeMode::Notifier => write!(f, "notifier"),
        }
    }
}

pub fn get_testing_sui_fullnode_rpc_url() -> String {
    std::env::var("SUI_FULLNODE_RPC_URL")
        .unwrap_or_else(|_| LOCAL_DEFAULT_SUI_FULLNODE_RPC_URL.to_string())
}

pub fn get_testing_sui_faucet_url() -> String {
    std::env::var("SUI_FAUCET_URL").unwrap_or_else(|_| LOCAL_DEFAULT_SUI_FAUCET_URL.to_string())
}

pub const LOCAL_DEFAULT_SUI_FULLNODE_RPC_URL: &str = "http://127.0.0.1:9000";
pub const LOCAL_DEFAULT_SUI_FAUCET_URL: &str = "http://127.0.0.1:9123/gas";

#[serde_as]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub enum SuiChainIdentifier {
    Mainnet,
    Testnet,
    Devnet,
    Custom,
}

impl fmt::Display for SuiChainIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SuiChainIdentifier::Mainnet => write!(f, "Mainnet"),
            SuiChainIdentifier::Testnet => write!(f, "Testnet"),
            SuiChainIdentifier::Devnet => write!(f, "Devnet"),
            SuiChainIdentifier::Custom => write!(f, "Custom"),
        }
    }
}

/// ika's on-chain identity (Move package + object IDs) for a public chain.
/// Deployment constants: the object IDs are immutable, and the package IDs are
/// the exact values the node config expects — the dwallet base id is the
/// **original v1** with the upgrade in `_v2` (event filtering accepts both),
/// and the system id is the **current/latest**. Sourced from
/// `deployed_contracts/{mainnet,testnet}/address.yaml` (NOT `ika_sui_config.yaml`,
/// which flattens packages to their latest under the base name).
#[derive(Clone, Copy, Debug)]
pub struct IkaOnChainIdentity {
    pub ika_package_id: ObjectID,
    pub ika_common_package_id: ObjectID,
    pub ika_dwallet_2pc_mpc_package_id: ObjectID,
    pub ika_dwallet_2pc_mpc_package_id_v2: ObjectID,
    pub ika_system_package_id: ObjectID,
    pub ika_system_object_id: ObjectID,
    pub ika_dwallet_coordinator_object_id: ObjectID,
}

/// The binary's compiled-in ika on-chain identity for a public chain, keyed off
/// `sui_chain_identifier` (which the verified genesis blob authenticates).
/// `None` on `Devnet`/`Custom` (localnet), where the IDs are freshly generated
/// each genesis and must be supplied via config.
pub fn compiled_in_ika_identity(chain: SuiChainIdentifier) -> Option<IkaOnChainIdentity> {
    fn oid(literal: &str) -> ObjectID {
        ObjectID::from_hex_literal(literal).expect("compiled-in ika object id literal is valid")
    }
    match chain {
        SuiChainIdentifier::Mainnet => Some(IkaOnChainIdentity {
            ika_package_id: oid(
                "0x7262fb2f7a3a14c888c438a3cd9b912469a58cf60f367352c46584262e8299aa",
            ),
            ika_common_package_id: oid(
                "0x9e1e9f8e4e51ee2421a8e7c0c6ab3ef27c337025d15333461b72b1b813c44175",
            ),
            ika_dwallet_2pc_mpc_package_id: oid(
                "0xdd24c62739923fbf582f49ef190b4a007f981ca6eb209ca94f3a8eaf7c611317",
            ),
            ika_dwallet_2pc_mpc_package_id_v2: oid(
                "0x23b5bd96051923f800c3a2150aacdcdd8d39e1df2dce4dac69a00d2d8c7f7e77",
            ),
            ika_system_package_id: oid(
                "0xd69f947d7ee6f224dd0dd31ec3ec30c0dd0f713a1de55d564e8e98910c4f9553",
            ),
            ika_system_object_id: oid(
                "0x215de95d27454d102d6f82ff9c54d8071eb34d5706be85b5c73cbd8173013c80",
            ),
            ika_dwallet_coordinator_object_id: oid(
                "0x5ea59bce034008a006425df777da925633ef384ce25761657ea89e2a08ec75f3",
            ),
        }),
        SuiChainIdentifier::Testnet => Some(IkaOnChainIdentity {
            ika_package_id: oid(
                "0x1f26bb2f711ff82dcda4d02c77d5123089cb7f8418751474b9fb744ce031526a",
            ),
            ika_common_package_id: oid(
                "0x96fc75633b6665cf84690587d1879858ff76f88c10c945e299f90bf4e0985eb0",
            ),
            ika_dwallet_2pc_mpc_package_id: oid(
                "0xf02f5960c94fce1899a3795b5d11fd076bc70a8d0e20a2b19923d990ed490730",
            ),
            ika_dwallet_2pc_mpc_package_id_v2: oid(
                "0x6573a6c13daf26a64eb8a37d3c7a4391b353031e223072ca45b1ff9366f59293",
            ),
            ika_system_package_id: oid(
                "0xde05f49e5f1ee13ed06c1e243c0a8e8fe858e1d8689476fdb7009af8ddc3c38b",
            ),
            ika_system_object_id: oid(
                "0x2172c6483ccd24930834e30102e33548b201d0607fb1fdc336ba3267d910dec6",
            ),
            ika_dwallet_coordinator_object_id: oid(
                "0x4d157b7415a298c56ec2cb1dcab449525fa74aec17ddba376a83a7600f2062fc",
            ),
        }),
        SuiChainIdentifier::Devnet | SuiChainIdentifier::Custom => None,
    }
}

/// serde default for the on-chain id fields: a ZERO sentinel meaning "unset",
/// filled from [`compiled_in_ika_identity`] at startup (see
/// [`SuiConnectorConfig::resolve_ika_on_chain_identity`]). `0x0` is never a real
/// package/object id, so it is a safe "not provided" marker.
fn unset_object_id() -> ObjectID {
    ObjectID::ZERO
}

/// Where this validator gets Sui state from.
///
/// `SuiStateDirect` runs against a Sui fullnode reachable over gRPC, and
/// (by default) also exposes a [`SuiStateMirror`](../../../ika-network)
/// service to peers — making this validator a *source* of verified
/// Sui state for the cluster.
///
/// `SuiStateMirrored` reads Sui state through the mirror service of a
/// peer instead of connecting to Sui directly. Reads are still verified
/// end-to-end via OCS, so the relayer is untrusted; an optional
/// `fallback_grpc_url` supplies a direct uplink for the methods the mirror
/// doesn't serve — `get_transaction` (genuinely un-relayable: its
/// `ExecutedTransaction` return isn't `Deserialize`), `get_committee` /
/// `list_owned_gas_coins`, and transaction submission (which a peer-only
/// node relays, but a fallback-equipped node sends over its own uplink).
#[derive(Clone, Debug, Deserialize, Serialize)]
// `rename_all` covers the variant tags; `rename_all_fields` is required to also
// kebab-case the fields *inside* struct variants (e.g. `fallback-grpc-url`).
// Without it those fields stay snake_case while every other config key is
// kebab-case, so an operator writing `fallback-grpc-url` would have it silently
// dropped — flipping a mirrored validator into peer-only.
#[serde(
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case",
    tag = "kind"
)]
pub enum SuiDataSource {
    SuiStateDirect {
        /// gRPC URL of a Sui fullnode this validator can reach directly.
        url: String,
        /// If true, expose `SuiStateMirror` to Ika peers so other validators
        /// can read Sui state through us. Defaults to true.
        #[serde(default = "default_true")]
        serve_mirror: bool,
    },
    SuiStateMirrored {
        /// Optional Sui gRPC URL used as a fallback for transaction submission
        /// and `get_transaction`. Trust unaffected — OCS verifies regardless.
        #[serde(skip_serializing_if = "Option::is_none")]
        fallback_grpc_url: Option<String>,
    },
}

fn default_true() -> bool {
    true
}

/// A Sui checkpoint **archive** used as a verified fallback source of
/// end-of-epoch checkpoints (object store: `epochs.json` + `{seq}.binpb.zst`).
/// Everything fetched is BLS-verified against the committee chain, so the
/// archive is an untrusted availability source — never a trust source.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct SuiCheckpointArchiveConfig {
    /// Object-store URL: `https://`, `s3://`, `gs://`, or `file://`.
    pub url: String,
    /// Backend credentials/flags, e.g. `("aws-region", "us-west-2")` or
    /// `("no-sign-request", "true")`.
    #[serde(default)]
    pub options: Vec<(String, String)>,
}

/// The Sui read-transport a node boots, decided by [`select_sui_transport`]
/// purely from config shape + role — never from chain state, so a protocol
/// flag can't halt running validators en masse at an upgrade boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuiTransportPlan {
    /// Old-style config (no `sui-data-source`) on a validator: the deprecated
    /// JSON-RPC read path — the only one that serves `query_events`, which a
    /// validator needs for MPC event ingestion. Sui is sunsetting JSON-RPC.
    LegacyJsonRpc,
    /// `sui-state-mirrored` with no `fallback-grpc-url`: the node has no direct
    /// Sui uplink, so every read crosses the verified OCS relay.
    PeerOnlyRelay,
    /// A direct gRPC uplink: `sui-state-direct`, `sui-state-mirrored` with a
    /// fallback, or a notifier/fullnode on an old-style config (Sui fullnodes
    /// serve gRPC at the same endpoint as JSON-RPC).
    Grpc,
}

/// Decide the Sui read-transport from a node's config shape and role, rejecting
/// the invalid combinations. Pure so it can be exhaustively unit-tested; the
/// `ika-node` boot path executes the returned plan (build the client, stand up
/// the relay, …).
///
/// The choice keys off the SHAPE of the node's own config, never off chain
/// state — both read paths consume the same on-chain state, and transport must
/// stay node-local so a protocol flag can't halt running validators at an
/// upgrade boundary. Inputs:
/// - `data_source`: the `sui-data-source` section, if present (new-style).
/// - `sui_rpc_url_present`: whether the legacy `sui-rpc-url` field is set. Only
///   consulted on an old-style config; ignored (but loggable) once
///   `data_source` is present.
/// - `has_anchor`: whether a Sui trust anchor is configured (enables OCS).
/// - `mode`: the node's role. A validator runs MPC and needs a Sui event
///   source; a notifier submits transactions; a fullnode does neither.
pub fn select_sui_transport(
    data_source: Option<&SuiDataSource>,
    sui_rpc_url_present: bool,
    has_anchor: bool,
    mode: NodeMode,
) -> Result<SuiTransportPlan, String> {
    match data_source {
        // Old-style config (no `sui-data-source` section).
        None => {
            if !sui_rpc_url_present {
                // No endpoint at all — fail closed rather than guess.
                return Err(
                    "no Sui endpoint configured: set `sui-data-source` (gRPC; the \
                     supported path) — the legacy `sui-rpc-url` field alone selects the \
                     deprecated JSON-RPC path"
                        .to_string(),
                );
            }
            if has_anchor {
                return Err(
                    "a Sui trust anchor is configured but `sui-data-source` is not; the \
                     anchor-verified OCS path runs over gRPC — add a sui-data-source section"
                        .to_string(),
                );
            }
            // A validator reads MPC events over JSON-RPC `query_events` (gRPC
            // cannot serve them); notifiers/fullnodes run no event ingestion and
            // read gRPC at the same fullnode endpoint.
            Ok(if mode.is_validator() {
                SuiTransportPlan::LegacyJsonRpc
            } else {
                SuiTransportPlan::Grpc
            })
        }
        // New-style config (`sui-data-source` present): all Sui I/O over gRPC.
        Some(source) => {
            if mode.is_validator() && !has_anchor {
                return Err(
                    "`sui-data-source` is set but no Sui trust anchor is configured: a \
                     validator on the gRPC path has no MPC event source without one (no JSON-RPC \
                     `query_events`, and the verified BagEventPump requires the committee chain); \
                     configure sui_genesis (or sui_unsafe_genesis_committee on private nets)"
                        .to_string(),
                );
            }
            // A notifier is the only role that submits transactions. Peer-only
            // (`sui-state-mirrored` with no fallback) has no direct Sui uplink:
            // its relayed submission path returns *unverified* effects bytes, so
            // the design assumes notifiers never run peer-only. Enforce it here
            // rather than let a misconfigured notifier submit through that path.
            if mode.is_notifier()
                && matches!(
                    source,
                    SuiDataSource::SuiStateMirrored {
                        fallback_grpc_url: None
                    }
                )
            {
                return Err(
                    "a notifier is configured peer-only (`sui-state-mirrored` with no \
                     `fallback-grpc-url`), but a notifier submits transactions and a peer-only \
                     node has no direct Sui uplink — its relayed submission returns unverified \
                     effects; set `fallback-grpc-url`, or use `sui-state-direct`"
                        .to_string(),
                );
            }
            Ok(match source {
                SuiDataSource::SuiStateMirrored {
                    fallback_grpc_url: None,
                } => SuiTransportPlan::PeerOnlyRelay,
                _ => SuiTransportPlan::Grpc,
            })
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct SuiConnectorConfig {
    /// Legacy JSON-RPC url of a Sui fullnode (old-style configs). Ignored
    /// whenever [`SuiConnectorConfig::sui_data_source`] is present, and
    /// optional so a migrated config can DROP this field entirely. At least
    /// one of the two must be set; a config with neither has no Sui endpoint
    /// and is rejected at startup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sui_rpc_url: Option<String>,
    /// Source of Sui state and tx-submission for this node — the new-style
    /// gRPC config that replaces `sui_rpc_url`. Its PRESENCE is what selects
    /// the read path: a config without it is an old-style (pre-OCS) config,
    /// and a validator on one keeps the DEPRECATED legacy JSON-RPC path
    /// (Sui is sunsetting JSON-RPC — migrate by adding this section plus a
    /// trust anchor). When present, all Sui I/O runs over gRPC and a
    /// validator must also configure a trust anchor (its MPC event source on
    /// this path is the anchor-verified `BagEventPump`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sui_data_source: Option<SuiDataSource>,
    /// Optional pinned list of Ika peer ids that expose `SuiStateMirror`.
    /// If empty when reading over the mirror (`SuiDataSource::SuiStateMirrored`),
    /// the connector will try every connected peer (relying on those that
    /// don't implement the service to error fast).
    #[serde(default)]
    pub sui_state_mirror_peers: Vec<String>,
    /// Genesis bootstrap committee for chains that haven't reached
    /// their first end-of-epoch yet (brand-new localnets, fresh-init
    /// testnet). Used as `committee[0]`. `sui_genesis` takes priority over
    /// this when both are set.
    ///
    /// **UNSAFE for production.** Bypasses the genesis-blob trust root — the
    /// operator pins the committee directly, with no cross-check against the
    /// compiled-in chain identifier. Production deployments should always use
    /// `sui_genesis`. The `unsafe_` prefix is the universal convention for
    /// "this opt-out skips a safety property."
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sui_unsafe_genesis_committee: Option<sui_types::committee::Committee>,
    /// Path to a Sui **genesis blob** — the genesis-rooted OCS trust root. On
    /// boot the node loads this blob, recomputes its genesis checkpoint digest,
    /// verifies it against the compiled-in chain identifier for
    /// `sui_chain_identifier`, and bootstraps `committee[0]` from it (the OCS
    /// ratchet then walks the end-of-epoch chain forward). The trust root is
    /// the 32-byte compiled-in chain identifier; the blob is verified against
    /// it, never trusted wholesale.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sui_genesis: Option<PathBuf>,
    /// Optional Sui checkpoint archive used as a *verified fallback* source of
    /// end-of-epoch checkpoints when the upstream fullnode has pruned them (and
    /// for cold genesis bootstrap). Verified, never trusted — see
    /// [`SuiCheckpointArchiveConfig`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sui_checkpoint_archive: Option<SuiCheckpointArchiveConfig>,
    /// When the committee ratchet reaches an end-of-epoch checkpoint that the
    /// upstream has pruned, it cannot BLS-verify the `committee[E] →
    /// committee[E+1]` transition. If this is `true` it falls back to fetching
    /// `committee[E+1]` directly from the (untrusted) endpoint — trust degrades
    /// to "what the endpoint says." Default `false`: the ratchet instead returns
    /// `OcsError::ProofChainBroken` and the operator must re-anchor closer to
    /// the current epoch. Only enable on chains/operators that accept the
    /// degraded trust to preserve liveness from a stale anchor.
    #[serde(default)]
    pub allow_unverified_committee_fallback: bool,
    /// When the persisted OCS committee state cannot be deserialized on boot —
    /// typically after a Sui version upgrade changed its on-disk BCS layout —
    /// automatically wipe the committee tables and re-bootstrap the committee
    /// chain from the genesis blob (re-ratcheting forward to the current epoch)
    /// instead of failing to boot. Default `false`: rebuilding the trust chain
    /// is normally a deliberate operator action (clear the OCS committee tables,
    /// then restart so the next boot re-bootstraps from genesis). Requires a
    /// genesis blob (`sui_genesis`), or an unsafe-genesis committee on private
    /// nets, to be configured. The rebuildable verified-object cache always
    /// self-recovers regardless of this flag; only the committee trust chain is
    /// gated by it.
    #[serde(default)]
    pub auto_reanchor_on_format_change: bool,
    /// The expected sui chain identifier connecting to.
    pub sui_chain_identifier: SuiChainIdentifier,
    /// The move package ID of ika (IKA) on sui. Omit on mainnet/testnet to use
    /// the compiled-in default (see [`compiled_in_ika_identity`]); required on
    /// localnet/Custom.
    #[serde(default = "unset_object_id")]
    pub ika_package_id: ObjectID,
    /// The move package id of `ika_common` on sui.
    #[serde(default = "unset_object_id")]
    pub ika_common_package_id: ObjectID,
    /// The move package id of ika_dwallet_2pc_mpc on sui — the **original v1**
    /// (the upgrade is `ika_dwallet_2pc_mpc_package_id_v2`).
    #[serde(default = "unset_object_id")]
    pub ika_dwallet_2pc_mpc_package_id: ObjectID,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ika_dwallet_2pc_mpc_package_id_v2: Option<ObjectID>,
    /// The move package ID of `ika_system` on sui (the **current/latest**).
    #[serde(default = "unset_object_id")]
    pub ika_system_package_id: ObjectID,
    /// The object ID of the Ika system on sui.
    #[serde(default = "unset_object_id")]
    pub ika_system_object_id: ObjectID,
    /// The object id of ika_dwallet_coordinator on sui.
    #[serde(default = "unset_object_id")]
    pub ika_dwallet_coordinator_object_id: ObjectID,

    /// How many checkpoints of OCS-verified state the direct-node cache retains
    /// (the prune window for the perpetual `verified_object_cache`, and the
    /// depth a mirrored peer can bootstrap from this node). Snapshots more than
    /// this many checkpoints behind the head are dropped; never prunes below the
    /// oldest committee-verifiable checkpoint. Defaults to
    /// `DEFAULT_VERIFIED_CACHE_RETENTION_CHECKPOINTS` (~a few epochs) when unset;
    /// larger = deeper history served to peers and answerable after the fullnode
    /// prunes, at more DB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_cache_retention_checkpoints: Option<u64>,

    /// Only for sui connector notifiers, don't set `notifier_client_key_pair` otherwise.
    /// Path of the file where sui client key (any SuiKeyPair) is stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notifier_client_key_pair: Option<KeyPairWithPath>,

    /// Override the last processed EventID for sui module `ika_system`.
    /// When set, SuiSyncer will start from this cursor (exclusively) instead of the one in storage.
    /// If the cursor is not found in storage or override, the query will start from genesis.
    /// Key: sui module, Value: last processed EventID (tx_digest, event_seq).
    /// Note 1: This field should be rarely used. Only use it when you understand how to follow up.
    /// Note 2: the EventID needs to be valid, namely it must exist and matches the filter.
    /// Otherwise, it will miss one event because of fullnode Event query semantics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sui_ika_system_module_last_processed_event_id_override: Option<EventID>,
}

/// Checkpoints of OCS-verified state the direct-node cache retains by default
/// (~a few epochs): wide enough that idle Ika objects — the System / Coordinator
/// inner, modified only at epoch boundaries — stay covered, while bounding the
/// perpetual `verified_object_cache` and the in-memory map. Tune per chain.
pub const DEFAULT_VERIFIED_CACHE_RETENTION_CHECKPOINTS: u64 = 432_000;

impl SuiConnectorConfig {
    pub fn verified_cache_retention_checkpoints(&self) -> u64 {
        self.verified_cache_retention_checkpoints
            .unwrap_or(DEFAULT_VERIFIED_CACHE_RETENTION_CHECKPOINTS)
    }

    /// Fill any unset (ZERO) on-chain id field from the binary's compiled-in
    /// per-chain ika identity (keyed off `sui_chain_identifier`). A
    /// config-supplied (non-ZERO) value always wins, so every id is overridable
    /// per field. On localnet (`Custom`/`Devnet`) there is no compiled-in
    /// identity, so every id must be supplied explicitly; an id still ZERO after
    /// resolution is a hard error. Subsumes the old per-chain dwallet-`_v2`
    /// hardcode in `ika-node`.
    pub fn resolve_ika_on_chain_identity(&mut self) -> anyhow::Result<()> {
        if let Some(id) = compiled_in_ika_identity(self.sui_chain_identifier) {
            fn fill(field: &mut ObjectID, default: ObjectID) {
                if *field == ObjectID::ZERO {
                    *field = default;
                }
            }
            fill(&mut self.ika_package_id, id.ika_package_id);
            fill(&mut self.ika_common_package_id, id.ika_common_package_id);
            fill(
                &mut self.ika_dwallet_2pc_mpc_package_id,
                id.ika_dwallet_2pc_mpc_package_id,
            );
            fill(&mut self.ika_system_package_id, id.ika_system_package_id);
            fill(&mut self.ika_system_object_id, id.ika_system_object_id);
            fill(
                &mut self.ika_dwallet_coordinator_object_id,
                id.ika_dwallet_coordinator_object_id,
            );
            if self.ika_dwallet_2pc_mpc_package_id_v2.is_none() {
                self.ika_dwallet_2pc_mpc_package_id_v2 = Some(id.ika_dwallet_2pc_mpc_package_id_v2);
            }
        }
        for (name, value) in [
            ("ika_package_id", self.ika_package_id),
            ("ika_common_package_id", self.ika_common_package_id),
            (
                "ika_dwallet_2pc_mpc_package_id",
                self.ika_dwallet_2pc_mpc_package_id,
            ),
            ("ika_system_package_id", self.ika_system_package_id),
            ("ika_system_object_id", self.ika_system_object_id),
            (
                "ika_dwallet_coordinator_object_id",
                self.ika_dwallet_coordinator_object_id,
            ),
        ] {
            if value == ObjectID::ZERO {
                anyhow::bail!(
                    "sui_connector_config.{name} is unset and chain {} has no compiled-in \
                     default; set it explicitly (required on localnet / Custom)",
                    self.sui_chain_identifier
                );
            }
        }
        Ok(())
    }
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct NodeConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_seed_key_pair: Option<RootSeedWithPath>,
    #[serde(default = "default_authority_key_pair")]
    pub protocol_key_pair: AuthorityKeyPairWithPath,
    #[serde(default = "default_key_pair")]
    pub consensus_key_pair: KeyPairWithPath,
    #[serde(default = "default_key_pair")]
    pub account_key_pair: KeyPairWithPath,
    #[serde(default = "default_key_pair")]
    pub network_key_pair: KeyPairWithPath,

    pub db_path: PathBuf,

    #[serde(default = "default_grpc_address")]
    pub network_address: Multiaddr,

    pub sui_connector_config: SuiConnectorConfig,

    #[serde(default = "default_metrics_address")]
    pub metrics_address: SocketAddr,

    #[serde(default = "default_admin_interface_port")]
    pub admin_interface_port: u16,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub consensus_config: Option<ConsensusConfig>,

    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub remove_deprecated_tables: bool,

    #[serde(default)]
    pub p2p_config: P2pConfig,

    /// Size of the broadcast channel used for notifying other systems of end of epoch.
    ///
    /// If unspecified, this will default to `128`.
    #[serde(default = "default_end_of_epoch_broadcast_channel_capacity")]
    pub end_of_epoch_broadcast_channel_capacity: usize,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<MetricsConfig>,

    /// In a `ika-node` binary, this is set to SupportedProtocolVersions::SYSTEM_DEFAULT
    /// in ika-node/src/main.rs. It is present in the config so that it can be changed by tests in
    /// order to test protocol upgrades.
    #[serde(skip)]
    pub supported_protocol_versions: Option<SupportedProtocolVersions>,

    #[serde(default)]
    pub state_archive_write_config: StateArchiveConfig,

    #[serde(default)]
    pub state_archive_read_config: Vec<StateArchiveConfig>,
    #[serde(default = "default_authority_overload_config")]
    pub authority_overload_config: AuthorityOverloadConfig,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_with_range: Option<RunWithRange>,

    /// Retention window for per-epoch authority store directories
    /// (`<db-path>/live/store/epoch_<N>/`): the current epoch plus this
    /// many prior epochs are kept; older directories are deleted at each
    /// epoch transition and on a periodic tick. Defaults to
    /// `DEFAULT_AUTHORITY_DB_RETENTION_EPOCHS` when unset — without
    /// pruning these directories grow unbounded (everything a later epoch
    /// needs lives in the `perpetual/` sibling, which is never touched).
    /// Set a very large value to effectively retain everything.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_db_retention_epochs: Option<u64>,

    /// Period of the authority store pruner's periodic tick. Defaults to
    /// one hour when unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_db_pruner_period_secs: Option<u64>,

    /// Cap on the number of concurrent dwallet-MPC cryptographic computations
    /// (the orchestrator's core budget). `None` (default) uses the host core
    /// count. Set this low to bound a validator's CPU + peak memory when many
    /// validators are co-located on one machine — e.g. CI test clusters, where
    /// each unbounded validator's class-groups crypto otherwise starves the pod.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_mpc_computation_cores: Option<usize>,
}

/// Keep the current epoch plus this many prior per-epoch authority store
/// directories by default. Two prior epochs preserve a post-mortem window
/// while keeping disk usage bounded; the consensus store already prunes by
/// default (retention 0), so retention here is the conservative side of an
/// existing policy, not a new one.
pub const DEFAULT_AUTHORITY_DB_RETENTION_EPOCHS: u64 = 2;

fn default_grpc_address() -> Multiaddr {
    "/ip4/0.0.0.0/tcp/8080".parse().unwrap()
}
fn default_authority_key_pair() -> AuthorityKeyPairWithPath {
    AuthorityKeyPairWithPath::new(get_key_pair_from_rng::<AuthorityKeyPair, _>(&mut OsRng).1)
}

fn default_key_pair() -> KeyPairWithPath {
    KeyPairWithPath::new(
        get_key_pair_from_rng::<AccountKeyPair, _>(&mut OsRng)
            .1
            .into(),
    )
}

fn default_metrics_address() -> SocketAddr {
    use std::net::{IpAddr, Ipv4Addr};
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 9184)
}

pub fn default_admin_interface_port() -> u16 {
    1337
}

pub fn default_end_of_epoch_broadcast_channel_capacity() -> usize {
    128
}

impl Config for NodeConfig {}

impl NodeConfig {
    pub fn protocol_key_pair(&self) -> &AuthorityKeyPair {
        self.protocol_key_pair.authority_keypair()
    }

    pub fn consensus_key_pair(&self) -> &NetworkKeyPair {
        match self.consensus_key_pair.keypair() {
            SuiKeyPair::Ed25519(kp) => kp,
            other => {
                panic!("Invalid keypair type: {other:?}, only Ed25519 is allowed for worker key")
            }
        }
    }

    pub fn network_key_pair(&self) -> &NetworkKeyPair {
        match self.network_key_pair.keypair() {
            SuiKeyPair::Ed25519(kp) => kp,
            other => {
                panic!("Invalid keypair type: {other:?}, only Ed25519 is allowed for network key")
            }
        }
    }

    pub fn protocol_public_key(&self) -> AuthorityPublicKeyBytes {
        self.protocol_key_pair().public().into()
    }

    /// The node's own `AuthorityName` (committee identity): its BLS protocol
    /// public key.
    pub fn authority_name(&self) -> AuthorityPublicKeyBytes {
        self.protocol_public_key()
    }

    pub fn db_path(&self) -> PathBuf {
        self.db_path.join("live")
    }

    pub fn db_checkpoint_path(&self) -> PathBuf {
        self.db_path.join("db_checkpoints")
    }

    pub fn archive_path(&self) -> PathBuf {
        self.db_path.join("archive")
    }

    pub fn snapshot_path(&self) -> PathBuf {
        self.db_path.join("snapshot")
    }

    pub fn network_address(&self) -> &Multiaddr {
        &self.network_address
    }

    pub fn consensus_config(&self) -> Option<&ConsensusConfig> {
        self.consensus_config.as_ref()
    }

    pub fn authority_db_retention_epochs(&self) -> u64 {
        self.authority_db_retention_epochs
            .unwrap_or(DEFAULT_AUTHORITY_DB_RETENTION_EPOCHS)
    }

    pub fn authority_db_pruner_period(&self) -> Duration {
        self.authority_db_pruner_period_secs
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(3_600))
    }

    pub fn sui_address(&self) -> SuiAddress {
        (&self.account_key_pair.keypair().public()).into()
    }

    pub fn archive_reader_config(&self) -> Vec<ArchiveReaderConfig> {
        self.state_archive_read_config
            .iter()
            .flat_map(|config| {
                config
                    .object_store_config
                    .as_ref()
                    .map(|remote_store_config| ArchiveReaderConfig {
                        remote_store_config: remote_store_config.clone(),
                        download_concurrency: NonZeroUsize::new(config.concurrency)
                            .unwrap_or(NonZeroUsize::new(5).unwrap()),
                        use_for_pruning_watermark: config.use_for_pruning_watermark,
                    })
            })
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConsensusConfig {
    /// Base consensus DB path for all epochs.
    pub db_path: PathBuf,

    /// The number of epochs for which to retain the consensus DBs. Setting it to 0 will make a consensus DB getting
    /// dropped as soon as system is switched to a new epoch.
    pub db_retention_epochs: Option<u64>,

    /// Pruner will run on every epoch change, but it will also check periodically on every `db_pruner_period_secs`
    /// seconds to see if there are any epoch DBs to remove.
    pub db_pruner_period_secs: Option<u64>,

    /// Maximum number of pending transactions to submit to consensus, including those
    /// in submission wait.
    /// Default to 20_000 inflight limit, assuming 20_000 txn tps * 1 sec consensus latency.
    pub max_pending_transactions: Option<usize>,

    /// When defined caps the calculated submission position to the max_submit_position. Even if the
    /// is elected to submit from a higher position than this, it will "reset" to the max_submit_position.
    pub max_submit_position: Option<usize>,

    /// The submit delay step to consensus defined in milliseconds. When provided it will
    /// override the current back off logic otherwise the default backoff logic will be applied based
    /// on consensus latency estimates.
    pub submit_delay_step_override_millis: Option<u64>,

    pub parameters: Option<ConsensusParameters>,
}

impl ConsensusConfig {
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn max_pending_transactions(&self) -> usize {
        self.max_pending_transactions.unwrap_or(20_000)
    }

    pub fn submit_delay_step_override(&self) -> Option<Duration> {
        self.submit_delay_step_override_millis
            .map(Duration::from_millis)
    }

    pub fn db_retention_epochs(&self) -> u64 {
        self.db_retention_epochs.unwrap_or(0)
    }

    pub fn db_pruner_period(&self) -> Duration {
        // Default to 1 hour
        self.db_pruner_period_secs
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(3_600))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct MetricsConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_interval_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ArchiveReaderConfig {
    pub remote_store_config: ObjectStoreConfig,
    pub download_concurrency: NonZeroUsize,
    pub use_for_pruning_watermark: bool,
}

#[derive(Default, Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct StateArchiveConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_store_config: Option<ObjectStoreConfig>,
    pub concurrency: usize,
    pub use_for_pruning_watermark: bool,
}

/// Configuration for the threshold(s) at which we consider the system
/// to be overloaded. When one of the threshold is passed, the node may
/// stop processing new transactions and/or certificates until the congestion
/// resolves.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct AuthorityOverloadConfig {
    #[serde(default = "default_max_txn_age_in_queue")]
    pub max_txn_age_in_queue: Duration,

    // The interval of checking overload signal.
    #[serde(default = "default_overload_monitor_interval")]
    pub overload_monitor_interval: Duration,

    // The execution queueing latency when entering load shedding mode.
    #[serde(default = "default_execution_queue_latency_soft_limit")]
    pub execution_queue_latency_soft_limit: Duration,

    // The execution queueing latency when entering aggressive load shedding mode.
    #[serde(default = "default_execution_queue_latency_hard_limit")]
    pub execution_queue_latency_hard_limit: Duration,

    // The maximum percentage of transactions to shed in load shedding mode.
    #[serde(default = "default_max_load_shedding_percentage")]
    pub max_load_shedding_percentage: u32,

    // When in aggressive load shedding mode, the minimum percentage of
    // transactions to shed.
    #[serde(default = "default_min_load_shedding_percentage_above_hard_limit")]
    pub min_load_shedding_percentage_above_hard_limit: u32,

    // If transaction ready rate is below this rate, we consider the validator
    // is well under used, and will not enter load shedding mode.
    #[serde(default = "default_safe_transaction_ready_rate")]
    pub safe_transaction_ready_rate: u32,

    // When set to true, transaction signing may be rejected when the validator
    // is overloaded.
    #[serde(default = "default_check_system_overload_at_signing")]
    pub check_system_overload_at_signing: bool,

    // When set to true, transaction execution may be rejected when the validator
    // is overloaded.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub check_system_overload_at_execution: bool,

    // Reject a transaction if transaction manager queue length is above this threshold.
    // 100_000 = 10k TPS * 5s resident time in transaction manager (pending + executing) * 2.
    #[serde(default = "default_max_transaction_manager_queue_length")]
    pub max_transaction_manager_queue_length: usize,

    // Reject a transaction if the number of pending transactions depending on the object
    // is above the threshold.
    #[serde(default = "default_max_transaction_manager_per_object_queue_length")]
    pub max_transaction_manager_per_object_queue_length: usize,
}

fn default_max_txn_age_in_queue() -> Duration {
    Duration::from_millis(500)
}

fn default_overload_monitor_interval() -> Duration {
    Duration::from_secs(10)
}

fn default_execution_queue_latency_soft_limit() -> Duration {
    Duration::from_secs(1)
}

fn default_execution_queue_latency_hard_limit() -> Duration {
    Duration::from_secs(10)
}

fn default_max_load_shedding_percentage() -> u32 {
    95
}

fn default_min_load_shedding_percentage_above_hard_limit() -> u32 {
    50
}

fn default_safe_transaction_ready_rate() -> u32 {
    100
}

fn default_check_system_overload_at_signing() -> bool {
    true
}

fn default_max_transaction_manager_queue_length() -> usize {
    100_000
}

fn default_max_transaction_manager_per_object_queue_length() -> usize {
    20
}

impl Default for AuthorityOverloadConfig {
    fn default() -> Self {
        Self {
            max_txn_age_in_queue: default_max_txn_age_in_queue(),
            overload_monitor_interval: default_overload_monitor_interval(),
            execution_queue_latency_soft_limit: default_execution_queue_latency_soft_limit(),
            execution_queue_latency_hard_limit: default_execution_queue_latency_hard_limit(),
            max_load_shedding_percentage: default_max_load_shedding_percentage(),
            min_load_shedding_percentage_above_hard_limit:
                default_min_load_shedding_percentage_above_hard_limit(),
            safe_transaction_ready_rate: default_safe_transaction_ready_rate(),
            check_system_overload_at_signing: true,
            check_system_overload_at_execution: false,
            max_transaction_manager_queue_length: default_max_transaction_manager_queue_length(),
            max_transaction_manager_per_object_queue_length:
                default_max_transaction_manager_per_object_queue_length(),
        }
    }
}

fn default_authority_overload_config() -> AuthorityOverloadConfig {
    AuthorityOverloadConfig::default()
}

// RunWithRange is used to specify the ending epoch/checkpoint to process.
// this is intended for use with disaster recovery debugging and verification workflows, never in normal operations
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub enum RunWithRange {
    Epoch(EpochId),
    Checkpoint(DWalletCheckpointSequenceNumber),
}

impl RunWithRange {
    // is epoch_id > RunWithRange::Epoch
    pub fn is_epoch_gt(&self, epoch_id: EpochId) -> bool {
        matches!(self, RunWithRange::Epoch(e) if epoch_id > *e)
    }

    pub fn matches_checkpoint(&self, seq_num: DWalletCheckpointSequenceNumber) -> bool {
        matches!(self, RunWithRange::Checkpoint(seq) if *seq == seq_num)
    }
}

/// Wrapper struct for AuthorityKeyPair that can be deserialized from a file path.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct AuthorityKeyPairWithPath {
    #[serde(flatten)]
    location: AuthorityKeyPairLocation,

    #[serde(skip)]
    keypair: OnceCell<Arc<AuthorityKeyPair>>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Eq)]
#[serde_as]
#[serde(untagged)]
enum AuthorityKeyPairLocation {
    InPlace { value: Arc<AuthorityKeyPair> },
    File { path: PathBuf },
}

impl AuthorityKeyPairWithPath {
    pub fn new(kp: AuthorityKeyPair) -> Self {
        let cell: OnceCell<Arc<AuthorityKeyPair>> = OnceCell::new();
        let arc_kp = Arc::new(kp);
        // OK to unwrap panic because authority should not start without all keypairs loaded.
        cell.set(arc_kp.clone())
            .expect("Failed to set authority keypair");
        Self {
            location: AuthorityKeyPairLocation::InPlace { value: arc_kp },
            keypair: cell,
        }
    }

    pub fn new_from_path(path: PathBuf) -> Self {
        let cell: OnceCell<Arc<AuthorityKeyPair>> = OnceCell::new();
        // OK to unwrap panic because authority should not start without all keypairs loaded.
        cell.set(Arc::new(read_authority_keypair_from_file(&path)))
            .expect("Failed to set authority keypair");
        Self {
            location: AuthorityKeyPairLocation::File { path },
            keypair: cell,
        }
    }

    pub fn authority_keypair(&self) -> &AuthorityKeyPair {
        self.keypair
            .get_or_init(|| match &self.location {
                AuthorityKeyPairLocation::InPlace { value } => value.clone(),
                AuthorityKeyPairLocation::File { path } => {
                    // OK to unwrap panic because authority should not start without all keypairs loaded.
                    Arc::new(read_authority_keypair_from_file(path))
                }
            })
            .as_ref()
    }
}

/// Read from file as Base64 encoded `privkey` and return a AuthorityKeyPair.
pub fn read_authority_keypair_from_file(path: &PathBuf) -> AuthorityKeyPair {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("Invalid authority keypair file at path {:?}", &path));
    AuthorityKeyPair::decode_base64(contents.as_str().trim())
        .unwrap_or_else(|_| panic!("Invalid authority keypair file at path {:?}", &path))
}

/// Wrapper struct for RootSeed that can be deserialized from a file path.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct RootSeedWithPath {
    #[serde(flatten)]
    location: RootSeedLocation,

    #[serde(skip)]
    seed: OnceCell<RootSeed>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Eq)]
#[serde(untagged)]
enum RootSeedLocation {
    InPlace { value: RootSeed },
    File { path: PathBuf },
}

impl RootSeedWithPath {
    pub fn new(seed: RootSeed) -> Self {
        let cell: OnceCell<RootSeed> = OnceCell::new();
        // OK to unwrap panic because validator should not start without root seed loaded.
        cell.set(seed.clone()).expect("Failed to set root seed");
        Self {
            location: RootSeedLocation::InPlace { value: seed },
            seed: cell,
        }
    }

    pub fn new_from_path(path: PathBuf) -> Self {
        let cell: OnceCell<RootSeed> = OnceCell::new();
        // OK to unwrap panic because class_groups should not start without all keypairs loaded.
        cell.set(RootSeed::from_file(path.clone()).unwrap())
            .expect("Failed to set root seed");
        Self {
            location: RootSeedLocation::File { path },
            seed: cell,
        }
    }

    pub fn root_seed(&self) -> &RootSeed {
        self.seed.get_or_init(|| match &self.location {
            RootSeedLocation::InPlace { value } => value.clone(),
            RootSeedLocation::File { path } => {
                // OK to unwrap panic because validator
                // should not start without seed loaded.
                RootSeed::from_file(path.clone()).unwrap()
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direct() -> SuiDataSource {
        SuiDataSource::SuiStateDirect {
            url: "http://direct:9000".to_string(),
            serve_mirror: true,
        }
    }
    fn mirrored_with_fallback() -> SuiDataSource {
        SuiDataSource::SuiStateMirrored {
            fallback_grpc_url: Some("http://fallback:9000".to_string()),
        }
    }
    fn peer_only_source() -> SuiDataSource {
        SuiDataSource::SuiStateMirrored {
            fallback_grpc_url: None,
        }
    }

    const ALL_MODES: [NodeMode; 3] = [NodeMode::Validator, NodeMode::Fullnode, NodeMode::Notifier];

    // ---- compiled-in on-chain ika identity resolution ----

    fn config_for_chain(chain: SuiChainIdentifier) -> SuiConnectorConfig {
        SuiConnectorConfig {
            sui_rpc_url: None,
            sui_data_source: Some(direct()),
            sui_state_mirror_peers: vec![],
            sui_unsafe_genesis_committee: None,
            sui_genesis: None,
            sui_checkpoint_archive: None,
            allow_unverified_committee_fallback: false,
            auto_reanchor_on_format_change: false,
            sui_chain_identifier: chain,
            ika_package_id: ObjectID::ZERO,
            ika_common_package_id: ObjectID::ZERO,
            ika_dwallet_2pc_mpc_package_id: ObjectID::ZERO,
            ika_dwallet_2pc_mpc_package_id_v2: None,
            ika_system_package_id: ObjectID::ZERO,
            ika_system_object_id: ObjectID::ZERO,
            ika_dwallet_coordinator_object_id: ObjectID::ZERO,
            verified_cache_retention_checkpoints: None,
            notifier_client_key_pair: None,
            sui_ika_system_module_last_processed_event_id_override: None,
        }
    }

    #[test]
    fn resolves_compiled_in_ids_for_public_chains() {
        for chain in [SuiChainIdentifier::Mainnet, SuiChainIdentifier::Testnet] {
            let mut cfg = config_for_chain(chain);
            cfg.resolve_ika_on_chain_identity().unwrap();
            let id = compiled_in_ika_identity(chain).unwrap();
            assert_eq!(cfg.ika_package_id, id.ika_package_id);
            assert_eq!(cfg.ika_common_package_id, id.ika_common_package_id);
            assert_eq!(
                cfg.ika_dwallet_2pc_mpc_package_id,
                id.ika_dwallet_2pc_mpc_package_id
            );
            assert_eq!(
                cfg.ika_dwallet_2pc_mpc_package_id_v2,
                Some(id.ika_dwallet_2pc_mpc_package_id_v2)
            );
            assert_eq!(cfg.ika_system_package_id, id.ika_system_package_id);
            assert_eq!(cfg.ika_system_object_id, id.ika_system_object_id);
            assert_eq!(
                cfg.ika_dwallet_coordinator_object_id,
                id.ika_dwallet_coordinator_object_id
            );
            // The dwallet base id is v1 — distinct from the v2 upgrade.
            assert_ne!(
                cfg.ika_dwallet_2pc_mpc_package_id, id.ika_dwallet_2pc_mpc_package_id_v2,
                "{chain}: base id must be v1, not the v2 upgrade"
            );
        }
    }

    #[test]
    fn config_supplied_id_overrides_compiled_in() {
        let mut cfg = config_for_chain(SuiChainIdentifier::Mainnet);
        let custom = ObjectID::from_hex_literal("0x1234").unwrap();
        cfg.ika_system_object_id = custom;
        cfg.resolve_ika_on_chain_identity().unwrap();
        assert_eq!(cfg.ika_system_object_id, custom, "explicit value must win");
        // Other unset fields still get the compiled-in default.
        let id = compiled_in_ika_identity(SuiChainIdentifier::Mainnet).unwrap();
        assert_eq!(cfg.ika_package_id, id.ika_package_id);
    }

    #[test]
    fn localnet_custom_requires_explicit_ids() {
        let mut cfg = config_for_chain(SuiChainIdentifier::Custom);
        let err = cfg.resolve_ika_on_chain_identity().unwrap_err();
        assert!(err.to_string().contains("no compiled-in default"), "{err}");
    }

    #[test]
    fn v2_kept_when_config_supplies_it() {
        let mut cfg = config_for_chain(SuiChainIdentifier::Testnet);
        let custom_v2 = ObjectID::from_hex_literal("0xabcd").unwrap();
        cfg.ika_dwallet_2pc_mpc_package_id_v2 = Some(custom_v2);
        cfg.resolve_ika_on_chain_identity().unwrap();
        assert_eq!(
            cfg.ika_dwallet_2pc_mpc_package_id_v2,
            Some(custom_v2),
            "explicit v2 must win"
        );
    }

    // ---- old-style config (no `sui-data-source`) ----

    /// No endpoint at all is rejected before anything else — independent of
    /// anchor/role, the operator gets the "no Sui endpoint" error.
    #[test]
    fn no_endpoint_is_rejected() {
        for has_anchor in [false, true] {
            for mode in ALL_MODES {
                let err = select_sui_transport(None, false, has_anchor, mode).unwrap_err();
                assert!(
                    err.contains("no Sui endpoint configured"),
                    "anchor={has_anchor} mode={mode}: {err}"
                );
            }
        }
    }

    /// An old-style validator (only `sui-rpc-url`, no anchor) keeps the
    /// deprecated JSON-RPC path; a notifier/fullnode on the same config reads
    /// gRPC at that endpoint.
    #[test]
    fn old_style_routes_by_role() {
        assert_eq!(
            select_sui_transport(None, true, false, NodeMode::Validator),
            Ok(SuiTransportPlan::LegacyJsonRpc)
        );
        assert_eq!(
            select_sui_transport(None, true, false, NodeMode::Fullnode),
            Ok(SuiTransportPlan::Grpc)
        );
        assert_eq!(
            select_sui_transport(None, true, false, NodeMode::Notifier),
            Ok(SuiTransportPlan::Grpc)
        );
    }

    /// A trust anchor without a `sui-data-source` section is rejected (the
    /// anchor-verified OCS path runs over gRPC) — for every role.
    #[test]
    fn anchor_without_data_source_is_rejected() {
        for mode in ALL_MODES {
            let err = select_sui_transport(None, true, true, mode).unwrap_err();
            assert!(
                err.contains("trust anchor is configured but `sui-data-source` is not"),
                "mode={mode}: {err}"
            );
        }
    }

    // ---- new-style config (`sui-data-source` present) ----

    /// A validator on the gRPC path with no anchor has no MPC event source —
    /// rejected for every data-source variant.
    #[test]
    fn new_style_validator_without_anchor_is_rejected() {
        for source in [direct(), mirrored_with_fallback(), peer_only_source()] {
            let err =
                select_sui_transport(Some(&source), false, false, NodeMode::Validator).unwrap_err();
            assert!(
                err.contains("no Sui trust anchor is configured"),
                "{source:?}: {err}"
            );
        }
    }

    /// Direct and mirrored-with-fallback both use a direct gRPC uplink.
    #[test]
    fn direct_and_mirrored_with_fallback_use_grpc() {
        assert_eq!(
            select_sui_transport(Some(&direct()), false, true, NodeMode::Validator),
            Ok(SuiTransportPlan::Grpc)
        );
        assert_eq!(
            select_sui_transport(
                Some(&mirrored_with_fallback()),
                false,
                true,
                NodeMode::Validator
            ),
            Ok(SuiTransportPlan::Grpc)
        );
    }

    /// `sui-state-mirrored` with no fallback is the peer-only relay path for a
    /// validator or a fullnode (neither submits transactions).
    #[test]
    fn peer_only_uses_the_relay() {
        assert_eq!(
            select_sui_transport(Some(&peer_only_source()), false, true, NodeMode::Validator),
            Ok(SuiTransportPlan::PeerOnlyRelay)
        );
        assert_eq!(
            select_sui_transport(Some(&peer_only_source()), false, true, NodeMode::Fullnode),
            Ok(SuiTransportPlan::PeerOnlyRelay)
        );
    }

    /// A notifier submits transactions, which a peer-only node can't do safely
    /// (its relayed submission returns unverified effects) — so a notifier
    /// configured peer-only is rejected, while a notifier with a fallback (or
    /// direct) uplink is fine.
    #[test]
    fn a_notifier_configured_peer_only_is_rejected() {
        let err = select_sui_transport(Some(&peer_only_source()), false, true, NodeMode::Notifier)
            .unwrap_err();
        assert!(
            err.contains("notifier") && err.contains("peer-only"),
            "{err}"
        );
        assert_eq!(
            select_sui_transport(
                Some(&mirrored_with_fallback()),
                false,
                true,
                NodeMode::Notifier
            ),
            Ok(SuiTransportPlan::Grpc)
        );
        assert_eq!(
            select_sui_transport(Some(&direct()), false, true, NodeMode::Notifier),
            Ok(SuiTransportPlan::Grpc)
        );
    }

    /// A fullnode is exempt from the anchor requirement and routes purely on the
    /// data-source variant — including peer-only, which it may use (it never
    /// submits).
    #[test]
    fn a_fullnode_is_exempt_from_the_anchor_requirement() {
        assert_eq!(
            select_sui_transport(Some(&direct()), false, false, NodeMode::Fullnode),
            Ok(SuiTransportPlan::Grpc)
        );
        assert_eq!(
            select_sui_transport(Some(&peer_only_source()), false, false, NodeMode::Fullnode),
            Ok(SuiTransportPlan::PeerOnlyRelay)
        );
    }

    /// Once `sui-data-source` is present, the legacy `sui-rpc-url` field never
    /// changes the decision — the new-style section always wins, for every role.
    #[test]
    fn data_source_presence_ignores_the_legacy_rpc_url() {
        for source in [direct(), mirrored_with_fallback(), peer_only_source()] {
            for mode in ALL_MODES {
                assert_eq!(
                    select_sui_transport(Some(&source), true, true, mode),
                    select_sui_transport(Some(&source), false, true, mode),
                    "{source:?} mode={mode}: rpc-url presence must not matter"
                );
            }
        }
    }

    // ---- `SuiDataSource` serde shape (kebab-case wire format) ----

    /// The on-disk node config is YAML and every key is kebab-case. The
    /// `SuiDataSource` enum is internally tagged on `kind`, and
    /// `rename_all_fields = "kebab-case"` is what makes the *fields inside*
    /// struct variants kebab-case too. This test pins the whole wire contract:
    ///
    /// - `kind: sui-state-mirrored` + `fallback-grpc-url: ...` deserializes into
    ///   `SuiStateMirrored { fallback_grpc_url: Some(..) }`.
    /// - `kind: sui-state-direct` + `serve-mirror: false` deserializes into
    ///   `SuiStateDirect { serve_mirror: false }`.
    /// - Serializing back round-trips to the kebab-case keys (`kind`,
    ///   `fallback-grpc-url`, `serve-mirror`), not snake_case.
    /// - The silent-default risk: a *snake_case* `fallback_grpc_url` key is an
    ///   unknown field to the kebab-case-renamed variant, so it is dropped and
    ///   the field stays `None` — exactly the misconfig the `rename_all_fields`
    ///   comment in the production code warns about (a mirrored validator
    ///   silently flips to peer-only). `SuiDataSource` has no
    ///   `deny_unknown_fields`, and serde does not support it on internally
    ///   tagged enum variants, so the parse *succeeds* with the field unset
    ///   rather than erroring — this test documents that behavior.
    #[test]
    fn sui_data_source_deserializes_kebab_case_fields() {
        // sui-state-mirrored with a kebab-case fallback-grpc-url populates the field.
        let mirrored: SuiDataSource = serde_yaml::from_str(
            "kind: sui-state-mirrored\nfallback-grpc-url: http://fallback:9000\n",
        )
        .expect("kebab-case mirrored config must deserialize");
        assert!(
            matches!(
                &mirrored,
                SuiDataSource::SuiStateMirrored {
                    fallback_grpc_url: Some(url),
                } if url == "http://fallback:9000"
            ),
            "expected SuiStateMirrored with the fallback set, got {mirrored:?}"
        );

        // sui-state-direct with serve-mirror: false parses serve_mirror = false
        // (and the kebab-case `url` field).
        let direct_no_mirror: SuiDataSource = serde_yaml::from_str(
            "kind: sui-state-direct\nurl: http://direct:9000\nserve-mirror: false\n",
        )
        .expect("kebab-case direct config must deserialize");
        assert!(
            matches!(
                &direct_no_mirror,
                SuiDataSource::SuiStateDirect {
                    url,
                    serve_mirror: false,
                } if url == "http://direct:9000"
            ),
            "expected SuiStateDirect {{ serve_mirror: false }}, got {direct_no_mirror:?}"
        );

        // Serialize back: keys must be kebab-case, not snake_case.
        let mirrored_yaml =
            serde_yaml::to_string(&mirrored).expect("serialize mirrored back to yaml");
        assert!(
            mirrored_yaml.contains("kind: sui-state-mirrored"),
            "serialized tag must be kebab-case: {mirrored_yaml}"
        );
        assert!(
            mirrored_yaml.contains("fallback-grpc-url:"),
            "serialized field must round-trip to kebab-case: {mirrored_yaml}"
        );
        assert!(
            !mirrored_yaml.contains("fallback_grpc_url"),
            "serialized field must NOT be snake_case: {mirrored_yaml}"
        );

        let direct_yaml =
            serde_yaml::to_string(&direct_no_mirror).expect("serialize direct back to yaml");
        assert!(
            direct_yaml.contains("kind: sui-state-direct") && direct_yaml.contains("serve-mirror:"),
            "serialized direct must use kebab-case keys: {direct_yaml}"
        );
        assert!(
            !direct_yaml.contains("serve_mirror"),
            "serialized field must NOT be snake_case: {direct_yaml}"
        );

        // Full structural round-trip: re-parsing the serialized form yields the
        // same variant + field values.
        let mirrored_round: SuiDataSource =
            serde_yaml::from_str(&mirrored_yaml).expect("re-parse serialized mirrored");
        assert!(matches!(
            mirrored_round,
            SuiDataSource::SuiStateMirrored {
                fallback_grpc_url: Some(url),
            } if url == "http://fallback:9000"
        ));

        // Silent-default risk: a snake_case `fallback_grpc_url` key does NOT
        // populate the field. The variant's fields are kebab-case-renamed, so
        // `fallback_grpc_url` is an unrecognized key; with no
        // `deny_unknown_fields` (unsupported on internally tagged enums) the
        // parse succeeds and the field stays None — flipping a would-be
        // mirrored-with-fallback validator into peer-only.
        let snake: SuiDataSource = serde_yaml::from_str(
            "kind: sui-state-mirrored\nfallback_grpc_url: http://fallback:9000\n",
        )
        .expect("snake_case key is silently ignored, not an error");
        assert!(
            matches!(
                snake,
                SuiDataSource::SuiStateMirrored {
                    fallback_grpc_url: None,
                }
            ),
            "snake_case `fallback_grpc_url` must be dropped, leaving the field None \
             (documents the silent-default misconfig risk)"
        );
    }

    /// An old-style config (no `sui-data-source`) that nonetheless carries a Sui
    /// trust anchor is a misconfiguration: the anchor enables the OCS path, which
    /// runs over gRPC and therefore requires a `sui-data-source` section. With
    /// `sui-rpc-url` present (so we get past the no-endpoint check) and
    /// `has_anchor = true`, `select_sui_transport` rejects this for *every* role
    /// with a message that names the anchor-without-data-source mismatch.
    #[test]
    fn old_style_config_with_anchor_is_rejected_message() {
        for mode in ALL_MODES {
            let err = select_sui_transport(None, true, true, mode)
                .expect_err("anchor without sui-data-source must be rejected");
            assert!(
                err.contains("trust anchor is configured but `sui-data-source` is not"),
                "mode={mode}: error must flag the anchor-without-data-source misconfig, got: {err}"
            );
            assert!(
                err.contains("OCS"),
                "mode={mode}: error should mention the OCS path, got: {err}"
            );
        }
    }
}
