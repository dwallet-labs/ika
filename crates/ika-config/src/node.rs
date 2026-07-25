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
    /// Requires `consensus_config` and `root_seed_key_pair` to be set in NodeConfig.
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
                if config.root_seed_key_pair.is_none() {
                    return Err(anyhow!(
                        "Validator mode requires root_seed_key_pair to be set in NodeConfig"
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

    /// Validates the role-specific configuration and removes key material that
    /// the selected role must never use.
    ///
    /// Legacy non-validator configurations may still contain a validator
    /// root-seed path. Discard the descriptor without resolving it so no
    /// non-validator initialization path can open or derive values from that
    /// file.
    pub fn validate_and_prepare_config(&self, config: &mut NodeConfig) -> Result<()> {
        self.validate_config(config)?;
        // Resolve the on-chain ika identity before anything reads the
        // resolved id fields — `IkaRuntimes::new` keys its mock-crypto
        // refusal off `ika_system_object_id`, so resolution must precede
        // runtime construction, not just node start.
        config
            .sui_connector_config
            .resolve_ika_on_chain_identity()?;
        if !self.is_validator() {
            config.root_seed_key_pair = None;
        }
        Ok(())
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

/// Config-supplied ika on-chain identity (Move package + object IDs), for
/// chains with **no compiled-in identity** — localnet / private nets
/// (`Devnet`/`Custom`), where the IDs are freshly generated each genesis.
///
/// **UNSAFE for public chains.** On `Mainnet`/`Testnet` the identity is
/// compiled into the binary keyed off `sui_chain_identifier` (see
/// [`compiled_in_ika_identity`]) and a config carrying this override is
/// rejected at startup: an operator-level identity swap on a public chain
/// would redirect the node to different packages/objects than the network it
/// claims to join. The `unsafe_` prefix is the universal convention for
/// "this opt-out skips a safety property."
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct IkaIdentityOverride {
    /// The move package ID of ika (IKA) on sui.
    pub ika_package_id: ObjectID,
    /// The move package id of `ika_common` on sui.
    pub ika_common_package_id: ObjectID,
    /// The move package id of ika_dwallet_2pc_mpc on sui — the **original
    /// v1** (the upgrade is `ika_dwallet_2pc_mpc_package_id_v2`).
    pub ika_dwallet_2pc_mpc_package_id: ObjectID,
    /// The v2 upgrade of the dwallet package; omit on a chain where no
    /// upgrade has been published (fresh localnets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ika_dwallet_2pc_mpc_package_id_v2: Option<ObjectID>,
    /// The move package ID of `ika_system` on sui (the **current/latest**).
    pub ika_system_package_id: ObjectID,
    /// The object ID of the Ika system on sui.
    pub ika_system_object_id: ObjectID,
    /// The object id of ika_dwallet_coordinator on sui.
    pub ika_dwallet_coordinator_object_id: ObjectID,
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
//
// `deny_unknown_fields` closes the general form of the same trap: ANY
// misspelled key in this section (`falback-grpc-url`, `fallback-url`,
// `fallback_grpc_url`, ...) would otherwise be silently ignored, and since
// every field here is optional-or-defaulted, the config still deserializes —
// as a DIFFERENT transport plan than the operator wrote (mirrored-with-
// fallback silently becomes peer-only). Transport selection is a boot-time,
// operator-authored choice: fail the boot with a naming error instead.
#[serde(
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case",
    tag = "kind",
    deny_unknown_fields
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

/// The public Sui checkpoint stores for the well-known networks. They retain
/// the complete **end-of-epoch** checkpoint history (a root `epochs.json` plus
/// `{seq}.binpb.zst` blobs) needed for committee-chain proofs, even though they
/// don't promise retention of every ordinary checkpoint.
/// The public Sui checkpoint stores. Retention (verified empirically
/// 2026-07-24): **every end-of-epoch checkpoint since epoch 0 is retained**,
/// along with the root `epochs.json` enumeration — epoch 0's EOP checkpoint
/// (`9769.binpb.zst` on mainnet, `5543.binpb.zst` on testnet) still serves
/// HTTP 200. The ~30-day retention window applies to *ordinary* checkpoints
/// only (e.g. mainnet `1.binpb.zst` is 404). The OCS committee ratchet needs
/// exactly the EOP checkpoints, so these stores cover a full genesis→latest
/// bootstrap on both public chains.
pub const SUI_MAINNET_CHECKPOINT_ARCHIVE_URL: &str = "https://checkpoints.mainnet.sui.io";
pub const SUI_TESTNET_CHECKPOINT_ARCHIVE_URL: &str = "https://checkpoints.testnet.sui.io";

/// Resolve the end-of-epoch checkpoint archive the verified OCS connector
/// stack should use. An explicit `sui-checkpoint-archive` config always wins,
/// verbatim (URL and options untouched). With none configured, the known
/// public chains fall back to their public Sui checkpoint store; there is no
/// default to guess for `Devnet`/`Custom` (localnet), so those resolve to
/// `None`.
///
/// Trust is unaffected either way: the archive is an untrusted availability
/// source, and every checkpoint fetched from it is BLS-verified against the
/// genesis-rooted committee chain (see [`SuiCheckpointArchiveConfig`]).
pub fn resolve_sui_checkpoint_archive(
    chain_identifier: SuiChainIdentifier,
    configured: Option<&SuiCheckpointArchiveConfig>,
) -> Option<SuiCheckpointArchiveConfig> {
    if let Some(explicit) = configured {
        return Some(explicit.clone());
    }
    let url = match chain_identifier {
        SuiChainIdentifier::Mainnet => SUI_MAINNET_CHECKPOINT_ARCHIVE_URL,
        SuiChainIdentifier::Testnet => SUI_TESTNET_CHECKPOINT_ARCHIVE_URL,
        SuiChainIdentifier::Devnet | SuiChainIdentifier::Custom => return None,
    };
    Some(SuiCheckpointArchiveConfig {
        url: url.to_string(),
        options: vec![],
    })
}

/// The Sui read-transport a node boots, decided by [`select_sui_transport`]
/// purely from config shape + role — never from chain state, so a protocol
/// flag can't halt running validators en masse at an upgrade boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuiTransportPlan {
    /// Old-style config (no `sui-data-source`), any role: the deprecated
    /// JSON-RPC path — the 1.1.8 behavior the config shape used to select.
    /// A binary upgrade must not change a node's transport under an
    /// unchanged config (an endpoint that serves JSON-RPC need not serve
    /// Sui gRPC, and for a notifier that mismatch surfaces as a
    /// network-wide epoch-advance stall); moving to gRPC is an explicit
    /// config migration (`sui-data-source`). Also the only path serving
    /// `query_events`, which a validator needs for MPC event ingestion.
    /// Sui is sunsetting JSON-RPC.
    LegacyJsonRpc,
    /// `sui-state-mirrored` with no `fallback-grpc-url`: the node has no direct
    /// Sui uplink, so every read crosses the verified OCS relay.
    PeerOnlyRelay,
    /// A direct gRPC uplink: `sui-state-direct`, or `sui-state-mirrored` with a
    /// fallback.
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
            // Every role keeps the JSON-RPC path the same config selected on
            // 1.1.8: a binary upgrade must not silently change a node's
            // transport (`sui-rpc-url` endpoints are not guaranteed to serve
            // Sui gRPC — many managed providers don't — and for the notifier,
            // the sole submitter of checkpoints and advance_epoch, a soft
            // gRPC failure is a network-wide epoch-advance stall). Moving to
            // gRPC is an explicit migration: add `sui-data-source`. The
            // JSON-RPC backend serves every role's needs, as on 1.1.8:
            // `query_events` for validator MPC ingestion, quorum-driver
            // submission for the notifier.
            Ok(SuiTransportPlan::LegacyJsonRpc)
        }
        // New-style config (`sui-data-source` present): all Sui I/O over gRPC.
        Some(source) => {
            if mode.is_validator() && !has_anchor {
                return Err(
                    "`sui-data-source` is set but no Sui trust anchor is configured: a \
                     validator on the gRPC path has no MPC event source without one (no JSON-RPC \
                     `query_events`, and the verified BagEventPump requires the committee chain); \
                     configure sui_genesis"
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
    /// [`SuiCheckpointArchiveConfig`]. When unset, the verified OCS connector
    /// defaults to the public Sui checkpoint store on `mainnet`/`testnet`
    /// (see [`resolve_sui_checkpoint_archive`]); an explicit value here always
    /// wins.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sui_checkpoint_archive: Option<SuiCheckpointArchiveConfig>,
    /// The expected sui chain identifier connecting to.
    pub sui_chain_identifier: SuiChainIdentifier,
    /// ika's on-chain identity override — **only** for chains with no
    /// compiled-in identity (localnet / `Devnet` / `Custom`), where it is
    /// required. Rejected at startup on `Mainnet`/`Testnet`, where the
    /// identity is compiled into the binary keyed off `sui_chain_identifier`
    /// (see [`IkaIdentityOverride`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ika_unsafe_identity_override: Option<IkaIdentityOverride>,
    /// The resolved on-chain ids below are filled at startup by
    /// [`Self::resolve_ika_on_chain_identity`] — from the compiled-in
    /// identity on `Mainnet`/`Testnet`, from `ika_unsafe_identity_override`
    /// on `Devnet`/`Custom`. They are NOT part of the config-file surface
    /// (`serde(skip)`): a flat `ika-package-id:`-style key in the YAML is
    /// ignored.
    #[serde(skip, default = "unset_object_id")]
    pub ika_package_id: ObjectID,
    #[serde(skip, default = "unset_object_id")]
    pub ika_common_package_id: ObjectID,
    #[serde(skip, default = "unset_object_id")]
    pub ika_dwallet_2pc_mpc_package_id: ObjectID,
    #[serde(skip)]
    pub ika_dwallet_2pc_mpc_package_id_v2: Option<ObjectID>,
    #[serde(skip, default = "unset_object_id")]
    pub ika_system_package_id: ObjectID,
    #[serde(skip, default = "unset_object_id")]
    pub ika_system_object_id: ObjectID,
    #[serde(skip, default = "unset_object_id")]
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

    /// Pay the notifier's gas from its SUI **Address Balance** (SIP-58)
    /// instead of owned gas-coin objects. Submissions then carry no gas
    /// `ObjectRef` at all (`ValidDuring` expiration, empty gas payment), which
    /// removes the whole class of stale-gas-version wedges the coin path
    /// fights: the transaction is valid regardless of how far this node's
    /// fullnode view lags.
    ///
    /// Requirements before enabling:
    /// - The target Sui network must have address-balance gas payments
    ///   enabled (Sui protocol >= 108 on testnet, >= 124 on mainnet; always
    ///   on for localnets at max version).
    /// - The notifier address must hold its SUI in the ADDRESS BALANCE, not
    ///   (only) in coin objects — deposit via the Sui CLI/SDK balance
    ///   transfer. Each submission reserves the full gas budget from the
    ///   balance for the transaction's validity window.
    ///
    /// Default `false`: the gas-coin path remains the production default
    /// until this mode has been canaried on testnet.
    #[serde(default)]
    pub notifier_gas_from_address_balance: bool,

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

    /// Resolve the runtime ika on-chain identity (packages + objects), keyed
    /// off `sui_chain_identifier`:
    ///
    /// - `Mainnet`/`Testnet`: the identity is compiled into the binary
    ///   ([`compiled_in_ika_identity`]) and is the sole source; a config
    ///   carrying `ika_unsafe_identity_override` is rejected — the on-chain
    ///   identity of a public chain is not operator-overridable.
    /// - `Devnet`/`Custom` (localnet / private nets): no compiled-in identity
    ///   exists (the IDs are freshly generated each genesis), so
    ///   `ika_unsafe_identity_override` is required and is the sole source.
    ///
    /// Idempotent; must run before anything reads the resolved id fields
    /// (wired into [`NodeMode::validate_and_prepare_config`], so every
    /// binary entry point resolves before use).
    pub fn resolve_ika_on_chain_identity(&mut self) -> anyhow::Result<()> {
        match compiled_in_ika_identity(self.sui_chain_identifier) {
            Some(id) => {
                if self.ika_unsafe_identity_override.is_some() {
                    anyhow::bail!(
                        "sui_connector_config.ika-unsafe-identity-override is set, but chain \
                         {} has a compiled-in ika identity; overriding it on a public chain \
                         is not supported — remove the override (it is only for localnet / \
                         private nets)",
                        self.sui_chain_identifier
                    );
                }
                self.ika_package_id = id.ika_package_id;
                self.ika_common_package_id = id.ika_common_package_id;
                self.ika_dwallet_2pc_mpc_package_id = id.ika_dwallet_2pc_mpc_package_id;
                self.ika_dwallet_2pc_mpc_package_id_v2 = Some(id.ika_dwallet_2pc_mpc_package_id_v2);
                self.ika_system_package_id = id.ika_system_package_id;
                self.ika_system_object_id = id.ika_system_object_id;
                self.ika_dwallet_coordinator_object_id = id.ika_dwallet_coordinator_object_id;
            }
            None => {
                let Some(over) = self.ika_unsafe_identity_override else {
                    anyhow::bail!(
                        "chain {} has no compiled-in ika identity (its IDs are freshly \
                         generated each genesis); set \
                         sui_connector_config.ika-unsafe-identity-override with the chain's \
                         package/object ids",
                        self.sui_chain_identifier
                    );
                };
                for (name, value) in [
                    ("ika-package-id", over.ika_package_id),
                    ("ika-common-package-id", over.ika_common_package_id),
                    (
                        "ika-dwallet-2pc-mpc-package-id",
                        over.ika_dwallet_2pc_mpc_package_id,
                    ),
                    ("ika-system-package-id", over.ika_system_package_id),
                    ("ika-system-object-id", over.ika_system_object_id),
                    (
                        "ika-dwallet-coordinator-object-id",
                        over.ika_dwallet_coordinator_object_id,
                    ),
                ] {
                    if value == ObjectID::ZERO {
                        anyhow::bail!(
                            "sui_connector_config.ika-unsafe-identity-override.{name} is the \
                             ZERO object id, which is never a real package/object id"
                        );
                    }
                }
                self.ika_package_id = over.ika_package_id;
                self.ika_common_package_id = over.ika_common_package_id;
                self.ika_dwallet_2pc_mpc_package_id = over.ika_dwallet_2pc_mpc_package_id;
                // `None` (no upgrade published on this chain) is a supported
                // downstream value — preserve it rather than inventing one.
                self.ika_dwallet_2pc_mpc_package_id_v2 = over.ika_dwallet_2pc_mpc_package_id_v2;
                self.ika_system_package_id = over.ika_system_package_id;
                self.ika_system_object_id = over.ika_system_object_id;
                self.ika_dwallet_coordinator_object_id = over.ika_dwallet_coordinator_object_id;
            }
        }
        Ok(())
    }
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct NodeConfig {
    /// Validator-only seed for MPC key derivation. Non-validator processes
    /// accept this field for backward compatibility but discard it before
    /// initialization.
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
            sui_genesis: None,
            sui_checkpoint_archive: None,
            sui_chain_identifier: chain,
            ika_unsafe_identity_override: None,
            ika_package_id: ObjectID::ZERO,
            ika_common_package_id: ObjectID::ZERO,
            ika_dwallet_2pc_mpc_package_id: ObjectID::ZERO,
            ika_dwallet_2pc_mpc_package_id_v2: None,
            ika_system_package_id: ObjectID::ZERO,
            ika_system_object_id: ObjectID::ZERO,
            ika_dwallet_coordinator_object_id: ObjectID::ZERO,
            verified_cache_retention_checkpoints: None,
            notifier_client_key_pair: None,
            notifier_gas_from_address_balance: false,
            sui_ika_system_module_last_processed_event_id_override: None,
        }
    }

    fn config_for_mode(mode: NodeMode) -> NodeConfig {
        let mut sui_connector_config = config_for_chain(SuiChainIdentifier::Mainnet);
        if mode.is_notifier() {
            sui_connector_config.notifier_client_key_pair = Some(default_key_pair());
        }
        let consensus_config = mode.is_validator().then(|| ConsensusConfig {
            db_path: "consensus-db".into(),
            db_retention_epochs: None,
            db_pruner_period_secs: None,
            max_pending_transactions: None,
            max_submit_position: None,
            submit_delay_step_override_millis: None,
            parameters: None,
        });

        NodeConfig {
            root_seed_key_pair: mode
                .is_validator()
                .then(|| RootSeedWithPath::new(RootSeed::random_seed())),
            protocol_key_pair: default_authority_key_pair(),
            consensus_key_pair: default_key_pair(),
            account_key_pair: default_key_pair(),
            network_key_pair: default_key_pair(),
            db_path: "node-db".into(),
            network_address: default_grpc_address(),
            sui_connector_config,
            metrics_address: default_metrics_address(),
            admin_interface_port: default_admin_interface_port(),
            consensus_config,
            remove_deprecated_tables: false,
            p2p_config: P2pConfig::default(),
            end_of_epoch_broadcast_channel_capacity:
                default_end_of_epoch_broadcast_channel_capacity(),
            metrics: None,
            supported_protocol_versions: None,
            state_archive_write_config: StateArchiveConfig::default(),
            state_archive_read_config: vec![],
            authority_overload_config: AuthorityOverloadConfig::default(),
            run_with_range: None,
            authority_db_retention_epochs: None,
            authority_db_pruner_period_secs: None,
            max_mpc_computation_cores: None,
        }
    }

    fn unreadable_root_seed() -> RootSeedWithPath {
        serde_yaml::from_str("path: notifier-root-seed-must-not-be-read\n")
            .expect("a root-seed path descriptor must deserialize without reading the path")
    }

    #[test]
    fn notifier_config_without_root_seed_is_accepted() {
        let config = config_for_mode(NodeMode::Notifier);
        let yaml = serde_yaml::to_string(&config).expect("notifier config must serialize");
        assert!(!yaml.contains("root-seed-key-pair"));
        let mut parsed: NodeConfig =
            serde_yaml::from_str(&yaml).expect("notifier config without a root seed must parse");

        NodeMode::Notifier
            .validate_and_prepare_config(&mut parsed)
            .expect("notifier configuration must not require a validator root seed");
    }

    #[test]
    fn legacy_notifier_config_with_root_seed_still_parses() {
        let mut config = config_for_mode(NodeMode::Notifier);
        config.root_seed_key_pair = Some(unreadable_root_seed());
        let yaml = serde_yaml::to_string(&config).expect("legacy notifier config must serialize");

        let parsed: NodeConfig =
            serde_yaml::from_str(&yaml).expect("legacy notifier config must deserialize");
        assert!(parsed.root_seed_key_pair.is_some());
    }

    #[test]
    fn validator_config_without_root_seed_is_rejected() {
        let mut config = config_for_mode(NodeMode::Validator);
        config.root_seed_key_pair = None;

        let error = NodeMode::Validator
            .validate_and_prepare_config(&mut config)
            .expect_err("validator configuration must require a root seed");
        assert!(
            error.to_string().contains("root_seed_key_pair"),
            "unexpected validation error: {error}"
        );
    }

    #[test]
    fn notifier_preparation_discards_root_seed_without_reading_it() {
        let mut config = config_for_mode(NodeMode::Notifier);
        config.root_seed_key_pair = Some(unreadable_root_seed());

        NodeMode::Notifier
            .validate_and_prepare_config(&mut config)
            .expect("an unreadable legacy root-seed path must not affect notifier initialization");
        assert!(config.root_seed_key_pair.is_none());
    }

    #[test]
    fn fullnode_preparation_discards_root_seed_without_reading_it() {
        let mut config = config_for_mode(NodeMode::Fullnode);
        config.root_seed_key_pair = Some(unreadable_root_seed());

        NodeMode::Fullnode
            .validate_and_prepare_config(&mut config)
            .expect("an unreadable root-seed path must not affect fullnode initialization");
        assert!(config.root_seed_key_pair.is_none());
    }

    #[test]
    fn prepared_notifier_config_omits_root_seed_when_serialized() {
        let mut config = config_for_mode(NodeMode::Notifier);
        config.root_seed_key_pair = Some(unreadable_root_seed());
        NodeMode::Notifier
            .validate_and_prepare_config(&mut config)
            .unwrap();

        let yaml = serde_yaml::to_string(&config).unwrap();
        assert!(!yaml.contains("root-seed-key-pair"));
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

    fn test_identity_override() -> IkaIdentityOverride {
        fn oid(byte: u8) -> ObjectID {
            ObjectID::from_single_byte(byte)
        }
        IkaIdentityOverride {
            ika_package_id: oid(1),
            ika_common_package_id: oid(2),
            ika_dwallet_2pc_mpc_package_id: oid(3),
            ika_dwallet_2pc_mpc_package_id_v2: None,
            ika_system_package_id: oid(4),
            ika_system_object_id: oid(5),
            ika_dwallet_coordinator_object_id: oid(6),
        }
    }

    /// The on-chain identity of a public chain is not operator-overridable:
    /// a Mainnet/Testnet config carrying the unsafe override is rejected
    /// outright, never partially applied.
    #[test]
    fn identity_override_rejected_on_public_chains() {
        for chain in [SuiChainIdentifier::Mainnet, SuiChainIdentifier::Testnet] {
            let mut cfg = config_for_chain(chain);
            cfg.ika_unsafe_identity_override = Some(test_identity_override());
            let err = cfg.resolve_ika_on_chain_identity().unwrap_err();
            assert!(
                err.to_string()
                    .contains("overriding it on a public chain is not supported"),
                "{chain}: {err}"
            );
            assert_eq!(
                cfg.ika_package_id,
                ObjectID::ZERO,
                "{chain}: a rejected override must not partially resolve"
            );
        }
    }

    /// Localnet/private chains (`Devnet`/`Custom`) have no compiled-in
    /// identity: the unsafe override is required, and is the sole source of
    /// every resolved id (an absent `_v2` stays `None` — "no upgrade
    /// published" is a supported downstream value).
    #[test]
    fn identity_override_required_and_sole_source_on_private_chains() {
        for chain in [SuiChainIdentifier::Devnet, SuiChainIdentifier::Custom] {
            let mut cfg = config_for_chain(chain);
            let err = cfg.resolve_ika_on_chain_identity().unwrap_err();
            assert!(
                err.to_string().contains("ika-unsafe-identity-override"),
                "{chain}: {err}"
            );

            let over = test_identity_override();
            cfg.ika_unsafe_identity_override = Some(over);
            cfg.resolve_ika_on_chain_identity().unwrap();
            assert_eq!(cfg.ika_package_id, over.ika_package_id);
            assert_eq!(cfg.ika_common_package_id, over.ika_common_package_id);
            assert_eq!(
                cfg.ika_dwallet_2pc_mpc_package_id,
                over.ika_dwallet_2pc_mpc_package_id
            );
            assert_eq!(cfg.ika_dwallet_2pc_mpc_package_id_v2, None);
            assert_eq!(cfg.ika_system_package_id, over.ika_system_package_id);
            assert_eq!(cfg.ika_system_object_id, over.ika_system_object_id);
            assert_eq!(
                cfg.ika_dwallet_coordinator_object_id,
                over.ika_dwallet_coordinator_object_id
            );
        }
    }

    /// A ZERO id inside the override is a config mistake, not a real id —
    /// rejected rather than resolved into a node that queries object 0x0.
    #[test]
    fn identity_override_rejects_zero_ids() {
        let mut cfg = config_for_chain(SuiChainIdentifier::Custom);
        let mut over = test_identity_override();
        over.ika_system_object_id = ObjectID::ZERO;
        cfg.ika_unsafe_identity_override = Some(over);
        let err = cfg.resolve_ika_on_chain_identity().unwrap_err();
        assert!(
            err.to_string().contains("ika-system-object-id"),
            "the error must name the offending field: {err}"
        );
    }

    /// The resolved id fields are runtime outputs, not config inputs: a YAML
    /// carrying the old flat `ika-package-id`-style keys parses (serde
    /// ignores unknown fields) but the values are discarded — on a public
    /// chain resolution still yields the compiled-in identity.
    #[test]
    fn flat_id_keys_in_yaml_are_ignored() {
        let yaml = r#"
sui-data-source:
  kind: sui-state-direct
  url: "http://unused:9000"
  serve-mirror: false
sui-chain-identifier: mainnet
ika-package-id: "0x1111111111111111111111111111111111111111111111111111111111111111"
ika-system-object-id: "0x2222222222222222222222222222222222222222222222222222222222222222"
"#;
        let mut cfg: SuiConnectorConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            cfg.ika_package_id,
            ObjectID::ZERO,
            "flat keys must not deserialize into the resolved fields"
        );
        cfg.resolve_ika_on_chain_identity().unwrap();
        let id = compiled_in_ika_identity(SuiChainIdentifier::Mainnet).unwrap();
        assert_eq!(cfg.ika_package_id, id.ika_package_id);
        assert_eq!(cfg.ika_system_object_id, id.ika_system_object_id);
    }

    /// Round-trip: the override struct serializes under the
    /// `ika-unsafe-identity-override` key with kebab-case fields, and an
    /// absent `_v2` stays absent.
    #[test]
    fn identity_override_yaml_round_trip() {
        let mut cfg = config_for_chain(SuiChainIdentifier::Custom);
        cfg.ika_unsafe_identity_override = Some(test_identity_override());
        let yaml = serde_yaml::to_string(&cfg).unwrap();
        assert!(yaml.contains("ika-unsafe-identity-override"), "{yaml}");
        assert!(
            !yaml.contains("ika-dwallet-2pc-mpc-package-id-v2"),
            "absent v2 must not serialize: {yaml}"
        );
        let parsed: SuiConnectorConfig = serde_yaml::from_str(&yaml).unwrap();
        let over = parsed.ika_unsafe_identity_override.unwrap();
        assert_eq!(over.ika_package_id, test_identity_override().ika_package_id);
        assert_eq!(over.ika_dwallet_2pc_mpc_package_id_v2, None);
    }

    // ---- default end-of-epoch checkpoint archive resolution ----

    /// An explicit archive config wins verbatim on every chain — URL and
    /// options untouched, never merged with or replaced by the network default.
    #[test]
    fn explicit_archive_wins_on_every_chain() {
        let explicit = SuiCheckpointArchiveConfig {
            url: "s3://my-own-archive".to_string(),
            options: vec![("aws-region".to_string(), "us-west-2".to_string())],
        };
        for chain in [
            SuiChainIdentifier::Mainnet,
            SuiChainIdentifier::Testnet,
            SuiChainIdentifier::Devnet,
            SuiChainIdentifier::Custom,
        ] {
            let resolved = resolve_sui_checkpoint_archive(chain, Some(&explicit))
                .expect("explicit config must resolve");
            assert_eq!(resolved.url, explicit.url, "{chain}");
            assert_eq!(resolved.options, explicit.options, "{chain}");
        }
    }

    /// With no archive configured, the known public chains default to their
    /// public Sui checkpoint store.
    #[test]
    fn public_chains_default_to_public_checkpoint_store() {
        for (chain, url) in [
            (
                SuiChainIdentifier::Mainnet,
                SUI_MAINNET_CHECKPOINT_ARCHIVE_URL,
            ),
            (
                SuiChainIdentifier::Testnet,
                SUI_TESTNET_CHECKPOINT_ARCHIVE_URL,
            ),
        ] {
            let resolved =
                resolve_sui_checkpoint_archive(chain, None).expect("public chain must default");
            assert_eq!(resolved.url, url, "{chain}");
            assert!(resolved.options.is_empty(), "{chain}");
        }
    }

    /// No default is guessed for chains without a known public store.
    #[test]
    fn no_default_archive_for_devnet_or_custom() {
        for chain in [SuiChainIdentifier::Devnet, SuiChainIdentifier::Custom] {
            assert!(
                resolve_sui_checkpoint_archive(chain, None).is_none(),
                "{chain}: must not guess an archive"
            );
        }
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

    /// An old-style config (only `sui-rpc-url`, no anchor) keeps the
    /// deprecated JSON-RPC path for EVERY role — the transport a 1.1.8 node
    /// ran on that exact config. A binary upgrade must never flip transport
    /// under an unchanged config (the endpoint may not serve Sui gRPC, and a
    /// notifier failing softly on gRPC stalls epoch advance network-wide);
    /// gRPC requires explicitly configuring `sui-data-source`.
    #[test]
    fn old_style_keeps_legacy_json_rpc_for_every_role() {
        for mode in ALL_MODES {
            assert_eq!(
                select_sui_transport(None, true, false, mode),
                Ok(SuiTransportPlan::LegacyJsonRpc),
                "mode={mode}"
            );
        }
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
    /// - Fail-closed on unrecognized keys: a *snake_case* `fallback_grpc_url`
    ///   or a misspelled `falback-grpc-url` ERRORS the parse
    ///   (`deny_unknown_fields`) instead of being silently dropped — every
    ///   field in this section is optional-or-defaulted, so a dropped key
    ///   would otherwise boot a DIFFERENT transport plan than the operator
    ///   wrote (mirrored-with-fallback flipping to peer-only). Empirically
    ///   verified to work on this serde version despite the internally-tagged
    ///   enum (an earlier note here claimed otherwise).
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

        // Fail-closed on unrecognized keys (`deny_unknown_fields`): a
        // snake_case `fallback_grpc_url` — or any typo — must ERROR at parse
        // time, not silently deserialize with the field unset. Every field
        // in this section is optional-or-defaulted, so a silently-dropped
        // key wouldn't fail anything downstream either: the node would just
        // boot a DIFFERENT transport plan than the operator wrote
        // (mirrored-with-fallback flipping to peer-only).
        let snake = serde_yaml::from_str::<SuiDataSource>(
            "kind: sui-state-mirrored\nfallback_grpc_url: http://fallback:9000\n",
        );
        assert!(
            snake.is_err(),
            "a snake_case key must fail the parse (fail-closed), not be silently dropped"
        );
        let typo = serde_yaml::from_str::<SuiDataSource>(
            "kind: sui-state-mirrored\nfalback-grpc-url: http://fallback:9000\n",
        );
        assert!(
            typo.is_err(),
            "a misspelled key must fail the parse (fail-closed), not flip the node to peer-only"
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
