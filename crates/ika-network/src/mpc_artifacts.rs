// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! P2P endpoints for MPC-related off-chain artifacts: validator
//! `mpc_data` blobs, joiner announcement relay, and per-epoch
//! handoff certs.
//!
//! Three orthogonal concerns share one Anemo service (still wire-
//! named `ValidatorMetadata` for backwards compatibility — see
//! `build.rs`). Inside this crate the public surface is broken up
//! by purpose into three submodules:
//! - [`blob_store`] for content-addressed `mpc_data` blobs.
//! - [`announcement_relay`] for joiner announcement forwarding.
//! - [`handoff_cert`] for per-epoch cert retrieval.
//!
//! The [`server::Server`] type implements the Anemo service and
//! routes each method to the relevant submodule's storage/handle.

use anemo::codegen::InboundRequestLayer;
use anemo_tower::inflight_limit;
use std::sync::Arc;

mod generated {
    include!(concat!(env!("OUT_DIR"), "/ika.ValidatorMetadata.rs"));
}

/// Bound on an outbound `ValidatorMetadata` RPC.
///
/// Every call in this module is issued with one. Two of them —
/// the handoff-certificate fetch and the blob fetch — are awaited inside the
/// deliberately unbounded prepare-then-start barrier a validator crosses when
/// entering an epoch, so a peer that accepts the stream and never answers
/// would otherwise hold the validator out of the epoch indefinitely. anemo
/// applies no default request timeout and ika configures none.
pub const ARTIFACT_RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Bound on a blob fetch specifically, which moves real data rather than a
/// small message: the blob cache is sized in hundreds of megabytes, so a
/// single MPC-data blob can be tens of MB and 30s would systematically fail
/// the slowest-but-honest peers on an inter-region link. Callers fall through
/// to the next peer on timeout, so a generous bound costs a retry at worst.
pub const BLOB_RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

pub mod announcement_relay;
pub mod blob_store;
pub mod handoff_cert;
mod server;

pub use generated::{
    validator_metadata_client::ValidatorMetadataClient,
    validator_metadata_server::{ValidatorMetadata, ValidatorMetadataServer},
};
pub use server::Server;

pub use announcement_relay::{
    AnnouncementRelay, AnnouncementRelayHandle, SubmitMpcDataAnnouncementRequest,
    SubmitMpcDataAnnouncementResponse, submit_announcement_to_committee,
    submit_announcement_to_peer,
};
pub use blob_store::{
    GetMpcDataBlobRequest, InMemoryBlobStore, MpcDataBlob, MpcDataBlobStorage, fetch_blob,
    mpc_data_blob_hash,
};
pub use handoff_cert::{
    GetCertifiedHandoffAttestationRequest, HandoffCertStorage, fetch_certified_handoff_attestation,
};

/// Build a `ValidatorMetadataServer` backed by `storage`, an
/// announcement-relay handle, and a certified-handoff store. The
/// relay handle starts empty; the node installs a relay impl into
/// it once per-epoch state is up. The cert store is wired directly
/// to perpetual storage at construction time.
/// Concurrent `GetMpcDataBlob` reads. A blob is multi-megabyte MPC data
/// served out of storage, so this is the heaviest of the three — calibrated
/// alongside `sui_state_mirror`'s heaviest read (`changeset_page`, 16).
const INFLIGHT_GET_BLOB: usize = 16;

/// Concurrent `SubmitMpcDataAnnouncement` relays. The handler holds while the
/// announcement is sequenced through consensus rather than returning
/// immediately, so a held slot is expensive in wall-clock, not just memory.
const INFLIGHT_SUBMIT_ANNOUNCEMENT: usize = 16;

/// Concurrent `GetCertifiedHandoffAttestation` reads — a single certificate,
/// cheap, matching `sui_state_mirror`'s checkpoint-read tier.
const INFLIGHT_GET_HANDOFF_CERT: usize = 64;

pub fn build_server<S: MpcDataBlobStorage, C: HandoffCertStorage>(
    storage: Arc<S>,
    relay: Arc<AnnouncementRelayHandle>,
    cert_storage: Arc<C>,
) -> ValidatorMetadataServer<Server<S, C>> {
    // Every served RPC gets an inflight ceiling. This service had none at all,
    // so any host able to open an anemo connection could hold unlimited
    // concurrent multi-megabyte blob reads, or unlimited relay calls that each
    // occupy the handler until consensus sequences them. The sibling
    // `SuiStateMirror` service in this crate caps all ten of its methods; this
    // one capped none. (`add_layer_for_*` is generic over its own request
    // type, so the layers are built inline rather than via a shared helper.)
    macro_rules! inflight {
        ($n:expr) => {
            InboundRequestLayer::new(inflight_limit::InflightLimitLayer::new(
                $n,
                inflight_limit::WaitMode::ReturnError,
            ))
        };
    }
    ValidatorMetadataServer::new(Server::new(storage, relay, cert_storage))
        .add_layer_for_get_mpc_data_blob(inflight!(INFLIGHT_GET_BLOB))
        .add_layer_for_submit_mpc_data_announcement(inflight!(INFLIGHT_SUBMIT_ANNOUNCEMENT))
        .add_layer_for_get_certified_handoff_attestation(inflight!(INFLIGHT_GET_HANDOFF_CERT))
}
