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

use std::sync::Arc;

mod generated {
    include!(concat!(env!("OUT_DIR"), "/ika.ValidatorMetadata.rs"));
}

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
pub fn build_server<S: MpcDataBlobStorage, C: HandoffCertStorage>(
    storage: Arc<S>,
    relay: Arc<AnnouncementRelayHandle>,
    cert_storage: Arc<C>,
) -> ValidatorMetadataServer<Server<S, C>> {
    ValidatorMetadataServer::new(Server::new(storage, relay, cert_storage))
}
