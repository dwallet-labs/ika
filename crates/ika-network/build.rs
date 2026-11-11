// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::{
    env,
    path::{Path, PathBuf},
};

type Result<T> = ::std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn main() -> Result<()> {
    let out_dir = if env::var("DUMP_GENERATED_GRPC").is_ok() {
        PathBuf::from("")
    } else {
        PathBuf::from(env::var("OUT_DIR")?)
    };

    build_anemo_services(&out_dir);

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=DUMP_GENERATED_GRPC");

    Ok(())
}

fn build_anemo_services(out_dir: &Path) {
    let codec_path = "mysten_network::codec::anemo::BcsSnappyCodec";

    let discovery = anemo_build::manual::Service::builder()
        .name("Discovery")
        .package("ika")
        .method(
            anemo_build::manual::Method::builder()
                .name("get_known_peers_v2")
                .route_name("GetKnownPeersV2")
                .request_type("()")
                .response_type("crate::discovery::GetKnownPeersResponseV2")
                .codec_path(codec_path)
                .build(),
        )
        .build();

    let state_sync = anemo_build::manual::Service::builder()
        .name("StateSync")
        .package("ika")
        .method(
            anemo_build::manual::Method::builder()
                .name("push_dwallet_checkpoint_message")
                .route_name("PushCheckpointMessage")
                .request_type("ika_types::messages_dwallet_checkpoint::CertifiedDWalletCheckpointMessage")
                .response_type("()")
                .codec_path(codec_path)
                .build(),
        )
        .method(
            anemo_build::manual::Method::builder()
                .name("get_dwallet_checkpoint_message")
                .route_name("GetCheckpointMessage")
                .request_type("crate::state_sync::GetCheckpointMessageRequest")
                .response_type("Option<ika_types::messages_dwallet_checkpoint::CertifiedDWalletCheckpointMessage>")
                .codec_path(codec_path)
                .build(),
        )
        .method(
            anemo_build::manual::Method::builder()
                .name("get_dwallet_checkpoint_availability")
                .route_name("GetDWalletCheckpointAvailability")
                .request_type("()")
                .response_type("crate::state_sync::GetDWalletCheckpointAvailabilityResponse")
                .codec_path(codec_path)
                .build(),
        )
        .method(
            anemo_build::manual::Method::builder()
                .name("get_chain_identifier")
                .route_name("GetChainIdentifier")
                .request_type("()")
                .response_type("crate::state_sync::GetChainIdentifierResponse")
                .codec_path(codec_path)
                .build(),
        )
        .method(
            anemo_build::manual::Method::builder()
                .name("push_system_checkpoint")
                .route_name("PushSystemCheckpoint")
                .request_type("ika_types::messages_system_checkpoints::CertifiedSystemCheckpointMessage")
                .response_type("()")
                .codec_path(codec_path)
                .build(),
        )
        .method(
            anemo_build::manual::Method::builder()
                .name("get_system_checkpoint")
                .route_name("GetSystemCheckpoint")
                .request_type("crate::state_sync::server::GetSystemCheckpointRequest")
                .response_type(
                    "Option<ika_types::messages_system_checkpoints::CertifiedSystemCheckpointMessage>",
                )
                .codec_path(codec_path)
                .build(),
        )
        .method(
            anemo_build::manual::Method::builder()
                .name("get_system_checkpoint_availability")
                .route_name("GetSystemCheckpointAvailability")
                .request_type("()")
                .response_type("crate::state_sync::server::GetSystemCheckpointAvailabilityResponse")
                .codec_path(codec_path)
                .build(),
        )
        .build();

    let validator_metadata = anemo_build::manual::Service::builder()
        .name("ValidatorMetadata")
        .package("ika")
        .method(
            anemo_build::manual::Method::builder()
                .name("get_mpc_data_blob")
                .route_name("GetMpcDataBlob")
                .request_type("crate::mpc_artifacts::GetMpcDataBlobRequest")
                .response_type("Option<crate::mpc_artifacts::MpcDataBlob>")
                .codec_path(codec_path)
                .build(),
        )
        .method(
            anemo_build::manual::Method::builder()
                .name("submit_mpc_data_announcement")
                .route_name("SubmitMpcDataAnnouncement")
                .request_type("crate::mpc_artifacts::SubmitMpcDataAnnouncementRequest")
                .response_type("crate::mpc_artifacts::SubmitMpcDataAnnouncementResponse")
                .codec_path(codec_path)
                .build(),
        )
        .method(
            anemo_build::manual::Method::builder()
                .name("get_certified_handoff_attestation")
                .route_name("GetCertifiedHandoffAttestation")
                .request_type("crate::mpc_artifacts::GetCertifiedHandoffAttestationRequest")
                .response_type("Option<ika_types::handoff::CertifiedHandoffAttestation>")
                .codec_path(codec_path)
                .build(),
        )
        .build();

    let sui_state_mirror = anemo_build::manual::Service::builder()
        .name("SuiStateMirror")
        .package("ika")
        .method(
            anemo_build::manual::Method::builder()
                .name("get_chain_identifier")
                .route_name("GetChainIdentifier")
                .request_type("()")
                .response_type("String")
                .codec_path(codec_path)
                .build(),
        )
        .method(
            anemo_build::manual::Method::builder()
                .name("get_current_epoch")
                .route_name("GetCurrentEpoch")
                .request_type("()")
                .response_type("u64")
                .codec_path(codec_path)
                .build(),
        )
        // NOTE: no `get_reference_gas_price` RPC. Gas price is only needed to
        // build transactions, which is notifier-gated to a direct uplink — no
        // read-only mirrored/peer-only node ever needs it, so the relay doesn't
        // serve it. (It lives on the `SuiWriter` trait for the direct writer
        // path; the mirror transport implements no writer surface at all.)
        .method(
            anemo_build::manual::Method::builder()
                .name("get_latest_checkpoint")
                .route_name("GetLatestCheckpoint")
                .request_type("()")
                .response_type("sui_types::messages_checkpoint::CertifiedCheckpointSummary")
                .codec_path(codec_path)
                .build(),
        )
        // Trust-anchor bootstrap. Mirrored validators with no
        // perpetual committee state need to fetch the operator-pinned
        // checkpoint summary by digest before the ratchet can run.
        .method(
            anemo_build::manual::Method::builder()
                .name("get_checkpoint_summary_by_digest")
                .route_name("GetCheckpointSummaryByDigest")
                .request_type("crate::sui_state_mirror::GetCheckpointSummaryByDigestRequest")
                .response_type("sui_types::messages_checkpoint::CertifiedCheckpointSummary")
                .codec_path(codec_path)
                .build(),
        )
        // Ratchet primitives. Used by the committee ratchet on sui-state-mirrored to
        // BLS-verify end-of-epoch transitions — these need full checkpoint
        // contents and a checkpoint→tx index, neither of which fits the
        // proof-based shape.
        .method(
            anemo_build::manual::Method::builder()
                .name("get_full_checkpoint")
                .route_name("GetFullCheckpoint")
                .request_type("crate::sui_state_mirror::GetFullCheckpointRequest")
                .response_type("sui_types::full_checkpoint_content::CheckpointData")
                .codec_path(codec_path)
                .build(),
        )
        // Changeset stream for mirrored-node currency: per checkpoint, the
        // committee-signed summary + its modified object-set (ids, not bodies).
        .method(
            anemo_build::manual::Method::builder()
                .name("changeset_page")
                .route_name("ChangesetPage")
                .request_type("crate::sui_state_mirror::ChangesetPageRequest")
                .response_type("crate::sui_state_mirror::ChangesetPageResponse")
                .codec_path(codec_path)
                .build(),
        )
        .method(
            anemo_build::manual::Method::builder()
                .name("last_checkpoint_of_epoch")
                .route_name("LastCheckpointOfEpoch")
                .request_type("crate::sui_state_mirror::LastCheckpointOfEpochRequest")
                .response_type("sui_types::messages_checkpoint::CheckpointSequenceNumber")
                .codec_path(codec_path)
                .build(),
        )
        // NOTE: no `get_transaction_checkpoint` RPC. It was only ever reached
        // by `get_events_by_tx_digest` (the notifier's removed tx-commit gate);
        // the committee ratchet uses `last_checkpoint_of_epoch` /
        // `get_current_epoch` / `get_full_checkpoint`, not this. It survives
        // as an inherent `SuiGrpcClient` method for *direct* proof building
        // (`LocalProofProvider` over the node's own gRPC), which never relays.
        // Verified-read surface (the hot path for consumers). Each response
        // carries the object, the BLS-signed summary at the checkpoint
        // where the object was last modified, and an OCSInclusionProof
        // against that summary's checkpoint_artifacts_digest.
        .method(
            anemo_build::manual::Method::builder()
                .name("verified_object")
                .route_name("VerifiedObject")
                .request_type("crate::sui_state_mirror::VerifiedObjectRequest")
                .response_type("crate::proof_provider::VerifiedObjectResponse")
                .codec_path(codec_path)
                .build(),
        )
        .method(
            anemo_build::manual::Method::builder()
                .name("batch_verified_objects")
                .route_name("BatchVerifiedObjects")
                .request_type("crate::sui_state_mirror::BatchVerifiedObjectsRequest")
                .response_type("crate::proof_provider::BatchVerifiedObjectsResponse")
                .codec_path(codec_path)
                .build(),
        )
        .method(
            anemo_build::manual::Method::builder()
                .name("verified_dynamic_fields_page")
                .route_name("VerifiedDynamicFieldsPage")
                .request_type("crate::proof_provider::VerifiedDynamicFieldsPageRequest")
                .response_type("crate::proof_provider::VerifiedDynamicFieldsPageResponse")
                .codec_path(codec_path)
                .build(),
        )
        // NOTE: no `submit_transaction` RPC. The relay serves verified READS
        // only — writes (ika checkpoint write-back) are notifier-gated and the
        // notifier always uses a direct uplink, so no node ever submits through
        // the relay. A submit-via-relay surface would only be an unverified-
        // effects + amplification-DoS hazard (see `SuiMirrorTransport::execute_transaction`).
        .build();

    anemo_build::manual::Builder::new()
        .out_dir(out_dir)
        .compile(&[discovery, state_sync, validator_metadata, sui_state_mirror]);
}
