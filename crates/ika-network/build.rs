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
                .request_type("crate::validator_metadata::GetMpcDataBlobRequest")
                .response_type("Option<crate::validator_metadata::MpcDataBlob>")
                .codec_path(codec_path)
                .build(),
        )
        .method(
            anemo_build::manual::Method::builder()
                .name("submit_mpc_data_announcement")
                .route_name("SubmitMpcDataAnnouncement")
                .request_type("crate::validator_metadata::SubmitMpcDataAnnouncementRequest")
                .response_type("crate::validator_metadata::SubmitMpcDataAnnouncementResponse")
                .codec_path(codec_path)
                .build(),
        )
        .method(
            anemo_build::manual::Method::builder()
                .name("get_certified_handoff_attestation")
                .route_name("GetCertifiedHandoffAttestation")
                .request_type("crate::validator_metadata::GetCertifiedHandoffAttestationRequest")
                .response_type("Option<ika_types::handoff::CertifiedHandoffAttestation>")
                .codec_path(codec_path)
                .build(),
        )
        .build();

    anemo_build::manual::Builder::new()
        .out_dir(out_dir)
        .compile(&[discovery, state_sync, validator_metadata]);
}
