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
                .request_type("ika_types::checkpoint::CertifiedCheckpointMessage<ika_types::checkpoint::DWallet>")
                .response_type("()")
                .codec_path(codec_path)
                .build(),
        )
        .method(
            anemo_build::manual::Method::builder()
                .name("get_dwallet_checkpoint_message")
                .route_name("GetCheckpointMessage")
                .request_type("crate::state_sync::GetCheckpointMessageRequest")
                .response_type("Option<ika_types::checkpoint::CertifiedCheckpointMessage<ika_types::checkpoint::DWallet>>")
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
                .request_type("ika_types::checkpoint::CertifiedCheckpointMessage<ika_types::checkpoint::System>")
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
                    "Option<ika_types::checkpoint::CertifiedCheckpointMessage<ika_types::checkpoint::System>>",
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
    anemo_build::manual::Builder::new()
        .out_dir(out_dir)
        .compile(&[discovery, state_sync]);
}
