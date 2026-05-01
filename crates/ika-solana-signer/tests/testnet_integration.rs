// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Live integration test against Sui testnet + Ika testnet.
//!
//! Skipped at runtime when `IKA_DWALLET_ID` is unset, so `cargo test --release`
//! stays green for contributors without a provisioned dWallet.
//!
//! Required env vars (mirrors the TS `@solana/keychain-ika` integration test
//! setup so the same provisioned dWallet works for both):
//!
//! - `SUI_RPC_URL` — Sui fullnode URL (testnet).
//! - `SUI_KEYPAIR` — Bech32 `suiprivkey1…` (output of `sui keytool export
//!   <addr> --json`). The address must own the dWallet cap and have IKA + SUI.
//! - `IKA_DWALLET_ID` — Active ed25519 dWallet object ID.
//! - `IKA_DWALLET_CAP_ID` — `DWalletCap` object ID owned by the keypair.
//! - `IKA_SECRET_SHARE_HEX` — Hex-encoded user secret share (raw bytes — same
//!   format `ika dwallet create --output-secret hex` emits).
//! - `IKA_IKA_COIN_ID` — IKA `Coin<IKA>` object ID owned by the keypair with
//!   enough balance to pay presign + sign fees.

use std::str::FromStr;

use fastcrypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use fastcrypto::traits::{ToFromBytes, VerifyingKey};
use ika_solana_signer::{IkaSigner, IkaSignerConfig, PresignMode, SecretShareSource};
use ika_types::messages_dwallet_mpc::IkaNetworkConfig;
use sui_types::base_types::ObjectID;
use sui_types::crypto::SuiKeyPair;

fn testnet_network_config() -> IkaNetworkConfig {
    // Verbatim from `deployed_contracts/testnet/address.yaml`. Hardcoded so the
    // test is self-contained and doesn't have to reach into the workspace
    // layout at runtime.
    IkaNetworkConfig::new(
        ObjectID::from_str("0x1f26bb2f711ff82dcda4d02c77d5123089cb7f8418751474b9fb744ce031526a")
            .unwrap(),
        ObjectID::from_str("0x96fc75633b6665cf84690587d1879858ff76f88c10c945e299f90bf4e0985eb0")
            .unwrap(),
        ObjectID::from_str("0xf02f5960c94fce1899a3795b5d11fd076bc70a8d0e20a2b19923d990ed490730")
            .unwrap(),
        Some(
            ObjectID::from_str("0x6573a6c13daf26a64eb8a37d3c7a4391b353031e223072ca45b1ff9366f59293")
                .unwrap(),
        ),
        ObjectID::from_str("0xae71e386fd4cff3a080001c4b74a9e485cd6a209fa98fb272ab922be68869148")
            .unwrap(),
        ObjectID::from_str("0x2172c6483ccd24930834e30102e33548b201d0607fb1fdc336ba3267d910dec6")
            .unwrap(),
        ObjectID::from_str("0x4d157b7415a298c56ec2cb1dcab449525fa74aec17ddba376a83a7600f2062fc")
            .unwrap(),
    )
}

fn env_or_skip(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => {
            eprintln!("[skip] env var {key} unset; skipping live testnet integration test");
            None
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signs_message_against_testnet() {
    // Gate on the dWallet ID being set so the test is skipped on machines
    // without a provisioned dWallet rather than failing.
    let Some(dwallet_id) = env_or_skip("IKA_DWALLET_ID") else {
        return;
    };
    let dwallet_id = ObjectID::from_str(&dwallet_id).expect("IKA_DWALLET_ID is not a valid ObjectID");

    let sui_rpc_url = std::env::var("SUI_RPC_URL").expect("SUI_RPC_URL required");
    let sui_keypair_bech32 = std::env::var("SUI_KEYPAIR").expect("SUI_KEYPAIR required");
    let dwallet_cap_id = ObjectID::from_str(
        &std::env::var("IKA_DWALLET_CAP_ID").expect("IKA_DWALLET_CAP_ID required"),
    )
    .expect("IKA_DWALLET_CAP_ID is not a valid ObjectID");
    let secret_share_hex =
        std::env::var("IKA_SECRET_SHARE_HEX").expect("IKA_SECRET_SHARE_HEX required");
    let ika_coin_id = ObjectID::from_str(
        &std::env::var("IKA_IKA_COIN_ID").expect("IKA_IKA_COIN_ID required"),
    )
    .expect("IKA_IKA_COIN_ID is not a valid ObjectID");

    let payer = SuiKeyPair::decode(&sui_keypair_bech32)
        .expect("SUI_KEYPAIR must be a Bech32 `suiprivkey1…` string");
    let secret_share = hex::decode(secret_share_hex.trim_start_matches("0x"))
        .expect("IKA_SECRET_SHARE_HEX is not valid hex");

    let cfg = IkaSignerConfig {
        sui_rpc_url,
        ika_network_config: testnet_network_config(),
        payer,
        dwallet_id,
        dwallet_cap_id,
        share_source: SecretShareSource::Bytes(secret_share),
        presign_mode: PresignMode::PerSignGlobal,
        ika_coin_id,
        sui_coin_id: None,
        gas_budget: 1_000_000_000,
        poll_timeout: None,
        poll_interval: None,
    };

    let signer = IkaSigner::create(cfg).await.expect("IkaSigner::create failed");
    assert!(signer.is_available().await, "is_available should be true for an Active dWallet");

    let pubkey_bytes = signer.pubkey();
    let pubkey = Ed25519PublicKey::from_bytes(&pubkey_bytes)
        .expect("dWallet pubkey is not a valid Ed25519 point");

    let message = b"hello from ika-solana-signer integration test";
    let signature_bytes = signer
        .sign_message(message)
        .await
        .expect("sign_message failed against testnet");

    let signature = Ed25519Signature::from_bytes(&signature_bytes)
        .expect("returned signature is not a valid Ed25519 signature");

    pubkey
        .verify(message, &signature)
        .expect("ed25519 signature did not verify under the dWallet pubkey");
}
