// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Read-side helpers for driving a dWallet sign flow against Sui.
//!
//! These were lifted out of the `ika` CLI so embedded signers (e.g.
//! `ika-solana-signer`) can reuse them without depending on `WalletContext`.
//! Each function takes a `sui_sdk::SuiClient` directly.

pub mod coin;
pub mod common;
pub mod encryption;
pub mod metadata;
pub mod network_key;
pub mod presign;
pub mod sign_session;
pub mod tx;

pub use coin::find_ika_coin;
pub use common::{
    extract_bytes_from_json, extract_event_field, extract_nested_event_field, fetch_object_fields,
    fetch_tx_events, hex_decode,
};
pub use encryption::{derive_encryption_keys, fetch_encrypted_share_for_dwallet};
pub use metadata::{DWalletMetadata, fetch_dwallet_metadata};
pub use network_key::{NetworkKeyInfo, get_network_key_info, get_network_key_info_for};
pub use presign::{fetch_presign_output, is_presign_cap_verified};
pub use sign_session::{SignSessionResult, find_sign_session_id, poll_sign_session};
