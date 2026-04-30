// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Solana Ed25519 signer backed by an Ika dWallet.
//!
//! Wraps a pre-provisioned ed25519 dWallet on the Ika network and exposes
//! `sign_message` returning a 64-byte Ed25519 signature. Intended to be
//! adapted into [`solana-keychain`](https://github.com/solana-foundation/solana-keychain)'s
//! `SolanaSigner` trait by a thin downstream crate.
//!
//! # API shape
//!
//! - [`IkaSigner::create`] takes a pre-built [`IkaSignerConfig`] (Sui RPC URL,
//!   keypair to pay Sui gas + IKA fees, dWallet ID, secret share source) and
//!   fetches the dWallet's metadata + Ed25519 public key once.
//! - [`IkaSigner::pubkey`] returns the 32-byte Ed25519 public key (Solana address).
//! - [`IkaSigner::sign_message`] runs the MPC sign flow against Sui and returns
//!   the 64-byte Ed25519 signature.
//! - [`IkaSigner::is_available`] does a lightweight check that the Sui RPC is
//!   reachable and the dWallet is in `Active` state.
//!
//! # Provisioning
//!
//! dWallet creation, key import, and presign provisioning are out of scope —
//! use the `ika` CLI or the TypeScript `IkaTransaction` API. This crate only
//! signs with an existing ed25519 dWallet.

mod config;
mod error;
mod flow;
mod pubkey;
mod signer;

pub use config::{IkaSignerConfig, PresignMode, SecretShareSource};
pub use error::IkaSignerError;
pub use signer::IkaSigner;
