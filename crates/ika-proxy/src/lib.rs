// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear
pub mod admin;
pub mod config;
pub mod consumer;
pub mod handlers;
pub mod histogram_relay;
pub mod metrics;
pub mod middleware;
pub mod peers;
pub mod prom_to_mimir;
pub mod remote_write;

/// var extracts environment variables at runtime with a default fallback value
/// if a default is not provided, the value is simply an empty string if not found
/// This function will return the provided default if env::var cannot find the key
/// or if the key is somehow malformed.
#[macro_export]
macro_rules! var {
    ($key:expr) => {
        match std::env::var($key) {
            Ok(val) => val,
            Err(_) => "".into(),
        }
    };
    ($key:expr, $default:expr) => {
        match std::env::var($key) {
            Ok(val) => val.parse::<_>().unwrap(),
            Err(_) => $default,
        }
    };
}
