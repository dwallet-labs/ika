// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Bind-with-retry plumbing shared by the node's local HTTP servers — the
//! admin endpoint (`admin.rs`) and the Prometheus metrics endpoint
//! (`metrics.rs`).
//!
//! Both servers are spawned onto a runtime where a panic ends the process:
//! the release profile sets `panic = 'abort'`, and the node turns
//! `crash_on_panic` on by default. An `unwrap` on `TcpListener::bind`
//! therefore turns a transient `AddrInUse` — a port race on a shared CI
//! runner, or a restart racing its own port through `TIME_WAIT` — into node
//! death at boot, for a server that is not a correctness component.
//!
//! Retrying rides out the transient case; the bound on the retries means a
//! genuinely misconfigured duplicate port ends in a single loud give-up rather
//! than an unbounded background loop. Every attempt warns with the address, so
//! a misconfiguration is visible immediately either way.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::sleep;
use tracing::warn;

/// How long to wait between bind attempts.
pub(crate) const BIND_RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// How many times to attempt the bind before giving up on the server.
/// Together with the interval this keeps trying for ~2 minutes, comfortably
/// past the ~60s a socket spends in `TIME_WAIT` after a restart.
pub(crate) const BIND_ATTEMPTS: u32 = 25;

/// Bind a listener on `socket_address`, retrying `attempts` times at
/// `retry_interval`. `None` once the attempts are exhausted — never panics.
///
/// `server_name` only labels the log lines, so a give-up is attributable to
/// the right endpoint.
pub(crate) async fn bind_with_retry(
    server_name: &str,
    socket_address: SocketAddr,
    attempts: u32,
    retry_interval: Duration,
) -> Option<TcpListener> {
    for attempt in 1..=attempts {
        match TcpListener::bind(&socket_address).await {
            Ok(listener) => return Some(listener),
            Err(err) => warn!(
                server = server_name,
                address =% socket_address,
                attempt,
                attempts,
                error =? err,
                "failed to bind the server, retrying"
            ),
        }
        if attempt < attempts {
            sleep(retry_interval).await;
        }
    }
    None
}

/// Helpers shared by the bind-path tests in `admin.rs` and `metrics.rs`.
#[cfg(test)]
pub(crate) mod test_support {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::net::TcpListener;

    /// A listener squatting on an ephemeral port, plus that port's address.
    pub(crate) async fn squatted_port() -> (TcpListener, SocketAddr) {
        let squatter = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind a squatter on an ephemeral port");
        let address = squatter.local_addr().expect("squatter local address");
        (squatter, address)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::squatted_port;
    use super::*;
    use std::time::Instant;

    /// The retry budget is a bound, not a loop: a duplicate port that is
    /// never released ends in one give-up after the configured attempts.
    #[tokio::test]
    async fn the_bind_retry_is_bounded() {
        let (_squatter, address) = squatted_port().await;

        let started = Instant::now();
        assert!(
            bind_with_retry("test", address, 4, Duration::from_millis(50))
                .await
                .is_none()
        );
        // Four attempts are three sleeps; no sleep is wasted after the last.
        assert!(started.elapsed() >= Duration::from_millis(150));
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}
