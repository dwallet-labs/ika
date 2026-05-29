// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Joiner announcement relay: joining validators (not yet in the
//! consensus committee) submit their signed
//! `ValidatorMpcDataAnnouncement` to a current-committee peer
//! over this RPC; the peer verifies it and forwards to consensus.

use anemo::{Network, PeerId};
use arc_swap::ArcSwapOption;
use ika_types::validator_metadata::SignedValidatorMpcDataAnnouncement;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::ValidatorMetadataClient;

/// Wrapped by a joining validator (not yet in the consensus committee)
/// to ask a current-committee peer to relay their `mpc_data`
/// announcement into consensus. The peer verifies the joiner's
/// Ed25519 consensus-key signature against the installed
/// `JoinerPubkeyProvider` (next-epoch committee consensus pubkeys)
/// before relaying.
///
/// The joiner pushes its `mpc_data` blob bytes alongside the signed
/// announcement: the joiner is not in the current committee's peer
/// set, so a relayer can't dial back to fetch the blob, and no other
/// current-committee peer holds it either. Pushing it here lets the
/// relayer cache + serve the bytes (the rest of the committee then
/// resolves them via the existing content-addressed P2P fetch). The
/// relayer verifies the bytes hash to `announcement.announcement.blob_hash`
/// before trusting them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitMpcDataAnnouncementRequest {
    pub announcement: SignedValidatorMpcDataAnnouncement,
    pub blob: Vec<u8>,
}

/// Result of a relay attempt. `Accepted` means the relayer queued the
/// announcement for consensus submission; it does NOT guarantee
/// inclusion. `Rejected { reason }` means the relayer is unwilling
/// (e.g. no epoch store yet, signature didn't verify, etc.).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SubmitMpcDataAnnouncementResponse {
    Accepted,
    Rejected { reason: String },
}

/// Wraps the consensus-submission side of the relay. Implemented by
/// the node once the per-epoch store + consensus adapter are up;
/// before that, the server holds `None` and rejects requests.
///
/// Implementations are responsible for:
/// - verifying the joiner's Ed25519 consensus-key signature against
///   the installed `JoinerPubkeyProvider` (next-epoch committee
///   consensus pubkeys) — the relay is joiner-only; current-committee
///   validators submit their own announcements directly via consensus,
/// - bouncing duplicates by the latest-by-timestamp rule,
/// - submitting the resulting `ConsensusTransaction` via the adapter.
#[async_trait::async_trait]
pub trait AnnouncementRelay: Send + Sync + 'static {
    async fn relay(
        &self,
        announcement: SignedValidatorMpcDataAnnouncement,
        blob: Vec<u8>,
    ) -> Result<(), String>;
}

/// Late-bindable holder for the announcement relay. The Anemo server
/// is constructed at node startup, well before the first epoch store
/// exists; the node installs a relay impl once the epoch state is up
/// and re-installs across epoch transitions.
#[derive(Default)]
pub struct AnnouncementRelayHandle {
    inner: ArcSwapOption<Box<dyn AnnouncementRelay>>,
}

impl AnnouncementRelayHandle {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn install(&self, relay: Box<dyn AnnouncementRelay>) {
        self.inner.store(Some(Arc::new(relay)));
    }

    pub fn clear(&self) {
        self.inner.store(None);
    }

    pub fn is_installed(&self) -> bool {
        self.inner.load().is_some()
    }

    pub(crate) fn current(&self) -> Option<Arc<Box<dyn AnnouncementRelay>>> {
        self.inner.load_full()
    }
}

/// Ask `peer` to relay `announcement` into consensus on behalf of
/// the signer. Used by a joining validator that isn't yet a member of
/// the consensus committee: it fans this RPC out to every current-
/// committee peer it can reach, and one honest relayer is enough.
pub async fn submit_announcement_to_peer(
    network: &Network,
    peer_id: PeerId,
    announcement: SignedValidatorMpcDataAnnouncement,
    blob: Vec<u8>,
) -> anyhow::Result<SubmitMpcDataAnnouncementResponse> {
    let peer = network
        .peer(peer_id)
        .ok_or_else(|| anyhow::anyhow!("peer not connected: {peer_id}"))?;
    let mut client = ValidatorMetadataClient::new(peer);
    let response = client
        .submit_mpc_data_announcement(SubmitMpcDataAnnouncementRequest { announcement, blob })
        .await
        .map_err(|status| anyhow::anyhow!("submit_mpc_data_announcement failed: {status:?}"))?;
    Ok(response.into_inner())
}

/// Fan out a single announcement to every supplied peer concurrently.
/// Returns the per-peer outcomes for telemetry; the joiner can stop
/// once it sees enough `Accepted`s. We never block reconfig on this
/// — the joiner is best-effort and current-committee validators
/// don't need every relay attempt to succeed.
pub async fn submit_announcement_to_committee(
    network: &Network,
    peers: &[PeerId],
    announcement: SignedValidatorMpcDataAnnouncement,
    blob: Vec<u8>,
) -> Vec<(PeerId, anyhow::Result<SubmitMpcDataAnnouncementResponse>)> {
    let futures = peers.iter().map(|peer_id| {
        let peer_id = *peer_id;
        let announcement = announcement.clone();
        let blob = blob.clone();
        async move {
            let result = submit_announcement_to_peer(network, peer_id, announcement, blob).await;
            (peer_id, result)
        }
    });
    futures::future::join_all(futures).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn relay_handle_starts_empty_then_installs_and_clears() {
        let handle = AnnouncementRelayHandle::new();
        assert!(!handle.is_installed());
        assert!(handle.current().is_none());

        struct StubRelay;
        #[async_trait::async_trait]
        impl AnnouncementRelay for StubRelay {
            async fn relay(
                &self,
                _: SignedValidatorMpcDataAnnouncement,
                _: Vec<u8>,
            ) -> Result<(), String> {
                Ok(())
            }
        }

        handle.install(Box::new(StubRelay));
        assert!(handle.is_installed());
        assert!(handle.current().is_some());

        handle.clear();
        assert!(!handle.is_installed());
        assert!(handle.current().is_none());
    }

    #[test]
    fn relay_handle_install_drops_previous_relay() {
        // Re-installing replaces the previously-installed relay.
        // This is used at every epoch boundary to re-bind the
        // relay to the freshly-built epoch store. We verify by
        // observing that the first relay's Drop runs as soon as
        // the second one is installed.
        struct DropCounter(Arc<AtomicU32>);
        #[async_trait::async_trait]
        impl AnnouncementRelay for DropCounter {
            async fn relay(
                &self,
                _: SignedValidatorMpcDataAnnouncement,
                _: Vec<u8>,
            ) -> Result<(), String> {
                Ok(())
            }
        }
        impl Drop for DropCounter {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let first_drops = Arc::new(AtomicU32::new(0));
        let second_drops = Arc::new(AtomicU32::new(0));
        let handle = AnnouncementRelayHandle::new();

        handle.install(Box::new(DropCounter(first_drops.clone())));
        assert_eq!(first_drops.load(Ordering::SeqCst), 0);

        handle.install(Box::new(DropCounter(second_drops.clone())));
        assert_eq!(
            first_drops.load(Ordering::SeqCst),
            1,
            "first relay dropped on swap"
        );
        assert_eq!(second_drops.load(Ordering::SeqCst), 0);

        handle.clear();
        assert_eq!(
            second_drops.load(Ordering::SeqCst),
            1,
            "second relay dropped on clear"
        );
    }
}
