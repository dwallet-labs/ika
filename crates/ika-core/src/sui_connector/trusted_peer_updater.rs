// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Long-lived task that keeps a node's p2p `known_peers` populated from the
//! union of the on-chain {active, next-epoch, previous} committees AND the
//! `pending_active_set` — refreshed every few seconds so the volatile pending /
//! next-epoch sets stay current MID-epoch, not only at the boundary.
//!
//! Why pending + mid-epoch: a freshly-registered validator (a joiner) lands in
//! `pending_active_set` before it is active and before it can read anything over
//! the OCS relay. With that set in `known_peers`, the existing DIRECT validators
//! DIAL it; that inbound connection is what lets a peer-only joiner boot — its
//! `wait_for_mirror_peers` gate is satisfied by an inbound dial (a pinned peer
//! connecting, or in automatic mode a dialing peer that answers the
//! SuiStateMirror probe), with no fallback uplink and no static seed peers.
//! The read rides the node's own `SuiConnector` (direct gRPC on a direct node,
//! the OCS verified relay on a peer-only node), so there is no parallel reader.
//!
//! The set is pushed via `TrustedPeerChangeEvent`, which the discovery service
//! MERGEs into `known_peers` (it never prunes), so this coexists with the
//! existing startup/reconfiguration pushes.

use anemo::PeerId;
use anemo::types::{PeerAffinity, PeerInfo};
use ika_network::discovery::TrustedPeerChangeEvent;
use ika_sui_client::SuiConnectorClient;
use ika_types::crypto::AuthorityName;
use ika_types::sui::SystemInner;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;
use sui_types::base_types::ObjectID;
use tokio::sync::watch;
use tracing::{debug, warn};

/// How often to re-read the validator set + pending set. Real-time enough that a
/// fresh joiner is dialed within a few seconds of registering.
const REFRESH_INTERVAL: Duration = Duration::from_secs(3);

/// Continuously feed the p2p trusted-peer set from the {active, next, previous}
/// committee + `pending_active_set`. Runs for the node's lifetime; returns when
/// the discovery receiver is dropped (node shutdown).
pub async fn refresh_trusted_peers_loop(
    sui_client: Arc<SuiConnectorClient>,
    sender: watch::Sender<TrustedPeerChangeEvent>,
    self_authority: AuthorityName,
) {
    let mut last_sent: BTreeMap<PeerId, PeerInfo> = BTreeMap::new();
    let mut consecutive_failures: u64 = 0;
    loop {
        tokio::time::sleep(REFRESH_INTERVAL).await;
        match refresh_once(&sui_client, self_authority).await {
            Ok(peers) => {
                if consecutive_failures > 0 {
                    debug!(consecutive_failures, "trusted-peer refresh recovered");
                    consecutive_failures = 0;
                }
                if peers != last_sent {
                    let new_peers = peers.values().cloned().collect();
                    // Receiver dropped => the node is shutting down; stop.
                    if sender.send(TrustedPeerChangeEvent { new_peers }).is_err() {
                        return;
                    }
                    last_sent = peers;
                }
            }
            Err(e) => {
                // Keep the last good set (the watch channel still holds it, so
                // known_peers is unaffected) and retry. Throttle the warn so an
                // RPC outage doesn't repeat the same line every tick.
                if consecutive_failures.is_multiple_of(20) {
                    warn!(error = %e, consecutive_failures, "trusted-peer refresh failed; keeping last set");
                } else {
                    debug!(error = %e, "trusted-peer refresh failed");
                }
                consecutive_failures += 1;
            }
        }
    }
}

/// One refresh: read the system, union the validator-ids across the four sets,
/// resolve each to a `PeerInfo`, and return the set deduped by `PeerId` (with
/// self excluded). Each `StakingPool` is self-describing (its verified
/// `validator_info` yields the name + network key + address), so no id↔pool
/// alignment is needed.
async fn refresh_once(
    sui_client: &SuiConnectorClient,
    self_authority: AuthorityName,
) -> anyhow::Result<BTreeMap<PeerId, PeerInfo>> {
    let (_, system_inner) = sui_client
        .get_system_inner()
        .await
        .map_err(|e| anyhow::anyhow!("get_system_inner: {e}"))?;
    let SystemInner::V1(si) = system_inner;

    let mut ids: BTreeSet<ObjectID> = BTreeSet::new();
    ids.extend(
        si.validator_set
            .active_committee
            .members
            .iter()
            .map(|m| m.validator_id),
    );
    ids.extend(
        si.validator_set
            .previous_committee
            .members
            .iter()
            .map(|m| m.validator_id),
    );
    if let Some(next) = &si.validator_set.next_epoch_committee {
        ids.extend(next.members.iter().map(|m| m.validator_id));
    }
    // The load-bearing set for dialing a fresh joiner (it's the only set a
    // joiner is in during the registration window). A failure to read it must
    // not drop the committee peers, so degrade gracefully rather than aborting
    // the whole refresh.
    match sui_client
        .get_pending_active_set_ids(si.validator_set.pending_active_set.id)
        .await
    {
        Ok(pending) => ids.extend(pending),
        Err(e) => warn!(
            error = %e,
            "pending_active_set read failed; proceeding with committee peers only"
        ),
    }

    if ids.is_empty() {
        return Ok(BTreeMap::new());
    }

    let pools = sui_client
        .get_validators_info_by_ids(ids.into_iter().collect())
        .await
        .map_err(|e| anyhow::anyhow!("get_validators_info_by_ids: {e}"))?;

    let mut out: BTreeMap<PeerId, PeerInfo> = BTreeMap::new();
    for pool in &pools {
        let verified = match pool.validator_info.verify() {
            Ok(v) => v,
            Err(code) => {
                warn!(code, "validator_info.verify failed; skipping as a peer");
                continue;
            }
        };
        let name: AuthorityName = (&verified.protocol_pubkey).into();
        // Self-exclusion under either identity basis: `self_authority` is
        // the node's name for its CURRENT epoch, whose basis can differ
        // from this read's at the authority-name flip boundary.
        let consensus_basis_name = AuthorityName::from_consensus_key(&verified.consensus_pubkey);
        if name == self_authority || consensus_basis_name == self_authority {
            continue;
        }
        let address = verified
            .p2p_address
            .to_anemo_address()
            .into_iter()
            .collect::<Vec<_>>();
        if address.is_empty() {
            warn!(
                ?name,
                "validator has no usable p2p address; skipping as a peer"
            );
            continue;
        }
        let peer_id = PeerId(verified.network_pubkey.0.to_bytes());
        out.insert(
            peer_id,
            PeerInfo {
                peer_id,
                affinity: PeerAffinity::High,
                address,
            },
        );
    }
    Ok(out)
}
