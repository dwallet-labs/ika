// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Per-epoch task that emits this validator's signed
//! `HandoffSignatureMessage` exactly once, when the local
//! `EndOfPublish` signal asserts the current epoch.
//!
//! Decoupled from `EndOfPublishSender` so the handoff cert is its
//! own protocol step — the two used to share a task by accident of
//! triggering on the same condition. Wiring contributors is the
//! caller's job: pass any number of
//! `Arc<dyn HandoffItemsBuilder>` and the task will fold their
//! contributions into the attestation.

use crate::authority::authority_per_epoch_store::{
    AuthorityPerEpochStore, AuthorityPerEpochStoreTrait,
};
use crate::consensus_adapter::SubmitToConsensus;
use crate::validator_metadata::{HandoffItemsBuilder, next_committee_pubkey_set};
use fastcrypto::ed25519::Ed25519KeyPair;
use ika_types::committee::Committee;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_consensus::ConsensusTransaction;
use ika_types::messages_dwallet_mpc::{
    DWalletNetworkEncryptionKeyData, DWalletNetworkEncryptionKeyState,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use sui_types::base_types::ObjectID;
use tokio::sync::watch::Receiver;
use tracing::{info, warn};

pub struct HandoffSignatureSender {
    epoch_store: Weak<AuthorityPerEpochStore>,
    epoch_id: u64,
    consensus_adapter: Arc<dyn SubmitToConsensus>,
    end_of_publish_receiver: Receiver<Option<u64>>,
    consensus_keypair: Arc<Ed25519KeyPair>,
    next_epoch_committee_receiver: Receiver<Committee>,
    /// Chain-synced view of every `DWalletNetworkEncryptionKey` and
    /// its canonical DKG / current-reconfiguration output bytes.
    /// Updated by `sui_syncer::sync_dwallet_network_keys`. Read at
    /// signing time to hydrate the local digest cache with
    /// consensus/chain-deterministic hashes — sidestepping the race
    /// where the local MPC-driven cache may not yet contain the
    /// digest when EndOfPublish fires.
    network_keys_receiver: Receiver<Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>>,
    builders: Vec<Arc<dyn HandoffItemsBuilder>>,
    sent: AtomicBool,
}

impl HandoffSignatureSender {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_store: Weak<AuthorityPerEpochStore>,
        epoch_id: u64,
        consensus_adapter: Arc<dyn SubmitToConsensus>,
        end_of_publish_receiver: Receiver<Option<u64>>,
        consensus_keypair: Arc<Ed25519KeyPair>,
        next_epoch_committee_receiver: Receiver<Committee>,
        network_keys_receiver: Receiver<Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>>,
        builders: Vec<Arc<dyn HandoffItemsBuilder>>,
    ) -> Self {
        Self {
            epoch_store,
            epoch_id,
            consensus_adapter,
            end_of_publish_receiver,
            consensus_keypair,
            next_epoch_committee_receiver,
            network_keys_receiver,
            builders,
            sent: AtomicBool::new(false),
        }
    }

    pub async fn run(&self) {
        if let Some(epoch_store) = self.epoch_store.upgrade()
            && !epoch_store
                .protocol_config()
                .off_chain_validator_metadata_enabled()
        {
            info!(
                epoch = self.epoch_id,
                "off-chain validator metadata disabled; handoff signature sender exiting"
            );
            return;
        }
        loop {
            if *self.end_of_publish_receiver.borrow() == Some(self.epoch_id)
                && !self.sent.load(Ordering::Acquire)
                && let Err(err) = self.send().await
            {
                warn!(error=?err, "failed to send handoff signature; will retry");
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    fn epoch_store(&self) -> DwalletMPCResult<Arc<AuthorityPerEpochStore>> {
        self.epoch_store
            .upgrade()
            .ok_or(DwalletMPCError::EpochEnded(self.epoch_id))
    }

    /// Returns true once the locally-cached `network_keys_receiver`
    /// snapshot shows every known network encryption key in the
    /// terminal `NetworkReconfigurationCompleted` state with a
    /// non-empty reconfiguration output. This is the same
    /// post-condition the chain-side EndOfPublish gate checks
    /// (`all_network_encryption_keys_reconfiguration_completed`),
    /// re-validated against the local snapshot so we don't sign
    /// off a stale view that some peers have already moved past.
    ///
    /// Empty snapshot is treated as not-ready (we should at least
    /// see the keys before claiming readiness). If there are no
    /// keys on chain at all this path is unreachable — EndOfPublish
    /// wouldn't have fired in the first place.
    fn snapshot_ready_for_signing(&self) -> bool {
        let snapshot = self.network_keys_receiver.borrow().clone();
        if snapshot.is_empty() {
            return false;
        }
        snapshot.iter().all(|(_, data)| {
            matches!(
                data.state,
                DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted
            ) && !data.current_reconfiguration_public_output.is_empty()
        })
    }

    /// For each network encryption key that has finished its initial
    /// DKG, re-cache the canonical DKG output bytes into the per-epoch
    /// digest table. Idempotent — re-caching the same bytes keeps the
    /// same digest (the cache layer is content-addressed). The DKG
    /// output is a one-time stable value, so caching it from the
    /// (possibly-lagging) `network_keys_receiver` snapshot can't diverge
    /// across the committee. The per-epoch reconfiguration output is
    /// intentionally left to its consensus-ordered sources — see the
    /// note in the loop body.
    fn hydrate_protocol_output_digests_from_chain(
        &self,
        epoch_store: &Arc<AuthorityPerEpochStore>,
    ) {
        let snapshot = self.network_keys_receiver.borrow().clone();
        for (key_id, data) in snapshot.iter() {
            // DKG output: present once the key crosses out of
            // `AwaitingNetworkDKG`. Always cache if we have non-empty
            // bytes — re-caching with the same canonical bytes is a
            // no-op for the digest.
            if !data.network_dkg_public_output.is_empty()
                && !matches!(
                    data.state,
                    DWalletNetworkEncryptionKeyState::AwaitingNetworkDKG
                )
                && let Err(e) =
                    epoch_store.cache_network_dkg_output(*key_id, &data.network_dkg_public_output)
            {
                warn!(
                    error = ?e,
                    key_id = ?key_id,
                    "failed to hydrate network DKG digest from chain bytes"
                );
            }
            // NOTE: the current-epoch *reconfiguration* output is
            // deliberately NOT hydrated here. Unlike the one-time DKG
            // output, it is a per-epoch consensus-ordered outcome, and
            // this `network_keys_receiver` snapshot is a non-consensus
            // watch channel that can lag a round behind. Hydrating it
            // would overwrite the consensus-voted reconfiguration digest
            // — already mirrored into the per-epoch cache by
            // `mpc_manager` (from `agreed_network_key_data`) and written
            // by the local reconfiguration MPC in `dwallet_mpc_service`,
            // both deterministic — with a possibly-stale value, so two
            // signers would hash different `NetworkReconfigurationOutput`
            // digests and cross-reject as `AttestationMismatch`. We let
            // the consensus-voted value in the cache stand.
        }
    }

    async fn send(&self) -> DwalletMPCResult<()> {
        let epoch_store = self.epoch_store()?;
        let next_committee = self.next_epoch_committee_receiver.borrow().clone();
        if next_committee.epoch() != self.epoch_id + 1 {
            // Committee sync task hasn't caught up with the next
            // epoch yet; defer until it has.
            return Ok(());
        }
        // Defer signing until every known network encryption key
        // shows the terminal NetworkReconfigurationCompleted state
        // in the locally-cached chain snapshot. EndOfPublish has
        // already fired on chain (which is what triggers us getting
        // here), but the watch-channel snapshot may be one poll
        // cycle stale — signing off a stale snapshot is exactly the
        // race that surfaces as `AttestationMismatch` across the
        // committee. The sui_syncer refreshes its snapshot every
        // 5s on chain-state change, so this loop converges quickly.
        if !self.snapshot_ready_for_signing() {
            return Ok(());
        }
        // Hash the FULL next-committee membership — the identical set
        // the joiner verifier reconstructs, both via
        // `next_committee_pubkey_set`. Membership is chain-deterministic:
        // `new_committee` seats every chain member regardless of the
        // freeze (the freeze only filters which members' class-groups are
        // *assembled*, not who sits on the committee), so every signer
        // derives the same set and the joiner reproduces it from the
        // committee it installs. Do NOT narrow this by the frozen
        // mpc_data set: a still-seated member the freeze excluded from
        // assembly is present in the joiner's committee, so narrowing here
        // makes the cert structurally unverifiable by the very joiner it
        // certifies whenever the freeze excludes a seated member.
        let next_committee_pubkeys = next_committee_pubkey_set(&next_committee);
        // Hydrate the local digest cache from the chain-canonical
        // output bytes BEFORE building the attestation. Reading
        // from chain (via the `network_keys_receiver` published by
        // `sui_syncer`) is the only consensus-deterministic source
        // — the original local MPC-driven cache writes race with
        // EndOfPublish (a slow validator can see EndOfPublish
        // before its own MPC produces output, so the cache is
        // empty at signing time and the items list diverges from
        // peers => signatures cross-reject as `AttestationMismatch`).
        self.hydrate_protocol_output_digests_from_chain(&epoch_store);
        let attestation = epoch_store
            .build_local_handoff_attestation(next_committee_pubkeys, &self.builders)
            .map_err(DwalletMPCError::IkaError)?;
        // The off-chain validator-metadata flag also gates
        // EndOfPublishV2 emission — the bundled flow is the only
        // shape used while the off-chain pipeline is active. Bundle
        // this validator's signed handoff with its EndOfPublish
        // vote into a single consensus message; this eliminates the
        // pre-V2 race where a separate HandoffSignature could
        // arrive at peers out of order with EndOfPublish and
        // produce divergent aggregator states across the committee.
        let signed = epoch_store
            .build_local_signed_handoff_message(attestation, &self.consensus_keypair)
            .map_err(DwalletMPCError::IkaError)?;
        let tx = ConsensusTransaction::new_end_of_publish_v2(epoch_store.name, signed);
        self.consensus_adapter
            .submit_to_consensus(&[tx], &epoch_store)
            .await?;
        self.sent.store(true, Ordering::Release);
        info!(epoch = self.epoch_id, "submitted local handoff signature");
        Ok(())
    }
}
