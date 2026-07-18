// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Per-epoch task that emits this validator's signed
//! `HandoffSignatureMessage` (bundled into `EndOfPublishV2`) once the
//! local `EndOfPublish` signal asserts the current epoch, re-submitting
//! the idempotent bundle until it is confirmed sequenced — a successful
//! `submit_to_consensus` only hands the tx to a background submitter
//! that can still fail to sequence at the epoch boundary or on crash.
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
use ika_network::mpc_artifacts::mpc_data_blob_hash;
use ika_types::committee::Committee;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_consensus::ConsensusTransaction;
use ika_types::messages_dwallet_mpc::{
    DWalletNetworkEncryptionKeyData, DWalletNetworkEncryptionKeyState,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use sui_types::base_types::ObjectID;
use tokio::sync::watch::Receiver;
use tracing::{debug, info, warn};

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
    /// Number of `EndOfPublishV2` submissions so far this epoch. Used
    /// only to bound logging: the first submission (and every 30th
    /// thereafter, so a boundary sequencing stall still surfaces) logs
    /// at info, the 1s re-submissions in between at debug.
    submit_attempts: AtomicU64,
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
            submit_attempts: AtomicU64::new(0),
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
        // Throttle the failure-path warn: the loop ticks every 1s, so a
        // persistent submit error would otherwise warn per second. Warn on
        // the first failure and every 30th consecutive one (~30s), debug in
        // between; the counter resets on success.
        let mut consecutive_send_failures: u64 = 0;
        loop {
            // `send` self-gates on confirmation (re-submits the
            // idempotent bundle until our EndOfPublishV2 is recorded),
            // so the loop just drives it each tick once EndOfPublish has
            // fired for this epoch.
            if *self.end_of_publish_receiver.borrow() == Some(self.epoch_id) {
                match self.send().await {
                    Ok(()) => consecutive_send_failures = 0,
                    Err(err) => {
                        if consecutive_send_failures.is_multiple_of(30) {
                            warn!(
                                error=?err,
                                consecutive_failures = consecutive_send_failures,
                                "failed to send handoff signature; will retry"
                            );
                        } else {
                            debug!(
                                error=?err,
                                consecutive_failures = consecutive_send_failures,
                                "failed to send handoff signature; will retry"
                            );
                        }
                        consecutive_send_failures += 1;
                    }
                }
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
    /// terminal `NetworkReconfigurationCompleted` state AND this
    /// epoch's reconfiguration output has been computed locally
    /// (present in the current-epoch per-epoch digest table). This is
    /// the same post-condition the chain-side EndOfPublish gate checks
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
        // Gate the reconfiguration output on this epoch's epoch-keyed
        // digest slice (this validator's own locally-computed bytes,
        // filed under the reconfiguration session's own epoch), NOT the
        // overlay snapshot. The overlay can surface the prior epoch's
        // output via the perpetual mirror, which would let this validator
        // sign a stale `NetworkReconfigurationOutput` digest that diverges
        // from peers. Reading the same epoch-keyed slice the handoff items
        // builder reads keeps the readiness gate and the attestation
        // strictly in sync.
        let Some(epoch_store) = self.epoch_store.upgrade() else {
            return false;
        };
        let Ok(reconfig_for_epoch) =
            epoch_store.get_network_reconfiguration_output_digests_for_epoch(self.epoch_id)
        else {
            return false;
        };
        snapshot.iter().all(|(key_id, data)| {
            matches!(
                data.state,
                DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted
            ) && reconfig_for_epoch.contains_key(key_id)
        })
    }

    /// For each network encryption key that has finished its initial
    /// DKG and has NO locally-recorded DKG digest yet, cache the DKG
    /// output bytes from the overlay snapshot into the per-epoch digest
    /// table. Fill-absence ONLY: a validator that saw EndOfPublish
    /// before its own MPC produced/cached the output would otherwise
    /// build an attestation missing the `NetworkDkgOutput` item and
    /// cross-reject peers as `AttestationMismatch`. The per-epoch
    /// reconfiguration output is intentionally left to its
    /// consensus-ordered sources — see the note in the loop body.
    ///
    /// NEVER overwrite an existing digest: the local mirror is written
    /// canonically by the instantiation path (the reconstructed V3
    /// output once the V2→V3 canonical migration flips) and by the
    /// cert-anchored barrier install — both strictly more authoritative
    /// than this watch snapshot, which can carry the chain's original
    /// pre-V3 anchor whenever the syncer chain-read before the
    /// off-chain blob source was installed (a post-restart window).
    /// An unconditional write here clobbered the DURABLE perpetual
    /// canonical mirror with that anchor, permanently failing the
    /// handoff-cert DKG-digest adoption gate every later epoch — the
    /// never-instantiated variant of issue #1852.
    fn hydrate_protocol_output_digests_from_chain(
        &self,
        epoch_store: &Arc<AuthorityPerEpochStore>,
    ) {
        let snapshot = self.network_keys_receiver.borrow().clone();
        hydrate_network_dkg_digests(epoch_store, &snapshot);
    }

    async fn send(&self) -> DwalletMPCResult<()> {
        let epoch_store = self.epoch_store()?;
        // Confirmation-based gate (mirrors `MpcDataAnnouncementSender`):
        // stop once our `EndOfPublishV2` has actually sequenced — i.e.
        // our EndOfPublish vote is recorded in this epoch's durable
        // table. A successful `submit_to_consensus` only hands the tx to
        // a background submitter that can still fail to sequence at the
        // epoch boundary (exactly when `EndOfPublishV2` fires) or on
        // crash; the old one-shot `sent` flag then silently dropped this
        // validator's EOP vote + handoff signature for the whole epoch.
        // The `EndOfPublishV2` consensus key is `(authority)`, so
        // re-submitting the idempotent bundle dedups instead of stacking.
        //
        // Steady-state early-out: once our own EndOfPublish vote is durably
        // recorded AND the aggregator has been built (an expected attestation
        // installed at least once this epoch), this task has nothing left to
        // do — the bundle was sequenced and restart recovery, if any, already
        // ran. Without this gate, every 1s tick from EndOfPublish until epoch
        // teardown would re-run the hydrate+build+install below: a full-blob
        // Blake2b re-hash plus an unconditional perpetual-blob rewrite per
        // network key (MB-scale), on every validator, at the epoch boundary.
        // The vote check alone is deliberately NOT sufficient: on the first
        // post-restart tick the aggregator is empty, so this gate does not
        // fire and the install below replays the durable signature rows,
        // rebuilds the aggregator, and re-mints+persists the certificate
        // (buffered-quorum adoption alone only sees signatures that arrive
        // AFTER the restart). This also bounds the re-install of a DIVERGENT
        // rebuilt attestation — which drops signature rows endorsing the
        // previously-installed one — to that single recovery pass instead of
        // a standing per-tick behavior.
        if epoch_store
            .has_recorded_end_of_publish_vote(&epoch_store.name)
            .map_err(DwalletMPCError::IkaError)?
            && epoch_store.handoff_aggregator_installed()
        {
            return Ok(());
        }
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
        // Fill ABSENT DKG digests from the overlay snapshot BEFORE
        // building the attestation: a slow validator can see
        // EndOfPublish before its own MPC produced/cached the output,
        // and an empty cache at signing time makes the items list
        // diverge from peers => signatures cross-reject as
        // `AttestationMismatch`. Fill-absence only — the snapshot is
        // NOT authoritative over an existing digest (post-restart it
        // can carry the chain's pre-V3 anchor; see
        // `hydrate_network_dkg_digests`).
        self.hydrate_protocol_output_digests_from_chain(&epoch_store);
        let attestation = epoch_store
            .build_local_handoff_attestation(next_committee_pubkeys, &self.builders)
            .map_err(DwalletMPCError::IkaError)?;
        // Install BEFORE the vote gate below. This is the restart-recovery
        // path: on the first post-restart tick the in-memory aggregator is
        // empty, so install replays the durable signature rows, rebuilds the
        // aggregator, and re-mints+persists the cert. It must run even when
        // our own EndOfPublish vote is already recorded (the case a
        // restart-after-EndOfPublishV2 hits) — which is why the vote check
        // alone doesn't gate it. Reaching here repeatedly is prevented by the
        // steady-state early-out at the top (vote recorded + aggregator
        // installed), NOT by this call being cheap: the hydrate above
        // re-hashes and rewrites full key blobs.
        //
        // NOTE (divergence tradeoff, deliberate): if the rebuilt attestation
        // DIFFERS from the previously-installed one, the install drops the
        // durable signature rows endorsing the old attestation. For a
        // divergent validator that had adopted the quorum's attestation via
        // buffered signatures, this discards that quorum's rows — its local
        // close gate can flip and it closes via the grace backstop instead of
        // the quorum commit. Its recovery is the barrier peer-fetch of the
        // quorum cert (the persisted cert itself is NOT deleted). The
        // alternative — keeping rows keyed by attestation digest — is heavier
        // schema surgery on a gate that the planned sequence-pure close-gate
        // rework retires; see dev-docs/plans/handoff-barrier-escape-and-pure-close-gate.md.
        epoch_store
            .install_expected_handoff_attestation(attestation.clone())
            .map_err(DwalletMPCError::IkaError)?;
        // Now gate the sign+submit: if our EndOfPublish vote is already
        // durably recorded, the bundle was already sequenced — don't
        // re-sign/re-submit — but the install above has recovered the
        // aggregator regardless.
        if epoch_store
            .has_recorded_end_of_publish_vote(&epoch_store.name)
            .map_err(DwalletMPCError::IkaError)?
        {
            return Ok(());
        }
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
        // First submission (and every 30th re-submission, so a boundary
        // sequencing stall still surfaces at info, ~every 30s) logs at
        // info; the expected 1s re-submit-until-confirmed ticks in
        // between log at debug.
        let attempt = self.submit_attempts.fetch_add(1, Ordering::AcqRel);
        if attempt == 0 || attempt.is_multiple_of(30) {
            info!(
                epoch = self.epoch_id,
                attempt, "submitted local handoff signature (will re-submit until confirmed)"
            );
        } else {
            debug!(
                epoch = self.epoch_id,
                attempt, "re-submitted local handoff signature (not yet confirmed)"
            );
        }
        Ok(())
    }
}

/// For each network encryption key in the overlay snapshot that has
/// finished its initial DKG and has NO locally-recorded DKG digest yet,
/// cache the snapshot's DKG output bytes into the local digest cache.
/// Fill-absence ONLY: a validator that saw EndOfPublish before its own
/// MPC produced/cached the output would otherwise build an attestation
/// missing the `NetworkDkgOutput` item and cross-reject peers as
/// `AttestationMismatch`.
///
/// NEVER overwrite an existing digest: the local mirror is written
/// canonically by the instantiation path (the reconstructed V3 output
/// once the V2→V3 canonical migration flips) and by the cert-anchored
/// barrier install — both strictly more authoritative than this watch
/// snapshot, which can carry the chain's original pre-V3 anchor whenever
/// the syncer chain-read before the off-chain blob source was installed
/// (a post-restart window). An unconditional write here clobbered the
/// DURABLE perpetual canonical mirror with that anchor, permanently
/// failing the handoff-cert DKG-digest adoption gate every later epoch —
/// the never-instantiated variant of issue #1852.
///
/// The per-epoch reconfiguration output is deliberately NOT hydrated
/// here. Unlike the one-time DKG output, it is epoch-specific, and the
/// overlay snapshot is a non-consensus watch channel that can surface
/// the *prior* epoch's output (via the perpetual mirror) a round behind.
/// The reconfiguration digest is written solely by this validator's
/// local reconfiguration MPC in `dwallet_mpc_service`, keyed by the
/// reconfiguration session's own epoch, and both the handoff items
/// builder and `snapshot_ready_for_signing` read it from that epoch-keyed
/// slice (`get_network_reconfiguration_output_digests_for_epoch`).
/// Hydrating from the lagging snapshot would file a possibly-stale value
/// under this epoch, so two signers would hash different
/// `NetworkReconfigurationOutput` digests and cross-reject as
/// `AttestationMismatch`.
fn hydrate_network_dkg_digests(
    epoch_store: &Arc<AuthorityPerEpochStore>,
    snapshot: &HashMap<ObjectID, DWalletNetworkEncryptionKeyData>,
) {
    // The merged per-epoch + perpetual view — the same view the
    // attestation items builder reads, so "absent here" is exactly
    // "the attestation would omit the item".
    //
    // The view is read once per pass, so a canonical write landing
    // between this read and the cache write below can be overwritten by
    // the snapshot value for a key that was absent at the read. The
    // window is one pass, requires the key's first-ever cache to race
    // it, and the barrier's cert-anchored DKG repair heals the affected
    // epoch at the next boundary — accepted rather than locked.
    let existing_dkg_digests = epoch_store
        .get_network_dkg_output_digests()
        .unwrap_or_default();
    for (key_id, data) in snapshot.iter() {
        // DKG output: present once the key crosses out of
        // `AwaitingNetworkDKG`. Cache only when no digest is recorded
        // for the key yet (fill-absence; see above).
        if data.network_dkg_public_output.is_empty()
            || matches!(
                data.state,
                DWalletNetworkEncryptionKeyState::AwaitingNetworkDKG
            )
        {
            continue;
        }
        if let Some(existing) = existing_dkg_digests.get(key_id) {
            // A skip may be correct; a SILENT skip on a contradiction
            // never is: an overlay carrying bytes that hash differently
            // from the recorded canonical digest is the #1852
            // hydration-clobber signature (e.g. the chain's pre-V3
            // anchor after a restart) — surface it. Routine
            // identical-bytes skips stay quiet.
            let snapshot_digest = mpc_data_blob_hash(&data.network_dkg_public_output);
            if *existing != snapshot_digest {
                warn!(
                    key_id = ?key_id,
                    existing_digest = ?existing,
                    snapshot_digest = ?snapshot_digest,
                    "overlay snapshot's DKG bytes contradict the locally-recorded canonical \
                     digest — keeping the canonical value (fill-absence hydration never \
                     overwrites); if this validator was recently restarted this is the \
                     stale pre-V3-anchor overlay shape"
                );
            }
            continue;
        }
        if let Err(e) =
            epoch_store.cache_network_dkg_output(*key_id, &data.network_dkg_public_output)
        {
            warn!(
                error = ?e,
                key_id = ?key_id,
                "failed to hydrate network DKG digest from chain bytes"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
    use crate::authority::epoch_start_configuration::EpochStartConfiguration;
    use crate::epoch::epoch_metrics::EpochMetrics;
    use ika_types::digests::ChainIdentifier;
    use ika_types::messages_dwallet_mpc::IkaNetworkConfig;
    use ika_types::sui::EpochStartSystem;
    use prometheus::Registry;

    fn snapshot_entry(
        key_id: ObjectID,
        dkg_bytes: &[u8],
    ) -> (ObjectID, DWalletNetworkEncryptionKeyData) {
        (
            key_id,
            DWalletNetworkEncryptionKeyData {
                id: key_id,
                current_epoch: 0,
                dkg_at_epoch: 0,
                network_dkg_public_output: dkg_bytes.to_vec(),
                current_reconfiguration_public_output: vec![],
                state: DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted,
            },
        )
    }

    /// The hydration pass is fill-absence only (#1852, never-instantiated
    /// variant): a key with an existing locally-recorded DKG digest must NOT
    /// be overwritten by the overlay snapshot's bytes — the snapshot can
    /// carry the chain's pre-V3 anchor after a restart, and the durable
    /// canonical mirror it would clobber is what the handoff-cert DKG-digest
    /// adoption gate verifies. A key with no recorded digest is still filled.
    #[tokio::test]
    async fn hydration_fills_absent_digests_but_never_overwrites() {
        let (committee, _keys) = Committee::new_simple_test_committee_of_size(4);
        let committee = Arc::new(committee);
        let names: Vec<_> = committee.names().copied().collect();
        let dir = tempfile::tempdir().unwrap();
        let epoch_start_configuration =
            EpochStartConfiguration::new(EpochStartSystem::new_for_testing_with_epoch(0)).unwrap();
        let epoch_store = AuthorityPerEpochStore::new(
            names[0],
            committee.clone(),
            dir.path(),
            None,
            EpochMetrics::new(&Registry::new()),
            epoch_start_configuration,
            ChainIdentifier::default(),
            IkaNetworkConfig::new_for_testing(),
        )
        .unwrap();
        let perpetual_dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(perpetual_dir.path(), None));
        epoch_store.install_perpetual_tables_for_handoff(perpetual);

        let mirrored_key = ObjectID::random();
        let fresh_key = ObjectID::random();
        let canonical_bytes = b"canonical v3 dkg output".to_vec();
        let anchor_bytes = b"chain pre-v3 dkg anchor".to_vec();
        let fresh_bytes = b"fresh key dkg output".to_vec();

        // The instantiation path already mirrored the canonical bytes.
        epoch_store
            .cache_network_dkg_output(mirrored_key, &canonical_bytes)
            .unwrap();

        // Post-restart overlay snapshot: the mirrored key carries the
        // chain's pre-V3 anchor; the fresh key has no local digest yet.
        let snapshot = HashMap::from([
            snapshot_entry(mirrored_key, &anchor_bytes),
            snapshot_entry(fresh_key, &fresh_bytes),
        ]);
        hydrate_network_dkg_digests(&epoch_store, &snapshot);

        let digests = epoch_store.get_network_dkg_output_digests().unwrap();
        assert_eq!(
            digests.get(&mirrored_key),
            Some(&mpc_data_blob_hash(&canonical_bytes)),
            "hydration must never overwrite an existing (canonical) DKG digest"
        );
        assert_eq!(
            digests.get(&fresh_key),
            Some(&mpc_data_blob_hash(&fresh_bytes)),
            "hydration must still fill a key with no recorded digest"
        );
    }
}
