// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Concrete `AnnouncementRelay` impl for the Anemo
//! `SubmitMpcDataAnnouncement` RPC.
//!
//! Joiners who aren't in the consensus committee yet can't submit
//! their own `ValidatorMpcDataAnnouncement` to consensus directly.
//! They fan out the signed announcement to every current-committee
//! validator over the new RPC; whichever validator accepts it
//! forwards it as a `ConsensusTransaction`. One honest relayer per
//! announcement is sufficient.
//!
//! This impl runs:
//! 1. Cheap envelope checks (sig epoch == announcement epoch,
//!    announcement.validator == sig.authority).
//! 2. The pure verifier
//!    `verify_joiner_announcement` against the currently-installed
//!    `JoinerPubkeyProvider`. Rejection here stops spam from
//!    abusing us as a one-way pipe.
//! 3. Consensus submission of the wrapped
//!    `ConsensusTransaction::new_validator_mpc_data_announcement`.

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::blob_cache::BlobCache;
use crate::consensus_adapter::SubmitToConsensus;
use crate::validator_metadata::{
    JoinerAnnouncementVerdict, PeerBlobVerdict, verify_joiner_announcement,
    verify_peer_blob_for_relay,
};
use ika_network::mpc_artifacts::AnnouncementRelay;
use ika_types::messages_consensus::ConsensusTransaction;
use ika_types::validator_metadata::SignedValidatorMpcDataAnnouncement;
use std::sync::{Arc, Weak};

pub struct ConsensusBackedAnnouncementRelay {
    epoch_store: Weak<AuthorityPerEpochStore>,
    consensus_adapter: Arc<dyn SubmitToConsensus>,
    blob_cache: Arc<BlobCache>,
}

impl ConsensusBackedAnnouncementRelay {
    pub fn new(
        epoch_store: Weak<AuthorityPerEpochStore>,
        consensus_adapter: Arc<dyn SubmitToConsensus>,
        blob_cache: Arc<BlobCache>,
    ) -> Self {
        Self {
            epoch_store,
            consensus_adapter,
            blob_cache,
        }
    }
}

#[async_trait::async_trait]
impl AnnouncementRelay for ConsensusBackedAnnouncementRelay {
    async fn relay(
        &self,
        announcement: SignedValidatorMpcDataAnnouncement,
        blob: Vec<u8>,
    ) -> Result<(), String> {
        let Some(epoch_store) = self.epoch_store.upgrade() else {
            return Err("epoch ended".to_string());
        };
        let current_epoch = epoch_store.epoch();
        let next_epoch = current_epoch.saturating_add(1);
        // Joiner announcements target `next_epoch`. Current-epoch
        // announcements would come from validators that are
        // already in the committee and can submit themselves —
        // refuse to relay those.
        if announcement.announcement.epoch != next_epoch {
            return Err(format!(
                "announcement epoch {} is not next_epoch {next_epoch}",
                announcement.announcement.epoch
            ));
        }
        let Some(provider) = epoch_store.joiner_pubkey_provider() else {
            return Err("joiner pubkey provider not installed".to_string());
        };
        match verify_joiner_announcement(&announcement, provider.as_ref().as_ref(), next_epoch) {
            JoinerAnnouncementVerdict::Accept => {}
            verdict => {
                return Err(format!("joiner verify rejected: {verdict:?}"));
            }
        }
        // Cache the pushed blob write-through. The joiner isn't in our
        // peer set, so neither we nor the rest of the committee can
        // fetch its `mpc_data` back from it — pushing it on the relay
        // is the only path. Verify it commits to the signed digest and
        // decodes to valid mpc_data before trusting it (the joiner's
        // signature binds `blob_hash`, so a hash mismatch is a
        // protocol violation; hash-matching-but-undecodable bytes
        // would poison our serve cache, so refuse both). Once cached,
        // the in-memory mirror lets the rest of the committee resolve
        // the joiner via the existing content-addressed P2P fetch.
        let digest = announcement.announcement.blob_hash;
        match verify_peer_blob_for_relay(&blob, &digest) {
            PeerBlobVerdict::Accept => {}
            verdict => {
                return Err(format!("joiner blob rejected: {verdict:?}"));
            }
        }
        self.blob_cache
            .insert(digest, blob.clone())
            .map_err(|e| format!("cache joiner blob failed: {e}"))?;
        // Carry the joiner's blob in-band on the consensus relay so the
        // whole committee obtains the bytes via consensus replication
        // rather than each member fetching them peer-to-peer.
        let tx =
            ConsensusTransaction::new_relayed_validator_mpc_data_announcement(announcement, blob);
        self.consensus_adapter
            .submit_to_consensus(&[tx], &epoch_store)
            .await
            .map_err(|e| format!("consensus submit failed: {e}"))?;
        Ok(())
    }
}
