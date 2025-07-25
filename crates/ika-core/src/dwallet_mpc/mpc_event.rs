// Copyright (c) dWallet Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::dwallet_dkg::{
    dwallet_dkg_first_party_session_request, dwallet_dkg_second_party_session_request,
    dwallet_imported_key_verification_request_event_session_request,
};
use crate::dwallet_mpc::dwallet_mpc_service::DWalletMPCService;
use crate::dwallet_mpc::encrypt_user_share::start_encrypted_share_verification_session_request;
use crate::dwallet_mpc::make_dwallet_user_secret_key_shares_public::make_dwallet_user_secret_key_shares_public_request_event_session_request;
use crate::dwallet_mpc::mpc_manager::DWalletMPCManager;
use crate::dwallet_mpc::mpc_session::MPCEventData;
use crate::dwallet_mpc::network_dkg::network_dkg_session_request;
use crate::dwallet_mpc::presign::presign_party_session_request;
use crate::dwallet_mpc::reconfiguration::network_decryption_key_reconfiguration_session_request_from_event;
use crate::dwallet_mpc::sign::{
    get_verify_partial_signatures_session_request, sign_party_session_request,
};
use dwallet_mpc_types::dwallet_mpc::DWalletMPCNetworkKeyScheme;
use ika_types::error::{IkaError, IkaResult};
use ika_types::messages_dwallet_mpc::{
    DBSuiEvent, DWalletDKGFirstRoundRequestEvent, DWalletDKGSecondRoundRequestEvent,
    DWalletEncryptionKeyReconfigurationRequestEvent, DWalletImportedKeyVerificationRequestEvent,
    DWalletMPCEvent, DWalletNetworkDKGEncryptionKeyRequestEvent, DWalletSessionEvent,
    DWalletSessionEventTrait, EncryptedShareVerificationRequestEvent, FutureSignRequestEvent,
    MakeDWalletUserSecretKeySharesPublicRequestEvent, PresignRequestEvent,
    SESSIONS_MANAGER_MODULE_NAME, SignRequestEvent,
};
use serde::de::DeserializeOwned;
use std::mem;
use std::time::Duration;
use sui_types::dynamic_field::Field;
use sui_types::id::ID;
use tokio::sync::broadcast;
use tracing::{debug, error, warn};

impl DWalletMPCManager {
    /// Handle a batch of MPC events.
    ///
    /// This function might be called more than once for a given session, as we periodically
    /// check for uncompleted events - in which case the event will be ignored.
    ///
    /// A new MPC session is only created once at the first time the event was received
    /// (per-epoch, if it was uncompleted in the previous epoch,
    /// it will be created again for the next one.)
    ///
    /// If the event already exists in `self.mpc_sessions`, we do not add it.
    ///
    /// If there is no `session_request`, and we've got it in this call,
    /// we update that field in the open session.
    pub(crate) async fn handle_mpc_event_batch(&mut self, events: Vec<DWalletMPCEvent>) {
        // We only update `next_active_committee` in this block. Once it's set,
        // there will no longer be any pending events targeting it for this epoch.
        if self.next_active_committee.is_none() {
            let got_next_active_committee = self.try_receiving_next_active_committee();
            if got_next_active_committee {
                let events_pending_for_next_active_committee =
                    mem::take(&mut self.events_pending_for_next_active_committee);

                for event in events_pending_for_next_active_committee {
                    self.handle_mpc_event(event);
                    tokio::task::yield_now().await;
                }
            }
        }

        // First, try to update the network keys.
        let newly_updated_network_keys_ids = self.maybe_update_network_keys().await;

        // Now handle events for which we've just received the corresponding public data.
        // Since events are only queued in `events_pending_for_network_key` within this function,
        // receiving the network key ensures no further events will be pending for that key.
        // Therefore, it's safe to process them now, as the queue will remain empty afterward.
        for key_id in newly_updated_network_keys_ids {
            let events_pending_for_newly_updated_network_key = self
                .events_pending_for_network_key
                .remove(&key_id)
                .unwrap_or_default();

            for event in events_pending_for_newly_updated_network_key {
                // We know this won't fail on a missing network key,
                // but it could be waiting for the next committee,
                // in which case it would be added to that queue.
                // in which case it would be added to that queue.
                self.handle_mpc_event(event);
            }
            tokio::task::yield_now().await;
        }

        for event in events {
            self.handle_mpc_event(event);
            tokio::task::yield_now().await;
        }
    }

    /// Handle an MPC event.
    ///
    /// This function might be called more than once for a given session, as we periodically
    /// check for uncompleted events.
    ///
    /// A new MPC session is only created once at the first time the event was received
    /// (per-epoch, if it was uncompleted in the previous epoch, it will be created again for the next one.)
    ///
    /// If the event already exists in `self.mpc_sessions`, we do not add it.
    ///
    /// If there is no `session_request`, and we've got it in this call,
    /// we update that field in the open session.
    fn handle_mpc_event(&mut self, event: DWalletMPCEvent) {
        let session_identifier = event.session_request.session_identifier;

        // Avoid instantiation of completed events by checking they belong to the current epoch.
        // We only pull uncompleted events, so we skip the check for those,
        // but pushed events might be completed.
        if !event.pulled && event.session_request.epoch != self.epoch_id {
            warn!(
                session_identifier=?session_identifier,
                session_type=?event.session_request.session_type,
                event_epoch=?event.session_request.epoch,
                "received an event for a different epoch, skipping"
            );

            return;
        }

        if event.session_request.requires_network_key_data {
            if let Some(network_encryption_key_id) = event
                .session_request
                .request_input
                .get_network_encryption_key_id()
            {
                if !self
                    .network_keys
                    .key_public_data_exists(&network_encryption_key_id)
                {
                    // We don't yet have the data for this network encryption key,
                    // so we add it to the queue.
                    debug!(
                        session_request=?event.session_request,
                        session_type=?event.session_request.session_type,
                        network_encryption_key_id=?network_encryption_key_id,
                        "Adding event to pending for the network key"
                    );

                    let events_pending_for_this_network_key = self
                        .events_pending_for_network_key
                        .entry(network_encryption_key_id)
                        .or_default();

                    if events_pending_for_this_network_key
                        .iter()
                        .all(|e| e.session_request.session_identifier != session_identifier)
                    {
                        // Add an event with this session ID only if it doesn't exist.
                        events_pending_for_this_network_key.push(event);
                    }

                    return;
                }
            }
        }

        if event.session_request.requires_next_active_committee
            && self.next_active_committee.is_none()
        {
            // We don't have the next active committee yet,
            // so we have to add this event to the pending queue until it arrives.
            debug!(
                session_request=?event.session_request,
                session_type=?event.session_request.session_type,
                "Adding event to pending for the next epoch active committee"
            );

            if self
                .events_pending_for_next_active_committee
                .iter()
                .all(|e| e.session_request.session_identifier != session_identifier)
            {
                // Add an event with this session ID only if it doesn't exist.
                self.events_pending_for_next_active_committee.push(event);
            }

            return;
        }

        if let Some(session) = self.mpc_sessions.get(&session_identifier) {
            if session.mpc_event_data.is_some() {
                // The corresponding session already has its event data set, nothing to do.
                return;
            }
        }

        let mpc_event_data = match MPCEventData::try_new(
            event.clone(),
            &self.access_structure,
            &self.committee,
            &self.network_keys,
            self.next_active_committee.clone(),
            self.validators_class_groups_public_keys_and_proofs.clone(),
        ) {
            Ok(mpc_event_data) => mpc_event_data,
            Err(e) => {
                error!(error=?e, event=?event, "failed to handle dWallet MPC event with error");

                return;
            }
        };

        self.dwallet_mpc_metrics
            .add_received_event_start(&mpc_event_data.request_input);

        if let Some(session) = self.mpc_sessions.get_mut(&session_identifier) {
            session.mpc_event_data = Some(mpc_event_data.clone());
        } else {
            self.new_mpc_session(&session_identifier, Some(mpc_event_data));
        }
    }

    /// Parses a Sui event into a dWallet MPC event.
    pub(crate) fn parse_sui_event(
        &self,
        event: DBSuiEvent,
    ) -> anyhow::Result<Option<DWalletMPCEvent>> {
        let session_request = if event.type_
            == DWalletSessionEvent::<DWalletImportedKeyVerificationRequestEvent>::type_(
                &self.packages_config,
            ) {
            dwallet_imported_key_verification_request_event_session_request(
                deserialize_event_contents::<DWalletImportedKeyVerificationRequestEvent>(
                    &event.contents,
                    event.pulled,
                )?,
            )
        } else if event.type_
            == DWalletSessionEvent::<MakeDWalletUserSecretKeySharesPublicRequestEvent>::type_(
                &self.packages_config,
            )
        {
            make_dwallet_user_secret_key_shares_public_request_event_session_request(
                deserialize_event_contents::<MakeDWalletUserSecretKeySharesPublicRequestEvent>(
                    &event.contents,
                    event.pulled,
                )?,
            )
        } else if event.type_
            == DWalletSessionEvent::<DWalletDKGFirstRoundRequestEvent>::type_(&self.packages_config)
        {
            dwallet_dkg_first_party_session_request(deserialize_event_contents::<
                DWalletDKGFirstRoundRequestEvent,
            >(&event.contents, event.pulled)?)?
        } else if event.type_
            == DWalletSessionEvent::<DWalletDKGSecondRoundRequestEvent>::type_(
                &self.packages_config,
            )
        {
            dwallet_dkg_second_party_session_request(deserialize_event_contents::<
                DWalletDKGSecondRoundRequestEvent,
            >(&event.contents, event.pulled)?)
        } else if event.type_
            == DWalletSessionEvent::<PresignRequestEvent>::type_(&self.packages_config)
        {
            let deserialized_event: DWalletSessionEvent<PresignRequestEvent> =
                deserialize_event_contents(&event.contents, event.pulled)?;

            presign_party_session_request(deserialized_event)
        } else if event.type_
            == DWalletSessionEvent::<SignRequestEvent>::type_(&self.packages_config)
        {
            let deserialized_event: DWalletSessionEvent<SignRequestEvent> =
                deserialize_event_contents(&event.contents, event.pulled)?;

            sign_party_session_request(&deserialized_event)
        } else if event.type_
            == DWalletSessionEvent::<FutureSignRequestEvent>::type_(&self.packages_config)
        {
            let deserialized_event: DWalletSessionEvent<FutureSignRequestEvent> =
                deserialize_event_contents(&event.contents, event.pulled)?;

            get_verify_partial_signatures_session_request(&deserialized_event)
        } else if event.type_
            == DWalletSessionEvent::<DWalletNetworkDKGEncryptionKeyRequestEvent>::type_(
                &self.packages_config,
            )
        {
            let deserialized_event: DWalletSessionEvent<
                DWalletNetworkDKGEncryptionKeyRequestEvent,
            > = deserialize_event_contents(&event.contents, event.pulled)?;

            network_dkg_session_request(deserialized_event, DWalletMPCNetworkKeyScheme::Secp256k1)?
        } else if event.type_
            == DWalletSessionEvent::<DWalletEncryptionKeyReconfigurationRequestEvent>::type_(
                &self.packages_config,
            )
        {
            let deserialized_event: DWalletSessionEvent<
                DWalletEncryptionKeyReconfigurationRequestEvent,
            > = deserialize_event_contents(&event.contents, event.pulled)?;

            network_decryption_key_reconfiguration_session_request_from_event(deserialized_event)
        } else if event.type_
            == DWalletSessionEvent::<EncryptedShareVerificationRequestEvent>::type_(
                &self.packages_config,
            )
        {
            let deserialized_event: DWalletSessionEvent<EncryptedShareVerificationRequestEvent> =
                deserialize_event_contents(&event.contents, event.pulled)?;

            start_encrypted_share_verification_session_request(deserialized_event)
        } else {
            return Ok(None);
        };

        let event = DWalletMPCEvent {
            session_request,
            pulled: event.pulled,
        };

        Ok(Some(event))
    }

    pub(crate) fn parse_sui_events(&mut self, events: Vec<DBSuiEvent>) -> Vec<DWalletMPCEvent> {
        events
            .into_iter()
            .filter_map(|event| {
                if event.type_.address
                    != *self.packages_config.packages.ika_dwallet_2pc_mpc_package_id
                    || event.type_.module != SESSIONS_MANAGER_MODULE_NAME.into()
                {
                    error!(
                        module=?event.type_.module,
                        address=?event.type_.address,
                        "received an event from a wrong SUI module - rejecting!"
                    );

                    None
                } else {
                    match self.parse_sui_event(event.clone()) {
                        Ok(Some(event)) => {
                            debug!(
                                session_identifier=?event.session_request.session_identifier,
                                session_type=?event.session_request.session_type,
                                mpc_protocol=?event.session_request.request_input,
                                mpc_round=?event.session_request.request_input,
                                current_epoch=?self.epoch_id,
                                "Successfully parsed a Sui event"
                            );

                            Some(event)
                        }
                        Ok(None) => {
                            debug!(
                                event=?event,
                                "Received an event that does not trigger the start of an MPC flow"
                            );

                            None
                        }
                        Err(e) => {
                            error!(
                                event=?event,
                                error=?e,
                                "Error while parsing Sui event"
                            );

                            None
                        }
                    }
                }
            })
            .collect()
    }
}

impl DWalletMPCService {
    /// Proactively pull uncompleted events from the Sui network.
    /// We do that to ensure we don't miss any events.
    /// These events might be from a different Epoch, not necessarily the current one
    pub(crate) async fn fetch_uncompleted_events(&mut self) -> Vec<DBSuiEvent> {
        let epoch_store = self.epoch_store.clone();
        loop {
            match self
                .sui_client
                .pull_dwallet_mpc_uncompleted_events(epoch_store.epoch())
                .await
            {
                Ok(events) => {
                    for event in &events {
                        debug!(
                            event_type=?event.type_,
                            current_epoch=?epoch_store.epoch(),
                            contents=?event.contents.clone(),
                            "Successfully fetched an uncompleted event from Sui"
                        );
                    }
                    return events;
                }
                Err(err) => {
                    error!(
                        error=?err,
                        current_epoch=?self.epoch_store.epoch(),
                         "failed to load missed events from Sui"
                    );
                    if let IkaError::EpochEnded(_) = err {
                        return vec![];
                    };
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }

    /// Read events from perpetual tables, remove them, and store in the current epoch tables.
    pub(crate) fn receive_new_sui_events(&mut self) -> IkaResult<Vec<DBSuiEvent>> {
        let pending_events = match self.new_events_receiver.try_recv() {
            Ok(events) => {
                for event in &events {
                    debug!(
                        event_type=?event.type_,
                        id=?event.id,
                        contents=?event.bcs.clone().into_bytes(),
                        current_epoch=?self.epoch_store.epoch(),
                        "Received an event from Sui"
                    );
                }
                events
            }
            Err(broadcast::error::TryRecvError::Empty) => {
                debug!("No new Sui events to process");
                return Ok(vec![]);
            }
            Err(e) => {
                return Err(IkaError::ReceiverError(e.to_string()));
            }
        };

        let events: Vec<_> = pending_events
            .into_iter()
            .map(|event| DBSuiEvent {
                type_: event.type_,
                contents: event.bcs.into_bytes(),
                pulled: false,
            })
            .collect();

        Ok(events)
    }
}

/// The type of the event is different when we receive an emitted event and when we
/// fetch the event's the dynamic field directly from Sui.
fn deserialize_event_contents<T: DeserializeOwned + DWalletSessionEventTrait>(
    event_contents: &[u8],
    pulled: bool,
) -> Result<DWalletSessionEvent<T>, bcs::Error> {
    if pulled {
        bcs::from_bytes::<Field<ID, DWalletSessionEvent<T>>>(event_contents)
            .map(|field| field.value)
    } else {
        bcs::from_bytes::<DWalletSessionEvent<T>>(event_contents)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_pushed_event() {
        let contents: [u8; 182] = [
            1, 0, 0, 0, 0, 0, 0, 0, 42, 125, 37, 180, 18, 118, 110, 162, 78, 250, 210, 254, 212,
            113, 47, 204, 30, 77, 60, 26, 0, 223, 126, 59, 190, 182, 109, 198, 141, 60, 230, 72, 0,
            5, 0, 0, 0, 0, 0, 0, 0, 32, 65, 13, 165, 26, 198, 19, 129, 225, 102, 181, 38, 127, 82,
            227, 181, 17, 93, 110, 102, 157, 221, 147, 236, 191, 147, 63, 41, 90, 30, 150, 62, 45,
            221, 150, 223, 223, 219, 76, 93, 29, 157, 231, 56, 171, 228, 227, 63, 176, 17, 19, 114,
            143, 222, 30, 131, 125, 77, 147, 172, 250, 221, 12, 213, 49, 102, 7, 52, 69, 166, 204,
            245, 69, 130, 39, 112, 223, 197, 227, 177, 154, 133, 137, 136, 110, 100, 148, 70, 108,
            118, 245, 89, 113, 172, 32, 44, 251, 235, 242, 75, 50, 116, 215, 239, 218, 220, 35,
            219, 184, 115, 253, 169, 181, 154, 210, 255, 84, 236, 13, 165, 22, 194, 214, 134, 253,
            131, 133, 99, 183, 0, 0, 0, 0,
        ];

        let res = deserialize_event_contents::<DWalletDKGFirstRoundRequestEvent>(&contents, false);

        assert!(
            res.is_ok(),
            "should deserialize pushed event, got error {:?}",
            res.err().unwrap()
        );

        let res = deserialize_event_contents::<DWalletDKGFirstRoundRequestEvent>(&contents, true);

        assert!(
            res.is_err(),
            "should fail to deserialize pushed event as a pulled event, got error {:?}",
            res.err().unwrap()
        );
    }

    #[test]
    fn deserializes_pulled_event() {
        let contents: [u8; 171] = [
            186, 166, 100, 86, 49, 207, 80, 207, 154, 105, 179, 229, 138, 148, 167, 113, 229, 137,
            213, 125, 240, 17, 115, 24, 239, 150, 9, 8, 33, 232, 87, 141, 86, 116, 15, 142, 39,
            115, 79, 200, 4, 203, 25, 92, 167, 181, 42, 212, 184, 174, 99, 70, 193, 165, 176, 238,
            86, 107, 178, 167, 142, 151, 83, 102, 1, 0, 0, 0, 0, 0, 0, 0, 86, 116, 15, 142, 39,
            115, 79, 200, 4, 203, 25, 92, 167, 181, 42, 212, 184, 174, 99, 70, 193, 165, 176, 238,
            86, 107, 178, 167, 142, 151, 83, 102, 1, 32, 186, 100, 160, 245, 184, 131, 140, 125,
            22, 112, 53, 22, 218, 232, 70, 207, 138, 127, 92, 239, 54, 154, 150, 210, 143, 196,
            153, 197, 12, 23, 196, 169, 235, 242, 75, 50, 116, 215, 239, 218, 220, 35, 219, 184,
            115, 253, 169, 181, 154, 210, 255, 84, 236, 13, 165, 22, 194, 214, 134, 253, 131, 133,
            99, 183, 0,
        ];

        let res = deserialize_event_contents::<DWalletNetworkDKGEncryptionKeyRequestEvent>(
            &contents, true,
        );

        assert!(
            res.is_ok(),
            "should deserialize pulled event, got error {:?}",
            res.err().unwrap()
        );

        let res = deserialize_event_contents::<DWalletNetworkDKGEncryptionKeyRequestEvent>(
            &contents, false,
        );

        assert!(
            res.is_err(),
            "should fail to deserialize pulled event as a pushed event, got error {:?}",
            res.err().unwrap()
        );
    }
}
