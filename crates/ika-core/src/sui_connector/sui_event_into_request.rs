use crate::dwallet_session_request::DWalletSessionRequest;
use crate::request_protocol_data::{
    dwallet_dkg_and_sign_protocol_data, dwallet_dkg_protocol_data,
    encrypted_share_verification_protocol_data, imported_key_verification_protocol_data,
    make_dwallet_user_secret_key_shares_public_protocol_data,
    network_encryption_key_dkg_protocol_data, network_encryption_key_reconfiguration_protocol_data,
    partial_signature_verification_protocol_data, presign_protocol_data, sign_protocol_data,
};
use ika_types::dwallet_mpc_error::DwalletMPCResult;
use ika_types::messages_dwallet_mpc::{
    DWALLET_SESSION_EVENT_STRUCT_NAME, DWalletDKGRequestEvent,
    DWalletEncryptionKeyReconfigurationRequestEvent, DWalletImportedKeyVerificationRequestEvent,
    DWalletNetworkDKGEncryptionKeyRequestEvent, DWalletSessionEvent, DWalletSessionEventTrait,
    EncryptedShareVerificationRequestEvent, FutureSignRequestEvent, IkaNetworkConfig,
    MakeDWalletUserSecretKeySharesPublicRequestEvent, PresignRequestEvent,
    SESSIONS_MANAGER_MODULE_NAME, SignDuringDKGRequestEvent, SignRequestEvent,
};
use ika_types::noa_checkpoint::CounterpartyChainKind;
use move_core_types::language_storage::StructTag;
use serde::de::DeserializeOwned;
use sui_types::base_types::ObjectID;
use sui_types::dynamic_field::Field;
use sui_types::id::ID;
use tracing::{error, info};

/// The dwallet package addresses this binary will accept events from.
///
/// A Sui package upgrade does NOT move existing types — Sui records type
/// identity per datatype in the package's `TypeOrigin` table, so a type carried
/// forward keeps the ORIGINAL address while a type **first defined in the
/// upgrade** carries the UPGRADE address. Both are therefore live at once (as
/// of 2026-07-25 the deployed dwallet package has 79 types at the original and
/// 7 at the upgrade, five of them events), which is why this set is a set and
/// not one id.
pub fn accepted_dwallet_packages(packages_config: &IkaNetworkConfig) -> Vec<ObjectID> {
    let mut ids = vec![packages_config.packages.ika_dwallet_2pc_mpc_package_id];
    if let Some(v2) = packages_config.packages.ika_dwallet_2pc_mpc_package_id_v2 {
        ids.push(v2);
    }
    ids
}

/// Outcome of comparing the chain's dwallet package against the set this
/// binary accepts events from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageDrift {
    /// The chain's executable package is one we accept.
    Known,
    /// The chain is EXECUTING a dwallet package this binary does not accept
    /// events from. Any event type first defined in it is being dropped.
    Executing(ObjectID),
    /// An upgrade is staged but not yet migrated to. Nothing is dropped yet —
    /// this is the lead time to ship the constant.
    Pending(ObjectID),
}

/// Detect a dwallet package upgrade this binary does not know about.
///
/// The event filter below admits an event only if its type address is in
/// [`accepted_dwallet_packages`]. Because an upgrade's newly-defined types
/// carry the UPGRADE address, a package upgrade the config has not been taught
/// about makes those events fail that filter — the node silently loses those
/// sessions. This is the same failure shape as #1908 (a fleet deaf to events
/// because a compiled-in package id did not match the chain), reached by a
/// different route, and this check is what makes it visible.
///
/// Deliberately NOT fatal: an upgrade that defines no new event types is
/// harmless, and refusing to boot the whole fleet on a benign upgrade would be
/// worse than the degradation. The caller warns and counts instead.
pub fn detect_dwallet_package_drift(
    packages_config: &IkaNetworkConfig,
    executing_package_id: ObjectID,
    staged_package_id: Option<ObjectID>,
) -> PackageDrift {
    let accepted = accepted_dwallet_packages(packages_config);
    if !accepted.contains(&executing_package_id) {
        return PackageDrift::Executing(executing_package_id);
    }
    // Only report a staged upgrade we don't already accept; once the constant
    // ships, the same staged id is no longer news.
    match staged_package_id {
        Some(staged) if !accepted.contains(&staged) => PackageDrift::Pending(staged),
        _ => PackageDrift::Known,
    }
}

pub fn sui_event_into_session_request(
    packages_config: &IkaNetworkConfig,
    event_type: StructTag,
    contents: &[u8],
    pulled: bool,
) -> anyhow::Result<Option<DWalletSessionRequest>> {
    let accepted = accepted_dwallet_packages(packages_config);
    if !accepted.contains(&ObjectID::from(event_type.address))
        || event_type.module != SESSIONS_MANAGER_MODULE_NAME.into()
    {
        error!(
            module=?event_type.module,
            address=?event_type.address,
            ?accepted,
            "received an event from a wrong SUI module - rejecting! (if the address is an \
             unrecognised dwallet package, the chain upgraded and this binary needs its id — \
             see ika_dwallet_package_drift)"
        );
        return Err(anyhow::anyhow!(
            "received an event from a wrong SUI module - rejecting!"
        ));
    }
    if !event_type
        .to_string()
        .contains(&DWALLET_SESSION_EVENT_STRUCT_NAME.to_string())
    {
        info!("received an event that is not a DWalletSessionEvent - ignoring!",);
        return Ok(None);
    }

    let session_request = if event_type.to_string().contains(
        &DWalletImportedKeyVerificationRequestEvent::type_(packages_config)
            .name
            .to_string(),
    ) {
        dwallet_imported_key_verification_request_event_session_request(
            deserialize_event_contents::<DWalletImportedKeyVerificationRequestEvent>(
                contents, pulled,
            )?,
            pulled,
        )?
    } else if event_type.to_string().contains(
        &MakeDWalletUserSecretKeySharesPublicRequestEvent::type_(packages_config)
            .name
            .to_string(),
    ) {
        make_dwallet_user_secret_key_shares_public_request_event_session_request(
            deserialize_event_contents::<MakeDWalletUserSecretKeySharesPublicRequestEvent>(
                contents, pulled,
            )?,
            pulled,
        )?
    } else if event_type.to_string().contains(
        &DWalletDKGRequestEvent::type_(packages_config)
            .name
            .to_string(),
    ) {
        let parsed_event = deserialize_event_contents::<DWalletDKGRequestEvent>(contents, pulled)?;
        match &parsed_event.event_data.sign_during_dkg_request {
            None => dwallet_dkg_session_request(parsed_event, pulled)?,
            Some(sign_during_dkg_request) => dwallet_dkg_with_sign_session_request(
                parsed_event.clone(),
                pulled,
                sign_during_dkg_request,
            )?,
        }
    } else if event_type
        .to_string()
        .contains(&PresignRequestEvent::type_(packages_config).name.to_string())
    {
        let deserialized_event: DWalletSessionEvent<PresignRequestEvent> =
            deserialize_event_contents(contents, pulled)?;

        presign_party_session_request(deserialized_event, pulled)?
    } else if event_type.to_string().contains(
        &FutureSignRequestEvent::type_(packages_config)
            .name
            .to_string(),
    ) {
        let deserialized_event: DWalletSessionEvent<FutureSignRequestEvent> =
            deserialize_event_contents(contents, pulled)?;

        get_verify_partial_signatures_session_request(&deserialized_event, pulled)?
    } else if event_type
        .to_string()
        .contains(&SignRequestEvent::type_(packages_config).name.to_string())
    {
        let deserialized_event: DWalletSessionEvent<SignRequestEvent> =
            deserialize_event_contents(contents, pulled)?;

        sign_party_session_request(&deserialized_event, pulled)?
    } else if event_type.to_string().contains(
        &DWalletNetworkDKGEncryptionKeyRequestEvent::type_(packages_config)
            .name
            .to_string(),
    ) {
        let deserialized_event: DWalletSessionEvent<DWalletNetworkDKGEncryptionKeyRequestEvent> =
            deserialize_event_contents(contents, pulled)?;

        network_dkg_session_request(deserialized_event, pulled)?
    } else if event_type.to_string().contains(
        &DWalletEncryptionKeyReconfigurationRequestEvent::type_(packages_config)
            .name
            .to_string(),
    ) {
        let deserialized_event: DWalletSessionEvent<
            DWalletEncryptionKeyReconfigurationRequestEvent,
        > = deserialize_event_contents(contents, pulled)?;

        network_decryption_key_reconfiguration_session_request_from_event(
            deserialized_event,
            pulled,
        )?
    } else if event_type.to_string().contains(
        &EncryptedShareVerificationRequestEvent::type_(packages_config)
            .name
            .to_string(),
    ) {
        let deserialized_event: DWalletSessionEvent<EncryptedShareVerificationRequestEvent> =
            deserialize_event_contents(contents, pulled)?;

        start_encrypted_share_verification_session_request(deserialized_event, pulled)?
    } else {
        return Ok(None);
    };

    Ok(Some(session_request))
}

fn make_dwallet_user_secret_key_shares_public_request_event_session_request(
    deserialized_event: DWalletSessionEvent<MakeDWalletUserSecretKeySharesPublicRequestEvent>,
    pulled: bool,
) -> DwalletMPCResult<DWalletSessionRequest> {
    Ok(DWalletSessionRequest {
        counterparty_chain: Some(CounterpartyChainKind::Sui),
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: Some(deserialized_event.session_sequence_number),
        protocol_data: make_dwallet_user_secret_key_shares_public_protocol_data(
            deserialized_event.event_data.clone(),
        )?,
        epoch: deserialized_event.epoch,
        requires_network_key_data: true,
        requires_next_active_committee: false,
        pulled,
    })
}

fn dwallet_imported_key_verification_request_event_session_request(
    deserialized_event: DWalletSessionEvent<DWalletImportedKeyVerificationRequestEvent>,
    pulled: bool,
) -> DwalletMPCResult<DWalletSessionRequest> {
    Ok(DWalletSessionRequest {
        counterparty_chain: Some(CounterpartyChainKind::Sui),
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: Some(deserialized_event.session_sequence_number),
        protocol_data: imported_key_verification_protocol_data(
            deserialized_event.event_data.clone(),
        )?,
        epoch: deserialized_event.epoch,
        requires_network_key_data: true,
        requires_next_active_committee: false,
        pulled,
    })
}

fn dwallet_dkg_session_request(
    deserialized_event: DWalletSessionEvent<DWalletDKGRequestEvent>,
    pulled: bool,
) -> DwalletMPCResult<DWalletSessionRequest> {
    Ok(DWalletSessionRequest {
        counterparty_chain: Some(CounterpartyChainKind::Sui),
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: Some(deserialized_event.session_sequence_number),
        protocol_data: dwallet_dkg_protocol_data(
            deserialized_event.event_data.clone(),
            deserialized_event.event_data.user_secret_key_share,
        )?,
        epoch: deserialized_event.epoch,
        requires_network_key_data: true,
        requires_next_active_committee: false,
        pulled,
    })
}

fn dwallet_dkg_with_sign_session_request(
    deserialized_event: DWalletSessionEvent<DWalletDKGRequestEvent>,
    pulled: bool,
    sign_during_dkg_request: &SignDuringDKGRequestEvent,
) -> DwalletMPCResult<DWalletSessionRequest> {
    Ok(DWalletSessionRequest {
        counterparty_chain: Some(CounterpartyChainKind::Sui),
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: Some(deserialized_event.session_sequence_number),
        protocol_data: dwallet_dkg_and_sign_protocol_data(
            deserialized_event.event_data.clone(),
            deserialized_event.event_data.user_secret_key_share,
            sign_during_dkg_request,
        )?,
        epoch: deserialized_event.epoch,
        requires_network_key_data: true,
        requires_next_active_committee: false,
        pulled,
    })
}

fn presign_party_session_request(
    deserialized_event: DWalletSessionEvent<PresignRequestEvent>,
    pulled: bool,
) -> DwalletMPCResult<DWalletSessionRequest> {
    Ok(DWalletSessionRequest {
        counterparty_chain: Some(CounterpartyChainKind::Sui),
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: Some(deserialized_event.session_sequence_number),
        protocol_data: presign_protocol_data(deserialized_event.event_data.clone())?,
        epoch: deserialized_event.epoch,
        requires_network_key_data: true,
        requires_next_active_committee: false,
        pulled,
    })
}

fn sign_party_session_request(
    deserialized_event: &DWalletSessionEvent<SignRequestEvent>,
    pulled: bool,
) -> DwalletMPCResult<DWalletSessionRequest> {
    Ok(DWalletSessionRequest {
        counterparty_chain: Some(CounterpartyChainKind::Sui),
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: Some(deserialized_event.session_sequence_number),
        protocol_data: sign_protocol_data(deserialized_event.event_data.clone())?,
        epoch: deserialized_event.epoch,
        requires_network_key_data: true,
        requires_next_active_committee: false,
        pulled,
    })
}

fn get_verify_partial_signatures_session_request(
    deserialized_event: &DWalletSessionEvent<FutureSignRequestEvent>,
    pulled: bool,
) -> DwalletMPCResult<DWalletSessionRequest> {
    Ok(DWalletSessionRequest {
        counterparty_chain: Some(CounterpartyChainKind::Sui),
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: Some(deserialized_event.session_sequence_number),
        protocol_data: partial_signature_verification_protocol_data(
            deserialized_event.event_data.clone(),
        )?,
        epoch: deserialized_event.epoch,
        requires_network_key_data: true,
        requires_next_active_committee: false,
        pulled,
    })
}

fn network_dkg_session_request(
    deserialized_event: DWalletSessionEvent<DWalletNetworkDKGEncryptionKeyRequestEvent>,
    pulled: bool,
) -> DwalletMPCResult<DWalletSessionRequest> {
    Ok(DWalletSessionRequest {
        counterparty_chain: Some(CounterpartyChainKind::Sui),
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: Some(deserialized_event.session_sequence_number),
        protocol_data: network_encryption_key_dkg_protocol_data(
            deserialized_event.event_data.clone(),
        )?,
        epoch: deserialized_event.epoch,
        requires_network_key_data: false,
        requires_next_active_committee: false,
        pulled,
    })
}

fn network_decryption_key_reconfiguration_session_request_from_event(
    deserialized_event: DWalletSessionEvent<DWalletEncryptionKeyReconfigurationRequestEvent>,
    pulled: bool,
) -> DwalletMPCResult<DWalletSessionRequest> {
    Ok(DWalletSessionRequest {
        counterparty_chain: Some(CounterpartyChainKind::Sui),
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: Some(deserialized_event.session_sequence_number),
        protocol_data: network_encryption_key_reconfiguration_protocol_data(
            deserialized_event.event_data.clone(),
        )?,
        epoch: deserialized_event.epoch,
        requires_network_key_data: true,
        requires_next_active_committee: true,
        pulled,
    })
}

fn start_encrypted_share_verification_session_request(
    deserialized_event: DWalletSessionEvent<EncryptedShareVerificationRequestEvent>,
    pulled: bool,
) -> DwalletMPCResult<DWalletSessionRequest> {
    Ok(DWalletSessionRequest {
        counterparty_chain: Some(CounterpartyChainKind::Sui),
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: Some(deserialized_event.session_sequence_number),
        protocol_data: encrypted_share_verification_protocol_data(
            deserialized_event.event_data.clone(),
        )?,
        epoch: deserialized_event.epoch,
        requires_network_key_data: true,
        requires_next_active_committee: false,
        pulled,
    })
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
mod package_drift_tests {
    use super::*;

    fn cfg(v1: ObjectID, v2: Option<ObjectID>) -> IkaNetworkConfig {
        IkaNetworkConfig::new(
            ObjectID::random(),
            ObjectID::random(),
            v1,
            v2,
            ObjectID::random(),
            ObjectID::random(),
            ObjectID::random(),
        )
    }

    /// The set is a SET because a Sui upgrade leaves existing types on the
    /// original address while newly-defined types carry the upgrade address —
    /// both are live at once.
    #[test]
    fn accepted_set_contains_both_versions() {
        let (v1, v2) = (ObjectID::random(), ObjectID::random());
        let accepted = accepted_dwallet_packages(&cfg(v1, Some(v2)));
        assert_eq!(accepted, vec![v1, v2]);
    }

    #[test]
    fn accepted_set_is_just_v1_when_no_upgrade_is_configured() {
        let v1 = ObjectID::random();
        assert_eq!(accepted_dwallet_packages(&cfg(v1, None)), vec![v1]);
    }

    #[test]
    fn no_drift_when_the_chain_runs_a_package_we_accept() {
        let (v1, v2) = (ObjectID::random(), ObjectID::random());
        let config = cfg(v1, Some(v2));
        // Executing the upgrade we already know about, nothing staged.
        assert_eq!(
            detect_dwallet_package_drift(&config, v2, None),
            PackageDrift::Known
        );
        // Still on the original.
        assert_eq!(
            detect_dwallet_package_drift(&config, v1, None),
            PackageDrift::Known
        );
    }

    /// The live failure: the chain upgraded, this binary was never taught the
    /// new id, so every event type first defined in it fails the address
    /// filter and its sessions are lost.
    #[test]
    fn executing_an_unknown_package_is_drift() {
        let (v1, v2, v3) = (ObjectID::random(), ObjectID::random(), ObjectID::random());
        assert_eq!(
            detect_dwallet_package_drift(&cfg(v1, Some(v2)), v3, None),
            PackageDrift::Executing(v3)
        );
    }

    /// A staged upgrade is the lead time — nothing is dropped until it
    /// migrates, so it must be reported distinctly from the executing case.
    #[test]
    fn a_staged_unknown_upgrade_is_reported_as_pending() {
        let (v1, v2, v3) = (ObjectID::random(), ObjectID::random(), ObjectID::random());
        assert_eq!(
            detect_dwallet_package_drift(&cfg(v1, Some(v2)), v2, Some(v3)),
            PackageDrift::Pending(v3)
        );
    }

    /// Once the constant ships, the same staged id must stop being reported —
    /// otherwise the alert never clears and gets ignored.
    #[test]
    fn a_staged_upgrade_we_already_accept_is_not_drift() {
        let (v1, v2) = (ObjectID::random(), ObjectID::random());
        assert_eq!(
            detect_dwallet_package_drift(&cfg(v1, Some(v2)), v1, Some(v2)),
            PackageDrift::Known
        );
    }

    /// Executing-unknown outranks pending: the drop is happening now.
    #[test]
    fn executing_drift_takes_precedence_over_a_pending_one() {
        let (v1, v2, v3, v4) = (
            ObjectID::random(),
            ObjectID::random(),
            ObjectID::random(),
            ObjectID::random(),
        );
        assert_eq!(
            detect_dwallet_package_drift(&cfg(v1, Some(v2)), v3, Some(v4)),
            PackageDrift::Executing(v3)
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::sui_connector::sui_event_into_request::deserialize_event_contents;
    use ika_types::messages_dwallet_mpc::{
        DWalletDKGFirstRoundRequestEvent, DWalletNetworkDKGEncryptionKeyRequestEvent,
        test_helpers::new_dwallet_session_event,
    };
    use sui_types::base_types::ObjectID;
    use sui_types::dynamic_field::Field;
    use sui_types::id::{ID, UID};

    #[test]
    fn deserializes_pushed_event() {
        let event = new_dwallet_session_event(
            false,
            5,
            vec![42; 32],
            DWalletDKGFirstRoundRequestEvent {
                dwallet_id: ObjectID::random(),
                dwallet_cap_id: ObjectID::random(),
                dwallet_network_encryption_key_id: ObjectID::random(),
                curve: 0,
            },
        );
        let contents = bcs::to_bytes(&event).expect("should serialize pushed event");

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
        let event = new_dwallet_session_event(
            true,
            1,
            vec![42; 32],
            DWalletNetworkDKGEncryptionKeyRequestEvent {
                dwallet_network_encryption_key_id: ObjectID::random(),
                params_for_network: vec![1, 2, 3],
            },
        );
        let field = Field {
            id: UID {
                id: ID {
                    bytes: ObjectID::random(),
                },
            },
            name: ID {
                bytes: ObjectID::random(),
            },
            value: event,
        };
        let contents = bcs::to_bytes(&field).expect("should serialize pulled event");

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
