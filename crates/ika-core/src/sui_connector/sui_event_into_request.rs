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
use move_core_types::language_storage::StructTag;
use serde::de::DeserializeOwned;
use sui_types::dynamic_field::Field;
use sui_types::id::ID;
use tracing::{error, info};

pub fn sui_event_into_session_request(
    packages_config: &IkaNetworkConfig,
    event_type: StructTag,
    contents: &[u8],
    pulled: bool,
) -> anyhow::Result<Option<DWalletSessionRequest>> {
    if (event_type.address != *packages_config.packages.ika_dwallet_2pc_mpc_package_id
        && (packages_config
            .packages
            .ika_dwallet_2pc_mpc_package_id_v2
            .is_none()
            || event_type.address
                != *packages_config
                    .packages
                    .ika_dwallet_2pc_mpc_package_id_v2
                    .unwrap()))
        || event_type.module != SESSIONS_MANAGER_MODULE_NAME.into()
    {
        error!(
            module=?event_type.module,
            address=?event_type.address,
            "received an event from a wrong SUI module - rejecting!"
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
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: deserialized_event.session_sequence_number,
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
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: deserialized_event.session_sequence_number,
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
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: deserialized_event.session_sequence_number,
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
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: deserialized_event.session_sequence_number,
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
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: deserialized_event.session_sequence_number,
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
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: deserialized_event.session_sequence_number,
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
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: deserialized_event.session_sequence_number,
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
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: deserialized_event.session_sequence_number,
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
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: deserialized_event.session_sequence_number,
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
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: deserialized_event.session_sequence_number,
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
