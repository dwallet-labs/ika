use crate::dwallet_session_request::DWalletSessionRequest;
use crate::request_protocol_data::{
    dwallet_dkg_first_protocol_data, dwallet_dkg_second_protocol_data,
    encrypted_share_verification_protocol_data, imported_key_verification_protocol_data,
    make_dwallet_user_secret_key_shares_public_protocol_data,
    network_encryption_key_dkg_protocol_data, network_encryption_key_reconfiguration_protocol_data,
    partial_signature_verification_protocol_data, presign_protocol_data, sign_protocol_data,
};
use dwallet_mpc_types::dwallet_mpc::DWalletMPCNetworkKeyScheme;
use ika_types::dwallet_mpc_error::DwalletMPCResult;
use ika_types::messages_dwallet_mpc::{
    DWalletDKGFirstRoundRequestEvent, DWalletDKGSecondRoundRequestEvent,
    DWalletEncryptionKeyReconfigurationRequestEvent, DWalletImportedKeyVerificationRequestEvent,
    DWalletNetworkDKGEncryptionKeyRequestEvent, DWalletSessionEvent, DWalletSessionEventTrait,
    EncryptedShareVerificationRequestEvent, FutureSignRequestEvent, IkaNetworkConfig,
    MakeDWalletUserSecretKeySharesPublicRequestEvent, PresignRequestEvent,
    SESSIONS_MANAGER_MODULE_NAME, SignRequestEvent,
};
use move_core_types::language_storage::StructTag;
use serde::de::DeserializeOwned;
use sui_types::dynamic_field::Field;
use sui_types::id::ID;
use tracing::error;

pub fn sui_event_into_session_request(
    packages_config: &IkaNetworkConfig,
    event_type: StructTag,
    contents: &[u8],
    pulled: bool,
) -> anyhow::Result<Option<DWalletSessionRequest>> {
    if event_type.address != *packages_config.packages.ika_dwallet_2pc_mpc_package_id
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

    let session_request = if event_type
        == DWalletSessionEvent::<DWalletImportedKeyVerificationRequestEvent>::type_(packages_config)
    {
        dwallet_imported_key_verification_request_event_session_request(
            deserialize_event_contents::<DWalletImportedKeyVerificationRequestEvent>(
                &contents, pulled,
            )?,
            pulled,
        )?
    } else if event_type
        == DWalletSessionEvent::<MakeDWalletUserSecretKeySharesPublicRequestEvent>::type_(
            packages_config,
        )
    {
        make_dwallet_user_secret_key_shares_public_request_event_session_request(
            deserialize_event_contents::<MakeDWalletUserSecretKeySharesPublicRequestEvent>(
                &contents, pulled,
            )?,
            pulled,
        )?
    } else if event_type
        == DWalletSessionEvent::<DWalletDKGFirstRoundRequestEvent>::type_(packages_config)
    {
        dwallet_dkg_first_party_session_request(
            deserialize_event_contents::<DWalletDKGFirstRoundRequestEvent>(&contents, pulled)?,
            pulled,
        )?
    } else if event_type
        == DWalletSessionEvent::<DWalletDKGSecondRoundRequestEvent>::type_(packages_config)
    {
        dwallet_dkg_second_party_session_request(
            deserialize_event_contents::<DWalletDKGSecondRoundRequestEvent>(&contents, pulled)?,
            pulled,
        )?
    } else if event_type == DWalletSessionEvent::<PresignRequestEvent>::type_(packages_config) {
        let deserialized_event: DWalletSessionEvent<PresignRequestEvent> =
            deserialize_event_contents(&contents, pulled)?;

        presign_party_session_request(deserialized_event, pulled)?
    } else if event_type == DWalletSessionEvent::<SignRequestEvent>::type_(packages_config) {
        let deserialized_event: DWalletSessionEvent<SignRequestEvent> =
            deserialize_event_contents(&contents, pulled)?;

        sign_party_session_request(&deserialized_event, pulled)?
    } else if event_type == DWalletSessionEvent::<FutureSignRequestEvent>::type_(packages_config) {
        let deserialized_event: DWalletSessionEvent<FutureSignRequestEvent> =
            deserialize_event_contents(&contents, pulled)?;

        get_verify_partial_signatures_session_request(&deserialized_event, pulled)?
    } else if event_type
        == DWalletSessionEvent::<DWalletNetworkDKGEncryptionKeyRequestEvent>::type_(packages_config)
    {
        let deserialized_event: DWalletSessionEvent<DWalletNetworkDKGEncryptionKeyRequestEvent> =
            deserialize_event_contents(&contents, pulled)?;

        network_dkg_session_request(
            deserialized_event,
            DWalletMPCNetworkKeyScheme::Secp256k1,
            pulled,
        )?
    } else if event_type
        == DWalletSessionEvent::<DWalletEncryptionKeyReconfigurationRequestEvent>::type_(
            packages_config,
        )
    {
        let deserialized_event: DWalletSessionEvent<
            DWalletEncryptionKeyReconfigurationRequestEvent,
        > = deserialize_event_contents(&contents, pulled)?;

        network_decryption_key_reconfiguration_session_request_from_event(
            deserialized_event,
            pulled,
        )?
    } else if event_type
        == DWalletSessionEvent::<EncryptedShareVerificationRequestEvent>::type_(packages_config)
    {
        let deserialized_event: DWalletSessionEvent<EncryptedShareVerificationRequestEvent> =
            deserialize_event_contents(&contents, pulled)?;

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
        session_src: deserialized_event.session_type,
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
        session_src: deserialized_event.session_type,
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

fn dwallet_dkg_first_party_session_request(
    deserialized_event: DWalletSessionEvent<DWalletDKGFirstRoundRequestEvent>,
    pulled: bool,
) -> DwalletMPCResult<DWalletSessionRequest> {
    Ok(DWalletSessionRequest {
        session_src: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: deserialized_event.session_sequence_number,
        protocol_data: dwallet_dkg_first_protocol_data(deserialized_event.event_data.clone())?,
        epoch: deserialized_event.epoch,
        requires_network_key_data: true,
        requires_next_active_committee: false,
        pulled,
    })
}

fn dwallet_dkg_second_party_session_request(
    deserialized_event: DWalletSessionEvent<DWalletDKGSecondRoundRequestEvent>,
    pulled: bool,
) -> DwalletMPCResult<DWalletSessionRequest> {
    Ok(DWalletSessionRequest {
        session_src: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: deserialized_event.session_sequence_number,
        protocol_data: dwallet_dkg_second_protocol_data(deserialized_event.event_data.clone())?,
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
        session_src: deserialized_event.session_type,
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
        session_src: deserialized_event.session_type,
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
        session_src: deserialized_event.session_type,
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
    key_scheme: DWalletMPCNetworkKeyScheme,
    pulled: bool,
) -> DwalletMPCResult<DWalletSessionRequest> {
    match key_scheme {
        DWalletMPCNetworkKeyScheme::Secp256k1 => {
            network_dkg_secp256k1_session_request(deserialized_event, pulled)
        }
        DWalletMPCNetworkKeyScheme::Ristretto => {
            network_dkg_ristretto_session_request(deserialized_event, pulled)
        }
    }
}

fn network_dkg_secp256k1_session_request(
    deserialized_event: DWalletSessionEvent<DWalletNetworkDKGEncryptionKeyRequestEvent>,
    pulled: bool,
) -> DwalletMPCResult<DWalletSessionRequest> {
    Ok(DWalletSessionRequest {
        session_src: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: deserialized_event.session_sequence_number,
        protocol_data: network_encryption_key_dkg_protocol_data(
            DWalletMPCNetworkKeyScheme::Secp256k1,
            deserialized_event.event_data.clone(),
        )?,
        epoch: deserialized_event.epoch,
        requires_network_key_data: false,
        requires_next_active_committee: false,
        pulled,
    })
}

fn network_dkg_ristretto_session_request(
    deserialized_event: DWalletSessionEvent<DWalletNetworkDKGEncryptionKeyRequestEvent>,
    pulled: bool,
) -> DwalletMPCResult<DWalletSessionRequest> {
    Ok(DWalletSessionRequest {
        session_src: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: deserialized_event.session_sequence_number,
        protocol_data: network_encryption_key_dkg_protocol_data(
            DWalletMPCNetworkKeyScheme::Ristretto,
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
        session_src: deserialized_event.session_type,
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
        session_src: deserialized_event.session_type,
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
    };

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
