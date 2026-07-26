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

/// Introducing versions the compiled-in constants do NOT cover.
///
/// `introducing_versions` is the chain's own answer to "which addresses can a
/// type from this package carry" — the distinct packages in its `TypeOrigin`
/// table (see `OcsVerifiedReader::verified_package_type_origins`). A type's
/// address is fixed at the version that first defined it, so this set is exact:
/// anything in it that the binary does not accept is an address whose events
/// are being dropped, and anything the binary accepts beyond it is merely
/// unused.
///
/// Comparing against the chain's *executing* version instead would only be a
/// proxy — it false-positives on an upgrade that introduces no new types, and
/// says nothing about which addresses actually appear.
pub fn uncovered_introducing_versions(
    packages_config: &IkaNetworkConfig,
    introducing_versions: &[ObjectID],
) -> Vec<ObjectID> {
    let accepted = accepted_dwallet_packages(packages_config);
    introducing_versions
        .iter()
        .filter(|id| !accepted.contains(id))
        .copied()
        .collect()
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
             see ika_dwallet_uncovered_introducing_versions)"
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
mod package_coverage_tests {
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

    /// The accepted set is a SET because a Move type's address is fixed at the
    /// version that first introduced it — so an upgraded package's types are
    /// spread across every introducing version, all of them live at once.
    #[test]
    fn accepted_set_contains_both_versions() {
        let (v1, v2) = (ObjectID::random(), ObjectID::random());
        assert_eq!(accepted_dwallet_packages(&cfg(v1, Some(v2))), vec![v1, v2]);
    }

    #[test]
    fn accepted_set_is_just_v1_when_no_upgrade_is_configured() {
        let v1 = ObjectID::random();
        assert_eq!(accepted_dwallet_packages(&cfg(v1, None)), vec![v1]);
    }

    /// The shape on both live networks today: the chain introduces types at v1
    /// and v2, and the binary accepts exactly those.
    #[test]
    fn fully_covered_introducing_versions_report_nothing() {
        let (v1, v2) = (ObjectID::random(), ObjectID::random());
        assert!(
            uncovered_introducing_versions(&cfg(v1, Some(v2)), &[v1, v2]).is_empty(),
            "accepting every introducing version must report no gap"
        );
    }

    /// The live failure: the chain introduced types at a version the binary was
    /// never taught, so every event type introduced there is dropped.
    #[test]
    fn an_unaccepted_introducing_version_is_reported() {
        let (v1, v2, v3) = (ObjectID::random(), ObjectID::random(), ObjectID::random());
        assert_eq!(
            uncovered_introducing_versions(&cfg(v1, Some(v2)), &[v1, v2, v3]),
            vec![v3]
        );
    }

    /// Multiple upgrades can each introduce types; all uncovered ones must be
    /// named, not just the newest, so one release can carry them together.
    #[test]
    fn every_uncovered_version_is_reported() {
        let (v1, v2, v3, v4) = (
            ObjectID::random(),
            ObjectID::random(),
            ObjectID::random(),
            ObjectID::random(),
        );
        assert_eq!(
            uncovered_introducing_versions(&cfg(v1, None), &[v1, v2, v3, v4]),
            vec![v2, v3, v4]
        );
    }

    /// Accepting MORE than the chain introduces is harmless — an unused
    /// constant drops nothing — so it must not be reported as a gap. This is
    /// what makes the signal actionable rather than noisy.
    #[test]
    fn accepting_more_than_the_chain_introduces_is_not_a_gap() {
        let (v1, v2) = (ObjectID::random(), ObjectID::random());
        assert!(
            uncovered_introducing_versions(&cfg(v1, Some(v2)), &[v1]).is_empty(),
            "an accepted-but-unused version is not a coverage gap"
        );
    }

    /// Once the release ships the missing id, the gap must clear — an alert
    /// that never clears gets ignored.
    #[test]
    fn the_gap_clears_once_the_id_is_accepted() {
        let (v1, v2, v3) = (ObjectID::random(), ObjectID::random(), ObjectID::random());
        let introducing = [v1, v2, v3];
        assert_eq!(
            uncovered_introducing_versions(&cfg(v1, Some(v2)), &introducing),
            vec![v3]
        );
        // ...ship v3 as the configured upgrade id:
        assert!(uncovered_introducing_versions(&cfg(v1, Some(v3)), &[v1, v3]).is_empty());
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
