use crate::dwallet_mpc::protocol_cryptographic_data::ProtocolCryptographicData;
use crate::request_protocol_data::ProtocolData;
use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, DWalletSignatureAlgorithm};
use group::HashScheme;
use ika_types::messages_dwallet_mpc::{SessionIdentifier, SessionType};
use std::cmp::Ordering;
use std::fmt;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DWalletSessionRequest {
    pub session_type: SessionType,
    /// Unique identifier for the MPC session.
    pub session_identifier: SessionIdentifier,
    pub session_sequence_number: u64,
    pub(crate) protocol_data: ProtocolData,
    pub epoch: u64,
    pub requires_network_key_data: bool,
    pub requires_next_active_committee: bool,
    // True when the event was pulled from the state of the object,
    // and False when it was pushed as an event.
    pub pulled: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DWalletSessionRequestMetricData {
    name: String,
    curve: Option<DWalletCurve>,
    hash_scheme: Option<HashScheme>,
    signature_algorithm: Option<DWalletSignatureAlgorithm>,
}

impl fmt::Display for DWalletSessionRequestMetricData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl PartialOrd<Self> for DWalletSessionRequest {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DWalletSessionRequest {
    fn cmp(&self, other: &Self) -> Ordering {
        // System sessions have a higher priority than user session and therefore come first (are smaller).
        // Both system and user sessions are sorted by their sequence number between themselves.
        match (self.session_type, other.session_type) {
            (SessionType::User, SessionType::User) => self
                .session_sequence_number
                .cmp(&other.session_sequence_number),
            (SessionType::System, SessionType::User) => Ordering::Less,
            (SessionType::System, SessionType::System) => self
                .session_sequence_number
                .cmp(&other.session_sequence_number),
            (SessionType::User, SessionType::System) => Ordering::Greater,
        }
    }
}

impl DWalletSessionRequestMetricData {
    pub fn curve(&self) -> String {
        let Some(curve) = self.curve else {
            return "Unknown".to_string();
        };
        curve.to_string()
    }

    pub fn hash_scheme(&self) -> String {
        let Some(hash_scheme) = &self.hash_scheme else {
            return "Unknown".to_string();
        };
        hash_scheme.to_string()
    }

    pub fn signature_algorithm(&self) -> String {
        let Some(signature_algorithm) = &self.signature_algorithm else {
            return "Unknown".to_string();
        };
        signature_algorithm.to_string()
    }
}

impl From<&ProtocolData> for DWalletSessionRequestMetricData {
    fn from(protocol_specific_data: &ProtocolData) -> Self {
        match protocol_specific_data {
            ProtocolData::DWalletDKG { data, .. } => DWalletSessionRequestMetricData {
                name: data.to_string(),
                curve: Some(data.curve),
                hash_scheme: None,
                signature_algorithm: None,
            },
            ProtocolData::DWalletDKGAndSign { data, .. } => DWalletSessionRequestMetricData {
                name: data.to_string(),
                curve: Some(data.curve),
                hash_scheme: Some(data.hash_scheme),
                signature_algorithm: Some(data.signature_algorithm),
            },
            ProtocolData::ImportedKeyVerification { data, .. } => DWalletSessionRequestMetricData {
                name: data.to_string(),
                curve: Some(data.curve),
                hash_scheme: None,
                signature_algorithm: None,
            },
            ProtocolData::MakeDWalletUserSecretKeySharesPublic { data, .. } => {
                DWalletSessionRequestMetricData {
                    name: data.to_string(),
                    curve: Some(data.curve),
                    hash_scheme: None,
                    signature_algorithm: None,
                }
            }
            ProtocolData::DKGFirst { data, .. } => DWalletSessionRequestMetricData {
                name: data.to_string(),
                curve: Some(data.curve),
                hash_scheme: None,
                signature_algorithm: None,
            },
            ProtocolData::DKGSecond { data, .. } => DWalletSessionRequestMetricData {
                name: data.to_string(),
                curve: Some(data.curve),
                hash_scheme: None,
                signature_algorithm: None,
            },
            ProtocolData::Presign { data, .. } => DWalletSessionRequestMetricData {
                name: data.to_string(),
                curve: Some(data.curve),
                hash_scheme: None,
                signature_algorithm: Some(data.signature_algorithm),
            },
            ProtocolData::Sign { data, .. } => DWalletSessionRequestMetricData {
                name: data.to_string(),
                curve: Some(data.curve),
                hash_scheme: Some(data.hash_scheme),
                signature_algorithm: Some(data.signature_algorithm),
            },
            ProtocolData::NetworkEncryptionKeyDkg { data, .. } => DWalletSessionRequestMetricData {
                name: data.to_string(),
                curve: None,
                hash_scheme: None,
                signature_algorithm: None,
            },
            ProtocolData::NetworkEncryptionKeyReconfiguration { data, .. } => {
                DWalletSessionRequestMetricData {
                    name: data.to_string(),
                    curve: None,
                    hash_scheme: None,
                    signature_algorithm: None,
                }
            }
            ProtocolData::EncryptedShareVerification { data, .. } => {
                DWalletSessionRequestMetricData {
                    name: data.to_string(),
                    curve: Some(data.curve),
                    hash_scheme: None,
                    signature_algorithm: None,
                }
            }
            ProtocolData::PartialSignatureVerification { data, .. } => {
                DWalletSessionRequestMetricData {
                    name: data.to_string(),
                    curve: Some(data.curve),
                    hash_scheme: Some(data.hash_scheme),
                    signature_algorithm: Some(data.signature_algorithm),
                }
            }
        }
    }
}

impl From<&ProtocolCryptographicData> for DWalletSessionRequestMetricData {
    fn from(advance_specific_data: &ProtocolCryptographicData) -> Self {
        match advance_specific_data {
            ProtocolCryptographicData::ImportedKeyVerification { data, .. } => {
                DWalletSessionRequestMetricData {
                    name: data.to_string(),
                    curve: Some(data.curve),
                    hash_scheme: None,
                    signature_algorithm: None,
                }
            }
            ProtocolCryptographicData::MakeDWalletUserSecretKeySharesPublic { data, .. } => {
                DWalletSessionRequestMetricData {
                    name: data.to_string(),
                    curve: Some(data.curve),
                    hash_scheme: None,
                    signature_algorithm: None,
                }
            }
            ProtocolCryptographicData::DKGFirst { data, .. } => DWalletSessionRequestMetricData {
                name: data.to_string(),
                curve: Some(data.curve),
                hash_scheme: None,
                signature_algorithm: None,
            },
            ProtocolCryptographicData::DKGSecond { data, .. } => DWalletSessionRequestMetricData {
                name: data.to_string(),
                curve: Some(data.curve),
                hash_scheme: None,
                signature_algorithm: None,
            },
            ProtocolCryptographicData::DWalletDKG { data, .. } => DWalletSessionRequestMetricData {
                name: data.to_string(),
                curve: Some(data.curve),
                hash_scheme: None,
                signature_algorithm: None,
            },
            ProtocolCryptographicData::Presign { data, .. } => DWalletSessionRequestMetricData {
                name: data.to_string(),
                curve: Some(data.curve),
                hash_scheme: None,
                signature_algorithm: Some(data.signature_algorithm),
            },
            ProtocolCryptographicData::Sign { data, .. } => DWalletSessionRequestMetricData {
                name: data.to_string(),
                curve: Some(data.curve),
                hash_scheme: Some(data.hash_scheme),
                signature_algorithm: Some(data.signature_algorithm),
            },
            ProtocolCryptographicData::DWalletDKGAndSign { data, .. } => {
                DWalletSessionRequestMetricData {
                    name: data.to_string(),
                    curve: Some(data.curve),
                    hash_scheme: Some(data.hash_scheme),
                    signature_algorithm: Some(data.signature_algorithm),
                }
            }
            ProtocolCryptographicData::NetworkEncryptionKeyDkgV1 { data, .. } => {
                // TODO (#1508): Remove the curve label completely from protocols the curve label is irrelevant for
                DWalletSessionRequestMetricData {
                    name: data.to_string(),
                    curve: None,
                    hash_scheme: None,
                    signature_algorithm: None,
                }
            }
            ProtocolCryptographicData::NetworkEncryptionKeyV1Reconfiguration { data, .. } => {
                DWalletSessionRequestMetricData {
                    name: data.to_string(),
                    curve: None,
                    hash_scheme: None,
                    signature_algorithm: None,
                }
            }
            ProtocolCryptographicData::EncryptedShareVerification { data, .. } => {
                DWalletSessionRequestMetricData {
                    name: data.to_string(),
                    curve: Some(data.curve),
                    hash_scheme: None,
                    signature_algorithm: None,
                }
            }
            ProtocolCryptographicData::PartialSignatureVerification { data, .. } => {
                DWalletSessionRequestMetricData {
                    name: data.to_string(),
                    curve: Some(data.curve),
                    hash_scheme: Some(data.hash_scheme),
                    signature_algorithm: Some(data.signature_algorithm),
                }
            }
            ProtocolCryptographicData::NetworkEncryptionKeyV1ToV2Reconfiguration {
                data, ..
            } => DWalletSessionRequestMetricData {
                name: data.to_string(),
                curve: None,
                hash_scheme: None,
                signature_algorithm: None,
            },
            ProtocolCryptographicData::NetworkEncryptionKeyV2Reconfiguration { data, .. } => {
                DWalletSessionRequestMetricData {
                    name: data.to_string(),
                    // TODO (#1491): Set curve, hash scheme & signature algorithm metrics fields for each protocol
                    curve: None,
                    hash_scheme: None,
                    signature_algorithm: None,
                }
            }
            ProtocolCryptographicData::NetworkEncryptionKeyDkgV2 { .. } => {
                DWalletSessionRequestMetricData {
                    name: "NetworkEncryptionKeyDkgV2".to_string(),
                    // TODO (#1491): Set curve, hash scheme & signature algorithm metrics fields for each protocol
                    curve: None,
                    hash_scheme: None,
                    signature_algorithm: None,
                }
            }
        }
    }
}
