use base64::{Engine as _, engine::general_purpose::STANDARD};
use dwallet_mpc_types::dwallet_mpc::VersionedMPCData;
use ika_types::crypto::{AuthorityPublicKeyBytes, AuthoritySignature, NetworkPublicKey};
use serde::{Deserialize, Serialize};
use sui_types::base_types::SuiAddress;
use sui_types::multiaddr::Multiaddr;

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub name: String,
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    pub mpc_data: VersionedMPCData,
    pub account_address: SuiAddress,
    pub protocol_public_key: AuthorityPublicKeyBytes,
    pub consensus_public_key: NetworkPublicKey,
    pub network_public_key: NetworkPublicKey,
    pub network_address: Multiaddr,
    pub computation_price: u64,
    pub commission_rate: u16,
    pub p2p_address: Multiaddr,
    // keep only current and call it consensus_address
    pub consensus_address: Multiaddr,
    pub description: String,
    pub image_url: String,
    pub project_url: String,
    pub proof_of_possession: AuthoritySignature,
}

impl ValidatorInfo {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn sui_address(&self) -> SuiAddress {
        self.account_address
    }

    pub fn protocol_public_key(&self) -> AuthorityPublicKeyBytes {
        self.protocol_public_key
    }

    pub fn worker_public_key(&self) -> &NetworkPublicKey {
        &self.consensus_public_key
    }

    pub fn network_public_key(&self) -> &NetworkPublicKey {
        &self.network_public_key
    }

    pub fn network_address(&self) -> &Multiaddr {
        &self.network_address
    }
    pub fn proof_of_possession(&self) -> &AuthoritySignature {
        &self.proof_of_possession
    }
}

fn as_base64<S>(bytes: &VersionedMPCData, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let encoded = STANDARD.encode(bcs::to_bytes(&bytes).map_err(serde::ser::Error::custom)?);
    serializer.serialize_str(&encoded)
}

fn from_base64<'de, D>(deserializer: D) -> Result<VersionedMPCData, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let base64_str: String = Deserialize::deserialize(deserializer)?;
    bcs::from_bytes(
        &STANDARD
            .decode(&base64_str)
            .map_err(serde::de::Error::custom)?,
    )
    .map_err(serde::de::Error::custom)
}
