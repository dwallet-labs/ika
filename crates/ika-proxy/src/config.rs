// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear
use anyhow::{Context, Result};
use core::time::Duration;
use ika_config::node::{
    IkaIdentityOverride, SuiChainIdentifier, SuiGrpcHeaders, compiled_in_ika_identity,
};
use ika_types::messages_dwallet_mpc::{IkaNetworkConfig, IkaObjectsConfig, IkaPackageConfig};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_with::{DurationSeconds, serde_as};
use std::net::SocketAddr;
use sui_types::base_types::ObjectID;
use tracing::debug;

// todo(zeev): change defaults here.

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProxyConfig {
    pub network: String,
    pub listen_address: SocketAddr,
    pub remote_write: RemoteWriteConfig,
    pub dynamic_peers: DynamicPeerValidationConfig,
    pub static_peers: Option<StaticPeerValidationConfig>,
    pub metrics_address: String,
    pub histogram_address: String,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RemoteWriteConfig {
    /// the remote_write url to post data to
    #[serde(default = "remote_write_url")]
    pub url: String,
    /// username is used for posting data to the remote_write api
    pub username: String,
    pub password: String,

    /// Sets the maximum idle connection per host allowed in the pool.
    /// <https://docs.rs/reqwest/latest/reqwest/struct.ClientBuilder.html#method.pool_max_idle_per_host>
    #[serde(default = "pool_max_idle_per_host_default")]
    pub pool_max_idle_per_host: usize,
}

/// Controls which Ika validators the proxy accepts. Committee membership is
/// refreshed from a Sui fullnode over gRPC.
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DynamicPeerValidationConfig {
    /// Sui gRPC URL used to obtain valid peers on the blockchain.
    pub grpc_url: String,
    /// Metadata attached to every request sent to the gRPC endpoint.
    #[serde(default, skip_serializing_if = "SuiGrpcHeaders::is_empty")]
    pub headers: SuiGrpcHeaders,
    /// The expected Sui chain. Mainnet and Testnet select the compiled-in Ika
    /// package and object IDs.
    pub sui_chain_identifier: SuiChainIdentifier,
    /// Ika's on-chain identity for Devnet, Custom, and local networks, whose
    /// package and object IDs are created with genesis. This has the same
    /// safety semantics as validator/notifier configuration: it is required
    /// when no compiled-in identity exists and rejected on Mainnet/Testnet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ika_unsafe_identity_override: Option<IkaIdentityOverride>,
    #[serde_as(as = "DurationSeconds<u64>")]
    pub interval: Duration,
    /// if certificate_file and private_key are not provided, we'll create a self-signed
    /// cert using this hostname
    #[serde(default = "hostname_default")]
    pub hostname: Option<String>,

    /// incoming client connections to this proxy will be presented with this pub key
    /// please use an absolute path
    pub certificate_file: Option<String>,
    /// private key for tls
    /// please use an absolute path
    pub private_key: Option<String>,
}

impl DynamicPeerValidationConfig {
    /// Resolve the chain-specific Ika package/object IDs into the form used by
    /// the gRPC Sui client.
    pub fn ika_network_config(&self) -> Result<IkaNetworkConfig> {
        let (
            ika_package_id,
            ika_common_package_id,
            ika_dwallet_2pc_mpc_package_id,
            ika_dwallet_2pc_mpc_package_id_v2,
            ika_system_package_id,
            ika_system_object_id,
            ika_dwallet_coordinator_object_id,
        ) = match compiled_in_ika_identity(self.sui_chain_identifier) {
            Some(identity) => {
                if self.ika_unsafe_identity_override.is_some() {
                    anyhow::bail!(
                        "dynamic-peers.ika-unsafe-identity-override is set, but chain {} has a \
                         compiled-in Ika identity; overriding it on a public chain is not \
                         supported",
                        self.sui_chain_identifier
                    );
                }
                (
                    identity.ika_package_id,
                    identity.ika_common_package_id,
                    identity.ika_dwallet_2pc_mpc_package_id,
                    Some(identity.ika_dwallet_2pc_mpc_package_id_v2),
                    identity.ika_system_package_id,
                    identity.ika_system_object_id,
                    identity.ika_dwallet_coordinator_object_id,
                )
            }
            None => {
                let Some(identity) = self.ika_unsafe_identity_override else {
                    anyhow::bail!(
                        "chain {} has no compiled-in Ika identity; set \
                         dynamic-peers.ika-unsafe-identity-override with the chain's package \
                         and object IDs",
                        self.sui_chain_identifier
                    );
                };
                (
                    identity.ika_package_id,
                    identity.ika_common_package_id,
                    identity.ika_dwallet_2pc_mpc_package_id,
                    identity.ika_dwallet_2pc_mpc_package_id_v2,
                    identity.ika_system_package_id,
                    identity.ika_system_object_id,
                    identity.ika_dwallet_coordinator_object_id,
                )
            }
        };

        for (name, value) in [
            ("ika-package-id", ika_package_id),
            ("ika-common-package-id", ika_common_package_id),
            (
                "ika-dwallet-2pc-mpc-package-id",
                ika_dwallet_2pc_mpc_package_id,
            ),
            ("ika-system-package-id", ika_system_package_id),
            ("ika-system-object-id", ika_system_object_id),
            (
                "ika-dwallet-coordinator-object-id",
                ika_dwallet_coordinator_object_id,
            ),
        ] {
            if value == ObjectID::ZERO {
                anyhow::bail!(
                    "dynamic-peers.ika-unsafe-identity-override.{name} is the ZERO object ID"
                );
            }
        }

        Ok(IkaNetworkConfig {
            packages: IkaPackageConfig {
                ika_package_id,
                ika_common_package_id,
                ika_dwallet_2pc_mpc_package_id,
                ika_dwallet_2pc_mpc_package_id_v2,
                ika_system_package_id,
            },
            objects: IkaObjectsConfig {
                ika_system_object_id,
                ika_dwallet_coordinator_object_id,
            },
        })
    }
}

/// Unlike dynamic validation, static validation uses configured public keys.
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct StaticPeerValidationConfig {
    pub pub_keys: Vec<StaticPubKey>,
}

/// StaticPubKey holds a human friendly name, ip and the key file for the pub key
/// if you don't have a valid public routable ip, use an ip from 169.254.0.0/16.
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct StaticPubKey {
    /// friendly name we will see in metrics
    pub name: String,
    /// the peer_id from a node config file (Ed25519 PublicKey)
    pub peer_id: String,
}

/// the default idle worker per host (reqwest to remote write url call)
fn pool_max_idle_per_host_default() -> usize {
    8
}

/// the default hostname we will use if not provided
fn hostname_default() -> Option<String> {
    Some("localhost".to_string())
}

/// the default remote write url
fn remote_write_url() -> String {
    "http://metrics-gw.testnet.sui.io/api/v1/push".to_string()
}

/// load our config file from a path
pub fn load<P: AsRef<std::path::Path>, T: DeserializeOwned + Serialize>(path: P) -> Result<T> {
    let path = path.as_ref();
    debug!("Reading config from {:?}", path);
    Ok(serde_yaml::from_reader(
        std::fs::File::open(path).context(format!("cannot open {:?}", path))?,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn config_load() {
        const TEMPLATE: &str = include_str!("./data/config.yaml");

        let template: ProxyConfig = serde_yaml::from_str(TEMPLATE).unwrap();
        template.dynamic_peers.ika_network_config().unwrap();
    }

    #[test]
    fn public_chain_uses_compiled_in_identity() {
        const TEMPLATE: &str = include_str!("./data/config.yaml");

        let mut template: ProxyConfig = serde_yaml::from_str(TEMPLATE).unwrap();
        template.dynamic_peers.sui_chain_identifier = SuiChainIdentifier::Mainnet;
        template.dynamic_peers.ika_unsafe_identity_override = None;

        let resolved = template.dynamic_peers.ika_network_config().unwrap();
        let expected = compiled_in_ika_identity(SuiChainIdentifier::Mainnet).unwrap();
        assert_eq!(resolved.packages.ika_package_id, expected.ika_package_id);
        assert_eq!(
            resolved.objects.ika_system_object_id,
            expected.ika_system_object_id
        );

        template.dynamic_peers.ika_unsafe_identity_override = Some(
            serde_yaml::from_str(
                "ika-package-id: '0x1'\n\
                 ika-common-package-id: '0x2'\n\
                 ika-dwallet-2pc-mpc-package-id: '0x3'\n\
                 ika-system-package-id: '0x4'\n\
                 ika-system-object-id: '0x5'\n\
                 ika-dwallet-coordinator-object-id: '0x6'\n",
            )
            .unwrap(),
        );
        assert!(
            template
                .dynamic_peers
                .ika_network_config()
                .unwrap_err()
                .to_string()
                .contains("overriding it on a public chain is not supported")
        );
    }

    #[test]
    fn custom_chain_requires_a_nonzero_override() {
        const TEMPLATE: &str = include_str!("./data/config.yaml");

        let mut template: ProxyConfig = serde_yaml::from_str(TEMPLATE).unwrap();
        template.dynamic_peers.ika_unsafe_identity_override = None;
        assert!(
            template
                .dynamic_peers
                .ika_network_config()
                .unwrap_err()
                .to_string()
                .contains("ika-unsafe-identity-override")
        );

        let mut identity = serde_yaml::from_str::<IkaIdentityOverride>(
            "ika-package-id: '0x1'\n\
             ika-common-package-id: '0x2'\n\
             ika-dwallet-2pc-mpc-package-id: '0x3'\n\
             ika-system-package-id: '0x4'\n\
             ika-system-object-id: '0x5'\n\
             ika-dwallet-coordinator-object-id: '0x6'\n",
        )
        .unwrap();
        identity.ika_system_object_id = ObjectID::ZERO;
        template.dynamic_peers.ika_unsafe_identity_override = Some(identity);
        assert!(
            template
                .dynamic_peers
                .ika_network_config()
                .unwrap_err()
                .to_string()
                .contains("ZERO object ID")
        );
    }

    #[test]
    fn legacy_rpc_and_flat_identity_fields_are_rejected() {
        const TEMPLATE: &str = include_str!("./data/config.yaml");
        let legacy_url = TEMPLATE.replace("grpc-url:", "url:");
        assert!(serde_yaml::from_str::<ProxyConfig>(&legacy_url).is_err());

        let flat_identity = TEMPLATE
            .replace("  ika-unsafe-identity-override:\n", "")
            .replace("    ika-", "  ika-");
        assert!(serde_yaml::from_str::<ProxyConfig>(&flat_identity).is_err());
    }

    #[test]
    fn shipped_example_configs_parse_and_resolve() {
        for config in [
            include_str!("../demo-config.yaml"),
            include_str!("../local-config.yaml"),
            include_str!("../monitoring/config/proxy-docker-config.yaml"),
        ] {
            let config: ProxyConfig = serde_yaml::from_str(config).unwrap();
            config.dynamic_peers.ika_network_config().unwrap();
        }
    }
}
