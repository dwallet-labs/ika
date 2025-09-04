// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::network_config::NetworkConfig;
use crate::node_config_builder::{FullnodeConfigBuilder, ValidatorConfigBuilder};
use crate::validator_initialization_config::ValidatorInitializationConfig;
use crate::validator_initialization_config::ValidatorInitializationConfigBuilder;
use ika_config::initiation::InitiationParameters;
use ika_config::node::{
    AuthorityOverloadConfig, RunWithRange, get_testing_sui_faucet_url,
    get_testing_sui_fullnode_rpc_url,
};
use ika_protocol_config::ProtocolVersion;
use ika_types::committee::Committee;
use ika_types::crypto::AuthorityName;
use ika_types::crypto::{AccountKeyPair, KeypairTraits, get_key_pair_from_rng};
use ika_types::supported_protocol_versions::SupportedProtocolVersions;
use rand::rngs::OsRng;
use std::path::PathBuf;
use std::{num::NonZeroUsize, path::Path, sync::Arc};
use sui_macros::nondeterministic;

pub enum CommitteeConfig {
    Size(NonZeroUsize),
    Validators(Vec<ValidatorInitializationConfig>),
    AccountKeys(Vec<AccountKeyPair>),
    /// Indicates that a committee should be deterministically generated, using the provided rng
    /// as a source of randomness as well as generating deterministic network port information.
    Deterministic((NonZeroUsize, Option<Vec<AccountKeyPair>>)),
}

pub type SupportedProtocolVersionsCallback = Arc<
    dyn Fn(
            usize,                 /* validator idx */
            Option<AuthorityName>, /* None for fullnode */
        ) -> SupportedProtocolVersions
        + Send
        + Sync
        + 'static,
>;

#[derive(Clone)]
pub enum ProtocolVersionsConfig {
    // use SYSTEM_DEFAULT
    Default,
    // Use one range for all validators.
    Global(SupportedProtocolVersions),
    // A closure that returns the versions for each validator.
    // TODO: This doesn't apply to fullnodes.
    PerValidator(SupportedProtocolVersionsCallback),
}

pub type StateAccumulatorV2EnabledCallback = Arc<dyn Fn(usize) -> bool + Send + Sync + 'static>;

#[derive(Clone)]
pub enum StateAccumulatorV2EnabledConfig {
    Global(bool),
    PerValidator(StateAccumulatorV2EnabledCallback),
}

pub struct ConfigBuilder<R = OsRng> {
    rng: Option<R>,
    config_directory: PathBuf,
    sui_fullnode_rpc_url: String,
    sui_faucet_url: String,
    epoch_duration_ms: Option<u64>,
    protocol_version: Option<ProtocolVersion>,
    supported_protocol_versions_config: Option<ProtocolVersionsConfig>,
    committee: CommitteeConfig,
    computation_price_per_unit_size: Option<u64>,
    authority_overload_config: Option<AuthorityOverloadConfig>,
    max_submit_position: Option<usize>,
    submit_delay_step_override_millis: Option<u64>,
    fullnode_count: usize,
    // Default to supported_protocol_versions_config, but can be overridden.
    fullnode_supported_protocol_versions_config: Option<ProtocolVersionsConfig>,
    fullnode_run_with_range: Option<RunWithRange>,
}

impl ConfigBuilder {
    pub fn new<P: AsRef<Path>>(
        config_directory: P,
        sui_fullnode_rpc_url: String,
        sui_faucet_url: String,
    ) -> Self {
        Self {
            rng: Some(OsRng),
            config_directory: config_directory.as_ref().into(),
            sui_fullnode_rpc_url,
            sui_faucet_url,
            epoch_duration_ms: None,
            protocol_version: None,
            supported_protocol_versions_config: None,
            // FIXME: A network with only 1 validator does not have liveness.
            // We need to change this. There are some tests that depend on it though.
            committee: CommitteeConfig::Size(NonZeroUsize::new(1).unwrap()),
            computation_price_per_unit_size: None,
            authority_overload_config: None,
            max_submit_position: None,
            submit_delay_step_override_millis: None,
            fullnode_count: 0,
            fullnode_supported_protocol_versions_config: None,
            fullnode_run_with_range: None,
        }
    }

    pub fn new_with_temp_dir() -> Self {
        let sui_fullnode_rpc_url = get_testing_sui_fullnode_rpc_url();
        let sui_faucet_url = get_testing_sui_faucet_url();
        Self::new(
            nondeterministic!(tempfile::tempdir().unwrap()).keep(),
            sui_fullnode_rpc_url,
            sui_faucet_url,
        )
    }
}

impl<R> ConfigBuilder<R> {
    pub fn committee(mut self, committee: CommitteeConfig) -> Self {
        self.committee = committee;
        self
    }

    pub fn committee_size(mut self, committee_size: NonZeroUsize) -> Self {
        self.committee = CommitteeConfig::Size(committee_size);
        self
    }

    pub fn deterministic_committee_size(mut self, committee_size: NonZeroUsize) -> Self {
        self.committee = CommitteeConfig::Deterministic((committee_size, None));
        self
    }

    pub fn deterministic_committee_validators(mut self, keys: Vec<AccountKeyPair>) -> Self {
        self.committee = CommitteeConfig::Deterministic((
            NonZeroUsize::new(keys.len()).expect("Validator keys should be non-empty"),
            Some(keys),
        ));
        self
    }

    pub fn with_validator_account_keys(mut self, keys: Vec<AccountKeyPair>) -> Self {
        self.committee = CommitteeConfig::AccountKeys(keys);
        self
    }

    pub fn with_validators(mut self, validators: Vec<ValidatorInitializationConfig>) -> Self {
        self.committee = CommitteeConfig::Validators(validators);
        self
    }

    pub fn with_computation_price_per_unit_size(
        mut self,
        computation_price_per_unit_size: u64,
    ) -> Self {
        self.computation_price_per_unit_size = Some(computation_price_per_unit_size);
        self
    }

    pub fn with_epoch_duration(mut self, epoch_duration_ms: u64) -> Self {
        self.epoch_duration_ms = Some(epoch_duration_ms);
        self
    }

    pub fn with_protocol_version(mut self, protocol_version: ProtocolVersion) -> Self {
        self.protocol_version = Some(protocol_version);
        self
    }

    pub fn with_supported_protocol_versions(mut self, c: SupportedProtocolVersions) -> Self {
        self.supported_protocol_versions_config = Some(ProtocolVersionsConfig::Global(c));
        self
    }

    pub fn with_supported_protocol_version_callback(
        mut self,
        func: SupportedProtocolVersionsCallback,
    ) -> Self {
        self.supported_protocol_versions_config = Some(ProtocolVersionsConfig::PerValidator(func));
        self
    }

    pub fn with_supported_protocol_versions_config(mut self, c: ProtocolVersionsConfig) -> Self {
        self.supported_protocol_versions_config = Some(c);
        self
    }

    pub fn with_authority_overload_config(mut self, c: AuthorityOverloadConfig) -> Self {
        self.authority_overload_config = Some(c);
        self
    }

    pub fn with_max_submit_position(mut self, max_submit_position: usize) -> Self {
        self.max_submit_position = Some(max_submit_position);
        self
    }

    pub fn with_submit_delay_step_override_millis(
        mut self,
        submit_delay_step_override_millis: u64,
    ) -> Self {
        self.submit_delay_step_override_millis = Some(submit_delay_step_override_millis);
        self
    }

    pub fn with_fullnode_count(mut self, fullnode_count: usize) -> Self {
        self.fullnode_count = fullnode_count;
        self
    }

    pub fn with_fullnode_supported_protocol_versions_config(
        mut self,
        fullnode_supported_protocol_versions_config: ProtocolVersionsConfig,
    ) -> Self {
        self.fullnode_supported_protocol_versions_config =
            Some(fullnode_supported_protocol_versions_config);
        self
    }

    pub fn with_fullnode_run_with_range(mut self, fullnode_run_with_range: RunWithRange) -> Self {
        self.fullnode_run_with_range = Some(fullnode_run_with_range);
        self
    }

    pub fn rng<N: rand::RngCore + rand::CryptoRng>(self, rng: N) -> ConfigBuilder<N> {
        ConfigBuilder {
            rng: Some(rng),
            config_directory: self.config_directory,
            sui_fullnode_rpc_url: self.sui_fullnode_rpc_url,
            sui_faucet_url: self.sui_faucet_url,
            epoch_duration_ms: self.epoch_duration_ms,
            protocol_version: self.protocol_version,
            supported_protocol_versions_config: self.supported_protocol_versions_config,
            committee: self.committee,
            computation_price_per_unit_size: self.computation_price_per_unit_size,
            authority_overload_config: self.authority_overload_config,
            max_submit_position: self.max_submit_position,
            submit_delay_step_override_millis: self.submit_delay_step_override_millis,
            fullnode_count: self.fullnode_count,
            fullnode_supported_protocol_versions_config: self
                .fullnode_supported_protocol_versions_config,
            fullnode_run_with_range: self.fullnode_run_with_range,
        }
    }
}

impl<R: rand::RngCore + rand::CryptoRng> ConfigBuilder<R> {
    //TODO right now we always randomize ports, we may want to have a default port configuration
    pub async fn build(self) -> Result<NetworkConfig, anyhow::Error> {
        let committee = self.committee;

        let mut rng = self.rng.unwrap();
        let mut validator_initialization_configs = match committee {
            CommitteeConfig::Size(size) => {
                // We always get fixed protocol keys from this function (which is isolated from
                // external test randomness because it uses a fixed seed). Necessary because some
                // tests call `make_tx_certs_and_signed_effects`, which locally forges a cert using
                // this same committee.
                let (_, keys) = Committee::new_simple_test_committee_of_size(size.into());

                keys.into_iter()
                    .map(|authority_key| {
                        let mut builder = ValidatorInitializationConfigBuilder::new()
                            .with_protocol_key_pair(authority_key);
                        if let Some(rgp) = self.computation_price_per_unit_size {
                            builder = builder.with_computation_price(rgp);
                        }

                        builder.build(&mut rng)
                    })
                    .collect::<Vec<_>>()
            }

            CommitteeConfig::Validators(v) => v,

            CommitteeConfig::AccountKeys(keys) => {
                // See above re fixed protocol keys
                let (_, protocol_keys) = Committee::new_simple_test_committee_of_size(keys.len());
                keys.into_iter()
                    .zip(protocol_keys)
                    .map(|(account_key, protocol_key)| {
                        let mut builder = ValidatorInitializationConfigBuilder::new()
                            .with_protocol_key_pair(protocol_key)
                            .with_account_key_pair(account_key);
                        if let Some(rgp) = self.computation_price_per_unit_size {
                            builder = builder.with_computation_price(rgp);
                        }
                        builder.build(&mut rng)
                    })
                    .collect::<Vec<_>>()
            }
            CommitteeConfig::Deterministic((size, keys)) => {
                // If no keys are provided, generate them.
                let keys = keys.unwrap_or(
                    (0..size.get())
                        .map(|_| get_key_pair_from_rng(&mut rng).1)
                        .collect(),
                );

                let mut configs = vec![];
                for (i, key) in keys.into_iter().enumerate() {
                    let port_offset = 8000 + i * 10;
                    let mut builder = ValidatorInitializationConfigBuilder::new()
                        .with_ip("127.0.0.1".to_owned())
                        .with_account_key_pair(key)
                        .with_deterministic_ports(port_offset as u16);
                    if let Some(rgp) = self.computation_price_per_unit_size {
                        builder = builder.with_computation_price(rgp);
                    }
                    configs.push(builder.build(&mut rng));
                }
                configs
            }
        };

        for (i, validator) in validator_initialization_configs.iter_mut().enumerate() {
            validator.name = validator.name.clone().or(Some(format!("validator-{i}")));
        }

        let mut initiation_parameters = InitiationParameters::new();
        if let Some(epoch_duration_ms) = self.epoch_duration_ms {
            initiation_parameters.epoch_duration_ms = epoch_duration_ms;
        }
        if let Some(protocol_version) = self.protocol_version {
            initiation_parameters.protocol_version = protocol_version.as_u64();
        }
        let (
            ika_package_id,
            ika_common_package_id,
            ika_dwallet_2pc_mpc_package_id,
            ika_system_package_id,
            ika_system_object_id,
            ika_dwallet_coordinator_object_id,
            publisher_keypair,
        ) = crate::sui_client::init_ika_on_sui(
            &validator_initialization_configs,
            self.sui_fullnode_rpc_url.to_string(),
            self.sui_faucet_url.to_string(),
            initiation_parameters,
        )
        .await?;

        let validator_configs = validator_initialization_configs
            .iter()
            .enumerate()
            .map(|(idx, validator)| {
                let mut builder = ValidatorConfigBuilder::new()
                    .with_config_directory(self.config_directory.clone());

                if let Some(max_submit_position) = self.max_submit_position {
                    builder = builder.with_max_submit_position(max_submit_position);
                }

                if let Some(submit_delay_step_override_millis) =
                    self.submit_delay_step_override_millis
                {
                    builder = builder
                        .with_submit_delay_step_override_millis(submit_delay_step_override_millis);
                }

                if let Some(authority_overload_config) = &self.authority_overload_config {
                    builder =
                        builder.with_authority_overload_config(authority_overload_config.clone());
                }

                if let Some(spvc) = &self.supported_protocol_versions_config {
                    let supported_versions = match spvc {
                        ProtocolVersionsConfig::Default => {
                            SupportedProtocolVersions::SYSTEM_DEFAULT
                        }
                        ProtocolVersionsConfig::Global(v) => *v,
                        ProtocolVersionsConfig::PerValidator(func) => {
                            func(idx, Some(validator.key_pair.public().into()))
                        }
                    };
                    builder = builder.with_supported_protocol_versions(supported_versions);
                }

                builder.build(
                    validator,
                    self.sui_fullnode_rpc_url.clone(),
                    ika_package_id,
                    ika_common_package_id,
                    ika_dwallet_2pc_mpc_package_id,
                    ika_system_package_id,
                    ika_system_object_id,
                    ika_dwallet_coordinator_object_id,
                )
            })
            .collect();
        let mut fullnode_config_builder = FullnodeConfigBuilder::new()
            .with_config_directory(self.config_directory.clone())
            .with_run_with_range(self.fullnode_run_with_range);

        if let Some(spvc) = &self.fullnode_supported_protocol_versions_config {
            let supported_versions = match spvc {
                ProtocolVersionsConfig::Default => SupportedProtocolVersions::SYSTEM_DEFAULT,
                ProtocolVersionsConfig::Global(v) => *v,
                ProtocolVersionsConfig::PerValidator(func) => func(0, None),
            };
            fullnode_config_builder =
                fullnode_config_builder.with_supported_protocol_versions(supported_versions);
        }

        let mut fullnode_configs = Vec::new();
        if self.fullnode_count > 0 {
            (0..self.fullnode_count).for_each(|idx| {
                let builder = fullnode_config_builder.clone();
                let notifier_client_key_pair = if idx == 0 {
                    Some(publisher_keypair.copy())
                } else {
                    None
                };
                let config = builder.build(
                    &mut OsRng,
                    &validator_initialization_configs,
                    self.sui_fullnode_rpc_url.clone(),
                    ika_package_id,
                    ika_common_package_id,
                    ika_dwallet_2pc_mpc_package_id,
                    ika_system_package_id,
                    ika_system_object_id,
                    ika_dwallet_coordinator_object_id,
                    notifier_client_key_pair,
                );
                fullnode_configs.push(config);
            });
        }
        Ok(NetworkConfig {
            validator_configs,
            fullnode_configs,
            validator_initialization_configs,
            ika_package_id,
            ika_common_package_id,
            ika_dwallet_2pc_mpc_package_id,
            ika_system_package_id,
            ika_system_object_id,
            ika_dwallet_coordinator_object_id,
        })
    }
}
