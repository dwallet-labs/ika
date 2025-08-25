// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use clap::*;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::{
    cell::RefCell,
    collections::BTreeSet,
    sync::atomic::{AtomicBool, Ordering},
};
use sui_protocol_config_macros::{
    ProtocolConfigAccessors, ProtocolConfigFeatureFlagsGetters, ProtocolConfigOverride,
};
use tracing::{info, warn};

/// The minimum and maximum protocol versions supported by this build.
const MIN_PROTOCOL_VERSION: u64 = 1;
const MAX_PROTOCOL_VERSION: u64 = 1;

// Record history of protocol version allocations here:
//
// Version 1: Original version.

#[derive(Copy, Clone, Debug, Hash, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtocolVersion(u64);

impl ProtocolVersion {
    // The minimum and maximum protocol version supported by this binary. Counterintuitively, this constant may
    // change over time as support for old protocol versions is removed from the source. This
    // ensures that when a new network (such as a testnet) is created, its genesis committee will
    // use a protocol version that is actually supported by the binary.
    pub const MIN: Self = Self(MIN_PROTOCOL_VERSION);

    pub const MAX: Self = Self(MAX_PROTOCOL_VERSION);

    #[cfg(not(msim))]
    const MAX_ALLOWED: Self = Self::MAX;

    // We create one additional "fake" version in simulator builds so that we can test upgrades.
    #[cfg(msim)]
    pub const MAX_ALLOWED: Self = Self(MAX_PROTOCOL_VERSION + 1);

    pub fn new(v: u64) -> Self {
        Self(v)
    }

    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    // For serde deserialization - we don't define a Default impl because there isn't a single
    // universally appropriate default value.
    pub fn max() -> Self {
        Self::MAX
    }
}

impl From<u64> for ProtocolVersion {
    fn from(v: u64) -> Self {
        Self::new(v)
    }
}

impl std::ops::Sub<u64> for ProtocolVersion {
    type Output = Self;
    fn sub(self, rhs: u64) -> Self::Output {
        Self::new(self.0 - rhs)
    }
}

impl std::ops::Add<u64> for ProtocolVersion {
    type Output = Self;
    fn add(self, rhs: u64) -> Self::Output {
        Self::new(self.0 + rhs)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Copy, PartialOrd, Ord, Eq, ValueEnum)]
pub enum Chain {
    Mainnet,
    Testnet,
    Unknown,
}

impl Default for Chain {
    fn default() -> Self {
        Self::Unknown
    }
}

impl Chain {
    pub fn as_str(self) -> &'static str {
        match self {
            Chain::Mainnet => "mainnet",
            Chain::Testnet => "testnet",
            Chain::Unknown => "unknown",
        }
    }
}

pub struct Error(pub String);

// TODO: There are quite a few non boolean values in the feature flags. We should move them out.
/// Records on/off feature flags that may vary at each protocol version.
#[derive(Default, Clone, Serialize, Deserialize, Debug, ProtocolConfigFeatureFlagsGetters)]
struct FeatureFlags {
    // Add feature flags here, e.g.:
    // #[serde(skip_serializing_if = "is_false")]
    // new_protocol_feature: bool,
    // === Used at Sui consensus for current ProtocolConfig version (MAX 84) ===

    // Probe rounds received by peers from every authority.
    #[serde(skip_serializing_if = "is_false")]
    consensus_round_prober: bool,

    // Enables Mysticeti fastpath.
    #[serde(skip_serializing_if = "is_false")]
    mysticeti_fastpath: bool,

    // Set number of leaders per round for Mysticeti commits.
    #[serde(skip_serializing_if = "Option::is_none")]
    mysticeti_num_leaders_per_round: Option<usize>,

    // If true, enable zstd compression for consensus tonic network.
    #[serde(skip_serializing_if = "is_false")]
    consensus_zstd_compression: bool,

    // If true, enabled batched block sync in consensus.
    #[serde(skip_serializing_if = "is_false")]
    consensus_batched_block_sync: bool,

    // If true, enforces checkpoint timestamps are non-decreasing.
    #[serde(skip_serializing_if = "is_false")]
    enforce_checkpoint_timestamp_monotonicity: bool,
}

#[allow(unused)]
fn is_false(b: &bool) -> bool {
    !b
}

#[allow(unused)]
fn is_empty(b: &BTreeSet<String>) -> bool {
    b.is_empty()
}

/// Ordering mechanism for transactions in one Narwhal consensus output.
#[derive(Default, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum ConsensusTransactionOrdering {
    /// No ordering. Transactions are processed in the order they appear in the consensus output.
    #[default]
    None,
    /// Order transactions by computation price, highest first.
    ByGasPrice,
}

impl ConsensusTransactionOrdering {
    pub fn is_none(&self) -> bool {
        matches!(self, ConsensusTransactionOrdering::None)
    }
}

/// Constants that change the behavior of the protocol.
///
/// The value of each constant here must be fixed for a given protocol version. To change the value
/// of a constant, advance the protocol version, and add support for it in `get_for_version` under
/// the new version number.
/// (below).
///
/// To add a new field to this struct, use the following procedure:
/// - Advance the protocol version.
/// - Add the field as a private `Option<T>` to the struct.
/// - Initialize the field to `None` in prior protocol versions.
/// - Initialize the field to `Some(val)` for your new protocol version.
/// - Add a public getter that simply unwraps the field.
/// - Two public getters of the form `field(&self) -> field_type`
///     and `field_as_option(&self) -> Option<field_type>` will be automatically generated for you.
/// Example for a field: `new_constant: Option<u64>`
/// ```rust,ignore
///      pub fn new_constant(&self) -> u64 {
///         self.new_constant.expect(Self::CONSTANT_ERR_MSG)
///     }
///      pub fn new_constant_as_option(&self) -> Option<u64> {
///         self.new_constant.expect(Self::CONSTANT_ERR_MSG)
///     }
/// ```
/// With `pub fn new_constant(&self) -> u64`, if the constant is accessed in a protocol version
/// in which it is not defined, the validator will crash. (Crashing is necessary because
/// this type of error would almost always result in forking if not prevented here).
/// If you don't want the validator to crash, you can use the
/// `pub fn new_constant_as_option(&self) -> Option<u64>` getter, which will
/// return `None` if the field is not defined at that version.
/// - If you want a customized getter, you can add a method in the impl.
#[skip_serializing_none]
#[derive(Clone, Serialize, Debug, ProtocolConfigAccessors, ProtocolConfigOverride)]
pub struct ProtocolConfig {
    pub version: ProtocolVersion,

    feature_flags: FeatureFlags,

    // === Core Protocol ===
    /// Max number of transactions per dwallet checkpoint.
    /// Note that this is a protocol constant and not a config as validators must have this set to
    /// the same value, otherwise they *will* fork.
    max_messages_per_dwallet_checkpoint: Option<u64>,

    /// Max number of transactions per iks system checkpoint.
    /// Note that this is a protocol constant and not a config as validators must have this set to
    /// the same value, otherwise they *will* fork.
    max_messages_per_system_checkpoint: Option<u64>,

    /// Max size of a dwallet checkpoint in bytes.
    /// Note that this is a protocol constant and not a config as validators must have this set to
    /// the same value, otherwise they *will* fork.
    max_dwallet_checkpoint_size_bytes: Option<u64>,

    /// Max size of an ika system checkpoint in bytes.
    /// Note that this is a protocol constant and not a config as validators must have this set to
    /// the same value, otherwise they *will* fork.
    max_system_checkpoint_size_bytes: Option<u64>,

    /// A protocol upgrade always requires 2f+1 stake to agree. We support a buffer of additional
    /// stake (as a fraction of f, expressed in basis points) that is required before an upgrade
    /// can happen automatically. 10000bps would indicate that complete unanimity is required (all
    /// 3f+1 must vote), while 0bps would indicate that 2f+1 is sufficient.
    buffer_stake_for_protocol_upgrade_bps: Option<u64>,

    // === Consensus ===
    /// Dictates the threshold (percentage of stake) that is used to calculate the "bad" nodes to be
    /// swapped when creating the consensus schedule. The values should be of the range [0 - 33]. Anything
    /// above 33 (f) will not be allowed.
    consensus_bad_nodes_stake_threshold: Option<u64>,

    // === Used at Sui consensus for current ProtocolConfig version (MAX 84) ===
    /// The maximum serialised transaction size (in bytes) accepted by consensus. That should be bigger than the
    /// `max_tx_size_bytes` with some additional headroom.
    consensus_max_transaction_size_bytes: Option<u64>,

    /// The maximum number of transactions included in a consensus block.
    consensus_max_num_transactions_in_block: Option<u64>,

    /// The maximum size of transactions included in a consensus block.
    consensus_max_transactions_in_block_bytes: Option<u64>,

    /// Configures the garbage collection depth for consensus. When is unset or `0` then the garbage collection
    /// is disabled.
    consensus_gc_depth: Option<u32>,
    decryption_key_reconfiguration_third_round_delay: Option<u64>,
    network_dkg_third_round_delay: Option<u64>,
    reconfiguration_version: Option<u64>,
}

// feature flags
impl ProtocolConfig {
    // Add checks for feature flag support here, e.g.:
    // pub fn check_new_protocol_feature_supported(&self) -> Result<(), Error> {
    //     if self.feature_flags.new_protocol_feature_supported {
    //         Ok(())
    //     } else {
    //         Err(Error(format!(
    //             "new_protocol_feature is not supported at {:?}",
    //             self.version
    //         )))
    //     }
    // }

    pub fn consensus_round_prober(&self) -> bool {
        self.feature_flags.consensus_round_prober
    }

    pub fn mysticeti_num_leaders_per_round(&self) -> Option<usize> {
        self.feature_flags.mysticeti_num_leaders_per_round
    }

    pub fn gc_depth(&self) -> u32 {
        if cfg!(msim) {
            // exercise a very low gc_depth
            5
        } else {
            self.consensus_gc_depth.unwrap_or(0)
        }
    }

    pub fn mysticeti_fastpath(&self) -> bool {
        if let Some(enabled) = is_mysticeti_fpc_enabled_in_env() {
            return enabled;
        }
        self.feature_flags.mysticeti_fastpath
    }

    pub fn consensus_batched_block_sync(&self) -> bool {
        self.feature_flags.consensus_batched_block_sync
    }

    pub fn enforce_checkpoint_timestamp_monotonicity(&self) -> bool {
        self.feature_flags.enforce_checkpoint_timestamp_monotonicity
    }

    pub fn consensus_zstd_compression(&self) -> bool {
        self.feature_flags.consensus_zstd_compression
    }
}

#[cfg(not(msim))]
static POISON_VERSION_METHODS: AtomicBool = AtomicBool::new(false);

// Use a thread local in sim tests for test isolation.
#[cfg(msim)]
thread_local! {
    static POISON_VERSION_METHODS: AtomicBool = AtomicBool::new(false);
}

// Instantiations for each protocol version.
impl ProtocolConfig {
    /// Get the value ProtocolConfig that are in effect during the given protocol version.
    pub fn get_for_version(version: ProtocolVersion, chain: Chain) -> Self {
        // ProtocolVersion can be deserialized so we need to check it here as well.
        assert!(
            version >= ProtocolVersion::MIN,
            "Network protocol version is {:?}, but the minimum supported version by the binary is {:?}. Please upgrade the binary.",
            version,
            ProtocolVersion::MIN.0,
        );
        assert!(
            version <= ProtocolVersion::MAX_ALLOWED,
            "Network protocol version is {:?}, but the maximum supported version by the binary is {:?}. Please upgrade the binary.",
            version,
            ProtocolVersion::MAX_ALLOWED.0,
        );

        let mut ret = Self::get_for_version_impl(version, chain);
        ret.version = version;

        ret = CONFIG_OVERRIDE.with(|ovr| {
            match &*ovr.borrow() { Some(override_fn) => {
                warn!(
                    "overriding ProtocolConfig settings with custom settings (you should not see this log outside of tests)"
                );
                override_fn(version, ret)
            } _ => {
                ret
            }}
        });

        if std::env::var("IKA_PROTOCOL_CONFIG_OVERRIDE_ENABLE").is_ok() {
            warn!(
                "overriding ProtocolConfig settings with custom settings; this may break non-local networks"
            );
            let overrides: ProtocolConfigOptional =
                serde_env::from_env_with_prefix("IKA_PROTOCOL_CONFIG_OVERRIDE")
                    .expect("failed to parse ProtocolConfig override env variables");
            overrides.apply_to(&mut ret);
        }

        ret
    }

    /// Get the value ProtocolConfig that are in effect during the given protocol version.
    /// Or none if the version is not supported.
    pub fn get_for_version_if_supported(version: ProtocolVersion, chain: Chain) -> Option<Self> {
        if version.0 >= ProtocolVersion::MIN.0 && version.0 <= ProtocolVersion::MAX_ALLOWED.0 {
            let mut ret = Self::get_for_version_impl(version, chain);
            ret.version = version;
            Some(ret)
        } else {
            None
        }
    }

    #[cfg(not(msim))]
    pub fn poison_get_for_min_version() {
        POISON_VERSION_METHODS.store(true, Ordering::Relaxed);
    }

    #[cfg(not(msim))]
    fn load_poison_get_for_min_version() -> bool {
        POISON_VERSION_METHODS.load(Ordering::Relaxed)
    }

    #[cfg(msim)]
    pub fn poison_get_for_min_version() {
        POISON_VERSION_METHODS.with(|p| p.store(true, Ordering::Relaxed));
    }

    #[cfg(msim)]
    fn load_poison_get_for_min_version() -> bool {
        POISON_VERSION_METHODS.with(|p| p.load(Ordering::Relaxed))
    }

    /// Convenience to get the constants at the current minimum supported version.
    /// Mainly used by client code that may not yet be protocol-version aware.
    pub fn get_for_min_version() -> Self {
        if Self::load_poison_get_for_min_version() {
            panic!("get_for_min_version called on validator");
        }
        ProtocolConfig::get_for_version(ProtocolVersion::MIN, Chain::Unknown)
    }

    /// CAREFUL! - You probably want to use `get_for_version` instead.
    ///
    /// Convenience to get the constants at the current maximum supported version.
    /// Mainly used by genesis. Note well that this function uses the max version
    /// supported locally by the node, which is not necessarily the current version
    /// of the network. ALSO, this function disregards chain specific config (by
    /// using Chain::Unknown), thereby potentially returning a protocol config that
    /// is incorrect for some feature flags. Definitely safe for testing and for
    /// protocol version 11 and prior.
    #[allow(non_snake_case)]
    pub fn get_for_max_version_UNSAFE() -> Self {
        if Self::load_poison_get_for_min_version() {
            panic!("get_for_max_version_UNSAFE called on validator");
        }
        ProtocolConfig::get_for_version(ProtocolVersion::MAX, Chain::Unknown)
    }

    fn get_for_version_impl(version: ProtocolVersion, _chain: Chain) -> Self {
        #[cfg(msim)]
        {
            // populate the fake simulator version # with a different base tx cost.
            if version == ProtocolVersion::MAX_ALLOWED {
                let mut config = Self::get_for_version_impl(version - 1, Chain::Unknown);
                config.base_tx_cost_fixed = Some(config.base_tx_cost_fixed() + 1000);
                return config;
            }
        }

        // IMPORTANT: Never modify the value of any constant for a pre-existing protocol version.
        // To change the values here you must create a new protocol version with the new values!
        let mut cfg = Self {
            // will be overwritten before being returned
            version,

            // All flags are disabled in V1
            feature_flags: Default::default(),

            max_messages_per_dwallet_checkpoint: Some(500),
            max_messages_per_system_checkpoint: Some(500),

            // The `max_tx_size_bytes` on Sui is `128 * 1024`, but we must keep the transaction size lower to avoid reaching the maximum computation fee.
            max_dwallet_checkpoint_size_bytes: Some(50 * 1024),
            max_system_checkpoint_size_bytes: Some(50 * 1024),

            buffer_stake_for_protocol_upgrade_bps: Some(5000),

            // Taking a baby step approach, we consider only 20% by stake as bad nodes so we
            // have an 80% by stake of nodes participating in the leader committee. That allow
            // us for more redundancy in case we have validators under performing - since the
            // responsibility is shared amongst more nodes. We can increase that once we do have
            // higher confidence.
            consensus_bad_nodes_stake_threshold: Some(30),

            // TODO (#873): Implement a production grade configuration upgrade mechanism
            // We use the `_for_testing` functions because they are currently the only way
            // to modify Sui's protocol configuration from external crates.
            // I have opened an [issue](https://github.com/MystenLabs/sui/issues/21891)
            // in the Sui repository to address this limitation.
            // This value has been derived from monitoring the largest message
            // size in real world scenarios.
            consensus_max_transaction_size_bytes: Some(315218930),
            consensus_max_transactions_in_block_bytes: Some(315218930),
            consensus_max_num_transactions_in_block: Some(512),
            consensus_gc_depth: Some(60),
            // The delay is measured in consensus rounds.
            decryption_key_reconfiguration_third_round_delay: Some(10),
            network_dkg_third_round_delay: Some(10),
        };

        cfg.feature_flags.mysticeti_num_leaders_per_round = Some(1);
        cfg.feature_flags.consensus_round_prober = true;
        cfg.feature_flags.consensus_zstd_compression = true;
        cfg.feature_flags.consensus_batched_block_sync = true;
        cfg.feature_flags.enforce_checkpoint_timestamp_monotonicity = true;

        #[allow(clippy::never_loop)]
        for cur in 2..=version.0 {
            match cur {
                1 => unreachable!(),
                // Use this template when making changes:
                //
                //     // modify an existing constant.
                //     existing_constant: Some(7),
                //
                //     // Add a new constant (which is set to None in prior versions).
                //     new_constant: Some(new_value),
                //
                //     // Remove a constant (ensure that it is never accessed during this version).
                //     existing_constant: None,
                _ => panic!("unsupported version {version:?}"),
            }
        }
        cfg
    }

    /// Override one or more settings in the config, for testing.
    /// This must be called at the beginning of the test, before get_for_(min|max)_version is
    /// called, since those functions cache their return value.
    pub fn apply_overrides_for_testing(
        override_fn: impl Fn(ProtocolVersion, Self) -> Self + Send + 'static,
    ) -> OverrideGuard {
        CONFIG_OVERRIDE.with(|ovr| {
            let mut cur = ovr.borrow_mut();
            assert!(cur.is_none(), "config override already present");
            *cur = Some(Box::new(override_fn));
            OverrideGuard
        })
    }
}

// Setters for tests.
// This is only needed for feature_flags. Please suffix each setter with `_for_testing`.
// Non-feature_flags should already have test setters defined through macros.
impl ProtocolConfig {
    pub fn set_mysticeti_num_leaders_per_round_for_testing(&mut self, val: Option<usize>) {
        self.feature_flags.mysticeti_num_leaders_per_round = val;
    }

    pub fn set_consensus_round_prober_for_testing(&mut self, val: bool) {
        self.feature_flags.consensus_round_prober = val;
    }

    pub fn set_mysticeti_fastpath_for_testing(&mut self, val: bool) {
        self.feature_flags.mysticeti_fastpath = val;
    }

    pub fn set_consensus_batched_block_sync_for_testing(&mut self, val: bool) {
        self.feature_flags.consensus_batched_block_sync = val;
    }

    pub fn set_enforce_checkpoint_timestamp_monotonicity_for_testing(&mut self, val: bool) {
        self.feature_flags.enforce_checkpoint_timestamp_monotonicity = val;
    }
}

type OverrideFn = dyn Fn(ProtocolVersion, ProtocolConfig) -> ProtocolConfig + Send;

thread_local! {
    static CONFIG_OVERRIDE: RefCell<Option<Box<OverrideFn>>> = RefCell::new(None);
}

#[must_use]
pub struct OverrideGuard;

impl Drop for OverrideGuard {
    fn drop(&mut self) {
        info!("restoring override fn");
        CONFIG_OVERRIDE.with(|ovr| {
            *ovr.borrow_mut() = None;
        });
    }
}

/// Defines which limit got crossed.
/// The value which crossed the limit and value of the limit crossed are embedded
#[derive(PartialEq, Eq)]
pub enum LimitThresholdCrossed {
    None,
    Soft(u128, u128),
    Hard(u128, u128),
}

/// Convenience function for comparing limit ranges
/// V::MAX must be at >= U::MAX and T::MAX
pub fn check_limit_in_range<T: Into<V>, U: Into<V>, V: PartialOrd + Into<u128>>(
    x: T,
    soft_limit: U,
    hard_limit: V,
) -> LimitThresholdCrossed {
    let x: V = x.into();
    let soft_limit: V = soft_limit.into();

    debug_assert!(soft_limit <= hard_limit);

    // It is important to preserve this comparison order because if soft_limit == hard_limit
    // we want LimitThresholdCrossed::Hard
    if x >= hard_limit {
        LimitThresholdCrossed::Hard(x.into(), hard_limit.into())
    } else if x < soft_limit {
        LimitThresholdCrossed::None
    } else {
        LimitThresholdCrossed::Soft(x.into(), soft_limit.into())
    }
}

#[macro_export]
macro_rules! check_limit {
    ($x:expr_2021, $hard:expr_2021) => {
        check_limit!($x, $hard, $hard)
    };
    ($x:expr_2021, $soft:expr_2021, $hard:expr_2021) => {
        check_limit_in_range($x as u64, $soft, $hard)
    };
}

/// Used to check which limits were crossed if the TX is metered (not system tx)
/// Args are: is_metered, value_to_check, metered_limit, unmetered_limit
/// metered_limit is always less than or equal to unmetered_hard_limit
#[macro_export]
macro_rules! check_limit_by_meter {
    ($is_metered:expr_2021, $x:expr_2021, $metered_limit:expr_2021, $unmetered_hard_limit:expr_2021, $metric:expr_2021) => {{
        // If this is metered, we use the metered_limit limit as the upper bound
        let (h, metered_str) = if $is_metered {
            ($metered_limit, "metered")
        } else {
            // Unmetered gets more headroom
            ($unmetered_hard_limit, "unmetered")
        };
        use ika_protocol_config::check_limit_in_range;
        let result = check_limit_in_range($x as u64, $metered_limit, h);
        match result {
            LimitThresholdCrossed::None => {}
            LimitThresholdCrossed::Soft(_, _) => {
                $metric.with_label_values(&[metered_str, "soft"]).inc();
            }
            LimitThresholdCrossed::Hard(_, _) => {
                $metric.with_label_values(&[metered_str, "hard"]).inc();
            }
        };
        result
    }};
}

pub fn is_mysticeti_fpc_enabled_in_env() -> Option<bool> {
    if let Ok(v) = std::env::var("CONSENSUS") {
        if v == "mysticeti_fpc" {
            return Some(true);
        } else if v == "mysticeti" {
            return Some(false);
        }
    }
    None
}

#[cfg(all(test, not(msim)))]
mod test {
    use insta::assert_yaml_snapshot;

    use super::*;

    #[test]
    fn snapshot_tests() {
        println!("\n============================================================================");
        println!("!                                                                          !");
        println!("! IMPORTANT: never update snapshots from this test. only add new versions! !");
        println!("!                                                                          !");
        println!("============================================================================\n");
        for chain_id in &[Chain::Unknown, Chain::Mainnet, Chain::Testnet] {
            // make Chain::Unknown snapshots compatible with pre-chain-id snapshots so that we
            // don't break the release-time compatibility tests. Once Chain Id configs have been
            // released everywhere, we can remove this and only test Mainnet and Testnet
            let chain_str = match chain_id {
                Chain::Unknown => "".to_string(),
                _ => format!("{chain_id:?}_"),
            };
            for i in MIN_PROTOCOL_VERSION..=MAX_PROTOCOL_VERSION {
                let cur = ProtocolVersion::new(i);
                assert_yaml_snapshot!(
                    format!("{}version_{}", chain_str, cur.as_u64()),
                    ProtocolConfig::get_for_version(cur, *chain_id)
                );
            }
        }
    }

    #[test]
    fn test_getters() {
        let prot: ProtocolConfig =
            ProtocolConfig::get_for_version(ProtocolVersion::new(1), Chain::Unknown);
        assert_eq!(
            prot.max_messages_per_dwallet_checkpoint(),
            prot.max_messages_per_dwallet_checkpoint_as_option()
                .unwrap()
        );
    }

    #[test]
    fn test_setters() {
        let mut prot: ProtocolConfig =
            ProtocolConfig::get_for_version(ProtocolVersion::new(1), Chain::Unknown);
        prot.set_max_messages_per_dwallet_checkpoint_for_testing(123);
        assert_eq!(prot.max_messages_per_dwallet_checkpoint(), 123);

        prot.set_max_messages_per_dwallet_checkpoint_from_str_for_testing("321".to_string());
        assert_eq!(prot.max_messages_per_dwallet_checkpoint(), 321);

        prot.disable_max_messages_per_dwallet_checkpoint_for_testing();
        assert_eq!(prot.max_messages_per_dwallet_checkpoint_as_option(), None);

        prot.set_attr_for_testing(
            "max_messages_per_dwallet_checkpoint".to_string(),
            "456".to_string(),
        );
        assert_eq!(prot.max_messages_per_dwallet_checkpoint(), 456);
    }

    #[test]
    #[should_panic(expected = "unsupported version")]
    fn max_version_test() {
        // When this does not panic, version higher than MAX_PROTOCOL_VERSION exists.
        // To fix, bump MAX_PROTOCOL_VERSION or disable this check for the version.
        let _ = ProtocolConfig::get_for_version_impl(
            ProtocolVersion::new(MAX_PROTOCOL_VERSION + 1),
            Chain::Unknown,
        );
    }

    #[test]
    fn lookup_by_string_test() {
        let prot: ProtocolConfig =
            ProtocolConfig::get_for_version(ProtocolVersion::new(1), Chain::Unknown);
        // Does not exist
        assert!(prot.lookup_attr("some random string".to_string()).is_none());

        assert!(
            prot.lookup_attr("max_messages_per_dwallet_checkpoint".to_string())
                == Some(ProtocolConfigValue::u64(
                    prot.max_messages_per_dwallet_checkpoint()
                )),
        );

        let protocol_config: ProtocolConfig =
            ProtocolConfig::get_for_version(ProtocolVersion::new(1), Chain::Unknown);

        // We had this in version 1
        assert_eq!(
            protocol_config
                .attr_map()
                .get("max_messages_per_dwallet_checkpoint")
                .unwrap(),
            &Some(ProtocolConfigValue::u64(
                protocol_config.max_messages_per_dwallet_checkpoint()
            ))
        );

        // Check feature flags
        let prot: ProtocolConfig =
            ProtocolConfig::get_for_version(ProtocolVersion::new(1), Chain::Unknown);
        // Does not exist
        assert!(
            prot.feature_flags
                .lookup_attr("some random string".to_owned())
                .is_none()
        );
        assert!(
            !prot
                .feature_flags
                .attr_map()
                .contains_key("some random string")
        );
    }

    #[test]
    fn limit_range_fn_test() {
        let low = 100u32;
        let high = 10000u64;

        assert!(check_limit!(1u8, low, high) == LimitThresholdCrossed::None);
        assert!(matches!(
            check_limit!(255u16, low, high),
            LimitThresholdCrossed::Soft(255u128, 100)
        ));
        // This wont compile because lossy
        //assert!(check_limit!(100000000u128, low, high) == LimitThresholdCrossed::None);
        // This wont compile because lossy
        //assert!(check_limit!(100000000usize, low, high) == LimitThresholdCrossed::None);

        assert!(matches!(
            check_limit!(2550000u64, low, high),
            LimitThresholdCrossed::Hard(2550000, 10000)
        ));

        assert!(matches!(
            check_limit!(2550000u64, high, high),
            LimitThresholdCrossed::Hard(2550000, 10000)
        ));

        assert!(matches!(
            check_limit!(1u8, high),
            LimitThresholdCrossed::None
        ));

        assert!(check_limit!(255u16, high) == LimitThresholdCrossed::None);

        assert!(matches!(
            check_limit!(2550000u64, high),
            LimitThresholdCrossed::Hard(2550000, 10000)
        ));
    }
}
