// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear
use fastcrypto::ed25519::Ed25519PublicKey;
use ika_types::sui::EpochStartSystemTrait;
use ika_types::sui::EpochStartValidatorInfoTrait;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};
use sui_tls::Allower;
use tracing::info;

/// AllowedPeers is a mapping of public key to AllowedPeer data
pub type AllowedPeers = Arc<RwLock<HashMap<Ed25519PublicKey, AllowedPeer>>>;

#[derive(Hash, PartialEq, Eq, Debug, Clone)]
pub struct AllowedPeer {
    pub name: String,
    pub public_key: Ed25519PublicKey,
}

/// SuiNodeProvider queries the sui blockchain and keeps a record of known validators based on the response from
/// sui_getValidators.  The node name, public key and other info is extracted from the chain and stored in this
/// data structure.  We pass this struct to the tls verifier and it depends on the state contained within.
/// Handlers also use this data in an Extractor extension to check incoming clients on the http api against known keys.
#[derive(Clone)]
pub struct SuiNodeProvider {
    client: Arc<ika_sui_client::SuiConnectorClient>,
    rpc_poll_interval: Duration,
    pub inner: SuiNodeProviderInner,
}

#[derive(Debug, Clone)]
pub struct SuiNodeProviderInner {
    sui_nodes: AllowedPeers,
    static_nodes: AllowedPeers,
}

impl Allower for SuiNodeProviderInner {
    fn allowed(&self, key: &Ed25519PublicKey) -> bool {
        self.static_nodes.read().unwrap().contains_key(key)
            || self.sui_nodes.read().unwrap().contains_key(key)
    }
}

impl SuiNodeProvider {
    pub fn new(
        rpc_poll_interval: Duration,
        static_peers: Vec<AllowedPeer>,
        client: Arc<ika_sui_client::SuiConnectorClient>,
    ) -> Self {
        // build our hashmap with the static pub keys. we only do this one time at binary startup.
        let static_nodes: HashMap<Ed25519PublicKey, AllowedPeer> = static_peers
            .into_iter()
            .map(|v| (v.public_key.clone(), v))
            .collect();
        let static_nodes = Arc::new(RwLock::new(static_nodes));
        let sui_nodes = Arc::new(RwLock::new(HashMap::new()));
        Self {
            client,
            rpc_poll_interval,
            inner: SuiNodeProviderInner {
                sui_nodes,
                static_nodes,
            },
        }
    }

    /// get is used to retrieve peer info in our handlers
    pub fn get(&self, key: &Ed25519PublicKey) -> Option<AllowedPeer> {
        info!("look for {:?}", key);
        // check static nodes first
        if let Some(v) = self.inner.static_nodes.read().unwrap().get(key) {
            return Some(AllowedPeer {
                name: v.name.to_owned(),
                public_key: v.public_key.to_owned(),
            });
        }
        // check sui validators
        if let Some(v) = self.inner.sui_nodes.read().unwrap().get(key) {
            return Some(AllowedPeer {
                name: v.name.to_owned(),
                public_key: v.public_key.to_owned(),
            });
        }
        None
    }

    /// Get a mutable reference to the allowed sui validator map
    pub fn get_sui_mut(&mut self) -> &mut AllowedPeers {
        &mut self.inner.sui_nodes
    }

    async fn update_sui_validator_set(&self) {
        let system_inner = self.client.must_get_system_inner_object().await;
        let epoch_start = self.client.must_get_epoch_start_system(&system_inner).await;
        let validators = epoch_start.get_ika_validators();
        let validators = validators
            .into_iter()
            .map(|v| {
                (
                    v.get_network_pubkey(),
                    AllowedPeer {
                        name: v.get_name(),
                        public_key: v.get_network_pubkey(),
                    },
                )
            })
            .collect::<Vec<_>>();
        info!("found {:?} ika validators", validators);
        let mut allow = self.inner.sui_nodes.write().unwrap();
        allow.clear();
        allow.extend(validators);
        info!(
            "{} sui validators managed to make it on the allow list",
            allow.len()
        );
    }

    /// poll_peer_list will act as a refresh interval for our cache.
    pub fn poll_peer_list(&self) {
        info!("Started polling for peers using client");

        let rpc_poll_interval = self.rpc_poll_interval;
        let cloned_self = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(rpc_poll_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;
                cloned_self.update_sui_validator_set().await;
            }
        });
    }
}
