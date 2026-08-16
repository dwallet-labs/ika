// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::fs::File;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use fastcrypto::encoding::{Base64, Encoding};
use serde::Deserialize;
use sui_crypto::SuiSigner;
use sui_crypto::simple::SimpleKeypair;
use sui_keys::keystore::AccountKeystore;
use sui_sdk::wallet_context::WalletContext;
use sui_types::base_types::SuiAddress;
use sui_types::crypto::Signature;
use sui_types::signature::GenericSignature;
use sui_types::transaction::{TransactionData, TransactionDataAPI};

/// The wallet capabilities Ika transaction construction actually needs.
///
/// Keeping this interface independent of Sui main's `WalletContext` lets CLI
/// and application callers use standalone SDK keys while Sui test-cluster code
/// can continue to adapt its in-memory upstream wallet.
#[async_trait]
pub trait TransactionContext: Send + Sync {
    fn active_address(&self) -> Result<SuiAddress, anyhow::Error>;

    fn rpc_url(&self) -> Result<&str, anyhow::Error>;

    fn environment_alias(&self) -> Result<&str, anyhow::Error>;

    fn keypair_bytes(&self, address: SuiAddress) -> Result<Vec<u8>, anyhow::Error>;

    async fn sign_transaction(
        &self,
        transaction: &TransactionData,
    ) -> Result<Signature, anyhow::Error>;
}

#[async_trait]
impl TransactionContext for WalletContext {
    fn active_address(&self) -> Result<SuiAddress, anyhow::Error> {
        self.config
            .active_address
            .or_else(|| self.config.keystore.addresses().first().copied())
            .ok_or_else(|| anyhow::anyhow!("Sui wallet has no managed addresses"))
    }

    fn rpc_url(&self) -> Result<&str, anyhow::Error> {
        Ok(&self.get_active_env()?.rpc)
    }

    fn environment_alias(&self) -> Result<&str, anyhow::Error> {
        Ok(&self.get_active_env()?.alias)
    }

    fn keypair_bytes(&self, address: SuiAddress) -> Result<Vec<u8>, anyhow::Error> {
        Ok(self.config.keystore.export(&address)?.to_bytes())
    }

    async fn sign_transaction(
        &self,
        transaction: &TransactionData,
    ) -> Result<Signature, anyhow::Error> {
        let sender = transaction.sender();
        Ok(self
            .config
            .keystore
            .sign_secure(
                &sender,
                transaction,
                shared_crypto::intent::Intent::sui_transaction(),
            )
            .await?)
    }
}

/// Minimal standalone-SDK wallet for a single active signing key.
pub struct SdkTransactionContext {
    rpc_url: String,
    environment_alias: String,
    active_address: SuiAddress,
    keypairs: Vec<SimpleKeypair>,
}

impl SdkTransactionContext {
    pub fn new(
        environment_alias: impl Into<String>,
        rpc_url: impl Into<String>,
        keypair: SimpleKeypair,
    ) -> Self {
        let active_address = keypair.verifying_key().derive_address().into();
        Self {
            rpc_url: rpc_url.into(),
            environment_alias: environment_alias.into(),
            active_address,
            keypairs: vec![keypair],
        }
    }

    /// Loads the active environment and simple key from a Sui CLI
    /// `client.yaml` plus its file-based `sui.keystore`.
    ///
    /// External signers and serialized in-memory test keystores remain on the
    /// `WalletContext` adapter because the standalone SDK has no equivalent
    /// configuration or external-signer abstraction.
    pub fn from_sui_client_config(path: impl AsRef<Path>) -> Result<Self, anyhow::Error> {
        let path = path.as_ref();
        let config: ClientConfig = serde_yaml::from_reader(File::open(path)?)?;
        let active_env = config
            .active_env
            .ok_or_else(|| anyhow::anyhow!("Sui client config has no active environment"))?;
        let rpc_url = config
            .envs
            .into_iter()
            .find(|environment| environment.alias == active_env)
            .map(|environment| environment.rpc)
            .ok_or_else(|| {
                anyhow::anyhow!("active Sui environment {active_env} is not configured")
            })?;
        let configured_active_address = config.active_address;
        let key_path = config.keystore.file.ok_or_else(|| {
            anyhow::anyhow!("standalone wallet loading supports only a file-based Sui keystore")
        })?;
        let encoded_keys: Vec<String> = serde_json::from_reader(File::open(&key_path)?)?;
        let keypairs = encoded_keys
            .into_iter()
            .map(|encoded| SimpleKeypair::from_base64(&encoded))
            .collect::<Result<Vec<_>, _>>()?;
        let active_address = configured_active_address
            .or_else(|| {
                keypairs
                    .first()
                    .map(|keypair| keypair.verifying_key().derive_address().into())
            })
            .ok_or_else(|| anyhow::anyhow!("Sui keystore has no keys"))?;
        anyhow::ensure!(
            keypairs.iter().any(|keypair| {
                SuiAddress::from(keypair.verifying_key().derive_address()) == active_address
            }),
            {
                let active_address = configured_active_address
                    .map(|address| address.to_string())
                    .unwrap_or_else(|| "<unset>".to_owned());
                format!(
                    "active address {active_address} is not present in {}",
                    key_path.display()
                )
            }
        );

        Ok(Self {
            rpc_url,
            environment_alias: active_env,
            active_address,
            keypairs,
        })
    }
}

#[async_trait]
impl TransactionContext for SdkTransactionContext {
    fn active_address(&self) -> Result<SuiAddress, anyhow::Error> {
        Ok(self.active_address)
    }

    fn rpc_url(&self) -> Result<&str, anyhow::Error> {
        Ok(&self.rpc_url)
    }

    fn environment_alias(&self) -> Result<&str, anyhow::Error> {
        Ok(&self.environment_alias)
    }

    fn keypair_bytes(&self, address: SuiAddress) -> Result<Vec<u8>, anyhow::Error> {
        let keypair = self
            .keypairs
            .iter()
            .find(|keypair| SuiAddress::from(keypair.verifying_key().derive_address()) == address)
            .ok_or_else(|| anyhow::anyhow!("standalone wallet has no key for address {address}"))?;
        Ok(Base64::decode(&keypair.to_base64())?)
    }

    async fn sign_transaction(
        &self,
        transaction: &TransactionData,
    ) -> Result<Signature, anyhow::Error> {
        let sender = transaction.sender();
        let keypair = self
            .keypairs
            .iter()
            .find(|keypair| SuiAddress::from(keypair.verifying_key().derive_address()) == sender)
            .ok_or_else(|| anyhow::anyhow!("standalone wallet has no key for sender {sender}"))?;
        let transaction: sui_sdk_types::Transaction = transaction.clone().try_into()?;
        match GenericSignature::try_from(keypair.sign_transaction(&transaction)?)? {
            GenericSignature::Signature(signature) => Ok(signature),
            _ => anyhow::bail!("simple standalone key produced a non-simple signature"),
        }
    }
}

#[derive(Deserialize)]
struct ClientConfig {
    keystore: ClientKeystore,
    envs: Vec<ClientEnvironment>,
    active_env: Option<String>,
    active_address: Option<SuiAddress>,
}

#[derive(Deserialize)]
struct ClientKeystore {
    #[serde(rename = "File")]
    file: Option<PathBuf>,
}

#[derive(Deserialize)]
struct ClientEnvironment {
    alias: String,
    rpc: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_legacy_file_keystore_and_infers_active_address() {
        let directory = tempfile::tempdir().unwrap();
        let keystore_path = directory.path().join("sui.keystore");
        let config_path = directory.path().join("client.yaml");
        let key_bytes = [vec![0], vec![7; 32]].concat();
        let second_key_bytes = [vec![0], vec![8; 32]].concat();
        let encoded_key = Base64::encode(&key_bytes);
        let encoded_second_key = Base64::encode(&second_key_bytes);
        let second_address: SuiAddress = SimpleKeypair::from_base64(&encoded_second_key)
            .unwrap()
            .verifying_key()
            .derive_address()
            .into();
        std::fs::write(
            &keystore_path,
            serde_json::to_vec(&vec![encoded_key, encoded_second_key]).unwrap(),
        )
        .unwrap();
        std::fs::write(
            &config_path,
            format!(
                "keystore:\n  File: {}\nenvs:\n  - alias: localnet\n    rpc: http://127.0.0.1:9000\nactive_env: localnet\nactive_address: ~\n",
                keystore_path.display()
            ),
        )
        .unwrap();

        let context = SdkTransactionContext::from_sui_client_config(config_path).unwrap();
        assert_eq!(context.environment_alias().unwrap(), "localnet");
        assert_eq!(context.rpc_url().unwrap(), "http://127.0.0.1:9000");
        assert_eq!(
            context
                .keypair_bytes(context.active_address().unwrap())
                .unwrap(),
            key_bytes
        );
        assert_eq!(
            context.keypair_bytes(second_address).unwrap(),
            second_key_bytes
        );
    }
}
