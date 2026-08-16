// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::path::Path;
use std::sync::OnceLock;

use async_trait::async_trait;
use fastcrypto::encoding::{Base64, Encoding};
use sui_crypto::SuiSigner;
use sui_crypto::simple::SimpleKeypair;
use sui_keys::keystore::{AccountKeystore, Keystore};
use sui_sdk::wallet_context::WalletContext;
use sui_sdk_types::Transaction as SdkTransaction;
use sui_types::base_types::SuiAddress;
use sui_types::crypto::Signature;
use sui_types::signature::GenericSignature;
use sui_types::transaction::{TransactionData, TransactionDataAPI};

use crate::grpc::SuiGrpcClient;

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

    fn grpc_client(&self) -> Result<SuiGrpcClient, anyhow::Error>;

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
            .or_else(|| self.get_addresses().first().copied())
            .ok_or_else(|| anyhow::anyhow!("Sui wallet has no managed addresses"))
    }

    fn rpc_url(&self) -> Result<&str, anyhow::Error> {
        Ok(&self.get_active_env()?.rpc)
    }

    fn environment_alias(&self) -> Result<&str, anyhow::Error> {
        Ok(&self.get_active_env()?.alias)
    }

    fn grpc_client(&self) -> Result<SuiGrpcClient, anyhow::Error> {
        let environment = self.get_active_env()?;
        Ok(SuiGrpcClient::connect_with_basic_auth(
            &environment.rpc,
            environment.basic_auth.as_deref(),
        )?)
    }

    fn keypair_bytes(&self, address: SuiAddress) -> Result<Vec<u8>, anyhow::Error> {
        Ok(self.config.keystore.export(&address)?.to_bytes())
    }

    async fn sign_transaction(
        &self,
        transaction: &TransactionData,
    ) -> Result<Signature, anyhow::Error> {
        let sender = transaction.sender();
        let keystore = wallet_keystore_for_address(self, sender)?;
        Ok(keystore
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
    wallet_fallback: Option<WalletContext>,
    basic_auth: Option<String>,
    grpc_client: OnceLock<SuiGrpcClient>,
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
            wallet_fallback: None,
            basic_auth: None,
            grpc_client: OnceLock::new(),
        }
    }

    /// Loads a Sui CLI configuration. Ordinary local simple keys use the
    /// standalone signer; active external keys retain the `WalletContext`
    /// adapter because the standalone SDK has no external-signer abstraction.
    pub fn from_sui_client_config(path: impl AsRef<Path>) -> Result<Self, anyhow::Error> {
        let path = path.as_ref();
        let wallet = WalletContext::new(path)?;
        let environment = wallet.get_active_env()?;
        let rpc_url = environment.rpc.clone();
        let environment_alias = environment.alias.clone();
        let basic_auth = environment.basic_auth.clone();
        let active_address = wallet
            .config
            .active_address
            .or_else(|| wallet.get_addresses().first().copied())
            .ok_or_else(|| anyhow::anyhow!("Sui wallet has no managed addresses"))?;
        let local_addresses = wallet.config.keystore.addresses();
        let keypairs = local_addresses
            .iter()
            .map(|address| {
                let keypair = wallet.config.keystore.export(address)?;
                SimpleKeypair::from_base64(&Base64::encode(keypair.to_bytes()))
                    .map_err(anyhow::Error::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let wallet_fallback = (!local_addresses.contains(&active_address)).then_some(wallet);

        Ok(Self {
            rpc_url,
            environment_alias,
            active_address,
            keypairs,
            wallet_fallback,
            basic_auth,
            grpc_client: OnceLock::new(),
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

    fn grpc_client(&self) -> Result<SuiGrpcClient, anyhow::Error> {
        if let Some(client) = self.grpc_client.get() {
            return Ok(client.clone());
        }
        let client =
            SuiGrpcClient::connect_with_basic_auth(&self.rpc_url, self.basic_auth.as_deref())?;
        let _ = self.grpc_client.set(client);
        Ok(self
            .grpc_client
            .get()
            .expect("gRPC client was initialized")
            .clone())
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
        if let Some(wallet) = &self.wallet_fallback {
            let sender = transaction.sender();
            return Ok(wallet_keystore_for_address(wallet, sender)?
                .sign_secure(
                    &sender,
                    transaction,
                    shared_crypto::intent::Intent::sui_transaction(),
                )
                .await?);
        }
        let sender = transaction.sender();
        let keypair = self
            .keypairs
            .iter()
            .find(|keypair| SuiAddress::from(keypair.verifying_key().derive_address()) == sender)
            .ok_or_else(|| anyhow::anyhow!("standalone wallet has no key for sender {sender}"))?;
        let transaction: SdkTransaction = transaction.clone().try_into()?;
        match GenericSignature::try_from(keypair.sign_transaction(&transaction)?)? {
            GenericSignature::Signature(signature) => Ok(signature),
            _ => anyhow::bail!("simple standalone key produced a non-simple signature"),
        }
    }
}

fn wallet_keystore_for_address(
    wallet: &WalletContext,
    address: SuiAddress,
) -> Result<&Keystore, anyhow::Error> {
    if wallet.config.keystore.addresses().contains(&address) {
        return Ok(&wallet.config.keystore);
    }
    if let Some(external_keys) = &wallet.config.external_keys
        && external_keys.addresses().contains(&address)
    {
        return Ok(external_keys);
    }
    anyhow::bail!("Sui wallet has no signing key for address {address}")
}

#[cfg(test)]
mod tests {
    use std::fs;

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
        let first_address: SuiAddress = SimpleKeypair::from_base64(&encoded_key)
            .unwrap()
            .verifying_key()
            .derive_address()
            .into();
        let second_address: SuiAddress = SimpleKeypair::from_base64(&encoded_second_key)
            .unwrap()
            .verifying_key()
            .derive_address()
            .into();
        fs::write(
            &keystore_path,
            serde_json::to_vec(&vec![encoded_key, encoded_second_key]).unwrap(),
        )
        .unwrap();
        fs::write(
            &config_path,
            format!(
                "keystore:\n  File: {}\nenvs:\n  - alias: localnet\n    rpc: http://127.0.0.1:9000\n    ws: ~\n    basic_auth: user:password\nactive_env: localnet\nactive_address: ~\n",
                keystore_path.display()
            ),
        )
        .unwrap();

        let context = SdkTransactionContext::from_sui_client_config(config_path).unwrap();
        assert_eq!(context.environment_alias().unwrap(), "localnet");
        assert_eq!(context.rpc_url().unwrap(), "http://127.0.0.1:9000");
        assert_eq!(context.basic_auth.as_deref(), Some("user:password"));
        let expected_active_address = first_address.min(second_address);
        let expected_active_key = if expected_active_address == first_address {
            &key_bytes
        } else {
            &second_key_bytes
        };
        assert_eq!(
            context
                .keypair_bytes(context.active_address().unwrap())
                .unwrap(),
            expected_active_key.clone()
        );
        assert_eq!(
            context.keypair_bytes(second_address).unwrap(),
            second_key_bytes
        );
    }

    #[test]
    fn loads_read_only_context_when_active_address_has_no_local_key() {
        let directory = tempfile::tempdir().unwrap();
        let keystore_path = directory.path().join("sui.keystore");
        let config_path = directory.path().join("client.yaml");
        let active_address = SuiAddress::random_for_testing_only();
        fs::write(&keystore_path, "[]").unwrap();
        fs::write(
            &config_path,
            format!(
                "keystore:\n  File: {}\nenvs:\n  - alias: localnet\n    rpc: http://127.0.0.1:9000\n    ws: ~\n    basic_auth: ~\nactive_env: localnet\nactive_address: {}\n",
                keystore_path.display(),
                active_address
            ),
        )
        .unwrap();

        let context = SdkTransactionContext::from_sui_client_config(config_path).unwrap();
        assert_eq!(context.active_address().unwrap(), active_address);
        assert!(context.wallet_fallback.is_some());
    }
}
