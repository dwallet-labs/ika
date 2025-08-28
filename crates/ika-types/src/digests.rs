// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::{env, fmt};

use crate::error::IkaError;
use fastcrypto::encoding::{Base58, Encoding, Hex};
use ika_protocol_config::Chain;
use once_cell::sync::{Lazy, OnceCell};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::{Bytes, serde_as};
use sui_types::base_types::ObjectID;
pub use sui_types::digests::ConsensusCommitDigest;
use sui_types::sui_serde::Readable;
use tracing::info;

/// A representation of a 32 byte digest
#[serde_as]
#[derive(
    Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct Digest(
    #[schemars(with = "Base58")]
    #[serde_as(as = "Readable<Base58, Bytes>")]
    [u8; 32],
);

impl Digest {
    pub const ZERO: Self = Digest([0; 32]);

    pub const fn new(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    pub fn generate<R: rand::RngCore + rand::CryptoRng>(mut rng: R) -> Self {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn random() -> Self {
        Self::generate(rand::thread_rng())
    }

    pub const fn inner(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn into_inner(self) -> [u8; 32] {
        self.0
    }

    pub fn next_lexicographical(&self) -> Option<Self> {
        let mut next_digest = *self;
        let pos = next_digest.0.iter().rposition(|&byte| byte != 255)?;
        next_digest.0[pos] += 1;
        next_digest
            .0
            .iter_mut()
            .skip(pos + 1)
            .for_each(|byte| *byte = 0);
        Some(next_digest)
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; 32]> for Digest {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<Digest> for [u8; 32] {
    fn from(digest: Digest) -> Self {
        digest.into_inner()
    }
}

impl From<[u8; 32]> for Digest {
    fn from(digest: [u8; 32]) -> Self {
        Self::new(digest)
    }
}

impl TryFrom<Vec<u8>> for Digest {
    type Error = IkaError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, IkaError> {
        let bytes: [u8; 32] =
            <[u8; 32]>::try_from(&bytes[..]).map_err(|_| IkaError::InvalidDigestLength {
                expected: 32,
                actual: bytes.len(),
            })?;

        Ok(Self::from(bytes))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO avoid the allocation
        f.write_str(&Base58::encode(self.0))
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::LowerHex for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }

        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }

        Ok(())
    }
}

impl fmt::UpperHex for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }

        for byte in self.0 {
            write!(f, "{byte:02X}")?;
        }

        Ok(())
    }
}

/// Representation of a network's identifier by the genesis checkpoint's digest
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct ChainIdentifier(ObjectID);

impl Default for ChainIdentifier {
    fn default() -> Self {
        Self(ObjectID::ZERO)
    }
}

pub const MAINNET_CHAIN_IDENTIFIER_BASE58: &str = "3FFWaJu1SeurUdyLuWbhc7xE7ThvVqfHkjopBge3vLVu";
pub const TESTNET_CHAIN_IDENTIFIER_BASE58: &str = "3FZxkWnWSKp64iY6h6GrBuW3CKxxpBDcnfEVyTZ8EZnV";

pub static MAINNET_CHAIN_IDENTIFIER: OnceCell<ChainIdentifier> = OnceCell::new();
pub static TESTNET_CHAIN_IDENTIFIER: OnceCell<ChainIdentifier> = OnceCell::new();

/// For testing purposes or bootstrapping chain reconfiguration, you can set
/// this environment variable to force protocol config to use a specific Chain.
const IKA_PROTOCOL_CONFIG_CHAIN_OVERRIDE_ENV_VAR_NAME: &str = "IKA_PROTOCOL_CONFIG_CHAIN_OVERRIDE";

static IKA_PROTOCOL_CONFIG_CHAIN_OVERRIDE: Lazy<Option<Chain>> = Lazy::new(|| {
    if let Ok(s) = env::var(IKA_PROTOCOL_CONFIG_CHAIN_OVERRIDE_ENV_VAR_NAME) {
        info!("IKA_PROTOCOL_CONFIG_CHAIN_OVERRIDE: {:?}", s);
        match s.as_str() {
            "mainnet" => Some(Chain::Mainnet),
            "testnet" => Some(Chain::Testnet),
            "" => None,
            _ => panic!("unrecognized IKA_PROTOCOL_CONFIG_CHAIN_OVERRIDE: {s:?}"),
        }
    } else {
        None
    }
});

impl ChainIdentifier {
    /// take a short 4 byte identifier and convert it into a ChainIdentifier
    /// short ids come from the JSON RPC getChainIdentifier and are encoded in hex
    pub fn from_chain_short_id(short_id: &String) -> Option<Self> {
        if Hex::from_bytes(&Base58::decode(MAINNET_CHAIN_IDENTIFIER_BASE58).ok()?)
            .encoded_with_format()
            .starts_with(&format!("0x{short_id}"))
        {
            Some(get_mainnet_chain_identifier())
        } else if Hex::from_bytes(&Base58::decode(TESTNET_CHAIN_IDENTIFIER_BASE58).ok()?)
            .encoded_with_format()
            .starts_with(&format!("0x{short_id}"))
        {
            Some(get_testnet_chain_identifier())
        } else {
            None
        }
    }

    pub fn chain(&self) -> Chain {
        let mainnet_id = get_mainnet_chain_identifier();
        let testnet_id = get_testnet_chain_identifier();

        let chain = match self {
            id if *id == mainnet_id => Chain::Mainnet,
            id if *id == testnet_id => Chain::Testnet,
            _ => Chain::Unknown,
        };
        if let Some(override_chain) = *IKA_PROTOCOL_CONFIG_CHAIN_OVERRIDE {
            if chain != Chain::Unknown {
                panic!("not allowed to override real chain {chain:?}");
            }
            return override_chain;
        }

        chain
    }

    // pub fn as_bytes(&self) -> &[u8; 32] {
    //     self.as_bytes()
    // }

    pub fn base58_encode(&self) -> String {
        Base58::encode(self.0)
    }
}

pub fn get_mainnet_chain_identifier() -> ChainIdentifier {
    let object_id = MAINNET_CHAIN_IDENTIFIER.get_or_init(|| {
        let object_id = ObjectID::new(
            Base58::decode(MAINNET_CHAIN_IDENTIFIER_BASE58)
                .expect("mainnet genesis checkpoint digest literal is invalid")
                .try_into()
                .expect("Mainnet genesis checkpoint digest literal has incorrect length"),
        );
        ChainIdentifier::from(object_id)
    });
    *object_id
}

pub fn get_testnet_chain_identifier() -> ChainIdentifier {
    let object_id = TESTNET_CHAIN_IDENTIFIER.get_or_init(|| {
        let object_id = ObjectID::new(
            Base58::decode(TESTNET_CHAIN_IDENTIFIER_BASE58)
                .expect("testnet genesis checkpoint digest literal is invalid")
                .try_into()
                .expect("Testnet genesis checkpoint digest literal has incorrect length"),
        );
        ChainIdentifier::from(object_id)
    });
    *object_id
}

impl fmt::Display for ChainIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.as_ref()[0..4].iter() {
            write!(f, "{byte:02x}")?;
        }

        Ok(())
    }
}

impl From<ObjectID> for ChainIdentifier {
    fn from(object_id: ObjectID) -> Self {
        Self(object_id)
    }
}

/// Representation of a [`DWalletCheckpointMessageDigest`] digest
#[derive(
    Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct DWalletCheckpointMessageDigest(Digest);

impl DWalletCheckpointMessageDigest {
    pub const fn new(digest: [u8; 32]) -> Self {
        Self(Digest::new(digest))
    }

    pub fn generate<R: rand::RngCore + rand::CryptoRng>(rng: R) -> Self {
        Self(Digest::generate(rng))
    }

    pub fn random() -> Self {
        Self(Digest::random())
    }

    pub const fn inner(&self) -> &[u8; 32] {
        self.0.inner()
    }

    pub const fn into_inner(self) -> [u8; 32] {
        self.0.into_inner()
    }

    pub fn base58_encode(&self) -> String {
        Base58::encode(self.0)
    }

    pub fn next_lexicographical(&self) -> Option<Self> {
        self.0.next_lexicographical().map(Self)
    }
}

impl AsRef<[u8]> for DWalletCheckpointMessageDigest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<[u8; 32]> for DWalletCheckpointMessageDigest {
    fn as_ref(&self) -> &[u8; 32] {
        self.0.as_ref()
    }
}

impl From<DWalletCheckpointMessageDigest> for [u8; 32] {
    fn from(digest: DWalletCheckpointMessageDigest) -> Self {
        digest.into_inner()
    }
}

impl From<[u8; 32]> for DWalletCheckpointMessageDigest {
    fn from(digest: [u8; 32]) -> Self {
        Self::new(digest)
    }
}

impl TryFrom<Vec<u8>> for DWalletCheckpointMessageDigest {
    type Error = IkaError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, IkaError> {
        Digest::try_from(bytes).map(DWalletCheckpointMessageDigest)
    }
}

impl fmt::Display for DWalletCheckpointMessageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Debug for DWalletCheckpointMessageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DWalletCheckpointDigest")
            .field(&self.0)
            .finish()
    }
}

impl fmt::LowerHex for DWalletCheckpointMessageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for DWalletCheckpointMessageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

impl std::str::FromStr for DWalletCheckpointMessageDigest {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut result = [0; 32];
        let buffer = Base58::decode(s).map_err(|e| anyhow::anyhow!(e))?;
        if buffer.len() != 32 {
            return Err(anyhow::anyhow!("Invalid digest length. Expected 32 bytes"));
        }
        result.copy_from_slice(&buffer);
        Ok(DWalletCheckpointMessageDigest::new(result))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
pub struct DWalletCheckpointContentsDigest(Digest);

impl DWalletCheckpointContentsDigest {
    pub const fn new(digest: [u8; 32]) -> Self {
        Self(Digest::new(digest))
    }

    pub fn generate<R: rand::RngCore + rand::CryptoRng>(rng: R) -> Self {
        Self(Digest::generate(rng))
    }

    pub fn random() -> Self {
        Self(Digest::random())
    }

    pub const fn inner(&self) -> &[u8; 32] {
        self.0.inner()
    }

    pub const fn into_inner(self) -> [u8; 32] {
        self.0.into_inner()
    }

    pub fn base58_encode(&self) -> String {
        Base58::encode(self.0)
    }

    pub fn next_lexicographical(&self) -> Option<Self> {
        self.0.next_lexicographical().map(Self)
    }
}

impl AsRef<[u8]> for DWalletCheckpointContentsDigest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<[u8; 32]> for DWalletCheckpointContentsDigest {
    fn as_ref(&self) -> &[u8; 32] {
        self.0.as_ref()
    }
}

impl TryFrom<Vec<u8>> for DWalletCheckpointContentsDigest {
    type Error = IkaError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, IkaError> {
        Digest::try_from(bytes).map(DWalletCheckpointContentsDigest)
    }
}

impl From<DWalletCheckpointContentsDigest> for [u8; 32] {
    fn from(digest: DWalletCheckpointContentsDigest) -> Self {
        digest.into_inner()
    }
}

impl From<[u8; 32]> for DWalletCheckpointContentsDigest {
    fn from(digest: [u8; 32]) -> Self {
        Self::new(digest)
    }
}

impl fmt::Display for DWalletCheckpointContentsDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Debug for DWalletCheckpointContentsDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DWalletCheckpointContentsDigest")
            .field(&self.0)
            .finish()
    }
}

impl std::str::FromStr for DWalletCheckpointContentsDigest {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut result = [0; 32];
        let buffer = Base58::decode(s).map_err(|e| anyhow::anyhow!(e))?;
        if buffer.len() != 32 {
            return Err(anyhow::anyhow!("Invalid digest length. Expected 32 bytes"));
        }
        result.copy_from_slice(&buffer);
        Ok(DWalletCheckpointContentsDigest::new(result))
    }
}

impl fmt::LowerHex for DWalletCheckpointContentsDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for DWalletCheckpointContentsDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}
/// A digest of a certificate, which commits to the signatures as well as the tx.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CertificateDigest(Digest);

impl CertificateDigest {
    pub const fn new(digest: [u8; 32]) -> Self {
        Self(Digest::new(digest))
    }

    pub fn random() -> Self {
        Self(Digest::random())
    }
}

impl fmt::Debug for CertificateDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CertificateDigest").field(&self.0).finish()
    }
}

/// A digest of a SenderSignedData, which commits to the signatures as well as the tx.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SenderSignedDataDigest(Digest);

impl SenderSignedDataDigest {
    pub const fn new(digest: [u8; 32]) -> Self {
        Self(Digest::new(digest))
    }
}

impl fmt::Debug for SenderSignedDataDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SenderSignedDataDigest")
            .field(&self.0)
            .finish()
    }
}

/// A message will have a (unique) digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
pub struct MessageDigest(Digest);

impl Default for MessageDigest {
    fn default() -> Self {
        Self::ZERO
    }
}

impl MessageDigest {
    pub const ZERO: Self = Self(Digest::ZERO);

    pub const fn new(digest: [u8; 32]) -> Self {
        Self(Digest::new(digest))
    }

    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    pub fn generate<R: rand::RngCore + rand::CryptoRng>(rng: R) -> Self {
        Self(Digest::generate(rng))
    }

    pub fn random() -> Self {
        Self(Digest::random())
    }

    pub fn inner(&self) -> &[u8; 32] {
        self.0.inner()
    }

    pub fn into_inner(self) -> [u8; 32] {
        self.0.into_inner()
    }

    pub fn base58_encode(&self) -> String {
        Base58::encode(self.0)
    }

    pub fn next_lexicographical(&self) -> Option<Self> {
        self.0.next_lexicographical().map(Self)
    }
}

impl AsRef<[u8]> for MessageDigest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<[u8; 32]> for MessageDigest {
    fn as_ref(&self) -> &[u8; 32] {
        self.0.as_ref()
    }
}

impl From<MessageDigest> for [u8; 32] {
    fn from(digest: MessageDigest) -> Self {
        digest.into_inner()
    }
}

impl From<[u8; 32]> for MessageDigest {
    fn from(digest: [u8; 32]) -> Self {
        Self::new(digest)
    }
}

impl fmt::Display for MessageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Debug for MessageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MessageDigest").field(&self.0).finish()
    }
}

impl fmt::LowerHex for MessageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for MessageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

impl TryFrom<&[u8]> for MessageDigest {
    type Error = IkaError;

    fn try_from(bytes: &[u8]) -> Result<Self, IkaError> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| IkaError::InvalidMessageDigest)?;
        Ok(Self::new(arr))
    }
}

impl TryFrom<Vec<u8>> for MessageDigest {
    type Error = IkaError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, IkaError> {
        Digest::try_from(bytes).map(MessageDigest)
    }
}

impl std::str::FromStr for MessageDigest {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut result = [0; 32];
        let buffer = Base58::decode(s).map_err(|e| anyhow::anyhow!(e))?;
        if buffer.len() != 32 {
            return Err(anyhow::anyhow!("Invalid digest length. Expected 32 bytes"));
        }
        result.copy_from_slice(&buffer);
        Ok(MessageDigest::new(result))
    }
}

/// Representation of a DWalletMPCMessage's digest
#[derive(
    Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct DWalletMPCMessageDigest(pub Digest);

impl DWalletMPCMessageDigest {
    pub const fn new(digest: [u8; 32]) -> Self {
        Self(Digest::new(digest))
    }

    pub fn generate<R: rand::RngCore + rand::CryptoRng>(rng: R) -> Self {
        Self(Digest::generate(rng))
    }

    pub fn random() -> Self {
        Self(Digest::random())
    }

    pub const fn inner(&self) -> &[u8; 32] {
        self.0.inner()
    }

    pub const fn into_inner(self) -> [u8; 32] {
        self.0.into_inner()
    }

    pub fn base58_encode(&self) -> String {
        Base58::encode(self.0)
    }

    pub fn next_lexicographical(&self) -> Option<Self> {
        self.0.next_lexicographical().map(Self)
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
)]
/// The digest type of the DWalletMPCOutput.
/// Needed in order to implement the [`crate::message_envelope::Message`] trait for the DWalletMPCOutput,
/// which is needed in order to send the message over the network.
pub struct DWalletMPCOutputDigest(pub Digest);

impl DWalletMPCOutputDigest {
    pub const fn new(digest: [u8; 32]) -> Self {
        Self(Digest::new(digest))
    }

    pub fn generate<R: rand::RngCore + rand::CryptoRng>(rng: R) -> Self {
        Self(Digest::generate(rng))
    }

    pub fn random() -> Self {
        Self(Digest::random())
    }

    pub const fn inner(&self) -> &[u8; 32] {
        self.0.inner()
    }

    pub const fn into_inner(self) -> [u8; 32] {
        self.0.into_inner()
    }

    pub fn base58_encode(&self) -> String {
        Base58::encode(self.0)
    }

    pub fn next_lexicographical(&self) -> Option<Self> {
        self.0.next_lexicographical().map(Self)
    }
}

/// Representation of a SystemCheckpoint's digest
#[derive(
    Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct SystemCheckpointMessageDigest(Digest);

impl SystemCheckpointMessageDigest {
    pub const fn new(digest: [u8; 32]) -> Self {
        Self(Digest::new(digest))
    }

    pub fn generate<R: rand::RngCore + rand::CryptoRng>(rng: R) -> Self {
        Self(Digest::generate(rng))
    }

    pub fn random() -> Self {
        Self(Digest::random())
    }

    pub const fn inner(&self) -> &[u8; 32] {
        self.0.inner()
    }

    pub const fn into_inner(self) -> [u8; 32] {
        self.0.into_inner()
    }

    pub fn base58_encode(&self) -> String {
        Base58::encode(self.0)
    }

    pub fn next_lexicographical(&self) -> Option<Self> {
        self.0.next_lexicographical().map(Self)
    }
}

impl AsRef<[u8]> for SystemCheckpointMessageDigest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<[u8; 32]> for SystemCheckpointMessageDigest {
    fn as_ref(&self) -> &[u8; 32] {
        self.0.as_ref()
    }
}

impl From<SystemCheckpointMessageDigest> for [u8; 32] {
    fn from(digest: SystemCheckpointMessageDigest) -> Self {
        digest.into_inner()
    }
}

impl From<[u8; 32]> for SystemCheckpointMessageDigest {
    fn from(digest: [u8; 32]) -> Self {
        Self::new(digest)
    }
}

impl TryFrom<Vec<u8>> for SystemCheckpointMessageDigest {
    type Error = IkaError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, IkaError> {
        Digest::try_from(bytes).map(SystemCheckpointMessageDigest)
    }
}

impl fmt::Display for SystemCheckpointMessageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Debug for SystemCheckpointMessageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SystemCheckpointDigest")
            .field(&self.0)
            .finish()
    }
}

impl fmt::LowerHex for SystemCheckpointMessageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for SystemCheckpointMessageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

impl std::str::FromStr for SystemCheckpointMessageDigest {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut result = [0; 32];
        let buffer = Base58::decode(s).map_err(|e| anyhow::anyhow!(e))?;
        if buffer.len() != 32 {
            return Err(anyhow::anyhow!("Invalid digest length. Expected 32 bytes"));
        }
        result.copy_from_slice(&buffer);
        Ok(SystemCheckpointMessageDigest::new(result))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
pub struct SystemCheckpointContentsDigest(Digest);

impl SystemCheckpointContentsDigest {
    pub const fn new(digest: [u8; 32]) -> Self {
        Self(Digest::new(digest))
    }

    pub fn generate<R: rand::RngCore + rand::CryptoRng>(rng: R) -> Self {
        Self(Digest::generate(rng))
    }

    pub fn random() -> Self {
        Self(Digest::random())
    }

    pub const fn inner(&self) -> &[u8; 32] {
        self.0.inner()
    }

    pub const fn into_inner(self) -> [u8; 32] {
        self.0.into_inner()
    }

    pub fn base58_encode(&self) -> String {
        Base58::encode(self.0)
    }

    pub fn next_lexicographical(&self) -> Option<Self> {
        self.0.next_lexicographical().map(Self)
    }
}

impl AsRef<[u8]> for SystemCheckpointContentsDigest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<[u8; 32]> for SystemCheckpointContentsDigest {
    fn as_ref(&self) -> &[u8; 32] {
        self.0.as_ref()
    }
}

impl TryFrom<Vec<u8>> for SystemCheckpointContentsDigest {
    type Error = IkaError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, IkaError> {
        Digest::try_from(bytes).map(SystemCheckpointContentsDigest)
    }
}

impl From<SystemCheckpointContentsDigest> for [u8; 32] {
    fn from(digest: SystemCheckpointContentsDigest) -> Self {
        digest.into_inner()
    }
}

impl From<[u8; 32]> for SystemCheckpointContentsDigest {
    fn from(digest: [u8; 32]) -> Self {
        Self::new(digest)
    }
}

impl fmt::Display for SystemCheckpointContentsDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Debug for SystemCheckpointContentsDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SystemCheckpointContentsDigest")
            .field(&self.0)
            .finish()
    }
}

impl std::str::FromStr for SystemCheckpointContentsDigest {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut result = [0; 32];
        let buffer = Base58::decode(s).map_err(|e| anyhow::anyhow!(e))?;
        if buffer.len() != 32 {
            return Err(anyhow::anyhow!("Invalid digest length. Expected 32 bytes"));
        }
        result.copy_from_slice(&buffer);
        Ok(SystemCheckpointContentsDigest::new(result))
    }
}

impl fmt::LowerHex for SystemCheckpointContentsDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for SystemCheckpointContentsDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}
