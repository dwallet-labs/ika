// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear
use crate::committee::CommitteeTrait;
use crate::committee::{Committee, EpochId, StakeUnit};
use crate::error::{IkaError, IkaResult};
use crate::ika_serde::IkaBitmap;
use crate::intent::{Intent, IntentMessage, IntentScope};
use anyhow::{Error, anyhow};
use derive_more::AsRef;
pub use enum_dispatch::enum_dispatch;
use fastcrypto::bls12381::min_pk::{
    BLS12381AggregateSignature, BLS12381AggregateSignatureAsBytes, BLS12381KeyPair,
    BLS12381PrivateKey, BLS12381PublicKey, BLS12381Signature,
};
use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519PrivateKey, Ed25519PublicKey};
use fastcrypto::encoding::{Base64, Encoding, Hex};
use fastcrypto::error::FastCryptoError;
use fastcrypto::hash::{Blake2b256, HashFunction, Keccak256};
use fastcrypto::secp256k1::Secp256k1PublicKey;
use fastcrypto::secp256r1::Secp256r1PublicKey;
pub use fastcrypto::traits::KeyPair as KeypairTraits;
pub use fastcrypto::traits::Signer;
pub use fastcrypto::traits::{
    AggregateAuthenticator, Authenticator, EncodeDecodeBase64, SigningKey, ToFromBytes,
    VerifyingKey,
};
use move_core_types::account_address::AccountAddress;
use rand::SeedableRng;
use rand::rngs::StdRng;
use roaring::RoaringBitmap;
use schemars::JsonSchema;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{Bytes, DeserializeAs, SerializeAs, serde_as};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::str::FromStr;
use sui_types::base_types::{ConciseableName, SuiAddress};
use sui_types::crypto::SignatureScheme;
use sui_types::sui_serde::Readable;
use tracing::{instrument, warn};

// Authority Objects
pub type AuthorityKeyPair = BLS12381KeyPair;
pub type AuthorityPublicKey = BLS12381PublicKey;
pub type AuthorityPrivateKey = BLS12381PrivateKey;
pub type AuthoritySignature = BLS12381Signature;
pub type AggregateAuthoritySignature = BLS12381AggregateSignature;
pub type AggregateAuthoritySignatureAsBytes = BLS12381AggregateSignatureAsBytes;

// TODO(joyqvq): prefix these types with Default, DefaultAccountKeyPair etc
pub type AccountKeyPair = Ed25519KeyPair;
pub type AccountPublicKey = Ed25519PublicKey;
pub type AccountPrivateKey = Ed25519PrivateKey;

pub type NetworkKeyPair = Ed25519KeyPair;
pub type NetworkPublicKey = Ed25519PublicKey;
pub type NetworkPrivateKey = Ed25519PrivateKey;

pub type DefaultHash = Blake2b256;

pub const DEFAULT_EPOCH_ID: EpochId = 0;

/// A validator's committee identity: its Ed25519 consensus public key, held
/// as the raw 32 bytes with no padding.
///
/// Distinct from [`AuthorityPublicKeyBytes`], which is the 48-byte BLS
/// protocol-key container. The two were the same type through protocol v5,
/// when the BLS key WAS the identity; they are different things now and
/// conflating them is how a name derived from the wrong key silently drops a
/// validator out of its own committee.
///
/// On the wire it is the raw 32 bytes. Through protocol v6 it was emitted
/// zero-padded into the 48-byte container instead; that form is no longer
/// produced but still DECODES, because records written before the v7 boundary
/// hold it.
#[serde_as]
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
    AsRef,
)]
#[as_ref(forward)]
pub struct AuthorityName(
    #[schemars(with = "Base64")]
    #[serde_as(
        serialize_as = "AuthorityNameEncoding",
        deserialize_as = "LenientAuthorityName"
    )]
    pub [u8; Ed25519PublicKey::LENGTH],
);

impl AuthorityName {
    pub const ZERO: Self = Self([0u8; Ed25519PublicKey::LENGTH]);

    /// The canonical name of a validator identified by its consensus key.
    pub fn from_consensus_key(key: &NetworkPublicKey) -> Self {
        let mut bytes = [0u8; Ed25519PublicKey::LENGTH];
        bytes.copy_from_slice(key.as_bytes());
        Self(bytes)
    }

    /// The consensus key this name IS.
    pub fn to_consensus_key(self) -> Result<NetworkPublicKey, FastCryptoError> {
        Ed25519PublicKey::from_bytes(&self.0)
    }
}

impl ToFromBytes for AuthorityName {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        let bytes: [u8; Ed25519PublicKey::LENGTH] = bytes
            .try_into()
            .map_err(|_| FastCryptoError::InvalidInput)?;
        Ok(Self(bytes))
    }
}

impl From<&NetworkPublicKey> for AuthorityName {
    fn from(key: &NetworkPublicKey) -> Self {
        Self::from_consensus_key(key)
    }
}

impl FromStr for AuthorityName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = Hex::decode(s).map_err(|e| anyhow!(e))?;
        Self::from_bytes(&value[..]).map_err(|e| anyhow!(e))
    }
}

/// A `Debug`/`Display` wrapper printing a short prefix, mirroring
/// [`ConciseAuthorityPublicKeyBytesRef`] for the BLS container.
pub struct ConciseAuthorityNameRef<'a>(&'a AuthorityName);

impl Debug for ConciseAuthorityNameRef<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "k#{}..", Hex::encode(&self.0.0[..4]))
    }
}

impl Display for ConciseAuthorityNameRef<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        Debug::fmt(self, f)
    }
}

pub struct ConciseAuthorityName(AuthorityName);

impl Debug for ConciseAuthorityName {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "k#{}..", Hex::encode(&self.0.0[..4]))
    }
}

impl Display for ConciseAuthorityName {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        Debug::fmt(self, f)
    }
}

impl<'a> ConciseableName<'a> for AuthorityName {
    type ConciseTypeRef = ConciseAuthorityNameRef<'a>;
    type ConciseType = ConciseAuthorityName;

    fn concise(&'a self) -> ConciseAuthorityNameRef<'a> {
        ConciseAuthorityNameRef(self)
    }

    fn concise_owned(&self) -> ConciseAuthorityName {
        ConciseAuthorityName(*self)
    }
}

impl Default for AuthorityName {
    fn default() -> Self {
        Self::ZERO
    }
}

impl Debug for AuthorityName {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "k#{}", Hex::encode(self.0))
    }
}

impl Display for AuthorityName {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        Debug::fmt(self, f)
    }
}

/// Creates a proof of that the authority account address is owned by the
/// holder of authority protocol key, and also ensures that the authority
/// protocol public key exists. A proof of possession is an authority
/// signature committed over the intent message `intent || message || epoch` (See
/// more at [struct IntentMessage] and [struct Intent]) where the message is
/// constructed as `authority_pubkey_bytes || authority_account_address`.
pub fn generate_proof_of_possession(
    keypair: &AuthorityKeyPair,
    address: SuiAddress,
) -> AuthoritySignature {
    let mut msg: Vec<u8> = Vec::new();
    msg.extend_from_slice(keypair.public().as_bytes());
    msg.extend_from_slice(address.as_ref());
    AuthoritySignature::new_secure(
        &IntentMessage::new(Intent::ika_app(IntentScope::ProofOfPossession), msg),
        &DEFAULT_EPOCH_ID,
        keypair,
    )
}

/// Verify proof of possession against the expected intent message,
/// consisting of the protocol pubkey and the authority account address.
pub fn verify_proof_of_possession(
    pop: &AuthoritySignature,
    protocol_pubkey: &AuthorityPublicKey,
    sui_address: SuiAddress,
) -> Result<(), IkaError> {
    protocol_pubkey
        .validate()
        .map_err(|_| IkaError::InvalidSignature {
            error: "Fail to validate pubkey".to_string(),
        })?;
    let mut msg = protocol_pubkey.as_bytes().to_vec();
    msg.extend_from_slice(sui_address.as_ref());
    pop.verify_secure(
        &IntentMessage::new(Intent::ika_app(IntentScope::ProofOfPossession), msg),
        DEFAULT_EPOCH_ID,
        protocol_pubkey.into(),
    )
}

pub trait IkaPublicKey: VerifyingKey {
    const SIGNATURE_SCHEME: SignatureScheme;
}

impl IkaPublicKey for BLS12381PublicKey {
    const SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::BLS12381;
}

impl IkaPublicKey for Ed25519PublicKey {
    const SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::ED25519;
}

impl IkaPublicKey for Secp256k1PublicKey {
    const SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::Secp256k1;
}

impl IkaPublicKey for Secp256r1PublicKey {
    const SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::Secp256r1;
}

fn ika_public_key_into_sui_address<T: IkaPublicKey>(pk: &T) -> SuiAddress {
    let mut hasher = DefaultHash::default();
    hasher.update([T::SIGNATURE_SCHEME.flag()]);
    hasher.update(pk);
    let g_arr = hasher.finalize();
    AccountAddress::new(g_arr.digest).into()
}

/// Defines the compressed version of the public key that we pass around
/// in Ika
#[serde_as]
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
    AsRef,
)]
#[as_ref(forward)]
pub struct AuthorityPublicKeyBytes(
    #[schemars(with = "Base64")]
    #[serde_as(as = "Readable<Base64, Bytes>")]
    pub [u8; AuthorityPublicKey::LENGTH],
);

/// Width-aware serialization is GONE: `AuthorityName` is the raw 32-byte
/// Ed25519 consensus key, unconditionally.
///
/// Through protocol v6 it was that key zero-padded into the 48-byte container
/// the BLS protocol key occupied, and v7 flipped the whole committee to the
/// short form at one epoch boundary. With `MIN_PROTOCOL_VERSION = 7` no
/// supported version emits the padded form, so the ambient process state that
/// carried the width — a static, a thread-local override, and the cross-epoch
/// retry that consumed them — is deleted rather than left as dead scaffolding
/// a future reader has to reason about.
///
/// What made that scaffolding necessary is worth keeping in view, because it
/// governs any future change to a wire encoding: `AuthorityName` is a field of
/// `AuthorityCapabilitiesV1`, of ten MPC consensus messages, and of
/// `HandoffItemKey`, and both `verify_handoff_signature` and
/// `hash_next_committee_pubkey_set` reconstruct signed and hashed bytes by
/// re-serializing locally. Two validators emitting different widths therefore
/// compute different digests and reject each other's signatures while parsing
/// each other's messages perfectly. Any such change must ride a protocol
/// version so the whole committee flips together — never a per-binary switch.
///
/// DECODING stays lenient (see `LenientAuthorityKeyBytes`): rows and archives
/// written before the v7 boundary hold the 48-byte form, and a node must keep
/// reading its own history.
/// Serializer for [`AuthorityName`]: the raw 32 bytes, always.
struct AuthorityNameEncoding;

impl SerializeAs<[u8; Ed25519PublicKey::LENGTH]> for AuthorityNameEncoding {
    fn serialize_as<S>(
        source: &[u8; Ed25519PublicKey::LENGTH],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: &[u8] = source.as_slice();
        if serializer.is_human_readable() {
            serializer.serialize_str(&Base64::encode(bytes))
        } else {
            serializer.serialize_bytes(bytes)
        }
    }
}

/// Length-lenient deserializer for [`AuthorityName`]: accepts the raw 32 bytes
/// and the 48-byte padded form, so a node reads both widths regardless of which
/// one it emits. A 48-byte value whose tail is NOT zero is a BLS-basis name
/// from a pre-v6 epoch; it cannot be represented as a consensus key, so it is
/// rejected rather than silently truncated. Nothing live decodes such a record
/// (see `CommitteeStore`), and failing loudly is what keeps a truncated,
/// wrong-identity name from ever entering a committee.
struct LenientAuthorityName;

impl<'de> DeserializeAs<'de, [u8; Ed25519PublicKey::LENGTH]> for LenientAuthorityName {
    fn deserialize_as<D>(deserializer: D) -> Result<[u8; Ed25519PublicKey::LENGTH], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = if deserializer.is_human_readable() {
            let encoded = String::deserialize(deserializer)?;
            Base64::decode(&encoded).map_err(D::Error::custom)?
        } else {
            Bytes::deserialize_as(deserializer)?
        };
        match bytes.len() {
            len if len == Ed25519PublicKey::LENGTH => {
                bytes.as_slice().try_into().map_err(D::Error::custom)
            }
            len if len == AuthorityPublicKey::LENGTH => {
                if bytes[Ed25519PublicKey::LENGTH..].iter().any(|b| *b != 0) {
                    return Err(D::Error::custom(
                        "48-byte AuthorityName with a non-zero tail is a pre-v6 BLS-basis name \
                         and has no consensus-key representation",
                    ));
                }
                bytes[..Ed25519PublicKey::LENGTH]
                    .try_into()
                    .map_err(D::Error::custom)
            }
            len => Err(D::Error::custom(format!(
                "invalid AuthorityName length {len}: expected {} or {}",
                Ed25519PublicKey::LENGTH,
                AuthorityPublicKey::LENGTH,
            ))),
        }
    }
}

impl<'a> ConciseableName<'a> for AuthorityPublicKeyBytes {
    type ConciseTypeRef = ConciseAuthorityPublicKeyBytesRef<'a>;
    type ConciseType = ConciseAuthorityPublicKeyBytes;

    /// Get a ConciseAuthorityPublicKeyBytesRef. Usage:
    ///
    ///   debug!(name = ?authority.concise());
    ///   format!("{:?}", authority.concise());
    fn concise(&'a self) -> ConciseAuthorityPublicKeyBytesRef<'a> {
        ConciseAuthorityPublicKeyBytesRef(self)
    }

    fn concise_owned(&self) -> ConciseAuthorityPublicKeyBytes {
        ConciseAuthorityPublicKeyBytes(*self)
    }
}

/// A wrapper around AuthorityPublicKeyBytes that provides a concise Debug impl.
pub struct ConciseAuthorityPublicKeyBytesRef<'a>(&'a AuthorityPublicKeyBytes);

impl Debug for ConciseAuthorityPublicKeyBytesRef<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        let s = Hex::encode(self.0.0.get(0..4).ok_or(std::fmt::Error)?);
        write!(f, "k#{s}..")
    }
}

impl Display for ConciseAuthorityPublicKeyBytesRef<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        Debug::fmt(self, f)
    }
}

/// A wrapper around AuthorityPublicKeyBytes but owns it.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConciseAuthorityPublicKeyBytes(AuthorityPublicKeyBytes);

impl Debug for ConciseAuthorityPublicKeyBytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        let s = Hex::encode(self.0.0.get(0..4).ok_or(std::fmt::Error)?);
        write!(f, "k#{s}..")
    }
}

impl Display for ConciseAuthorityPublicKeyBytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        Debug::fmt(self, f)
    }
}

impl TryFrom<AuthorityPublicKeyBytes> for AuthorityPublicKey {
    type Error = FastCryptoError;

    fn try_from(bytes: AuthorityPublicKeyBytes) -> Result<AuthorityPublicKey, Self::Error> {
        AuthorityPublicKey::from_bytes(bytes.as_ref())
    }
}

impl From<&AuthorityPublicKey> for AuthorityPublicKeyBytes {
    fn from(pk: &AuthorityPublicKey) -> AuthorityPublicKeyBytes {
        AuthorityPublicKeyBytes::from_bytes(pk.as_ref()).unwrap()
    }
}

impl AuthorityPublicKeyBytes {
    fn fmt_impl(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        let s = Hex::encode(self.0);
        write!(f, "k#{s}")?;
        Ok(())
    }
}

impl Debug for AuthorityPublicKeyBytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        self.fmt_impl(f)
    }
}

impl Display for AuthorityPublicKeyBytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        self.fmt_impl(f)
    }
}

impl ToFromBytes for AuthorityPublicKeyBytes {
    fn from_bytes(bytes: &[u8]) -> Result<Self, fastcrypto::error::FastCryptoError> {
        let bytes: [u8; AuthorityPublicKey::LENGTH] = bytes
            .try_into()
            .map_err(|_| fastcrypto::error::FastCryptoError::InvalidInput)?;
        Ok(AuthorityPublicKeyBytes(bytes))
    }
}

impl AuthorityPublicKeyBytes {
    pub const ZERO: Self = Self::new([0u8; AuthorityPublicKey::LENGTH]);

    /// This ensures it's impossible to construct an instance with other than registered lengths
    pub const fn new(bytes: [u8; AuthorityPublicKey::LENGTH]) -> AuthorityPublicKeyBytes
where {
        AuthorityPublicKeyBytes(bytes)
    }

    /// The canonical `AuthorityName` of a validator identified by its
    /// consensus Ed25519 key: the 32 key bytes zero-padded up to the 48-byte
    /// container, so the wire encoding (and every name-keyed map) is
    /// untouched by the identity basis. Zero padding is enforced here — the
    /// only constructor for consensus-basis names — so equality and hashing
    /// are consistent. The consensus key is recoverable as the first 32
    /// bytes, symmetric to how a BLS-basis name decodes to the BLS key.
    pub fn from_consensus_key(key: &NetworkPublicKey) -> Self {
        let mut bytes = [0u8; AuthorityPublicKey::LENGTH];
        bytes[..Ed25519PublicKey::LENGTH].copy_from_slice(key.as_bytes());
        AuthorityPublicKeyBytes(bytes)
    }
}

impl FromStr for AuthorityPublicKeyBytes {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = Hex::decode(s).map_err(|e| anyhow!(e))?;
        Self::from_bytes(&value[..]).map_err(|e| anyhow!(e))
    }
}

impl Default for AuthorityPublicKeyBytes {
    fn default() -> Self {
        Self::ZERO
    }
}

//
// Add helper calls for Authority Signature
//

pub trait IkaAuthoritySignature {
    fn verify_secure<T>(
        &self,
        value: &IntentMessage<T>,
        epoch_id: EpochId,
        author: AuthorityPublicKeyBytes,
    ) -> Result<(), IkaError>
    where
        T: Serialize;

    fn new_secure<T>(
        value: &IntentMessage<T>,
        epoch_id: &EpochId,
        secret: &dyn Signer<Self>,
    ) -> Self
    where
        T: Serialize;
}

impl IkaAuthoritySignature for AuthoritySignature {
    #[instrument(level = "trace", skip_all)]
    fn new_secure<T>(value: &IntentMessage<T>, epoch: &EpochId, secret: &dyn Signer<Self>) -> Self
    where
        T: Serialize,
    {
        let mut intent_msg_bytes =
            bcs::to_bytes(&value).expect("Message serialization should not fail");
        epoch.write(&mut intent_msg_bytes);
        secret.sign(&intent_msg_bytes)
    }

    #[instrument(level = "trace", skip_all)]
    fn verify_secure<T>(
        &self,
        value: &IntentMessage<T>,
        epoch: EpochId,
        author: AuthorityPublicKeyBytes,
    ) -> Result<(), IkaError>
    where
        T: Serialize,
    {
        let mut message = bcs::to_bytes(&value).expect("Message serialization should not fail");
        epoch.write(&mut message);

        let public_key = AuthorityPublicKey::try_from(author).map_err(|_| {
            IkaError::KeyConversionError(
                "Failed to serialize public key bytes to valid public key".to_string(),
            )
        })?;
        public_key
            .verify(&message[..], self)
            .map_err(|e| IkaError::InvalidSignature {
                error: format!(
                    "Fail to verify auth sig {} epoch: {} author: {}",
                    e,
                    epoch,
                    author.concise()
                ),
            })
    }
}

/// Generate a random committee key pairs with a given committee size
pub fn random_committee_key_pairs_of_size(size: usize) -> Vec<AuthorityKeyPair> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..size)
        .map(|_| {
            // TODO: We are generating the keys 4 times to match exactly as how we generate
            // keys in ConfigBuilder::build (ika-config/src/network_config_builder). This is because
            // we are using these key generation functions as fixtures and we call them
            // independently in different paths and exact the results to be the same.
            // We should eliminate them.
            let key_pair = get_key_pair_from_rng::<AuthorityKeyPair, _>(&mut rng);
            get_key_pair_from_rng::<AuthorityKeyPair, _>(&mut rng);
            get_key_pair_from_rng::<AccountKeyPair, _>(&mut rng);
            get_key_pair_from_rng::<AccountKeyPair, _>(&mut rng);
            key_pair.1
        })
        .collect()
}
/// Generate a keypair from the specified RNG (useful for testing with seedable rngs).
pub fn get_key_pair_from_rng<KP: KeypairTraits, R>(csprng: &mut R) -> (SuiAddress, KP)
where
    R: rand::CryptoRng + rand::RngCore,
    <KP as KeypairTraits>::PubKey: IkaPublicKey,
{
    let kp = KP::generate(&mut StdRng::from_rng(csprng).unwrap());
    (ika_public_key_into_sui_address(kp.public()), kp)
}
/// AuthoritySignInfoTrait is a trait used specifically for a few structs in messages.rs
/// to template on whether the struct is signed by an authority. We want to limit how
/// those structs can be instantiated on, hence the sealed trait.
/// TODO: We could also add the aggregated signature as another impl of the trait.
///       This will make CertifiedTransaction also an instance of the same struct.
pub trait AuthoritySignInfoTrait: private::SealedAuthoritySignInfoTrait {
    fn verify_secure<T: Serialize>(
        &self,
        data: &T,
        intent: Intent,
        committee: &Committee,
    ) -> IkaResult;

    fn add_to_verification_obligation<'a>(
        &self,
        committee: &'a Committee,
        obligation: &mut VerificationObligation<'a>,
        message_index: usize,
    ) -> IkaResult<()>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EmptySignInfo {}
impl AuthoritySignInfoTrait for EmptySignInfo {
    fn verify_secure<T: Serialize>(
        &self,
        _data: &T,
        _intent: Intent,
        _committee: &Committee,
    ) -> IkaResult {
        Ok(())
    }

    fn add_to_verification_obligation<'a>(
        &self,
        _committee: &'a Committee,
        _obligation: &mut VerificationObligation<'a>,
        _message_index: usize,
    ) -> IkaResult<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Serialize, Deserialize)]
pub struct AuthoritySignInfo {
    pub epoch: EpochId,
    pub authority: AuthorityName,
    pub signature: AuthoritySignature,
}

impl AuthoritySignInfoTrait for AuthoritySignInfo {
    fn verify_secure<T: Serialize>(
        &self,
        data: &T,
        intent: Intent,
        committee: &Committee,
    ) -> IkaResult<()> {
        let mut obligation = VerificationObligation::default();
        let idx = obligation.add_message(data, self.epoch, intent);
        self.add_to_verification_obligation(committee, &mut obligation, idx)?;
        obligation.verify_all()?;
        Ok(())
    }

    fn add_to_verification_obligation<'a>(
        &self,
        committee: &'a Committee,
        obligation: &mut VerificationObligation<'a>,
        message_index: usize,
    ) -> IkaResult<()> {
        fp_ensure!(
            self.epoch == committee.epoch(),
            IkaError::WrongEpoch {
                expected_epoch: committee.epoch(),
                actual_epoch: self.epoch,
            }
        );
        let weight = committee.weight(&self.authority);
        fp_ensure!(
            weight > 0,
            IkaError::UnknownSigner {
                signer: Some(self.authority.concise().to_string()),
                index: None,
                committee: Box::new(committee.clone())
            }
        );

        obligation
            .public_keys
            .get_mut(message_index)
            .ok_or(IkaError::InvalidAddress)?
            .push(committee.public_key(&self.authority)?);
        obligation
            .signatures
            .get_mut(message_index)
            .ok_or(IkaError::InvalidAddress)?
            .add_signature(self.signature.clone())
            .map_err(|_| IkaError::InvalidSignature {
                error: "Fail to aggregator auth sig".to_string(),
            })?;
        Ok(())
    }
}

impl AuthoritySignInfo {
    pub fn new<T>(
        epoch: EpochId,
        value: &T,
        intent: Intent,
        name: AuthorityName,
        secret: &dyn Signer<AuthoritySignature>,
    ) -> Self
    where
        T: Serialize,
    {
        Self {
            epoch,
            authority: name,
            signature: AuthoritySignature::new_secure(
                &IntentMessage::new(intent, value),
                &epoch,
                secret,
            ),
        }
    }
}

impl Hash for AuthoritySignInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.epoch.hash(state);
        self.authority.hash(state);
    }
}

impl Display for AuthoritySignInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AuthoritySignInfo {{ epoch: {:?}, authority: {} }}",
            self.epoch, self.authority,
        )
    }
}

impl PartialEq for AuthoritySignInfo {
    fn eq(&self, other: &Self) -> bool {
        // We do not compare the signature, because there can be multiple
        // valid signatures for the same epoch and authority.
        self.epoch == other.epoch && self.authority == other.authority
    }
}

/// Represents at least a quorum (could be more) of authority signatures.
/// STRONG_THRESHOLD indicates whether to use the quorum threshold for quorum check.
/// When STRONG_THRESHOLD is true, the quorum is valid when the total stake is
/// at least the quorum threshold (2f+1) of the committee; when STRONG_THRESHOLD is false,
/// the quorum is valid when the total stake is at least the validity threshold (f+1) of
/// the committee.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AuthorityQuorumSignInfo<const STRONG_THRESHOLD: bool> {
    pub epoch: EpochId,
    #[schemars(with = "Base64")]
    pub signature: AggregateAuthoritySignature,
    #[schemars(with = "Base64")]
    #[serde_as(as = "IkaBitmap")]
    pub signers_map: RoaringBitmap,
}

pub type AuthorityStrongQuorumSignInfo = AuthorityQuorumSignInfo<true>;

// Variant of [AuthorityStrongQuorumSignInfo] but with a serialized signature, to be used in
// external APIs.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct IkaAuthorityStrongQuorumSignInfo {
    pub epoch: EpochId,
    pub signature: AggregateAuthoritySignatureAsBytes,
    #[schemars(with = "Base64")]
    #[serde_as(as = "IkaBitmap")]
    pub signers_map: RoaringBitmap,
}

impl From<&AuthorityStrongQuorumSignInfo> for IkaAuthorityStrongQuorumSignInfo {
    fn from(info: &AuthorityStrongQuorumSignInfo) -> Self {
        Self {
            epoch: info.epoch,
            signature: (&info.signature).into(),
            signers_map: info.signers_map.clone(),
        }
    }
}

impl TryFrom<&IkaAuthorityStrongQuorumSignInfo> for AuthorityStrongQuorumSignInfo {
    type Error = FastCryptoError;

    fn try_from(info: &IkaAuthorityStrongQuorumSignInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            epoch: info.epoch,
            signature: (&info.signature).try_into()?,
            signers_map: info.signers_map.clone(),
        })
    }
}

// Note: if you meet an error due to this line it may be because you need an Eq implementation for `CertifiedTransaction`,
// or one of the structs that include it, i.e. `ConfirmationTransaction`, `TransactionInfoResponse` or `ObjectInfoResponse`.
//
// Please note that any such implementation must be agnostic to the exact set of signatures in the certificate, as
// clients are allowed to equivocate on the exact nature of valid certificates they send to the system. This assertion
// is a simple tool to make sure certificates are accounted for correctly - should you remove it, you're on your own to
// maintain the invariant that valid certificates with distinct signatures are equivalent, but yet-unchecked
// certificates that differ on signers aren't.
//
// see also https://github.com/MystenLabs/sui/issues/266
static_assertions::assert_not_impl_any!(AuthorityStrongQuorumSignInfo: Hash, Eq, PartialEq);

impl<const STRONG_THRESHOLD: bool> AuthoritySignInfoTrait
    for AuthorityQuorumSignInfo<STRONG_THRESHOLD>
{
    fn verify_secure<T: Serialize>(
        &self,
        data: &T,
        intent: Intent,
        committee: &Committee,
    ) -> IkaResult {
        let mut obligation = VerificationObligation::default();
        let idx = obligation.add_message(data, self.epoch, intent);
        self.add_to_verification_obligation(committee, &mut obligation, idx)?;
        obligation.verify_all()?;
        Ok(())
    }

    fn add_to_verification_obligation<'a>(
        &self,
        committee: &'a Committee,
        obligation: &mut VerificationObligation<'a>,
        message_index: usize,
    ) -> IkaResult<()> {
        // Check epoch
        fp_ensure!(
            self.epoch == committee.epoch(),
            IkaError::WrongEpoch {
                expected_epoch: committee.epoch(),
                actual_epoch: self.epoch,
            }
        );

        let mut weight = 0;

        // Create obligations for the committee signatures
        obligation
            .signatures
            .get_mut(message_index)
            .ok_or(IkaError::InvalidAuthenticator)?
            .add_aggregate(self.signature.clone())
            .map_err(|_| IkaError::InvalidSignature {
                error: "Signature Aggregation failed".to_string(),
            })?;

        let selected_public_keys = obligation
            .public_keys
            .get_mut(message_index)
            .ok_or(IkaError::InvalidAuthenticator)?;

        for authority_index in self.signers_map.iter() {
            let authority = committee
                .authority_by_index(authority_index)
                .ok_or_else(|| IkaError::UnknownSigner {
                    signer: None,
                    index: Some(authority_index),
                    committee: Box::new(committee.clone()),
                })?;

            // Update weight.
            let voting_rights = committee.weight(authority);
            fp_ensure!(
                voting_rights > 0,
                IkaError::UnknownSigner {
                    signer: Some(authority.concise().to_string()),
                    index: Some(authority_index),
                    committee: Box::new(committee.clone()),
                }
            );
            weight += voting_rights;

            selected_public_keys.push(committee.public_key(authority)?);
        }

        fp_ensure!(
            weight >= Self::quorum_threshold(committee),
            IkaError::CertificateRequiresQuorum
        );

        Ok(())
    }
}

impl<const STRONG_THRESHOLD: bool> AuthorityQuorumSignInfo<STRONG_THRESHOLD> {
    pub fn new_from_auth_sign_infos(
        auth_sign_infos: Vec<AuthoritySignInfo>,
        committee: &Committee,
    ) -> IkaResult<Self> {
        fp_ensure!(
            auth_sign_infos.iter().all(|a| a.epoch == committee.epoch),
            IkaError::InvalidSignature {
                error: "All signatures must be from the same epoch as the committee".to_string()
            }
        );
        let total_stake: StakeUnit = auth_sign_infos
            .iter()
            .map(|a| committee.weight(&a.authority))
            .sum();
        fp_ensure!(
            total_stake >= Self::quorum_threshold(committee),
            IkaError::InvalidSignature {
                error: "Signatures don't have enough stake to form a quorum".to_string()
            }
        );

        let signatures: BTreeMap<_, _> = auth_sign_infos
            .into_iter()
            .map(|a| (a.authority, a.signature))
            .collect();
        let mut map = RoaringBitmap::new();
        for pk in signatures.keys() {
            map.insert(
                committee
                    .authority_index(pk)
                    .ok_or_else(|| IkaError::UnknownSigner {
                        signer: Some(pk.concise().to_string()),
                        index: None,
                        committee: Box::new(committee.clone()),
                    })?,
            );
        }
        let sigs: Vec<AuthoritySignature> = signatures.into_values().collect();

        Ok(AuthorityQuorumSignInfo {
            epoch: committee.epoch,
            signature: AggregateAuthoritySignature::aggregate(&sigs).map_err(|e| {
                IkaError::InvalidSignature {
                    error: e.to_string(),
                }
            })?,
            signers_map: map,
        })
    }

    pub fn quorum_threshold(committee: &Committee) -> StakeUnit {
        committee.threshold::<STRONG_THRESHOLD>()
    }

    pub fn len(&self) -> u64 {
        self.signers_map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signers_map.is_empty()
    }
}

impl<const S: bool> Display for AuthorityQuorumSignInfo<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "{} {{ epoch: {:?}, signers_map: {:?} }}",
            if S {
                "AuthorityStrongQuorumSignInfo"
            } else {
                "AuthorityWeakQuorumSignInfo"
            },
            self.epoch,
            self.signers_map,
        )?;
        Ok(())
    }
}

mod private {
    pub trait SealedAuthoritySignInfoTrait {}
    impl SealedAuthoritySignInfoTrait for super::EmptySignInfo {}
    impl SealedAuthoritySignInfoTrait for super::AuthoritySignInfo {}
    impl<const S: bool> SealedAuthoritySignInfoTrait for super::AuthorityQuorumSignInfo<S> {}
}

/// Something that we know how to hash and sign.
pub trait Signable<W> {
    fn write(&self, writer: &mut W);
}

pub trait SignableBytes
where
    Self: Sized,
{
    fn from_signable_bytes(bytes: &[u8]) -> Result<Self, Error>;
}

/// Activate the blanket implementation of `Signable` based on serde and BCS.
/// * We use `serde_name` to extract a seed from the name of structs and enums.
/// * We use `BCS` to generate canonical bytes ikatable for hashing and signing.
///
/// # Safety
/// We protect the access to this marker trait through a "sealed trait" pattern:
/// impls must be add added here (nowehre else) which lets us note those impls
/// MUST be on types that comply with the `serde_name` machinery
/// for the below implementations not to panic. One way to check they work is to write
/// a unit test for serialization to / deserialization from signable bytes.
mod bcs_signable {

    pub trait BcsSignable: serde::Serialize + serde::de::DeserializeOwned {}
    impl BcsSignable for crate::committee::Committee {}
    impl BcsSignable for crate::messages_dwallet_checkpoint::DWalletCheckpointMessage {}
    impl BcsSignable for crate::messages_system_checkpoints::SystemCheckpointMessage {}

    impl BcsSignable for crate::message::DWalletCheckpointMessageKind {}
}

impl<T, W> Signable<W> for T
where
    T: bcs_signable::BcsSignable,
    W: std::io::Write,
{
    fn write(&self, writer: &mut W) {
        let name = serde_name::trace_name::<Self>().expect("Self must be a struct or an enum");
        // Note: This assumes that names never contain the separator `::`.
        write!(writer, "{name}::").expect("Hasher should not fail");
        bcs::serialize_into(writer, &self).expect("Message serialization should not fail");
    }
}

impl<W> Signable<W> for EpochId
where
    W: std::io::Write,
{
    fn write(&self, writer: &mut W) {
        bcs::serialize_into(writer, &self).expect("Message serialization should not fail");
    }
}

impl<T> SignableBytes for T
where
    T: bcs_signable::BcsSignable,
{
    fn from_signable_bytes(bytes: &[u8]) -> Result<Self, Error> {
        // Remove name tag before deserialization using BCS
        let name = serde_name::trace_name::<Self>().expect("Self should be a struct or an enum");
        let name_byte_len = format!("{name}::").bytes().len();
        Ok(bcs::from_bytes(bytes.get(name_byte_len..).ok_or_else(
            || anyhow!("Failed to deserialize to {name}."),
        )?)?)
    }
}

fn hash<S: Signable<H>, H: HashFunction<DIGEST_SIZE>, const DIGEST_SIZE: usize>(
    signable: &S,
) -> [u8; DIGEST_SIZE] {
    let mut digest = H::default();
    signable.write(&mut digest);
    let hash = digest.finalize();
    hash.into()
}

pub fn default_hash<S: Signable<DefaultHash>>(signable: &S) -> [u8; 32] {
    hash::<S, DefaultHash, 32>(signable)
}

pub fn keccak256_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::default();
    hasher.write_all(bytes).expect("Hasher should not fail");
    let digest = hasher.finalize();
    digest.into()
}

#[derive(Default)]
pub struct VerificationObligation<'a> {
    pub messages: Vec<Vec<u8>>,
    pub signatures: Vec<AggregateAuthoritySignature>,
    pub public_keys: Vec<Vec<&'a AuthorityPublicKey>>,
}

impl<'a> VerificationObligation<'a> {
    pub fn new() -> VerificationObligation<'a> {
        VerificationObligation::default()
    }

    /// Add a new message to the list of messages to be verified.
    /// Returns the index of the message.
    pub fn add_message<T>(&mut self, message_value: &T, epoch: EpochId, intent: Intent) -> usize
    where
        T: Serialize,
    {
        let intent_msg = IntentMessage::new(intent, message_value);
        let mut intent_msg_bytes =
            bcs::to_bytes(&intent_msg).expect("Message serialization should not fail");
        epoch.write(&mut intent_msg_bytes);
        self.signatures.push(AggregateAuthoritySignature::default());
        self.public_keys.push(Vec::new());
        self.messages.push(intent_msg_bytes);
        self.messages.len() - 1
    }

    // Attempts to add signature and public key to the obligation. If this fails, ensure to call `verify` manually.
    pub fn add_signature_and_public_key(
        &mut self,
        signature: &AuthoritySignature,
        public_key: &'a AuthorityPublicKey,
        idx: usize,
    ) -> IkaResult<()> {
        self.public_keys
            .get_mut(idx)
            .ok_or(IkaError::InvalidAuthenticator)?
            .push(public_key);
        self.signatures
            .get_mut(idx)
            .ok_or(IkaError::InvalidAuthenticator)?
            .add_signature(signature.clone())
            .map_err(|_| IkaError::InvalidSignature {
                error: "Failed to add signature to obligation".to_string(),
            })?;
        Ok(())
    }

    pub fn verify_all(self) -> IkaResult<()> {
        let mut pks = Vec::with_capacity(self.public_keys.len());
        for pk in self.public_keys.clone() {
            pks.push(pk.into_iter());
        }
        AggregateAuthoritySignature::batch_verify(
            &self.signatures.iter().collect::<Vec<_>>()[..],
            pks,
            &self.messages.iter().map(|x| &x[..]).collect::<Vec<_>>()[..],
        )
        .map_err(|e| {
            let message = format!(
                "pks: {:?}, messages: {:?}, sigs: {:?}",
                self.public_keys,
                self.messages
                    .iter()
                    .map(Base64::encode)
                    .collect::<Vec<String>>(),
                self.signatures
                    .iter()
                    .map(|s| Base64::encode(s.as_ref()))
                    .collect::<Vec<String>>()
            );

            let chunk_size = 2048;

            // This error message may be very long, so we print out the error in chunks of to avoid
            // hitting a max log line length on the system.
            for (i, chunk) in message
                .as_bytes()
                .chunks(chunk_size)
                .map(std::str::from_utf8)
                .enumerate()
            {
                warn!(
                    "Failed to batch verify aggregated auth sig: {} (chunk {}): {}",
                    e,
                    i,
                    chunk.unwrap()
                );
            }

            IkaError::InvalidSignature {
                error: format!("Failed to batch verify aggregated auth sig: {e}"),
            }
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn consensus_key_bytes() -> [u8; Ed25519PublicKey::LENGTH] {
        let mut bytes = [0u8; Ed25519PublicKey::LENGTH];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8 + 100;
        }
        bytes
    }

    fn name() -> AuthorityName {
        AuthorityName(consensus_key_bytes())
    }

    fn padded(key: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; AuthorityPublicKey::LENGTH];
        v[..key.len()].copy_from_slice(key);
        v
    }

    /// BCS encoding of a byte string: ULEB128 length prefix followed by
    /// the bytes (all lengths here fit in a single prefix byte).
    fn bcs_byte_string(bytes: &[u8]) -> Vec<u8> {
        let mut wire = vec![bytes.len() as u8];
        wire.extend_from_slice(bytes);
        wire
    }

    /// The only wire format: the raw 32-byte consensus key. Byte-exact,
    /// because this is what every signature and digest in the protocol is
    /// reconstructed from — a silent change here splits the committee.
    #[test]
    fn authority_name_is_emitted_as_the_raw_consensus_key() {
        let serialized = bcs::to_bytes(&name()).unwrap();
        assert_eq!(serialized, bcs_byte_string(&consensus_key_bytes()));
        let round_tripped: AuthorityName = bcs::from_bytes(&serialized).unwrap();
        assert_eq!(round_tripped, name());

        let json = serde_json::to_string(&name()).unwrap();
        assert_eq!(
            json,
            format!("\"{}\"", Base64::encode(consensus_key_bytes()))
        );
    }

    /// The padded form is never EMITTED any more, but it must still DECODE:
    /// rows and archives written before the v7 boundary hold it, and a node
    /// has to keep reading its own history. Dropping this tolerance would
    /// turn every pre-v7 persisted name into a deserialization failure.
    #[test]
    fn the_pre_v7_padded_form_still_decodes() {
        let padded_wire = bcs_byte_string(&padded(&consensus_key_bytes()));
        let decoded: AuthorityName = bcs::from_bytes(&padded_wire).unwrap();
        assert_eq!(
            decoded,
            name(),
            "a pre-v7 record must read back identically"
        );

        assert_ne!(
            padded_wire,
            bcs::to_bytes(&name()).unwrap(),
            "decoding it is not the same as emitting it — this binary emits only the short form"
        );
    }

    /// A 48-byte value with a NON-zero tail is a pre-v6 BLS-basis name. It has
    /// no consensus-key representation, so it must be rejected rather than
    /// truncated into a different validator's identity.
    #[test]
    fn a_bls_basis_name_is_rejected_not_truncated() {
        let mut bls = padded(&consensus_key_bytes());
        bls[AuthorityPublicKey::LENGTH - 1] = 0xAA;
        assert!(bcs::from_bytes::<AuthorityName>(&bcs_byte_string(&bls)).is_err());
    }

    #[test]
    fn rejects_lengths_other_than_consensus_and_container() {
        for len in [0usize, 31, 33, 47, 49] {
            assert!(
                bcs::from_bytes::<AuthorityName>(&bcs_byte_string(&vec![0x11; len])).is_err(),
                "length {len} must be rejected"
            );
        }
    }

    /// `from_consensus_key` agrees with the decoder, and the key is
    /// recoverable — a name IS the consensus key.
    #[test]
    fn from_consensus_key_round_trips_through_the_wire() {
        let keypair = Ed25519KeyPair::generate(&mut StdRng::from_seed([7; 32]));
        let built = AuthorityName::from_consensus_key(keypair.public());
        let decoded: AuthorityName =
            bcs::from_bytes(&bcs_byte_string(keypair.public().as_bytes())).unwrap();
        assert_eq!(built, decoded);
        assert_eq!(&built.0[..], keypair.public().as_bytes());
        assert_eq!(built.to_consensus_key().unwrap(), *keypair.public());
    }

    /// The BLS container is a fixed 48-byte key with no width games: it is a
    /// different type from `AuthorityName` now, and must stay plainly encoded.
    #[test]
    fn bls_container_is_plain_fixed_width() {
        let bytes: Vec<u8> = (0..AuthorityPublicKey::LENGTH as u8).collect();
        let key = AuthorityPublicKeyBytes(bytes.as_slice().try_into().unwrap());
        let serialized = bcs::to_bytes(&key).unwrap();
        assert_eq!(serialized, bcs_byte_string(&bytes));
        let round_tripped: AuthorityPublicKeyBytes = bcs::from_bytes(&serialized).unwrap();
        assert_eq!(round_tripped, key);
        // And it does NOT accept the short form: it is not a name.
        assert!(
            bcs::from_bytes::<AuthorityPublicKeyBytes>(&bcs_byte_string(&consensus_key_bytes()))
                .is_err()
        );
    }
}
