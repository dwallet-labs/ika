---
ika repo: /mnt/nvme0n1p1/ika (branch: dev)
ika pinned cryptography-private rev: babbb483 ("Remove redundant public key and nonce is neutral check")
inkrypto main (abd7f01) corresponds to cryptography-private: 6ae3d92b ("Take latest inkrypto")
cryptography-private main: 33fa7e1e ("Add missing debug_assert bounds checks...")
cryptography-private branch under review: 2pc-mpc-userless (tip: 3ca0ed5e)
date: 2026-04-09
---

# ika's inkrypto API Usage and Breaking Changes

## Part 1: API Catalog — What ika uses, categorized by break severity

### HIGHEST

Serialized wire types, protocol inputs/outputs, and protocol execution APIs.
A change to any of these breaks protocol compatibility, requires coordinated
upgrade, or requires new data the caller doesn't have.

**Serialized wire types** — BCS-serialized, flow between validators or stored on-chain:

| Type | Where in ika | How used |
|------|-------------|----------|
| `decentralized_party::reconfiguration::Message` enum | ika-core reconfiguration.rs | MPC party message between validators (opaque Vec<u8>) |
| `decentralized_party::reconfiguration::PublicInput` | ika-core reconfiguration.rs | Constructed and passed to Party::advance |
| `decentralized_party::dkg::Message` enum | ika-core network_dkg.rs | MPC party message between validators |
| `decentralized_party::dkg::PublicOutput` | ika-core network_dkg.rs | BCS-serialized into VersionedNetworkDkgOutput |
| `dkg::decentralized_party::{Output, VersionedOutput}` | dwallet-mpc-types, ika-core | BCS-serialized in VersionedDwalletDKGPublicOutput |
| `dkg::centralized_party::{Output, VersionedOutput}` | dwallet-mpc-types, centralized-party | BCS-serialized for DKG outputs |
| `ProtocolPublicParameters` (all curves) | dwallet-mpc-types, centralized-party | BCS-serialized and transmitted |
| `ecdsa::presign::decentralized_party::Message` enum | opaque via MPC framework | MPC party message between validators |
| `schnorr::ahe::sign::decentralized_party::Message` enum | opaque via MPC framework | MPC party message between validators |
| `ecdsa::sign::decentralized_party::Message` | opaque via MPC framework | MPC party message between validators |
| Signature types (`ECDSASecp256k1Signature`, etc.) | ika-core mpc_computations.rs | BCS-deserialized from sign output |
| `schnorr::PartialSignature` | sign messages | Serialized in centralized party sign message |
| `CompactIbqf`, `KnowledgeOfDiscreteLogUCProof` | ika-types committee.rs | Stored on-chain per validator |
| `CiphertextSpaceValue` | embedded in DKG outputs | Part of serialized DKG output |
| `DecryptionKeySharePublicParameters` (all curves) | dwallet-mpc-types NetworkEncryptionKeyPublicData | Stored in epoch data |
| Presign output (`VersionedPresign`, `Presign`) | ika-core presign.rs | BCS-serialized into VersionedPresignOutput |

**Protocol public/private inputs** — data validators must provide to run protocols:

| Input | Where in ika | What it contains |
|-------|-------------|-----------------|
| `decentralized_party::reconfiguration::PublicInput` | ika-core reconfiguration.rs | Protocol params, encryption keys, PVSS keys+proofs per party per curve, access structure, decryption key share params |
| `decentralized_party::dkg::PublicInput` (network DKG) | ika-core network_dkg.rs | Protocol params, public key share and proof, key share verification method |
| `ecdsa::sign::decentralized_party::PublicInput` | ika-core sign.rs | DKG output, presign, sign message, decryption key share public params, expected decrypters |
| `ecdsa::sign::decentralized_party::DKGSignPublicInput` | ika-core sign.rs | Same as above but combined with DKG |
| `ecdsa::presign::decentralized_party::PublicInput` | ika-core presign.rs | Protocol params, optional targeted DKG output |
| Sign private input (`HashMap<PartyID, DecryptionKeyShare>`) | ika-core sign.rs | Per-party decryption key shares |
| Reconfiguration private input (decryption key shares) | ika-core reconfiguration.rs | Per-party decryption key shares for threshold decryption |

**Protocol execution APIs** — ika calls these to run cryptographic computations:

| API | Where in ika | How used |
|-----|-------------|----------|
| `sign::Protocol` trait + associated types | sign.rs, centralized-party | Trait bounds, associated type references |
| `presign::Protocol` trait + associated types | presign.rs | Trait bounds, PresignParty references |
| `dkg::Protocol` trait + associated types | dwallet_dkg.rs, network_dkg.rs, encrypt_user_share.rs, centralized-party | DKG party types, verification methods |
| `P::SignDecentralizedParty` / `P::DKGSignDecentralizedParty` | sign.rs | Party type for advance_with_guaranteed_output |
| `P::PresignParty` | presign.rs | Party type for advance_with_guaranteed_output |
| `P::DKGDecentralizedParty` | dwallet_dkg.rs | Party type for advance_with_guaranteed_output |
| `P::DKGCentralizedPartyRound::advance()` | centralized-party | Runs centralized DKG |
| `P::TrustedDealerDKGCentralizedPartyRound::advance()` | centralized-party | Runs trusted dealer DKG |
| `SignCentralizedParty::advance()` | centralized-party | Runs centralized sign |
| `verify_centralized_party_partial_signature()` | sign.rs, native_computations.rs | Verifies partial signature |
| `verify_encryption_of_centralized_party_share_proof()` | encrypt_user_share.rs | Verifies encrypted share |
| `verify_centralized_party_public_key_share()` | make_dwallet_user_secret_key_shares_public.rs | Verifies key share |
| `SignDecentralizedPartyPublicInput::from(tuple)` | sign.rs | Constructs sign public input via .into() |
| `DKGSignDecentralizedPartyPublicInput::from(tuple)` | sign.rs | Constructs DKG+sign public input via .into() |
| `SignCentralizedPartyPublicInput::from(tuple)` | centralized-party | Constructs centralized public input via .into() |
| `PresignPublicInput::from(tuple)` | presign.rs | Constructs presign public input via .into() |
| Per-curve protocol type aliases (`ECDSAProtocol`, `TaprootProtocol`, etc.) | ika-types, presign.rs, sign.rs | Used as generic parameter P |
| Per-curve `DKGProtocol` type aliases | dwallet_dkg.rs, network_dkg.rs | Used for DKG party instantiation |
| `P::DecryptionKeyShare` / `P::DecryptionKeySharePublicParameters` | sign.rs | Used in sign public input construction |
| `ProtocolPublicParameters::new()` | centralized-party | Constructs protocol params |
| `dkg::Party::PublicInput::new()` | network_dkg.rs | Constructs network DKG input |
| `decrypt_decryption_key_shares()` | network_dkg.rs | Extracts key shares from DKG output |

### MEDIUM — Group Arithmetic APIs

Used only in `dwallet-mpc-centralized-party` (the centralized party computation
module). Changes here are mechanical — same data available, different call syntax.

| API | How used |
|-----|----------|
| `GroupElement` operator overloads (`+`, `-`, `*`) | Direct group arithmetic |
| `GroupElement::scale*()` methods | Scalar multiplication |
| `GroupElement::Value` with Copy trait | Implicit copies of values |
| `HomomorphicCommitmentScheme::commit()` | Commitment computation |

### LOW — Type-Only / Lightweight

Used purely as type annotations, struct fields, constants, or simple conversions.
No cryptographic computation.

| API | Where in ika | How used |
|-----|-------------|----------|
| `group::PartyID` | 15+ files across ika-core, ika-types | HashMap keys, error fields, function params |
| `group::HashScheme` | mpc_protocol_configuration.rs, session request, sign data | Enum stored in structs |
| `mpc::WeightedThresholdAccessStructure` | authority_per_epoch_store.rs, mpc_manager.rs, request.rs | Constructed from committee data |
| `mpc::Weight` | dwallet_mpc/mod.rs | Type for access structure construction |
| `mpc::MajorityVote` | mpc_manager.rs | Imported but unused |
| `mpc::GuaranteedOutputDeliveryRoundResult` | dwallet_mpc_service.rs, request.rs | Return type from advance calls |
| `mpc::guaranteed_output_delivery::AdvanceRequest` | protocol_cryptographic_data.rs | Message container type |
| `commitment::CommitmentSizedNumber` | dwallet-rng, mpc_computations.rs | Session ID type, byte conversion |
| `group::{OsCsRng, CsRng}` | dwallet-rng, centralized-party | RNG trait bounds |
| `group::{GroupElement, CyclicGroupElement, Samplable}` | centralized-party | Trait bounds in generic code |
| `class_groups::SecretKeyShareSizedInteger` | protocol_cryptographic_data.rs | Type in HashMap values |
| `homomorphic_encryption::GroupsPublicParametersAccessors` | centralized-party | Trait for accessing public params |

---

## Part 2: Breaking Changes — What actually changed (babbb483 -> main)

---

## HIGHEST

### 1. Validators must generate and distribute HPKE and PVSS encryption keys (NEW DATA)

The reconfiguration protocol and new DKG rounds (5-7) now require per-validator
HPKE encryption keys (Curve25519-based) and PVSS encryption keys per curve.
This is entirely new key material that doesn't exist in ika today.

**Reconfiguration PublicInput** gained these new fields requiring validator keys:
- `secp256k1_pvss_encryption_keys_and_proofs: HashMap<PartyID, (CompactIbqf, Proof)>`
- `ristretto_pvss_encryption_keys_and_proofs: HashMap<PartyID, (CompactIbqf, Proof)>`
- `secp256r1_pvss_encryption_keys_and_proofs: HashMap<PartyID, (CompactIbqf, Proof)>`
- Per-curve `encryption_key`, `setup_parameters`, `public_verification_keys`
- `access_structure: WeightedThresholdAccessStructure`
- `threshold_encryption_of_secret_key_share_parts_to_sharing_public_input`

**VSS Presign PrivateInput** requires `EncryptionSecretKey` (HPKE private key).

**VSS Sign PrivateInput** requires secret key shares, nonce shares, session ID,
blending index, and polynomial commitments — all produced by the new
threshold_encryption_to_sharing protocol.

Impact: validators must generate HPKE keypairs, generate PVSS encryption keypairs
per curve, store them, distribute public keys on-chain, and provide private keys
as protocol inputs. This requires new key management infrastructure in ika.

### 2. DKG extended from 4 to 7 rounds with new wire messages (SERIALIZATION BREAK)

Three new `decentralized_party::dkg::Message` variants added:

- `VerifiedDealers { fourth_round_output, threshold_encryption_dealing_message: DealingRoundMessage }`
- `AccusedDealers { threshold_encryption_accusation_message: AccusationRoundMessage }`
- `ThresholdDecryptSecretKeyShares { threshold_encryption_decryption_round_message: ThresholdDecryptionRoundMessage }`

These implement the threshold_encryption_of_secret_key_share_parts_to_sharing
sub-protocol (4 rounds: dealing, accusation, decryption, aggregation) that
converts threshold-encrypted secrets into Shamir shares across 4 curves × 2 parts.

**DKG PublicOutput** gained new field:
`threshold_encryption_to_sharing_output` containing polynomial commitments,
PVSS randomizer dealings, and masked secrets for all 8 secret parts.

### 3. Reconfiguration protocol messages changed (SERIALIZATION BREAK)

`decentralized_party::reconfiguration::Message` enum:

1. `DealDecryptionKeyContributionAndProveCoefficientCommitments` gained field:
   `threshold_encryption_of_secret_key_share_parts_to_sharing_dealing_message`

2. `VerifiedRandomizerDealers` changed from tuple variant to struct variant with:
   `class_groups_message` + `threshold_encryption_...accusation_message`
   (tuple vs struct is a BCS serialization break)

3. `ThresholdDecryptShares` gained field:
   `threshold_encryption_..._decryption_round_message`

Validators at babbb483 cannot deserialize messages from main.

### 4. New threshold_encryption_to_sharing protocol (NEW PROTOCOL)

Entirely new 4-round sub-protocol embedded in DKG rounds 5-7:
- Round 1 (Dealing): PVSS dealings for randomizers across 4 curves × 2 parts
- Round 2 (Accusation): Verify PVSS shares, accuse malicious dealers
- Round 3 (Decryption): Threshold decrypt E(x+r), produce decryption shares with proofs
- Round 4 (Aggregation): Aggregate VSS shares into final Shamir shares

Produces per-party Shamir secret key shares needed by VSS sign protocol.

### 5. sign::Protocol / presign::Protocol trait hierarchy decoupled

`sign::Protocol` no longer extends `dkg::Protocol`. DKG types accessed via
`<Self::DKGProtocol as dkg::Protocol>::TypeName` instead of `Self::TypeName`.

### 6. DKGProtocol type aliases now point to a distinct type

All per-curve aliases now point to `class_groups::asynchronous::DKGProtocol<...>`
instead of the sign protocol type.

### 7. DecryptionKeyShare / DecryptionKeySharePublicParameters removed

Replaced by `SignDecentralizedPartyPrivateInput`. For AHE protocols the concrete
type is still `HashMap<PartyID, SecretKeyShareSizedInteger>` (same data). For VSS
protocols, requires the richer PrivateInput struct from threshold_encryption_to_sharing.

### 8. New sign::Protocol associated types

- `VerifiedSignData` — extracted verified data from sign message
- `SignDecentralizedPartyPrivateInput` — replaces hardcoded DecryptionKeyShare

### 9. New presign::Protocol associated types

- `HPKEEncryptionKey` (= `()` for AHE, Curve25519 key for VSS)
- `PresignPrivateInput` (= `()` for AHE, HPKE secret key for VSS)

### 10. verify_centralized_party_partial_signature return type changed

`Result<()>` → `Result<Self::VerifiedSignData>`.

### 11. New SignData enum wraps SignMessage in sign public inputs

```rust
pub enum SignData<SignMessage, VerifiedSignData> {
    Unverified(SignMessage),
    Verified(VerifiedSignData),
    ToBeEmulated,
}
```

### 12. New dkg::Protocol method: threshold_dkg_output (required)

### 13. All From<tuple> constructors removed from public input types

Must construct structs directly. Affects:
- `ecdsa::sign::decentralized_party::{PublicInput, DKGSignPublicInput}`
- `ecdsa::presign::decentralized_party::PublicInput`
- `sign::Protocol::{SignCentralizedPartyPublicInput, SignDecentralizedPartyPublicInput}`

### No breaks in these wire types (verified field-for-field identical):

`dkg::{centralized,decentralized}_party::{Output, VersionedOutput}`,
`ProtocolPublicParameters`, all signature types, all presign/sign MPC Party
Message and PublicOutput types, `CompactIbqf`, `KnowledgeOfDiscreteLogUCProof`,
`CiphertextSpaceValue`, `schnorr::PartialSignature`.

---

## MEDIUM — API Changes Not Requiring New Information

### GroupElement arithmetic operators removed

`+`, `-`, `+=`, `-=`, unary `-` removed. Replace with:
- `a.add_vartime(&b, &pp)` or `a.add_constant_time(&b, &pp)`
- `a.neg_constant_time(&pp)`
- `a.sub_constant_time(&b, &pp)`

### All scale methods require &PublicParameters

Every `scale()`, `scale_vartime()`, `scale_integer()` etc. gains `&pp` param.

### Copy removed from GroupElement and GroupElement::Value

Must use `.clone()`. `+ Copy` bound needed explicitly where required.

### Copy bounds added to encryption associated types

`CiphertextSpaceGroupElement: Copy`, `RandomnessSpaceGroupElement: Copy`.

### HomomorphicCommitmentScheme::commit new parameter

Extra `&public_parameters` argument.

### Error enum changes

New variants: `InvalidSignatureShare`, `DecryptionFailed`, `IdentityEphemeralKey`,
`TorsionEphemeralKey`, `MaliciousMessageAsync`, `MaliciousMessagePreventsAdvance`,
`Serialization(String)`. `AsyncProofAggregation` source changed to `proof_aggregation`.

---

## LOW — Renames and Path Changes

- `schnorr::presign` → `schnorr::ahe::presign`
- `schnorr::sign::centralized_party::PartialSignature` → `schnorr::PartialSignature`
- PVSS types → `chinese_remainder_theorem` submodule
- `mpc::SeedableCollection` → `group::SeedableCollection`
- `proof::aggregation` → standalone `proof_aggregation` crate
- `maurer::aggregation` → standalone `maurer_aggregation` crate
- Scale method renames (`*_accelerated` → `*_by`)
- `LinearlyCombinable` trait removed → methods on `GroupElement`
