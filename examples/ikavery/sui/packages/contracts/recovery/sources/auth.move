/// Unified authentication for the recovery module.
///
/// Every member is a `(scheme, public_key)` pair. Authorization is a
/// signature over a per-operation challenge — never `ctx.sender()`. This
/// decouples auth from the Sui sender, so a sponsor wallet can be the
/// transaction sender (and gas-owner) while a member's wallet just signs
/// the challenge on the side.
///
/// Schemes:
///   0 = Ed25519        (32-byte pubkey, raw `signPersonalMessage` sig)
///   1 = Secp256k1      (33-byte compressed pubkey, raw `signPersonalMessage` sig)
///   2 = Secp256r1      (33-byte compressed pubkey, raw `signPersonalMessage` sig)
///   3 = WebAuthn       (33-byte compressed secp256r1 passkey pubkey, full
///                       WebAuthn assertion envelope verified by `assertion`)
///   4 = SenderAddress  (32-byte Sui address — auth gate is `ctx.sender() == addr`,
///                       which is exactly how Sui validators verify zkLogin /
///                       MultiSig / Passkey-as-sender signatures on the way in.
///                       These members are *approver-only*: they can propose +
///                       approve, but they cannot execute, because they don't
///                       hold an encrypted user-share — see `recovery::recovery`.)
///
/// Member id (used for dedup, voter tracking, and the registry) =
///   `[scheme_byte, ...pubkey_or_address_bytes]`. Different schemes never
/// collide because we always prefix the byte tag.
module recovery::auth;

use std::bcs;
use sui::address;
use sui::ecdsa_k1;
use sui::ecdsa_r1;
use sui::ed25519;
use sui::hash;
use sui::vec_set::VecSet;

use recovery::assertion::{Self, WebAuthnAssertion};

const SCHEME_ED25519: u8 = 0;
const SCHEME_SECP256K1: u8 = 1;
const SCHEME_SECP256R1: u8 = 2;
const SCHEME_WEBAUTHN: u8 = 3;
const SCHEME_SENDER_ADDRESS: u8 = 4;

/// `hash` arg for ecdsa_{k1,r1}::*_verify — 0 means SHA-256.
const SHA256_HASH: u8 = 0;

const EUnknownMember: u64 = 1;
const EBadSignature: u64 = 2;
const EBadChallengeLength: u64 = 3;
const EBadPubkeyLength: u64 = 4;
/// Caller passed a SenderAddress credential whose embedded address doesn't
/// match `ctx.sender()`. The credential is constructed by capturing the
/// sender, so this only fires if a caller hand-built one with a forged
/// address — but verifying it explicitly is cheap and closes the loophole.
const EWrongSender: u64 = 5;

// ===== Credential =====

public enum Credential has drop {
    Ed25519    { signature: vector<u8>, public_key: vector<u8> },
    Secp256k1  { signature: vector<u8>, public_key: vector<u8> },
    Secp256r1  { signature: vector<u8>, public_key: vector<u8> },
    WebAuthn(WebAuthnAssertion),
    /// Approver-only: authorized when the embedded address equals
    /// `ctx.sender()`. The address is captured at construction (in the same
    /// PTB as verification, since `Credential` has `drop` only) so it cannot
    /// drift; verification still re-checks against the live sender to defeat
    /// hand-built forgeries.
    SenderAddress(address),
}

public fun ed25519_credential(
    signature: vector<u8>,
    public_key: vector<u8>,
): Credential {
    Credential::Ed25519 { signature, public_key }
}

public fun secp256k1_credential(
    signature: vector<u8>,
    public_key: vector<u8>,
): Credential {
    Credential::Secp256k1 { signature, public_key }
}

public fun secp256r1_credential(
    signature: vector<u8>,
    public_key: vector<u8>,
): Credential {
    Credential::Secp256r1 { signature, public_key }
}

public fun webauthn_credential(a: WebAuthnAssertion): Credential {
    Credential::WebAuthn(a)
}

/// Wrap `ctx.sender()` as a credential. Use this for member identities whose
/// authentication is delegated to Sui's tx-signature pipeline (zkLogin,
/// MultiSig, Passkey-as-sender). The validators have already verified the
/// signature on the way in by the time Move runs — we only need to confirm
/// the sender is in the members set.
public fun sender_credential(ctx: &TxContext): Credential {
    Credential::SenderAddress(ctx.sender())
}

/// True if the credential is the approver-only variant. Callers that gate
/// "execute"-style operations on having an encrypted user share should use
/// this to fail fast with a clear message before consuming any presigns.
public fun is_approver_only(cred: &Credential): bool {
    match (cred) {
        Credential::SenderAddress(_) => true,
        _ => false,
    }
}

/// Verify the credential against the unified members set and challenge.
/// Returns the canonical voter id `[scheme, ...pubkey_or_address]`.
public(package) fun verify(
    cred: Credential,
    members: &VecSet<vector<u8>>,
    expected_challenge: &vector<u8>,
    ctx: &TxContext,
): vector<u8> {
    assert!(expected_challenge.length() == 32, EBadChallengeLength);
    match (cred) {
        Credential::Ed25519 { signature, public_key } => {
            assert!(public_key.length() == 32, EBadPubkeyLength);
            let id = member_id(SCHEME_ED25519, &public_key);
            assert!(members.contains(&id), EUnknownMember);
            let digest = personal_message_digest(expected_challenge);
            let ok = ed25519::ed25519_verify(&signature, &public_key, &digest);
            assert!(ok, EBadSignature);
            id
        },
        Credential::Secp256k1 { signature, public_key } => {
            assert!(public_key.length() == 33, EBadPubkeyLength);
            let id = member_id(SCHEME_SECP256K1, &public_key);
            assert!(members.contains(&id), EUnknownMember);
            let digest = personal_message_digest(expected_challenge);
            let ok = ecdsa_k1::secp256k1_verify(&signature, &public_key, &digest, SHA256_HASH);
            assert!(ok, EBadSignature);
            id
        },
        Credential::Secp256r1 { signature, public_key } => {
            assert!(public_key.length() == 33, EBadPubkeyLength);
            let id = member_id(SCHEME_SECP256R1, &public_key);
            assert!(members.contains(&id), EUnknownMember);
            let digest = personal_message_digest(expected_challenge);
            let ok = ecdsa_r1::secp256r1_verify(&signature, &public_key, &digest, SHA256_HASH);
            assert!(ok, EBadSignature);
            id
        },
        Credential::WebAuthn(a) => {
            // assertion does the crypto + challenge-in-clientDataJSON check;
            // membership is enforced here against the unified set.
            let pk = *assertion::public_key(&a);
            let id = member_id(SCHEME_WEBAUTHN, &pk);
            assert!(members.contains(&id), EUnknownMember);
            assertion::verify_signature(&a, expected_challenge);
            id
        },
        Credential::SenderAddress(addr) => {
            assert!(addr == ctx.sender(), EWrongSender);
            let addr_bytes = address::to_bytes(addr);
            let id = member_id(SCHEME_SENDER_ADDRESS, &addr_bytes);
            assert!(members.contains(&id), EUnknownMember);
            id
        },
    }
}

/// Recreate the 32-byte digest a Sui wallet's `signPersonalMessage`
/// produces:
///   `blake2b256([3, 0, 0] || bcs(message))`
/// where bcs of `vector<u8>` is `uleb128(len) || bytes`.
fun personal_message_digest(challenge: &vector<u8>): vector<u8> {
    let intent = vector[3u8, 0u8, 0u8];
    let payload = bcs::to_bytes(challenge);
    let mut signed = intent;
    vector::append(&mut signed, payload);
    hash::blake2b256(&signed)
}

fun member_id(scheme: u8, public_key: &vector<u8>): vector<u8> {
    let mut id = vector::empty<u8>();
    id.push_back(scheme);
    vector::append(&mut id, *public_key);
    id
}

// ===== NewMember =====

public enum NewMember has store, copy, drop {
    Ed25519(vector<u8>),
    Secp256k1(vector<u8>),
    Secp256r1(vector<u8>),
    WebAuthn(vector<u8>),
    /// Approver-only member. Identified by Sui address; auth is `ctx.sender()`
    /// at action time. Doesn't need an encryption key registered, doesn't
    /// receive a re-encrypted user share.
    SenderAddress(address),
}

public fun new_ed25519_member(public_key: vector<u8>): NewMember {
    NewMember::Ed25519(public_key)
}
public fun new_secp256k1_member(public_key: vector<u8>): NewMember {
    NewMember::Secp256k1(public_key)
}
public fun new_secp256r1_member(public_key: vector<u8>): NewMember {
    NewMember::Secp256r1(public_key)
}
public fun new_webauthn_member(public_key: vector<u8>): NewMember {
    NewMember::WebAuthn(public_key)
}
public fun new_sender_member(addr: address): NewMember {
    NewMember::SenderAddress(addr)
}

/// True for members whose identity is just an address — no encryption share
/// gets re-encrypted to them, so they can't be the executor of a recovery.
public fun is_approver_only_member(m: &NewMember): bool {
    match (m) {
        NewMember::SenderAddress(_) => true,
        _ => false,
    }
}

/// Canonical id bytes used everywhere — registry, voter dedup, members set.
public(package) fun new_member_id_bytes(m: &NewMember): vector<u8> {
    match (m) {
        NewMember::Ed25519(pk)    => member_id(SCHEME_ED25519, pk),
        NewMember::Secp256k1(pk)  => member_id(SCHEME_SECP256K1, pk),
        NewMember::Secp256r1(pk)  => member_id(SCHEME_SECP256R1, pk),
        NewMember::WebAuthn(pk)   => member_id(SCHEME_WEBAUTHN, pk),
        NewMember::SenderAddress(addr) => member_id(SCHEME_SENDER_ADDRESS, &address::to_bytes(*addr)),
    }
}

public(package) fun is_already_member(
    m: &NewMember,
    members: &VecSet<vector<u8>>,
): bool {
    members.contains(&new_member_id_bytes(m))
}

public(package) fun insert_member(
    m: NewMember,
    members: &mut VecSet<vector<u8>>,
) {
    members.insert(new_member_id_bytes(&m));
}

/// Remove a member by canonical id bytes (`[scheme, ...pubkey_or_address]`).
/// Aborts with `EUnknownMember` if the id isn't present — callers gate on
/// presence before this so the abort signals a programming error.
public(package) fun remove_member(
    member_id_bytes: vector<u8>,
    members: &mut VecSet<vector<u8>>,
) {
    members.remove(&member_id_bytes);
}
