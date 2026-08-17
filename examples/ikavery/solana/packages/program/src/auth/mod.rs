//! Unified authentication for the recovery module.
//!
//! Every member is a `(scheme, public_key_or_address)` pair. The on-chain
//! authorization gate is "this credential signed the per-operation challenge
//! AND the resulting member-id is in the recovery's set" — the Solana
//! tx-level signer is decoupled from the auth identity, so a sponsor wallet
//! can pay fees while a member's wallet authorises the action separately.
//!
//! Schemes (matching `recovery::auth` on Sui for cross-chain id parity):
//!   0 = Ed25519        (32-byte pubkey)
//!   1 = Secp256k1      (33-byte compressed pubkey)
//!   2 = Secp256r1      (33-byte compressed pubkey)
//!   3 = WebAuthn       (33-byte compressed secp256r1 passkey pubkey)
//!   4 = SolanaAddress  (32-byte Solana address — the dynamic.xyz / Phantom
//!                       wallet path. Authorised by being a tx Signer; the
//!                       runtime has already verified the ed25519 signature
//!                       on the way in. Mirrors Sui's `SenderAddress` scheme.)
//!
//! Member id (used for dedup, voter tracking, and the cross-chain registry):
//!   `[scheme_byte, ...pubkey_or_address_bytes]`. Different schemes never
//! collide because we always prefix the byte tag.

pub mod challenges;
pub mod members;
pub mod precompile;
pub mod secp256k1;
pub mod webauthn;

use solana_address::Address;

#[cfg(not(target_os = "solana"))]
extern crate alloc;
#[cfg(not(target_os = "solana"))]
use alloc::vec::Vec;

pub const SCHEME_ED25519: u8 = 0;
pub const SCHEME_SECP256K1: u8 = 1;
pub const SCHEME_SECP256R1: u8 = 2;
pub const SCHEME_WEBAUTHN: u8 = 3;
pub const SCHEME_SOLANA_ADDRESS: u8 = 4;

/// Pubkey lengths per scheme (bytes after the 1-byte scheme tag).
pub const ED25519_PUBKEY_LEN: usize = 32;
pub const SECP256K1_PUBKEY_LEN: usize = 33;
pub const SECP256R1_PUBKEY_LEN: usize = 33;
pub const WEBAUTHN_PUBKEY_LEN: usize = 33;
pub const SOLANA_ADDRESS_LEN: usize = 32;

/// The longest member-id is `1 + 33 = 34` bytes (any 33-byte-pubkey scheme).
pub const MAX_MEMBER_ID_LEN: usize = 34;

/// Active member-id length for a scheme tag, including the tag byte.
/// Returns `None` for unknown schemes.
#[inline]
pub fn id_len_for_scheme(scheme: u8) -> Option<usize> {
    Some(
        1 + match scheme {
            SCHEME_ED25519 => ED25519_PUBKEY_LEN,
            SCHEME_SECP256K1 => SECP256K1_PUBKEY_LEN,
            SCHEME_SECP256R1 => SECP256R1_PUBKEY_LEN,
            SCHEME_WEBAUTHN => WEBAUTHN_PUBKEY_LEN,
            SCHEME_SOLANA_ADDRESS => SOLANA_ADDRESS_LEN,
            _ => return None,
        },
    )
}

/// Errors returned from credential verification + member-set operations.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AuthError {
    UnknownMember,
    BadSignature,
    BadChallengeLength,
    BadPubkeyLength,
    /// The `SolanaAddress` credential's embedded address didn't match the
    /// declared Signer. Mirrors Sui's `EWrongSender`.
    WrongSigner,
    /// No precompile invocation in the tx covered the credential / challenge.
    NoMatchingPrecompile,
    /// The Instructions-sysvar account address wasn't `Sysvar1nstructions…`.
    BadInstructionsSysvar,
    /// `client_data_json` parse / hash / challenge check failed.
    BadWebAuthnAssertion,
    /// Solana ships a Secp256k1 precompile, but only an ETH-style one
    /// (recovers a 20-byte address, not a 33-byte compressed pubkey).
    /// Wiring it up needs an on-chain pubkey-to-address mapper that we
    /// haven't built yet — see task #112.
    SchemeNotYetSupported,
}

/// On-the-wire credential a caller presents to a recovery instruction.
///
/// `SolanaAddress` is the only variant whose verification works on-chain
/// today: the Solana runtime has already verified the ed25519 signature
/// (the wallet is a tx Signer), so the program only needs to confirm the
/// declared address actually signed and that the resulting member-id is in
/// the set. The other variants are reserved data-model slots and currently
/// return [`AuthError::SchemeNotYetSupported`].
#[derive(Debug, Clone)]
pub enum Credential<'a> {
    Ed25519 {
        signature: &'a [u8],
        public_key: &'a [u8],
    },
    Secp256k1 {
        signature: &'a [u8],
        public_key: &'a [u8],
    },
    Secp256r1 {
        signature: &'a [u8],
        public_key: &'a [u8],
    },
    WebAuthn(&'a [u8]),
    /// Approver path: the wallet is a Solana tx Signer and `addr` is its
    /// declared address. Verification only needs to confirm the Signer's
    /// address matches `addr` and that the canonical id is in the set —
    /// no on-chain crypto.
    SolanaAddress(Address),
}

impl<'a> Credential<'a> {
    /// True when the credential identifies an approver-only member — i.e.
    /// one that doesn't carry signing material in-band. Mirrors Sui's
    /// `is_approver_only`. On Solana there's no encrypted user-share so
    /// every member is functionally approver-only, but this is preserved
    /// for symmetry with the Sui registry contract.
    #[inline]
    pub fn is_approver_only(&self) -> bool {
        matches!(self, Credential::SolanaAddress(_))
    }

    /// Scheme byte used in the canonical member-id.
    #[inline]
    pub fn scheme(&self) -> u8 {
        match self {
            Credential::Ed25519 { .. } => SCHEME_ED25519,
            Credential::Secp256k1 { .. } => SCHEME_SECP256K1,
            Credential::Secp256r1 { .. } => SCHEME_SECP256R1,
            Credential::WebAuthn(_) => SCHEME_WEBAUTHN,
            Credential::SolanaAddress(_) => SCHEME_SOLANA_ADDRESS,
        }
    }
}

/// Member-id bytes: `[scheme_byte, ...public_key_or_address_bytes]`.
///
/// Variable-length output because secp256k1 / secp256r1 / webauthn
/// pubkeys are 33 bytes (compressed) while ed25519 / solana addresses are
/// 32. On-chain storage in [`crate::state`] pads each slot to
/// [`MAX_MEMBER_ID_LEN`]; the active id length for a slot is implied by
/// its scheme tag — see [`id_len_for_scheme`].
#[cfg(not(target_os = "solana"))]
pub fn member_id(scheme: u8, public_key_or_address: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + public_key_or_address.len());
    out.push(scheme);
    out.extend_from_slice(public_key_or_address);
    out
}

/// Write the canonical member-id into `out` and return the number of bytes
/// written (`1 + public_key_or_address.len()`). Returns `None` if the
/// destination buffer is too small.
///
/// no_std-friendly companion to [`member_id`]; used on-chain where we
/// cannot allocate a `Vec`.
pub fn write_member_id(scheme: u8, public_key_or_address: &[u8], out: &mut [u8]) -> Option<usize> {
    let needed = 1 + public_key_or_address.len();
    if out.len() < needed {
        return None;
    }
    out[0] = scheme;
    out[1..needed].copy_from_slice(public_key_or_address);
    Some(needed)
}

/// Specification for a member at recovery-creation or roster-change time.
///
/// `Solana(addr)` is the dynamic.xyz path on Solana. The remaining variants
/// store a data-only record so the cross-chain registry stays addressable
/// even before Quasar #184 lands the precompile-inspection path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewMember<'a> {
    Ed25519(&'a [u8]),
    Secp256k1(&'a [u8]),
    Secp256r1(&'a [u8]),
    WebAuthn(&'a [u8]),
    Solana(Address),
}

impl<'a> NewMember<'a> {
    /// Mirrors `recovery::auth::is_approver_only_member`. On Solana every
    /// member is functionally approver-only — kept for cross-chain id
    /// stability with Sui's registry semantics, where this flag drives
    /// whether a member can host an encrypted user share.
    #[inline]
    pub fn is_approver_only(&self) -> bool {
        matches!(self, NewMember::Solana(_))
    }

    #[inline]
    pub fn scheme(&self) -> u8 {
        match self {
            NewMember::Ed25519(_) => SCHEME_ED25519,
            NewMember::Secp256k1(_) => SCHEME_SECP256K1,
            NewMember::Secp256r1(_) => SCHEME_SECP256R1,
            NewMember::WebAuthn(_) => SCHEME_WEBAUTHN,
            NewMember::Solana(_) => SCHEME_SOLANA_ADDRESS,
        }
    }

    /// Length the resulting canonical id will occupy.
    #[inline]
    pub fn id_len(&self) -> usize {
        1 + match self {
            NewMember::Ed25519(pk) => pk.len(),
            NewMember::Secp256k1(pk) => pk.len(),
            NewMember::Secp256r1(pk) => pk.len(),
            NewMember::WebAuthn(pk) => pk.len(),
            NewMember::Solana(_) => SOLANA_ADDRESS_LEN,
        }
    }

    /// Pubkey bytes the canonical id will carry after the scheme tag.
    /// For `Solana(addr)` this is the 32-byte address.
    #[inline]
    pub fn key_bytes(&self) -> &[u8] {
        match self {
            NewMember::Ed25519(pk)
            | NewMember::Secp256k1(pk)
            | NewMember::Secp256r1(pk)
            | NewMember::WebAuthn(pk) => pk,
            NewMember::Solana(addr) => addr.as_array().as_slice(),
        }
    }

    /// Canonical member-id bytes (heap-allocating). Tests use this; on-chain
    /// code uses [`write_new_member_id`].
    #[cfg(not(target_os = "solana"))]
    pub fn id_bytes(&self) -> Vec<u8> {
        member_id(self.scheme(), self.key_bytes())
    }

    /// no_std variant: writes the canonical id into `out` and returns the
    /// number of bytes written.
    pub fn write_id(&self, out: &mut [u8]) -> Option<usize> {
        write_member_id(self.scheme(), self.key_bytes(), out)
    }
}

/// Verify that the tx contains evidence the credential authorised an
/// operation whose challenge digest is `challenge`.
///
/// `payer_address` is the on-tx Signer that paid for the transaction.
/// For `SolanaAddress` credentials this is *the credential itself*; for
/// every other scheme it is just a gas sponsor and verification falls
/// through to either an Instructions-sysvar precompile inspection
/// (Ed25519, Secp256r1, WebAuthn) or a `secp256k1_recover` syscall
/// (Secp256k1) — see the per-arm match below.
///
/// `instructions_sysvar_data` is the raw byte slice borrowed from the
/// Instructions sysvar account. Cross-instruction-index precompile
/// records aren't supported (see [`crate::precompile`]).
///
/// `client_data_json` is only meaningful for `SCHEME_WEBAUTHN`; pass an
/// empty slice for every other scheme.
///
/// `auth_signature` is only meaningful for `SCHEME_SECP256K1`. Layout:
/// `signature[0..64] = r || s`, `signature[64] = recovery_id` (0 or 1).
/// Pass zeroes for every other scheme.
#[allow(clippy::too_many_arguments)]
pub fn verify_credential(
    scheme: u8,
    pubkey: &[u8],
    challenge: &[u8; 32],
    payer_address: &Address,
    instructions_sysvar_data: &[u8],
    client_data_json: &[u8],
    auth_signature: &[u8; 65],
) -> Result<(), AuthError> {
    match scheme {
        SCHEME_SOLANA_ADDRESS => {
            if pubkey.len() != SOLANA_ADDRESS_LEN {
                return Err(AuthError::BadPubkeyLength);
            }
            if pubkey != payer_address.as_array().as_slice() {
                return Err(AuthError::WrongSigner);
            }
            Ok(())
        }
        SCHEME_ED25519 => {
            if pubkey.len() != ED25519_PUBKEY_LEN {
                return Err(AuthError::BadPubkeyLength);
            }
            precompile::find_verified(
                instructions_sysvar_data,
                &precompile::ED25519_PRECOMPILE_ID,
                ED25519_PUBKEY_LEN,
                64,
                |rec| rec.public_key == pubkey && rec.message == challenge.as_slice(),
            )
            .map(|_| ())
            .map_err(map_precompile_err)
        }
        SCHEME_SECP256R1 => {
            if pubkey.len() != SECP256R1_PUBKEY_LEN {
                return Err(AuthError::BadPubkeyLength);
            }
            precompile::find_verified(
                instructions_sysvar_data,
                &precompile::SECP256R1_PRECOMPILE_ID,
                SECP256R1_PUBKEY_LEN,
                64,
                |rec| rec.public_key == pubkey && rec.message == challenge.as_slice(),
            )
            .map(|_| ())
            .map_err(map_precompile_err)
        }
        SCHEME_WEBAUTHN => {
            if pubkey.len() != WEBAUTHN_PUBKEY_LEN {
                return Err(AuthError::BadPubkeyLength);
            }
            precompile::find_verified(
                instructions_sysvar_data,
                &precompile::SECP256R1_PRECOMPILE_ID,
                WEBAUTHN_PUBKEY_LEN,
                64,
                |rec| {
                    rec.public_key == pubkey
                        && webauthn::verify_assertion(rec.message, client_data_json, challenge)
                            .is_ok()
                },
            )
            .map(|_| ())
            .map_err(map_precompile_err)
        }
        SCHEME_SECP256K1 => {
            if pubkey.len() != SECP256K1_PUBKEY_LEN {
                return Err(AuthError::BadPubkeyLength);
            }
            secp256k1::verify(pubkey, challenge, auth_signature)
        }
        _ => Err(AuthError::SchemeNotYetSupported),
    }
}

#[inline]
fn map_precompile_err(e: precompile::PrecompileError) -> AuthError {
    match e {
        precompile::PrecompileError::NotInstructionsSysvar => AuthError::BadInstructionsSysvar,
        _ => AuthError::NoMatchingPrecompile,
    }
}

/// Lift an [`AuthError`] into the program's `ProgramError` surface.
pub fn auth_error_to_program_error(e: AuthError) -> quasar_lang::prelude::ProgramError {
    use crate::error::IkaveryError;
    match e {
        AuthError::BadPubkeyLength => IkaveryError::BadPubkeyLength.into(),
        AuthError::WrongSigner => IkaveryError::WrongSigner.into(),
        AuthError::NoMatchingPrecompile => IkaveryError::NoMatchingPrecompile.into(),
        AuthError::BadInstructionsSysvar => IkaveryError::BadInstructionsSysvar.into(),
        AuthError::BadWebAuthnAssertion => IkaveryError::BadWebAuthnAssertion.into(),
        AuthError::SchemeNotYetSupported => IkaveryError::SchemeNotYetSupported.into(),
        // The remaining variants are only produced by host-side construction
        // helpers and shouldn't surface from `verify_credential`.
        AuthError::UnknownMember | AuthError::BadSignature | AuthError::BadChallengeLength => {
            IkaveryError::SchemeNotYetSupported.into()
        }
    }
}

/// Validate a `NewMember`'s pubkey-length matches its scheme. Mirrors the
/// `EBadPubkeyLength` checks in Sui's `verify`.
pub fn validate_new_member(m: &NewMember<'_>) -> Result<(), AuthError> {
    let actual = match m {
        NewMember::Ed25519(pk) => pk.len(),
        NewMember::Secp256k1(pk) => pk.len(),
        NewMember::Secp256r1(pk) => pk.len(),
        NewMember::WebAuthn(pk) => pk.len(),
        NewMember::Solana(_) => SOLANA_ADDRESS_LEN,
    };
    let expected = match m.scheme() {
        SCHEME_ED25519 => ED25519_PUBKEY_LEN,
        SCHEME_SECP256K1 => SECP256K1_PUBKEY_LEN,
        SCHEME_SECP256R1 => SECP256R1_PUBKEY_LEN,
        SCHEME_WEBAUTHN => WEBAUTHN_PUBKEY_LEN,
        SCHEME_SOLANA_ADDRESS => SOLANA_ADDRESS_LEN,
        _ => return Err(AuthError::BadPubkeyLength),
    };
    if actual != expected {
        return Err(AuthError::BadPubkeyLength);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;

    fn ones(n: usize) -> std::vec::Vec<u8> {
        vec![1u8; n]
    }

    #[test]
    fn new_webauthn_member_id_prefixes_scheme_byte() {
        let pk = ones(WEBAUTHN_PUBKEY_LEN);
        let m = NewMember::WebAuthn(&pk);
        let id = m.id_bytes();
        assert_eq!(id[0], SCHEME_WEBAUTHN);
        assert_eq!(&id[1..], pk.as_slice());
        assert_eq!(id.len(), 1 + WEBAUTHN_PUBKEY_LEN);
    }

    #[test]
    fn new_solana_member_id_prefixes_scheme_byte() {
        let addr = Address::new_from_array([7u8; 32]);
        let m = NewMember::Solana(addr);
        let id = m.id_bytes();
        assert_eq!(id[0], SCHEME_SOLANA_ADDRESS);
        assert_eq!(&id[1..], addr.as_array().as_slice());
        assert_eq!(id.len(), 1 + SOLANA_ADDRESS_LEN);
    }

    #[test]
    fn webauthn_and_solana_ids_cannot_collide() {
        let key = [9u8; 32];
        let webauthn_pk = {
            let mut pk = vec![0u8; WEBAUTHN_PUBKEY_LEN];
            pk[..32].copy_from_slice(&key);
            pk
        };
        let webauthn_id = NewMember::WebAuthn(&webauthn_pk).id_bytes();
        let solana_id = NewMember::Solana(Address::new_from_array(key)).id_bytes();
        assert_ne!(webauthn_id, solana_id);
        assert_ne!(webauthn_id[0], solana_id[0]);
    }

    #[test]
    fn ed25519_and_secp256k1_ids_cannot_collide() {
        let pk32 = ones(ED25519_PUBKEY_LEN);
        let pk33 = ones(SECP256K1_PUBKEY_LEN);
        let id_ed = NewMember::Ed25519(&pk32).id_bytes();
        let id_k1 = NewMember::Secp256k1(&pk33).id_bytes();
        assert_ne!(id_ed[0], id_k1[0]);
    }

    #[test]
    fn is_approver_only_member_only_true_for_solana() {
        let pk32 = ones(32);
        let pk33 = ones(33);
        assert!(!NewMember::Ed25519(&pk32).is_approver_only());
        assert!(!NewMember::Secp256k1(&pk33).is_approver_only());
        assert!(!NewMember::Secp256r1(&pk33).is_approver_only());
        assert!(!NewMember::WebAuthn(&pk33).is_approver_only());
        assert!(NewMember::Solana(Address::new_from_array([0u8; 32])).is_approver_only());
    }

    #[test]
    fn write_member_id_matches_heap_form() {
        let pk = ones(WEBAUTHN_PUBKEY_LEN);
        let mut buf = [0u8; MAX_MEMBER_ID_LEN];
        let n = write_member_id(SCHEME_WEBAUTHN, &pk, &mut buf).unwrap();
        let heap = member_id(SCHEME_WEBAUTHN, &pk);
        assert_eq!(&buf[..n], heap.as_slice());
    }

    #[test]
    fn write_member_id_rejects_too_small_buffer() {
        let pk = ones(WEBAUTHN_PUBKEY_LEN);
        let mut buf = [0u8; 4];
        assert_eq!(write_member_id(SCHEME_WEBAUTHN, &pk, &mut buf), None);
    }

    #[test]
    fn validate_new_member_accepts_correct_lengths() {
        assert!(validate_new_member(&NewMember::Ed25519(&ones(32))).is_ok());
        assert!(validate_new_member(&NewMember::Secp256k1(&ones(33))).is_ok());
        assert!(validate_new_member(&NewMember::Secp256r1(&ones(33))).is_ok());
        assert!(validate_new_member(&NewMember::WebAuthn(&ones(33))).is_ok());
        assert!(
            validate_new_member(&NewMember::Solana(Address::new_from_array([0u8; 32]))).is_ok()
        );
    }

    #[test]
    fn validate_new_member_rejects_wrong_lengths() {
        assert_eq!(
            validate_new_member(&NewMember::Ed25519(&ones(31))),
            Err(AuthError::BadPubkeyLength)
        );
        assert_eq!(
            validate_new_member(&NewMember::Secp256k1(&ones(32))),
            Err(AuthError::BadPubkeyLength)
        );
        assert_eq!(
            validate_new_member(&NewMember::WebAuthn(&ones(34))),
            Err(AuthError::BadPubkeyLength)
        );
    }

    #[test]
    fn credential_scheme_matches_new_member_scheme() {
        let pk32 = ones(32);
        let pk33 = ones(33);
        let sig = ones(64);
        assert_eq!(
            Credential::Ed25519 {
                signature: &sig,
                public_key: &pk32
            }
            .scheme(),
            NewMember::Ed25519(&pk32).scheme()
        );
        assert_eq!(
            Credential::Secp256k1 {
                signature: &sig,
                public_key: &pk33
            }
            .scheme(),
            NewMember::Secp256k1(&pk33).scheme()
        );
        assert_eq!(
            Credential::WebAuthn(&pk33).scheme(),
            NewMember::WebAuthn(&pk33).scheme()
        );
        let addr = Address::new_from_array([1u8; 32]);
        assert_eq!(
            Credential::SolanaAddress(addr).scheme(),
            NewMember::Solana(addr).scheme()
        );
    }
}
