//! Secp256k1 (k1) credential verification.
//!
//! Mirrors `recovery::auth`'s `Credential::Secp256k1` arm on Sui:
//! same canonical id (`[scheme, ...33-byte compressed pubkey]`).
//!
//! Sui exposes `ecdsa_k1::secp256k1_verify(sig, pk, msg, hash)` directly.
//! Solana doesn't, but its `secp256k1_recover` syscall returns the
//! 64-byte uncompressed pubkey that produced a (sig, hash) pair. Compress
//! it and compare to the 33-byte pubkey stored in the roster. That's the
//! same proof: the signer holds the private key for the stored pubkey.
//!
//! On SBF we declare the syscall extern directly (no_std-friendly) rather
//! than depending on `solana-secp256k1-recover` — that crate isn't
//! `#![no_std]` and pulls a duplicate `panic_impl` into our build.

use super::{AuthError, SECP256K1_PUBKEY_LEN};

/// 64-byte (r||s) ECDSA signature plus a 1-byte recovery_id (0 or 1).
pub const AUTH_SIGNATURE_LEN: usize = 65;

#[cfg(target_os = "solana")]
mod sbf {
    extern "C" {
        pub fn sol_secp256k1_recover(
            hash: *const u8,
            recovery_id: u64,
            signature: *const u8,
            result: *mut u8,
        ) -> u64;
    }
}

#[cfg(target_os = "solana")]
fn recover(challenge: &[u8; 32], recovery_id: u8, sig_rs: &[u8]) -> Result<[u8; 64], AuthError> {
    let mut out = [0u8; 64];
    let rc = unsafe {
        sbf::sol_secp256k1_recover(
            challenge.as_ptr(),
            recovery_id as u64,
            sig_rs.as_ptr(),
            out.as_mut_ptr(),
        )
    };
    if rc == 0 {
        Ok(out)
    } else {
        Err(AuthError::BadSignature)
    }
}

#[cfg(not(target_os = "solana"))]
fn recover(challenge: &[u8; 32], recovery_id: u8, sig_rs: &[u8]) -> Result<[u8; 64], AuthError> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    let recid = RecoveryId::from_byte(recovery_id).ok_or(AuthError::BadSignature)?;
    let sig = Signature::from_slice(sig_rs).map_err(|_| AuthError::BadSignature)?;
    let vk = VerifyingKey::recover_from_prehash(challenge, &sig, recid)
        .map_err(|_| AuthError::BadSignature)?;
    let point = vk.to_encoded_point(false);
    let bytes = point.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(AuthError::BadSignature);
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes[1..]);
    Ok(out)
}

/// Verify that `auth_signature` was produced by the private key whose
/// 33-byte compressed pubkey is `compressed_pubkey`, signing `challenge`.
pub fn verify(
    compressed_pubkey: &[u8],
    challenge: &[u8; 32],
    auth_signature: &[u8; AUTH_SIGNATURE_LEN],
) -> Result<(), AuthError> {
    if compressed_pubkey.len() != SECP256K1_PUBKEY_LEN {
        return Err(AuthError::BadPubkeyLength);
    }
    let recovery_id = auth_signature[64];
    if recovery_id > 1 {
        return Err(AuthError::BadSignature);
    }
    let sig_rs = &auth_signature[..64];
    let uncompressed = recover(challenge, recovery_id, sig_rs)?;

    // Compress: 0x02 if y even, 0x03 if y odd, then the 32-byte x-coord.
    // `uncompressed = x(32) || y(32)`; the parity is the LSB of y[31].
    let prefix = if uncompressed[63] & 1 == 0 {
        0x02
    } else {
        0x03
    };
    let mut compressed = [0u8; SECP256K1_PUBKEY_LEN];
    compressed[0] = prefix;
    compressed[1..].copy_from_slice(&uncompressed[..32]);

    if compressed.as_slice() != compressed_pubkey {
        return Err(AuthError::BadSignature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature, SigningKey};
    use std::vec::Vec;

    fn fresh_keypair_and_sig(challenge: &[u8; 32]) -> (Vec<u8>, [u8; 65]) {
        let seed = [0x42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed.into()).unwrap();
        let verifying_key = signing_key.verifying_key();
        let compressed = verifying_key.to_encoded_point(true).as_bytes().to_vec();

        let (sig, recid): (Signature, RecoveryId) = signing_key.sign_prehash(challenge).unwrap();
        let sig_bytes = sig.to_bytes();

        let mut out = [0u8; 65];
        out[..64].copy_from_slice(sig_bytes.as_slice());
        out[64] = recid.to_byte();
        (compressed, out)
    }

    #[test]
    fn round_trip_real_keypair() {
        let challenge = [0xa5u8; 32];
        let (compressed_pk, sig) = fresh_keypair_and_sig(&challenge);
        verify(&compressed_pk, &challenge, &sig).expect("happy path");
    }

    #[test]
    fn rejects_wrong_pubkey() {
        let challenge = [0xa5u8; 32];
        let (mut compressed_pk, sig) = fresh_keypair_and_sig(&challenge);
        compressed_pk[5] ^= 1;
        let err = verify(&compressed_pk, &challenge, &sig).unwrap_err();
        assert_eq!(err, AuthError::BadSignature);
    }

    #[test]
    fn rejects_wrong_challenge() {
        let challenge = [0xa5u8; 32];
        let (compressed_pk, sig) = fresh_keypair_and_sig(&challenge);
        let other = [0xa6u8; 32];
        let err = verify(&compressed_pk, &other, &sig).unwrap_err();
        assert_eq!(err, AuthError::BadSignature);
    }

    #[test]
    fn rejects_bad_pubkey_length() {
        let challenge = [0xa5u8; 32];
        let (_, sig) = fresh_keypair_and_sig(&challenge);
        let too_short = [0u8; 32];
        assert_eq!(
            verify(&too_short, &challenge, &sig),
            Err(AuthError::BadPubkeyLength)
        );
    }

    #[test]
    fn rejects_invalid_recovery_id() {
        let challenge = [0xa5u8; 32];
        let (compressed_pk, mut sig) = fresh_keypair_and_sig(&challenge);
        sig[64] = 27;
        assert_eq!(
            verify(&compressed_pk, &challenge, &sig),
            Err(AuthError::BadSignature)
        );
    }

    #[test]
    fn cross_chain_id_parity_with_sui() {
        // Both chains store `[scheme=1, ...33-byte compressed pubkey]`.
        let challenge = [0u8; 32];
        let (compressed_pk, _sig) = fresh_keypair_and_sig(&challenge);
        assert_eq!(compressed_pk.len(), 33);
        assert!(compressed_pk[0] == 0x02 || compressed_pk[0] == 0x03);
    }
}
