//! WebAuthn assertion validation — Sui-parity.
//!
//! When a passkey signs a recovery operation it doesn't sign the raw
//! 32-byte challenge directly. Instead the authenticator signs:
//!
//!   `signed = authenticator_data || sha256(client_data_json)`
//!
//! where `client_data_json` is a UTF-8 JSON blob the *browser* (not the
//! authenticator) constructs:
//!
//!   `{"type":"webauthn.get","challenge":"<b64url(challenge)>","origin":"…"}`
//!
//! The Secp256r1 precompile only verifies the signature over `signed`. It
//! cannot check that the embedded challenge is *our* challenge — that
//! check lives here. We:
//!
//!   1. Take `signed` from the precompile (already verified by the
//!      runtime to have been signed by the credential's pubkey).
//!   2. Split off the trailing 32 bytes (must equal `sha256(cdj)`).
//!   3. Build the canonical needle `"challenge":"<base64url(challenge)>"`
//!      and substring-search `client_data_json` for it. This is the same
//!      check `recovery::assertion::verify_signature` uses on Sui — so a
//!      passkey + cdj that pass on one chain pass on the other.
//!
//! `rpIdHash` and the user-presence (`UP`) flag are intentionally not
//! validated. Sui's check doesn't validate them either; the relying-party
//! domain is a frontend concern (origin gating, RP id pinning) and adding
//! it on-chain would couple the program to a deployment. The substring
//! check is escape-safe in practice because the challenge is a 32-byte
//! base64url alphabet payload (`[A-Za-z0-9_-]`, 43 chars unpadded), so it
//! can't contain `"` or other JSON metacharacters.

use solana_sha256_hasher::hashv;

/// Errors surfaced from WebAuthn assertion parsing. Mapped into
/// [`crate::auth::AuthError`] at call sites.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum WebAuthnError {
    /// `signed` was shorter than 32 bytes — can't even hold the trailing
    /// `sha256(cdj)`. No real authenticator emits this.
    SignedTooShort,
    /// Trailing 32 bytes of `signed` didn't match `sha256(client_data_json)`.
    ClientDataHashMismatch,
    /// `client_data_json` did not contain `"challenge":"<b64url>"`
    /// matching the operation challenge.
    ChallengeMismatch,
}

/// Verify the assertion's signed payload commits to `expected_challenge`.
///
/// `signed` is `record.message` from a Secp256r1 precompile invocation —
/// already verified by the runtime to have been signed by the
/// credential's pubkey. `client_data_json` is the raw JSON the browser
/// produced; the caller passes it as an instruction argument.
pub fn verify_assertion(
    signed: &[u8],
    client_data_json: &[u8],
    expected_challenge: &[u8; 32],
) -> Result<(), WebAuthnError> {
    if signed.len() < 32 {
        return Err(WebAuthnError::SignedTooShort);
    }
    let split = signed.len() - 32;
    let cdj_hash_in_signed = &signed[split..];
    let cdj_hash = hashv(&[client_data_json]).to_bytes();
    if cdj_hash.as_slice() != cdj_hash_in_signed {
        return Err(WebAuthnError::ClientDataHashMismatch);
    }

    // Build needle: "challenge":"<43-char b64url>"
    let mut needle = [0u8; 13 + 43 + 1];
    let prefix = b"\"challenge\":\"";
    needle[..prefix.len()].copy_from_slice(prefix);
    base64url_encode_32(
        expected_challenge,
        &mut needle[prefix.len()..prefix.len() + 43],
    );
    needle[prefix.len() + 43] = b'"';

    if !contains_subsequence(client_data_json, &needle) {
        return Err(WebAuthnError::ChallengeMismatch);
    }
    Ok(())
}

/// Encode a 32-byte input as 43-char unpadded base64url. Writes exactly
/// 43 bytes into `out`.
fn base64url_encode_32(input: &[u8; 32], out: &mut [u8]) {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    debug_assert_eq!(out.len(), 43);
    // 10 full 3-byte groups -> 40 chars
    let mut g = 0;
    while g < 10 {
        let b0 = input[g * 3] as u32;
        let b1 = input[g * 3 + 1] as u32;
        let b2 = input[g * 3 + 2] as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out[g * 4] = ALPHA[((n >> 18) & 0x3f) as usize];
        out[g * 4 + 1] = ALPHA[((n >> 12) & 0x3f) as usize];
        out[g * 4 + 2] = ALPHA[((n >> 6) & 0x3f) as usize];
        out[g * 4 + 3] = ALPHA[(n & 0x3f) as usize];
        g += 1;
    }
    // Final 2 bytes -> 3 chars (no padding)
    let b0 = input[30] as u32;
    let b1 = input[31] as u32;
    out[40] = ALPHA[((b0 >> 2) & 0x3f) as usize];
    out[41] = ALPHA[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize];
    out[42] = ALPHA[((b1 & 0x0f) << 2) as usize];
}

#[inline]
fn contains_subsequence(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if hay.len() < needle.len() {
        return false;
    }
    let last = hay.len() - needle.len();
    let mut i = 0;
    while i <= last {
        if &hay[i..i + needle.len()] == needle {
            return true;
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    fn b64url_encode(bytes: &[u8]) -> std::string::String {
        const ALPHA: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = std::string::String::new();
        let mut i = 0;
        while i + 3 <= bytes.len() {
            let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | bytes[i + 2] as u32;
            out.push(ALPHA[((n >> 18) & 0x3f) as usize] as char);
            out.push(ALPHA[((n >> 12) & 0x3f) as usize] as char);
            out.push(ALPHA[((n >> 6) & 0x3f) as usize] as char);
            out.push(ALPHA[(n & 0x3f) as usize] as char);
            i += 3;
        }
        match bytes.len() - i {
            0 => {}
            1 => {
                let n = (bytes[i] as u32) << 16;
                out.push(ALPHA[((n >> 18) & 0x3f) as usize] as char);
                out.push(ALPHA[((n >> 12) & 0x3f) as usize] as char);
            }
            2 => {
                let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
                out.push(ALPHA[((n >> 18) & 0x3f) as usize] as char);
                out.push(ALPHA[((n >> 12) & 0x3f) as usize] as char);
                out.push(ALPHA[((n >> 6) & 0x3f) as usize] as char);
            }
            _ => unreachable!(),
        }
        out
    }

    fn build_cdj(challenge_bytes: &[u8]) -> Vec<u8> {
        let enc = b64url_encode(challenge_bytes);
        let s = std::format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"https://example.com\"}}",
            enc
        );
        s.into_bytes()
    }

    fn build_signed(client_data_json: &[u8]) -> Vec<u8> {
        let mut auth_data: Vec<u8> = vec![0x77u8; 32];
        auth_data.push(0x01);
        auth_data.extend_from_slice(&[0u8; 4]);
        let cdj_hash = hashv(&[client_data_json]).to_bytes();
        let mut signed = auth_data;
        signed.extend_from_slice(&cdj_hash);
        signed
    }

    #[test]
    fn happy_path_verifies_with_matching_challenge() {
        let challenge = [0xa5u8; 32];
        let cdj = build_cdj(&challenge);
        let signed = build_signed(&cdj);
        verify_assertion(&signed, &cdj, &challenge).unwrap();
    }

    #[test]
    fn rejects_mismatched_challenge() {
        let challenge = [0xa5u8; 32];
        let cdj = build_cdj(&challenge);
        let signed = build_signed(&cdj);
        let other = [0xa6u8; 32];
        assert_eq!(
            verify_assertion(&signed, &cdj, &other),
            Err(WebAuthnError::ChallengeMismatch)
        );
    }

    #[test]
    fn rejects_cdj_hash_mismatch() {
        let challenge = [0xa5u8; 32];
        let cdj = build_cdj(&challenge);
        let signed = build_signed(&cdj);
        let mut tampered = cdj.clone();
        let len = tampered.len();
        tampered[len - 2] = b'X';
        assert_eq!(
            verify_assertion(&signed, &tampered, &challenge),
            Err(WebAuthnError::ClientDataHashMismatch)
        );
    }

    #[test]
    fn rejects_signed_too_short() {
        let signed = [0u8; 30];
        let cdj = build_cdj(&[0u8; 32]);
        assert_eq!(
            verify_assertion(&signed, &cdj, &[0u8; 32]),
            Err(WebAuthnError::SignedTooShort)
        );
    }

    #[test]
    fn rejects_when_challenge_field_absent() {
        let challenge = [0xa5u8; 32];
        let cdj = b"{\"type\":\"webauthn.get\",\"origin\":\"x\"}".to_vec();
        let signed = build_signed(&cdj);
        assert_eq!(
            verify_assertion(&signed, &cdj, &challenge),
            Err(WebAuthnError::ChallengeMismatch)
        );
    }

    #[test]
    fn base64url_encode_32_matches_reference() {
        let input = [
            0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let mut got = [0u8; 43];
        base64url_encode_32(&input, &mut got);
        let expected = b64url_encode(&input);
        assert_eq!(&got, expected.as_bytes());
    }

    #[test]
    fn substring_match_tolerates_whitespace_around_field() {
        // Sui's substring check matches the canonical form regardless of
        // surrounding JSON formatting; whitespace inside the JSON object
        // outside the `"challenge":"..."` token doesn't break the search.
        let challenge = [0xa5u8; 32];
        let enc = b64url_encode(&challenge);
        let s = std::format!(
            "{{ \"type\":\"webauthn.get\" , \"challenge\":\"{}\" , \"origin\":\"x\" }}",
            enc
        );
        let cdj = s.into_bytes();
        let signed = build_signed(&cdj);
        verify_assertion(&signed, &cdj, &challenge).unwrap();
    }
}
