/// WebAuthn (passkey) assertion verification for the recovery module.
///
/// `WebAuthnAssertion` carries a passkey signature and the data the
/// authenticator signed. `verify` checks (a) the public key is in an
/// authorized set, (b) the signature is valid over `authenticator_data ||
/// sha256(client_data_json)` (per WebAuthn §6.3.3), and (c) the JSON's
/// `challenge` field equals the expected operation-bound challenge.
module recovery::assertion;

use std::hash;
use sui::ecdsa_r1;

const ECDSA_R1_SHA256: u8 = 1;

const EAssertionInvalid: u64 = 2;
const EChallengeMismatch: u64 = 3;
const EBadChallengeLength: u64 = 4;

public struct WebAuthnAssertion has drop {
    public_key: vector<u8>,
    authenticator_data: vector<u8>,
    client_data_json: vector<u8>,
    signature: vector<u8>,
}

public fun new(
    public_key: vector<u8>,
    authenticator_data: vector<u8>,
    client_data_json: vector<u8>,
    signature: vector<u8>,
): WebAuthnAssertion {
    WebAuthnAssertion { public_key, authenticator_data, client_data_json, signature }
}

public(package) fun public_key(self: &WebAuthnAssertion): &vector<u8> { &self.public_key }
public(package) fun authenticator_data(self: &WebAuthnAssertion): &vector<u8> { &self.authenticator_data }
public(package) fun client_data_json(self: &WebAuthnAssertion): &vector<u8> { &self.client_data_json }
public(package) fun signature(self: &WebAuthnAssertion): &vector<u8> { &self.signature }

/// Verify the assertion's signature and challenge binding. Membership is
/// checked by the caller (`auth::verify`) against the unified members set.
/// Aborts on any failure; returns nothing on success.
public(package) fun verify_signature(
    self: &WebAuthnAssertion,
    expected_challenge: &vector<u8>,
) {
    assert!(expected_challenge.length() == 32, EBadChallengeLength);

    let cd_hash = hash::sha2_256(self.client_data_json);
    let mut signed = vector::empty<u8>();
    vector::append(&mut signed, self.authenticator_data);
    vector::append(&mut signed, cd_hash);

    let ok = ecdsa_r1::secp256r1_verify(
        &self.signature,
        &self.public_key,
        &signed,
        ECDSA_R1_SHA256,
    );
    assert!(ok, EAssertionInvalid);

    let encoded = base64url_encode_32(expected_challenge);
    let mut needle = vector::empty<u8>();
    vector::append(&mut needle, b"\"challenge\":\"");
    vector::append(&mut needle, encoded);
    vector::push_back(&mut needle, 34u8); // closing "
    assert!(contains_subvec(&self.client_data_json, &needle), EChallengeMismatch);
}

/// Encode a 32-byte input as 43-char unpadded base64url.
public(package) fun base64url_encode_32(input: &vector<u8>): vector<u8> {
    assert!(input.length() == 32, EBadChallengeLength);
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = vector::empty<u8>();
    // 10 full 3-byte groups -> 40 chars
    let mut g = 0;
    while (g < 10) {
        let b0 = (*input.borrow(g * 3) as u64);
        let b1 = (*input.borrow(g * 3 + 1) as u64);
        let b2 = (*input.borrow(g * 3 + 2) as u64);
        let combined = (b0 << 16) | (b1 << 8) | b2;
        out.push_back(*alphabet.borrow(((combined >> 18) & 0x3f) as u64));
        out.push_back(*alphabet.borrow(((combined >> 12) & 0x3f) as u64));
        out.push_back(*alphabet.borrow(((combined >> 6) & 0x3f) as u64));
        out.push_back(*alphabet.borrow((combined & 0x3f) as u64));
        g = g + 1;
    };
    // Final 2 bytes -> 3 chars (no padding)
    let b0 = (*input.borrow(30) as u64);
    let b1 = (*input.borrow(31) as u64);
    out.push_back(*alphabet.borrow(((b0 >> 2) & 0x3f) as u64));
    out.push_back(*alphabet.borrow(((((b0 & 0x03) << 4) | (b1 >> 4)) & 0x3f) as u64));
    out.push_back(*alphabet.borrow((((b1 & 0x0f) << 2) & 0x3f) as u64));
    out
}

/// O(n*m) substring check.
public(package) fun contains_subvec(haystack: &vector<u8>, needle: &vector<u8>): bool {
    let h_len = haystack.length();
    let n_len = needle.length();
    if (n_len == 0) return true;
    if (h_len < n_len) return false;
    let last = h_len - n_len;
    let mut i = 0;
    while (i <= last) {
        let mut j = 0;
        let mut matched = true;
        while (j < n_len) {
            if (*haystack.borrow(i + j) != *needle.borrow(j)) {
                matched = false;
                break
            };
            j = j + 1;
        };
        if (matched) return true;
        i = i + 1;
    };
    false
}
