#[test_only]
module recovery::assertion_tests;

use recovery::assertion;
use std::hash;

// === base64url_encode_32 ===

#[test]
fun base64url_zeros_is_43_As() {
    let zeros = vector[
        0u8, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let out = assertion::base64url_encode_32(&zeros);
    assert!(out.length() == 43, 0);
    let mut i = 0;
    while (i < 43) {
        assert!(*out.borrow(i) == b"A"[0], 1);
        i = i + 1;
    };
}

#[test]
fun base64url_sha256_hello_known_vector() {
    let h = hash::sha2_256(b"hello");
    let out = assertion::base64url_encode_32(&h);
    assert!(out == b"LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ", 0);
}

#[test]
fun base64url_all_ones_known_vector() {
    let all_ff = vector[
        0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    let out = assertion::base64url_encode_32(&all_ff);
    // 32 0xff -> first 40 chars all '_' (each 6-bit group is 0x3f);
    // last 2 bytes 0xffff -> sextets 0x3f, 0x3f, 0x3c -> "__8".
    let mut expected = vector::empty<u8>();
    let mut i: u64 = 0;
    while (i < 40) { expected.push_back(b"_"[0]); i = i + 1; };
    expected.push_back(b"_"[0]);
    expected.push_back(b"_"[0]);
    expected.push_back(b"8"[0]);
    assert!(out == expected, 0);
}

#[test]
fun base64url_uses_url_safe_alphabet() {
    // 0xfb -> 6 bits "111110" = 62 = '-' in URL-safe (vs '+' in standard).
    // 0xff -> 6 bits "111111" = 63 = '_' (vs '/').
    // Construct an input where the first six bits are 62, then 63.
    // First byte = 0b11111011 = 0xfb -> first sextet 111110 (62='-'),
    // second sextet wants 111111 -> next 6 bits: 11<00>(11..) -> need 0x3f starting bit 7.
    // Easiest: pad rest with 0xff so we'll see '-' then '_' near the start.
    let mut bytes = vector::empty<u8>();
    bytes.push_back(0xfb);
    let mut i = 0;
    while (i < 31) { bytes.push_back(0xff); i = i + 1; };
    let out = assertion::base64url_encode_32(&bytes);
    assert!(*out.borrow(0) == b"-"[0], 0);
    assert!(*out.borrow(1) == b"_"[0], 1);
}

#[test]
#[expected_failure(abort_code = assertion::EBadChallengeLength)]
fun base64url_rejects_short_input() {
    let short = vector[0u8, 0, 0];
    assertion::base64url_encode_32(&short);
}

// === contains_subvec ===

#[test]
fun substring_present_middle() {
    assert!(assertion::contains_subvec(&b"abcdefghij", &b"def"), 0);
}

#[test]
fun substring_present_start() {
    assert!(assertion::contains_subvec(&b"abcdefghij", &b"abc"), 0);
}

#[test]
fun substring_present_end() {
    assert!(assertion::contains_subvec(&b"abcdefghij", &b"hij"), 0);
}

#[test]
fun substring_absent() {
    assert!(!assertion::contains_subvec(&b"abcdefghij", &b"xyz"), 0);
}

#[test]
fun substring_empty_needle_matches_anything() {
    assert!(assertion::contains_subvec(&b"abc", &b""), 0);
    assert!(assertion::contains_subvec(&b"", &b""), 1);
}

#[test]
fun substring_longer_needle_cannot_match() {
    assert!(!assertion::contains_subvec(&b"abc", &b"abcd"), 0);
    assert!(!assertion::contains_subvec(&b"", &b"a"), 1);
}

#[test]
fun substring_handles_partial_overlap() {
    // "abab" contains "ab" but the second 'a' starts a partial match for "abc"
    // that should fail and resume one position later.
    assert!(!assertion::contains_subvec(&b"ababd", &b"abc"), 0);
    assert!(assertion::contains_subvec(&b"ababd", &b"bd"), 1);
}

// === Realistic clientDataJSON challenge match ===

#[test]
fun client_data_json_challenge_match() {
    let expected = hash::sha2_256(b"hello");
    let encoded = assertion::base64url_encode_32(&expected);

    let mut cdj = vector::empty<u8>();
    vector::append(&mut cdj, b"{\"type\":\"webauthn.get\",\"challenge\":\"");
    vector::append(&mut cdj, encoded);
    vector::append(&mut cdj, b"\",\"origin\":\"https://recovery.example\",\"crossOrigin\":false}");

    let mut needle = vector::empty<u8>();
    vector::append(&mut needle, b"\"challenge\":\"");
    vector::append(&mut needle, encoded);
    vector::push_back(&mut needle, 34u8);

    assert!(assertion::contains_subvec(&cdj, &needle), 0);
}

#[test]
fun client_data_json_with_extra_fields_still_matches() {
    let expected = hash::sha2_256(b"recover-now");
    let encoded = assertion::base64url_encode_32(&expected);

    let mut cdj = vector::empty<u8>();
    // Different key order + extra fields some browsers append.
    vector::append(&mut cdj, b"{\"origin\":\"https://recovery.example\",\"type\":\"webauthn.get\",\"crossOrigin\":false,\"challenge\":\"");
    vector::append(&mut cdj, encoded);
    vector::append(&mut cdj, b"\",\"androidPackageName\":\"com.example\"}");

    let mut needle = vector::empty<u8>();
    vector::append(&mut needle, b"\"challenge\":\"");
    vector::append(&mut needle, encoded);
    vector::push_back(&mut needle, 34u8);

    assert!(assertion::contains_subvec(&cdj, &needle), 0);
}

#[test]
fun client_data_json_with_wrong_challenge_fails_lookup() {
    let expected = hash::sha2_256(b"intended");
    let actual = hash::sha2_256(b"forged"); // attacker-supplied
    let actual_encoded = assertion::base64url_encode_32(&actual);

    let mut cdj = vector::empty<u8>();
    vector::append(&mut cdj, b"{\"type\":\"webauthn.get\",\"challenge\":\"");
    vector::append(&mut cdj, actual_encoded);
    vector::append(&mut cdj, b"\"}");

    let mut expected_needle = vector::empty<u8>();
    vector::append(&mut expected_needle, b"\"challenge\":\"");
    vector::append(&mut expected_needle, assertion::base64url_encode_32(&expected));
    vector::push_back(&mut expected_needle, 34u8);

    assert!(!assertion::contains_subvec(&cdj, &expected_needle), 0);
}

// === WebAuthnAssertion accessors ===

#[test]
fun assertion_accessors_round_trip() {
    let pk = b"public-key-bytes";
    let ad = b"auth-data";
    let cdj = b"{\"challenge\":\"abc\"}";
    let sig = b"signature-bytes";
    let a = assertion::new(pk, ad, cdj, sig);
    assert!(assertion::public_key(&a) == &pk, 0);
    assert!(assertion::authenticator_data(&a) == &ad, 1);
    assert!(assertion::client_data_json(&a) == &cdj, 2);
    assert!(assertion::signature(&a) == &sig, 3);
}
