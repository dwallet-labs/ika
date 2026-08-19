/// Tests for `recovery::auth` — covers the SenderAddress path of `verify`
/// and the `NewMember` helpers (id bytes, dedup check, dispatch insert).
///
/// The WebAuthn path of `verify` is exercised by `assertion_verify_tests`
/// (same WebAuthn fixture).
#[test_only]
module recovery::auth_tests;

use recovery::auth;
use sui::address;
use sui::test_scenario;
use sui::vec_set;

const ALICE: address = @0xA11CE;
const BOB: address = @0xB0B;

const PK_A: vector<u8> = vector[
    0x02, 0x51, 0x5c, 0x3d, 0x6e, 0xb9, 0xe3, 0x96, 0xb9, 0x04, 0xd3, 0xfe,
    0xca, 0x7f, 0x54, 0xfd, 0xcd, 0x0c, 0xc1, 0xe9, 0x97, 0xbf, 0x37, 0x5d,
    0xca, 0x51, 0x5a, 0xd0, 0xa6, 0xc3, 0xb4, 0x03, 0x5f,
];

/// 32-byte challenge used by tests that exercise `auth::verify` on the
/// SenderAddress credential. The sender path doesn't actually consume the
/// bytes (the Sui tx signature already binds the PTB), but `auth::verify`
/// still asserts `length == 32` so we feed a real 32-byte vector.
const ZERO_CHALLENGE: vector<u8> = vector[
    0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// scheme bytes (mirrored from auth.move's private constants).
const SCHEME_WEBAUTHN: u8 = 3;
const SCHEME_SENDER_ADDRESS: u8 = 4;

fun prefixed(scheme: u8, rest: vector<u8>): vector<u8> {
    let mut id = vector::empty<u8>();
    id.push_back(scheme);
    id.append(rest);
    id
}

// ===== NewMember helpers =====

#[test]
fun new_webauthn_member_id_prefixes_scheme_byte() {
    let m = auth::new_webauthn_member(PK_A);
    assert!(auth::new_member_id_bytes(&m) == prefixed(SCHEME_WEBAUTHN, PK_A), 0);
}

#[test]
fun new_sender_member_id_prefixes_scheme_byte() {
    let m = auth::new_sender_member(ALICE);
    let expected = prefixed(SCHEME_SENDER_ADDRESS, address::to_bytes(ALICE));
    assert!(auth::new_member_id_bytes(&m) == expected, 0);
}

#[test]
fun webauthn_and_sender_ids_cannot_collide() {
    // Different scheme bytes ⇒ ids never collide even before considering
    // the body length difference.
    let pk = auth::new_webauthn_member(PK_A);
    let s = auth::new_sender_member(ALICE);
    let pk_id = auth::new_member_id_bytes(&pk);
    let s_id = auth::new_member_id_bytes(&s);
    assert!(*pk_id.borrow(0) == SCHEME_WEBAUTHN, 0);
    assert!(*s_id.borrow(0) == SCHEME_SENDER_ADDRESS, 1);
    assert!(pk_id != s_id, 2);
}

#[test]
fun is_already_member_webauthn_branch() {
    let mut members = vec_set::empty<vector<u8>>();
    members.insert(prefixed(SCHEME_WEBAUTHN, PK_A));

    let m_in = auth::new_webauthn_member(PK_A);
    let m_out = auth::new_sender_member(ALICE);
    assert!(auth::is_already_member(&m_in, &members), 0);
    assert!(!auth::is_already_member(&m_out, &members), 1);
}

#[test]
fun is_already_member_sender_branch() {
    let mut members = vec_set::empty<vector<u8>>();
    members.insert(prefixed(SCHEME_SENDER_ADDRESS, address::to_bytes(ALICE)));

    let m_in = auth::new_sender_member(ALICE);
    let m_out = auth::new_sender_member(BOB);
    assert!(auth::is_already_member(&m_in, &members), 0);
    assert!(!auth::is_already_member(&m_out, &members), 1);
}

#[test]
fun insert_member_writes_into_unified_set() {
    let mut members = vec_set::empty<vector<u8>>();

    auth::insert_member(auth::new_webauthn_member(PK_A), &mut members);
    auth::insert_member(auth::new_sender_member(ALICE), &mut members);

    assert!(members.length() == 2, 0);
    assert!(members.contains(&prefixed(SCHEME_WEBAUTHN, PK_A)), 1);
    assert!(
        members.contains(&prefixed(SCHEME_SENDER_ADDRESS, address::to_bytes(ALICE))),
        2,
    );
}

#[test]
fun is_approver_only_member_only_true_for_sender() {
    let pk = auth::new_webauthn_member(PK_A);
    let s = auth::new_sender_member(ALICE);
    assert!(!auth::is_approver_only_member(&pk), 0);
    assert!(auth::is_approver_only_member(&s), 1);
}

// ===== Credential::SenderAddress verify =====

#[test]
fun sender_credential_verify_returns_canonical_id() {
    let mut scenario = test_scenario::begin(ALICE);
    let mut members = vec_set::empty<vector<u8>>();
    let alice_id = prefixed(SCHEME_SENDER_ADDRESS, address::to_bytes(ALICE));
    members.insert(alice_id);

    let challenge = ZERO_CHALLENGE;
    let voter = auth::verify(
        auth::sender_credential(scenario.ctx()),
        &members,
        &challenge,
        scenario.ctx(),
    );
    assert!(voter == prefixed(SCHEME_SENDER_ADDRESS, address::to_bytes(ALICE)), 0);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = auth::EUnknownMember)]
fun sender_credential_rejects_non_member() {
    let mut scenario = test_scenario::begin(ALICE);
    let mut members = vec_set::empty<vector<u8>>();
    // ALICE is the sender, but only BOB is in the members set.
    members.insert(prefixed(SCHEME_SENDER_ADDRESS, address::to_bytes(BOB)));

    let challenge = ZERO_CHALLENGE;
    let _ = auth::verify(
        auth::sender_credential(scenario.ctx()),
        &members,
        &challenge,
        scenario.ctx(),
    );
    scenario.end();
}

#[test]
#[expected_failure(abort_code = auth::EBadChallengeLength)]
fun verify_rejects_short_challenge_on_sender_path() {
    let mut scenario = test_scenario::begin(ALICE);
    let mut members = vec_set::empty<vector<u8>>();
    members.insert(prefixed(SCHEME_SENDER_ADDRESS, address::to_bytes(ALICE)));

    // Challenge-length check fires before the sender-address arm runs.
    let too_short = vector[0u8, 1, 2, 3, 4, 5, 6, 7];
    let _ = auth::verify(
        auth::sender_credential(scenario.ctx()),
        &members,
        &too_short,
        scenario.ctx(),
    );
    scenario.end();
}
