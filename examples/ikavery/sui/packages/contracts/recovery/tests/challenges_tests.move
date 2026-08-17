#[test_only]
module recovery::challenges_tests;

use recovery::challenges;

// === u64_to_le_bytes ===

#[test]
fun u64_le_zero() {
    assert!(challenges::u64_to_le_bytes(0) == vector[0u8, 0, 0, 0, 0, 0, 0, 0], 0);
}

#[test]
fun u64_le_one() {
    assert!(challenges::u64_to_le_bytes(1) == vector[1u8, 0, 0, 0, 0, 0, 0, 0], 0);
}

#[test]
fun u64_le_max() {
    assert!(
        challenges::u64_to_le_bytes(0xffffffffffffffff)
            == vector[0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        0,
    );
}

#[test]
fun u64_le_arbitrary() {
    assert!(
        challenges::u64_to_le_bytes(0x0807060504030201) == vector[1u8, 2, 3, 4, 5, 6, 7, 8],
        0,
    );
}

// === bundle_hash ===

#[test]
fun bundle_hash_is_32_bytes() {
    let msgs = vector[b"a"];
    assert!(challenges::bundle_hash(&msgs).length() == 32, 0);
}

#[test]
fun bundle_hash_is_deterministic() {
    let msgs = vector[b"tx0", b"tx1", b"tx2"];
    assert!(challenges::bundle_hash(&msgs) == challenges::bundle_hash(&msgs), 0);
}

#[test]
fun bundle_hash_changes_with_order() {
    let a = vector[b"tx0", b"tx1"];
    let b = vector[b"tx1", b"tx0"];
    assert!(challenges::bundle_hash(&a) != challenges::bundle_hash(&b), 0);
}

#[test]
fun bundle_hash_changes_with_count() {
    let one = vector[b"tx0"];
    let two = vector[b"tx0", b"tx0"];
    assert!(challenges::bundle_hash(&one) != challenges::bundle_hash(&two), 0);
}

#[test]
fun bundle_hash_changes_with_content() {
    let a = vector[b"tx0"];
    let b = vector[b"tx1"];
    assert!(challenges::bundle_hash(&a) != challenges::bundle_hash(&b), 0);
}

#[test]
fun bundle_hash_empty_is_well_defined() {
    let msgs: vector<vector<u8>> = vector::empty();
    assert!(challenges::bundle_hash(&msgs).length() == 32, 0);
}

// === domain separation: same recovery+counter, different ops -> different challenges ===

#[test]
fun propose_and_approve_disagree() {
    let id = b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
    let bundle = challenges::bundle_hash(&vector[b"x"]);
    assert!(challenges::propose(id, bundle, 0) != challenges::approve(id, 0), 0);
}

#[test]
fun enroll_propose_and_approve_disagree() {
    let id = b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
    let pk = b"some-pubkey";
    assert!(
        challenges::enroll_propose(id, pk, 0) != challenges::enroll_approve(id, 0),
        0,
    );
}

#[test]
fun propose_and_enroll_propose_disagree() {
    let id = b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
    let bundle_or_pk = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    assert!(
        challenges::propose(id, bundle_or_pk, 7) != challenges::enroll_propose(id, bundle_or_pk, 7),
        0,
    );
}

// === counter / nonce sensitivity ===

#[test]
fun propose_changes_with_nonce() {
    let id = b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
    let bundle = challenges::bundle_hash(&vector[b"x"]);
    assert!(challenges::propose(id, bundle, 0) != challenges::propose(id, bundle, 1), 0);
}

#[test]
fun approve_changes_with_proposal_id() {
    let id = b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
    assert!(challenges::approve(id, 0) != challenges::approve(id, 1), 0);
}

#[test]
fun approve_changes_with_recovery_id() {
    let a = b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
    let b = b"\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb";
    assert!(challenges::approve(a, 0) != challenges::approve(b, 0), 0);
}

#[test]
fun all_challenges_are_32_bytes() {
    let id = b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
    let bundle = challenges::bundle_hash(&vector[b"x"]);
    let pk = b"pk";
    let removals = vector[b"\x00pk1", b"\x01pk2"];
    let payload = challenges::roster_change_payload(&removals, 2, true);
    assert!(challenges::propose(id, bundle, 0).length() == 32, 0);
    assert!(challenges::approve(id, 0).length() == 32, 1);
    assert!(challenges::enroll_propose(id, pk, 0).length() == 32, 2);
    assert!(challenges::enroll_approve(id, 0).length() == 32, 3);
    assert!(challenges::roster_change_propose(id, payload, 0).length() == 32, 4);
    assert!(challenges::roster_change_approve(id, 0).length() == 32, 5);
    assert!(payload.length() == 32, 6);
}

// === roster_change challenges ===

#[test]
fun roster_change_propose_and_approve_disagree() {
    let id = b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
    let removals = vector[b"\x00pk"];
    let payload = challenges::roster_change_payload(&removals, 1, true);
    assert!(
        challenges::roster_change_propose(id, payload, 0)
            != challenges::roster_change_approve(id, 0),
        0,
    );
}

#[test]
fun roster_change_payload_changes_with_threshold_present() {
    let removals = vector[b"\x00pk"];
    let with_thr = challenges::roster_change_payload(&removals, 2, true);
    let no_thr = challenges::roster_change_payload(&removals, 2, false);
    assert!(with_thr != no_thr, 0);
}

#[test]
fun roster_change_payload_changes_with_threshold_value() {
    let removals = vector[b"\x00pk"];
    let a = challenges::roster_change_payload(&removals, 2, true);
    let b = challenges::roster_change_payload(&removals, 3, true);
    assert!(a != b, 0);
}

#[test]
fun roster_change_payload_changes_with_removal_set() {
    let a = challenges::roster_change_payload(&vector[b"\x00pkA"], 1, true);
    let b = challenges::roster_change_payload(&vector[b"\x00pkB"], 1, true);
    assert!(a != b, 0);
}

#[test]
fun roster_change_payload_changes_with_removal_count() {
    let one = challenges::roster_change_payload(&vector[b"\x00pkA"], 1, true);
    let two = challenges::roster_change_payload(&vector[b"\x00pkA", b"\x00pkB"], 1, true);
    assert!(one != two, 0);
}

#[test]
fun roster_change_propose_changes_with_nonce() {
    let id = b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
    let payload = challenges::roster_change_payload(&vector[b"\x00pk"], 1, true);
    assert!(
        challenges::roster_change_propose(id, payload, 0)
            != challenges::roster_change_propose(id, payload, 1),
        0,
    );
}

#[test]
fun roster_change_separate_from_other_propose_tags() {
    let id = b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
    // Use the same payload bytes; tag separation must still distinguish.
    let payload = challenges::bundle_hash(&vector[b"x"]);
    assert!(challenges::roster_change_propose(id, payload, 0) != challenges::propose(id, payload, 0), 0);
    assert!(challenges::roster_change_propose(id, payload, 0) != challenges::enroll_propose(id, payload, 0), 1);
}
