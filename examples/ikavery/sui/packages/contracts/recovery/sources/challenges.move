/// Operation-bound challenge construction for the recovery module.
///
/// Every passkey-gated entry point requires a WebAuthn assertion whose
/// challenge equals one of these well-known SHA-256 digests, computed over a
/// domain tag, the recovery shared object id, and operation-specific payload.
/// Domain tags separate operations so an assertion for `propose` can never be
/// replayed against `approve`. Nonces (for propose / enroll_propose) prevent
/// replays of stale assertions for the same op.
#[allow(implicit_const_copy)]
module recovery::challenges;

use std::hash;

const TAG_PROPOSE: vector<u8> = b"recovery::propose";
const TAG_APPROVE: vector<u8> = b"recovery::approve";
const TAG_EXECUTE: vector<u8> = b"recovery::execute";
const TAG_ENROLL_PROPOSE: vector<u8> = b"recovery::enroll_propose";
const TAG_ENROLL_APPROVE: vector<u8> = b"recovery::enroll_approve";
const TAG_ROSTER_CHANGE_PROPOSE: vector<u8> = b"recovery::roster_change_propose";
const TAG_ROSTER_CHANGE_APPROVE: vector<u8> = b"recovery::roster_change_approve";

/// Encode a u64 as little-endian 8 bytes.
public(package) fun u64_to_le_bytes(v: u64): vector<u8> {
    let mut bytes = vector::empty<u8>();
    let mut i: u64 = 0;
    while (i < 8) {
        let shift = ((i as u8)) * 8;
        bytes.push_back(((v >> shift) & 0xff) as u8);
        i = i + 1;
    };
    bytes
}

/// `sha256(n_le || sha256(msg_0) || ... || sha256(msg_{n-1}))`.
public(package) fun bundle_hash(messages: &vector<vector<u8>>): vector<u8> {
    let mut buf = vector::empty<u8>();
    let n = messages.length();
    vector::append(&mut buf, u64_to_le_bytes(n));
    let mut i = 0;
    while (i < n) {
        let h = hash::sha2_256(*messages.borrow(i));
        vector::append(&mut buf, h);
        i = i + 1;
    };
    hash::sha2_256(buf)
}

/// `sha256("recovery::propose" || recovery_id || bundle_hash || nonce_le)`.
public(package) fun propose(
    recovery_id_bytes: vector<u8>,
    bundle_hash_bytes: vector<u8>,
    nonce: u64,
): vector<u8> {
    domain_3(&TAG_PROPOSE, recovery_id_bytes, bundle_hash_bytes, nonce)
}

/// `sha256("recovery::approve" || recovery_id || proposal_id_le)`.
public(package) fun approve(recovery_id_bytes: vector<u8>, proposal_id: u64): vector<u8> {
    domain_2_u64(&TAG_APPROVE, recovery_id_bytes, proposal_id)
}

/// `sha256("recovery::execute" || recovery_id || proposal_id_le)`.
public(package) fun execute(recovery_id_bytes: vector<u8>, proposal_id: u64): vector<u8> {
    domain_2_u64(&TAG_EXECUTE, recovery_id_bytes, proposal_id)
}

/// `sha256("recovery::enroll_propose" || recovery_id || new_pubkey || nonce_le)`.
public(package) fun enroll_propose(
    recovery_id_bytes: vector<u8>,
    new_pubkey: vector<u8>,
    nonce: u64,
): vector<u8> {
    domain_3(&TAG_ENROLL_PROPOSE, recovery_id_bytes, new_pubkey, nonce)
}

/// `sha256("recovery::enroll_approve" || recovery_id || enrollment_id_le)`.
public(package) fun enroll_approve(recovery_id_bytes: vector<u8>, enrollment_id: u64): vector<u8> {
    domain_2_u64(&TAG_ENROLL_APPROVE, recovery_id_bytes, enrollment_id)
}

/// Hash a roster-change payload so it fits into the fixed-size challenge:
///   `sha256(num_removals_le || removals[0] || ... || new_threshold_le_or_zero || has_new_threshold_byte)`
/// `removals[i]` is the canonical member-id bytes (`[scheme, ...pubkey/addr]`)
/// concatenated with its length prefix so different splits can't alias.
public(package) fun roster_change_payload(
    members_to_remove: &vector<vector<u8>>,
    new_threshold: u64,
    has_new_threshold: bool,
): vector<u8> {
    let mut buf = vector::empty<u8>();
    let n = members_to_remove.length();
    vector::append(&mut buf, u64_to_le_bytes(n));
    let mut i = 0;
    while (i < n) {
        let id = members_to_remove.borrow(i);
        vector::append(&mut buf, u64_to_le_bytes(id.length()));
        vector::append(&mut buf, *id);
        i = i + 1;
    };
    vector::append(&mut buf, u64_to_le_bytes(new_threshold));
    buf.push_back(if (has_new_threshold) 1u8 else 0u8);
    hash::sha2_256(buf)
}

/// `sha256("recovery::roster_change_propose" || recovery_id || payload_hash || nonce_le)`.
public(package) fun roster_change_propose(
    recovery_id_bytes: vector<u8>,
    payload_hash: vector<u8>,
    nonce: u64,
): vector<u8> {
    domain_3(&TAG_ROSTER_CHANGE_PROPOSE, recovery_id_bytes, payload_hash, nonce)
}

/// `sha256("recovery::roster_change_approve" || recovery_id || roster_change_id_le)`.
public(package) fun roster_change_approve(
    recovery_id_bytes: vector<u8>,
    roster_change_id: u64,
): vector<u8> {
    domain_2_u64(&TAG_ROSTER_CHANGE_APPROVE, recovery_id_bytes, roster_change_id)
}

fun domain_3(
    tag: &vector<u8>,
    recovery_id_bytes: vector<u8>,
    payload: vector<u8>,
    counter: u64,
): vector<u8> {
    let mut buf = vector::empty<u8>();
    vector::append(&mut buf, *tag);
    vector::append(&mut buf, recovery_id_bytes);
    vector::append(&mut buf, payload);
    vector::append(&mut buf, u64_to_le_bytes(counter));
    hash::sha2_256(buf)
}

fun domain_2_u64(
    tag: &vector<u8>,
    recovery_id_bytes: vector<u8>,
    counter: u64,
): vector<u8> {
    let mut buf = vector::empty<u8>();
    vector::append(&mut buf, *tag);
    vector::append(&mut buf, recovery_id_bytes);
    vector::append(&mut buf, u64_to_le_bytes(counter));
    hash::sha2_256(buf)
}
