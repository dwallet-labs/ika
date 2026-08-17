//! Operation-bound challenge construction.
//!
//! Every recovery instruction that requires member authorisation is gated
//! on a credential signing one of these well-known SHA-256 digests. The
//! domain tag distinguishes operations so an assertion for `propose` can
//! never be replayed against `approve`. Counters / nonces prevent replays
//! of stale assertions for the same op.
//!
//! Wire format matches `recovery::challenges` on Sui byte-for-byte so a
//! future cross-chain registry can index assertions produced on either
//! chain under the same id.

use solana_sha256_hasher::hashv;

pub const TAG_PROPOSE: &[u8] = b"recovery::propose";
pub const TAG_APPROVE: &[u8] = b"recovery::approve";
pub const TAG_EXECUTE: &[u8] = b"recovery::execute";
pub const TAG_ENROLL_PROPOSE: &[u8] = b"recovery::enroll_propose";
pub const TAG_ENROLL_APPROVE: &[u8] = b"recovery::enroll_approve";
pub const TAG_ROSTER_CHANGE_PROPOSE: &[u8] = b"recovery::roster_change_propose";
pub const TAG_ROSTER_CHANGE_APPROVE: &[u8] = b"recovery::roster_change_approve";

/// Maximum messages in a single sweep bundle. Sized to fit on the BPF
/// stack (each entry holds a 32-byte hash).
pub const MAX_BUNDLE_MESSAGES: usize = 32;

/// Maximum members removed in a single roster change.
pub const MAX_ROSTER_REMOVALS: usize = crate::state::MAX_MEMBERS;

/// `sha256(n_le || sha256(msg_0) || ... || sha256(msg_{n-1}))`.
///
/// Returns `IntentBufferOverflow`-equivalent error indirectly: the caller
/// must keep the bundle within `MAX_BUNDLE_MESSAGES`.
pub fn bundle_hash(messages: &[&[u8]]) -> Option<[u8; 32]> {
    if messages.len() > MAX_BUNDLE_MESSAGES {
        return None;
    }
    let n = (messages.len() as u64).to_le_bytes();
    let mut hashes = [[0u8; 32]; MAX_BUNDLE_MESSAGES];
    for (i, m) in messages.iter().enumerate() {
        hashes[i] = hashv(&[m]).to_bytes();
    }
    let mut slices: [&[u8]; 1 + MAX_BUNDLE_MESSAGES] = [&[]; 1 + MAX_BUNDLE_MESSAGES];
    slices[0] = &n;
    for i in 0..messages.len() {
        slices[1 + i] = &hashes[i];
    }
    Some(hashv(&slices[..1 + messages.len()]).to_bytes())
}

/// Variant of [`bundle_hash`] that takes pre-computed per-tx digests instead
/// of the raw messages. Used by `propose` so the on-chain handler can verify
/// the credential's signed challenge without re-hashing N message-byte
/// payloads (which collectively wouldn't fit in a Solana tx packet anyway).
///
/// `sha256(n_le || digest_0 || ... || digest_{n-1})` — structurally identical
/// to `bundle_hash` when each `digest_i = sha256(msg_i)`, so a credential
/// signing one form proves it signed the other.
pub fn bundle_hash_from_digests(digests: &[[u8; 32]]) -> Option<[u8; 32]> {
    if digests.len() > MAX_BUNDLE_MESSAGES {
        return None;
    }
    let n = (digests.len() as u64).to_le_bytes();
    let mut slices: [&[u8]; 1 + MAX_BUNDLE_MESSAGES] = [&[]; 1 + MAX_BUNDLE_MESSAGES];
    slices[0] = &n;
    for (i, d) in digests.iter().enumerate() {
        slices[1 + i] = d;
    }
    Some(hashv(&slices[..1 + digests.len()]).to_bytes())
}

/// `sha256("recovery::propose" || recovery_id || bundle_hash || nonce_le)`.
pub fn propose(recovery_id_bytes: &[u8], bundle_hash_bytes: &[u8], nonce: u64) -> [u8; 32] {
    domain_3(TAG_PROPOSE, recovery_id_bytes, bundle_hash_bytes, nonce)
}

/// `sha256("recovery::approve" || recovery_id || proposal_id_le)`.
pub fn approve(recovery_id_bytes: &[u8], proposal_id: u64) -> [u8; 32] {
    domain_2_u64(TAG_APPROVE, recovery_id_bytes, proposal_id)
}

/// `sha256("recovery::execute" || recovery_id || proposal_id_le)`.
pub fn execute(recovery_id_bytes: &[u8], proposal_id: u64) -> [u8; 32] {
    domain_2_u64(TAG_EXECUTE, recovery_id_bytes, proposal_id)
}

/// `sha256("recovery::enroll_propose" || recovery_id || new_pubkey || nonce_le)`.
pub fn enroll_propose(recovery_id_bytes: &[u8], new_pubkey: &[u8], nonce: u64) -> [u8; 32] {
    domain_3(TAG_ENROLL_PROPOSE, recovery_id_bytes, new_pubkey, nonce)
}

/// `sha256("recovery::enroll_approve" || recovery_id || enrollment_id_le)`.
pub fn enroll_approve(recovery_id_bytes: &[u8], enrollment_id: u64) -> [u8; 32] {
    domain_2_u64(TAG_ENROLL_APPROVE, recovery_id_bytes, enrollment_id)
}

/// `sha256("recovery::roster_change_propose" || recovery_id || payload_hash || nonce_le)`.
pub fn roster_change_propose(
    recovery_id_bytes: &[u8],
    payload_hash_bytes: &[u8],
    nonce: u64,
) -> [u8; 32] {
    domain_3(
        TAG_ROSTER_CHANGE_PROPOSE,
        recovery_id_bytes,
        payload_hash_bytes,
        nonce,
    )
}

/// `sha256("recovery::roster_change_approve" || recovery_id || roster_change_id_le)`.
pub fn roster_change_approve(recovery_id_bytes: &[u8], roster_change_id: u64) -> [u8; 32] {
    domain_2_u64(
        TAG_ROSTER_CHANGE_APPROVE,
        recovery_id_bytes,
        roster_change_id,
    )
}

/// Hash a roster-change payload so it fits into the fixed-size challenge:
///   `sha256(num_removals_le || removals[0] || ... || new_threshold_le_or_zero || has_new_threshold_byte)`
/// `removals[i]` is the canonical member-id bytes (`[scheme, ...pubkey/addr]`)
/// concatenated with its length prefix so different splits can't alias.
pub fn roster_change_payload(
    members_to_remove: &[&[u8]],
    new_threshold: u64,
    has_new_threshold: bool,
) -> Option<[u8; 32]> {
    if members_to_remove.len() > MAX_ROSTER_REMOVALS {
        return None;
    }
    let n_le = (members_to_remove.len() as u64).to_le_bytes();
    let new_threshold_le = new_threshold.to_le_bytes();
    let has_byte = [if has_new_threshold { 1u8 } else { 0u8 }];

    let mut len_prefixes: [[u8; 8]; MAX_ROSTER_REMOVALS] = [[0u8; 8]; MAX_ROSTER_REMOVALS];
    for (i, m) in members_to_remove.iter().enumerate() {
        len_prefixes[i] = (m.len() as u64).to_le_bytes();
    }

    let mut slices: [&[u8]; 3 + 2 * MAX_ROSTER_REMOVALS] = [&[]; 3 + 2 * MAX_ROSTER_REMOVALS];
    let mut idx = 0;
    slices[idx] = &n_le;
    idx += 1;
    for (i, m) in members_to_remove.iter().enumerate() {
        slices[idx] = &len_prefixes[i];
        idx += 1;
        slices[idx] = m;
        idx += 1;
    }
    slices[idx] = &new_threshold_le;
    idx += 1;
    slices[idx] = &has_byte;
    idx += 1;
    Some(hashv(&slices[..idx]).to_bytes())
}

fn domain_3(tag: &[u8], recovery_id_bytes: &[u8], payload: &[u8], counter: u64) -> [u8; 32] {
    let counter_le = counter.to_le_bytes();
    hashv(&[tag, recovery_id_bytes, payload, &counter_le]).to_bytes()
}

fn domain_2_u64(tag: &[u8], recovery_id_bytes: &[u8], counter: u64) -> [u8; 32] {
    let counter_le = counter.to_le_bytes();
    hashv(&[tag, recovery_id_bytes, &counter_le]).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        hashv(&[bytes]).to_bytes()
    }

    #[test]
    fn approve_reproduces_explicit_concat_hash() {
        let recovery_id = [0xa1u8; 32];
        let proposal_id: u64 = 7;
        let mut concat = vec![];
        concat.extend_from_slice(TAG_APPROVE);
        concat.extend_from_slice(&recovery_id);
        concat.extend_from_slice(&proposal_id.to_le_bytes());
        assert_eq!(approve(&recovery_id, proposal_id), sha256(&concat));
    }

    #[test]
    fn execute_reproduces_explicit_concat_hash() {
        let recovery_id = [0x99u8; 32];
        let proposal_id: u64 = 42;
        let mut concat = vec![];
        concat.extend_from_slice(TAG_EXECUTE);
        concat.extend_from_slice(&recovery_id);
        concat.extend_from_slice(&proposal_id.to_le_bytes());
        assert_eq!(execute(&recovery_id, proposal_id), sha256(&concat));
    }

    #[test]
    fn propose_with_bundle_reproduces_explicit_concat() {
        let recovery_id = [0x11u8; 32];
        let msg = b"hello";
        let nonce: u64 = 3;
        let bundle = bundle_hash(&[msg]).unwrap();
        let mut concat = vec![];
        concat.extend_from_slice(TAG_PROPOSE);
        concat.extend_from_slice(&recovery_id);
        concat.extend_from_slice(&bundle);
        concat.extend_from_slice(&nonce.to_le_bytes());
        assert_eq!(propose(&recovery_id, &bundle, nonce), sha256(&concat));
    }

    #[test]
    fn bundle_hash_single_message_matches_explicit_form() {
        let msg = b"sweep-this-tx";
        let inner = sha256(msg);
        let mut concat = vec![];
        concat.extend_from_slice(&1u64.to_le_bytes());
        concat.extend_from_slice(&inner);
        assert_eq!(bundle_hash(&[msg]).unwrap(), sha256(&concat));
    }

    #[test]
    fn bundle_hash_zero_messages_well_defined() {
        let h = bundle_hash(&[]).unwrap();
        let mut concat = vec![];
        concat.extend_from_slice(&0u64.to_le_bytes());
        assert_eq!(h, sha256(&concat));
    }

    #[test]
    fn bundle_hash_rejects_oversize() {
        let msg: &[u8] = b"x";
        let big: std::vec::Vec<&[u8]> = std::iter::repeat_n(msg, MAX_BUNDLE_MESSAGES + 1).collect();
        assert!(bundle_hash(&big).is_none());
    }

    #[test]
    fn different_tags_cannot_collide() {
        let r = [0x55u8; 32];
        assert_ne!(approve(&r, 1), execute(&r, 1));
        assert_ne!(approve(&r, 1), roster_change_approve(&r, 1));
        assert_ne!(approve(&r, 1), enroll_approve(&r, 1));
    }

    #[test]
    fn different_counters_cannot_collide() {
        let r = [0x55u8; 32];
        assert_ne!(approve(&r, 1), approve(&r, 2));
    }

    #[test]
    fn roster_change_payload_one_removal_matches_explicit() {
        let id = b"\x04abcdef";
        let payload = roster_change_payload(&[id], 3, true).unwrap();
        let mut concat = vec![];
        concat.extend_from_slice(&1u64.to_le_bytes());
        concat.extend_from_slice(&(id.len() as u64).to_le_bytes());
        concat.extend_from_slice(id);
        concat.extend_from_slice(&3u64.to_le_bytes());
        concat.push(1);
        assert_eq!(payload, sha256(&concat));
    }

    #[test]
    fn roster_change_payload_no_threshold_change_uses_zero_byte() {
        let id = b"\x04xyz";
        let with_change = roster_change_payload(&[id], 0, true).unwrap();
        let no_change = roster_change_payload(&[id], 0, false).unwrap();
        assert_ne!(with_change, no_change);
    }

    #[test]
    fn roster_change_payload_zero_removals_well_defined() {
        let h = roster_change_payload(&[], 5, true).unwrap();
        let mut concat = vec![];
        concat.extend_from_slice(&0u64.to_le_bytes());
        concat.extend_from_slice(&5u64.to_le_bytes());
        concat.push(1);
        assert_eq!(h, sha256(&concat));
    }

    #[test]
    fn roster_change_payload_rejects_oversize() {
        let id: &[u8] = b"\x04abc";
        let big: std::vec::Vec<&[u8]> = std::iter::repeat_n(id, MAX_ROSTER_REMOVALS + 1).collect();
        assert!(roster_change_payload(&big, 0, false).is_none());
    }
}
