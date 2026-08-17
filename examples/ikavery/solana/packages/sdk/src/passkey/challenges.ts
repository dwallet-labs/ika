/**
 * Operation-bound challenge construction — TS port of
 * `solana/packages/program/src/auth/challenges.rs`. Every recovery
 * instruction that requires member authorisation gates on a credential
 * signing one of these well-known SHA-256 digests. Wire format matches
 * the program byte-for-byte.
 */

import { sha256 } from '@noble/hashes/sha256';

const TAG_PROPOSE = utf8('recovery::propose');
const TAG_APPROVE = utf8('recovery::approve');
const TAG_EXECUTE = utf8('recovery::execute');
const TAG_ENROLL_PROPOSE = utf8('recovery::enroll_propose');
const TAG_ENROLL_APPROVE = utf8('recovery::enroll_approve');
const TAG_ROSTER_CHANGE_PROPOSE = utf8('recovery::roster_change_propose');
const TAG_ROSTER_CHANGE_APPROVE = utf8('recovery::roster_change_approve');

export const MAX_BUNDLE_MESSAGES = 32;

function utf8(s: string): Uint8Array {
	return new TextEncoder().encode(s);
}

function u64leBytes(n: number | bigint): Uint8Array {
	const out = new Uint8Array(8);
	const dv = new DataView(out.buffer);
	dv.setBigUint64(0, BigInt(n), true);
	return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
	let total = 0;
	for (const p of parts) total += p.length;
	const out = new Uint8Array(total);
	let off = 0;
	for (const p of parts) {
		out.set(p, off);
		off += p.length;
	}
	return out;
}

/** `sha256(n_le || sha256(msg_0) || ... || sha256(msg_{n-1}))`. */
export function bundleHash(messages: Uint8Array[]): Uint8Array {
	if (messages.length > MAX_BUNDLE_MESSAGES) {
		throw new Error(`bundleHash: ${messages.length} messages exceeds cap ${MAX_BUNDLE_MESSAGES}`);
	}
	const parts: Uint8Array[] = [u64leBytes(messages.length)];
	for (const m of messages) parts.push(sha256(m));
	return sha256(concat(parts));
}

/**
 * Variant of [`bundleHash`] that takes pre-computed per-tx digests. Mirrors
 * the on-chain `auth::challenges::bundle_hash_from_digests` so propose
 * callers can hash the bundle without the raw message bytes.
 *
 * `sha256(n_le || digest_0 || ... || digest_{n-1})` — equal to `bundleHash`
 * when each `digest_i = sha256(msg_i)`.
 */
export function bundleHashFromDigests(digests: Uint8Array[]): Uint8Array {
	if (digests.length > MAX_BUNDLE_MESSAGES) {
		throw new Error(`bundleHashFromDigests: ${digests.length} > cap ${MAX_BUNDLE_MESSAGES}`);
	}
	for (let i = 0; i < digests.length; i++) {
		const d = digests[i] as Uint8Array;
		if (d.length !== 32) {
			throw new Error(`bundleHashFromDigests: digests[${i}] must be 32 bytes, got ${d.length}`);
		}
	}
	const parts: Uint8Array[] = [u64leBytes(digests.length), ...digests];
	return sha256(concat(parts));
}

/** `sha256("recovery::propose" || recovery_id || bundle_hash || nonce_le)`. */
export function proposeChallenge(
	recoveryIdBytes: Uint8Array,
	bundleHashBytes: Uint8Array,
	nonce: number | bigint,
): Uint8Array {
	return sha256(concat([TAG_PROPOSE, recoveryIdBytes, bundleHashBytes, u64leBytes(nonce)]));
}

/** `sha256("recovery::approve" || recovery_id || proposal_id_le)`. */
export function approveChallenge(
	recoveryIdBytes: Uint8Array,
	proposalId: number | bigint,
): Uint8Array {
	return sha256(concat([TAG_APPROVE, recoveryIdBytes, u64leBytes(proposalId)]));
}

/** `sha256("recovery::execute" || recovery_id || proposal_id_le)`. */
export function executeChallenge(
	recoveryIdBytes: Uint8Array,
	proposalId: number | bigint,
): Uint8Array {
	return sha256(concat([TAG_EXECUTE, recoveryIdBytes, u64leBytes(proposalId)]));
}

/** `sha256("recovery::enroll_propose" || recovery_id || new_pubkey || nonce_le)`. */
export function enrollProposeChallenge(
	recoveryIdBytes: Uint8Array,
	newPubkey: Uint8Array,
	nonce: number | bigint,
): Uint8Array {
	return sha256(concat([TAG_ENROLL_PROPOSE, recoveryIdBytes, newPubkey, u64leBytes(nonce)]));
}

/** `sha256("recovery::enroll_approve" || recovery_id || enrollment_id_le)`. */
export function enrollApproveChallenge(
	recoveryIdBytes: Uint8Array,
	enrollmentId: number | bigint,
): Uint8Array {
	return sha256(concat([TAG_ENROLL_APPROVE, recoveryIdBytes, u64leBytes(enrollmentId)]));
}

/** `sha256("recovery::roster_change_propose" || recovery_id || payload_hash || nonce_le)`. */
export function rosterChangeProposeChallenge(
	recoveryIdBytes: Uint8Array,
	payloadHashBytes: Uint8Array,
	nonce: number | bigint,
): Uint8Array {
	return sha256(
		concat([TAG_ROSTER_CHANGE_PROPOSE, recoveryIdBytes, payloadHashBytes, u64leBytes(nonce)]),
	);
}

/** `sha256("recovery::roster_change_approve" || recovery_id || roster_change_id_le)`. */
export function rosterChangeApproveChallenge(
	recoveryIdBytes: Uint8Array,
	rosterChangeId: number | bigint,
): Uint8Array {
	return sha256(concat([TAG_ROSTER_CHANGE_APPROVE, recoveryIdBytes, u64leBytes(rosterChangeId)]));
}

/**
 * Hash a roster-change payload to fit in the fixed-size challenge:
 *   `sha256(num_removals_le || len(r0)_le || r0 || ... || new_threshold_le_or_zero || has_new_threshold_byte)`
 * where each `removals[i]` is the canonical member-id bytes (`[scheme, ...pubkey/addr]`).
 */
export function rosterChangePayloadHash(
	membersToRemove: Uint8Array[],
	newThreshold: number | bigint,
	hasNewThreshold: boolean,
): Uint8Array {
	const parts: Uint8Array[] = [u64leBytes(membersToRemove.length)];
	for (const m of membersToRemove) {
		parts.push(u64leBytes(m.length));
		parts.push(m);
	}
	parts.push(u64leBytes(newThreshold));
	parts.push(new Uint8Array([hasNewThreshold ? 1 : 0]));
	return sha256(concat(parts));
}
