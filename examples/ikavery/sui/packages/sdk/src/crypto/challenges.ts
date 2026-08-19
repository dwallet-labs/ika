import { u64ToLeBytes } from '@fesal-packages/ikavery-core';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, hexToBytes } from '@noble/hashes/utils.js';

import {
	TAG_APPROVE,
	TAG_ENROLL_APPROVE,
	TAG_ENROLL_PROPOSE,
	TAG_EXECUTE,
	TAG_PROPOSE,
	TAG_ROSTER_CHANGE_APPROVE,
	TAG_ROSTER_CHANGE_PROPOSE,
} from '../constants';

const encoder = new TextEncoder();

function recoveryIdBytes(recoveryId: string): Uint8Array {
	return hexToBytes(recoveryId.startsWith('0x') ? recoveryId.slice(2) : recoveryId);
}

/** `sha256("recovery::propose" || recovery_id || intent_hash || nonce_le)`. */
export function buildProposeChallenge(
	recoveryId: string,
	intentHash: Uint8Array,
	nonce: bigint,
): Uint8Array {
	return sha256(
		concatBytes(
			encoder.encode(TAG_PROPOSE),
			recoveryIdBytes(recoveryId),
			intentHash,
			u64ToLeBytes(nonce),
		),
	);
}

/** `sha256("recovery::approve" || recovery_id || proposal_id_le)`. */
export function buildApproveChallenge(recoveryId: string, proposalId: bigint): Uint8Array {
	return sha256(
		concatBytes(encoder.encode(TAG_APPROVE), recoveryIdBytes(recoveryId), u64ToLeBytes(proposalId)),
	);
}

/** `sha256("recovery::execute" || recovery_id || proposal_id_le)`. */
export function buildExecuteChallenge(recoveryId: string, proposalId: bigint): Uint8Array {
	return sha256(
		concatBytes(encoder.encode(TAG_EXECUTE), recoveryIdBytes(recoveryId), u64ToLeBytes(proposalId)),
	);
}

/** `sha256("recovery::enroll_propose" || recovery_id || new_pubkey || nonce_le)`. */
export function buildEnrollProposeChallenge(
	recoveryId: string,
	newPubkey: Uint8Array,
	nonce: bigint,
): Uint8Array {
	return sha256(
		concatBytes(
			encoder.encode(TAG_ENROLL_PROPOSE),
			recoveryIdBytes(recoveryId),
			newPubkey,
			u64ToLeBytes(nonce),
		),
	);
}

/** `sha256("recovery::enroll_approve" || recovery_id || enrollment_id_le)`. */
export function buildEnrollApproveChallenge(recoveryId: string, enrollmentId: bigint): Uint8Array {
	return sha256(
		concatBytes(
			encoder.encode(TAG_ENROLL_APPROVE),
			recoveryIdBytes(recoveryId),
			u64ToLeBytes(enrollmentId),
		),
	);
}

/**
 * Hash a roster-change payload. Mirrors `challenges::roster_change_payload`:
 *   `sha256(num_removals_le || (len_le || id)* || new_threshold_le_or_zero || has_new_threshold_byte)`
 *
 * Each `members_to_remove[i]` MUST be the canonical id bytes
 * (`[scheme, ...pubkey/addr]`) — same shape as `Recovery.members`.
 */
export function buildRosterChangePayloadHash(
	membersToRemove: Uint8Array[],
	newThreshold: bigint | null,
): Uint8Array {
	const parts: Uint8Array[] = [];
	parts.push(u64ToLeBytes(BigInt(membersToRemove.length)));
	for (const id of membersToRemove) {
		parts.push(u64ToLeBytes(BigInt(id.length)));
		parts.push(id);
	}
	parts.push(u64ToLeBytes(newThreshold ?? 0n));
	parts.push(new Uint8Array([newThreshold === null ? 0 : 1]));
	return sha256(concatBytes(...parts));
}

/** `sha256("recovery::roster_change_propose" || recovery_id || payload_hash || nonce_le)`. */
export function buildRosterChangeProposeChallenge(
	recoveryId: string,
	membersToRemove: Uint8Array[],
	newThreshold: bigint | null,
	nonce: bigint,
): Uint8Array {
	const payloadHash = buildRosterChangePayloadHash(membersToRemove, newThreshold);
	return sha256(
		concatBytes(
			encoder.encode(TAG_ROSTER_CHANGE_PROPOSE),
			recoveryIdBytes(recoveryId),
			payloadHash,
			u64ToLeBytes(nonce),
		),
	);
}

/** `sha256("recovery::roster_change_approve" || recovery_id || roster_change_id_le)`. */
export function buildRosterChangeApproveChallenge(
	recoveryId: string,
	rosterChangeId: bigint,
): Uint8Array {
	return sha256(
		concatBytes(
			encoder.encode(TAG_ROSTER_CHANGE_APPROVE),
			recoveryIdBytes(recoveryId),
			u64ToLeBytes(rosterChangeId),
		),
	);
}
