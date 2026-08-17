import type { RecoveryClient } from '../client';
import * as moveRecovery from '../generated/recovery/recovery';

/**
 * Subset of the `Recovery` shared object we need off-chain to drive flows
 * (challenge nonces, current proposal/enrollment counters, member checks).
 * All fields are `bigint` to match the codegen BCS decoder.
 */
export interface RecoveryState {
	recoveryId: string;
	threshold: bigint;
	nonce: bigint;
	nextProposalId: bigint;
	nextEnrollmentId: bigint;
	nextRosterChangeId: bigint;
	/**
	 * Unified members set. Each entry is `[scheme_byte, ...pubkey]` — the same
	 * canonical id Move uses for voter dedup, the registry index, and the
	 * members set itself. Schemes: 0=Ed25519, 1=Secp256k1, 2=Secp256r1,
	 * 3=WebAuthn.
	 */
	members: Uint8Array[];
	presignCount: bigint;
	/** Each entry's `presign_id` — what `Presign` object id to fetch when a
	 * propose call will consume the cap at the matching index. */
	presignIds: string[];
	importedKeyDwalletId: string;
	dwalletNetworkEncryptionKeyId: string;
	/** Inner UID of the proposals Table — used as `parentId` for dynamic-field reads. */
	proposalsTableId: string;
	/** Inner UID of the enrollments Table. */
	enrollmentsTableId: string;
	/** Inner UID of the roster_changes Table. */
	rosterChangesTableId: string;
}

export async function readRecoveryState(client: RecoveryClient): Promise<RecoveryState> {
	const { object } = await client.suiClient.core.getObject({
		objectId: client.ref.recoveryId,
		include: { content: true },
	});
	if (!object.content) {
		throw new Error(`readRecoveryState: object ${client.ref.recoveryId} returned no content`);
	}
	const decoded = moveRecovery.Recovery.parse(object.content);
	return {
		recoveryId: decoded.id,
		threshold: BigInt(decoded.threshold),
		nonce: BigInt(decoded.nonce),
		nextProposalId: BigInt(decoded.next_proposal_id),
		nextEnrollmentId: BigInt(decoded.next_enrollment_id),
		nextRosterChangeId: BigInt(decoded.next_roster_change_id),
		members: decoded.members.contents.map((bs) => Uint8Array.from(bs)),
		presignCount: BigInt(decoded.presigns.length),
		presignIds: decoded.presigns.map((p) => p.presign_id),
		importedKeyDwalletId: decoded.imported_key_cap.dwallet_id,
		dwalletNetworkEncryptionKeyId: decoded.dwallet_network_encryption_key_id,
		proposalsTableId: decoded.proposals.id,
		enrollmentsTableId: decoded.enrollments.id,
		rosterChangesTableId: decoded.roster_changes.id,
	};
}
