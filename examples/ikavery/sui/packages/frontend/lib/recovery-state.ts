import { moveRecovery } from '@fesal-packages/ikavery-sui-sdk';
import type { ClientWithCoreApi } from '@mysten/sui/client';

import { env } from './env';

export type Scheme = 'ed25519' | 'secp256k1' | 'secp256r1' | 'webauthn' | 'sender_address';

export const SCHEME_BYTE: Record<Scheme, number> = {
	ed25519: 0,
	secp256k1: 1,
	secp256r1: 2,
	webauthn: 3,
	sender_address: 4,
};

const SCHEME_FOR_BYTE: Record<number, Scheme | undefined> = {
	0: 'ed25519',
	1: 'secp256k1',
	2: 'secp256r1',
	3: 'webauthn',
	4: 'sender_address',
};

/** True for member schemes that hold no encrypted share — they can vote but can't execute. */
export function isApproverOnlyScheme(s: Scheme): boolean {
	return s === 'sender_address';
}

export interface VaultMember {
	/** Canonical id bytes `[scheme_byte, ...pubkey_or_address]`. */
	id: Uint8Array;
	scheme: Scheme;
	/**
	 * Pubkey only (no scheme prefix) for raw schemes; 32-byte address for
	 * `sender_address`. Treat as an opaque identity blob — use `scheme` to
	 * decide how to render it.
	 */
	publicKey: Uint8Array;
}

export interface VaultState {
	recoveryId: string;
	dwalletId: string;
	threshold: number;
	/** Decoded view of the unified members set. */
	members: VaultMember[];
	presignCount: number;
	nonce: bigint;
	nextProposalId: bigint;
	nextEnrollmentId: bigint;
	dwalletNetworkEncryptionKeyId: string;
	proposalsTableId: string;
	enrollmentsTableId: string;
	rosterChangesTableId: string;
	nextRosterChangeId: bigint;
}

export async function readVaultState(
	suiClient: ClientWithCoreApi,
	recoveryId: string,
): Promise<VaultState> {
	const { object } = await suiClient.core.getObject({
		objectId: recoveryId,
		include: { content: true },
	});
	if (!object.content) {
		throw new Error(`recovery object ${recoveryId} has no content`);
	}
	const decoded = moveRecovery.Recovery.parse(object.content);
	return {
		recoveryId: decoded.id,
		dwalletId: decoded.imported_key_cap.dwallet_id,
		threshold: Number(decoded.threshold),
		members: decoded.members.contents.map((bs) => decodeMember(bs)),
		presignCount: decoded.presigns.length,
		nonce: BigInt(decoded.nonce),
		nextProposalId: BigInt(decoded.next_proposal_id),
		nextEnrollmentId: BigInt(decoded.next_enrollment_id),
		dwalletNetworkEncryptionKeyId: decoded.dwallet_network_encryption_key_id,
		proposalsTableId: decoded.proposals.id,
		enrollmentsTableId: decoded.enrollments.id,
		rosterChangesTableId: decoded.roster_changes.id,
		nextRosterChangeId: BigInt(decoded.next_roster_change_id),
	};
}

function decodeMember(bytes: number[] | Uint8Array): VaultMember {
	const id = Uint8Array.from(bytes);
	if (id.length === 0) throw new Error('member id is empty');
	const scheme = SCHEME_FOR_BYTE[id[0]!];
	if (!scheme) throw new Error(`member id has unknown scheme byte ${id[0]}`);
	return { id, scheme, publicKey: id.slice(1) };
}

export function vaultMemberCount(state: VaultState): number {
	return state.members.length;
}

/**
 * Match a (scheme, pubkey) identity against a vault's members. Returns the
 * matched member or null. Used to figure out which signer the user can
 * authenticate as on this device.
 */
export function findMember(
	state: VaultState,
	scheme: Scheme,
	publicKey: Uint8Array,
): VaultMember | null {
	for (const m of state.members) {
		if (m.scheme !== scheme) continue;
		if (bytesEq(m.publicKey, publicKey)) return m;
	}
	return null;
}

export function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}

export function explorerObjectUrl(objectId: string): string {
	return `https://suiscan.xyz/${env.network}/object/${objectId}`;
}
