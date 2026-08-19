import type { Transaction, TransactionArgument } from '@mysten/sui/transactions';

import * as moveAuth from '../generated/recovery/auth';

/**
 * High-level shape for an authentication identity that the SDK turns into a
 * Move-side `auth::NewMember`. Mirrors the five enum variants on-chain. Each
 * member id is `[scheme_byte, ...pubkey_or_address]` and is what gets stored
 * in the recovery's unified `members` set + the registry index.
 *
 * Lengths:
 *  - ed25519:        32-byte raw pubkey
 *  - secp256k1:      33-byte compressed pubkey
 *  - secp256r1:      33-byte compressed pubkey
 *  - webauthn:       33-byte compressed P-256 passkey pubkey
 *  - sender_address: 32-byte Sui address (approver-only — see credential.ts)
 */
export type NewMemberInput =
	| { scheme: 'ed25519'; publicKey: Uint8Array }
	| { scheme: 'secp256k1'; publicKey: Uint8Array }
	| { scheme: 'secp256r1'; publicKey: Uint8Array }
	| { scheme: 'webauthn'; publicKey: Uint8Array }
	| { scheme: 'sender_address'; address: string };

const SCHEME_BYTE: Record<NewMemberInput['scheme'], number> = {
	ed25519: 0,
	secp256k1: 1,
	secp256r1: 2,
	webauthn: 3,
	sender_address: 4,
};

function addressToBytes(addr: string): Uint8Array {
	const hex = addr.replace(/^0x/, '').padStart(64, '0');
	if (hex.length !== 64) {
		throw new Error(`memberIdBytes: invalid Sui address ${addr}`);
	}
	const out = new Uint8Array(32);
	for (let i = 0; i < 32; i++) {
		out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	}
	return out;
}

/**
 * Canonical id bytes used everywhere (members set, voter dedup, registry).
 * Matches `auth::new_member_id_bytes` on-chain.
 */
export function memberIdBytes(m: NewMemberInput): Uint8Array {
	if (m.scheme === 'sender_address') {
		const out = new Uint8Array(33);
		out[0] = SCHEME_BYTE.sender_address;
		out.set(addressToBytes(m.address), 1);
		return out;
	}
	const out = new Uint8Array(1 + m.publicKey.length);
	out[0] = SCHEME_BYTE[m.scheme];
	out.set(m.publicKey, 1);
	return out;
}

/** True if this member is approver-only (no encrypted share, can't execute). */
export function isApproverOnlyMember(m: NewMemberInput): boolean {
	return m.scheme === 'sender_address';
}

/**
 * Build a `vector<auth::NewMember>` PTB argument from a list of high-level
 * inputs. Each entry is constructed via the matching `auth::new_*_member`
 * builder so the on-chain enum variants line up.
 */
export function buildNewMembersVec(
	tx: Transaction,
	packageId: string,
	members: NewMemberInput[],
): TransactionArgument {
	const elements = members.map((m) => newMemberToMoveArg(tx, packageId, m));
	return tx.makeMoveVec({
		type: `${packageId}::auth::NewMember`,
		elements,
	});
}

/** Build a single `auth::NewMember` PTB argument. */
export function newMemberToMoveArg(tx: Transaction, packageId: string, m: NewMemberInput) {
	switch (m.scheme) {
		case 'ed25519':
			return moveAuth.newEd25519Member({
				package: packageId,
				arguments: [Array.from(m.publicKey)],
			})(tx);
		case 'secp256k1':
			return moveAuth.newSecp256k1Member({
				package: packageId,
				arguments: [Array.from(m.publicKey)],
			})(tx);
		case 'secp256r1':
			return moveAuth.newSecp256r1Member({
				package: packageId,
				arguments: [Array.from(m.publicKey)],
			})(tx);
		case 'webauthn':
			return moveAuth.newWebauthnMember({
				package: packageId,
				arguments: [Array.from(m.publicKey)],
			})(tx);
		case 'sender_address':
			return moveAuth.newSenderMember({
				package: packageId,
				arguments: [m.address],
			})(tx);
	}
}
