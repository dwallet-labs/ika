import { PublicKey } from '@solana/web3.js';

import {
	ED25519_PUBKEY_LEN,
	MEMBER_SLOT_LEN,
	SCHEME_ED25519,
	SCHEME_SECP256K1,
	SCHEME_SECP256R1,
	SCHEME_SOLANA_ADDRESS,
	SCHEME_WEBAUTHN,
	SECP256K1_PUBKEY_LEN,
	SECP256R1_PUBKEY_LEN,
	SOLANA_ADDRESS_LEN,
	WEBAUTHN_PUBKEY_LEN,
} from './constants';

/** Length of the canonical id portion of a member slot for a given scheme. */
export function idLenForScheme(scheme: number): number {
	switch (scheme) {
		case SCHEME_ED25519:
			return 1 + ED25519_PUBKEY_LEN;
		case SCHEME_SECP256K1:
			return 1 + SECP256K1_PUBKEY_LEN;
		case SCHEME_SECP256R1:
			return 1 + SECP256R1_PUBKEY_LEN;
		case SCHEME_WEBAUTHN:
			return 1 + WEBAUTHN_PUBKEY_LEN;
		case SCHEME_SOLANA_ADDRESS:
			return 1 + SOLANA_ADDRESS_LEN;
		default:
			throw new Error(`unknown scheme: ${scheme}`);
	}
}

/**
 * Pack a credential into the on-chain `MemberSlot` byte layout —
 * `[scheme, ...pubkey_or_address, ...zero_pad]` of length `MEMBER_SLOT_LEN`.
 */
export function packMemberSlot(scheme: number, pubkeyOrAddress: Uint8Array): Uint8Array {
	const expected = idLenForScheme(scheme) - 1;
	if (pubkeyOrAddress.length !== expected) {
		throw new Error(
			`scheme ${scheme} expects ${expected}-byte pubkey, got ${pubkeyOrAddress.length}`,
		);
	}
	const slot = new Uint8Array(MEMBER_SLOT_LEN);
	slot[0] = scheme;
	slot.set(pubkeyOrAddress, 1);
	return slot;
}

/** Pack a Solana address (the `SCHEME_SOLANA_ADDRESS` path). */
export function packSolanaMember(address: PublicKey): Uint8Array {
	return packMemberSlot(SCHEME_SOLANA_ADDRESS, address.toBytes());
}

/**
 * Slice a member slot to its canonical id (`[scheme, ...pubkey]` with no
 * trailing padding). Same shape Move uses for set membership / voter dedup.
 */
export function memberIdBytes(slot: Uint8Array): Uint8Array {
	if (slot.length !== MEMBER_SLOT_LEN) {
		throw new Error(`expected ${MEMBER_SLOT_LEN}-byte slot`);
	}
	const len = idLenForScheme(slot[0]!);
	return slot.slice(0, len);
}

/**
 * Pack up to MAX_MEMBERS slots into the fixed-size byte buffer that
 * `create_recovery` and `propose_roster_change` ix args expect. Pads with
 * zeroes; returns `[buffer, count]`.
 */
export function packMembers(
	slots: Uint8Array[],
	bufLen: number,
): { packed: Uint8Array; count: number } {
	const packed = new Uint8Array(bufLen);
	for (let i = 0; i < slots.length; i++) {
		const off = i * MEMBER_SLOT_LEN;
		if (off + MEMBER_SLOT_LEN > bufLen) {
			throw new Error('too many members for buffer');
		}
		packed.set(slots[i]!, off);
	}
	return { packed, count: slots.length };
}

/** Pad a per-scheme pubkey to the wire-format AUTH_PUBKEY_BYTES buffer. */
export function padAuthPubkey(pubkey: Uint8Array, bufLen: number): Uint8Array {
	if (pubkey.length > bufLen) {
		throw new Error(`pubkey ${pubkey.length}b exceeds ${bufLen}b buffer`);
	}
	const out = new Uint8Array(bufLen);
	out.set(pubkey, 0);
	return out;
}
