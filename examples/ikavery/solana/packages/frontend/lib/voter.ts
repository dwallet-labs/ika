'use client';

import {
	memberIdBytes,
	packMemberSlot,
	packSolanaMember,
	SCHEME_WEBAUTHN,
} from '@fesal-packages/ikavery-solana-sdk';
import { PublicKey } from '@solana/web3.js';

import { hexToBytes, loadActiveImporter, type CachedImporter } from '@/lib/storage';
import type { StoredMember } from '@/store/setup';

/**
 * Resolve the local roster identity (`voter`) for an op against a vault.
 *
 * Two inputs feed in: the cached importer in IDB (passkey or wallet from
 * /setup) and the connected wallet from Dynamic. We pick the one that is
 * actually on the on-chain roster — passkey wins if both qualify, since
 * a user who chose a passkey at setup wants assertion-based auth.
 *
 * Returns `null` if neither identity is on the roster — caller should
 * surface a "you're not on this vault's roster" error.
 */
export async function resolveVoter(opts: {
	rosterMemberSlots: Uint8Array[];
	primaryWalletAddress?: string | null;
}): Promise<StoredMember | null> {
	const cached = await loadActiveImporter();
	const cachedAsMember = cached ? cachedToStored(cached) : null;
	if (cachedAsMember && isOnRoster(cachedAsMember, opts.rosterMemberSlots)) {
		return cachedAsMember;
	}
	if (opts.primaryWalletAddress) {
		try {
			const walletMember: StoredMember = {
				kind: 'wallet',
				address: opts.primaryWalletAddress,
			};
			if (isOnRoster(walletMember, opts.rosterMemberSlots)) {
				return walletMember;
			}
		} catch {
			// Invalid base58 — fall through.
		}
	}
	return null;
}

export function cachedToStored(c: CachedImporter): StoredMember {
	if (c.kind === 'passkey') {
		return {
			kind: 'passkey',
			credentialIdHex: c.credentialIdHex,
			publicKeyHex: c.publicKeyHex,
			label: c.label,
		};
	}
	return {
		kind: 'wallet',
		address: c.address,
		walletName: c.walletName,
	};
}

export function memberSlotForVoter(voter: StoredMember): Uint8Array {
	if (voter.kind === 'passkey') {
		return packMemberSlot(SCHEME_WEBAUTHN, hexToBytes(voter.publicKeyHex));
	}
	return packSolanaMember(new PublicKey(voter.address));
}

function isOnRoster(member: StoredMember, slots: Uint8Array[]): boolean {
	const localId = memberIdBytes(memberSlotForVoter(member));
	return slots.some((slot) => bytesEq(memberIdBytes(slot), localId));
}

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}
