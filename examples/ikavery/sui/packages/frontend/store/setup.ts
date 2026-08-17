'use client';

import type { NewMemberInput } from '@fesal-packages/ikavery-sui-sdk';
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

import { hexToBytes } from '@/lib/storage';

/**
 * Persistence-safe member shape. Zustand's `persist` middleware uses
 * JSON.stringify, which turns a `Uint8Array` into a plain index-keyed object
 * that's no longer iterable on rehydrate — silently producing 0-byte passkey
 * members at PTB build time. So in the store we hold hex; we convert to
 * `NewMemberInput` only at the boundary that actually builds the PTB.
 *
 * Three variants:
 *  - `passkey` and key-holding `wallet` members carry an encryption identity
 *    (serialized `UserShareEncryptionKeys`) captured during setup. They can
 *    propose, approve, and execute (after holding their share).
 *  - `approver` members are address-only — used for zkLogin / MultiSig /
 *    Passkey-as-sender wallets that don't produce a deterministic
 *    signPersonalMessage signature, so we can't derive a stable encryption
 *    identity for them. They can propose + approve but can't execute.
 */
export type StoredMember =
	| {
			kind: 'passkey';
			/** Compressed P-256 (33 bytes) — the WebAuthn member pubkey. */
			publicKeyHex: string;
			credentialIdHex: string;
			encryptionKeysBytesHex: string;
			encryptionAddress: string;
	  }
	| {
			kind: 'wallet';
			address: string;
			walletName?: string;
			scheme: 'ed25519' | 'secp256k1' | 'secp256r1';
			/** Raw account public key — 32 bytes (ed25519) or 33 bytes (k1/r1). */
			publicKeyHex: string;
			encryptionKeysBytesHex: string;
			encryptionAddress: string;
	  }
	| {
			/**
			 * Address-only "approver" member. Auth gate is `ctx.sender() == address`,
			 * which Sui validators verify on the way in for zkLogin / MultiSig /
			 * Passkey-as-sender. No encryption identity → can vote but cannot
			 * execute (no encrypted share to decrypt).
			 */
			kind: 'approver';
			address: string;
			walletName?: string;
			/** Originating Sui scheme tag for display only (zklogin / multisig / passkey / unknown). */
			origin: 'zklogin' | 'multisig' | 'passkey' | 'unknown';
	  };

export function toNewMember(m: StoredMember): NewMemberInput {
	if (m.kind === 'passkey') {
		return { scheme: 'webauthn', publicKey: hexToBytes(m.publicKeyHex) };
	}
	if (m.kind === 'approver') {
		return { scheme: 'sender_address', address: m.address };
	}
	return { scheme: m.scheme, publicKey: hexToBytes(m.publicKeyHex) };
}

/** Identity-uniqueness key for dedup. Same key ⇒ same on-chain member id. */
function identityKey(m: StoredMember): string {
	if (m.kind === 'approver') return `approver:${m.address.toLowerCase()}`;
	return `${m.kind}:${m.publicKeyHex.toLowerCase()}`;
}

export function sameIdentity(a: StoredMember, b: StoredMember): boolean {
	return identityKey(a) === identityKey(b);
}

export interface SetupState {
	/**
	 * Step 1 — initial user identity. May be a passkey OR a wallet. Decoupled
	 * from the gas-paying wallet (which can be any funded Sui account).
	 */
	importer: StoredMember | null;

	/** Step 2 — chosen members + threshold. */
	members: StoredMember[];
	threshold: number;

	/** Step 3 — solana ed25519 secret key, base58 or hex string. Cleared after import. */
	solanaSecretInput: string;

	/** Step 5 — set after successful import. */
	result: {
		recoveryId: string;
		dwalletId: string;
		encryptedUserShareId: string;
		txDigest: string;
	} | null;

	setImporter: (d: StoredMember | null) => void;
	setMembers: (m: StoredMember[]) => void;
	setThreshold: (t: number) => void;
	setSolanaSecretInput: (s: string) => void;
	setResult: (r: SetupState['result']) => void;
	reset: () => void;
}

const initial: Pick<
	SetupState,
	'importer' | 'members' | 'threshold' | 'solanaSecretInput' | 'result'
> = {
	importer: null,
	members: [],
	threshold: 2,
	solanaSecretInput: '',
	result: null,
};

export const useSetup = create<SetupState>()(
	persist(
		(set, get) => ({
			...initial,
			setImporter: (importer) => {
				// Keep the roster in sync: drop the old importer if present, and put
				// the new one at the front. The protocol requires initialMembers[0]
				// to be the importer, so seeding here removes a manual step and
				// prevents the user from ending up in an unsubmittable state.
				const prev = get().importer;
				const others = get().members.filter((m) => {
					if (prev && sameIdentity(m, prev)) return false;
					if (importer && sameIdentity(m, importer)) return false;
					return true;
				});
				const members = importer ? [importer, ...others] : others;
				set({ importer, members });
			},
			setMembers: (members) => set({ members }),
			setThreshold: (threshold) => set({ threshold }),
			setSolanaSecretInput: (solanaSecretInput) => set({ solanaSecretInput }),
			setResult: (result) => set({ result }),
			reset: () => set({ ...initial }),
		}),
		{
			name: 'recovery.setup',
			// v6: adds `approver` member kind for zkLogin/MultiSig/Passkey-as-sender
			// wallets that have no deterministic encryption identity. v5 entries
			// are silently dropped — they predate the variant tag.
			version: 6,
			partialize: (state) => ({
				importer: state.importer,
				members: state.members,
				threshold: state.threshold,
				result: state.result,
			}),
			// Stored state from earlier shapes is incompatible (renamed `device` →
			// `importer`, dropped `prfSeedHex`). Just discard and start fresh.
			migrate: () => ({ ...initial }),
		},
	),
);
