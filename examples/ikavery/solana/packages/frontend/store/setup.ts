'use client';

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

/**
 * Roster member as captured during /setup. Solana parity with Sui's two-card
 * pattern: the importer can be either a passkey (WebAuthn / secp256r1) or a
 * Solana wallet, and other roster slots can be paste-added wallet addresses
 * or enrolled later as passkeys via the enrollment flow.
 *
 * On-chain, passkey members live in `SCHEME_WEBAUTHN` slots keyed by a
 * 33-byte compressed P-256 public key; wallet members live in
 * `SCHEME_SOLANA_ADDRESS` slots keyed by the raw 32-byte ed25519 pubkey.
 * The mapping is in `lib/seal-vault.ts` and the assertion plumbing lives in
 * `lib/recover.ts` / `lib/enrollment.ts` / `lib/roster.ts`.
 */
export type StoredMember =
	| {
			kind: 'passkey';
			/** Hex of the WebAuthn credential id stored at enrollment. */
			credentialIdHex: string;
			/** Hex of the 33-byte compressed P-256 public key. On-chain member id. */
			publicKeyHex: string;
			/** Optional human label. */
			label?: string;
	  }
	| {
			kind: 'wallet';
			/** Base58 Solana address. Always 32 raw bytes. */
			address: string;
			/** Optional human label — Dynamic surfaces wallet brand for the importer. */
			walletName?: string;
	  };

export interface SealedResult {
	/** Base58 of the on-chain Recovery PDA. */
	recovery: string;
	/** Base58 of the recoveryId nonce keypair pubkey (also the seed for the PDA). */
	recoveryId: string;
	/** Base58 of the dWallet's *Solana pubkey form* (NOT the PDA). */
	dwalletPubkey: string;
	/** Base58 of the dWallet PDA — what the SDK reads from. */
	dwalletAccount: string;
	/** create_recovery tx signature. */
	signature: string;
	/** Lamports the dWallet needs to fund a sweep. Surfaces on /sealed as a CTA. */
	recommendedFundingLamports: number;
}

export type SealPhase =
	'idle' | 'dkg' | 'awaiting-pda' | 'transfer-authority' | 'create-recovery' | 'done';

export interface SetupState {
	/** Step 1 — connected importer (passkey or wallet) + member 0. */
	importer: StoredMember | null;
	/** Step 2 — full roster (always includes the importer at index 0). */
	members: StoredMember[];
	threshold: number;
	/** Step 3 — Solana ed25519 secret as user pasted it. Cleared after sealing. */
	solanaSecretInput: string;
	/** Step 5 — populated after a successful seal. */
	result: SealedResult | null;

	setImporter: (m: StoredMember | null) => void;
	setMembers: (ms: StoredMember[]) => void;
	setThreshold: (t: number) => void;
	setSolanaSecretInput: (v: string) => void;
	setResult: (r: SealedResult | null) => void;
	reset: () => void;
}

const INITIAL: Omit<
	SetupState,
	'setImporter' | 'setMembers' | 'setThreshold' | 'setSolanaSecretInput' | 'setResult' | 'reset'
> = {
	importer: null,
	members: [],
	threshold: 1,
	solanaSecretInput: '',
	result: null,
};

export const useSetup = create<SetupState>()(
	persist(
		(set) => ({
			...INITIAL,
			setImporter: (m) =>
				set((state) => {
					if (!m) return { ...state, importer: null, members: [] };
					const others = state.members.filter((x) => !sameMember(x, m));
					const prev = state.importer;
					const filtered = prev ? others.filter((x) => !sameMember(x, prev)) : others;
					return { ...state, importer: m, members: [m, ...filtered] };
				}),
			setMembers: (ms) => set({ members: ms }),
			setThreshold: (t) => set({ threshold: t }),
			setSolanaSecretInput: (v) => set({ solanaSecretInput: v }),
			setResult: (r) => set({ result: r }),
			reset: () => set(INITIAL),
		}),
		{
			name: 'ikavery-solana.setup',
			// v2 — discriminated `StoredMember` (passkey | wallet). v1 entries lack
			// `kind`; migrate by clearing setup state so the user starts fresh.
			version: 2,
			partialize: (state) => ({
				importer: state.importer,
				members: state.members,
				threshold: state.threshold,
				result: state.result,
			}),
			migrate: () => ({ ...INITIAL }),
		},
	),
);

/** Two members compare equal iff their on-chain id bytes match. */
export function sameMember(a: StoredMember, b: StoredMember): boolean {
	if (a.kind !== b.kind) return false;
	if (a.kind === 'passkey' && b.kind === 'passkey') {
		return a.publicKeyHex.toLowerCase() === b.publicKeyHex.toLowerCase();
	}
	if (a.kind === 'wallet' && b.kind === 'wallet') {
		return a.address === b.address;
	}
	return false;
}

/** Short, stable display id (~14 chars) for any member kind. */
export function memberDisplayId(m: StoredMember): string {
	if (m.kind === 'passkey') {
		const h = m.publicKeyHex;
		return `${h.slice(0, 10)}…${h.slice(-6)}`;
	}
	const a = m.address;
	return `${a.slice(0, 10)}…${a.slice(-6)}`;
}

/** Long-form id for copy buttons / receipts. */
export function memberFullId(m: StoredMember): string {
	return m.kind === 'passkey' ? m.publicKeyHex : m.address;
}

/** Stable React key for any member kind. */
export function memberKey(m: StoredMember): string {
	return m.kind === 'passkey' ? `pk:${m.publicKeyHex}` : `w:${m.address}`;
}

/** Short kind label for "Passkey" / "Wallet · …" UI. */
export function memberKindLabel(m: StoredMember): string {
	if (m.kind === 'passkey') return m.label ?? 'Passkey';
	return m.walletName ? `Wallet · ${m.walletName}` : 'Wallet';
}
