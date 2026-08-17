'use client';

import { del, get, set } from 'idb-keyval';

/**
 * IndexedDB-backed cache for the importer's identity (passkey or wallet)
 * across reloads. Same shape as roster `StoredMember` plus `createdAt` so
 * the importer can also be added to the roster without re-deriving.
 */
export type CachedImporter =
	| {
			kind: 'passkey';
			credentialIdHex: string;
			/** Compressed P-256 (33 bytes) — used as the WebAuthn member pubkey. */
			publicKeyHex: string;
			encryptionKeysBytesHex: string;
			encryptionAddress: string;
			createdAt: number;
	  }
	| {
			kind: 'wallet';
			address: string;
			walletName?: string;
			/** Sui signature scheme of the wallet's account. */
			scheme: 'ed25519' | 'secp256k1' | 'secp256r1';
			/**
			 * Raw account public key (32 bytes for ed25519, 33 bytes compressed for
			 * secp256k1/r1). Combined with `scheme`, this is the canonical member
			 * identity on-chain.
			 */
			publicKeyHex: string;
			encryptionKeysBytesHex: string;
			encryptionAddress: string;
			createdAt: number;
	  };

const ACTIVE_IMPORTER_KEY = 'recovery.activeImporter';
const SAVED_VAULTS_KEY = 'recovery.savedVaults';
const ENROLLMENT_STASH_KEY = 'recovery.enrollmentStash';

export interface SavedVault {
	recoveryId: string;
	dwalletId: string;
	threshold: number;
	totalMembers: number;
	createdAt: number;
	/**
	 * Object id of *this device's* encrypted-user-share for this vault. Set at
	 * import time for the importer; set at enroll-acceptance time for other
	 * devices. Without it, the device can't decrypt → can't propose / approve.
	 */
	myEncryptedUserShareId?: string;
}

export async function saveActiveImporter(d: CachedImporter): Promise<void> {
	await set(ACTIVE_IMPORTER_KEY, d);
}

export async function loadActiveImporter(): Promise<CachedImporter | null> {
	return ((await get(ACTIVE_IMPORTER_KEY)) as CachedImporter | undefined) ?? null;
}

export async function clearActiveImporter(): Promise<void> {
	await del(ACTIVE_IMPORTER_KEY);
}

export async function appendSavedVault(v: SavedVault): Promise<void> {
	const existing = ((await get(SAVED_VAULTS_KEY)) as SavedVault[] | undefined) ?? [];
	await set(SAVED_VAULTS_KEY, [v, ...existing.filter((x) => x.recoveryId !== v.recoveryId)]);
}

export async function loadSavedVaults(): Promise<SavedVault[]> {
	return ((await get(SAVED_VAULTS_KEY)) as SavedVault[] | undefined) ?? [];
}

/**
 * Captured enrollee identity for a key-holder member that was proposed from
 * this browser. Lets the same browser later register the encryption key on
 * Ika (idempotent retry) or carry the keys to a fresh device. Keyed by
 * `(recoveryId, encryptionAddress)` so multiple pending enrollments coexist.
 */
export interface EnrollmentStashEntry {
	recoveryId: string;
	/** The new member's `UserShareEncryptionKeys.getSuiAddress()`. */
	encryptionAddress: string;
	/** Serialized `UserShareEncryptionKeys` bytes (hex). */
	encryptionKeysBytesHex: string;
	createdAt: number;
}

export async function saveEnrollmentStash(
	entry: Omit<EnrollmentStashEntry, 'createdAt'>,
): Promise<void> {
	const all = ((await get(ENROLLMENT_STASH_KEY)) as EnrollmentStashEntry[] | undefined) ?? [];
	const next: EnrollmentStashEntry = { ...entry, createdAt: Date.now() };
	const filtered = all.filter(
		(e) =>
			!(
				e.recoveryId === entry.recoveryId &&
				e.encryptionAddress.toLowerCase() === entry.encryptionAddress.toLowerCase()
			),
	);
	await set(ENROLLMENT_STASH_KEY, [next, ...filtered]);
}

export async function loadEnrollmentStash(
	recoveryId: string,
	encryptionAddress: string,
): Promise<EnrollmentStashEntry | null> {
	const all = ((await get(ENROLLMENT_STASH_KEY)) as EnrollmentStashEntry[] | undefined) ?? [];
	const target = encryptionAddress.toLowerCase();
	return (
		all.find((e) => e.recoveryId === recoveryId && e.encryptionAddress.toLowerCase() === target) ??
		null
	);
}

export function bytesToHex(b: Uint8Array): string {
	return Array.from(b)
		.map((x) => x.toString(16).padStart(2, '0'))
		.join('');
}

export function hexToBytes(hex: string): Uint8Array {
	const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
	if (clean.length % 2 !== 0) throw new Error('hex string has odd length');
	const out = new Uint8Array(clean.length / 2);
	for (let i = 0; i < out.length; i++) {
		out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
	}
	return out;
}
