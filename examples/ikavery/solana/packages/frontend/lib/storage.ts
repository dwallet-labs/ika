'use client';

import { idbDel as del, idbGet as get, idbSet as set } from '@/lib/idb';

/**
 * IDB-backed cache for the importer's identity (passkey or wallet) across
 * page reloads. Mirrors the Sui frontend's `lib/storage.ts` shape so future
 * cross-chain code can use the same persistence layer.
 *
 * Solana pre-alpha has no encrypted-user-share concept yet, so we don't
 * carry encryption identity bytes — just enough to recreate the on-chain
 * member id and drive a per-op WebAuthn assertion.
 */
export type CachedImporter =
	| {
			kind: 'passkey';
			credentialIdHex: string;
			/** 33-byte compressed P-256 pubkey, hex-encoded. */
			publicKeyHex: string;
			label?: string;
			createdAt: number;
	  }
	| {
			kind: 'wallet';
			address: string;
			walletName?: string;
			createdAt: number;
	  };

const ACTIVE_IMPORTER_KEY = 'ikavery-solana:active-importer';

export async function saveActiveImporter(d: CachedImporter): Promise<void> {
	await set(ACTIVE_IMPORTER_KEY, d);
}

export async function loadActiveImporter(): Promise<CachedImporter | null> {
	return (await get<CachedImporter>(ACTIVE_IMPORTER_KEY)) ?? null;
}

export async function clearActiveImporter(): Promise<void> {
	await del(ACTIVE_IMPORTER_KEY);
}

export function bytesToHex(b: Uint8Array): string {
	return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
	const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
	if (clean.length % 2 !== 0) throw new Error('hex string has odd length');
	const out = new Uint8Array(clean.length / 2);
	for (let i = 0; i < out.length; i++) {
		out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
	}
	return out;
}

/**
 * The DKG attestation bundle returned by `/api/seal-prepare`. Persisted at
 * seal time so the recovery flow (Phase 4) can re-issue gRPC Presign / Sign
 * calls against the same dWallet without doing DKG again.
 */
export interface DkgBundle {
	/** Base58 of the on-chain Recovery PDA. The map key. */
	recovery: string;
	/** Base58 of the recoveryId nonce keypair pubkey. */
	recoveryId: string;
	/** Base58 of the dWallet pubkey (Solana-address form). */
	dwalletPubkey: string;
	/** Base58 of the dWallet PDA the program reads from. */
	dwalletAccount: string;
	/** Base58 of the importer's wallet pubkey — the original gRPC sender. */
	senderPubkey: string;

	// Hex-encoded BCS blobs. Phase 4 decodes these for Presign / Sign.
	attestationDataHex: string;
	networkSignatureHex: string;
	networkPubkeyHex: string;

	/** ms since epoch when this vault was sealed. */
	sealedAt: number;
}

const DKG_PREFIX = 'ikavery-solana:dkg:';

export async function saveDkgBundle(b: DkgBundle): Promise<void> {
	await set(DKG_PREFIX + b.recovery, b);
}

export async function loadDkgBundle(recovery: string): Promise<DkgBundle | null> {
	const v = await get<DkgBundle>(DKG_PREFIX + recovery);
	return v ?? null;
}

export async function clearDkgBundle(recovery: string): Promise<void> {
	await del(DKG_PREFIX + recovery);
}

/**
 * Saved-vaults index — a list of recoveries this browser has seen, so the
 * `/vault` listing page can render without an on-chain getProgramAccounts.
 * Solana's RPC quota makes the per-program scan a 429 magnet.
 */
export interface SavedVault {
	recovery: string;
	recoveryId: string;
	dwalletPubkey: string;
	threshold: number;
	totalMembers: number;
	createdAt: number;
}

const VAULTS_KEY = 'ikavery-solana:vaults';

export async function appendSavedVault(v: SavedVault): Promise<void> {
	const existing = (await get<SavedVault[]>(VAULTS_KEY)) ?? [];
	// Dedup by recovery id; latest entry wins.
	const filtered = existing.filter((x) => x.recovery !== v.recovery);
	await set(VAULTS_KEY, [v, ...filtered]);
}

export async function loadSavedVaults(): Promise<SavedVault[]> {
	return (await get<SavedVault[]>(VAULTS_KEY)) ?? [];
}

/**
 * Source token account a sweep references — `mint`, `tokenAccount`, `amount`
 * (bigint as a string for IDB safety), `decimals`, and `programId`. Mirrors
 * core's `SourceTokenAccount` plus serializable forms.
 */
export interface SerializedTokenAccount {
	mint: string;
	tokenAccount: string;
	/** Bigint stringified — IDB serializes BigInt to lossy via structuredClone. */
	amount: string;
	decimals: number;
	programId: string;
}

/**
 * Sweep bundle authored at propose time. A bundle is one or more on-chain
 * Proposals; each Proposal carries a single MessageV0 because Solana caps
 * proposal payloads at 512 bytes. The full bundle is stashed under each
 * proposal's PDA so any device can reach it from any one proposal.
 *
 * The broadcaster rebuilds each MessageV0 from the bundle args at execute
 * time with a fresh blockhash — the on-chain intent digest excludes the
 * blockhash, so structural equivalence holds.
 */
export interface SweepBundle {
	/** Recovery PDA (base58). */
	recovery: string;
	/** Proposal PDAs (base58), index `i` of this array signs message `i`. */
	proposalAddresses: string[];
	/** Proposal indexes corresponding 1:1 with `proposalAddresses`. */
	proposalIndexes: number[];
	/** dWallet pubkey (base58) — the source of all sweeps in this bundle. */
	source: string;
	/** Final destination (base58). */
	destination: string;
	/** dWallet's SOL balance at propose time (lamports as string). */
	solBalanceLamports: string;
	/** Per-tx fee reserve held back from the SOL transfer (lamports as string). */
	feeReserveLamports: string;
	/** Token accounts to sweep (empty for SOL-only). */
	tokenAccounts: SerializedTokenAccount[];
	/** ms since epoch when this bundle was authored. */
	proposedAt: number;
}

const BUNDLE_PREFIX = 'ikavery-solana:bundle:';

export async function saveSweepBundle(bundle: SweepBundle): Promise<void> {
	// Stash the same blob under each proposal PDA so any per-proposal page can
	// reach the full bundle without scanning storage.
	for (const proposal of bundle.proposalAddresses) {
		await set(BUNDLE_PREFIX + proposal, bundle);
	}
}

export async function loadSweepBundle(proposal: string): Promise<SweepBundle | null> {
	return (await get<SweepBundle>(BUNDLE_PREFIX + proposal)) ?? null;
}
