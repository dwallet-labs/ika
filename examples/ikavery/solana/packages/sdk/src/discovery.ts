import { PublicKey, type Commitment, type Connection } from '@solana/web3.js';

import { decodeRecovery, type RecoveryAccount } from './codec/recovery';
import { DISC_RECOVERY, IKAVERY_PROGRAM_ID, MEMBER_SLOT_LEN } from './constants';
import { TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID } from './sweep/message';

/** Per-recovery match returned by `listRecoveriesForMember`. */
export interface RecoveryMatch {
	/** Recovery PDA address. */
	recovery: PublicKey;
	/** Index of the matching member slot inside that recovery (0..7). */
	slotIndex: number;
}

/** Decoded recovery + its on-chain address, returned by `listAllRecoveries`. */
export interface DecodedRecovery {
	recovery: PublicKey;
	account: RecoveryAccount;
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Tiny base58 encoder for the memcmp filter bytes. Avoids pulling in a full
 * bs58 dep at the SDK boundary; `getProgramAccounts` filters expect a base58
 * string, not raw bytes.
 */
function bytesToBase58(bytes: Uint8Array): string {
	let zeros = 0;
	while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
	let buf: number[] = Array.from(bytes.slice(zeros));
	const out: number[] = [];
	while (buf.length > 0) {
		let carry = 0;
		const next: number[] = [];
		for (const b of buf) {
			const acc = carry * 256 + b;
			const q = Math.floor(acc / 58);
			carry = acc % 58;
			if (next.length > 0 || q !== 0) next.push(q);
		}
		out.push(carry);
		buf = next;
	}
	let s = '';
	for (let i = 0; i < zeros; i++) s += '1';
	for (let i = out.length - 1; i >= 0; i--) {
		s += BASE58_ALPHABET[out[i] as number];
	}
	return s;
}

const DISC_FILTER = {
	memcmp: { offset: 0, bytes: bytesToBase58(new Uint8Array([DISC_RECOVERY])) },
} as const;

/**
 * Fetch every Recovery account on this Solana cluster in one
 * `getProgramAccounts` call (filtered by discriminator) and decode it
 * client-side. Members are fixed-size and the active set is short, so
 * pulling full data and scanning in JS is cheaper than fanning out
 * per-slot memcmp filters.
 *
 * Public RPCs rate-limit `getProgramAccounts` aggressively. Callers should
 * cache the result (e.g. via React Query) and only call this behind
 * explicit user action.
 */
export async function listAllRecoveries(
	connection: Connection,
	opts: { programId?: PublicKey; commitment?: Commitment } = {},
): Promise<DecodedRecovery[]> {
	const programId = opts.programId ?? IKAVERY_PROGRAM_ID;
	const commitment = opts.commitment ?? 'confirmed';
	const result = await connection.getProgramAccounts(programId, {
		commitment,
		filters: [DISC_FILTER],
	});
	const out: DecodedRecovery[] = [];
	for (const r of result) {
		try {
			out.push({
				recovery: r.pubkey,
				account: decodeRecovery(r.account.data),
			});
		} catch {
			// Skip unparseable rows — likely an older layout version, harmless
			// for discovery purposes.
		}
	}
	return out;
}

/**
 * Find every Recovery whose roster contains `memberSlot`. Backed by
 * `listAllRecoveries` (one RPC call), with the membership check done in
 * JS. Pass a pre-fetched list via `recoveries` to share one fetch across
 * multiple membership checks (passkey + wallet).
 */
export async function listRecoveriesForMember(
	connection: Connection,
	memberSlot: Uint8Array,
	opts: {
		programId?: PublicKey;
		commitment?: Commitment;
		/** Pre-fetched recoveries to scan in lieu of issuing a new RPC call. */
		recoveries?: DecodedRecovery[];
	} = {},
): Promise<RecoveryMatch[]> {
	if (memberSlot.length !== MEMBER_SLOT_LEN) {
		throw new Error(`memberSlot must be ${MEMBER_SLOT_LEN} bytes; got ${memberSlot.length}`);
	}
	const recoveries =
		opts.recoveries ??
		(await listAllRecoveries(connection, {
			programId: opts.programId,
			commitment: opts.commitment,
		}));
	const matches: RecoveryMatch[] = [];
	for (const r of recoveries) {
		for (let i = 0; i < r.account.members.length; i++) {
			if (slotEq(r.account.members[i] as Uint8Array, memberSlot)) {
				matches.push({ recovery: r.recovery, slotIndex: i });
				break;
			}
		}
	}
	return matches;
}

function slotEq(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}

/**
 * Token account on the dWallet ready to be swept. Shape matches
 * `@fesal-packages/ikavery-core`'s `SourceTokenAccount`, but in serializable
 * form (PublicKeys as base58, amount as bigint).
 */
export interface DiscoveredTokenAccount {
	mint: PublicKey;
	tokenAccount: PublicKey;
	amount: bigint;
	decimals: number;
	programId: PublicKey;
}

/**
 * List every non-empty SPL token account owned by `owner`. Walks both the
 * original Token program and Token-2022 because either can hold balances on
 * the dWallet pubkey. Only accounts with `amount > 0` are returned — empty
 * (0-balance) ATAs would still occupy a tx slot in the sweep but contribute
 * nothing, so callers should filter them out anyway.
 */
export async function discoverTokenAccounts(
	connection: Connection,
	owner: PublicKey,
	opts: { commitment?: Commitment } = {},
): Promise<DiscoveredTokenAccount[]> {
	const commitment = opts.commitment ?? 'confirmed';
	const out: DiscoveredTokenAccount[] = [];
	for (const programId of [TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID]) {
		const result = await connection.getParsedTokenAccountsByOwner(owner, { programId }, commitment);
		for (const { account, pubkey } of result.value) {
			const data = account.data as
				| {
						parsed?: {
							info?: {
								mint?: string;
								tokenAmount?: { amount?: string; decimals?: number };
							};
						};
				  }
				| undefined;
			const info = data?.parsed?.info;
			const mint = info?.mint;
			const amountStr = info?.tokenAmount?.amount;
			const decimals = info?.tokenAmount?.decimals;
			if (!mint || !amountStr || decimals === undefined) continue;
			const amount = BigInt(amountStr);
			if (amount === 0n) continue;
			out.push({
				mint: new PublicKey(mint),
				tokenAccount: pubkey,
				amount,
				decimals,
				programId,
			});
		}
	}
	return out;
}
