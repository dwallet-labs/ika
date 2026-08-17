import { bcs } from '@mysten/sui/bcs';
import type { ClientWithCoreApi } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';

import { env } from './env';

/**
 * Lookup every Recovery the given member id belongs to via the on-chain
 * `recovery::registry`. Uses a `simulateTransaction` call — read-only, no
 * gas, no signer required, and crucially no WASM, so this can run on the
 * main thread without needing the worker.
 *
 * `memberId` is the canonical `[scheme_byte, ...publicKey]` shape:
 *   - scheme 0 ed25519:   1 + 32 bytes
 *   - scheme 1 secp256k1: 1 + 33 bytes
 *   - scheme 2 secp256r1: 1 + 33 bytes
 *   - scheme 3 webauthn:  1 + 33 bytes (compressed P-256 passkey pubkey)
 */
export async function listRecoveriesForMember(
	suiClient: ClientWithCoreApi,
	memberId: Uint8Array,
): Promise<string[]> {
	const tx = new Transaction();
	tx.setSender('0x0000000000000000000000000000000000000000000000000000000000000000');
	tx.moveCall({
		target: `${env.recoveryPackageId}::registry::list_for_member`,
		arguments: [tx.object(env.recoveryRegistryId), tx.pure.vector('u8', Array.from(memberId))],
	});
	const r = await suiClient.core.simulateTransaction({
		transaction: tx,
		include: { commandResults: true },
	});
	if (r.$kind !== 'Transaction') return [];
	const ret = r.commandResults?.[0]?.returnValues?.[0];
	if (!ret) return [];
	return bcs.vector(bcs.Address).parse(ret.bcs);
}

export type MemberScheme = 'ed25519' | 'secp256k1' | 'secp256r1' | 'webauthn';

const SCHEME_BYTE: Record<MemberScheme, number> = {
	ed25519: 0,
	secp256k1: 1,
	secp256r1: 2,
	webauthn: 3,
};

/** Build `[scheme_byte, ...publicKey]` — must match `auth::new_member_id_bytes`. */
export function memberIdFor(scheme: MemberScheme, publicKey: Uint8Array): Uint8Array {
	const out = new Uint8Array(1 + publicKey.length);
	out[0] = SCHEME_BYTE[scheme];
	out.set(publicKey, 1);
	return out;
}
