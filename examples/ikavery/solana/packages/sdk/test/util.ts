/**
 * Bridge from web3.js v1 `TransactionInstruction` to the Kit `IInstruction`
 * shape that litesvm v1 expects. The wire format is identical; only the
 * client-side type system differs between the two libraries.
 *
 * For signer accounts that aren't the fee payer, pass them via `extraSigners`
 * keyed by base58 address — Kit attaches them to the instruction's account
 * metas so `signTransactionMessageWithSigners` can collect their signatures.
 */

import type { IInstruction, TransactionSigner } from '@solana/kit';
import { AccountRole, address } from '@solana/kit';
import type { TransactionInstruction } from '@solana/web3.js';

export function toKitIx(
	v1: TransactionInstruction,
	extraSigners: Record<string, TransactionSigner> = {},
): IInstruction {
	return {
		programAddress: address(v1.programId.toBase58()),
		accounts: v1.keys.map((k) => {
			const addr = address(k.pubkey.toBase58());
			const role = k.isSigner
				? k.isWritable
					? AccountRole.WRITABLE_SIGNER
					: AccountRole.READONLY_SIGNER
				: k.isWritable
					? AccountRole.WRITABLE
					: AccountRole.READONLY;
			const signer = extraSigners[k.pubkey.toBase58()];
			if (k.isSigner && signer) {
				return { address: addr, role, signer };
			}
			return { address: addr, role };
		}),
		data: new Uint8Array(v1.data),
	};
}
