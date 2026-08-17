import { PublicKey, TransactionInstruction } from '@solana/web3.js';

import { IKA_DWALLET_PROGRAM_ID, IX_DWALLET_TRANSFER_OWNERSHIP } from './constants';

/**
 * Direct (non-CPI) `TransferOwnership` instruction on the dWallet program.
 *
 * After DKG the dWallet's authority is the user keypair that called gRPC.
 * To let a Quasar program (e.g. ikavery) issue `MessageApproval` on the
 * dWallet's behalf, the user must transfer authority to that program's
 * CPI authority PDA. One-way: once transferred, only the new authority's
 * program can move it back.
 *
 * Account layout (dWallet program, direct mode):
 *   [0] current_authority — read-only Signer (the Solana ed25519 pubkey)
 *   [1] dwallet           — writable, program-owned
 *
 * Data: [disc=24, ...new_authority(32 bytes)] = 33 bytes total.
 */
export function buildTransferDwalletAuthorityIx(params: {
	currentAuthority: PublicKey;
	dwallet: PublicKey;
	newAuthority: PublicKey;
}): TransactionInstruction {
	const data = new Uint8Array(33);
	data[0] = IX_DWALLET_TRANSFER_OWNERSHIP;
	data.set(params.newAuthority.toBytes(), 1);
	return new TransactionInstruction({
		programId: IKA_DWALLET_PROGRAM_ID,
		keys: [
			{ pubkey: params.currentAuthority, isSigner: true, isWritable: false },
			{ pubkey: params.dwallet, isSigner: false, isWritable: true },
		],
		data: Buffer.from(data),
	});
}
