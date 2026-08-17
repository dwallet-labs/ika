'use client';

import {
	packMemberSlot,
	packSolanaMember,
	passkey,
	SCHEME_SOLANA_ADDRESS,
	SCHEME_WEBAUTHN,
} from '@fesal-packages/ikavery-solana-sdk';
import { PublicKey, type TransactionInstruction } from '@solana/web3.js';

import { hexToBytes } from '@/lib/storage';
import type { StoredMember } from '@/store/setup';

export interface ProducedAuth {
	/** secp256r1 SigVerify ix(es) to prepend to the recovery ix. */
	precompileIxs: TransactionInstruction[];
	/** Credential bundle the SDK ix builders consume. */
	credential: {
		scheme: number;
		pubkey: Uint8Array;
		clientDataJson?: Uint8Array;
	};
	/** On-chain canonical member slot for this voter. */
	memberSlot: Uint8Array;
}

/**
 * Drive a per-op authorisation: WebAuthn assertion + secp256r1 precompile
 * for passkey voters, no-op precompile + plain SCHEME_SOLANA_ADDRESS for
 * wallet voters. Wallet voters pin to whoever signs the outer tx — the
 * on-chain handler validates that the credential's address matches a
 * Signer in the same tx.
 */
export async function produceAuth(opts: {
	voter: StoredMember;
	/** The Solana pubkey signing the outer tx — matched against wallet voters. */
	proposer: PublicKey;
	challenge: Uint8Array;
}): Promise<ProducedAuth> {
	if (opts.voter.kind === 'passkey') {
		const publicKey = hexToBytes(opts.voter.publicKeyHex);
		const credentialId = hexToBytes(opts.voter.credentialIdHex);
		const result = await passkey.runWebAuthnAssertion({
			credentialId,
			publicKey,
			challenge: opts.challenge,
		});
		return {
			precompileIxs: [result.precompileIx],
			credential: result.credential,
			memberSlot: packMemberSlot(SCHEME_WEBAUTHN, publicKey),
		};
	}
	const walletPub = new PublicKey(opts.voter.address);
	if (!walletPub.equals(opts.proposer)) {
		throw new Error(
			`Connected wallet ${opts.proposer.toBase58()} doesn't match the roster member ${walletPub.toBase58()} authorising this op. Reconnect with the right wallet.`,
		);
	}
	return {
		precompileIxs: [],
		credential: {
			scheme: SCHEME_SOLANA_ADDRESS,
			pubkey: walletPub.toBytes(),
		},
		memberSlot: packSolanaMember(walletPub),
	};
}
