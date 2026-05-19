// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Cross-chain demo: a single Ed25519 dWallet acts as a Solana key. Sign a
 * `VersionedTransaction` and publish to Solana devnet. Source is still Sui
 * (the network that runs the MPC) — only the signing target chain is Solana.
 *
 *   $ pnpm sign-solana
 *
 * The example uses a SystemProgram transfer to itself so it can run without
 * a funded recipient; the signer address still needs devnet SOL though.
 */

import {
	Connection,
	PublicKey,
	SystemProgram,
	TransactionMessage,
	VersionedTransaction,
} from '@solana/web3.js';
import { Curve, publicKeyFromDWalletOutput } from '@ika.xyz/sdk';
import { buildIka, run } from './shared.js';

run('sign + broadcast Solana transaction (Ed25519 shared dWallet)', async () => {
	const ika = await buildIka(Curve.ED25519);

	const dWallet = await ika.sui.createDWallet({
		kind: 'shared',
		curve: Curve.ED25519,
	});
	const pubkeyBytes = await publicKeyFromDWalletOutput(Curve.ED25519, dWallet.publicOutput);
	const payer = new PublicKey(pubkeyBytes);
	console.log('dWallet Solana pubkey:', payer.toBase58());
	console.log('fund this address with devnet SOL before continuing.');

	const conn = new Connection(process.env.SOLANA_RPC_URL ?? 'https://api.devnet.solana.com');
	const { blockhash } = await conn.getLatestBlockhash('confirmed');

	const tx = new VersionedTransaction(
		new TransactionMessage({
			payerKey: payer,
			recentBlockhash: blockhash,
			instructions: [
				SystemProgram.transfer({
					fromPubkey: payer,
					toPubkey: payer,
					lamports: 1,
				}),
			],
		}).compileToV0Message(),
	);

	const signed = await dWallet.solana.sign({ kind: 'transaction', tx });
	// Narrow the union discriminator. `kind: 'message'` payloads are not
	// broadcastable, so the publisher refuses them at the type level.
	if (signed.payload.kind !== 'transaction') {
		throw new Error('expected transaction-mode payload');
	}
	console.log('signed; broadcasting...');

	const sig = await ika.publish({ chain: 'solana', payload: signed.payload });
	console.log('solana signature:', sig);
});
