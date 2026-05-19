// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Compose multiple coordinator operations in a single Sui PTB via
 * `ika.sui.transaction(...)`. The callback receives a builder bundle
 * (`{ tx, ikaTx, pay }`) and may invoke as many coordinator calls as
 * needed; the plugin handles fee-coin allocation, signing, and exec.
 *
 *   $ pnpm compose
 *
 * Use this when a single atomic Sui tx must commit several Ika ops together
 * (e.g. multiple signs against one set of approvals, or a DKG followed by
 * an immediate sign in the same block).
 */

import { Curve, Hash, SignatureAlgorithm } from '@ika.xyz/sdk';
import { buildIka, run } from './shared.js';

run('compose multiple sign ops into one PTB', async () => {
	const ika = await buildIka(Curve.ED25519);

	// First, create a dWallet and request a presign through the high-level
	// API. We need both before composing the multi-sign tx — the dWallet
	// must be Active and the presign must be Completed.
	const dWallet = await ika.sui.createDWallet({
		kind: 'shared',
		curve: Curve.ED25519,
	});

	// Two independent messages signed in the same PTB by the same dWallet.
	const messages = [
		new TextEncoder().encode('first-message'),
		new TextEncoder().encode('second-message'),
	];
	const presigns = await Promise.all(
		messages.map(() =>
			ika.sui.requestGlobalPresign({
				curve: Curve.ED25519,
				signatureAlgorithm: SignatureAlgorithm.EdDSA,
			}),
		),
	);

	// Now compose both signs into one Sui transaction. `ika.sui.compose.sign`
	// adds a sign Move call to the in-flight IkaTransaction; the plugin
	// transfers leftover fee coins back to the signer after the callback
	// returns and executes the tx in one shot.
	const { exec } = await ika.sui.transaction(async ({ ikaTx, pay }) => {
		for (let i = 0; i < messages.length; i++) {
			const { ika: ikaCoin, sui: suiCoin } = pay();
			await ika.sui.compose.sign({
				ikaTx,
				dWallet,
				message: messages[i],
				curve: Curve.ED25519,
				signatureAlgorithm: SignatureAlgorithm.EdDSA,
				hash: Hash.SHA512,
				presign: presigns[i],
				ikaCoin,
				suiCoin,
			});
		}
	});

	console.log('PTB digest:', exec.digest);
});
