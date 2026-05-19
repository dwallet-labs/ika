// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Create a SHARED dWallet (Ed25519). The user's secret share is published on
 * chain, so the network can sign autonomously — no per-call user participation
 * required. Best fit for DAOs, contracts, automation, and any flow where the
 * dWallet acts on behalf of multiple holders.
 *
 *   $ pnpm shared-dwallet
 */

import { Curve } from '@ika.xyz/sdk';
import { buildIka, run } from './shared.js';

run('shared dWallet (ED25519)', async () => {
	const ika = await buildIka(Curve.ED25519);

	const dWallet = await ika.sui.createDWallet({
		kind: 'shared',
		curve: Curve.ED25519,
	});

	console.log('dWallet id:        ', dWallet.id);
	console.log('dWallet cap id:    ', dWallet.dWalletCapId);
	console.log('kind:              ', dWallet.kind);
	console.log('curve:             ', dWallet.curve);
	console.log('derived Sui addr:  ', await dWallet.sui.getAddress());
	console.log('derived Solana key:', await dWallet.solana.getAddress());
});
