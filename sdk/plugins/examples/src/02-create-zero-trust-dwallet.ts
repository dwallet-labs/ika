// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Create a ZERO-TRUST dWallet (secp256k1). The user's secret share is
 * encrypted to their USEK and stored on chain. Every signing request must
 * include the encrypted share so the user-side party can be reconstructed —
 * the network alone cannot sign. Best fit for personal wallets / max
 * security.
 *
 *   $ pnpm zero-trust-dwallet
 *
 * The returned handle carries `encryptedShareId`, so downstream
 * `requestSign` / `sui.sign` / `solana.sign` calls work out of the box
 * without an explicit override.
 */

import { Curve } from '@ika.xyz/sdk';

import { buildIka, run } from './shared.js';

run('zero-trust dWallet (SECP256K1)', async () => {
	const ika = await buildIka(Curve.SECP256K1);

	const dWallet = await ika.sui.createDWallet({
		kind: 'zero-trust',
		curve: Curve.SECP256K1,
	});

	console.log('dWallet id:           ', dWallet.id);
	console.log('dWallet cap id:       ', dWallet.dWalletCapId);
	console.log('encrypted share id:   ', dWallet.encryptedShareId);
	console.log('derived Sui address:  ', await dWallet.sui.getAddress());

	// The handle is already decorated, so we can sign directly without
	// passing the encrypted share id explicitly — it travels on the handle.
	const message = new TextEncoder().encode('hello zero-trust');
	const signed = await dWallet.sui.sign({ kind: 'message', message });
	console.log('off-chain signature:  ', signed.payload.signature.slice(0, 24) + '...');
});
