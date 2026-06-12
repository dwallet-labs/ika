// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * End-to-end Sui flow: build a `Transaction`, sign with the dWallet via
 * `ika.sui.sign`, then publish via `ika.publish({ chain: 'sui', payload })`.
 * The dWallet pays its own gas, so the address returned by
 * `dWallet.sui.getAddress()` needs SUI before this runs.
 *
 *   $ pnpm sign-sui
 */

import { Curve } from '@ika.xyz/sdk';
import { Transaction } from '@mysten/sui/transactions';

import { buildIka, loadEnv, run } from './shared.js';

run('sign + broadcast Sui transaction (Ed25519 shared dWallet)', async () => {
	const { suiClient } = loadEnv();
	const ika = await buildIka(Curve.ED25519);

	const dWallet = await ika.sui.createDWallet({
		kind: 'shared',
		curve: Curve.ED25519,
	});
	const sender = await dWallet.sui.getAddress();
	console.log('dWallet Sui address:', sender);
	console.log('fund this address with testnet SUI before continuing.');

	const tx = new Transaction();
	tx.setSender(sender);
	const [coin] = tx.splitCoins(tx.gas, [1]);
	tx.transferObjects([coin], sender);

	const signed = await dWallet.sui.sign({ kind: 'transaction', tx, suiClient });
	console.log('signed; broadcasting...');

	const digest = await ika.publish({ chain: 'sui', payload: signed.payload });
	console.log('digest:', digest);
});
