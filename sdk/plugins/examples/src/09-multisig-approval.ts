// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Demonstrates the `buildApproval` hook for non-standard authorization. The
 * default approval builder calls `ikaTx.approveMessage({ dWalletCap, ... })`
 * with the dWallet's own cap. When the cap lives elsewhere — held by a
 * multisig Move module, a custodial contract, a sponsored-approval flow —
 * pass a hook that returns the approval `TransactionObjectArgument` built
 * however your authorization model needs.
 *
 *   $ pnpm multisig-approval
 *
 * This example uses the standard `ikaTx.approveMessage` so it actually
 * runs, but the same hook shape is what you use to call your own Move
 * module that consumes a multisig vote and returns a MessageApproval.
 */

import { Curve, Hash, SignatureAlgorithm } from '@ika.xyz/sdk';
import { buildIka, run } from './shared.js';

run('custom buildApproval hook', async () => {
	const ika = await buildIka(Curve.ED25519);

	const dWallet = await ika.sui.createDWallet({
		kind: 'shared',
		curve: Curve.ED25519,
	});

	const message = new TextEncoder().encode('multisig-approved message');

	// Hook signature: (ikaTx, defaultCap) => TransactionObjectArgument.
	// `defaultCap` is the cap-id string the plugin would otherwise have used.
	// Replace with a tx.moveCall to your own approval-issuing module:
	//
	//   const approval = tx.moveCall({
	//     target: `${MY_PACKAGE}::multisig::approve_sign`,
	//     arguments: [tx.object(VOTE_REGISTRY), tx.pure.vector('u8', message)],
	//   });
	//   return approval;
	//
	// The example below delegates to the standard approval to keep the run
	// path green; swap it in your own integration.
	const signed = await dWallet.sui.sign({
		kind: 'message',
		message,
		buildApproval: (ikaTx, defaultCap) =>
			ikaTx.approveMessage({
				dWalletCap: defaultCap,
				curve: Curve.ED25519,
				signatureAlgorithm: SignatureAlgorithm.EdDSA,
				hashScheme: Hash.SHA512,
				message,
			}),
	});

	console.log('signed via custom approval hook:', signed.payload.signature.slice(0, 24) + '...');
});
