// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * `createDWallet({ kind: 'imported-key-shared' })` bundles verify + reveal.
 * If the reveal step fails after verify succeeds the dWallet is preserved
 * as a regular imported-key handle, and the failure is surfaced as
 * `ImportedKeySharedPartialError`. The error object carries:
 *
 *   - `verifiedDWallet`  the already-verified imported-key dWallet handle
 *   - `cause`            the underlying failure
 *   - `retryReveal()`    re-runs only the reveal step (acknowledgement is
 *                        carried over from the bundled call)
 *
 * This pattern means recovery does NOT require persisting any extra state:
 * just catch the error and call `retryReveal()` until it succeeds.
 *
 *   $ pnpm recovery
 *
 * For the lower-level case where a regular `requestDKG` or
 * `requestImportedKeyVerification` leaves a dWallet in
 * `AwaitingKeyHolderSignature`, use `ika.sui.acceptEncryptedShare(...)`
 * instead. That path requires the original `userPublicOutput` and
 * `encryptedShareId`, so persist both alongside the dWallet id at DKG time.
 */

import { ImportedKeySharedPartialError } from '@ika.xyz/plugins/sui/source';
import { Curve } from '@ika.xyz/sdk';
import { secp256k1 } from '@noble/curves/secp256k1.js';

import { buildIka, run } from './shared.js';

run('recover a partial imported-key-shared DKG', async () => {
	const ika = await buildIka(Curve.SECP256K1);

	const scalar = secp256k1.utils.randomSecretKey();
	const importedKey = new Uint8Array([0x20, ...scalar]);

	try {
		const dWallet = await ika.sui.createDWallet({
			kind: 'imported-key-shared',
			curve: Curve.SECP256K1,
			importedKey,
			acknowledge: 'i-understand-this-is-irreversible',
		});
		console.log('happy path — dWallet went Active:', dWallet.id);
	} catch (err) {
		if (err instanceof ImportedKeySharedPartialError) {
			console.log('partial DKG. verified dWallet preserved at:', err.verifiedDWallet.id);
			console.log('cause:', err.cause);
			console.log('retrying only the reveal step...');
			const dWallet = await err.retryReveal();
			console.log('recovered to:', dWallet.id, '(kind:', dWallet.kind + ')');
		} else {
			throw err;
		}
	}
});
