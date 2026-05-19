// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Migrate an existing secp256k1 secret key into Ika as an IMPORTED-KEY
 * dWallet. The plain scalar is sent into the verification round once and is
 * never persisted in plaintext on chain — what gets stored is the encrypted
 * share owned by the user's USEK.
 *
 *   $ pnpm import-key
 *
 * Imported-key ECDSA cannot use the global presign pool; the example uses
 * `requestPresign({ dWallet, ... })` for a per-dWallet presign.
 */

import { Curve, Hash, SignatureAlgorithm } from '@ika.xyz/sdk';
import { secp256k1 } from '@noble/curves/secp256k1.js';

import { buildIka, run } from './shared.js';

run('imported-key dWallet (SECP256K1)', async () => {
	const ika = await buildIka(Curve.SECP256K1);

	// 0x20 prefix = `Vec<u8>` length tag for the 32-byte scalar.
	const scalar = secp256k1.utils.randomSecretKey();
	const importedKey = new Uint8Array([0x20, ...scalar]);

	const { dWallet, encryptedShareId } = await ika.sui.requestImportedKeyVerification({
		importedKey,
		curve: Curve.SECP256K1,
	});
	console.log('imported dWallet id:', dWallet.id);
	console.log('encrypted share id: ', encryptedShareId);

	// Imported-key ECDSA must use a per-dWallet presign (not the global pool).
	const presign = await ika.sui.requestPresign({
		dWallet,
		signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
	});

	const signed = await ika.sui.requestSign({
		dWallet,
		message: new TextEncoder().encode('imported-key sign'),
		curve: Curve.SECP256K1,
		signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
		hash: Hash.SHA256,
		presign,
	});
	console.log('signature length:   ', signed.signature.length);
});
