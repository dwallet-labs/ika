// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Bitcoin signing via the destination plugin. The dWallet's secp256k1 key
 * acts as a Bitcoin signer across all four spending modes the plugin
 * supports:
 *
 *   - `p2pkh`         legacy `1...` / `m...` address     — ECDSA + DoubleSHA256
 *   - `p2wpkh`        native segwit `bc1q...` / `tb1q...` — ECDSA + DoubleSHA256
 *   - `p2sh-p2wpkh`   nested segwit `3...` / `2...`      — ECDSA + DoubleSHA256
 *   - `p2tr-script`   taproot `bc1p...` / `tb1p...` script path
 *                                                       — Schnorr + SHA256
 *
 * Key-path Taproot is structurally unsupported: Ika MPC cannot tweak the
 * dWallet's internal key (BIP-341). The plugin uses a NUMS internal pubkey
 * for `p2tr-script` so the key path is provably unspendable.
 *
 *   $ pnpm sign-bitcoin
 *
 * Runs in two parts:
 *
 *   1. Derive an address for each mode and sign a sample preimage in each.
 *      `kind: 'preimage'` is the "I already have the sighash bytes" entry
 *      point — handy for handing the raw signature to whatever assembles
 *      the broadcast tx (Move multisig, web frontend, etc.).
 *
 *   2. Demonstrate the cross-signer pattern: a backend keypair funds the
 *      DKG and points the resulting `dWalletCap` at the user's address
 *      via `capRecipient`. The user then signs through
 *      `ika.sui.withSigner(userSigner)` — the same source, no second
 *      `IkaClient`. Set `IKA_TESTNET_USER_PRIVATE_KEY` to enable this
 *      section; otherwise it's skipped with a hint.
 *
 * Real PSBT-signing flows live in the multisig-bitcoin demo and in
 * `sdk/typescript/test/localnet/sui-source.localnet.test.ts`.
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
bitcoin.initEccLib(ecc as Parameters<typeof bitcoin.initEccLib>[0]);

import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Curve } from '@ika.xyz/sdk';
import { IkaClient } from '@ika.xyz/sdk/plugin';
import { suiSource } from '@ika.xyz/plugins/sui/source';
import { btc } from '@ika.xyz/plugins/bitcoin/destination';
import type { BitcoinMode } from '@ika.xyz/plugins/bitcoin/destination';

import { loadEnv, loadUseks, run } from './shared.js';

const ALL_MODES: ReadonlyArray<BitcoinMode> = [
	'p2pkh',
	'p2wpkh',
	'p2sh-p2wpkh',
	'p2tr-script',
];

run('Bitcoin sign across all four modes (+ cross-signer DKG/sign)', async () => {
	const { signer, suiClient } = loadEnv();
	const useks = await loadUseks(Curve.SECP256K1);

	const ika = new IkaClient()
		.use(suiSource({ network: 'testnet', signer, userShareEncryptionKeys: useks, suiClient }))
		.use(btc());

	// ----- Part 1: one dWallet, four modes, one signature per mode --------

	const dWallet = await ika.sui.createDWallet({
		kind: 'shared',
		curve: Curve.SECP256K1,
	});

	console.log('Addresses derived from one dWallet:');
	for (const mode of ALL_MODES) {
		const addr = await dWallet.bitcoin.getAddress({ mode, network: 'testnet' });
		console.log(`  ${mode.padEnd(15)} ${addr}`);
	}

	console.log('\nSignatures (preimage mode — bytes are illustrative):');
	for (const mode of ALL_MODES) {
		const preimage = new TextEncoder().encode(`example-sighash-${mode}`);
		const signed = await dWallet.bitcoin.sign({ kind: 'preimage', preimage, mode });
		if (signed.payload.kind !== 'preimage') throw new Error('unreachable');
		// ECDSA modes return a 64-byte (r || s) buffer; Taproot is a 64-byte
		// Schnorr signature. The plugin's PSBT mode adds the sighash flag /
		// DER encoding / witness packing — preimage mode returns the raw bytes.
		console.log(
			`  ${mode.padEnd(15)} ${signed.payload.signature.length}B  ` +
				Buffer.from(signed.payload.signature).toString('hex').slice(0, 32) +
				'…',
		);
	}

	// ----- Part 2: backend creates dWallet, user signs --------------------
	//
	// Real-world split-trust pattern: an operator/backend keypair funds the
	// DKG and routes the cap to the end user's Sui address. The user then
	// signs through the same `IkaClient` via `withSigner(userSigner)` —
	// reuses init state, USEK cache, and dWallet decoration without a second
	// plugin install.

	const userPrivateKey = process.env.IKA_TESTNET_USER_PRIVATE_KEY;
	if (!userPrivateKey) {
		console.log(
			'\n(Set IKA_TESTNET_USER_PRIVATE_KEY=suiprivkey... to also run the ' +
				'cross-signer demo: backend funds DKG, user signs.)',
		);
		return;
	}

	const userSigner = Ed25519Keypair.fromSecretKey(userPrivateKey);
	const userAddress = userSigner.getPublicKey().toSuiAddress();

	console.log('\nBackend creates a fresh shared dWallet whose cap goes to the user:');
	console.log(`  backend (DKG funder): ${signer.getPublicKey().toSuiAddress()}`);
	console.log(`  user    (cap owner):  ${userAddress}`);

	const userDWallet = await ika.sui.createDWallet({
		kind: 'shared',
		curve: Curve.SECP256K1,
		// Cap lands at the user's address instead of the backend's. The user
		// can now produce `MessageApproval`s and request signs without
		// needing the backend on every operation.
		capRecipient: userAddress,
	});
	console.log(`  dWallet cap: ${userDWallet.dWalletCapId} (owned by ${userAddress})`);

	// Re-bind the source so subsequent tx submissions come from the user.
	// Same IkaClient — destination plugins (btc) still decorate the dWallet
	// the same way; only `signAndExecute` and `signerAddress` swap.
	const userView = ika.sui.withSigner(userSigner);
	const reFetched = await userView.getDWallet(userDWallet.dWalletId);

	const preimage = new TextEncoder().encode('signed-by-user-after-backend-dkg');
	const signedByUser = await reFetched.bitcoin.sign({
		kind: 'preimage',
		preimage,
		mode: 'p2tr-script',
	});
	if (signedByUser.payload.kind !== 'preimage') throw new Error('unreachable');
	console.log(
		'  p2tr-script signature produced under the user signer:',
		Buffer.from(signedByUser.payload.signature).toString('hex').slice(0, 32) + '…',
	);
});
