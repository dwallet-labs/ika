// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Ethereum signing via the destination plugin. The dWallet's secp256k1 key
 * acts as an Ethereum account: derives the address, signs an EIP-1559
 * transaction, and (optionally) broadcasts via the publisher.
 *
 *   $ pnpm sign-ethereum
 *
 * Three sign modes are supported by `ika.ethereum.sign`:
 *   - `kind: 'transaction'`  EIP-1559 / EIP-2930 / legacy tx → serialized signed bytes
 *   - `kind: 'message'`      EIP-191 personal_sign           → 65-byte signature hex
 *   - `kind: 'typedData'`    EIP-712 typed data              → 65-byte signature hex
 *
 * Cross-chain: source is still Sui (the network that runs the MPC). Only the
 * signing target chain is Ethereum.
 */

import { type Hex } from 'viem';
import { sepolia } from 'viem/chains';
import { Curve } from '@ika.xyz/sdk';
import { IkaClient } from '@ika.xyz/sdk/plugin';
import { suiSource } from '@ika.xyz/plugins/sui/source';
import { eth } from '@ika.xyz/plugins/ethereum/destination';
import { ethPublisher } from '@ika.xyz/plugins/ethereum/publisher';
import { loadEnv, loadUseks, run } from './shared.js';

run('Ethereum sign + broadcast (SECP256K1 shared dWallet)', async () => {
	const { signer, suiClient } = loadEnv();
	const useks = await loadUseks(Curve.SECP256K1);

	// Bring the ethereum destination + publisher into the client surface.
	const ika = new IkaClient()
		.use(
			suiSource({ network: 'testnet', signer, userShareEncryptionKeys: useks, suiClient }),
		)
		.use(eth())
		.use(
			ethPublisher({
				url: process.env.ETH_RPC_URL ?? 'https://rpc.sepolia.org',
				chain: sepolia,
				confirm: true,
				confirmations: 1,
			}),
		);

	const dWallet = await ika.sui.createDWallet({
		kind: 'shared',
		curve: Curve.SECP256K1,
	});
	const ethAddress = await dWallet.ethereum.getAddress();
	console.log('Ethereum address:', ethAddress);
	console.log('Fund this address with Sepolia ETH before broadcasting.');

	const signedMsg = await dWallet.ethereum.sign({
		kind: 'message',
		message: new TextEncoder().encode('hello via ika'),
	});
	if (signedMsg.payload.kind !== 'message') throw new Error('unreachable');
	console.log('personal_sign signature:', signedMsg.payload.signature);

	if (!process.env.ETH_BROADCAST) {
		console.log('Set ETH_BROADCAST=1 to also sign + broadcast a Sepolia self-transfer.');
		return;
	}

	const signedTx = await dWallet.ethereum.sign({
		kind: 'transaction',
		tx: {
			type: 'eip1559',
			chainId: sepolia.id,
			nonce: 0, // bump per real flow; fetch via your RPC
			to: ethAddress,
			value: 1n,
			maxFeePerGas: 50_000_000_000n,
			maxPriorityFeePerGas: 2_000_000_000n,
			gas: 21_000n,
		},
	});
	if (signedTx.payload.kind !== 'transaction') throw new Error('unreachable');
	console.log('signed tx hash:', signedTx.payload.hash);

	const txHash: Hex = await ika.publish({ chain: 'ethereum', payload: signedTx.payload });
	console.log('broadcast tx hash:', txHash);
});
