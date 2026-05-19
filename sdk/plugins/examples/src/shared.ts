// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Shared bootstrap used by every example. Builds a typed `IkaClient` with the
 * Sui source and both Sui and Solana destinations + publishers wired in.
 *
 * Configure via env vars:
 *
 *   IKA_TESTNET_PRIVATE_KEY   bech32 `suiprivkey...` for the Sui signer
 *   IKA_USEK_SEED             arbitrary string used to derive the USEK
 *                             (deterministic; same seed gives the same dWallet
 *                             encryption keys across runs)
 *   SUI_RPC_URL               optional override for the Sui RPC endpoint
 *   SOLANA_RPC_URL            optional override for the Solana RPC endpoint
 */

import { getJsonRpcFullnodeUrl, SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Curve, UserShareEncryptionKeys } from '@ika.xyz/sdk';
import { IkaClient } from '@ika.xyz/sdk/plugin';
import { suiSource } from '@ika.xyz/plugins/sui/source';
import { sui } from '@ika.xyz/plugins/sui/destination';
import { suiPublisher } from '@ika.xyz/plugins/sui/publisher';
import { solana } from '@ika.xyz/plugins/solana/destination';
import { solanaDevnet } from '@ika.xyz/plugins/solana/publisher';

export interface ExampleEnv {
	readonly signer: Ed25519Keypair;
	readonly suiClient: SuiJsonRpcClient;
}

export function loadEnv(): ExampleEnv {
	const privateKey = required('IKA_TESTNET_PRIVATE_KEY');
	const signer = Ed25519Keypair.fromSecretKey(privateKey);
	const suiClient = new SuiJsonRpcClient({
		url: process.env.SUI_RPC_URL ?? getJsonRpcFullnodeUrl('testnet'),
		network: 'testnet',
	});
	return { signer, suiClient };
}

/**
 * Build the user-share encryption keys for a given curve. Deterministic in the
 * seed: re-running with the same seed reproduces the same dWallet keys, which
 * is useful for examples that need to find a previously created dWallet.
 */
export async function loadUseks(curve: Curve): Promise<UserShareEncryptionKeys> {
	const seed = required('IKA_USEK_SEED');
	return UserShareEncryptionKeys.fromRootSeedKey(new TextEncoder().encode(seed), curve);
}

/**
 * Returns a fully-wired client with all four default plugins installed. Source
 * is Sui (testnet); destinations cover both Sui and Solana; publishers cover
 * the Sui testnet RPC and Solana devnet.
 */
export async function buildIka(curve: Curve) {
	const { signer, suiClient } = loadEnv();
	const useks = await loadUseks(curve);
	return new IkaClient()
		.use(suiSource({ network: 'testnet', signer, userShareEncryptionKeys: useks, suiClient }))
		.use(sui())
		.use(suiPublisher({ suiClient }))
		.use(solana())
		.use(solanaDevnet({ confirm: true }));
}

function required(name: string): string {
	const v = process.env[name];
	if (!v) throw new Error(`Missing env var ${name}. See examples/README.md.`);
	return v;
}

/** Tiny wrapper so each example's `main()` shows up cleanly on the console. */
export async function run(label: string, fn: () => Promise<void>): Promise<void> {
	console.log(`\n=== ${label} ===\n`);
	const t0 = Date.now();
	try {
		await fn();
		console.log(`\nOK (${((Date.now() - t0) / 1000).toFixed(1)}s)`);
	} catch (err) {
		console.error(`\nFAILED: ${err instanceof Error ? err.message : String(err)}`);
		process.exit(1);
	}
}
