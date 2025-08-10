// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { toHex } from '@mysten/bcs';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { getFaucetHost, requestSuiFromFaucetV2 } from '@mysten/sui/faucet';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Secp256k1Keypair } from '@mysten/sui/keypairs/secp256k1';
import type { Transaction, TransactionObjectArgument } from '@mysten/sui/transactions';
import { randomBytes } from '@noble/hashes/utils.js';

import { IkaClient } from '../../src/client/ika-client.js';
import { IkaTransaction } from '../../src/client/ika-transaction.js';
import { getNetworkConfig } from '../../src/client/network-configs.js';
import type { IkaConfig } from '../../src/client/types.js';
import { UserShareEncryptionKeys } from '../../src/client/user-share-encryption-keys.js';

// Store random seeds per test to ensure deterministic behavior within each test
const testSeeds = new Map<string, Uint8Array>();

/**
 * Creates a deterministic seed for a test.
 * Each test gets a random seed when first called, but subsequent calls for the same test
 * return the same seed to ensure deterministic behavior within the test.
 */
export function createDeterministicSeed(testName: string): Uint8Array {
	if (!testSeeds.has(testName)) {
		// Generate a random seed for this test on first call
		const randomSeed = new Uint8Array(randomBytes(32));
		testSeeds.set(testName, randomSeed);
	}
	return testSeeds.get(testName)!;
}

/**
 * Clears the stored seed for a test (useful for cleanup)
 */
export function clearTestSeed(testName: string): void {
	testSeeds.delete(testName);
}

/**
 * Clears all stored test seeds
 */
export function clearAllTestSeeds(): void {
	testSeeds.clear();
}

/**
 * Creates a SuiClient for testing
 */
export function createTestSuiClient(): SuiClient {
	return new SuiClient({
		url: getFullnodeUrl('localnet'),
	});
}

/**
 * Requests funds from the faucet for a given address
 */
export async function requestTestFaucetFunds(address: string): Promise<void> {
	const maxRetries = 3;
	const baseDelay = 5000; // 5 seconds

	for (let attempt = 1; attempt <= maxRetries; attempt++) {
		try {
			await requestSuiFromFaucetV2({
				host: getFaucetHost('localnet'),
				recipient: address,
			});

			// Add a small delay to allow the faucet transaction to propagate
			await sleep(2000);
			return;
		} catch (error: any) {
			if (error.message?.includes('Too many requests') || error.name === 'FaucetRateLimitError') {
				const delay = baseDelay * attempt; // Exponential backoff
				console.warn(
					`⏳ Faucet rate limit hit for ${address}. Waiting ${delay / 1000}s before retry ${attempt}/${maxRetries}...`,
				);

				if (attempt < maxRetries) {
					await sleep(delay);
					continue;
				} else {
					console.warn(
						`❌ Failed to fund ${address} after ${maxRetries} attempts. Proceeding without funds.`,
					);
					return;
				}
			} else {
				console.warn(`❌ Faucet error for ${address}:`, error.message);
				return;
			}
		}
	}
}

/**
 * Creates an IkaClient for testing
 */
export function createTestIkaClient(suiClient: SuiClient): IkaClient {
	return new IkaClient({
		suiClient,
		network: 'localnet',
		config: getNetworkConfig('localnet'),
	});
}

/**
 * Executes a transaction with deterministic signing
 */
export async function executeTestTransaction(
	suiClient: SuiClient,
	transaction: Transaction,
	testName: string,
) {
	const seed = createDeterministicSeed(testName);
	const signerKeypair = Ed25519Keypair.deriveKeypairFromSeed(toHex(seed));

	return suiClient.signAndExecuteTransaction({
		transaction,
		signer: signerKeypair,
		options: {
			showEvents: true,
		},
	});
}

/**
 * Generates deterministic keypair for testing
 */
export function generateTestKeypair(testName: string) {
	const seed = createDeterministicSeed(testName);
	const userKeypair = Ed25519Keypair.deriveKeypairFromSeed(toHex(seed));

	const userShareEncryptionKeys = UserShareEncryptionKeys.fromRootSeedKey(seed);

	return {
		userShareEncryptionKeys,
		signerAddress: userKeypair.getPublicKey().toSuiAddress(),
		signerPublicKey: userKeypair.getPublicKey().toRawBytes(),
		userKeypair,
	};
}

/**
 * Generates deterministic keypair for imported DWallet testing
 */
export function generateTestKeypairForImportedDWallet(testName: string) {
	const seed = createDeterministicSeed(testName);
	const userKeypair = Ed25519Keypair.deriveKeypairFromSeed(toHex(seed));

	const userShareEncryptionKeys = UserShareEncryptionKeys.fromRootSeedKey(seed);
	const dWalletKeypair = Secp256k1Keypair.fromSeed(seed);

	return {
		userShareEncryptionKeys,
		dWalletKeypair,
		signerAddress: userKeypair.getPublicKey().toSuiAddress(),
		signerPublicKey: userKeypair.getPublicKey().toRawBytes(),
		userKeypair,
	};
}

/**
 * Creates an empty IKA token for transactions
 */
export function createEmptyTestIkaToken(tx: Transaction, ikaConfig: IkaConfig) {
	return tx.moveCall({
		target: `0x2::coin::zero`,
		arguments: [],
		typeArguments: [`${ikaConfig.packages.ikaPackage}::ika::IKA`],
	});
}

/**
 * Destroys an empty IKA token
 */
export function destroyEmptyTestIkaToken(
	tx: Transaction,
	ikaConfig: IkaConfig,
	ikaToken: TransactionObjectArgument,
) {
	return tx.moveCall({
		target: `0x2::coin::destroy_zero`,
		arguments: [ikaToken],
		typeArguments: [`${ikaConfig.packages.ikaPackage}::ika::IKA`],
	});
}

/**
 * Test helper for setting up a basic IkaTransaction
 */
export function createTestIkaTransaction(
	ikaClient: IkaClient,
	transaction: Transaction,
	userShareEncryptionKeys?: UserShareEncryptionKeys,
) {
	return new IkaTransaction({
		ikaClient,
		transaction,
		userShareEncryptionKeys,
	});
}

/**
 * Creates a deterministic message for testing
 */
export function createTestMessage(testName: string, suffix: string = ''): Uint8Array {
	const message = `test-message-${testName}${suffix}`;
	return new TextEncoder().encode(message);
}

/**
 * Sleep utility for tests
 */
export function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Retry utility for tests that need to wait for network state changes
 */
export async function retryUntil<T>(
	fn: () => Promise<T>,
	condition: (result: T) => boolean,
	maxAttempts: number = 30,
	delayMs: number = 1000,
): Promise<T> {
	for (let attempt = 1; attempt <= maxAttempts; attempt++) {
		try {
			const result = await fn();
			if (condition(result)) {
				return result;
			}
		} catch (error) {
			if (attempt === maxAttempts) {
				throw error;
			}
		}

		if (attempt < maxAttempts) {
			await sleep(delayMs);
		}
	}

	throw new Error(`Condition not met after ${maxAttempts} attempts`);
}

export const DEFAULT_TIMEOUT = 600_000; // 10 minutes

export function delay(seconds: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, seconds * 1000));
}
