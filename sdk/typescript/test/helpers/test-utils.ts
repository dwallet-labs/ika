// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import fs from 'fs';
import path from 'path';
import { toHex } from '@mysten/bcs';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { getFaucetHost, requestSuiFromFaucetV2 } from '@mysten/sui/faucet';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Secp256k1Keypair } from '@mysten/sui/keypairs/secp256k1';
import type { Transaction, TransactionObjectArgument } from '@mysten/sui/transactions';
import { randomBytes } from '@noble/hashes/utils.js';
import { expect } from 'vitest';

import { IkaClient } from '../../src/client/ika-client.js';
import { IkaTransaction } from '../../src/client/ika-transaction.js';
import { getNetworkConfig } from '../../src/client/network-configs.js';
import {
	Curve,
	Hash,
	IkaConfig,
	SignatureAlgorithm,
	ZeroTrustDWallet,
} from '../../src/client/types.js';
import { UserShareEncryptionKeys } from '../../src/client/user-share-encryption-keys.js';
import { createCompleteDWallet, testPresign, testSign } from './dwallet-test-helpers';

// Store random seeds per test to ensure deterministic behavior within each test
const testSeeds = new Map<string, Uint8Array>();

export async function getObjectWithType<TObject>(
	suiClient: SuiClient,
	objectID: string,
	isObject: (obj: any) => obj is TObject,
): Promise<TObject> {
	let timeout = 600_000; // Default timeout of 10 minutes
	const startTime = Date.now();
	while (Date.now() - startTime <= timeout) {
		// Wait for a bit before polling again, objects might not be available immediately.
		const interval = 1;
		await delay(interval);
		const res = await suiClient.getObject({
			id: objectID,
			options: { showContent: true },
		});

		const objectData =
			res.data?.content?.dataType === 'moveObject' && isObject(res.data.content.fields)
				? (res.data.content.fields as TObject)
				: null;

		if (objectData) {
			return objectData;
		}
	}
	const seconds = ((Date.now() - startTime) / 1000).toFixed(2);
	throw new Error(
		`timeout: unable to fetch an object within ${
			timeout / (60 * 1000)
		} minutes (${seconds} seconds passed).`,
	);
}

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
		url: process.env.SUI_TESTNET_URL || getFullnodeUrl('localnet'),
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
				host: process.env.SUI_FAUCET_URL || getFaucetHost('localnet'),
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

export function findIkaConfigFile(): string {
	const possiblePaths = [
		// Current working directory
		'ika_config.json',
		// One level up
		'../ika_config.json',
		// Two levels up (current hardcoded path)
		'../../ika_config.json',
		// Three levels up
		'../../../ika_config.json',
		// From environment variable if set
		...(process.env.IKA_CONFIG_PATH ? [process.env.IKA_CONFIG_PATH] : []),
		// From project root (assuming we're in sdk/typescript/src/client/)
		path.resolve(__dirname, '../../../../ika_config.json'),
		// From workspace root (assuming we're in sdk/typescript/)
		path.resolve(__dirname, '../../../ika_config.json'),
	];

	for (const configPath of possiblePaths) {
		try {
			const resolvedPath = path.resolve(configPath);
			if (fs.existsSync(resolvedPath)) {
				return resolvedPath;
			}
		} catch {
			// Continue to next path if this one fails
			continue;
		}
	}

	throw new Error(
		`Could not find ika_config.json file. Tried the following locations:\n` +
			`${possiblePaths.map((p) => `  - ${p}`).join('\n')}\n\n` +
			`Please ensure the file exists in one of these locations, or set the IKA_CONFIG_PATH environment variable.`,
	);
}

/**
 * Creates an IkaClient for testing
 */
export function createTestIkaClient(suiClient: SuiClient): IkaClient {
	const configPath = findIkaConfigFile();
	const parsedJson = JSON.parse(fs.readFileSync(configPath, 'utf8'));

	return new IkaClient({
		suiClient,
		config: {
			packages: {
				ikaPackage: parsedJson.packages.ika_package_id,
				ikaCommonPackage: parsedJson.packages.ika_common_package_id,
				ikaDwallet2pcMpcPackage: parsedJson.packages.ika_dwallet_2pc_mpc_package_id,
				ikaSystemPackage: parsedJson.packages.ika_system_package_id,
			},
			objects: {
				ikaSystemObject: {
					objectID: parsedJson.objects.ika_system_object_id,
					initialSharedVersion: 0,
				},
				ikaDWalletCoordinator: {
					objectID: parsedJson.objects.ika_dwallet_coordinator_object_id,
					initialSharedVersion: 0,
				},
			},
		},
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

	return await executeTestTransactionWithKeypair(suiClient, transaction, signerKeypair);
}

/**
 * Executes a transaction with deterministic signing using a provided keypair.
 */
export async function executeTestTransactionWithKeypair(
	suiClient: SuiClient,
	transaction: Transaction,
	signerKeypair: Ed25519Keypair,
) {
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
export async function generateTestKeypair(testName: string) {
	const seed = createDeterministicSeed(testName);
	const userKeypair = Ed25519Keypair.deriveKeypairFromSeed(toHex(seed));

	const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
		seed,
		Curve.SECP256K1,
	);

	return {
		userShareEncryptionKeys,
		signerAddress: userKeypair.getPublicKey().toSuiAddress(),
		signerPublicKey: userKeypair.getPublicKey().toRawBytes(),
		userKeypair,
	};
}

/**
 * Generates deterministic keypair for Imported Key DWallet testing
 */
export async function generateTestKeypairForImportedKeyDWallet(testName: string) {
	const seed = createDeterministicSeed(testName);
	const userKeypair = Ed25519Keypair.deriveKeypairFromSeed(toHex(seed));

	const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
		seed,
		Curve.SECP256K1,
	);
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

export function delay(seconds: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, seconds * 1000));
}

export async function runSignFullFlow(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	testName: string,
) {
	const {
		dWallet: activeDWallet,
		encryptedUserSecretKeyShare,
		userShareEncryptionKeys,
		signerAddress,
	} = await createCompleteDWallet(ikaClient, suiClient, testName);

	// Step 2: Create presign
	const presignRequestEvent = await testPresign(
		ikaClient,
		suiClient,
		activeDWallet,
		SignatureAlgorithm.ECDSA,
		signerAddress,
		testName,
	);

	expect(presignRequestEvent).toBeDefined();
	expect(presignRequestEvent.event_data.presign_id).toBeDefined();

	// Step 3: Wait for presign to complete
	const presignObject = await retryUntil(
		() =>
			ikaClient.getPresignInParticularState(presignRequestEvent.event_data.presign_id, 'Completed'),
		(presign) => presign !== null,
		30,
		2000,
	);

	expect(presignObject).toBeDefined();
	expect(presignObject.state.$kind).toBe('Completed');

	// Step 4: Sign a message
	const message = createTestMessage(testName);
	await testSign(
		ikaClient,
		suiClient,
		activeDWallet as ZeroTrustDWallet,
		userShareEncryptionKeys,
		presignObject,
		encryptedUserSecretKeyShare,
		message,
		Hash.KECCAK256,
		SignatureAlgorithm.ECDSA,
		testName,
	);
}

export async function waitForEpochSwitch(ikaClient: IkaClient) {
	const startEpoch = await ikaClient.getEpoch();
	let epochSwitched = false;
	while (!epochSwitched) {
		if ((await ikaClient.getEpoch()) > startEpoch) {
			epochSwitched = true;
		} else {
			await delay(5);
		}
	}
}
