// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { SuiClient } from '@mysten/sui/client';

import type { IkaClient } from '../../src/client/ika-client.js';
import type { UserShareEncryptionKeys } from '../../src/client/user-share-encryption-keys.js';
import { createTestIkaClient, createTestSuiClient, generateTestKeypair } from './test-utils.js';

// Shared test instances to reduce memory usage across all tests
export class SharedTestSetup {
	private static instance: SharedTestSetup | null = null;
	public suiClient: SuiClient | null = null;
	public ikaClient: IkaClient | null = null;
	public sharedKeypairs: Map<string, ReturnType<typeof generateTestKeypair>> = new Map();
	private initialized = false;

	private constructor() {}

	/**
	 * Get the singleton instance of SharedTestSetup
	 */
	public static getInstance(): SharedTestSetup {
		if (!SharedTestSetup.instance) {
			SharedTestSetup.instance = new SharedTestSetup();
		}
		return SharedTestSetup.instance;
	}

	/**
	 * Initialize shared test instances
	 */
	public async initialize(): Promise<void> {
		if (this.initialized) {
			return;
		}

		// Create shared SuiClient and IkaClient
		this.suiClient = createTestSuiClient();
		this.ikaClient = createTestIkaClient(this.suiClient);
		await this.ikaClient.initialize();

		this.initialized = true;
	}

	/**
	 * Get or create a shared keypair for a test
	 */
	public getSharedKeypair(testName: string): ReturnType<typeof generateTestKeypair> {
		if (!this.sharedKeypairs.has(testName)) {
			this.sharedKeypairs.set(testName, generateTestKeypair(testName));
		}
		return this.sharedKeypairs.get(testName)!;
	}

	/**
	 * Get shared SuiClient instance
	 */
	public getSuiClient(): SuiClient {
		if (!this.suiClient) {
			throw new Error('SharedTestSetup not initialized. Call initialize() first.');
		}
		return this.suiClient;
	}

	/**
	 * Get shared IkaClient instance
	 */
	public getIkaClient(): IkaClient {
		if (!this.ikaClient) {
			throw new Error('SharedTestSetup not initialized. Call initialize() first.');
		}
		return this.ikaClient;
	}

	/**
	 * Check if the setup is initialized
	 */
	public isInitialized(): boolean {
		return this.initialized;
	}

	/**
	 * Clear all shared instances (for cleanup)
	 */
	public cleanup(): void {
		this.suiClient = null;
		this.ikaClient = null;
		this.sharedKeypairs.clear();
		this.initialized = false;
	}

	/**
	 * Reset the singleton instance (mainly for testing)
	 */
	public static reset(): void {
		if (SharedTestSetup.instance) {
			SharedTestSetup.instance.cleanup();
		}
		SharedTestSetup.instance = null;
	}
}

/**
 * Helper function to get shared test setup
 */
export async function getSharedTestSetup(): Promise<SharedTestSetup> {
	const setup = SharedTestSetup.getInstance();
	if (!setup.isInitialized()) {
		await setup.initialize();
	}
	return setup;
}

/**
 * Helper function for tests that need individual instances (for gas-consuming operations)
 */
export async function createIndividualTestSetup(testName: string) {
	const sharedSetup = await getSharedTestSetup();
	const { userShareEncryptionKeys, signerAddress, signerPublicKey, userKeypair } =
		await sharedSetup.getSharedKeypair(testName);

	return {
		suiClient: sharedSetup.getSuiClient(),
		ikaClient: sharedSetup.getIkaClient(),
		userShareEncryptionKeys,
		signerAddress,
		signerPublicKey,
		userKeypair,
	};
}
