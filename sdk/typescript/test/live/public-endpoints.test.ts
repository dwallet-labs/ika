// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { SuiGrpcClient } from '@mysten/sui/grpc';
import { describe, expect, test } from 'vitest';

import { IkaClient } from '../../src/client/ika-client.js';
import { getNetworkConfig } from '../../src/client/network-configs.js';
import { Curve } from '../../src/client/types.js';

/**
 * Read-only probe against the LIVE public Sui fullnodes of mainnet and testnet.
 *
 * It exists because the SDK can rot without a single line of it changing: the
 * transport it talks (public fullnodes dropped JSON-RPC), or the on-chain data
 * shape it decodes (a new versioned MPC output variant the bundled WASM does
 * not know) can move underneath a release. Both classes shipped broken for
 * months before a user reported them. Nothing here needs funds, a keypair, or
 * a localnet — it only reads.
 *
 * Failures are classified deliberately: a fullnode that is unreachable or
 * erroring at the transport level skips the assertion instead of failing it,
 * so a Sui-side outage does not turn into a red build on an unrelated PR. Any
 * error the SDK itself raises after the connection works is a hard failure.
 */

const NETWORKS = ['mainnet', 'testnet'] as const;

type Network = (typeof NETWORKS)[number];

const ATTEMPTS = 3;
const BACKOFF_MS = 5_000;

function baseUrlFor(network: Network): string {
	const override = process.env[`SUI_${network.toUpperCase()}_GRPC_URL`];
	return override || `https://fullnode.${network}.sui.io:443`;
}

/**
 * Distinguishes "the endpoint did not answer" from "the SDK could not handle
 * what it answered". Only the latter is a defect on our side.
 */
function isEndpointUnavailable(error: unknown): boolean {
	const text = [
		(error as Error)?.message,
		((error as Error)?.cause as Error)?.message,
		String(error),
	]
		.filter(Boolean)
		.join(' ')
		.toLowerCase();

	return [
		'fetch failed',
		'econnrefused',
		'econnreset',
		'enotfound',
		'etimedout',
		'socket hang up',
		'503',
		'502',
		'504',
		'unavailable',
		'deadline_exceeded',
		'too many requests',
	].some((marker) => text.includes(marker));
}

async function withRetries<T>(operation: () => Promise<T>): Promise<T> {
	let lastError: unknown;

	for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
		try {
			return await operation();
		} catch (error) {
			lastError = error;
			if (!isEndpointUnavailable(error) || attempt === ATTEMPTS) {
				throw error;
			}
			await new Promise((resolve) => setTimeout(resolve, BACKOFF_MS * attempt));
		}
	}

	throw lastError;
}

describe.each(NETWORKS)('public %s endpoint', (network) => {
	async function probe<T>(
		skip: (note?: string) => void,
		operation: (ikaClient: IkaClient) => Promise<T>,
	): Promise<T | undefined> {
		const suiClient = new SuiGrpcClient({ network, baseUrl: baseUrlFor(network) });
		const ikaClient = new IkaClient({ suiClient, config: getNetworkConfig(network), cache: true });

		try {
			return await withRetries(async () => {
				await ikaClient.initialize();
				return operation(ikaClient);
			});
		} catch (error) {
			if (isEndpointUnavailable(error)) {
				skip(`${network} fullnode unreachable: ${(error as Error).message}`);
				return undefined;
			}
			throw error;
		}
	}

	// Guards the transport: public fullnodes serve gRPC only, and `initialize()`
	// is where a wrong transport surfaces ("Method not found").
	test('initializes and reads the current epoch over gRPC', async ({ skip }) => {
		const epoch = await probe(skip, (ikaClient) => ikaClient.getEpoch());
		if (epoch === undefined) return;

		expect(epoch).toBeGreaterThan(0);
	});

	// Guards the decoders: the network encryption key and the protocol public
	// parameters derived from it are versioned MPC outputs, so a network that
	// starts emitting a newer variant than the bundled WASM understands breaks
	// every user-side dWallet operation while plain object reads still work.
	test('derives protocol public parameters from the live network key', async ({ skip }) => {
		const result = await probe(skip, async (ikaClient) => {
			const networkEncryptionKey = await ikaClient.getLatestNetworkEncryptionKey();
			const protocolPublicParameters = await ikaClient.getProtocolPublicParameters(
				undefined,
				Curve.SECP256K1,
			);
			return { networkEncryptionKey, protocolPublicParameters };
		});
		if (result === undefined) return;

		expect(result.networkEncryptionKey.id).toMatch(/^0x[0-9a-f]{64}$/);
		expect(result.protocolPublicParameters.length).toBeGreaterThan(0);
	});
});
