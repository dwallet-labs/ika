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
 * A failing assertion must mean "the SDK is broken", never "Sui had a bad
 * minute", and an outage must never be able to hide a real defect. Rather than
 * guess which of those two a failure was from its error text — every marker
 * that could match an outage can also appear inside a genuine SDK error, and
 * the SDK wraps transport errors in its own `NetworkError` besides — the probe
 * asks the endpoint directly: on failure it makes an independent, minimal gRPC
 * call, and only a fullnode that fails THAT turns the failure into a skip.
 */

const NETWORKS = ['mainnet', 'testnet'] as const;

type Network = (typeof NETWORKS)[number];

const ATTEMPTS = 3;
const BACKOFF_MS = 5_000;

/**
 * The gRPC transport's own `timeout` option only sets the `grpc-timeout`
 * request header, which a fullnode that never answers is free to ignore, and
 * `SuiGrpcClient` forwards only `baseUrl`/`fetchInit` to the transport anyway.
 * So the deadline has to be imposed here, or a hung endpoint would run until
 * undici's ~300s header timeout and blow the job's wall-clock budget.
 */
const OPERATION_DEADLINE_MS = 60_000;
const REACHABILITY_DEADLINE_MS = 10_000;

class DeadlineExceeded extends Error {
	constructor(label: string, ms: number) {
		super(`${label} exceeded ${ms}ms`);
		this.name = 'DeadlineExceeded';
	}
}

function baseUrlFor(network: Network): string {
	const override = process.env[`SUI_${network.toUpperCase()}_GRPC_URL`];
	return override || `https://fullnode.${network}.sui.io:443`;
}

async function withDeadline<T>(label: string, ms: number, run: () => Promise<T>): Promise<T> {
	let timer: ReturnType<typeof setTimeout>;

	try {
		return await Promise.race([
			run(),
			new Promise<never>((_, reject) => {
				timer = setTimeout(() => reject(new DeadlineExceeded(label, ms)), ms);
			}),
		]);
	} finally {
		clearTimeout(timer!);
	}
}

/**
 * The oracle. `getServiceInfo` is the cheapest call the fullnode serves and
 * goes over the same transport as everything the probe does, so it answers
 * exactly one question: was the endpoint able to talk to us at all?
 */
async function isEndpointReachable(suiClient: SuiGrpcClient): Promise<boolean> {
	try {
		await withDeadline('reachability check', REACHABILITY_DEADLINE_MS, async () => {
			await suiClient.ledgerService.getServiceInfo({});
		});
		return true;
	} catch {
		return false;
	}
}

/** `skip()` throws a `PendingError`; the throw documents that and fires only if that ever changes. */
function skipRun(skip: (note?: string) => void, reason: string): never {
	skip(reason);
	throw new Error(`unreachable: vitest skip() is expected to throw (${reason})`);
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

describe.each(NETWORKS)('public %s endpoint', (network) => {
	async function probe<T>(
		skip: (note?: string) => void,
		operation: (ikaClient: IkaClient) => Promise<T>,
	): Promise<T> {
		for (let attempt = 1; ; attempt++) {
			const suiClient = new SuiGrpcClient({ network, baseUrl: baseUrlFor(network) });
			const ikaClient = new IkaClient({
				suiClient,
				config: getNetworkConfig(network),
				cache: true,
			});

			try {
				return await withDeadline(`${network} probe`, OPERATION_DEADLINE_MS, async () => {
					await ikaClient.initialize();
					return operation(ikaClient);
				});
			} catch (error) {
				// The endpoint answered, so whatever went wrong is ours.
				if (await isEndpointReachable(suiClient)) {
					throw error;
				}

				if (attempt === ATTEMPTS) {
					return skipRun(
						skip,
						`${network} fullnode unreachable after ${ATTEMPTS} attempts: ${(error as Error).message}`,
					);
				}

				await sleep(BACKOFF_MS * attempt);
			}
		}
	}

	// Guards the transport: public fullnodes serve gRPC only, and `initialize()`
	// is where a wrong transport surfaces ("Method not found").
	test('initializes and reads the current epoch over gRPC', async ({ skip }) => {
		const epoch = await probe(skip, (ikaClient) => ikaClient.getEpoch());

		expect(epoch).toBeGreaterThan(0);
	});

	// Guards the decoders: the network encryption key and the protocol public
	// parameters derived from it are versioned MPC outputs, so a network that
	// starts emitting a newer variant than the bundled WASM understands breaks
	// every user-side dWallet operation while plain object reads still work.
	test('derives protocol public parameters from the live network key', async ({ skip }) => {
		const { networkEncryptionKey, protocolPublicParameters } = await probe(
			skip,
			async (ikaClient) => ({
				networkEncryptionKey: await ikaClient.getLatestNetworkEncryptionKey(),
				protocolPublicParameters: await ikaClient.getProtocolPublicParameters(
					undefined,
					Curve.SECP256K1,
				),
			}),
		);

		expect(networkEncryptionKey.id).toMatch(/^0x[0-9a-f]{64}$/);
		expect(protocolPublicParameters.length).toBeGreaterThan(0);
	});
});
