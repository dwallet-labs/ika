// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it, beforeAll } from 'vitest';

import {
	createClassGroupsKeypair,
	createRandomSessionIdentifier,
	sessionIdentifierDigest,
} from '../../src/client/cryptography';
import { initializeWasm } from '../../src/client/wasm-loader';
import { Curve } from '../../src/client/types';

// Benchmark configuration
const ITERATIONS = 10;
const WARMUP_ITERATIONS = 2;

interface BenchmarkResult {
	name: string;
	avgMs: number;
	minMs: number;
	maxMs: number;
	iterations: number;
}

async function benchmark(name: string, fn: () => Promise<void>, iterations: number = ITERATIONS): Promise<BenchmarkResult> {
	// Warmup
	for (let i = 0; i < WARMUP_ITERATIONS; i++) {
		await fn();
	}

	const times: number[] = [];
	for (let i = 0; i < iterations; i++) {
		const start = performance.now();
		await fn();
		const end = performance.now();
		times.push(end - start);
	}

	const avgMs = times.reduce((a, b) => a + b, 0) / times.length;
	const minMs = Math.min(...times);
	const maxMs = Math.max(...times);

	return { name, avgMs, minMs, maxMs, iterations };
}

function formatResult(result: BenchmarkResult): string {
	return `${result.name}: avg=${result.avgMs.toFixed(2)}ms, min=${result.minMs.toFixed(2)}ms, max=${result.maxMs.toFixed(2)}ms (${result.iterations} iterations)`;
}

describe('WASM Cryptography Benchmarks', () => {
	let wasmLoadTime: number;

	beforeAll(async () => {
		// Measure WASM loading time
		const start = performance.now();
		await initializeWasm();
		wasmLoadTime = performance.now() - start;
		console.log(`\n📦 WASM Module Load Time: ${wasmLoadTime.toFixed(2)}ms\n`);
	});

	it('should benchmark createClassGroupsKeypair for SECP256K1', async () => {
		const seed = new Uint8Array(32);
		crypto.getRandomValues(seed);

		const result = await benchmark(
			'createClassGroupsKeypair (SECP256K1)',
			async () => {
				await createClassGroupsKeypair(seed, Curve.SECP256K1);
			}
		);

		console.log(formatResult(result));
		expect(result.avgMs).toBeDefined();
	});

	it('should benchmark createClassGroupsKeypair for SECP256R1', async () => {
		const seed = new Uint8Array(32);
		crypto.getRandomValues(seed);

		const result = await benchmark(
			'createClassGroupsKeypair (SECP256R1)',
			async () => {
				await createClassGroupsKeypair(seed, Curve.SECP256R1);
			}
		);

		console.log(formatResult(result));
		expect(result.avgMs).toBeDefined();
	});

	it('should benchmark createClassGroupsKeypair for RISTRETTO', async () => {
		const seed = new Uint8Array(32);
		crypto.getRandomValues(seed);

		const result = await benchmark(
			'createClassGroupsKeypair (RISTRETTO)',
			async () => {
				await createClassGroupsKeypair(seed, Curve.RISTRETTO);
			}
		);

		console.log(formatResult(result));
		expect(result.avgMs).toBeDefined();
	});

	it('should benchmark createClassGroupsKeypair for ED25519', async () => {
		const seed = new Uint8Array(32);
		crypto.getRandomValues(seed);

		const result = await benchmark(
			'createClassGroupsKeypair (ED25519)',
			async () => {
				await createClassGroupsKeypair(seed, Curve.ED25519);
			}
		);

		console.log(formatResult(result));
		expect(result.avgMs).toBeDefined();
	});

	it('should benchmark sessionIdentifierDigest', async () => {
		const bytesToHash = new Uint8Array(32);
		const senderAddress = new Uint8Array(32);
		crypto.getRandomValues(bytesToHash);
		crypto.getRandomValues(senderAddress);

		const result = await benchmark(
			'sessionIdentifierDigest',
			async () => {
				sessionIdentifierDigest(bytesToHash, senderAddress);
			},
			100 // More iterations for fast operations
		);

		console.log(formatResult(result));
		expect(result.avgMs).toBeDefined();
	});

	it('should benchmark createRandomSessionIdentifier', async () => {
		const result = await benchmark(
			'createRandomSessionIdentifier',
			async () => {
				createRandomSessionIdentifier();
			},
			100
		);

		console.log(formatResult(result));
		expect(result.avgMs).toBeDefined();
	});

	it('should output summary', async () => {
		console.log('\n📊 Benchmark Summary:');
		console.log('==========================================');
		console.log(`WASM Load Time: ${wasmLoadTime.toFixed(2)}ms`);
		console.log('==========================================\n');
	});
});
