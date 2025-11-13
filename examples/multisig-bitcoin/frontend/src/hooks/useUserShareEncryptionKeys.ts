import { Curve, UserShareEncryptionKeys } from '@ika.xyz/sdk';
import { useQuery } from '@tanstack/react-query';
import * as Comlink from 'comlink';
import { useMemo } from 'react';

type WorkerApi = {
	computeKeys: (seed: string, curve: Curve) => Promise<number[]>;
};

// Cache the worker API to avoid recreating it
let cachedWorkerApi: WorkerApi | null = null;

/**
 * Creates and caches a Web Worker for computing keys off the main thread
 */
const getWorker = (): WorkerApi | null => {
	if (cachedWorkerApi) {
		return cachedWorkerApi;
	}

	if (typeof Worker === 'undefined') {
		return null;
	}

	try {
		// Create worker from the worker file
		// Next.js webpack will handle bundling this
		const worker = new Worker(new URL('../workers/computeKeys.worker.ts', import.meta.url), {
			type: 'module',
		});

		// Wrap with comlink to get a typed API
		cachedWorkerApi = Comlink.wrap<WorkerApi>(worker);
		return cachedWorkerApi;
	} catch (error) {
		console.warn('Failed to create Web Worker, falling back to main thread:', error);
		return null;
	}
};

/**
 * Computes keys using a Web Worker if available, otherwise falls back to main thread
 */
const computeKeysWithWorker = async (): Promise<UserShareEncryptionKeys> => {
	const workerApi = getWorker();

	if (!workerApi) {
		// Fallback: compute on main thread (will block but better than nothing)
		return await UserShareEncryptionKeys.fromRootSeedKey(
			new TextEncoder().encode('bitcoin_multisig_ika'),
			Curve.SECP256K1,
		);
	}

	try {
		// Compute in worker (truly off main thread)
		const serializedKeysArray = await workerApi.computeKeys(
			'bitcoin_multisig_ika',
			Curve.SECP256K1,
		);

		// Reconstruct on main thread (fast operation)
		const serializedBytes = new Uint8Array(serializedKeysArray);
		return UserShareEncryptionKeys.fromShareEncryptionKeysBytes(serializedBytes);
	} catch (error) {
		console.warn('Worker computation failed, falling back to main thread:', error);
		// Fallback to main thread
		return await UserShareEncryptionKeys.fromRootSeedKey(
			new TextEncoder().encode('bitcoin_multisig_ika'),
			Curve.SECP256K1,
		);
	}
};

/**
 * Pre-computes user share encryption keys when the app loads.
 * Uses a Web Worker to prevent blocking the main thread.
 */
export const useUserShareEncryptionKeys = () => {
	// Use a stable query key that doesn't depend on account
	// The keys are deterministic based on the seed, so we can cache them
	const queryKey = useMemo(() => ['userShareEncryptionKeys', Curve.SECP256K1], []);

	return useQuery({
		queryKey,
		queryFn: async () => {
			// Small delay to ensure UI renders first
			await new Promise((resolve) => setTimeout(resolve, 100));
			return computeKeysWithWorker();
		},
		// Cache indefinitely since the keys are deterministic
		staleTime: Infinity,
		gcTime: Infinity,
		// Start loading immediately when the hook is mounted
		enabled: true,
	});
};
