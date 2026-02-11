import { Curve } from '@ika.xyz/sdk';
import { toHex } from '@mysten/sui/utils';
import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';

import { computeKeysWithWorker } from '../workers/api';

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
			return await computeKeysWithWorker();
		},
		// Cache indefinitely since the keys are deterministic
		staleTime: Infinity,
		gcTime: Infinity,
		// Start loading immediately when the hook is mounted
		enabled: true,
	});
};
