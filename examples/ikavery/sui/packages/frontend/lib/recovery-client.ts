'use client';

import { RecoveryClient } from '@fesal-packages/ikavery-sui-sdk';
import { getNetworkConfig, IkaClient } from '@ika.xyz/sdk';
import type { ClientWithCoreApi } from '@mysten/sui/client';

import { env } from './env';

export function buildRecoveryClient(
	suiClient: ClientWithCoreApi,
	recoveryId: string,
): RecoveryClient {
	const ikaClient = new IkaClient({
		suiClient,
		config: getNetworkConfig(env.network),
		cache: true,
	});
	return new RecoveryClient({
		ikaClient,
		suiClient,
		ref: {
			packageId: env.recoveryPackageId,
			recoveryId,
			registryId: env.recoveryRegistryId,
		},
		rpId: env.rpId,
	});
}

export function buildIkaClient(suiClient: ClientWithCoreApi): IkaClient {
	return new IkaClient({
		suiClient,
		config: getNetworkConfig(env.network),
		cache: true,
	});
}
