import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { describe, it } from 'vitest';

import { testCreateNetworkKey } from '../helpers/network-dkg-test-helpers';
import { createTestIkaClient, createTestSuiClient } from '../helpers/test-utils';

describe('Network keys creation tests', () => {
	it('should create a network key', async () => {
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		const publisherMnemonic =
			'spatial crunch gloom joy during vapor hold genius gold fold athlete glide';

		let publisherKeypair = Ed25519Keypair.deriveKeypair(publisherMnemonic);
		const keyID = await testCreateNetworkKey(
			suiClient,
			'0xf70a9cc2d1c5c6a2e90ec25f930da6610fc932b99e150337b9f832f1eeddd977',
			publisherKeypair,
		);
		console.log({ keyID });
	});
});
