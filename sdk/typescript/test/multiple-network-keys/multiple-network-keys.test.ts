import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { describe, it } from 'vitest';

import { testCreateNetworkKey } from '../helpers/network-dkg-test-helpers';
import { createTestIkaClient, createTestSuiClient } from '../helpers/test-utils';

describe('Network keys creation tests', () => {
	it(async () => {
		const testName = 'network-key-creation-test';
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		const publisherMnemonic =
			'circle item cruel elegant rescue cluster bone before ecology rude comfort rare';

		let publisherKeypair = Ed25519Keypair.deriveKeypair(publisherMnemonic);
		const keyID = await testCreateNetworkKey(
			suiClient,
			'0x6c39e2381922a6fab197043992d162a694166517a665330d862bdecd68401281',
			testName,
		);
		console.log({ keyID });
	});
});
