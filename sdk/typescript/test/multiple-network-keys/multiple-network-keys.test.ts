import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { describe, it } from 'vitest';

import { testCreateNetworkKey } from '../helpers/network-dkg-test-helpers';
import { createTestIkaClient, createTestSuiClient, runSignFullFlow } from '../helpers/test-utils';

describe('Network keys creation tests', () => {
	it('should create a network key', async () => {
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		const publisherMnemonic =
			'dwarf cake vanish damage music express alter creek deal stomach favorite prosper';

		let publisherKeypair = Ed25519Keypair.deriveKeypair(publisherMnemonic);
		const keyID = await testCreateNetworkKey(
			suiClient,
			'0xf544325c13894dd444fb2f5becba917fd59de0ad2f50996b284793d7d6d3e173',
			publisherKeypair,
		);
		console.log({ keyID });
	});

	it('should create a network key and run a full flow with it', async () => {
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		const publisherMnemonic =
			'dwarf cake vanish damage music express alter creek deal stomach favorite prosper';

		let publisherKeypair = Ed25519Keypair.deriveKeypair(publisherMnemonic);
		const keyID = await testCreateNetworkKey(
			suiClient,
			'0xf544325c13894dd444fb2f5becba917fd59de0ad2f50996b284793d7d6d3e173',
			publisherKeypair,
		);

		ikaClient.encryptionKeyOptions.encryptionKeyID = keyID;
		await runSignFullFlow(ikaClient, suiClient, 'network-key-full-flow');
	});
});
