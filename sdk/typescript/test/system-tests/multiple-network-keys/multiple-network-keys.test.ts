import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { describe, it } from 'vitest';

import { testCreateNetworkKey } from '../../helpers/network-dkg-test-helpers';
import {
	createTestIkaClient,
	createTestSuiClient,
	runSignFullFlowWithV1Dwallet,
	waitForEpochSwitch,
} from '../../helpers/test-utils';

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
		await runSignFullFlowWithV1Dwallet(ikaClient, suiClient, 'network-key-full-flow');
	});

	it(
		'create multiple network keys and run multiple full flows with each of them',
		async () => {
			// IMPORTANT: Update with values from your Ika chain before running the test.
			// The publisher mnemonic can be fetched from the publisher logs while it deploys the Ika network,
			// and the protocol Cap ID is one of the objects owned by it with the type `ProtocolCap`.
			const protocolCapID = '0xf544325c13894dd444fb2f5becba917fd59de0ad2f50996b284793d7d6d3e173';
			const publisherMnemonic =
				'dwarf cake vanish damage music express alter creek deal stomach favorite prosper';

			let publisherKeypair = Ed25519Keypair.deriveKeypair(publisherMnemonic);

			const numOfNetworkKeys = 2;
			const flowsPerKey = 2;
			const suiClient = createTestSuiClient();
			const ikaClient = createTestIkaClient(suiClient);
			// First wait for an epoch switch, to avoid creating the keys in the second half of the epoch.
			await waitForEpochSwitch(ikaClient);
			const keys: string[] = [];
			for (let i = 0; i < numOfNetworkKeys; i++) {
				const networkKeyID = await testCreateNetworkKey(suiClient, protocolCapID, publisherKeypair);
				keys.push(networkKeyID);
			}
			await waitForEpochSwitch(ikaClient);
			console.log('Epoch switched, start running full flows');
			const tasks = keys
				.map((networkKeyID) =>
					Array(flowsPerKey)
						.fill(null)
						.map(async (_, index) => {
							return runFullFlowTestWithNetworkKey(
								networkKeyID,
								`${networkKeyID}-${index.toString()}`,
							);
						}),
				)
				.flat();
			await Promise.all(tasks);
		},
		60 * 1000 * 60 * 4,
	);
});

export async function runFullFlowTestWithNetworkKey(networkKeyID: string, nameSuffix = '') {
	const suiClient = createTestSuiClient();
	const ikaClient = createTestIkaClient(suiClient);
	await ikaClient.initialize();
	ikaClient.encryptionKeyOptions.encryptionKeyID = networkKeyID;
	await runSignFullFlowWithV1Dwallet(ikaClient, suiClient, `network-key-full-flow-${nameSuffix}`);
}
