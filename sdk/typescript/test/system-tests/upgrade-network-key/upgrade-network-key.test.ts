import fs from 'fs';
import path from 'path';
import { network_key_version } from '@ika.xyz/ika-wasm';
import { KubeConfig } from '@kubernetes/client-node';
import { execa } from 'execa';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
	createTestIkaClient,
	createTestSuiClient, delay,
	waitForEpochSwitch,
} from '../../helpers/test-utils';
import { deployIkaNetwork, NAMESPACE_NAME, TEST_ROOT_DIR } from '../globals';
import { createValidatorPod, killValidatorPod } from '../pods';

describe('system tests', () => {
	it('run a full flow test of upgrading the network key version and the move code', async () => {
		require('dotenv').config({ path: `${TEST_ROOT_DIR}/.env` });

		// ------------ Create Ika Genesis ------------
		const createIkaGenesisPath = `${TEST_ROOT_DIR}/create-ika-genesis-mac.sh`;
		await execa({
			stdout: ['pipe', 'inherit'],
			stderr: ['pipe', 'inherit'],
			cwd: TEST_ROOT_DIR,
		})`${createIkaGenesisPath}`;
		await fs.copyFile(
			`${TEST_ROOT_DIR}/${process.env.SUBDOMAIN}/publisher/ika_config.json`,
			path.resolve(process.cwd(), '../../ika_config.json'),
		);

		console.log(`Ika genesis created, deploying ika network`);
		console.log('Validators added to the next committee, deploying ika network');
		await deployIkaNetwork();
		console.log('Ika network deployed, waiting for epoch switch');
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();
		await waitForEpochSwitch(ikaClient);
		console.log('Epoch switched, verifying the network key version is V1');
		const networkKey = await ikaClient.getConfiguredNetworkEncryptionKey();
		let networkKeyBytes = await ikaClient.readTableVecAsRawBytes(networkKey.publicOutputID);
		const networkKeyVersion = network_key_version(networkKeyBytes);
		expect(networkKeyVersion).toBe(1);
		console.log('Network key version is V1, upgrading validators binaries to V2');
		process.env.DOCKER_TAG = 'us-docker.pkg.dev/common-449616/ika-common-containers/ika-node:v2key';
		const kc = new KubeConfig();
		kc.loadFromDefault();
		for (let i = 0; i < Number(process.env.VALIDATOR_NUM); i++) {
			await killValidatorPod(kc, NAMESPACE_NAME, i + 1);
			await delay(1);
			await createValidatorPod(kc, NAMESPACE_NAME, i + 1);
		}
		console.log('All validators upgraded, waiting for two epoch switches (the protocol version may have been changed after the epoch middle)');
		await waitForEpochSwitch(ikaClient);
		await waitForEpochSwitch(ikaClient);
		console.log('Two epochs switched, verifying the network key version is V2');
		networkKeyBytes = await ikaClient.readTableVecAsRawBytes(networkKey.publicOutputID);
		const newNetworkKeyVersion = network_key_version(networkKeyBytes);
		expect(newNetworkKeyVersion).toBe(2);

		// console.log('Ika network deployed, waiting for epoch switch');
	}, 3_600_000);
});
