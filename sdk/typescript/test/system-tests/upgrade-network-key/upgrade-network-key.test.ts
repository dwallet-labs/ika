import fs from 'fs';
import path from 'path';
import { network_key_version } from '@ika.xyz/ika-wasm';
import { KubeConfig } from '@kubernetes/client-node';
import { SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { execa } from 'execa';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
	createTestIkaClient,
	createTestSuiClient,
	delay,
	runSignFullFlowWithV1Dwallet,
	runSignFullFlowWithV2Dwallet,
	waitForEpochSwitch,
} from '../../helpers/test-utils';
import {
	deployUpgradedPackage,
	migrateCoordinator,
} from '../../move-upgrade/upgrade-ika-twopc-mpc.test';
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
		console.log(
			'All validators upgraded, waiting for two epoch switches (the protocol version may have been changed after the epoch middle)',
		);
		await waitForEpochSwitch(ikaClient);
		await waitForEpochSwitch(ikaClient);
		console.log('Two epochs switched, verifying the network key version is V2');
		networkKeyBytes = await ikaClient.readTableVecAsRawBytes(networkKey.publicOutputID);
		const newNetworkKeyVersion = network_key_version(networkKeyBytes);
		expect(newNetworkKeyVersion).toBe(2);
		console.log('Network key version is V2, verifying v1 dWallet full flow still works');
		await runSignFullFlowWithV1Dwallet(ikaClient, suiClient, `v1-dwallet-sign-full-flow-test`);
		console.log('V1 dWallet full flow works, upgrading the Move contracts to V2');
		const signer = Ed25519Keypair.deriveKeypair(
			'nature carry layer home plunge alter long space struggle ethics siege clerk',
		);
		const protocolCapID = '0xd7eef0703c67aebdc1651ba5a3e21881c8272626030f3324e79e1378c690d0af';
		const packagePath = '/root/code/dwallet-network/contracts/ika_dwallet_2pc_mpc';

		const upgradedPackageID = await deployUpgradedPackage(
			suiClient,
			signer,
			packagePath,
			ikaClient,
			protocolCapID,
		);
		await delay(5); // wait for the upgrade to be fully processed
		await migrateCoordinator(suiClient, signer, ikaClient, protocolCapID, upgradedPackageID);
		await delay(5); // wait for the migration to be fully processed
		console.log('Move contracts upgraded to V2, verifying v2 dWallet full flow works');
		await runSignFullFlowWithV2Dwallet(ikaClient, suiClient, `v2-dwallet-sign-full-flow-test`);
		console.log('V2 dWallet full flow works, test completed successfully');
	}, 3_600_000);
});
