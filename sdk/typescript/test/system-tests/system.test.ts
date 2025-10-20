import { promises as fs } from 'fs';
import path from 'path';
import { KubeConfig } from '@kubernetes/client-node';
import { execa } from 'execa';
import { describe, it } from 'vitest';

import {
	createTestIkaClient,
	createTestSuiClient,
	delay,
	runSignFullFlowWithV1Dwallet,
	waitForEpochSwitch,
} from '../helpers/test-utils';
import { createConfigMaps } from './config-map';
import { createIkaGenesis, deployIkaNetwork, NAMESPACE_NAME, TEST_ROOT_DIR } from './globals';
import { createValidatorPod, killValidatorPod } from './pods';

describe('system tests', () => {
	it('deploy the ika network from the current directory to the local kubernetes cluster', async () => {
		require('dotenv').config({ path: `${TEST_ROOT_DIR}/.env` });
		await deployIkaNetwork();
	});

	it('should kill a validator pod', async () => {
		require('dotenv').config({ path: `${TEST_ROOT_DIR}/.env` });
		const kc = new KubeConfig();
		kc.loadFromDefault();
		await killValidatorPod(kc, NAMESPACE_NAME, Number(5));
	});

	it('should start a validator pod', async () => {
		require('dotenv').config({ path: `${TEST_ROOT_DIR}/.env` });
		const kc = new KubeConfig();
		kc.loadFromDefault();
		await createValidatorPod(kc, NAMESPACE_NAME, Number(5));
	});

	it('run a full flow test of adding validators to the next epoch', async () => {
		// The number of validators to add to the next epoch
		const numOfValidatorsToAdd = 3;
		// The number of old validators to kill after the validators has been added, used to verify the new validators
		// are operational.
		const numOfValidatorsToKill = 2;

		require('dotenv').config({ path: `${TEST_ROOT_DIR}/.env` });

		const startCommitteeSize = Number(process.env.VALIDATOR_NUM);
		// ------------ Create Ika Genesis ------------
		await createIkaGenesis();
		console.log(
			`Ika genesis created, adding ${numOfValidatorsToAdd} validators to the next committee`,
		);
		const addValidatorScriptPath = `${TEST_ROOT_DIR}/add-validators-to-next-committee.sh`;
		await execa(
			addValidatorScriptPath,
			[numOfValidatorsToAdd.toString(), (startCommitteeSize + 1).toString()],
			{
				stdout: ['pipe', 'inherit'],
				stderr: ['pipe', 'inherit'],
				cwd: TEST_ROOT_DIR,
			},
		);

		console.log('Validators added to the next committee, deploying ika network');
		await deployIkaNetwork();

		console.log('Ika network deployed, waiting for epoch switch');
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();
		await waitForEpochSwitch(ikaClient);
		console.log('Epoch switched, start new validators & kill old ones');
		const kc = new KubeConfig();
		kc.loadFromDefault();
		await createConfigMaps(
			kc,
			NAMESPACE_NAME,
			Number(process.env.VALIDATOR_NUM) + numOfValidatorsToAdd,
			true,
		);

		for (let i = 0; i < numOfValidatorsToAdd; i++) {
			await createValidatorPod(kc, NAMESPACE_NAME, startCommitteeSize + 1 + i);
		}

		// sleep for three minutes to allow the new validators to start and join the network
		await delay(180);

		for (let i = 0; i < numOfValidatorsToKill; i++) {
			await killValidatorPod(kc, NAMESPACE_NAME, i + 1);
		}

		console.log('deployed new validators, running a full flow test');

		await runSignFullFlowWithV1Dwallet(ikaClient, suiClient, `system-test-full-flow`);
	}, 3_600_000);

	it('run system upgrade test - upgrade validators from v1 to v2 binary', async () => {
		require('dotenv').config({ path: `${TEST_ROOT_DIR}/.env` });

		const numOfValidators = Number(process.env.VALIDATOR_NUM);
		console.log(`Starting system upgrade test with ${numOfValidators} validators`);

		// ------------ Create Ika Genesis ------------
		await createIkaGenesis();
		console.log('Ika genesis created, deploying ika network with v1 binaries');

		// Deploy network with v1 binaries
		await deployIkaNetwork();
		console.log('Ika network deployed with v1 binaries, waiting for epoch switch');

		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();
		await waitForEpochSwitch(ikaClient);
		console.log('Epoch switched, network is running with v1 binaries');

		// Verify network works with v1
		await runSignFullFlowWithV1Dwallet(ikaClient, suiClient, `system-test-upgrade-v1`);
		console.log('V1 network verified, starting upgrade process');

		const kc = new KubeConfig();
		kc.loadFromDefault();

		// Create upgrade function that kills and recreates a validator with v2 binary
		const upgradeValidator = async (validatorID: number) => {
			console.log(`Upgrading validator ${validatorID} to v2 binary`);
			await killValidatorPod(kc, NAMESPACE_NAME, validatorID);

			// Wait a bit for the pod to be fully terminated
			await delay(5);

			// Create new pod with v2 binary (assuming DOCKER_TAG_V2 is set in .env)
			const originalDockerTag = process.env.DOCKER_TAG;
			process.env.DOCKER_TAG = process.env.DOCKER_TAG_V2 || process.env.DOCKER_TAG;

			await createValidatorPod(kc, NAMESPACE_NAME, validatorID);

			// Restore original docker tag
			process.env.DOCKER_TAG = originalDockerTag;

			console.log(`Validator ${validatorID} upgraded to v2 binary`);
		};

		// Upgrade validators with random delays between 60-180 seconds
		const upgradePromises: Promise<void>[] = [];
		for (let i = 1; i <= numOfValidators; i++) {
			const randomDelay = Math.floor(Math.random() * 120) + 60; // 60-180 seconds
			console.log(`Validator ${i} will be upgraded in ${randomDelay} seconds`);

			const upgradePromise = (async () => {
				await delay(randomDelay);
				await upgradeValidator(i);
			})();

			upgradePromises.push(upgradePromise);
		}

		// Wait for all upgrades to complete
		console.log('Waiting for all validators to be upgraded...');
		await Promise.all(upgradePromises);
		console.log('All validators upgraded to v2 binaries');

		// Wait for network to stabilize after upgrades
		await delay(60);
		console.log('Network stabilized, verifying v2 network functionality');

		// Verify network still works after upgrade
		await runSignFullFlowWithV1Dwallet(ikaClient, suiClient, `system-test-upgrade-v2`);
		console.log('System upgrade test completed successfully');
	}, 3_600_000);
});
