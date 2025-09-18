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
});
