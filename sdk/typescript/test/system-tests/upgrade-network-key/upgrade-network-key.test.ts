import fs from 'fs';
import path from 'path';
import { execa } from 'execa';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { deployIkaNetwork, TEST_ROOT_DIR } from '../globals';

describe('system tests', () => {
	it('run a full flow test of upgrading the network key version and the move code', async () => {
		require('dotenv').config({ path: `${TEST_ROOT_DIR}/.env` });

		const startCommitteeSize = Number(process.env.VALIDATOR_NUM);
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
		const addValidatorScriptPath = `${TEST_ROOT_DIR}/add-validators-to-next-committee.sh`;
		console.log('Validators added to the next committee, deploying ika network');
		await deployIkaNetwork();

		console.log('Ika network deployed, waiting for epoch switch');
	}, 3_600_000);
});
