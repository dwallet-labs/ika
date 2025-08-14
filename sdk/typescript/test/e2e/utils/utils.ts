import { Buffer } from 'buffer';
import {
	public_key_from_dwallet_output,
	verify_secp_signature,
} from '@dwallet-network/dwallet-mpc-wasm';
import { expect } from 'vitest';

import { createDWallet } from '../../../src/dwallet-mpc/dkg.js';
import type { Config } from '../../../src/dwallet-mpc/globals.js';
import {
	checkpointCreationTime,
	delay,
	getNetworkPublicParameters,
	getSystemInner,
} from '../../../src/dwallet-mpc/globals.js';
import { presign } from '../../../src/dwallet-mpc/presign.js';
import { Hash, sign } from '../../../src/dwallet-mpc/sign.js';

export async function waitForEpochSwitch(conf: Config) {
	let systemInner = await getSystemInner(conf);
	const startEpoch = systemInner.fields.value.fields.epoch;
	let epochSwitched = false;
	while (!epochSwitched) {
		systemInner = await getSystemInner(conf);
		if (systemInner.fields.value.fields.epoch > startEpoch) {
			epochSwitched = true;
		} else {
			await delay(5_000);
		}
	}
}

export async function runFullFlowTestWithNetworkKey(conf: Config, networkKeyID: string) {
	const networkDecryptionKeyPublicOutput = await getNetworkPublicParameters(conf, networkKeyID);
	console.log('Creating dWallet...');
	console.time('Step 1: dWallet Creation');
	const dwallet = await createDWallet(conf, networkKeyID, networkDecryptionKeyPublicOutput);
	console.log(`dWallet has been created successfully: ${dwallet.dwalletID}`);
	console.timeEnd('Step 1: dWallet Creation');
	await delay(checkpointCreationTime);
	console.log('Running Presign...');
	console.time('Step 2: Presign Phase');
	const completedPresign = await presign(conf, dwallet.dwalletID);
	console.timeEnd('Step 2: Presign Phase');
	console.log(`Step 2: Presign completed | presignID = ${completedPresign.id.id}`);
	await delay(checkpointCreationTime);
	console.log('Running Sign...');
	console.time('Step 3: Sign Phase');
	const signRes = await sign(
		conf,
		completedPresign.id.id,
		dwallet.dwallet_cap_id,
		Buffer.from('hello world'),
		dwallet.secret_share,
		networkDecryptionKeyPublicOutput,
		Hash.KECCAK256,
	);
	console.log(`Sing completed successfully: ${signRes.id.id}`);
	console.timeEnd('Step 3: Sign Phase');
	const isValid = verify_secp_signature(
		public_key_from_dwallet_output(dwallet.output),
		signRes.state.fields.signature,
		Buffer.from('hello world'),
		networkDecryptionKeyPublicOutput,
		Hash.KECCAK256,
	);
	expect(isValid).toBeTruthy();
}
