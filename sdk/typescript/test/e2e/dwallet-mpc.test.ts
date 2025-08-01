// Copyright (c) dWallet Labs, Ltd..
// SPDX-License-Identifier: BSD-3-Clause-Clear

import path from 'path';
import {
	public_key_from_dwallet_output,
	sample_dwallet_keypair,
	verify_secp_signature,
} from '@dwallet-network/dwallet-mpc-wasm';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { getFaucetHost, requestSuiFromFaucetV2 } from '@mysten/sui/faucet';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { beforeEach, describe, expect, it } from 'vitest';

import { createDWallet, launchDKGFirstRoundWithGivenCoins } from '../../src/dwallet-mpc/dkg';
import {
	checkpointCreationTime,
	Config,
	delay,
	DWALLET_NETWORK_VERSION,
	getAllChildObjectsIDs,
	getNetworkPublicParameters,
	getObjectWithType,
	isCoordinatorInner,
	isSystemInner,
	isValidator,
} from '../../src/dwallet-mpc/globals';
import { createImportedDWallet } from '../../src/dwallet-mpc/import-dwallet';
import { presign } from '../../src/dwallet-mpc/presign';
import {
	isDWalletWithPublicUserSecretKeyShares,
	makeDWalletUserSecretKeySharesPublicRequestEvent,
} from '../../src/dwallet-mpc/publish_secret_share';
import {
	completeFutureSign,
	createUnverifiedPartialUserSignatureCap,
	Hash,
	sign,
	signWithImportedDWallet,
	verifySignWithPartialUserSignatures,
} from '../../src/dwallet-mpc/sign';

const fiveMinutes = 5 * 60 * 1000;
describe('Test dWallet MPC', () => {
	let conf: Config;

	beforeEach(async () => {
		const keypair = Ed25519Keypair.deriveKeypairFromSeed('0x1');
		const dWalletSeed = new Uint8Array(32).fill(8);
		const encryptedSecretShareSigningKeypair = Ed25519Keypair.deriveKeypairFromSeed(
			Buffer.from(dWalletSeed).toString('hex'),
		);
		const address = keypair.getPublicKey().toSuiAddress();
		console.log(`Address: ${address}`);
		const suiClient = new SuiClient({ url: getFullnodeUrl('localnet') });
		await requestSuiFromFaucetV2({
			host: getFaucetHost('localnet'),
			recipient: address,
		});

		conf = {
			suiClientKeypair: keypair,
			client: suiClient,
			timeout: fiveMinutes,
			ikaConfig: require(path.resolve(process.cwd(), '../../ika_config.json')),
			dWalletSeed,
			encryptedSecretShareSigningKeypair,
		};
		await delay(2000);
	});

	it('read the network decryption key', async () => {
		const networkDecryptionKeyPublicOutput = await getNetworkPublicParameters(conf);
		console.log(`networkDecryptionKeyPublicOutput: ${networkDecryptionKeyPublicOutput}`);
	});

	it('should create a dWallet (DKG)', async () => {
		const networkDecryptionKeyPublicOutput = await getNetworkPublicParameters(conf);
		const dwallet = await createDWallet(conf, networkDecryptionKeyPublicOutput);
		console.log(`dWallet has been created successfully: ${dwallet}`);
	});

	it('should run presign', async () => {
		const networkDecryptionKeyPublicOutput = await getNetworkPublicParameters(conf);
		const dwallet = await createDWallet(conf, networkDecryptionKeyPublicOutput);
		console.log(`dWallet has been created successfully: ${dwallet}`);
		const completedPresign = await presign(conf, dwallet.dwalletID);
		console.log(`presign has been created successfully: ${completedPresign.id.id}`);
	});

	it('should sign full flow', async () => {
		const networkDecryptionKeyPublicOutput = await getNetworkPublicParameters(conf);
		console.log('Creating dWallet...');
		console.time('Step 1: dWallet Creation');
		const dwallet = await createDWallet(conf, networkDecryptionKeyPublicOutput);
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
	});

	it('should launch DKG first round with given coins', async () => {
		console.log('Creating dWallet...');
		// loop while true
		await launchDKGFirstRoundWithGivenCoins(
			conf,
			'0xb95fb6971af6769848be326e9428c7843ad4dd76481cf0f1a2d11d42f0a07406',
			'0xcdcdd1ba19c6b97cc805fab550c4d6382d72c98fa9a7a81b10dd1e0a046b8f6f',
		);
	});

	it('should print the fees collection objects', async () => {
		const coordinatorInner = await getObjectWithType(
			conf,
			'0xf5f3bb04d2fc15d9061d54d877a2ab5d73d5fb3426404616009a2ce44a7c4be2',
			isCoordinatorInner,
		);
		console.log({
			fee_charged_ika:
				coordinatorInner.fields.value.fields.pricing_and_fee_manager.fields.fee_charged_ika,
			gas_fee_reimbursement_sui_system_call_value:
				coordinatorInner.fields.value.fields.pricing_and_fee_manager.fields
					.gas_fee_reimbursement_sui_system_call_value,
			gas_fee_reimbursement_sui_system_call_balance:
				coordinatorInner.fields.value.fields.pricing_and_fee_manager.fields
					.gas_fee_reimbursement_sui_system_call_balance,
		});
	});

	it('should create a dwallet and publish its secret share', async () => {
		const networkDecryptionKeyPublicOutput = await getNetworkPublicParameters(conf);
		console.log('Creating dWallet...');
		const dwallet = await createDWallet(conf, networkDecryptionKeyPublicOutput);
		console.log(`dWallet has been created successfully: ${dwallet.dwalletID}`);
		await delay(checkpointCreationTime);
		console.log('Running publish secret share...');
		await makeDWalletUserSecretKeySharesPublicRequestEvent(
			conf,
			dwallet.dwalletID,
			dwallet.secret_share,
		);
	});

	it('should create a dwallet, publish its secret share and sign with the published share', async () => {
		const networkDecryptionKeyPublicOutput = await getNetworkPublicParameters(conf);
		console.log('Creating dWallet...');
		const dwallet = await createDWallet(conf, networkDecryptionKeyPublicOutput);
		console.log(`dWallet has been created successfully: ${dwallet.dwalletID}`);
		await delay(checkpointCreationTime);
		console.log('Running publish secret share...');
		await makeDWalletUserSecretKeySharesPublicRequestEvent(
			conf,
			dwallet.dwalletID,
			dwallet.secret_share,
		);
		const dwalletWithSecretShare = await getObjectWithType(
			conf,
			dwallet.dwalletID,
			isDWalletWithPublicUserSecretKeyShares,
		);
		console.log(`secretShare: ${dwalletWithSecretShare}`);
		console.log('Running Presign...');
		const completedPresign = await presign(conf, dwalletWithSecretShare.id.id);
		console.log(`presign has been created successfully: ${completedPresign.id.id}`);
		await delay(checkpointCreationTime);
		console.log('Running Sign...');
		const signResponse = await sign(
			conf,
			completedPresign.id.id,
			dwalletWithSecretShare.dwallet_cap_id,
			Buffer.from('hello world'),
			dwalletWithSecretShare.public_user_secret_key_share,
			networkDecryptionKeyPublicOutput,
			Hash.KECCAK256,
		);
		const publicKey = public_key_from_dwallet_output(dwallet.output);
		const isValid = verify_secp_signature(
			publicKey,
			signResponse.state.fields.signature,
			Buffer.from('hello world'),
			networkDecryptionKeyPublicOutput,
			Hash.KECCAK256,
		);
		expect(isValid).toBeTruthy();
	});

	it('should complete future sign', async () => {
		const networkDecryptionKeyPublicOutput = await getNetworkPublicParameters(conf);

		console.log('Step 1: dWallet Creation');
		console.time('Step 1: dWallet Creation');
		const dwallet = await createDWallet(conf, networkDecryptionKeyPublicOutput);
		console.timeEnd('Step 1: dWallet Creation');
		console.log(`Step 1: dWallet created | dWalletID = ${dwallet.dwalletID}`);
		await delay(checkpointCreationTime);

		console.log('Step 2: Presign Phase');
		console.time('Step 2: Presign Phase');
		const completedPresign = await presign(conf, dwallet.dwalletID);
		console.timeEnd('Step 2: Presign Phase');
		console.log(`Step 2: Presign completed | presignID = ${completedPresign.id.id}`);
		await delay(checkpointCreationTime);
		const unverifiedPartialUserSignatureCapID = await createUnverifiedPartialUserSignatureCap(
			conf,
			completedPresign.id.id,
			dwallet.dwallet_cap_id,
			Buffer.from('hello world'),
			dwallet.secret_share,
			networkDecryptionKeyPublicOutput,
			Hash.KECCAK256,
		);
		await delay(checkpointCreationTime);
		const verifiedPartialUserSignatureCapID = await verifySignWithPartialUserSignatures(
			conf,
			unverifiedPartialUserSignatureCapID!,
		);
		await delay(checkpointCreationTime);
		await completeFutureSign(
			conf,
			dwallet.dwallet_cap_id,
			Buffer.from('hello world'),
			Hash.KECCAK256,
			verifiedPartialUserSignatureCapID,
		);
	});

	it('should create an imported dWallet', async () => {
		const networkDecryptionKeyPublicOutput = await getNetworkPublicParameters(conf);
		const [secretKey, _publicKey] = sample_dwallet_keypair(networkDecryptionKeyPublicOutput);
		const dwallet = await createImportedDWallet(conf, secretKey);
		console.log({ ...dwallet });
	});

	it('should create an imported dWallet, publish its secret share and sign with it', async () => {
		const networkDecryptionKeyPublicOutput = await getNetworkPublicParameters(conf);
		const [secretKey, _publicKey] = sample_dwallet_keypair(networkDecryptionKeyPublicOutput);
		const dwallet = await createImportedDWallet(conf, secretKey);
		await delay(checkpointCreationTime);
		console.log({ ...dwallet });
		console.log('Running publish secret share...');
		await makeDWalletUserSecretKeySharesPublicRequestEvent(
			conf,
			dwallet.dwalletID,
			dwallet.secret_share,
		);
		const dwalletWithSecretShare = await getObjectWithType(
			conf,
			dwallet.dwalletID,
			isDWalletWithPublicUserSecretKeyShares,
		);
		console.log(`secretShare: ${dwalletWithSecretShare}`);
		console.log('Running Presign...');
		const completedPresign = await presign(conf, dwalletWithSecretShare.id.id);
		console.log(`presign has been created successfully: ${completedPresign.id.id}`);
		await delay(checkpointCreationTime);
		console.log('Running Sign...');
		const signature = await signWithImportedDWallet(
			conf,
			completedPresign.id.id,
			dwalletWithSecretShare.dwallet_cap_id,
			Buffer.from('hello world'),
			dwalletWithSecretShare.public_user_secret_key_share,
			networkDecryptionKeyPublicOutput,
			Hash.KECCAK256,
		);
		const isValid = verify_secp_signature(
			public_key_from_dwallet_output(dwallet.output),
			signature.state.fields.signature,
			Buffer.from('hello world'),
			networkDecryptionKeyPublicOutput,
			Hash.KECCAK256,
		);
		expect(isValid).toBeTruthy();
	});

	it('should create an imported dWallet, sign with it & verify the signature against the original public key', async () => {
		const networkDecryptionKeyPublicOutput = await getNetworkPublicParameters(conf);
		const [secretKey, publicKey] = sample_dwallet_keypair(networkDecryptionKeyPublicOutput);
		const dwallet = await createImportedDWallet(conf, secretKey);
		console.log({ ...dwallet });
		await delay(checkpointCreationTime);
		console.log('Running Presign...');
		const completedPresign = await presign(conf, dwallet.dwalletID);
		console.log(`presign has been created successfully: ${completedPresign.id.id}`);
		await delay(checkpointCreationTime);
		console.log('Running Sign...');
		const signature = await signWithImportedDWallet(
			conf,
			completedPresign.id.id,
			dwallet.dwallet_cap_id,
			Buffer.from('hello world'),
			dwallet.secret_share,
			networkDecryptionKeyPublicOutput,
			Hash.KECCAK256,
		);
		const isValid = verify_secp_signature(
			publicKey,
			signature.state.fields.signature,
			Buffer.from('hello world'),
			networkDecryptionKeyPublicOutput,
			Hash.KECCAK256,
		);
		expect(isValid).toBeTruthy();
	});

	it('should fetch all the validator operator cap ids from Sui', async () => {
		const dynamicFields = await conf.client.getDynamicFields({
			parentId: conf.ikaConfig.objects.ika_system_object_id,
		});
		const innerCoordinatorState = await conf.client.getDynamicFieldObject({
			parentId: conf.ikaConfig.objects.ika_system_object_id,
			name: dynamicFields.data[0].name,
		});
		const systemInner = innerCoordinatorState.data?.content;
		if (!isSystemInner(systemInner)) {
			console.log("couldn't fetch the inner system state");
			return;
		}
		const validatorTableID =
			systemInner.fields.value.fields.validator_set.fields.validators.fields.id.id;
		const allValidatorsIDs = await getAllChildObjectsIDs(conf, validatorTableID);
		const operatorCapIDs = await Promise.all(
			allValidatorsIDs.map(async (id) => {
				const validator = await getObjectWithType(conf, id, isValidator);
				return validator.operation_cap_id;
			}),
		);

		console.log(operatorCapIDs.join(' '));
	});
});

describe('tests that do not require faucet requests', () => {
	let conf: Config;

	beforeEach(async () => {
		const keypair = Ed25519Keypair.deriveKeypairFromSeed('0x1');
		const dWalletSeed = new Uint8Array(32).fill(8);
		const encryptedSecretShareSigningKeypair = Ed25519Keypair.deriveKeypairFromSeed(
			Buffer.from(dWalletSeed).toString('hex'),
		);
		const address = keypair.getPublicKey().toSuiAddress();
		console.log(`Address: ${address}`);
		const suiClient = new SuiClient({ url: getFullnodeUrl('localnet') });
		conf = {
			suiClientKeypair: keypair,
			client: suiClient,
			timeout: fiveMinutes,
			ikaConfig: require(path.resolve(process.cwd(), '../../ika_config.json')),
			dWalletSeed,
			encryptedSecretShareSigningKeypair,
		};
		await delay(2000);
	});

	it('should print the fees collection objects', async () => {
		// eslint-disable-next-line no-constant-condition
		while (true) {
			const dynamicFields = await conf.client.getDynamicFields({
				parentId: conf.ikaConfig.ika_dwallet_coordinator_object_id,
			});
			const coordinatorInner = await conf.client.getDynamicFieldObject({
				parentId: conf.ikaConfig.ika_dwallet_coordinator_object_id,
				name: dynamicFields.data[DWALLET_NETWORK_VERSION].name,
			});
			if (!isCoordinatorInner(coordinatorInner.data?.content)) {
				throw new Error('Invalid coordinator inner');
			}
			console.log({
				fee_charged_ika:
					coordinatorInner.data.content.fields.value.fields.pricing_and_fee_manager.fields
						.fee_charged_ika,
				gas_fee_reimbursement_sui_system_call_value:
					coordinatorInner.data.content.fields.value.fields.pricing_and_fee_manager.fields
						.gas_fee_reimbursement_sui_system_call_value,
				gas_fee_reimbursement_sui_system_call_balance:
					coordinatorInner.data.content.fields.value.fields.pricing_and_fee_manager.fields
						.gas_fee_reimbursement_sui_system_call_balance,
			});
			await delay(100);
		}
	});
});
