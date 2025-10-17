import { promises as fs } from 'fs';
import { exec } from 'node:child_process';
import path from 'path';
import * as TOML from '@iarna/toml';
import { network_key_version } from '@ika.xyz/ika-wasm';
import { dumpYaml, KubeConfig, loadYaml } from '@kubernetes/client-node';
import { SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { execa } from 'execa';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { fetchAllDynamicFields, IkaClient } from '../../../src';
import { createCompleteDWallet } from '../../helpers/dwallet-test-helpers';
import {
	createTestIkaClient,
	createTestSuiClient,
	delay,
	generateTestKeypair,
	requestTestFaucetFunds,
	runSignFullFlowWithDWallet,
	runSignFullFlowWithV1Dwallet,
	runSignFullFlowWithV2Dwallet,
	waitForEpochSwitch,
} from '../../helpers/test-utils';
import { runSignFullFlowTestWithImportedDwallet } from '../../imported-dwallet/imported-dwallet-sign.test';
import {
	deployUpgradedPackage,
	getProtocolCapID,
	getPublisherKeypair,
	migrateCoordinator,
} from '../../move-upgrade/upgrade-ika-twopc-mpc.test';
import { createConfigMaps } from '../config-map';
import { deployIkaNetwork, NAMESPACE_NAME, NETWORK_SERVICE_NAME, TEST_ROOT_DIR } from '../globals';
import { createPods, createValidatorPod, killAllPods, killValidatorPod } from '../pods';

describe('system tests', () => {
	it('run a full flow test of upgrading the network key version and the move code', async () => {
		const v2NetworkKeyDockerTag = 'itaylevy134/ika-node:v2key6';

		const testName = 'upgrade-network-key';
		// Generate deterministic keypair for this test
		const { userShareEncryptionKeys, signerPublicKey, signerAddress } =
			await generateTestKeypair(testName);

		// Request faucet funds for the test address
		await requestTestFaucetFunds(signerAddress);
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
		await deployIkaNetwork();
		console.log('Ika network deployed, waiting for epoch switch');
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();
		await waitForEpochSwitch(ikaClient);
		console.log('Epoch switched, verifying the network key version is V1');
		const networkKey = await ikaClient.getConfiguredNetworkEncryptionKey();
		let networkKeyBytes = await ikaClient.readTableVecAsRawBytes(networkKey.networkDKGOutputID);
		const networkKeyVersion = network_key_version(networkKeyBytes);
		expect(networkKeyVersion).toBe(1);
		console.log('Network key version is V1, creating a dWallet with it');
		const dwallet = await createCompleteDWallet(ikaClient, suiClient, testName, true);
		console.log('DWallet created successfully, running a full sign flow with it');
		await runSignFullFlowWithDWallet(ikaClient, suiClient, dwallet, testName);
		console.log('V1 dWallet full flow works, upgrading the validators docker image');
		process.env.DOCKER_TAG = v2NetworkKeyDockerTag;
		const kc = new KubeConfig();
		kc.loadFromDefault();
		// Restart each validator pod one by one to pick up the docker tag change
		for (let i = 0; i < Number(process.env.VALIDATOR_NUM); i++) {
			try {
				await killValidatorPod(kc, NAMESPACE_NAME, i + 1);
			} catch (e) {}
			await delay(15);
			await createValidatorPod(kc, NAMESPACE_NAME, i + 1);
		}
		console.log(
			'All validators upgraded, running a full sign flow with the previously created v1 dWallet',
		);
		await runSignFullFlowWithDWallet(ikaClient, suiClient, dwallet, testName);
		console.log(
			'Signing with the old v1 dWallet works, waiting for the network key to upgrade to V2',
		);
		await waitForV2NetworkKey(ikaClient);
		console.log('Network key upgraded to V2, verifying the v1 dWallet full flow still works');
		await delay(3); // wait for a few seconds to release the gas objects
		await runSignFullFlowWithDWallet(ikaClient, suiClient, dwallet, testName);
		console.log(
			'V1 dWallet full flow works with previously created dWallet, creating a new v1 dWallet and verifying it works',
		);
		await runSignFullFlowWithV1Dwallet(ikaClient, suiClient, testName, false);
		console.log('V1 dWallet full flow works, upgrading the Move contracts to V2');

		const twopc_mpc_contracts_path = path.join(
			TEST_ROOT_DIR,
			'../../../../contracts/ika_dwallet_2pc_mpc',
		);

		const ika_twopc_move_toml = TOML.parse(
			await fs.readFile(path.join(twopc_mpc_contracts_path, 'Move.toml'), 'utf8'),
		);
		ika_twopc_move_toml.addresses.ika = ikaClient.ikaConfig.packages.ikaPackage;
		await fs.writeFile(
			path.join(twopc_mpc_contracts_path, 'Move.toml'),
			TOML.stringify(ika_twopc_move_toml),
		);
		const ikaMoveToml = TOML.parse(
			await fs.readFile(path.join(TEST_ROOT_DIR, '../../../../contracts/ika/Move.toml'), 'utf8'),
		);
		ikaMoveToml.package['published-at'] = ikaClient.ikaConfig.packages.ikaPackage;
		ikaMoveToml.addresses.ika = ikaClient.ikaConfig.packages.ikaPackage;
		await fs.writeFile(
			path.join(TEST_ROOT_DIR, '../../../../contracts/ika/Move.toml'),
			TOML.stringify(ikaMoveToml),
		);
		const ikaCommonToml = TOML.parse(
			await fs.readFile(
				path.join(TEST_ROOT_DIR, '../../../../contracts/ika_common/Move.toml'),
				'utf8',
			),
		);
		ikaCommonToml.package['published-at'] = ikaClient.ikaConfig.packages.ikaCommonPackage;
		ikaCommonToml.addresses.ika_common = ikaClient.ikaConfig.packages.ikaCommonPackage;
		await fs.writeFile(
			path.join(TEST_ROOT_DIR, '../../../../contracts/ika_common/Move.toml'),
			TOML.stringify(ikaCommonToml),
		);

		const signer = await getPublisherKeypair();
		const protocolCapID = await getProtocolCapID(
			suiClient,
			signer.getPublicKey().toSuiAddress(),
			ikaClient,
		);

		const upgradedPackageID = await deployUpgradedPackage(
			suiClient,
			signer,
			twopc_mpc_contracts_path,
			ikaClient,
			protocolCapID,
		);
		await delay(5);
		console.log(`Upgraded package deployed at: ${upgradedPackageID}`);
		console.log('running the migration to the upgraded package');

		await migrateCoordinator(suiClient, signer, ikaClient, protocolCapID, upgradedPackageID);

		console.log('Migration complete, updating the validators with the new package ID');
		await updateOperatorsConfigWithNewPackageID(upgradedPackageID);
		await createConfigMaps(kc, NAMESPACE_NAME, Number(process.env.VALIDATOR_NUM), true);
		await killAllPods(kc, NAMESPACE_NAME, Number(process.env.VALIDATOR_NUM));
		await delay(30);
		await createPods(kc, NAMESPACE_NAME, Number(process.env.VALIDATOR_NUM));

		console.log('Move contracts upgraded to V2, running sign full flow and verifying it works');
		ikaClient.ikaConfig.packages.ikaDwallet2pcMpcPackage = upgradedPackageID;
		await runSignFullFlowWithV2Dwallet(ikaClient, suiClient, testName, false);
		console.log('V2 dWallet full flow works, test completed successfully');

		await runSignFullFlowTestWithImportedDwallet(testName, ikaClient, suiClient, false);
		console.log(
			'Imported dWallet full flow works, creating a new v2 dWallet and verifying it works',
		);
		// TODO (#1530): Verify sign works with all supported curves in the network key update system test
	}, 3_600_000);
});

async function waitForV2NetworkKey(ikaClient: IkaClient) {
	let networkKeyVersion = 1;
	while (networkKeyVersion !== 2) {
		ikaClient.invalidateCache();
		const networkKey = await ikaClient.getConfiguredNetworkEncryptionKey();
		if (networkKey.reconfigurationOutputID) {
			const networkKeyBytes = await ikaClient.readTableVecAsRawBytes(
				networkKey.reconfigurationOutputID,
			);
			networkKeyVersion = network_key_version(networkKeyBytes);
		}
		await delay(5);
	}
}

async function updateOperatorsConfigWithNewPackageID(upgradedPackageID: string) {
	for (let i = 0; i < Number(process.env.VALIDATOR_NUM); i++) {
		let validatorYamlPath = `${TEST_ROOT_DIR}/${NETWORK_SERVICE_NAME}.${NAMESPACE_NAME}.svc.cluster.local/val${i + 1}.${NETWORK_SERVICE_NAME}.${NAMESPACE_NAME}.svc.cluster.local/validator.yaml`;
		exec(
			`yq e '.["sui-connector-config"]["ika-dwallet-2pc-mpc-package-id-v2"] = "${upgradedPackageID}"' -i "${validatorYamlPath}"`,
		);
	}
	const fullNodeYamlPath = `${TEST_ROOT_DIR}/${NETWORK_SERVICE_NAME}.${NAMESPACE_NAME}.svc.cluster.local/publisher/fullnode.yaml`;
	exec(
		`yq e '.["sui-connector-config"]["ika-dwallet-2pc-mpc-package-id"] = "${upgradedPackageID}"' -i "${fullNodeYamlPath}"`,
	);
}
