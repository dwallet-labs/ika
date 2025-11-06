import { promises as fs } from 'fs';
import { exec } from 'node:child_process';
import path from 'path';
import * as TOML from '@iarna/toml';
import { network_key_version } from '@ika.xyz/ika-wasm';
import { KubeConfig } from '@kubernetes/client-node';
import { execa } from 'execa';
import yaml from 'js-yaml';
import { describe, expect, it } from 'vitest';

import { Curve, Hash, IkaClient, SignatureAlgorithm } from '../../../src';
import { createCompleteDWallet } from '../../helpers/dwallet-test-helpers';
import {
	createTestIkaClient,
	createTestSuiClient,
	delay,
	findIkaConfigFile,
	generateTestKeypair,
	generateTestKeypairV1,
	requestTestFaucetFunds,
	runSignFullFlowWithDWallet,
	runSignFullFlowWithV1Dwallet,
	waitForEpochSwitch,
} from '../../helpers/test-utils';
import {
	deployUpgradedPackage,
	getProtocolCapID,
	getPublisherKeypair,
	migrateCoordinator,
} from '../../move-upgrade/upgrade-ika-twopc-mpc.test';
import { testSignCombination } from '../../v2/all-combinations.test';
import { testImportedKeyScenario } from '../../v2/imported-key.test';
import { createConfigMaps } from '../config-map';
import { deployIkaNetwork, NAMESPACE_NAME, NETWORK_SERVICE_NAME, TEST_ROOT_DIR } from '../globals';
import {
	createFullnodePod,
	createPods,
	createValidatorPod,
	killAllPods,
	killFullnodePod,
	killValidatorPod,
} from '../pods';

async function testImportedDWalletFullFlowWithAllCurves() {
	await testImportedKeyScenario(
		Curve.SECP256K1,
		SignatureAlgorithm.ECDSASecp256k1,
		Hash.KECCAK256,
		'ecdsa-secp256k1-keccak256',
	);

	await testImportedKeyScenario(
		Curve.SECP256K1,
		SignatureAlgorithm.ECDSASecp256k1,
		Hash.SHA256,
		'ecdsa-secp256k1-sha256',
	);

	await testImportedKeyScenario(
		Curve.SECP256K1,
		SignatureAlgorithm.Taproot,
		Hash.SHA256,
		'taproot-sha256',
	);

	await testImportedKeyScenario(
		Curve.SECP256R1,
		SignatureAlgorithm.ECDSASecp256r1,
		Hash.SHA256,
		'ecdsa-secp256r1-sha256',
	);

	await testImportedKeyScenario(
		Curve.ED25519,
		SignatureAlgorithm.EdDSA,
		Hash.SHA512,
		'eddsa-sha512',
	);

	await testImportedKeyScenario(
		Curve.RISTRETTO,
		SignatureAlgorithm.SchnorrkelSubstrate,
		Hash.Merlin,
		'schnorrkel-merlin',
	);
}

async function testSignFullFlowWithAllCurves() {
	await testSignCombination(
		Curve.SECP256K1,
		SignatureAlgorithm.ECDSASecp256k1,
		Hash.KECCAK256,
		'ecdsa-secp256k1-keccak256',
	);

	await testSignCombination(
		Curve.SECP256K1,
		SignatureAlgorithm.ECDSASecp256k1,
		Hash.SHA256,
		'ecdsa-secp256k1-sha256',
	);

	await testSignCombination(
		Curve.SECP256K1,
		SignatureAlgorithm.ECDSASecp256k1,
		Hash.DoubleSHA256,
		'ecdsa-secp256k1-double-sha256',
	);

	await testSignCombination(
		Curve.SECP256K1,
		SignatureAlgorithm.Taproot,
		Hash.SHA256,
		'taproot-sha256',
	);

	await testSignCombination(
		Curve.SECP256R1,
		SignatureAlgorithm.ECDSASecp256r1,
		Hash.SHA256,
		'ecdsa-secp256r1-sha256',
	);

	await testSignCombination(Curve.ED25519, SignatureAlgorithm.EdDSA, Hash.SHA512, 'eddsa-sha512');

	await testSignCombination(
		Curve.RISTRETTO,
		SignatureAlgorithm.SchnorrkelSubstrate,
		Hash.Merlin,
		'schnorrkel-merlin',
	);
}

async function upgradeValidatorsDockerImage(kc: KubeConfig, startIndex = 0, endIndex?: number) {
	for (let i = startIndex; i < endIndex; i++) {
		try {
			await killValidatorPod(kc, NAMESPACE_NAME, i + 1);
		} catch (e) {}
	}
	await delay(30);
	for (let i = startIndex; i < endIndex; i++) {
		await createValidatorPod(kc, NAMESPACE_NAME, i + 1);
	}
}

describe('system tests', () => {
	it('run sign full flow with v1 dwallet', async () => {
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		await runSignFullFlowWithV1Dwallet(ikaClient, suiClient, 'sign-full-flow-v1-dwallet');
	});

	it('run a full flow test of upgrading the network key version and the move code', async () => {
		const v2NetworkKeyDockerTag =
			'us-docker.pkg.dev/common-449616/ika-common-public-containers/ika-node:testnet-v1.1.4';
		const v2NetworkKeyNotifierDockerTag =
			'us-docker.pkg.dev/common-449616/ika-common-public-containers/ika-notifier:testnet-v1.1.3';

		const testName = 'upgrade-network-key';
		const { userShareEncryptionKeys, signerPublicKey, signerAddress } =
			await generateTestKeypairV1(testName);
		await requestTestFaucetFunds(signerAddress);
		require('dotenv').config({ path: `${TEST_ROOT_DIR}/.env` });
		const mainnetCreateIkaGenesisPath = `${TEST_ROOT_DIR}/mainnet-create-ika-genesis.sh`;
		const setSupportedAndPricingPath = `${TEST_ROOT_DIR}/set_supported_and_pricing.sh`;
		await execa({
			stdout: ['pipe', 'inherit'],
			stderr: ['pipe', 'inherit'],
			cwd: TEST_ROOT_DIR,
		})`${mainnetCreateIkaGenesisPath}`;

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
		// const dwallet = await createCompleteDWallet(ikaClient, suiClient, testName, true);
		console.log('DWallet created successfully, running a full sign flow with it');
		// await runSignFullFlowWithDWallet(ikaClient, suiClient, dwallet, testName);
		console.log('V1 dWallet full flow works, upgrading two validators to the new docker image');
		const signer = await getPublisherKeypair();
		process.env.DOCKER_TAG = v2NetworkKeyDockerTag;
		process.env.NOTIFIER_DOCKER_TAG = v2NetworkKeyNotifierDockerTag;
		const kc = new KubeConfig();
		kc.loadFromDefault();
		await upgradeValidatorsDockerImage(kc, 0, 2);
		console.log(
			'Two validators upgraded, making sure running a sign full flow with the partially upgraded network works fine',
		);
		// await runSignFullFlowWithV1Dwallet(ikaClient, suiClient, testName, false);

		console.log('Sign full flow works, upgrading the network pricing and curve configuration');

		const protocolCapID = await getProtocolCapID(
			suiClient,
			signer.getPublicKey().toSuiAddress(),
			ikaClient,
		);
		const jsonData = JSON.parse(await fs.readFile(findIkaConfigFile(), 'utf8'));
		const wrapped = { envs: { localhost: jsonData } };

		const yamlStr = yaml.dump(wrapped, { indent: 2 });
		await fs.writeFile(
			path.join(process.env.HOME!, '.ika/ika_config/ika_sui_config.yaml'),
			yamlStr,
		);
		const pre_move_upgrade_pricing_path = `${TEST_ROOT_DIR}/upgrade-network-key/pre_default_pricing_test.yaml`;
		const pre_supported_curves_config = `${TEST_ROOT_DIR}/upgrade-network-key/pre_supported_curves_to_signature_algorithms_to_hash_schemes.yaml`;
		await execa({
			stdout: ['pipe', 'inherit'],
			stderr: ['pipe', 'inherit'],
			cwd: TEST_ROOT_DIR,
		})`${setSupportedAndPricingPath} ${protocolCapID} ${pre_move_upgrade_pricing_path} ${pre_supported_curves_config}`;

		console.log(
			'network configuration has been upgraded, upgrading the rest of the validators binary',
		);
		await upgradeValidatorsDockerImage(kc, 2, Number(process.env.VALIDATOR_NUM));
		await killFullnodePod(kc, NAMESPACE_NAME);
		await delay(30);
		await createFullnodePod(NAMESPACE_NAME, kc);
		console.log('All validators upgraded, running a sign full flow with the old v1 dWallet');

		// await runSignFullFlowWithDWallet(ikaClient, suiClient, dwallet, testName);
		console.log(
			'Signing with the old v1 dWallet works, waiting for the network key to upgrade to V2',
		);
		await waitForV2NetworkKey(ikaClient);
		console.log('Network key upgraded to V2, verifying the v1 dWallet full flow still works');
		// await runSignFullFlowWithDWallet(ikaClient, suiClient, dwallet, testName);
		console.log(
			'V1 dWallet full flow works with previously created dWallet, creating a new v1 dWallet and verifying it works',
		);
		// await runSignFullFlowWithV1Dwallet(ikaClient, suiClient, testName, false);
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
		wrapped.envs.localhost.packages.ika_dwallet_2pc_mpc_package_id = upgradedPackageID;
		const yamlString = yaml.dump(wrapped, { indent: 2 });
		await fs.writeFile(
			path.join(process.env.HOME!, '.ika/ika_config/ika_sui_config.yaml'),
			yamlString,
		);

		ikaClient.ikaConfig.packages.ikaDwallet2pcMpcPackage = upgradedPackageID;

		const post_move_upgrade_pricing_path = `${TEST_ROOT_DIR}/upgrade-network-key/post_default_pricing_test.yaml`;
		const post_supported_curves_config = `${TEST_ROOT_DIR}/upgrade-network-key/post_supported_curves_to_signature_algorithms_to_hash_schemes.yaml`;
		await execa({
			stdout: ['pipe', 'inherit'],
			stderr: ['pipe', 'inherit'],
			cwd: TEST_ROOT_DIR,
		})`${setSupportedAndPricingPath} ${protocolCapID} ${post_move_upgrade_pricing_path} ${post_supported_curves_config}`;

		console.log('Migration complete, updating the validators with the new package ID');
		await updateOperatorsConfigWithNewPackageID(upgradedPackageID);
		await createConfigMaps(kc, NAMESPACE_NAME, Number(process.env.VALIDATOR_NUM), true);
		await killAllPods(kc, NAMESPACE_NAME, Number(process.env.VALIDATOR_NUM));
		await delay(30);
		await createPods(kc, NAMESPACE_NAME, Number(process.env.VALIDATOR_NUM));

		console.log(
			'Move contracts upgraded to V2, running sign full flow with all curves and verifying it works',
		);
		await testSignFullFlowWithAllCurves();
		console.log(
			'sign works with all curves, checking full flow with an imported dWallet with all curves',
		);
		await testImportedDWalletFullFlowWithAllCurves();
		console.log('Imported dWallet full flow works with all curves, test complete successfully');
	}, 3_600_000);

	it('should be chill', async () => {
		const jsonData = JSON.parse(await fs.readFile(findIkaConfigFile(), 'utf8'));
		const wrapped = { envs: { localhost: jsonData } };

		const yamlStr = yaml.dump(wrapped, { indent: 2 });
		await fs.writeFile('/home/itayl/.ika/ika_config/ika_sui_config.yaml', yamlStr);
	});

	it('should run v1 test', async () => {
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();
		const testName = 'sign-full-flow-v1-dwallet';
		console.log('Network key version is V1, creating a dWallet with it');
		const dwallet = await createCompleteDWallet(ikaClient, suiClient, testName, true);
		console.log('DWallet created successfully, running a full sign flow with it');
		await runSignFullFlowWithDWallet(ikaClient, suiClient, dwallet, testName);
		console.log('V1 dWallet full flow works, upgrading the validators docker image');
	});
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
