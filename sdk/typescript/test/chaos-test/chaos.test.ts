import { CoreV1Api, KubeConfig, V1Namespace } from '@kubernetes/client-node';
import { describe, it } from 'vitest';

import { createConfigMaps } from './config-map';
import { NAMESPACE_NAME, TEST_ROOT_DIR } from './globals';
import { createNetworkServices } from './network-service';
import { createPods, createValidatorPod, killValidatorPod } from './pods';

const createNamespace = async (kc: KubeConfig, namespaceName: string) => {
	const k8sApi = kc.makeApiClient(CoreV1Api);
	const namespaceBody: V1Namespace = {
		metadata: {
			name: namespaceName,
		},
	};
	await k8sApi.createNamespace({ body: namespaceBody });
};

async function deployIkaNetwork() {
	const kc = new KubeConfig();
	kc.loadFromDefault();
	await createNamespace(kc, NAMESPACE_NAME);
	await createConfigMaps(kc, NAMESPACE_NAME, Number(process.env.VALIDATOR_NUM));
	await createPods(kc, NAMESPACE_NAME, Number(process.env.VALIDATOR_NUM));
	await createNetworkServices(kc, NAMESPACE_NAME);
}

describe('chaos tests', () => {
	it('deploy the ika network from the current directory to the local kubernetes cluster', async () => {
		require('dotenv').config({ path: `${TEST_ROOT_DIR}/.env` });
		await deployIkaNetwork();
	});

	it('deploy a network, add a validator for the next committee, and verify addition was successful', async () => {
		// let
		// require('dotenv').config({ path: `${TEST_ROOT_DIR}/.env` });
		// await deployIkaNetwork();
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

	it('should redeploy the config map with the new validator metadata', async () => {
		require('dotenv').config({ path: `${TEST_ROOT_DIR}/.env` });
		const kc = new KubeConfig();
		kc.loadFromDefault();
		await createConfigMaps(kc, NAMESPACE_NAME, Number(process.env.VALIDATOR_NUM) + 1, true);
	});
});
