import { CoreV1Api, KubeConfig, V1Namespace } from '@kubernetes/client-node';
import { describe, it } from 'vitest';

import { createConfigMap } from './config-map';
import { NAMESPACE_NAME, TEST_ROOT_DIR } from './globals';
import { createNetworkServices } from './network-service';
import { createPods } from './pods';

const createNamespace = async (kc: KubeConfig, namespaceName: string) => {
	const k8sApi = kc.makeApiClient(CoreV1Api);
	const namespaceBody: V1Namespace = {
		metadata: {
			name: namespaceName,
		},
	};
	await k8sApi.createNamespace({ body: namespaceBody });
};

describe('chaos tests', () => {
	it('deploy the ika network from the current directory to the local kubernetes cluster', async () => {
		require('dotenv').config({ path: `${TEST_ROOT_DIR}/.env` });
		const kc = new KubeConfig();
		kc.loadFromDefault();
		await createNamespace(kc, NAMESPACE_NAME);
		await createConfigMap(kc, NAMESPACE_NAME, Number(process.env.VALIDATOR_NUM));
		await createPods(kc, NAMESPACE_NAME, Number(process.env.VALIDATOR_NUM));
		await createNetworkServices(kc, NAMESPACE_NAME);
	});
});
