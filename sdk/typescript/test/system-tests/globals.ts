import { CoreV1Api, KubeConfig, V1Namespace } from '@kubernetes/client-node';

import { createConfigMaps } from './config-map';
import { createNetworkServices } from './network-service';
import { createPods } from './pods';

export const CONFIG_MAP_NAME = 'ika-system-test-config';
export const NETWORK_SERVICE_NAME = 'ika-dns-service';
export const NAMESPACE_NAME = 'ika';
export const TEST_ROOT_DIR = `${process.cwd()}/test/system-test`;
export const createNamespace = async (kc: KubeConfig, namespaceName: string) => {
	const k8sApi = kc.makeApiClient(CoreV1Api);
	const namespaceBody: V1Namespace = {
		metadata: {
			name: namespaceName,
		},
	};
	await k8sApi.createNamespace({ body: namespaceBody });
};

export async function deployIkaNetwork() {
	const kc = new KubeConfig();
	kc.loadFromDefault();
	await createNamespace(kc, NAMESPACE_NAME);
	await createConfigMaps(kc, NAMESPACE_NAME, Number(process.env.VALIDATOR_NUM));
	await createPods(kc, NAMESPACE_NAME, Number(process.env.VALIDATOR_NUM));
	await createNetworkServices(kc, NAMESPACE_NAME);
}
