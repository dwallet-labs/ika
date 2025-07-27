import fs from 'fs';
import path from 'path';
import type { KubeConfig, V1ConfigMap } from '@kubernetes/client-node';
import { CoreV1Api } from '@kubernetes/client-node';

import { CONFIG_MAP_NAME, NAMESPACE_NAME, NETWORK_SERVICE_NAME, TEST_ROOT_DIR } from './globals.js';

export async function createConfigMap(
	kc: KubeConfig,
	namespaceName: string,
	numOfValidators: number,
): Promise<V1ConfigMap> {
	const k8sApi = kc.makeApiClient(CoreV1Api);
	const fullNodeYaml = fs.readFileSync(
		path.resolve(
			TEST_ROOT_DIR,
			`${NETWORK_SERVICE_NAME}.${NAMESPACE_NAME}.svc.cluster.local/publisher/fullnode.yaml`,
		),
		'utf8',
	);
	const validatorsConfig: Record<string, string> = {};
	for (let i = 0; i < numOfValidators; i++) {
		validatorsConfig[`validator${i + 1}_class-groups.key`] = fs.readFileSync(
			path.resolve(
				TEST_ROOT_DIR,
				`${NETWORK_SERVICE_NAME}.${NAMESPACE_NAME}.svc.cluster.local/val${i + 1}.${NETWORK_SERVICE_NAME}.${NAMESPACE_NAME}.svc.cluster.local/key-pairs/class-groups.key`,
			),
			'utf8',
		);
		validatorsConfig[`validator${i + 1}_consensus.key`] = fs.readFileSync(
			`${TEST_ROOT_DIR}/${NETWORK_SERVICE_NAME}.${NAMESPACE_NAME}.svc.cluster.local/val${i + 1}.${NETWORK_SERVICE_NAME}.${NAMESPACE_NAME}.svc.cluster.local/key-pairs/consensus.key`,
			'utf8',
		);
		validatorsConfig[`validator${i + 1}_network.key`] = fs.readFileSync(
			`${TEST_ROOT_DIR}/${NETWORK_SERVICE_NAME}.${NAMESPACE_NAME}.svc.cluster.local/val${i + 1}.${NETWORK_SERVICE_NAME}.${NAMESPACE_NAME}.svc.cluster.local/key-pairs/network.key`,
			'utf8',
		);
		validatorsConfig[`validator${i + 1}_protocol.key`] = fs.readFileSync(
			`${TEST_ROOT_DIR}/${NETWORK_SERVICE_NAME}.${NAMESPACE_NAME}.svc.cluster.local/val${i + 1}.${NETWORK_SERVICE_NAME}.${NAMESPACE_NAME}.svc.cluster.local/key-pairs/protocol.key`,
			'utf8',
		);
		validatorsConfig[`validator${i + 1}.yaml`] = fs.readFileSync(
			`${TEST_ROOT_DIR}/${NETWORK_SERVICE_NAME}.${NAMESPACE_NAME}.svc.cluster.local/val${i + 1}.${NETWORK_SERVICE_NAME}.${NAMESPACE_NAME}.svc.cluster.local/validator.yaml`,
			'utf-8',
		);
	}

	const configMap: V1ConfigMap = {
		metadata: {
			namespace: namespaceName,
			name: CONFIG_MAP_NAME,
		},
		data: {
			'fullnode.yaml': fullNodeYaml,
			'notifier.key': fs.readFileSync(
				`${TEST_ROOT_DIR}/${NETWORK_SERVICE_NAME}.${NAMESPACE_NAME}.svc.cluster.local/publisher/sui_config/publisher.key`,
				'utf8',
			),
			...validatorsConfig,
		},
	};
	return await k8sApi.createNamespacedConfigMap({
		namespace: namespaceName,
		body: configMap,
	});
}
