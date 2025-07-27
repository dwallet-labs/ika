import type { KubeConfig, V1Pod } from '@kubernetes/client-node';
import { CoreV1Api } from '@kubernetes/client-node';

import { CONFIG_MAP_NAME, NETWORK_SERVICE_NAME } from './globals.js';

export function getPodNameForValidatorID(validatorID: number): string {
	return `ika-val-${validatorID}`;
}

export async function killValidatorPod(kc: KubeConfig, namespaceName: string, validatorID: number) {
	const k8sApi = kc.makeApiClient(CoreV1Api);
	await k8sApi.deleteNamespacedPod({
		namespace: namespaceName,
		name: getPodNameForValidatorID(validatorID),
	});
}

export async function createValidatorPod(
	kc: KubeConfig,
	namespaceName: string,
	validatorID: number,
) {
	const k8sApi = kc.makeApiClient(CoreV1Api);
	const pod: V1Pod = {
		metadata: {
			name: getPodNameForValidatorID(validatorID),
			namespace: namespaceName,
			labels: {
				app: 'validator',
			},
		},
		spec: {
			hostname: `val${validatorID}`,
			subdomain: NETWORK_SERVICE_NAME,
			containers: [
				{
					env: [
						{
							name: 'RUST_LOG',
							value: 'off,ika_node=info,ika_core=info',
						},
						{
							name: 'RUST_MIN_STACK',
							value: '16777216',
						},
						{
							name: 'RUST_BACKTRACE',
							value: 'full',
						},
					],
					command: ['/opt/ika/bin/ika-node', '--config-path', '/opt/ika/config/validator.yaml'],
					name: 'ika-node',
					image: process.env.DOCKER_TAG,
					volumeMounts: [
						{
							name: 'config-vol',
							mountPath: '/opt/ika/key-pairs/class-groups.seed',
							subPath: 'class-groups.seed',
						},
						{
							name: 'config-vol',
							mountPath: '/opt/ika/key-pairs/consensus.key',
							subPath: 'consensus.key',
						},
						{
							name: 'config-vol',
							mountPath: '/opt/ika/key-pairs/network.key',
							subPath: 'network.key',
						},
						{
							name: 'config-vol',
							mountPath: '/opt/ika/key-pairs/protocol.key',
							subPath: 'protocol.key',
						},
						{
							name: 'config-vol',
							mountPath: '/opt/ika/config/validator.yaml',
							subPath: 'validator.yaml',
						},
					],
				},
			],
			volumes: [
				{
					name: 'config-vol',
					configMap: {
						name: CONFIG_MAP_NAME,
						items: [
							{
								key: `validator${validatorID}_class-groups.seed`,
								path: 'class-groups.seed',
							},
							{
								key: `validator${validatorID}_consensus.key`,
								path: 'consensus.key',
							},
							{
								key: `validator${validatorID}_network.key`,
								path: 'network.key',
							},
							{
								key: `validator${validatorID}_protocol.key`,
								path: 'protocol.key',
							},
							{
								key: `validator${validatorID}.yaml`,
								path: 'validator.yaml',
							},
						],
					},
				},
			],
			restartPolicy: 'Never',
		},
	};
	await k8sApi.createNamespacedPod({
		namespace: namespaceName,
		body: pod,
	});
}

export async function createPods(kc: KubeConfig, namespaceName: string, numOfValidators: number) {
	const k8sApi = kc.makeApiClient(CoreV1Api);
	for (let i = 0; i < numOfValidators; i++) {
		await createValidatorPod(kc, namespaceName, i + 1);
	}
	const fullnodePod = {
		metadata: {
			name: `ika-fullnode`,
			namespace: namespaceName,
		},
		spec: {
			hostname: 'fullnode',
			subdomain: NETWORK_SERVICE_NAME,
			containers: [
				{
					env: [
						{
							name: 'RUST_LOG',
							value: 'off,ika_node=info,ika_core=info',
						},
						{
							name: 'RUST_MIN_STACK',
							value: '16777216',
						},
					],
					command: ['/opt/ika/bin/ika-node', '--config-path', '/opt/ika/config/fullnode.yaml'],
					name: 'ika-node',
					image: process.env.DOCKER_TAG,
					volumeMounts: [
						{
							name: 'config-vol',
							mountPath: '/opt/ika/key-pairs/notifier.key',
							subPath: 'notifier.key',
						},
						{
							name: 'config-vol',
							mountPath: '/opt/ika/config/fullnode.yaml',
							subPath: 'fullnode.yaml',
						},
					],
				},
			],
			volumes: [
				{
					name: 'config-vol',
					configMap: {
						name: CONFIG_MAP_NAME,
						items: [
							{
								key: `notifier.key`,
								path: 'notifier.key',
							},
							{
								key: `fullnode.yaml`,
								path: 'fullnode.yaml',
							},
						],
					},
				},
			],
			restartPolicy: 'Never',
		},
	};
	await k8sApi.createNamespacedPod({
		namespace: namespaceName,
		body: fullnodePod,
	});
}
