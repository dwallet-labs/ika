import type { KubeConfig, V1Pod } from '@kubernetes/client-node';
import { CoreV1Api } from '@kubernetes/client-node';

import { CONFIG_MAP_NAME, NETWORK_SERVICE_NAME } from './globals.js';

export async function createPods(kc: KubeConfig, namespaceName: string, numOfValidators: number) {
	const k8sApi = kc.makeApiClient(CoreV1Api);
	for (let i = 0; i < numOfValidators; i++) {
		const pod: V1Pod = {
			metadata: {
				name: `ika-val-${i + 1}`,
				namespace: namespaceName,
				labels: {
					app: 'validator',
				},
			},
			spec: {
				hostname: `val${i + 1}`,
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
						command: ['/opt/ika/bin/ika-node', '--config-path', '/opt/ika/config/validator.yaml'],
						name: 'ika-node',
						image: process.env.DOCKER_TAG,
						volumeMounts: [
							{
								name: 'config-vol',
								mountPath: '/opt/ika/key-pairs/class-groups.key',
								subPath: 'class-groups.key',
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
									key: `validator${i + 1}_class-groups.key`,
									path: 'class-groups.key',
								},
								{
									key: `validator${i + 1}_consensus.key`,
									path: 'consensus.key',
								},
								{
									key: `validator${i + 1}_network.key`,
									path: 'network.key',
								},
								{
									key: `validator${i + 1}_protocol.key`,
									path: 'protocol.key',
								},
								{
									key: `validator${i + 1}.yaml`,
									path: 'validator.yaml',
								},
							],
						},
					},
				],
				restartPolicy: 'Always',
			},
		};
		await k8sApi.createNamespacedPod({
			namespace: namespaceName,
			body: pod,
		});
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
			restartPolicy: 'Always',
		},
	};
	await k8sApi.createNamespacedPod({
		namespace: namespaceName,
		body: fullnodePod,
	});
}
