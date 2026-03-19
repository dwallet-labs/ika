import type { KubeConfig } from '@kubernetes/client-node';
import { CoreV1Api } from '@kubernetes/client-node';

import { NETWORK_SERVICE_NAME } from './globals.js';

export async function createNetworkServices(kc: KubeConfig, namespaceName: string) {
	const k8sApi = kc.makeApiClient(CoreV1Api);
	await k8sApi.createNamespacedService({
		namespace: namespaceName,
		body: {
			metadata: {
				name: NETWORK_SERVICE_NAME,
			},
			spec: {
				clusterIP: 'None',
				ports: [
					{
						name: 'tx-interface',
						protocol: 'TCP',
						port: 8080,
						targetPort: 8080,
					},
					{
						name: 'p2p-sync',
						protocol: 'UDP',
						port: 8084,
						targetPort: 8084,
					},
					{
						name: 'metrics',
						protocol: 'TCP',
						port: 9184,
						targetPort: 9184,
					},
					{
						name: 'admin',
						protocol: 'TCP',
						port: 1337,
						targetPort: 1337,
					},
				],
				selector: {
					app: 'validator',
				},
				sessionAffinity: 'None',
				ipFamilies: ['IPv4'],
				ipFamilyPolicy: 'SingleStack',
				internalTrafficPolicy: 'Cluster',
			},
		},
	});
}
