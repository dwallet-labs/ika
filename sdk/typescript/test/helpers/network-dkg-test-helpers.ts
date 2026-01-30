import type { ClientWithCoreApi } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';

import * as CoordinatorInnerModule from '../../src/generated/ika_dwallet_2pc_mpc/coordinator_inner.js';
import { requestDwalletNetworkEncryptionKeyDkgByCap } from '../../src/tx/coordinator';
import { verifyProtocolCap } from '../../src/tx/system';
import {
	createTestIkaClient,
	executeTestTransactionWithKeypair,
	getObjectWithType,
} from './test-utils';

interface ActiveNetworkKey {
	state: {
		variant: 'NetworkDKGCompleted';
	};
	id: { id: string };
}

export async function testCreateNetworkKey(
	suiClient: ClientWithCoreApi,
	protocolCapID: string,
	publisherKeypair: Ed25519Keypair,
): Promise<string> {
	const ikaClient = createTestIkaClient(suiClient);
	await ikaClient.initialize();
	const tx = new Transaction();
	const coordinatorStateArg = tx.sharedObjectRef({
		objectId: ikaClient.ikaConfig.objects.ikaDWalletCoordinator.objectID,
		initialSharedVersion: ikaClient.ikaConfig.objects.ikaDWalletCoordinator.initialSharedVersion,
		mutable: true,
	});
	const systemStateArg = tx.sharedObjectRef({
		objectId: ikaClient.ikaConfig.objects.ikaSystemObject.objectID,
		initialSharedVersion: ikaClient.ikaConfig.objects.ikaSystemObject.initialSharedVersion,
		mutable: false,
	});
	const verifiedProtocolCap = verifyProtocolCap(
		ikaClient.ikaConfig,
		systemStateArg,
		protocolCapID,
		tx,
	);
	requestDwalletNetworkEncryptionKeyDkgByCap(
		ikaClient.ikaConfig,
		coordinatorStateArg,
		Uint8Array.from([]),
		verifiedProtocolCap,
		tx,
	);
	const result = await executeTestTransactionWithKeypair(suiClient, tx, publisherKeypair);
	const dkgEvent = result.events?.find((event) =>
		event.type.includes('DWalletNetworkDKGEncryptionKeyRequestEvent'),
	);
	if (!dkgEvent) {
		throw new Error(
			`DWalletNetworkDKGEncryptionKeyRequestEvent not found in events: ${JSON.stringify(result.events)}`,
		);
	}
	const startDKGEvent =
		CoordinatorInnerModule.DWalletNetworkDKGEncryptionKeyRequestEvent.fromBase64(dkgEvent.bcs);
	console.log('Start DKG Event:', startDKGEvent);
	console.log('Network Key ID:', startDKGEvent.dwallet_network_encryption_key_id);
	await getObjectWithType(
		suiClient,
		startDKGEvent.dwallet_network_encryption_key_id,
		isActiveNetworkKey,
	);
	return startDKGEvent.dwallet_network_encryption_key_id;
}

function isActiveNetworkKey(obj: any): obj is ActiveNetworkKey {
	return obj?.state?.variant === 'NetworkDKGCompleted';
}
