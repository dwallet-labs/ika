import { bcs } from '@mysten/bcs';
import { Transaction } from '@mysten/sui/transactions';

import {
	Config,
	createSessionIdentifier,
	DWALLET_COORDINATOR_MOVE_MODULE_NAME,
	DWALLET_SYSTEM_MOVE_MODULE_NAME,
	getInitialSharedVersion,
	getNetworkDecryptionKeyID,
	SUI_PACKAGE_ID,
} from './globals';

export async function createNetworkKey(c: Config, protocolCapID: string): Promise<string> {
	const tx = new Transaction();
	const emptyIKACoin = tx.moveCall({
		target: `${SUI_PACKAGE_ID}::coin::zero`,
		arguments: [],
		typeArguments: [`${c.ikaConfig.packages.ika_package_id}::ika::IKA`],
	});
	const dwalletStateArg = tx.sharedObjectRef({
		objectId: c.ikaConfig.objects.ika_dwallet_coordinator_object_id,
		initialSharedVersion: await getInitialSharedVersion(
			c,
			c.ikaConfig.objects.ika_dwallet_coordinator_object_id,
		),
		mutable: true,
	});
	let verifiedProtocolCap = tx.moveCall({
		target: `${c.ikaConfig.packages.ika_system_package_id}::${DWALLET_SYSTEM_MOVE_MODULE_NAME}::verify_protocol_cap`,
		arguments: [dwalletStateArg, tx.object(protocolCapID)],
	});
	const dwalletCap = tx.moveCall({
		target: `${c.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::request_dwallet_network_encryption_key_dkg_by_cap`,
		arguments: [dwalletStateArg, tx.pure(bcs.vector(bcs.u8()).serialize([]))],
	});
	tx.transferObjects([dwalletCap], c.suiClientKeypair.toSuiAddress());
	tx.moveCall({
		target: `${SUI_PACKAGE_ID}::coin::destroy_zero`,
		arguments: [emptyIKACoin],
		typeArguments: [`${c.ikaConfig.packages.ika_package_id}::ika::IKA`],
	});
	const result = await c.client.signAndExecuteTransaction({
		signer: c.suiClientKeypair,
		transaction: tx,
		options: {
			showEffects: true,
			showEvents: true,
		},
	});
	const startDKGEvent = result.events?.at(1)?.parsedJson;
	if (!isStartDKGFirstRoundEvent(startDKGEvent)) {
		throw new Error('invalid start DKG first round event');
	}
	const dwalletID = startDKGEvent.event_data.dwallet_id;
	const output = await waitForDKGFirstRoundOutput(c, dwalletID);
	return {
		sessionIdentifier: startDKGEvent.session_identifier_preimage,
		output: output,
		dwalletCapID: startDKGEvent.event_data.dwallet_cap_id,
		dwalletID,
	};
}
