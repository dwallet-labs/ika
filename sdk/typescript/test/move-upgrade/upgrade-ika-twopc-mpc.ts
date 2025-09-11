import { execSync } from 'child_process';
import { bcs } from '@mysten/bcs';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';

import { createTestIkaClient } from '../helpers/test-utils';
import { IkaClient } from '../../src';

const packagePath = '/root/code/dwallet-network/contracts/ika_dwallet_2pc_mpc';

async function deployUpgradedPackage(suiClient: SuiClient, signer: Ed25519Keypair, packagePath: string, ikaClient: IkaClient, protocolCapID: string): Promise<string> {
	const { modules, dependencies, digest } = JSON.parse(
		execSync(
			`sui move build --dump-bytecode-as-base64 --path ${packagePath}`,
			{
				encoding: 'utf-8',
			},
		),
	);

	const tx = new Transaction();
	let protocolCap = tx.object(protocolCapID);
	let systemStateArg = tx.sharedObjectRef({
		objectId: ikaClient.ikaConfig.objects.ikaSystemObject.objectID,
		initialSharedVersion: ikaClient.ikaConfig.objects.ikaSystemObject.initialSharedVersion,
		mutable: true,
	});
	let coordinatorStateArg = tx.sharedObjectRef({
		objectId: ikaClient.ikaConfig.objects.ikaDWalletCoordinator.objectID,
		initialSharedVersion: ikaClient.ikaConfig.objects.ikaDWalletCoordinator.initialSharedVersion,
		mutable: true,
	});

	tx.moveCall({
		target: `${ikaClient.ikaConfig.packages.ikaSystemPackage}::system::set_approved_upgrade_by_cap`,
		arguments: [
			systemStateArg,
			tx.pure.id(ikaClient.ikaConfig.packages.ikaDwallet2pcMpcPackage),
			tx.pure(bcs.option(bcs.vector(bcs.u8())).serialize(digest)),
			protocolCap,
		],
	});

	let [upgradeTicket, upgradeApprover] = tx.moveCall({
		target: `${ikaClient.ikaConfig.packages.ikaSystemPackage}::system::authorize_upgrade`,
		arguments: [systemStateArg, tx.pure.id(ikaClient.ikaConfig.packages.ikaDwallet2pcMpcPackage)],
	});

	const receipt = tx.upgrade({
		modules,
		dependencies,
		package: ikaClient.ikaConfig.packages.ikaDwallet2pcMpcPackage,
		ticket: upgradeTicket,
	});

	tx.moveCall({
		target: `${ikaClient.ikaConfig.packages.ikaSystemPackage}::system::commit_upgrade`,
		arguments: [systemStateArg, receipt, upgradeApprover],
	});
	tx.moveCall({
		target: `${ikaClient.ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::commit_upgrade`,
		arguments: [coordinatorStateArg, upgradeApprover],
	});

	tx.moveCall({
		target: `${ikaClient.ikaConfig.packages.ikaSystemPackage}::system::finalize_upgrade`,
		arguments: [systemStateArg, upgradeApprover],
	});
	const result = await suiClient.signAndExecuteTransaction({
		signer,
		transaction: tx,
		options: {
			showEffects: true,
			showObjectChanges: true,
		},
	});
	return result.effects.created.at(0).reference.objectId;
}

export async function updateIkaCoordinator() {
	let signer = Ed25519Keypair.deriveKeypair(
		'olive concert bargain feel shoot clean reward swim network castle aspect parade',
	);

	//
	// tx.moveCall({
	// 	target: `${ikaClient.ikaConfig.packages.ikaSystemPackage}::system::commit_upgrade`,
	// 	arguments: [systemStateArg, receipt, upgradeApprover],
	// });
	// tx.moveCall({
	// 	target: `${ikaClient.ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::commit_upgrade`,
	// 	arguments: [coordinatorStateArg, upgradeApprover],
	// });
	//
	// tx.moveCall({
	// 	target: `${ikaClient.ikaConfig.packages.ikaSystemPackage}::system::finalize_upgrade`,
	// 	arguments: [systemStateArg, upgradeApprover],
	// });
	// const client = new SuiClient({ url: getFullnodeUrl('localnet') });
	// const result = await client.signAndExecuteTransaction({
	// 	signer,
	// 	transaction: tx,
	// 	options: {
	// 		showEffects: true,
	// 		showObjectChanges: true,
	//
	// 	},
	// });
	//
	// console.log(result);
	const migrateTx = new Transaction();

	let systemStateArg = migrateTx.sharedObjectRef({
		objectId: ikaClient.ikaConfig.objects.ikaSystemObject.objectID,
		initialSharedVersion: ikaClient.ikaConfig.objects.ikaSystemObject.initialSharedVersion,
		mutable: true,
	});

	let coordinatorStateArg = migrateTx.sharedObjectRef({
		objectId: ikaClient.ikaConfig.objects.ikaDWalletCoordinator.objectID,
		initialSharedVersion: ikaClient.ikaConfig.objects.ikaDWalletCoordinator.initialSharedVersion,
		mutable: true,
	});
	protocolCap = migrateTx.object('0x67cfbdf4d56c2bea5746dd523e2d8fabd885e3e090e8da5400b86f7c316430c3');
	let verifiedProtocolCap = migrateTx.moveCall({
		target: `${ikaClient.ikaConfig.packages.ikaSystemPackage}::system::verify_protocol_cap`,
		arguments: [systemStateArg, protocolCap],
	});

	// migrateTx.moveCall({
	// 	target: `${result.effects.created.at(0).reference.objectId}::coordinator::try_migrate_by_cap`,
	// 	arguments: [coordinatorStateArg, verifiedProtocolCap],
	// });
	migrateTx.moveCall({
		target: `0x12b76afe3db6b2ed0881f7a22b4ad5f5d58a2bdf8dcf3770b9f86d746a4d3dad::coordinator::try_migrate_by_cap`,
		arguments: [coordinatorStateArg, verifiedProtocolCap],
	});
	const migrateResult = await suiClient.signAndExecuteTransaction({
		signer,
		transaction: migrateTx,
		options: {
			showEffects: true,
			showObjectChanges: true,
		},
	});
}
