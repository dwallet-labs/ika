import { execSync } from 'child_process';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';

import { createTestIkaClient } from '../helpers/test-utils';

const packagePath = '/root/code/dwallet-network/contracts/ika_dwallet_2pc_mpc';

async function main() {
	let signer = Ed25519Keypair.deriveKeypair('<PUBLISHER-KEYPAIR>');
	const { modules, dependencies, digest } = JSON.parse(
		execSync(`sui move build --dump-bytecode-as-base64 --path ${packagePath}`, {
			encoding: 'utf-8',
		}),
	);

	const tx = new Transaction();
	const protocolCap = tx.object('<PROTOCOL-CAP-ID>');
	const suiClient = new SuiClient({ url: getFullnodeUrl('localnet') });
	const ikaClient = createTestIkaClient(suiClient);
	const systemStateArg = tx.sharedObjectRef({
		objectId: ikaClient.ikaConfig.objects.ikaSystemObject.objectID,
		initialSharedVersion: ikaClient.ikaConfig.objects.ikaSystemObject.initialSharedVersion,
		mutable: true,
	});
	const coordinatorStateArg = tx.sharedObjectRef({
		objectId: ikaClient.ikaConfig.objects.ikaDWalletCoordinator.objectID,
		initialSharedVersion: ikaClient.ikaConfig.objects.ikaDWalletCoordinator.initialSharedVersion,
		mutable: true,
	});

	tx.moveCall({
		target: `${ikaClient.ikaConfig.packages.ikaSystemPackage}::system::set_approved_upgrade_by_cap`,
		arguments: [
			systemStateArg,
			tx.pure.id(ikaClient.ikaConfig.packages.ikaDwallet2pcMpcPackage),
			tx.pure(digest),
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
		target: `${ikaClient.ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::commit_upgrade`,
		arguments: [systemStateArg, receipt, upgradeApprover],
	});

	let verifiedProtocolCap = tx.moveCall({
		target: `${ikaClient.ikaConfig.packages.ikaSystemPackage}::system::verify_protocol_cap`,
		arguments: [systemStateArg, protocolCap],
	});

	tx.moveCall({
		target: `${ikaClient.ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::try_migrate_by_cap`,
		arguments: [coordinatorStateArg, verifiedProtocolCap],
	});

	const client = new SuiClient({ url: getFullnodeUrl('localnet') });
	const result = await client.signAndExecuteTransaction({
		signer,
		transaction: tx,
		options: {
			showEffects: true,
			showObjectChanges: true,
		},
	});

	console.log(result);
}

main()
	.catch((e) => {
		console.error(e);
		process.exit(1);
	})
	.then(() => process.exit(0));
