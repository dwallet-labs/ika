import { execSync } from 'child_process';
import { promises as fs } from 'fs';
import path from 'path';
import * as TOML from '@iarna/toml';
import { bcs } from '@mysten/bcs';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { describe, it } from 'vitest';

import { IkaClient } from '../../src';
import { createTestIkaClient, delay } from '../helpers/test-utils';
import { createIkaGenesis, TEST_ROOT_DIR } from '../system-tests/globals';

describe('Upgrade twopc_mpc Move package', () => {
	it('Update the twopc_mpc package and migrate the dwallet coordinator', async () => {
		await createIkaGenesis();
		const signer = await getPublisherKeypair();
		const suiClient = new SuiClient({ url: getFullnodeUrl('localnet') });
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		const twopc_mpc_contracts_path = path.join(
			TEST_ROOT_DIR,
			'../../../../contracts/ika_dwallet_2pc_mpc',
		);
		const ika_twopc_move_toml = TOML.parse(
			await fs.readFile(path.join(twopc_mpc_contracts_path, 'Move.toml'), 'utf8'),
		);
		ika_twopc_move_toml.addresses.ika = ikaClient.ikaConfig.packages.ikaPackage;
		await fs.writeFile(
			path.join(twopc_mpc_contracts_path, 'Move.toml'),
			TOML.stringify(ika_twopc_move_toml),
		);
		const ikaMoveToml = TOML.parse(
			await fs.readFile(path.join(TEST_ROOT_DIR, '../../../../contracts/ika/Move.toml'), 'utf8'),
		);
		ikaMoveToml.package['published-at'] = ikaClient.ikaConfig.packages.ikaPackage;
		ikaMoveToml.addresses.ika = ikaClient.ikaConfig.packages.ikaPackage;
		await fs.writeFile(
			path.join(TEST_ROOT_DIR, '../../../../contracts/ika/Move.toml'),
			TOML.stringify(ikaMoveToml),
		);
		const ikaCommonToml = TOML.parse(
			await fs.readFile(
				path.join(TEST_ROOT_DIR, '../../../../contracts/ika_common/Move.toml'),
				'utf8',
			),
		);
		ikaCommonToml.package['published-at'] = ikaClient.ikaConfig.packages.ikaCommonPackage;
		ikaCommonToml.addresses.ika_common = ikaClient.ikaConfig.packages.ikaCommonPackage;
		await fs.writeFile(
			path.join(TEST_ROOT_DIR, '../../../../contracts/ika_common/Move.toml'),
			TOML.stringify(ikaCommonToml),
		);

		const protocolCapID = await getProtocolCapID(
			suiClient,
			signer.getPublicKey().toSuiAddress(),
			ikaClient,
		);

		const upgradedPackageID = await deployUpgradedPackage(
			suiClient,
			signer,
			twopc_mpc_contracts_path,
			ikaClient,
			protocolCapID,
		);
		await delay(5); // wait for the upgrade to be fully processed
		await migrateCoordinator(suiClient, signer, ikaClient, protocolCapID, upgradedPackageID);
	});
});

export async function getPublisherKeypair(): Promise<Ed25519Keypair> {
	let publisherMnemonicBytes = await fs.readFile(
		`${TEST_ROOT_DIR}/${process.env.SUBDOMAIN}/publisher/sui_config/publisher.seed`,
	);
	const publisherMnemonic = new TextDecoder().decode(publisherMnemonicBytes);
	return Ed25519Keypair.deriveKeypair(publisherMnemonic.trimEnd());
}

export async function getProtocolCapID(
	suiClient: SuiClient,
	publisherAddress: string,
	ikaClient: IkaClient,
): Promise<string> {
	const protocolCapID = (
		await suiClient.getOwnedObjects({
			owner: publisherAddress,
			filter: {
				StructType: `${ikaClient.ikaConfig.packages.ikaCommonPackage}::protocol_cap::ProtocolCap`,
			},
		})
	).data.at(0).data.objectId;
	return protocolCapID;
}

export async function deployUpgradedPackage(
	suiClient: SuiClient,
	signer: Ed25519Keypair,
	packagePath: string,
	ikaClient: IkaClient,
	protocolCapID: string,
): Promise<string> {
	const { modules, dependencies, digest } = JSON.parse(
		execSync(`sui move build --dump-bytecode-as-base64 --path ${packagePath}`, {
			encoding: 'utf-8',
		}),
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

export async function migrateCoordinator(
	suiClient: SuiClient,
	signer: Ed25519Keypair,
	ikaClient: IkaClient,
	protocolCapID: string,
	new2PCMPCPackageID: string,
) {
	const tx = new Transaction();

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
	const protocolCap = tx.object(protocolCapID);
	const verifiedProtocolCap = tx.moveCall({
		target: `${ikaClient.ikaConfig.packages.ikaSystemPackage}::system::verify_protocol_cap`,
		arguments: [systemStateArg, protocolCap],
	});
	tx.moveCall({
		target: `${new2PCMPCPackageID}::coordinator::try_migrate_by_cap`,
		arguments: [coordinatorStateArg, verifiedProtocolCap],
	});
	await suiClient.signAndExecuteTransaction({
		signer,
		transaction: tx,
		options: {
			showEffects: true,
			showObjectChanges: true,
		},
	});
}
