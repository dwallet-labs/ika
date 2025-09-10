import { execSync } from 'child_process';
import { readFileSync } from 'fs';
import { homedir } from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction, UpgradePolicy } from '@mysten/sui/transactions';
import { fromBase64 } from '@mysten/sui/utils';
import { createTestIkaClient } from '../helpers/test-utils';

const SUI = 'sui';
const POLICY_PACKAGE_ID = '<POLICY-PACKAGE>';
const EXAMPLE_PACKAGE_ID = '<EXAMPLE-PACKAGE>';
const CAP_ID = '<EXAMPLE-UPGRADE-CAP>';
const sender = execSync(`${SUI} client active-address`, { encoding: 'utf8' }).trim();
const signer = (() => {
	const keystore = JSON.parse(
		readFileSync(path.join(homedir(), '.sui', 'sui_config', 'sui.keystore'), 'utf8'),
	);

	for (const priv of keystore) {
		const raw = fromBase64(priv);
		if (raw[0] !== 0) {
			continue;
		}

		const pair = Ed25519Keypair.fromSecretKey(raw.slice(1));
		if (pair.getPublicKey().toSuiAddress() === sender) {
			return pair;
		}
	}

	throw new Error(`key pair not found for sender: ${sender}`);
})();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packagePath = path.join(__dirname, 'example');

const { modules, dependencies, digest } = JSON.parse(
	execSync(`${SUI} move build --dump-bytecode-as-base64 --path ${packagePath}`, {
		encoding: 'utf-8',
	}),
);

const tx = new Transaction();
const cap = tx.object(CAP_ID);
const protocolCap = tx.object("<PROTOCOL-CAP-ID>");
const suiClient = new SuiClient({ url: getFullnodeUrl('localnet') });
const ikaClient = createTestIkaClient(suiClient)
tx.moveCall(

)

const ticket = tx.moveCall({
	target: `${POLICY_PACKAGE_ID}::day_of_week::authorize_upgrade`,
	arguments: [cap, tx.pure(UpgradePolicy.COMPATIBLE), tx.pure(digest)],
});

const receipt = tx.upgrade({
	modules,
	dependencies,
	packageId: EXAMPLE_PACKAGE_ID,
	ticket,
});

tx.moveCall({
	target: `${POLICY_PACKAGE_ID}::day_of_week::commit_upgrade`,
	arguments: [cap, receipt],
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