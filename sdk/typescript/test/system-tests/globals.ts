import { promises as fs } from 'fs';
import path from 'path';
import { execa } from 'execa';

export const CONFIG_MAP_NAME = 'ika-system-test-config';
export const NETWORK_SERVICE_NAME = 'ika-dns-service';
export const NAMESPACE_NAME = 'ika';
export const TEST_ROOT_DIR = `${process.cwd()}/test/system-tests`;

export async function createIkaGenesis() {
	require('dotenv').config({ path: `${TEST_ROOT_DIR}/.env` });
	const createIkaGenesisPath = `${TEST_ROOT_DIR}/create-ika-genesis-mac.sh`;
	await execa({
		stdout: ['pipe', 'inherit'],
		stderr: ['pipe', 'inherit'],
		cwd: TEST_ROOT_DIR,
	})`${createIkaGenesisPath}`;
	await fs.copyFile(
		`${TEST_ROOT_DIR}/${process.env.SUBDOMAIN}/publisher/ika_config.json`,
		path.resolve(process.cwd(), '../../ika_config.json'),
	);
}
