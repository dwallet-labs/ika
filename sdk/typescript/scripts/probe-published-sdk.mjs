// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Probes the PUBLISHED @ika.xyz/sdk from npm, not this checkout.
 *
 * The repo-source probe (`test/live/public-endpoints.test.ts`) cannot see the
 * failure mode that motivated it: the WASM published as @ika.xyz/ika-wasm@0.2.1
 * could not decode V4-tagged reconfiguration outputs while this repo's source
 * could, so a HEAD-built probe reported green for months while every install
 * from npm was broken. This script installs what a user actually gets and runs
 * the same reads against the same live endpoints, which also exercises the
 * packaging itself — `files` whitelist, `exports` map, dependency ranges.
 *
 * Exit codes: 0 = the published SDK works (or the fullnodes were unreachable,
 * which is not its fault), 1 = a user installing it today is broken.
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const NETWORKS = ['mainnet', 'testnet'];
const SPEC = process.env.IKA_SDK_SPEC || '@ika.xyz/sdk@latest';
const OPERATION_DEADLINE_MS = 60_000;
const REACHABILITY_DEADLINE_MS = 10_000;

const workdir = mkdtempSync(join(tmpdir(), 'ika-published-probe-'));
writeFileSync(join(workdir, 'package.json'), JSON.stringify({ type: 'module' }));

console.log(`Installing ${SPEC} into ${workdir}`);
execFileSync('npm', ['install', SPEC, '--no-audit', '--no-fund', '--silent'], {
	cwd: workdir,
	stdio: 'inherit',
});

const { getNetworkConfig, IkaClient } = await import(
	join(workdir, 'node_modules/@ika.xyz/sdk/dist/esm/index.js')
);
const { SuiGrpcClient } = await import(
	join(workdir, 'node_modules/@mysten/sui/dist/grpc/index.mjs')
);

const installed = JSON.parse(
	execFileSync('npm', ['ls', '@ika.xyz/sdk', '@ika.xyz/ika-wasm', '--json'], {
		cwd: workdir,
		encoding: 'utf8',
	}),
);
console.log('Resolved:', JSON.stringify(installed.dependencies, null, 1));

async function withDeadline(label, ms, run) {
	let timer;
	try {
		return await Promise.race([
			run(),
			new Promise((_, reject) => {
				timer = setTimeout(() => reject(new Error(`${label} exceeded ${ms}ms`)), ms);
			}),
		]);
	} finally {
		clearTimeout(timer);
	}
}

let brokenForUsers = false;

for (const network of NETWORKS) {
	const baseUrl =
		process.env[`SUI_${network.toUpperCase()}_GRPC_URL`] ||
		`https://fullnode.${network}.sui.io:443`;
	const suiClient = new SuiGrpcClient({ network, baseUrl });
	const ikaClient = new IkaClient({ suiClient, config: getNetworkConfig(network), cache: true });

	try {
		await withDeadline(`${network} probe`, OPERATION_DEADLINE_MS, async () => {
			await ikaClient.initialize();
			await ikaClient.getEpoch();
			await ikaClient.getLatestNetworkEncryptionKey();
			await ikaClient.getProtocolPublicParameters(undefined, 'SECP256K1');
		});
		console.log(`${network}: published SDK OK`);
	} catch (error) {
		// Same oracle as the source probe: ask the endpoint whether it is the
		// one at fault before blaming the package.
		const reachable = await withDeadline('reachability check', REACHABILITY_DEADLINE_MS, () =>
			suiClient.ledgerService.getServiceInfo({}),
		).then(
			() => true,
			() => false,
		);

		if (!reachable) {
			console.log(`${network}: SKIPPED — fullnode unreachable (${error.message})`);
			continue;
		}

		brokenForUsers = true;
		console.error(`${network}: PUBLISHED SDK BROKEN — ${error.message}`);
		if (error.cause) console.error(`  cause: ${error.cause.message ?? error.cause}`);
	}
}

if (brokenForUsers) {
	console.error(
		'\nThe package on npm fails against a healthy fullnode. If this checkout works, ' +
			'the fix is to publish the pending release, not to change code.',
	);
	process.exit(1);
}
