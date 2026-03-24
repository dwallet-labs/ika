#!/usr/bin/env node
// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * ika-ows CLI — Open Wallet Standard backed by Ika dWallet MPC signing.
 *
 * Mirrors the OWS CLI structure with Ika-specific extensions:
 *   wallet, sign, presign, pay, mnemonic, policy, key
 */

import { Command } from 'commander';

import { generateMnemonic, deriveAddressFromMnemonic } from '../mnemonic.js';
import type { IkaOWSProvider } from '../provider.js';

const program = new Command();

program
	.name('ika-ows')
	.description('Open Wallet Standard CLI backed by Ika dWallet MPC signing')
	.version('0.1.0');

// ─── Shared Helpers ──────────────────────────────────────────────────────

function getNetwork(): 'testnet' | 'mainnet' {
	const net = process.env['IKA_OWS_NETWORK'] ?? 'mainnet';
	if (net !== 'testnet' && net !== 'mainnet') {
		throw new Error(`Invalid network: ${net}`);
	}
	return net;
}

async function createProvider(): Promise<IkaOWSProvider> {
	const { Ed25519Keypair } = await import('@mysten/sui/keypairs/ed25519');
	const { IkaOWSProvider: Provider } = await import('../provider.js');

	const hex = process.env['IKA_OWS_KEYPAIR'];
	if (!hex) throw new Error('Set IKA_OWS_KEYPAIR env (hex-encoded ed25519 secret key, 32 bytes)');

	const keypair = Ed25519Keypair.fromSecretKey(Buffer.from(hex, 'hex'));
	const provider = new Provider({
		network: getNetwork(),
		keypair,
		vaultPath: process.env['IKA_OWS_VAULT_PATH'],
	});
	await provider.initialize();
	return provider;
}

// ─── wallet ──────────────────────────────────────────────────────────────

const wallet = program.command('wallet').description('Wallet management');

wallet
	.command('create')
	.description('Create a new mnemonic-backed wallet (imported into Ika for MPC signing)')
	.requiredOption('--name <name>', 'Wallet name')
	.option('--words <count>', 'BIP-39 word count', '12')
	.option('--curve <curve>', 'Curve: SECP256K1, ED25519, SECP256R1', 'SECP256K1')
	.option('--show-mnemonic', 'Display the generated mnemonic')
	.action(async (opts) => {
		const passphrase = process.env['IKA_OWS_PASSPHRASE'] ?? '';
		const provider = await createProvider();
		const w = await provider.createWallet(opts.name, passphrase, {
			words: parseInt(opts.words),
			curve: opts.curve,
		});
		console.log(JSON.stringify(w, null, 2));
		if (opts.showMnemonic) {
			console.log(`\nMnemonic: ${provider.exportWallet(opts.name, passphrase)}`);
		}
	});

wallet
	.command('dkg')
	.description('Create a pure MPC wallet via DKG (no mnemonic, maximum security)')
	.requiredOption('--name <name>', 'Wallet name')
	.option('--curve <curve>', 'Curve: SECP256K1, ED25519, SECP256R1', 'SECP256K1')
	.action(async (opts) => {
		const provider = await createProvider();
		const w = await provider.createDWallet(opts.name, { curve: opts.curve });
		console.log(JSON.stringify(w, null, 2));
	});

wallet
	.command('import')
	.description('Import wallet from mnemonic or private key')
	.requiredOption('--name <name>', 'Wallet name')
	.option('--mnemonic', 'Import from mnemonic')
	.option('--private-key', 'Import from private key')
	.option('--value <secret>', 'Mnemonic phrase or hex private key')
	.option('--curve <curve>', 'Curve', 'SECP256K1')
	.option('--index <n>', 'BIP-44 account index (mnemonic only)', '0')
	.action(async (opts) => {
		const provider = await createProvider();
		const passphrase = process.env['IKA_OWS_PASSPHRASE'] ?? '';

		if (opts.mnemonic) {
			const mnemonic = opts.value ?? process.env['IKA_OWS_MNEMONIC'];
			if (!mnemonic) throw new Error('Provide mnemonic via --value or IKA_OWS_MNEMONIC env');
			const w = await provider.importWalletMnemonic(opts.name, mnemonic, passphrase, {
				curve: opts.curve,
				index: parseInt(opts.index),
			});
			console.log(JSON.stringify(w, null, 2));
		} else if (opts.privateKey) {
			const key = opts.value ?? process.env['IKA_OWS_PRIVATE_KEY'];
			if (!key) throw new Error('Provide key via --value or IKA_OWS_PRIVATE_KEY env');
			const w = await provider.importWalletPrivateKey(opts.name, key, { curve: opts.curve });
			console.log(JSON.stringify(w, null, 2));
		} else {
			throw new Error('Specify --mnemonic or --private-key');
		}
	});

wallet
	.command('list')
	.description('List all wallets')
	.action(async () => {
		const provider = await createProvider();
		console.log(JSON.stringify(provider.listWallets(), null, 2));
	});

wallet
	.command('export')
	.description('Export wallet secret (mnemonic or user share)')
	.requiredOption('--wallet <name>', 'Wallet name or ID')
	.action(async (opts) => {
		const provider = await createProvider();
		const passphrase = process.env['IKA_OWS_PASSPHRASE'] ?? '';
		console.log(provider.exportWallet(opts.wallet, passphrase));
	});

wallet
	.command('delete')
	.description('Delete a wallet from the vault')
	.requiredOption('--wallet <name>', 'Wallet name or ID')
	.action(async (opts) => {
		const provider = await createProvider();
		provider.deleteWallet(opts.wallet);
		console.log(`Deleted: ${opts.wallet}`);
	});

wallet
	.command('rename')
	.description('Rename a wallet')
	.requiredOption('--wallet <name>', 'Wallet name or ID')
	.requiredOption('--new-name <newName>', 'New name')
	.action(async (opts) => {
		const provider = await createProvider();
		provider.renameWallet(opts.wallet, opts.newName);
		console.log(`Renamed to: ${opts.newName}`);
	});

wallet
	.command('info')
	.description('Show wallet details')
	.requiredOption('--wallet <name>', 'Wallet name or ID')
	.action(async (opts) => {
		const provider = await createProvider();
		console.log(JSON.stringify(provider.getWallet(opts.wallet), null, 2));
	});

// ─── sign ────────────────────────────────────────────────────────────────

const sign = program.command('sign').description('Sign transactions and messages via MPC');

sign
	.command('tx')
	.description('Sign a hex-encoded transaction')
	.requiredOption('--wallet <name>', 'Wallet name or ID')
	.requiredOption('--chain <chain>', 'CAIP-2 chain ID (e.g., eip155:1)')
	.requiredOption('--tx <hex>', 'Hex-encoded transaction bytes')
	.option('--json', 'Output structured JSON')
	.action(async (opts) => {
		const provider = await createProvider();
		const result = await provider.signTransaction(opts.wallet, opts.chain, opts.tx);
		console.log(opts.json ? JSON.stringify(result, null, 2) : result.signature);
	});

sign
	.command('message')
	.description('Sign an arbitrary message')
	.requiredOption('--wallet <name>', 'Wallet name or ID')
	.requiredOption('--chain <chain>', 'CAIP-2 chain ID')
	.requiredOption('--message <msg>', 'Message to sign')
	.option('--encoding <enc>', 'Message encoding: utf8 or hex', 'utf8')
	.option('--json', 'Output structured JSON')
	.action(async (opts) => {
		const provider = await createProvider();
		const result = await provider.signMessage(
			opts.wallet,
			opts.chain,
			opts.message,
			opts.encoding,
		);
		console.log(opts.json ? JSON.stringify(result, null, 2) : result.signature);
	});

// ─── presign ─────────────────────────────────────────────────────────────

const presign = program
	.command('presign')
	.description('Manage pre-computed presigns for fast signing');

presign
	.command('prefill')
	.description('Pre-create presigns for a wallet')
	.requiredOption('--wallet <name>', 'Wallet name or ID')
	.option('--algorithm <algo>', 'Signature algorithm', 'ECDSASecp256k1')
	.option('--count <n>', 'Number of presigns to create', '5')
	.action(async (opts) => {
		const provider = await createProvider();
		console.log(`Creating ${opts.count} presigns for ${opts.wallet} (${opts.algorithm})...`);
		const ids = await provider.prefillPresigns(opts.wallet, opts.algorithm, parseInt(opts.count));
		console.log(`Created ${ids.length} presigns:`);
		ids.forEach((id: string) => console.log(`  ${id}`));
	});

presign
	.command('list')
	.description('Show available presigns for a wallet')
	.requiredOption('--wallet <name>', 'Wallet name or ID')
	.option('--algorithm <algo>', 'Signature algorithm', 'ECDSASecp256k1')
	.action(async (opts) => {
		const provider = await createProvider();
		console.log(
			`Available: ${provider.availablePresigns(opts.wallet, opts.algorithm)}`,
		);
	});

// ─── pay (x402) ──────────────────────────────────────────────────────────

const pay = program
	.command('pay')
	.description('x402 automatic payment handling');

pay
	.command('request')
	.description('Make an HTTP request with automatic x402 payment')
	.argument('<url>', 'Target URL')
	.requiredOption('--wallet <name>', 'Wallet to pay from')
	.option('--chain <chain>', 'Payment chain', 'eip155:8453')
	.option('--method <method>', 'HTTP method', 'GET')
	.option('--body <json>', 'Request body')
	.option('--header <kv...>', 'Custom headers (key:value)')
	.option('--json', 'Output structured JSON')
	.action(async (url: string, opts) => {
		const provider = await createProvider();

		const headers: Record<string, string> = {};
		if (opts.header) {
			for (const h of opts.header as string[]) {
				const [key, ...valParts] = h.split(':');
				if (key) headers[key] = valParts.join(':').trim();
			}
		}

		// Initial request.
		let response = await fetch(url, {
			method: opts.method,
			headers: {
				...headers,
				...(opts.body ? { 'Content-Type': 'application/json' } : {}),
			},
			body: opts.body ?? undefined,
		});

		// x402: if 402, sign payment and retry.
		if (response.status === 402) {
			const paymentHeader =
				response.headers.get('x-payment') ?? response.headers.get('x402-payment');
			if (!paymentHeader) {
				throw new Error('Server returned 402 but no payment header found');
			}

			const paymentRequest = JSON.parse(paymentHeader) as {
				chain?: string;
				tx?: string;
				data?: string;
			};
			const txHex = paymentRequest.tx ?? paymentRequest.data;
			if (!txHex) throw new Error('Payment header missing tx/data field');

			const paymentChain = paymentRequest.chain ?? opts.chain;
			console.error(`Signing x402 payment on ${paymentChain}...`);
			const sig = await provider.signTransaction(opts.wallet, paymentChain, txHex);

			response = await fetch(url, {
				method: opts.method,
				headers: {
					...headers,
					...(opts.body ? { 'Content-Type': 'application/json' } : {}),
					'x-payment-signature': sig.signature,
					'x402-payment-signature': sig.signature,
				},
				body: opts.body ?? undefined,
			});
		}

		const body = await response.text();
		if (opts.json) {
			console.log(
				JSON.stringify({
					status: response.status,
					headers: Object.fromEntries((response.headers as any).entries()),
					body,
				}, null, 2),
			);
		} else {
			console.log(body);
		}
	});

// ─── mnemonic ────────────────────────────────────────────────────────────

const mnemonic = program
	.command('mnemonic')
	.description('BIP-39 mnemonic utilities');

mnemonic
	.command('generate')
	.description('Generate a BIP-39 mnemonic phrase')
	.option('--words <count>', 'Word count: 12 or 24', '12')
	.action((opts) => {
		console.log(generateMnemonic(parseInt(opts.words)));
	});

mnemonic
	.command('derive')
	.description('Derive an address from a mnemonic for a given chain')
	.requiredOption('--chain <chain>', 'Chain family: evm, solana, bitcoin, sui, cosmos, etc.')
	.option('--mnemonic <phrase>', 'Mnemonic (or IKA_OWS_MNEMONIC env)')
	.option('--index <n>', 'Account index', '0')
	.action((opts) => {
		const m = opts.mnemonic ?? process.env['IKA_OWS_MNEMONIC'];
		if (!m) throw new Error('Provide mnemonic via --mnemonic or IKA_OWS_MNEMONIC env');
		console.log(deriveAddressFromMnemonic(m, opts.chain, parseInt(opts.index)));
	});

// ─── policy ──────────────────────────────────────────────────────────────

const policy = program
	.command('policy')
	.description('OWS policy management');

policy
	.command('create')
	.description('Create a declarative policy from a JSON file')
	.requiredOption('--name <name>', 'Policy name')
	.requiredOption('--file <path>', 'JSON rules file')
	.action(async (opts) => {
		const fs = require('node:fs');
		const provider = await createProvider();
		const rules = JSON.parse(fs.readFileSync(opts.file, 'utf-8'));
		const policy = provider.policies.createPolicy(opts.name, rules);
		console.log(JSON.stringify(policy, null, 2));
	});

policy
	.command('list')
	.description('List all declarative policies')
	.action(async () => {
		const provider = await createProvider();
		console.log(JSON.stringify(provider.policies.listPolicies(), null, 2));
	});

policy
	.command('show')
	.description('Show a specific policy')
	.requiredOption('--id <id>', 'Policy ID')
	.action(async (opts) => {
		const provider = await createProvider();
		console.log(JSON.stringify(provider.policies.getPolicy(opts.id), null, 2));
	});

policy
	.command('delete')
	.description('Delete a policy')
	.requiredOption('--id <id>', 'Policy ID')
	.requiredOption('--confirm', 'Confirm deletion')
	.action(async (opts) => {
		const provider = await createProvider();
		provider.policies.deletePolicy(opts.id);
		console.log(`Deleted policy: ${opts.id}`);
	});

// ─── serve ───────────────────────────────────────────────────────────────

program
	.command('serve')
	.description('Start the OWS REST API server')
	.option('--port <port>', 'Port to listen on', '3420')
	.option('--host <host>', 'Hostname to bind to', '127.0.0.1')
	.action(async (opts) => {
		const apiKey = process.env['IKA_OWS_API_KEY'];
		if (!apiKey) throw new Error('Set IKA_OWS_API_KEY env for Bearer token authentication');

		const provider = await createProvider();
		const { startServer } = await import('../server.js');
		startServer({
			provider,
			apiKey,
			port: parseInt(opts.port),
			host: opts.host,
		});
	});

// ─── Run ─────────────────────────────────────────────────────────────────

program.parseAsync(process.argv).catch((err) => {
	console.error(`Error: ${err.message ?? err}`);
	process.exit(1);
});
