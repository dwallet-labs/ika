// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// Full source+destination e2e against the docker localnet stack. The Ika
// container publishes Move packages to Sui and runs the in-memory MPC swarm;
// these tests drive the real `suiSource` plugin through every destination
// plugin (ethereum, bitcoin, solana, sui) end-to-end:
//
//   register encryption key → shared DKG → global presign → sign → broadcast
//   on the destination chain → confirm
//
// On localnet the coordinator's IKA pricing is zero, so the test signer
// builds a zero-balance IKA fee coin via `coin::zero<IKA>` (see
// `ikaFeePerOp: 0n` below). The Sui faucet covers the SUI gas.

import { existsSync } from 'node:fs';
import * as ecc from '@bitcoinerlab/secp256k1';
import { btc, buildP2trScriptPath } from '@ika.xyz/plugins/bitcoin/destination';
import type { BitcoinMode } from '@ika.xyz/plugins/bitcoin/destination';
import { bitcoinPublisher } from '@ika.xyz/plugins/bitcoin/publisher';
import { eth } from '@ika.xyz/plugins/ethereum/destination';
import { ethPublisher } from '@ika.xyz/plugins/ethereum/publisher';
import { solana } from '@ika.xyz/plugins/solana/destination';
import { solanaPublisher } from '@ika.xyz/plugins/solana/publisher';
import { sui as suiDestination } from '@ika.xyz/plugins/sui/destination';
import { suiPublisher } from '@ika.xyz/plugins/sui/publisher';
import { suiSource, type SuiSourceExtend } from '@ika.xyz/plugins/sui/source';
import {
	IkaClient as CoreIkaClient,
	Curve,
	publicKeyFromDWalletOutput,
	SignatureAlgorithm,
	UserShareEncryptionKeys,
} from '@ika.xyz/sdk';
import { IkaClient } from '@ika.xyz/sdk/plugin';
import { SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction as SuiTransaction } from '@mysten/sui/transactions';
import {
	Connection,
	LAMPORTS_PER_SOL,
	PublicKey,
	SystemProgram,
	TransactionMessage,
	VersionedTransaction,
} from '@solana/web3.js';
import * as bitcoin from 'bitcoinjs-lib';
import { createPublicClient, http, parseEther, type Hex } from 'viem';
import { foundry } from 'viem/chains';
import { beforeAll, describe, expect, it } from 'vitest';

import { bitcoinRegtest } from './_helpers/bitcoin.js';
import { waitForJsonRpc } from './_helpers/chain-ready.js';
import { loadLocalnetIkaConfig } from './_helpers/ika-localnet.js';

bitcoin.initEccLib(ecc as Parameters<typeof bitcoin.initEccLib>[0]);

const SUI_RPC = process.env.SUI_LOCALNET_URL ?? 'http://127.0.0.1:9000';
const SUI_FAUCET = process.env.SUI_FAUCET_URL ?? 'http://127.0.0.1:9123/v2/gas';
const ANVIL_URL = process.env.ANVIL_URL ?? 'http://127.0.0.1:8545';
const BITCOIN_RPC_URL = process.env.BITCOIN_RPC_URL ?? 'http://test:test@127.0.0.1:18443/';
const SOLANA_RPC = process.env.SOLANA_RPC_URL ?? 'http://127.0.0.1:8899';
const IKA_CONFIG_PATH =
	process.env.IKA_LOCALNET_CONFIG ??
	new URL('./ika-state/ika_config.json', import.meta.url).pathname;

const ready = {
	sui: false,
	eth: false,
	btc: false,
	sol: false,
	ika: false,
};
beforeAll(async () => {
	ready.sui = await waitForJsonRpc(SUI_RPC, 'sui_getChainIdentifier', 3_000);
	ready.eth = await waitForJsonRpc(ANVIL_URL, 'eth_chainId', 3_000);
	ready.sol = await waitForJsonRpc(SOLANA_RPC, 'getHealth', 3_000);
	try {
		// Reuse the regtest helper for the probe — its `rpc()` already
		// handles Basic auth from the URL userinfo, where a raw `fetch`
		// in some Node builds does not.
		await bitcoinRegtest(BITCOIN_RPC_URL).rpc('getblockchaininfo');
		ready.btc = true;
	} catch {
		ready.btc = false;
	}
	ready.ika = ready.sui && existsSync(IKA_CONFIG_PATH);
	const summary = JSON.stringify(ready);
	if (!ready.ika) {
		console.warn(`ika not reachable — ${summary}. Run the localnet stack first.`);
	}
}, 15_000);

describe('sui source localnet — full e2e through ika MPC + all destinations', () => {
	it(
		'shared DKG → presign → sign ethereum tx → broadcast to anvil → confirm',
		async (test) => {
			if (!ready.ika || !ready.eth) return test.skip();

			const suiClient = makeSuiClient();
			const config = await loadLocalnetIkaConfig(suiClient, { configPath: IKA_CONFIG_PATH });
			await waitForNetworkEncryptionKey(suiClient, config);

			const { ika, dWallet, signer } = await bootstrapDWallet({
				suiClient,
				config,
				curve: Curve.SECP256K1,
				destinations: [
					eth(),
					ethPublisher({
						url: ANVIL_URL,
						chain: foundry,
						confirm: true,
						confirmations: 1,
						confirmTimeoutMs: 30_000,
					}),
				],
			});
			void signer;

			const ethAddress = await dWallet.ethereum.getAddress();
			expect(ethAddress).toMatch(/^0x[0-9a-fA-F]{40}$/);

			// Anvil's RPC lets us fund any address synthetically.
			await anvilRpc(ANVIL_URL, 'anvil_setBalance', [ethAddress, '0x56bc75e2d63100000']);
			const eth1 = createPublicClient({ chain: foundry, transport: http(ANVIL_URL) });
			expect(await eth1.getBalance({ address: ethAddress as Hex })).toBeGreaterThan(
				parseEther('99'),
			);

			const nonce = await eth1.getTransactionCount({ address: ethAddress as Hex });
			const signed = await dWallet.ethereum.sign({
				kind: 'transaction',
				tx: {
					type: 'eip1559',
					chainId: foundry.id,
					nonce,
					to: ethAddress as Hex,
					value: 1n,
					maxFeePerGas: 2_000_000_000n,
					maxPriorityFeePerGas: 1_000_000_000n,
					gas: 21_000n,
				},
			});
			if (signed.payload.kind !== 'transaction') throw new Error('unreachable');

			const txHash = await ika.publish({ ...signed, payload: signed.payload });
			expect(txHash).toMatch(/^0x[0-9a-f]{64}$/);
			const receipt = await eth1.getTransactionReceipt({ hash: txHash as Hex });
			expect(receipt.status).toBe('success');
			expect(receipt.from.toLowerCase()).toBe(ethAddress.toLowerCase());
		},
		5 * 60_000,
	);

	it(
		'shared DKG → batched presigns → sign one UTXO per bitcoin mode (P2PKH, P2WPKH, P2SH-P2WPKH, P2TR script-path) → confirm each',
		async (test) => {
			if (!ready.ika || !ready.btc) return test.skip();

			const suiClient = makeSuiClient();
			const config = await loadLocalnetIkaConfig(suiClient, { configPath: IKA_CONFIG_PATH });
			await waitForNetworkEncryptionKey(suiClient, config);

			const chain = bitcoinRegtest(BITCOIN_RPC_URL);
			await chain.ensureWallet('localnet');
			await chain.primeWallet('localnet');

			const { ika, dWallet } = await bootstrapDWallet({
				suiClient,
				config,
				curve: Curve.SECP256K1,
				destinations: [
					btc(),
					bitcoinPublisher({
						apiBaseUrl: 'http://unused',
						broadcast: (hex) => chain.sendRawTransaction(hex),
					}),
				],
			});

			// Four modes, four presigns: three share `(ECDSASecp256k1,
			// DoubleSHA256)`, one uses `(Taproot, SHA256)`. Each sign
			// consumes one presign. Batch them into a single Sui PTB so
			// the validators run all four MPC computations in parallel
			// (~30s for the slowest), instead of 4× ~30s sequentially.
			const modes: BitcoinMode[] = ['p2pkh', 'p2wpkh', 'p2sh-p2wpkh', 'p2tr-script'];
			const presigns = await batchedPresigns(ika, [
				SignatureAlgorithm.ECDSASecp256k1,
				SignatureAlgorithm.ECDSASecp256k1,
				SignatureAlgorithm.ECDSASecp256k1,
				SignatureAlgorithm.Taproot,
			]);
			const presignByMode: Record<BitcoinMode, (typeof presigns)[number]> = {
				p2pkh: presigns[0],
				p2wpkh: presigns[1],
				'p2sh-p2wpkh': presigns[2],
				'p2tr-script': presigns[3],
			};

			const compressedPubkey = await publicKeyFromDWalletOutput(
				Curve.SECP256K1,
				dWallet.publicOutput as Uint8Array,
			);

			for (const mode of modes) {
				const dWalletAddress = await dWallet.bitcoin.getAddress({
					mode,
					network: 'regtest',
				});
				await chain.send('localnet', dWalletAddress, 1);
				await chain.mine(1);
				const utxos = await chain.scanUtxos(dWalletAddress);
				expect(utxos.length, `no UTXO funded for ${mode}`).toBeGreaterThan(0);
				const utxo = utxos[0];

				const walletAddress = (await chain.walletRpc('localnet', 'getnewaddress', [])) as string;
				const psbt = new bitcoin.Psbt({ network: bitcoin.networks.regtest });
				const valueSats = BigInt(Math.round(utxo.amount * 1e8));

				if (mode === 'p2pkh') {
					const prevHex = (await chain.rpc('getrawtransaction', [utxo.txid])) as string;
					psbt.addInput({
						hash: Buffer.from(utxo.txid, 'hex').reverse(),
						index: utxo.vout,
						nonWitnessUtxo: Buffer.from(prevHex, 'hex'),
					});
				} else if (mode === 'p2tr-script') {
					const xOnly = compressedPubkey.subarray(1);
					const bundle = buildP2trScriptPath(xOnly, 'regtest');
					psbt.addInput({
						hash: Buffer.from(utxo.txid, 'hex').reverse(),
						index: utxo.vout,
						witnessUtxo: {
							script: Buffer.from(utxo.scriptPubKey, 'hex'),
							value: valueSats,
						},
						tapInternalKey: bundle.internalPubkey,
						tapLeafScript: [
							{
								leafVersion: bundle.redeem.redeemVersion,
								script: bundle.redeem.output,
								controlBlock: bundle.payment.witness![bundle.payment.witness!.length - 1],
							},
						],
					});
				} else if (mode === 'p2sh-p2wpkh') {
					const innerP2wpkh = bitcoin.payments.p2wpkh({
						pubkey: Buffer.from(compressedPubkey),
						network: bitcoin.networks.regtest,
					});
					psbt.addInput({
						hash: Buffer.from(utxo.txid, 'hex').reverse(),
						index: utxo.vout,
						witnessUtxo: {
							script: Buffer.from(utxo.scriptPubKey, 'hex'),
							value: valueSats,
						},
						redeemScript: innerP2wpkh.output as Buffer,
					});
				} else {
					psbt.addInput({
						hash: Buffer.from(utxo.txid, 'hex').reverse(),
						index: utxo.vout,
						witnessUtxo: {
							script: Buffer.from(utxo.scriptPubKey, 'hex'),
							value: valueSats,
						},
					});
				}
				psbt.addOutput({ address: walletAddress, value: valueSats - 500n });

				const signed = await dWallet.bitcoin.sign({
					kind: 'psbt',
					psbt,
					inputIndex: 0,
					mode,
					network: 'regtest',
					presign: presignByMode[mode],
				});
				if (signed.payload.kind !== 'psbt') throw new Error('unreachable');

				const txid = await ika.publish({ ...signed, payload: signed.payload });
				expect(txid, `publish for ${mode} returned wrong txid`).toBe(signed.payload.txid);

				await chain.mine(1);
				const confirmed = (await chain.rpc('getrawtransaction', [txid, true])) as {
					confirmations: number;
				};
				expect(confirmed.confirmations, `${mode} tx not confirmed`).toBeGreaterThan(0);
			}
		},
		10 * 60_000,
	);

	it(
		'shared DKG → presign → sign solana tx → broadcast to test-validator → confirm',
		async (test) => {
			if (!ready.ika || !ready.sol) return test.skip();

			const suiClient = makeSuiClient();
			const config = await loadLocalnetIkaConfig(suiClient, { configPath: IKA_CONFIG_PATH });
			await waitForNetworkEncryptionKey(suiClient, config);

			const conn = new Connection(SOLANA_RPC, 'confirmed');
			const { ika, dWallet } = await bootstrapDWallet({
				suiClient,
				config,
				curve: Curve.ED25519,
				destinations: [
					solana(),
					solanaPublisher({
						connection: conn,
						// skipPreflight bypasses the validator's local
						// simulation, which is the step that rejects on
						// blockhash-not-found. The tx still has to land on
						// chain to count as e2e, so we confirm below — but
						// allow extra time because the MPC sign round can
						// push us close to the ~60s blockhash window on
						// solana-test-validator when the swarm is warm but
						// loaded (epoch reconfiguration overlap).
						sendOptions: { skipPreflight: true },
						confirm: true,
						confirmTimeoutMs: 60_000,
						commitment: 'confirmed',
					}),
				],
			});

			const dWalletAddress = await dWallet.solana.getAddress();
			const payer = new PublicKey(dWalletAddress);
			const airdropSig = await conn.requestAirdrop(payer, 2 * LAMPORTS_PER_SOL);
			const airdropLatest = await conn.getLatestBlockhash('confirmed');
			await conn.confirmTransaction(
				{
					signature: airdropSig,
					blockhash: airdropLatest.blockhash,
					lastValidBlockHeight: airdropLatest.lastValidBlockHeight,
				},
				'confirmed',
			);
			expect(await conn.getBalance(payer, 'confirmed')).toBeGreaterThanOrEqual(LAMPORTS_PER_SOL);

			// Pre-request the global presign so the sign tx itself doesn't
			// pay for both presign + sign on-chain (~30s each on a healthy
			// swarm). Solana's blockhash window is ~60s on test-validator;
			// the airdrop confirmation alone eats some of it. Doing presign
			// before fetching the signing-blockhash keeps the gap small.
			const presign = await ika.sui.requestGlobalPresign({
				curve: Curve.ED25519,
				signatureAlgorithm: SignatureAlgorithm.EdDSA,
			});

			// Fetch the freshest blockhash right before signing and use the
			// same one for the tx and the publisher's expiry check.
			const latest = await conn.getLatestBlockhash('confirmed');
			const tx = new VersionedTransaction(
				new TransactionMessage({
					payerKey: payer,
					recentBlockhash: latest.blockhash,
					instructions: [
						SystemProgram.transfer({ fromPubkey: payer, toPubkey: payer, lamports: 1 }),
					],
				}).compileToV0Message(),
			);
			const signed = await dWallet.solana.sign({ kind: 'transaction', tx, presign });
			if (signed.payload.kind !== 'transaction') throw new Error('unreachable');

			const sig = await ika.publish({ ...signed, payload: signed.payload });
			expect(typeof sig).toBe('string');
			const status = await conn.getSignatureStatuses([sig], { searchTransactionHistory: false });
			expect(status.value[0]?.err).toBeNull();
		},
		5 * 60_000,
	);

	it(
		'shared DKG → presign → sign sui tx → broadcast via publisher',
		async (test) => {
			if (!ready.ika) return test.skip();

			const suiClient = makeSuiClient();
			const config = await loadLocalnetIkaConfig(suiClient, { configPath: IKA_CONFIG_PATH });
			await waitForNetworkEncryptionKey(suiClient, config);

			const { ika, dWallet } = await bootstrapDWallet({
				suiClient,
				config,
				curve: Curve.ED25519,
				destinations: [suiDestination(), suiPublisher({ suiClient })],
			});

			const dWalletAddress = await dWallet.sui.getAddress();
			const faucetRes = await fetch(SUI_FAUCET, {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({ FixedAmountRequest: { recipient: dWalletAddress } }),
			});
			if (!faucetRes.ok) {
				throw new Error(`faucet: ${faucetRes.status} ${await faucetRes.text()}`);
			}

			let gasReady = false;
			for (let i = 0; i < 30; i++) {
				// `getCoins` is on the top-level SuiJsonRpcClient, not on
				// `.core` (despite the existing sui.localnet.test using
				// `.core.getCoins` — that test is itself a runtime fallback).
				const coins = await (
					suiClient as unknown as {
						getCoins: (input: { owner: string }) => Promise<{ data: unknown[] }>;
					}
				).getCoins({ owner: dWalletAddress });
				if (coins.data.length > 0) {
					gasReady = true;
					break;
				}
				await new Promise((r) => setTimeout(r, 500));
			}
			expect(gasReady).toBe(true);

			const tx = new SuiTransaction();
			tx.setSender(dWalletAddress);
			const [coin] = tx.splitCoins(tx.gas, [1]);
			tx.transferObjects([coin], dWalletAddress);

			const signed = await dWallet.sui.sign({
				kind: 'transaction',
				tx,
				suiClient,
			});

			const digest = await ika.publish(signed);
			expect(typeof digest).toBe('string');
			expect(digest.length).toBeGreaterThan(0);
		},
		5 * 60_000,
	);
});

// Build an IkaClient wired to the localnet config with the given destination
// plugins, run a shared DKG of the requested curve, and return the decorated
// dWallet ready to call into any of the destinations. Each call generates a
// fresh signer/USEK so tests don't share Sui object state.
//
// Typing note: this helper is generic in the destinations list and would
// require deep TS gymnastics to surface the merged dWallet namespace
// statically. The tests below cast the returned `dWallet` to the namespace
// they need (e.g. `dWallet.ethereum`) at the call site — runtime decoration
// is what actually attaches the namespace.
type BootstrappedClient = ReturnType<typeof _emptyIkaClient> & {
	sui: SuiSourceExtend['sui'];
	publish: (signed: unknown) => Promise<string>;
};

function _emptyIkaClient() {
	return new IkaClient();
}

async function bootstrapDWallet<C extends Curve>(opts: {
	suiClient: SuiJsonRpcClient;
	config: import('@ika.xyz/sdk').IkaConfig;
	curve: C;
	destinations: ReadonlyArray<unknown>;
}): Promise<{ ika: BootstrappedClient; dWallet: any; signer: Ed25519Keypair }> {
	const { suiClient, config, curve, destinations } = opts;
	const signer = Ed25519Keypair.generate();
	await faucetSui(SUI_FAUCET, signer.getPublicKey().toSuiAddress());

	const useks = await UserShareEncryptionKeys.fromRootSeedKey(
		new TextEncoder().encode(`localnet-e2e-${Date.now()}-${Math.random()}`),
		curve,
	);

	const initial = new IkaClient().use(
		suiSource({
			network: 'testnet',
			signer,
			userShareEncryptionKeys: useks,
			suiClient,
			config,
			ikaFeePerOp: 0n,
		}),
	);
	// `IkaClient.use` is variadic in its types; chaining through an array of
	// destinations loses that information. Cast to a permissive shape so the
	// call sites can dot into `dWallet.<chain>` without TS objecting.
	let stackedAny: unknown = initial;
	for (const plugin of destinations) {
		stackedAny = (stackedAny as { use: (p: unknown) => unknown }).use(plugin);
	}
	const stacked = stackedAny as BootstrappedClient;
	await stacked.ready();

	const dWallet = await stacked.sui.createDWallet({ kind: 'shared', curve });
	return { ika: stacked, dWallet, signer };
}

function makeSuiClient(): SuiJsonRpcClient {
	return new SuiJsonRpcClient({ url: SUI_RPC, network: 'localnet' });
}

async function faucetSui(faucetUrl: string, address: string): Promise<void> {
	const res = await fetch(faucetUrl, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ FixedAmountRequest: { recipient: address } }),
	});
	if (!res.ok) {
		throw new Error(`sui faucet returned ${res.status}: ${await res.text()}`);
	}
	// Faucet returns immediately but the coin takes a beat to index.
	await new Promise((r) => setTimeout(r, 1_500));
}

async function waitForNetworkEncryptionKey(
	suiClient: SuiJsonRpcClient,
	config: import('@ika.xyz/sdk').IkaConfig,
	timeoutMs: number = 180_000,
): Promise<void> {
	const probe = new CoreIkaClient({ suiClient, config, cache: false });
	await probe.initialize();
	const deadline = Date.now() + timeoutMs;
	let lastErr: unknown;
	while (Date.now() < deadline) {
		try {
			probe.invalidateEncryptionKeyCache?.();
			const key = await probe.getLatestNetworkEncryptionKey();
			if (key.networkDKGOutputID) {
				await probe.getProtocolPublicParameters(undefined, Curve.SECP256K1);
				return;
			}
		} catch (err) {
			lastErr = err;
		}
		await new Promise((r) => setTimeout(r, 2_000));
	}
	throw new Error(
		`network encryption key never reached DKG-complete (waited ${
			timeoutMs / 1000
		}s). last error: ${lastErr instanceof Error ? lastErr.message : String(lastErr)}`,
	);
}

// Batch N global presigns into a single Sui PTB. The MPC computations all
// run in parallel inside the swarm afterwards, so the wall time is
// roughly one presign's worth (~30s) regardless of `algorithms.length`.
async function batchedPresigns(
	ika: BootstrappedClient,
	algorithms: ReadonlyArray<SignatureAlgorithm>,
) {
	const { ikaDwallet2pcMpc } = await import('@ika.xyz/sdk');
	const sessionsManager = ikaDwallet2pcMpc.SessionsManagerModule;
	const coordInner = ikaDwallet2pcMpc.CoordinatorInnerModule;
	const presignEvent = sessionsManager.DWalletSessionEvent(coordInner.PresignRequestEvent);

	const netKeyId = (await ika.sui.client.getLatestNetworkEncryptionKey()).id;

	const { exec } = await ika.sui.transaction(async ({ tx, ikaTx, pay }) => {
		const caps: ReturnType<typeof ikaTx.requestGlobalPresign>[] = [];
		for (const algo of algorithms) {
			const p = pay();
			caps.push(
				ikaTx.requestGlobalPresign({
					dwalletNetworkEncryptionKeyId: netKeyId,
					curve: Curve.SECP256K1,
					signatureAlgorithm: algo as never,
					ikaCoin: p.ika,
					suiCoin: p.sui,
				}),
			);
		}
		// Move calls return the unverified cap — transfer all of them to the
		// signer so the PTB doesn't drop them (PTB validation would reject).
		tx.transferObjects(caps, ika.sui.address);
	});

	const events =
		(exec as { events?: ReadonlyArray<{ eventType: string; bcs?: number[] | null }> }).events ?? [];
	const ids = events
		.filter((e) => e.eventType.includes('PresignRequestEvent'))
		.map((e) => presignEvent.parse(new Uint8Array(e.bcs ?? [])).event_data.presign_id as string);
	if (ids.length !== algorithms.length) {
		throw new Error(
			`batchedPresigns: expected ${algorithms.length} PresignRequestEvents, got ${ids.length}`,
		);
	}

	// Poll each presign to Completed in parallel. The validators compute
	// these concurrently, so the wait is bounded by the slowest, not the sum.
	const presigns = await Promise.all(
		ids.map((id) =>
			ika.sui.client.getPresignInParticularState(id, 'Completed', { timeout: 180_000 }),
		),
	);
	return presigns;
}

async function anvilRpc(url: string, method: string, params: unknown[]): Promise<unknown> {
	const res = await fetch(url, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
	});
	const body = (await res.json()) as { result?: unknown; error?: { message: string } };
	if (body.error) throw new Error(`anvil ${method} → ${body.error.message}`);
	return body.result;
}
