'use client';

import {
	Curve,
	DWalletWithState,
	Hash,
	IkaClient,
	objResToBcs,
	SignatureAlgorithm,
} from '@ika.xyz/sdk';
import {
	bitcoinPublisher,
	type BitcoinNetwork as PluginBitcoinNetwork,
} from '@ika.xyz/plugins/bitcoin/publisher';
import {
	buildBip341Preimage,
	buildCheckSigScript,
	buildP2trScriptPath,
	computeTapLeafHash,
	toXOnlyPubkey,
} from '@ika.xyz/plugins/bitcoin/destination';
import { bcs } from '@mysten/sui/bcs';
import { SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import * as bitcoin from 'bitcoinjs-lib';

import { transactionRequest } from '../generated/ika_btc_multisig/multisig';
import * as MultisigModule from '../generated/ika_btc_multisig/multisig';
import { createSignatureWithWorker } from '../workers/api';

export interface UTXO {
	txid: string;
	vout: number;
	value: number;
	status: {
		confirmed: boolean;
		block_height?: number;
	};
}

export interface SignableTransaction {
	psbt: bitcoin.Psbt;
	psbtBase64: string;
	inputIndex: number;
}

/**
 * Multisig P2TR wallet. Holds the dWallet, derives the script-path Taproot
 * address using the plugin layer, and builds + broadcasts transactions on
 * behalf of the multisig contract.
 *
 * Key plugin handoffs:
 *   - `buildP2trScriptPath`  derives the address + control block
 *   - `buildBip341Preimage`  builds the BIP-341/342 preimage the MPC signs
 *   - `computeTapLeafHash`   identifies the script in the tree
 *   - `bitcoinPublisher`     broadcasts via Esplora `POST /tx`
 *
 * Ika MPC cannot tweak keys (BIP-341 internal-key tweaking) so this wallet
 * is SCRIPT-PATH ONLY. The internal pubkey is the NUMS point — key-path
 * spending is provably impossible.
 */
export class MultisigBitcoinWallet {
	private readonly address: string;
	private readonly bitcoinNetwork: 'testnet' | 'mainnet';
	private readonly apiBaseUrl: string;
	private readonly p2tr: bitcoin.payments.Payment;
	private readonly redeem: { output: Buffer; redeemVersion: number };
	private readonly tapLeafHash: Buffer;
	private readonly xOnlyPubkey: Uint8Array;
	private readonly publisher: ReturnType<typeof bitcoinPublisher>;

	constructor(
		network: 'testnet' | 'mainnet' = 'testnet',
		private readonly publicKey: Uint8Array,
		private readonly ikaClient: IkaClient,
		private readonly suiClient: SuiClient,
		private readonly packageAddress: string,
		public readonly object: {
			multisig: string;
			coordinator: string;
			dWallet: DWalletWithState<'Active'>;
		},
	) {
		this.bitcoinNetwork = network;
		this.apiBaseUrl =
			network === 'mainnet'
				? 'https://blockstream.info/api'
				: 'https://blockstream.info/testnet/api';

		// Accept either compressed (33B) or x-only (32B) pubkey; the plugin's
		// `toXOnlyPubkey` normalizes the rest of the flow.
		this.xOnlyPubkey = toXOnlyPubkey(this.publicKey);
		if (this.xOnlyPubkey.length !== 32) {
			throw new Error('Public key must reduce to 32 bytes (x-only) for BIP-340');
		}

		// One plugin call replaces the manual P2TR / scriptTree assembly.
		const bundle = buildP2trScriptPath(this.xOnlyPubkey, network as PluginBitcoinNetwork);
		this.address = bundle.address;
		this.p2tr = bundle.payment;
		this.redeem = bundle.redeem;
		this.tapLeafHash = Buffer.from(
			computeTapLeafHash(buildCheckSigScript(this.xOnlyPubkey), bundle.redeem.redeemVersion),
		);

		this.publisher = bitcoinPublisher({ apiBaseUrl: this.apiBaseUrl });
	}

	getAddress(): string {
		return this.address;
	}

	getNetwork(): 'testnet' | 'mainnet' {
		return this.bitcoinNetwork;
	}

	async getBalance(): Promise<bigint> {
		const utxos = await this.getUTXOs();
		return utxos.reduce((sum, utxo) => sum + BigInt(utxo.value), 0n);
	}

	async getBalanceWithUnconfirmed(): Promise<{
		confirmed: bigint;
		unconfirmed: bigint;
		total: bigint;
	}> {
		const response = await fetch(`${this.apiBaseUrl}/address/${this.address}/utxo`);
		if (!response.ok) {
			throw new Error(`Failed to fetch UTXOs: ${response.statusText}`);
		}
		const utxos: UTXO[] = await response.json();
		const confirmed = utxos
			.filter((u) => u.status.confirmed)
			.reduce((sum, u) => sum + BigInt(u.value), 0n);
		const unconfirmed = utxos
			.filter((u) => !u.status.confirmed)
			.reduce((sum, u) => sum + BigInt(u.value), 0n);
		return { confirmed, unconfirmed, total: confirmed + unconfirmed };
	}

	/** Build a P2TR script-path PSBT spending the supplied UTXO. */
	async sendTransaction(
		toAddress: string,
		amount: bigint,
		feeRate: number,
		utxo: UTXO,
	): Promise<SignableTransaction> {
		// 1 script-path input + 2 outputs is the typical shape.
		const estimatedSize = 1 * 68 + 2 * 43 + 10;
		const fee = BigInt(Math.ceil(estimatedSize * feeRate));

		const utxoValue = BigInt(utxo.value);
		if (utxoValue < amount + fee) {
			throw new Error(
				`Insufficient UTXO value. Have: ${utxoValue}, Need: ${amount + fee} (${amount} + ${fee} fee)`,
			);
		}

		const psbt = new bitcoin.Psbt({
			network:
				this.bitcoinNetwork === 'mainnet' ? bitcoin.networks.bitcoin : bitcoin.networks.testnet,
		});

		const txHex = await this.#fetchTransactionHex(utxo.txid);
		const tx = bitcoin.Transaction.fromHex(txHex);

		psbt.addInput({
			hash: utxo.txid,
			index: utxo.vout,
			witnessUtxo: {
				script: tx.outs[utxo.vout].script,
				value: utxoValue,
			},
			tapInternalKey: this.p2tr.internalPubkey!,
			tapLeafScript: [
				{
					leafVersion: this.redeem.redeemVersion,
					script: this.redeem.output,
					controlBlock: this.p2tr.witness![this.p2tr.witness!.length - 1],
				},
			],
		});

		psbt.addOutput({ address: toAddress, value: amount });

		const change = utxoValue - amount - fee;
		if (change > 0n) {
			psbt.addOutput({ address: this.address, value: change });
		}

		return { psbt, psbtBase64: psbt.toBase64(), inputIndex: 0 };
	}

	async sendTransactionSui(
		toAddress: string,
		amount: bigint,
		feeRate: number,
		utxo: UTXO,
	): Promise<{
		transaction: Transaction;
		preimage: Uint8Array;
		psbt: bitcoin.Psbt;
		messageCentralizedSignature: Uint8Array;
	}> {
		const { psbt, inputIndex } = await this.sendTransaction(toAddress, amount, feeRate, utxo);

		const multisig = await this.#getMultisig();
		const presign = await this.ikaClient.getPresignInParticularState(
			multisig.presigns[0].presign_id,
			'Completed',
		);

		// One plugin call replaces ~330 lines of hand-rolled BIP-341 preimage
		// assembly. The plugin reads `witnessUtxo` from the PSBT for the
		// commits to all prev-out scripts and values, so we hand it those
		// directly from the only input we built.
		const tx = bitcoin.Transaction.fromBuffer(psbt.data.getTransaction());
		const witnessUtxo = psbt.data.inputs[inputIndex].witnessUtxo;
		if (!witnessUtxo) throw new Error('Expected witnessUtxo on the script-path input');
		const preimage = buildBip341Preimage({
			tx,
			inputIndex,
			prevOutScripts: [new Uint8Array(witnessUtxo.script)],
			values: [BigInt(witnessUtxo.value)],
			hashType: bitcoin.Transaction.SIGHASH_DEFAULT,
			leafHash: new Uint8Array(this.tapLeafHash),
		});

		const messageCentralizedSignature = await createSignatureWithWorker({
			protocolPublicParameters: Array.from(await this.ikaClient.getProtocolPublicParameters()),
			publicOutput: Array.from(this.object.dWallet.state.Active.public_output),
			publicUserSecretKeyShare: Array.from(this.object.dWallet.public_user_secret_key_share ?? []),
			presign: Array.from(presign.state.Completed.presign),
			preimage: Array.from(preimage),
			hash: Hash.SHA256,
			signatureAlgorithm: SignatureAlgorithm.Taproot,
			curve: Curve.SECP256K1,
		});

		const transaction = new Transaction();
		const byteVector = bcs.vector(bcs.u8());
		transaction.add(
			transactionRequest({
				package: this.packageAddress,
				arguments: {
					self: this.object.multisig,
					coordinator: this.object.coordinator,
					preimage: byteVector.serialize(preimage).parse(),
					messageCentralizedSignature: byteVector.serialize(messageCentralizedSignature).parse(),
					psbt: byteVector.serialize(psbt.toBuffer()).parse(),
				},
			}),
		);

		return {
			transaction,
			preimage,
			psbt,
			messageCentralizedSignature: new Uint8Array(messageCentralizedSignature),
		};
	}

	async getUTXOs(): Promise<UTXO[]> {
		const response = await fetch(`${this.apiBaseUrl}/address/${this.address}/utxo`);
		if (!response.ok) {
			throw new Error(`Failed to fetch UTXOs: ${response.statusText}`);
		}
		const utxos: UTXO[] = await response.json();
		return utxos.filter((u) => u.status.confirmed);
	}

	findSuitableUTXO(utxos: UTXO[], amount: bigint, feeRate: number): UTXO | null {
		const estimatedSize = 1 * 68 + 2 * 43 + 10;
		const estimatedFee = BigInt(Math.ceil(estimatedSize * feeRate));
		const totalNeeded = amount + estimatedFee;
		const sorted = [...utxos].sort((a, b) => a.value - b.value);
		return sorted.find((u) => BigInt(u.value) >= totalNeeded) || null;
	}

	/**
	 * Apply the network's BIP-340 Schnorr signature to the PSBT input as a
	 * `tapScriptSig` (NOT `tapKeySig` — we're script-path spending), finalize,
	 * and return the signed tx hex.
	 */
	finalizeTransaction(psbt: bitcoin.Psbt, signature: Uint8Array, inputIndex: number): string {
		psbt
			.updateInput(inputIndex, {
				tapScriptSig: [
					{
						pubkey: Buffer.from(this.xOnlyPubkey),
						signature: Buffer.from(signature),
						leafHash: this.tapLeafHash,
					},
				],
			})
			.finalizeAllInputs();
		return psbt.extractTransaction().toHex();
	}

	/** Broadcast a finalized signed tx hex via the plugin's Esplora publisher. */
	async broadcastTransaction(txHex: string): Promise<string> {
		return this.publisher.broadcast({
			chain: 'bitcoin',
			payload: {
				kind: 'psbt',
				// `psbt` is unused by the publisher; we already have the signed hex.
				psbt: new bitcoin.Psbt(),
				signedTxHex: txHex,
				// `txid` is recomputed from `signedTxHex` on the publisher side
				// only for sanity checking; using a placeholder here is safe
				// because the publisher returns the broadcast result directly.
				txid: bitcoin.Transaction.fromHex(txHex).getId(),
				network: this.bitcoinNetwork as PluginBitcoinNetwork,
				mode: 'p2tr-script',
				sender: this.address,
			},
		});
	}

	async findBroadcastedTransactionByOutputs(
		psbt: bitcoin.Psbt,
		createdAfter?: number,
	): Promise<{
		found: boolean;
		txid?: string;
		confirmed?: boolean;
		confirmations?: number;
		blockHeight?: number;
	}> {
		const tx = bitcoin.Transaction.fromBuffer(psbt.data.getTransaction());
		const network =
			this.bitcoinNetwork === 'mainnet' ? bitcoin.networks.bitcoin : bitcoin.networks.testnet;
		const expectedOutputs = tx.outs.map((out) => {
			try {
				return {
					address: bitcoin.address.fromOutputScript(out.script, network),
					value: Number(out.value),
				};
			} catch {
				return { address: null as string | null, value: Number(out.value) };
			}
		});

		const response = await fetch(`${this.apiBaseUrl}/address/${this.address}/txs`);
		if (!response.ok) return { found: false };

		const transactions = await response.json();
		const currentHeight = await this.#getCurrentBlockHeight();

		for (const txData of transactions) {
			if (createdAfter && txData.status?.block_time && txData.status.block_time < createdAfter) {
				continue;
			}
			if (!txData.vout || txData.vout.length !== expectedOutputs.length) continue;
			let outputsMatch = true;
			for (let i = 0; i < expectedOutputs.length; i++) {
				const expected = expectedOutputs[i];
				const actual = txData.vout[i];
				if (actual.value !== expected.value) {
					outputsMatch = false;
					break;
				}
				if (
					expected.address &&
					actual.scriptpubkey_address &&
					actual.scriptpubkey_address !== expected.address
				) {
					outputsMatch = false;
					break;
				}
			}
			if (outputsMatch) {
				return {
					found: true,
					txid: txData.txid,
					confirmed: txData.status?.confirmed ?? false,
					confirmations:
						currentHeight && txData.status?.block_height
							? currentHeight - txData.status.block_height + 1
							: 0,
					blockHeight: txData.status?.block_height,
				};
			}
		}
		return { found: false };
	}

	async #getMultisig(): Promise<typeof MultisigModule.Multisig.$inferType> {
		const multisig = await this.suiClient
			.getObject({
				id: this.object.multisig,
				options: { showBcs: true },
			})
			.then((obj) => MultisigModule.Multisig.fromBase64(objResToBcs(obj)));
		return multisig;
	}

	async #fetchTransactionHex(txid: string): Promise<string> {
		const response = await fetch(`${this.apiBaseUrl}/tx/${txid}/hex`);
		if (!response.ok) {
			throw new Error(`Failed to fetch transaction: ${response.statusText}`);
		}
		return await response.text();
	}

	async #getCurrentBlockHeight(): Promise<number | null> {
		try {
			const response = await fetch(`${this.apiBaseUrl}/blocks/tip/height`);
			if (!response.ok) return null;
			return parseInt(await response.text(), 10);
		} catch {
			return null;
		}
	}
}
