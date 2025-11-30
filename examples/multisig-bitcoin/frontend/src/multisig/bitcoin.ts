'use client';

import {
	Curve,
	DWalletWithState,
	Hash,
	IkaClient,
	objResToBcs,
	SignatureAlgorithm,
} from '@ika.xyz/sdk';
import { bcs } from '@mysten/sui/bcs';
import { SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { sha256 } from '@noble/hashes/sha2';
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

export class MultisigBitcoinWallet {
	private readonly address: string;
	private readonly bitcoinNetwork: bitcoin.Network;
	private readonly apiBaseUrl: string;
	private readonly p2tr: bitcoin.payments.Payment;
	private readonly scriptTree: { output: Buffer };
	private readonly redeem: {
		output: Buffer;
		redeemVersion: number;
	};
	private readonly internalPubkey: Buffer;

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
		// Set Bitcoin network and API URL
		this.bitcoinNetwork =
			network === 'mainnet' ? bitcoin.networks.bitcoin : bitcoin.networks.testnet;
		this.apiBaseUrl =
			network === 'mainnet'
				? 'https://blockstream.info/api'
				: 'https://blockstream.info/testnet/api';

		// Ensure we have x-only public key (32 bytes) for BIP-340 Schnorr signatures
		if (this.publicKey.length === 33) {
			this.publicKey = this.publicKey.slice(1);
		}

		if (this.publicKey.length !== 32) {
			throw new Error('Public key must be 32 bytes (x-only) for BIP-340');
		}

		// ============================================
		// SCRIPT PATH SPENDING SETUP
		// ============================================
		// We use script path spending because our MPC doesn't support tweaked keys.
		// With script path, we sign with the UNTWEAKED public key.

		// Create Tapscript: <32-byte-pubkey> OP_CHECKSIG
		// This verifies BIP-340 Schnorr signatures against our untweaked MPC public key
		const scriptASM = Buffer.concat([
			Buffer.from([0x20]), // OP_PUSHBYTES_32 (push next 32 bytes)
			Buffer.from(this.publicKey), // 32-byte x-only public key from MPC
			Buffer.from([0xac]), // OP_CHECKSIG
		]);

		this.redeem = {
			output: scriptASM,
			redeemVersion: 0xc0, // Tapscript leaf version (192 decimal)
		};

		// Create script tree with our single checksig script
		this.scriptTree = {
			output: scriptASM,
		};

		// Use "Nothing Up My Sleeve" (NUMS) point as internal pubkey
		// This is the H point = SHA256("H"), used as a provably unspendable key
		// Since we only use script path, this internal key is never used for signing
		this.internalPubkey = Buffer.from(
			'50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0',
			'hex',
		);

		// Create Taproot P2TR address with script path
		const p2tr = bitcoin.payments.p2tr(
			{
				internalPubkey: this.internalPubkey,
				scriptTree: this.scriptTree,
				redeem: this.redeem,
				network: this.bitcoinNetwork,
			},
			{
				validate: true,
			},
		);

		if (!p2tr.address) {
			throw new Error('Failed to generate Taproot address');
		}

		this.p2tr = p2tr;
		this.address = p2tr.address;
	}

	getAddress(): string {
		return this.address;
	}

	getNetwork(): 'testnet' | 'mainnet' {
		return this.bitcoinNetwork === bitcoin.networks.testnet ? 'testnet' : 'mainnet';
	}

	async getBalance(): Promise<bigint> {
		const utxos = await this.getUTXOs();
		const balance = utxos.reduce((sum, utxo) => sum + BigInt(utxo.value), BigInt(0));
		return balance;
	}

	async getBalanceWithUnconfirmed(): Promise<{
		confirmed: bigint;
		unconfirmed: bigint;
		total: bigint;
	}> {
		try {
			const response = await fetch(`${this.apiBaseUrl}/address/${this.address}/utxo`);

			if (!response.ok) {
				throw new Error(`Failed to fetch UTXOs: ${response.statusText}`);
			}

			const utxos: UTXO[] = await response.json();

			const confirmed = utxos
				.filter((utxo) => utxo.status.confirmed)
				.reduce((sum, utxo) => sum + BigInt(utxo.value), BigInt(0));

			const unconfirmed = utxos
				.filter((utxo) => !utxo.status.confirmed)
				.reduce((sum, utxo) => sum + BigInt(utxo.value), BigInt(0));

			return {
				confirmed,
				unconfirmed,
				total: confirmed + unconfirmed,
			};
		} catch (error) {
			throw new Error(
				`Error fetching balance: ${error instanceof Error ? error.message : 'Unknown error'}`,
			);
		}
	}

	/**
	 * Create a transaction ready for signing (SCRIPT PATH SPENDING)
	 *
	 * @param toAddress - Recipient Bitcoin address
	 * @param amount - Amount to send in satoshis
	 * @param feeRate - Fee rate in sat/vByte
	 * @param utxo - The UTXO to spend (user-selected)
	 * @returns SignableTransaction containing PSBT for IKA/MPC signing
	 *
	 * Note: Uses script path spending which requires signing with UNTWEAKED key
	 */
	async sendTransaction(
		toAddress: string,
		amount: bigint,
		feeRate: number,
		utxo: UTXO,
	): Promise<SignableTransaction> {
		// Estimate transaction size and fee for single input with script path
		// Script path is slightly larger than key path due to script reveal
		const estimatedSize = 1 * 68 + 2 * 43 + 10; // 1 script path input, 2 outputs
		const fee = BigInt(Math.ceil(estimatedSize * feeRate));

		// Check if the UTXO can cover the amount + fee
		const utxoValue = BigInt(utxo.value);
		if (utxoValue < amount + fee) {
			throw new Error(
				`Insufficient UTXO value. Have: ${utxoValue}, Need: ${amount + fee} (${amount} + ${fee} fee)`,
			);
		}

		// Create transaction
		const psbt = new bitcoin.Psbt({ network: this.bitcoinNetwork });

		// Fetch the transaction hex for this UTXO
		const txHex = await this.#fetchTransactionHex(utxo.txid);
		const tx = bitcoin.Transaction.fromHex(txHex);

		// Add input with SCRIPT PATH spending information
		psbt.addInput({
			hash: utxo.txid,
			index: utxo.vout,
			witnessUtxo: {
				script: tx.outs[utxo.vout].script,
				value: utxoValue,
			},
			// For script path spending, we need:
			tapInternalKey: this.internalPubkey, // NUMS point (not used for signing)
			tapLeafScript: [
				{
					leafVersion: this.redeem.redeemVersion, // 0xc0
					script: this.redeem.output, // Our checksig script
					controlBlock: this.p2tr.witness![this.p2tr.witness!.length - 1], // Merkle proof
				},
			],
		});

		// Add recipient output
		psbt.addOutput({
			address: toAddress,
			value: amount,
		});

		// Add change output if necessary
		const change = utxoValue - amount - fee;
		if (change > BigInt(0)) {
			psbt.addOutput({
				address: this.address,
				value: change,
			});
		}

		// Serialize PSBT for external signing
		const psbtBase64 = psbt.toBase64();

		return {
			psbt,
			psbtBase64,
			inputIndex: 0,
		};
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

		const transaction = new Transaction();

		const multisig = await this.#getMultisig();

		const presign = await this.ikaClient.getPresignInParticularState(
			multisig.presigns[0].presign_id,
			'Completed',
		);

		const tx = bitcoin.Transaction.fromBuffer(psbt.data.getTransaction());

		// Calculate leaf hash for script path spending
		const leafHash = this.#getLeafHash();

		// Build preimage with leaf hash (required for script path spending)
		const preimage = this.#taprootPreimage(
			tx,
			inputIndex,
			[psbt.data.inputs[inputIndex].witnessUtxo!.script],
			[psbt.data.inputs[inputIndex].witnessUtxo!.value],
			bitcoin.Transaction.SIGHASH_DEFAULT,
			leafHash, // Include leaf hash for script path
		);

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
		try {
			const response = await fetch(`${this.apiBaseUrl}/address/${this.address}/utxo`);

			if (!response.ok) {
				throw new Error(`Failed to fetch UTXOs: ${response.statusText}`);
			}

			const utxos: UTXO[] = await response.json();

			// Only return confirmed UTXOs
			return utxos.filter((utxo) => utxo.status.confirmed);
		} catch (error) {
			throw new Error(
				`Error fetching UTXOs: ${error instanceof Error ? error.message : 'Unknown error'}`,
			);
		}
	}

	/**
	 * Find a suitable UTXO for a transaction
	 * Prefers UTXOs that can cover the amount + fee with minimal change
	 */
	findSuitableUTXO(utxos: UTXO[], amount: bigint, feeRate: number): UTXO | null {
		// Script path input: ~68 vbytes (includes script + control block)
		// Output: ~43 vbytes
		const estimatedSize = 1 * 68 + 2 * 43 + 10;
		const estimatedFee = BigInt(Math.ceil(estimatedSize * feeRate));
		const totalNeeded = amount + estimatedFee;

		// Sort UTXOs by value (ascending)
		const sortedUtxos = [...utxos].sort((a, b) => a.value - b.value);

		// Find the smallest UTXO that can cover the amount + fee
		return sortedUtxos.find((utxo) => BigInt(utxo.value) >= totalNeeded) || null;
	}

	finalizeTransaction(psbt: bitcoin.Psbt, signature: Uint8Array, inputIndex: number): string {
		// Get leaf hash for verification
		const leafHash = this.#getLeafHash();

		// For SCRIPT PATH spending, use tapScriptSig (not tapKeySig)
		psbt
			.updateInput(inputIndex, {
				tapScriptSig: [
					{
						pubkey: this.publicKey, // Untweaked public key
						signature: signature, // BIP-340 Schnorr signature
						leafHash: leafHash, // Identifies which script in the tree
					},
				],
			})
			.finalizeAllInputs();

		// Extract the final transaction
		const tx = psbt.extractTransaction();

		return tx.toHex();
	}

	async broadcastTransaction(txHex: string): Promise<string> {
		try {
			const response = await fetch(`${this.apiBaseUrl}/tx`, {
				method: 'POST',
				body: txHex,
			});

			if (!response.ok) {
				const errorText = await response.text();
				throw new Error(`Failed to broadcast transaction: ${errorText}`);
			}

			return await response.text(); // Returns the txid
		} catch (error) {
			throw new Error(
				`Error broadcasting transaction: ${error instanceof Error ? error.message : 'Unknown error'}`,
			);
		}
	}

	/**
	 * Check if a transaction with specific outputs has been broadcasted by searching address history
	 * This is a heuristic check that looks for transactions at this address with matching output patterns
	 * @param psbt - The PSBT containing the transaction
	 * @param createdAfter - Optional timestamp to filter transactions created after this time (in seconds)
	 * @returns Object with potential match information
	 */
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
		try {
			// Get the unsigned transaction from PSBT
			const tx = bitcoin.Transaction.fromBuffer(psbt.data.getTransaction());

			// Build expected output addresses
			const network = this.bitcoinNetwork;
			const expectedOutputs = tx.outs.map((output) => {
				try {
					const address = bitcoin.address.fromOutputScript(output.script, network);
					return {
						address,
						value: Number(output.value),
					};
				} catch {
					return {
						address: null,
						value: Number(output.value),
					};
				}
			});

			console.log('Looking for transaction with outputs:', expectedOutputs);
			console.log('Created after timestamp:', createdAfter);

			// Fetch recent transactions for this address
			const response = await fetch(`${this.apiBaseUrl}/address/${this.address}/txs`);

			if (!response.ok) {
				console.error('Failed to fetch transactions:', response.statusText);
				return { found: false };
			}

			const transactions = await response.json();
			const currentHeight = await this.#getCurrentBlockHeight();

			console.log(`Checking ${transactions.length} transactions...`);

			// Look for a transaction with matching outputs
			for (const txData of transactions) {
				// Filter by timestamp if provided (both are in Unix seconds)
				// createdAfter is in seconds, block_time is also in seconds
				if (createdAfter && txData.status?.block_time) {
					if (txData.status.block_time < createdAfter) {
						continue;
					}
				}

				// Check if the outputs match
				if (txData.vout && txData.vout.length === expectedOutputs.length) {
					let outputsMatch = true;

					for (let i = 0; i < expectedOutputs.length; i++) {
						const expectedOutput = expectedOutputs[i];
						const actualOutput = txData.vout[i];

						// Check if value matches
						if (actualOutput.value !== expectedOutput.value) {
							outputsMatch = false;
							break;
						}

						// Also check address if available
						if (expectedOutput.address && actualOutput.scriptpubkey_address) {
							if (actualOutput.scriptpubkey_address !== expectedOutput.address) {
								outputsMatch = false;
								break;
							}
						}
					}

					if (outputsMatch) {
						console.log('Found matching transaction:', txData.txid);
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
			}

			console.log('No matching transaction found');
			return { found: false };
		} catch (error) {
			console.error('Error searching for broadcasted transaction:', error);
			return { found: false };
		}
	}

	/**
	 * Build Taproot preimage for signing
	 * Based on BIP-0341 and BIP-0342
	 *
	 * @param tx - The Bitcoin transaction
	 * @param inIndex - Index of the input being signed
	 * @param prevOutScripts - Previous output scripts for all inputs
	 * @param values - Values (in satoshis) for all inputs
	 * @param hashType - Sighash type
	 * @param leafHash - Optional Taproot leaf hash for script path spending
	 * @param annex - Optional annex data
	 * @returns The preimage (tagHash || tagHash || [0x00] || sigMsg) ready for MPC signing
	 *          This should be hashed with SHA256 to get the final TapSighash
	 */
	#taprootPreimage(
		tx: bitcoin.Transaction,
		inIndex: number,
		prevOutScripts: (Buffer | Uint8Array)[],
		values: bigint[],
		hashType: number,
		leafHash?: Buffer | Uint8Array,
		annex?: Buffer | Uint8Array,
	): Uint8Array {
		if (values.length !== tx.ins.length || prevOutScripts.length !== tx.ins.length) {
			throw new Error('Must supply prevout script and value for all inputs');
		}

		const outputType =
			hashType === bitcoin.Transaction.SIGHASH_DEFAULT
				? bitcoin.Transaction.SIGHASH_ALL
				: hashType & bitcoin.Transaction.SIGHASH_OUTPUT_MASK;

		const inputType = hashType & bitcoin.Transaction.SIGHASH_INPUT_MASK;

		const isAnyoneCanPay = inputType === bitcoin.Transaction.SIGHASH_ANYONECANPAY;
		const isNone = outputType === bitcoin.Transaction.SIGHASH_NONE;
		const isSingle = outputType === bitcoin.Transaction.SIGHASH_SINGLE;

		const EMPTY_BUFFER = Buffer.alloc(0);

		let hashPrevouts = EMPTY_BUFFER;
		let hashAmounts = EMPTY_BUFFER;
		let hashScriptPubKeys = EMPTY_BUFFER;
		let hashSequences = EMPTY_BUFFER;
		let hashOutputs = EMPTY_BUFFER;

		// Helper to convert Uint8Array to Buffer
		const toBuffer = (data: Buffer | Uint8Array): Buffer => {
			return Buffer.isBuffer(data) ? data : Buffer.from(data);
		};

		// Helper to write 64-bit unsigned integer in little-endian format
		const writeUInt64LE = (buffer: Buffer, value: bigint, offset: number): void => {
			// Write 64-bit unsigned integer as little-endian bytes
			const low = Number(value & BigInt(0xffffffff));
			const high = Number((value >> BigInt(32)) & BigInt(0xffffffff));
			buffer.writeUInt32LE(low, offset);
			buffer.writeUInt32LE(high, offset + 4);
		};

		// Helper to calculate varint size
		const varSliceSize = (script: Buffer | Uint8Array): number => {
			const length = script.length;
			if (length < 0xfd) return 1 + length;
			if (length <= 0xffff) return 3 + length;
			if (length <= 0xffffffff) return 5 + length;
			return 9 + length;
		};

		if (!isAnyoneCanPay) {
			// Hash prevouts
			const prevoutsBuffer = Buffer.allocUnsafe(36 * tx.ins.length);
			let offset = 0;
			for (const txIn of tx.ins) {
				const hashBuffer = toBuffer(txIn.hash);
				hashBuffer.copy(prevoutsBuffer, offset);
				offset += 32;
				prevoutsBuffer.writeUInt32LE(txIn.index, offset);
				offset += 4;
			}
			hashPrevouts = Buffer.from(sha256(prevoutsBuffer));

			// Hash amounts
			const amountsBuffer = Buffer.allocUnsafe(8 * values.length);
			offset = 0;
			for (const value of values) {
				writeUInt64LE(amountsBuffer, value, offset);
				offset += 8;
			}
			hashAmounts = Buffer.from(sha256(amountsBuffer));

			// Hash script pubkeys
			const scriptPubKeysSize = prevOutScripts.reduce(
				(sum, script) => sum + varSliceSize(script),
				0,
			);
			const scriptPubKeysBuffer = Buffer.allocUnsafe(scriptPubKeysSize);
			offset = 0;
			for (const script of prevOutScripts) {
				const scriptBuffer = toBuffer(script);
				const length = scriptBuffer.length;
				if (length < 0xfd) {
					scriptPubKeysBuffer.writeUInt8(length, offset);
					offset += 1;
				} else if (length <= 0xffff) {
					scriptPubKeysBuffer.writeUInt8(0xfd, offset);
					offset += 1;
					scriptPubKeysBuffer.writeUInt16LE(length, offset);
					offset += 2;
				} else if (length <= 0xffffffff) {
					scriptPubKeysBuffer.writeUInt8(0xfe, offset);
					offset += 1;
					scriptPubKeysBuffer.writeUInt32LE(length, offset);
					offset += 4;
				} else {
					scriptPubKeysBuffer.writeUInt8(0xff, offset);
					offset += 1;
					writeUInt64LE(scriptPubKeysBuffer, BigInt(length), offset);
					offset += 8;
				}
				scriptBuffer.copy(scriptPubKeysBuffer, offset);
				offset += length;
			}
			hashScriptPubKeys = Buffer.from(sha256(scriptPubKeysBuffer.slice(0, offset)));

			// Hash sequences
			const sequencesBuffer = Buffer.allocUnsafe(4 * tx.ins.length);
			offset = 0;
			for (const txIn of tx.ins) {
				sequencesBuffer.writeUInt32LE(txIn.sequence, offset);
				offset += 4;
			}
			hashSequences = Buffer.from(sha256(sequencesBuffer));
		}

		// Hash outputs
		if (!(isNone || isSingle)) {
			if (!tx.outs.length) {
				throw new Error('Add outputs to the transaction before signing.');
			}
			const txOutsSize = tx.outs.reduce((sum, out) => sum + 8 + varSliceSize(out.script), 0);
			const outputsBuffer = Buffer.allocUnsafe(txOutsSize);
			let offset = 0;
			for (const out of tx.outs) {
				writeUInt64LE(outputsBuffer, BigInt(out.value), offset);
				offset += 8;
				const scriptBuffer = toBuffer(out.script);
				const length = scriptBuffer.length;
				if (length < 0xfd) {
					outputsBuffer.writeUInt8(length, offset);
					offset += 1;
				} else if (length <= 0xffff) {
					outputsBuffer.writeUInt8(0xfd, offset);
					offset += 1;
					outputsBuffer.writeUInt16LE(length, offset);
					offset += 2;
				} else if (length <= 0xffffffff) {
					outputsBuffer.writeUInt8(0xfe, offset);
					offset += 1;
					outputsBuffer.writeUInt32LE(length, offset);
					offset += 4;
				} else {
					outputsBuffer.writeUInt8(0xff, offset);
					offset += 1;
					writeUInt64LE(outputsBuffer, BigInt(length), offset);
					offset += 8;
				}
				scriptBuffer.copy(outputsBuffer, offset);
				offset += length;
			}
			hashOutputs = Buffer.from(sha256(outputsBuffer.slice(0, offset)));
		} else if (isSingle && inIndex < tx.outs.length) {
			const out = tx.outs[inIndex];
			const outputSize = 8 + varSliceSize(out.script);
			const outputBuffer = Buffer.allocUnsafe(outputSize);
			let offset = 0;
			writeUInt64LE(outputBuffer, BigInt(out.value), offset);
			offset += 8;
			const scriptBuffer = toBuffer(out.script);
			const length = scriptBuffer.length;
			if (length < 0xfd) {
				outputBuffer.writeUInt8(length, offset);
				offset += 1;
			} else if (length <= 0xffff) {
				outputBuffer.writeUInt8(0xfd, offset);
				offset += 1;
				outputBuffer.writeUInt16LE(length, offset);
				offset += 2;
			} else if (length <= 0xffffffff) {
				outputBuffer.writeUInt8(0xfe, offset);
				offset += 1;
				outputBuffer.writeUInt32LE(length, offset);
				offset += 4;
			} else {
				outputBuffer.writeUInt8(0xff, offset);
				offset += 1;
				writeUInt64LE(outputBuffer, BigInt(length), offset);
				offset += 8;
			}
			scriptBuffer.copy(outputBuffer, offset);
			offset += length;
			hashOutputs = Buffer.from(sha256(outputBuffer.slice(0, offset)));
		}

		const spendType = (leafHash ? 2 : 0) + (annex ? 1 : 0);

		// Calculate signature message size
		const sigMsgSize =
			174 - (isAnyoneCanPay ? 49 : 0) - (isNone ? 32 : 0) + (annex ? 32 : 0) + (leafHash ? 37 : 0);

		// Build signature message
		const sigMsgParts: Buffer[] = [];

		// Hash type
		sigMsgParts.push(Buffer.from([hashType]));

		// Transaction
		const versionBuffer = Buffer.allocUnsafe(4);
		versionBuffer.writeUInt32LE(tx.version, 0);
		sigMsgParts.push(versionBuffer);

		const locktimeBuffer = Buffer.allocUnsafe(4);
		locktimeBuffer.writeUInt32LE(tx.locktime, 0);
		sigMsgParts.push(locktimeBuffer);

		sigMsgParts.push(hashPrevouts);
		sigMsgParts.push(hashAmounts);
		sigMsgParts.push(hashScriptPubKeys);
		sigMsgParts.push(hashSequences);

		if (!(isNone || isSingle)) {
			sigMsgParts.push(hashOutputs);
		}

		// Input
		sigMsgParts.push(Buffer.from([spendType]));

		if (isAnyoneCanPay) {
			const input = tx.ins[inIndex];
			sigMsgParts.push(toBuffer(input.hash));
			const indexBuffer = Buffer.allocUnsafe(4);
			indexBuffer.writeUInt32LE(input.index, 0);
			sigMsgParts.push(indexBuffer);

			const valueBuffer = Buffer.allocUnsafe(8);
			writeUInt64LE(valueBuffer, values[inIndex], 0);
			sigMsgParts.push(valueBuffer);

			const scriptBuffer = toBuffer(prevOutScripts[inIndex]);
			const scriptLength = scriptBuffer.length;
			const scriptVarint = Buffer.allocUnsafe(
				scriptLength < 0xfd ? 1 : scriptLength <= 0xffff ? 3 : scriptLength <= 0xffffffff ? 5 : 9,
			);
			let scriptOffset = 0;
			if (scriptLength < 0xfd) {
				scriptVarint.writeUInt8(scriptLength, scriptOffset);
				scriptOffset = 1;
			} else if (scriptLength <= 0xffff) {
				scriptVarint.writeUInt8(0xfd, scriptOffset);
				scriptVarint.writeUInt16LE(scriptLength, scriptOffset + 1);
				scriptOffset = 3;
			} else if (scriptLength <= 0xffffffff) {
				scriptVarint.writeUInt8(0xfe, scriptOffset);
				scriptVarint.writeUInt32LE(scriptLength, scriptOffset + 1);
				scriptOffset = 5;
			} else {
				scriptVarint.writeUInt8(0xff, scriptOffset);
				writeUInt64LE(scriptVarint, BigInt(scriptLength), scriptOffset + 1);
				scriptOffset = 9;
			}
			sigMsgParts.push(scriptVarint.slice(0, scriptOffset));
			sigMsgParts.push(scriptBuffer);

			const sequenceBuffer = Buffer.allocUnsafe(4);
			sequenceBuffer.writeUInt32LE(input.sequence, 0);
			sigMsgParts.push(sequenceBuffer);
		} else {
			const indexBuffer = Buffer.allocUnsafe(4);
			indexBuffer.writeUInt32LE(inIndex, 0);
			sigMsgParts.push(indexBuffer);
		}

		if (annex) {
			const annexBuffer = toBuffer(annex);
			const annexLength = annexBuffer.length;
			let annexVarintSize = 1;
			if (annexLength >= 0xfd) {
				annexVarintSize = annexLength <= 0xffff ? 3 : annexLength <= 0xffffffff ? 5 : 9;
			}
			const annexVarint = Buffer.allocUnsafe(annexVarintSize);
			let annexOffset = 0;
			if (annexLength < 0xfd) {
				annexVarint.writeUInt8(annexLength, annexOffset);
				annexOffset = 1;
			} else if (annexLength <= 0xffff) {
				annexVarint.writeUInt8(0xfd, annexOffset);
				annexVarint.writeUInt16LE(annexLength, annexOffset + 1);
				annexOffset = 3;
			} else if (annexLength <= 0xffffffff) {
				annexVarint.writeUInt8(0xfe, annexOffset);
				annexVarint.writeUInt32LE(annexLength, annexOffset + 1);
				annexOffset = 5;
			} else {
				annexVarint.writeUInt8(0xff, annexOffset);
				writeUInt64LE(annexVarint, BigInt(annexLength), annexOffset + 1);
				annexOffset = 9;
			}
			const annexWithVarint = Buffer.concat([annexVarint.slice(0, annexOffset), annexBuffer]);
			sigMsgParts.push(Buffer.from(sha256(annexWithVarint)));
		}

		// Output
		if (isSingle) {
			sigMsgParts.push(hashOutputs);
		}

		// BIP342 extension
		if (leafHash) {
			sigMsgParts.push(toBuffer(leafHash));
			sigMsgParts.push(Buffer.from([0]));
			const leafHashExt = Buffer.allocUnsafe(4);
			leafHashExt.writeUInt32LE(0xffffffff, 0);
			sigMsgParts.push(leafHashExt);
		}

		// Concatenate all parts
		const sigMsg = Buffer.concat(sigMsgParts);

		// Compute tagged hash: SHA256(tagHash || tagHash || [0x00] || sigMsg)
		// Where tagHash = SHA256("TapSighash")
		const tagHash = Uint8Array.from([
			244, 10, 72, 223, 75, 42, 112, 200, 180, 146, 75, 242, 101, 70, 97, 237, 61, 149, 253, 102,
			163, 19, 235, 135, 35, 117, 151, 198, 40, 228, 160, 49, 244, 10, 72, 223, 75, 42, 112, 200,
			180, 146, 75, 242, 101, 70, 97, 237, 61, 149, 253, 102, 163, 19, 235, 135, 35, 117, 151, 198,
			40, 228, 160, 49,
		]);
		const preimage = Buffer.concat([tagHash, Buffer.from([0x00]), sigMsg]);

		// Return preimage (tagHash || tagHash || [0x00] || sigMsg)
		// This is what MPC signs - it will hash this with SHA256 to get the TapSighash
		return new Uint8Array(preimage);
	}

	/**
	 * Calculate the leaf hash for the taproot script
	 * TapLeaf hash = SHA256(SHA256("TapLeaf") || SHA256("TapLeaf") || version || script_len || script)
	 *
	 * This is required for script path spending to identify which script in the tree we're using.
	 */
	#getLeafHash(): Buffer {
		const tagHash = Buffer.from(sha256('TapLeaf'));
		const version = Buffer.from([this.redeem.redeemVersion]); // 0xc0

		// Encode script length as compact size
		const scriptLen = this.redeem.output.length;
		let scriptLenEncoded: Buffer;
		if (scriptLen < 0xfd) {
			scriptLenEncoded = Buffer.from([scriptLen]);
		} else if (scriptLen <= 0xffff) {
			scriptLenEncoded = Buffer.allocUnsafe(3);
			scriptLenEncoded.writeUInt8(0xfd, 0);
			scriptLenEncoded.writeUInt16LE(scriptLen, 1);
		} else if (scriptLen <= 0xffffffff) {
			scriptLenEncoded = Buffer.allocUnsafe(5);
			scriptLenEncoded.writeUInt8(0xfe, 0);
			scriptLenEncoded.writeUInt32LE(scriptLen, 1);
		} else {
			scriptLenEncoded = Buffer.allocUnsafe(9);
			scriptLenEncoded.writeUInt8(0xff, 0);
			scriptLenEncoded.writeBigUInt64LE(BigInt(scriptLen), 1);
		}

		// Calculate tagged hash: SHA256(tagHash || tagHash || version || scriptLen || script)
		const leafHash = Buffer.from(
			sha256(Buffer.concat([tagHash, tagHash, version, scriptLenEncoded, this.redeem.output])),
		);

		return leafHash;
	}

	async #getMultisig(): Promise<typeof MultisigModule.Multisig.$inferType> {
		const multisig = await this.suiClient
			.getObject({
				id: this.object.multisig,
				options: {
					showBcs: true,
				},
			})
			.then((obj) => MultisigModule.Multisig.fromBase64(objResToBcs(obj)));

		return multisig;
	}

	async #fetchTransactionHex(txid: string): Promise<string> {
		try {
			const response = await fetch(`${this.apiBaseUrl}/tx/${txid}/hex`);

			if (!response.ok) {
				throw new Error(`Failed to fetch transaction: ${response.statusText}`);
			}

			return await response.text();
		} catch (error) {
			throw new Error(
				`Error fetching transaction: ${error instanceof Error ? error.message : 'Unknown error'}`,
			);
		}
	}

	async #getCurrentBlockHeight(): Promise<number | null> {
		try {
			const response = await fetch(`${this.apiBaseUrl}/blocks/tip/height`);

			if (!response.ok) {
				return null;
			}

			const height = await response.text();
			return parseInt(height, 10);
		} catch (error) {
			return null;
		}
	}
}
