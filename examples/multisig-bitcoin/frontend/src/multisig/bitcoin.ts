/**
 * MultisigBitcoinWallet - A Taproot-based Bitcoin wallet for MPC/dWallet integration
 *
 * Workflow:
 * 1. Create wallet with aggregated public key from MPC/dWallet
 * 2. Get balance and UTXOs
 * 3. User selects a UTXO to spend
 * 4. Create signable transaction (returns PSBT)
 * 5. Send PSBT to IKA/MPC for signing
 * 6. Receive signature from MPC
 * 7. Finalize transaction with signature
 * 8. Broadcast to network
 *
 * Example:
 * ```typescript
 * const wallet = new MultisigBitcoinWallet('testnet', aggregatedPublicKey);
 * const utxos = await wallet.getUTXOs();
 * const utxo = wallet.findSuitableUTXO(utxos, amount, feeRate);
 *
 * // Create transaction
 * const { psbt, psbtBase64, inputIndex } = await wallet.sendTransaction(
 *   recipientAddress,
 *   amount,
 *   feeRate,
 *   utxo
 * );
 *
 * // Send psbtBase64 to IKA/MPC for signing
 * const signature = await ikaMPCSign(psbtBase64, inputIndex);
 *
 * // Finalize and broadcast
 * const txHex = wallet.finalizeTransaction(psbt, signature, inputIndex);
 * const txid = await wallet.broadcastTransaction(Buffer.from(txHex).toString('hex'));
 * ```
 */
import * as bitcoin from 'bitcoinjs-lib';

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

	constructor(
		private readonly network: 'testnet' | 'mainnet' = 'testnet',
		private readonly publicKey: Uint8Array,
	) {
		this.network = network;
		this.publicKey = publicKey;

		// Set Bitcoin network and API URL
		this.bitcoinNetwork =
			network === 'mainnet' ? bitcoin.networks.bitcoin : bitcoin.networks.testnet;
		this.apiBaseUrl =
			network === 'mainnet'
				? 'https://blockstream.info/api'
				: 'https://blockstream.info/testnet/api';

		// Create Taproot address from public key
		const p2tr = bitcoin.payments.p2tr({
			internalPubkey: Buffer.from(this.publicKey), // x-only pubkey (32 bytes)
			network: this.bitcoinNetwork,
		});

		if (!p2tr.address) {
			throw new Error('Failed to generate Taproot address');
		}

		this.address = p2tr.address;
	}

	getAddress(): string {
		return this.address;
	}

	async getBalance(): Promise<bigint> {
		const utxos = await this.getUTXOs();
		const balance = utxos.reduce((sum, utxo) => sum + BigInt(utxo.value), BigInt(0));
		return balance;
	}

	/**
	 * Create a transaction ready for signing
	 *
	 * @param toAddress - Recipient Bitcoin address
	 * @param amount - Amount to send in satoshis
	 * @param feeRate - Fee rate in sat/vByte
	 * @param utxo - The UTXO to spend (user-selected)
	 * @returns SignableTransaction containing PSBT for IKA/MPC signing
	 *
	 * Note: This creates a single-input transaction, requiring only ONE signature from IKA/MPC
	 */
	async sendTransaction(
		toAddress: string,
		amount: bigint,
		feeRate: number,
		utxo: UTXO,
	): Promise<SignableTransaction> {
		// Estimate transaction size and fee for single input
		// Taproot input: ~57.5 vbytes, output: ~43 vbytes
		const estimatedSize = 1 * 58 + 2 * 43 + 10; // 1 input, 2 outputs
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
		const txHex = await this.fetchTransactionHex(utxo.txid);
		const tx = bitcoin.Transaction.fromHex(txHex);

		// Add the single input
		psbt.addInput({
			hash: utxo.txid,
			index: utxo.vout,
			witnessUtxo: {
				script: tx.outs[utxo.vout].script,
				value: utxoValue,
			},
			tapInternalKey: Buffer.from(this.publicKey),
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

	private async fetchTransactionHex(txid: string): Promise<string> {
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

	/**
	 * Estimate the fee for a transaction with a single input
	 */
	estimateFee(feeRate: number, hasChange: boolean = true): bigint {
		// Taproot input: ~57.5 vbytes, output: ~43 vbytes
		const estimatedSize = 1 * 58 + (hasChange ? 2 : 1) * 43 + 10;
		return BigInt(Math.ceil(estimatedSize * feeRate));
	}

	/**
	 * Find a suitable UTXO for a transaction
	 * Prefers UTXOs that can cover the amount + fee with minimal change
	 */
	findSuitableUTXO(utxos: UTXO[], amount: bigint, feeRate: number): UTXO | null {
		const estimatedFee = this.estimateFee(feeRate, true);
		const totalNeeded = amount + estimatedFee;

		// Sort UTXOs by value (ascending)
		const sortedUtxos = [...utxos].sort((a, b) => a.value - b.value);

		// Find the smallest UTXO that can cover the amount + fee
		return sortedUtxos.find((utxo) => BigInt(utxo.value) >= totalNeeded) || null;
	}

	finalizeTransaction(psbt: bitcoin.Psbt, signature: Uint8Array, inputIndex: number): Uint8Array {
		// Add the signature to the PSBT
		// For Taproot key path spending, we use tapKeySig
		psbt.updateInput(inputIndex, {
			tapKeySig: Buffer.from(signature),
		});

		// Finalize the input
		psbt.finalizeInput(inputIndex);

		// Extract the final transaction
		const tx = psbt.extractTransaction();
		return new Uint8Array(tx.toBuffer());
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
}
