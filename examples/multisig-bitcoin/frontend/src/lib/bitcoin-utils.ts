import * as secp256k1 from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';
import { sha256 } from 'bitcoinjs-lib/src/crypto';

// Bitcoin testnet configuration
export const BITCOIN_NETWORK = bitcoin.networks.testnet;

// UTXO interface for transaction inputs
export interface UTXO {
	txid: string;
	vout: number;
	value: number;
	scriptPubKey: string;
}

// Bitcoin transaction creation utilities
export class BitcoinUtils {
	/**
	 * Create a Bitcoin PSBT (Partially Signed Bitcoin Transaction) for multisig
	 * @param utxos Array of UTXOs to spend
	 * @param recipientAddress Recipient Bitcoin address
	 * @param amount Amount to send in satoshis
	 * @param fee Fee in satoshis
	 * @param changeAddress Change address for remaining funds
	 * @returns PSBT hex and PSBT hash for identification
	 */
	static createTransaction(
		utxos: UTXO[],
		recipientAddress: string,
		amount: number,
		fee: number,
		changeAddress: string,
	): Buffer {
		try {
			// Create a new transaction builder
			const psbt = new bitcoin.Psbt({ network: BITCOIN_NETWORK });

			// Calculate total input value
			const totalInput = utxos.reduce((sum, utxo) => sum + utxo.value, 0);

			// Add a small buffer to account for fee estimation inaccuracies
			const buffer = Math.max(500, Math.ceil(fee * 0.05)); // At least 500 sats or 5% of fee
			const adjustedTotalRequired = amount + fee + buffer;

			// Debug logging for funds validation
			console.log('Funds validation:', {
				totalInput,
				amount,
				fee,
				buffer,
				adjustedTotalRequired,
				isInsufficient: totalInput < adjustedTotalRequired,
				utxoCount: utxos.length,
				utxoValues: utxos.map((u) => u.value),
			});

			// Validate inputs with buffer
			if (totalInput < adjustedTotalRequired) {
				throw new Error(
					`Insufficient funds for transaction. Need ${adjustedTotalRequired} sats, have ${totalInput} sats (including ${buffer} sats buffer)`,
				);
			}

			// Add inputs
			utxos.forEach((utxo) => {
				psbt.addInput({
					hash: utxo.txid,
					index: utxo.vout,
					witnessUtxo: {
						script: Buffer.from(utxo.scriptPubKey, 'hex'),
						value: utxo.value,
					},
				});
			});

			// Add recipient output
			psbt.addOutput({
				address: recipientAddress,
				value: amount,
			});

			// Calculate change
			const changeAmount = totalInput - amount - fee;
			if (changeAmount > 0) {
				psbt.addOutput({
					address: changeAddress,
					value: changeAmount,
				});
			}

			const psbtHex = psbt.toBuffer();

			return psbtHex;
		} catch (error) {
			throw new Error(`Failed to create Bitcoin transaction: ${error}`);
		}
	}

	/**
	 * Validate a Bitcoin address
	 * @param address Bitcoin address to validate
	 * @param network Bitcoin network (testnet/mainnet)
	 * @returns True if address is valid
	 */
	static validateAddress(address: string, network = BITCOIN_NETWORK): boolean {
		try {
			console.log(
				`Validating address: ${address} on network: ${network === bitcoin.networks.testnet ? 'testnet' : 'mainnet'}`,
			);
			const script = bitcoin.address.toOutputScript(address, network);
			console.log(`Address validation successful, script length: ${script.length}`);
			return true;
		} catch (error) {
			console.warn(`Address validation failed for ${address}:`, error);

			// Additional debugging for testnet addresses
			if (network === bitcoin.networks.testnet) {
				console.log(`Testnet address format check:`);
				console.log(`- Starts with 'tb1' (Bech32): ${address.startsWith('tb1')}`);
				console.log(`- Length: ${address.length}`);
				console.log(`- Address prefix: ${address.substring(0, 3)}`);
			}

			return false;
		}
	}

	/**
	 * Convert amount from BTC to satoshis
	 * @param btc Amount in BTC
	 * @returns Amount in satoshis
	 */
	static btcToSatoshis(btc: number): number {
		return Math.floor(btc * 100000000);
	}

	/**
	 * Convert amount from satoshis to BTC
	 * @param satoshis Amount in satoshis
	 * @returns Amount in BTC
	 */
	static satoshisToBtc(satoshis: number): number {
		return satoshis / 100000000;
	}

	/**
	 * Calculate estimated transaction fee
	 * @param inputCount Number of inputs
	 * @param outputCount Number of outputs
	 * @param feeRate Fee rate in sat/vB
	 * @returns Estimated fee in satoshis
	 */
	static calculateFee(inputCount: number, outputCount: number, feeRate = 1): number {
		// Conservative estimation for P2WPKH (segwit) transactions:
		// - 41 bytes per P2WPKH input (vs 148 for legacy)
		// - 31 bytes per P2WPKH output (vs 34 for legacy)
		// - 10.5 bytes overhead for segwit transactions
		// Using slightly higher estimates for safety
		const txSize = inputCount * 45 + outputCount * 35 + 15;
		const fee = Math.ceil(txSize * feeRate);

		// Ensure minimum fee of 1000 sats for very small transactions
		return Math.max(fee, 1000);
	}

	/**
	 * Fetch UTXOs for a Bitcoin address from the network
	 * @param address Bitcoin address
	 * @returns Array of UTXOs
	 */
	static async fetchUTXOs(address: string): Promise<UTXO[]> {
		try {
			const response = await fetch(`https://mempool.space/testnet/api/address/${address}/utxo`);
			if (!response.ok) {
				throw new Error(`Failed to fetch UTXOs: ${response.statusText}`);
			}

			const utxos = await response.json();

			return utxos.map((utxo: any) => ({
				txid: utxo.txid,
				vout: utxo.vout,
				value: utxo.value,
				scriptPubKey: utxo.scriptpubkey || '', // Get scriptPubKey from mempool API
			}));
		} catch (error) {
			console.error('Error fetching UTXOs:', error);
			throw new Error('Failed to fetch UTXOs from network');
		}
	}

	/**
	 * Get current fee estimates from the network
	 * @returns Current fee rates
	 */
	static async getNetworkFeeRates(): Promise<{ fastest: number; halfHour: number; hour: number }> {
		try {
			const response = await fetch('https://mempool.space/testnet/api/v1/fees/recommended');
			if (!response.ok) {
				throw new Error(`Failed to fetch fee estimates: ${response.statusText}`);
			}

			const fees = await response.json();
			return {
				fastest: fees.fastestFee || 10,
				halfHour: fees.halfHourFee || 5,
				hour: fees.hourFee || 2,
			};
		} catch (error) {
			console.error('Error fetching fee estimates:', error);
			// Fallback to conservative fee rates
			return { fastest: 10, halfHour: 5, hour: 2 };
		}
	}

	/**
	 * Calculate Bitcoin address from public key
	 * @param publicKey Public key as Uint8Array
	 * @returns Bitcoin address
	 */
	static async getAddressFromPublicKey(publicKey: Uint8Array): Promise<string> {
		try {
			let pubKeyBuffer = Buffer.from(publicKey);

			console.log('Original public key length:', pubKeyBuffer.length);
			console.log('Original public key (hex):', pubKeyBuffer.toString('hex'));

			// Initialize ECC library for bitcoinjs-lib v6+
			bitcoin.initEccLib(secp256k1);

			// Handle different public key formats
			let finalPubKey: Buffer = Buffer.alloc(0);

			if (pubKeyBuffer.length === 33 || pubKeyBuffer.length === 65) {
				// Already in compressed or uncompressed format
				finalPubKey = pubKeyBuffer;
			} else if (pubKeyBuffer.length === 32) {
				// Raw 32-byte public key (x-coordinate only), assume compressed format
				// For secp256k1, we need to determine if y is even or odd
				// Since we don't have y, we'll try both possibilities and use the valid one
				const x = pubKeyBuffer;

				// Try even y (compressed format with 0x02 prefix)
				const evenY = Buffer.concat([Buffer.from([0x02]), x]);
				if (secp256k1.isPoint(evenY)) {
					finalPubKey = evenY;
				} else {
					// Try odd y (compressed format with 0x03 prefix)
					const oddY = Buffer.concat([Buffer.from([0x03]), x]);
					if (secp256k1.isPoint(oddY)) {
						finalPubKey = oddY;
					} else {
						throw new Error('Could not reconstruct valid public key from 32-byte input');
					}
				}
			} else if (pubKeyBuffer.length === 34) {
				// 34-byte key might have an extra byte, try removing the first byte
				console.log('Processing 34-byte key, first byte:', pubKeyBuffer[0]);
				finalPubKey = pubKeyBuffer.subarray(1);
				console.log('After removing first byte, length:', finalPubKey.length);
				console.log('After removing first byte, is valid point:', secp256k1.isPoint(finalPubKey));
				if (!secp256k1.isPoint(finalPubKey)) {
					throw new Error('Invalid 34-byte public key format');
				}
			} else {
				throw new Error(
					`Invalid public key length: ${pubKeyBuffer.length} bytes. Expected 32, 33, 34, or 65 bytes.`,
				);
			}

			// Validate that it's a valid ECDSA public key
			if (!secp256k1.isPoint(finalPubKey)) {
				throw new Error('Invalid public key: not a valid elliptic curve point');
			}

			// Generate P2WPKH (Bech32) address directly from public key for better faucet compatibility
			console.log('Final public key length:', finalPubKey.length);
			console.log('Final public key (hex):', finalPubKey.toString('hex'));

			const { address } = bitcoin.payments.p2wpkh({
				pubkey: finalPubKey,
				network: BITCOIN_NETWORK,
			});

			if (!address) {
				throw new Error('Failed to generate Bitcoin address');
			}

			console.log('Generated Bitcoin address:', address);
			console.log('Address validation result:', BitcoinUtils.validateAddress(address));

			// Verify the generated address format (Bech32 for testnet should start with 'tb1')
			const isValidTestnetFormat = address.startsWith('tb1');
			console.log('Generated address has valid testnet Bech32 format:', isValidTestnetFormat);

			if (!isValidTestnetFormat) {
				console.error('ERROR: Generated address does not have valid testnet Bech32 format!');
				console.error('Expected: starts with tb1');
				console.error('Got:', address.substring(0, 3));
			}

			return address;
		} catch (error) {
			throw new Error(`Failed to calculate Bitcoin address from public key: ${error}`);
		}
	}
}

// Export utility functions for easy access
export const {
	validateAddress,
	btcToSatoshis,
	satoshisToBtc,
	calculateFee,
	fetchUTXOs,
	getNetworkFeeRates,
	getAddressFromPublicKey,
} = BitcoinUtils;
