// Bitcoin testnet configuration
export const BITCOIN_CONFIG = {
	network: 'testnet',
	rpcUrl: 'https://mempool.space/testnet/api',
	explorerUrl: 'https://mempool.space/testnet',
	faucet: {
		url: 'https://bitcoinfaucet.uo1.net',
		alternativeUrls: ['https://testnet-faucet.com', 'https://faucet.testnet.bitcoincloud.net'],
	},
	feeEstimates: {
		fast: 2, // sat/vB
		normal: 1,
		slow: 0.5,
	},
	// Testnet addresses for development
	testAddresses: {
		faucet: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx', // Example testnet address
	},
};

// Bitcoin API utilities
export class BitcoinAPI {
	private static readonly MEMPOOL_API = BITCOIN_CONFIG.rpcUrl;

	/**
	 * Get Bitcoin balance for an address
	 * @param address Bitcoin address
	 * @returns Balance in satoshis
	 */
	static async getBalance(address: string): Promise<number> {
		try {
			const response = await fetch(`${this.MEMPOOL_API}/address/${address}`);
			if (!response.ok) {
				throw new Error(`Failed to fetch balance: ${response.statusText}`);
			}
			const data = await response.json();
			return data.chain_stats.funded_txo_sum - data.chain_stats.spent_txo_sum;
		} catch (error) {
			console.error('Error fetching Bitcoin balance:', error);
			throw new Error('Failed to fetch Bitcoin balance');
		}
	}

	/**
	 * Get UTXOs for an address
	 * @param address Bitcoin address
	 * @returns Array of UTXOs
	 */
	static async getUTXOs(address: string): Promise<any[]> {
		try {
			const response = await fetch(`${this.MEMPOOL_API}/address/${address}/utxo`);
			if (!response.ok) {
				throw new Error(`Failed to fetch UTXOs: ${response.statusText}`);
			}
			return await response.json();
		} catch (error) {
			console.error('Error fetching UTXOs:', error);
			throw new Error('Failed to fetch UTXOs');
		}
	}

	/**
	 * Get current fee estimates
	 * @returns Fee estimates in sat/vB
	 */
	static async getFeeEstimates(): Promise<{ fast: number; normal: number; slow: number }> {
		try {
			const response = await fetch(`${this.MEMPOOL_API}/v1/fees/recommended`);
			if (!response.ok) {
				throw new Error(`Failed to fetch fee estimates: ${response.statusText}`);
			}
			const data = await response.json();
			return {
				fast: data.fastestFee || BITCOIN_CONFIG.feeEstimates.fast,
				normal: data.halfHourFee || BITCOIN_CONFIG.feeEstimates.normal,
				slow: data.hourFee || BITCOIN_CONFIG.feeEstimates.slow,
			};
		} catch (error) {
			console.error('Error fetching fee estimates:', error);
			return BITCOIN_CONFIG.feeEstimates;
		}
	}

	/**
	 * Get transaction details
	 * @param txid Transaction ID
	 * @returns Transaction details
	 */
	static async getTransaction(txid: string): Promise<any> {
		try {
			const response = await fetch(`${this.MEMPOOL_API}/tx/${txid}`);
			if (!response.ok) {
				throw new Error(`Failed to fetch transaction: ${response.statusText}`);
			}
			return await response.json();
		} catch (error) {
			console.error('Error fetching transaction:', error);
			throw new Error('Failed to fetch transaction details');
		}
	}

	/**
	 * Get explorer URL for address
	 * @param address Bitcoin address
	 * @returns Explorer URL
	 */
	static getExplorerUrl(address: string): string {
		return `${BITCOIN_CONFIG.explorerUrl}/address/${address}`;
	}

	/**
	 * Get explorer URL for transaction
	 * @param txid Transaction ID
	 * @returns Explorer URL
	 */
	static getTransactionUrl(txid: string): string {
		return `${BITCOIN_CONFIG.explorerUrl}/tx/${txid}`;
	}
}

// Faucet utilities for testnet
export class BitcoinFaucet {
	/**
	 * Get information about available testnet faucets
	 * @param address Bitcoin testnet address to receive funds
	 * @returns Information about faucet services
	 */
	static async requestFunds(address: string): Promise<{
		success: boolean;
		message: string;
		faucets: Array<{ name: string; url: string; description: string }>;
	}> {
		try {
			console.log(`Getting faucet information for address: ${address}`);

			const faucets = [
				{
					name: 'Bitcoin Testnet Faucet',
					url: 'https://bitcoinfaucet.uo1.net',
					description: 'Free testnet Bitcoin faucet with captcha verification',
				},
				{
					name: 'Testnet Faucet',
					url: 'https://testnet-faucet.com',
					description: 'Simple testnet faucet for development',
				},
				{
					name: 'Bitcoin Cloud Testnet Faucet',
					url: 'https://faucet.testnet.bitcoincloud.net',
					description: 'Cloud-based testnet faucet service',
				},
			];

			return {
				success: true,
				message:
					'Use one of the faucets below to get testnet Bitcoin. Copy your address and visit the faucet website.',
				faucets,
			};
		} catch (error) {
			console.error('Error getting faucet info:', error);
			return {
				success: false,
				message: 'Failed to get faucet information.',
				faucets: [],
			};
		}
	}

	/**
	 * Get available faucet services
	 * @returns Array of available faucet URLs
	 */
	static getAvailableFaucets(): string[] {
		return BITCOIN_CONFIG.faucet.alternativeUrls;
	}
}
