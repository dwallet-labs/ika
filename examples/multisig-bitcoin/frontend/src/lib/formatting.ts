/**
 * Shortens an address or hash for display
 */
export function shorten(value: string, length: number = 6): string {
	if (!value) return '';
	if (value.length <= length * 2) return value;
	return `${value.slice(0, length)}…${value.slice(-length)}`;
}

/**
 * Formats a number with thousand separators
 */
export function formatNumber(value: string | number | bigint): string {
	return Number(value).toLocaleString();
}

/**
 * Formats satoshis with commas
 */
export function formatSats(sats: string | number | bigint): string {
	return `${formatNumber(sats)} sats`;
}

/**
 * Formats a duration in seconds to human-readable format
 * Shows up to 2 units (e.g., "7 days 5 hours", "2 hours 30 minutes")
 */
export function formatDuration(seconds: number): string {
	if (seconds === 0) {
		return '0 seconds';
	}

	const parts: string[] = [];

	const days = Math.floor(seconds / 86400);
	const hours = Math.floor((seconds % 86400) / 3600);
	const minutes = Math.floor((seconds % 3600) / 60);
	const secs = Math.floor(seconds % 60);

	if (days > 0) {
		parts.push(`${days} day${days !== 1 ? 's' : ''}`);
		if (hours > 0) {
			parts.push(`${hours} hour${hours !== 1 ? 's' : ''}`);
		}
	} else if (hours > 0) {
		parts.push(`${hours} hour${hours !== 1 ? 's' : ''}`);
		if (minutes > 0) {
			parts.push(`${minutes} minute${minutes !== 1 ? 's' : ''}`);
		}
	} else if (minutes > 0) {
		parts.push(`${minutes} minute${minutes !== 1 ? 's' : ''}`);
		if (secs > 0) {
			parts.push(`${secs} second${secs !== 1 ? 's' : ''}`);
		}
	} else {
		parts.push(`${secs} second${secs !== 1 ? 's' : ''}`);
	}

	return parts.slice(0, 2).join(' ');
}

/**
 * Validates a Bitcoin address format
 */
export function isValidBitcoinAddress(address: string): boolean {
	// Basic validation for Bitcoin addresses
	// Supports legacy (1...), P2SH (3...), and Bech32 (bc1... or tb1...)
	const legacyRegex = /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/;
	const bech32Regex = /^(bc1|tb1)[a-z0-9]{39,87}$/;

	return legacyRegex.test(address) || bech32Regex.test(address);
}

/**
 * Validates a Sui address format
 */
export function isValidSuiAddress(address: string): boolean {
	// Sui addresses are 0x followed by 64 hex characters
	return /^0x[a-fA-F0-9]{64}$/.test(address);
}
