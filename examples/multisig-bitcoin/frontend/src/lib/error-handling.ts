import { toast } from 'sonner';

/**
 * Formats an error into a user-friendly message
 */
export function formatError(error: unknown): string {
	if (error instanceof Error) {
		// Handle specific error messages
		const message = error.message;

		// Wallet errors
		if (message.includes('User rejected')) {
			return 'Transaction was rejected';
		}
		if (message.includes('Insufficient funds')) {
			return 'Insufficient funds for this transaction';
		}
		if (message.includes('Network')) {
			return 'Network error. Please check your connection';
		}

		// Generic error
		return message;
	}

	if (typeof error === 'string') {
		return error;
	}

	return 'An unexpected error occurred';
}

/**
 * Shows a success toast notification
 */
export function showSuccessToast(message: string, description?: string) {
	toast.success(message, {
		description,
		duration: 4000,
	});
}

/**
 * Shows an error toast notification
 */
export function showErrorToast(error: unknown, fallbackMessage?: string) {
	const message = formatError(error);
	toast.error(fallbackMessage || 'Error', {
		description: message,
		duration: 5000,
	});
}

/**
 * Shows a loading toast notification
 */
export function showLoadingToast(message: string) {
	return toast.loading(message);
}

/**
 * Shows an info toast notification
 */
export function showInfoToast(message: string, description?: string) {
	toast.info(message, {
		description,
		duration: 4000,
	});
}

/**
 * Dismisses a toast by ID
 */
export function dismissToast(toastId: string | number) {
	toast.dismiss(toastId);
}
