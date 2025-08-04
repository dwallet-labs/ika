/**
 * Custom error types for Ika Client operations
 */

export class IkaClientError extends Error {
	constructor(
		message: string,
		public readonly cause?: Error,
	) {
		super(message);
		this.name = 'IkaClientError';
	}
}

export class ObjectNotFoundError extends IkaClientError {
	constructor(objectType: string, objectId?: string, cause?: Error) {
		const idInfo = objectId ? ` with ID ${objectId}` : '';
		super(`${objectType} object${idInfo} not found`, cause);
		this.name = 'ObjectNotFoundError';
	}
}

export class InvalidObjectError extends IkaClientError {
	constructor(objectType: string, objectId?: string, cause?: Error) {
		const idInfo = objectId ? ` (ID: ${objectId})` : '';
		super(`Invalid ${objectType} object${idInfo}: Expected structure not found`, cause);
		this.name = 'InvalidObjectError';
	}
}

export class CacheError extends IkaClientError {
	constructor(message: string, cause?: Error) {
		super(`Cache error: ${message}`, cause);
		this.name = 'CacheError';
	}
}

export class NetworkError extends IkaClientError {
	constructor(message: string, cause?: Error) {
		super(`Network error: ${message}`, cause);
		this.name = 'NetworkError';
	}
}
