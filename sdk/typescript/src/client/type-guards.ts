import {
	Coordinator,
	CoordinatorInner,
	DWalletNetworkDecryptionKey,
	MoveDynamicField,
	MoveObject,
	StartDKGFirstRoundEvent,
	System,
	SystemInner,
} from './types';

/**
 * Type guard utilities for Move objects and Ika-specific types
 */

export function isCoordinatorInner(obj: any): obj is CoordinatorInner {
	return (
		obj?.fields?.value?.fields?.dwallet_network_encryption_keys !== undefined &&
		obj?.fields?.value?.fields?.current_epoch !== undefined
	);
}

export function isCoordinator(obj: any): obj is Coordinator {
	return obj?.fields?.package_id !== undefined && obj?.fields?.version !== undefined;
}

export function isSystem(obj: any): obj is System {
	return obj?.fields?.package_id !== undefined && obj?.fields?.version !== undefined;
}

export function isSystemInner(obj: any): obj is SystemInner {
	return (
		obj?.fields?.value?.fields?.validator_set?.fields?.validators?.fields?.id?.id !== undefined
	);
}

export function isDWalletNetworkDecryptionKey(obj: any): obj is DWalletNetworkDecryptionKey {
	return (
		obj?.fields?.network_dkg_public_output?.fields?.contents?.fields?.id?.id !== undefined &&
		obj?.fields?.network_dkg_public_output?.fields?.contents?.fields?.id?.id !== null
	);
}

export function isMoveObject<TFields>(obj: any): obj is MoveObject<TFields> {
	return obj?.fields !== undefined;
}

export function isMoveDynamicField(obj: any): obj is MoveDynamicField {
	return obj?.fields?.name !== undefined && obj?.fields?.value !== undefined;
}

export function isStartDKGFirstRoundEvent(obj: any): obj is StartDKGFirstRoundEvent {
	return (
		!!obj?.event_data?.dwallet_id &&
		!!obj?.session_identifier_preimage &&
		!!obj?.event_data?.dwallet_cap_id &&
		!!obj?.event_data?.dwallet_network_encryption_key_id
	);
}

/**
 * Validates that an object has the expected structure and throws a descriptive error if not
 */
export function validateObject<T>(
	obj: any,
	guard: (obj: any) => obj is T,
	objectType: string,
	objectId?: string,
): T {
	if (!guard(obj)) {
		const idInfo = objectId ? ` (ID: ${objectId})` : '';
		throw new Error(`Invalid ${objectType} object${idInfo}: Expected structure not found`);
	}
	return obj;
}
