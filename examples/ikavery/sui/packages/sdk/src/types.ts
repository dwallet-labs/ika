import type { IkaClient } from '@ika.xyz/sdk';
import type { ClientWithCoreApi } from '@mysten/sui/client';
import type { Keypair } from '@mysten/sui/cryptography';

/** Identifying info for the recovery instance and the package that owns it. */
export interface RecoveryRef {
	packageId: string;
	recoveryId: string; // shared object id
	/**
	 * Object id of the shared `recovery::registry::Registry` (created at publish
	 * time). Used by `create()` and `executeEnrollment()` to maintain the
	 * member -> recoveries discovery index.
	 */
	registryId: string;
}

/** RecoveryClient configuration. */
export interface RecoveryClientConfig {
	ikaClient: IkaClient;
	/** Sui RPC client used by flows that need to sign + execute PTBs. */
	suiClient: ClientWithCoreApi;
	ref: RecoveryRef;
	/** WebAuthn relying-party id, e.g. "recovery.example.com". */
	rpId: string;
	/**
	 * Gas signer for recovery::* PTBs. Defaults to a one-shot keypair the SDK
	 * funds via the configured sponsor (not implemented in this skeleton).
	 */
	gasSigner?: Keypair;
}
