// Account decoders
export * from './codec/recovery';
export * from './codec/proposal';
export * from './codec/roster-change';
export * from './codec/enrollment';
export * from './codec/approvals';

// Constants + scheme tags
export * from './constants';

// Member-slot packing + auth-pubkey padding
export * from './credential';

// Member-based vault discovery (getProgramAccounts wrapper).
export * from './discovery';

// PDA derivation
export * from './pda';

// Instruction builders
export * from './ix';

// Passkey / WebAuthn auth — challenge derivation, secp256r1 precompile ix
// builder, and `navigator.credentials.get` driver. Browser-only consumers
// import from here; Node-side helpers (challenges) work in any environment.
export * as passkey from './passkey';

// High-level flow helpers (state readers + send-and-confirm wrappers)
export * from './flows/state';
export * from './flows/recover';
export * from './flows/roster-change';
export * from './flows/enrollment';

// Ika dWallet pre-alpha integration helpers (PDAs, transfer-authority ix).
// Keep these in their own namespace under `dwallet/` since they reference
// the upstream dWallet program, not ikavery itself.
export * as ikaDwallet from './dwallet';

// Sweep message helper
export {
	ATA_IX_CREATE_IDEMPOTENT,
	ATA_PROGRAM_ID,
	buildSweepMessage,
	closeSplAccount,
	createIdempotentAta,
	SPL_IX_CLOSE_ACCOUNT,
	SPL_IX_TRANSFER_CHECKED,
	TOKEN_2022_PROGRAM_ID,
	TOKEN_PROGRAM_ID,
	transferSol,
	transferSplTokenChecked,
	type BuildSweepMessageParams,
	type CloseSplAccountParams,
	type CreateIdempotentAtaParams,
	type SweepMessageV0,
	type TransferSplCheckedParams,
} from './sweep/message';
