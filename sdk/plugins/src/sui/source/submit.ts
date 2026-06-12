// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Non-custodial submit helpers. The high-level `ika.sui.createDWallet` and
 * `ika.sui.requestSign` orchestrate everything end to end and require a USEK
 * on the source. These helpers cover the OTHER side: an orchestrator that
 * receives precomputed user payloads (from a browser, a hardware wallet,
 * another service) and just needs to wire the corresponding Move calls into
 * an in-flight `IkaTransaction`. No USEK is touched.
 *
 * Use these inside `ika.sui.transaction(...)` so fee allocation and execution
 * are handled by the plugin envelope; the parsed dWallet / sign ids come out
 * of the resulting `exec.events`.
 */

import type {
	Curve,
	Hash,
	IkaConfig,
	IkaTransaction,
	Presign,
	SignatureAlgorithm,
} from '@ika.xyz/sdk';
import {
	coordinatorTransactions,
	fromCurveToNumber,
	validateCurveSignatureAlgorithm,
	validateHashSignatureCombination,
} from '@ika.xyz/sdk';
import type { Transaction, TransactionObjectArgument } from '@mysten/sui/transactions';

export interface SubmitDKGArgs {
	readonly ikaConfig: IkaConfig;
	readonly ikaTx: IkaTransaction;
	readonly tx: Transaction;
	readonly curve: Curve;
	readonly networkEncryptionKeyId: string;
	/** Precomputed by the user's frontend via `prepareDKG`. */
	readonly userDKGMessage: Uint8Array;
	/** Precomputed by the user's frontend; ciphertext for the network. */
	readonly encryptedUserShareAndProof: Uint8Array;
	/** Precomputed by the user's frontend; centralized DKG public output. */
	readonly userPublicOutput: Uint8Array;
	/** Sui address of the USEK that will hold the encrypted share. */
	readonly encryptionKeyAddress: string;
	/** User's signing pubkey (ed25519, used to authenticate the encryption-key registration). */
	readonly signerPublicKey: Uint8Array;
	/** Session identifier handle from `ikaTx.registerSessionIdentifier(bytes)`. */
	readonly sessionIdentifier: TransactionObjectArgument;
	readonly ikaCoin: TransactionObjectArgument;
	readonly suiCoin: TransactionObjectArgument;
	/**
	 * If set, the helper also emits the `registerEncryptionKey` Move call
	 * before the DKG request. Use this for first-time submitters; skip it
	 * (omit the field) when the encryption key is already registered to
	 * avoid the `dynamic_field::add` abort.
	 */
	readonly registerEncryptionKey?: {
		readonly encryptionKey: Uint8Array;
		readonly encryptionKeySignature: Uint8Array;
	};
}

/**
 * Submit a DKG request from precomputed user payloads. Returns the
 * `dWalletCap` `TransactionObjectArgument` so the caller can transfer it to
 * whichever holder owns the dWallet (typically `tx.transferObjects([cap],
 * recipient)`).
 */
export function submitDKG(args: SubmitDKGArgs): TransactionObjectArgument {
	const { ikaConfig } = args;
	const coordRef = args.tx.object(ikaConfig.objects.ikaDWalletCoordinator.objectID);

	if (args.registerEncryptionKey) {
		coordinatorTransactions.registerEncryptionKeyTx(
			ikaConfig,
			coordRef,
			fromCurveToNumber(args.curve),
			args.registerEncryptionKey.encryptionKey,
			args.registerEncryptionKey.encryptionKeySignature,
			args.signerPublicKey,
			args.tx,
		);
	}

	const [dWalletCap] = coordinatorTransactions.requestDWalletDKG(
		ikaConfig,
		coordRef,
		args.networkEncryptionKeyId,
		fromCurveToNumber(args.curve),
		args.userDKGMessage,
		args.encryptedUserShareAndProof,
		args.encryptionKeyAddress,
		args.userPublicOutput,
		args.signerPublicKey,
		args.sessionIdentifier,
		null,
		args.ikaCoin,
		args.suiCoin,
		args.tx,
	);
	return dWalletCap;
}

export interface SubmitSignArgs {
	readonly ikaConfig: IkaConfig;
	readonly ikaTx: IkaTransaction;
	readonly tx: Transaction;
	readonly dWalletId: string;
	readonly dWalletCapId: string;
	readonly encryptedUserSecretKeyShareId: string;
	/** Caller-supplied; produced by `userShareEncryptionKeys.getUserOutputSignature` on the user device. */
	readonly userOutputSignature: Uint8Array;
	readonly presign: Presign;
	readonly message: Uint8Array;
	/** Caller-supplied; produced by `createUserSignMessageWithPublicOutput` on the user device. */
	readonly userSignMessage: Uint8Array;
	readonly curve: Curve;
	readonly signatureAlgorithm: SignatureAlgorithm;
	readonly hash: Hash;
	readonly ikaCoin: TransactionObjectArgument;
	readonly suiCoin: TransactionObjectArgument;
}

/**
 * Submit a sign request from a precomputed user payload. Emits three Move
 * calls in order: `acceptEncryptedUserShare` (transitions the dWallet from
 * `AwaitingKeyHolderSignature` to `Active`), `verifyPresignCap` + `approveMessage`
 * (through the in-flight `ikaTx`, no USEK), and `requestSign` (with the
 * precomputed `userSignMessage`).
 *
 * The resulting `sign_id` lives in the `SignRequestEvent` of the executed
 * transaction; parse it from `exec.events` with the BCS helpers in
 * `@ika.xyz/sdk`.
 */
export function submitSign(args: SubmitSignArgs): void {
	validateCurveSignatureAlgorithm(args.curve, args.signatureAlgorithm);
	validateHashSignatureCombination(args.hash, args.signatureAlgorithm);

	const { ikaConfig } = args;
	const coordRef = args.tx.object(ikaConfig.objects.ikaDWalletCoordinator.objectID);

	coordinatorTransactions.acceptEncryptedUserShare(
		ikaConfig,
		coordRef,
		args.dWalletId,
		args.encryptedUserSecretKeyShareId,
		args.userOutputSignature,
		args.tx,
	);

	const verifiedPresignCap = args.ikaTx.verifyPresignCap({ presign: args.presign });
	const messageApproval = args.ikaTx.approveMessage({
		dWalletCap: args.dWalletCapId,
		curve: args.curve,
		// `approveMessage` types `signatureAlgorithm` per-curve; the validate
		// call above already enforces the combination, so the cast is safe.
		signatureAlgorithm: args.signatureAlgorithm as never,
		hashScheme: args.hash as never,
		message: args.message,
	});

	coordinatorTransactions.requestSign(
		ikaConfig,
		coordRef,
		verifiedPresignCap,
		messageApproval,
		args.userSignMessage,
		args.ikaTx.createSessionIdentifier(),
		args.ikaCoin,
		args.suiCoin,
		args.tx,
	);
}
