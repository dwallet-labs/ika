// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Transaction builders for the OWS Policy Engine Move contract.
 *
 * Each function constructs a Move call as part of a Sui PTB.
 * The policy engine package ID must be provided in
 * {@link PolicyEngineConfig.packageId}.
 */

import { bcs } from '@mysten/sui/bcs';
import type { Transaction, TransactionObjectArgument } from '@mysten/sui/transactions';

/** Sui Clock shared object ID. */
export const SUI_CLOCK_OBJECT_ID = '0x6';

// ─── Engine Creation ─────────────────────────────────────────────────────

export function createWithDkgCap(
	packageId: string,
	dwalletCapId: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${packageId}::policy_engine::create_with_dkg_cap`,
		arguments: [tx.object(dwalletCapId)],
	});
}

export function createWithImportedKeyCap(
	packageId: string,
	importedKeyDwalletCapId: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${packageId}::policy_engine::create_with_imported_key_cap`,
		arguments: [tx.object(importedKeyDwalletCapId)],
	});
}

// ─── Admin: Access ──────────────────────────────────────────────────────

export function grantAccess(
	packageId: string,
	engineId: string,
	adminCapId: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${packageId}::policy_engine::grant_access`,
		arguments: [tx.object(engineId), tx.object(adminCapId)],
	});
}

export function revokeAccess(
	packageId: string,
	accessCapId: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${packageId}::policy_engine::revoke_access`,
		arguments: [tx.object(accessCapId)],
	});
}

// ─── Admin: Pause ───────────────────────────────────────────────────────

export function pause(
	packageId: string,
	engineId: string,
	adminCapId: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${packageId}::policy_engine::pause`,
		arguments: [tx.object(engineId), tx.object(adminCapId)],
	});
}

export function unpause(
	packageId: string,
	engineId: string,
	adminCapId: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${packageId}::policy_engine::unpause`,
		arguments: [tx.object(engineId), tx.object(adminCapId)],
	});
}

// ─── Admin: Rule Management ─────────────────────────────────────────────

export function addRateLimit(
	packageId: string,
	engineId: string,
	adminCapId: string,
	maxPerWindow: number | bigint,
	windowMs: number | bigint,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${packageId}::rate_limit::add`,
		arguments: [
			tx.object(engineId),
			tx.object(adminCapId),
			tx.pure.u64(maxPerWindow),
			tx.pure.u64(windowMs),
			tx.object(SUI_CLOCK_OBJECT_ID),
		],
	});
}

export function removeRateLimit(
	packageId: string,
	engineId: string,
	adminCapId: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${packageId}::rate_limit::remove`,
		arguments: [tx.object(engineId), tx.object(adminCapId)],
	});
}

export function addExpiry(
	packageId: string,
	engineId: string,
	adminCapId: string,
	expiryMs: number | bigint,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${packageId}::expiry::add`,
		arguments: [tx.object(engineId), tx.object(adminCapId), tx.pure.u64(expiryMs)],
	});
}

export function removeExpiry(
	packageId: string,
	engineId: string,
	adminCapId: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${packageId}::expiry::remove`,
		arguments: [tx.object(engineId), tx.object(adminCapId)],
	});
}

export function addSenderAllowlist(
	packageId: string,
	engineId: string,
	adminCapId: string,
	allowed: string[],
	tx: Transaction,
) {
	tx.moveCall({
		target: `${packageId}::sender_allowlist::add`,
		arguments: [
			tx.object(engineId),
			tx.object(adminCapId),
			tx.pure(bcs.vector(bcs.Address).serialize(allowed)),
		],
	});
}

export function removeSenderAllowlist(
	packageId: string,
	engineId: string,
	adminCapId: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${packageId}::sender_allowlist::remove`,
		arguments: [tx.object(engineId), tx.object(adminCapId)],
	});
}

export function addAllowedAlgorithms(
	packageId: string,
	engineId: string,
	adminCapId: string,
	pairs: Array<{ signatureAlgorithm: number; hashScheme: number }>,
	tx: Transaction,
) {
	// AllowedPair is a Move struct — we need to construct it via moveCall.
	// Pass as parallel vectors and construct pairs on-chain, or use individual add_pair calls.
	// For simplicity, add pairs one by one after registering with empty list isn't ideal.
	// The Move function takes vector<AllowedPair>. We need BCS for this.
	// AllowedPair { signature_algorithm: u32, hash_scheme: u32 }
	const pairsBcs = bcs.vector(
		bcs.struct('AllowedPair', { signature_algorithm: bcs.u32(), hash_scheme: bcs.u32() }),
	).serialize(pairs.map(p => ({
		signature_algorithm: p.signatureAlgorithm,
		hash_scheme: p.hashScheme,
	})));

	tx.moveCall({
		target: `${packageId}::allowed_algorithms::add`,
		arguments: [tx.object(engineId), tx.object(adminCapId), tx.pure(pairsBcs)],
	});
}

export function removeAllowedAlgorithms(
	packageId: string,
	engineId: string,
	adminCapId: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${packageId}::allowed_algorithms::remove`,
		arguments: [tx.object(engineId), tx.object(adminCapId)],
	});
}

export function addSpendingBudget(
	packageId: string,
	engineId: string,
	adminCapId: string,
	maxPerWindow: number | bigint,
	maxPerTx: number | bigint,
	windowMs: number | bigint,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${packageId}::spending_budget::add`,
		arguments: [
			tx.object(engineId),
			tx.object(adminCapId),
			tx.pure.u64(maxPerWindow),
			tx.pure.u64(maxPerTx),
			tx.pure.u64(windowMs),
			tx.object(SUI_CLOCK_OBJECT_ID),
		],
	});
}

export function removeSpendingBudget(
	packageId: string,
	engineId: string,
	adminCapId: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${packageId}::spending_budget::remove`,
		arguments: [tx.object(engineId), tx.object(adminCapId)],
	});
}

export function addTargetFilter(
	packageId: string,
	engineId: string,
	adminCapId: string,
	allowedTargets: Uint8Array[],
	blockedTargets: Uint8Array[],
	tx: Transaction,
) {
	const vecVecU8 = bcs.vector(bcs.vector(bcs.u8()));
	tx.moveCall({
		target: `${packageId}::target_filter::add`,
		arguments: [
			tx.object(engineId),
			tx.object(adminCapId),
			tx.pure(vecVecU8.serialize(allowedTargets)),
			tx.pure(vecVecU8.serialize(blockedTargets)),
		],
	});
}

export function removeTargetFilter(
	packageId: string,
	engineId: string,
	adminCapId: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${packageId}::target_filter::remove`,
		arguments: [tx.object(engineId), tx.object(adminCapId)],
	});
}

export function addTimeDelay(
	packageId: string,
	engineId: string,
	adminCapId: string,
	delayMs: number | bigint,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${packageId}::time_delay::add`,
		arguments: [
			tx.object(engineId),
			tx.object(adminCapId),
			tx.pure.u64(delayMs),
		],
	});
}

export function removeTimeDelay(
	packageId: string,
	engineId: string,
	adminCapId: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${packageId}::time_delay::remove`,
		arguments: [tx.object(engineId), tx.object(adminCapId)],
	});
}

// ─── Admin: Destroy ─────────────────────────────────────────────────────

export function destroyAndReclaimDkgCap(
	packageId: string,
	engineId: string,
	adminCapId: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${packageId}::policy_engine::destroy_and_reclaim_dkg_cap`,
		arguments: [tx.object(engineId), tx.object(adminCapId)],
	});
}

export function destroyAndReclaimImportedKeyCap(
	packageId: string,
	engineId: string,
	adminCapId: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${packageId}::policy_engine::destroy_and_reclaim_imported_key_cap`,
		arguments: [tx.object(engineId), tx.object(adminCapId)],
	});
}

// ─── Request Lifecycle ──────────────────────────────────────────────────

export function createRequest(
	packageId: string,
	engineId: string,
	accessCapId: string,
	signatureAlgorithm: number,
	hashScheme: number,
	message: Uint8Array,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${packageId}::policy_engine::create_request`,
		arguments: [
			tx.object(engineId),
			tx.object(accessCapId),
			tx.pure.u32(signatureAlgorithm),
			tx.pure.u32(hashScheme),
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
		],
	});
}

export function addReceipt(
	packageId: string,
	ruleModuleName: string,
	ruleTypeName: string,
	request: TransactionObjectArgument,
	receipt: TransactionObjectArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${packageId}::policy_engine::add_receipt`,
		typeArguments: [`${packageId}::${ruleModuleName}::${ruleTypeName}`],
		arguments: [request, receipt],
	});
}

export function confirmDkg(
	packageId: string,
	engineId: string,
	coordinatorId: string,
	request: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${packageId}::policy_engine::confirm_dkg`,
		arguments: [tx.object(engineId), tx.object(coordinatorId), request],
	});
}

export function confirmImportedKey(
	packageId: string,
	engineId: string,
	coordinatorId: string,
	request: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${packageId}::policy_engine::confirm_imported_key`,
		arguments: [tx.object(engineId), tx.object(coordinatorId), request],
	});
}

export function cancelRequest(
	packageId: string,
	request: TransactionObjectArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${packageId}::policy_engine::cancel`,
		arguments: [request],
	});
}

// ─── Rules: Enforce Functions ────────────────────────────────────────────

export function enforceRateLimit(
	packageId: string,
	engineId: string,
	request: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${packageId}::rate_limit::enforce`,
		arguments: [tx.object(engineId), request, tx.object(SUI_CLOCK_OBJECT_ID)],
	});
}

export function enforceExpiry(
	packageId: string,
	engineId: string,
	request: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${packageId}::expiry::enforce`,
		arguments: [tx.object(engineId), request, tx.object(SUI_CLOCK_OBJECT_ID)],
	});
}

export function enforceSenderAllowlist(
	packageId: string,
	engineId: string,
	request: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${packageId}::sender_allowlist::enforce`,
		arguments: [tx.object(engineId), request],
	});
}

export function enforceAllowedAlgorithms(
	packageId: string,
	engineId: string,
	request: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${packageId}::allowed_algorithms::enforce`,
		arguments: [tx.object(engineId), request],
	});
}

export function enforceSpendingBudget(
	packageId: string,
	engineId: string,
	request: TransactionObjectArgument,
	declaredValue: bigint | number,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${packageId}::spending_budget::enforce`,
		arguments: [
			tx.object(engineId),
			request,
			tx.pure.u64(declaredValue),
			tx.object(SUI_CLOCK_OBJECT_ID),
		],
	});
}

export function enforceTargetFilter(
	packageId: string,
	engineId: string,
	request: TransactionObjectArgument,
	declaredTarget: Uint8Array,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${packageId}::target_filter::enforce`,
		arguments: [
			tx.object(engineId),
			request,
			tx.pure(bcs.vector(bcs.u8()).serialize(declaredTarget)),
		],
	});
}

export function enforceTimeDelay(
	packageId: string,
	engineId: string,
	request: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${packageId}::time_delay::enforce`,
		arguments: [tx.object(engineId), request, tx.object(SUI_CLOCK_OBJECT_ID)],
	});
}

// ─── Time Delay: Commit ──────────────────────────────────────────────────

export function timeDelayCommit(
	packageId: string,
	engineId: string,
	accessCapId: string,
	messageHash: Uint8Array,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${packageId}::time_delay::commit`,
		arguments: [
			tx.object(engineId),
			tx.object(accessCapId),
			tx.pure(bcs.vector(bcs.u8()).serialize(messageHash)),
			tx.object(SUI_CLOCK_OBJECT_ID),
		],
	});
}
