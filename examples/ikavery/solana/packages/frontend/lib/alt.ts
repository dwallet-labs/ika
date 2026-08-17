'use client';

import type { Wallet } from '@dynamic-labs/sdk-react-core';
import { isSolanaWallet } from '@dynamic-labs/solana';
import { SYSVAR_INSTRUCTIONS_ID, SYSVAR_RENT_ID } from '@fesal-packages/ikavery-solana-sdk';
import {
	AddressLookupTableProgram,
	PublicKey,
	SystemProgram,
	TransactionMessage,
	VersionedTransaction,
	type AddressLookupTableAccount,
	type Connection,
} from '@solana/web3.js';

import { idbGet as get, idbSet as set } from '@/lib/idb';

/**
 * The ikavery `propose`/`approve`/`execute` ix data is large enough that
 * a v0 transaction without ALT compression overruns the 1232-byte
 * single-tx packet cap on devnet/mainnet. We create one ALT per recovery
 * (lazily, on the first sweep) and persist its address in IndexedDB so
 * subsequent approvers + executors don't re-pay the ~0.0014 SOL rent.
 */
const ALT_PREFIX = 'ikavery-solana:alt:';

function altKey(recovery: PublicKey): string {
	return ALT_PREFIX + recovery.toBase58();
}

export async function loadCachedAltAddress(recovery: PublicKey): Promise<PublicKey | null> {
	const v = await get<string>(altKey(recovery));
	if (!v) return null;
	try {
		return new PublicKey(v);
	} catch {
		return null;
	}
}

async function fetchAlt(
	connection: Connection,
	address: PublicKey,
): Promise<AddressLookupTableAccount | null> {
	const fetched = await connection.getAddressLookupTable(address);
	return fetched.value ?? null;
}

/**
 * Resolve an ALT for `recovery`. If a cached one exists and is still
 * fetchable on-chain, return it; otherwise create a fresh one signed by
 * the connected wallet.
 *
 * The ALT carries the three sysvars + system program every ikavery ix
 * touches plus the per-recovery static accounts (recovery PDA,
 * recoveryId nonce). Members that vary per ix (proposal PDA, member id
 * hash, approval PDA) intentionally stay outside — they're cheap and
 * change per call.
 */
export async function ensureAltForRecovery(params: {
	connection: Connection;
	primaryWallet: Wallet;
	payer: PublicKey;
	recovery: PublicKey;
	recoveryId: PublicKey;
	dwallet: PublicKey;
	dwalletAccount: PublicKey;
	cpiAuthority: PublicKey;
	coordinator: PublicKey;
	dwalletProgram: PublicKey;
}): Promise<AddressLookupTableAccount> {
	const {
		connection,
		primaryWallet,
		payer,
		recovery,
		recoveryId,
		dwallet,
		dwalletAccount,
		cpiAuthority,
		coordinator,
		dwalletProgram,
	} = params;

	const cached = await loadCachedAltAddress(recovery);
	if (cached) {
		const alt = await fetchAlt(connection, cached);
		if (alt) return alt;
	}

	if (!isSolanaWallet(primaryWallet)) {
		throw new Error("Connected wallet doesn't expose a Solana signer — reconnect via the widget.");
	}
	const signer = await primaryWallet.getSigner();

	const slot = await connection.getSlot('finalized');
	const [createIx, lookupTableAddress] = AddressLookupTableProgram.createLookupTable({
		authority: payer,
		payer,
		recentSlot: slot,
	});
	const extendIx = AddressLookupTableProgram.extendLookupTable({
		payer,
		authority: payer,
		lookupTable: lookupTableAddress,
		addresses: [
			SYSVAR_INSTRUCTIONS_ID,
			SYSVAR_RENT_ID,
			SystemProgram.programId,
			recovery,
			recoveryId,
			dwallet,
			dwalletAccount,
			cpiAuthority,
			coordinator,
			dwalletProgram,
		],
	});

	const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
	const message = new TransactionMessage({
		payerKey: payer,
		recentBlockhash: blockhash,
		instructions: [createIx, extendIx],
	}).compileToV0Message();
	const tx = new VersionedTransaction(message);
	const signed = await signer.signTransaction(tx);
	const sig = await connection.sendRawTransaction(signed.serialize(), {
		skipPreflight: false,
		preflightCommitment: 'confirmed',
	});
	await connection.confirmTransaction(
		{ signature: sig, blockhash, lastValidBlockHeight },
		'confirmed',
	);

	// ALT lookups settle a slot or two after creation; poll briefly.
	for (let attempt = 0; attempt < 10; attempt++) {
		await new Promise((r) => setTimeout(r, 500));
		const alt = await fetchAlt(connection, lookupTableAddress);
		if (alt) {
			await set(altKey(recovery), lookupTableAddress.toBase58());
			return alt;
		}
	}
	throw new Error(
		`ALT ${lookupTableAddress.toBase58()} did not become visible — Solana RPC may be lagging, retry`,
	);
}
