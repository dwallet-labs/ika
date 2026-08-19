import type { ClientWithCoreApi, SuiClientTypes } from '@mysten/sui/client';
import type { Keypair } from '@mysten/sui/cryptography';
import type { Transaction } from '@mysten/sui/transactions';

/**
 * Result of a successful transaction execution. Mirrors the shape returned
 * by `suiClient.core.signAndExecuteTransaction({include: { events, effects, objectTypes }})`,
 * because that's what the SDK's flow code consumes.
 */
export type TransactionExecuteResult = SuiClientTypes.TransactionResult<{
	events: true;
	effects: true;
	objectTypes: true;
}>;

/**
 * Abstraction over "sign and execute a transaction". Both a CLI Keypair and
 * a browser wallet adapter can implement this — the SDK's flow code only
 * cares about the address and the signAndExecute method.
 *
 * Use {@link executorFromKeypair} to wrap a Keypair (CLI scripts), or
 * implement this interface yourself for wallet-adapter integrations
 * (browser, Slush, dApp Kit).
 */
export interface TransactionExecutor {
	/** Sui address that will appear as `ctx.sender()` and pay gas. */
	address: string;
	/** Sign and execute the transaction. */
	signAndExecute(transaction: Transaction): Promise<TransactionExecuteResult>;
}

/**
 * Wrap a Keypair into a TransactionExecutor. Used by CLI scripts that hold
 * the signing key directly.
 */
export function executorFromKeypair(
	keypair: Keypair,
	suiClient: ClientWithCoreApi,
): TransactionExecutor {
	return {
		address: keypair.toSuiAddress(),
		signAndExecute: (transaction) =>
			suiClient.core.signAndExecuteTransaction({
				transaction,
				signer: keypair,
				include: { events: true, effects: true, objectTypes: true },
			}),
	};
}

export interface SponsoredExecutorOptions {
	/** The user — `ctx.sender()` in Move; what credential auth checks against. */
	sender: Keypair;
	/** The gas payer — pays SUI for the transaction. */
	sponsor: Keypair;
	suiClient: ClientWithCoreApi;
}

/**
 * Sponsored-gas executor: the sender authorizes the transaction (their
 * address is what `ctx.sender()` resolves to and what credential auth checks
 * against), while a separate sponsor account pays gas. Both keypairs sign
 * the same transaction bytes and the resulting signatures are submitted as
 * a multi-sig pair.
 *
 * The executor's `address` is the sender's, so flow code that compares
 * `executor.address` against on-chain member lists keeps working unchanged.
 */
export function sponsoredExecutor(opts: SponsoredExecutorOptions): TransactionExecutor {
	const { sender, sponsor, suiClient } = opts;
	const senderAddr = sender.toSuiAddress();
	const sponsorAddr = sponsor.toSuiAddress();
	return {
		address: senderAddr,
		signAndExecute: async (transaction) => {
			transaction.setSenderIfNotSet(senderAddr);
			transaction.setGasOwner(sponsorAddr);
			const bytes = await transaction.build({ client: suiClient });
			const [senderSig, sponsorSig] = await Promise.all([
				sender.signTransaction(bytes),
				sponsor.signTransaction(bytes),
			]);
			return suiClient.core.executeTransaction({
				transaction: bytes,
				signatures: [senderSig.signature, sponsorSig.signature],
				include: { events: true, effects: true, objectTypes: true },
			});
		},
	};
}
