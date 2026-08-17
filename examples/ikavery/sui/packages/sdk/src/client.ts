import type { IkaClient } from '@ika.xyz/sdk';
import { bcs } from '@mysten/sui/bcs';
import type { ClientWithCoreApi } from '@mysten/sui/client';
import type { Keypair } from '@mysten/sui/cryptography';
import { Transaction } from '@mysten/sui/transactions';

import * as moveAssertion from './generated/recovery/assertion';
import * as moveAuth from './generated/recovery/auth';
import * as moveRecovery from './generated/recovery/recovery';
import type { RecoveryClientConfig, RecoveryRef } from './types';

/**
 * Holds shared config (ika client, package + recovery id, rpId, gas signer)
 * and re-exposes the codegenned PTB builders bound to the configured package
 * id. High-level session methods are added in subsequent tasks.
 */
export class RecoveryClient {
	readonly ikaClient: IkaClient;
	readonly suiClient: ClientWithCoreApi;
	readonly ref: RecoveryRef;
	readonly rpId: string;
	readonly gasSigner?: Keypair;

	constructor(config: RecoveryClientConfig) {
		this.ikaClient = config.ikaClient;
		this.suiClient = config.suiClient;
		this.ref = config.ref;
		this.rpId = config.rpId;
		this.gasSigner = config.gasSigner;
	}

	get ikaCoinType(): string {
		return `${this.ikaClient.ikaConfig.packages.ikaPackage}::ika::IKA`;
	}

	/**
	 * PTB builders for `recovery::recovery`, with `package` defaulted to this
	 * client's deployed package id. Caller can still override per-call.
	 */
	get move() {
		const pkg = this.ref.packageId;
		return {
			newAssertion: (args: Parameters<typeof moveAssertion._new>[0]['arguments']) =>
				moveAssertion._new({ package: pkg, arguments: args }),
			ed25519Credential: (args: Parameters<typeof moveAuth.ed25519Credential>[0]['arguments']) =>
				moveAuth.ed25519Credential({ package: pkg, arguments: args }),
			secp256k1Credential: (
				args: Parameters<typeof moveAuth.secp256k1Credential>[0]['arguments'],
			) => moveAuth.secp256k1Credential({ package: pkg, arguments: args }),
			secp256r1Credential: (
				args: Parameters<typeof moveAuth.secp256r1Credential>[0]['arguments'],
			) => moveAuth.secp256r1Credential({ package: pkg, arguments: args }),
			webauthnCredential: (args: Parameters<typeof moveAuth.webauthnCredential>[0]['arguments']) =>
				moveAuth.webauthnCredential({ package: pkg, arguments: args }),
			senderCredential: () => moveAuth.senderCredential({ package: pkg }),
			newEd25519Member: (args: Parameters<typeof moveAuth.newEd25519Member>[0]['arguments']) =>
				moveAuth.newEd25519Member({ package: pkg, arguments: args }),
			newSecp256k1Member: (args: Parameters<typeof moveAuth.newSecp256k1Member>[0]['arguments']) =>
				moveAuth.newSecp256k1Member({ package: pkg, arguments: args }),
			newSecp256r1Member: (args: Parameters<typeof moveAuth.newSecp256r1Member>[0]['arguments']) =>
				moveAuth.newSecp256r1Member({ package: pkg, arguments: args }),
			newWebauthnMember: (args: Parameters<typeof moveAuth.newWebauthnMember>[0]['arguments']) =>
				moveAuth.newWebauthnMember({ package: pkg, arguments: args }),
			newSenderMember: (args: Parameters<typeof moveAuth.newSenderMember>[0]['arguments']) =>
				moveAuth.newSenderMember({ package: pkg, arguments: args }),
			create: (args: Parameters<typeof moveRecovery.create>[0]['arguments']) =>
				moveRecovery.create({ package: pkg, arguments: args }),
			replenishPresigns: (
				args: Parameters<typeof moveRecovery.replenishPresigns>[0]['arguments'],
			) => moveRecovery.replenishPresigns({ package: pkg, arguments: args }),
			propose: (args: Parameters<typeof moveRecovery.propose>[0]['arguments']) =>
				moveRecovery.propose({ package: pkg, arguments: args }),
			approve: (args: Parameters<typeof moveRecovery.approve>[0]['arguments']) =>
				moveRecovery.approve({ package: pkg, arguments: args }),
			execute: (args: Parameters<typeof moveRecovery.execute>[0]['arguments']) =>
				moveRecovery.execute({ package: pkg, arguments: args }),
			proposeEnrollment: (
				args: Parameters<typeof moveRecovery.proposeEnrollment>[0]['arguments'],
			) => moveRecovery.proposeEnrollment({ package: pkg, arguments: args }),
			approveEnrollment: (
				args: Parameters<typeof moveRecovery.approveEnrollment>[0]['arguments'],
			) => moveRecovery.approveEnrollment({ package: pkg, arguments: args }),
			executeEnrollment: (
				args: Parameters<typeof moveRecovery.executeEnrollment>[0]['arguments'],
			) => moveRecovery.executeEnrollment({ package: pkg, arguments: args }),
			executeEnrollmentApproverOnly: (
				args: Parameters<typeof moveRecovery.executeEnrollmentApproverOnly>[0]['arguments'],
			) =>
				moveRecovery.executeEnrollmentApproverOnly({
					package: pkg,
					arguments: args,
				}),
			proposeRosterChange: (
				args: Parameters<typeof moveRecovery.proposeRosterChange>[0]['arguments'],
			) => moveRecovery.proposeRosterChange({ package: pkg, arguments: args }),
			approveRosterChange: (
				args: Parameters<typeof moveRecovery.approveRosterChange>[0]['arguments'],
			) => moveRecovery.approveRosterChange({ package: pkg, arguments: args }),
			executeRosterChange: (
				args: Parameters<typeof moveRecovery.executeRosterChange>[0]['arguments'],
			) => moveRecovery.executeRosterChange({ package: pkg, arguments: args }),
		};
	}

	/**
	 * Discovery: list every recovery the given member id belongs to. The id is
	 * the canonical bytes used by the contract — 32 bytes for an address (use
	 * the raw address bytes, no 0x prefix), 33 bytes for a passkey (compressed
	 * secp256r1 public key).
	 *
	 * Implemented as a `simulateTransaction` against `registry::list_for_member`
	 * — read-only, no gas, no signer needed.
	 */
	async listRecoveriesForMember(memberId: Uint8Array): Promise<string[]> {
		const tx = new Transaction();
		// simulateTransaction needs *some* sender, even though we never execute.
		tx.setSender('0x0000000000000000000000000000000000000000000000000000000000000000');
		tx.moveCall({
			target: `${this.ref.packageId}::registry::list_for_member`,
			arguments: [tx.object(this.ref.registryId), tx.pure.vector('u8', Array.from(memberId))],
		});
		const r = await this.suiClient.core.simulateTransaction({
			transaction: tx,
			include: { commandResults: true },
		});
		if (r.$kind !== 'Transaction') {
			throw new Error(`listRecoveriesForMember: ${JSON.stringify(r.FailedTransaction.status)}`);
		}
		const ret = r.commandResults?.[0]?.returnValues?.[0];
		if (!ret) return [];
		return bcs.vector(bcs.Address).parse(ret.bcs);
	}
}
