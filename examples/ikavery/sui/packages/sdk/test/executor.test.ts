import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { describe, expect, test } from 'bun:test';

import { executorFromKeypair, sponsoredExecutor } from '../src/executor';

describe('executorFromKeypair', () => {
	test("address matches the keypair's Sui address", () => {
		const kp = new Ed25519Keypair();
		const exec = executorFromKeypair(kp, {} as never);
		expect(exec.address).toBe(kp.toSuiAddress());
	});
});

describe('sponsoredExecutor', () => {
	test('address resolves to the sender, not the sponsor', () => {
		// The whole point of sponsorship: `ctx.sender()` is the user even though
		// the sponsor pays gas. Flow code keys credential auth off the sender's
		// address, so executor.address must be the sender.
		const sender = new Ed25519Keypair();
		const sponsor = new Ed25519Keypair();
		const exec = sponsoredExecutor({ sender, sponsor, suiClient: {} as never });
		expect(exec.address).toBe(sender.toSuiAddress());
		expect(exec.address).not.toBe(sponsor.toSuiAddress());
	});
});

describe('executorFromKeypair signAndExecute', () => {
	test('forwards include={events,effects,objectTypes} to suiClient.core', async () => {
		let captured:
			| {
					transaction: unknown;
					signer: unknown;
					include: {
						events?: boolean;
						effects?: boolean;
						objectTypes?: boolean;
					};
			  }
			| undefined;
		const fakeClient = {
			core: {
				signAndExecuteTransaction: async (args: {
					transaction: unknown;
					signer: unknown;
					include: {
						events?: boolean;
						effects?: boolean;
						objectTypes?: boolean;
					};
				}) => {
					captured = args;
					return { digest: 'abc' } as never;
				},
			},
		} as never;
		const kp = new Ed25519Keypair();
		const exec = executorFromKeypair(kp, fakeClient);
		const fakeTx = { kind: 'fake-tx' } as never;
		const result = await exec.signAndExecute(fakeTx);
		expect((result as { digest: string }).digest).toBe('abc');
		expect(captured?.include).toEqual({
			events: true,
			effects: true,
			objectTypes: true,
		});
		expect(captured?.transaction).toBe(fakeTx);
		expect(captured?.signer).toBe(kp);
	});
});

describe('sponsoredExecutor signAndExecute', () => {
	test('sets sender + gas owner, dual-signs, and forwards bytes to executeTransaction', async () => {
		const sender = new Ed25519Keypair();
		const sponsor = new Ed25519Keypair();
		const buildBytes = new Uint8Array([1, 2, 3, 4]);
		const senderSetCalls: string[] = [];
		const gasOwnerCalls: string[] = [];
		let executeArgs: { transaction: Uint8Array; signatures: string[] } | undefined;
		const fakeTx = {
			setSenderIfNotSet: (addr: string) => senderSetCalls.push(addr),
			setGasOwner: (addr: string) => gasOwnerCalls.push(addr),
			build: async () => buildBytes,
		} as never;
		const fakeClient = {
			core: {
				executeTransaction: async (args: { transaction: Uint8Array; signatures: string[] }) => {
					executeArgs = args;
					return { digest: 'ok' } as never;
				},
			},
		} as never;

		const exec = sponsoredExecutor({ sender, sponsor, suiClient: fakeClient });
		const out = await exec.signAndExecute(fakeTx);
		expect((out as { digest: string }).digest).toBe('ok');
		expect(senderSetCalls).toEqual([sender.toSuiAddress()]);
		expect(gasOwnerCalls).toEqual([sponsor.toSuiAddress()]);
		expect(executeArgs?.transaction).toBe(buildBytes);
		expect(executeArgs?.signatures.length).toBe(2);
	});
});
