'use client';

import type { DeriveCommand, DeriveEvent } from '@/workers/derive.worker';

export interface DerivedIdentity {
	/** Serialized `UserShareEncryptionKeys` ready to feed back into the SDK. */
	keysBytes: Uint8Array;
	/** Sui address that owns the derived encryption key. */
	encryptionAddress: string;
}

interface PendingJob {
	resolve: (r: DerivedIdentity) => void;
	reject: (e: Error) => void;
}

class DeriveBridge {
	private worker: Worker | null = null;
	private nextId = 1;
	private pending = new Map<number, PendingJob>();

	private ensureWorker(): Worker {
		if (this.worker) return this.worker;
		const worker = new Worker(new URL('../workers/derive.worker.ts', import.meta.url), {
			type: 'module',
			name: 'ika-derive',
		});
		worker.addEventListener('message', (e: MessageEvent<DeriveEvent>) => {
			const ev = e.data;
			const job = this.pending.get(ev.id);
			if (!job) return;
			this.pending.delete(ev.id);
			if (ev.type === 'result') {
				job.resolve({
					keysBytes: ev.keysBytes,
					encryptionAddress: ev.encryptionAddress,
				});
			} else {
				job.reject(new Error(ev.error));
			}
		});
		worker.addEventListener('error', (e) => {
			const err = new Error(e.message || 'derive worker crashed');
			for (const [id, job] of this.pending) {
				this.pending.delete(id);
				job.reject(err);
			}
		});
		this.worker = worker;
		return worker;
	}

	derive(seed: Uint8Array): Promise<DerivedIdentity> {
		const worker = this.ensureWorker();
		const id = this.nextId++;
		return new Promise<DerivedIdentity>((resolve, reject) => {
			this.pending.set(id, { resolve, reject });
			const cmd: DeriveCommand = { type: 'derive', id, seed };
			worker.postMessage(cmd);
		});
	}
}

const bridge = new DeriveBridge();

/**
 * Derive an Ika encryption identity from a 32-byte seed in a worker. Same
 * deterministic shape as the SDK's `deriveDeviceIdentity` — passing the same
 * seed always yields the same `keysBytes` + `encryptionAddress`.
 */
export function deriveIdentity(seed: Uint8Array): Promise<DerivedIdentity> {
	return bridge.derive(seed);
}
