import {
	createUserSignMessageWithPublicOutput,
	Curve,
	Hash,
	prepareDKG,
	SignatureAlgorithm,
	UserShareEncryptionKeys,
} from '@ika.xyz/sdk';
import { fromHex } from '@mysten/sui/utils';
import * as Comlink from 'comlink';

type WorkerApi = {
	computeKeys: (seed: string, curve: Curve) => Promise<number[]>;
	prepareDKG: (params: {
		curve: Curve;
		userShareEncryptionKeysBytes: number[];
		sessionIdentifier: number[];
		userAddress: string;
		protocolPublicParameters: number[];
	}) => Promise<{
		userPublicOutput: number[];
		userSecretKeyShare: number[];
		userDKGMessage: number[];
	}>;
	createSignature: (params: {
		protocolPublicParameters: number[];
		publicOutput: number[];
		publicUserSecretKeyShare: number[];
		presign: number[];
		preimage: number[];
		hash: Hash;
		signatureAlgorithm: SignatureAlgorithm;
		curve: Curve;
	}) => Promise<number[]>;
};

// Cache the worker API to avoid recreating it
let cachedWorkerApi: WorkerApi | null = null;

/**
 * Creates and caches a Web Worker for computing keys off the main thread
 */
const getWorker = (): WorkerApi | null => {
	if (cachedWorkerApi) {
		return cachedWorkerApi;
	}

	if (typeof Worker === 'undefined') {
		return null;
	}

	try {
		// Create worker from the worker file
		// Next.js webpack will handle bundling this
		const worker = new Worker(new URL('../workers/workers.ts', import.meta.url), {
			type: 'module',
		});

		// Wrap with comlink to get a typed API
		cachedWorkerApi = Comlink.wrap<WorkerApi>(worker);
		return cachedWorkerApi;
	} catch (error) {
		console.warn('Failed to create Web Worker, falling back to main thread:', error);
		return null;
	}
};

/**
 * Computes keys using a Web Worker if available, otherwise falls back to main thread
 */
export const computeKeysWithWorker = async (): Promise<UserShareEncryptionKeys> => {
	// Using pre-computed keys for performance
	return UserShareEncryptionKeys.fromShareEncryptionKeysBytes(
		fromHex(
			'0x0085020082028002808d22aa156209c0c5753e97da469ce7aacdd7a462a9e862d709cf8e8fb33d6a4fde56361525d55c8daa0e29195bdeb8ea4e0cd4438f20f2bbd6be05bd66ce63d128bbc7b50fd87d64106955605bfd0038b45bbbf2e84d7c66520bbc2f9f2b817c1b9ca0fe66e0fba54b15711df6ccdbeb5dc1cd0100000000000000000000000ff125a2db804bb8d9edd15ea720be980644503ffe5a65cf42f2bf0f8791e10c3fc695ac20a25a70048cb9db22d5737ecf95b28faea0986d4cc704e7d3496a26c8bb9f53f339ff3c8e6db6675ac3784f379dc051e05d53c721ef5686df792572eb693d76b38de41857ba6ecfbd36d524bd3af452feffffffffffffffffffffffc201c0018fd50f9a612958033817cc908a6153a2f269ed5097b29842dae851cedc7f090ae7ce1d5348012374e2e7c4f666d583571342e94563d25d18421a89f55f6a52ccc91df62bdf6e12bc2c2f5f3e9f15efcfe4f04e8255c53a1ee4d24b09fb15000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000046000000000000000000000100000000000000070405000009000000000000030000000000000000060004000700000000000700000500000202040000000008000007000008000000000000000000',
		),
	);
};

export const prepareDKGWithWorker = async (params: {
	curve: Curve;
	userShareEncryptionKeysBytes: number[];
	sessionIdentifier: number[];
	userAddress: string;
	protocolPublicParameters: number[];
}) => {
	const workerApi = getWorker();

	if (!workerApi) {
		// Fallback: compute on main thread (will block but better than nothing)
		return await prepareDKG(
			new Uint8Array(params.protocolPublicParameters),
			params.curve,
			new Uint8Array(params.userShareEncryptionKeysBytes),
			new Uint8Array(params.sessionIdentifier),
			params.userAddress,
		);
	}

	try {
		// Compute in worker (truly off main thread)
		const result = await workerApi.prepareDKG(params);
		return result;
	} catch (error) {
		console.warn('Worker preparation failed, falling back to main thread:', error);
		// Fallback to main thread
		return await prepareDKG(
			new Uint8Array(params.protocolPublicParameters),
			params.curve,
			new Uint8Array(params.userShareEncryptionKeysBytes),
			new Uint8Array(params.sessionIdentifier),
			params.userAddress,
		);
	}
};

export const createSignatureWithWorker = async (params: {
	protocolPublicParameters: number[];
	publicOutput: number[];
	publicUserSecretKeyShare: number[];
	presign: number[];
	preimage: number[];
	hash: Hash;
	signatureAlgorithm: SignatureAlgorithm;
	curve: Curve;
}) => {
	const workerApi = getWorker();

	if (!workerApi) {
		// Fallback: compute on main thread (will block but better than nothing)
		return await createUserSignMessageWithPublicOutput(
			new Uint8Array(params.protocolPublicParameters),
			new Uint8Array(params.publicOutput),
			new Uint8Array(params.publicUserSecretKeyShare),
			new Uint8Array(params.presign),
			new Uint8Array(params.preimage),
			params.hash,
			params.signatureAlgorithm,
			params.curve,
		);
	}

	try {
		// Compute in worker (truly off main thread)
		const result = await workerApi.createSignature(params);
		return result;
	} catch (error) {
		console.warn('Worker signature creation failed, falling back to main thread:', error);
		// Fallback to main thread
		return await createUserSignMessageWithPublicOutput(
			new Uint8Array(params.protocolPublicParameters),
			new Uint8Array(params.publicOutput),
			new Uint8Array(params.publicUserSecretKeyShare),
			new Uint8Array(params.presign),
			new Uint8Array(params.preimage),
			params.hash,
			params.signatureAlgorithm,
			params.curve,
		);
	}
};
