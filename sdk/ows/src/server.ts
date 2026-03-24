// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * OWS REST API server — expose wallet operations over HTTP.
 *
 * Framework-agnostic: {@link handleRequest} processes a parsed request
 * and returns a response object. The standalone {@link startServer}
 * wraps it in a Node `http.Server` for quick deployment.
 *
 * ## Endpoints
 *
 * | Method | Path                        | Description                              |
 * |--------|-----------------------------|------------------------------------------|
 * | GET    | /wallets                    | List all wallets                         |
 * | GET    | /wallets/:id                | Get wallet details                       |
 * | POST   | /wallets                    | Create mnemonic wallet                   |
 * | POST   | /wallets/dkg                | Create DKG wallet                        |
 * | POST   | /wallets/import/mnemonic    | Import from mnemonic                     |
 * | POST   | /wallets/import/private-key | Import from private key                  |
 * | DELETE | /wallets/:id                | Delete wallet                            |
 * | POST   | /sign/transaction           | Sign a transaction (hex)                 |
 * | POST   | /sign/message               | Sign a message                           |
 * | POST   | /presigns/prefill           | Pre-create presigns                      |
 * | GET    | /presigns/available         | Check available presigns                 |
 * | POST   | /commit                     | Commit message hash (time_delay rule)    |
 * | GET    | /health                     | Health check                             |
 *
 * ## Authentication
 *
 * All endpoints (except `/health`) require a Bearer token in the
 * `Authorization` header. The token is set via `IkaOWSServerConfig.apiKey`.
 *
 * @packageDocumentation
 */

import * as http from 'node:http';

import type { IkaOWSProvider } from './provider.js';
import { OWSError } from './errors.js';
import { hexToBytes } from './crypto.js';

// ─── Types ───────────────────────────────────────────────────────────────

export interface IkaOWSServerConfig {
	/** The initialized provider instance. */
	provider: IkaOWSProvider;
	/** Bearer token for API authentication. */
	apiKey: string;
	/** Port to listen on (standalone server only). Default: 3420. */
	port?: number;
	/** Hostname to bind to. Default: '127.0.0.1'. */
	host?: string;
}

export interface OWSRequest {
	method: string;
	path: string;
	body: Record<string, unknown>;
	headers: Record<string, string | undefined>;
}

export interface OWSResponse {
	status: number;
	body: unknown;
}

// ─── Request Handler (framework-agnostic) ────────────────────────────────

/**
 * Handle an OWS REST request.
 *
 * This is the core routing + handler function. It's framework-agnostic:
 * parse your framework's request into an {@link OWSRequest}, call this,
 * and serialize the {@link OWSResponse} back.
 */
export async function handleRequest(
	provider: IkaOWSProvider,
	apiKey: string,
	req: OWSRequest,
): Promise<OWSResponse> {
	// Auth check (skip for health).
	if (req.path !== '/health') {
		const authHeader = req.headers['authorization'] ?? req.headers['Authorization'];
		if (!authHeader || authHeader !== `Bearer ${apiKey}`) {
			return { status: 401, body: { error: 'Unauthorized' } };
		}
	}

	try {
		return await route(provider, req);
	} catch (e) {
		if (e instanceof OWSError) {
			return { status: 400, body: { error: e.message, code: e.code } };
		}
		const message = e instanceof Error ? e.message : String(e);
		return { status: 500, body: { error: message } };
	}
}

// ─── Router ──────────────────────────────────────────────────────────────

async function route(provider: IkaOWSProvider, req: OWSRequest): Promise<OWSResponse> {
	const { method, path, body } = req;

	// Health.
	if (path === '/health' && method === 'GET') {
		return {
			status: 200,
			body: {
				status: 'ok',
				initialized: provider.isInitialized,
				address: provider.getSuiAddress(),
			},
		};
	}

	// ─── Wallets ──────────────────────────────────────────────────────

	if (path === '/wallets' && method === 'GET') {
		return { status: 200, body: provider.listWallets() };
	}

	if (path === '/wallets' && method === 'POST') {
		const wallet = await provider.createWallet(
			body.name as string,
			body.passphrase as string,
			{
				curve: body.curve as any,
				words: body.words as number | undefined,
				timeout: body.timeout as number | undefined,
			},
		);
		return { status: 201, body: wallet };
	}

	if (path === '/wallets/dkg' && method === 'POST') {
		const wallet = await provider.createDWallet(body.name as string, {
			curve: body.curve as any,
			timeout: body.timeout as number | undefined,
		});
		return { status: 201, body: wallet };
	}

	if (path === '/wallets/import/mnemonic' && method === 'POST') {
		const wallet = await provider.importWalletMnemonic(
			body.name as string,
			body.mnemonic as string,
			body.passphrase as string,
			{
				curve: body.curve as any,
				index: body.index as number | undefined,
				timeout: body.timeout as number | undefined,
			},
		);
		return { status: 201, body: wallet };
	}

	if (path === '/wallets/import/private-key' && method === 'POST') {
		const wallet = await provider.importWalletPrivateKey(
			body.name as string,
			body.privateKey as string,
			{
				curve: body.curve as any,
				timeout: body.timeout as number | undefined,
			},
		);
		return { status: 201, body: wallet };
	}

	// /wallets/:id
	const walletMatch = path.match(/^\/wallets\/(.+)$/);
	if (walletMatch) {
		const id = walletMatch[1]!;

		if (method === 'GET') {
			return { status: 200, body: provider.getWallet(id) };
		}

		if (method === 'DELETE') {
			provider.deleteWallet(id);
			return { status: 200, body: { deleted: id } };
		}
	}

	// ─── Signing ──────────────────────────────────────────────────────

	if (path === '/sign/transaction' && method === 'POST') {
		const result = await provider.signTransaction(
			body.wallet as string,
			body.chain as string,
			body.transaction as string,
			{
				hashOverride: body.hashOverride as any,
				signatureAlgorithmOverride: body.signatureAlgorithmOverride as any,
				timeout: body.timeout as number | undefined,
				interval: body.interval as number | undefined,
				declaredValue: body.declaredValue as bigint | number | undefined,
				declaredTarget: body.declaredTarget
					? hexToBytes(body.declaredTarget as string)
					: undefined,
			},
		);
		return { status: 200, body: result };
	}

	if (path === '/sign/message' && method === 'POST') {
		const result = await provider.signMessage(
			body.wallet as string,
			body.chain as string,
			body.message as string,
			(body.encoding as 'utf8' | 'hex') ?? 'utf8',
			{
				hashOverride: body.hashOverride as any,
				signatureAlgorithmOverride: body.signatureAlgorithmOverride as any,
				timeout: body.timeout as number | undefined,
				interval: body.interval as number | undefined,
				declaredValue: body.declaredValue as bigint | number | undefined,
				declaredTarget: body.declaredTarget
					? hexToBytes(body.declaredTarget as string)
					: undefined,
			},
		);
		return { status: 200, body: result };
	}

	// ─── Presigns ─────────────────────────────────────────────────────

	if (path === '/presigns/prefill' && method === 'POST') {
		const ids = await provider.prefillPresigns(
			body.wallet as string,
			body.signatureAlgorithm as any,
			body.count as number,
		);
		return { status: 200, body: { presignIds: ids, count: ids.length } };
	}

	if (path === '/presigns/available' && method === 'GET') {
		const wallet = (req.body.wallet ?? req.headers['x-wallet']) as string;
		const algo = (req.body.signatureAlgorithm ?? req.headers['x-algorithm'] ?? 'ECDSASecp256k1') as string;
		const count = provider.availablePresigns(wallet, algo as any);
		return { status: 200, body: { available: count } };
	}

	// ─── Time Delay Commit ────────────────────────────────────────────

	if (path === '/commit' && method === 'POST') {
		const messageHash = hexToBytes(body.messageHash as string);
		await provider.commitTimeDelay(messageHash);
		return { status: 200, body: { committed: true } };
	}

	return { status: 404, body: { error: 'Not found' } };
}

// ─── Standalone Server ───────────────────────────────────────────────────

/**
 * Start a standalone HTTP server exposing the OWS REST API.
 *
 * @returns The `http.Server` instance (already listening).
 *
 * @example
 * ```ts
 * const provider = new IkaOWSProvider({ ... });
 * await provider.initialize();
 *
 * const server = startServer({
 *   provider,
 *   apiKey: process.env.OWS_API_KEY!,
 *   port: 3420,
 * });
 * ```
 */
export function startServer(config: IkaOWSServerConfig): http.Server {
	const { provider, apiKey, port = 3420, host = '127.0.0.1' } = config;

	const server = http.createServer(async (req, res) => {
		const url = new URL(req.url ?? '/', `http://${req.headers.host}`);
		const bodyChunks: Buffer[] = [];

		req.on('data', (chunk: Buffer) => bodyChunks.push(chunk));
		req.on('end', async () => {
			let body: Record<string, unknown> = {};
			if (bodyChunks.length > 0) {
				try {
					body = JSON.parse(Buffer.concat(bodyChunks).toString('utf-8'));
				} catch {
					res.writeHead(400, { 'Content-Type': 'application/json' });
					res.end(JSON.stringify({ error: 'Invalid JSON body' }));
					return;
				}
			}

			const owsReq: OWSRequest = {
				method: req.method ?? 'GET',
				path: url.pathname,
				body,
				headers: req.headers as Record<string, string | undefined>,
			};

			const owsRes = await handleRequest(provider, apiKey, owsReq);

			res.writeHead(owsRes.status, { 'Content-Type': 'application/json' });
			res.end(JSON.stringify(owsRes.body, null, '\t'));
		});
	});

	server.listen(port, host, () => {
		console.log(`OWS server listening on http://${host}:${port}`);
	});

	return server;
}
