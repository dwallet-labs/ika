'use client';

import { Button, Card } from '@fesal-packages/ikavery-frontend-ui';
import { AlertCircle, ArrowLeft, ArrowRight, Eye, EyeOff, Wand2 } from 'lucide-react';
import { useRouter } from 'next/navigation';
import * as React from 'react';

import { useSetup } from '@/store/setup';

import { FieldLabel, Mono, StepFooter, StepHeader } from '../_parts';

export default function KeyStep() {
	const router = useRouter();
	const importer = useSetup((s) => s.importer);
	const members = useSetup((s) => s.members);
	const value = useSetup((s) => s.solanaSecretInput);
	const setValue = useSetup((s) => s.setSolanaSecretInput);
	const [reveal, setReveal] = React.useState(false);

	React.useEffect(() => {
		if (!importer) router.replace('/setup/connect');
		else if (members.length === 0) router.replace('/setup/threshold');
	}, [importer, members, router]);

	const parsed = React.useMemo(() => parseSolanaSecret(value), [value]);

	function handlePaste() {
		void navigator.clipboard
			.readText()
			.then((t) => setValue(t.trim()))
			.catch(() => {
				/* clipboard denied */
			});
	}

	function handleGenerateDemo() {
		const bytes = crypto.getRandomValues(new Uint8Array(32));
		setValue(bytesToBase58(bytes));
	}

	function handleClear() {
		setValue('');
	}

	return (
		<>
			<StepHeader
				ord="03 / Key"
				title="Hand over"
				italic="the Solana key."
				hint="Paste a 32-byte ed25519 secret as base58, hex, or a 64-element JSON array (Solana CLI keypair format). The bytes never leave this browser tab. They are encrypted to your passkey and submitted directly to the Ika network."
			/>

			<Card tone="raised" className="p-6 sm:p-8">
				<FieldLabel
					required
					hint={parsed.ok ? `${parsed.bytes.length} bytes detected` : '32 or 64 bytes'}
				>
					Solana secret key
				</FieldLabel>
				<div className="relative">
					<textarea
						value={value}
						onChange={(e) => setValue(e.target.value)}
						placeholder="Paste base58, hex, or [1, 2, 3, …]"
						spellCheck={false}
						autoCorrect="off"
						autoCapitalize="off"
						rows={4}
						className={`w-full font-mono text-[13px] text-text bg-surface border border-border rounded-md p-4 resize-none focus:outline-none focus:border-clay/60 placeholder:text-text-4 ${
							reveal ? '' : '[-webkit-text-security:disc] [text-security:disc]'
						}`}
						style={
							{
								WebkitTextSecurity: reveal ? 'none' : 'disc',
							} as React.CSSProperties
						}
					/>
					<button
						type="button"
						onClick={() => setReveal((v) => !v)}
						className="absolute top-3 right-3 inline-flex items-center gap-1.5 smallcaps text-text-3 hover:text-text"
						aria-label={reveal ? 'Hide secret' : 'Reveal secret'}
					>
						{reveal ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
						{reveal ? 'Hide' : 'Reveal'}
					</button>
				</div>
				<div className="mt-4 flex flex-wrap items-center gap-2">
					<Button variant="secondary" size="sm" onClick={handlePaste}>
						Paste from clipboard
					</Button>
					<Button variant="ghost" size="sm" onClick={handleGenerateDemo}>
						<Wand2 className="h-3.5 w-3.5" /> Generate a demo key
					</Button>
					{value && (
						<Button variant="ghost" size="sm" onClick={handleClear}>
							Clear
						</Button>
					)}
				</div>

				{value && !parsed.ok && (
					<div className="mt-5 flex items-start gap-3 px-4 py-3 rounded-md border border-clay/40 bg-clay/[0.06]">
						<AlertCircle className="h-4 w-4 text-clay mt-0.5 flex-none" />
						<div className="text-[13px] leading-[1.55] text-text-2">
							<span className="text-clay">{parsed.error}</span>
							<span className="block text-text-3 mt-1">
								Need a key? Click {`"Generate a demo key"`} for a throwaway one. Ikavery only
								operates on Sui testnet and Solana devnet.
							</span>
						</div>
					</div>
				)}

				{parsed.ok && (
					<div className="mt-5 surface px-4 py-3">
						<div className="flex items-baseline justify-between mb-1">
							<span className="smallcaps text-text-3">Public key</span>
							<span className="smallcaps text-sage">Detected</span>
						</div>
						<Mono>{parsed.publicKey}</Mono>
					</div>
				)}
			</Card>

			<Card tone="vault" className="p-5 sm:p-6 mt-4">
				<div className="flex items-start gap-3 text-[13px] leading-[1.55] text-text-2">
					<AlertCircle className="h-4 w-4 text-clay mt-0.5 flex-none" />
					<p>
						Demo only. Use a fresh keypair generated specifically for this session. Use only with
						devnet SOL. Do not paste a key that holds real funds.
					</p>
				</div>
			</Card>

			<StepFooter
				hint="The key is held in memory only. It is wiped when this tab closes or after a successful import."
				back={
					<Button variant="ghost" size="default" onClick={() => router.push('/setup/threshold')}>
						<ArrowLeft className="h-3.5 w-3.5" /> Back
					</Button>
				}
				next={
					<Button
						variant="primary"
						size="lg"
						disabled={!parsed.ok}
						onClick={() => router.push('/setup/review')}
					>
						Review <ArrowRight className="h-4 w-4" />
					</Button>
				}
			/>
		</>
	);
}

interface ParseOk {
	ok: true;
	bytes: Uint8Array; // 32 or 64
	publicKey: string; // base58
}
interface ParseErr {
	ok: false;
	error: string;
}

function parseSolanaSecret(input: string): ParseOk | ParseErr {
	const trimmed = input.trim();
	if (!trimmed) return { ok: false, error: 'Empty input.' };

	// JSON array (Solana CLI keypair file)
	if (trimmed.startsWith('[')) {
		try {
			const arr = JSON.parse(trimmed) as number[];
			if (!Array.isArray(arr) || !arr.every((n) => typeof n === 'number' && n >= 0 && n <= 255)) {
				return {
					ok: false,
					error: 'JSON array must contain only 0-255 integers.',
				};
			}
			if (arr.length !== 32 && arr.length !== 64) {
				return {
					ok: false,
					error: `JSON array must be 32 or 64 bytes, got ${arr.length}.`,
				};
			}
			const bytes = new Uint8Array(arr);
			const pub = derivePublicKey(bytes);
			return { ok: true, bytes, publicKey: pub };
		} catch {
			return {
				ok: false,
				error: 'Invalid JSON. Use the Solana CLI keypair format.',
			};
		}
	}

	// Hex
	if (/^(0x)?[0-9a-fA-F]+$/.test(trimmed)) {
		const clean = trimmed.startsWith('0x') ? trimmed.slice(2) : trimmed;
		if (clean.length === 64 || clean.length === 128) {
			const bytes = new Uint8Array(clean.length / 2);
			for (let i = 0; i < bytes.length; i++) {
				bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
			}
			return { ok: true, bytes, publicKey: derivePublicKey(bytes) };
		}
		if (clean.length === 32 || clean.length === 64 || clean.length === 96) {
			// odd hex lengths fall through to base58 attempt
		}
	}

	// base58
	try {
		const bytes = base58Decode(trimmed);
		if (bytes.length !== 32 && bytes.length !== 64) {
			return {
				ok: false,
				error: `Decoded ${bytes.length} bytes; need 32 or 64.`,
			};
		}
		return { ok: true, bytes, publicKey: derivePublicKey(bytes) };
	} catch (e) {
		return {
			ok: false,
			error:
				e instanceof Error ? `Could not decode as base58: ${e.message}` : 'Could not decode input.',
		};
	}
}

/**
 * For a 64-byte expanded form, the last 32 bytes ARE the public key.
 * For a 32-byte seed, the public key would require an ed25519 derivation,
 * which we skip here, returning a placeholder so the UI can show "Detected"
 * without a heavy crypto dep on this page.
 */
function derivePublicKey(bytes: Uint8Array): string {
	if (bytes.length === 64) return bytesToBase58(bytes.slice(32));
	return '(seed only — public key derived at import)';
}

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function bytesToBase58(bytes: Uint8Array): string {
	let n = 0n;
	for (const b of bytes) n = (n << 8n) | BigInt(b);
	let out = '';
	while (n > 0n) {
		const r = Number(n % 58n);
		n = n / 58n;
		out = B58_ALPHABET[r] + out;
	}
	for (const b of bytes) {
		if (b !== 0) break;
		out = '1' + out;
	}
	return out;
}

function base58Decode(s: string): Uint8Array {
	let n = 0n;
	for (const ch of s) {
		const idx = B58_ALPHABET.indexOf(ch);
		if (idx < 0) throw new Error(`invalid character "${ch}"`);
		n = n * 58n + BigInt(idx);
	}
	const bytes: number[] = [];
	while (n > 0n) {
		bytes.unshift(Number(n & 0xffn));
		n = n >> 8n;
	}
	for (const ch of s) {
		if (ch !== '1') break;
		bytes.unshift(0);
	}
	return new Uint8Array(bytes);
}
