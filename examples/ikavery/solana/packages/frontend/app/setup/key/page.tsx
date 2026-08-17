'use client';

import { Button, Card } from '@fesal-packages/ikavery-frontend-ui';
import { AlertCircle, ArrowLeft, ArrowRight, Eye, EyeOff, Loader2, Wand2 } from 'lucide-react';
import { useRouter } from 'next/navigation';
import * as React from 'react';

import { generateDemoSecret, parseSolanaSecret } from '@/lib/parse-secret';
import { useSetup } from '@/store/setup';

import { FieldLabel, Mono, StepFooter, StepHeader } from '../_parts';

export default function KeyStep() {
	const router = useRouter();
	const importer = useSetup((s) => s.importer);
	const members = useSetup((s) => s.members);
	const value = useSetup((s) => s.solanaSecretInput);
	const setValue = useSetup((s) => s.setSolanaSecretInput);
	const [reveal, setReveal] = React.useState(false);
	const [generating, setGenerating] = React.useState(false);

	React.useEffect(() => {
		if (!importer) router.replace('/setup/connect');
		else if (members.length === 0) router.replace('/setup/threshold');
	}, [importer, members, router]);

	const parsed = React.useMemo(() => parseSolanaSecret(value), [value]);

	async function handlePaste() {
		try {
			const t = await navigator.clipboard.readText();
			setValue(t.trim());
		} catch {
			/* clipboard denied */
		}
	}

	async function handleGenerateDemo() {
		setGenerating(true);
		try {
			const expanded = await generateDemoSecret();
			setValue(expanded);
		} finally {
			setGenerating(false);
		}
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
				hint="Paste a 32-byte ed25519 seed or the 64-byte expanded form (Phantom export). Accepts base58, hex, or the Solana CLI JSON keypair format. The bytes never leave this browser tab — the dKG ceremony posts a signed import to Ika's mock signer; the secret is wiped after."
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
					<Button variant="ghost" size="sm" onClick={handleGenerateDemo} disabled={generating}>
						{generating ? (
							<Loader2 className="h-3.5 w-3.5 animate-spin" />
						) : (
							<Wand2 className="h-3.5 w-3.5" />
						)}
						Generate a demo key
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
								Need a key? Click {`"Generate a demo key"`} for a throwaway one. Ikavery on Solana
								operates on devnet only.
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
						Demo only. Use a fresh keypair generated specifically for this session, funded with
						devnet SOL only. Do not paste a key that holds real funds — Ika&apos;s pre-alpha mock
						signer resets without warning.
					</p>
				</div>
			</Card>

			<StepFooter
				hint="The key is held in memory only. It's wiped when this tab closes or after a successful import."
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
