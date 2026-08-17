import {
	Button,
	CountUp,
	CursorSpotlight,
	Reveal,
	Shell,
	ShellFooter,
	Tile,
	TileEyebrow,
	VaultDial,
} from '@fesal-packages/ikavery-frontend-ui';
import {
	ArrowUpRight,
	Ban,
	CheckCircle2,
	Code2,
	KeyRound,
	Quote,
	Shield,
	Timer,
} from 'lucide-react';

import { AppDisclaimerModal } from '@/components/app-disclaimer-modal';
import { AppShellHeader } from '@/components/app-shell-header';

export default function LandingPage() {
	return (
		<Shell>
			<AppDisclaimerModal />
			<CursorSpotlight />
			<AppShellHeader />

			{/* HERO. Vault dial as the centerpiece, copy on the side. */}
			<section className="relative mx-auto max-w-[1280px] px-4 sm:px-6 lg:px-10 pt-10 sm:pt-14 lg:pt-20 pb-20 sm:pb-28 lg:pb-32">
				<div className="grid grid-cols-12 gap-6 lg:gap-8 items-center">
					<div className="col-span-12 lg:col-span-5 lg:order-2 flex justify-center">
						<Reveal delay={0.6}>
							<VaultDial initialThreshold={3} count={5} />
						</Reveal>
					</div>

					<div className="col-span-12 lg:col-span-7 lg:order-1">
						<Reveal delay={0}>
							<span className="smallcaps text-clay">Proof of concept · Tap any device</span>
						</Reveal>
						<Reveal delay={0.08} y={20}>
							<h1 className="mt-4 sm:mt-5 font-display text-[44px] sm:text-[64px] md:text-[88px] lg:text-[112px] leading-[0.94] tracking-[-0.035em] text-text">
								Three taps,
								<br />
								<span className="italic text-text-2">your key is back.</span>
							</h1>
						</Reveal>
						<Reveal delay={0.22}>
							<p className="mt-6 sm:mt-7 max-w-[480px] text-[15px] sm:text-[17px] leading-[1.6] text-text-2">
								A demo of one approach to passkey-gated key custody. Splits a private key across the
								devices you already carry, lets any quorum sign on demand. Supports both{' '}
								<span className="text-text">Sui</span> and <span className="text-text">Solana</span>
								, runs on <span className="text-text">Ika 2PC-MPC</span>, gated by{' '}
								<span className="text-text">WebAuthn passkeys</span>. The purpose is to show, not to
								ship.
							</p>
						</Reveal>
						<Reveal delay={0.34}>
							<div className="mt-7 sm:mt-9 flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
								<Button size="lg" variant="primary" asChild>
									<a href="/setup/connect">
										Build a vault
										<ArrowUpRight className="h-4 w-4" strokeWidth={2.4} />
									</a>
								</Button>
								<Button size="lg" variant="secondary" asChild>
									<a href="/vault">I have a vault</a>
								</Button>
							</div>
						</Reveal>
					</div>
				</div>
			</section>

			{/* BENTO. Mixed sizes, mixed tones. */}
			<section className="relative mx-auto max-w-[1280px] px-4 sm:px-6 lg:px-10 pb-20 sm:pb-28 lg:pb-32">
				<div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 lg:auto-rows-[180px] gap-3">
					{/* Quote tile, full-width banner-style */}
					<Tile span={{ col: 3, row: 1 }} tone="raised" className="sm:col-span-2 lg:col-span-3">
						<div className="flex items-start gap-3 sm:gap-4">
							<Quote className="h-6 w-6 sm:h-7 sm:w-7 text-clay flex-none mt-1" strokeWidth={1.4} />
							<p className="font-display italic text-[22px] sm:text-[28px] lg:text-[36px] leading-[1.2] sm:leading-[1.15] tracking-[-0.02em] text-text-2">
								A vault should not depend on a single fragile thing. Not a seed phrase, not a phone,
								not a memory.{' '}
								<span className="text-text not-italic font-display">
									It should depend on a quorum.
								</span>
							</p>
						</div>
					</Tile>

					{/* Speed counter */}
					<Tile className="flex flex-col justify-between">
						<div className="flex items-center justify-between">
							<TileEyebrow>Recovery time</TileEyebrow>
							<Timer className="h-4 w-4 text-text-3" />
						</div>
						<div>
							<div className="font-display text-[64px] leading-none tabular text-text">
								<CountUp value={30} suffix="s" />
							</div>
							<p className="mt-2 text-[12.5px] text-text-3">
								From propose to broadcast, on a normal connection.
							</p>
						</div>
					</Tile>

					{/* Code snippet, two-row */}
					<Tile
						span={{ col: 2, row: 2 }}
						tone="raised"
						className="p-0 overflow-hidden flex flex-col"
					>
						<div className="flex items-center justify-between px-6 pt-5 pb-3 border-b border-border bg-surface-3/30">
							<div className="flex items-center gap-2">
								<Code2 className="h-3.5 w-3.5 text-text-3" />
								<TileEyebrow>ikavery.import.ts</TileEyebrow>
							</div>
							<span className="smallcaps text-text-3">5 lines</span>
						</div>
						<pre className="flex-1 px-6 py-5 font-mono text-[13px] leading-[1.7] tabular text-text-2 overflow-x-auto">
							<code>
								{`import { importSolanaKey } from "@fesal-packages/ikavery-sui-sdk";

const vault = await importSolanaKey({
  key: solanaSecret,
  passkey: await registerPasskey(),
  threshold: { k: 3, of: 5 },
});`}
							</code>
						</pre>
						<div className="flex items-center justify-between px-6 py-3 border-t border-border bg-surface-3/30">
							<span className="smallcaps text-sage flex items-center gap-1.5">
								<CheckCircle2 className="h-3 w-3" /> Returns vault.id
							</span>
							<code className="font-mono text-[11.5px] text-clay">0x91938c…1f142</code>
						</div>
					</Tile>

					{/* Threshold mini-explainer */}
					<Tile className="flex flex-col justify-between">
						<div className="flex items-center justify-between">
							<TileEyebrow>Threshold</TileEyebrow>
							<KeyRound className="h-4 w-4 text-text-3" />
						</div>
						<div>
							<div className="font-display text-[40px] leading-none tabular text-text">
								k <span className="text-text-3">of</span> N
							</div>
							<p className="mt-2 text-[12.5px] text-text-3">
								You set both numbers. Most pick 3 of 5.
							</p>
						</div>
					</Tile>

					{/* What you skip */}
					<Tile className="flex flex-col justify-between">
						<div className="flex items-center justify-between">
							<TileEyebrow>You skip</TileEyebrow>
							<Ban className="h-4 w-4 text-text-3" />
						</div>
						<div>
							<ul className="space-y-0.5 text-[14px]">
								<SkipItem>Losing your private key</SkipItem>
								<SkipItem>Storing your private key</SkipItem>
								<SkipItem>Trusting a custodian</SkipItem>
							</ul>
						</div>
					</Tile>

					{/* Trust model, two-col */}
					<Tile span={{ col: 2 }}>
						<div className="flex items-center justify-between mb-3">
							<TileEyebrow>Trust assumptions</TileEyebrow>
							<Shield className="h-4 w-4 text-text-3" />
						</div>
						<div className="font-display text-[32px] leading-[1.05] tracking-[-0.02em] text-text">
							<span className="text-text-3 italic">None.</span> The contract verifies a passkey
							signature directly, in Move.
						</div>
						<div className="mt-4 font-mono text-[12px] text-clay">recovery::verify_assertion</div>
					</Tile>
				</div>
			</section>

			{/* Closing CTA */}
			<section className="relative mx-auto max-w-[1280px] px-4 sm:px-6 lg:px-10 pb-20 sm:pb-24">
				<div className="surface-raised relative overflow-hidden p-7 sm:p-10 lg:p-16">
					<div className="absolute inset-0 pointer-events-none">
						<div
							className="absolute -top-40 -right-40 h-[500px] w-[500px] rounded-full"
							style={{
								background: 'radial-gradient(closest-side, rgba(200,121,99,0.22), transparent 70%)',
							}}
						/>
						<div
							className="absolute -bottom-32 -left-32 h-[400px] w-[400px] rounded-full"
							style={{
								background: 'radial-gradient(closest-side, rgba(156,175,136,0.1), transparent 70%)',
							}}
						/>
					</div>
					<div className="relative grid grid-cols-12 gap-6 lg:gap-8 items-end">
						<div className="col-span-12 lg:col-span-8">
							<span className="smallcaps text-clay">Begin</span>
							<h2 className="mt-3 font-display text-[36px] sm:text-[44px] lg:text-[64px] leading-[1] tracking-[-0.025em] text-text">
								One key.
								<br />
								<span className="italic text-text-2">Many keepers.</span>
							</h2>
							<p className="mt-4 sm:mt-5 max-w-[480px] text-[14.5px] sm:text-[15.5px] text-text-2">
								Setup takes about two minutes per device. Stop after the first if you want. Add more
								whenever you are ready.
							</p>
						</div>
						<div className="col-span-12 lg:col-span-4 flex flex-col sm:flex-row gap-3 lg:justify-end">
							<Button size="xl" variant="primary" asChild>
								<a href="/setup/connect">
									Build a vault
									<ArrowUpRight className="h-4 w-4" strokeWidth={2.4} />
								</a>
							</Button>
							<Button size="xl" variant="outline" asChild>
								<a href="/vault">Open vault</a>
							</Button>
						</div>
					</div>
				</div>
			</section>

			<ShellFooter />
		</Shell>
	);
}

function SkipItem({ children }: { children: React.ReactNode }) {
	return (
		<li className="flex items-center gap-3 py-1 text-text-2">
			<span className="font-mono text-[15px] text-clay leading-none flex-none w-3.5 text-center">
				×
			</span>
			<span className="line-through decoration-text-4/50 decoration-[1px] underline-offset-[3px]">
				{children}
			</span>
		</li>
	);
}
