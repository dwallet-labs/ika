import { ArrowUpRight, Github } from 'lucide-react';

const SUI_PACKAGE_ID = '0x7addf2362f50ddf4ec51e7eaa2f8c40db8a45c2b3a8f2e1de1a6d24dadafedef';
const SOLANA_PROGRAM_ID = 'ikavRY1xV8t3Ye4iWf2yC7VnMhzsrCPjE5tQK1bxFHa';
const REPO_URL = 'https://github.com/Iamknownasfesal/ikavery';

function shortId(id: string): string {
	// Match the start length of "0x" prefixed Sui ids (10 = "0x" + 8) so both
	// chain ids visually balance: "0x7addf236…fedef" / "ikavRY1xV…bxFHa".
	if (id.length <= 18) return id;
	return `${id.slice(0, 10)}…${id.slice(-6)}`;
}

export default function HomePage() {
	return (
		<div className="relative z-10 min-h-screen flex flex-col">
			<SiteHeader />

			<main className="flex-1 mx-auto w-full max-w-[1080px] px-4 sm:px-8 lg:px-10 pt-8 sm:pt-12 lg:pt-14 pb-12 sm:pb-16">
				<Hero />
				<Implementations />
				<Stack />
			</main>

			<SiteFooter />
		</div>
	);
}

/* ───────────── Header ───────────── */

function SiteHeader() {
	return (
		<header className="sticky top-0 z-30 backdrop-blur-md bg-canvas/80 border-b border-border">
			<div className="mx-auto max-w-[1080px] px-4 sm:px-8 lg:px-10 h-12 flex items-center justify-between">
				<a href="/" className="flex items-center gap-2.5 group" aria-label="ikavery home">
					<Mark />
					<span className="font-mono text-[13px] tabular text-text">ikavery</span>
					<span className="font-mono text-[11px] tabular text-text-4">v0.1</span>
				</a>

				<nav className="flex items-center gap-3 sm:gap-5">
					<a
						href="#implementations"
						className="hidden sm:inline font-mono text-[12px] tabular text-text-3 hover:text-text transition-colors"
					>
						implementations
					</a>
					<a
						href="#stack"
						className="hidden sm:inline font-mono text-[12px] tabular text-text-3 hover:text-text transition-colors"
					>
						stack
					</a>
					<a
						href={REPO_URL}
						target="_blank"
						rel="noreferrer"
						className="inline-flex h-8 px-2 items-center gap-1.5 rounded-md border border-border text-text-3 hover:border-clay/60 hover:text-clay transition-colors font-mono text-[12px] tabular"
						aria-label="Source on GitHub"
					>
						<Github className="h-3.5 w-3.5" strokeWidth={2} />
						<span className="hidden sm:inline">github</span>
					</a>
				</nav>
			</div>
		</header>
	);
}

/* ───────────── Hero ───────────── */

function Hero() {
	return (
		<section className="grid grid-cols-1 lg:grid-cols-12 gap-6 lg:gap-10 items-start">
			<div className="lg:col-span-8">
				<div className="font-mono text-[11.5px] tabular text-clay tracking-[0.16em] uppercase">
					{'// proof of concept · pre-alpha'}
				</div>

				<h1 className="mt-4 font-display text-text text-[40px] sm:text-[56px] lg:text-[68px] leading-[1.02] tracking-[-0.025em]">
					Threshold-signed
					<br />
					key custody. <span className="italic text-text-2">Two reference implementations.</span>
				</h1>

				<p className="mt-6 max-w-[640px] text-[15px] sm:text-[16px] leading-[1.6] text-text-2">
					Place a key under <Code>k-of-n</Code> MPC via <Code>Ika 2PC-MPC</Code>. Same protocol on
					Sui and Solana, reachable from one set of TypeScript SDKs.
				</p>
			</div>

			<aside className="lg:col-span-4 lg:pt-10">
				<BlockNote />
			</aside>
		</section>
	);
}

function BlockNote() {
	return (
		<div className="border border-border rounded-md bg-surface/40 p-4 sm:p-5 font-mono text-[12px] tabular leading-[1.7] text-text-2">
			<div className="text-text-4 mb-2.5 tracking-[0.04em]">{'// disclaimer'}</div>
			<p>
				Pre-alpha. Not audited. No warranty. Sui testnet and Solana devnet only. Do not use with
				real funds. State on devnet may reset without notice.
			</p>
		</div>
	);
}

/* ───────────── Implementations ───────────── */

function Implementations() {
	return (
		<section id="implementations" className="mt-14 sm:mt-20">
			<SectionHeader index="01" title="implementations" trailing="02 chains" />
			<div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
				<ChainBlock
					slug="sui"
					tagline="Sui Move · Ika 2PC-MPC"
					summary="Move package on Sui. Recovery proposals are signed once a quorum approves on-chain."
					href="https://sui.ikavery.com"
					meta={[
						{ k: 'network', v: 'testnet' },
						{ k: 'package', v: shortId(SUI_PACKAGE_ID), full: SUI_PACKAGE_ID },
						{ k: 'sdk', v: '@fesal-packages/ikavery-sui-sdk' },
					]}
				/>
				<ChainBlock
					slug="solana"
					tagline="Quasar · Ika 2PC-MPC"
					summary="Quasar program on Solana. Recovery proposals are signed once a quorum approves on-chain."
					href="https://solana.ikavery.com"
					meta={[
						{ k: 'network', v: 'devnet' },
						{
							k: 'program',
							v: shortId(SOLANA_PROGRAM_ID),
							full: SOLANA_PROGRAM_ID,
						},
						{ k: 'sdk', v: '@fesal-packages/ikavery-solana-sdk' },
					]}
				/>
			</div>
		</section>
	);
}

interface MetaRow {
	k: string;
	v: string;
	/** Optional full value, exposed via `title` on hover. Used for truncated ids. */
	full?: string;
}

function ChainBlock({
	slug,
	tagline,
	summary,
	href,
	meta,
}: {
	slug: string;
	tagline: string;
	summary: string;
	href: string;
	meta: MetaRow[];
}) {
	return (
		<a
			href={href}
			className="group flex flex-col border border-border rounded-md bg-surface/30 hover:bg-surface/50 hover:border-clay/50 transition-colors overflow-hidden h-full"
		>
			<div className="px-4 sm:px-5 py-3.5 border-b border-border flex items-center justify-between">
				<div className="flex items-baseline gap-3">
					<span className="font-mono text-[10.5px] tabular text-text-4 tracking-[0.16em] uppercase">
						chain
					</span>
					<span className="font-mono text-[15px] tabular text-text font-medium">{slug}</span>
				</div>
				<span className="inline-flex h-7 w-7 items-center justify-center rounded-full border border-border-strong text-text-3 group-hover:border-clay group-hover:text-clay group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-all duration-300">
					<ArrowUpRight className="h-3.5 w-3.5" strokeWidth={2} />
				</span>
			</div>

			<div className="px-4 sm:px-5 py-4 sm:py-5 flex flex-col gap-3 sm:gap-4">
				<div className="font-mono text-[11.5px] tabular text-clay tracking-[0.04em]">{tagline}</div>
				<p className="text-[13.5px] sm:text-[14px] leading-[1.55] text-text-2">{summary}</p>
			</div>

			<dl className="px-4 sm:px-5 py-3.5 border-t border-border bg-surface/20 grid grid-cols-1 gap-x-5 gap-y-1.5 font-mono text-[11.5px] tabular leading-[1.55] mt-auto">
				{meta.map(({ k, v, full }) => (
					<div key={k} className="flex gap-3 min-w-0">
						<dt className="text-text-4 w-[60px] sm:w-[68px] flex-none">{k}</dt>
						<dd className="text-text-2 truncate" title={full ?? undefined}>
							{v}
						</dd>
					</div>
				))}
			</dl>

			<div className="px-4 sm:px-5 py-3 border-t border-border flex items-center justify-between font-mono text-[12px] tabular text-text-3 group-hover:text-clay transition-colors gap-3">
				<span className="truncate">open {hrefHost(href)}</span>
				<span aria-hidden className="flex-none">
					→
				</span>
			</div>
		</a>
	);
}

function hrefHost(url: string): string {
	return url.replace(/^https?:\/\//, '');
}

/* ───────────── Stack ───────────── */

function Stack() {
	return (
		<section id="stack" className="mt-14 sm:mt-20">
			<SectionHeader index="02" title="stack" trailing="" />
			<div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
				<StackBlock title="protocol" rows={['Ika 2PC-MPC', 'zero-trust dWallets']} />
				<StackBlock title="onchain" rows={['Sui Move', 'Quasar (Solana)']} />
				<StackBlock title="client" rows={['TypeScript SDKs', 'Next.js + React']} />
			</div>
		</section>
	);
}

function StackBlock({ title, rows }: { title: string; rows: string[] }) {
	return (
		<div className="border border-border rounded-md p-4 sm:p-5 bg-surface/30">
			<div className="font-mono text-[10.5px] tabular text-text-4 tracking-[0.16em] uppercase mb-3">
				{title}
			</div>
			<ul className="flex flex-col gap-1.5 font-mono text-[12.5px] tabular text-text-2">
				{rows.map((r) => (
					<li key={r} className="flex items-center gap-2">
						<span aria-hidden className="h-1 w-1 rounded-full bg-clay/70" />
						{r}
					</li>
				))}
			</ul>
		</div>
	);
}

/* ───────────── Footer ───────────── */

function SiteFooter() {
	return (
		<footer className="border-t border-border">
			<div className="mx-auto max-w-[1080px] px-4 sm:px-8 lg:px-10 py-8 flex flex-col sm:flex-row sm:items-center justify-between gap-4 font-mono text-[11.5px] tabular text-text-3 tracking-[0.04em]">
				<span>pre-alpha · not audited · no warranty</span>
				<a
					href={REPO_URL}
					target="_blank"
					rel="noreferrer"
					className="inline-flex items-center gap-1.5 hover:text-clay transition-colors"
				>
					<Github className="h-3 w-3" />
					source: github.com/Iamknownasfesal/ikavery
				</a>
			</div>
		</footer>
	);
}

/* ───────────── Bits ───────────── */

function SectionHeader({
	index,
	title,
	trailing,
}: {
	index: string;
	title: string;
	trailing?: string;
}) {
	return (
		<div className="mb-5 sm:mb-6 flex items-baseline gap-4">
			<span className="font-mono text-[11px] tabular text-text-4 tracking-[0.16em] uppercase">
				{'// '}
				{index} · {title}
			</span>
			<span className="flex-1 h-px bg-border" aria-hidden />
			{trailing && (
				<span className="font-mono text-[11px] tabular text-text-4 tracking-[0.16em] uppercase">
					{trailing}
				</span>
			)}
		</div>
	);
}

function Code({ children }: { children: React.ReactNode }) {
	return (
		<code className="font-mono text-[13px] tabular text-text bg-surface/60 border border-border rounded px-1.5 py-0.5 mx-0.5">
			{children}
		</code>
	);
}

function Mark() {
	// Pixel-art squid with skeleton key. 16x10 grid; "1" = ink, "2" = clay.
	const grid = [
		'0000011110000000',
		'0000111111000000',
		'0001111111110000',
		'0001101101100000',
		'0001111111100222',
		'0001111111111202',
		'0001111111120222',
		'0000111111000000',
		'0001010101000000',
		'0010101010100000',
	];
	return (
		<div className="relative flex h-7 w-7 items-center justify-center bg-clay/10 border border-clay/40 rounded-[3px] transition-colors group-hover:bg-clay/20 group-hover:border-clay/60">
			<svg width="28" height="17.5" viewBox="0 0 16 10" shapeRendering="crispEdges" aria-hidden>
				{grid.flatMap((row, y) =>
					row
						.split('')
						.map((cell, x) =>
							cell !== '0' ? (
								<rect
									key={`${x},${y}`}
									x={x}
									y={y}
									width="1"
									height="1"
									fill={cell === '2' ? 'var(--color-clay)' : 'var(--color-text)'}
								/>
							) : null,
						),
				)}
			</svg>
		</div>
	);
}
