import { BookOpen, Code2, Globe, Layers, Puzzle, Send, Terminal, Zap } from 'lucide-react';
import Image from 'next/image';
import Link from 'next/link';

const features = [
	{
		title: 'Solana Integration (pre-alpha)',
		description:
			'Use Solana as the coordination chain. Pinocchio, Anchor, and Native frameworks supported.',
		href: 'https://solana-pre-alpha.ika.xyz',
		icon: Globe,
		gradient: 'from-[#9945FF] to-[#14F195]',
		external: true,
	},
	{
		title: 'Quickstart',
		description: 'Sign your first Bitcoin transaction with a dWallet in under ten minutes.',
		href: '/docs/learn/quickstart',
		icon: Zap,
		gradient: 'from-pink-500 to-rose-500',
	},
	{
		title: 'Learn',
		description: 'Concepts, trust model, and the 2PC-MPC protocol behind dWallets.',
		href: '/docs/learn',
		icon: BookOpen,
		gradient: 'from-blue-500 to-cyan-500',
	},
	{
		title: 'Build with the SDK',
		description: 'The TypeScript SDK and the plugin layer for cross-chain signing.',
		href: '/docs/build',
		icon: Code2,
		gradient: 'from-violet-500 to-purple-500',
	},
	{
		title: 'Plugins',
		description: 'Bitcoin, Ethereum, Solana, and Sui destinations. Compose them on one client.',
		href: '/docs/build/plugins',
		icon: Puzzle,
		gradient: 'from-purple-500 to-indigo-500',
	},
	{
		title: 'Move integration',
		description: 'Consume dWallet capabilities from Sui Move contracts.',
		href: '/docs/build/move-integration',
		icon: Layers,
		gradient: 'from-indigo-500 to-blue-500',
	},
	{
		title: 'Operate a validator',
		description: 'Hardware, keys, configuration, monitoring, and incident response.',
		href: '/docs/operate',
		icon: Terminal,
		gradient: 'from-emerald-500 to-teal-500',
	},
	{
		title: 'AI Skills',
		description: 'Claude Code and other agents get expert context for Ika out of the box.',
		href: '/docs/ai-skills',
		icon: Send,
		gradient: 'from-amber-500 to-orange-500',
	},
];

export default function HomePage() {
	return (
		<main className="min-h-screen">
			{/* Hero Section */}
			<section className="relative overflow-hidden">
				<div className="absolute inset-0 bg-hero-gradient dark:bg-hero-gradient-dark" />
				<div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-pink-100/50 via-transparent to-transparent dark:from-pink-900/20" />
				<div className="absolute inset-0 bg-[linear-gradient(to_right,#ec489910_1px,transparent_1px),linear-gradient(to_bottom,#ec489910_1px,transparent_1px)] bg-[size:4rem_4rem]" />

				<div className="relative mx-auto max-w-6xl px-6 py-24 sm:py-32 lg:py-40">
					<div className="text-center animate-fade-in-up">
						{/* Badge */}
						<div className="mb-8 inline-flex items-center gap-2 rounded-full border border-pink-200 dark:border-pink-800 bg-pink-50 dark:bg-pink-950/50 px-4 py-1.5 text-sm font-medium text-pink-700 dark:text-pink-300">
							<Globe className="h-4 w-4" />
							Bridgeless Capital Markets
						</div>

						{/* Title */}
						<h1 className="text-4xl font-extrabold tracking-tight sm:text-5xl md:text-6xl lg:text-7xl">
							Build with <span className="gradient-text">Ika</span>
						</h1>

						{/* Subtitle */}
						<p className="mx-auto mt-6 max-w-3xl text-lg text-fd-muted-foreground sm:text-xl">
							Ika is a permissionless MPC signing network. Coordinate on Solana (pre-alpha) or on
							Sui today. dWallets sign for Bitcoin, Ethereum, Solana, Sui, and other chains without
							bridges, wrapping, or centralized custody.
						</p>

						{/* Solana callout */}
						<Link
							href="https://solana-pre-alpha.ika.xyz"
							target="_blank"
							className="mt-6 inline-flex items-center gap-2.5 rounded-full bg-gradient-to-r from-[#9945FF]/10 to-[#14F195]/10 dark:from-[#9945FF]/20 dark:to-[#14F195]/20 border border-[#9945FF]/40 dark:border-[#9945FF]/30 px-5 py-2 transition-all hover:scale-105 hover:shadow-lg hover:shadow-[#9945FF]/10"
						>
							<Image
								src="/solana-logo.svg"
								alt="Solana"
								width={16}
								height={16}
								className="dark:brightness-0 dark:invert"
							/>
							<span className="text-sm font-medium text-[#9945FF] dark:text-[#14F195]">
								Solana coordination chain (pre-alpha) is live on devnet
							</span>
							<span className="h-1.5 w-1.5 rounded-full bg-[#14F195] animate-pulse" />
						</Link>

						{/* CTA Buttons */}
						<div className="mt-10 flex flex-col sm:flex-row items-center justify-center gap-4">
							<Link
								href="/docs/learn/quickstart"
								className="btn-primary inline-flex items-center gap-2"
							>
								<Zap className="h-5 w-5" />
								Get Started
							</Link>
							<Link
								href="https://github.com/dwallet-labs/ika"
								target="_blank"
								rel="noopener noreferrer"
								className="btn-secondary inline-flex items-center gap-2"
							>
								<svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24">
									<path
										fillRule="evenodd"
										d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
										clipRule="evenodd"
									/>
								</svg>
								View on GitHub
							</Link>
						</div>
					</div>
				</div>
			</section>

			{/* Value Proposition Section */}
			<section className="relative py-16 sm:py-20 border-b border-fd-border">
				<div className="mx-auto max-w-6xl px-6">
					<div className="grid gap-8 md:grid-cols-3">
						<div className="text-center">
							<div className="mx-auto mb-4 inline-flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-pink-500 to-rose-500 text-white shadow-lg">
								<Globe className="h-6 w-6" />
							</div>
							<h3 className="text-lg font-semibold mb-2">No bridges</h3>
							<p className="text-sm text-fd-muted-foreground">
								A dWallet's signature on Bitcoin is a regular Bitcoin signature. No wrapped tokens, no
								bridge layer, no centralized custodian.
							</p>
						</div>
						<div className="text-center">
							<div className="mx-auto mb-4 inline-flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-blue-500 to-cyan-500 text-white shadow-lg">
								<Layers className="h-6 w-6" />
							</div>
							<h3 className="text-lg font-semibold mb-2">Zero-trust signing</h3>
							<p className="text-sm text-fd-muted-foreground">
								The signing key is split between the user and the validator network. Neither side can
								sign alone.
							</p>
						</div>
						<div className="text-center">
							<div className="mx-auto mb-4 inline-flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-emerald-500 to-teal-500 text-white shadow-lg">
								<Zap className="h-6 w-6" />
							</div>
							<h3 className="text-lg font-semibold mb-2">Programmable</h3>
							<p className="text-sm text-fd-muted-foreground">
								Solana programs (pre-alpha) and Sui Move contracts hold dWallet capabilities and
								gate signatures behind on-chain logic.
							</p>
						</div>
					</div>
				</div>
			</section>

			{/* Features Section */}
			<section className="relative py-20 sm:py-28">
				<div className="mx-auto max-w-6xl px-6">
					<div className="text-center mb-16">
						<h2 className="text-3xl font-bold tracking-tight sm:text-4xl">
							Explore the documentation
						</h2>
						<p className="mt-4 text-lg text-fd-muted-foreground">
							Everything you need to build, operate, or learn.
						</p>
					</div>

					<div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
						{features.map((feature, index) => (
							<Link
								key={feature.title}
								href={feature.href}
								target={feature.external ? '_blank' : undefined}
								rel={feature.external ? 'noopener noreferrer' : undefined}
								className="group relative overflow-hidden rounded-2xl border border-fd-border bg-fd-card p-6 transition-all duration-300 hover:border-pink-300 dark:hover:border-pink-700 hover:shadow-lg hover:shadow-pink-500/10 card-hover"
								style={{ animationDelay: `${index * 100}ms` }}
							>
								<div
									className={`absolute inset-0 bg-gradient-to-br ${feature.gradient} opacity-0 group-hover:opacity-5 transition-opacity duration-300`}
								/>

								<div className="relative">
									<div
										className={`mb-4 inline-flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br ${feature.gradient} text-white shadow-lg`}
									>
										<feature.icon className="h-6 w-6" />
									</div>

									<h3 className="text-xl font-semibold mb-2 group-hover:text-pink-600 dark:group-hover:text-pink-400 transition-colors">
										{feature.title}
									</h3>
									<p className="text-fd-muted-foreground text-sm leading-relaxed">
										{feature.description}
									</p>

									<div className="mt-4 flex items-center text-sm font-medium text-pink-600 dark:text-pink-400">
										Learn more
										<svg
											className="ml-1 h-4 w-4 transition-transform group-hover:translate-x-1"
											fill="none"
											viewBox="0 0 24 24"
											stroke="currentColor"
										>
											<path
												strokeLinecap="round"
												strokeLinejoin="round"
												strokeWidth={2}
												d="M9 5l7 7-7 7"
											/>
										</svg>
									</div>
								</div>
							</Link>
						))}
					</div>
				</div>
			</section>

			{/* Quick Links Section */}
			<section className="relative py-20 bg-fd-muted/50">
				<div className="mx-auto max-w-6xl px-6">
					<div className="rounded-2xl border border-fd-border bg-fd-card p-8 sm:p-12">
						<div className="grid gap-8 lg:grid-cols-2 lg:gap-12 items-center">
							<div>
								<h2 className="text-2xl font-bold tracking-tight sm:text-3xl">
									Ready to build?
								</h2>
								<p className="mt-4 text-fd-muted-foreground">
									Start on the Solana pre-alpha or install the Sui-coordinated SDK and plugin
									layer.
								</p>
								<div className="mt-6 flex flex-col gap-3">
									<div className="flex flex-col gap-1.5">
										<span className="text-xs uppercase tracking-wide text-fd-muted-foreground">
											Solana (pre-alpha)
										</span>
										<Link
											href="https://solana-pre-alpha.ika.xyz"
											target="_blank"
											rel="noopener noreferrer"
											className="inline-flex w-fit items-center gap-2 rounded-lg bg-gradient-to-r from-[#9945FF]/10 to-[#14F195]/10 border border-[#9945FF]/40 px-4 py-2 text-sm font-medium text-[#9945FF] dark:text-[#14F195] hover:scale-[1.02] transition-transform"
										>
											<Image
												src="/solana-logo.svg"
												alt="Solana"
												width={14}
												height={14}
												className="dark:brightness-0 dark:invert"
											/>
											Open the Solana pre-alpha docs
										</Link>
									</div>
									<div className="flex flex-col gap-1.5">
										<span className="text-xs uppercase tracking-wide text-fd-muted-foreground">
											Sui
										</span>
										<code className="inline-flex w-fit items-center gap-2 rounded-lg bg-fd-muted px-4 py-2 text-sm font-mono">
											<span className="text-pink-600 dark:text-pink-400">$</span>
											pnpm add @ika.xyz/sdk @ika.xyz/plugins @mysten/sui
										</code>
									</div>
								</div>
							</div>
							<div className="flex flex-col sm:flex-row gap-4 lg:justify-end">
								<Link href="/docs/learn/quickstart" className="btn-primary text-center">
									Get Started
								</Link>
								<Link href="/docs/learn/trust-model" className="btn-secondary text-center">
									Trust model
								</Link>
							</div>
						</div>
					</div>
				</div>
			</section>

			{/* Footer */}
			<footer className="border-t border-fd-border py-12">
				<div className="mx-auto max-w-6xl px-6">
					<div className="flex flex-col sm:flex-row items-center justify-between gap-4">
						<p className="text-sm text-fd-muted-foreground">
							&copy; {new Date().getFullYear()} dWallet Labs, Ltd. All rights reserved.
						</p>
						<div className="flex items-center gap-6">
							<Link
								href="https://solana-pre-alpha.ika.xyz"
								target="_blank"
								rel="noopener noreferrer"
								className="text-fd-muted-foreground hover:text-fd-foreground transition-colors"
							>
								Solana (pre-alpha)
							</Link>
							<Link
								href="https://github.com/dwallet-labs/ika"
								target="_blank"
								rel="noopener noreferrer"
								className="text-fd-muted-foreground hover:text-fd-foreground transition-colors"
							>
								GitHub
							</Link>
							<Link
								href="/whitepaper.pdf"
								target="_blank"
								className="text-fd-muted-foreground hover:text-fd-foreground transition-colors"
							>
								Whitepaper
							</Link>
						</div>
					</div>
				</div>
			</footer>
		</main>
	);
}
