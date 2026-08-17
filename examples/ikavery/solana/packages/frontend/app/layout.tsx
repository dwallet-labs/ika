import type { Metadata } from 'next';
import { Hanken_Grotesk, IBM_Plex_Mono, Instrument_Serif } from 'next/font/google';

import { DynamicProviders } from '@/lib/dynamic-providers';

import './globals.css';

const display = Instrument_Serif({
	subsets: ['latin'],
	weight: ['400'],
	style: ['normal', 'italic'],
	variable: '--font-display',
	display: 'swap',
});

const body = Hanken_Grotesk({
	subsets: ['latin'],
	variable: '--font-body',
	display: 'swap',
});

const mono = IBM_Plex_Mono({
	subsets: ['latin'],
	weight: ['300', '400', '500', '600'],
	variable: '--font-mono',
	display: 'swap',
});

const tagline = 'Keys kept by quorum.';
const description =
	'Ikavery places a Solana private key behind a threshold of wallets you already trust. Recover it any time by signing on a quorum.';

export const metadata: Metadata = {
	metadataBase: new URL('https://solana.ikavery.com'),
	applicationName: 'Ikavery · Solana',
	title: {
		default: `Ikavery · ${tagline}`,
		template: '%s · Ikavery',
	},
	description,
	keywords: ['Ikavery', 'Ika', 'Solana', 'passkey', 'MPC', 'key recovery', 'self-custody'],
	authors: [{ name: 'fesal', url: 'https://github.com/iamknownasfesal' }],
	creator: 'fesal',
	openGraph: {
		type: 'website',
		siteName: 'Ikavery · Solana',
		title: `Ikavery · ${tagline}`,
		description,
		url: '/',
		locale: 'en_US',
	},
	twitter: {
		card: 'summary_large_image',
		title: `Ikavery · ${tagline}`,
		description,
		creator: '@iamknownasfesal',
	},
	robots: {
		index: true,
		follow: true,
	},
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
	return (
		<html lang="en" className={`${display.variable} ${body.variable} ${mono.variable}`}>
			<body className="font-body antialiased">
				<DynamicProviders>{children}</DynamicProviders>
			</body>
		</html>
	);
}
