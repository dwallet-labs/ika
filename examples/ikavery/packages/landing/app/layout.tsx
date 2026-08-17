import type { Metadata } from 'next';
import { Hanken_Grotesk, IBM_Plex_Mono, Instrument_Serif } from 'next/font/google';

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

const description =
	'Threshold-signed key custody on Sui and Solana. k-of-n MPC via Ika 2PC-MPC. Pre-alpha, not audited.';

export const metadata: Metadata = {
	metadataBase: new URL('https://ikavery.com'),
	applicationName: 'ikavery',
	title: {
		default: 'ikavery · threshold-signed key custody',
		template: '%s · ikavery',
	},
	description,
	keywords: [
		'Ikavery',
		'Ika',
		'Sui',
		'Solana',
		'MPC',
		'2PC-MPC',
		'key recovery',
		'threshold signing',
		'self-custody',
	],
	authors: [{ name: 'fesal', url: 'https://github.com/Iamknownasfesal/ikavery' }],
	creator: 'fesal',
	openGraph: {
		type: 'website',
		siteName: 'ikavery',
		title: 'ikavery · threshold-signed key custody',
		description,
		url: '/',
		locale: 'en_US',
	},
	twitter: {
		card: 'summary_large_image',
		title: 'ikavery · threshold-signed key custody',
		description,
		creator: '@iamknownasfesal',
	},
	robots: { index: true, follow: true },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
	return (
		<html lang="en" className={`${display.variable} ${body.variable} ${mono.variable}`}>
			<body className="font-body antialiased">{children}</body>
		</html>
	);
}
