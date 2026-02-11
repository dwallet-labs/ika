import { createPreset } from 'fumadocs-ui/tailwind-plugin';
import type { Config } from 'tailwindcss';

const config: Config = {
	content: [
		'./components/**/*.{ts,tsx}',
		'./app/**/*.{ts,tsx}',
		'./content/**/*.mdx',
		'./mdx-components.tsx',
		'./node_modules/fumadocs-ui/dist/**/*.js',
	],
	presets: [createPreset()],
	theme: {
		extend: {
			fontFamily: {
				sans: ['DM Sans', 'system-ui', '-apple-system', 'sans-serif'],
				mono: ['DM Mono', 'SF Mono', 'Monaco', 'monospace'],
			},
			colors: {
				ika: {
					50: '#fdf2f8',
					100: '#fce7f3',
					200: '#fbcfe8',
					300: '#f9a8d4',
					400: '#f472b6',
					500: '#ec4899',
					600: '#db2777',
					700: '#be185d',
				},
			},
			backgroundImage: {
				'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
				'gradient-conic': 'conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))',
			},
			animation: {
				'fade-in': 'fade-in 0.3s ease-out',
				'fade-up': 'fade-up 0.4s ease-out',
			},
			keyframes: {
				'fade-in': {
					'0%': { opacity: '0' },
					'100%': { opacity: '1' },
				},
				'fade-up': {
					'0%': { opacity: '0', transform: 'translateY(8px)' },
					'100%': { opacity: '1', transform: 'translateY(0)' },
				},
			},
			boxShadow: {
				soft: '0 2px 8px rgba(0, 0, 0, 0.04)',
				medium: '0 4px 12px rgba(0, 0, 0, 0.06)',
			},
		},
	},
};

export default config;
