import type * as Preset from '@docusaurus/preset-classic';
import type { Config } from '@docusaurus/types';
import { themes as prismThemes } from 'prism-react-renderer';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

const config: Config = {
	title: 'Ika Docs',
	tagline: 'Ika Documentation',
	favicon: 'img/ika-logo.png',

	// Future flags, see https://docusaurus.io/docs/api/docusaurus-config#future
	future: {
		v4: true, // Improve compatibility with the upcoming Docusaurus v4
	},

	// Set the production url of your site here
	url: 'https://docs.ika.xyz',
	// Set the /<baseUrl>/ pathname under which your site is served
	// For GitHub pages deployment, it is often '/<projectName>/'
	baseUrl: '/',

	// GitHub pages deployment config.
	// If you aren't using GitHub pages, you don't need these.
	organizationName: 'dwallet-labs', // Usually your GitHub org/user name.
	projectName: 'ika-docs', // Usually your repo name.

	onBrokenLinks: 'throw',
	onBrokenMarkdownLinks: 'warn',

	// Even if you don't use internationalization, you can use this field to set
	// useful metadata like html lang. For example, if your site is Chinese, you
	// may want to replace "en" with "zh-Hans".
	i18n: {
		defaultLocale: 'en',
		locales: ['en'],
	},

	presets: [
		[
			'classic',
			{
				docs: {
					routeBasePath: '/', // Serve the docs at the site's root
					sidebarPath: './sidebars.ts',
					// Please change this to your repo.
					// Remove this to remove the "edit this page" links.
					editUrl: 'https://github.com/dwallet-labs/dwallet-network/tree/main/docs/',
				},
				blog: false, // Disable the blog plugin
				theme: {
					customCss: './src/css/custom.css',
				},
			} satisfies Preset.Options,
		],
	],

	themes: ['@docusaurus/theme-mermaid'],

	markdown: {
		mermaid: true,
	},

	themeConfig: {
		// Replace with your project's social card
		image: 'img/ika-social-card.png',
		navbar: {
			title: 'Ika Docs',
			logo: {
				alt: 'Ika Docs Logo',
				src: 'img/icon-white.png',
				className: 'navbar-logo',
			},
			items: [
				{
					type: 'docSidebar',
					sidebarId: 'sdkGuidesSidebar',
					position: 'left',
					label: 'SDK Guides',
				},
				{
					type: 'docSidebar',
					sidebarId: 'coreConceptsSidebar',
					position: 'left',
					label: 'Core Concepts',
				},
				{
					type: 'docSidebar',
					sidebarId: 'operatorGuidesSidebar',
					position: 'left',
					label: 'Operator Guides',
				},
				{
					type: 'docSidebar',
					sidebarId: 'codeExamplesSidebar',
					position: 'left',
					label: 'Code Examples',
				},
			],
		},
		footer: {
			copyright: `Copyright © ${new Date().getFullYear()} dWallet Labs, Ltd.`,
		},
		prism: {
			theme: prismThemes.oneLight,
			darkTheme: prismThemes.oneDark,
			additionalLanguages: [
				'bash',
				'json',
				'toml',
				'yaml',
				'rust',
				'typescript',
				'javascript',
				'python',
			],
			defaultLanguage: 'typescript',
		},
		mermaid: {
			theme: {
				light: 'neutral',
				dark: 'dark',
			},
		},
	} satisfies Preset.ThemeConfig,
};

export default config;
