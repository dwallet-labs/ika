// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { createRequire } from 'node:module';
import { fixupPluginRules } from '@eslint/compat';
import js from '@eslint/js';
import importX from 'eslint-plugin-import-x';
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended';
import unusedImports from 'eslint-plugin-unused-imports';
import globals from 'globals';
import tseslint from 'typescript-eslint';

const require = createRequire(import.meta.url);
const requireExtensions = require('eslint-plugin-require-extensions');

export default tseslint.config(
	// Global ignores (replaces .eslintignore)
	{
		ignores: [
			'**/node_modules/**',
			'**/build/**',
			'**/dist/**',
			'**/coverage/**',
			'**/next-env.d.ts',
			'**/doc/book/**',
			'**/external-crates/**',
			'**/storybook-static/**',
			'**/.next/**',
			'**/generated/**',
			'**/CHANGELOG.md',
			'**/target/**',
			'docs/**',
			'examples/**',
			'sdk/typescript/examples/**',
			'sdk/typescript/test/**',
			'sdk/sui/test/system-tests/**',
			'sdk/sui/test/integration/**',
		],
	},

	// Base configs
	js.configs.recommended,
	...tseslint.configs.recommended,
	importX.flatConfigs.typescript,

	// Main rules
	{
		languageOptions: {
			globals: {
				...globals.es2020,
			},
		},
		plugins: {
			'require-extensions': fixupPluginRules(requireExtensions),
			'unused-imports': unusedImports,
		},
		rules: {
			'prefer-const': 'error',
			'no-case-declarations': 'off',
			'no-implicit-coercion': [2, { number: true, string: true, boolean: false }],
			'@typescript-eslint/no-explicit-any': 'off',
			'@typescript-eslint/no-redeclare': 'off',
			'@typescript-eslint/no-restricted-types': [
				'error',
				{
					types: {
						Buffer: {
							message:
								'Buffer usage increases bundle size and is not consistently implemented on web.',
						},
					},
				},
			],
			'no-restricted-globals': [
				'error',
				{
					name: 'Buffer',
					message: 'Buffer usage increases bundle size and is not consistently implemented on web.',
				},
			],
			'@typescript-eslint/no-unused-vars': [
				'error',
				{
					argsIgnorePattern: '^_',
					varsIgnorePattern: '^_',
					vars: 'all',
					args: 'none',
					ignoreRestSiblings: true,
				},
			],
		},
	},

	// SDK-specific overrides
	{
		files: ['sdk/**/*'],
		rules: {
			'require-extensions/require-extensions': 'error',
			'require-extensions/require-index': 'error',
			'@typescript-eslint/consistent-type-imports': ['error'],
			'import-x/consistent-type-specifier-style': ['error', 'prefer-top-level'],
			'import-x/no-cycle': ['error'],
		},
	},

	// Test file overrides
	{
		files: ['**/*.test.*', '**/*.spec.*'],
		rules: {
			'require-extensions/require-extensions': 'off',
			'require-extensions/require-index': 'off',
			'@typescript-eslint/consistent-type-imports': ['off'],
			'import-x/consistent-type-specifier-style': ['off'],
			'no-restricted-globals': ['off'],
			'@typescript-eslint/no-restricted-types': ['off'],
		},
	},

	// CommonJS config files
	{
		files: ['**/*.config.js'],
		languageOptions: {
			globals: {
				...globals.node,
			},
		},
	},

	// Prettier must be last
	eslintPluginPrettierRecommended,
);
