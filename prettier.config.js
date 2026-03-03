// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module.exports = {
	printWidth: 100,
	singleQuote: true,
	useTabs: true,
	plugins: ['@ianvs/prettier-plugin-sort-imports'],
	importOrder: [
		'<BUILT_IN_MODULES>',
		'<THIRD_PARTY_MODULES>',
		'',
		'^@/(.*)$',
		'^~/(.*)$',
		'',
		'^[.]',
	],
	overrides: [
		{
			files: 'sdk/**/*',
			options: {
				proseWrap: 'always',
			},
		},
	],
};
