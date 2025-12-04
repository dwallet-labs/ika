// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { SuiCodegenConfig } from '@mysten/codegen';

const config: SuiCodegenConfig = {
	output: './src/generated',
	packages: [
		{
			package: '@local-pkg/multisig-contract',
			path: '../contract',
			packageName: 'ika_btc_multisig',
		},
	],
	generateSummaries: false,
};

export default config;
