// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { SuiCodegenConfig } from '@mysten/codegen';

const config: SuiCodegenConfig = {
	output: './src/generated',
	packages: [
		{
			package: '0x9fd74e7ad831f13730ddb59072978eeb51b1eb840f97238d836b27953be52180',
			path: './contract',
		},
	],
};

export default config;
