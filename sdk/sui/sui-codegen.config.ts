// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { SuiCodegenConfig } from '@mysten/codegen';

const config: SuiCodegenConfig = {
	output: './src/generated',
	packages: [
		{
			package: '@local-pkg/2pc-mpc',
			path: '../../contracts/ika_dwallet_2pc_mpc',
		},
		{
			package: '@local-pkg/common',
			path: '../../contracts/ika_common',
		},
		{
			package: '@local-pkg/system',
			path: '../../contracts/ika_system',
		},
		{
			package: '@local-pkg/ika',
			path: '../../contracts/ika',
		},
	],
};

export default config;
