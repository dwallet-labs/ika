#! /usr/bin/env tsx
// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear
import { buildPackage } from './inner/build-package';

buildPackage().catch((error: unknown) => {
	console.error(error);
	process.exit(1);
});
