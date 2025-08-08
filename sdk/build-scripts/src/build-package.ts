#! /usr/bin/env tsx
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import buildPackage from './inner/build-package';

buildPackage().catch((error: unknown) => {
	console.error(error);
	process.exit(1);
});
