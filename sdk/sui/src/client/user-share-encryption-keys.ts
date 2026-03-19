// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// Re-export the core UserShareEncryptionKeys class.
// Sui-specific functions (getSuiAddress, getUserOutputSignature, etc.)
// are in ./cryptography.ts as standalone functions.
export { UserShareEncryptionKeys, VersionedUserShareEncryptionKeysBcs } from '@ika.xyz/core';
