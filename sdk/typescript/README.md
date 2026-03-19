### @ika.xyz/sdk — DEPRECATED

> **This package is deprecated.** Use [`@ika.xyz/sui`](../sui/) instead.

`@ika.xyz/sdk` v0.5.0 is a thin compatibility shim that re-exports everything from `@ika.xyz/sui`. It exists solely to give existing users a migration path.

## Migrating

```diff
- npm install @ika.xyz/sdk
+ npm install @ika.xyz/sui
```

```diff
- import { IkaClient, Curve } from '@ika.xyz/sdk';
+ import { IkaClient, Curve } from '@ika.xyz/sui';
```

See the [`@ika.xyz/sui` README](../sui/README.md#migrating-from-ikaxyz-sdk) for the full migration guide, including API changes to `UserShareEncryptionKeys`.

### License

BSD-3-Clause-Clear (c) dWallet Labs, Ltd.
