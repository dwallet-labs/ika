# digest compatibility alias

Source: crates.io `digest` 0.11.3, from RustCrypto/traits. The upstream
source and licenses are preserved. The only source change is re-exporting
`common` as `crypto_common` in `src/lib.rs`.

Sui testnet-v1.82.1 requires stable digest through argon2. Ika's pinned
inkrypto revision requires curve25519-dalek 5.0.0-pre.1, which still imports
`digest::crypto_common::BlockSizeUser`. The alias names the same dependency
and adds no hashing, curve, or serialization implementation.

Both the root and excluded WASM workspace patch crates.io to this directory.
Remove the override when inkrypto's pinned dependencies use `digest::common`.
