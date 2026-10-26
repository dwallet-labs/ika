`legacy-validator-mpc-data.bcs` contains public encryption keys and proofs
derived on native 64-bit from the known test root seed `[31u8; 32]` with
cryptography-private revision `0d5046dff586258e10fc82541b625fc935893172`.
It contains no private key material.

The fixture was generated in release mode with real crypto (`threshold` and
`parallel`, without `unsafe_mock`). Child seeds use the unchanged Merlin
labels in `dwallet-rng::RootSeed`. The old revision's
`generate_class_groups_keypair`, `generate_pvss_keypairs` and
`generate_and_uc_prove_encryption_keypair` produce the five fields of
`ValidatorEncryptionKeysAndProofs` in their declared order. BCS serializes that
bundle inside `VersionedMPCData::V1(MPCDataV1 { mpc_data_bytes })`.

- Size: 72,864 bytes.
- SHA256: `df2a84a7448afb4dd11dca6558bae4805147e60f312a06f622cb49cc5a399058`.
- Ika Blake2b256 blob digest:
  `c30c04b8799e93fe512df873bd1d464f336c160d50636c9389f57cf7f46d3219`.

Keep this fixture frozen. Regenerating it with the upgraded proof generator
would hide the historical-bundle mismatch the recovery test must detect.
