# @ika.xyz/ika-wasm

## 0.3.0

### Minor Changes

- 7d10043: Rebuilt against the current MPC crypto revision.

  **Required — 0.2.x cannot decode what the live networks emit**

  - `reconfiguration_public_output_to_protocol_pp` in 0.2.x understands only V1- and V2-tagged
    decryption-key reconfiguration outputs. Mainnet and testnet now write V4-tagged outputs every
    epoch, so the 0.2.x build throws ``invalid value: integer `3`, expected variant index 0 <= i < 2``
    and every caller that derives protocol public parameters — which is every user-side dWallet
    operation — fails. Plain object reads are unaffected, so the break surfaces late.
  - V2- and V3-tagged (pre-aggregation) outputs are no longer decodable at all and V1 is rejected
    explicitly; the crypto types behind them were removed upstream. Only V4 is supported.

  Consumed by `@ika.xyz/sdk@0.5.0`. A direct consumer of this package must move to 0.3.0 as well —
  upgrading the SDK alone is not enough if the WASM version is pinned separately.
