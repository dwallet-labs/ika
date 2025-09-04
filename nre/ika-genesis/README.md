## IKA Network

> See the func `init_ika_on_sui` for more info.

1. Publish two smart contracts to the Sui Devnet blockchain - `crates/ika-move-packages/packages`.
    - First publish `ika` and then `ika-system`.
2. Mint Ika tokens `crates/ika-swarm-config/src/sui_client.rs`
3. Init the Env with `initialize()` func `from init.move` inside ika-system.
4. Create Validator Candidate.
5. Stake (By treasury).
6. Validator Join.
7. After all the validators have been created call initialize from `system.move`.
