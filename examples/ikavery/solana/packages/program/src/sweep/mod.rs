//! Sweep parsing pipeline: raw Solana message bytes → parsed instructions
//! → canonical intent digest. The same bytes-in / digest-out invariant
//! that `recovery::sweep::propose` and `recovery::sweep::execute` use on
//! Sui, just over Solana's tx layout.

pub mod intent;
pub mod solana_msg;
