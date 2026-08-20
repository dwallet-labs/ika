// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Decoding of Rust structs that mirror deployed Move struct layouts.
//!
//! A few Rust types — `DWalletCoordinatorInnerV1`, `SystemInnerV1`,
//! `DWalletNetworkEncryptionKey` — are plain untagged `#[derive(Deserialize)]`
//! structs whose field order must match, byte for byte, the layout of a Move
//! struct already deployed on chain. Nothing in the bytes says which layout
//! produced them: the OCS proof chain (committee BLS → artifacts digest →
//! Merkle inclusion → id binding → currency) authenticates *provenance* — that
//! these bytes are the chain's — and never *shape*. A tagged type like
//! `VersionedMPCData` fails closed on an unknown variant; these cannot.
//!
//! Decoding here is already as strict as BCS allows. `bcs::from_bytes` runs the
//! deserializer to `end()` and rejects residue, every one of these mirrors is
//! the last value in its byte stream, and each terminates in a fixed-width tail
//! (`extra_fields: Bag` is 40 bytes; the fieldless `state` enum is one). So a
//! layout change that alters the encoded length does surface. What it surfaces
//! as is the problem: a bare `remaining input`, or an `unexpected end of input`
//! raised several fields past the one that actually moved. That error names the
//! wrong place, and has already cost this repo multiple CI cycles of hunting in
//! the wrong struct (`dev-docs/learnings/pitfalls.md`, "Sui types & encoding").
//!
//! [`decode_chain_mirror`] is the decode entry point for these types. It adds
//! nothing to the strictness — that was already maximal — and everything to the
//! attribution of the failure.
//!
//! Drift is *prevented*, rather than merely diagnosed, at build time by two
//! guards that have to be updated together:
//! `scripts/check-chain-mirror-layout.sh` ties the Move declarations to the Rust
//! mirrors, and a golden layout test sits beside each mirror. Neither can act at
//! runtime; see `dev-docs/conventions/chain-mirror-layout.md` for what that does
//! and does not buy.

use serde::de::DeserializeOwned;

/// A Rust struct mirroring a deployed Move struct layout, paired with the Move
/// declaration it must stay identical to.
///
/// Exists only to build the message of a failed decode: it names the Move source
/// the reader's expectation came from, so a drift points at the two files that
/// have to agree rather than at the byte offset where the mis-parse ran out.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ChainMirror {
    /// The Rust type being decoded, spelled as it is at the call site —
    /// `Field<u64, DWalletCoordinatorInnerV1>` for a mirror read out of a
    /// versioned dynamic field, since that whole wrapper is what BCS consumes.
    pub rust_type: &'static str,
    /// The Move struct whose on-chain layout `rust_type` mirrors.
    pub move_struct: &'static str,
    /// Repo-root-relative path of the Move source declaring `move_struct`.
    pub move_source: &'static str,
}

/// The coordinator inner state, read out of the `Field<u64, _>` dynamic field
/// that the `DWalletCoordinator` outer object stores it under.
pub const DWALLET_COORDINATOR_INNER_V1: ChainMirror = ChainMirror {
    rust_type: "Field<u64, DWalletCoordinatorInnerV1>",
    move_struct: "DWalletCoordinatorInner",
    move_source: "contracts/ika_dwallet_2pc_mpc/sources/coordinator_inner.move",
};

/// The system inner state, read out of the `Field<u64, _>` dynamic field that
/// the `System` outer object stores it under.
pub const SYSTEM_INNER_V1: ChainMirror = ChainMirror {
    rust_type: "Field<u64, SystemInnerV1>",
    move_struct: "SystemInner",
    move_source: "contracts/ika_system/sources/system/system_inner.move",
};

/// A network encryption key. Unlike the two inners this is a `key` object read
/// directly, so its Move `id: UID` is the mirror's leading `ObjectID` and there
/// is no version wrapper in front of it at all.
pub const DWALLET_NETWORK_ENCRYPTION_KEY: ChainMirror = ChainMirror {
    rust_type: "DWalletNetworkEncryptionKey",
    move_struct: "DWalletNetworkEncryptionKey",
    move_source: "contracts/ika_dwallet_2pc_mpc/sources/coordinator_inner.move",
};

/// BCS-decode on-chain bytes into an untagged Rust mirror of a Move struct,
/// attributing a failure to the layout drift that is one of its causes.
///
/// Identical to `bcs::from_bytes` on the success path, including its exhaustion
/// check. On the error path it returns [`decode_error_message`].
pub fn decode_chain_mirror<T: DeserializeOwned>(
    bytes: &[u8],
    mirror: ChainMirror,
) -> Result<T, String> {
    bcs::from_bytes(bytes).map_err(|e| decode_error_message(bytes.len(), mirror, &e.to_string()))
}

/// The attributed message [`decode_chain_mirror`] produces on failure.
///
/// Split out so a test can assert on it without having to synthesise bytes that
/// fail to decode as every mirror.
fn decode_error_message(byte_len: usize, mirror: ChainMirror, cause: &str) -> String {
    let ChainMirror {
        rust_type,
        move_struct,
        move_source,
    } = mirror;
    format!(
        "failed to BCS-decode {byte_len} on-chain bytes as `{rust_type}`: {cause}. \
         `{rust_type}` is an UNTAGGED mirror of Move `{move_struct}` \
         ({move_source}), so this is as plausibly a LAYOUT DRIFT — the deployed \
         Move struct no longer matching the Rust mirror — as it is a corrupt or \
         truncated read, and a verified read does not rule that out: the proof \
         chain authenticates where the bytes came from, never what shape they \
         are. Diff the Move declaration against the Rust struct field by field \
         before debugging the field this decode died in. \
         See dev-docs/conventions/chain-mirror-layout.md"
    )
}

/// Shared assertion for the golden layout pins that sit beside each mirror.
///
/// The pins themselves live next to the structs they pin (`mod tests` in
/// `sui/system_inner_v1.rs` and in `messages_dwallet_mpc.rs`), because the
/// struct literal that populates a mirror is half the guard: with every field
/// written out and no `..Default::default()`, an added or removed field fails to
/// compile there. Only the assertion is shared.
#[cfg(test)]
pub(crate) mod test_support {
    use super::ChainMirror;
    use fastcrypto::hash::{Blake2b256, HashFunction};
    use serde::Serialize;

    /// Assert a mirror's BCS encoding against its pin, and say what to do about
    /// a mismatch rather than only that two values differ.
    ///
    /// Callers must pass a FULLY-POPULATED value: every field distinct, every
    /// collection non-empty, every `Option` `Some`. Zeroes everywhere would let
    /// a swap of two same-width fields encode identically, and an empty `Vec` or
    /// a `None` hides the shape of what it contains — which is the shape being
    /// pinned.
    pub(crate) fn assert_pinned_layout<T: Serialize>(
        mirror: ChainMirror,
        value: &T,
        pinned_len: usize,
        pinned_digest: &str,
    ) {
        let bytes = bcs::to_bytes(value).expect("a chain mirror must BCS-encode");
        let digest = hex::encode(Blake2b256::digest(&bytes).digest);

        let guidance = format!(
            "\n\nThe BCS layout of `{}` changed (pinned {pinned_len} bytes / {pinned_digest}, \
             got {} bytes / {digest}).\n\n\
             This struct is an UNTAGGED mirror of Move `{}` ({}). Its field order is the wire \
             format of bytes a deployed package already wrote, and nothing in those bytes \
             identifies which layout produced them, so a change here re-interprets live chain \
             state instead of failing closed.\n\n\
             A pure rename is safe — BCS is positional — and only the pin needs updating. An \
             add, remove, reorder, or retype is not: the Move struct has to have changed to \
             match, and it cannot change in place, because Sui's compatible-policy upgrade \
             checker rejects datatype layout changes. Such a change reaches chain only through \
             a `VERSION` bump plus `migrate()`, or a fresh package publish — and either way the \
             arm that maps chain versions onto this struct (`match wrapper.version {{ 1 | 2 => \
             .. }}`, in ika-sui-client/src/lib.rs and \
             ika-core/src/sui_connector/verified_reader.rs) must stop claiming those versions \
             share one layout. Update `scripts/chain-mirror-layout.txt` in the same change.\n\n\
             See dev-docs/conventions/chain-mirror-layout.md.\n",
            mirror.rust_type,
            bytes.len(),
            mirror.move_struct,
            mirror.move_source,
        );

        // Length first: it is the half a human can act on directly, and an
        // added or removed field moves it.
        assert_eq!(bytes.len(), pinned_len, "{guidance}");
        assert_eq!(digest, pinned_digest, "{guidance}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The failure this helper exists for is a human reading a log line at
    /// 3am, so assert on the parts that redirect them: the underlying bcs
    /// cause is preserved, and the Move source and the drift hypothesis are
    /// both named.
    #[test]
    fn decode_error_names_the_move_source_and_the_drift_hypothesis() {
        let message = decode_error_message(41, DWALLET_NETWORK_ENCRYPTION_KEY, "remaining input");

        assert!(message.contains("remaining input"), "{message}");
        assert!(message.contains("41 on-chain bytes"), "{message}");
        assert!(message.contains("DWalletNetworkEncryptionKey"), "{message}");
        assert!(
            message.contains("contracts/ika_dwallet_2pc_mpc/sources/coordinator_inner.move"),
            "{message}"
        );
        assert!(message.contains("LAYOUT DRIFT"), "{message}");
    }

    /// A mirror read through a versioned dynamic field is decoded as the whole
    /// `Field<u64, _>`, and the message must say so — a reader told only
    /// "DWalletCoordinatorInnerV1" would not think to check the 40-byte
    /// `Field` header that precedes it.
    #[test]
    fn versioned_inner_mirrors_name_the_field_wrapper_they_decode_through() {
        assert_eq!(
            DWALLET_COORDINATOR_INNER_V1.rust_type,
            "Field<u64, DWalletCoordinatorInnerV1>"
        );
        assert_eq!(SYSTEM_INNER_V1.rust_type, "Field<u64, SystemInnerV1>");
    }

    /// The success path must stay byte-identical to `bcs::from_bytes`,
    /// exhaustion check included — the helper is attribution, not a relaxation.
    #[test]
    fn decode_matches_bcs_from_bytes_including_the_exhaustion_check() {
        let bytes = bcs::to_bytes(&(7u64, 9u64)).unwrap();

        let decoded: (u64, u64) =
            decode_chain_mirror(&bytes, DWALLET_NETWORK_ENCRYPTION_KEY).unwrap();
        assert_eq!(decoded, (7, 9));

        // One trailing byte, exactly what an appended Move field looks like.
        let with_residue = [bytes.as_slice(), &[0u8]].concat();
        let error =
            decode_chain_mirror::<(u64, u64)>(&with_residue, DWALLET_NETWORK_ENCRYPTION_KEY)
                .unwrap_err();
        assert!(error.contains("LAYOUT DRIFT"), "{error}");

        // One byte short, what an inserted Move field looks like from here.
        let truncated = &bytes[..bytes.len() - 1];
        let error = decode_chain_mirror::<(u64, u64)>(truncated, DWALLET_NETWORK_ENCRYPTION_KEY)
            .unwrap_err();
        assert!(error.contains("LAYOUT DRIFT"), "{error}");
    }
}
