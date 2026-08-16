// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Classification of every per-epoch table into state that is REBUILT from the
//! consensus commit stream on every boot, and state that must SURVIVE a boot.
//!
//! A validator treats the consensus store as the only truth for epoch-scoped
//! state: on every start it deletes the derived tables and re-derives them by
//! replaying the epoch's commits (see
//! `dev-docs/specs/event-sourced-epoch.md`). That is only sound if the split
//! between "re-derivable from the commits" and "not re-derivable" is exact:
//!
//! - a table classified [`EpochStateClass::Derived`] that is NOT re-derivable
//!   is silently lost at the next restart;
//! - a table classified [`EpochStateClass::Preserved`] that the replay DOES
//!   write survives with rows the replay may not reach. Where the replay
//!   accumulates rather than overwrites, that double-counts; where it
//!   overwrites — the per-round streams, keyed by round — it looks harmless
//!   until a boot whose consensus store lost its tail keeps rows for commits
//!   the store no longer has.
//!
//! So the classification is written down ONCE, here, and the wipe, the
//! post-wipe check and the tests are all generated from that one list — there
//! is no second list to drift.
//! `dev-docs/derived-epoch-state-audit.md` carries the per-table reasoning; this
//! module carries the machine-checked half.

use std::fmt;

/// Which side of the wipe a per-epoch table falls on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochStateClass {
    /// A pure function of the epoch's consensus commit prefix. Deleted at
    /// boot and rebuilt by the replay. Every consensus-visible decision must
    /// live here, because only a derived table is guaranteed to be
    /// attributable to a commit rather than to whatever happened to reach
    /// RocksDB before the process died.
    Derived,
    /// Not re-derivable from the commits with the work a replay is willing to
    /// do. Four sources qualify:
    ///
    /// - **private MPC material** this node computed and never published
    ///   (a replay would have to re-run the cryptography, which the catch-up
    ///   gate deliberately suppresses);
    /// - **presign pool contents, their ordinals and their idempotency
    ///   markers** — the pool is consumed by pops that are NOT all driven by
    ///   consensus order, so a rebuilt pool would hand out different presigns
    ///   than never-crashed peers bound (#1928, #1934, #1952);
    /// - **artifacts fetched from peers or read from Sui**, which arrive
    ///   outside the commit stream;
    /// - **operator-set local overrides**.
    Preserved,
}

impl fmt::Display for EpochStateClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Derived => f.write_str("derived"),
            Self::Preserved => f.write_str("preserved"),
        }
    }
}

/// One row of the audit table: the `AuthorityEpochTables` field name, its
/// class, and the one-line reason a reader can check against the code.
#[derive(Debug, Clone, Copy)]
pub struct EpochStateEntry {
    pub field: &'static str,
    pub class: EpochStateClass,
    pub reason: &'static str,
}

/// Declares the classification of every `AuthorityEpochTables` field and, from
/// the same list, generates:
///
/// - `EPOCH_STATE_REGISTRY` — the audit table the tests iterate;
/// - `AuthorityEpochTables::wipe_derived_state` — point-deletes every
///   `Derived` table and leaves every `Preserved` one untouched;
/// - `non_empty_derived_tables`, the post-wipe startup invariant.
///
/// Adding a field to `AuthorityEpochTables` without adding it here fails
/// `every_epoch_table_is_classified`, which compares this list against the
/// column families `DBMapUtils` actually generated, so the classification
/// cannot be skipped. Getting the class WRONG is caught by
/// `every_table_the_consensus_fold_writes_is_classified_derived`, which takes
/// its answer from folding real commits rather than from this list.
///
/// The deletion is a chunked sweep of point deletes rather than
/// `Map::schedule_delete_all`. That helper takes the table's first and last
/// keys and issues `schedule_delete_range(first, last)`
/// (`typed-store/src/rocks/mod.rs:1913-1925`), which lowers to
/// `delete_range_cf` over the half-open `[first, last)` and so leaves the last
/// row behind; its doc also warns that range deletions may stay visible until
/// compaction. Point deletes are unconditionally safe on both counts, and a
/// partial wipe is precisely the half-derived state this design exists to make
/// impossible.
macro_rules! epoch_state_registry {
    ($( $class:ident $field:ident : $reason:literal ),* $(,)?) => {
        /// Every per-epoch table with its class. See
        /// [`crate::authority::derived_epoch_state`].
        pub(crate) const EPOCH_STATE_REGISTRY: &[EpochStateEntry] = &[
            $(
                EpochStateEntry {
                    field: stringify!($field),
                    class: EpochStateClass::$class,
                    reason: $reason,
                },
            )*
        ];

        impl AuthorityEpochTables {
            /// Deletes every table classified [`EpochStateClass::Derived`],
            /// returning the number of rows removed per table. Callers must
            /// follow with a full replay of the epoch's commits: between this
            /// call and the replay reaching the store head the node holds no
            /// epoch-scoped derived state at all.
            pub(crate) fn wipe_derived_state(&self) -> IkaResult<Vec<(&'static str, u64)>> {
                let mut wiped = Vec::new();
                $( epoch_state_registry!(@wipe self, wiped, $class, $field); )*
                Ok(wiped)
            }

            /// Names of the derived tables that still hold rows. Empty is the
            /// startup invariant immediately after
            /// [`Self::wipe_derived_state`]; a non-empty result means the wipe
            /// did not complete and the replay would fold onto surviving
            /// state.
            pub(crate) fn non_empty_derived_tables(&self) -> Vec<&'static str> {
                let mut remaining = Vec::new();
                $( epoch_state_registry!(@check self, remaining, $class, $field); )*
                remaining
            }

            /// Every row of one table, serialized, for comparing a table
            /// against itself across a wipe-and-rebuild. Serialized rather
            /// than `Debug`-formatted because the property under test is
            /// byte-identity of the rebuilt state, not that it looks alike.
            #[cfg(test)]
            pub(crate) fn classified_table_rows(
                &self,
                field: &str,
            ) -> Vec<(Vec<u8>, Vec<u8>)> {
                $( epoch_state_registry!(@rows self, field, $field); )*
                panic!("no per-epoch table named `{field}`")
            }
        }
    };

    (@wipe $tables:ident, $wiped:ident, Derived, $field:ident) => {
        let removed = wipe_table(&$tables.$field)?;
        if removed > 0 {
            $wiped.push((stringify!($field), removed));
        }
    };
    (@wipe $tables:ident, $wiped:ident, Preserved, $field:ident) => {};

    (@check $tables:ident, $remaining:ident, Derived, $field:ident) => {
        if !$tables.$field.is_empty() {
            $remaining.push(stringify!($field));
        }
    };
    (@check $tables:ident, $remaining:ident, Preserved, $field:ident) => {};

    (@rows $tables:ident, $wanted:ident, $field:ident) => {
        if $wanted == stringify!($field) {
            return $tables
                .$field
                .safe_iter()
                .map(|row| {
                    let (key, value) = row.expect("reading a per-epoch table row");
                    (
                        bcs::to_bytes(&key).expect("serializing a per-epoch table key"),
                        bcs::to_bytes(&value).expect("serializing a per-epoch table value"),
                    )
                })
                .collect();
        }
    };
}

pub(crate) use epoch_state_registry;
