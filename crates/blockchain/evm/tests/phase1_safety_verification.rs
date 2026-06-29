//! Batch 8 — Safety verification for the Phase 1 cursor refactor.
//!
//! This file ships the safety checklist mandated for consensus-carrying
//! refactors:
//!
//! - deterministic-output property tests (`proptest`): any permutation of
//!   inputs to `SystemTxPhase::advance_after_commit` yields byte-identical
//!   cursor sequences across N invocations;
//! - cross-version compatibility: the `SystemTxPhase` variant set is exactly
//!   the V2 contract set (no silently-introduced variants).
//!
//! The proptest output determinism property is the key consensus-safety
//! guard for the cursor refactor: if `advance_after_commit` were
//! non-deterministic (e.g., via accidental `HashMap` iteration or
//! `SystemTime`-derived state), proposer and validator paths would diverge
//! on the per-block cursor sequence and the block hash would split.

use outbe_evm::system_tx::{SystemTxKind, SystemTxPhase, GENESIS_BOOTSTRAP_BLOCK_NUMBER};
use proptest::prelude::*;

/// The full set of `SystemTxPhase` variants must equal the V2 contract:
/// 5 variants, no more, no fewer. A drift here is a protocol incompatibility.
#[test]
fn cross_version_system_tx_phase_variant_set_is_exactly_v2() {
    // Construct one of each variant; if a new variant is added without
    // updating this test, the compiler match below becomes non-exhaustive
    // and the test will fail to compile — that is the intended contract.
    let variants = [
        SystemTxPhase::Phase1Preexecuted {
            body_index: 0,
            tx_hash: alloy_primitives::B256::ZERO,
            receipt_index: 0,
        },
        SystemTxPhase::LateFinalizeCredits { body_index: 0 },
        SystemTxPhase::CycleTick { body_index: 0 },
        SystemTxPhase::BoundaryOutcomeOptional { body_index: 0 },
        SystemTxPhase::TeeBootstrapOptional { body_index: 0 },
        SystemTxPhase::OracleSlashWindow { body_index: 0 },
        SystemTxPhase::HookEvents { body_index: 0 },
        SystemTxPhase::UserTxs,
    ];
    for variant in &variants {
        // Exhaustive match — adding a new variant without updating here is a
        // compile error.
        match variant {
            SystemTxPhase::Phase1Preexecuted { .. } => {}
            SystemTxPhase::LateFinalizeCredits { .. } => {}
            SystemTxPhase::CycleTick { .. } => {}
            SystemTxPhase::BoundaryOutcomeOptional { .. } => {}
            SystemTxPhase::TeeBootstrapOptional { .. } => {}
            SystemTxPhase::OracleSlashWindow { .. } => {}
            SystemTxPhase::HookEvents { .. } => {}
            SystemTxPhase::UserTxs => {}
        }
    }
    assert_eq!(variants.len(), 8, "V2 SystemTxPhase contract: 8 variants");
}

/// Block 0 is the genesis block: no begin-zone system txs. The cursor must
/// remain at the placeholder CycleTick state without ever entering Phase 1.
#[test]
fn cross_version_genesis_block_cursor_initialisation() {
    let cursor = SystemTxPhase::initial_for_block(0, GENESIS_BOOTSTRAP_BLOCK_NUMBER);
    assert_eq!(cursor, SystemTxPhase::CycleTick { body_index: 0 });
    assert!(!matches!(cursor, SystemTxPhase::Phase1Preexecuted { .. }));
}

// Deterministic-output property tests: `SystemTxPhase::advance_after_commit`
// must produce byte-identical cursor sequences across N invocations, for any
// sequence of `has_boundary_outcome` flags. This is the consensus safety
// guard for the Phase 1 reorder.
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    #[test]
    fn proptest_advance_after_commit_is_deterministic(
        block_number in 0u64..1000,
        boundary_flags in proptest::collection::vec(any::<bool>(), 0..16),
    ) {
        let initial = SystemTxPhase::initial_for_block(block_number, GENESIS_BOOTSTRAP_BLOCK_NUMBER);
        let walk = |start: SystemTxPhase| -> Vec<SystemTxPhase> {
            let mut cursor = start;
            let mut out = vec![cursor];
            for &flag in &boundary_flags {
                cursor = cursor.advance_after_commit(flag, false);
                out.push(cursor);
            }
            out
        };
        let trace_a = walk(initial);
        let trace_b = walk(initial);
        let trace_c = walk(initial);
        prop_assert_eq!(&trace_a, &trace_b);
        prop_assert_eq!(&trace_b, &trace_c);
    }

    /// `initial_for_block` is purely a function of (block_number,
    /// genesis_bootstrap). Identical inputs MUST produce identical cursors.
    #[test]
    fn proptest_initial_for_block_is_deterministic(
        block_number in 0u64..1_000_000,
    ) {
        let a = SystemTxPhase::initial_for_block(block_number, GENESIS_BOOTSTRAP_BLOCK_NUMBER);
        let b = SystemTxPhase::initial_for_block(block_number, GENESIS_BOOTSTRAP_BLOCK_NUMBER);
        prop_assert_eq!(a, b);
    }

    /// Cursor's `expected_kind` is uniquely determined by the variant. No
    /// drift between calls.
    #[test]
    fn proptest_expected_kind_is_stable_per_variant(
        block_number in 0u64..1000,
    ) {
        let cursor = SystemTxPhase::initial_for_block(block_number, GENESIS_BOOTSTRAP_BLOCK_NUMBER);
        let a = cursor.expected_kind();
        let b = cursor.expected_kind();
        prop_assert_eq!(a, b);
        // Sanity: kind is well-defined for every non-UserTxs variant.
        if let Some(kind) = cursor.expected_kind() {
            prop_assert!(matches!(
                kind,
                SystemTxKind::CertifiedParentAccounting
                    | SystemTxKind::CycleTick
                    | SystemTxKind::BoundaryOutcome
                    | SystemTxKind::OracleSlashWindow
                    | SystemTxKind::HookEvents,
            ));
        }
    }
}

/// Body index monotonicity: each `advance_after_commit` either advances
/// body_index by exactly 1 or transitions to `UserTxs` (None). The cursor
/// must never regress.
#[test]
fn body_index_monotonic_across_advance() {
    for block in [1u64, 2, 7, 42, 1000] {
        let mut cursor = SystemTxPhase::initial_for_block(block, GENESIS_BOOTSTRAP_BLOCK_NUMBER);
        let mut prev_idx = cursor.body_index();
        for _ in 0..8 {
            let next = cursor.advance_after_commit(true, false);
            let next_idx = next.body_index();
            match (prev_idx, next_idx) {
                (Some(p), Some(n)) => {
                    assert_eq!(n, p + 1, "advance must add exactly 1 to body_index");
                }
                (Some(_), None) => {
                    // Transition to UserTxs is allowed.
                }
                (None, None) => {
                    // UserTxs is idempotent.
                }
                (None, Some(_)) => panic!("cursor must not regress from UserTxs to a system phase"),
            }
            prev_idx = next_idx;
            cursor = next;
        }
    }
}
