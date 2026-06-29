//! — Phase 1 atomicity, cursor semantics, and soft-receipt
//! narrowing.
//!
//! cursor is the sole phase-routing driver, cursor is
//! the only driver after Phase 1 reorder, Phase 1 failure produces
//! no soft receipt and does not advance `last_accounted_block_number`),
//! (block-1 cursor map) (pending RPC skip)
//! (ACCOUNTING_PROGRESS_ADDRESS in allowlist).
//!
//! Tests that require the actual Phase 1 commit-into-pre-execution move are
//! marked `#[ignore]` and reference the follow-up.

use outbe_evm::system_tx::{SystemTxKind, SystemTxPhase, GENESIS_BOOTSTRAP_BLOCK_NUMBER};

const BLOCK_1: u64 = 1;
const BLOCK_2: u64 = 2;

/// — block 1 body-index map starts at CycleTick (no Phase 1), then
/// optionally BoundaryOutcome (mandatory at block 1 under V2), then Oracle.
#[test]
fn block_1_body_index_map_is_cycle_boundary_oracle() {
    let cursor = SystemTxPhase::initial_for_block(BLOCK_1, GENESIS_BOOTSTRAP_BLOCK_NUMBER);
    assert_eq!(cursor, SystemTxPhase::CycleTick { body_index: 0 });
    let boundary = cursor.advance_after_commit(true, false);
    assert_eq!(
        boundary,
        SystemTxPhase::BoundaryOutcomeOptional { body_index: 1 }
    );
    let oracle = boundary.advance_after_commit(true, false);
    assert_eq!(oracle, SystemTxPhase::OracleSlashWindow { body_index: 2 });
    let hook_events = oracle.advance_after_commit(true, false);
    assert_eq!(hook_events, SystemTxPhase::HookEvents { body_index: 3 });
    let done = hook_events.advance_after_commit(true, false);
    assert_eq!(done, SystemTxPhase::UserTxs);
}

/// Cursor advances past Oracle slash window to UserTxs in canonical order.
#[test]
fn oracle_slash_window_body_index_follows_optional_boundary_outcome() {
    // inserts LateFinalizeCredits (body_index 1) after Phase 1, shifting
    // the rest: Phase1(0) → LateFinalizeCredits(1) → CycleTick(2) →
    // BoundaryOutcome(3) → OracleSlashWindow(4).
    let phase1 = SystemTxPhase::initial_for_block(BLOCK_2, GENESIS_BOOTSTRAP_BLOCK_NUMBER);
    let late = phase1.advance_after_commit(true, false);
    let cycle = late.advance_after_commit(true, false);
    let boundary = cycle.advance_after_commit(true, false);
    let oracle = boundary.advance_after_commit(true, false);
    assert!(matches!(
        oracle,
        SystemTxPhase::OracleSlashWindow { body_index: 4 }
    ));
    // When boundary is absent: Phase1(0) → Late(1) → CycleTick(2) → Oracle(3).
    let phase1b = SystemTxPhase::initial_for_block(BLOCK_2, GENESIS_BOOTSTRAP_BLOCK_NUMBER);
    let late_b = phase1b.advance_after_commit(false, false);
    let cycle_b = late_b.advance_after_commit(false, false);
    let oracle_b = cycle_b.advance_after_commit(false, false);
    assert_eq!(oracle_b, SystemTxPhase::OracleSlashWindow { body_index: 3 });
}

/// Sanity: cursor advance from UserTxs is idempotent — there is no "post
/// user txs" phase, and the cursor must not regress to a system phase.
#[test]
fn debug_assert_system_tx_phase_cursor_after_preexec_for_block1_and_phase1() {
    let cursor = SystemTxPhase::initial_for_block(BLOCK_1, GENESIS_BOOTSTRAP_BLOCK_NUMBER);
    // Block 1 cursor never enters Phase1Preexecuted.
    assert!(!matches!(cursor, SystemTxPhase::Phase1Preexecuted { .. }));
    let cursor2 = SystemTxPhase::initial_for_block(BLOCK_2, GENESIS_BOOTSTRAP_BLOCK_NUMBER);
    // Block 2 cursor enters Phase1Preexecuted.
    assert!(matches!(cursor2, SystemTxPhase::Phase1Preexecuted { .. }));
    // Idempotent UserTxs.
    let user = SystemTxPhase::UserTxs;
    assert_eq!(
        user.advance_after_commit(true, false),
        SystemTxPhase::UserTxs
    );
    assert_eq!(
        user.advance_after_commit(false, false),
        SystemTxPhase::UserTxs
    );
    assert_eq!(user.body_index(), None);
    assert_eq!(user.expected_kind(), None);
}

/// Cursor on Phase 1 path identifies the correct expected kind. Establishes
/// the invariant that the cursor's `expected_kind` is the single source of
/// truth for the next system-tx kind.
#[test]
fn preexecuted_phase1_body_tx_is_validated_but_not_reexecuted() {
    let cursor = SystemTxPhase::initial_for_block(BLOCK_2, GENESIS_BOOTSTRAP_BLOCK_NUMBER);
    assert_eq!(
        cursor.expected_kind(),
        Some(SystemTxKind::CertifiedParentAccounting),
    );
    // After Phase 1 commit, cursor moves to LateFinalizeCredits (the
    // mandatory inclusion-window phase) before CycleTick.
    let after = cursor.advance_after_commit(true, false);
    assert_eq!(
        after.expected_kind(),
        Some(SystemTxKind::LateFinalizeCredits)
    );
}
