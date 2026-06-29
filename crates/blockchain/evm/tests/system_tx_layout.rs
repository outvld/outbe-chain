//! V2 begin-zone system-tx layout invariants.
//!
//! Covers AC1/AC3/AC4 + the block-1 mandatory BoundaryOutcome rule + the
//! block-0 prohibition of begin-zone system txs. Codec-level rejection of V1
//! input bytes is tested at every legacy selector + version combination.

use outbe_evm::system_tx::{
    expected_begin_block_kinds, validate_active_system_tx_set, BodyZone, SystemTxError,
    SystemTxInputV2, SystemTxKind, SystemTxLayout, BOUNDARY_OUTCOME_SELECTOR,
    CERTIFIED_PARENT_ACCOUNTING_SELECTOR, CYCLE_TICK_SELECTOR, ORACLE_SLASH_WINDOW_SELECTOR,
    SYSTEM_TX_INPUT_VERSION,
};

/// Empty layout — used by the block-1 / block-0 layout tests that only need to
/// drive the membership check, not the structural splitter.
fn empty_layout() -> SystemTxLayout<'static> {
    SystemTxLayout {
        begin: Vec::new(),
        user: Vec::new(),
        end: Vec::new(),
    }
}

/// AC4: active selectors are present and have their fork-specific byte
/// sequences.
#[test]
fn active_selectors_have_expected_byte_sequence() {
    assert_eq!(
        CERTIFIED_PARENT_ACCOUNTING_SELECTOR,
        [0x4f, 0x53, 0x41, 0x33]
    ); // "OSA3"
    assert_eq!(CYCLE_TICK_SELECTOR, [0x4f, 0x53, 0x43, 0x32]); // "OSC2"
    assert_eq!(BOUNDARY_OUTCOME_SELECTOR, [0x4f, 0x53, 0x42, 0x32]); // "OSB2"
    assert_eq!(ORACLE_SLASH_WINDOW_SELECTOR, [0x4f, 0x53, 0x4f, 0x32]); // "OSO2"
    assert_eq!(SYSTEM_TX_INPUT_VERSION, 2);
}

/// AC4 + INV1: V2 selectors must differ from V1 byte sequences.
#[test]
fn v2_selectors_differ_from_legacy_v1_selectors() {
    let v1_selectors: [[u8; 4]; 4] = [
        *b"OSF1", // legacy FinalizationAndSlashing
        *b"OSC1", // legacy CycleTick
        *b"OSB1", // legacy BoundaryOutcome
        *b"OSO1", // legacy OracleSlashWindow
    ];
    let v2_selectors: [[u8; 4]; 4] = [
        CERTIFIED_PARENT_ACCOUNTING_SELECTOR,
        CYCLE_TICK_SELECTOR,
        BOUNDARY_OUTCOME_SELECTOR,
        ORACLE_SLASH_WINDOW_SELECTOR,
    ];
    for v1 in v1_selectors {
        assert!(
            !v2_selectors.contains(&v1),
            "V2 selector set must not contain any V1 selector bytes: {v1:?}"
        );
    }
}

/// Legacy V1 system-tx input bytes are rejected at every height.
///
/// Two failure modes proven here: (a) the V1 selector bytes (`OSF1` / `OSC1`
/// / `OSB1` / `OSO1`) are unknown to the V2 selector parser; (b) even if a
/// caller padded an unknown body with version byte `1`, the decoder rejects
/// it because `SYSTEM_TX_INPUT_VERSION == 2`.
#[test]
fn legacy_v1_system_tx_rejected_at_all_heights() {
    let v1_selectors_and_bodies: [(&[u8; 4], &[u8]); 4] = [
        (b"OSF1", b""), // FinalizationAndSlashing carried metadata; selector alone suffices for rejection.
        (b"OSC1", b""),
        (b"OSB1", b""),
        (b"OSO1", b""),
    ];
    for (selector, body) in v1_selectors_and_bodies {
        let mut bytes = Vec::with_capacity(5 + body.len());
        bytes.extend_from_slice(selector);
        bytes.push(1); // V1 version
        bytes.extend_from_slice(body);
        let err = SystemTxInputV2::decode(&bytes).expect_err("V1 selector must be rejected");
        match err {
            SystemTxError::UnknownSelector(actual) => {
                assert_eq!(
                    actual, *selector,
                    "decoder must surface the unknown V1 selector"
                );
            }
            other => panic!("expected UnknownSelector, got {other:?}"),
        }
    }

    // Also assert: a V2 selector with the legacy version byte `1` is rejected.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&CYCLE_TICK_SELECTOR);
    bytes.push(1); // wrong (legacy) version
    let err = SystemTxInputV2::decode(&bytes)
        .expect_err("V1 version byte must be rejected even under a V2 selector");
    assert!(
        matches!(err, SystemTxError::UnsupportedVersion(1)),
        "{err:?}"
    );
}

/// Block 1 under V2 must carry a BoundaryOutcome system tx (genesis bootstrap).
#[test]
fn block_1_layout_requires_boundary_outcome_for_v2() {
    let err = validate_active_system_tx_set(&empty_layout(), 1, false, false)
        .expect_err("block 1 without BoundaryOutcome must be rejected under V2");
    assert!(
        matches!(err, SystemTxError::V2Block1MissingBoundaryOutcome),
        "{err:?}",
    );

    // Expected kinds at block 1 with BoundaryOutcome present:
    let expected = expected_begin_block_kinds(1, true, false);
    assert_eq!(
        expected,
        vec![
            SystemTxKind::CycleTick,
            SystemTxKind::BoundaryOutcome,
            SystemTxKind::OracleSlashWindow,
            SystemTxKind::HookEvents,
        ],
        "block 1 V2 layout must include CycleTick, BoundaryOutcome, OracleSlashWindow, HookEvents",
    );
}

/// Block 0 must not carry any begin-zone system tx under V2.
#[test]
fn block_0_has_no_begin_zone_system_txs_under_v2() {
    // Membership check accepts an empty layout at block 0 regardless of
    // `has_boundary_outcome` (genesis cannot be a boundary parent of itself).
    validate_active_system_tx_set(&empty_layout(), 0, false, false)
        .expect("empty layout at block 0 must be accepted under V2");
    validate_active_system_tx_set(&empty_layout(), 0, true, false)
        .expect("empty layout at block 0 must be accepted even if has_boundary_outcome is true");

    let expected = expected_begin_block_kinds(0, false, false);
    assert!(
        expected.is_empty(),
        "block 0 must have no expected begin-zone system tx kinds; got {expected:?}",
    );
    let expected_with_bo = expected_begin_block_kinds(0, true, false);
    assert!(
        expected_with_bo.is_empty(),
        "block 0 must have no expected begin-zone system tx kinds even with has_boundary_outcome=true; got {expected_with_bo:?}",
    );
}

/// V2 begin-zone ordering: CertifiedParentAccounting (≥2), CycleTick (≥1),
/// BoundaryOutcome (when present), OracleSlashWindow (≥1).
#[test]
fn v2_begin_zone_ordering_is_canonical() {
    // Block 2+ canonical layout (no BoundaryOutcome on the parent).
    let expected = expected_begin_block_kinds(2, false, false);
    assert_eq!(
        expected,
        vec![
            SystemTxKind::CertifiedParentAccounting,
            SystemTxKind::LateFinalizeCredits,
            SystemTxKind::CycleTick,
            SystemTxKind::OracleSlashWindow,
            SystemTxKind::HookEvents,
        ],
    );

    // Block 2+ with BoundaryOutcome present (e.g. epoch boundary).
    let expected = expected_begin_block_kinds(42, true, false);
    assert_eq!(
        expected,
        vec![
            SystemTxKind::CertifiedParentAccounting,
            SystemTxKind::LateFinalizeCredits,
            SystemTxKind::CycleTick,
            SystemTxKind::BoundaryOutcome,
            SystemTxKind::OracleSlashWindow,
            SystemTxKind::HookEvents,
        ],
    );

    // All begin-zone kinds resolve to BeginBlock body zone.
    for kind in [
        SystemTxKind::CertifiedParentAccounting,
        SystemTxKind::LateFinalizeCredits,
        SystemTxKind::CycleTick,
        SystemTxKind::BoundaryOutcome,
        SystemTxKind::OracleSlashWindow,
        SystemTxKind::HookEvents,
    ] {
        assert_eq!(kind.body_zone(), BodyZone::BeginBlock);
        assert!(kind.begin_order().is_some());
        assert!(kind.end_order().is_none());
    }
}
