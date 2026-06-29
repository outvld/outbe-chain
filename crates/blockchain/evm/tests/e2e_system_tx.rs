use alloy_consensus::{SignableTransaction as _, Transaction as _, TxLegacy};
use alloy_primitives::{address, Address, Bytes, Signature, TxKind, B256, U256};
use outbe_evm::system_tx::{
    build_unsigned_system_tx, split_system_layout, system_tx_visible_gas_limit,
    validate_active_system_tx_set, SystemTxInputV2, SystemTxKind, MAX_SYSTEM_TXS_PER_BLOCK,
    SYSTEM_TX_ARTIFACT_GAS_LIMIT, SYSTEM_TX_VISIBLE_GAS_FLOOR,
};
use outbe_primitives::{
    consensus::{DkgBoundaryArtifact, ReshareResult, OUTBE_MAX_EXTRA_DATA_SIZE},
    consensus_metadata::{CertifiedParentAccountingMetadata, ParentParticipationProof},
};
use reth_ethereum::TransactionSigned;

const CHAIN_ID: u64 = 2026;
const BLOCK_NUMBER: u64 = 42;
const USER_BLOCK_GAS_LIMIT: u64 = 30_000_000;

fn numbered_address(n: u64) -> Address {
    let mut bytes = [0u8; 20];
    bytes[12..].copy_from_slice(&n.to_be_bytes());
    Address::from(bytes)
}

fn sample_metadata() -> CertifiedParentAccountingMetadata {
    CertifiedParentAccountingMetadata {
        finalized_block_number: BLOCK_NUMBER - 1,
        finalized_block_hash: B256::repeat_byte(0x41),
        finalized_epoch: 7,
        finalized_view: 42,
        parent_view: 41,
        ordered_committee: vec![address!("0x1111111111111111111111111111111111111111")],
        signer_bitmap: vec![1],
        proof: Bytes::from_static(b"cert"),
        committee_set_hash: B256::repeat_byte(0x77),
        vrf_material_version: 3,
        vrf_group_public_key_hash: B256::repeat_byte(0x88),
        proof_kind: ParentParticipationProof::Finalization,
        // V2 contract requires `missed_proposers` to be empty.
        missed_proposers: Vec::new(),
    }
}

fn large_metadata() -> CertifiedParentAccountingMetadata {
    const COMMITTEE_SIZE: usize = 128;
    let ordered_committee = (0..COMMITTEE_SIZE)
        .map(|idx| numbered_address(10_000 + idx as u64))
        .collect::<Vec<_>>();
    CertifiedParentAccountingMetadata {
        ordered_committee,
        signer_bitmap: vec![1; COMMITTEE_SIZE],
        proof: Bytes::from(vec![0xAB; OUTBE_MAX_EXTRA_DATA_SIZE - 1_024]),
        ..sample_metadata()
    }
}

fn sample_boundary() -> DkgBoundaryArtifact {
    DkgBoundaryArtifact {
        epoch: 8,
        dkg_cycle: 2,
        freeze_height: BLOCK_NUMBER - 2,
        planned_activation_height: BLOCK_NUMBER,
        target_set_hash: B256::repeat_byte(0x33),
        vrf_material_version: 3,
        vrf_group_public_key: B256::repeat_byte(0x44),
        vrf_group_public_key_bytes: Bytes::from_static(&[0x44u8; 96]),
        committee_set_hash: B256::repeat_byte(0x66),
        is_validator_set_change: true,
        outcome: Bytes::from_static(b"boundary"),
        is_full_dkg: false,
        tee_recipient_pubkeys: Vec::new(),
        tee_reshare_registrations: Vec::new(),
        endorsement_signature: alloy_primitives::Bytes::new(),
        reshare: ReshareResult {
            new_active_set: vec![address!("0x3333333333333333333333333333333333333333")],
            active_set_hash: B256::repeat_byte(0x55),
        },
    }
}

fn large_boundary() -> DkgBoundaryArtifact {
    const ACTIVE_SET_SIZE: usize = 128;
    let mut artifact = sample_boundary();
    artifact.reshare.new_active_set = (0..ACTIVE_SET_SIZE)
        .map(|idx| numbered_address(20_000 + idx as u64))
        .collect();
    artifact.outcome = Bytes::from(vec![0xCD; OUTBE_MAX_EXTRA_DATA_SIZE - 4_000]);
    artifact.vrf_group_public_key_bytes = Bytes::from(vec![0x44; 96]);
    artifact
}

fn input_for(kind: SystemTxKind) -> SystemTxInputV2 {
    match kind {
        SystemTxKind::CertifiedParentAccounting => SystemTxInputV2::CertifiedParentAccounting {
            metadata: sample_metadata(),
        },
        SystemTxKind::LateFinalizeCredits => SystemTxInputV2::LateFinalizeCredits {
            artifact: outbe_primitives::reshare_artifact::LateFinalizeCreditsArtifact::default(),
        },
        SystemTxKind::CycleTick => SystemTxInputV2::CycleTick,
        SystemTxKind::BoundaryOutcome => SystemTxInputV2::BoundaryOutcome {
            artifact: sample_boundary(),
        },
        SystemTxKind::TeeBootstrap => SystemTxInputV2::TeeBootstrap {
            payload: outbe_primitives::tee_bootstrap::TeeBootstrapPayload {
                policy_hash: B256::ZERO,
                committee_snapshot_hash: B256::ZERO,
                committee_snapshot_block: BLOCK_NUMBER,
                key_epoch: 0,
                tribute_offer_epoch: 0,
                dkg_transcript_hash: B256::ZERO,
                tribute_offer_public_key: B256::ZERO,
                tribute_offer_group_public_key: alloy_primitives::Bytes::new(),
                registrations: Vec::new(),
                policy: outbe_primitives::tee_bootstrap::TeePolicy::default(),
                validator_signatures: Vec::new(),
            },
        },
        SystemTxKind::OracleSlashWindow => SystemTxInputV2::OracleSlashWindow,
        SystemTxKind::HookEvents => SystemTxInputV2::HookEvents,
    }
}

fn signed_system_tx(kind: SystemTxKind, ordinal: u8, input: SystemTxInputV2) -> TransactionSigned {
    let input = input.encode().expect("system input encodes");
    build_unsigned_system_tx(kind, ordinal, BLOCK_NUMBER, CHAIN_ID, input)
        .expect("system tx builds")
        .into_signed(Signature::test_signature())
        .into()
}

fn system_tx(kind: SystemTxKind, ordinal: u8) -> TransactionSigned {
    signed_system_tx(kind, ordinal, input_for(kind))
}

fn user_tx() -> TransactionSigned {
    TxLegacy {
        chain_id: Some(CHAIN_ID),
        nonce: 0,
        gas_price: 0,
        gas_limit: 21_000,
        to: TxKind::Call(address!("0x4444444444444444444444444444444444444444")),
        value: U256::ZERO,
        input: Bytes::new(),
    }
    .into_signed(Signature::test_signature())
    .into()
}

#[test]
fn full_begin_system_prefix_validates_before_user_transactions() {
    let txs = vec![
        system_tx(SystemTxKind::CertifiedParentAccounting, 0),
        system_tx(SystemTxKind::LateFinalizeCredits, 1),
        system_tx(SystemTxKind::CycleTick, 2),
        system_tx(SystemTxKind::BoundaryOutcome, 3),
        system_tx(SystemTxKind::OracleSlashWindow, 4),
        system_tx(SystemTxKind::HookEvents, 5),
        user_tx(),
    ];

    let layout = split_system_layout(&txs).expect("layout splits");
    validate_active_system_tx_set(&layout, BLOCK_NUMBER, true, false)
        .expect("full system tx set validates");

    assert_eq!(
        layout
            .begin_block_kinds()
            .expect("begin_block kinds decode"),
        vec![
            SystemTxKind::CertifiedParentAccounting,
            SystemTxKind::LateFinalizeCredits,
            SystemTxKind::CycleTick,
            SystemTxKind::BoundaryOutcome,
            SystemTxKind::OracleSlashWindow,
            SystemTxKind::HookEvents,
        ]
    );
    assert_eq!(layout.user.len(), 1);
    assert!(layout.end.is_empty());
}

#[test]
fn missing_or_extra_receipt_visible_system_txs_are_rejected() {
    let missing_oracle = vec![
        system_tx(SystemTxKind::CertifiedParentAccounting, 0),
        system_tx(SystemTxKind::CycleTick, 1),
        system_tx(SystemTxKind::BoundaryOutcome, 2),
    ];
    let layout = split_system_layout(&missing_oracle).expect("layout splits");
    assert!(validate_active_system_tx_set(&layout, BLOCK_NUMBER, true, false).is_err());

    let unexpected_boundary = vec![
        system_tx(SystemTxKind::CertifiedParentAccounting, 0),
        system_tx(SystemTxKind::CycleTick, 1),
        system_tx(SystemTxKind::BoundaryOutcome, 2),
        system_tx(SystemTxKind::OracleSlashWindow, 3),
        system_tx(SystemTxKind::HookEvents, 4),
    ];
    let layout = split_system_layout(&unexpected_boundary).expect("layout splits");
    assert!(validate_active_system_tx_set(&layout, BLOCK_NUMBER, false, false).is_err());
}

#[test]
fn system_tx_wire_limits_leave_runtime_gas_headroom() {
    assert_eq!(MAX_SYSTEM_TXS_PER_BLOCK, 16);
    assert_eq!(SYSTEM_TX_ARTIFACT_GAS_LIMIT, 10_000_000_000);

    for (ordinal, kind) in [
        SystemTxKind::CertifiedParentAccounting,
        SystemTxKind::LateFinalizeCredits,
        SystemTxKind::CycleTick,
        SystemTxKind::BoundaryOutcome,
        SystemTxKind::OracleSlashWindow,
        SystemTxKind::HookEvents,
    ]
    .into_iter()
    .enumerate()
    {
        let tx = system_tx(kind, ordinal.try_into().expect("ordinal fits"));
        assert_eq!(
            tx.gas_limit(),
            system_tx_visible_gas_limit(tx.input()).expect("visible system gas computes")
        );
        assert!(tx.gas_limit() >= SYSTEM_TX_VISIBLE_GAS_FLOOR);
        assert!(tx.gas_limit() < USER_BLOCK_GAS_LIMIT);
        assert!(tx.gas_limit() < SYSTEM_TX_ARTIFACT_GAS_LIMIT);
        assert_eq!(
            tx.nonce(),
            BLOCK_NUMBER * u64::from(MAX_SYSTEM_TXS_PER_BLOCK) + ordinal as u64
        );
    }
}

#[test]
fn gas_12_system_prefix_aggregate_visible_gas_must_fit_block_cap() {
    let txs = vec![
        signed_system_tx(
            SystemTxKind::CertifiedParentAccounting,
            0,
            SystemTxInputV2::CertifiedParentAccounting {
                metadata: large_metadata(),
            },
        ),
        // mandatory phase. The realistic per-block late-credit count is
        // <= K (a few in-window targets), so an empty/small artifact here keeps
        // the worst case dominated by CPA + BoundaryOutcome.
        signed_system_tx(
            SystemTxKind::LateFinalizeCredits,
            1,
            SystemTxInputV2::LateFinalizeCredits {
                artifact: Default::default(),
            },
        ),
        signed_system_tx(SystemTxKind::CycleTick, 2, SystemTxInputV2::CycleTick),
        signed_system_tx(
            SystemTxKind::BoundaryOutcome,
            3,
            SystemTxInputV2::BoundaryOutcome {
                artifact: large_boundary(),
            },
        ),
        signed_system_tx(
            SystemTxKind::OracleSlashWindow,
            4,
            SystemTxInputV2::OracleSlashWindow,
        ),
        signed_system_tx(SystemTxKind::HookEvents, 5, SystemTxInputV2::HookEvents),
    ];
    let layout = split_system_layout(&txs).expect("worst-case system prefix layout splits");
    validate_active_system_tx_set(&layout, BLOCK_NUMBER, true, false)
        .expect("worst-case active system tx set validates");
    assert_eq!(txs.len(), 6);
    assert!(txs.len() <= usize::from(MAX_SYSTEM_TXS_PER_BLOCK));

    let aggregate_envelope_gas: u64 = txs.iter().map(|tx| tx.gas_limit()).sum();
    for tx in &txs {
        assert_eq!(
            tx.gas_limit(),
            system_tx_visible_gas_limit(tx.input()).expect("visible system gas computes"),
            "GAS-12: each worst-case system tx must carry deterministic visible gas"
        );
        assert!(tx.gas_limit() >= SYSTEM_TX_VISIBLE_GAS_FLOOR);
        assert!(tx.gas_limit() < SYSTEM_TX_ARTIFACT_GAS_LIMIT);
    }

    assert!(
        aggregate_envelope_gas <= USER_BLOCK_GAS_LIMIT,
        "GAS-12: worst-case visible begin-zone system envelope gas {aggregate_envelope_gas} \
         exceeds the block gas limit {USER_BLOCK_GAS_LIMIT}"
    );
}

#[test]
fn gas_15_visible_system_tx_gas_must_not_exceed_visible_block_gas_limit_for_generic_replay() {
    let cycle = system_tx(SystemTxKind::CycleTick, 1);

    assert!(
        cycle.gas_limit() <= USER_BLOCK_GAS_LIMIT,
        "GAS-15: visible system tx gas {} exceeds visible block gas limit {USER_BLOCK_GAS_LIMIT}; \
         stock Ethereum replay/import will not treat this as a normal user tx",
        cycle.gas_limit()
    );
    assert_eq!(
        cycle.gas_limit(),
        system_tx_visible_gas_limit(cycle.input()).expect("visible gas computes")
    );
    assert!(cycle.gas_limit() >= SYSTEM_TX_VISIBLE_GAS_FLOOR);
    assert!(cycle.gas_limit() < SYSTEM_TX_ARTIFACT_GAS_LIMIT);
}
