use alloy_primitives::{address, Address, U256};

use outbe_primitives::error::PrecompileError;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;

use crate::api::{get_active_version, is_version_active_eq, is_version_active_gte, version_at_height};
use crate::constants::{MIN_ACTIVATION_BUFFER, VOTING_WINDOW_BLOCKS};
use crate::precompile::{get_plan_return, proposal_status_to_abi, IUpdate};
use crate::schema::Update;
use crate::state::{normalize_version, ProposalStatus, VoteKind, VoteTally};

const PROPOSER: Address = address!("0x1111111111111111111111111111111111111111");
const VOTER_A: Address = address!("0x2222222222222222222222222222222222222222");
const VOTER_B: Address = address!("0x3333333333333333333333333333333333333333");

fn with_update<F: FnOnce(StorageHandle)>(f: F) {
    let mut provider = HashMapStorageProvider::new(1);
    let storage = StorageHandle::new(&mut provider);
    f(storage);
}

fn min_activation(current: u64) -> u64 {
    current
        .saturating_add(VOTING_WINDOW_BLOCKS)
        .saturating_add(MIN_ACTIVATION_BUFFER)
}

#[test]
fn create_plan_writes_fields_and_pending_index() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let plan_id = update
            .create_proposal(
                PROPOSER,
                "v1.2.3",
                min_activation(current),
                b"release-notes",
                current,
            )
            .unwrap();

        assert_eq!(plan_id, U256::from(1));
        let plan = update.read_plan(plan_id).unwrap().unwrap();
        assert_eq!(plan.version, "v1.2.3");
        assert_eq!(plan.proposer, PROPOSER);
        assert_eq!(plan.proposed_at_height, current);
        assert_eq!(plan.status, ProposalStatus::Pending);
        assert_eq!(plan.info, b"release-notes");
        assert_eq!(plan.tally(), VoteTally { yes: 0, no: 0 });
        assert_eq!(update.list_pending_plan_ids().unwrap(), vec![U256::from(1)]);
    });
}

#[test]
fn cast_vote_increments_counters_and_rejects_duplicate() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 50u64;
        let plan_id = update
            .create_proposal(
                PROPOSER,
                "v1.0.1",
                min_activation(current),
                b"",
                current,
            )
            .unwrap();

        update
            .cast_vote_approve(plan_id, VOTER_A, true, current + 1)
            .unwrap();
        update
            .cast_vote_approve(plan_id, VOTER_B, false, current + 2)
            .unwrap();

        let plan = update.read_plan(plan_id).unwrap().unwrap();
        assert_eq!(plan.tally(), VoteTally { yes: 1, no: 1 });

        let err = update
            .cast_vote_approve(plan_id, VOTER_A, false, current + 3)
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("already voted")
        ));
    });
}

#[test]
fn vote_kind_bool_roundtrip() {
    assert_eq!(VoteKind::from_approve(true), VoteKind::Yes);
    assert_eq!(VoteKind::from_approve(false), VoteKind::No);
    assert!(VoteKind::Yes.to_approve());
    assert!(!VoteKind::No.to_approve());
}

#[test]
fn proposal_status_abi_conversion() {
    assert_eq!(ProposalStatus::Pending.to_abi_u8(), 0);
    assert_eq!(ProposalStatus::Cancelled.to_abi_u8(), 5);
    assert_eq!(
        ProposalStatus::from_abi_u8(0).unwrap(),
        ProposalStatus::Pending
    );
    assert_eq!(
        proposal_status_to_abi(ProposalStatus::Approved),
        IUpdate::PlanStatus::Approved
    );
}

#[test]
fn get_plan_return_matches_abi_shape() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 10u64;
        let plan_id = update
            .create_proposal(
                PROPOSER,
                "v1.0.0",
                min_activation(current),
                b"meta",
                current,
            )
            .unwrap();
        let plan = update.read_plan(plan_id).unwrap().unwrap();
        let ret = get_plan_return(&plan);
        assert_eq!(ret.proposalId, plan_id);
        assert_eq!(ret.proposer, PROPOSER);
        assert_eq!(ret.proposedAtHeight, current);
        assert_eq!(ret.version, "v1.0.0");
        assert_eq!(ret.info.as_ref(), b"meta");
        assert_eq!(ret.status, IUpdate::PlanStatus::Pending);
        assert_eq!(ret.state.yes, 0);
        assert_eq!(ret.state.no, 0);
    });
}

#[test]
fn cancel_proposal_removes_pending_index() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 10u64;
        let plan_id = update
            .create_proposal(
                PROPOSER,
                "v2.0.0",
                min_activation(current),
                b"",
                current,
            )
            .unwrap();

        update.cancel_proposal(plan_id, PROPOSER, current + 1).unwrap();
        let plan = update.read_plan(plan_id).unwrap().unwrap();
        assert_eq!(plan.status, ProposalStatus::Cancelled);
        assert!(update.list_pending_plan_ids().unwrap().is_empty());
    });
}

#[test]
fn active_version_helpers_roundtrip() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        update.set_active_version("v1.5.0", 500).unwrap();

        assert_eq!(get_active_version(storage.clone()).unwrap(), Some("v1.5.0".into()));
        assert_eq!(version_at_height(storage.clone(), 500).unwrap(), Some("v1.5.0".into()));
        assert!(is_version_active_eq(storage.clone(), "v1.5.0").unwrap());
        assert!(is_version_active_gte(storage.clone(), "v1.4.9").unwrap());
        assert!(!is_version_active_eq(storage.clone(), "v1.5.1").unwrap());
    });
}

#[test]
fn rejects_downgrade_proposal() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        update.set_active_version("v2.0.0", 1).unwrap();

        let err = update
            .create_proposal(PROPOSER, "v1.9.9", min_activation(10), b"", 10)
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("downgrade")
        ));
    });
}

#[test]
fn normalize_version_lowercases_input() {
    assert_eq!(normalize_version("V1.2.3").unwrap(), "v1.2.3");
    assert!(normalize_version("1.2.3").is_err());
}

#[test]
fn precompile_abi_compiles() {
    use alloy_sol_types::SolCall;
    let _ = IUpdate::createProposalCall::SIGNATURE;
    let _ = IUpdate::castVoteCall::SIGNATURE;
    let _ = IUpdate::getActiveVersionCall::SIGNATURE;
}
