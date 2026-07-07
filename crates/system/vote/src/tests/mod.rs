use alloy_primitives::{address, Address, U256};

use outbe_primitives::addresses::UPDATE_ADDRESS;
use outbe_primitives::block::{BlockContext, BlockRuntimeContext};
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;
use outbe_validatorset::contract::ValidatorSet;
use outbe_validatorset::logic::status;

use crate::api::{get_proposal, get_proposal_voters, list_proposals, list_proposals_by_status};
use crate::constants::VOTING_WINDOW_BLOCKS;
use crate::errors::VoteError;
use crate::handlers::{VoteTarget, VoteTargetRegistry};
use crate::runtime::quorum_reached;
use crate::schema::ProposalStatus;
use crate::schema::Vote;
use crate::state::{calculate_vote_tally, vote_key, VoteKind, VoteTally};
use outbe_update::constants::MIN_ACTIVATION_BUFFER;
use outbe_update::encode_protocol_version;
use outbe_update::payload::encode_schedule_update_json;
use outbe_update::ProtocolVersion;
use serde_json::Value;

struct TestUpdateVoteTarget;

impl VoteTarget for TestUpdateVoteTarget {
    fn target_module(&self) -> Address {
        UPDATE_ADDRESS
    }

    fn validate(&self, payload: &Value, _current_height: u64, _chain_id: u64) -> Result<()> {
        if payload.is_object() {
            Ok(())
        } else {
            Err(VoteError::InvalidPayload.into())
        }
    }

    fn handle_approved(
        &self,
        _ctx: &BlockRuntimeContext,
        _proposal_id: U256,
        _payload: &Value,
    ) -> Result<()> {
        Ok(())
    }
}

static TEST_UPDATE_VOTE_TARGET: TestUpdateVoteTarget = TestUpdateVoteTarget;
static TEST_VOTE_HANDLERS: &[&dyn VoteTarget] = &[&TEST_UPDATE_VOTE_TARGET];
static TEST_VOTE_REGISTRY: VoteTargetRegistry = VoteTargetRegistry::new(TEST_VOTE_HANDLERS);

pub(super) fn test_vote_registry() -> &'static VoteTargetRegistry {
    &TEST_VOTE_REGISTRY
}

pub(super) fn create_proposal_test(
    vote: &mut Vote<'_>,
    proposer: Address,
    target_module: Address,
    payload: &str,
    current_height: u64,
) -> Result<U256> {
    vote.create_proposal(
        proposer,
        target_module,
        payload,
        current_height,
        test_vote_registry(),
    )
}

pub(super) const PROPOSER: Address = address!("0x1111111111111111111111111111111111111111");
pub(super) const VOTER_A: Address = address!("0x2222222222222222222222222222222222222222");
pub(super) const VOTER_B: Address = address!("0x3333333333333333333333333333333333333333");
pub(super) const PENDING_VOTER: Address = address!("0x4444444444444444444444444444444444444444");
pub(super) const VALIDATOR_OWNER: Address = address!("0xffffffffffffffffffffffffffffffffffffffff");

mod guards;
mod precompile;

fn dummy_pubkey(seed: u8) -> [u8; 48] {
    let mut pk = [0u8; 48];
    pk[0] = seed;
    pk
}

pub(super) fn register_active_validator(storage: StorageHandle, addr: Address, seed: u8) {
    let mut vs = ValidatorSet::new(storage.clone());
    vs.config_owner.write(VALIDATOR_OWNER).unwrap();
    vs.config_max_validators.write(100).unwrap();
    vs.register_validator(VALIDATOR_OWNER, addr, &dummy_pubkey(seed))
        .unwrap();
    vs.activate_validator(addr).unwrap();
}

pub(super) fn register_pending_validator(storage: StorageHandle, addr: Address, seed: u8) {
    let mut vs = ValidatorSet::new(storage.clone());
    vs.config_owner.write(VALIDATOR_OWNER).unwrap();
    vs.config_max_validators.write(100).unwrap();
    vs.register_validator(VALIDATOR_OWNER, addr, &dummy_pubkey(seed))
        .unwrap();
    vs.mark_pending(addr).unwrap();
    assert_eq!(
        vs.val_status.read(&addr).unwrap(),
        status::PENDING,
        "fixture must leave validator in PENDING status"
    );
}

pub(super) fn setup_default_validators(storage: StorageHandle) {
    register_active_validator(storage.clone(), PROPOSER, 1);
    register_active_validator(storage.clone(), VOTER_A, 2);
    register_active_validator(storage.clone(), VOTER_B, 3);
}

pub(super) fn min_activation_at(height: u64) -> u64 {
    height.saturating_add(MIN_ACTIVATION_BUFFER)
}

pub(super) fn update_json_payload(
    version: ProtocolVersion,
    activation_height: u64,
    info: &str,
) -> String {
    encode_schedule_update_json(version, activation_height, info)
}

pub(super) fn empty_update_payload(current_height: u64) -> String {
    update_json_payload(
        encode_protocol_version(1, 2),
        min_activation_at(current_height),
        "",
    )
}

pub(super) fn with_vote<F: FnOnce(StorageHandle)>(f: F) {
    let mut provider = HashMapStorageProvider::new(1);
    let storage = StorageHandle::new(&mut provider);
    setup_default_validators(storage.clone());
    f(storage);
}

fn block_ctx(storage: StorageHandle, block_number: u64) -> BlockRuntimeContext {
    BlockRuntimeContext::new(BlockContext::empty_for_tests(block_number, 0, 1), storage)
}

pub(super) trait VoteTestExt {
    fn process_begin_block_test(&mut self, block_number: u64) -> Result<()>;
}

impl VoteTestExt for Vote<'_> {
    fn process_begin_block_test(&mut self, block_number: u64) -> Result<()> {
        let ctx = block_ctx(self.storage.clone(), block_number);
        self.process_begin_block(&ctx, test_vote_registry())
    }
}

#[test]
fn proposal_status_storage_roundtrip() {
    assert_eq!(ProposalStatus::Pending.to_u8(), 0);
    assert_eq!(ProposalStatus::Expired.to_u8(), 3);
    assert_eq!(
        ProposalStatus::from_u8(ProposalStatus::Approved.to_u8()).unwrap(),
        ProposalStatus::Approved
    );
    assert!(ProposalStatus::Approved.is_terminal());
    assert!(!ProposalStatus::Pending.is_terminal());
    assert!(ProposalStatus::from_u8(4).is_err());
}

#[test]
fn vote_kind_bool_roundtrip() {
    assert_eq!(VoteKind::from_approve(true), VoteKind::Yes);
    assert_eq!(VoteKind::from_approve(false), VoteKind::No);
    assert!(VoteKind::Yes.to_approve());
    assert!(!VoteKind::No.to_approve());
}

#[test]
fn quorum_uses_two_thirds_threshold() {
    assert!(!quorum_reached(0, 0));
    assert!(!quorum_reached(2, 4));
    assert!(quorum_reached(3, 4));
    assert!(quorum_reached(2, 3));
}

#[test]
fn vote_key_depends_on_proposal_and_voter() {
    let voter_a = address!("0x1111111111111111111111111111111111111111");
    let voter_b = address!("0x2222222222222222222222222222222222222222");

    assert_ne!(
        vote_key(U256::from(1), voter_a),
        vote_key(U256::from(2), voter_a)
    );
    assert_ne!(
        vote_key(U256::from(1), voter_a),
        vote_key(U256::from(1), voter_b)
    );
}

#[test]
fn write_vote_appends_ordered_voters() {
    with_vote(|storage| {
        let mut governance = Vote::new(storage.clone());
        let current = 10u64;
        let proposal_id = create_proposal_test(
            &mut governance,
            PROPOSER,
            UPDATE_ADDRESS,
            &empty_update_payload(current),
            current,
        )
        .unwrap();

        governance
            .cast_vote_approve(proposal_id, VOTER_A, true, current + 1)
            .unwrap();
        governance
            .cast_vote_approve(proposal_id, VOTER_B, false, current + 2)
            .unwrap();

        assert_eq!(
            governance.read_proposal_voters(proposal_id).unwrap(),
            vec![VOTER_A, VOTER_B]
        );
        assert_eq!(
            governance.read_proposal_voters(proposal_id).unwrap().len(),
            2
        );
        assert_eq!(
            governance
                .votes_map
                .read(&vote_key(proposal_id, VOTER_A))
                .unwrap(),
            1
        );
        assert_eq!(
            governance
                .votes_map
                .read(&vote_key(proposal_id, VOTER_B))
                .unwrap(),
            2
        );
    });
}

#[test]
fn duplicate_vote_is_rejected() {
    with_vote(|storage| {
        let mut governance = Vote::new(storage.clone());
        let current = 20u64;
        let proposal_id = create_proposal_test(
            &mut governance,
            PROPOSER,
            UPDATE_ADDRESS,
            &empty_update_payload(current),
            current,
        )
        .unwrap();

        governance
            .cast_vote_approve(proposal_id, VOTER_A, true, current + 1)
            .unwrap();

        let err = governance
            .cast_vote_approve(proposal_id, VOTER_A, false, current + 2)
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("already voted")
        ));

        assert_eq!(
            governance.read_proposal_voters(proposal_id).unwrap(),
            vec![VOTER_A]
        );
    });
}

#[test]
fn get_proposal_voters_pagination_is_deterministic() {
    with_vote(|storage| {
        let mut governance = Vote::new(storage.clone());
        let current = 30u64;
        let proposal_id = create_proposal_test(
            &mut governance,
            PROPOSER,
            UPDATE_ADDRESS,
            &empty_update_payload(current),
            current,
        )
        .unwrap();

        governance
            .cast_vote_approve(proposal_id, VOTER_A, true, current + 1)
            .unwrap();
        governance
            .cast_vote_approve(proposal_id, VOTER_B, false, current + 2)
            .unwrap();

        assert_eq!(
            get_proposal_voters(storage.clone(), proposal_id, U256::ZERO, U256::from(1)).unwrap(),
            vec![VOTER_A]
        );
        assert_eq!(
            get_proposal_voters(storage.clone(), proposal_id, U256::from(1), U256::from(1))
                .unwrap(),
            vec![VOTER_B]
        );
        assert_eq!(
            get_proposal_voters(storage.clone(), proposal_id, U256::from(1), U256::from(10))
                .unwrap(),
            vec![VOTER_B]
        );
        assert!(
            get_proposal_voters(storage, proposal_id, U256::from(2), U256::from(1))
                .unwrap()
                .is_empty()
        );
    });
}

#[test]
fn get_proposal_uses_active_set_at_read_time() {
    with_vote(|storage| {
        let mut governance = Vote::new(storage.clone());
        let current = 40u64;
        let proposal_id = create_proposal_test(
            &mut governance,
            PROPOSER,
            UPDATE_ADDRESS,
            &empty_update_payload(current),
            current,
        )
        .unwrap();

        governance
            .cast_vote_approve(proposal_id, VOTER_A, true, current + 1)
            .unwrap();
        governance
            .cast_vote_approve(proposal_id, VOTER_B, true, current + 2)
            .unwrap();

        let info = get_proposal(storage.clone(), proposal_id).unwrap().unwrap();
        assert_eq!(info.state, VoteTally { yes: 2, no: 0 });
        assert_eq!(info.voters_count, 2);

        ValidatorSet::new(storage.clone())
            .deactivate_validator(VALIDATOR_OWNER, VOTER_A)
            .unwrap();

        let info = get_proposal(storage, proposal_id).unwrap().unwrap();
        assert_eq!(info.state, VoteTally { yes: 1, no: 0 });
        assert_eq!(info.voters_count, 2);
    });
}

#[test]
fn inactive_voter_is_ignored_at_deadline_tally() {
    with_vote(|storage| {
        let mut governance = Vote::new(storage.clone());
        let current = 100u64;
        let deadline = current + VOTING_WINDOW_BLOCKS + 1;
        let version = encode_protocol_version(1, 2);
        let activation = deadline.saturating_add(MIN_ACTIVATION_BUFFER);
        let payload = update_json_payload(version, activation, "");
        let proposal_id =
            create_proposal_test(&mut governance, PROPOSER, UPDATE_ADDRESS, &payload, current)
                .unwrap();

        governance
            .cast_vote_approve(proposal_id, VOTER_A, true, current + 1)
            .unwrap();

        ValidatorSet::new(storage.clone())
            .deactivate_validator(VALIDATOR_OWNER, VOTER_A)
            .unwrap();

        governance
            .cast_vote_approve(proposal_id, PROPOSER, true, current + 2)
            .unwrap();
        governance
            .cast_vote_approve(proposal_id, VOTER_B, true, current + 3)
            .unwrap();

        let deadline = current + VOTING_WINDOW_BLOCKS + 1;
        governance.process_begin_block_test(deadline).unwrap();

        let record = governance.proposals.get(proposal_id).unwrap().unwrap();
        assert_eq!(record.proposal_status().unwrap(), ProposalStatus::Approved);

        let active = crate::state::active_validator_addresses(storage.clone()).unwrap();
        let tally = calculate_vote_tally(&governance, &record, &active).unwrap();
        assert_eq!(tally, VoteTally { yes: 2, no: 0 });
        assert_eq!(
            governance.read_proposal_voters(proposal_id).unwrap(),
            vec![VOTER_A, PROPOSER, VOTER_B]
        );
    });
}

#[test]
fn deadline_quorum_requires_two_thirds_of_active_set() {
    with_vote(|storage| {
        let mut governance = Vote::new(storage.clone());
        let current = 200u64;
        let proposal_id = create_proposal_test(
            &mut governance,
            PROPOSER,
            UPDATE_ADDRESS,
            &empty_update_payload(current),
            current,
        )
        .unwrap();

        governance
            .cast_vote_approve(proposal_id, VOTER_A, true, current + 1)
            .unwrap();

        let deadline = current + VOTING_WINDOW_BLOCKS + 1;
        governance.process_begin_block_test(deadline).unwrap();

        let record = governance.proposals.get(proposal_id).unwrap().unwrap();
        assert_eq!(record.proposal_status().unwrap(), ProposalStatus::Expired);
    });
}

#[test]
fn list_proposals_and_by_status_are_paginated() {
    with_vote(|storage| {
        let mut governance = Vote::new(storage.clone());
        let current = 300u64;
        let first = create_proposal_test(
            &mut governance,
            PROPOSER,
            UPDATE_ADDRESS,
            &empty_update_payload(current),
            current,
        )
        .unwrap();
        let second = create_proposal_test(
            &mut governance,
            VOTER_A,
            UPDATE_ADDRESS,
            &empty_update_payload(current + 1),
            current + 1,
        )
        .unwrap();

        assert_eq!(
            list_proposals(storage.clone(), U256::ZERO, U256::from(10)).unwrap(),
            vec![first, second]
        );
        assert_eq!(
            list_proposals_by_status(
                storage.clone(),
                ProposalStatus::Pending,
                U256::ZERO,
                U256::from(1)
            )
            .unwrap(),
            vec![first]
        );
        assert_eq!(
            list_proposals_by_status(
                storage,
                ProposalStatus::Pending,
                U256::from(1),
                U256::from(1)
            )
            .unwrap(),
            vec![second]
        );
    });
}
