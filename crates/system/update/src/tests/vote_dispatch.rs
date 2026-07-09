use alloy_primitives::address;
use alloy_sol_types::SolEvent;

use crate::handlers::UpgradeHandlerRegistry;
use crate::precompile::IUpdate;
use crate::schema::Update;
use crate::vote_target::UpdateVoteTarget;
use outbe_primitives::addresses::UPDATE_ADDRESS;
use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::PrecompileError;
use outbe_vote::constants::VOTING_WINDOW_BLOCKS;
use outbe_vote::handlers::{VoteTarget, VoteTargetRegistry};
use outbe_vote::schema::ProposalStatus;
use outbe_vote::schema::Vote;

use crate::payload::encode_schedule_update_json;
use crate::tests::{block_ctx, min_activation, PV};

static UPDATE_VOTE_TARGET: UpdateVoteTarget = UpdateVoteTarget;
static VOTE_HANDLERS: &[&dyn VoteTarget] = &[&UPDATE_VOTE_TARGET];
static VOTE_TARGET_REGISTRY: VoteTargetRegistry = VoteTargetRegistry::new(VOTE_HANDLERS);

static EMPTY_UPGRADE_HANDLER_REGISTRY: UpgradeHandlerRegistry = UpgradeHandlerRegistry::new(&[]);

const PROPOSER: alloy_primitives::Address = address!("0x1111111111111111111111111111111111111111");
const VOTER_A: alloy_primitives::Address = address!("0x2222222222222222222222222222222222222222");
const VOTER_B: alloy_primitives::Address = address!("0x3333333333333333333333333333333333333333");
const UNKNOWN_TARGET: alloy_primitives::Address =
    address!("0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead");

fn empty_update_payload(current_height: u64) -> String {
    encode_schedule_update_json(
        PV,
        min_activation(current_height.saturating_add(VOTING_WINDOW_BLOCKS)),
        "",
    )
}

fn with_vote<F: FnOnce(outbe_primitives::storage::StorageHandle)>(f: F) {
    let mut provider = outbe_primitives::storage::hashmap::HashMapStorageProvider::new(1);
    let storage = outbe_primitives::storage::StorageHandle::new(&mut provider);
    setup_validators(storage.clone());
    f(storage);
}

fn setup_validators(storage: outbe_primitives::storage::StorageHandle) {
    let owner = address!("0xffffffffffffffffffffffffffffffffffffffff");
    for (addr, seed) in [(PROPOSER, 1u8), (VOTER_A, 2), (VOTER_B, 3)] {
        let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
        vs.config_owner.write(owner).unwrap();
        vs.config_max_validators.write(100).unwrap();
        let mut pk = [0u8; 48];
        pk[0] = seed;
        vs.register_validator(owner, addr, &pk).unwrap();
        vs.activate_validator(addr).unwrap();
    }
}

fn process_begin_block_test(storage: outbe_primitives::storage::StorageHandle, block_number: u64) {
    let ctx = block_ctx(storage.clone(), block_number);
    Vote::new(storage)
        .process_begin_block(&ctx, &VOTE_TARGET_REGISTRY)
        .unwrap();
}

#[test]
fn approved_vote_proposal_schedules_update_and_activates() {
    with_vote(|storage| {
        let mut governance = Vote::new(storage.clone());
        let current = 100u64;
        let deadline = current + VOTING_WINDOW_BLOCKS + 1;
        let activation = min_activation(deadline);
        let payload = encode_schedule_update_json(PV, activation, "notes");
        let proposal_id = governance
            .create_proposal(
                PROPOSER,
                UPDATE_ADDRESS,
                &payload,
                current,
                &VOTE_TARGET_REGISTRY,
            )
            .unwrap();

        governance
            .cast_vote_approve(proposal_id, VOTER_A, true, current + 1)
            .unwrap();
        governance
            .cast_vote_approve(proposal_id, VOTER_B, true, current + 2)
            .unwrap();

        process_begin_block_test(storage.clone(), deadline);

        let record = governance.proposals.get(proposal_id).unwrap().unwrap();
        assert_eq!(record.proposal_status().unwrap(), ProposalStatus::Approved);

        let mut update = Update::new(storage.clone());
        let scheduled = update.read_scheduled_update(proposal_id).unwrap().unwrap();
        assert_eq!(scheduled.version, PV);
        assert_eq!(scheduled.activation_height, activation);

        let ctx = BlockRuntimeContext::new(
            outbe_primitives::block::BlockContext::empty_for_tests(activation, 0, 1),
            storage.clone(),
        );
        update
            .process_begin_block_with_handlers(&ctx, &EMPTY_UPGRADE_HANDLER_REGISTRY)
            .unwrap();

        assert_eq!(update.get_active_version().unwrap(), PV);
        assert_eq!(update.get_active_version_height().unwrap(), activation);
    });
}

#[test]
fn invalid_json_payload_is_rejected_at_creation() {
    with_vote(|storage| {
        let mut governance = Vote::new(storage.clone());
        let err = governance
            .create_proposal(
                PROPOSER,
                UPDATE_ADDRESS,
                "not-json",
                200,
                &VOTE_TARGET_REGISTRY,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("invalid proposal payload")
        ));
    });
}

#[test]
fn invalid_update_payload_is_rejected_at_creation() {
    with_vote(|storage| {
        let mut governance = Vote::new(storage.clone());
        let err = governance
            .create_proposal(
                PROPOSER,
                UPDATE_ADDRESS,
                r#"{"version":0,"activationHeight":1000,"info":""}"#,
                200,
                &VOTE_TARGET_REGISTRY,
            )
            .unwrap_err();
        assert!(matches!(err, PrecompileError::Revert(_)));
    });
}

#[test]
fn handler_conflict_marks_proposal_rejected() {
    with_vote(|storage| {
        let mut vote = Vote::new(storage.clone());
        let current = 250u64;
        let deadline = current + VOTING_WINDOW_BLOCKS + 1;
        let activation = min_activation(deadline);
        let payload = encode_schedule_update_json(PV, activation, "");

        let first = vote
            .create_proposal(
                PROPOSER,
                UPDATE_ADDRESS,
                &payload,
                current,
                &VOTE_TARGET_REGISTRY,
            )
            .unwrap();
        for (voter, off) in [(VOTER_A, 1), (VOTER_B, 2)] {
            vote.cast_vote_approve(first, voter, true, current + off)
                .unwrap();
        }
        process_begin_block_test(storage.clone(), deadline);
        assert_eq!(
            vote.proposals
                .get(first)
                .unwrap()
                .unwrap()
                .proposal_status()
                .unwrap(),
            ProposalStatus::Approved
        );

        let second = vote
            .create_proposal(
                VOTER_A,
                UPDATE_ADDRESS,
                &payload,
                current + 1,
                &VOTE_TARGET_REGISTRY,
            )
            .unwrap();
        for (voter, off) in [(VOTER_A, 3), (VOTER_B, 4)] {
            vote.cast_vote_approve(second, voter, true, current + off)
                .unwrap();
        }
        process_begin_block_test(storage.clone(), deadline + 1);
        assert_eq!(
            vote.proposals
                .get(second)
                .unwrap()
                .unwrap()
                .proposal_status()
                .unwrap(),
            ProposalStatus::Rejected
        );
    });
}

#[test]
fn unknown_target_is_rejected_at_creation() {
    with_vote(|storage| {
        let mut vote = Vote::new(storage.clone());
        let current = 260u64;
        let payload = empty_update_payload(current);
        let err = vote
            .create_proposal(
                PROPOSER,
                UNKNOWN_TARGET,
                &payload,
                current,
                &VOTE_TARGET_REGISTRY,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("unknown vote target module")
        ));
    });
}

#[test]
fn expired_update_proposal_does_not_emit_upgrade_activated() {
    let mut provider = outbe_primitives::storage::hashmap::HashMapStorageProvider::new(1);
    let storage = outbe_primitives::storage::StorageHandle::new(&mut provider);
    setup_validators(storage.clone());

    let mut vote = Vote::new(storage.clone());
    let current = 400u64;
    let payload =
        encode_schedule_update_json(PV, min_activation(current + VOTING_WINDOW_BLOCKS), "");
    let proposal_id = vote
        .create_proposal(
            PROPOSER,
            UPDATE_ADDRESS,
            &payload,
            current,
            &VOTE_TARGET_REGISTRY,
        )
        .unwrap();
    vote.cast_vote_approve(proposal_id, VOTER_A, true, current + 1)
        .unwrap();

    let deadline = current + VOTING_WINDOW_BLOCKS + 1;
    process_begin_block_test(storage.clone(), deadline);
    assert_eq!(
        vote.proposals
            .get(proposal_id)
            .unwrap()
            .unwrap()
            .proposal_status()
            .unwrap(),
        ProposalStatus::Expired
    );

    let update = Update::new(storage);
    assert!(update.read_scheduled_update(proposal_id).unwrap().is_none());
    assert!(!provider
        .get_events(UPDATE_ADDRESS)
        .iter()
        .any(|log| log.topics().first() == Some(&IUpdate::UpgradeActivated::SIGNATURE_HASH)));
}
