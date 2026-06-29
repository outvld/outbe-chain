//! End-to-end vote and update flows across modules.
//!
//! Complements crate-local unit tests by wiring validator set, vote tallying,
//! update scheduling/activation, and (where needed) pre-execution hooks in one runtime.

use alloy_primitives::{address, Address, B256, U256};
use alloy_sol_types::{SolCall, SolEvent};

use outbe_evm::executor::run_outbe_pre_execution_hooks;
use outbe_primitives::addresses::UPDATE_ADDRESS;
use outbe_primitives::block::{BlockContext, BlockRuntimeContext};
use outbe_primitives::error::PrecompileError;
use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};
use outbe_update::handlers::EMPTY_UPGRADE_HANDLER_REGISTRY;
use outbe_update::lifecycle::UpdateLifecycle;
use outbe_update::precompile::{dispatch, IUpdate};
use outbe_update::schema::Update;
use outbe_update::state::ScheduledUpdateStatus;
use outbe_update::{encode_protocol_version, encode_scheduled_update_payload, ProtocolVersion};
use outbe_validatorset::contract::ValidatorSet;
use outbe_vote::constants::VOTING_WINDOW_BLOCKS;
use outbe_vote::schema::ProposalStatus;
use outbe_vote::schema::Vote;
use outbe_vote::targets::{SCHEDULE_UPDATE_ACTION, UPDATE_TARGET_MODULE};

const CHAIN_ID: u64 = 1;
const PROPOSER: Address = address!("0x1111111111111111111111111111111111111111");
const VOTER_A: Address = address!("0x2222222222222222222222222222222222222222");
const VOTER_B: Address = address!("0x3333333333333333333333333333333333333333");
const VOTER_C: Address = address!("0x4444444444444444444444444444444444444444");
const VALIDATOR_OWNER: Address = address!("0xffffffffffffffffffffffffffffffffffffffff");

const V1_2: ProtocolVersion = encode_protocol_version(1, 2);
const V1_3: ProtocolVersion = encode_protocol_version(1, 3);

fn min_activation(current: u64) -> u64 {
    current.saturating_add(outbe_update::constants::MIN_ACTIVATION_BUFFER)
}

fn dummy_pubkey(seed: u8) -> [u8; 48] {
    let mut pk = [0u8; 48];
    pk[0] = seed;
    pk
}

fn register_active_validator(storage: StorageHandle, addr: Address, seed: u8) {
    let mut vs = ValidatorSet::new(storage.clone());
    if vs.config_owner.read().unwrap().is_zero() {
        vs.config_owner.write(VALIDATOR_OWNER).unwrap();
        vs.config_max_validators.write(100).unwrap();
    }
    vs.register_validator(VALIDATOR_OWNER, addr, &dummy_pubkey(seed))
        .unwrap();
    vs.activate_validator(addr).unwrap();
}

fn setup_four_validators(storage: StorageHandle) {
    register_active_validator(storage.clone(), PROPOSER, 1);
    register_active_validator(storage.clone(), VOTER_A, 2);
    register_active_validator(storage.clone(), VOTER_B, 3);
    register_active_validator(storage.clone(), VOTER_C, 4);
}

fn tally_block(created: u64) -> u64 {
    created.saturating_add(VOTING_WINDOW_BLOCKS + 1)
}

fn proposal_activation(created: u64) -> u64 {
    min_activation(tally_block(created))
}

fn seed_oracle_for_pre_exec(storage: StorageHandle) {
    let mut oracle = outbe_oracle::contract::OracleContract::new(storage);
    if oracle.register_pair("COEN", "0xUSD").is_err() {
        return;
    }
    let _ = oracle.set_exchange_rate(
        Address::ZERO,
        "COEN",
        "0xUSD",
        U256::from(1_000_000_000_000_000_000u128),
        0,
        0,
    );
}

fn with_runtime_at<F: FnOnce(StorageHandle, u64)>(current: u64, f: F) {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.set_block_number(current);
    let storage = StorageHandle::new(&mut provider);
    f(storage, current);
}

fn with_vote_runtime_at<F: FnOnce(StorageHandle, u64)>(current: u64, f: F) {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.set_block_number(current);
    let storage = StorageHandle::new(&mut provider);
    setup_four_validators(storage.clone());
    seed_oracle_for_pre_exec(storage.clone());
    f(storage, current);
}

fn block_ctx(storage: StorageHandle, block_number: u64) -> BlockRuntimeContext {
    BlockRuntimeContext::new(
        BlockContext::new(block_number, block_number, CHAIN_ID, PROPOSER, Vec::new()),
        storage,
    )
}

fn schedule_update(
    update: &mut Update<'_>,
    proposal_id: U256,
    version: ProtocolVersion,
    activation: u64,
    current: u64,
) {
    let payload = encode_scheduled_update_payload(version, activation, b"");
    update
        .schedule_update_from_vote(proposal_id, &payload, current)
        .expect("schedule_update_from_vote should succeed");
}

fn run_vote_begin_block(storage: StorageHandle, block_number: u64) {
    let ctx = block_ctx(storage, block_number);
    Vote::new(ctx.storage.clone())
        .process_begin_block(&ctx)
        .expect("vote begin block should succeed");
}

fn run_update_begin_block(storage: StorageHandle, block_number: u64) {
    let ctx = block_ctx(storage, block_number);
    UpdateLifecycle::begin_block_with_handlers(&ctx, &EMPTY_UPGRADE_HANDLER_REGISTRY)
        .expect("update begin block should succeed");
}

fn run_pre_execution_hooks(storage: StorageHandle, block_number: u64) {
    storage
        .set_block_timestamp(U256::from(block_number))
        .expect("set block timestamp");
    let ctx = block_ctx(storage, block_number);
    run_outbe_pre_execution_hooks(&ctx, None).expect("pre-exec hooks should succeed");
}

fn dispatch_get_active_version_u32(storage: StorageHandle) -> u32 {
    let active_data = IUpdate::getActiveVersionCall {}.abi_encode();
    let active_bytes = dispatch(storage, &active_data, PROPOSER, U256::ZERO)
        .expect("getActiveVersion dispatch should succeed");
    IUpdate::getActiveVersionCall::abi_decode_returns(&active_bytes).expect("decode active version")
}

fn has_update_event(provider: &HashMapStorageProvider, topic0: B256) -> bool {
    provider
        .get_events(UPDATE_ADDRESS)
        .iter()
        .any(|log| log.topics().first() == Some(&topic0))
}

fn create_update_proposal(
    vote: &mut Vote<'_>,
    version: ProtocolVersion,
    activation: u64,
    current: u64,
) -> U256 {
    create_update_proposal_from(vote, PROPOSER, version, activation, current)
}

fn create_update_proposal_from(
    vote: &mut Vote<'_>,
    proposer: Address,
    version: ProtocolVersion,
    activation: u64,
    current: u64,
) -> U256 {
    let payload = encode_scheduled_update_payload(version, activation, b"");
    vote.create_proposal(
        proposer,
        UPDATE_TARGET_MODULE,
        SCHEDULE_UPDATE_ACTION,
        &payload,
        current,
    )
    .unwrap()
}

#[test]
fn scheduled_update_activates_at_height() {
    with_runtime_at(100, |storage, current| {
        let activation = min_activation(current);
        let proposal_id = U256::from(1);
        let mut update = Update::new(storage.clone());
        schedule_update(&mut update, proposal_id, V1_2, activation, current);
        run_update_begin_block(storage.clone(), activation);

        let scheduled = update.read_scheduled_update(proposal_id).unwrap().unwrap();
        assert_eq!(scheduled.status, ScheduledUpdateStatus::Activated);
        assert_eq!(dispatch_get_active_version_u32(storage), V1_2.raw());
        assert_eq!(V1_2.to_string(), "v1.2");
    });
}

#[test]
fn downgrade_schedule_rejected() {
    with_runtime_at(10, |storage, current| {
        let mut update = Update::new(storage.clone());
        update.set_active_version(V1_3, 1).unwrap();

        let payload = encode_scheduled_update_payload(V1_2, min_activation(current), b"");
        let err = update
            .schedule_update_from_vote(U256::from(1), &payload, current)
            .unwrap_err();
        assert!(
            matches!(
                err,
                PrecompileError::Revert(msg) if msg.contains("downgrade")
            ),
            "downgrade schedule must be rejected"
        );
    });
}

#[test]
fn conflicting_activation_heights_rejected() {
    with_runtime_at(100, |storage, current| {
        let activation = min_activation(current);
        let mut update = Update::new(storage.clone());
        schedule_update(&mut update, U256::from(1), V1_2, activation, current);

        let payload = encode_scheduled_update_payload(V1_3, activation, b"");
        let err = update
            .schedule_update_from_vote(U256::from(2), &payload, current)
            .unwrap_err();
        assert!(
            matches!(
                err,
                PrecompileError::Revert(msg) if msg.contains("activation height")
            ),
            "conflicting activation height must be rejected"
        );
    });
}

#[test]
fn lifecycle_events_visible_in_provider() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.set_block_number(100);
    let storage = StorageHandle::new(&mut provider);

    let activation = min_activation(100);
    let proposal_id = U256::from(1);
    let mut update = Update::new(storage.clone());
    schedule_update(&mut update, proposal_id, V1_2, activation, 100);
    run_update_begin_block(storage, activation);

    assert!(has_update_event(
        &provider,
        IUpdate::ScheduledUpdateCreated::SIGNATURE_HASH
    ));
    assert!(has_update_event(
        &provider,
        IUpdate::UpgradeActivated::SIGNATURE_HASH
    ));
}

#[test]
fn legacy_vote_selectors_rejected_at_update_address() {
    with_runtime_at(100, |storage, _current| {
        let err = dispatch(storage, &[0xb1, 0xa1, 0x41, 0x06], PROPOSER, U256::ZERO).unwrap_err();
        assert!(matches!(err, PrecompileError::Revert(_)));
    });
}

#[test]
fn startup_binary_version_check_rejects_older_binary() {
    let err =
        outbe_update::startup::assert_binary_protocol_compatible(encode_protocol_version(2, 0))
            .unwrap_err();
    assert!(err.contains("older than on-chain active"));
}

#[test]
fn startup_binary_version_check_allows_pre_vote_chain() {
    outbe_update::startup::assert_binary_protocol_compatible(ProtocolVersion::ZERO).unwrap();
}

#[test]
fn full_vote_update_flow_3_of_4_yes_approves_schedules_and_activates() {
    with_vote_runtime_at(100, |storage, current| {
        let activation = proposal_activation(current);
        let mut vote = Vote::new(storage.clone());
        let proposal_id = create_update_proposal(&mut vote, V1_2, activation, current);

        vote.cast_vote_approve(proposal_id, VOTER_A, true, current + 1)
            .unwrap();
        vote.cast_vote_approve(proposal_id, VOTER_B, true, current + 2)
            .unwrap();
        vote.cast_vote_approve(proposal_id, VOTER_C, true, current + 3)
            .unwrap();

        run_vote_begin_block(storage.clone(), tally_block(current));

        let record = vote.proposals.get(proposal_id).unwrap().unwrap();
        assert_eq!(record.proposal_status().unwrap(), ProposalStatus::Approved);

        let update = Update::new(storage.clone());
        let scheduled = update.read_scheduled_update(proposal_id).unwrap().unwrap();
        assert_eq!(scheduled.version, V1_2);
        assert_eq!(scheduled.activation_height, activation);

        run_update_begin_block(storage.clone(), activation);

        let update = Update::new(storage.clone());
        assert_eq!(update.get_active_version().unwrap(), V1_2);
        assert_eq!(update.get_active_version_height().unwrap(), activation);
        assert_eq!(update.version_at_height(activation).unwrap(), V1_2);
    });
}

#[test]
fn full_vote_update_flow_2_of_4_yes_expires_without_update_state_change() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.set_block_number(100);
    let storage = StorageHandle::new(&mut provider);
    setup_four_validators(storage.clone());

    let current = 100u64;
    let activation = proposal_activation(current);
    let mut vote = Vote::new(storage.clone());
    let proposal_id = create_update_proposal(&mut vote, V1_2, activation, current);

    vote.cast_vote_approve(proposal_id, PROPOSER, true, current + 1)
        .unwrap();
    vote.cast_vote_approve(proposal_id, VOTER_A, true, current + 2)
        .unwrap();
    vote.cast_vote_approve(proposal_id, VOTER_B, false, current + 3)
        .unwrap();
    vote.cast_vote_approve(proposal_id, VOTER_C, false, current + 4)
        .unwrap();

    run_vote_begin_block(storage.clone(), tally_block(current));

    let record = vote.proposals.get(proposal_id).unwrap().unwrap();
    assert_eq!(record.proposal_status().unwrap(), ProposalStatus::Expired);

    let update = Update::new(storage);
    assert!(update.read_scheduled_update(proposal_id).unwrap().is_none());
    assert_eq!(
        update.get_active_version().unwrap(),
        ProtocolVersion::ZERO
    );
    assert_eq!(update.get_active_version_height().unwrap(), 0);
    assert!(!has_update_event(
        &provider,
        IUpdate::UpgradeActivated::SIGNATURE_HASH
    ));
}

#[test]
fn downgrade_vote_proposal_rejected_without_update_state_change() {
    with_vote_runtime_at(100, |storage, current| {
        let mut update = Update::new(storage.clone());
        update.set_active_version(V1_3, 50).unwrap();

        let activation = proposal_activation(current);
        let mut vote = Vote::new(storage.clone());
        let proposal_id = create_update_proposal(&mut vote, V1_2, activation, current);

        for (voter, seed) in [(VOTER_A, 1), (VOTER_B, 2), (VOTER_C, 3)] {
            vote.cast_vote_approve(proposal_id, voter, true, current + seed)
                .unwrap();
        }

        run_vote_begin_block(storage.clone(), tally_block(current));

        let record = vote.proposals.get(proposal_id).unwrap().unwrap();
        assert_eq!(record.proposal_status().unwrap(), ProposalStatus::Rejected);

        let update = Update::new(storage.clone());
        assert!(update.read_scheduled_update(proposal_id).unwrap().is_none());
        assert_eq!(update.get_active_version().unwrap(), V1_3);
        assert_eq!(update.get_active_version_height().unwrap(), 50);
    });
}

#[test]
fn conflicting_update_proposal_rejected_without_update_state_change() {
    with_vote_runtime_at(100, |storage, current| {
        let activation = proposal_activation(current);

        let mut vote = Vote::new(storage.clone());
        let first = create_update_proposal(&mut vote, V1_2, activation, current);
        for (voter, seed) in [(VOTER_A, 1), (VOTER_B, 2), (VOTER_C, 3)] {
            vote.cast_vote_approve(first, voter, true, current + seed)
                .unwrap();
        }

        let second = create_update_proposal_from(&mut vote, VOTER_A, V1_3, activation, current);
        vote.cast_vote_approve(second, PROPOSER, true, current + 4)
            .unwrap();
        vote.cast_vote_approve(second, VOTER_A, true, current + 5)
            .unwrap();
        vote.cast_vote_approve(second, VOTER_B, true, current + 6)
            .unwrap();

        run_vote_begin_block(storage.clone(), tally_block(current));

        let first_record = vote.proposals.get(first).unwrap().unwrap();
        let second_record = vote.proposals.get(second).unwrap().unwrap();
        assert_eq!(
            first_record.proposal_status().unwrap(),
            ProposalStatus::Approved
        );
        assert_eq!(
            second_record.proposal_status().unwrap(),
            ProposalStatus::Rejected
        );

        let update = Update::new(storage.clone());
        assert!(update.read_scheduled_update(first).unwrap().is_some());
        assert!(update.read_scheduled_update(second).unwrap().is_none());
    assert_eq!(
        update.get_active_version().unwrap(),
        ProtocolVersion::ZERO
    );
    });
}

#[test]
fn activation_does_not_downgrade_when_newer_version_already_active() {
    with_runtime_at(100, |storage, current| {
        let activation_early = min_activation(current);
        let activation_late = activation_early + 500;
        let mut update = Update::new(storage.clone());
        schedule_update(&mut update, U256::from(1), V1_3, activation_early, current);
        schedule_update(&mut update, U256::from(2), V1_2, activation_late, current);

        run_update_begin_block(storage.clone(), activation_early);
        assert_eq!(
            Update::new(storage.clone()).get_active_version().unwrap(),
            V1_3
        );
        let stale = Update::new(storage.clone())
            .read_scheduled_update(U256::from(2))
            .unwrap()
            .unwrap();
        assert_eq!(stale.status, ScheduledUpdateStatus::Canceled);

        run_update_begin_block(storage.clone(), activation_late);
        assert_eq!(
            Update::new(storage.clone()).get_active_version().unwrap(),
            V1_3,
            "activating an older scheduled update must not downgrade active version"
        );
    });
}

#[test]
fn executor_runs_vote_before_update() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.set_block_number(100_000);
    let storage = StorageHandle::new(&mut provider);
    setup_four_validators(storage.clone());
    seed_oracle_for_pre_exec(storage.clone());

    let activation_block = 100_300u64;
    let mut update = Update::new(storage.clone());
    schedule_update(
        &mut update,
        U256::from(100),
        V1_2,
        activation_block,
        100_000,
    );

    let created = activation_block - 1 - VOTING_WINDOW_BLOCKS;
    let proposal_activation = proposal_activation(created);
    let mut vote = Vote::new(storage.clone());
    let proposal_id = vote
        .create_proposal(
            PROPOSER,
            UPDATE_TARGET_MODULE,
            SCHEDULE_UPDATE_ACTION,
            &encode_scheduled_update_payload(V1_3, proposal_activation, b""),
            created,
        )
        .unwrap();
    for (voter, off) in [(VOTER_A, 1), (VOTER_B, 2), (VOTER_C, 3)] {
        vote.cast_vote_approve(proposal_id, voter, true, created + off)
            .unwrap();
    }

    run_pre_execution_hooks(storage.clone(), activation_block);

    let update = Update::new(storage.clone());
    assert_eq!(
        update
            .read_scheduled_update(U256::from(100))
            .unwrap()
            .unwrap()
            .status,
        ScheduledUpdateStatus::Activated
    );
    assert_eq!(update.get_active_version().unwrap(), V1_2);

    let vote = Vote::new(storage.clone());
    let record = vote.proposals.get(proposal_id).unwrap().unwrap();
    assert_eq!(record.proposal_status().unwrap(), ProposalStatus::Approved);
    assert!(update.read_scheduled_update(proposal_id).unwrap().is_some());
}
