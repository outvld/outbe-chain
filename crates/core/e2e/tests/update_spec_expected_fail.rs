//! Executable update-module specs from `test_task_update.md`.
//!
//! Cross-module flows use `outbe_evm::executor::run_outbe_pre_execution_hooks` and
//! high-level `UPDATE_ADDRESS` precompile dispatch. Operator/RPC/CLI/localnet gaps
//! are marked with checked `#[should_panic(expected = "SPEC_EXPECTED_FAIL: ...")]`.

use alloy_primitives::{address, Address, U256};
use alloy_sol_types::{SolCall, SolEvent};

use outbe_primitives::addresses::UPDATE_ADDRESS;
use outbe_primitives::block::{BlockContext, BlockRuntimeContext};
use outbe_primitives::error::PrecompileError;
use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};
use outbe_update::precompile::{dispatch, IUpdate};
use outbe_update::schema::Update;
use outbe_update::state::{protocol_version_major, protocol_version_minor, ProposalStatus};
use outbe_update::{encode_protocol_version, ProtocolVersion};
use outbe_validatorset::contract::ValidatorSet;

const CHAIN_ID: u64 = 1;
const PROPOSER: Address = address!("0x1111111111111111111111111111111111111111");
const VOTER_A: Address = address!("0x2222222222222222222222222222222222222222");
const VOTER_B: Address = address!("0x3333333333333333333333333333333333333333");
const VOTER_C: Address = address!("0x5555555555555555555555555555555555555555");
const VALIDATOR_OWNER: Address = address!("0xffffffffffffffffffffffffffffffffffffffff");

const V1_2: ProtocolVersion = encode_protocol_version(1, 2);
const V1_3: ProtocolVersion = encode_protocol_version(1, 3);

fn dummy_pubkey(seed: u8) -> [u8; 48] {
    let mut pk = [0u8; 48];
    pk[0] = seed;
    pk
}

fn register_active_validator(storage: StorageHandle, addr: Address, seed: u8) {
    let mut vs = ValidatorSet::new(storage.clone());
    vs.config_owner.write(VALIDATOR_OWNER).unwrap();
    vs.config_max_validators.write(100).unwrap();
    vs.register_validator(VALIDATOR_OWNER, addr, &dummy_pubkey(seed))
        .unwrap();
    vs.activate_validator(addr).unwrap();
}

fn seed_oracle_pair(storage: StorageHandle) {
    let mut oracle = outbe_oracle::contract::OracleContract::new(storage);
    oracle.register_pair("COEN", "0xUSD").unwrap();
    oracle
        .set_exchange_rate(
            Address::ZERO,
            "COEN",
            "0xUSD",
            U256::from(1_000_000_000_000_000_000u128),
            0,
            0,
        )
        .unwrap();
}

fn setup_four_validators(storage: StorageHandle) {
    register_active_validator(storage.clone(), PROPOSER, 1);
    register_active_validator(storage.clone(), VOTER_A, 2);
    register_active_validator(storage.clone(), VOTER_B, 3);
    register_active_validator(storage.clone(), VOTER_C, 4);
    seed_oracle_pair(storage);
}

fn min_activation(current: u64) -> u64 {
    current
        .saturating_add(outbe_update::constants::VOTING_WINDOW_BLOCKS)
        .saturating_add(outbe_update::constants::MIN_ACTIVATION_BUFFER)
}

fn spec_version_string(version: ProtocolVersion) -> String {
    format!(
        "v{}.{}.0",
        protocol_version_major(version),
        protocol_version_minor(version)
    )
}

fn with_runtime_at<F: FnOnce(StorageHandle, u64)>(current: u64, f: F) {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.set_block_number(current);
    let storage = StorageHandle::new(&mut provider);
    setup_four_validators(storage.clone());
    f(storage, current);
}

fn dispatch_create_proposal(
    storage: StorageHandle,
    proposer: Address,
    version: ProtocolVersion,
    activation: u64,
) -> U256 {
    let create_data = IUpdate::createProposalCall {
        version,
        activationHeight: activation,
        info: Default::default(),
    }
    .abi_encode();
    let created = dispatch(storage.clone(), &create_data, proposer, U256::ZERO)
        .expect("createProposal dispatch should succeed");
    IUpdate::createProposalCall::abi_decode_returns(&created).expect("decode proposal id")
}

fn dispatch_cast_vote(storage: StorageHandle, voter: Address, proposal_id: U256, approve: bool) {
    let vote_data = IUpdate::castVoteCall {
        proposalId: proposal_id,
        approve,
    }
    .abi_encode();
    dispatch(storage, &vote_data, voter, U256::ZERO).expect("castVote dispatch should succeed");
}

fn dispatch_get_active_version_u32(storage: StorageHandle) -> u32 {
    let active_data = IUpdate::getActiveVersionCall {}.abi_encode();
    let active_bytes = dispatch(storage, &active_data, PROPOSER, U256::ZERO)
        .expect("getActiveVersion dispatch should succeed");
    IUpdate::getActiveVersionCall::abi_decode_returns(&active_bytes).expect("decode active version")
}

fn run_begin_block(storage: StorageHandle, block_number: u64) {
    storage
        .set_block_timestamp(U256::from(block_number))
        .expect("set block timestamp");
    let ctx = BlockRuntimeContext::new(
        BlockContext::new(block_number, block_number, CHAIN_ID, PROPOSER, Vec::new()),
        storage,
    );
    outbe_evm::executor::run_outbe_pre_execution_hooks(&ctx, None)
        .expect("pre-execution hook chain should succeed");
}

fn has_update_event(provider: &HashMapStorageProvider, topic0: alloy_primitives::B256) -> bool {
    provider
        .get_events(UPDATE_ADDRESS)
        .iter()
        .any(|log| log.topics().first() == Some(&topic0))
}

// ---- runnable cross-module flows --------------------------------------------

#[test]
fn e2e_full_flow_three_yes_activates() {
    with_runtime_at(100, |storage, current| {
        let activation = min_activation(current);
        let proposal_id = dispatch_create_proposal(storage.clone(), PROPOSER, V1_2, activation);
        dispatch_cast_vote(storage.clone(), VOTER_A, proposal_id, true);
        dispatch_cast_vote(storage.clone(), VOTER_B, proposal_id, true);
        dispatch_cast_vote(storage.clone(), VOTER_C, proposal_id, true);

        let update = Update::new(storage.clone());
        let deadline = update
            .read_proposal(proposal_id)
            .unwrap()
            .unwrap()
            .voting_deadline_height;

        run_begin_block(storage.clone(), deadline + 1);
        run_begin_block(storage.clone(), activation);

        let proposal = update.read_proposal(proposal_id).unwrap().unwrap();
        assert_eq!(proposal.status, ProposalStatus::Activated);
        assert_eq!(dispatch_get_active_version_u32(storage), V1_2);
        assert_eq!(spec_version_string(V1_2), "v1.2.0");
    });
}

#[test]
fn e2e_two_yes_expires() {
    with_runtime_at(100, |storage, current| {
        let proposal_id =
            dispatch_create_proposal(storage.clone(), PROPOSER, V1_2, min_activation(current));
        dispatch_cast_vote(storage.clone(), VOTER_A, proposal_id, true);
        dispatch_cast_vote(storage.clone(), VOTER_B, proposal_id, true);

        let update = Update::new(storage.clone());
        let deadline = update
            .read_proposal(proposal_id)
            .unwrap()
            .unwrap()
            .voting_deadline_height;
        run_begin_block(storage.clone(), deadline + 1);

        let proposal = update.read_proposal(proposal_id).unwrap().unwrap();
        assert_eq!(proposal.status, ProposalStatus::Expired);
        assert_eq!(dispatch_get_active_version_u32(storage), 0);
    });
}

#[test]
fn e2e_downgrade_attempt_rejected() {
    with_runtime_at(10, |storage, current| {
        let mut update = Update::new(storage.clone());
        update.set_active_version(V1_3, 1).unwrap();

        let err = dispatch(
            storage.clone(),
            &IUpdate::createProposalCall {
                version: encode_protocol_version(1, 2),
                activationHeight: min_activation(current),
                info: Default::default(),
            }
            .abi_encode(),
            PROPOSER,
            U256::ZERO,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                PrecompileError::Revert(msg) if msg.contains("downgrade")
            ),
            "downgrade proposal must be rejected"
        );
    });
}

#[test]
fn e2e_conflicting_proposals() {
    with_runtime_at(100, |storage, current| {
        let activation = min_activation(current);
        let first = dispatch_create_proposal(storage.clone(), PROPOSER, V1_2, activation);
        let second = dispatch_create_proposal(storage.clone(), PROPOSER, V1_3, activation);

        for proposal_id in [first, second] {
            dispatch_cast_vote(storage.clone(), VOTER_A, proposal_id, true);
            dispatch_cast_vote(storage.clone(), VOTER_B, proposal_id, true);
            dispatch_cast_vote(storage.clone(), VOTER_C, proposal_id, true);
        }

        let update = Update::new(storage.clone());
        let deadline = update
            .read_proposal(first)
            .unwrap()
            .unwrap()
            .voting_deadline_height;
        run_begin_block(storage.clone(), deadline + 1);

        assert_eq!(
            update.read_proposal(first).unwrap().unwrap().status,
            ProposalStatus::Approved
        );
        assert_eq!(
            update.read_proposal(second).unwrap().unwrap().status,
            ProposalStatus::Rejected
        );
    });
}

#[test]
fn e2e_lifecycle_events_visible_in_transaction_receipts() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.set_block_number(100);
    let storage = StorageHandle::new(&mut provider);
    setup_four_validators(storage.clone());

    let activation = min_activation(100);
    let proposal_id = dispatch_create_proposal(storage.clone(), PROPOSER, V1_2, activation);
    dispatch_cast_vote(storage.clone(), VOTER_A, proposal_id, true);
    dispatch_cast_vote(storage.clone(), VOTER_B, proposal_id, true);
    dispatch_cast_vote(storage.clone(), VOTER_C, proposal_id, true);

    let update = Update::new(storage.clone());
    let deadline = update
        .read_proposal(proposal_id)
        .unwrap()
        .unwrap()
        .voting_deadline_height;
    run_begin_block(storage.clone(), deadline + 1);
    run_begin_block(storage.clone(), activation);

    let approved_event_exists =
        has_update_event(&provider, IUpdate::ProposalApproved::SIGNATURE_HASH);
    let activated_event_exists =
        has_update_event(&provider, IUpdate::UpgradeActivated::SIGNATURE_HASH);
    assert!(
        approved_event_exists && activated_event_exists,
        "lifecycle processing must emit approval and activation events"
    );
}

// ---- operator / RPC / localnet gaps -----------------------------------------

#[test]
#[should_panic(expected = "SPEC_EXPECTED_FAIL: outbe_getUpdateProposal RPC not implemented")]
fn e2e_rpc_proposal_status_tracks_each_phase() {
    let rpc_status_tracks_each_phase = false;
    assert!(
        rpc_status_tracks_each_phase,
        "SPEC_EXPECTED_FAIL: outbe_getUpdateProposal RPC not implemented"
    );
}

#[test]
#[should_panic(expected = "SPEC_EXPECTED_FAIL: outbe_getActiveVersion RPC not implemented")]
fn e2e_rpc_active_version_after_activation() {
    let active_version_rpc_available = false;
    assert!(
        active_version_rpc_available,
        "SPEC_EXPECTED_FAIL: outbe_getActiveVersion RPC not implemented"
    );
}

#[test]
#[should_panic(expected = "SPEC_EXPECTED_FAIL: outbe-cli update commands not implemented")]
fn e2e_cli_propose_vote_status_flow() {
    let cli_update_commands_available = false;
    assert!(
        cli_update_commands_available,
        "SPEC_EXPECTED_FAIL: outbe-cli update commands not implemented"
    );
}

#[test]
#[should_panic(expected = "SPEC_EXPECTED_FAIL: localnet update smoke not implemented")]
fn e2e_localnet_update_smoke() {
    let localnet_update_smoke_available = false;
    assert!(
        localnet_update_smoke_available,
        "SPEC_EXPECTED_FAIL: localnet update smoke not implemented"
    );
}

#[test]
#[should_panic(
    expected = "SPEC_EXPECTED_FAIL: multi-node determinism harness for update flow not implemented"
)]
fn e2e_deterministic_state_root_across_nodes() {
    let multi_node_determinism_harness_available = false;
    assert!(
        multi_node_determinism_harness_available,
        "SPEC_EXPECTED_FAIL: multi-node determinism harness for update flow not implemented"
    );
}

#[test]
#[should_panic(
    expected = "SPEC_EXPECTED_FAIL: startup binary-version fail-fast check not implemented"
)]
fn e2e_startup_binary_older_than_active_version_fails() {
    let startup_binary_version_check_available = false;
    assert!(
        startup_binary_version_check_available,
        "SPEC_EXPECTED_FAIL: startup binary-version fail-fast check not implemented"
    );
}
