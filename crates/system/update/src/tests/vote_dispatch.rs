use alloy_primitives::{address, B256};
use alloy_sol_types::SolEvent;
use outbe_ocompregistry::{poc_schema_limits, OcompRegistry};
use outbe_primitives::addresses::UPDATE_ADDRESS;
use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::PrecompileError;
use outbe_primitives::tee_attestation_v1::{
    AttestationMode, PlatformTcbStatusSetV1, QvlTcbStatusV1, TeeMeasurementRuleV1, TeePolicyV1,
};
use outbe_teeregistry::TeeRegistry;
use outbe_vote::constants::VOTING_WINDOW_BLOCKS;
use outbe_vote::handlers::{VoteTarget, VoteTargetRegistry};
use outbe_vote::schema::ProposalStatus;
use outbe_vote::schema::Vote;

use crate::handlers::UpgradeHandlerRegistry;
use crate::payload::{encode_schedule_update_json, ScheduleUpdatePayload};
use crate::precompile::IUpdate;
use crate::schema::Update;
use crate::tests::{block_ctx, min_activation, ocomp_authority, ocomp_successor, CHAIN_ID, PV};
use crate::vote_target::UpdateVoteTarget;

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

fn tee_policy(
    genesis_hash: B256,
    policy_version: u64,
    activation_height: u64,
    predecessor_policy_hash: B256,
    mrenclave: B256,
) -> TeePolicyV1 {
    TeePolicyV1 {
        policy_version,
        chain_id: alloy_primitives::U256::from(CHAIN_ID).to_be_bytes(),
        genesis_hash,
        activation_height,
        predecessor_policy_hash,
        attestation_mode: AttestationMode::DcapRequired,
        intel_root_der_hash: B256::repeat_byte(0x31),
        quote_version: 3,
        tee_type: 0,
        attestation_key_type: 2,
        qe_vendor_id: [
            0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f,
            0x06, 0x07,
        ],
        certification_data_type: 5,
        tcb_info_schema_version: 3,
        qe_identity_schema_version: 2,
        minimum_tcb_evaluation_data_number: 1,
        accepted_platform_tcb_statuses: PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
        accepted_qe_tcb_status: QvlTcbStatusV1::UpToDate,
        minimum_lease: 3_600,
        maximum_lease: 604_800,
        collateral_margin: 3_600,
        resource_schedule_hash: B256::repeat_byte(0x32),
        measurement_rules: vec![TeeMeasurementRuleV1 {
            mrenclave,
            mrsigner: B256::repeat_byte(0x34),
            isv_prod_id: 7,
            minimum_isv_svn: 2,
            admit_from_height: activation_height,
            admit_until_height_exclusive: u64::MAX,
        }],
    }
}

fn with_vote<F: FnOnce(outbe_primitives::storage::StorageHandle)>(f: F) {
    let mut provider =
        outbe_primitives::storage::hashmap::HashMapStorageProvider::new_with_chain_identity(
            CHAIN_ID,
            B256::repeat_byte(0x01),
        );
    provider.set_block_number(1);
    let storage = outbe_primitives::storage::StorageHandle::new(&mut provider);
    setup_validators(storage.clone());
    f(storage);
}

fn setup_validators(storage: outbe_primitives::storage::StorageHandle) {
    let owner = address!("0xffffffffffffffffffffffffffffffffffffffff");
    for (addr, seed) in [(PROPOSER, 1u8), (VOTER_A, 2), (VOTER_B, 3)] {
        let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
        vs.config_owner.write(owner).unwrap();
        vs.set_config_max_validators(100).unwrap();
        let mut pk = [0u8; 48];
        pk[0] = seed;
        vs.register_validator(owner, addr, &pk).unwrap();
        vs.activate_validator_via_boundary_for_test(addr).unwrap();
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
            outbe_primitives::block::BlockContext::empty_for_tests(activation, 0, CHAIN_ID),
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
fn approved_software_update_atomically_stages_successor_tee_policy() {
    with_vote(|storage| {
        let current_height = 100u64;
        let deadline = current_height + VOTING_WINDOW_BLOCKS + 1;
        let activation = min_activation(deadline);
        let genesis_hash = storage.genesis_hash().unwrap();
        let current = tee_policy(genesis_hash, 1, 1, B256::ZERO, B256::repeat_byte(0x41));
        let successor = tee_policy(
            genesis_hash,
            2,
            activation,
            current.policy_hash().unwrap(),
            B256::repeat_byte(0x42),
        );
        TeeRegistry::new(storage.clone())
            .install_initial_policy_v1(&current)
            .unwrap();
        let payload = serde_json::to_string(
            &ScheduleUpdatePayload::with_tee_policy(PV, activation, "release", &successor).unwrap(),
        )
        .unwrap();

        let mut vote = Vote::new(storage.clone());
        let proposal_id = vote
            .create_proposal(
                PROPOSER,
                UPDATE_ADDRESS,
                &payload,
                current_height,
                &VOTE_TARGET_REGISTRY,
            )
            .unwrap();
        vote.cast_vote_approve(proposal_id, VOTER_A, true, current_height + 1)
            .unwrap();
        vote.cast_vote_approve(proposal_id, VOTER_B, true, current_height + 2)
            .unwrap();

        process_begin_block_test(storage.clone(), deadline);

        assert_eq!(
            vote.proposals
                .get(proposal_id)
                .unwrap()
                .unwrap()
                .proposal_status()
                .unwrap(),
            ProposalStatus::Approved
        );
        assert_eq!(
            TeeRegistry::new(storage)
                .staged_successor_policy_v1()
                .unwrap(),
            Some((proposal_id, successor))
        );
    });
}

#[test]
fn one_approved_update_atomically_stages_tee_and_ocomp_successors() {
    with_vote(|storage| {
        let current_height = 100u64;
        let deadline = current_height + VOTING_WINDOW_BLOCKS + 1;
        let activation = min_activation(deadline);
        let genesis_hash = storage.genesis_hash().unwrap();
        let current_tee = tee_policy(genesis_hash, 1, 1, B256::ZERO, B256::repeat_byte(0x51));
        let successor_tee = tee_policy(
            genesis_hash,
            2,
            activation,
            current_tee.policy_hash().unwrap(),
            B256::repeat_byte(0x52),
        );
        TeeRegistry::new(storage.clone())
            .install_initial_policy_v1(&current_tee)
            .unwrap();

        let current_ocomp = ocomp_authority(genesis_hash);
        let successor_ocomp = ocomp_successor(genesis_hash, activation);
        let limits = poc_schema_limits();
        OcompRegistry::new(storage.clone())
            .initialize_genesis_authority(&current_ocomp, B256::repeat_byte(0x53), 1, 1, &limits)
            .unwrap();

        let payload = ScheduleUpdatePayload::with_tee_policy(
            PV,
            activation,
            "TEE and OCOMP release",
            &successor_tee,
        )
        .unwrap()
        .with_ocomp_successor(&successor_ocomp)
        .unwrap();
        let mut vote = Vote::new(storage.clone());
        let proposal_id = vote
            .create_proposal(
                PROPOSER,
                UPDATE_ADDRESS,
                &serde_json::to_string(&payload).unwrap(),
                current_height,
                &VOTE_TARGET_REGISTRY,
            )
            .unwrap();
        vote.cast_vote_approve(proposal_id, VOTER_A, true, current_height + 1)
            .unwrap();
        vote.cast_vote_approve(proposal_id, VOTER_B, true, current_height + 2)
            .unwrap();

        process_begin_block_test(storage.clone(), deadline);

        assert_eq!(
            TeeRegistry::new(storage.clone())
                .staged_successor_policy_v1()
                .unwrap(),
            Some((proposal_id, successor_tee))
        );
        assert_eq!(
            OcompRegistry::new(storage)
                .staged_successor(&limits)
                .unwrap(),
            Some((proposal_id, successor_ocomp))
        );
    });
}

#[test]
fn wrong_policy_predecessor_rolls_back_update_schedule_and_staging() {
    with_vote(|storage| {
        let current_height = 100u64;
        let deadline = current_height + VOTING_WINDOW_BLOCKS + 1;
        let activation = min_activation(deadline);
        let genesis_hash = storage.genesis_hash().unwrap();
        let current = tee_policy(genesis_hash, 1, 1, B256::ZERO, B256::repeat_byte(0x43));
        let successor = tee_policy(
            genesis_hash,
            2,
            activation,
            B256::repeat_byte(0xee),
            B256::repeat_byte(0x44),
        );
        TeeRegistry::new(storage.clone())
            .install_initial_policy_v1(&current)
            .unwrap();
        let payload = serde_json::to_string(
            &ScheduleUpdatePayload::with_tee_policy(PV, activation, "bad predecessor", &successor)
                .unwrap(),
        )
        .unwrap();
        let mut vote = Vote::new(storage.clone());
        let proposal_id = vote
            .create_proposal(
                PROPOSER,
                UPDATE_ADDRESS,
                &payload,
                current_height,
                &VOTE_TARGET_REGISTRY,
            )
            .unwrap();
        vote.cast_vote_approve(proposal_id, VOTER_A, true, current_height + 1)
            .unwrap();
        vote.cast_vote_approve(proposal_id, VOTER_B, true, current_height + 2)
            .unwrap();

        process_begin_block_test(storage.clone(), deadline);

        assert_eq!(
            vote.proposals
                .get(proposal_id)
                .unwrap()
                .unwrap()
                .proposal_status()
                .unwrap(),
            ProposalStatus::Error
        );
        assert!(Update::new(storage.clone())
            .read_scheduled_update(proposal_id)
            .unwrap()
            .is_none());
        assert_eq!(
            TeeRegistry::new(storage)
                .staged_successor_policy_v1()
                .unwrap(),
            None
        );
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
                r#"{"version":"0.0","activationHeight":1000,"info":""}"#,
                200,
                &VOTE_TARGET_REGISTRY,
            )
            .unwrap_err();
        assert!(matches!(err, PrecompileError::Revert(_)));
    });
}

#[test]
fn handler_conflict_marks_proposal_error() {
    with_vote(|storage| {
        let mut vote = Vote::new(storage.clone());
        let current = 250u64;
        let deadline = current + VOTING_WINDOW_BLOCKS + 1;
        let activation = min_activation(deadline + 1);
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
            ProposalStatus::Error
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
    let mut provider = outbe_primitives::storage::hashmap::HashMapStorageProvider::new(CHAIN_ID);
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
