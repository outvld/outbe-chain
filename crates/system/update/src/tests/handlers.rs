use std::sync::atomic::{AtomicUsize, Ordering};

use alloy_sol_types::SolEvent;
use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::{PrecompileError, Result};

use crate::api::get_active_version;
use crate::handlers::{UpgradeHandlerRegistry, UpgradeHandlerSpec, EMPTY_UPGRADE_HANDLER_REGISTRY};
use crate::schema::Update;
use crate::state::{ProposalInfo, ProposalStatus};

use super::{
    block_ctx, event_count, min_activation, with_update, with_update_provider, UpdateTestExt,
    PROPOSER, V1_2, VOTER_A, VOTER_B,
};

static REGISTERED_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);
static REPLAY_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);

fn registered_counting_handler(_ctx: &BlockRuntimeContext, _proposal: &ProposalInfo) -> Result<()> {
    REGISTERED_HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

fn replay_counting_handler(_ctx: &BlockRuntimeContext, _proposal: &ProposalInfo) -> Result<()> {
    REPLAY_HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

fn failing_handler(_ctx: &BlockRuntimeContext, _proposal: &ProposalInfo) -> Result<()> {
    Err(PrecompileError::Fatal("handler failed".into()))
}

static REGISTERED_HANDLER_SPEC: UpgradeHandlerSpec = UpgradeHandlerSpec {
    version: Some(V1_2),
    label: "registered_counting_handler",
    handler: registered_counting_handler,
};

static REPLAY_HANDLER_SPEC: UpgradeHandlerSpec = UpgradeHandlerSpec {
    version: Some(V1_2),
    label: "replay_counting_handler",
    handler: replay_counting_handler,
};

static FAILING_HANDLER_SPEC: UpgradeHandlerSpec = UpgradeHandlerSpec {
    version: Some(V1_2),
    label: "failing_handler",
    handler: failing_handler,
};

static REGISTERED_HANDLER_REGISTRY: UpgradeHandlerRegistry =
    UpgradeHandlerRegistry::new(&[REGISTERED_HANDLER_SPEC]);

static REPLAY_HANDLER_REGISTRY: UpgradeHandlerRegistry =
    UpgradeHandlerRegistry::new(&[REPLAY_HANDLER_SPEC]);

static FAILING_HANDLER_REGISTRY: UpgradeHandlerRegistry =
    UpgradeHandlerRegistry::new(&[FAILING_HANDLER_SPEC]);

fn approve_and_wait_for_activation(
    update: &mut Update<'_>,
    proposal_id: alloy_primitives::U256,
    current: u64,
) {
    update
        .cast_vote_approve(proposal_id, VOTER_A, true, current + 1)
        .unwrap();
    update
        .cast_vote_approve(proposal_id, VOTER_B, true, current + 2)
        .unwrap();

    let deadline = update
        .read_proposal(proposal_id)
        .unwrap()
        .unwrap()
        .voting_deadline_height;
    update.process_begin_block_test(deadline + 1).unwrap();
    assert_eq!(
        update.read_proposal(proposal_id).unwrap().unwrap().status,
        ProposalStatus::Approved
    );
}

#[test]
fn activation_without_handler_succeeds() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        let proposal_id = update
            .create_proposal(PROPOSER, V1_2, activation, b"", current)
            .unwrap();
        approve_and_wait_for_activation(&mut update, proposal_id, current);

        let ctx = block_ctx(storage.clone(), activation);
        update
            .process_begin_block_with_handlers(&ctx, &EMPTY_UPGRADE_HANDLER_REGISTRY)
            .unwrap();

        assert_eq!(
            update.read_proposal(proposal_id).unwrap().unwrap().status,
            ProposalStatus::Activated
        );
        assert_eq!(get_active_version(storage).unwrap(), Some(V1_2));
    });
}

#[test]
fn registered_handler_is_called_before_activation() {
    REGISTERED_HANDLER_CALLS.store(0, Ordering::SeqCst);
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        let proposal_id = update
            .create_proposal(PROPOSER, V1_2, activation, b"", current)
            .unwrap();
        approve_and_wait_for_activation(&mut update, proposal_id, current);

        let ctx = block_ctx(storage.clone(), activation);
        update
            .process_begin_block_with_handlers(&ctx, &REGISTERED_HANDLER_REGISTRY)
            .unwrap();

        assert_eq!(REGISTERED_HANDLER_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(
            update.read_proposal(proposal_id).unwrap().unwrap().status,
            ProposalStatus::Activated
        );
        assert_eq!(get_active_version(storage).unwrap(), Some(V1_2));
    });
}

#[test]
fn handler_failure_is_fatal_and_leaves_proposal_unactivated() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        let proposal_id = update
            .create_proposal(PROPOSER, V1_2, activation, b"", current)
            .unwrap();
        approve_and_wait_for_activation(&mut update, proposal_id, current);

        let ctx = block_ctx(storage.clone(), activation);
        let err = update
            .process_begin_block_with_handlers(&ctx, &FAILING_HANDLER_REGISTRY)
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Fatal(message) if message.contains("handler failed")
        ));

        assert_eq!(
            update.read_proposal(proposal_id).unwrap().unwrap().status,
            ProposalStatus::Approved
        );
        assert_ne!(get_active_version(storage).unwrap(), Some(V1_2));
    });
}

#[test]
fn activated_proposal_does_not_reinvoke_handler_on_replay() {
    REPLAY_HANDLER_CALLS.store(0, Ordering::SeqCst);
    let provider = with_update_provider(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        let proposal_id = update
            .create_proposal(PROPOSER, V1_2, activation, b"", current)
            .unwrap();
        approve_and_wait_for_activation(&mut update, proposal_id, current);

        let ctx = block_ctx(storage.clone(), activation);
        update
            .process_begin_block_with_handlers(&ctx, &REPLAY_HANDLER_REGISTRY)
            .unwrap();
        update
            .process_begin_block_with_handlers(&ctx, &REPLAY_HANDLER_REGISTRY)
            .unwrap();
    });

    assert_eq!(REPLAY_HANDLER_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(
        event_count(
            &provider,
            crate::precompile::IUpdate::UpgradeActivated::SIGNATURE_HASH,
        ),
        1
    );
}
