use std::sync::atomic::{AtomicUsize, Ordering};

use alloy_primitives::U256;
use alloy_sol_types::SolEvent;
use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::{PrecompileError, Result};

use crate::api::get_active_version;
use crate::handlers::{UpgradeHandler, UpgradeHandlerRegistry};
use crate::schema::ScheduledUpdateStatus;
use crate::schema::Update;
use crate::state::ScheduledUpdateInfo;
use crate::ProtocolVersion;

use super::{block_ctx, min_activation, schedule_update, with_update, with_update_provider, V1_2};

static EMPTY_UPGRADE_HANDLER_REGISTRY: UpgradeHandlerRegistry = UpgradeHandlerRegistry::new(&[]);

static REGISTERED_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);
static REPLAY_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);

struct RegisteredCountingHandler;

impl UpgradeHandler for RegisteredCountingHandler {
    fn version(&self) -> ProtocolVersion {
        V1_2
    }

    fn label(&self) -> &'static str {
        "registered_counting_handler"
    }

    fn handle(
        &self,
        _ctx: &BlockRuntimeContext,
        _scheduled: &ScheduledUpdateInfo,
    ) -> Result<()> {
        REGISTERED_HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct ReplayCountingHandler;

impl UpgradeHandler for ReplayCountingHandler {
    fn version(&self) -> ProtocolVersion {
        V1_2
    }

    fn label(&self) -> &'static str {
        "replay_counting_handler"
    }

    fn handle(
        &self,
        _ctx: &BlockRuntimeContext,
        _scheduled: &ScheduledUpdateInfo,
    ) -> Result<()> {
        REPLAY_HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct FailingHandler;

impl UpgradeHandler for FailingHandler {
    fn version(&self) -> ProtocolVersion {
        V1_2
    }

    fn label(&self) -> &'static str {
        "failing_handler"
    }

    fn handle(
        &self,
        _ctx: &BlockRuntimeContext,
        _scheduled: &ScheduledUpdateInfo,
    ) -> Result<()> {
        Err(PrecompileError::Fatal("handler failed".into()))
    }
}

static REGISTERED_COUNTING_HANDLER: RegisteredCountingHandler = RegisteredCountingHandler;
static REPLAY_COUNTING_HANDLER: ReplayCountingHandler = ReplayCountingHandler;
static FAILING_HANDLER: FailingHandler = FailingHandler;

static REGISTERED_HANDLER_REGISTRY: UpgradeHandlerRegistry =
    UpgradeHandlerRegistry::new(&[&REGISTERED_COUNTING_HANDLER]);

static REPLAY_HANDLER_REGISTRY: UpgradeHandlerRegistry =
    UpgradeHandlerRegistry::new(&[&REPLAY_COUNTING_HANDLER]);

static FAILING_HANDLER_REGISTRY: UpgradeHandlerRegistry =
    UpgradeHandlerRegistry::new(&[&FAILING_HANDLER]);

#[test]
fn activation_without_handler_succeeds() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        let proposal_id = U256::from(1);
        schedule_update(&mut update, proposal_id, V1_2, activation, "", current).unwrap();

        let ctx = block_ctx(storage.clone(), activation);
        update
            .process_begin_block_with_handlers(&ctx, &EMPTY_UPGRADE_HANDLER_REGISTRY)
            .unwrap();

        assert_eq!(
            update
                .read_scheduled_update(proposal_id)
                .unwrap()
                .unwrap()
                .status,
            ScheduledUpdateStatus::Activated
        );
        assert_eq!(get_active_version(storage).unwrap(), V1_2);
    });
}

#[test]
fn registered_handler_is_called_before_activation() {
    REGISTERED_HANDLER_CALLS.store(0, Ordering::SeqCst);
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        let proposal_id = U256::from(1);
        schedule_update(&mut update, proposal_id, V1_2, activation, "", current).unwrap();

        let ctx = block_ctx(storage.clone(), activation);
        update
            .process_begin_block_with_handlers(&ctx, &REGISTERED_HANDLER_REGISTRY)
            .unwrap();

        assert_eq!(REGISTERED_HANDLER_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(
            update
                .read_scheduled_update(proposal_id)
                .unwrap()
                .unwrap()
                .status,
            ScheduledUpdateStatus::Activated
        );
        assert_eq!(get_active_version(storage).unwrap(), V1_2);
    });
}

#[test]
fn handler_failure_is_fatal_and_leaves_update_unactivated() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        let proposal_id = U256::from(1);
        schedule_update(&mut update, proposal_id, V1_2, activation, "", current).unwrap();

        let ctx = block_ctx(storage.clone(), activation);
        let err = update
            .process_begin_block_with_handlers(&ctx, &FAILING_HANDLER_REGISTRY)
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Fatal(message) if message.contains("handler failed")
        ));

        assert_eq!(
            update
                .read_scheduled_update(proposal_id)
                .unwrap()
                .unwrap()
                .status,
            ScheduledUpdateStatus::Scheduled
        );
        assert_ne!(get_active_version(storage).unwrap(), V1_2);
    });
}

#[test]
fn activated_update_does_not_reinvoke_handler_on_replay() {
    REPLAY_HANDLER_CALLS.store(0, Ordering::SeqCst);
    let provider = with_update_provider(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        let proposal_id = U256::from(1);
        schedule_update(&mut update, proposal_id, V1_2, activation, "", current).unwrap();

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

fn event_count(
    provider: &outbe_primitives::storage::hashmap::HashMapStorageProvider,
    topic0: alloy_primitives::B256,
) -> usize {
    use outbe_primitives::addresses::UPDATE_ADDRESS;
    provider
        .get_events(UPDATE_ADDRESS)
        .iter()
        .filter(|log| log.topics().first() == Some(&topic0))
        .count()
}
