use std::sync::atomic::{AtomicUsize, Ordering};

use alloy_primitives::{B256, U256};
use alloy_sol_types::SolEvent;
use outbe_ocompregistry::{poc_schema_limits, OcompRegistry};
use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};
use outbe_primitives::tee_attestation_v1::{
    AttestationMode, PlatformTcbStatusSetV1, QvlTcbStatusV1, TeeMeasurementRuleV1, TeePolicyV1,
};
use outbe_teeregistry::TeeRegistry;

use crate::api::get_active_version;
use crate::handlers::{UpgradeHandler, UpgradeHandlerRegistry};
use crate::schema::ScheduledUpdateStatus;
use crate::schema::Update;
use crate::state::ScheduledUpdateInfo;
use crate::ProtocolVersion;

use super::{
    block_ctx, min_activation, ocomp_authority, ocomp_successor, schedule_update, with_update,
    with_update_provider, CHAIN_ID, PV,
};

static EMPTY_UPGRADE_HANDLER_REGISTRY: UpgradeHandlerRegistry = UpgradeHandlerRegistry::new(&[]);

static REGISTERED_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);
static REPLAY_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);

struct RegisteredCountingHandler;

impl UpgradeHandler for RegisteredCountingHandler {
    fn version(&self) -> ProtocolVersion {
        PV
    }

    fn label(&self) -> &'static str {
        "registered_counting_handler"
    }

    fn handle(&self, _ctx: &BlockRuntimeContext, _scheduled: &ScheduledUpdateInfo) -> Result<()> {
        REGISTERED_HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct ReplayCountingHandler;

impl UpgradeHandler for ReplayCountingHandler {
    fn version(&self) -> ProtocolVersion {
        PV
    }

    fn label(&self) -> &'static str {
        "replay_counting_handler"
    }

    fn handle(&self, _ctx: &BlockRuntimeContext, _scheduled: &ScheduledUpdateInfo) -> Result<()> {
        REPLAY_HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct FailingHandler;

impl UpgradeHandler for FailingHandler {
    fn version(&self) -> ProtocolVersion {
        PV
    }

    fn label(&self) -> &'static str {
        "failing_handler"
    }

    fn handle(&self, _ctx: &BlockRuntimeContext, _scheduled: &ScheduledUpdateInfo) -> Result<()> {
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

fn update_tee_policy(
    genesis_hash: B256,
    policy_version: u64,
    activation_height: u64,
    predecessor_policy_hash: B256,
    mrenclave: B256,
) -> TeePolicyV1 {
    TeePolicyV1 {
        policy_version,
        chain_id: U256::from(CHAIN_ID).to_be_bytes(),
        genesis_hash,
        activation_height,
        predecessor_policy_hash,
        attestation_mode: AttestationMode::DcapRequired,
        intel_root_der_hash: B256::repeat_byte(0x61),
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
        resource_schedule_hash: B256::repeat_byte(0x62),
        measurement_rules: vec![TeeMeasurementRuleV1 {
            mrenclave,
            mrsigner: B256::repeat_byte(0x64),
            isv_prod_id: 7,
            minimum_isv_svn: 2,
            admit_from_height: activation_height,
            admit_until_height_exclusive: u64::MAX,
        }],
    }
}

#[test]
fn activation_without_handler_succeeds() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        let proposal_id = U256::from(1);
        schedule_update(&mut update, proposal_id, PV, activation, "", current).unwrap();

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
        assert_eq!(get_active_version(storage).unwrap(), PV);
    });
}

#[test]
fn software_update_activation_promotes_its_staged_tee_policy() {
    let genesis_hash = B256::repeat_byte(0x60);
    let proposal_id = U256::from(11);
    let activation = 101;
    let current = update_tee_policy(genesis_hash, 1, 1, B256::ZERO, B256::repeat_byte(0x65));
    let successor = update_tee_policy(
        genesis_hash,
        2,
        activation,
        current.policy_hash().unwrap(),
        B256::repeat_byte(0x66),
    );
    let mut provider = HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, genesis_hash);
    provider.set_block_number(1);
    StorageHandle::enter(&mut provider, |storage| {
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&current).unwrap();
        registry
            .stage_successor_policy_v1(proposal_id, &successor)
            .unwrap();
        schedule_update(
            &mut Update::new(storage),
            proposal_id,
            PV,
            activation,
            "TEE release",
            1,
        )
        .unwrap();
    });

    provider.set_block_number(activation);
    StorageHandle::enter(&mut provider, |storage| {
        let ctx = block_ctx(storage.clone(), activation);
        Update::new(storage.clone())
            .process_begin_block_with_handlers(&ctx, &EMPTY_UPGRADE_HANDLER_REGISTRY)
            .unwrap();
        assert_eq!(
            TeeRegistry::new(storage).active_policy_v1().unwrap(),
            successor
        );
    });
}

#[test]
fn software_update_activation_promotes_ocomp_and_keeps_the_predecessor_readable() {
    let genesis_hash = B256::repeat_byte(0x70);
    let proposal_id = U256::from(21);
    let activation = 101;
    let current = ocomp_authority(genesis_hash);
    let successor = ocomp_successor(genesis_hash, activation);
    let limits = poc_schema_limits();
    let mut provider = HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, genesis_hash);
    provider.set_block_number(1);
    StorageHandle::enter(&mut provider, |storage| {
        let mut registry = OcompRegistry::new(storage.clone());
        registry
            .initialize_genesis_authority(&current, B256::repeat_byte(0x71), 1, 1, &limits)
            .unwrap();
        registry
            .stage_successor(proposal_id, &successor, &limits)
            .unwrap();
        schedule_update(
            &mut Update::new(storage),
            proposal_id,
            PV,
            activation,
            "OCOMP release",
            1,
        )
        .unwrap();
    });

    provider.set_block_number(activation);
    StorageHandle::enter(&mut provider, |storage| {
        let ctx = block_ctx(storage.clone(), activation);
        Update::new(storage.clone())
            .process_begin_block_with_handlers(&ctx, &EMPTY_UPGRADE_HANDLER_REGISTRY)
            .unwrap();
        let registry = OcompRegistry::new(storage);
        assert_eq!(
            registry.active_authority(&limits).unwrap(),
            Some(successor.authority.clone())
        );
        assert_eq!(
            registry
                .authority_by_bundle_hash(current.request_profile.protocol_bundle_hash, &limits)
                .unwrap(),
            Some(current)
        );
        assert_eq!(registry.staged_successor(&limits).unwrap(), None);
    });
}

#[test]
fn handler_failure_rolls_back_tee_policy_promotion_with_update_activation() {
    let genesis_hash = B256::repeat_byte(0x67);
    let proposal_id = U256::from(12);
    let activation = 101;
    let current = update_tee_policy(genesis_hash, 1, 1, B256::ZERO, B256::repeat_byte(0x68));
    let successor = update_tee_policy(
        genesis_hash,
        2,
        activation,
        current.policy_hash().unwrap(),
        B256::repeat_byte(0x69),
    );
    let mut provider = HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, genesis_hash);
    provider.set_block_number(1);
    StorageHandle::enter(&mut provider, |storage| {
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&current).unwrap();
        registry
            .stage_successor_policy_v1(proposal_id, &successor)
            .unwrap();
        schedule_update(
            &mut Update::new(storage),
            proposal_id,
            PV,
            activation,
            "TEE release",
            1,
        )
        .unwrap();
    });

    provider.set_block_number(activation);
    StorageHandle::enter(&mut provider, |storage| {
        let ctx = block_ctx(storage.clone(), activation);
        assert!(matches!(
            Update::new(storage.clone())
                .process_begin_block_with_handlers(&ctx, &FAILING_HANDLER_REGISTRY),
            Err(PrecompileError::Fatal(_))
        ));
        let registry = TeeRegistry::new(storage.clone());
        assert_eq!(registry.active_policy_v1().unwrap(), current);
        assert_eq!(
            registry.staged_successor_policy_v1().unwrap(),
            Some((proposal_id, successor))
        );
        assert_eq!(
            Update::new(storage)
                .read_scheduled_update(proposal_id)
                .unwrap()
                .unwrap()
                .status,
            ScheduledUpdateStatus::Scheduled
        );
    });
}

#[test]
fn activating_update_discards_staged_policy_owned_by_canceled_update() {
    let genesis_hash = B256::repeat_byte(0x6a);
    let staged_proposal_id = U256::from(13);
    let activating_proposal_id = U256::from(14);
    let staged_activation = 202;
    let activating_height = 101;
    let current = update_tee_policy(genesis_hash, 1, 1, B256::ZERO, B256::repeat_byte(0x6b));
    let successor = update_tee_policy(
        genesis_hash,
        2,
        staged_activation,
        current.policy_hash().unwrap(),
        B256::repeat_byte(0x6c),
    );
    let mut provider = HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, genesis_hash);
    provider.set_block_number(1);
    StorageHandle::enter(&mut provider, |storage| {
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&current).unwrap();
        registry
            .stage_successor_policy_v1(staged_proposal_id, &successor)
            .unwrap();
        let mut update = Update::new(storage);
        schedule_update(
            &mut update,
            staged_proposal_id,
            PV,
            staged_activation,
            "superseded TEE release",
            1,
        )
        .unwrap();
        schedule_update(
            &mut update,
            activating_proposal_id,
            PV,
            activating_height,
            "selected release",
            1,
        )
        .unwrap();
    });

    provider.set_block_number(activating_height);
    StorageHandle::enter(&mut provider, |storage| {
        let ctx = block_ctx(storage.clone(), activating_height);
        Update::new(storage.clone())
            .process_begin_block_with_handlers(&ctx, &EMPTY_UPGRADE_HANDLER_REGISTRY)
            .unwrap();

        let registry = TeeRegistry::new(storage.clone());
        assert_eq!(registry.active_policy_v1().unwrap(), current);
        assert_eq!(registry.staged_successor_policy_v1().unwrap(), None);

        let update = Update::new(storage);
        assert_eq!(
            update
                .read_scheduled_update(activating_proposal_id)
                .unwrap()
                .unwrap()
                .status,
            ScheduledUpdateStatus::Activated
        );
        assert_eq!(
            update
                .read_scheduled_update(staged_proposal_id)
                .unwrap()
                .unwrap()
                .status,
            ScheduledUpdateStatus::Canceled
        );
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
        schedule_update(&mut update, proposal_id, PV, activation, "", current).unwrap();

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
        assert_eq!(get_active_version(storage).unwrap(), PV);
    });
}

#[test]
fn handler_failure_is_fatal_and_leaves_update_unactivated() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        let proposal_id = U256::from(1);
        schedule_update(&mut update, proposal_id, PV, activation, "", current).unwrap();

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
        assert_ne!(get_active_version(storage).unwrap(), PV);
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
        schedule_update(&mut update, proposal_id, PV, activation, "", current).unwrap();

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
