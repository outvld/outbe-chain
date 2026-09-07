//! Embedded OCOMP observer and local FullNode readiness gate.
//!
//! Finalized chain state remains the only authority. ExEx notifications are
//! drained for Reth backpressure, while the provider's finalized head selects
//! the exact canonical range processed here.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{DirBuilder, File, OpenOptions},
    io::{Read as _, Write},
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::Duration,
};

use alloy_consensus::{BlockHeader as _, Transaction as _, TxReceipt as _};
use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolEvent as _;
use eyre::{bail, Context as _};
use futures::StreamExt as _;
use metrics::{counter, gauge, histogram};
use outbe_metadosis::precompile::IMetadosis;
use outbe_node::{
    finalized_frame::{read_bounded_finalized_frames, FinalizedFrame, RethFinalizedFrameSource},
    ocomp::retention::{observe_finalized_request, FinalizedRequestObservationV1},
    projection::{
        projection_frame_failure_class, FinalizedProjectionSink, FinalizedTargetReconciliationV1,
        ProjectionRuntimeRecoveryHandle, ProjectionRuntimeRecoveryV1, ReadyOffchainDataProjection,
        RuntimeBodyFailure, PROJECTION_RECOVERY_DEADLINE,
    },
};
use outbe_ocomp::payout_submitter::PayoutTickOutcomeV1;
use outbe_ocomp::{
    bundle::PinnedProtocolBundle,
    discovery_control::DiscoveryOfferRefV1,
    discovery_spool::{ContiguousCheckpointStoreV1, DiscoverySpoolV1, RetirementReportV1},
    embedded::{
        EmbeddedJobActionV1, EmbeddedJobEventV1, EmbeddedJobGenerationV1, EmbeddedJobStateV1,
        EmbeddedOcompJobsV1, EmbeddedOcompModeV1, EmbeddedTerminalReasonV1,
    },
    embedded_runtime::{
        EmbeddedComputeOutcomeV1, EmbeddedMaterializationOutcomeV1, EmbeddedNodePolicyV1,
        EmbeddedOcompBundleConfigV1, EmbeddedOcompDomainConfigV1, EmbeddedOcompDomainV1,
        EmbeddedOcompRuntimeErrorV1, EmbeddedPayoutOutcomeV1, EmbeddedVoteOutcomeV1,
    },
    supervisor::DiscoveryRecord,
};
use outbe_ocomp_protocol::{
    common::BoundedBytes,
    control::{FinalizedJobSpecV1, FinalizedJobSummaryV1},
    local_control::EndpointIdentity,
    profile::poc_schema_limits,
    result::LysisResultV1,
    state::{OcompJobRecordV1, OcompJobStatus},
    vote::{decode_submit_lysis_result, ResultVoteV1},
};
use outbe_primitives::{
    addresses::METADOSIS_ADDRESS,
    projection::{
        ProjectionCheckpoint, ProjectionFailure, ProjectionFailureClass,
        ProjectionReadinessPublisher, ProjectionStatus,
    },
    storage::readonly::{ReadOnlyStorageProvider, StorageReader},
    storage::StorageHandle,
    OutbeReceipt,
};
use reth_ethereum::exex::{ExExContext, ExExEvent, ExExNotificationsStream};
use reth_node_builder::FullNodeComponents;
use reth_primitives_traits::Block as _;
use reth_provider::{
    BlockHashReader, BlockIdReader, BlockNumReader, BlockReader, ReceiptProvider, StateProvider,
    StateProviderFactory,
};
use tracing::{error, info, warn};

/// Days each embedded payout tick looks back over.
const PAYOUT_LOOKBACK_DAYS: u32 = 30;
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// The drain and finalized reader share one publication order. Once either
/// reports a fatal failure, an in-flight reader tick cannot overwrite it.
#[derive(Clone)]
struct OcompReadinessV1(Arc<std::sync::Mutex<ProjectionReadinessPublisher>>);

impl OcompReadinessV1 {
    fn publish(&self, status: ProjectionStatus) {
        match self.0.lock() {
            Ok(publisher) => {
                if !matches!(publisher.current(), ProjectionStatus::Fatal { .. }) {
                    publisher.publish(status);
                }
            }
            Err(poisoned) => poisoned.into_inner().publish(ProjectionStatus::Fatal {
                checkpoint: None,
                error: ProjectionFailure::new(
                    ProjectionFailureClass::Other,
                    "OCOMP readiness publication lock is poisoned",
                ),
            }),
        }
    }
}

#[derive(Clone)]
pub struct OcompExExBundleConfigV1 {
    pub worker_address: std::net::SocketAddr,
    pub identity: EndpointIdentity,
    pub protocol_bundle: PinnedProtocolBundle,
}

#[derive(Clone)]
pub struct OcompExExConfigV1 {
    pub domain_root: PathBuf,
    pub discovery_spool_root: PathBuf,
    pub bundles: Vec<OcompExExBundleConfigV1>,
    pub policy: EmbeddedNodePolicyV1,
    pub validator_rpc_url: Option<String>,
    pub chain_id: u64,
    pub genesis_hash: B256,
    pub retention_selector: Arc<outbe_node::ocomp::retention::SharedOcompRetentionSelector>,
    pub retention_required: bool,
}

#[derive(Clone, Debug)]
pub struct OcompExExExitV1 {
    pub failure: ProjectionFailure,
}

#[derive(Debug)]
enum RetentionReconciliationDispositionV1 {
    ProcessFrame,
    RetryFrame(outbe_node::ocomp::retention::RetentionError),
    Fatal(outbe_node::ocomp::retention::RetentionError),
}

fn classify_retention_reconciliation(
    result: Result<(), outbe_node::ocomp::retention::RetentionError>,
    retention_required: bool,
) -> RetentionReconciliationDispositionV1 {
    match result {
        Ok(()) => RetentionReconciliationDispositionV1::ProcessFrame,
        Err(outbe_node::ocomp::retention::RetentionError::RetentionCoordinatorNotInstalled)
            if !retention_required =>
        {
            RetentionReconciliationDispositionV1::ProcessFrame
        }
        Err(
            error @ (outbe_node::ocomp::retention::RetentionError::JournalUnavailable { .. }
            | outbe_node::ocomp::retention::RetentionError::Quarantined(_)
            | outbe_node::ocomp::retention::RetentionError::RegistryCapacity
            | outbe_node::ocomp::retention::RetentionError::RetentionCoordinatorNotInstalled),
        ) => RetentionReconciliationDispositionV1::RetryFrame(error),
        Err(error) => RetentionReconciliationDispositionV1::Fatal(error),
    }
}

fn retention_runtime_error_requires_frame_retry(error: &eyre::Report) -> bool {
    matches!(
        error.downcast_ref::<outbe_node::ocomp::retention::RetentionError>(),
        Some(
            outbe_node::ocomp::retention::RetentionError::JournalUnavailable { .. }
                | outbe_node::ocomp::retention::RetentionError::Quarantined(_)
                | outbe_node::ocomp::retention::RetentionError::RegistryCapacity
        )
    )
}

#[derive(Clone, Copy, Debug)]
struct RequestLocatorV1 {
    intent_id: B256,
    wwd: u32,
    pending_nonce: u64,
    attempt: u32,
    activation_preconditions_hash: B256,
    block_number: u64,
    block_hash: B256,
    state_root: B256,
    before_request: ProjectionCheckpoint,
}

struct RuntimeJobV1 {
    record: DiscoveryRecord,
    generation: EmbeddedJobGenerationV1,
    cancelled: Arc<AtomicBool>,
    compute_started: bool,
    vote_eligibility: LocalVoteEligibilityV1,
    vote_started: bool,
    canonical_result: Option<LysisResultV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalVoteEligibilityV1 {
    Pending,
    Eligible,
    NotMember,
}

fn advance_vote_eligibility(
    current: LocalVoteEligibilityV1,
    observed: outbe_node::ocomp::retention::OcompSnapshotEligibilityV1,
) -> eyre::Result<LocalVoteEligibilityV1> {
    if current != LocalVoteEligibilityV1::Pending {
        return Ok(current);
    }
    match observed {
        outbe_node::ocomp::retention::OcompSnapshotEligibilityV1::Eligible => {
            Ok(LocalVoteEligibilityV1::Eligible)
        }
        outbe_node::ocomp::retention::OcompSnapshotEligibilityV1::NotMember => {
            Ok(LocalVoteEligibilityV1::NotMember)
        }
        outbe_node::ocomp::retention::OcompSnapshotEligibilityV1::Unavailable { .. } => {
            Ok(LocalVoteEligibilityV1::Pending)
        }
        outbe_node::ocomp::retention::OcompSnapshotEligibilityV1::Corrupt { detail } => {
            bail!("pinned OCOMP vote membership is corrupt: {detail}");
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MaterializationAttemptKeyV1 {
    queue_sequence: u64,
    first_nod_ordinal: u32,
}

fn bound_materialization_attempts(
    attempts: &mut BTreeMap<MaterializationAttemptKeyV1, u64>,
    current: Option<MaterializationAttemptKeyV1>,
) {
    attempts.retain(|key, _| Some(*key) == current);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CanonicalJobDispositionV1 {
    AwaitingFinality,
    FinalizedAwaitingOpen,
    VotingOpen,
    Completed,
    Closed {
        reason: EmbeddedTerminalReasonV1,
        has_finalized_job: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AsyncOutcomeProjectionV1 {
    Active,
    CheckpointPruned,
}

fn classify_async_outcome_projection(
    runtime_generation: Option<EmbeddedJobGenerationV1>,
    reducer_generation: Option<EmbeddedJobGenerationV1>,
) -> eyre::Result<AsyncOutcomeProjectionV1> {
    match (runtime_generation, reducer_generation) {
        (Some(runtime), Some(reducer)) if runtime == reducer => {
            Ok(AsyncOutcomeProjectionV1::Active)
        }
        (None, None) => Ok(AsyncOutcomeProjectionV1::CheckpointPruned),
        (Some(_), Some(_)) => {
            bail!("OCOMP runtime and reducer generations disagree");
        }
        (Some(_), None) | (None, Some(_)) => {
            bail!("OCOMP runtime and reducer projections disagree");
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalResultRestorePolicyV1 {
    Never,
    BeforeCompute,
    AfterCanonicalCompleted,
}

fn local_result_restore_policy(
    disposition: CanonicalJobDispositionV1,
    policy: EmbeddedNodePolicyV1,
    discovered: bool,
    eligibility_became_available: bool,
    compute_started: bool,
) -> LocalResultRestorePolicyV1 {
    match disposition {
        CanonicalJobDispositionV1::VotingOpen
            if discovered || eligibility_became_available || !compute_started =>
        {
            LocalResultRestorePolicyV1::BeforeCompute
        }
        CanonicalJobDispositionV1::Completed
            if policy == EmbeddedNodePolicyV1::FullNode && (discovered || !compute_started) =>
        {
            LocalResultRestorePolicyV1::AfterCanonicalCompleted
        }
        CanonicalJobDispositionV1::AwaitingFinality
        | CanonicalJobDispositionV1::FinalizedAwaitingOpen
        | CanonicalJobDispositionV1::VotingOpen
        | CanonicalJobDispositionV1::Completed
        | CanonicalJobDispositionV1::Closed { .. } => LocalResultRestorePolicyV1::Never,
    }
}

fn classify_canonical_job(
    status: OcompJobStatus,
    has_finalized_job: bool,
) -> eyre::Result<CanonicalJobDispositionV1> {
    Ok(match status {
        OcompJobStatus::AwaitingFinality if !has_finalized_job => {
            CanonicalJobDispositionV1::AwaitingFinality
        }
        OcompJobStatus::AwaitingFinality => CanonicalJobDispositionV1::FinalizedAwaitingOpen,
        OcompJobStatus::VotingOpen if has_finalized_job => CanonicalJobDispositionV1::VotingOpen,
        OcompJobStatus::Completed if has_finalized_job => CanonicalJobDispositionV1::Completed,
        OcompJobStatus::Expired => CanonicalJobDispositionV1::Closed {
            reason: EmbeddedTerminalReasonV1::Expired,
            has_finalized_job,
        },
        OcompJobStatus::Failed => CanonicalJobDispositionV1::Closed {
            reason: EmbeddedTerminalReasonV1::Failed,
            has_finalized_job,
        },
        OcompJobStatus::VotingOpen | OcompJobStatus::Completed => {
            bail!("OCOMP canonical status/finalized payload shape is invalid");
        }
    })
}

async fn wait_for_node_teardown() -> ! {
    std::future::pending::<()>().await;
    unreachable!("pending future completed")
}

fn finalized_reader_lags(finalized_head: u64, scanned: u64, closed: u64) -> (u64, u64) {
    (
        finalized_head.saturating_sub(scanned),
        finalized_head.saturating_sub(closed),
    )
}

fn publish_finalized_reader_metrics(finalized_head: u64, scanned: u64, closed: u64) {
    let (reader_lag, closure_lag) = finalized_reader_lags(finalized_head, scanned, closed);
    gauge!("outbe_ocomp_finalized_head_number").set(finalized_head as f64);
    gauge!("outbe_ocomp_finalized_reader_checkpoint_number").set(scanned as f64);
    gauge!("outbe_ocomp_finalized_reader_lag_blocks").set(reader_lag as f64);
    gauge!("outbe_ocomp_closure_checkpoint_number").set(closed as f64);
    gauge!("outbe_ocomp_closure_lag_blocks").set(closure_lag as f64);
}

fn record_discovery_retirement_report(report: RetirementReportV1) {
    if report.completed != 0 {
        counter!("outbe_ocomp_discovery_spool_retired_total").increment(report.completed);
    }
    gauge!("outbe_ocomp_discovery_spool_retirement_intents")
        .set(report.waiting_for_checkpoint as f64);
}

struct EmbeddedOcompExExV1<P> {
    provider: P,
    policy: EmbeddedNodePolicyV1,
    domain: EmbeddedOcompDomainV1,
    readiness: OcompReadinessV1,
    exit: tokio::sync::mpsc::UnboundedSender<OcompExExExitV1>,
    requests: BTreeMap<B256, RequestLocatorV1>,
    materialized_requests: BTreeSet<B256>,
    jobs: BTreeMap<B256, RuntimeJobV1>,
    intent_jobs: BTreeMap<B256, B256>,
    discovery_spools: BTreeMap<B256, DiscoverySpoolV1>,
    pending_offers: BTreeMap<B256, DiscoveryOfferRefV1>,
    acknowledged_exports: BTreeSet<B256>,
    retention_selector: Arc<outbe_node::ocomp::retention::SharedOcompRetentionSelector>,
    closure_checkpoint: ContiguousCheckpointStoreV1,
    latest_scanned_checkpoint: ProjectionCheckpoint,
    state: EmbeddedOcompJobsV1,
    scanned_height: u64,
    scanned_hash: B256,
    compute_tx: mpsc::Sender<EmbeddedComputeOutcomeV1>,
    compute_rx: mpsc::Receiver<EmbeddedComputeOutcomeV1>,
    vote_tx: mpsc::Sender<EmbeddedVoteOutcomeV1>,
    vote_rx: mpsc::Receiver<EmbeddedVoteOutcomeV1>,
    materialization_tx: mpsc::Sender<EmbeddedMaterializationOutcomeV1>,
    materialization_rx: mpsc::Receiver<EmbeddedMaterializationOutcomeV1>,
    materialization_active: Option<MaterializationAttemptKeyV1>,
    payout_tx: mpsc::Sender<EmbeddedPayoutOutcomeV1>,
    payout_rx: mpsc::Receiver<EmbeddedPayoutOutcomeV1>,
    payout_active: bool,
    materialization_attempt_heights: BTreeMap<MaterializationAttemptKeyV1, u64>,
    chain_id: u64,
    genesis_hash: B256,
    fatal: Option<ProjectionFailure>,
}

pub async fn run_ocomp_exex<Node>(
    ctx: ExExContext<Node>,
    ready_projection: ReadyOffchainDataProjection,
    config: OcompExExConfigV1,
    readiness: ProjectionReadinessPublisher,
    exit: tokio::sync::mpsc::UnboundedSender<OcompExExExitV1>,
) -> eyre::Result<()>
where
    Node: FullNodeComponents,
    Node::Provider: BlockIdReader
        + BlockHashReader
        + BlockNumReader
        + BlockReader
        + ReceiptProvider<Receipt = OutbeReceipt>
        + StateProviderFactory
        + Clone
        + Send
        + Sync
        + 'static,
{
    gauge!("outbe_ocomp_finalized_loop_fatal").set(0.0);
    let readiness = OcompReadinessV1(Arc::new(std::sync::Mutex::new(readiness)));
    let provider = ctx.provider().clone();
    // OCOMP owns a nonexecuting finalized reader. Its closure is not an EVM
    // execution head, and must never select Reth historical execution backfill.
    let notifications = without_execution_backfill(ctx.notifications);
    let drain_readiness = readiness.clone();
    let drain_exit = exit.clone();
    let mut notification_drain = tokio::task::JoinSet::new();
    notification_drain.spawn(async move {
        let error = drain_exex_notifications(notifications).await;
        let failure = ProjectionFailure::new(ProjectionFailureClass::Other, error.to_string());
        drain_readiness.publish(ProjectionStatus::Fatal {
            checkpoint: None,
            error: failure.clone(),
        });
        let _ = drain_exit.send(OcompExExExitV1 { failure });
        error
    });
    let limits = poc_schema_limits();
    let mut discovery_spools = BTreeMap::new();
    for bundle in &config.bundles {
        let bundle_hash = bundle.protocol_bundle.hash();
        discovery_spools.insert(
            bundle_hash,
            DiscoverySpoolV1::open(
                config
                    .discovery_spool_root
                    .join(hex::encode(bundle_hash.as_slice())),
                config.chain_id,
                config.genesis_hash,
                limits,
            )?,
        );
    }
    let closure_checkpoint = ContiguousCheckpointStoreV1::open(
        config.discovery_spool_root.join("closure-checkpoint-v1"),
        ProjectionCheckpoint {
            block_number: 0,
            block_hash: config.genesis_hash,
        },
    )?;
    let domain = EmbeddedOcompDomainV1::open(EmbeddedOcompDomainConfigV1 {
        domain_root: config.domain_root,
        registry_generation: 1,
        bundles: config
            .bundles
            .into_iter()
            .map(|bundle| EmbeddedOcompBundleConfigV1 {
                worker_address: bundle.worker_address,
                identity: bundle.identity,
                protocol_bundle: bundle.protocol_bundle,
            })
            .collect(),
        policy: config.policy,
        validator_rpc_url: config.validator_rpc_url,
        limits,
    })
    .map_err(|error| eyre::eyre!("open Node-owned OCOMP domain: {error}"))?;
    if let Some(detail) = load_persisted_fatal_evidence(domain.fatal_evidence_root())? {
        gauge!("outbe_ocomp_finalized_loop_fatal").set(1.0);
        let failure = ProjectionFailure::new(
            ProjectionFailureClass::Other,
            format!("embedded OCOMP persisted fatal evidence: {detail}"),
        );
        readiness.publish(ProjectionStatus::Fatal {
            checkpoint: None,
            error: failure.clone(),
        });
        let _ = exit.send(OcompExExExitV1 { failure });
        wait_for_node_teardown().await;
    }
    let closed = closure_checkpoint.current()?;
    if closed.block_number > 0 {
        let canonical = provider
            .block_hash(closed.block_number)
            .wrap_err("validate unified OCOMP closure checkpoint")?
            .ok_or_else(|| eyre::eyre!("unified OCOMP closure checkpoint is unavailable"))?;
        if canonical != closed.block_hash {
            bail!("unified OCOMP closure checkpoint conflicts with canonical history");
        }
    }
    readiness.publish(ProjectionStatus::CatchingUp {
        checkpoint: Some(closed),
    });
    let projection_sink = Arc::new(std::sync::Mutex::new(FinalizedProjectionSink::new(
        ready_projection,
    )));
    let (mut projection_runtime_failures, projection_runtime_recovery) = {
        let sink = projection_sink
            .lock()
            .map_err(|_| eyre::eyre!("unified projection sink lock is poisoned"))?;
        (
            sink.runtime_failure_receiver()?,
            sink.runtime_recovery_handle()?,
        )
    };
    {
        let sink = projection_sink
            .lock()
            .map_err(|_| eyre::eyre!("unified projection sink lock is poisoned"))?;
        if let Some(projected) = sink.durable_checkpoint() {
            if projected.block_number < closed.block_number
                || (projected.block_number == closed.block_number
                    && projected.block_hash != closed.block_hash)
            {
                bail!("unified OCOMP closure checkpoint is ahead of durable projection");
            }
        } else if closed.block_number != 0 {
            bail!("unified OCOMP closure exists before the durable projection checkpoint");
        }
    }
    let mut startup_retirements = RetirementReportV1::default();
    for spool in discovery_spools.values() {
        let report = spool.complete_retirements_through(closed.block_number)?;
        startup_retirements.completed = startup_retirements
            .completed
            .saturating_add(report.completed);
        startup_retirements.waiting_for_checkpoint = startup_retirements
            .waiting_for_checkpoint
            .saturating_add(report.waiting_for_checkpoint);
    }
    record_discovery_retirement_report(startup_retirements);
    let frame_source = RethFinalizedFrameSource::new(provider.clone());
    let mode = match config.policy {
        EmbeddedNodePolicyV1::Validator => EmbeddedOcompModeV1::Validator,
        EmbeddedNodePolicyV1::FullNode => EmbeddedOcompModeV1::FullNode,
    };
    let (compute_tx, compute_rx) = mpsc::channel();
    let (vote_tx, vote_rx) = mpsc::channel();
    let (materialization_tx, materialization_rx) = mpsc::channel();
    let (payout_tx, payout_rx) = mpsc::channel();
    let mut runtime = EmbeddedOcompExExV1 {
        provider,
        policy: config.policy,
        domain,
        readiness,
        exit,
        requests: BTreeMap::new(),
        materialized_requests: BTreeSet::new(),
        jobs: BTreeMap::new(),
        intent_jobs: BTreeMap::new(),
        discovery_spools,
        pending_offers: BTreeMap::new(),
        acknowledged_exports: BTreeSet::new(),
        retention_selector: config.retention_selector,
        closure_checkpoint,
        latest_scanned_checkpoint: closed,
        state: EmbeddedOcompJobsV1::new(mode),
        scanned_height: closed.block_number,
        scanned_hash: closed.block_hash,
        compute_tx,
        compute_rx,
        vote_tx,
        vote_rx,
        materialization_tx,
        materialization_rx,
        materialization_active: None,
        payout_tx,
        payout_rx,
        payout_active: false,
        materialization_attempt_heights: BTreeMap::new(),
        chain_id: config.chain_id,
        genesis_hash: config.genesis_hash,
        fatal: None,
    };

    let mut poll = tokio::time::interval(POLL_INTERVAL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut projection_health = tokio::time::interval(Duration::from_millis(250));
    projection_health.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut projection_unavailable_since = None;
    let mut projection_runtime_recovery_task = None;
    // Keep one sampled target throughout catch-up. Historical voting state
    // never authorizes effects; mandatory Completed verification uses this target.
    let mut recovery_target = None;
    let mut initial_finished_height_published = false;
    loop {
        let projection_runtime_deadline =
            projection_unavailable_since.map(|(_, since)| since + PROJECTION_RECOVERY_DEADLINE);
        tokio::select! {
            _ = wait_for_optional_deadline(projection_runtime_deadline) => {
                if let Some(failure) = consume_projection_runtime_deadline(
                    &projection_runtime_failures,
                    &mut projection_unavailable_since,
                ) {
                    projection_sink
                        .lock()
                        .map_err(|_| eyre::eyre!("unified projection sink lock is poisoned"))?
                        .publish_failure(failure.clone());
                    runtime.latch_external_failure(failure);
                    wait_for_node_teardown().await;
                }
            }
            _ = projection_health.tick() => {
                if let Some(failure) = projection_runtime_failure(
                    &projection_runtime_failures,
                    &mut projection_unavailable_since,
                    &projection_runtime_recovery,
                    &mut projection_runtime_recovery_task,
                ).await {
                    projection_sink
                        .lock()
                        .map_err(|_| eyre::eyre!("unified projection sink lock is poisoned"))?
                        .publish_failure(failure.clone());
                    runtime.latch_external_failure(failure);
                    wait_for_node_teardown().await;
                }
            }
            changed = projection_runtime_failures.changed() => {
                let failure = if changed.is_err() {
                    Some(projection_runtime_watch_closed_failure())
                } else {
                    projection_runtime_failure(
                        &projection_runtime_failures,
                        &mut projection_unavailable_since,
                        &projection_runtime_recovery,
                        &mut projection_runtime_recovery_task,
                    ).await
                };
                if let Some(failure) = failure {
                    projection_sink
                        .lock()
                        .map_err(|_| eyre::eyre!("unified projection sink lock is poisoned"))?
                        .publish_failure(failure.clone());
                    runtime.latch_external_failure(failure);
                    wait_for_node_teardown().await;
                }
            }
            result = notification_drain.join_next() => {
                runtime.latch_external_failure(ProjectionFailure::new(
                    ProjectionFailureClass::Other,
                    format!("OCOMP notification drain terminated: {result:?}"),
                ));
                wait_for_node_teardown().await;
            }
            _ = poll.tick() => {
                let tick_result: eyre::Result<()> = async {
                while let Ok(outcome) = runtime.compute_rx.try_recv() {
                    if let Err(error) = runtime.handle_compute(outcome) {
                        runtime.latch_fatal(B256::ZERO, format!("{error:#}"))?;
                        wait_for_node_teardown().await;
                    }
                    if runtime.fatal.is_some() {
                        wait_for_node_teardown().await;
                    }
                }
                while let Ok(outcome) = runtime.vote_rx.try_recv() {
                    if let Err(error) = runtime.handle_vote(outcome) {
                        runtime.latch_fatal(B256::ZERO, format!("{error:#}"))?;
                        wait_for_node_teardown().await;
                    }
                    if runtime.fatal.is_some() {
                        wait_for_node_teardown().await;
                    }
                }
                while let Ok(outcome) = runtime.materialization_rx.try_recv() {
                    runtime.handle_materialization(outcome);
                }
                while let Ok(outcome) = runtime.payout_rx.try_recv() {
                    runtime.handle_payout(outcome);
                }

                let finalized_target = runtime
                    .provider
                    .finalized_block_num_hash()
                    .wrap_err("sample unified finalized head")?;
                let reconciliation = projection_sink
                    .lock()
                    .map_err(|_| eyre::eyre!("unified projection sink lock is poisoned"))?
                    .reconcile_finalized_target(finalized_target.as_ref().map(|target| {
                        ProjectionCheckpoint {
                            block_number: target.number,
                            block_hash: target.hash,
                        }
                    }))?;
                let finalized_target = match reconciliation {
                    FinalizedTargetReconciliationV1::AwaitingProviderRecovery => None,
                    FinalizedTargetReconciliationV1::Process {
                        target,
                        recovered_floor,
                    } => {
                        let sampled = finalized_target.ok_or_else(|| {
                            eyre::eyre!("projection accepted an absent finalized target")
                        })?;
                        if sampled.number != target.block_number || sampled.hash != target.block_hash {
                            bail!("projection reconciled a different finalized target identity");
                        }
                        if let Some(floor) = recovered_floor {
                            let canonical = runtime
                                .provider
                                .block_hash(floor.block_number)
                                .wrap_err("revalidate recovered durable projection floor")?
                                .ok_or_else(|| {
                                    eyre::eyre!(
                                        "recovered durable projection floor {} ({}) is unavailable",
                                        floor.block_number,
                                        floor.block_hash
                                    )
                                })?;
                            if canonical != floor.block_hash {
                                bail!(
                                    "recovered durable projection floor {} changed from {} to {}",
                                    floor.block_number,
                                    floor.block_hash,
                                    canonical
                                );
                            }
                        }
                        Some(*recovery_target.get_or_insert(sampled))
                    }
                };
                if let Some(target) = finalized_target {
                    if !initial_finished_height_published {
                        let checkpoint = runtime.closure_checkpoint.current()?;
                        if checkpoint.block_number > target.number {
                            bail!("durable OCOMP closure is ahead of recovered finality");
                        }
                        publish_finished_height(&ctx.events, checkpoint)?;
                        initial_finished_height_published = true;
                    }
                    publish_finalized_reader_metrics(
                        target.number,
                        runtime.scanned_height,
                        runtime.closure_checkpoint.current()?.block_number,
                    );
                    let next_height = runtime
                        .scanned_height
                        .checked_add(1)
                        .ok_or_else(|| eyre::eyre!("unified finalized height overflow"))?;
                    let source = frame_source.clone();
                    let batch = tokio::task::spawn_blocking(move || {
                        read_bounded_finalized_frames(&source, next_height, target)
                    })
                    .await
                    .wrap_err("unified finalized reader worker failed")??;
                    if let Some(batch) = batch {
                        histogram!("outbe_ocomp_finalized_reader_batch_blocks")
                            .record(batch.frames().len() as f64);
                        'frames: for frame in batch.frames() {
                            let request_observation = observe_finalized_request(frame)?;
                            match classify_retention_reconciliation(
                                runtime
                                    .retention_selector
                                    .reconcile_finalized_frame(frame, request_observation),
                                config.retention_required,
                            ) {
                                RetentionReconciliationDispositionV1::ProcessFrame => {}
                                RetentionReconciliationDispositionV1::Fatal(error) => {
                                    return Err(error).wrap_err("finalized retention identity conflict");
                                }
                                RetentionReconciliationDispositionV1::RetryFrame(error) => {
                                    warn!(
                                        %error,
                                        block_number = frame.identity().number,
                                        block_hash = %frame.identity().hash,
                                        "unified OCOMP retention is not ready; retrying the same finalized frame"
                                    );
                                    break 'frames;
                                }
                            }
                            runtime.record_request_observation(frame, request_observation)?;
                            let sink = Arc::clone(&projection_sink);
                            let projected_frame = frame.clone();
                            let projection_deadline =
                                tokio::time::Instant::now() + PROJECTION_RECOVERY_DEADLINE;
                            let projection_write_deadline = projection_deadline.into_std();
                            let mut projection_task = tokio::task::spawn_blocking(move || {
                                sink.lock()
                                    .map_err(|_| eyre::eyre!("unified projection sink lock is poisoned"))?
                                    .project_frame_until(&projected_frame, projection_write_deadline)
                            });
                            let projection_result = loop {
                                let runtime_recovery_deadline = projection_unavailable_since
                                    .map(|(_, since)| since + PROJECTION_RECOVERY_DEADLINE);
                                tokio::select! {
                                    biased;
                                    _ = tokio::time::sleep_until(projection_deadline) => {
                                        let failure = ProjectionFailure::new(
                                            ProjectionFailureClass::MongoReconnectDeadline,
                                            "unified durable projection exceeded the recovery deadline",
                                        );
                                        runtime.latch_external_failure(failure);
                                        wait_for_node_teardown().await;
                                    }
                                    _ = wait_for_optional_deadline(runtime_recovery_deadline) => {
                                        if let Some(failure) = consume_projection_runtime_deadline(
                                            &projection_runtime_failures,
                                            &mut projection_unavailable_since,
                                        ) {
                                            runtime.latch_external_failure(failure);
                                            wait_for_node_teardown().await;
                                        }
                                    }
                                    result = &mut projection_task => break result,
                                    _ = projection_health.tick() => {
                                        if let Some(failure) = projection_runtime_failure(
                                            &projection_runtime_failures,
                                            &mut projection_unavailable_since,
                                            &projection_runtime_recovery,
                                            &mut projection_runtime_recovery_task,
                                        ).await {
                                            runtime.latch_external_failure(failure);
                                            wait_for_node_teardown().await;
                                        }
                                    }
                                    changed = projection_runtime_failures.changed() => {
                                        let failure = if changed.is_err() {
                                            Some(projection_runtime_watch_closed_failure())
                                        } else {
                                            projection_runtime_failure(
                                                &projection_runtime_failures,
                                                &mut projection_unavailable_since,
                                                &projection_runtime_recovery,
                                                &mut projection_runtime_recovery_task,
                                            ).await
                                        };
                                        if let Some(failure) = failure {
                                            runtime.latch_external_failure(failure);
                                            wait_for_node_teardown().await;
                                        }
                                    }
                                }
                            };
                            if let Err(error) = projection_result
                                .wrap_err("unified projection worker failed")
                                .and_then(|result| result)
                            {
                                let failure = projection_task_failure(error);
                                projection_sink
                                    .lock()
                                    .map_err(|_| eyre::eyre!("unified projection sink lock is poisoned"))?
                                    .publish_failure(failure.clone());
                                runtime.latch_external_failure(failure);
                                wait_for_node_teardown().await;
                            }
                            runtime.record_scanned_frame(frame)?;
                            // Reconcile against the sampled target as history arrives.
                            // Suppress old voting/offer effects, but preserve mandatory
                            // FullNode verification of canonically Completed jobs.
                            if let Err(error) = runtime.refresh_jobs(target.number, target.hash, false).await {
                                if retention_runtime_error_requires_frame_retry(&error) {
                                    warn!(%error, "OCOMP replay awaiting durable retention metadata");
                                    break 'frames;
                                }
                                return Err(error);
                            }
                            counter!("outbe_ocomp_finalized_reader_blocks_total").increment(1);
                            if frame.identity() == target {
                                runtime.reconcile_materialization(frame)?;
                                runtime.drive_payout(frame.block().header().timestamp());
                            }
                        }
                    }
                    projection_sink
                        .lock()
                        .map_err(|_| eyre::eyre!("unified projection sink lock is poisoned"))?
                        .publish_progress(ProjectionCheckpoint {
                            block_number: target.number,
                            block_hash: target.hash,
                        })?;
                    runtime
                        .retention_selector
                        .notify_finalized_height(target.number);
                    if runtime.scanned_height == target.number {
                        if let Err(error) = runtime.refresh_jobs(target.number, target.hash, true).await {
                            if retention_runtime_error_requires_frame_retry(&error) {
                                warn!(%error, "OCOMP recovery awaiting durable retention; retrying finalized reconciliation");
                                return Ok(());
                            }
                            return Err(error);
                        }
                        recovery_target = None;
                    }
                }

                gauge!("outbe_ocomp_discovery_pending_offers")
                    .set(runtime.pending_offers.len() as f64);

                if let Some(checkpoint) = runtime.flush_closure_checkpoint()? {
                    publish_finished_height(&ctx.events, checkpoint)?;
                }
                if let Some(target) = finalized_target {
                    if recovery_target.is_none() {
                        runtime.publish_observation_progress(ProjectionCheckpoint {
                            block_number: target.number,
                            block_hash: target.hash,
                        })?;
                    }
                    publish_finalized_reader_metrics(
                        target.number,
                        runtime.scanned_height,
                        runtime.closure_checkpoint.current()?.block_number,
                    );
                }
                Ok(())
                }.await;
                if let Err(error) = tick_result {
                    counter!("outbe_ocomp_finalized_loop_errors_total").increment(1);
                    runtime.latch_fatal(B256::ZERO, format!("unified finalized loop failed: {error:#}"))?;
                    wait_for_node_teardown().await;
                }
            }
        }
    }
}

impl<P> EmbeddedOcompExExV1<P>
where
    P: BlockIdReader
        + BlockHashReader
        + BlockReader
        + ReceiptProvider<Receipt = OutbeReceipt>
        + StateProviderFactory
        + Clone
        + Send
        + Sync
        + 'static,
{
    fn record_request_observation(
        &mut self,
        frame: &FinalizedFrame,
        observation: Option<FinalizedRequestObservationV1>,
    ) -> eyre::Result<()> {
        let Some(observation) = observation else {
            return Ok(());
        };
        let identity = frame.identity();
        let number = identity.number;
        let hash = identity.hash;
        let locator = RequestLocatorV1 {
            intent_id: observation.intent_id,
            wwd: observation.wwd,
            pending_nonce: observation.pending_nonce,
            attempt: observation.attempt,
            activation_preconditions_hash: observation.activation_preconditions_hash,
            block_number: number,
            block_hash: hash,
            state_root: frame.state_root(),
            before_request: ProjectionCheckpoint {
                block_number: number.saturating_sub(1),
                block_hash: frame.parent_hash(),
            },
        };
        self.validate_request(&locator, hash)?;
        match self.requests.get(&locator.intent_id) {
            Some(existing) if same_locator(*existing, locator) => {}
            Some(_) => {
                bail!("conflicting OCOMP request locator replay");
            }
            None => {
                self.requests.insert(locator.intent_id, locator);
            }
        }
        Ok(())
    }

    fn validate_request(&self, locator: &RequestLocatorV1, state_hash: B256) -> eyre::Result<()> {
        let limits = poc_schema_limits();
        let record = outbe_node::ocomp::retention::read_ocomp_job_record_at(
            &self.provider,
            state_hash,
            locator.intent_id,
            &limits,
        )
        .wrap_err("read exact OCOMP request record")?;
        let activation_hash = record
            .intent
            .activation_preconditions
            .activation_preconditions_hash(&limits)
            .wrap_err("hash OCOMP request activation preconditions")?;
        if record.intent_height != locator.block_number
            || record.intent.wwd != locator.wwd
            || record.intent.pending_nonce != locator.pending_nonce
            || record.intent.attempt != locator.attempt
            || activation_hash != locator.activation_preconditions_hash
        {
            bail!("OCOMP request locator disagrees with exact typed state");
        }
        Ok(())
    }

    async fn refresh_jobs(
        &mut self,
        height: u64,
        hash: B256,
        drive_work: bool,
    ) -> eyre::Result<()> {
        let limits = poc_schema_limits();
        let locators = self.requests.values().copied().collect::<Vec<_>>();
        for locator in locators {
            let record = outbe_node::ocomp::retention::read_ocomp_job_record_at(
                &self.provider,
                hash,
                locator.intent_id,
                &limits,
            )
            .wrap_err("read current exact OCOMP job record")?;
            let disposition = classify_canonical_job(record.status, record.finalized.is_some())?;
            match disposition {
                CanonicalJobDispositionV1::AwaitingFinality => continue,
                CanonicalJobDispositionV1::Closed {
                    has_finalized_job: false,
                    ..
                } => {
                    self.materialized_requests.insert(locator.intent_id);
                    continue;
                }
                CanonicalJobDispositionV1::FinalizedAwaitingOpen
                | CanonicalJobDispositionV1::VotingOpen
                | CanonicalJobDispositionV1::Completed
                | CanonicalJobDispositionV1::Closed {
                    has_finalized_job: true,
                    ..
                } => {}
            }
            let finalized = record
                .finalized
                .as_ref()
                .ok_or_else(|| eyre::eyre!("OCOMP finalized payload disappeared"))?;
            if finalized.finalized_request_block_hash != locator.block_hash
                || finalized.finalized_request_state_root != locator.state_root
            {
                bail!("OCOMP finalized job disagrees with its request block identity");
            }
            let job_id = record
                .intent
                .job_id(locator.block_hash, locator.state_root, &limits)
                .wrap_err("derive finalized OCOMP JobId")?;
            if job_id != finalized.job_id {
                bail!("OCOMP finalized job carries a conflicting JobId");
            }
            match self.intent_jobs.insert(locator.intent_id, job_id) {
                Some(existing) if existing != job_id => {
                    bail!("OCOMP intent replay resolved to a conflicting JobId");
                }
                Some(_) | None => {}
            }
            let discovered = !self.jobs.contains_key(&job_id);
            if discovered {
                let retained_candidates =
                    match self.retention_selector.discovery_job_records(job_id) {
                        Ok(record) => record,
                        Err(
                            outbe_node::ocomp::retention::RetentionError::RetentionCoordinatorNotInstalled,
                        ) => continue,
                        Err(outbe_node::ocomp::retention::RetentionError::InvalidTransition(_)) => {
                            let released = match self.retention_selector.released_job_authority(job_id) {
                                Ok(released) => released,
                                Err(outbe_node::ocomp::retention::RetentionError::InvalidTransition(_)) => None,
                                Err(error) => return Err(error.into()),
                            };
                            if let Some(released) = released {
                                if !matches!(disposition, CanonicalJobDispositionV1::Closed { .. } | CanonicalJobDispositionV1::Completed) {
                                    bail!("released OCOMP job is not canonically terminal");
                                }
                                self.verify_released_export_ack(locator, &record, job_id, &limits)?;
                                // Reconstruct the closed runtime projection as well as its
                                // intent mapping: retirement needs the exact original offer.
                                vec![(released.source_generation, outbe_node::ocomp::retention::FinalizedJobPinV1 {
                                    candidate: released.candidate,
                                    job_id,
                                    finality_recorded_height: finalized.finality_recorded_height,
                                    open_height: finalized.open_height,
                                    deadline_height: finalized.deadline_height,
                                })]
                            } else {
                                self.retention_selector
                                    .bind_canonical_finalized_job(locator.block_hash, &record)
                                    .wrap_err("bind OCOMP retention to canonical finalized typed state")?;
                                self.retention_selector
                                    .discovery_job_records(job_id)
                                    .wrap_err("load exact OCOMP retention generation after canonical binding")?
                            }
                        }
                        Err(error) => {
                            return Err(error).wrap_err("load exact OCOMP retention generation");
                        }
                    };
                let input_lease_id = record
                    .intent
                    .input_lease_id()
                    .wrap_err("derive exact OCOMP input lease")?;
                let mut fallback = None;
                let mut selected = None;
                for (source_generation, retained) in retained_candidates {
                    if retained.job_id != job_id
                        || retained.candidate.block_number != locator.block_number
                        || retained.candidate.block_hash != locator.block_hash
                        || retained.candidate.state_root != locator.state_root
                        || retained.candidate.intent_id != locator.intent_id
                        || retained.candidate.wwd != locator.wwd
                        || retained.candidate.ce_sealed_root != record.intent.ce_sealed_root
                        || retained.candidate.protocol_bundle_hash
                            != record.intent.protocol_bundle_hash
                        || retained.candidate.input_lease_id != input_lease_id
                        || retained.finality_recorded_height != finalized.finality_recorded_height
                        || retained.open_height != finalized.open_height
                        || retained.deadline_height != finalized.deadline_height
                    {
                        bail!("OCOMP retained pin disagrees with finalized typed state");
                    }
                    let candidate =
                        discovery_record(locator, &record, job_id, source_generation, &limits)?;
                    let spool = self
                        .discovery_spools
                        .get(&record.intent.protocol_bundle_hash)
                        .ok_or_else(|| {
                            eyre::eyre!(
                                "OCOMP discovery spool is missing for bundle {}",
                                record.intent.protocol_bundle_hash
                            )
                        })?;
                    let probe = DiscoveryOfferRefV1::from_spec(
                        self.chain_id,
                        self.genesis_hash,
                        candidate.generation,
                        &candidate.spec,
                        &limits,
                    )?;
                    let pending = spool.pending(&probe.observation_id)?;
                    let acknowledged = spool.ack(&probe.observation_id)?;
                    let durable_reference = pending
                        .as_ref()
                        .map(|pending| pending.reference.clone())
                        .or_else(|| acknowledged.as_ref().map(|ack| ack.reference.offer_ref()));
                    let has_durable_authority = durable_reference.as_ref() == Some(&probe);
                    if has_durable_authority {
                        if selected.replace(candidate).is_some() {
                            bail!("multiple OCOMP discovery generations have durable authority");
                        }
                    } else if fallback.is_none() {
                        fallback = Some(candidate);
                    }
                }
                let discovery = selected.or(fallback).ok_or_else(|| {
                    eyre::eyre!("OCOMP retention returned no discovery generation")
                })?;
                let generation = self
                    .state
                    .observe_job(job_id, finalized.deadline_height)
                    .wrap_err("observe embedded OCOMP job")?;
                let cancelled = Arc::new(AtomicBool::new(false));
                self.jobs.insert(
                    job_id,
                    RuntimeJobV1 {
                        record: discovery,
                        generation,
                        cancelled,
                        compute_started: false,
                        vote_eligibility: if self.policy == EmbeddedNodePolicyV1::Validator {
                            LocalVoteEligibilityV1::Pending
                        } else {
                            LocalVoteEligibilityV1::NotMember
                        },
                        vote_started: false,
                        canonical_result: None,
                    },
                );
            }
            let canonical_expired = matches!(
                disposition,
                CanonicalJobDispositionV1::Closed {
                    reason: EmbeddedTerminalReasonV1::Expired,
                    ..
                }
            );
            let export_acknowledged = if canonical_expired {
                false
            } else {
                self.reconcile_export_ack(job_id, &record, drive_work)?
            };
            self.retention_selector
                .reconcile_canonical_terminal(&record, height)?;
            if export_acknowledged {
                self.materialized_requests.insert(locator.intent_id);
            }

            match disposition {
                CanonicalJobDispositionV1::FinalizedAwaitingOpen => {}
                CanonicalJobDispositionV1::VotingOpen => {
                    if !export_acknowledged || !drive_work {
                        continue;
                    }
                    let eligibility_became_available =
                        self.refresh_vote_eligibility(locator, &record, job_id)?;
                    let compute_started = self
                        .jobs
                        .get(&job_id)
                        .ok_or_else(|| eyre::eyre!("embedded OCOMP job disappeared"))?
                        .compute_started;
                    if local_result_restore_policy(
                        disposition,
                        self.policy,
                        discovered,
                        eligibility_became_available,
                        compute_started,
                    ) == LocalResultRestorePolicyV1::BeforeCompute
                    {
                        self.restore_local_result(job_id)?;
                    }
                    self.ensure_compute_started(job_id)?;
                }
                CanonicalJobDispositionV1::Completed => {
                    if !export_acknowledged {
                        continue;
                    }
                    self.observe_completed(job_id, &record, height).await?;
                    if self.policy == EmbeddedNodePolicyV1::FullNode {
                        let compute_started = self
                            .jobs
                            .get(&job_id)
                            .ok_or_else(|| eyre::eyre!("embedded OCOMP job disappeared"))?
                            .compute_started;
                        if local_result_restore_policy(
                            disposition,
                            self.policy,
                            discovered,
                            false,
                            compute_started,
                        ) == LocalResultRestorePolicyV1::AfterCanonicalCompleted
                        {
                            self.restore_local_result(job_id)?;
                        }
                        self.ensure_compute_started(job_id)?;
                    }
                }
                CanonicalJobDispositionV1::Closed { reason, .. } => {
                    self.observe_terminal(job_id, reason)?;
                }
                CanonicalJobDispositionV1::AwaitingFinality => {
                    unreachable!("awaiting-finality records returned before job discovery")
                }
            }
            if height >= finalized.deadline_height
                && matches!(
                    self.state.state(job_id),
                    Some(
                        EmbeddedJobStateV1::Computing
                            | EmbeddedJobStateV1::LocalReady
                            | EmbeddedJobStateV1::WaitAtDeadline
                    )
                )
            {
                self.state
                    .reduce(job_id, EmbeddedJobEventV1::Deadline)
                    .wrap_err("observe OCOMP deadline")?;
            }
        }
        Ok(())
    }

    fn reconcile_export_ack(
        &mut self,
        job_id: B256,
        canonical: &OcompJobRecordV1,
        publish_offer: bool,
    ) -> eyre::Result<bool> {
        if self.acknowledged_exports.contains(&job_id) {
            return Ok(true);
        }
        let job = self
            .jobs
            .get(&job_id)
            .ok_or_else(|| eyre::eyre!("embedded OCOMP job disappeared before export"))?;
        let bundle_hash = job.record.spec.summary.protocol_bundle_hash;
        let spool = self.discovery_spools.get(&bundle_hash).ok_or_else(|| {
            eyre::eyre!("OCOMP discovery spool is missing for bundle {bundle_hash}")
        })?;
        let offer = match self.pending_offers.get(&job_id) {
            Some(reference) => reference.clone(),
            None if !publish_offer => DiscoveryOfferRefV1::from_spec(
                self.chain_id,
                self.genesis_hash,
                job.record.generation,
                &job.record.spec,
                &poc_schema_limits(),
            )?,
            None => {
                let (reference, _) = spool.put_offer(job.record.generation, &job.record.spec)?;
                self.pending_offers.insert(job_id, reference.clone());
                info!(
                    %job_id,
                    observation_id = %reference.observation_id,
                    generation = reference.generation,
                    "persisted durable OCOMP discovery offer; awaiting SnapshotExporter ACK"
                );
                reference
            }
        };
        let Some(acknowledgment) = spool.ack(&offer.observation_id)? else {
            return Ok(false);
        };
        if acknowledgment.reference.offer_ref() != offer {
            bail!("OCOMP spool ACK differs from the exact finalized offer");
        }
        self.retention_selector
            .confirm_canonical_export_ack(
                canonical,
                outbe_node::ocomp::retention::ExportAuthorityV1 {
                    source_generation: offer.generation,
                    lease_generation: acknowledgment.lease_generation,
                    manifest_hash: acknowledgment.manifest_hash,
                },
            )
            .wrap_err("commit exact exporter ACK to OCOMP retention")?;
        self.acknowledged_exports.insert(job_id);
        self.pending_offers.remove(&job_id);
        info!(
            %job_id,
            observation_id = %offer.observation_id,
            generation = offer.generation,
            lease_generation = acknowledgment.lease_generation,
            manifest_hash = %acknowledgment.manifest_hash,
            "committed durable SnapshotExporter ACK"
        );
        Ok(true)
    }

    fn verify_released_export_ack(
        &self,
        locator: RequestLocatorV1,
        record: &OcompJobRecordV1,
        job_id: B256,
        limits: &outbe_ocomp_protocol::SchemaLimits,
    ) -> eyre::Result<()> {
        let released = self
            .retention_selector
            .released_job_authority(job_id)?
            .ok_or_else(|| eyre::eyre!("closed OCOMP job has no released retention authority"))?;
        let input_lease_id = record
            .intent
            .input_lease_id()
            .wrap_err("derive released OCOMP input lease")?;
        if released.job_id != job_id
            || released.candidate.block_number != locator.block_number
            || released.candidate.block_hash != locator.block_hash
            || released.candidate.state_root != locator.state_root
            || released.candidate.intent_id != locator.intent_id
            || released.candidate.wwd != locator.wwd
            || released.candidate.ce_sealed_root != record.intent.ce_sealed_root
            || released.candidate.protocol_bundle_hash != record.intent.protocol_bundle_hash
            || released.candidate.input_lease_id != input_lease_id
        {
            bail!("released OCOMP retention authority conflicts with canonical typed state");
        }
        let candidate =
            discovery_record(locator, record, job_id, released.source_generation, limits)?;
        let recovered_export =
            if released.export.is_none() && record.status != OcompJobStatus::Expired {
                let spool = self
                    .discovery_spools
                    .get(&candidate.spec.summary.protocol_bundle_hash)
                    .ok_or_else(|| eyre::eyre!("released OCOMP job references an unknown spool"))?;
                let probe = DiscoveryOfferRefV1::from_spec(
                    self.chain_id,
                    self.genesis_hash,
                    released.source_generation,
                    &candidate.spec,
                    limits,
                )?;
                let ack = spool.ack(&probe.observation_id)?.ok_or_else(|| {
                    eyre::eyre!("released OCOMP job has no durable discovery ACK")
                })?;
                if ack.reference.offer_ref() != probe {
                    bail!("released OCOMP ACK differs from its original finalized offer");
                }
                let export = outbe_node::ocomp::retention::ExportAuthorityV1 {
                    source_generation: probe.generation,
                    lease_generation: ack.lease_generation,
                    manifest_hash: ack.manifest_hash,
                };
                self.retention_selector
                    .confirm_canonical_export_ack(record, export)?;
                Some(export)
            } else {
                released.export
            };
        let Some(export) = released_export_authority_for_status(record.status, recovered_export)?
        else {
            return Ok(());
        };
        let bundle_hash = candidate.spec.summary.protocol_bundle_hash;
        let spool = self.discovery_spools.get(&bundle_hash).ok_or_else(|| {
            eyre::eyre!("OCOMP discovery spool is missing for bundle {bundle_hash}")
        })?;
        let probe = DiscoveryOfferRefV1::from_spec(
            self.chain_id,
            self.genesis_hash,
            export.source_generation,
            &candidate.spec,
            limits,
        )?;
        let acknowledgment = spool
            .ack(&probe.observation_id)?
            .ok_or_else(|| eyre::eyre!("released OCOMP export has no durable discovery ACK"))?;
        let reference = acknowledgment.reference.offer_ref();
        if reference != probe
            || acknowledgment.lease_generation != export.lease_generation
            || acknowledgment.manifest_hash != export.manifest_hash
        {
            bail!("released OCOMP ACK conflicts with canonical durable authority");
        }
        Ok(())
    }

    fn record_scanned_frame(&mut self, frame: &FinalizedFrame) -> eyre::Result<()> {
        let identity = frame.identity();
        let checkpoint = ProjectionCheckpoint {
            block_number: identity.number,
            block_hash: identity.hash,
        };
        let expected_number = self
            .scanned_height
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("unified OCOMP scan height overflow"))?;
        if checkpoint.block_number != expected_number || frame.parent_hash() != self.scanned_hash {
            bail!("unified OCOMP frame scan is not contiguous");
        }
        self.scanned_height = identity.number;
        self.scanned_hash = identity.hash;
        self.latest_scanned_checkpoint = checkpoint;
        Ok(())
    }

    fn flush_closure_checkpoint(&mut self) -> eyre::Result<Option<ProjectionCheckpoint>> {
        let current = self.closure_checkpoint.current()?;
        let target = self
            .requests
            .values()
            .filter(|locator| !self.request_is_closed(locator.intent_id))
            .min_by_key(|locator| locator.block_number)
            .map_or(self.latest_scanned_checkpoint, |locator| {
                locator.before_request
            });
        if target.block_number <= current.block_number {
            self.prepare_closed_discovery_retirements(current.block_number)?;
            self.complete_discovery_retirements(current.block_number)?;
            self.prune_closed_requests_through(current.block_number)?;
            self.retention_selector
                .notify_closure_checkpoint(current.block_number);
            return Ok(None);
        }
        self.prepare_closed_discovery_retirements(target.block_number)?;
        self.complete_discovery_retirements(current.block_number)?;
        self.closure_checkpoint
            .compare_and_advance_to(current, target)?;
        self.complete_discovery_retirements(target.block_number)?;
        self.prune_closed_requests_through(target.block_number)?;
        self.retention_selector
            .notify_closure_checkpoint(target.block_number);
        Ok(Some(target))
    }

    fn prepare_closed_discovery_retirements(&self, closed_height: u64) -> eyre::Result<()> {
        for (intent_id, locator) in &self.requests {
            if locator.block_number > closed_height || !self.request_is_closed(*intent_id) {
                continue;
            }
            let Some(job_id) = self.intent_jobs.get(intent_id) else {
                continue;
            };
            let job = self.jobs.get(job_id).ok_or_else(|| {
                eyre::eyre!("closed OCOMP job disappeared before spool retirement")
            })?;
            let bundle_hash = job.record.spec.summary.protocol_bundle_hash;
            let spool = self.discovery_spools.get(&bundle_hash).ok_or_else(|| {
                eyre::eyre!("closed OCOMP job references an unknown discovery spool")
            })?;
            let reference = DiscoveryOfferRefV1::from_spec(
                self.chain_id,
                self.genesis_hash,
                job.record.generation,
                &job.record.spec,
                &poc_schema_limits(),
            )?;
            spool.prepare_retirement(&reference, closed_height)?;
        }
        Ok(())
    }

    fn complete_discovery_retirements(&self, closed_height: u64) -> eyre::Result<()> {
        let mut aggregate = RetirementReportV1::default();
        for spool in self.discovery_spools.values() {
            let report = spool.complete_retirements_through(closed_height)?;
            aggregate.completed = aggregate.completed.saturating_add(report.completed);
            aggregate.waiting_for_checkpoint = aggregate
                .waiting_for_checkpoint
                .saturating_add(report.waiting_for_checkpoint);
        }
        record_discovery_retirement_report(aggregate);
        Ok(())
    }

    fn prune_closed_requests_through(&mut self, closed_height: u64) -> eyre::Result<()> {
        let closed_intents = self
            .requests
            .iter()
            .filter_map(|(intent_id, locator)| {
                (locator.block_number <= closed_height && self.request_is_closed(*intent_id))
                    .then_some(*intent_id)
            })
            .collect::<Vec<_>>();
        for intent_id in closed_intents {
            if let Some(job_id) = self.intent_jobs.get(&intent_id).copied() {
                self.state
                    .prune_terminal_job(job_id)
                    .wrap_err("prune exact terminal OCOMP projection")?;
            }
            self.requests.remove(&intent_id);
            self.materialized_requests.remove(&intent_id);
            if let Some(job_id) = self.intent_jobs.remove(&intent_id) {
                self.jobs.remove(&job_id);
                self.acknowledged_exports.remove(&job_id);
                self.pending_offers.remove(&job_id);
            }
        }
        Ok(())
    }

    fn request_is_closed(&self, intent_id: B256) -> bool {
        let job_id = self.intent_jobs.get(&intent_id).copied();
        request_projection_is_closed(
            self.materialized_requests.contains(&intent_id),
            job_id.and_then(|job_id| self.state.state(job_id)),
            job_id.and_then(|job_id| self.state.terminal_reason(job_id)),
        )
    }

    fn publish_observation_progress(&self, target: ProjectionCheckpoint) -> eyre::Result<()> {
        let closed = self.closure_checkpoint.current()?;
        if closed.block_number > target.block_number
            || (closed.block_number == target.block_number
                && closed.block_hash != target.block_hash)
        {
            bail!("OCOMP closure checkpoint is ahead of or conflicts with finalized target");
        }
        let ready_height = self
            .state
            .progress_limit(self.scanned_height.min(target.block_number));
        let ready_hash = self
            .provider
            .block_hash(ready_height)?
            .ok_or_else(|| eyre::eyre!("OCOMP readiness checkpoint is unavailable"))?;
        let checkpoint = ProjectionCheckpoint {
            block_number: ready_height,
            block_hash: ready_hash,
        };
        self.readiness.publish(if checkpoint == target {
            ProjectionStatus::Ready { checkpoint }
        } else {
            ProjectionStatus::CatchingUp {
                checkpoint: Some(checkpoint),
            }
        });
        Ok(())
    }

    fn ensure_compute_started(&mut self, job_id: B256) -> eyre::Result<()> {
        let job = self
            .jobs
            .get_mut(&job_id)
            .ok_or_else(|| eyre::eyre!("embedded OCOMP job disappeared"))?;
        if job.compute_started {
            return Ok(());
        }
        self.domain.spawn_compute(
            job.record.clone(),
            job.generation,
            Arc::clone(&job.cancelled),
            self.compute_tx.clone(),
        )?;
        job.compute_started = true;
        info!(%job_id, "embedded OCOMP computation started");
        Ok(())
    }

    fn restore_local_result(&mut self, job_id: B256) -> eyre::Result<()> {
        let Some(loaded) = self.domain.load_local_result(job_id)? else {
            return Ok(());
        };
        self.jobs
            .get_mut(&job_id)
            .ok_or_else(|| eyre::eyre!("restored OCOMP job is unknown"))?
            .compute_started = true;
        let generation = self
            .jobs
            .get(&job_id)
            .ok_or_else(|| eyre::eyre!("restored OCOMP job is unknown"))?
            .generation;
        self.accept_local_result(
            job_id,
            generation,
            loaded.committed.result_digest,
            loaded.canonical_result,
        )?;
        info!(
            %job_id,
            result_digest = %loaded.committed.result_digest,
            "restored durable embedded OCOMP local result"
        );
        Ok(())
    }

    async fn observe_completed(
        &mut self,
        job_id: B256,
        record: &OcompJobRecordV1,
        finalized_height: u64,
    ) -> eyre::Result<()> {
        if self
            .jobs
            .get(&job_id)
            .and_then(|job| job.canonical_result.as_ref())
            .is_some()
        {
            return Ok(());
        }
        let terminal = record
            .terminal
            .as_ref()
            .ok_or_else(|| eyre::eyre!("completed OCOMP job lacks terminal record"))?;
        let binding = terminal
            .completed_binding
            .as_ref()
            .ok_or_else(|| eyre::eyre!("completed OCOMP job lacks completed binding"))?;
        if binding.quorum_height > finalized_height {
            bail!("OCOMP quorum is ahead of the reconciled finalized target");
        }
        let provider = self.provider.clone();
        let record = record.clone();
        let quorum_height = binding.quorum_height;
        let result_digest = binding.result_digest;
        let vote = tokio::task::spawn_blocking(move || {
            let quorum_hash = provider
                .block_hash(quorum_height)?
                .ok_or_else(|| eyre::eyre!("OCOMP quorum block is unavailable"))?;
            let source = RethFinalizedFrameSource::new(provider);
            let batch = read_bounded_finalized_frames(
                &source,
                quorum_height,
                (quorum_height, quorum_hash).into(),
            )?
            .ok_or_else(|| eyre::eyre!("OCOMP quorum frame is unavailable"))?;
            let frame = batch
                .frames()
                .first()
                .ok_or_else(|| eyre::eyre!("OCOMP quorum frame is missing"))?;
            canonical_vote_from_frame(frame, quorum_height, &record, result_digest)
        })
        .await
        .wrap_err("OCOMP quorum reader worker failed")??;
        let canonical = vote.result;
        let digest = canonical.result_digest(&poc_schema_limits())?;
        self.jobs
            .get_mut(&job_id)
            .ok_or_else(|| eyre::eyre!("embedded OCOMP job disappeared"))?
            .canonical_result = Some(canonical.clone());
        let action = self
            .state
            .reduce(
                job_id,
                EmbeddedJobEventV1::CanonicalCompleted {
                    result_digest: digest,
                },
            )
            .wrap_err("record canonical OCOMP result")?
            .action;
        if matches!(action, EmbeddedJobActionV1::ReleaseProgress { .. }) {
            self.verify_full_node_exact(job_id, &canonical)?;
        } else if let EmbeddedJobActionV1::FatalMismatch {
            local_result_digest,
            canonical_result_digest,
            ..
        } = action
        {
            self.persist_and_publish_mismatch(
                job_id,
                local_result_digest,
                canonical_result_digest,
            )?;
        }
        Ok(())
    }

    fn observe_terminal(
        &mut self,
        job_id: B256,
        reason: EmbeddedTerminalReasonV1,
    ) -> eyre::Result<()> {
        let first_observation = self.state.terminal_reason(job_id).is_none();
        self.state
            .reduce(job_id, EmbeddedJobEventV1::CanonicalClosed { reason })
            .wrap_err("record finalized OCOMP terminal state")?;
        if let Some(job) = self.jobs.get(&job_id) {
            job.cancelled.store(true, Ordering::Release);
        }
        if first_observation && reason == EmbeddedTerminalReasonV1::Expired {
            counter!("outbe_ocomp_canonical_jobs_cancelled_total", "reason" => "expired")
                .increment(1);
        }
        info!(%job_id, ?reason, "embedded OCOMP job reached canonical terminal state");
        Ok(())
    }

    fn handle_compute(&mut self, outcome: EmbeddedComputeOutcomeV1) -> eyre::Result<()> {
        let (generation, completed) = match outcome {
            EmbeddedComputeOutcomeV1::Completed {
                generation,
                completed,
            } => (generation, completed),
            EmbeddedComputeOutcomeV1::Unrecoverable {
                job_id,
                generation,
                detail,
            } => {
                let Some(projection) = self.async_outcome_projection(job_id)? else {
                    return Ok(());
                };
                if projection == AsyncOutcomeProjectionV1::CheckpointPruned {
                    info!(%job_id, %detail, "ignored checkpoint-pruned OCOMP computation failure");
                    return Ok(());
                }
                let action = self
                    .state
                    .reduce(job_id, EmbeddedJobEventV1::LocalFailed { generation })
                    .wrap_err("reduce embedded OCOMP local failure")?
                    .action;
                match action {
                    EmbeddedJobActionV1::FatalLocalFailure => {
                        persist_local_failure_evidence(
                            self.domain.fatal_evidence_root(),
                            job_id,
                            &detail,
                        )?;
                        self.latch_fatal(job_id, detail)?;
                    }
                    EmbeddedJobActionV1::Abstain => {
                        error!(%job_id, %detail, "Validator OCOMP computation failed; abstaining from vote");
                    }
                    EmbeddedJobActionV1::ProtocolOwned => {
                        info!(%job_id, %detail, "ignored late embedded OCOMP computation failure");
                    }
                    _ => {
                        bail!("unexpected embedded OCOMP local-failure action");
                    }
                }
                return Ok(());
            }
        };
        let job_id = completed.job_id;
        let Some(projection) = self.async_outcome_projection(job_id)? else {
            return Ok(());
        };
        if let Some(reason) =
            ignored_compute_result_reason(projection, self.state.terminal_reason(job_id))
        {
            counter!("outbe_ocomp_late_compute_results_ignored_total", "reason" => reason)
                .increment(1);
            info!(%job_id, reason, "ignored late OCOMP result before local persistence");
            return Ok(());
        }
        let committed = self.domain.commit_local_result(&completed)?;
        self.accept_local_result(
            job_id,
            generation,
            committed.result_digest,
            completed.canonical_result,
        )
    }

    fn accept_local_result(
        &mut self,
        job_id: B256,
        generation: EmbeddedJobGenerationV1,
        result_digest: B256,
        canonical_result: Vec<u8>,
    ) -> eyre::Result<()> {
        let action = self
            .state
            .reduce(
                job_id,
                EmbeddedJobEventV1::LocalCompleted {
                    generation,
                    result_digest,
                },
            )
            .wrap_err("record embedded OCOMP local result")?
            .action;
        match action {
            EmbeddedJobActionV1::SubmitVote { .. } => {
                let job = self
                    .jobs
                    .get_mut(&job_id)
                    .ok_or_else(|| eyre::eyre!("computed OCOMP job is unknown"))?;
                match job.vote_eligibility {
                    LocalVoteEligibilityV1::Pending => {
                        info!(%job_id, "pinned OCOMP vote membership is temporarily unavailable; retaining local result");
                    }
                    LocalVoteEligibilityV1::NotMember => {
                        if !job.vote_started {
                            info!(%job_id, "embedded OCOMP Validator is not in the pinned snapshot; abstaining");
                            job.vote_started = true;
                        }
                    }
                    LocalVoteEligibilityV1::Eligible if !job.vote_started => {
                        self.domain.spawn_validator_vote(
                            job.record.clone(),
                            job.generation,
                            result_digest,
                            canonical_result,
                            Arc::clone(&job.cancelled),
                            self.vote_tx.clone(),
                        )?;
                        job.vote_started = true;
                    }
                    LocalVoteEligibilityV1::Eligible => {}
                }
            }
            EmbeddedJobActionV1::ReleaseProgress { .. } => {
                let canonical = self
                    .jobs
                    .get(&job_id)
                    .and_then(|job| job.canonical_result.clone())
                    .ok_or_else(|| eyre::eyre!("canonical OCOMP result disappeared"))?;
                self.verify_full_node_exact(job_id, &canonical)?;
            }
            EmbeddedJobActionV1::FatalMismatch {
                local_result_digest,
                canonical_result_digest,
                ..
            } => self.persist_and_publish_mismatch(
                job_id,
                local_result_digest,
                canonical_result_digest,
            )?,
            EmbeddedJobActionV1::AwaitCanonical { .. } => {}
            // A quorum can form before the local computation finishes; the job
            // is then already canonical-settled and no local action remains.
            EmbeddedJobActionV1::ProtocolOwned => {
                info!(
                    %job_id,
                    %result_digest,
                    "embedded OCOMP local result arrived after canonical settlement; protocol owns the job"
                );
            }
            EmbeddedJobActionV1::AwaitLocalResult { .. }
            | EmbeddedJobActionV1::HoldProgress { .. }
            | EmbeddedJobActionV1::CloseTerminal { .. }
            | EmbeddedJobActionV1::Abstain
            | EmbeddedJobActionV1::FatalLocalFailure
            | EmbeddedJobActionV1::VoteFinalized { .. }
            | EmbeddedJobActionV1::FatalVoteFailure => {
                bail!("unexpected embedded OCOMP local-result action");
            }
        }
        Ok(())
    }

    fn refresh_vote_eligibility(
        &mut self,
        locator: RequestLocatorV1,
        record: &OcompJobRecordV1,
        job_id: B256,
    ) -> eyre::Result<bool> {
        if self.policy != EmbeddedNodePolicyV1::Validator {
            return Ok(false);
        }
        let current = self
            .jobs
            .get(&job_id)
            .ok_or_else(|| eyre::eyre!("embedded OCOMP job disappeared"))?
            .vote_eligibility;
        if current != LocalVoteEligibilityV1::Pending {
            return Ok(false);
        }
        let Some(ocomp_key_hash) = self.domain.validator_ocomp_key_hash() else {
            bail!("Validator OCOMP key hash is unavailable");
        };
        let observed = outbe_node::ocomp::retention::ocomp_snapshot_contains_key_at(
            &self.provider,
            locator.block_hash,
            &record.intent,
            ocomp_key_hash,
        );
        if let outbe_node::ocomp::retention::OcompSnapshotEligibilityV1::Unavailable { detail } =
            &observed
        {
            warn!(%job_id, %detail, "pinned OCOMP vote membership is temporarily unavailable");
        }
        let resolved = advance_vote_eligibility(current, observed)?;
        if resolved == LocalVoteEligibilityV1::Pending {
            return Ok(false);
        }
        self.jobs
            .get_mut(&job_id)
            .ok_or_else(|| eyre::eyre!("embedded OCOMP job disappeared"))?
            .vote_eligibility = resolved;
        Ok(resolved == LocalVoteEligibilityV1::Eligible)
    }

    fn handle_vote(&mut self, outcome: EmbeddedVoteOutcomeV1) -> eyre::Result<()> {
        let (job_id, event, detail) = match outcome {
            EmbeddedVoteOutcomeV1::Finalized {
                job_id,
                generation,
                success,
            } => (
                job_id,
                EmbeddedJobEventV1::VoteFinalized {
                    generation,
                    success,
                },
                None,
            ),
            EmbeddedVoteOutcomeV1::Unrecoverable {
                job_id,
                generation,
                detail,
            } => (
                job_id,
                EmbeddedJobEventV1::VoteFailed { generation },
                Some(detail),
            ),
        };
        let Some(projection) = self.async_outcome_projection(job_id)? else {
            return Ok(());
        };
        if projection == AsyncOutcomeProjectionV1::CheckpointPruned {
            info!(%job_id, "ignored checkpoint-pruned embedded OCOMP vote outcome");
            return Ok(());
        }
        match self
            .state
            .reduce(job_id, event)
            .wrap_err("reduce embedded OCOMP vote outcome")?
            .action
        {
            EmbeddedJobActionV1::VoteFinalized { success } => {
                info!(%job_id, success, "embedded OCOMP vote finalized");
            }
            EmbeddedJobActionV1::FatalVoteFailure => {
                self.latch_fatal(
                    job_id,
                    detail.unwrap_or_else(|| "embedded OCOMP vote failed".to_owned()),
                )?;
            }
            EmbeddedJobActionV1::ProtocolOwned => {
                info!(%job_id, "ignored late embedded OCOMP vote outcome");
            }
            _ => {
                bail!("unexpected embedded OCOMP vote action");
            }
        }
        Ok(())
    }

    fn async_outcome_projection(
        &mut self,
        job_id: B256,
    ) -> eyre::Result<Option<AsyncOutcomeProjectionV1>> {
        let classified = classify_async_outcome_projection(
            self.jobs.get(&job_id).map(|job| job.generation),
            self.state.generation(job_id),
        );
        match classified {
            Ok(projection) => Ok(Some(projection)),
            Err(error) => {
                self.latch_fatal(job_id, format!("{error:#}"))?;
                Ok(None)
            }
        }
    }

    fn reconcile_materialization(&mut self, frame: &FinalizedFrame) -> eyre::Result<()> {
        let identity = frame.identity();
        let height = identity.number;
        let hash = identity.hash;
        let Some(proposer) =
            finalized_materialization_proposer(height, frame.block().body().transactions())?
        else {
            return Ok(());
        };
        let state = self
            .provider
            .state_by_block_hash(hash)
            .wrap_err("open NOD materialization finalized state")?;
        let reader = OcompExExStateReaderV1 {
            state: state.as_ref(),
        };
        let mut readonly = ReadOnlyStorageProvider::new_with_chain_identity(
            reader,
            self.chain_id,
            self.genesis_hash,
        );
        let storage = StorageHandle::new(&mut readonly);
        let head = outbe_nod::NodContract::new(storage.clone())
            .ocomp_materialization_head()
            .wrap_err("read finalized NOD materialization head")?;
        let current_attempt = head.as_ref().map(|head| MaterializationAttemptKeyV1 {
            queue_sequence: head.queue_sequence,
            first_nod_ordinal: head.next_nod_ordinal,
        });
        bound_materialization_attempts(&mut self.materialization_attempt_heights, current_attempt);
        let profile = outbe_chain_constants::NodMaterializationProfileV1 {
            batch_subtree_height:
                outbe_chain_constants::get_nod_materialization_batch_subtree_height(),
            retry_interval_blocks:
                outbe_chain_constants::get_nod_materialization_retry_interval_blocks(),
            max_attempts_per_block:
                outbe_chain_constants::get_nod_materialization_max_attempts_per_block(),
        };
        let represented_validator = match self.domain.validator_sender_address() {
            Some(sender) => outbe_validatorset::contract::ValidatorSet::new(storage.clone())
                .resolve_validator_for_role(
                    sender,
                    outbe_validatorset::delegation::ValidatorDelegateRole::Ocomp,
                )
                .wrap_err("resolve finalized OCOMP materializer")?,
            None => None,
        };
        let progress_observed = head
            .as_ref()
            .is_some_and(|head| head.last_progress_height == height);
        if !should_wake_nod_materializer(
            self.policy,
            represented_validator,
            proposer,
            height,
            head.as_ref(),
            progress_observed,
            profile.retry_interval_blocks,
        ) {
            return Ok(());
        }
        let head = head.ok_or_else(|| eyre::eyre!("materialization wake lost FIFO head"))?;
        let key = MaterializationAttemptKeyV1 {
            queue_sequence: head.queue_sequence,
            first_nod_ordinal: head.next_nod_ordinal,
        };
        if self.materialization_active.is_some()
            || self.materialization_attempt_heights.get(&key) == Some(&height)
        {
            return Ok(());
        }
        // The bundle the generation was certified under is chain state, not runtime
        // state: a node that has forgotten every terminal job still materializes.
        let protocol_bundle_hash = outbe_nod::NodContract::new(storage)
            .ocomp_certified_generation(outbe_primitives::time::WorldwideDay::from(
                head.worldwide_day,
            ))?
            .ok_or_else(|| eyre::eyre!("materialization head has no certified generation"))?
            .protocol_bundle_hash;
        self.domain.spawn_validator_materialization(
            protocol_bundle_hash,
            head,
            profile.batch_subtree_height,
            self.materialization_tx.clone(),
        )?;
        self.materialization_active = Some(key);
        self.materialization_attempt_heights.insert(key, height);
        info!(
            queue_sequence = key.queue_sequence,
            first_nod_ordinal = key.first_nod_ordinal,
            "finalized proposer woke NOD materialization"
        );
        Ok(())
    }

    /// Ticks the payout sender owned by the embedded Supervisor.
    /// One tick at a time: the submitter journals its own progress, so a later
    /// block simply resumes where this one stopped.
    fn drive_payout(&mut self, timestamp: u64) {
        if self.payout_active {
            return;
        }
        // The chain's own clock, not the host's: a localnet can run a shifted
        // genesis, and a day the host has not reached yet still owes its payout.
        let mut day = outbe_primitives::time::worldwide_day_from_timestamp(timestamp);
        let mut days = Vec::with_capacity(PAYOUT_LOOKBACK_DAYS as usize + 1);
        for _ in 0..=PAYOUT_LOOKBACK_DAYS {
            days.push(day);
            day = outbe_primitives::time::previous_date_key(day);
        }
        days.reverse();
        match self.domain.spawn_validator_payout(
            days,
            Arc::new(AtomicBool::new(false)),
            self.payout_tx.clone(),
        ) {
            Ok(()) => self.payout_active = true,
            Err(EmbeddedOcompRuntimeErrorV1::FullNodeVoteAuthority) => {}
            Err(error) => warn!(?error, "OCOMP payout tick could not start"),
        }
    }

    fn handle_payout(&mut self, outcome: EmbeddedPayoutOutcomeV1) {
        self.payout_active = false;
        match outcome {
            EmbeddedPayoutOutcomeV1::Ticked(PayoutTickOutcomeV1::Idle) => {}
            EmbeddedPayoutOutcomeV1::Ticked(outcome) => {
                info!(?outcome, "OCOMP payout tick advanced");
            }
            EmbeddedPayoutOutcomeV1::Failed(detail) => {
                warn!(detail, "OCOMP payout tick failed");
            }
        }
    }

    fn handle_materialization(&mut self, outcome: EmbeddedMaterializationOutcomeV1) {
        let (key, success, detail) = match outcome {
            EmbeddedMaterializationOutcomeV1::Finalized {
                job_id,
                queue_sequence,
                first_nod_ordinal,
                success,
            } => {
                info!(%job_id, queue_sequence, first_nod_ordinal, success, "NOD materialization transaction finalized");
                (
                    MaterializationAttemptKeyV1 {
                        queue_sequence,
                        first_nod_ordinal,
                    },
                    Some(success),
                    None,
                )
            }
            EmbeddedMaterializationOutcomeV1::Unavailable {
                job_id,
                queue_sequence,
                first_nod_ordinal,
                detail,
            } => {
                warn!(%job_id, queue_sequence, first_nod_ordinal, %detail, "NOD materialization attempt unavailable");
                (
                    MaterializationAttemptKeyV1 {
                        queue_sequence,
                        first_nod_ordinal,
                    },
                    None,
                    Some(detail),
                )
            }
        };
        if self.materialization_active == Some(key) {
            self.materialization_active = None;
        }
        let _ = (success, detail);
    }

    fn verify_full_node_exact(&self, job_id: B256, canonical: &LysisResultV1) -> eyre::Result<()> {
        if self.policy == EmbeddedNodePolicyV1::FullNode {
            self.domain
                .verify_exact_canonical_result(job_id, canonical)?;
        }
        Ok(())
    }

    fn persist_and_publish_mismatch(
        &mut self,
        job_id: B256,
        local: B256,
        canonical: B256,
    ) -> eyre::Result<()> {
        persist_fatal_evidence(self.domain.fatal_evidence_root(), job_id, local, canonical)?;
        self.latch_fatal(
            job_id,
            format!("local result {local} differs from canonical result {canonical}"),
        )
    }

    fn latch_fatal(&mut self, job_id: B256, detail: String) -> eyre::Result<()> {
        if self.fatal.is_some() {
            return Ok(());
        }
        persist_generic_fatal_evidence(self.domain.fatal_evidence_root(), job_id, &detail)?;
        error!(%job_id, %detail, "embedded OCOMP requested local node shutdown");
        let failure = ProjectionFailure::new(
            ProjectionFailureClass::Other,
            format!("embedded OCOMP job {job_id}: {detail}"),
        );
        let allowed_height = self.state.progress_limit(self.scanned_height);
        let checkpoint = if allowed_height == self.scanned_height {
            Some(ProjectionCheckpoint {
                block_number: allowed_height,
                block_hash: self.scanned_hash,
            })
        } else {
            self.provider
                .block_hash(allowed_height)
                .ok()
                .flatten()
                .map(|block_hash| ProjectionCheckpoint {
                    block_number: allowed_height,
                    block_hash,
                })
        };
        self.fatal = Some(failure.clone());
        gauge!("outbe_ocomp_finalized_loop_fatal").set(1.0);
        self.readiness.publish(ProjectionStatus::Fatal {
            checkpoint,
            error: failure.clone(),
        });
        let _ = self.exit.send(OcompExExExitV1 { failure });
        Ok(())
    }

    fn latch_external_failure(&mut self, failure: ProjectionFailure) {
        if self.fatal.is_some() {
            return;
        }
        self.fatal = Some(failure.clone());
        gauge!("outbe_ocomp_finalized_loop_fatal").set(1.0);
        self.readiness.publish(ProjectionStatus::Fatal {
            checkpoint: Some(ProjectionCheckpoint {
                block_number: self.scanned_height,
                block_hash: self.scanned_hash,
            }),
            error: failure.clone(),
        });
        let _ = self.exit.send(OcompExExExitV1 { failure });
    }
}

async fn projection_runtime_failure(
    receiver: &tokio::sync::watch::Receiver<Option<RuntimeBodyFailure>>,
    unavailable_since: &mut Option<(u64, tokio::time::Instant)>,
    recovery: &ProjectionRuntimeRecoveryHandle,
    recovery_task: &mut Option<tokio::task::JoinHandle<ProjectionRuntimeRecoveryV1>>,
) -> Option<ProjectionFailure> {
    if recovery_task
        .as_ref()
        .is_some_and(tokio::task::JoinHandle::is_finished)
    {
        match recovery_task.take().expect("finished task exists").await {
            Ok(
                ProjectionRuntimeRecoveryV1::Recovered | ProjectionRuntimeRecoveryV1::Unavailable,
            ) => {}
            Ok(ProjectionRuntimeRecoveryV1::Fatal(failure)) => return Some(failure),
            Err(error) => {
                return Some(ProjectionFailure::new(
                    ProjectionFailureClass::Other,
                    format!("offchain runtime-body recovery worker failed: {error}"),
                ));
            }
        }
    }
    match receiver.borrow().clone() {
        None => {
            *unavailable_since = None;
            None
        }
        Some(RuntimeBodyFailure::Fatal(failure)) => Some(failure),
        Some(RuntimeBodyFailure::Unavailable { generation, since }) => {
            let since = tokio::time::Instant::from_std(since);
            *unavailable_since = Some((generation, since));
            if tokio::time::Instant::now() >= since + PROJECTION_RECOVERY_DEADLINE {
                return Some(projection_runtime_deadline_failure());
            }
            if recovery_task.is_none() {
                let recovery = recovery.clone();
                *recovery_task = Some(tokio::task::spawn_blocking(move || {
                    recovery.reconcile(generation)
                }));
            }
            None
        }
    }
}

async fn wait_for_optional_deadline(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

fn projection_runtime_deadline_failure() -> ProjectionFailure {
    ProjectionFailure::new(
        ProjectionFailureClass::MongoReconnectDeadline,
        "offchain runtime-body storage remained unavailable past the recovery deadline",
    )
}

fn consume_projection_runtime_deadline(
    receiver: &tokio::sync::watch::Receiver<Option<RuntimeBodyFailure>>,
    state: &mut Option<(u64, tokio::time::Instant)>,
) -> Option<ProjectionFailure> {
    let (expected_generation, since) = state.take()?;
    if tokio::time::Instant::now() < since + PROJECTION_RECOVERY_DEADLINE {
        return None;
    }
    matches!(
        receiver.borrow().clone(),
        Some(RuntimeBodyFailure::Unavailable { generation, .. })
            if generation == expected_generation
    )
    .then(projection_runtime_deadline_failure)
}

fn projection_runtime_watch_closed_failure() -> ProjectionFailure {
    ProjectionFailure::new(
        ProjectionFailureClass::ReadinessChannelClosed,
        "offchain runtime-body failure channel closed",
    )
}

fn projection_task_failure(error: eyre::Report) -> ProjectionFailure {
    let class = projection_frame_failure_class(&error);
    ProjectionFailure::new(
        class,
        format!("unified durable projection failed: {error:#}"),
    )
}

fn without_execution_backfill<N, S>(mut notifications: S) -> S
where
    N: reth_primitives_traits::NodePrimitives,
    S: ExExNotificationsStream<N>,
{
    notifications.set_without_head();
    notifications
}

async fn drain_exex_notifications<S, T>(mut notifications: S) -> eyre::Report
where
    S: futures::Stream<Item = eyre::Result<T>> + Unpin,
{
    while let Some(notification) = notifications.next().await {
        if let Err(error) = notification {
            return error.wrap_err("OCOMP live notification stream failed");
        }
    }
    eyre::eyre!("OCOMP live notification stream closed")
}

fn publish_finished_height(
    events: &tokio::sync::mpsc::UnboundedSender<ExExEvent>,
    checkpoint: ProjectionCheckpoint,
) -> eyre::Result<()> {
    events
        .send(ExExEvent::FinishedHeight(
            (checkpoint.block_number, checkpoint.block_hash).into(),
        ))
        .map_err(|_| eyre::eyre!("OCOMP FinishedHeight consumer is unavailable"))
}

#[cfg(test)]
fn all_requests_materialized(
    request_ids: impl IntoIterator<Item = B256>,
    materialized_requests: &BTreeSet<B256>,
) -> bool {
    request_ids
        .into_iter()
        .all(|intent_id| materialized_requests.contains(&intent_id))
}

fn discovery_record(
    locator: RequestLocatorV1,
    record: &OcompJobRecordV1,
    job_id: B256,
    generation: u64,
    limits: &outbe_ocomp_protocol::SchemaLimits,
) -> eyre::Result<DiscoveryRecord> {
    let finalized = record
        .finalized
        .as_ref()
        .ok_or_else(|| eyre::eyre!("OCOMP job is not finalized"))?;
    let spec = FinalizedJobSpecV1 {
        summary: FinalizedJobSummaryV1 {
            cursor: locator.block_number,
            job_id,
            intent_id: locator.intent_id,
            finalized_block_hash: locator.block_hash,
            finalized_state_root: locator.state_root,
            protocol_bundle_hash: record.intent.protocol_bundle_hash,
            open_height: finalized.open_height,
            deadline_height: finalized.deadline_height,
        },
        canonical_job_intent: BoundedBytes(record.intent.encode_canonical(limits)?),
    };
    spec.encode_body(limits)?;
    Ok(DiscoveryRecord {
        generation,
        cursor: locator.block_number,
        spec,
    })
}

fn canonical_vote_from_frame(
    frame: &FinalizedFrame,
    quorum_height: u64,
    record: &OcompJobRecordV1,
    expected_digest: B256,
) -> eyre::Result<ResultVoteV1> {
    if frame.identity().number != quorum_height {
        bail!("q-forming OCOMP vote is not in the current finalized frame");
    }
    let limits = poc_schema_limits();
    let intent_id = record.intent.intent_id(&limits)?;
    let finalized = record
        .finalized
        .as_ref()
        .ok_or_else(|| eyre::eyre!("completed OCOMP job is not finalized"))?;
    let mut matched = None;
    for (transaction, receipt) in frame.block().body().transactions().zip(frame.receipts()) {
        if !receipt.status() {
            continue;
        }
        let activates = receipt.logs().iter().any(|log| {
            if log.address != METADOSIS_ADDRESS
                || log.data.topics().first() != Some(&IMetadosis::LysisActivated::SIGNATURE_HASH)
            {
                return false;
            }
            IMetadosis::LysisActivated::decode_log(log).is_ok_and(|event| {
                event.data.intentId == intent_id
                    && event.data.jobId == finalized.job_id
                    && event.data.resultDigest == expected_digest
            })
        });
        if !activates || transaction.to() != Some(METADOSIS_ADDRESS) {
            continue;
        }
        let vote = decode_submit_lysis_result(transaction.input().as_ref(), &limits)
            .wrap_err("decode q-forming ResultVoteV1")?;
        let digest = vote.result_digest(&limits)?;
        vote.result.validate_finalized_intent(&record.intent)?;
        if vote.job_id != finalized.job_id
            || vote.protocol_bundle_hash != record.intent.protocol_bundle_hash
            || vote.attempt != record.intent.attempt
            || vote.result_validator_set_epoch != record.intent.result_validator_set_epoch
            || vote.result_committee_set_hash != record.intent.result_committee_set_hash
            || vote.result_ocomp_binding_hash != record.intent.result_ocomp_binding_hash
            || digest != expected_digest
        {
            bail!("q-forming ResultVoteV1 disagrees with finalized OCOMP authority");
        }
        if matched.replace(vote).is_some() {
            bail!("more than one q-forming OCOMP vote matched one completed job");
        }
    }
    matched.ok_or_else(|| eyre::eyre!("q-forming OCOMP ResultVoteV1 is missing"))
}

fn same_locator(left: RequestLocatorV1, right: RequestLocatorV1) -> bool {
    left.intent_id == right.intent_id
        && left.wwd == right.wwd
        && left.pending_nonce == right.pending_nonce
        && left.attempt == right.attempt
        && left.activation_preconditions_hash == right.activation_preconditions_hash
        && left.block_number == right.block_number
        && left.block_hash == right.block_hash
        && left.state_root == right.state_root
        && left.before_request == right.before_request
}

fn persist_fatal_evidence(
    root: &Path,
    job_id: B256,
    local: B256,
    canonical: B256,
) -> eyre::Result<()> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700).recursive(true).create(root)?;
    let path = root.join(format!("{}.mismatch-v1", hex::encode(job_id.as_slice())));
    let mut file = match OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    writeln!(file, "job_id={job_id}")?;
    writeln!(file, "local_result_digest={local}")?;
    writeln!(file, "canonical_result_digest={canonical}")?;
    file.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(())
}

const MAX_FATAL_EVIDENCE_BYTES: u64 = 64 * 1024;

fn persist_generic_fatal_evidence(root: &Path, job_id: B256, detail: &str) -> eyre::Result<()> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700).recursive(true).create(root)?;
    let path = root.join("sticky-fatal-v1");
    let mut file = match OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    writeln!(file, "job_id={job_id}")?;
    writeln!(file, "detail={detail}")?;
    file.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(())
}

fn load_persisted_fatal_evidence(root: &Path) -> eyre::Result<Option<String>> {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut paths = entries
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    let Some(path) = paths.into_iter().next() else {
        return Ok(None);
    };
    let file = File::open(&path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_FATAL_EVIDENCE_BYTES {
        bail!("embedded OCOMP fatal evidence has an invalid shape");
    }
    let mut detail = String::new();
    file.take(MAX_FATAL_EVIDENCE_BYTES + 1)
        .read_to_string(&mut detail)?;
    if detail.is_empty() || detail.len() as u64 > MAX_FATAL_EVIDENCE_BYTES {
        bail!("embedded OCOMP fatal evidence has an invalid length");
    }
    Ok(Some(detail))
}

fn persist_local_failure_evidence(root: &Path, job_id: B256, detail: &str) -> eyre::Result<()> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700).recursive(true).create(root)?;
    let path = root.join(format!("{}.fatal-local-v1", hex::encode(job_id.as_slice())));
    let mut file = match OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    writeln!(file, "job_id={job_id}")?;
    writeln!(file, "detail={detail}")?;
    file.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(())
}

fn authenticated_finalized_proposer<'a, T>(
    mut transactions: impl Iterator<Item = &'a T>,
) -> eyre::Result<Address>
where
    T: reth_primitives_traits::SignedTransaction + 'a,
{
    let transaction = transactions
        .next()
        .ok_or_else(|| eyre::eyre!("finalized block has no proposer-signed system transaction"))?;

    transaction
        .try_recover()
        .wrap_err("recover finalized block proposer from system transaction")
}

fn finalized_materialization_proposer<'a, T>(
    height: u64,
    transactions: impl Iterator<Item = &'a T>,
) -> eyre::Result<Option<Address>>
where
    T: reth_primitives_traits::SignedTransaction + 'a,
{
    if height == 0 {
        return Ok(None);
    }
    authenticated_finalized_proposer(transactions).map(Some)
}

fn should_wake_nod_materializer(
    policy: EmbeddedNodePolicyV1,
    represented_validator: Option<Address>,
    block_proposer: Address,
    finalized_height: u64,
    head: Option<&outbe_ocomp_protocol::nod_materialization::NodMaterializationHeadV1>,
    progress_observed: bool,
    retry_interval_blocks: u64,
) -> bool {
    if policy != EmbeddedNodePolicyV1::Validator
        || represented_validator != Some(block_proposer)
        || retry_interval_blocks == 0
    {
        return false;
    }
    let Some(head) = head.filter(|head| head.next_nod_ordinal < head.nod_count) else {
        return false;
    };
    progress_observed
        || finalized_height
            >= head
                .last_progress_height
                .saturating_add(retry_interval_blocks)
}

fn request_projection_is_closed(
    export_acknowledged: bool,
    state: Option<EmbeddedJobStateV1>,
    terminal_reason: Option<EmbeddedTerminalReasonV1>,
) -> bool {
    if terminal_reason == Some(EmbeddedTerminalReasonV1::Expired) {
        return true;
    }
    export_acknowledged
        && !matches!(
            state,
            Some(
                EmbeddedJobStateV1::Computing
                    | EmbeddedJobStateV1::WaitAtDeadline
                    | EmbeddedJobStateV1::LocalReady
            )
        )
}

fn released_export_authority_for_status(
    status: OcompJobStatus,
    export: Option<outbe_node::ocomp::retention::ExportAuthorityV1>,
) -> eyre::Result<Option<outbe_node::ocomp::retention::ExportAuthorityV1>> {
    if export.is_none() && status != OcompJobStatus::Expired {
        bail!("closed non-expired OCOMP job has no released export authority");
    }
    Ok(export)
}

fn ignored_compute_result_reason(
    projection: AsyncOutcomeProjectionV1,
    terminal_reason: Option<EmbeddedTerminalReasonV1>,
) -> Option<&'static str> {
    if projection == AsyncOutcomeProjectionV1::CheckpointPruned {
        Some("checkpoint_pruned")
    } else if terminal_reason == Some(EmbeddedTerminalReasonV1::Expired) {
        Some("expired")
    } else {
        None
    }
}

struct OcompExExStateReaderV1<'a> {
    state: &'a dyn StateProvider,
}

impl StorageReader for OcompExExStateReaderV1<'_> {
    fn read_storage(&self, address: Address, key: B256) -> outbe_primitives::error::Result<U256> {
        self.state
            .storage(address, key)
            .map(|value| value.unwrap_or_default())
            .map_err(|error| {
                outbe_primitives::error::PrecompileError::Storage(format!(
                    "OCOMP ExEx finalized state read failed: {error}"
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drain_fatal_cannot_be_overwritten_by_an_inflight_reader_tick() {
        let checkpoint = ProjectionCheckpoint {
            block_number: 5,
            block_hash: B256::repeat_byte(5),
        };
        let (publisher, handle) = outbe_primitives::projection::projection_readiness(
            checkpoint,
            ProjectionStatus::Ready { checkpoint },
        );
        let readiness = OcompReadinessV1(Arc::new(std::sync::Mutex::new(publisher)));
        let drain = readiness.clone();
        let (sent, received) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            drain.publish(ProjectionStatus::Fatal {
                checkpoint: None,
                error: ProjectionFailure::new(ProjectionFailureClass::Other, "drain closed"),
            });
            sent.send(()).unwrap();
        });
        received.recv().unwrap();
        readiness.publish(ProjectionStatus::Ready { checkpoint });
        thread.join().unwrap();
        assert!(
            matches!(handle.current(), ProjectionStatus::Fatal { error, .. } if error.message.as_ref() == "drain closed")
        );
    }

    #[tokio::test]
    async fn real_reth_restart_stream_never_reexecutes_an_older_closure_against_ce() {
        use outbe_compressed_entities::{
            CandidateCacheLimits, CeMdbx, CeTopologyV1, Commitment, CompressedTreeService,
            EntityRef, EnvironmentIdentity, ExactParentIdentity, FinalLeafMutation,
            FinalizedMarker, WwdEntityId, ACTIVE_COMMITMENT_SCHEME, LOCAL_STORAGE_SCHEMA_VERSION,
        };
        use outbe_primitives::{OutbeHeader, OutbePrimitives};
        use reth_chainspec::ChainSpecBuilder;
        use reth_ethereum::exex::{ExExHead, ExExNotification, ExExNotifications, Wal};
        use reth_provider::{test_utils::MockEthProvider, Chain};

        for changed_root in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let parent_hash = B256::repeat_byte(0x38);
            let head_hash = B256::repeat_byte(0x39);
            let parent_root = outbe_compressed_entities::sealed_root(B256::ZERO).unwrap();
            let db = CeMdbx::open(
                &root.path().join("ce"),
                EnvironmentIdentity {
                    local_storage_schema_version: LOCAL_STORAGE_SCHEMA_VERSION,
                    chain_id: outbe_primitives::chain::MAINNET_CHAIN_ID,
                    genesis_hash: parent_hash,
                    commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                    topology: CeTopologyV1.encode(),
                    tree_format: "ckb-smt-v0.6.1-poseidon-catalog-v3".to_owned(),
                    vendor_revision: "ad555350c866b2265d87d2d7fbd146fbc918bfe5".to_owned(),
                },
                FinalizedMarker {
                    commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                    height: 0,
                    block_hash: parent_hash,
                    parent_block_hash: B256::ZERO,
                    parent_root: B256::ZERO,
                    new_root: parent_root,
                },
            )
            .unwrap();
            let ce = Arc::new(
                CompressedTreeService::new(
                    db,
                    CandidateCacheLimits {
                        max_candidates: 4,
                        max_encoded_bytes: 1_000_000,
                    },
                )
                .unwrap(),
            );
            let parent = ExactParentIdentity {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                block_number: 0,
                block_hash: parent_hash,
                root: parent_root,
            };
            let mut id = [7_u8; 32];
            id[..4].copy_from_slice(&1_u32.to_be_bytes());
            let mutations = if changed_root {
                vec![FinalLeafMutation {
                    entity: EntityRef::Tribute(WwdEntityId::try_from(id.as_slice()).unwrap()),
                    final_leaf: Some(Commitment::try_from([3_u8; 32]).unwrap()),
                }]
            } else {
                Vec::new()
            };
            let batch = ce
                .open_parent(parent)
                .unwrap()
                .prepare_seal(1, &mutations, &[])
                .unwrap();
            let head_root = batch.new_root();
            ce.publish_candidate(head_hash, batch).unwrap();
            ce.apply_finalized(1, head_hash, head_root).unwrap();
            assert_eq!(head_root != parent_root, changed_root);
            assert!(
                ce.open_parent(parent).is_err(),
                "historical CE parent must remain rejected"
            );
            let marker = ce.finalized_marker().unwrap();

            let spec = Arc::new(
                ChainSpecBuilder::mainnet()
                    .chain(outbe_primitives::chain::MAINNET_CHAIN_ID.into())
                    .build()
                    .map_header(OutbeHeader::new),
            );
            let evm = outbe_evm::OutbeEvmConfig::new(spec).with_compressed_tree_service(ce.clone());
            // Deliberately no historical bodies: accidental execution backfill
            // cannot silently pass by executing an empty block fixture.
            let provider = MockEthProvider::<OutbePrimitives>::new();
            let (sender, receiver) = tokio::sync::mpsc::channel(1);
            let wal = Wal::<OutbePrimitives>::new(root.path().join("wal")).unwrap();
            let stream = ExExNotifications::new(
                (1, head_hash).into(),
                provider,
                evm,
                receiver,
                wal.handle(),
            )
            .with_head(ExExHead::new((0, parent_hash).into()));
            let mut stream = without_execution_backfill(stream);
            sender
                .send(ExExNotification::ChainCommitted {
                    new: Arc::new(Chain::default()),
                })
                .await
                .unwrap();
            let live = tokio::time::timeout(Duration::from_secs(2), stream.next())
                .await
                .expect("live notification stalled behind historical backfill")
                .expect("notification stream closed")
                .expect("historical execution was attempted");
            assert!(matches!(live, ExExNotification::ChainCommitted { .. }));
            assert_eq!(ce.finalized_marker().unwrap(), marker);
        }
    }

    #[test]
    fn deterministic_retention_conflicts_are_not_retried_as_storage_outages() {
        for error in [
            outbe_node::ocomp::retention::RetentionError::ConflictingCandidate,
            outbe_node::ocomp::retention::RetentionError::OrphanedCandidate,
            outbe_node::ocomp::retention::RetentionError::Poisoned,
        ] {
            assert!(matches!(
                classify_retention_reconciliation(Err(error), true),
                RetentionReconciliationDispositionV1::Fatal(_)
            ));
        }
        assert!(
            matches!(
                classify_retention_reconciliation(
                    Err(outbe_node::ocomp::retention::RetentionError::RegistryCapacity),
                    true
                ),
                RetentionReconciliationDispositionV1::RetryFrame(_)
            ),
            "replay pressure must allow the independent GC worker to reclaim closed history"
        );
    }

    #[tokio::test]
    async fn live_drain_does_not_wait_for_blocked_projection_or_provider_work() {
        let (mut sender, receiver) = futures::channel::mpsc::channel::<eyre::Result<u64>>(1);
        let drain = tokio::spawn(drain_exex_notifications(receiver));
        // No consumer/projection progress is supplied. More live notifications
        // than channel capacity must still be delivered without accumulating.
        tokio::time::timeout(Duration::from_secs(2), async {
            for height in 1..=128 {
                futures::SinkExt::send(&mut sender, Ok(height))
                    .await
                    .unwrap();
            }
        })
        .await
        .expect("live notification drain was blocked by unrelated work");
        drop(sender);
        assert!(drain.await.unwrap().to_string().contains("stream closed"));
    }

    #[test]
    fn restart_reannounces_durable_closure_without_advancing_and_detects_lost_consumer() {
        let root = tempfile::tempdir().unwrap();
        let genesis = ProjectionCheckpoint {
            block_number: 0,
            block_hash: B256::repeat_byte(1),
        };
        let closed = ProjectionCheckpoint {
            block_number: 338,
            block_hash: B256::repeat_byte(2),
        };
        let path = root.path().canonicalize().unwrap().join("closure");
        let store = ContiguousCheckpointStoreV1::open(&path, genesis).unwrap();
        store.compare_and_advance_to(genesis, closed).unwrap();
        drop(store); // crash after persistence, before FinishedHeight delivery
        let restored = ContiguousCheckpointStoreV1::open(&path, genesis).unwrap();
        let (events, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        publish_finished_height(&events, restored.current().unwrap()).unwrap();
        assert!(
            matches!(receiver.try_recv().unwrap(), ExExEvent::FinishedHeight(height)
            if height.number == closed.block_number && height.hash == closed.block_hash)
        );
        drop(receiver);
        assert!(publish_finished_height(&events, closed).is_err());
        assert_eq!(restored.current().unwrap(), closed);
    }

    #[test]
    fn retention_unavailability_and_quarantine_retry_without_a_fatal_node_exit() {
        let unavailable = classify_retention_reconciliation(
            Err(
                outbe_node::ocomp::retention::RetentionError::JournalUnavailable {
                    operation: "fsync temporary",
                    path: std::path::PathBuf::from("pin.v1.tmp"),
                    reason: "injected journal durability failure".to_owned(),
                },
            ),
            true,
        );
        assert!(matches!(
            unavailable,
            RetentionReconciliationDispositionV1::RetryFrame(
                outbe_node::ocomp::retention::RetentionError::JournalUnavailable { .. }
            )
        ));

        let quarantined = classify_retention_reconciliation(
            Err(outbe_node::ocomp::retention::RetentionError::Quarantined(
                "injected journal ambiguity".to_owned(),
            )),
            true,
        );
        assert!(matches!(
            quarantined,
            RetentionReconciliationDispositionV1::RetryFrame(
                outbe_node::ocomp::retention::RetentionError::Quarantined(_)
            )
        ));

        let wrapped_unavailable = Err::<(), _>(
            outbe_node::ocomp::retention::RetentionError::JournalUnavailable {
                operation: "fsync authoritative journal",
                path: std::path::PathBuf::from("pin.v1"),
                reason: "injected journal durability failure".to_owned(),
            },
        )
        .wrap_err("bind OCOMP retention to canonical finalized typed state")
        .expect_err("wrapped journal outage");
        assert!(retention_runtime_error_requires_frame_retry(
            &wrapped_unavailable
        ));

        let wrapped_quarantine =
            Err::<(), _>(outbe_node::ocomp::retention::RetentionError::Quarantined(
                "injected journal ambiguity".to_owned(),
            ))
            .wrap_err("commit exact exporter ACK to OCOMP retention")
            .expect_err("wrapped journal quarantine");
        assert!(retention_runtime_error_requires_frame_retry(
            &wrapped_quarantine
        ));
        assert!(!retention_runtime_error_requires_frame_retry(&eyre::eyre!(
            "unrelated finalized-frame failure"
        )));
    }

    #[test]
    fn cleared_or_replaced_outage_generation_cannot_trigger_an_old_deadline() {
        let since = tokio::time::Instant::now() - PROJECTION_RECOVERY_DEADLINE;
        let std_since = since.into_std();
        let (sender, receiver) =
            tokio::sync::watch::channel(Some(RuntimeBodyFailure::Unavailable {
                generation: 7,
                since: std_since,
            }));
        assert!(consume_projection_runtime_deadline(&receiver, &mut Some((7, since)),).is_some());

        sender.send_replace(None);
        let mut cleared_state = Some((7, since));
        assert!(consume_projection_runtime_deadline(&receiver, &mut cleared_state).is_none());
        assert!(cleared_state.is_none());

        sender.send_replace(Some(RuntimeBodyFailure::Unavailable {
            generation: 8,
            since: std_since,
        }));
        let mut replaced_state = Some((7, since));
        assert!(consume_projection_runtime_deadline(&receiver, &mut replaced_state).is_none());
        assert!(replaced_state.is_none());
    }

    #[test]
    fn canonical_status_matrix_is_exhaustive() {
        assert_eq!(
            classify_canonical_job(OcompJobStatus::AwaitingFinality, false).unwrap(),
            CanonicalJobDispositionV1::AwaitingFinality
        );
        assert_eq!(
            classify_canonical_job(OcompJobStatus::AwaitingFinality, true).unwrap(),
            CanonicalJobDispositionV1::FinalizedAwaitingOpen
        );
        assert_eq!(
            classify_canonical_job(OcompJobStatus::VotingOpen, true).unwrap(),
            CanonicalJobDispositionV1::VotingOpen
        );
        assert_eq!(
            classify_canonical_job(OcompJobStatus::Completed, true).unwrap(),
            CanonicalJobDispositionV1::Completed
        );
        for (status, reason) in [
            (OcompJobStatus::Expired, EmbeddedTerminalReasonV1::Expired),
            (OcompJobStatus::Failed, EmbeddedTerminalReasonV1::Failed),
        ] {
            for has_finalized_job in [false, true] {
                assert_eq!(
                    classify_canonical_job(status, has_finalized_job).unwrap(),
                    CanonicalJobDispositionV1::Closed {
                        reason,
                        has_finalized_job,
                    }
                );
            }
        }
        for (status, has_finalized_job) in [
            (OcompJobStatus::VotingOpen, false),
            (OcompJobStatus::Completed, false),
        ] {
            assert!(classify_canonical_job(status, has_finalized_job).is_err());
        }
    }

    #[test]
    fn async_outcome_projection_is_exact_or_retired() {
        let mut jobs = EmbeddedOcompJobsV1::new(EmbeddedOcompModeV1::Validator);
        let generation = jobs.observe_job(B256::repeat_byte(0x71), 70).unwrap();
        let other_generation = jobs.observe_job(B256::repeat_byte(0x72), 71).unwrap();
        assert_eq!(
            classify_async_outcome_projection(Some(generation), Some(generation)).unwrap(),
            AsyncOutcomeProjectionV1::Active
        );
        assert_eq!(
            classify_async_outcome_projection(None, None).unwrap(),
            AsyncOutcomeProjectionV1::CheckpointPruned
        );
        for (runtime, reducer) in [
            (Some(generation), None),
            (None, Some(generation)),
            (Some(generation), Some(other_generation)),
        ] {
            assert!(classify_async_outcome_projection(runtime, reducer).is_err());
        }
    }

    #[test]
    fn canonical_expiry_closes_without_export_ack_but_live_jobs_do_not() {
        assert!(request_projection_is_closed(
            false,
            Some(EmbeddedJobStateV1::Closed),
            Some(EmbeddedTerminalReasonV1::Expired),
        ));
        for state in [
            EmbeddedJobStateV1::Computing,
            EmbeddedJobStateV1::WaitAtDeadline,
            EmbeddedJobStateV1::LocalReady,
        ] {
            assert!(!request_projection_is_closed(false, Some(state), None));
            assert!(!request_projection_is_closed(true, Some(state), None));
        }
        assert!(request_projection_is_closed(
            true,
            Some(EmbeddedJobStateV1::Closed),
            Some(EmbeddedTerminalReasonV1::Failed),
        ));
    }

    #[test]
    fn only_canonical_expiry_accepts_released_retention_without_export_authority() {
        assert_eq!(
            released_export_authority_for_status(OcompJobStatus::Expired, None).unwrap(),
            None
        );
        for status in [OcompJobStatus::Completed, OcompJobStatus::Failed] {
            assert!(released_export_authority_for_status(status, None).is_err());
        }
    }

    #[test]
    fn expired_or_pruned_compute_is_rejected_before_persistence() {
        assert_eq!(
            ignored_compute_result_reason(
                AsyncOutcomeProjectionV1::Active,
                Some(EmbeddedTerminalReasonV1::Expired),
            ),
            Some("expired")
        );
        assert_eq!(
            ignored_compute_result_reason(AsyncOutcomeProjectionV1::CheckpointPruned, None),
            Some("checkpoint_pruned")
        );
        assert_eq!(
            ignored_compute_result_reason(
                AsyncOutcomeProjectionV1::Active,
                Some(EmbeddedTerminalReasonV1::Completed),
            ),
            None
        );
    }

    #[test]
    fn canonical_restore_policy_never_runs_before_open_or_after_close() {
        for disposition in [
            CanonicalJobDispositionV1::AwaitingFinality,
            CanonicalJobDispositionV1::FinalizedAwaitingOpen,
            CanonicalJobDispositionV1::Closed {
                reason: EmbeddedTerminalReasonV1::Expired,
                has_finalized_job: true,
            },
            CanonicalJobDispositionV1::Closed {
                reason: EmbeddedTerminalReasonV1::Failed,
                has_finalized_job: true,
            },
        ] {
            for policy in [
                EmbeddedNodePolicyV1::Validator,
                EmbeddedNodePolicyV1::FullNode,
            ] {
                assert_eq!(
                    local_result_restore_policy(disposition, policy, true, true, false),
                    LocalResultRestorePolicyV1::Never
                );
            }
        }
    }

    #[test]
    fn canonical_restore_policy_encodes_effect_order() {
        assert_eq!(
            local_result_restore_policy(
                CanonicalJobDispositionV1::VotingOpen,
                EmbeddedNodePolicyV1::Validator,
                true,
                false,
                false,
            ),
            LocalResultRestorePolicyV1::BeforeCompute
        );
        assert_eq!(
            local_result_restore_policy(
                CanonicalJobDispositionV1::VotingOpen,
                EmbeddedNodePolicyV1::FullNode,
                false,
                false,
                false,
            ),
            LocalResultRestorePolicyV1::BeforeCompute,
            "the FinalizedAwaitingOpen to VotingOpen transition restores before compute"
        );
        assert_eq!(
            local_result_restore_policy(
                CanonicalJobDispositionV1::VotingOpen,
                EmbeddedNodePolicyV1::Validator,
                false,
                true,
                true,
            ),
            LocalResultRestorePolicyV1::BeforeCompute
        );
        assert_eq!(
            local_result_restore_policy(
                CanonicalJobDispositionV1::Completed,
                EmbeddedNodePolicyV1::FullNode,
                true,
                false,
                false,
            ),
            LocalResultRestorePolicyV1::AfterCanonicalCompleted
        );
        assert_eq!(
            local_result_restore_policy(
                CanonicalJobDispositionV1::Completed,
                EmbeddedNodePolicyV1::Validator,
                true,
                true,
                false,
            ),
            LocalResultRestorePolicyV1::Never
        );
        assert_eq!(
            local_result_restore_policy(
                CanonicalJobDispositionV1::VotingOpen,
                EmbeddedNodePolicyV1::FullNode,
                false,
                false,
                true,
            ),
            LocalResultRestorePolicyV1::Never
        );
    }

    #[test]
    fn vote_eligibility_retries_only_unavailable_authority() {
        use outbe_node::ocomp::retention::OcompSnapshotEligibilityV1;

        let pending = advance_vote_eligibility(
            LocalVoteEligibilityV1::Pending,
            OcompSnapshotEligibilityV1::Unavailable {
                detail: "provider lag".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(pending, LocalVoteEligibilityV1::Pending);
        assert_eq!(
            advance_vote_eligibility(pending, OcompSnapshotEligibilityV1::Eligible).unwrap(),
            LocalVoteEligibilityV1::Eligible
        );

        let not_member = advance_vote_eligibility(
            LocalVoteEligibilityV1::Pending,
            OcompSnapshotEligibilityV1::NotMember,
        )
        .unwrap();
        assert_eq!(not_member, LocalVoteEligibilityV1::NotMember);
        assert_eq!(
            advance_vote_eligibility(not_member, OcompSnapshotEligibilityV1::Eligible).unwrap(),
            LocalVoteEligibilityV1::NotMember,
            "exact non-membership is a terminal abstention"
        );
        assert!(advance_vote_eligibility(
            LocalVoteEligibilityV1::Pending,
            OcompSnapshotEligibilityV1::Corrupt {
                detail: "binding mismatch".to_owned(),
            },
        )
        .is_err());
    }

    fn materialization_head(
        last_progress_height: u64,
    ) -> outbe_ocomp_protocol::nod_materialization::NodMaterializationHeadV1 {
        outbe_ocomp_protocol::nod_materialization::NodMaterializationHeadV1 {
            queue_sequence: 1,
            job_id: B256::repeat_byte(0x11),
            program_semantics_hash: B256::repeat_byte(0x22),
            worldwide_day: 20_260_812,
            generation: 1,
            nod_root: B256::repeat_byte(0x33),
            nod_count: 10,
            next_nod_ordinal: 8,
            last_progress_height,
        }
    }

    #[test]
    fn finalized_materialization_wake_uses_the_authenticated_system_tx_signer() {
        use outbe_primitives::{
            signer::OutbeEvmSigner,
            system_tx::{build_unsigned_system_tx, SystemTxInputV2},
        };

        let signer = OutbeEvmSigner::from_secret_bytes([0x41; 32]).expect("test signer");
        let input = SystemTxInputV2::CycleTick;
        let unsigned = build_unsigned_system_tx(
            input.kind(),
            0,
            2,
            outbe_primitives::chain::CHAIN_ID,
            input.encode().expect("canonical system input"),
        )
        .expect("unsigned system transaction");
        let signed = signer
            .sign_unsigned(unsigned)
            .expect("signed system transaction");

        let transactions = [signed];
        let proposer = authenticated_finalized_proposer(transactions.iter())
            .expect("recover authenticated finalized proposer");
        assert_eq!(proposer, signer.address());
        assert_ne!(
            proposer,
            outbe_primitives::addresses::REWARDS_ADDRESS,
            "the protocol reward beneficiary is not proposer identity"
        );
        assert!(should_wake_nod_materializer(
            EmbeddedNodePolicyV1::Validator,
            Some(signer.address()),
            proposer,
            100,
            Some(&materialization_head(90)),
            true,
            30,
        ));
    }

    #[test]
    fn genesis_without_system_transactions_has_no_materialization_proposer() {
        let transactions: Vec<outbe_primitives::OutbeTxEnvelope> = Vec::new();
        assert_eq!(
            finalized_materialization_proposer(0, transactions.iter())
                .expect("genesis has no materialization proposer"),
            None
        );
    }

    #[test]
    fn only_the_validator_representing_the_finalized_proposer_wakes_materialization() {
        let represented = alloy_primitives::Address::repeat_byte(0x11);
        let other = alloy_primitives::Address::repeat_byte(0x22);
        let head = materialization_head(90);

        assert!(should_wake_nod_materializer(
            EmbeddedNodePolicyV1::Validator,
            Some(represented),
            represented,
            100,
            Some(&head),
            true,
            30,
        ));
        assert!(!should_wake_nod_materializer(
            EmbeddedNodePolicyV1::Validator,
            Some(represented),
            other,
            100,
            Some(&head),
            true,
            30,
        ));
        assert!(!should_wake_nod_materializer(
            EmbeddedNodePolicyV1::FullNode,
            None,
            represented,
            100,
            Some(&head),
            true,
            30,
        ));
    }

    #[test]
    fn retry_wake_uses_the_resolved_interval_and_requires_an_incomplete_head() {
        let represented = alloy_primitives::Address::repeat_byte(0x11);
        let head = materialization_head(90);

        assert!(!should_wake_nod_materializer(
            EmbeddedNodePolicyV1::Validator,
            Some(represented),
            represented,
            119,
            Some(&head),
            false,
            30,
        ));
        assert!(should_wake_nod_materializer(
            EmbeddedNodePolicyV1::Validator,
            Some(represented),
            represented,
            120,
            Some(&head),
            false,
            30,
        ));
        assert!(!should_wake_nod_materializer(
            EmbeddedNodePolicyV1::Validator,
            Some(represented),
            represented,
            120,
            None,
            true,
            30,
        ));
    }

    #[test]
    fn materialization_retry_memory_tracks_only_the_current_head() {
        let old = MaterializationAttemptKeyV1 {
            queue_sequence: 1,
            first_nod_ordinal: 0,
        };
        let current = MaterializationAttemptKeyV1 {
            queue_sequence: 2,
            first_nod_ordinal: 8,
        };
        let mut attempts = BTreeMap::from([(old, 10), (current, 20)]);
        bound_materialization_attempts(&mut attempts, Some(current));
        assert_eq!(attempts, BTreeMap::from([(current, 20)]));
        bound_materialization_attempts(&mut attempts, None);
        assert!(attempts.is_empty());
    }

    #[tokio::test]
    async fn fatal_handoff_keeps_exex_alive_until_node_teardown() {
        assert!(
            tokio::time::timeout(Duration::from_millis(10), wait_for_node_teardown())
                .await
                .is_err(),
            "fatal handoff must not complete the Reth ExEx future"
        );
    }

    #[test]
    fn pre_finalization_request_blocks_checkpoint_until_job_materializes() {
        let intent_id = B256::repeat_byte(0x41);
        let mut materialized = std::collections::BTreeSet::new();
        assert!(!all_requests_materialized(
            [intent_id].into_iter(),
            &materialized
        ));
        materialized.insert(intent_id);
        assert!(all_requests_materialized(
            [intent_id].into_iter(),
            &materialized
        ));
    }

    #[test]
    fn finalized_reader_lag_tracks_scan_and_open_job_closure_independently() {
        assert_eq!(finalized_reader_lags(1_000, 900, 700), (100, 300));
        assert_eq!(finalized_reader_lags(900, 1_000, 1_000), (0, 0));
    }

    #[tokio::test]
    async fn notification_drain_reports_failure_and_closed_receiver() {
        let error = drain_exex_notifications(futures::stream::iter([
            Ok(()),
            Err(eyre::eyre!("injected stream error")),
        ]))
        .await;
        assert!(format!("{error:#}").contains("injected stream error"));
        let error = drain_exex_notifications(futures::stream::iter([Ok(())])).await;
        assert!(error.to_string().contains("stream closed"));
    }

    #[test]
    fn deterministic_projection_task_error_is_not_reported_as_mongo_timeout() {
        let failure = projection_task_failure(eyre::eyre!("malformed finalized frame"));
        assert_eq!(failure.class, ProjectionFailureClass::Other);
        assert!(failure.message.contains("malformed finalized frame"));
    }

    #[test]
    fn sticky_fatal_evidence_survives_restart_and_is_write_once() {
        let root = tempfile::tempdir().unwrap();
        let job_id = B256::repeat_byte(0x51);
        persist_generic_fatal_evidence(root.path(), job_id, "first fatal").unwrap();
        persist_generic_fatal_evidence(root.path(), B256::repeat_byte(0x52), "later fatal")
            .unwrap();

        let loaded = load_persisted_fatal_evidence(root.path())
            .unwrap()
            .expect("persisted fatal");
        assert!(loaded.contains("first fatal"));
        assert!(!loaded.contains("later fatal"));

        let mismatch_root = tempfile::tempdir().unwrap();
        persist_fatal_evidence(
            mismatch_root.path(),
            job_id,
            B256::repeat_byte(0x61),
            B256::repeat_byte(0x62),
        )
        .unwrap();
        assert!(load_persisted_fatal_evidence(mismatch_root.path())
            .unwrap()
            .expect("mismatch evidence")
            .contains("local_result_digest"));
    }
}
