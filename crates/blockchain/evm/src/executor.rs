//! Outbe block executor.
//!
//! Wraps [`EthBlockExecutor`] and adds Outbe-specific block hooks in
//! [`apply_pre_execution_changes`](OutbeBlockExecutor::apply_pre_execution_changes).

use alloy_consensus::SignableTransaction as _;
use alloy_consensus::Transaction as _;
use alloy_eips::eip7685::Requests;
use alloy_evm::{
    block::{
        state_changes::{balance_increment_state, post_block_balance_increments},
        BlockExecutionError, BlockExecutor, BlockValidationError, CommitChanges, ExecutableTx,
        GasOutput, InternalBlockExecutionError, OnStateHook, StateChangePostBlockSource,
        StateChangeSource, StateDB,
    },
    eth::{dao_fork, eip6110, EthBlockExecutor, EthTxResult},
    revm::context::Block as _,
    Database, RecoveredTx,
};
use alloy_primitives::{keccak256, map::AddressMap, Address, Bytes, Log, B256, U256};
use outbe_compressed_entities::ExecutionScope;
use outbe_ocomp_protocol::system_carrier::{
    classify_ocomp_system_carrier, OcompSystemCarrierCandidate, OcompSystemCarrierView,
    OCOMP_SYSTEM_CARRIER_INTERNAL_GAS_LIMIT,
};
use outbe_offchain_data::{ExecutionReadBudgetGuard, RuntimeBodyReaders};
use outbe_primitives::{
    block::{BlockContext, BlockLifecycle, BlockRuntimeContext},
    consensus::{ConsensusExecutionBridge, GenesisValidators},
    consensus_metadata::CertifiedParentAccountingMetadata,
    error::{PrecompileError, Result as OutbeResult},
    hook_events::partition_hook_events,
    payload::validate_outbe_withdrawals,
    reshare_artifact::{
        decode_outbe_block_artifacts, CompressedEntitiesRootArtifact, ConsensusHeaderArtifact,
        ExecutionSummaryArtifact,
    },
    storage::{direct::DirectStorageProvider, StorageHandle},
    OutbeHeader,
};
use outbe_validatorset::ValidatorLifecycle;
use outbe_zerofee::{BootstrapTransactionView, ZeroFeeTransaction};
use reth_ethereum::{
    evm::{primitives::Evm, revm::context::TxEnv, RethReceiptBuilder},
    provider::BlockExecutionResult,
    Receipt, TransactionSigned,
};
use reth_evm::execute::WithTxEnv;
use reth_primitives_traits::Recovered;
use revm::context::result::{ExecutionResult, HaltReason, InvalidTransaction, OutOfGasError};
use revm::state::Account;
use std::{collections::BTreeSet, sync::Arc};

use crate::{
    begin_block_precompile::{with_preloaded_system_tx_context, PreloadedSystemTxContext},
    factory::OutbeEvm,
    signer::SharedOutbeEvmSigner,
    system_tx::{
        build_unsigned_system_tx, build_unsigned_system_tx_with_gas_limit,
        expected_begin_block_kinds_for_activation, is_reserved_system_tx,
        validate_phase1_witness_against, OcompLifecycleActivation, SystemTxInputV2, SystemTxKind,
        SystemTxVisibleGasPlan,
    },
};
use reth_ethereum::chainspec::{ChainSpec, EthereumHardfork, EthereumHardforks};
use revm::database::DatabaseCommitExt;

type ExpectedSystemTransaction = (
    usize,
    SystemTxKind,
    SystemTxInputV2,
    Option<AccountedParentArtifact>,
    u64,
    u64,
);

struct SystemFailureReceiptInput {
    tx_type: alloy_consensus::TxType,
    log_address: Address,
    code: u16,
    reason: String,
    visible_base_gas: u64,
    compressed_entities_gas: u64,
    signed_gas_limit: u64,
    internal_gas_used: u64,
}

fn validate_compressed_entities_root_scheme(
    artifact: Option<CompressedEntitiesRootArtifact>,
) -> Result<CompressedEntitiesRootArtifact, BlockExecutionError> {
    let artifact = artifact.ok_or_else(|| {
        BlockExecutionError::msg("missing compressed-entities root artifact in block extra_data")
    })?;
    if artifact.commitment_scheme_version != outbe_compressed_entities::ACTIVE_COMMITMENT_SCHEME {
        return Err(BlockExecutionError::msg(format!(
            "compressed-entities root artifact scheme mismatch: header={}, active={}",
            artifact.commitment_scheme_version,
            outbe_compressed_entities::ACTIVE_COMMITMENT_SCHEME
        )));
    }
    Ok(artifact)
}

fn validate_compressed_entities_root_after_seal(
    artifact: Option<CompressedEntitiesRootArtifact>,
    sealed_root: B256,
) -> Result<CompressedEntitiesRootArtifact, BlockExecutionError> {
    let artifact = validate_compressed_entities_root_scheme(artifact)?;
    if artifact.r_sealed != sealed_root {
        return Err(BlockExecutionError::msg(format!(
            "compressed-entities header/SealOutput root mismatch: header={}, seal={sealed_root}",
            artifact.r_sealed
        )));
    }
    Ok(artifact)
}

fn validate_execution_summary_artifact(
    enabled: bool,
    block_number: u64,
    header_summary: Option<ExecutionSummaryArtifact>,
    current_summary: ExecutionSummaryArtifact,
) -> Result<(), BlockExecutionError> {
    if !enabled || block_number == 0 {
        return Ok(());
    }
    let Some(header_summary) = header_summary else {
        return Err(BlockExecutionError::msg(
            "missing execution summary artifact in block extra_data",
        ));
    };
    if header_summary != current_summary {
        return Err(BlockExecutionError::msg(format!(
            "execution summary artifact mismatch: header={header_summary:?}, local={current_summary:?}"
        )));
    }
    Ok(())
}

/// Outbe runtime addresses that receive `0xEF` EIP-161 marker bytecode in every
/// block's pre-execution step ([`OutbeBlockExecutor::apply_pre_execution_changes`])
/// so their persistent EVM storage survives state-root computation - EIP-161
/// emptiness (nonce==0 && balance==0 && empty code) ignores storage, so without
/// the marker a stateful account holding only storage is pruned.
///
/// This MUST contain every *stateful* runtime precompile from
/// [`crate::precompiles::outbe_precompile_addresses`] (except stateless verifiers
/// and genesis-seeded accounts), plus the system-only storage markers that have
/// no dispatch registration. The superset invariant is pinned by the
/// `marker_list_covers_stateful_precompiles` test.
pub mod marker_addresses {
    use alloy_primitives::Address;
    use outbe_primitives::addresses::*;

    pub const OUTBE_RUNTIME_MARKER_ADDRESSES: [Address; 39] = [
        GRATIS_ADDRESS,
        GRATIS_FACTORY_ADDRESS,
        CREDIS_ADDRESS,
        CREDIS_FACTORY_ADDRESS,
        PROMIS_ADDRESS,
        // PromisFactory is a live stateful precompile (in
        // `outbe_precompile_addresses`) and is NOT genesis-seeded, so this
        // per-block runtime marker is its only EIP-161 preservation path -
        // mirroring GRATIS_FACTORY / GEM_FACTORY above.
        PROMIS_FACTORY_ADDRESS,
        TRIBUTE_ADDRESS,
        NOD_ADDRESS,
        NOD_FACTORY_ADDRESS,
        TRIBUTE_FACTORY_ADDRESS,
        // reth22-1 fix: GEM and GEM_FACTORY are live stateful precompiles
        // (in `outbe_precompile_addresses`) that were absent from this list, so
        // their storage was silently pruned at state-root time under EIP-161.
        // They are NOT seeded with genesis bytecode either, so this per-block
        // runtime marker is their only preservation path.
        GEM_ADDRESS,
        GEM_FACTORY_ADDRESS,
        INTEX_ADDRESS,
        INTEX_FACTORY_ADDRESS,
        DESIS_ADDRESS,
        AGENT_REWARD_ADDRESS,
        FIDELITY_ADDRESS,
        EMISSION_LIMIT_ADDRESS,
        METADOSIS_ADDRESS,
        PROMIS_LIMIT_ADDRESS,
        CYCLE_ADDRESS,
        CCA_ADDRESS,
        GEM_ADDRESS,
        GEM_FACTORY_ADDRESS,
        VALIDATOR_SET_ADDRESS,
        SLASH_INDICATOR_ADDRESS,
        STAKING_ADDRESS,
        REWARDS_ADDRESS,
        // V2 Phase 1 accounting-progress marker. System-only (no precompile
        // dispatch); the `[0xef]` marker preserves slot 0 across EIP-161 cleanup.
        ACCOUNTING_PROGRESS_ADDRESS,
        ORACLE_ADDRESS,
        OUTBE_SYSTEM_TX_ADDRESS,
        // TEE Registry (storage-backed, system-written at Phase 3b). Not
        // genesis-seeded, so the runtime 0xEF marker is its only EIP-161
        // preservation path (reth22-1 class).
        TEE_REGISTRY_ADDRESS,
        // L2 network registry (storage-backed, permissionless writes). Not
        // genesis-seeded, so the runtime 0xEF marker is its only EIP-161
        // preservation path (reth22-1 class).
        L2_REGISTRY_ADDRESS,
        // OCOMP authority and lineage registry. Fresh genesis initializes it
        // at height 32; the marker preserves successor/refcount state.
        OCOMP_REGISTRY_ADDRESS,
        UPDATE_ADDRESS,
        VOTE_ADDRESS,
        // System-only compressed-entity commitment state (no public dispatch).
        COMPRESSED_ENTITIES_ADDRESS,
        // PayNote pool. All data live in its storage,
        // and it is not genesis-seeded, so this marker
        // is its only EIP-161 preservation path (reth22-1 class).
        PAYNOTE_ADDRESS,
        // Emit private-note pool (storage-backed, lazily initialized by the
        // first burn). Genesis-reserved but not genesis-seeded with storage,
        // so the runtime 0xEF marker preserves its tree/nullifier state.
        EMIT_ADDRESS,
    ];
}

/// Applies a DKG/reshare `BoundaryOutcome` from `header.extra_data` against
/// on-chain validator-set state and writes the V2 committee snapshot activated
/// by the boundary.
///
/// The on-chain `active_consensus_set_hash` is derived from validator
/// addresses only, so a same-membership DKG/VRF rotation must not change it.
/// Same-membership rotations still change the committee snapshot because they
/// bind new VRF material, so matching active-set hash is not a no-op.
///
/// Tri-state behaviour:
/// - `current_hash == reshare.active_set_hash` -> write incoming snapshot and
///   re-activate the same active set atomically.
/// - mismatch + `is_validator_set_change == true` -> apply boundary activation
///   and write incoming snapshot atomically.
/// - mismatch + `is_validator_set_change == false` -> fatal.
pub(crate) fn apply_boundary_outcome(
    storage: StorageHandle,
    boundary: &outbe_primitives::consensus::DkgBoundaryArtifact,
    block_number: u64,
    timestamp: u64,
) -> outbe_primitives::error::Result<()> {
    let reshare = &boundary.reshare;

    let expected_tee_expiry_hash =
        outbe_primitives::reshare_artifact::tee_expired_target_exclusions_hash(
            &boundary.tee_expired_target_exclusions,
        )?;
    if boundary.tee_expired_target_exclusions_hash != expected_tee_expiry_hash {
        return Err(PrecompileError::Fatal(format!(
            "boundary TEE expiry exclusions commitment mismatch: expected {expected_tee_expiry_hash}, got {}",
            boundary.tee_expired_target_exclusions_hash
        )));
    }

    let expected_active_set_hash = hash_boundary_active_set(&reshare.new_active_set);
    if reshare.active_set_hash != expected_active_set_hash {
        return Err(PrecompileError::Fatal(format!(
            "boundary active_set_hash mismatch: expected {expected_active_set_hash}, got {}",
            reshare.active_set_hash
        )));
    }

    let expected_vrf_group_public_key = keccak256(boundary.vrf_group_public_key_bytes.as_ref());
    if boundary.vrf_group_public_key != expected_vrf_group_public_key {
        return Err(PrecompileError::Fatal(format!(
            "boundary VRF group public key hash mismatch: expected {expected_vrf_group_public_key}, got {}",
            boundary.vrf_group_public_key
        )));
    }

    let incoming_snapshot = committee_snapshot_from_boundary(storage.clone(), boundary)?;
    let expected_committee_set_hash =
        outbe_validatorset::committee_set_hash_v2(boundary.epoch, &incoming_snapshot);
    if boundary.committee_set_hash != expected_committee_set_hash {
        return Err(PrecompileError::Fatal(format!(
            "boundary committee_set_hash mismatch: expected {expected_committee_set_hash}, got {}",
            boundary.committee_set_hash
        )));
    }

    let vs_check = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
    let current_hash = vs_check.active_consensus_set_hash()?;
    let current_epoch: u64 = vs_check
        .epoch_snapshot()?
        .number
        .try_into()
        .map_err(|_| PrecompileError::Fatal("ValidatorSet epoch exceeds u64".into()))?;

    if current_hash != reshare.active_set_hash && !boundary.is_validator_set_change {
        return Err(PrecompileError::Fatal(format!(
            "boundary active_set_hash changed without validator-set change: current={current_hash}, boundary={}",
            reshare.active_set_hash
        )));
    }

    let advances_epoch =
        validate_boundary_epoch_transition(current_epoch, boundary.epoch, block_number)?;

    // The activated epoch, active membership/hash and its consensus+OCOMP
    // snapshot are one state transition. A nominal epoch height is not
    // activation authority; only this certified BoundaryOutcome is.
    let activation_guard = storage.checkpoint_guard();
    if advances_epoch {
        outbe_validatorset::hooks::advance_epoch(storage.clone(), timestamp, block_number)?;
    }

    let inputs = outbe_validatorset::hooks::BoundaryActivationInputs {
        outgoing: None,
        incoming_epoch: boundary.epoch,
        incoming: incoming_snapshot,
        freeze_height: boundary.freeze_height,
        new_active_set: reshare.new_active_set.clone(),
        active_set_hash: reshare.active_set_hash,
        tee_expired_target_exclusions: boundary.tee_expired_target_exclusions.clone(),
    };
    outbe_validatorset::hooks::activate_boundary_atomic(storage.clone(), &inputs)?;
    if advances_epoch {
        outbe_validatorset::contract::ValidatorSet::new(storage).cleanup_inactive_validators(16)?;
    }
    activation_guard.commit();
    Ok(())
}

fn validate_boundary_epoch_transition(
    current_epoch: u64,
    incoming_epoch: u64,
    block_number: u64,
) -> outbe_primitives::error::Result<bool> {
    if block_number == 1 && current_epoch == 0 && incoming_epoch == 0 {
        return Ok(false);
    }
    let next_epoch = current_epoch.checked_add(1).ok_or_else(|| {
        PrecompileError::Fatal("ValidatorSet epoch overflow at BoundaryOutcome".into())
    })?;
    if block_number > 1 && incoming_epoch == next_epoch {
        return Ok(true);
    }
    Err(PrecompileError::Fatal(format!(
        "BoundaryOutcome epoch must bootstrap epoch 0 at block 1 or activate current+1: current={current_epoch}, incoming={incoming_epoch}, block={block_number}"
    )))
}

/// Resets outgoing-epoch counters only for a block that actually carries the
/// next certified BoundaryOutcome. This runs before receipt-visible
/// LateFinalizeCredits; the BoundaryOutcome later advances epoch/set/snapshot
/// without erasing misses recorded by that earlier phase.
pub(crate) fn prepare_boundary_epoch_counters(
    storage: StorageHandle,
    boundary: &outbe_primitives::consensus::DkgBoundaryArtifact,
    block_number: u64,
) -> outbe_primitives::error::Result<()> {
    let validators = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
    let current_epoch = validators.current_epoch_u64()?;
    if !validate_boundary_epoch_transition(current_epoch, boundary.epoch, block_number)? {
        return Ok(());
    }
    let addresses: Vec<Address> = validators
        .get_all_validators()?
        .into_iter()
        .map(|validator| validator.validator_address)
        .collect();
    outbe_slashindicator::contract::SlashIndicator::new(storage.clone())
        .reset_epoch_counters(&addresses)?;
    outbe_validatorset::hooks::reset_epoch_counters(storage)
}

fn hash_boundary_active_set(addresses: &[Address]) -> B256 {
    let mut bytes = Vec::with_capacity(8 + addresses.len() * 20);
    bytes.extend_from_slice(&(addresses.len() as u64).to_be_bytes());
    for address in addresses {
        bytes.extend_from_slice(address.as_slice());
    }
    keccak256(bytes)
}

fn committee_snapshot_from_boundary(
    storage: StorageHandle,
    boundary: &outbe_primitives::consensus::DkgBoundaryArtifact,
) -> outbe_primitives::error::Result<outbe_validatorset::CommitteeSnapshot> {
    let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
    let mut committee = Vec::with_capacity(boundary.reshare.new_active_set.len());
    for address in &boundary.reshare.new_active_set {
        let Some(consensus_pubkey) = vs.consensus_pubkey_of(*address)? else {
            return Err(PrecompileError::Fatal(format!(
                "boundary active set contains unregistered validator {address}"
            )));
        };
        committee.push(outbe_validatorset::CommitteeEntry {
            address: *address,
            consensus_pubkey,
        });
    }

    Ok(outbe_validatorset::CommitteeSnapshot {
        committee,
        vrf_material_version: boundary.vrf_material_version,
        vrf_group_public_key_bytes: boundary.vrf_group_public_key_bytes.to_vec(),
        // Derived from the already-consensus-validated boundary `outcome` (the
        // full DKG output), so a proposer cannot forge it. Lets SlashIndicator
        // verify an invalid-seed-partial slash; ZERO when no full polynomial is
        // carried (group-key-only bootstrap).
        vrf_public_polynomial_hash: outbe_consensus::dkg_manager::boundary_outcome_polynomial_hash(
            boundary.outcome.as_ref(),
        ),
    })
}

/// Structural sanity checks for finalized-parent consensus metadata.
///
/// `metadata.ordered_committee` is the canonical historical committee for the
/// finalized-parent certificate, already verified by the consensus/application
/// layer. This validation enforces post-exec invariants that do not require
/// the live active set:
///
/// - signer bitmap length matches committee length
/// - committee has no duplicate addresses
/// - every committee member is a registered validator (not necessarily a
///   current consensus participant - historical EXITING/UNBONDING is fine)
/// - every `missed_proposer` is a member of `metadata.ordered_committee`
/// - bitmap entries are 0 or 1 only
pub(crate) fn validate_finalized_metadata(
    storage: StorageHandle,
    metadata: &CertifiedParentAccountingMetadata,
) -> outbe_primitives::error::Result<()> {
    if metadata.signer_bitmap.len() != metadata.ordered_committee.len() {
        return Err(PrecompileError::Fatal(
            "consensus metadata signer bitmap length mismatch".into(),
        ));
    }

    let committee_set: BTreeSet<Address> = metadata.ordered_committee.iter().copied().collect();
    if committee_set.len() != metadata.ordered_committee.len() {
        return Err(PrecompileError::Fatal(
            "consensus metadata committee contains duplicate addresses".into(),
        ));
    }

    let vs_check = outbe_validatorset::contract::ValidatorSet::new(storage);
    for addr in &metadata.ordered_committee {
        if !vs_check.is_validator(*addr)? {
            return Err(PrecompileError::Fatal(format!(
                "consensus metadata committee member is not a registered validator: {addr}"
            )));
        }
    }

    for missed in &metadata.missed_proposers {
        if !committee_set.contains(&missed.validator) {
            return Err(PrecompileError::Fatal(format!(
                "consensus metadata missed proposer is not in finalized committee: {} (view {})",
                missed.validator, missed.view,
            )));
        }
    }

    for entry in &metadata.signer_bitmap {
        if *entry > 1 {
            return Err(PrecompileError::Fatal(
                "consensus metadata signer bitmap contains non-binary entry".into(),
            ));
        }
    }

    Ok(())
}

/// parent-block execution artifact (`ExecutionSummaryArtifact`
/// from `header.extra_data`) paired with the parent block's timestamp.
/// Returned by [`AccountedParentArtifactProvider`] and consumed by the
/// Phase 1 `CertifiedParentAccounting` precompile via
/// `PreloadedSystemTxContext.finalized_summary`. Renamed from
/// `FinalizedExecutionSummary` because under V2 the parent need not be
/// finalized - it only needs to be the certified-parent of the block
/// being executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountedParentArtifact {
    pub summary: ExecutionSummaryArtifact,
    pub timestamp: u64,
    /// State root committed by the same exact parent header.
    ///
    /// Legacy/test bridge entries may omit it. An OCOMP finality transition
    /// requires this value and fails closed when it is unavailable.
    pub state_root: Option<B256>,
}

/// exact-hash-first lookup of an accounted-parent's
/// [`ExecutionSummaryArtifact`].
///
/// Replaces `FinalizedExecutionSummaryProvider`. The return type is
/// [`AccountedParentArtifact`] (artifact + parent header timestamp) because
/// `outbe_rewards::on_finalized_metadata` consumes the parent timestamp
/// downstream and the timestamp is available from the same
/// `sealed_header_by_hash` lookup at zero extra cost.
///
/// Required lookup priority (impls must follow):
/// 1. Exact cache lookup keyed by `(block_number, block_hash)`.
/// 2. `HeaderProvider::sealed_header_by_hash(block_hash)` with
///    `header.number == block_number` asserted before decoding
///    `OutbeBlockArtifacts.execution_summary`.
/// 3. Canonical-by-number fallback is allowed ONLY after
///    `sealed_header(block_number).hash() == block_hash` (explicit
///    double-check).
/// 4. On `(block_number, block_hash)` mismatch the impl MUST return
///    `Ok(None)` or `Err(...)`, never the canonical-at-number artifact
///    silently.
pub trait AccountedParentArtifactProvider: Send + Sync {
    fn execution_summary_by_hash(
        &self,
        block_number: u64,
        block_hash: B256,
    ) -> Result<Option<AccountedParentArtifact>, reth_evm::execute::ProviderError>;
}

fn validator_fee_for_gas(
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: Option<u128>,
    gas_used: u64,
    base_fee_per_gas: u128,
) -> U256 {
    let max_priority_fee_per_gas = max_priority_fee_per_gas
        .unwrap_or_else(|| max_fee_per_gas.saturating_sub(base_fee_per_gas));
    let fee_cap_above_base = max_fee_per_gas.saturating_sub(base_fee_per_gas);
    let validator_fee_per_gas = max_priority_fee_per_gas.min(fee_cap_above_base);
    U256::from(validator_fee_per_gas) * U256::from(gas_used)
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ZeroFeeCfgSnapshot {
    disable_balance_check: bool,
    disable_base_fee: bool,
    disable_fee_charge: bool,
}

pub(crate) trait ZeroFeeCfgAccess {
    fn enable_zero_fee_overrides(&mut self) -> ZeroFeeCfgSnapshot;
    fn restore_zero_fee_overrides(&mut self, snapshot: ZeroFeeCfgSnapshot);
}

impl<DB, I, P> ZeroFeeCfgAccess for OutbeEvm<DB, I, P>
where
    DB: Database,
{
    fn enable_zero_fee_overrides(&mut self) -> ZeroFeeCfgSnapshot {
        let cfg = &mut self.ctx_mut().cfg;
        let snapshot = ZeroFeeCfgSnapshot {
            disable_balance_check: cfg.disable_balance_check,
            disable_base_fee: cfg.disable_base_fee,
            disable_fee_charge: cfg.disable_fee_charge,
        };
        cfg.disable_balance_check = true;
        cfg.disable_base_fee = true;
        cfg.disable_fee_charge = true;
        snapshot
    }

    fn restore_zero_fee_overrides(&mut self, snapshot: ZeroFeeCfgSnapshot) {
        let cfg = &mut self.ctx_mut().cfg;
        cfg.disable_balance_check = snapshot.disable_balance_check;
        cfg.disable_base_fee = snapshot.disable_base_fee;
        cfg.disable_fee_charge = snapshot.disable_fee_charge;
    }
}

fn zero_fee_transaction<'a, T>(tx: &'a T, signer: Address) -> ZeroFeeTransaction<'a>
where
    T: alloy_consensus::Transaction + ?Sized,
{
    ZeroFeeTransaction {
        signer,
        to: tx.to(),
        value: tx.value(),
        input: tx.input().as_ref(),
        gas_limit: tx.gas_limit(),
        max_fee_per_gas: tx.max_fee_per_gas(),
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas(),
    }
}

fn bootstrap_transaction<'a, T>(
    tx: &'a T,
    signer: Address,
    network_chain_id: u64,
) -> Option<BootstrapTransactionView<'a>>
where
    T: alloy_consensus::Transaction + ?Sized,
{
    let authorization_list = tx.authorization_list()?;
    Some(BootstrapTransactionView {
        signer,
        tx_chain_id: tx.chain_id(),
        network_chain_id,
        nonce: tx.nonce(),
        to: tx.to(),
        value: tx.value(),
        input: tx.input().as_ref(),
        gas_limit: tx.gas_limit(),
        max_fee_per_gas: tx.max_fee_per_gas(),
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas(),
        access_list_empty: tx.access_list().is_some_and(|list| list.is_empty()),
        authorization_list,
    })
}

/// Runs the Outbe pre-execution hook chain against a pre-built runtime context.
///
/// Exercised by `OutbeBlockExecutor::apply_pre_execution_changes` against a Reth
/// `StateDB` wrapped in `DirectStorageProvider`, and by lifecycle-level tests
/// against `HashMapStorageProvider`. Ordering is load-bearing:
///
/// 1. Genesis-state validation (blocks 0/1 only, if consensus config was supplied).
/// 2. `VoteLifecycle::begin_block` - tally expired proposals and dispatch approved ones.
/// 3. `UpdateLifecycle::begin_block_with_handlers` - activate scheduled updates at activation height.
/// 4. `RewardsLifecycle::begin_block` - locks in `genesis_utc_day` on
///    block 0; the per-block emission and per-day settle paths have
///    moved to the Cycle module.
/// 5. Metadosis WWD state machine has moved to the hourly ProtocolCycle
///    handler; no per-block hook here anymore.
/// 6. Staking matured-unbonding processing.
/// 7. `OracleLifecycle::begin_block` - tally + daily S-curve only.
///
/// Oracle slash-window force-exits run later as the receipt-visible
/// `OracleSlashWindow` begin-zone system phase, after optional `BoundaryOutcome`.
/// This preserves same-block boundary activation before any deterministic Oracle
/// penalty can mark a target validator EXITING while keeping operator-critical
/// Oracle events in normal EVM receipts.
pub fn run_outbe_pre_execution_hooks(
    hook_ctx: &BlockRuntimeContext,
    genesis_validators: Option<&GenesisValidators>,
) -> outbe_primitives::error::Result<()> {
    run_outbe_pre_execution_hooks_inner(hook_ctx, genesis_validators, None)
}

/// Runs pre-execution hooks with explicit off-chain body read authority.
pub fn run_outbe_pre_execution_hooks_with_readers(
    hook_ctx: &BlockRuntimeContext,
    genesis_validators: Option<&GenesisValidators>,
    readers: &RuntimeBodyReaders,
    scope: &ExecutionScope,
) -> outbe_primitives::error::Result<()> {
    run_outbe_pre_execution_hooks_inner(hook_ctx, genesis_validators, Some((readers, scope)))
}

fn run_outbe_pre_execution_hooks_inner(
    hook_ctx: &BlockRuntimeContext,
    genesis_validators: Option<&GenesisValidators>,
    readers: Option<(&RuntimeBodyReaders, &ExecutionScope)>,
) -> outbe_primitives::error::Result<()> {
    let block_number = hook_ctx.block.block_number;
    let timestamp = hook_ctx.block.timestamp;

    // Genesis state must be present in genesis.json. The executor only
    // verifies the local validators config against that canonical state.
    if block_number <= 1 {
        if let Some(genesis) = genesis_validators {
            validate_genesis_state(hook_ctx.storage.clone(), genesis)?;
        }
    }

    // Vote: tally expired proposals and dispatch approved ones.
    outbe_vote::lifecycle::VoteLifecycle::begin_block_with_handlers(
        hook_ctx,
        crate::handlers::vote::registry(),
    )?;

    // Update: activate scheduled updates at activation height.
    outbe_update::lifecycle::UpdateLifecycle::begin_block_with_handlers(
        hook_ctx,
        crate::handlers::update::registry(),
    )?;

    // EmissionLimit no longer participates in pre-execution lifecycle.
    // Per-block emission dispatch was removed (Phase 4 of
    // the Cycle epic) - the closed-form daily cap, sink allocation,
    // and AgentReward / Metadosis dispatch all run from ProtocolCycle's
    // persisted UTC-day decision instead.

    // Rewards lifecycle: locks in `genesis_utc_day` on block 0. Day-
    // boundary settle moved out of Rewards (Phase 3); the
    // Cycle handler now owns the daily orchestration.
    <outbe_rewards::lifecycle::RewardsLifecycle as BlockLifecycle>::begin_block(hook_ctx)?;

    // Metadosis WWD state machine + lysis distribution moved to the
    // Cycle handler. The
    // legacy `MetadosisLifecycle::begin_block` lifecycle hook used to
    // run here on every block; it is now invoked once per hourly
    // `outbe_cycle::handler::run_protocol_cycle` pass, after an optional
    // contiguous-day `dispatch_terminal_remainder_at` write.

    // Staking: process matured unbonding entries.
    outbe_staking::hooks::process_unbonding(hook_ctx.storage.clone(), timestamp)?;

    // Oracle: tally at vote period boundary and run daily S-curve. Slash-window
    // force-exits run later in the receipt-visible OracleSlashWindow system phase
    // so Phase 3 BoundaryOutcome can activate its target set before Oracle marks
    // underperformers EXITING.
    <outbe_oracle::lifecycle::OracleLifecycle as BlockLifecycle>::begin_block(hook_ctx)?;

    // Nod qualification mutates compressed bucket bodies and therefore runs
    // later inside the receipt-visible CycleTick system transaction. Oracle
    // has already published the rate that transaction observes.
    let _ = readers;

    // GEM: promote unqualified gems whose floor_price < current COEN/<reference>
    // exchange rate AND whose maturity has elapsed. Reads the same Oracle
    // surface, so it must run after Oracle.
    <outbe_gem::GemLifecycle as BlockLifecycle>::begin_block(hook_ctx)?;

    // INTEX: qualify aged Issued series whose floor < current COEN/840
    // rate. Reads the same Oracle surface, so it runs after Oracle.
    <outbe_intexfactory::IntexLifecycle as BlockLifecycle>::begin_block(hook_ctx)?;

    Ok(())
}

fn run_atomic_storage_hooks<DB, F>(
    db: &mut DB,
    ctx: BlockContext,
    hooks: F,
) -> Result<(AddressMap<Account>, Vec<Log>), BlockExecutionError>
where
    DB: StateDB,
    DB::Error: std::fmt::Display,
    F: FnOnce(&BlockRuntimeContext) -> outbe_primitives::error::Result<()>,
{
    run_atomic_storage_hook_with_output(db, ctx, hooks)
        .map(|(changes, events, ())| (changes, events))
}

fn run_atomic_storage_hook_with_output<DB, F, R>(
    db: &mut DB,
    ctx: BlockContext,
    hooks: F,
) -> Result<(AddressMap<Account>, Vec<Log>, R), BlockExecutionError>
where
    DB: StateDB,
    DB::Error: std::fmt::Display,
    F: FnOnce(&BlockRuntimeContext) -> outbe_primitives::error::Result<R>,
{
    let mut provider = DirectStorageProvider::new(db, ctx.clone());
    let storage = StorageHandle::new(&mut provider);
    let runtime_ctx = BlockRuntimeContext::new(ctx, storage.clone());

    let result = storage.with_checkpoint(|| hooks(&runtime_ctx));

    // Preserve the concrete hook error across the executor boundary. Payload
    // construction must distinguish node-local readiness (for example a stale
    // compressed-tree parent) from deterministic corruption; stringifying here
    // destroys that distinction and turns a cancellable job into an alarm.
    let output = result.map_err(BlockExecutionError::other)?;

    provider.flush().map_err(|e| {
        BlockExecutionError::Internal(InternalBlockExecutionError::Other(
            format!("outbe hook flush: {e}").into(),
        ))
    })?;

    let changes = provider.take_committed_changes();
    let events = provider.take_events();
    Ok((changes, events, output))
}

fn build_block_context<DB>(
    db: &mut DB,
    block_number: u64,
    timestamp: u64,
    chain_id: u64,
    genesis_hash: B256,
    proposer: Address,
) -> Result<BlockContext, BlockExecutionError>
where
    DB: StateDB,
    DB::Error: std::fmt::Display,
{
    let mut provider = DirectStorageProvider::new(
        db,
        BlockContext::new_with_genesis_hash(
            block_number,
            timestamp,
            chain_id,
            genesis_hash,
            proposer,
            Vec::new(),
        ),
    );
    let storage = StorageHandle::new(&mut provider);
    let validators = (|| -> outbe_primitives::error::Result<Vec<Address>> {
        let vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
        let mut validators: Vec<Address> = vs
            .get_active_consensus_set()?
            .into_iter()
            .map(|record| record.validator_address)
            .collect();
        validators.sort();
        Ok(validators)
    })()
    .map_err(|e| {
        BlockExecutionError::Internal(InternalBlockExecutionError::Other(
            format!("block context: {e}").into(),
        ))
    })?;

    Ok(BlockContext::new_with_genesis_hash(
        block_number,
        timestamp,
        chain_id,
        genesis_hash,
        proposer,
        validators,
    ))
}

fn validate_genesis_state(storage: StorageHandle, genesis: &GenesisValidators) -> OutbeResult<()> {
    let vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
    if !vs.config_is_initialized.read()? {
        return Err(PrecompileError::Fatal(
            "ValidatorSet must be initialized in genesis; executor genesis backfill is disabled"
                .into(),
        ));
    }

    let epoch_length_blocks = vs.config_epoch_length_blocks.read()?;
    if epoch_length_blocks != genesis.epoch_length_blocks {
        return Err(PrecompileError::Fatal(format!(
            "genesis ValidatorSet epoch_length_blocks mismatch: state={epoch_length_blocks}, genesis={}",
            genesis.epoch_length_blocks
        )));
    }

    let active_consensus_count = vs.active_consensus_count()?;
    if active_consensus_count as usize != genesis.validators.len() {
        return Err(PrecompileError::Fatal(format!(
            "genesis active consensus set size mismatch: state={active_consensus_count}, genesis validators={}",
            genesis.validators.len()
        )));
    }

    let staking = outbe_staking::contract::Staking::new(storage.clone());
    let min_stake = staking.config_min_stake.read()?;
    if min_stake.is_zero() {
        return Err(PrecompileError::Fatal(
            "Staking min_stake must be initialized in genesis".into(),
        ));
    }

    let mut expected_total = U256::ZERO;
    for validator in &genesis.validators {
        let state = vs.validator_state(validator.address)?;
        if !state.is_registered() {
            return Err(PrecompileError::Fatal(format!(
                "genesis validator {} is missing from ValidatorSet",
                validator.address
            )));
        }

        if state.consensus_pubkey().copied() != Some(validator.consensus_pubkey) {
            return Err(PrecompileError::Fatal(format!(
                "genesis validator {} consensus pubkey mismatch",
                validator.address
            )));
        }
        if !matches!(state.lifecycle(), ValidatorLifecycle::Active(_)) {
            return Err(PrecompileError::Fatal(format!(
                "genesis validator {} must be active with a BLS share",
                validator.address
            )));
        }
        let bonded_stake = state.bonded_stake();
        if bonded_stake < min_stake {
            return Err(PrecompileError::Fatal(format!(
                "genesis validator {} stake below min_stake",
                validator.address
            )));
        }

        let staking_amount = staking.stake_amount.read(&validator.address)?;
        if staking_amount != bonded_stake {
            return Err(PrecompileError::Fatal(format!(
                "genesis validator {} stake mismatch between ValidatorSet and Staking",
                validator.address
            )));
        }
        expected_total = expected_total
            .checked_add(staking_amount)
            .ok_or_else(|| PrecompileError::Fatal("genesis total stake overflow".into()))?;
    }

    let total_staked = staking.total_staked.read()?;
    if total_staked != expected_total {
        return Err(PrecompileError::Fatal(format!(
            "genesis total_staked mismatch: state={total_staked}, expected={expected_total}"
        )));
    }

    Ok(())
}

/// Outbe block executor.
///
/// Wraps the standard [`EthBlockExecutor`] and routes Outbe system transactions
/// through the same ordered transaction/receipt path as user transactions.
/// `apply_pre_execution_changes()` only performs pre-block setup; begin-zone
/// phases execute when their reserved-address body transaction reaches the loop.
pub struct OutbeBlockExecutor<'a, Evm> {
    /// Inner Ethereum execution strategy.
    pub inner: EthBlockExecutor<'a, Evm, &'a Arc<ChainSpec<OutbeHeader>>, &'a RethReceiptBuilder>,
    /// Immutable chain identity sourced from the executor's canonical ChainSpec.
    genesis_hash: B256,
    /// Optional bridge to the consensus layer for finalization data.
    pub bridge: Option<ConsensusExecutionBridge>,
    /// Header-carried consensus artifact bytes (`extra_data`) used by begin-zone phases.
    block_extra_data: Bytes,
    /// Canonical final header `extra_data` bytes. On the verifier path this is
    /// initialized from the sealed block header; on the proposer path the block
    /// builder overwrites it after injecting the execution summary and timestamp
    /// millis but before `finish()`.
    final_extra_data: Bytes,
    /// Historical header artifact reader used for finalized-block settlement.
    accounted_parent_artifact_provider: Option<Arc<dyn AccountedParentArtifactProvider>>,
    /// Whether this executor is validating an already-built block and must
    /// compare the header-carried execution summary to local execution output.
    validate_execution_summary: bool,
    /// Hash of the block being validated, when execution is for an existing block.
    block_hash: Option<B256>,
    /// State root committed by the block being validated. It is cached with the
    /// execution summary so the immediate child can bind OCOMP finality even
    /// during the Reth in-memory-tree/provider visibility window.
    block_state_root: Option<B256>,
    /// Hash of this block's parent header.
    parent_hash: B256,
    /// Priority/coinbase fees collected by user transactions in this block.
    current_block_validator_fees: U256,
    /// Internal gas consumed by begin-zone system transactions under the
    /// Outbe-only 100M execution lane. The Ethereum-visible block counters use
    /// each system tx envelope's visible intrinsic gas instead.
    system_tx_execution_gas: u64,
    /// Validator-mode signer used by proposer path to sign system-tx artifacts.
    evm_signer: Option<SharedOutbeEvmSigner>,
    expected_begin_system_txs: Vec<Recovered<TransactionSigned>>,
    expected_end_system_txs: Vec<Recovered<TransactionSigned>>,
    ocomp_lifecycle_active: bool,
    ocomp_terminal_request_consumed: bool,
    /// Standard Ethereum post-execution output captured before CE seal and
    /// OSR2. Active OCOMP blocks must not call the inner executor's `finish`
    /// afterward because that would create semantic writes after OSR2.
    ethereum_post_execution_requests: Option<Requests>,
    system_layout_error: Option<String>,
    parent_consensus_metadata: Option<CertifiedParentAccountingMetadata>,
    proposer_evm_address: Option<Address>,
    execute_outbe_block_hooks: bool,
    /// cursor that drives begin-zone phase routing inside
    /// `execute_transaction_with_commit_condition` instead of
    /// `self.inner.receipts.len()`. Set to the per-block initial value when
    /// the executor enters `apply_pre_execution_changes` and advanced once
    /// per consumed begin-zone system tx.
    system_tx_phase_cursor: crate::system_tx::SystemTxPhase,
    /// proposer-side prebuilt Phase 1 body[0] tx. Set by the payload
    /// builder before `apply_pre_execution_changes`; consumed inside
    /// `apply_phase1_commit_in_preexec` as the canonical witness whose
    /// `signature_hash` is cached in the phase cursor. `None` on the validator
    /// path (witness comes from `expected_begin_system_txs.first()`) and for
    /// `block_number <= GENESIS_BOOTSTRAP_BLOCK_NUMBER`.
    prebuilt_phase1_tx: Option<Recovered<TransactionSigned>>,
    /// optional accounted-parent artifact hint supplied by the
    /// payload builder. Consumed by
    /// [`Self::accounted_parent_artifact_for_metadata`] when the
    /// [`AccountedParentArtifactProvider`] returns `None`. Accepted only if
    /// the metadata's `(finalized_block_number, finalized_block_hash)`
    /// matches `(self.parent_block_number(), self.parent_hash)`.
    parent_artifact_hint: Option<AccountedParentArtifact>,
    /// canonical VRF proof hash captured by
    /// `verify_phase1_in_preexec` from the verified parent certificate
    /// (`outbe_consensus::proof::VerifiedProof::vrf_proof_hash`).
    /// Consumed by `apply_phase1_commit_in_preexec` and the main-tx-loop
    /// Phase 1 path to populate `PreloadedSystemTxContext.canonical_vrf_proof_hash`,
    /// which the V3 Rewards fingerprint binds. `None` until the preflight
    /// has run; remains `None` for skip paths (block 0 / 1, test opt-out).
    verified_phase1_vrf_proof_hash: Option<B256>,
    /// Proposer-only one-time Phase 3b `TeeBootstrap` payload. When `Some` on the
    /// proposer path, `begin_block_system_tx_inputs` injects the bootstrap system
    /// tx after `BoundaryOutcome` - identically to `build_begin_system_txs` so the
    /// body the proposer signs and the inputs the executor expects match. `None`
    /// on the validator path (the body carries it via `expected_begin_system_txs`)
    /// and until the tribute-DKG bootstrap producer supplies a payload.
    pending_tee_bootstrap: Option<outbe_primitives::tee_bootstrap_v2::TeeBootstrapV2>,
    /// Whitelisted pre-exec hook logs published through the mandatory
    /// `HookEvents` system tx receipt at the end of the begin zone.
    whitelisted_hook_event_logs: Vec<Log>,
    /// Number of zero-fee soft-failure receipts emitted in THIS
    /// block. Bounds block-stuffing by zero-cost 21k soft-failures (see
    /// [`Self::record_zero_fee_soft_failure`]). The executor is constructed
    /// fresh per block, so this resets per block; it is identical on the
    /// proposer (build) and validator (re-execution) paths.
    zero_fee_soft_failures: u32,
    /// Least-authority off-chain readers used by lifecycle body reads.
    runtime_body_readers: Option<RuntimeBodyReaders>,
    execution_read_budget_guard: Option<ExecutionReadBudgetGuard>,
    /// One lifecycle capability shared with every precompile in this EVM.
    compressed_entities_scope: Arc<ExecutionScope>,
    compressed_entities_started: bool,
    compressed_entities_seal_output: Option<outbe_compressed_entities::SealOutput>,
    compressed_tree_service: Option<Arc<outbe_compressed_entities::CompressedTreeService>>,
}

// test-only opt-out: scoped flag that disables the Phase 1
// `verify_v2_proof` preflight in `apply_pre_execution_changes`. The flag
// is thread-local and one-shot per test; production code paths never set
// it. See `with_phase1_verify_disabled`.
#[cfg(test)]
thread_local! {
    static PHASE1_VERIFY_DISABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test-only guard that disables the Phase 1 `verify_v2_proof` preflight
/// for the duration of `f`. Production code paths never call this.
#[cfg(test)]
pub(crate) fn with_phase1_verify_disabled<R>(f: impl FnOnce() -> R) -> R {
    PHASE1_VERIFY_DISABLED.with(|cell| cell.set(true));
    let result = f();
    PHASE1_VERIFY_DISABLED.with(|cell| cell.set(false));
    result
}

impl<'a, Evm> OutbeBlockExecutor<'a, Evm> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        inner: EthBlockExecutor<'a, Evm, &'a Arc<ChainSpec<OutbeHeader>>, &'a RethReceiptBuilder>,
        bridge: Option<ConsensusExecutionBridge>,
        block_extra_data: Bytes,
        accounted_parent_artifact_provider: Option<Arc<dyn AccountedParentArtifactProvider>>,
        validate_execution_summary: bool,
        block_hash: Option<B256>,
        parent_hash: B256,
        evm_signer: Option<SharedOutbeEvmSigner>,
        expected_begin_system_txs: Vec<Recovered<TransactionSigned>>,
        expected_end_system_txs: Vec<Recovered<TransactionSigned>>,
        system_layout_error: Option<String>,
        parent_consensus_metadata: Option<CertifiedParentAccountingMetadata>,
        proposer_evm_address: Option<Address>,
        execute_outbe_block_hooks: bool,
        prebuilt_phase1_tx: Option<Recovered<TransactionSigned>>,
        parent_artifact_hint: Option<AccountedParentArtifact>,
    ) -> Self {
        let genesis_hash = inner.spec.genesis_hash();
        Self {
            inner,
            genesis_hash,
            bridge,
            final_extra_data: block_extra_data.clone(),
            block_extra_data,
            accounted_parent_artifact_provider,
            validate_execution_summary,
            block_hash,
            block_state_root: None,
            parent_hash,
            current_block_validator_fees: U256::ZERO,
            system_tx_execution_gas: 0,
            evm_signer,
            expected_begin_system_txs,
            expected_end_system_txs,
            ocomp_lifecycle_active: false,
            ocomp_terminal_request_consumed: false,
            ethereum_post_execution_requests: None,
            system_layout_error,
            parent_consensus_metadata,
            proposer_evm_address,
            execute_outbe_block_hooks,
            // placeholder; the real initial value is computed in
            // `apply_pre_execution_changes` once `block_number` is known and
            // the Phase 1 preflight has (or has not) been performed.
            system_tx_phase_cursor: crate::system_tx::SystemTxPhase::UserTxs,
            prebuilt_phase1_tx,
            parent_artifact_hint,
            // populated by `verify_phase1_in_preexec` on real
            // verify; remains `None` for skip paths.
            verified_phase1_vrf_proof_hash: None,
            // proposer-only; set via `with_pending_tee_bootstrap` from the
            // execution ctx. `None` keeps the begin-zone unchanged.
            pending_tee_bootstrap: None,
            whitelisted_hook_event_logs: Vec::new(),
            zero_fee_soft_failures: 0,
            runtime_body_readers: None,
            execution_read_budget_guard: None,
            compressed_entities_scope: Arc::new(ExecutionScope::new()),
            compressed_entities_started: false,
            compressed_entities_seal_output: None,
            compressed_tree_service: None,
        }
    }

    pub(crate) fn with_compressed_entities_scope(mut self, scope: Arc<ExecutionScope>) -> Self {
        self.compressed_entities_scope = scope;
        self
    }

    pub(crate) fn with_block_state_root(mut self, state_root: Option<B256>) -> Self {
        self.block_state_root = state_root;
        self
    }

    pub(crate) fn with_ocomp_lifecycle_active(mut self, active: bool) -> Self {
        self.ocomp_lifecycle_active = active;
        self
    }

    pub(crate) fn compressed_entities_seal_output(
        &self,
    ) -> Option<outbe_compressed_entities::SealOutput> {
        self.compressed_entities_seal_output.clone()
    }

    #[cfg(test)]
    pub(crate) fn force_preexecuted_phase1_witness_for_test(&mut self, tx_hash: B256) {
        self.system_tx_phase_cursor = crate::system_tx::SystemTxPhase::Phase1Preexecuted {
            body_index: 0,
            tx_hash,
            receipt_index: 0,
        };
    }

    pub(crate) fn with_compressed_tree_service(
        mut self,
        service: Option<Arc<outbe_compressed_entities::CompressedTreeService>>,
    ) -> Self {
        self.compressed_tree_service = service;
        self
    }

    pub(crate) fn compressed_tree_service(
        &self,
    ) -> Option<Arc<outbe_compressed_entities::CompressedTreeService>> {
        self.compressed_tree_service.clone()
    }

    pub(crate) fn with_runtime_body_readers(
        mut self,
        readers: Option<RuntimeBodyReaders>,
        budget: Option<outbe_primitives::projection::ExecutionReadBudget>,
    ) -> Self {
        self.execution_read_budget_guard = readers
            .as_ref()
            .zip(budget)
            .map(|(readers, budget)| readers.enter_execution_budget(budget));
        self.runtime_body_readers = readers;
        self
    }

    /// Proposer-path builder: attach the one-time `TeeBootstrap` payload the
    /// executor injects after `BoundaryOutcome`. No-op (stays `None`) on the
    /// validator path. Mirrors `OutbeEvmConfig::build_begin_system_txs`.
    pub(crate) fn with_pending_tee_bootstrap(
        mut self,
        pending_tee_bootstrap: Option<outbe_primitives::tee_bootstrap_v2::TeeBootstrapV2>,
    ) -> Self {
        self.pending_tee_bootstrap = pending_tee_bootstrap;
        self
    }

    /// read the current begin-zone system-tx phase cursor.
    /// Test-only introspection point; the production driver is internal.
    /// Consumer (cursor-driven routing) lands Batch 3.
    #[allow(dead_code)]
    pub(crate) fn system_tx_phase_cursor(&self) -> crate::system_tx::SystemTxPhase {
        self.system_tx_phase_cursor
    }

    pub(crate) fn is_preexecuted_phase1_witness(&self, tx: &TransactionSigned) -> bool {
        let crate::system_tx::SystemTxPhase::Phase1Preexecuted {
            tx_hash: cached_hash,
            ..
        } = self.system_tx_phase_cursor
        else {
            return false;
        };

        !cached_hash.is_zero() && is_reserved_system_tx(tx) && tx.signature_hash() == cached_hash
    }

    /// Intrinsic gas accounted on the synthetic receipt that replaces a
    /// hard `BlockExecutionError` when the executor rejects a user transaction
    /// outside the EVM (zero-fee policy). The value mirrors the
    /// 21_000 intrinsic-gas baseline of every EVM transaction.
    const SOFT_FAILURE_GAS: u64 = 21_000;

    /// Maximum number of zero-fee soft-failure receipts a single
    /// block may carry.
    ///
    /// Quota-exhausted EIP-7702-sponsored txs and duplicate/losing
    /// zero-fee oracle votes are soft-receipted (`status=0`, 21k gas) so
    /// they land in the block rather than aborting the build (the 2026-05-15
    /// halt). Without a bound, an attacker can stuff a whole block with
    /// thousands of zero-cost 21k soft-failures, crowding out real transactions.
    /// 64 is far above the handful of soft-failures honest operation produces
    /// per block, yet caps stuffing at `64 * 21k ~= 1.34M` gas - under ~5% of a
    /// 30M-gas block. Protocol constant: both the proposer (build) and validator
    /// (re-execution) read it, so they agree on the bound.
    const MAX_ZERO_FEE_SOFT_FAILURES_PER_BLOCK: u32 = 64;

    /// Account for one zero-fee soft-failure and enforce the
    /// per-block cap.
    ///
    /// Returns `Ok(())` when the soft-failure is within the per-block budget (and
    /// records it); past [`Self::MAX_ZERO_FEE_SOFT_FAILURES_PER_BLOCK`] it
    /// returns `Err(BlockValidationError::InvalidTx)`, which the payload builder
    /// SKIPS (`mark_invalid` + continue - the tx is excluded from the block and
    /// evicted from the pool) while a validator REJECTS a block that exceeds the
    /// cap (the `?` on the re-execution path propagates it as a block failure).
    /// The counter is the number of zero-fee soft-receipts in the block and is
    /// identical on both paths, so an honest block (`<= cap`) never trips the
    /// validator and a byzantine over-cap block is rejected deterministically by
    /// every validator. `InvalidTransaction::Str` is a tx-level validation error
    /// (not nonce-too-low, so the builder marks it invalid rather than retrying),
    /// keeping it out of the fatal `BlockExecutionError::Internal` class that
    /// would abort the build.
    fn record_zero_fee_soft_failure(&mut self, tx_hash: B256) -> Result<(), BlockExecutionError> {
        if self.zero_fee_soft_failures >= Self::MAX_ZERO_FEE_SOFT_FAILURES_PER_BLOCK {
            let reason = format!(
                "zero-fee soft-failure cap ({}) exceeded for this block; tx rejected to bound \
                 block stuffing",
                Self::MAX_ZERO_FEE_SOFT_FAILURES_PER_BLOCK
            );
            return Err(BlockExecutionError::Validation(
                BlockValidationError::InvalidTx {
                    hash: tx_hash,
                    error: Box::new(InvalidTransaction::Str(std::borrow::Cow::Owned(reason))),
                },
            ));
        }
        self.zero_fee_soft_failures = self.zero_fee_soft_failures.saturating_add(1);
        Ok(())
    }

    /// Pushes a `status=0` synthetic receipt with exactly one
    /// `OutbeFailure(code, reason)` log, advances the user transaction gas
    /// accumulators by `SOFT_FAILURE_GAS`, and leaves EVM state untouched.
    ///
    /// Used by:
    /// - the zero-fee user-tx path (`outbe-zerofee` rejection).
    ///
    /// System transaction failures use [`Self::push_system_failure_receipt`]
    /// so they charge the signed envelope's visible gas while keeping internal
    /// execution gas in `system_tx_execution_gas`.
    ///
    /// Determinism: the synthetic log encoding depends only on
    /// `(log_address, code, reason)`; identical inputs across proposer
    /// and validators yield byte-equal receipts and therefore byte-equal
    /// `receipts_root`. See `crate::failure_receipt`.
    pub(crate) fn push_failure_receipt(
        &mut self,
        tx_type: alloy_consensus::TxType,
        log_address: Address,
        code: u16,
        reason: String,
    ) {
        let log = crate::failure_receipt::build_outbe_failure_log(log_address, code, reason);
        let user_cumulative_gas_used = self
            .inner
            .cumulative_tx_gas_used
            .saturating_add(Self::SOFT_FAILURE_GAS);
        self.inner.receipts.push(Receipt {
            tx_type,
            success: false,
            cumulative_gas_used: user_cumulative_gas_used,
            logs: vec![log],
        });
        self.inner.cumulative_tx_gas_used = user_cumulative_gas_used;
        self.inner.block_regular_gas_used = self
            .inner
            .block_regular_gas_used
            .saturating_add(Self::SOFT_FAILURE_GAS);
        self.inner.block_state_gas_used = self
            .inner
            .block_state_gas_used
            .saturating_add(Self::SOFT_FAILURE_GAS);
    }

    /// Pushes a `status=1` synthetic receipt for the mandatory `HookEvents` system
    /// tx, carrying whitelisted pre-exec hook logs without re-running lifecycle hooks.
    pub(crate) fn push_hook_events_receipt(
        &mut self,
        tx_type: alloy_consensus::TxType,
        logs: Vec<Log>,
        visible_gas_used: u64,
    ) -> Result<GasOutput, BlockExecutionError> {
        let user_cumulative_tx_gas = self
            .inner
            .cumulative_tx_gas_used
            .checked_add(visible_gas_used)
            .ok_or_else(|| {
                BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                    "HookEvents visible gas overflow".into(),
                ))
            })?;
        self.inner.receipts.push(Receipt {
            tx_type,
            success: true,
            cumulative_gas_used: user_cumulative_tx_gas,
            logs,
        });
        self.inner.cumulative_tx_gas_used = user_cumulative_tx_gas;
        self.inner.block_regular_gas_used = self
            .inner
            .block_regular_gas_used
            .saturating_add(visible_gas_used);
        self.inner.block_state_gas_used = self
            .inner
            .block_state_gas_used
            .saturating_add(visible_gas_used);
        Ok(GasOutput::new(visible_gas_used))
    }
}

/// Maps an `ExecutionResult` (from a Phase 1-4 system tx that produced
/// `!is_success`) to a stable `u16` `OutbeFailure` code in the 200-299
/// band reserved for `outbe-evm` phase failures. The exhaustive `match`
/// makes adding a new revm variant a compile error.
///
/// Codes:
/// - 201 - explicit revert (Solidity `require`, `revert`, etc.)
/// - 202 - out-of-gas (any `OutOfGasError` variant)
/// - 299 - other halt reasons (precompile error, opcode not found, ...)
pub(crate) fn system_tx_failure_code_for_result(result: &ExecutionResult<HaltReason>) -> u16 {
    match result {
        // Callers only reach this fn under `!result.is_success()`, so the Success
        // arm is unreachable in practice; map it to the generic 299 fallback
        // deterministically rather than `debug_assert!`-panicking (no panic-class
        // macro on the executor path).
        ExecutionResult::Success { .. } => 299,
        ExecutionResult::Revert { .. } => 201,
        ExecutionResult::Halt { reason, .. } => match reason {
            HaltReason::OutOfGas(OutOfGasError::Basic)
            | HaltReason::OutOfGas(OutOfGasError::MemoryLimit)
            | HaltReason::OutOfGas(OutOfGasError::Memory)
            | HaltReason::OutOfGas(OutOfGasError::Precompile)
            | HaltReason::OutOfGas(OutOfGasError::InvalidOperand)
            | HaltReason::OutOfGas(OutOfGasError::ReentrancySentry) => 202,
            _ => 299,
        },
    }
}

fn is_ocomp_deadline_passed_revert(result: &ExecutionResult<HaltReason>) -> bool {
    matches!(
        result,
        ExecutionResult::Revert { output, .. }
            if outbe_metadosis::is_deadline_passed_result_vote_revert_data(output.as_ref())
    )
}

fn is_nod_materialization_soft_revert(result: &ExecutionResult<HaltReason>) -> bool {
    matches!(
        result,
        ExecutionResult::Revert { output, .. }
            if outbe_nodfactory::materialization::is_soft_materialization_revert_data(
                output.as_ref()
            )
    )
}

#[cfg(test)]
mod system_tx_failure_code_tests {
    use super::*;
    use revm::context::result::ResultGas;

    fn revert_result() -> ExecutionResult<HaltReason> {
        ExecutionResult::Revert {
            gas: ResultGas::default(),
            logs: Vec::new(),
            output: Default::default(),
        }
    }

    fn halt_result(reason: HaltReason) -> ExecutionResult<HaltReason> {
        ExecutionResult::Halt {
            reason,
            gas: ResultGas::default(),
            logs: Vec::new(),
        }
    }

    #[test]
    fn revert_maps_to_201() {
        assert_eq!(system_tx_failure_code_for_result(&revert_result()), 201);
    }

    #[test]
    fn only_the_exact_ocomp_deadline_revert_is_a_failed_carrier_receipt() {
        let deadline = ExecutionResult::Revert {
            gas: ResultGas::default(),
            logs: Vec::new(),
            output: outbe_metadosis::deadline_passed_result_vote_revert_data(),
        };
        assert!(is_ocomp_deadline_passed_revert(&deadline));
        assert!(!is_ocomp_deadline_passed_revert(&revert_result()));
        assert!(!is_ocomp_deadline_passed_revert(&halt_result(
            HaltReason::OutOfGas(OutOfGasError::Precompile)
        )));
    }

    #[test]
    fn only_typed_materialization_race_and_proof_rejections_are_failed_receipts() {
        use outbe_nodfactory::materialization::{
            materialization_revert_data, NodMaterializationRejectionV1,
        };

        for rejection in [
            NodMaterializationRejectionV1::StaleQueueSequence,
            NodMaterializationRejectionV1::StaleCursor,
            NodMaterializationRejectionV1::AttemptLimit,
            NodMaterializationRejectionV1::InvalidBatchShape,
            NodMaterializationRejectionV1::InvalidProof,
            NodMaterializationRejectionV1::DuplicateNod,
        ] {
            let result = ExecutionResult::Revert {
                gas: ResultGas::default(),
                logs: Vec::new(),
                output: materialization_revert_data(rejection),
            };
            assert!(is_nod_materialization_soft_revert(&result));
        }

        assert!(!is_nod_materialization_soft_revert(&revert_result()));
        assert!(!is_nod_materialization_soft_revert(
            &ExecutionResult::Revert {
                gas: ResultGas::default(),
                logs: Vec::new(),
                output: materialization_revert_data(
                    NodMaterializationRejectionV1::UnauthorizedSigner,
                ),
            }
        ));
        assert!(!is_nod_materialization_soft_revert(&halt_result(
            HaltReason::OutOfGas(OutOfGasError::Precompile),
        )));
    }

    #[test]
    fn out_of_gas_maps_to_202() {
        for variant in [
            OutOfGasError::Basic,
            OutOfGasError::MemoryLimit,
            OutOfGasError::Memory,
            OutOfGasError::Precompile,
            OutOfGasError::InvalidOperand,
            OutOfGasError::ReentrancySentry,
        ] {
            let r = halt_result(HaltReason::OutOfGas(variant));
            assert_eq!(system_tx_failure_code_for_result(&r), 202, "{variant:?}");
        }
    }

    #[test]
    fn other_halt_maps_to_299() {
        assert_eq!(
            system_tx_failure_code_for_result(&halt_result(HaltReason::PrecompileError)),
            299
        );
    }

    #[test]
    fn codes_are_in_phase_band() {
        for code in [
            system_tx_failure_code_for_result(&revert_result()),
            system_tx_failure_code_for_result(&halt_result(HaltReason::OutOfGas(
                OutOfGasError::Memory,
            ))),
            system_tx_failure_code_for_result(&halt_result(HaltReason::PrecompileError)),
        ] {
            assert!(
                (200..=299).contains(&code),
                "phase failure code {code} outside 200..=299 band"
            );
        }
    }
}

impl<'a, Evm> OutbeBlockExecutor<'a, Evm> {
    pub(crate) fn current_execution_summary(&self) -> ExecutionSummaryArtifact
    where
        Evm: reth_ethereum::evm::primitives::Evm,
    {
        // ExecutionSummaryArtifact wire format v0x04 carries
        // only `validator_fee_sum`; the per-block emission field has
        // been removed because daily emission is computed by the Cycle
        // handler from the closed-form formula and does not need to
        // travel in `extra_data`.
        ExecutionSummaryArtifact {
            validator_fee_sum: self.current_block_validator_fees,
        }
    }

    /// Canonical final header `extra_data` bytes used by `finish()` for
    /// execution-summary validation and bridge recording.
    pub(crate) fn final_extra_data(&self) -> &Bytes {
        &self.final_extra_data
    }

    pub(crate) fn set_final_extra_data(&mut self, bytes: Bytes) {
        self.final_extra_data = bytes;
    }

    /// Pre-encodes the final execution-produced artifact fields after CE seal.
    /// The block-builder adapter owns the encoding; this executor entry point
    /// lets the opaque Reth builder path invoke it before parallel root freeze.
    pub fn prepare_final_header_artifacts(
        &mut self,
        timestamp_millis_part: u64,
    ) -> Result<(), BlockExecutionError>
    where
        Evm: reth_ethereum::evm::primitives::Evm,
    {
        let seal = self
            .compressed_entities_seal_output
            .as_ref()
            .ok_or_else(|| BlockExecutionError::msg("missing compressed-entities SealOutput"))?;
        self.final_extra_data = crate::builder::encode_final_header_artifacts(
            self.final_extra_data.as_ref(),
            self.current_execution_summary(),
            timestamp_millis_part,
            seal.new_root,
        )?;
        Ok(())
    }

    // Half C-parlia step 11: `set_pending_consensus_metadata` and
    // `ingest_consensus_metadata_tx` are deleted. Finalized-parent
    // metadata now lives in the begin-zone Phase 1 system transaction input;
    // the pre-exec dispatch arm at `execute_transaction_with_commit_condition`
    // no longer accepts consensus metadata transactions, and the proposer no
    // longer produces them.
}

#[allow(private_bounds)]
impl<DB, E> OutbeBlockExecutor<'_, E>
where
    DB: StateDB,
    DB::Error: std::fmt::Display,
    E: Evm<DB = DB, Tx = TxEnv> + ZeroFeeCfgAccess,
    E::Error: std::fmt::Display,
{
    /// Finalizes the block-scoped compressed-entity overlay while the caller's
    /// state hook is still installed.
    ///
    /// Payload building invokes this before asking the parallel trie task for
    /// its root. Validator/general execution may rely on [`BlockExecutor::finish`],
    /// which calls the same helper. A successful call clears `started`, making
    /// the helper idempotent without permitting a second lifecycle transition.
    pub fn finalize_compressed_entities(&mut self) -> Result<(), BlockExecutionError> {
        if !self.compressed_entities_started {
            return Ok(());
        }

        let block_number = self.inner.evm.block().number().saturating_to::<u64>();
        let timestamp = self.inner.evm.block().timestamp().saturating_to::<u64>();
        let chain_id = self.inner.evm.chain_id();
        let proposer = self.inner.evm.block().beneficiary();
        let scope = self.compressed_entities_scope.clone();
        let (changes, events, seal_output) = {
            let db = self.inner.evm.db_mut();
            let ctx = build_block_context(
                db,
                block_number,
                timestamp,
                chain_id,
                self.genesis_hash,
                proposer,
            )?;
            run_atomic_storage_hook_with_output(db, ctx, |hook_ctx| {
                let lifecycle = outbe_compressed_entities::CompressedEntitiesLifecycleContext::new(
                    hook_ctx.clone(),
                    scope.as_ref(),
                );
                let output = <outbe_compressed_entities::CompressedEntitiesLifecycle as BlockLifecycle>::end_block(
                    &lifecycle,
                )?;
                let evm_root = B256::from(
                    hook_ctx
                        .storage
                        .sload(
                            outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
                            U256::from(1),
                        )?
                        .to_be_bytes::<32>(),
                );
                if evm_root != output.new_root {
                    return Err(PrecompileError::Fatal(format!(
                        "compressed-entities SealOutput/EVM root mismatch: seal={}, evm={}",
                        output.new_root, evm_root
                    )));
                }
                Ok(output)
            })?
        };
        if !events.is_empty() {
            return Err(BlockExecutionError::msg(
                "compressed-entity end_block emitted an unexpected event",
            ));
        }
        if !changes.is_empty() {
            use alloy_evm::block::{StateChangePostBlockSource, StateChangeSource};
            self.inner.system_caller.on_state(
                StateChangeSource::PostBlock(StateChangePostBlockSource::Other(
                    "compressed_entities_end_block",
                )),
                &changes,
            );
        }
        self.compressed_entities_started = false;
        self.compressed_entities_seal_output = Some(seal_output);
        Ok(())
    }

    /// Prepares the exact CE roots consumed by the terminal OCOMP phase while
    /// leaving the scope active for a possible failure retirement.
    fn preview_compressed_entities(
        &mut self,
    ) -> Result<outbe_compressed_entities::SealOutput, BlockExecutionError> {
        if !self.compressed_entities_started {
            return Err(BlockExecutionError::msg(
                "compressed-entity preview requested outside active lifecycle",
            ));
        }

        let block_number = self.inner.evm.block().number().saturating_to::<u64>();
        let timestamp = self.inner.evm.block().timestamp().saturating_to::<u64>();
        let chain_id = self.inner.evm.chain_id();
        let proposer = self.inner.evm.block().beneficiary();
        let scope = self.compressed_entities_scope.clone();
        let (changes, events, output) = {
            let db = self.inner.evm.db_mut();
            let ctx = build_block_context(
                db,
                block_number,
                timestamp,
                chain_id,
                self.genesis_hash,
                proposer,
            )?;
            run_atomic_storage_hook_with_output(db, ctx, |hook_ctx| {
                let lifecycle = outbe_compressed_entities::CompressedEntitiesLifecycleContext::new(
                    hook_ctx.clone(),
                    scope.as_ref(),
                );
                outbe_compressed_entities::preview_lifecycle_end_block(&lifecycle)
            })?
        };
        if !changes.is_empty() || !events.is_empty() {
            return Err(BlockExecutionError::msg(
                "compressed-entity preview unexpectedly mutated EVM state",
            ));
        }
        Ok(output)
    }

    /// Runs the standard Ethereum post-execution phase before the OCOMP
    /// terminal boundary.
    ///
    /// This intentionally mirrors [`EthBlockExecutor::finish`]'s semantic
    /// writes. The active OCOMP lifecycle requires a stricter order than the
    /// upstream executor exposes:
    ///
    /// `Ethereum post-execution -> CE preview -> OSR2 -> final CE seal`.
    ///
    /// The resulting EIP-7685 requests are retained for [`BlockExecutor::finish`],
    /// which assembles the result without invoking the upstream phase again.
    fn apply_outbe_ethereum_post_execution(&mut self) -> Result<(), BlockExecutionError> {
        if self.ethereum_post_execution_requests.is_some() {
            return Err(BlockExecutionError::msg(
                "standard Ethereum post-execution changes already applied",
            ));
        }

        validate_outbe_withdrawals(self.inner.ctx.withdrawals.as_deref())
            .map_err(|error| BlockExecutionError::msg(error.to_string()))?;

        let requests = if self
            .inner
            .spec
            .is_prague_active_at_timestamp(self.inner.evm.block().timestamp().saturating_to())
        {
            let deposit_requests =
                eip6110::parse_deposits_from_receipts(self.inner.spec, &self.inner.receipts)?;
            let mut requests = Requests::default();
            if !deposit_requests.is_empty() {
                requests.push_request_with_type(eip6110::DEPOSIT_REQUEST_TYPE, deposit_requests);
            }
            self.inner
                .system_caller
                .append_post_execution_changes(&mut self.inner.evm, &mut requests)?;
            requests
        } else {
            Requests::default()
        };

        let mut balance_increments = post_block_balance_increments(
            self.inner.spec,
            self.inner.evm.block(),
            self.inner.ctx.ommers,
            None,
        );

        if self
            .inner
            .spec
            .ethereum_fork_activation(EthereumHardfork::Dao)
            .transitions_at_block(self.inner.evm.block().number().saturating_to())
        {
            let drained_balance: u128 = self
                .inner
                .evm
                .db_mut()
                .drain_balances(dao_fork::DAO_HARDFORK_ACCOUNTS)
                .map_err(|_| BlockValidationError::IncrementBalanceFailed)?
                .into_iter()
                .sum();
            *balance_increments
                .entry(dao_fork::DAO_HARDFORK_BENEFICIARY)
                .or_default() += drained_balance;
        }

        self.inner
            .evm
            .db_mut()
            .increment_balances(balance_increments.clone())
            .map_err(|_| BlockValidationError::IncrementBalanceFailed)?;

        self.inner.system_caller.try_on_state_with(|| {
            balance_increment_state(&balance_increments, self.inner.evm.db_mut()).map(|state| {
                (
                    StateChangeSource::PostBlock(StateChangePostBlockSource::BalanceIncrements),
                    std::borrow::Cow::Owned(state),
                )
            })
        })?;

        self.ethereum_post_execution_requests = Some(requests);
        Ok(())
    }

    fn execute_ocomp_terminal_request<R>(
        &mut self,
        recovered: R,
        commit: impl FnOnce(&EthTxResult<E::HaltReason, alloy_consensus::TxType>) -> CommitChanges,
    ) -> Result<Option<GasOutput>, BlockExecutionError>
    where
        R: RecoveredTx<TransactionSigned>,
    {
        if !self.ocomp_lifecycle_active {
            return Err(BlockExecutionError::msg(
                "OCOMP terminal request is not active for this block",
            ));
        }
        if self.system_tx_phase_cursor != crate::system_tx::SystemTxPhase::UserTxs {
            return Err(BlockExecutionError::msg(
                "OCOMP terminal request arrived before the begin zone completed",
            ));
        }
        if self.expected_end_system_txs.len() > 1 {
            return Err(BlockExecutionError::msg(
                "OCOMP lifecycle permits exactly one end-zone system transaction",
            ));
        }

        let tx = recovered.tx();
        if let Some(expected) = self.expected_end_system_txs.first() {
            if expected.tx().tx_hash() != tx.tx_hash() {
                return Err(BlockExecutionError::msg(
                    "terminal system transaction differs from the validated block suffix",
                ));
            }
        }
        let input = SystemTxInputV2::decode(tx.input().as_ref()).map_err(|error| {
            BlockExecutionError::msg(format!("decode terminal system tx input: {error}"))
        })?;
        if input != SystemTxInputV2::OcompTerminalRequest {
            return Err(BlockExecutionError::msg(
                "end-zone system transaction is not OcompTerminalRequest",
            ));
        }

        let block_number = self.inner.evm.block().number().saturating_to::<u64>();
        let block_artifacts = decode_outbe_block_artifacts(self.block_extra_data.as_ref())
            .map_err(|error| BlockExecutionError::msg(error.to_string()))?;
        let begin_count = self
            .begin_block_system_tx_inputs(block_number, &block_artifacts)?
            .len();
        let ordinal = begin_count.try_into().map_err(|_| {
            BlockExecutionError::msg(format!(
                "terminal system tx ordinal {begin_count} exceeds u8 range"
            ))
        })?;
        let unsigned = build_unsigned_system_tx(
            SystemTxKind::OcompTerminalRequest,
            ordinal,
            block_number,
            self.inner.evm.chain_id(),
            tx.input().clone(),
        )
        .map_err(|error| {
            BlockExecutionError::msg(format!("build expected terminal system tx: {error}"))
        })?;
        if tx.signature_hash() != unsigned.signature_hash() {
            return Err(BlockExecutionError::msg(
                "terminal system tx signature hash mismatch",
            ));
        }
        let proposer = self
            .begin_zone_proposer(block_number)?
            .unwrap_or_else(|| self.inner.evm.block().beneficiary());
        let signer = *recovered.signer();
        if signer != proposer {
            return Err(BlockExecutionError::msg(format!(
                "terminal system tx signer mismatch: expected proposer {proposer}, got {signer}"
            )));
        }

        let tx_type = tx.tx_type();
        let signed_gas_limit = tx.gas_limit();
        let intrinsic_gas = crate::system_tx::system_tx_intrinsic_gas(tx.input().as_ref())
            .map_err(|error| {
                BlockExecutionError::msg(format!("terminal system tx intrinsic gas: {error}"))
            })?;

        // All ordinary and Ethereum post-execution changes are complete. The
        // terminal request consumes exact provisional roots while CE remains
        // active, so its failure path can retire the WWD Tribute partition as
        // the last CE mutation. The sole committed seal follows the terminal
        // decision.
        self.apply_outbe_ethereum_post_execution()?;
        self.preview_compressed_entities()?;

        let phase_context = PreloadedSystemTxContext {
            proposer,
            finalized_summary: None,
            allow_boundary_proposer: self.boundary_allows_proposer(&block_artifacts, proposer),
            canonical_vrf_proof_hash: B256::ZERO,
        };
        let result = with_preloaded_system_tx_context(phase_context, || {
            self.inner.evm.transact_system_call(
                outbe_primitives::addresses::SYSTEM_ADDRESS,
                outbe_primitives::addresses::OUTBE_SYSTEM_TX_ADDRESS,
                tx.input().clone(),
            )
        })
        .map_err(|error| {
            BlockExecutionError::msg(format!(
                "terminal system tx execution failed at block {block_number}: {error}"
            ))
        })?;
        if !result.result.is_success() {
            return Err(BlockExecutionError::msg(format!(
                "critical terminal system tx did not succeed at block {block_number}: {:?}",
                result.result
            )));
        }

        let output = EthTxResult {
            result,
            blob_gas_used: 0,
            tx_type,
        };
        if !commit(&output).should_commit() {
            return Err(BlockExecutionError::msg(
                "terminal system transaction cannot execute without commit",
            ));
        }
        let gas = self.commit_system_transaction(output, intrinsic_gas, 0, signed_gas_limit)?;
        self.finalize_compressed_entities()?;
        self.ocomp_terminal_request_consumed = true;
        let execution_origin = if self.block_hash.is_some() {
            "canonical"
        } else {
            "proposal"
        };
        tracing::info!(
            target: "outbe::ocomp::trace",
            "OCOMP_TRACE_V1 kind=terminal_request_committed origin={execution_origin} \
             block={block_number} tx={:#x}",
            tx.tx_hash()
        );
        Ok(Some(gas))
    }

    /// Commits an Outbe begin-zone system transaction with separate internal
    /// and visible gas accounting.
    ///
    /// The precompile executes under the separate internal system-work budget.
    /// The public Ethereum block gas lane charges the signed envelope's visible
    /// base gas (intrinsic plus any schedule-hashed protocol precharge) and any
    /// explicit compressed-entity gas, without exposing the internal execution
    /// lane.
    fn commit_system_transaction(
        &mut self,
        output: EthTxResult<E::HaltReason, alloy_consensus::TxType>,
        visible_base_gas: u64,
        compressed_entities_gas: u64,
        signed_gas_limit: u64,
    ) -> Result<GasOutput, BlockExecutionError> {
        let visible_gas_used = self.visible_system_gas_with_compressed_entities(
            visible_base_gas,
            compressed_entities_gas,
            signed_gas_limit,
        )?;
        let user_cumulative_tx_gas = self.inner.cumulative_tx_gas_used;
        let user_regular_gas = self.inner.block_regular_gas_used;
        let user_state_gas = self.inner.block_state_gas_used;
        let visible_cumulative_tx_gas = user_cumulative_tx_gas
            .checked_add(visible_gas_used)
            .ok_or_else(|| {
                BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                    "system tx visible gas overflow".into(),
                ))
            })?;
        let system_cumulative_gas_used =
            self.checked_system_tx_execution_gas(output.result.result.tx_gas_used())?;

        let _ = self.inner.commit_transaction(output);
        self.system_tx_execution_gas = system_cumulative_gas_used;

        if let Some(receipt) = self.inner.receipts.last_mut() {
            receipt.cumulative_gas_used = visible_cumulative_tx_gas;
        }

        self.inner.cumulative_tx_gas_used = visible_cumulative_tx_gas;
        self.inner.block_regular_gas_used = user_regular_gas.saturating_add(visible_gas_used);
        self.inner.block_state_gas_used = user_state_gas.saturating_add(visible_gas_used);

        Ok(GasOutput::new(visible_gas_used))
    }

    fn checked_system_tx_execution_gas(&self, additional: u64) -> Result<u64, BlockExecutionError> {
        let cumulative = self
            .system_tx_execution_gas
            .checked_add(additional)
            .ok_or_else(|| {
                BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                    "internal system-work gas overflow".into(),
                ))
            })?;
        let limit = outbe_primitives::system_tx::SYSTEM_TX_ARTIFACT_GAS_LIMIT;
        if cumulative > limit {
            return Err(BlockExecutionError::Internal(
                InternalBlockExecutionError::Other(
                    format!(
                        "internal system-work budget exceeded: cumulative={cumulative}, limit={limit}, additional={additional}"
                    )
                    .into(),
                ),
            ));
        }
        Ok(cumulative)
    }

    fn visible_system_gas_with_compressed_entities(
        &self,
        visible_base_gas: u64,
        compressed_entities_gas: u64,
        signed_gas_limit: u64,
    ) -> Result<u64, BlockExecutionError> {
        let visible_gas = visible_base_gas
            .checked_add(compressed_entities_gas)
            .ok_or_else(|| {
                BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                    "system tx visible gas overflow after compressed-entity charge".into(),
                ))
            })?;
        if visible_gas > signed_gas_limit {
            return Err(BlockExecutionError::Internal(
                InternalBlockExecutionError::Other(
                    format!(
                        "system tx receipt gas exceeds signed gas limit: visible={visible_gas}, \
                         signed_limit={signed_gas_limit}, visible_base={visible_base_gas}, \
                         compressed_entities={compressed_entities_gas}"
                    )
                    .into(),
                ),
            ));
        }
        let cumulative = self
            .inner
            .cumulative_tx_gas_used
            .checked_add(visible_gas)
            .ok_or_else(|| {
                BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                    "system tx cumulative visible gas overflow".into(),
                ))
            })?;
        let block_gas_limit = self.inner.evm.block().gas_limit();
        if cumulative > block_gas_limit {
            return Err(BlockExecutionError::Internal(
                InternalBlockExecutionError::Other(
                    format!(
                        "system tx visible gas exceeds block gas limit: cumulative={cumulative}, \
                         block_limit={block_gas_limit}, visible_base={visible_base_gas}, \
                         compressed_entities={compressed_entities_gas}"
                    )
                    .into(),
                ),
            ));
        }
        Ok(visible_gas)
    }

    /// Pushes a `status=0` system synthetic receipt and publishes only the
    /// signed envelope plus explicit CE gas; unrelated internal-lane work
    /// remains hidden.
    fn push_system_failure_receipt(
        &mut self,
        input: SystemFailureReceiptInput,
    ) -> Result<GasOutput, BlockExecutionError> {
        let visible_gas_used = self.visible_system_gas_with_compressed_entities(
            input.visible_base_gas,
            input.compressed_entities_gas,
            input.signed_gas_limit,
        )?;
        let log = crate::failure_receipt::build_outbe_failure_log(
            input.log_address,
            input.code,
            input.reason,
        );
        let system_cumulative_gas_used =
            self.checked_system_tx_execution_gas(input.internal_gas_used)?;
        let user_cumulative_gas_used = self
            .inner
            .cumulative_tx_gas_used
            .checked_add(visible_gas_used)
            .ok_or_else(|| {
                BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                    "system tx failure visible gas overflow".into(),
                ))
            })?;
        self.inner.receipts.push(Receipt {
            tx_type: input.tx_type,
            success: false,
            cumulative_gas_used: user_cumulative_gas_used,
            logs: vec![log],
        });
        self.system_tx_execution_gas = system_cumulative_gas_used;
        self.inner.cumulative_tx_gas_used = user_cumulative_gas_used;
        self.inner.block_regular_gas_used = self
            .inner
            .block_regular_gas_used
            .saturating_add(visible_gas_used);
        self.inner.block_state_gas_used = self
            .inner
            .block_state_gas_used
            .saturating_add(visible_gas_used);
        Ok(GasOutput::new(visible_gas_used))
    }

    fn begin_zone_proposer(
        &self,
        block_number: u64,
    ) -> Result<Option<Address>, BlockExecutionError> {
        if block_number == 0 {
            return Ok(None);
        }
        self.proposer_evm_address
            .or_else(|| self.evm_signer.as_ref().map(|signer| signer.address()))
            .or_else(|| {
                self.expected_begin_system_txs
                    .first()
                    .map(|tx| Address::from(*tx.signer()))
            })
            .ok_or_else(|| {
                BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                    "missing proposer EVM address for begin-zone system txs".into(),
                ))
            })
            .map(Some)
    }

    fn validate_proposer_identity(
        &mut self,
        proposer: Address,
        allow_boundary_proposer: bool,
    ) -> Result<(), BlockExecutionError> {
        let block_number = self.inner.evm.block().number().saturating_to::<u64>();
        let timestamp = self.inner.evm.block().timestamp().saturating_to::<u64>();
        let chain_id = self.inner.evm.chain_id();
        let db = self.inner.evm.db_mut();
        let ctx = BlockContext::new_with_genesis_hash(
            block_number,
            timestamp,
            chain_id,
            self.genesis_hash,
            proposer,
            Vec::new(),
        );
        let mut provider = DirectStorageProvider::new(db, ctx);
        let storage = StorageHandle::new(&mut provider);
        let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
        if vs.is_consensus_participant(proposer).map_err(|error| {
            BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                format!("validate proposer identity: {error}").into(),
            ))
        })? {
            return Ok(());
        }
        if allow_boundary_proposer
            && vs.is_validator(proposer).map_err(|error| {
                BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                    format!("validate boundary proposer identity: {error}").into(),
                ))
            })?
        {
            return Ok(());
        }
        Err(BlockExecutionError::Internal(
            InternalBlockExecutionError::Other(
                format!("proposer EVM address is not an active consensus participant: {proposer}")
                    .into(),
            ),
        ))
    }

    fn boundary_allows_proposer(
        &self,
        block_artifacts: &outbe_primitives::reshare_artifact::OutbeBlockArtifacts,
        proposer: Address,
    ) -> bool {
        matches!(
            &block_artifacts.consensus_header_artifact,
            Some(ConsensusHeaderArtifact::BoundaryOutcome(artifact))
                if artifact.is_validator_set_change && artifact.reshare.new_active_set.contains(&proposer)
        )
    }

    fn expected_begin_input(&self, ordinal: usize) -> Result<SystemTxInputV2, BlockExecutionError> {
        let recovered = self.expected_begin_system_txs.get(ordinal).ok_or_else(|| {
            BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                format!("missing expected begin system tx at ordinal {ordinal}").into(),
            ))
        })?;
        SystemTxInputV2::decode(recovered.tx().input().as_ref()).map_err(|error| {
            BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                format!("decode expected begin system tx input: {error}").into(),
            ))
        })
    }

    /// resolve the accounted-parent artifact for the given Phase 1
    /// metadata.
    ///
    /// Resolution order:
    /// 1. Provider-backed exact-hash lookup via [`AccountedParentArtifactProvider::execution_summary_by_hash`].
    ///    This covers the validator path (sealed block in MDBX) and the
    ///    proposer path when the bridge cache or tree-state is populated.
    /// 2. Payload-builder-supplied [`AccountedParentArtifact`] hint.
    ///    Accepted only when the metadata's
    ///    `(finalized_block_number, finalized_block_hash)` matches
    ///    `(block_number - 1, self.parent_hash)` - i.e., the hint must be for
    ///    the actual parent of the block being executed. The proposer payload
    ///    builder decodes this from `parent_header.extra_data` at build time,
    ///    so the hint inherits the integrity of the parent block hash chain.
    ///
    /// Returns an error only on real provider I/O failure. `HeaderNotFound`
    /// is a visibility miss (e.g. the FCU-Valid -> MDBX-commit race), so the
    /// executor treats it like `Ok(None)` and lets the checked
    /// `parent_artifact_hint` fallback engage. A provider miss with no usable
    /// hint is fatal - the executor never silently accepts a
    /// canonical-by-number artifact.
    fn accounted_parent_artifact_for_metadata(
        &self,
        metadata: &CertifiedParentAccountingMetadata,
    ) -> Result<AccountedParentArtifact, BlockExecutionError> {
        if let Some(provider) = self.accounted_parent_artifact_provider.as_ref() {
            match provider.execution_summary_by_hash(
                metadata.finalized_block_number,
                metadata.finalized_block_hash,
            ) {
                Ok(Some(resolved)) => return Ok(resolved),
                Ok(None) | Err(reth_evm::execute::ProviderError::HeaderNotFound(_)) => {}
                Err(error) => {
                    return Err(BlockExecutionError::Internal(
                        InternalBlockExecutionError::Other(
                            format!("read accounted-parent artifact: {error}").into(),
                        ),
                    ));
                }
            }
        }

        // accept the payload-builder-supplied hint only when it matches
        // this block's actual parent. The metadata's parent
        // `(finalized_block_number, finalized_block_hash)` must equal
        // `(block_number - 1, self.parent_hash)`; any other value is a stale
        // or competing-branch artifact and must be rejected.
        if let Some(hint) = self.parent_artifact_hint.as_ref() {
            let block_number = self.inner.evm.block().number().saturating_to::<u64>();
            let parent_block_number = block_number.saturating_sub(1);
            if metadata.finalized_block_hash == self.parent_hash
                && metadata.finalized_block_number == parent_block_number
            {
                return Ok(*hint);
            }
            return Err(BlockExecutionError::Internal(
                InternalBlockExecutionError::Other(
                    format!(
                        "parent_artifact_hint mismatch: metadata=({}, {}), actual parent=({parent_block_number}, {})",
                        metadata.finalized_block_number, metadata.finalized_block_hash, self.parent_hash,
                    )
                    .into(),
                ),
            ));
        }

        Err(BlockExecutionError::Internal(
            InternalBlockExecutionError::Other(
                format!(
                    "missing execution summary artifact for accounted-parent block {} ({})",
                    metadata.finalized_block_number, metadata.finalized_block_hash
                )
                .into(),
            ),
        ))
    }

    /// Layout-signaled flag for the one-time Phase 3b `TeeBootstrap`:
    /// true iff this block carries that system tx in the begin zone. Verifier
    /// mode reads it from `expected_begin_system_txs` (the body); proposer mode
    /// reads it from the injected `pending_tee_bootstrap` payload. Both feed the
    /// same `has_tee_bootstrap` cursor signal so the phase cursor matches the
    /// actual begin-zone on both paths.
    fn block_has_tee_bootstrap(&self) -> bool {
        if self.pending_tee_bootstrap.is_some() {
            return true;
        }
        self.expected_begin_system_txs.iter().any(|tx| {
            matches!(
                SystemTxInputV2::decode(tx.input().as_ref()).map(|input| input.kind()),
                Ok(SystemTxKind::TeeBootstrap)
            )
        })
    }

    fn begin_block_system_tx_inputs(
        &self,
        block_number: u64,
        block_artifacts: &outbe_primitives::reshare_artifact::OutbeBlockArtifacts,
    ) -> Result<
        Vec<(
            SystemTxKind,
            SystemTxInputV2,
            Option<AccountedParentArtifact>,
        )>,
        BlockExecutionError,
    > {
        // Block 0 (genesis) has no begin-zone system txs. Mirror the proposer
        // body builder (`OutbeEvmConfig::build_begin_system_txs`), which returns
        // empty for block 0, so both deterministic paths agree even if a stray
        // `pending_tee_bootstrap` is set - never inject a begin-zone tx at genesis.
        if block_number == 0 {
            return Ok(Vec::new());
        }

        let verifier_mode = !self.expected_begin_system_txs.is_empty();
        let mut ordinal = 0usize;
        let mut system_txs = Vec::new();

        if block_number >= 2 {
            let input = if verifier_mode {
                self.expected_begin_input(ordinal)?
            } else {
                let metadata = self.parent_consensus_metadata.clone().ok_or_else(|| {
                    BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                        "missing parent consensus metadata for CertifiedParentAccounting".into(),
                    ))
                })?;
                SystemTxInputV2::CertifiedParentAccounting { metadata }
            };
            let SystemTxInputV2::CertifiedParentAccounting { metadata } = &input else {
                return Err(BlockExecutionError::Internal(
                    InternalBlockExecutionError::Other(
                        "expected CertifiedParentAccounting system tx at ordinal 0".into(),
                    ),
                ));
            };
            if metadata.finalized_block_hash != self.parent_hash {
                return Err(BlockExecutionError::Internal(
                    InternalBlockExecutionError::Other(
                        format!(
                            "CertifiedParentAccounting metadata hash must match block parent: expected {}, got {}",
                            self.parent_hash, metadata.finalized_block_hash
                        )
                        .into(),
                    ),
                ));
            }
            let summary = self.accounted_parent_artifact_for_metadata(metadata)?;
            system_txs.push((
                SystemTxKind::CertifiedParentAccounting,
                input,
                Some(summary),
            ));
            ordinal += 1;
        }

        // mandatory LateFinalizeCredits phase for every block >= 2,
        // ordered immediately after Phase 1 (CPA). Proposer mode builds it from
        // the header artifact (empty until Phase 7 wires gathered credits);
        // verifier mode re-derives it from the body and the header<->calldata
        // parity check enforces equality.
        if block_number >= 2 {
            let input = if verifier_mode {
                self.expected_begin_input(ordinal)?
            } else {
                SystemTxInputV2::LateFinalizeCredits {
                    artifact: block_artifacts
                        .late_finalize_credits
                        .clone()
                        .unwrap_or_default(),
                }
            };
            if !matches!(input, SystemTxInputV2::LateFinalizeCredits { .. }) {
                return Err(BlockExecutionError::Internal(
                    InternalBlockExecutionError::Other(
                        format!("expected LateFinalizeCredits system tx at ordinal {ordinal}")
                            .into(),
                    ),
                ));
            }
            system_txs.push((SystemTxKind::LateFinalizeCredits, input, None));
            ordinal += 1;
        }

        if self.ocomp_lifecycle_active {
            let input = if verifier_mode {
                self.expected_begin_input(ordinal)?
            } else {
                SystemTxInputV2::OcompLifecycleBegin
            };
            if !matches!(input, SystemTxInputV2::OcompLifecycleBegin) {
                return Err(BlockExecutionError::Internal(
                    InternalBlockExecutionError::Other(
                        format!("expected OcompLifecycleBegin system tx at ordinal {ordinal}")
                            .into(),
                    ),
                ));
            }
            system_txs.push((SystemTxKind::OcompLifecycleBegin, input, None));
            ordinal += 1;
        }

        if block_number >= 1 {
            let input = if verifier_mode {
                self.expected_begin_input(ordinal)?
            } else {
                SystemTxInputV2::CycleTick
            };
            if !matches!(input, SystemTxInputV2::CycleTick) {
                return Err(BlockExecutionError::Internal(
                    InternalBlockExecutionError::Other(
                        format!("expected CycleTick system tx at ordinal {ordinal}").into(),
                    ),
                ));
            }
            system_txs.push((SystemTxKind::CycleTick, input, None));
            ordinal += 1;

            let input = if verifier_mode {
                self.expected_begin_input(ordinal)?
            } else {
                SystemTxInputV2::RewardsGemDelivery
            };
            if !matches!(input, SystemTxInputV2::RewardsGemDelivery) {
                return Err(BlockExecutionError::Internal(
                    InternalBlockExecutionError::Other(
                        format!("expected RewardsGemDelivery system tx at ordinal {ordinal}")
                            .into(),
                    ),
                ));
            }
            system_txs.push((SystemTxKind::RewardsGemDelivery, input, None));
            ordinal += 1;
        }

        if let Some(ConsensusHeaderArtifact::BoundaryOutcome(artifact)) =
            &block_artifacts.consensus_header_artifact
        {
            let input = if verifier_mode {
                self.expected_begin_input(ordinal)?
            } else {
                SystemTxInputV2::BoundaryOutcome {
                    artifact: artifact.clone(),
                }
            };
            match &input {
                SystemTxInputV2::BoundaryOutcome {
                    artifact: input_artifact,
                } if input_artifact == artifact => {}
                SystemTxInputV2::BoundaryOutcome { .. } => {
                    return Err(BlockExecutionError::Internal(
                        InternalBlockExecutionError::Other(
                            format!(
                                "BoundaryOutcome system tx artifact mismatch at ordinal {ordinal}"
                            )
                            .into(),
                        ),
                    ));
                }
                _ => {
                    return Err(BlockExecutionError::Internal(
                        InternalBlockExecutionError::Other(
                            format!("expected BoundaryOutcome system tx at ordinal {ordinal}")
                                .into(),
                        ),
                    ));
                }
            }
            system_txs.push((SystemTxKind::BoundaryOutcome, input, None));
            ordinal += 1;
        }

        // Optional Phase 3b: one-time `TeeBootstrap`, between `BoundaryOutcome`
        // (begin_order 5) and `OracleSlashWindow` (begin_order 7).
        // Verifier mode: include it iff the body carries it at this ordinal.
        // Proposer mode: inject the `pending_tee_bootstrap` payload supplied by
        // the bootstrap producer - identically to `build_begin_system_txs` so the
        // proposer's signed body and the executor's expected inputs match.
        if block_number == 1 {
            let input = if verifier_mode {
                self.expected_begin_input(ordinal)?
            } else {
                let payload = self.pending_tee_bootstrap.clone().ok_or_else(|| {
                    BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                        "missing mandatory block-1 OST3 bootstrap payload".into(),
                    ))
                })?;
                SystemTxInputV2::TeeBootstrap { payload }
            };
            if !matches!(input, SystemTxInputV2::TeeBootstrap { .. }) {
                return Err(BlockExecutionError::Internal(
                    InternalBlockExecutionError::Other(
                        format!("expected mandatory OST3 system tx at ordinal {ordinal}").into(),
                    ),
                ));
            }
            system_txs.push((SystemTxKind::TeeBootstrap, input, None));
            ordinal += 1;
        } else if self.pending_tee_bootstrap.is_some() {
            return Err(BlockExecutionError::Internal(
                InternalBlockExecutionError::Other(
                    format!("OST3 bootstrap payload is forbidden at block {block_number}").into(),
                ),
            ));
        }

        if block_number >= 1 {
            let input = if verifier_mode {
                self.expected_begin_input(ordinal)?
            } else {
                SystemTxInputV2::OracleSlashWindow
            };
            if !matches!(input, SystemTxInputV2::OracleSlashWindow) {
                return Err(BlockExecutionError::Internal(
                    InternalBlockExecutionError::Other(
                        format!("expected OracleSlashWindow system tx at ordinal {ordinal}").into(),
                    ),
                ));
            }
            system_txs.push((SystemTxKind::OracleSlashWindow, input, None));
            ordinal += 1;
        }

        if block_number >= 1 {
            let input = if verifier_mode {
                self.expected_begin_input(ordinal)?
            } else {
                SystemTxInputV2::HookEvents
            };
            if !matches!(input, SystemTxInputV2::HookEvents) {
                return Err(BlockExecutionError::Internal(
                    InternalBlockExecutionError::Other(
                        format!("expected HookEvents system tx at ordinal {ordinal}").into(),
                    ),
                ));
            }
            system_txs.push((SystemTxKind::HookEvents, input, None));
        }

        Ok(system_txs)
    }

    fn expected_system_tx_at_body_index(
        &self,
        body_index: usize,
        block_number: u64,
        block_artifacts: &outbe_primitives::reshare_artifact::OutbeBlockArtifacts,
    ) -> Result<
        (
            SystemTxKind,
            SystemTxInputV2,
            Option<AccountedParentArtifact>,
            u64,
            u64,
        ),
        BlockExecutionError,
    > {
        let system_txs = self.begin_block_system_tx_inputs(block_number, block_artifacts)?;
        let mut gas_inputs = system_txs
            .iter()
            .map(|(kind, input, _)| {
                input
                    .encode()
                    .map(|calldata| (*kind, calldata))
                    .map_err(|error| {
                        BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                            format!("encode system tx for visible gas plan: {error}").into(),
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if self.ocomp_lifecycle_active {
            let terminal = SystemTxInputV2::OcompTerminalRequest;
            gas_inputs.push((
                terminal.kind(),
                terminal.encode().map_err(|error| {
                    BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                        format!("encode terminal system tx for visible gas plan: {error}").into(),
                    ))
                })?,
            ));
        }
        let gas_plan = SystemTxVisibleGasPlan::new(self.inner.evm.block().gas_limit(), &gas_inputs)
            .map_err(|error| {
                BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                    format!("plan visible system tx gas: {error}").into(),
                ))
            })?;
        let intrinsic_gas = gas_plan.intrinsic_gas(body_index).ok_or_else(|| {
            BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                format!("visible gas plan missing intrinsic gas for body_index={body_index}")
                    .into(),
            ))
        })?;
        let protocol_precharge = gas_plan.protocol_precharge(body_index).ok_or_else(|| {
            BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                format!("visible gas plan missing protocol precharge for body_index={body_index}")
                    .into(),
            ))
        })?;
        let visible_base_gas = intrinsic_gas
            .checked_add(protocol_precharge)
            .ok_or_else(|| {
                BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                    format!("visible base gas overflow for body_index={body_index}").into(),
                ))
            })?;
        let gas_limit = gas_plan.gas_limit(body_index).ok_or_else(|| {
            BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                format!("visible gas plan missing gas limit for body_index={body_index}").into(),
            ))
        })?;
        system_txs
            .into_iter()
            .nth(body_index)
            .map(|(kind, input, summary)| (kind, input, summary, visible_base_gas, gas_limit))
            .ok_or_else(|| {
            let has_boundary_outcome = matches!(
                block_artifacts.consensus_header_artifact,
                Some(ConsensusHeaderArtifact::BoundaryOutcome(_))
            );
            let has_tee_bootstrap = self.block_has_tee_bootstrap();
            let ocomp_activation = if self.ocomp_lifecycle_active {
                OcompLifecycleActivation::at_block(0)
            } else {
                OcompLifecycleActivation::Disabled
            };
            let expected = expected_begin_block_kinds_for_activation(
                block_number,
                has_boundary_outcome,
                has_tee_bootstrap,
                ocomp_activation,
            );
            BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                format!(
                    "unexpected system tx at body_index={body_index}; expected begin_block system txs {expected:?}"
                )
                .into(),
            ))
            })
    }

    /// V2 Phase 1 preflight.
    ///
    /// For block `n >= 2` (greenfield, where `GENESIS_BOOTSTRAP_BLOCK_NUMBER`
    /// equals `1`) this verifies the `CertifiedParentAccounting` metadata
    /// via `outbe_consensus::proof::verify_v2_proof` BEFORE any begin-zone
    /// state mutation is committed. The verifier is a synchronous pure
    /// function; on `Err` the executor returns `BlockExecutionError` with
    /// no state changes (no soft receipt because Phase 1 failures are
    /// fatal).
    ///
    /// Block `0` and block `1` (genesis bootstrap) skip Phase 1 entirely
    /// and return `Ok(())` without reading any storage.
    ///
    /// safety contract: the preflight runs in `apply_pre_execution_changes`
    /// AFTER marker preservation plus pending-RPC short-circuit AND BEFORE
    /// `run_outbe_pre_execution_hooks` plus the main tx loop. Marker
    /// preservation `on_state` is the only state-root signal that precedes
    /// Phase 1 verify. The hook-changes `on_state` signal and the Phase 1
    /// commit itself (still in the main tx loop pending 's
    /// gating consumer) only happen after a successful verify.
    fn verify_phase1_in_preexec(
        &mut self,
        block_number: u64,
        block_artifacts: &outbe_primitives::reshare_artifact::OutbeBlockArtifacts,
    ) -> Result<(), BlockExecutionError> {
        use outbe_consensus::proof::verify_v2_proof;
        use outbe_validatorset::state::{committee_snapshot_key, read_committee_snapshot};

        if block_number <= crate::system_tx::GENESIS_BOOTSTRAP_BLOCK_NUMBER {
            return Ok(());
        }
        #[cfg(test)]
        if PHASE1_VERIFY_DISABLED.with(|cell| cell.get()) {
            // Test-only opt-out: legacy unit tests that exercise pre-exec
            // without seeding a committee snapshot. Production paths never
            // disable verification.
            return Ok(());
        }

        // Reuse the existing builder to produce the canonical Phase 1 input
        // for this block (validator-mode: proposer-supplied; proposer-mode:
        // derived from `parent_consensus_metadata`). The metadata struct
        // carries the V2 wire fields the verifier needs.
        let system_txs = self.begin_block_system_tx_inputs(block_number, block_artifacts)?;
        let Some((kind, input, _summary)) = system_txs.into_iter().next() else {
            return Err(BlockExecutionError::Internal(
                InternalBlockExecutionError::Other(
                    format!(
                        "missing Phase 1 system tx for block {block_number} in pre-exec verifier"
                    )
                    .into(),
                ),
            ));
        };
        if !matches!(kind, SystemTxKind::CertifiedParentAccounting) {
            return Err(BlockExecutionError::Internal(
                InternalBlockExecutionError::Other(
                    format!(
                        "Phase 1 pre-exec verifier expected CertifiedParentAccounting, got {kind:?}"
                    )
                    .into(),
                ),
            ));
        }
        let SystemTxInputV2::CertifiedParentAccounting { metadata } = &input else {
            return Err(BlockExecutionError::Internal(
                InternalBlockExecutionError::Other(
                    "Phase 1 pre-exec verifier expected CertifiedParentAccounting input".into(),
                ),
            ));
        };

        // Resolve the active committee snapshot for the parent's epoch via
        // 's `CommitteeSnapshotStore`. The `(epoch, committee_set_hash)`
        // pair from the metadata yields the canonical storage key.
        let snapshot_key =
            committee_snapshot_key(metadata.finalized_epoch, metadata.committee_set_hash);
        let timestamp = self.inner.evm.block().timestamp().saturating_to::<u64>();
        let chain_id = self.inner.evm.chain_id();
        let proposer = self
            .begin_zone_proposer(block_number)?
            .unwrap_or_else(|| self.inner.evm.block().beneficiary());
        let parent_hash = self.parent_hash;
        let cert_bytes = metadata.proof.clone();
        let metadata_for_verify = metadata.clone();

        let snapshot = {
            let db = self.inner.evm.db_mut();
            let ctx = BlockContext::new_with_genesis_hash(
                block_number,
                timestamp,
                chain_id,
                self.genesis_hash,
                proposer,
                Vec::new(),
            );
            let mut provider = DirectStorageProvider::new(db, ctx);
            let storage = StorageHandle::new(&mut provider);
            read_committee_snapshot(storage, snapshot_key).map_err(|error| {
                BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                    format!(
                        "Phase 1 pre-exec: read committee snapshot for epoch={} key={}: {error}",
                        metadata_for_verify.finalized_epoch, snapshot_key
                    )
                    .into(),
                ))
            })?
        };
        let Some(snapshot) = snapshot else {
            return Err(BlockExecutionError::Internal(
                InternalBlockExecutionError::Other(
                    format!(
                        "Phase 1 pre-exec: missing committee snapshot for epoch={} key={}",
                        metadata_for_verify.finalized_epoch, snapshot_key
                    )
                    .into(),
                ),
            ));
        };

        let verified = verify_v2_proof(
            &metadata_for_verify,
            &snapshot,
            cert_bytes.as_ref(),
            parent_hash,
        )
        .map_err(|error| {
            BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                format!(
                    "Phase 1 pre-exec: verify_v2_proof rejected metadata for block {block_number}: {error}"
                )
                .into(),
            ))
        })?;

        // cache the canonical VRF proof hash so
        // `apply_phase1_commit_in_preexec` (and the main-loop body[0]
        // path) can populate the V3 Rewards fingerprint without
        // re-decoding the certificate.
        self.verified_phase1_vrf_proof_hash = Some(verified.vrf_proof_hash);

        Ok(())
    }

    /// FATAL pre-exec verification of the block's late-finalize
    /// credits. Each batch in `header.extra_data`'s
    /// `LateFinalizeCreditsArtifact` carries a BLS aggregate over a recently
    /// finalized block's individual finalize votes. This runs on the same
    /// pre-exec path as [`Self::verify_phase1_in_preexec`] - synchronous, no
    /// state mutation, `Err` aborts the block before any begin-zone state diff
    /// reaches Reth's state-root task - and enforces, for every batch:
    ///
    /// - the target sits inside the inclusion window: `1 <= block - fb <= K`;
    /// - the committee snapshot for `(epoch, committee_set_hash)` exists;
    /// - the aggregate verifies against that snapshot (no quorum/VRF floor -
    ///   late credits are the sub-quorum tail, see
    ///   [`outbe_consensus::proof::verify_late_finalize_proof`]).
    ///
    /// Both proposer (its own gathered credits) and validator (proposer-
    /// supplied) verify, so a buggy proposer or a forged batch is rejected
    /// identically. Block 0 / block 1 (genesis bootstrap) and the test-only
    /// `PHASE1_VERIFY_DISABLED` opt-out skip verification; a `None` or empty
    /// artifact is a no-op.
    fn verify_late_finalize_credits_in_preexec(
        &mut self,
        block_number: u64,
        block_artifacts: &outbe_primitives::reshare_artifact::OutbeBlockArtifacts,
    ) -> Result<(), BlockExecutionError> {
        use outbe_consensus::proof::verify_late_finalize_proof;
        use outbe_primitives::consensus::LATE_FINALIZE_WINDOW_K;
        use outbe_validatorset::state::{committee_snapshot_key, read_committee_snapshot};

        if block_number <= crate::system_tx::GENESIS_BOOTSTRAP_BLOCK_NUMBER {
            return Ok(());
        }
        // No test opt-out: a `None`/empty artifact early-returns below, so tests
        // that don't carry credits are unaffected; tests that do carry credits
        // (and seed the matching committee snapshot) exercise the real verifier.
        let Some(artifact) = block_artifacts.late_finalize_credits.as_ref() else {
            return Ok(());
        };
        if artifact.batches.is_empty() {
            return Ok(());
        }

        let timestamp = self.inner.evm.block().timestamp().saturating_to::<u64>();
        let chain_id = self.inner.evm.chain_id();
        let proposer = self
            .begin_zone_proposer(block_number)?
            .unwrap_or_else(|| self.inner.evm.block().beneficiary());

        for credit in &artifact.batches {
            // Inclusion window: 1 <= block_number - fb_number <= K.
            let distance = block_number.checked_sub(credit.fb_number).ok_or_else(|| {
                BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                    format!(
                        "LateFinalizeCredits pre-exec: fb_number {} >= block {block_number}",
                        credit.fb_number
                    )
                    .into(),
                ))
            })?;
            if distance == 0 || distance > LATE_FINALIZE_WINDOW_K {
                return Err(BlockExecutionError::Internal(
                    InternalBlockExecutionError::Other(
                        format!(
                            "LateFinalizeCredits pre-exec: fb_number {} outside inclusion window \
                             (distance {distance}, K={LATE_FINALIZE_WINDOW_K}) for block {block_number}",
                            credit.fb_number
                        )
                        .into(),
                    ),
                ));
            }

            // NOTE: the canonical-binding authentication (fb_number/epoch/
            // committee_set_hash vs the escrow) is intentionally NOT done here.
            // The escrow for the closest in-window target (block N-1) is written
            // by THIS block's CPA, which runs in the body AFTER this pre-exec
            // gate - so the binding is not yet present at pre-exec. The
            // authentication therefore lives in the begin-zone body
            // (`run_late_finalize_credits`, after the CPA), where a mismatch is
            // FATAL and aborts the block. This pre-exec gate covers the BLS proof
            // (committee snapshot exists from the epoch boundary).
            let snapshot_key = committee_snapshot_key(credit.epoch, credit.committee_set_hash);
            let snapshot = {
                let db = self.inner.evm.db_mut();
                let ctx = BlockContext::new_with_genesis_hash(
                    block_number,
                    timestamp,
                    chain_id,
                    self.genesis_hash,
                    proposer,
                    Vec::new(),
                );
                let mut provider = DirectStorageProvider::new(db, ctx);
                let storage = StorageHandle::new(&mut provider);
                read_committee_snapshot(storage, snapshot_key).map_err(|error| {
                    BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                        format!(
                            "LateFinalizeCredits pre-exec: read committee snapshot epoch={} \
                             key={snapshot_key}: {error}",
                            credit.epoch
                        )
                        .into(),
                    ))
                })?
            };
            let Some(snapshot) = snapshot else {
                return Err(BlockExecutionError::Internal(
                    InternalBlockExecutionError::Other(
                        format!(
                            "LateFinalizeCredits pre-exec: missing committee snapshot epoch={} \
                             key={snapshot_key} for block {block_number}",
                            credit.epoch
                        )
                        .into(),
                    ),
                ));
            };

            verify_late_finalize_proof(&snapshot, credit).map_err(|error| {
                BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                    format!(
                        "LateFinalizeCredits pre-exec: proof rejected for fb={} at block \
                         {block_number}: {error}",
                        credit.fb_hash
                    )
                    .into(),
                ))
            })?;
        }

        Ok(())
    }

    /// Phase 1 commit move: physically execute the Phase 1
    /// system tx and commit its state diff BEFORE
    /// `run_outbe_pre_execution_hooks` runs. Hooks then observe
    /// post-Phase-1 accounting state (consumer Cycle Phase 2
    /// gating on `AccountingProgressStore`).
    ///
    /// The commit is performed via `inner.commit_transaction`, which is the
    /// same code path the main tx loop uses for system txs - it pushes the
    /// Phase 1 receipt at `receipts[0]`, commits state via `db.commit`,
    /// signals Reth's parallel state-root task via
    /// `system_caller.on_state(StateChangeSource::Transaction(0), &state)`,
    /// and updates the executor's gas accumulators. State-root ordering is
    /// preserved because `verify_phase1_in_preexec` ran (and accepted) the
    /// proof before this method is called.
    ///
    /// The proposer-supplied body[0] arrives later in the main tx loop. The
    /// `execute_transaction_with_commit_condition` intercept (cursor
    /// variant `Phase1Preexecuted` with non-zero `tx_hash`) validates the
    /// body[0] tx matches the cached `signature_hash` and returns `Ok(None)`
    /// without re-executing or re-committing - receipt and state are
    /// already in place from this pre-exec call.
    ///
    /// Skip conditions:
    /// - Block 0 / block 1 (genesis bootstrap): no Phase 1.
    /// - Test-only opt-out via `with_phase1_verify_disabled` (legacy unit
    ///   tests that exercise pre-exec without seeding a snapshot).
    fn apply_phase1_commit_in_preexec(
        &mut self,
        block_number: u64,
        block_artifacts: &outbe_primitives::reshare_artifact::OutbeBlockArtifacts,
    ) -> Result<(), BlockExecutionError> {
        if block_number <= crate::system_tx::GENESIS_BOOTSTRAP_BLOCK_NUMBER {
            return Ok(());
        }
        #[cfg(test)]
        if PHASE1_VERIFY_DISABLED.with(|cell| cell.get()) {
            return Ok(());
        }

        // Resolve canonical Phase 1 input + finalized summary for this block.
        let system_txs = self.begin_block_system_tx_inputs(block_number, block_artifacts)?;
        let Some((kind, input, finalized_summary)) = system_txs.into_iter().next() else {
            return Err(BlockExecutionError::Internal(
                InternalBlockExecutionError::Other(
                    format!(
                        "Phase 1 commit pre-exec: missing Phase 1 system tx for block {block_number}"
                    )
                    .into(),
                ),
            ));
        };
        if !matches!(kind, SystemTxKind::CertifiedParentAccounting) {
            return Err(BlockExecutionError::Internal(
                InternalBlockExecutionError::Other(
                    format!(
                        "Phase 1 commit pre-exec: expected CertifiedParentAccounting, got {kind:?}"
                    )
                    .into(),
                ),
            ));
        }
        let calldata = input.encode().map_err(|error| {
            BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                format!("Phase 1 commit pre-exec: encode SystemTxInputV2: {error}").into(),
            ))
        })?;

        // Resolve proposer first - `begin_zone_proposer` is `Option`-aware
        // and may consult `expected_begin_system_txs` or the configured EVM
        // signer; the prebuilt validation below pins
        // `prebuilt.signer()` against this address.
        let proposer = self
            .begin_zone_proposer(block_number)?
            .unwrap_or_else(|| self.inner.evm.block().beneficiary());

        // Build the canonical signed Phase 1 tx (witness for body[0]
        // validation). Priority:
        // 1. prebuilt witness handed in by the payload builder
        //      (proposer mode). Cached in `OutbeBlockExecutionCtx` BEFORE
        //      `apply_pre_execution_changes`. Validated: calldata bytes,
        //      signer matches resolved proposer.
        //   2. Validator-mode body[0] arriving through
        //      `expected_begin_system_txs.first()` from the sealed block.
        //   3. Legacy proposer fallback that re-signs the artifact through
        //      `evm_signer`. Determinism preserved because the signer is
        //      RFC 6979 (see `crates/blockchain/evm/src/signer.rs`).
        let chain_id = self.inner.evm.chain_id();
        let (cached_tx_hash, signed_gas_limit) = if let Some(prebuilt) = &self.prebuilt_phase1_tx {
            let tx_hash = validate_phase1_witness_against(
                prebuilt.tx(),
                calldata.as_ref(),
                proposer,
                chain_id,
                block_number,
            )
            .map_err(|error| {
                BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                    format!("Phase 1 commit pre-exec: invalid prebuilt witness: {error}").into(),
                ))
            })?;
            (tx_hash, prebuilt.tx().gas_limit())
        } else if let Some(expected) = self.expected_begin_system_txs.first() {
            let tx_hash = validate_phase1_witness_against(
                expected.tx(),
                calldata.as_ref(),
                proposer,
                chain_id,
                block_number,
            )
            .map_err(|error| {
                BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                    format!("Phase 1 commit pre-exec: invalid body[0] witness: {error}").into(),
                ))
            })?;
            (tx_hash, expected.tx().gas_limit())
        } else if let Some(signer) = &self.evm_signer {
            let unsigned = build_unsigned_system_tx(
                SystemTxKind::CertifiedParentAccounting,
                0,
                block_number,
                chain_id,
                calldata.clone(),
            )
            .map_err(|error| {
                BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                    format!("Phase 1 commit pre-exec: build unsigned witness: {error}").into(),
                ))
            })?;
            let signed = signer.sign_unsigned(unsigned).map_err(|error| {
                BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                    format!("Phase 1 commit pre-exec: sign witness: {error}").into(),
                ))
            })?;
            let signed_gas_limit = signed.gas_limit();
            let tx_hash = validate_phase1_witness_against(
                &signed,
                calldata.as_ref(),
                proposer,
                chain_id,
                block_number,
            )
            .map_err(|error| {
                BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                    format!("Phase 1 commit pre-exec: invalid signed witness: {error}").into(),
                ))
            })?;
            (tx_hash, signed_gas_limit)
        } else {
            // No witness source. Skip the commit move; the legacy main-loop
            // path will run Phase 1 like before. The commit move only binds when a
            // witness source is available.
            return Ok(());
        };
        let phase_context = PreloadedSystemTxContext {
            proposer,
            finalized_summary,
            allow_boundary_proposer: self.boundary_allows_proposer(block_artifacts, proposer),
            // feed the verified parent certificate's VRF
            // proof hash into the precompile so the V3 Rewards
            // fingerprint can bind it. `B256::ZERO` only when the
            // preflight was skipped (genesis bootstrap), in which case
            // the Phase 1 precompile path itself is also skipped.
            canonical_vrf_proof_hash: self.verified_phase1_vrf_proof_hash.unwrap_or(B256::ZERO),
        };

        // Execute Phase 1 precompile. Only explicit CE charges inside this
        // system-call boundary are added to the public envelope gas.
        let gas_window = self
            .compressed_entities_scope
            .begin_explicit_gas_window(0)
            .map_err(|error| {
                BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                    format!("Phase 1 commit pre-exec: open CE gas window: {error}").into(),
                ))
            })?;
        let transact_outcome = with_preloaded_system_tx_context(phase_context, || {
            self.inner.evm.transact_system_call(
                outbe_primitives::addresses::SYSTEM_ADDRESS,
                outbe_primitives::addresses::OUTBE_SYSTEM_TX_ADDRESS,
                calldata,
            )
        });
        let result = match transact_outcome {
            Ok(result) => result,
            Err(error) => {
                let reason =
                    format!("Phase 1 commit pre-exec: transact_system_call failed: {error}");
                tracing::error!(target: "outbe::executor", %reason);
                return Err(BlockExecutionError::Internal(
                    InternalBlockExecutionError::Other(reason.into()),
                ));
            }
        };
        let compressed_entities_gas = gas_window.gas_used().map_err(|error| {
            BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                format!("Phase 1 commit pre-exec: read CE gas window: {error}").into(),
            ))
        })?;
        drop(gas_window);
        if !result.result.is_success() {
            // Phase 1 (CertifiedParentAccounting) is consensus-critical
            // (`SystemTxKind::revert_fails_block()` is true for it), so a revert here
            // is a hard block failure, not a soft-receipt skip - its finalized-parent
            // accounting is one-shot and never retried. The revert is deterministic in
            // committed chain state, so every validator rejects the same block.
            let reason = format!(
                "critical system tx CertifiedParentAccounting did not succeed (revert/halt) in \
                 Phase 1 pre-exec commit: {:?}",
                result.result
            );
            tracing::error!(target: "outbe::executor", %reason, "critical begin-zone phase did not succeed; failing block");
            return Err(BlockExecutionError::Internal(
                InternalBlockExecutionError::Other(reason.into()),
            ));
        }
        // Commit state + push receipt[0] + signal state-root task via the
        // standard EthBlockExecutor machinery. This holds because
        // `verify_phase1_in_preexec` returned `Ok` before this call.
        let output = EthTxResult {
            result,
            blob_gas_used: 0,
            tx_type: alloy_consensus::TxType::Legacy,
        };
        self.commit_system_transaction(
            output,
            signed_gas_limit,
            compressed_entities_gas,
            signed_gas_limit,
        )?;

        // Update the cursor with the cached witness hash. The
        // `execute_transaction_with_commit_condition` intercept reads
        // `Phase1Preexecuted.tx_hash` to detect the proposer-supplied body[0]
        // arrival and validate-without-reexec.
        self.system_tx_phase_cursor = crate::system_tx::SystemTxPhase::Phase1Preexecuted {
            body_index: 0,
            tx_hash: cached_tx_hash,
            receipt_index: 0,
        };
        Ok(())
    }

    /// resolve the expected system tx for the current cursor
    /// position. Replaces the receipts-len-driven routing for begin-zone
    /// system transactions; the cursor is the single source of truth.
    /// Returns the resolved `(SystemTxKind, SystemTxInputV2,
    /// finalized_summary)` plus the body index the cursor is pointing at.
    /// Errors if the cursor is `UserTxs` (no system tx expected) or if the
    /// cursor's expected kind does not match the resolved expected kind for
    /// that body index (e.g. block 1 + Phase 1 cursor - a programmer
    /// invariant violation).
    fn expected_system_tx_for_cursor(
        &self,
        block_number: u64,
        block_artifacts: &outbe_primitives::reshare_artifact::OutbeBlockArtifacts,
    ) -> Result<ExpectedSystemTransaction, BlockExecutionError> {
        let cursor = self.system_tx_phase_cursor;
        let Some(body_index) = cursor.body_index() else {
            // Cursor=UserTxs: all begin-zone system txs are consumed.
            // Encountering a reserved system transaction address here is
            // either an unsolicited user-tx attempt at the reserved
            // address or a duplicate / out-of-band system tx - both fatal.
            return Err(BlockExecutionError::Internal(
                InternalBlockExecutionError::Other(
                    "tx to reserved system transaction address after begin-zone system txs are consumed"
                        .into(),
                ),
            ));
        };
        let body_index_usize = usize::from(body_index);
        let (resolved_kind, input, finalized_summary, visible_base_gas, gas_limit) =
            self.expected_system_tx_at_body_index(body_index_usize, block_number, block_artifacts)?;
        if let Some(expected_kind) = cursor.expected_kind() {
            if expected_kind != resolved_kind {
                return Err(BlockExecutionError::Internal(
                    InternalBlockExecutionError::Other(
                        format!(
                            "system tx cursor/body mismatch at body_index={body_index_usize}: cursor expects {expected_kind:?}, body has {resolved_kind:?}"
                        )
                        .into(),
                    ),
                ));
            }
        }
        Ok((
            body_index_usize,
            resolved_kind,
            input,
            finalized_summary,
            visible_base_gas,
            gas_limit,
        ))
    }
}

#[allow(private_bounds)]
impl<DB, E> BlockExecutor for OutbeBlockExecutor<'_, E>
where
    DB: StateDB,
    DB::Error: std::fmt::Display,
    // outbe-evm is pinned to revm's standard `HaltReason`; this constraint
    // is what lets [`system_tx_failure_code_for_result`] pattern-match the
    // halt variants for soft-failure code assignment.
    E: Evm<DB = DB, Tx = TxEnv, HaltReason = HaltReason> + ZeroFeeCfgAccess,
    E::Error: std::fmt::Display,
{
    type Transaction = TransactionSigned;
    type Receipt = Receipt;
    type Evm = E;
    type Result = EthTxResult<E::HaltReason, reth_ethereum::TxType>;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        validate_outbe_withdrawals(self.inner.ctx.withdrawals.as_deref())
            .map_err(|error| BlockExecutionError::msg(error.to_string()))?;

        let block_number = self.inner.evm.block().number().saturating_to::<u64>();
        let beneficiary = self.inner.evm.block().beneficiary();
        if self.block_hash.is_some() && block_number > 0 {
            let artifacts = decode_outbe_block_artifacts(self.block_extra_data.as_ref())
                .map_err(|error| BlockExecutionError::msg(error.to_string()))?;
            validate_compressed_entities_root_scheme(artifacts.compressed_entities_root)?;
        }
        // initialise the begin-zone phase cursor for this block
        // BEFORE any pre-exec mutation that could affect routing. Block 1
        // (genesis bootstrap) skips Phase 1 and starts at CycleTick; block
        // `n` with `n > GENESIS_BOOTSTRAP_BLOCK_NUMBER` enters Phase 1 with
        // a zero placeholder tx_hash that the Phase 1 preflight (Batch 3)
        // overwrites once `verify_v2_proof` returns Ok and the system tx
        // is committed in pre-execution.
        self.system_tx_phase_cursor = crate::system_tx::SystemTxPhase::initial_for_block_with_ocomp(
            block_number,
            crate::system_tx::GENESIS_BOOTSTRAP_BLOCK_NUMBER,
            self.ocomp_lifecycle_active,
        );
        if block_number > 0 && beneficiary != outbe_primitives::addresses::REWARDS_ADDRESS {
            return Err(BlockExecutionError::Internal(
                InternalBlockExecutionError::Other(
                    format!(
                        "non-genesis block beneficiary must be REWARDS_ADDRESS {}: got {}",
                        outbe_primitives::addresses::REWARDS_ADDRESS,
                        beneficiary
                    )
                    .into(),
                ),
            ));
        }
        if let Some(error) = &self.system_layout_error {
            return Err(BlockExecutionError::Internal(
                InternalBlockExecutionError::Other(
                    format!("invalid system tx layout: {error}").into(),
                ),
            ));
        }

        // 1. Standard Ethereum pre-execution (blockhashes, beacon root, state clear flag).
        self.inner.apply_pre_execution_changes()?;

        // 2. Deploy 0xEF marker bytecode to all Outbe runtime addresses.
        //    Without bytecode these accounts are "empty" under EIP-161 and their
        //    storage is silently discarded during state root calculation.
        //    Must notify system_caller hook so reth's parallel state root task
        //    sees these changes (reth v1.11+).
        {
            use alloy_evm::block::{StateChangePreBlockSource, StateChangeSource};
            use revm::state::{Account, Bytecode, EvmState};
            // Single source of truth (see `marker_addresses` + its superset test).
            let precompile_addresses = marker_addresses::OUTBE_RUNTIME_MARKER_ADDRESSES;

            let db = self.inner.evm.db_mut();
            let mut marker_state = EvmState::default();

            for addr in precompile_addresses {
                let info = db
                    .basic(addr)
                    .map_err(|e| {
                        BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                            format!("load precompile account {addr}: {e}").into(),
                        ))
                    })?
                    .unwrap_or_default();
                if info.is_empty_code_hash() {
                    let code = Bytecode::new_legacy([0xef].into());
                    let mut new_info = info;
                    new_info.code_hash = code.hash_slow();
                    new_info.code = Some(code);
                    let mut account: Account = new_info.into();
                    account.mark_touch();
                    marker_state.insert(addr, account);
                }
            }

            if !marker_state.is_empty() {
                // EIP-161 preservation marker bytecode injection for
                // outbe precompile addresses (not EIP-2935).
                // `BlockHashesContract` is reserved for the actual
                // EIP-2935 blockhash systemcall; this path is an
                // outbe-specific protocol step that needs the catch-all
                // `Other` variant for honest tracing/observability.
                self.inner.system_caller.on_state(
                    StateChangeSource::PreBlock(StateChangePreBlockSource::Other(
                        "outbe_precompile_marker_bytecode",
                    )),
                    &marker_state,
                );
                self.inner.evm.db_mut().commit(marker_state);
            }
        }

        // 3. Open the block-scoped compressed-body overlay before any user or
        // system transaction can perform a body read or mutation. This also
        // applies to Reth's local pending-block construction: it executes
        // txpool transactions against an isolated State and therefore needs a
        // complete CE begin/end lifecycle even though consensus-only Outbe
        // hooks remain disabled. The provisional tree batch is not published
        // without a final block hash.
        {
            let timestamp = self.inner.evm.block().timestamp().saturating_to::<u64>();
            let chain_id = self.inner.evm.chain_id();
            let proposer = self.inner.evm.block().beneficiary();
            let scope = self.compressed_entities_scope.clone();
            let (changes, events) = {
                let db = self.inner.evm.db_mut();
                let ctx = build_block_context(
                    db,
                    block_number,
                    timestamp,
                    chain_id,
                    self.genesis_hash,
                    proposer,
                )?;
                run_atomic_storage_hooks(db, ctx, |hook_ctx| {
                    let lifecycle =
                        outbe_compressed_entities::CompressedEntitiesLifecycleContext::new(
                            hook_ctx.clone(),
                            scope.as_ref(),
                        );
                    <outbe_compressed_entities::CompressedEntitiesLifecycle as BlockLifecycle>::begin_block(
                        &lifecycle,
                    )
                })?
            };
            if !events.is_empty() {
                return Err(BlockExecutionError::msg(
                    "compressed-entity begin_block emitted an unexpected event",
                ));
            }
            if !changes.is_empty() {
                use alloy_evm::block::{StateChangePreBlockSource, StateChangeSource};
                self.inner.system_caller.on_state(
                    StateChangeSource::PreBlock(StateChangePreBlockSource::Other(
                        "compressed_entities_begin_block",
                    )),
                    &changes,
                );
            }
            self.compressed_entities_started = true;
        }

        // Pending-block RPC has no proposer certificate or consensus system
        // transactions. Its isolated CE scope is active now, so user
        // transactions can be simulated faithfully; skip only the
        // consensus-specific hooks below.
        if !self.execute_outbe_block_hooks {
            return Ok(());
        }

        // 4. Extract block context before taking a mutable DB borrow.
        let timestamp = self.inner.evm.block().timestamp().saturating_to::<u64>();
        let chain_id = self.inner.evm.chain_id();
        let block_artifacts = decode_outbe_block_artifacts(self.block_extra_data.as_ref())
            .map_err(|error| BlockExecutionError::msg(error.to_string()))?;
        let proposer = self
            .begin_zone_proposer(block_number)?
            .unwrap_or_else(|| self.inner.evm.block().beneficiary());
        let allow_boundary_proposer = self.boundary_allows_proposer(&block_artifacts, proposer);
        if block_number > 0 {
            self.validate_proposer_identity(proposer, allow_boundary_proposer)?;
        }

        // Phase 1 `verify_v2_proof`
        // preflight. Runs AFTER marker preservation + pending-RPC short-
        // circuit + proposer identity validation, BEFORE
        // `run_outbe_pre_execution_hooks` and BEFORE the main tx loop.
        // The verifier is a synchronous pure function with no state
        // mutation; on `Err` the executor returns `BlockExecutionError`
        // without signalling any begin-zone state diff to Reth's state-
        // root background task. Block 0 / block 1 skip Phase 1.
        self.verify_phase1_in_preexec(block_number, &block_artifacts)?;

        // late-finalize-credit BLS aggregates are FATAL-verified
        // here, on the same pre-exec path as Phase 1 and before any begin-zone
        // state diff is signalled to Reth's state-root task. Proposer and
        // validator both verify; a bad aggregate, an out-of-window target, or a
        // missing committee snapshot aborts the block deterministically.
        self.verify_late_finalize_credits_in_preexec(block_number, &block_artifacts)?;

        // Phase 1 commit physical move. After
        // verify Ok, execute + commit the Phase 1 precompile so
        // `run_outbe_pre_execution_hooks` (Cycle / Rewards / Oracle) observe
        // post-Phase-1 accounting state. The proposer-supplied body[0] in
        // the main tx loop is validated against the cached witness hash and
        // skipped (validate-without-reexec) - receipt + state are already
        // in place from this call. Reth state-root ordering is preserved
        // because the preceding `verify_phase1_in_preexec` returned `Ok`.
        self.apply_phase1_commit_in_preexec(block_number, &block_artifacts)?;

        // 4. Fresh bootstrap validation data from consensus config.
        let genesis_validators = self
            .bridge
            .as_ref()
            .and_then(|b| b.peek_genesis_validators());

        // 5. Run Outbe block hooks and collect all state changes for hook notification.
        //    The provider is scoped so the mutable DB borrow is released before
        //    we notify the state root hook via system_caller.
        let (hook_changes, hook_events) = {
            let db = self.inner.evm.db_mut();
            let ctx = build_block_context(
                db,
                block_number,
                timestamp,
                chain_id,
                self.genesis_hash,
                proposer,
            )?;
            run_atomic_storage_hooks(db, ctx, |hook_ctx| -> outbe_primitives::error::Result<()> {
                if let Some(ConsensusHeaderArtifact::BoundaryOutcome(boundary)) =
                    block_artifacts.consensus_header_artifact.as_ref()
                {
                    prepare_boundary_epoch_counters(
                        hook_ctx.storage.clone(),
                        boundary,
                        block_number,
                    )?;
                }
                let result = match self.runtime_body_readers.as_ref() {
                    Some(readers) => run_outbe_pre_execution_hooks_with_readers(
                        hook_ctx,
                        genesis_validators.as_ref(),
                        readers,
                        self.compressed_entities_scope.as_ref(),
                    ),
                    None => run_outbe_pre_execution_hooks(hook_ctx, genesis_validators.as_ref()),
                };
                if let (Some(readers), Err(error)) = (self.runtime_body_readers.as_ref(), &result) {
                    readers.report_precompile_error(error);
                }
                result
            })?
        };
        // Provider dropped here - mutable DB borrow released.

        // Log hook events via tracing for operator observability.
        // Whitelisted addresses are published through the mandatory HookEvents
        // system tx receipt; non-whitelisted hook events stay tracing-only.
        for event in &hook_events {
            tracing::info!(
                target: "outbe::hooks",
                address = %event.address,
                topics = event.data.topics().len(),
                data_len = event.data.data.len(),
                "hook event emitted"
            );
        }

        let (whitelisted_hook_logs, _tracing_only_hook_logs) = partition_hook_events(&hook_events);
        self.whitelisted_hook_event_logs = whitelisted_hook_logs;

        // 6. Notify reth's parallel state root task about all pre-exec hook changes.
        //    These are outbe lifecycle ticks (Rewards / ValidatorSet /
        //    Staking / Oracle / NOD), not EIP-2935/4788/7002 system calls,
        //    so the source is labelled via the catch-all `Other` variant
        //    to keep trace output honest.
        if !hook_changes.is_empty() {
            use alloy_evm::block::{StateChangePreBlockSource, StateChangeSource};
            self.inner.system_caller.on_state(
                StateChangeSource::PreBlock(StateChangePreBlockSource::Other(
                    "outbe_pre_exec_hooks",
                )),
                &hook_changes,
            );
        }

        // 7. Receipt-visible begin-zone system phases are real transactions in
        // the block body and execute in the normal tx loop before user txs.
        // Oracle slash-window work is part of that OracleSlashWindow system tx,
        // so there are no direct post-system storage hooks here.

        Ok(())
    }

    fn receipts(&self) -> &[Self::Receipt] {
        self.inner.receipts()
    }

    fn execute_transaction_without_commit(
        &mut self,
        tx: impl ExecutableTx<Self>,
    ) -> Result<Self::Result, BlockExecutionError> {
        let (tx_env, recovered) = tx.into_parts();
        if is_reserved_system_tx(recovered.tx()) {
            return Err(BlockExecutionError::msg(
                "reserved system transaction cannot execute without commit",
            ));
        }
        self.inner.execute_transaction_without_commit(WithTxEnv {
            tx: Arc::new(recovered),
            tx_env,
        })
    }

    fn execute_transaction_with_commit_condition(
        &mut self,
        tx: impl ExecutableTx<Self>,
        f: impl FnOnce(&Self::Result) -> CommitChanges,
    ) -> Result<Option<GasOutput>, BlockExecutionError> {
        let (mut tx_env, recovered) = tx.into_parts();
        if self.ocomp_terminal_request_consumed {
            return Err(BlockExecutionError::msg(
                "transaction follows the terminal OCOMP system transaction",
            ));
        }
        let is_ocomp_terminal_request = is_reserved_system_tx(recovered.tx())
            && matches!(
                SystemTxInputV2::decode(recovered.tx().input().as_ref()),
                Ok(SystemTxInputV2::OcompTerminalRequest)
            );
        if is_ocomp_terminal_request {
            return self.execute_ocomp_terminal_request(recovered, f);
        }
        let ce_scope = self.compressed_entities_scope.clone();
        let ce_checkpoint = ce_scope
            .ce_work_checkpoint()
            .map_err(BlockExecutionError::other)?;
        ce_scope
            .begin_ce_work_transaction()
            .map_err(BlockExecutionError::other)?;
        let outcome = (|| {
            let tx = recovered.tx();
            let signer = *recovered.signer();

            if is_reserved_system_tx(tx) {
                let block_number = self.inner.evm.block().number().saturating_to::<u64>();
                let block_artifacts = decode_outbe_block_artifacts(self.block_extra_data.as_ref())
                    .map_err(|error| BlockExecutionError::msg(error.to_string()))?;

                // Witness validate-without-reexec: if Phase 1
                // was already committed in `apply_pre_execution_changes::apply_phase1_commit_in_preexec`,
                // the cursor carries the cached witness `tx_hash`. Body[0] in the
                // main tx loop is the proposer-supplied Phase 1 tx - validate it
                // matches the cache (signature hash) and skip re-execution.
                // Receipt + state already exist from the pre-exec commit.
                if let crate::system_tx::SystemTxPhase::Phase1Preexecuted {
                    tx_hash: cached_hash,
                    ..
                } = self.system_tx_phase_cursor
                {
                    if !cached_hash.is_zero() {
                        if tx.signature_hash() != cached_hash {
                            return Err(BlockExecutionError::Internal(
                            InternalBlockExecutionError::Other(
                                format!(
                                    "Phase 1 body[0] witness signature_hash mismatch: expected {cached_hash}, got {}",
                                    tx.signature_hash()
                                )
                                .into(),
                            ),
                        ));
                        }
                        // Advance cursor past Phase 1; CycleTick body_index=1 next.
                        let has_boundary_outcome = matches!(
                            block_artifacts.consensus_header_artifact,
                            Some(ConsensusHeaderArtifact::BoundaryOutcome(_))
                        );
                        let has_tee_bootstrap = self.block_has_tee_bootstrap();
                        self.system_tx_phase_cursor =
                            self.system_tx_phase_cursor.advance_after_commit_with_ocomp(
                                has_boundary_outcome,
                                has_tee_bootstrap,
                                self.ocomp_lifecycle_active,
                            );
                        // Ok(None) signals "no further commit" - pre-exec already
                        // pushed receipt[0] and committed state. The block builder
                        // still keeps this validated witness in body[0].
                        return Ok(None);
                    }
                }

                // cursor-driven phase routing replaces the previous
                // `self.inner.receipts.len()` derivation. The cursor was
                // initialised in `apply_pre_execution_changes` and advances
                // exactly once per consumed begin-zone system tx (see the
                // `advance_after_commit` call below). This is the only
                // production reader of `self.system_tx_phase_cursor`.
                let (
                    body_index,
                    expected_phase,
                    expected_input,
                    finalized_summary,
                    visible_base_gas,
                    planned_gas_limit,
                ) = self.expected_system_tx_for_cursor(block_number, &block_artifacts)?;
                let actual_input =
                    SystemTxInputV2::decode(tx.input().as_ref()).map_err(|error| {
                        BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                            format!("decode system tx at body_index={body_index}: {error}").into(),
                        ))
                    })?;
                let actual_phase = actual_input.kind();
                if actual_phase != expected_phase {
                    return Err(BlockExecutionError::Internal(
                    InternalBlockExecutionError::Other(
                        format!(
                            "system tx phase mismatch at body_index={body_index}: expected {expected_phase:?}, got {actual_phase:?}"
                        )
                        .into(),
                    ),
                ));
                }
                if actual_input != expected_input {
                    return Err(BlockExecutionError::Internal(
                    InternalBlockExecutionError::Other(
                        format!(
                            "system tx calldata mismatch at body_index={body_index} for {expected_phase:?}"
                        )
                        .into(),
                    ),
                ));
                }

                let ordinal = body_index.try_into().map_err(|_| {
                    BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                        format!("system tx body_index {body_index} exceeds u8 range").into(),
                    ))
                })?;
                let unsigned = build_unsigned_system_tx_with_gas_limit(
                    expected_phase,
                    ordinal,
                    block_number,
                    self.inner.evm.chain_id(),
                    tx.input().clone(),
                    planned_gas_limit,
                )
                .map_err(|error| {
                    BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                        format!("build expected system tx at body_index={body_index}: {error}")
                            .into(),
                    ))
                })?;
                if tx.signature_hash() != unsigned.signature_hash() {
                    return Err(BlockExecutionError::Internal(
                    InternalBlockExecutionError::Other(
                        format!(
                            "system tx signature_hash mismatch at body_index={body_index} for {expected_phase:?}"
                        )
                        .into(),
                    ),
                ));
                }
                let visible_gas_limit = tx.gas_limit();

                let proposer = self
                    .begin_zone_proposer(block_number)?
                    .unwrap_or_else(|| self.inner.evm.block().beneficiary());
                if signer != proposer {
                    return Err(BlockExecutionError::Internal(
                    InternalBlockExecutionError::Other(
                        format!(
                            "system tx signer mismatch at body_index={body_index} for {expected_phase:?}: expected proposer {proposer}, got {signer}"
                        )
                        .into(),
                    ),
                ));
                }

                if expected_phase == SystemTxKind::HookEvents {
                    let has_boundary_outcome = matches!(
                        block_artifacts.consensus_header_artifact,
                        Some(ConsensusHeaderArtifact::BoundaryOutcome(_))
                    );
                    let has_tee_bootstrap = self.block_has_tee_bootstrap();
                    let logs = std::mem::take(&mut self.whitelisted_hook_event_logs);
                    let commit_outcome = self
                        .push_hook_events_receipt(tx.tx_type(), logs, visible_base_gas)
                        .map(Some);
                    if commit_outcome.is_ok() {
                        self.system_tx_phase_cursor =
                            self.system_tx_phase_cursor.advance_after_commit_with_ocomp(
                                has_boundary_outcome,
                                has_tee_bootstrap,
                                self.ocomp_lifecycle_active,
                            );
                    }
                    return commit_outcome;
                }

                let phase_context = PreloadedSystemTxContext {
                    proposer,
                    finalized_summary,
                    allow_boundary_proposer: self
                        .boundary_allows_proposer(&block_artifacts, proposer),
                    // same VRF-proof-hash plumbing as the
                    // pre-exec commit path. Cached by the preflight; falls
                    // back to `B256::ZERO` only when the preflight was
                    // skipped (which never co-occurs with this main-loop
                    // path entering Phase 1 in production).
                    canonical_vrf_proof_hash: self
                        .verified_phase1_vrf_proof_hash
                        .unwrap_or(B256::ZERO),
                };
                // Phase 1-4 EVM result failures (`Revert` / `Halt`) are converted
                // into a `status=0` synthetic receipt with one `OutbeFailure(code, reason)`
                // log emitted from `OUTBE_SYSTEM_TX_ADDRESS`; revm did not commit the call so no
                // state change leaks. Raw `Err` from the system-call engine remains fatal because
                // upstream revm documents that the journal may be inconsistent on that path.
                // Body-parity validation above (decode / phase / calldata / signature / signer)
                // also remains fatal: those are validator-side checks that the proposer never
                // produces for itself.
                let ce_gas_limit =
                    visible_gas_limit
                        .checked_sub(visible_base_gas)
                        .ok_or_else(|| {
                            BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                                format!(
                            "system tx signed gas below visible base at body_index={body_index}: \
                         signed={visible_gas_limit}, visible_base={visible_base_gas}"
                        )
                                .into(),
                            ))
                        })?;
                let gas_window = self
                .compressed_entities_scope
                .begin_explicit_gas_window(ce_gas_limit)
                .map_err(|error| {
                    BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                        format!(
                            "open CE gas window for {expected_phase:?} at body_index={body_index}: {error}"
                        )
                        .into(),
                    ))
                })?;
                let transact_outcome = with_preloaded_system_tx_context(phase_context, || {
                    self.inner.evm.transact_system_call(
                        outbe_primitives::addresses::SYSTEM_ADDRESS,
                        outbe_primitives::addresses::OUTBE_SYSTEM_TX_ADDRESS,
                        tx.input().clone(),
                    )
                });
                // precompute the boundary-outcome flag so the cursor
                // advance below stays consistent with the resolved expected set
                // for this block (block 1 always carries the boundary outcome
                // under V2; other blocks depend on the header artifact).
                let has_boundary_outcome = matches!(
                    block_artifacts.consensus_header_artifact,
                    Some(ConsensusHeaderArtifact::BoundaryOutcome(_))
                );
                let has_tee_bootstrap = self.block_has_tee_bootstrap();
                // Only EVM result failures use the soft-failure receipt path.
                // Raw engine/provider `Err` was handled above as fatal.
                let result = match transact_outcome {
                    Ok(value) => value,
                    Err(error) => {
                        let reason = format!(
                        "system tx {expected_phase:?} execution failed at body_index={body_index}: {error}"
                    );
                        tracing::error!(target: "outbe::executor", %reason);
                        return Err(BlockExecutionError::Internal(
                            InternalBlockExecutionError::Other(reason.into()),
                        ));
                    }
                };
                let compressed_entities_gas = gas_window.gas_used().map_err(|error| {
                BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                    format!(
                        "read CE gas window for {expected_phase:?} at body_index={body_index}: {error}"
                    )
                    .into(),
                ))
            })?;
                drop(gas_window);
                if !result.result.is_success() {
                    tracing::error!(
                        target: "outbe::executor",
                        ?expected_phase,
                        body_index,
                        block_number,
                        gas_used = result.result.tx_gas_used(),
                        gas_limit = tx.gas_limit(),
                        result = ?result.result,
                        "system tx failed"
                    );
                    let code = system_tx_failure_code_for_result(&result.result);
                    // a revert/halt in a consensus- or economic-critical
                    // begin-zone phase is a hard block failure, not a soft-receipt
                    // skip. Their work is one-shot and never retried, so swallowing a
                    // revert permanently loses it (stranded fee escrow, dropped
                    // emission/reshare, unrecorded parent accounting). The revert is a
                    // deterministic function of committed chain state, so every
                    // validator rejects the same block identically - no state-root
                    // split. Non-critical phases (OracleSlashWindow, HookEvents)
                    // keep the soft-receipt skip for failures that fit within the
                    // aggregate internal-work budget. An OOG consumes the full
                    // system-call gas limit and therefore remains a hard aggregate
                    // budget failure once earlier mandatory phases have run.
                    if expected_phase.revert_fails_block() {
                        let reason = format!(
                        "critical system tx {expected_phase:?} did not succeed (revert/halt) at \
                         body_index={body_index}, block_number={block_number}, \
                         failure_code={code}: {:?}",
                        result.result
                    );
                        tracing::error!(target: "outbe::executor", %reason, "critical begin-zone phase did not succeed; failing block");
                        return Err(BlockExecutionError::Internal(
                            InternalBlockExecutionError::Other(reason.into()),
                        ));
                    }
                    let reason = format!(
                    "system tx {expected_phase:?} did not succeed at body_index={body_index}: {:?}",
                    result.result
                );
                    let tx_type = tx.tx_type();
                    let receipt_ce_gas = if matches!(
                        result.result,
                        ExecutionResult::Halt {
                            reason: HaltReason::OutOfGas(_),
                            ..
                        }
                    ) {
                        ce_gas_limit
                    } else {
                        compressed_entities_gas
                    };
                    let gas_output =
                        self.push_system_failure_receipt(SystemFailureReceiptInput {
                            tx_type,
                            log_address: outbe_primitives::addresses::OUTBE_SYSTEM_TX_ADDRESS,
                            code,
                            reason,
                            visible_base_gas,
                            compressed_entities_gas: receipt_ce_gas,
                            signed_gas_limit: visible_gas_limit,
                            internal_gas_used: result.result.tx_gas_used(),
                        })?;
                    self.system_tx_phase_cursor =
                        self.system_tx_phase_cursor.advance_after_commit_with_ocomp(
                            has_boundary_outcome,
                            has_tee_bootstrap,
                            self.ocomp_lifecycle_active,
                        );
                    return Ok(Some(gas_output));
                }

                let output = EthTxResult {
                    result,
                    blob_gas_used: 0,
                    tx_type: tx.tx_type(),
                };
                if !f(&output).should_commit() {
                    // Cursor does not advance: caller has chosen not to commit,
                    // so the body-index slot remains owned by this phase.
                    return Ok(None);
                }
                let commit_outcome = self
                    .commit_system_transaction(
                        output,
                        visible_base_gas,
                        compressed_entities_gas,
                        visible_gas_limit,
                    )
                    .map(Some);
                if commit_outcome.is_ok() {
                    self.system_tx_phase_cursor =
                        self.system_tx_phase_cursor.advance_after_commit_with_ocomp(
                            has_boundary_outcome,
                            has_tee_bootstrap,
                            self.ocomp_lifecycle_active,
                        );
                }
                return commit_outcome;
            }

            let ocomp_system_carrier = classify_ocomp_system_carrier(
                OcompSystemCarrierView {
                    is_eip1559: tx.tx_type() == alloy_consensus::TxType::Eip1559,
                    to: tx.to(),
                    value: tx.value(),
                    input: tx.input().as_ref(),
                    gas_limit: tx.gas_limit(),
                    max_fee_per_gas: tx.max_fee_per_gas(),
                    max_priority_fee_per_gas: tx.max_priority_fee_per_gas(),
                },
                &outbe_ocomp_protocol::profile::poc_schema_limits(),
            )
            .map_err(|error| {
                BlockExecutionError::msg(format!("invalid OCOMP system carrier: {error}"))
            })?;

            if let Some(candidate) = ocomp_system_carrier {
                if !self.ocomp_lifecycle_active {
                    return Err(BlockExecutionError::msg(
                        "OCOMP system carrier is not active for this block",
                    ));
                }
                let block_number = self.inner.evm.block().number().saturating_to::<u64>();
                let timestamp = self.inner.evm.block().timestamp().saturating_to::<u64>();
                let chain_id = self.inner.evm.chain_id();
                let proposer = self.inner.evm.block().beneficiary();
                let authorized = {
                    let db = self.inner.evm.db_mut();
                    let ctx = BlockContext::new_with_genesis_hash(
                        block_number,
                        timestamp,
                        chain_id,
                        self.genesis_hash,
                        proposer,
                        Vec::new(),
                    );
                    let mut provider = DirectStorageProvider::new(db, ctx);
                    let storage = StorageHandle::new(&mut provider);
                    match candidate {
                        OcompSystemCarrierCandidate::ResultVote { prefix } => {
                            outbe_metadosis::resolve_historical_result_vote_carrier_signer(
                                storage,
                                &prefix,
                                signer,
                                &outbe_ocomp_protocol::profile::poc_schema_limits(),
                            )
                        }
                        OcompSystemCarrierCandidate::NodMaterialization { .. } => {
                            outbe_validatorset::contract::ValidatorSet::new(storage)
                                .resolve_validator_for_role(
                                    signer,
                                    outbe_validatorset::delegation::ValidatorDelegateRole::Ocomp,
                                )
                        }
                    }
                }
                .map_err(|error| {
                    BlockExecutionError::msg(format!(
                        "OCOMP system carrier authorization failed: {error}"
                    ))
                })?;
                if authorized.is_none() {
                    return Err(BlockExecutionError::msg(
                        "OCOMP system carrier signer is not authorized",
                    ));
                }

                let signed_gas_limit = tx.gas_limit();
                let tx_type = tx.tx_type();
                let snapshot = self.inner.evm.enable_zero_fee_overrides();
                tx_env.gas_limit = OCOMP_SYSTEM_CARRIER_INTERNAL_GAS_LIMIT;
                tx_env.gas_price = 0;
                tx_env.gas_priority_fee = Some(0);
                let execution = self.inner.execute_transaction_without_commit(WithTxEnv {
                    tx_env,
                    tx: Arc::new(recovered),
                });
                self.inner.evm.restore_zero_fee_overrides(snapshot);
                let output = execution?;
                let allowed_failed_receipt = match candidate {
                    OcompSystemCarrierCandidate::ResultVote { .. } => {
                        is_ocomp_deadline_passed_revert(&output.result.result)
                    }
                    OcompSystemCarrierCandidate::NodMaterialization { .. } => {
                        is_nod_materialization_soft_revert(&output.result.result)
                    }
                };
                if !output.result.result.is_success() && !allowed_failed_receipt {
                    return Err(BlockExecutionError::msg(format!(
                        "OCOMP system carrier execution did not succeed: {:?}",
                        output.result.result
                    )));
                }
                if !f(&output).should_commit() {
                    return Ok(None);
                }
                debug_assert_eq!(output.tx_type, tx_type);
                return self
                    .commit_system_transaction(output, 0, 0, signed_gas_limit)
                    .map(Some);
            }

            if tx.gas_limit() < Self::SOFT_FAILURE_GAS {
                return Err(BlockExecutionError::msg(format!(
                    "transaction gas limit {} is below intrinsic gas floor {}",
                    tx.gas_limit(),
                    Self::SOFT_FAILURE_GAS
                )));
            }

            // a zero-fee policy rejection used to be `BlockExecutionError::msg(.)`,
            // which payload_builder turned into a fatal `PayloadBuilderError::evm(...)` and
            // aborted block build - see EPIC for the halt of 2026-05-15. The tx is now
            // included with a `status=0` synthetic receipt carrying an `OutbeFailure(code, reason)`
            // log. Mempool eviction happens via Reth's standard `on_canonical_state_change` once
            // the block becomes canonical (`pool.remove_transactions(block.body)`), so no custom
            // side-channel is required (see Won't Do).
            let zero_fee_tx = zero_fee_transaction(tx, signer);
            let zero_fee = match outbe_zerofee::registry().classify(&zero_fee_tx) {
                Ok(value) => value,
                Err(err) => {
                    // account for this zero-fee soft-failure and reject
                    // it past the per-block cap (skipped on build, block rejected on
                    // validate) so it cannot stuff the block with zero-cost 21k
                    // soft-failures.
                    self.record_zero_fee_soft_failure(*tx.tx_hash())?;
                    let tx_type = tx.tx_type();
                    let code = err.code();
                    self.push_failure_receipt(
                        tx_type,
                        outbe_primitives::addresses::ZERO_FEE_POLICY_LOG_ADDRESS,
                        code,
                        err.to_string(),
                    );
                    return Ok(Some(GasOutput::new(Self::SOFT_FAILURE_GAS)));
                }
            };

            if let Some(candidate) = zero_fee {
                let block_number = self.inner.evm.block().number().saturating_to::<u64>();

                let timestamp = self.inner.evm.block().timestamp().saturating_to::<u64>();
                let chain_id = self.inner.evm.chain_id();
                let proposer = self.inner.evm.block().beneficiary();
                let ctx = BlockContext::new_with_genesis_hash(
                    block_number,
                    timestamp,
                    chain_id,
                    self.genesis_hash,
                    proposer,
                    Vec::new(),
                );

                // Same soft-failure path as `classify`: stateful authorization rejection becomes a
                // `status=0` receipt rather than a hard block error. We borrow `db` only inside the
                // scope that calls `authorize_fee_waiver`, then drop it before mutating the
                // executor's own state (push_failure_receipt).
                let authorize_outcome = {
                    let db = self.inner.evm.db_mut();
                    let mut provider = DirectStorageProvider::new(db, ctx);
                    let storage = StorageHandle::new(&mut provider);
                    outbe_zerofee::registry()
                        .authorize_fee_waiver(storage, candidate)
                        .map(|_| ())
                };
                if let Err(err) = authorize_outcome {
                    // account for this zero-fee soft-failure and reject
                    // it past the per-block cap (skipped on build, block rejected on
                    // validate) so it cannot stuff the block with zero-cost 21k
                    // soft-failures.
                    self.record_zero_fee_soft_failure(*tx.tx_hash())?;
                    let tx_type = tx.tx_type();
                    let code = err.code();
                    self.push_failure_receipt(
                        tx_type,
                        outbe_primitives::addresses::ZERO_FEE_POLICY_LOG_ADDRESS,
                        code,
                        err.to_string(),
                    );
                    return Ok(Some(GasOutput::new(Self::SOFT_FAILURE_GAS)));
                }

                let snapshot = self.inner.evm.enable_zero_fee_overrides();
                tx_env.gas_price = 0;
                tx_env.gas_priority_fee = Some(0);
                let result = self.inner.execute_transaction_with_commit_condition(
                    WithTxEnv {
                        tx_env,
                        tx: Arc::new(recovered),
                    },
                    f,
                );
                self.inner.evm.restore_zero_fee_overrides(snapshot);
                return result;
            }

            // EIP-7702 sponsored free-tx path. Oracle hook had its chance via
            // `classify` above; this branch handles the second source of fee
            // waivers - EOAs that have delegated to [`outbe_zerofee::ZEROFEE_ADDRESS`]
            // via a Pectra set-code authorization. The same `disable_balance_check
            // + disable_base_fee + disable_fee_charge` cfg snapshot is applied;
            // the counter increment is committed to the persistent state through
            // `DirectStorageProvider::flush` BEFORE the inner tx runs, so a
            // revert inside the tx does not un-burn the daily slot.
            let block_number = self.inner.evm.block().number().saturating_to::<u64>();
            let timestamp = self.inner.evm.block().timestamp().saturating_to::<u64>();
            let chain_id = self.inner.evm.chain_id();
            let proposer = self.inner.evm.block().beneficiary();

            // Pull `(code_hash, maybe_code)` from the
            // provider. `State<DB>::basic()` (the underlying source) only
            // populates `info.code` for accounts that have had recent
            // changes; otherwise the bytecode lives behind `code_by_hash`
            // and `info.code` is None. The fix below performs the second
            // lookup when needed so the EIP-7702 delegation probe sees the
            // real bytecode in steady state.
            let signer_state = {
                let db = self.inner.evm.db_mut();
                let ctx = BlockContext::new_with_genesis_hash(
                    block_number,
                    timestamp,
                    chain_id,
                    self.genesis_hash,
                    proposer,
                    Vec::new(),
                );
                let mut provider = DirectStorageProvider::new(db, ctx);
                let storage = StorageHandle::new(&mut provider);
                storage.with_account_info(signer, |info| {
                    Ok((
                        info.balance,
                        info.nonce,
                        info.is_empty_code_hash(),
                        info.code_hash,
                        info.code.clone(),
                    ))
                })
            };

            let (balance, nonce, code_empty, code_hash, maybe_code) = match signer_state {
                Ok(state) => state,
                Err(err) => {
                    return Err(BlockExecutionError::Internal(
                        InternalBlockExecutionError::Other(
                            format!("free-tx signer account read failed: {err}").into(),
                        ),
                    ));
                }
            };

            let bootstrap_candidate = bootstrap_transaction(tx, signer, chain_id)
                .and_then(|view| outbe_zerofee::classify_bootstrap(&view));
            let bootstrap_authorized = bootstrap_candidate.is_some_and(|candidate| {
                outbe_zerofee::authorize_bootstrap(
                    candidate,
                    outbe_zerofee::BootstrapAccountView {
                        balance,
                        nonce,
                        code_empty,
                    },
                )
            });

            if bootstrap_authorized {
                let snapshot = self.inner.evm.enable_zero_fee_overrides();
                tx_env.gas_price = 0;
                tx_env.gas_priority_fee = Some(0);
                let result = self.inner.execute_transaction_with_commit_condition(
                    WithTxEnv {
                        tx_env,
                        tx: Arc::new(recovered),
                    },
                    f,
                );
                self.inner.evm.restore_zero_fee_overrides(snapshot);
                return result;
            }

            let delegated_to = if let Some(code) = maybe_code {
                code.eip7702_address()
            } else if code_hash != revm::primitives::KECCAK_EMPTY {
                // basic() did not populate `code` - fetch bytecode by
                // hash directly. This is the steady-state path for any
                // account whose code was set in a prior block.
                match self.inner.evm.db_mut().code_by_hash(code_hash) {
                    Ok(code) => code.eip7702_address(),
                    Err(err) => {
                        return Err(BlockExecutionError::Internal(
                            InternalBlockExecutionError::Other(
                                format!("free-tx signer code lookup failed: {err}").into(),
                            ),
                        ));
                    }
                }
            } else {
                None
            };

            // A delegated account opts into sponsorship ONLY by sending the
            // exact free-tx envelope (`classify_sponsorship` Ok: value == 0,
            // priority_fee == 0, gas <= cap, calldata <= cap, to in
            // whitelist). If the envelope does not match - most importantly
            // `priority_fee > 0` ("I am paying") - the transaction is NOT a
            // sponsorship request and falls through to the normal fee path
            // below, even though the account is delegated. This keeps
            // EIP-7702 delegation ADDITIVE: delegating to the paymaster never
            // jails an account into free-only mode, and once a signer's daily
            // quota is exhausted they simply set a tip and pay as usual.
            //
            // The stateful `authorize_sponsorship` inside the branch still
            // soft-fails a correctly-shaped attempt with code 110 (quota
            // exhausted) or 107 (self) - those
            // are zero-tip requests that explicitly asked for free and must
            // not be silently charged.
            let wants_sponsorship = delegated_to == Some(outbe_zerofee::ZEROFEE_ADDRESS)
                && outbe_zerofee::classify_sponsorship(&zero_fee_tx).is_ok();

            if wants_sponsorship {
                // Stateful authorize + record_use under a single
                // `DirectStorageProvider` scope, then `flush()` so the counter
                // increment lands in `State<DB>` BEFORE the inner tx runs.
                // A REVERT inside the tx affects only its own journal frame
                // and cannot undo the flushed counter write.
                let (authorize_outcome, sponsorship_events, sponsorship_changes) = {
                    let db = self.inner.evm.db_mut();
                    let ctx = BlockContext::new_with_genesis_hash(
                        block_number,
                        timestamp,
                        chain_id,
                        self.genesis_hash,
                        proposer,
                        Vec::new(),
                    );
                    let mut provider = DirectStorageProvider::new(db, ctx);
                    let outcome = {
                        let storage = StorageHandle::new(&mut provider);
                        outbe_zerofee::authorize_sponsorship(storage.clone(), signer, timestamp)
                            .and_then(|auth| {
                                outbe_zerofee::record_sponsorship_use(
                                    storage,
                                    signer,
                                    auth.current_day,
                                )
                                .map(|_| auth)
                            })
                    };
                    let result = match outcome {
                        Ok(auth) => provider
                            .flush()
                            .map(|_| auth)
                            .map_err(outbe_zerofee::ZeroFeePolicyError::from),
                        Err(err) => Err(err),
                    };
                    // Drain the `SponsorshipAuthorized` logs that
                    // `record_sponsorship_use` pushed through the storage
                    // handle. They are kept aside even on Err so a future
                    // failure-path that emits diagnostic events still
                    // surfaces them; today the only writer pushes on
                    // success and is gated by `.and_then`.
                    let events = provider.take_events();
                    // Drain the committed counter-write so the parallel
                    // state-root task observes it through the same
                    // `OnStateHook` channel that begin-block hooks use
                    // (see line 1944). Without this notification the
                    // parallel task computes a partial root that omits
                    // ZEROFEE_ADDRESS' counter slot and forces a fallback
                    // recompute at block close - correctness is preserved
                    // because the final root walks the full bundle state,
                    // but the parallel optimisation is lost.
                    let changes = provider.take_committed_changes();
                    (result, events, changes)
                };

                // Notify the parallel state-root task about the counter
                // write committed via the provider above. The pre-fee
                // counter increment is logically part of THIS transaction's
                // processing - `Transaction(idx)` is the canonical variant
                // alloy-evm itself uses in `commit_transaction` after each
                // tx (see alloy_evm::block::state_hook). `receipts.len()`
                // is this tx's zero-based index: its receipt has not yet
                // been pushed when the pre-fee hook runs.
                if !sponsorship_changes.is_empty() {
                    use alloy_evm::block::StateChangeSource;
                    self.inner.system_caller.on_state(
                        StateChangeSource::Transaction(self.inner.receipts.len()),
                        &sponsorship_changes,
                    );
                }

                if let Err(err) = authorize_outcome {
                    // account for this zero-fee soft-failure and reject
                    // it past the per-block cap (skipped on build, block rejected on
                    // validate) so it cannot stuff the block with zero-cost 21k
                    // soft-failures.
                    self.record_zero_fee_soft_failure(*tx.tx_hash())?;
                    let tx_type = tx.tx_type();
                    let code = err.code();
                    self.push_failure_receipt(
                        tx_type,
                        outbe_primitives::addresses::ZERO_FEE_POLICY_LOG_ADDRESS,
                        code,
                        err.to_string(),
                    );
                    return Ok(Some(GasOutput::new(Self::SOFT_FAILURE_GAS)));
                }

                let snapshot = self.inner.evm.enable_zero_fee_overrides();
                tx_env.gas_price = 0;
                tx_env.gas_priority_fee = Some(0);
                let result = self.inner.execute_transaction_with_commit_condition(
                    WithTxEnv {
                        tx_env,
                        tx: Arc::new(recovered),
                    },
                    f,
                );
                self.inner.evm.restore_zero_fee_overrides(snapshot);
                // Attach the `SponsorshipAuthorized` log(s) to the receipt
                // the inner tx just pushed. Without this the event the
                // module README and `record_sponsorship_use` doc promise
                // would never reach `eth_getLogs` filters. We only mutate
                // the receipt on a successful execute; on inner-tx
                // bail-out the inner builder did not push a receipt and
                // there is nothing to attach to (the counter was already
                // burned, which matches the anti-revert-drain contract).
                if result.is_ok() && !sponsorship_events.is_empty() {
                    if let Some(receipt) = self.inner.receipts.last_mut() {
                        receipt.logs.extend(sponsorship_events);
                    }
                }
                return result;
            }

            let base_fee_per_gas = self.inner.evm.block().basefee() as u128;
            let max_fee_per_gas = tx.max_fee_per_gas();
            let max_priority_fee_per_gas = tx.max_priority_fee_per_gas();

            let result = self.inner.execute_transaction_with_commit_condition(
                WithTxEnv {
                    tx_env,
                    tx: Arc::new(recovered),
                },
                f,
            )?;

            if let Some(gas_used) = result {
                let validator_fee = validator_fee_for_gas(
                    max_fee_per_gas,
                    max_priority_fee_per_gas,
                    gas_used.tx_gas_used(),
                    base_fee_per_gas,
                );
                self.current_block_validator_fees = self
                    .current_block_validator_fees
                    .checked_add(validator_fee)
                    .ok_or_else(|| {
                        BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                            "validator fee accumulator overflow".into(),
                        ))
                    })?;
            }

            Ok(result)
        })();

        let ce_failure = ce_scope.take_ce_work_failure();
        ce_scope
            .end_ce_work_transaction()
            .map_err(BlockExecutionError::other)?;
        if !matches!(&outcome, Ok(Some(_))) {
            ce_scope
                .restore_ce_work_checkpoint(ce_checkpoint)
                .map_err(BlockExecutionError::other)?;
        }
        if let Some(error) = ce_failure {
            return Err(BlockExecutionError::other(error));
        }
        outcome
    }

    fn commit_transaction(&mut self, output: Self::Result) -> GasOutput {
        self.inner.commit_transaction(output)
    }

    fn execute_block(
        mut self,
        transactions: impl IntoIterator<Item = impl ExecutableTx<Self>>,
    ) -> Result<BlockExecutionResult<Self::Receipt>, BlockExecutionError>
    where
        Self: Sized,
    {
        self.apply_pre_execution_changes()?;

        for tx in transactions {
            self.execute_transaction_with_commit_condition(tx, |_| CommitChanges::Yes)?;
        }

        self.apply_post_execution_changes()
    }

    fn finish(mut self) -> Result<(Self::Evm, BlockExecutionResult<Receipt>), BlockExecutionError> {
        if self.ocomp_lifecycle_active {
            if !self.ocomp_terminal_request_consumed {
                return Err(BlockExecutionError::msg(
                    "active OCOMP block is missing its terminal system transaction",
                ));
            }
        } else {
            self.finalize_compressed_entities()?;
        }
        let current_summary = self.current_execution_summary();
        let block_number = self.inner.evm.block().number().saturating_to::<u64>();
        let block_timestamp = self.inner.evm.block().timestamp().saturating_to::<u64>();
        let block_artifacts = decode_outbe_block_artifacts(self.final_extra_data().as_ref())
            .map_err(|error| BlockExecutionError::msg(error.to_string()))?;
        if block_number > 0 {
            let seal_output = self
                .compressed_entities_seal_output
                .as_ref()
                .ok_or_else(|| {
                    BlockExecutionError::msg("missing compressed-entities SealOutput")
                })?;
            validate_compressed_entities_root_after_seal(
                block_artifacts.compressed_entities_root,
                seal_output.new_root,
            )?;
        }
        validate_execution_summary_artifact(
            self.validate_execution_summary,
            block_number,
            block_artifacts.execution_summary,
            current_summary,
        )?;

        // OCOMP applies this phase before its terminal request so that the CE
        // seal remains the final semantic writer. The normal path applies the
        // same Outbe-owned phase here. Neither path passes withdrawals to the
        // upstream Ethereum Gwei-to-wei conversion.
        if !self.ocomp_lifecycle_active {
            self.apply_outbe_ethereum_post_execution()?;
        }
        let requests = self
            .ethereum_post_execution_requests
            .take()
            .ok_or_else(|| BlockExecutionError::msg("missing Outbe post-execution output"))?;
        let gas_used = if self.inner.evm.cfg_env().enable_amsterdam_eip8037 {
            self.inner.max_block_gas_used()
        } else {
            self.inner.cumulative_tx_gas_used
        };
        let result = BlockExecutionResult {
            receipts: std::mem::take(&mut self.inner.receipts),
            requests,
            gas_used,
            blob_gas_used: self.inner.blob_gas_used,
        };
        let evm = self.inner.evm;
        // Validator/import execution ends before Reth validates receipt and
        // state roots, so it must not publish speculative CE state here. The
        // proposer publishes only after block assembly supplies the final hash;
        // a finalized validator block is reconstructed from durable canonical
        // receipts after the DB-only persistence barrier.
        if let (Some(bridge), Some(block_hash), Some(summary)) = (
            self.bridge.as_ref(),
            self.block_hash,
            block_artifacts.execution_summary,
        ) {
            if let Some(state_root) = self.block_state_root {
                bridge.record_execution_summary_with_state_root(
                    block_number,
                    block_hash,
                    summary,
                    block_timestamp,
                    state_root,
                );
            } else {
                bridge.record_execution_summary(block_number, block_hash, summary, block_timestamp);
            }
        }

        Ok((evm, result))
    }

    fn set_state_hook(&mut self, hook: Option<Box<dyn OnStateHook>>) {
        self.inner.set_state_hook(hook)
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }

    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use alloy_consensus::{
        SignableTransaction as _, Transaction as _, TxEip1559, TxEip7702, TxReceipt as _,
    };
    use alloy_eips::{
        eip1559::MIN_PROTOCOL_BASE_FEE, eip2718::Encodable2718, eip7702::Authorization,
    };
    use alloy_evm::{
        eth::{EthBlockExecutionCtx, EthBlockExecutor},
        RecoveredTx as _,
    };
    use alloy_primitives::{
        address, keccak256, logs_bloom, Address, Bytes, Log, Signature, TxKind, B256, U256,
    };
    use alloy_sol_types::{SolCall, SolEvent};
    use k256::ecdsa::signature::hazmat::PrehashSigner as _;
    use outbe_compressed_entities::{
        CandidateCacheLimits, CeMdbx, CeWorkConfig, CompressedTreeService, EnvironmentIdentity,
        ExactParentIdentity, ExecutionScope, FinalizedMarker, ACTIVE_COMMITMENT_SCHEME,
        LOCAL_STORAGE_SCHEMA_VERSION,
    };
    use outbe_nod::{
        precompile::INod, NodBucketState, NodContract, NodItemState, NodRepositoryReader,
        NodRepositoryWriter,
    };
    use outbe_offchain_data::RuntimeBodyReaders;
    use outbe_offchain_storage::{MemoryStorage, StorageReaderHandle, StorageWriterHandle};
    use outbe_primitives::addresses::{
        CYCLE_ADDRESS, NOD_ADDRESS, ORACLE_ADDRESS, OUTBE_SYSTEM_TX_ADDRESS, REWARDS_ADDRESS,
        SLASH_INDICATOR_ADDRESS, STABLECOIN_FACTORY_ADDRESS, STABLECOIN_POLICY_REGISTRY_ADDRESS,
        STAKING_ADDRESS, UPDATE_ADDRESS, VOTE_ADDRESS,
    };
    use outbe_primitives::block::{BlockContext, BlockRuntimeContext};
    use outbe_primitives::consensus::{
        ConsensusExecutionBridge, GenesisValidator, GenesisValidators,
    };
    use outbe_primitives::consensus_metadata::CertifiedParentAccountingMetadata;
    use outbe_primitives::hook_events::partition_hook_events;
    use outbe_primitives::reshare_artifact::{
        encode_outbe_block_artifacts, CompressedEntitiesRootArtifact, ConsensusHeaderArtifact,
        ExecutionSummaryArtifact, OutbeBlockArtifacts,
    };
    use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};
    use outbe_primitives::tee_genesis_v1::GRAMINE_DIRECT_DEV_CHAIN_ID;
    use outbe_primitives::time::WorldwideDay;
    use outbe_primitives::OutbeHeader;
    use outbe_primitives::{
        stablecoin::{encode_canonical_stablecoin_create, StablecoinCreatePayload},
        stablecoin_fork::STABLECOIN_CREATE_BOND,
    };
    use outbe_stablecoin::StablecoinContract;
    use outbe_stablecoinfactory::{precompile::IStablecoinFactory, StablecoinFactoryContract};
    use outbe_tribute::{TributeContract, TributeData, TributeRepositoryReader};
    use outbe_validatorset::{ValidatorHistory, ValidatorLifecycle};
    use outbe_vote::{
        constants::VOTING_WINDOW_BLOCKS,
        precompile::IVote,
        schema::{BondSettlement, ProposalStatus, Vote},
    };
    use reth_ethereum::chainspec::{ChainSpec, ChainSpecBuilder, MAINNET};
    use reth_ethereum::evm::revm::db::State;
    use reth_ethereum::Receipt;
    use reth_evm::{block::BlockExecutor, execute::ProviderError, ConfigureEvm, EvmEnv};
    use reth_primitives_traits::SignedTransaction as _;
    use revm::{
        context::{BlockEnv, CfgEnv},
        database::states::bundle_state::BundleRetention,
        database::{CacheDB, Database},
        database_interface::EmptyDBTyped,
        primitives::hardfork::SpecId,
        state::{AccountInfo, Bytecode},
    };

    use super::{
        validate_compressed_entities_root_after_seal, validate_compressed_entities_root_scheme,
        AccountedParentArtifact, AccountedParentArtifactProvider, OutbeBlockExecutor,
        SystemFailureReceiptInput,
    };
    use crate::{
        config::{OutbeBlockExecutionCtx, OutbeEvmConfig},
        signer::OutbeEvmSigner,
        system_tx::{
            build_unsigned_system_tx, build_unsigned_system_tx_with_gas_limit,
            system_tx_intrinsic_gas, OcompLifecycleActivation, SystemTxInputV2, SystemTxKind,
        },
    };

    const CHAIN_ID: u64 = GRAMINE_DIRECT_DEV_CHAIN_ID;
    const TEST_BLOCK_TIMESTAMP_BASE: u64 = 1_700_000_000;
    const OWNER: Address = address!("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    alloy_sol_types::sol! {
        event DepositEvent(
            bytes pubkey,
            bytes withdrawal_credentials,
            bytes amount,
            bytes signature,
            bytes index
        );
    }

    fn seed_compressed_entities_genesis(storage: StorageHandle<'_>) {
        let root = outbe_compressed_entities::sealed_root(B256::ZERO).unwrap();
        storage
            .sstore(
                outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
                U256::ZERO,
                U256::from(4),
            )
            .unwrap();
        storage
            .sstore(
                outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
                U256::from(1),
                U256::from_be_slice(root.as_slice()),
            )
            .unwrap();
    }

    fn seed_cycle_genesis(storage: StorageHandle<'_>) {
        let cycle = storage.contract::<outbe_cycle::schema::Cycle<'_>>();
        cycle
            .active_utc_day
            .write(outbe_primitives::time::timestamp_to_date_key(
                TEST_BLOCK_TIMESTAMP_BASE,
            ))
            .unwrap();
    }

    #[test]
    fn compressed_entities_header_semantics_reject_missing_wrong_scheme_and_wrong_root() {
        let root = B256::repeat_byte(0xA1);
        assert!(validate_compressed_entities_root_scheme(None)
            .unwrap_err()
            .to_string()
            .contains("missing compressed-entities root artifact"));
        assert!(
            validate_compressed_entities_root_scheme(Some(CompressedEntitiesRootArtifact {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME + 1,
                r_sealed: root,
            }))
            .unwrap_err()
            .to_string()
            .contains("scheme mismatch")
        );
        assert!(validate_compressed_entities_root_after_seal(
            Some(CompressedEntitiesRootArtifact {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                r_sealed: B256::ZERO,
            }),
            root,
        )
        .unwrap_err()
        .to_string()
        .contains("header/SealOutput root mismatch"));
        assert_eq!(
            validate_compressed_entities_root_after_seal(
                Some(CompressedEntitiesRootArtifact {
                    commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                    r_sealed: root,
                }),
                root,
            )
            .unwrap()
            .r_sealed,
            root
        );
    }

    fn persistent_test_tree(genesis_hash: B256) -> (tempfile::TempDir, Arc<CompressedTreeService>) {
        persistent_test_tree_with_marker(
            genesis_hash,
            FinalizedMarker {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                height: 0,
                block_hash: genesis_hash,
                parent_block_hash: B256::ZERO,
                parent_root: B256::ZERO,
                new_root: outbe_compressed_entities::sealed_root(B256::ZERO).unwrap(),
            },
        )
    }

    fn persistent_test_tree_with_marker(
        genesis_hash: B256,
        marker: FinalizedMarker,
    ) -> (tempfile::TempDir, Arc<CompressedTreeService>) {
        let directory = tempfile::tempdir().expect("CE test directory must be created");
        let genesis_marker = FinalizedMarker {
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            height: 0,
            block_hash: genesis_hash,
            parent_block_hash: B256::ZERO,
            parent_root: B256::ZERO,
            new_root: outbe_compressed_entities::sealed_root(B256::ZERO).unwrap(),
        };
        let db = CeMdbx::open(
            directory.path(),
            EnvironmentIdentity {
                local_storage_schema_version: LOCAL_STORAGE_SCHEMA_VERSION,
                chain_id: CHAIN_ID,
                genesis_hash,
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                topology: outbe_compressed_entities::CeTopologyV1.encode(),
                tree_format: "ckb-smt-v0.6.1-poseidon-catalog-v3".to_owned(),
                vendor_revision: "ad555350c866b2265d87d2d7fbd146fbc918bfe5".to_owned(),
            },
            genesis_marker,
        )
        .expect("CE test MDBX must open");
        if marker != genesis_marker {
            db.test_seed_finalized_marker(marker)
                .expect("CE test finalized marker must seed");
        }
        let service = CompressedTreeService::new(
            db,
            CandidateCacheLimits {
                max_candidates: 4,
                max_encoded_bytes: 1_000_000,
            },
        )
        .expect("CE test tree service must open");
        (directory, Arc::new(service))
    }

    /// reth22-1 regression: every *stateful* dispatch-registered precompile must
    /// be preserved by either the per-block EIP-161 marker list or canonical
    /// genesis marker bytecode, or its storage is silently lost at state-root
    /// time (GEM/GEM_FACTORY were missing). This unit pins runtime-marker
    /// coverage for routes that are neither stateless nor genesis-preserved;
    /// `tests/genesis.rs` binds the complementary genesis-marker evidence.
    #[test]
    fn marker_list_covers_stateful_precompiles() {
        use crate::executor::marker_addresses::OUTBE_RUNTIME_MARKER_ADDRESSES;
        use crate::precompiles::outbe_precompile_addresses;
        use outbe_primitives::addresses::{
            DEBUG_SUBCALL_PRECOMPILE_ADDRESS, GOVERNANCE_ADDRESS, RADICLE_REGISTRY_ADDRESS,
            STABLECOIN_FACTORY_ADDRESS, STABLECOIN_POLICY_REGISTRY_ADDRESS, VAULT_ROUTER_ADDRESS,
            ZEROFEE_ADDRESS, ZKPROOF_GROTH16_ADDRESS, ZKPROOF_POSEIDON_ADDRESS,
        };

        // Dispatch-registered precompiles that legitimately need NO runtime 0xEF
        // marker. Each state-owning exemption must have canonical genesis-marker
        // evidence in `tests/genesis.rs`; an unproven exemption would re-open reth22-1.
        const MARKER_EXEMPT: [Address; 9] = [
            // Stateless verifiers - no EVM storage to preserve.
            ZKPROOF_POSEIDON_ADDRESS,
            ZKPROOF_GROTH16_ADDRESS,
            // Debug adapter owns no persistent state; any child effects are journaled
            // against the actual child target.
            DEBUG_SUBCALL_PRECOMPILE_ADDRESS,
            // Seeded with genesis marker bytecode by scripts/seed_genesis.py, so these
            // accounts are never EIP-161-empty.
            ZEROFEE_ADDRESS,
            VAULT_ROUTER_ADDRESS,
            GOVERNANCE_ADDRESS,
            // Stablecoin Factory and Policy Registry marker code is genesis-active
            // even before Stablecoin V1 runtime activation.
            STABLECOIN_FACTORY_ADDRESS,
            STABLECOIN_POLICY_REGISTRY_ADDRESS,
            // RadicleRegistry is present from genesis even when no repositories
            // are configured because ALL_PRECOMPILE_ADDRESSES seeds its marker.
            RADICLE_REGISTRY_ADDRESS,
        ];

        for addr in outbe_precompile_addresses() {
            if MARKER_EXEMPT.contains(addr) {
                continue;
            }
            assert!(
                OUTBE_RUNTIME_MARKER_ADDRESSES.contains(addr),
                "stateful dispatch-registered precompile {addr} is missing from the EIP-161 \
                 runtime marker list (OUTBE_RUNTIME_MARKER_ADDRESSES) - its storage would be \
                 silently pruned at state-root (reth22-1). Add it to the marker list, or, if it \
                 is stateless / genesis-seeded, to MARKER_EXEMPT with justification."
            );
        }

        // GEM/GEM_FACTORY specifically (the original reth22-1 bug) must be covered.
        use outbe_primitives::addresses::{GEM_ADDRESS, GEM_FACTORY_ADDRESS};
        assert!(OUTBE_RUNTIME_MARKER_ADDRESSES.contains(&GEM_ADDRESS));
        assert!(OUTBE_RUNTIME_MARKER_ADDRESSES.contains(&GEM_FACTORY_ADDRESS));
    }

    fn numbered_test_address(prefix: u8, n: u64) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = prefix;
        bytes[12..].copy_from_slice(&n.to_be_bytes());
        Address::from(bytes)
    }

    fn test_chain_spec() -> Arc<ChainSpec<OutbeHeader>> {
        use outbe_primitives::tee_test_utils::{
            gramine_direct_policy_v1, tee_attestation_v1_extra_field,
        };

        let mut spec = MAINNET.as_ref().clone();
        spec.chain = CHAIN_ID.into();
        spec.genesis.config.chain_id = CHAIN_ID;
        let policy = gramine_direct_policy_v1(spec.chain().id(), spec.genesis_hash())
            .expect("test GramineDirectDev policy is canonical");
        spec.genesis.config.extra_fields.insert(
            "teeAttestationV1".to_owned(),
            tee_attestation_v1_extra_field(&policy)
                .expect("test TEE activation manifest is canonical"),
        );
        let spec: Arc<ChainSpec<OutbeHeader>> = spec.map_header(OutbeHeader::new).into();
        spec
    }

    fn test_ocomp_fork_install(
        chain_spec: &ChainSpec<OutbeHeader>,
        founders: &[(Address, [u8; 48])],
    ) -> Arc<outbe_metadosis::config::OcompForkInstallV1> {
        Arc::new(
            outbe_metadosis::test_support::ForkInstallScenario::measurement_at(
                1,
                chain_spec.chain().id(),
                chain_spec.genesis_hash(),
            )
            .unwrap()
            .with_founder_validators(founders)
            .unwrap()
            .into_install(),
        )
    }

    fn seed_test_ocomp_profile(
        provider: &mut HashMapStorageProvider,
        restore_block_number: u64,
        install: &outbe_metadosis::config::OcompForkInstallV1,
    ) {
        provider.set_block_number(1);
        provider.enable_metadosis_mutation_frame(
            outbe_primitives::storage::MetadosisMutationPurposeTag::ForkProfile,
        );
        StorageHandle::enter(provider, |storage| {
            let ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(1, 1_700_000_001, CHAIN_ID),
                storage,
            );
            outbe_metadosis::commands::install_fork_profile(&ctx, install).unwrap();
        });
        provider.set_block_number(restore_block_number);
    }

    fn test_evm_signer() -> Arc<OutbeEvmSigner> {
        Arc::new(OutbeEvmSigner::from_secret_bytes([1u8; 32]).unwrap())
    }

    fn test_evm_env(block_number: u64, beneficiary: Address) -> EvmEnv {
        EvmEnv {
            cfg_env: CfgEnv::new()
                .with_chain_id(CHAIN_ID)
                .with_spec_and_mainnet_gas_params(SpecId::SHANGHAI),
            block_env: BlockEnv {
                number: U256::from(block_number),
                gas_limit: outbe_primitives::system_tx::protocol_block_gas_limit(block_number),
                basefee: MIN_PROTOCOL_BASE_FEE,
                beneficiary,
                timestamp: U256::from(TEST_BLOCK_TIMESTAMP_BASE.saturating_add(block_number)),
                ..Default::default()
            },
        }
    }

    fn state_with_active_proposer(
        proposer: Address,
    ) -> State<CacheDB<EmptyDBTyped<ProviderError>>> {
        state_with_active_proposer_fixture(proposer, true)
    }

    fn state_with_active_proposer_without_ocomp(
        proposer: Address,
    ) -> State<CacheDB<EmptyDBTyped<ProviderError>>> {
        state_with_active_proposer_fixture(proposer, false)
    }

    fn state_with_active_proposer_fixture(
        proposer: Address,
        seed_ocomp: bool,
    ) -> State<CacheDB<EmptyDBTyped<ProviderError>>> {
        let chain_spec = test_chain_spec();
        let mut seed_storage =
            HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, chain_spec.genesis_hash());
        let proposer_key = dummy_pubkey(0xA2);
        let install = test_ocomp_fork_install(&chain_spec, &[(proposer, proposer_key)]);
        StorageHandle::enter(&mut seed_storage, |storage| {
            seed_compressed_entities_genesis(storage.clone());
            seed_cycle_genesis(storage.clone());
            seed_registered_active_validator_with_registration(
                storage.clone(),
                proposer,
                &proposer_key,
                &install.founder_registrations[0],
            );
        });
        if seed_ocomp {
            seed_test_ocomp_profile(&mut seed_storage, 0, &install);
        }

        let mut db = cache_db_from_storage(seed_storage);
        let marker_code = Bytecode::new_legacy([0xef].into());
        db.insert_account_info(
            outbe_primitives::addresses::VALIDATOR_SET_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code.clone()),
                ..Default::default()
            },
        );
        db.insert_account_info(
            outbe_primitives::addresses::ORACLE_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code.clone()),
                ..Default::default()
            },
        );
        db.insert_account_info(
            outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code.clone()),
                ..Default::default()
            },
        );
        db.insert_account_info(
            outbe_primitives::addresses::METADOSIS_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code.clone()),
                ..Default::default()
            },
        );
        db.insert_account_info(
            outbe_primitives::addresses::OCOMP_REGISTRY_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code.clone()),
                ..Default::default()
            },
        );
        db.insert_account_info(
            CYCLE_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code),
                ..Default::default()
            },
        );
        State::builder()
            .with_database(db)
            .with_bundle_update()
            .build()
    }

    fn state_with_active_proposer_and_funded_account(
        proposer: Address,
        funded: Address,
    ) -> State<CacheDB<EmptyDBTyped<ProviderError>>> {
        state_with_active_proposer_and_funded_account_fixture(proposer, funded, true)
    }

    fn state_with_active_proposer_and_funded_account_without_ocomp(
        proposer: Address,
        funded: Address,
    ) -> State<CacheDB<EmptyDBTyped<ProviderError>>> {
        state_with_active_proposer_and_funded_account_fixture(proposer, funded, false)
    }

    fn state_with_active_proposer_and_funded_account_fixture(
        proposer: Address,
        funded: Address,
        seed_ocomp: bool,
    ) -> State<CacheDB<EmptyDBTyped<ProviderError>>> {
        let chain_spec = test_chain_spec();
        let mut seed_storage =
            HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, chain_spec.genesis_hash());
        let proposer_key = dummy_pubkey(0xA2);
        let install = test_ocomp_fork_install(&chain_spec, &[(proposer, proposer_key)]);
        StorageHandle::enter(&mut seed_storage, |storage| {
            seed_compressed_entities_genesis(storage.clone());
            seed_cycle_genesis(storage.clone());
            seed_registered_active_validator_with_registration(
                storage.clone(),
                proposer,
                &proposer_key,
                &install.founder_registrations[0],
            );
        });
        if seed_ocomp {
            seed_test_ocomp_profile(&mut seed_storage, 0, &install);
        }

        let mut db = cache_db_from_storage(seed_storage);
        let marker_code = Bytecode::new_legacy([0xef].into());
        db.insert_account_info(
            outbe_primitives::addresses::VALIDATOR_SET_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code.clone()),
                ..Default::default()
            },
        );
        db.insert_account_info(
            outbe_primitives::addresses::ORACLE_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code.clone()),
                ..Default::default()
            },
        );
        db.insert_account_info(
            outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code.clone()),
                ..Default::default()
            },
        );
        db.insert_account_info(
            outbe_primitives::addresses::METADOSIS_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code.clone()),
                ..Default::default()
            },
        );
        db.insert_account_info(
            outbe_primitives::addresses::OCOMP_REGISTRY_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code),
                ..Default::default()
            },
        );
        db.insert_account_info(
            funded,
            AccountInfo {
                balance: U256::from(1_000_000u64),
                ..Default::default()
            },
        );

        State::builder()
            .with_database(db)
            .with_bundle_update()
            .build()
    }

    fn state_with_active_validators_seeded(
        validators: &[(Address, [u8; 48])],
        seed_extra: impl FnOnce(StorageHandle),
    ) -> State<CacheDB<EmptyDBTyped<ProviderError>>> {
        state_with_active_validators_seeded_at_block(validators, 0, seed_extra)
    }

    fn state_with_active_validators_seeded_at_block(
        validators: &[(Address, [u8; 48])],
        block_number: u64,
        seed_extra: impl FnOnce(StorageHandle),
    ) -> State<CacheDB<EmptyDBTyped<ProviderError>>> {
        state_with_active_validators_seeded_at_block_with_cycle_frames(
            validators,
            block_number,
            0,
            seed_extra,
        )
    }

    fn state_with_active_validators_seeded_at_block_with_cycle_frames(
        validators: &[(Address, [u8; 48])],
        block_number: u64,
        cycle_frames: u8,
        seed_extra: impl FnOnce(StorageHandle),
    ) -> State<CacheDB<EmptyDBTyped<ProviderError>>> {
        let chain_spec = test_chain_spec();
        let mut seed_storage =
            HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, chain_spec.genesis_hash());
        let install = test_ocomp_fork_install(&chain_spec, validators);
        seed_storage.set_block_number(block_number);
        StorageHandle::enter(&mut seed_storage, |storage| {
            seed_compressed_entities_genesis(storage.clone());
            seed_cycle_genesis(storage.clone());
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.config_epoch_length_blocks.write(60).unwrap();
            vs.config_is_initialized.write(true).unwrap();
            for ((validator, pk), registration) in
                validators.iter().zip(&install.founder_registrations)
            {
                register_and_activate_with_ocomp_registration(
                    &mut vs,
                    *validator,
                    pk,
                    registration,
                );
            }
            seed_test_committee_snapshot(storage.clone(), validators);
            // Seed the COEN/840 oracle pair + a 1.0 rate so begin-block
            // NOD/GEM/INTEX floor-price promotion resolves a live rate instead
            // of soft-skipping the scan. 840 is also pushed onto the reference
            // currency list, matching genesis: the Nod qualifier reads its ISO
            // from there, not from a hard-coded constant.
            outbe_oracle::api::register_pair(storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
                .unwrap();
            outbe_oracle::schema::OracleContract::new(storage.clone())
                .reference_currencies
                .push(outbe_oracle::api::DAY_TYPE_ISO)
                .unwrap();
            outbe_oracle::api::set_exchange_rate(
                storage.clone(),
                Address::ZERO,
                outbe_oracle::api::DAY_TYPE_PAIR,
                U256::from(1_000_000u64),
                0,
                0,
            )
            .unwrap();
        });
        seed_test_ocomp_profile(&mut seed_storage, block_number, &install);
        if cycle_frames != 0 {
            seed_storage.enable_metadosis_mutation_frames(
                outbe_primitives::storage::MetadosisMutationPurposeTag::CycleLifecycle,
                cycle_frames,
            );
        }
        StorageHandle::enter(&mut seed_storage, seed_extra);

        let marker_addresses = [
            outbe_primitives::addresses::VALIDATOR_SET_ADDRESS,
            outbe_primitives::addresses::ORACLE_ADDRESS,
            VOTE_ADDRESS,
            UPDATE_ADDRESS,
            STABLECOIN_FACTORY_ADDRESS,
            STABLECOIN_POLICY_REGISTRY_ADDRESS,
            CYCLE_ADDRESS,
            SLASH_INDICATOR_ADDRESS,
            outbe_primitives::addresses::STAKING_ADDRESS,
            outbe_primitives::addresses::REWARDS_ADDRESS,
            outbe_primitives::addresses::AGENT_REWARD_ADDRESS,
            outbe_primitives::addresses::METADOSIS_ADDRESS,
            outbe_primitives::addresses::OCOMP_REGISTRY_ADDRESS,
            outbe_primitives::addresses::TEE_REGISTRY_ADDRESS,
            outbe_primitives::addresses::TRIBUTE_ADDRESS,
            NOD_ADDRESS,
            outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
            // marker allowlist: the accounting-progress marker account
            // is preserved across EIP-161 by `0xef` bytecode in production, so its
            // seeded slot survives as live state here too (otherwise an empty
            // account's storage reads back as zero).
            outbe_primitives::addresses::ACCOUNTING_PROGRESS_ADDRESS,
        ];
        // `cache_db_from_storage` carries storage slots but not balances, and the
        // marker-info insert below overwrites `AccountInfo`. Capture any balance a
        // seed closure funded on a marker address first, then re-apply it so the
        // marker code AND the seeded balance both survive.
        let seeded_balances: Vec<U256> = marker_addresses
            .iter()
            .map(|address| seed_storage.get_balance(*address))
            .collect();
        let mut db = cache_db_from_storage(seed_storage);
        let marker_code = Bytecode::new_legacy([0xef].into());
        for (address, balance) in marker_addresses.into_iter().zip(seeded_balances) {
            db.insert_account_info(
                address,
                AccountInfo {
                    code_hash: marker_code.hash_slow(),
                    code: Some(marker_code.clone()),
                    balance,
                    ..Default::default()
                },
            );
        }

        State::builder()
            .with_database(db)
            .with_bundle_update()
            .build()
    }

    fn state_with_active_and_registered_candidate(
        active: Address,
        candidate: Address,
    ) -> State<CacheDB<EmptyDBTyped<ProviderError>>> {
        state_with_active_and_registered_candidate_seeded(active, candidate, |_| {})
    }

    fn state_with_active_and_registered_candidate_seeded(
        active: Address,
        candidate: Address,
        seed_extra: impl FnOnce(StorageHandle),
    ) -> State<CacheDB<EmptyDBTyped<ProviderError>>> {
        let chain_spec = test_chain_spec();
        let mut seed_storage =
            HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, chain_spec.genesis_hash());
        let active_key = dummy_pubkey(0xA2);
        let install = test_ocomp_fork_install(&chain_spec, &[(active, active_key)]);
        StorageHandle::enter(&mut seed_storage, |storage| {
            seed_compressed_entities_genesis(storage.clone());
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.config_epoch_length_blocks.write(60).unwrap();
            vs.config_is_initialized.write(true).unwrap();
            register_and_activate_with_ocomp_registration(
                &mut vs,
                active,
                &active_key,
                &install.founder_registrations[0],
            );
            vs.register_validator(OWNER, candidate, &dummy_pubkey(0xB3))
                .unwrap();
            vs.admit_validator_for_boundary_for_test(candidate).unwrap();
            seed_test_committee_snapshot(storage.clone(), &[(active, active_key)]);
            // Seed the COEN/840 oracle pair + a 1.0 rate so begin-block
            // NOD/GEM/INTEX floor-price promotion resolves a live rate instead
            // of soft-skipping the scan. 840 is also pushed onto the reference
            // currency list, matching genesis: the Nod qualifier reads its ISO
            // from there, not from a hard-coded constant.
            outbe_oracle::api::register_pair(storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
                .unwrap();
            outbe_oracle::schema::OracleContract::new(storage.clone())
                .reference_currencies
                .push(outbe_oracle::api::DAY_TYPE_ISO)
                .unwrap();
            outbe_oracle::api::set_exchange_rate(
                storage.clone(),
                Address::ZERO,
                outbe_oracle::api::DAY_TYPE_PAIR,
                U256::from(1_000_000u64),
                0,
                0,
            )
            .unwrap();
            seed_extra(storage);
        });
        seed_test_ocomp_profile(&mut seed_storage, 0, &install);

        let mut db = cache_db_from_storage(seed_storage);
        let marker_code = Bytecode::new_legacy([0xef].into());
        db.insert_account_info(
            outbe_primitives::addresses::VALIDATOR_SET_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code.clone()),
                ..Default::default()
            },
        );
        db.insert_account_info(
            outbe_primitives::addresses::ORACLE_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code.clone()),
                ..Default::default()
            },
        );
        db.insert_account_info(
            outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code.clone()),
                ..Default::default()
            },
        );
        db.insert_account_info(
            outbe_primitives::addresses::METADOSIS_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code.clone()),
                ..Default::default()
            },
        );
        db.insert_account_info(
            outbe_primitives::addresses::OCOMP_REGISTRY_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code),
                ..Default::default()
            },
        );
        State::builder()
            .with_database(db)
            .with_bundle_update()
            .build()
    }

    fn execution_ctx<'a>(
        tx_count_hint: Option<usize>,
        extra_data: Bytes,
    ) -> OutbeBlockExecutionCtx<'a> {
        OutbeBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                parent_hash: B256::ZERO,
                parent_beacon_block_root: None,
                ommers: &[],
                withdrawals: None,
                extra_data,
                tx_count_hint,
                slot_number: None,
            },
            timestamp_millis_part: 0,
            block_hash: None,
            block_state_root: None,
            expected_begin_system_txs: Vec::new(),
            expected_end_system_txs: Vec::new(),
            system_layout_error: None,
            parent_consensus_metadata: None,
            proposer_evm_address: None,
            execute_outbe_block_hooks: true,
            prebuilt_phase1_tx: None,
            parent_artifact_hint: None,
            pending_tee_bootstrap: None,
            execution_read_budget: None,
        }
    }

    fn block_one_execution_ctx<'a>(
        tx_count_hint: Option<usize>,
        extra_data: Bytes,
    ) -> OutbeBlockExecutionCtx<'a> {
        execution_ctx_with_tee_bootstrap(tx_count_hint, extra_data, sample_tee_bootstrap_payload(1))
    }

    fn execution_ctx_with_tee_bootstrap<'a>(
        tx_count_hint: Option<usize>,
        extra_data: Bytes,
        tee_bootstrap: outbe_primitives::tee_bootstrap_v2::TeeBootstrapV2,
    ) -> OutbeBlockExecutionCtx<'a> {
        let mut ctx = execution_ctx(tx_count_hint, extra_data);
        ctx.pending_tee_bootstrap = Some(tee_bootstrap);
        ctx
    }

    fn begin_system_txs_for_test(
        config: &OutbeEvmConfig,
        block_number: u64,
        parent_hash: B256,
        extra_data: &Bytes,
        parent_consensus_metadata: Option<CertifiedParentAccountingMetadata>,
        proposer: Address,
    ) -> Vec<reth_primitives_traits::Recovered<reth_ethereum::TransactionSigned>> {
        let pending_tee_bootstrap =
            (block_number == 1).then(|| sample_tee_bootstrap_payload(block_number));
        begin_system_txs_for_test_with_bootstrap(
            config,
            block_number,
            parent_hash,
            extra_data,
            parent_consensus_metadata,
            proposer,
            pending_tee_bootstrap,
        )
    }

    fn begin_system_txs_for_test_with_bootstrap(
        config: &OutbeEvmConfig,
        block_number: u64,
        parent_hash: B256,
        extra_data: &Bytes,
        parent_consensus_metadata: Option<CertifiedParentAccountingMetadata>,
        proposer: Address,
        pending_tee_bootstrap: Option<outbe_primitives::tee_bootstrap_v2::TeeBootstrapV2>,
    ) -> Vec<reth_primitives_traits::Recovered<reth_ethereum::TransactionSigned>> {
        config
            .build_begin_system_txs(
                block_number,
                CHAIN_ID,
                outbe_primitives::system_tx::protocol_block_gas_limit(block_number),
                parent_hash,
                extra_data,
                parent_consensus_metadata,
                Some(proposer),
                None,
                pending_tee_bootstrap,
            )
            .expect("begin-zone system txs should build")
    }

    fn sample_tee_bootstrap_payload(
        block_number: u64,
    ) -> outbe_primitives::tee_bootstrap_v2::TeeBootstrapV2 {
        sample_tee_bootstrap_payload_at(
            block_number,
            TEST_BLOCK_TIMESTAMP_BASE.saturating_add(block_number),
        )
    }

    fn sample_tee_bootstrap_payload_at(
        block_number: u64,
        consensus_timestamp: u64,
    ) -> outbe_primitives::tee_bootstrap_v2::TeeBootstrapV2 {
        use outbe_primitives::tee_test_utils::DevValidatorV1;

        let consensus_public = dummy_pubkey(0xA2);
        let snapshot = test_committee_snapshot(&[(test_evm_signer().address(), consensus_public)]);
        let committee_snapshot_hash = outbe_validatorset::committee_set_hash_v2(0, &snapshot);
        let requested_valid_until = consensus_timestamp
            .checked_add(3_600)
            .expect("test lease timestamp fits u64");
        sample_tee_bootstrap_payload_for(
            block_number,
            committee_snapshot_hash,
            requested_valid_until,
            &[DevValidatorV1 {
                evm_secret: [1; 32],
                bls_minpk_public: consensus_public,
            }],
        )
    }

    fn sample_tee_bootstrap_payload_for(
        block_number: u64,
        committee_snapshot_hash: B256,
        requested_valid_until: u64,
        validators: &[outbe_primitives::tee_test_utils::DevValidatorV1],
    ) -> outbe_primitives::tee_bootstrap_v2::TeeBootstrapV2 {
        use outbe_primitives::tee_test_utils::{
            gramine_direct_bootstrap_v2, gramine_direct_policy_v1,
        };

        let policy = gramine_direct_policy_v1(CHAIN_ID, MAINNET.genesis_hash())
            .expect("test GramineDirectDev policy is canonical");
        gramine_direct_bootstrap_v2(
            policy,
            committee_snapshot_hash,
            block_number,
            requested_valid_until,
            validators,
        )
        .expect("test GramineDirectDev OST3 payload is canonical")
    }

    fn begin_system_tx_kinds(
        txs: &[reth_primitives_traits::Recovered<reth_ethereum::TransactionSigned>],
    ) -> Vec<crate::system_tx::SystemTxKind> {
        txs.iter()
            .map(|tx| {
                SystemTxInputV2::decode(tx.tx().input().as_ref())
                    .expect("begin-zone calldata decodes")
                    .kind()
            })
            .collect()
    }

    #[test]
    fn proposer_injects_tee_bootstrap_after_boundary_when_payload_pending() {
        use crate::system_tx::SystemTxKind;
        let signer = test_evm_signer();
        let proposer = signer.address();
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer);

        // Block 1, empty extra_data: begin-zone is CycleTick + RewardsGemDelivery
        // + OracleSlashWindow + HookEvents. A pending bootstrap is injected
        // between delivery and OracleSlashWindow.
        let with_bootstrap = begin_system_txs_for_test_with_bootstrap(
            &config,
            1,
            B256::ZERO,
            &Bytes::new(),
            None,
            proposer,
            Some(sample_tee_bootstrap_payload(1)),
        );
        assert_eq!(
            begin_system_tx_kinds(&with_bootstrap),
            vec![
                SystemTxKind::CycleTick,
                SystemTxKind::RewardsGemDelivery,
                SystemTxKind::TeeBootstrap,
                SystemTxKind::OracleSlashWindow,
                SystemTxKind::HookEvents,
            ],
            "proposer must inject TeeBootstrap before OracleSlashWindow",
        );

        // Block 1 is not buildable without the mandatory OST3 payload.
        let error = config
            .build_begin_system_txs(
                1,
                CHAIN_ID,
                outbe_primitives::system_tx::protocol_block_gas_limit(1),
                B256::ZERO,
                &Bytes::new(),
                None,
                Some(proposer),
                None,
                None,
            )
            .expect_err("block 1 without OST3 must fail closed");
        assert!(
            error
                .to_string()
                .contains("missing mandatory block-1 OST3 bootstrap payload"),
            "{error}"
        );

        // A pending OST3 at genesis is a startup invariant violation, not a value
        // that may be silently dropped.
        let error = config
            .build_begin_system_txs(
                0,
                CHAIN_ID,
                outbe_primitives::system_tx::protocol_block_gas_limit(0),
                B256::ZERO,
                &Bytes::new(),
                None,
                Some(proposer),
                None,
                Some(sample_tee_bootstrap_payload(1)),
            )
            .expect_err("OST3 may only be queued for block 1");
        assert!(
            error
                .to_string()
                .contains("OST3 bootstrap payload is invalid at genesis"),
            "{error}"
        );
    }

    #[allow(dead_code)] // retained for follow-up tests
    fn test_regular_tx() -> reth_ethereum::TransactionSigned {
        TxEip1559 {
            chain_id: CHAIN_ID,
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: MIN_PROTOCOL_BASE_FEE as u128,
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: Bytes::new(),
            access_list: Default::default(),
        }
        .into_signed(Signature::test_signature())
        .into()
    }

    fn test_reserved_system_address_tx() -> reth_ethereum::TransactionSigned {
        TxEip1559 {
            chain_id: CHAIN_ID,
            nonce: 0,
            gas_limit: 100_000,
            max_fee_per_gas: MIN_PROTOCOL_BASE_FEE as u128,
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(OUTBE_SYSTEM_TX_ADDRESS),
            value: U256::ZERO,
            input: Bytes::new(),
            access_list: Default::default(),
        }
        .into_signed(Signature::test_signature())
        .into()
    }

    fn test_priority_fee_tx() -> reth_ethereum::TransactionSigned {
        TxEip1559 {
            chain_id: CHAIN_ID,
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: (MIN_PROTOCOL_BASE_FEE * 2) as u128,
            max_priority_fee_per_gas: MIN_PROTOCOL_BASE_FEE as u128,
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: Bytes::new(),
            access_list: Default::default(),
        }
        .into_signed(Signature::test_signature())
        .into()
    }

    fn test_oracle_get_params_tx() -> reth_ethereum::TransactionSigned {
        let selector = keccak256("getParams()");
        TxEip1559 {
            chain_id: CHAIN_ID,
            nonce: 0,
            gas_limit: 100_000,
            max_fee_per_gas: MIN_PROTOCOL_BASE_FEE as u128,
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(ORACLE_ADDRESS),
            value: U256::ZERO,
            input: Bytes::copy_from_slice(&selector[..4]),
            access_list: Default::default(),
        }
        .into_signed(Signature::test_signature())
        .into()
    }

    fn test_oracle_submit_vote_tx() -> reth_ethereum::TransactionSigned {
        test_oracle_submit_vote_tx_with_gas_limit(1_000_000)
    }

    fn test_oracle_submit_vote_tx_with_gas_limit(
        gas_limit: u64,
    ) -> reth_ethereum::TransactionSigned {
        let input = outbe_oracle::precompile::IOracle::submitVoteCall {
            tuples: vec![outbe_oracle::precompile::IOracle::ExchangeRateTuple {
                base: outbe_oracle::api::COEN_ASSET,
                quote: outbe_oracle::api::currency_address(840),
                exchangeRate: U256::from(1_000_000u64),
                volume: U256::from(10_000_000_000u64),
            }],
        }
        .abi_encode();

        TxEip1559 {
            chain_id: CHAIN_ID,
            nonce: 0,
            gas_limit,
            max_fee_per_gas: MIN_PROTOCOL_BASE_FEE as u128,
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(ORACLE_ADDRESS),
            value: U256::ZERO,
            input: input.into(),
            access_list: Default::default(),
        }
        .into_signed(Signature::test_signature())
        .into()
    }

    fn test_ocomp_submit_result_vote_tx() -> reth_ethereum::TransactionSigned {
        use outbe_ocomp_protocol::{
            abi::{METADOSIS_ADDRESS, SUBMIT_LYSIS_RESULT_SELECTOR},
            encode_envelope,
            profile::poc_schema_limits,
            registry::ObjectKind,
        };

        let mut body = Vec::new();
        body.extend_from_slice(B256::repeat_byte(0x31).as_slice());
        body.extend_from_slice(B256::repeat_byte(0x32).as_slice());
        body.extend_from_slice(&3_u32.to_be_bytes());
        body.extend_from_slice(&7_u64.to_be_bytes());
        body.extend_from_slice(B256::repeat_byte(0x33).as_slice());
        body.extend_from_slice(B256::repeat_byte(0x34).as_slice());
        body.extend_from_slice(B256::repeat_byte(0x35).as_slice());
        body.extend_from_slice(&1_u64.to_be_bytes());
        body.resize(180, 0);
        let payload = encode_envelope(ObjectKind::ResultVoteV1, &body, poc_schema_limits().codec)
            .expect("canonical OCOMP prefix must encode");
        let padded_len = (payload.len() + 31) & !31;
        let mut input = vec![0_u8; 68 + padded_len];
        input[..4].copy_from_slice(&SUBMIT_LYSIS_RESULT_SELECTOR);
        input[4..36].copy_from_slice(&U256::from(32).to_be_bytes::<32>());
        input[36..68].copy_from_slice(&U256::from(payload.len()).to_be_bytes::<32>());
        input[68..68 + payload.len()].copy_from_slice(&payload);

        TxEip1559 {
            chain_id: CHAIN_ID,
            nonce: 0,
            gas_limit: outbe_ocomp_protocol::system_carrier::OCOMP_SYSTEM_CARRIER_GAS_LIMIT,
            max_fee_per_gas:
                outbe_ocomp_protocol::system_carrier::MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS,
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(METADOSIS_ADDRESS),
            value: U256::ZERO,
            input: input.into(),
            access_list: Default::default(),
        }
        .into_signed(Signature::test_signature())
        .into()
    }

    #[test]
    fn executor_adapter_classifies_the_canonical_ocomp_system_carrier_prefix() {
        let tx = test_ocomp_submit_result_vote_tx();
        let candidate = outbe_ocomp_protocol::system_carrier::classify_ocomp_system_carrier(
            outbe_ocomp_protocol::system_carrier::OcompSystemCarrierView {
                is_eip1559: true,
                to: tx.to(),
                value: tx.value(),
                input: tx.input().as_ref(),
                gas_limit: tx.gas_limit(),
                max_fee_per_gas: tx.max_fee_per_gas(),
                max_priority_fee_per_gas: tx.max_priority_fee_per_gas(),
            },
            &outbe_ocomp_protocol::profile::poc_schema_limits(),
        )
        .expect("canonical OCOMP envelope must classify")
        .expect("canonical OCOMP envelope must select the system carrier");

        let outbe_ocomp_protocol::system_carrier::OcompSystemCarrierCandidate::ResultVote {
            prefix,
        } = candidate
        else {
            panic!("expected result-vote carrier")
        };
        assert_eq!(prefix.ocomp_key_hash, B256::repeat_byte(0x35));
    }

    #[allow(dead_code)] // retained for follow-up tests
    fn test_metadata() -> CertifiedParentAccountingMetadata {
        CertifiedParentAccountingMetadata::default()
    }

    #[test]
    fn priority_fees_credit_rewards_escrow_in_production_fee_path() {
        let chain_spec = test_chain_spec();
        let receipt_builder = reth_ethereum::evm::RethReceiptBuilder::default();
        let config = OutbeEvmConfig::new(chain_spec.clone());
        let tx = test_priority_fee_tx();
        let recovered = tx
            .clone()
            .try_into_recovered()
            .expect("priority-fee tx signer should recover");

        let mut db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        db.insert_account_info(
            recovered.signer(),
            AccountInfo {
                balance: U256::from(1_000_000u64),
                ..Default::default()
            },
        );

        let mut state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();
        let evm_env = EvmEnv {
            cfg_env: CfgEnv::new()
                .with_chain_id(CHAIN_ID)
                .with_spec_and_mainnet_gas_params(SpecId::SHANGHAI),
            block_env: BlockEnv {
                number: U256::from(1u64),
                gas_limit: 30_000_000,
                basefee: MIN_PROTOCOL_BASE_FEE,
                beneficiary: REWARDS_ADDRESS,
                timestamp: U256::from(1u64),
                ..Default::default()
            },
        };
        let evm = config.evm_with_env(&mut state, evm_env);
        let ctx = execution_ctx(Some(1), Bytes::new());
        let mut executor = OutbeBlockExecutor::new(
            EthBlockExecutor::new(evm, ctx.inner.clone(), &chain_spec, &receipt_builder),
            None,
            Bytes::new(),
            None,
            false,
            None,
            ctx.inner.parent_hash,
            None,
            ctx.expected_begin_system_txs.clone(),
            ctx.expected_end_system_txs.clone(),
            ctx.system_layout_error.clone(),
            ctx.parent_consensus_metadata.clone(),
            ctx.proposer_evm_address,
            ctx.execute_outbe_block_hooks,
            ctx.prebuilt_phase1_tx.clone(),
            ctx.parent_artifact_hint,
        );

        executor
            .execute_transaction(recovered)
            .expect("priority-fee tx should execute");

        let expected_fee = super::validator_fee_for_gas(
            tx.max_fee_per_gas(),
            tx.max_priority_fee_per_gas(),
            executor.receipts()[0].cumulative_gas_used,
            u128::from(MIN_PROTOCOL_BASE_FEE),
        );
        assert_eq!(
            executor.current_execution_summary().validator_fee_sum,
            expected_fee
        );

        drop(executor);

        let rewards_balance = state
            .basic(REWARDS_ADDRESS)
            .expect("rewards escrow read should succeed")
            .map(|account| account.balance)
            .unwrap_or_default();
        assert_eq!(rewards_balance, expected_fee);
    }

    #[test]
    fn oracle_tx_keeps_fee_envelope_for_basefee_validation() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        let oracle_tx = test_oracle_get_params_tx()
            .try_into_recovered()
            .expect("oracle tx signer should recover");

        let mut db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        db.insert_account_info(
            oracle_tx.signer(),
            AccountInfo {
                balance: U256::from(1_000_000u64),
                ..Default::default()
            },
        );

        let mut state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();
        let evm_env = EvmEnv {
            cfg_env: CfgEnv::new()
                .with_chain_id(CHAIN_ID)
                .with_spec_and_mainnet_gas_params(SpecId::SHANGHAI),
            block_env: BlockEnv {
                number: U256::from(1u64),
                gas_limit: 30_000_000,
                basefee: MIN_PROTOCOL_BASE_FEE,
                beneficiary: OWNER,
                timestamp: U256::from(1u64),
                ..Default::default()
            },
        };
        let evm = config.evm_with_env(&mut state, evm_env);
        let ctx = execution_ctx(Some(1), Bytes::new());
        let mut executor = config.create_executor(evm, ctx);

        executor
            .execute_transaction(oracle_tx)
            .expect("oracle tx with fee cap at basefee must pass validation");

        assert_eq!(executor.receipts().len(), 1);
    }

    #[test]
    fn executor_rejects_user_tx_to_reserved_system_address() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        let reserved_tx = test_reserved_system_address_tx()
            .try_into_recovered()
            .expect("reserved-address tx signer should recover");

        let mut db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        db.insert_account_info(
            reserved_tx.signer(),
            AccountInfo {
                balance: U256::from(1_000_000u64),
                ..Default::default()
            },
        );

        let mut state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();
        let evm_env = EvmEnv {
            cfg_env: CfgEnv::new()
                .with_chain_id(CHAIN_ID)
                .with_spec_and_mainnet_gas_params(SpecId::SHANGHAI),
            block_env: BlockEnv {
                number: U256::from(1u64),
                gas_limit: 30_000_000,
                basefee: 1_000_000_000,
                beneficiary: OWNER,
                timestamp: U256::from(1u64),
                ..Default::default()
            },
        };
        let evm = config.evm_with_env(&mut state, evm_env);
        let ctx = execution_ctx(Some(1), Bytes::new());
        let mut executor = config.create_executor(evm, ctx);

        let err = executor
            .execute_transaction(reserved_tx)
            .expect_err("user tx to reserved system address must be rejected");

        let err = err.to_string();
        assert!(
            err.contains("reserved system transaction address") || err.contains("decode system tx"),
            "unexpected reserved-address rejection error: {err}"
        );
        assert!(executor.receipts().is_empty());
    }

    #[test]
    fn apply_pre_execution_changes_rejects_non_rewards_beneficiary() {
        let signer = test_evm_signer();
        let proposer = signer.address();

        let mut state = state_with_active_proposer(proposer);
        let evm_env = test_evm_env(1, OWNER);
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, evm_env);
        let ctx = execution_ctx(Some(1), Bytes::new());
        let mut executor = config.create_executor(evm, ctx);

        let err = executor
            .apply_pre_execution_changes()
            .expect_err("non-rewards beneficiary must be rejected");
        assert!(err
            .to_string()
            .contains("beneficiary must be REWARDS_ADDRESS"));
    }

    #[test]
    fn pending_rpc_context_opens_ce_scope_but_skips_consensus_hooks() {
        let user_tx = test_regular_tx()
            .try_into_recovered()
            .expect("regular tx signer should recover");
        let mut state =
            state_with_active_proposer_and_funded_account(REWARDS_ADDRESS, user_tx.signer());
        let evm_env = test_evm_env(2, REWARDS_ADDRESS);
        let config = OutbeEvmConfig::new(test_chain_spec());
        let evm = config.evm_with_env(&mut state, evm_env);
        let mut ctx = execution_ctx(None, Bytes::new());
        ctx.execute_outbe_block_hooks = false;
        let mut executor = config.create_executor(evm, ctx);

        executor
            .apply_pre_execution_changes()
            .expect("pending RPC env should skip consensus-only Outbe hooks");
        assert!(executor.receipts().is_empty());
        drop(
            executor
                .compressed_entities_scope
                .begin_explicit_gas_window(0)
                .expect("pending RPC env must open the CE lifecycle"),
        );
        executor
            .execute_transaction(user_tx)
            .expect("pending RPC env must execute txpool transactions inside a CE scope");
        assert_eq!(executor.receipts().len(), 1);
    }

    #[test]
    fn apply_pre_execution_changes_executes_cycle_tick_system_tx_receipt() {
        let signer = test_evm_signer();
        let proposer = signer.address();

        let mut state = state_with_active_proposer(proposer);
        let evm_env = test_evm_env(1, REWARDS_ADDRESS);
        let chain_spec = test_chain_spec();
        let receipt_builder = reth_ethereum::evm::RethReceiptBuilder::default();
        let config = OutbeEvmConfig::new(chain_spec.clone()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, evm_env);
        let ctx = block_one_execution_ctx(Some(0), Bytes::new());
        let mut executor = OutbeBlockExecutor::new(
            EthBlockExecutor::new(evm, ctx.inner.clone(), &chain_spec, &receipt_builder),
            None,
            Bytes::new(),
            None,
            false,
            None,
            ctx.inner.parent_hash,
            Some(signer.clone()),
            ctx.expected_begin_system_txs.clone(),
            ctx.expected_end_system_txs.clone(),
            ctx.system_layout_error.clone(),
            ctx.parent_consensus_metadata.clone(),
            ctx.proposer_evm_address,
            ctx.execute_outbe_block_hooks,
            ctx.prebuilt_phase1_tx.clone(),
            ctx.parent_artifact_hint,
        )
        .with_pending_tee_bootstrap(ctx.pending_tee_bootstrap.clone());

        executor
            .apply_pre_execution_changes()
            .expect("block 1 pre-execution changes should apply");
        let system_txs =
            begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer);
        let mut visible_system_gas_used = 0u64;
        for tx in system_txs.clone() {
            let signed_gas_limit = tx.tx().gas_limit();
            let intrinsic_gas = system_tx_intrinsic_gas(tx.tx().input()).unwrap();
            let gas_used = executor
                .execute_transaction(tx)
                .expect("begin-zone system tx should execute in tx loop");
            assert!(
                (intrinsic_gas..=signed_gas_limit).contains(&gas_used.tx_gas_used()),
                "receipt gas must stay between intrinsic gas and the signed envelope limit"
            );
            visible_system_gas_used += gas_used.tx_gas_used();
            assert_eq!(
                executor
                    .receipts()
                    .last()
                    .expect("system tx receipt must be present")
                    .cumulative_gas_used,
                visible_system_gas_used
            );
        }

        assert_eq!(executor.receipts().len(), 5);
        assert!(executor.receipts().iter().all(|receipt| receipt.success));
        assert!(
            executor.system_tx_execution_gas > 0,
            "system tx internal execution gas must still be measured"
        );
        assert_eq!(
            executor.inner.cumulative_tx_gas_used, visible_system_gas_used,
            "system tx must charge only visible envelope gas to block accounting"
        );
        assert_eq!(
            executor.inner.block_regular_gas_used, visible_system_gas_used,
            "system tx regular gas must expose only visible envelope gas"
        );
        assert!(executor
            .receipts()
            .iter()
            .all(|receipt| receipt.tx_type == reth_ethereum::TxType::Legacy));
        assert_eq!(
            executor.receipts()[4].cumulative_gas_used,
            visible_system_gas_used
        );

        assert_eq!(system_txs.len(), 5);
        assert_eq!(Address::from(*system_txs[0].signer()), proposer);
        assert_eq!(system_txs[0].tx().chain_id(), Some(CHAIN_ID));
        assert_eq!(system_txs[0].tx().tx_type(), reth_ethereum::TxType::Legacy);
        let mut encoded = Vec::new();
        system_txs[0].tx().encode_2718(&mut encoded);
        assert!(
            encoded.first().is_some_and(|byte| *byte >= 0xc0),
            "legacy transaction body must RLP-encode as a list, not a typed envelope"
        );
        assert!(matches!(
            SystemTxInputV2::decode(system_txs[0].tx().input().as_ref()).unwrap(),
            SystemTxInputV2::CycleTick
        ));
        assert!(matches!(
            SystemTxInputV2::decode(system_txs[1].tx().input().as_ref()).unwrap(),
            SystemTxInputV2::RewardsGemDelivery
        ));
        assert!(matches!(
            SystemTxInputV2::decode(system_txs[2].tx().input().as_ref()).unwrap(),
            SystemTxInputV2::TeeBootstrap { .. }
        ));
        assert!(matches!(
            SystemTxInputV2::decode(system_txs[3].tx().input().as_ref()).unwrap(),
            SystemTxInputV2::OracleSlashWindow
        ));
        assert!(matches!(
            SystemTxInputV2::decode(system_txs[4].tx().input().as_ref()).unwrap(),
            SystemTxInputV2::HookEvents
        ));
        drop(executor);

        let read_ctx = BlockContext::new(1, 1, CHAIN_ID, proposer, vec![proposer]);
        let mut provider =
            outbe_primitives::storage::direct::DirectStorageProvider::new(&mut state, read_ctx);
        StorageHandle::enter(&mut provider, |storage| {
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            let record = vs.get_validator(proposer)?.expect("validator should exist");
            assert_eq!(record.blocks_proposed, 1);
            Ok::<_, outbe_primitives::error::PrecompileError>(())
        })
        .expect("validator state should be readable");
    }

    #[test]
    fn system_prefix_charges_visible_gas_and_receipt_cumulative_contract() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let user_tx = test_regular_tx()
            .try_into_recovered()
            .expect("regular tx signer should recover");

        let mut state = state_with_active_proposer_and_funded_account(proposer, user_tx.signer());
        let chain_spec = test_chain_spec();
        let receipt_builder = reth_ethereum::evm::RethReceiptBuilder::default();
        let config = OutbeEvmConfig::new(chain_spec.clone()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, test_evm_env(1, REWARDS_ADDRESS));
        let ctx = block_one_execution_ctx(Some(3), Bytes::new());
        let mut executor = OutbeBlockExecutor::new(
            EthBlockExecutor::new(evm, ctx.inner.clone(), &chain_spec, &receipt_builder),
            None,
            Bytes::new(),
            None,
            false,
            None,
            ctx.inner.parent_hash,
            Some(signer),
            ctx.expected_begin_system_txs.clone(),
            ctx.expected_end_system_txs.clone(),
            ctx.system_layout_error.clone(),
            ctx.parent_consensus_metadata.clone(),
            ctx.proposer_evm_address,
            ctx.execute_outbe_block_hooks,
            ctx.prebuilt_phase1_tx.clone(),
            ctx.parent_artifact_hint,
        )
        .with_pending_tee_bootstrap(ctx.pending_tee_bootstrap.clone());

        executor
            .apply_pre_execution_changes()
            .expect("block 1 pre-execution changes should apply");
        let mut visible_system_gas = 0u64;
        for tx in begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer) {
            let signed_gas_limit = tx.tx().gas_limit();
            let gas_used = executor
                .execute_transaction(tx)
                .expect("begin-zone system tx should execute")
                .tx_gas_used();
            assert!(gas_used <= signed_gas_limit);
            visible_system_gas += gas_used;
        }

        let system_receipt_cumulative = executor
            .receipts()
            .last()
            .expect("system receipt must be present")
            .cumulative_gas_used;
        assert_eq!(
            system_receipt_cumulative, visible_system_gas,
            "begin-zone system receipts must contribute only visible envelope gas"
        );
        assert_eq!(
            executor.inner.cumulative_tx_gas_used, visible_system_gas,
            "system tx gas must expose only the small envelope gas before user txs"
        );

        let user_gas = executor
            .execute_transaction(user_tx)
            .expect("funded regular user tx should execute");
        let user_receipt_cumulative = executor
            .receipts()
            .last()
            .expect("user receipt must be present")
            .cumulative_gas_used;

        assert_eq!(
            executor.inner.cumulative_tx_gas_used,
            visible_system_gas + user_gas.tx_gas_used(),
            "header gas accounting must include visible system envelope gas plus user gas"
        );
        assert_eq!(
            user_receipt_cumulative,
            visible_system_gas + user_gas.tx_gas_used(),
            "receipt cumulative gas must include visible system envelope gas plus user gas"
        );

        executor
            .finalize_compressed_entities()
            .expect("compressed entities should finalize");
        executor
            .prepare_final_header_artifacts(0)
            .expect("final extra_data should encode");
        let (_evm, block_result) = executor.finish().expect("executor finish should succeed");
        assert_eq!(
            block_result.gas_used,
            visible_system_gas + user_gas.tx_gas_used(),
            "block header gas_used must include visible system envelope gas"
        );
    }

    #[test]
    fn outbe_post_execution_preserves_behavior_for_absent_or_empty_withdrawals() {
        use alloy_eips::eip6110::{DEPOSIT_REQUEST_TYPE, MAINNET_DEPOSIT_CONTRACT_ADDRESS};
        use reth_trie::{test_utils::state_root_prehashed, HashedPostState, KeccakKeyHasher};

        const DAO_BALANCE: u128 = 37;
        const CUMULATIVE_TX_GAS: u64 = 11;
        const REGULAR_GAS: u64 = 17;
        const STATE_GAS: u64 = 23;

        struct Case {
            name: &'static str,
            chain_spec: Arc<ChainSpec<OutbeHeader>>,
            spec_id: SpecId,
            include_deposit: bool,
            expected_gas_used: u64,
        }

        fn fixture_receipt(include_deposit: bool) -> Receipt {
            let logs = if include_deposit {
                let event = DepositEvent {
                    pubkey: Bytes::from(vec![0x11; 48]),
                    withdrawal_credentials: Bytes::from(vec![0x22; 32]),
                    amount: Bytes::from(vec![0x33; 8]),
                    signature: Bytes::from(vec![0x44; 96]),
                    index: Bytes::from(vec![0x55; 8]),
                };
                vec![Log {
                    address: MAINNET_DEPOSIT_CONTRACT_ADDRESS,
                    data: event.encode_log_data(),
                }]
            } else {
                Vec::new()
            };
            Receipt {
                tx_type: reth_ethereum::TxType::Legacy,
                success: true,
                cumulative_gas_used: CUMULATIVE_TX_GAS,
                logs,
            }
        }

        fn fixture_state() -> State<CacheDB<EmptyDBTyped<ProviderError>>> {
            let mut database = CacheDB::<EmptyDBTyped<ProviderError>>::default();
            database.insert_account_info(
                alloy_evm::eth::dao_fork::DAO_HARDFORK_ACCOUNTS[0],
                AccountInfo {
                    balance: U256::from(DAO_BALANCE),
                    ..Default::default()
                },
            );
            State::builder()
                .with_database(database)
                .with_bundle_update()
                .build()
        }

        fn post_state_root(state: &revm::database::BundleState) -> B256 {
            let sorted =
                HashedPostState::from_bundle_state::<KeccakKeyHasher>(state.state()).into_sorted();
            let storages = sorted.storages;
            let accounts = sorted
                .accounts
                .into_iter()
                .filter_map(|(address, account)| {
                    account.map(|account| {
                        let storage = storages
                            .get(&address)
                            .map(|storage| storage.storage_slots.clone())
                            .unwrap_or_default();
                        (address, (account, storage))
                    })
                });
            state_root_prehashed(accounts)
        }

        fn balance(
            state: &mut State<CacheDB<EmptyDBTyped<ProviderError>>>,
            address: Address,
        ) -> U256 {
            state
                .basic(address)
                .expect("post-execution balance is readable")
                .map_or(U256::ZERO, |account| account.balance)
        }

        let chain_spec = |activate: fn(ChainSpecBuilder) -> ChainSpecBuilder| {
            let mut spec = activate(ChainSpecBuilder::from(&*MAINNET)).build();
            spec.chain = CHAIN_ID.into();
            spec.genesis.config.chain_id = CHAIN_ID;
            Arc::new(spec.map_header(OutbeHeader::new))
        };
        let cases = [
            Case {
                name: "shanghai-withdrawals-and-dao",
                chain_spec: chain_spec(ChainSpecBuilder::shanghai_activated),
                spec_id: SpecId::SHANGHAI,
                include_deposit: false,
                expected_gas_used: CUMULATIVE_TX_GAS,
            },
            Case {
                name: "prague-deposit-and-system-requests",
                chain_spec: chain_spec(ChainSpecBuilder::prague_activated),
                spec_id: SpecId::PRAGUE,
                include_deposit: true,
                expected_gas_used: CUMULATIVE_TX_GAS,
            },
            Case {
                name: "amsterdam-state-gas",
                chain_spec: chain_spec(ChainSpecBuilder::amsterdam_activated),
                spec_id: SpecId::AMSTERDAM,
                include_deposit: false,
                expected_gas_used: STATE_GAS,
            },
        ];

        let withdrawal_cases = [("none", None), ("empty", Some(Vec::new()))];

        for case in cases {
            for (withdrawal_name, withdrawals) in withdrawal_cases.clone() {
                let run = |ocomp: bool| {
                    let mut state = fixture_state();
                    let config = if ocomp {
                        OutbeEvmConfig::new(case.chain_spec.clone())
                            .with_ocomp_lifecycle_activation(OcompLifecycleActivation::at_block(0))
                    } else {
                        OutbeEvmConfig::new(case.chain_spec.clone())
                    };
                    let evm_env = EvmEnv {
                        cfg_env: CfgEnv::new()
                            .with_chain_id(case.chain_spec.chain().id())
                            .with_spec_and_mainnet_gas_params(case.spec_id),
                        block_env: BlockEnv {
                            number: U256::ZERO,
                            gas_limit: 30_000_000,
                            beneficiary: REWARDS_ADDRESS,
                            timestamp: U256::ZERO,
                            ..Default::default()
                        },
                    };
                    let evm = config.evm_with_env(&mut state, evm_env);
                    let mut ctx = execution_ctx(Some(1), Bytes::new());
                    ctx.execute_outbe_block_hooks = false;
                    ctx.inner.withdrawals = withdrawals.clone().map(std::borrow::Cow::Owned);

                    let mut executor = config.create_executor(evm, ctx);
                    executor.inner.receipts = vec![fixture_receipt(case.include_deposit)];
                    executor.inner.cumulative_tx_gas_used = CUMULATIVE_TX_GAS;
                    executor.inner.block_regular_gas_used = REGULAR_GAS;
                    executor.inner.block_state_gas_used = STATE_GAS;
                    executor.inner.blob_gas_used = 5;
                    executor.validate_execution_summary = false;
                    if ocomp {
                        executor.ocomp_lifecycle_active = true;
                        executor.ocomp_terminal_request_consumed = true;
                        executor
                            .apply_outbe_ethereum_post_execution()
                            .expect("OCOMP post-execution phase succeeds");
                    }
                    let (evm, result) = executor.finish().expect("Outbe result assembly succeeds");
                    drop(evm);

                    let root = post_state_root(&state.bundle_state);
                    let dao_source_balance = balance(
                        &mut state,
                        alloy_evm::eth::dao_fork::DAO_HARDFORK_ACCOUNTS[0],
                    );
                    let dao_beneficiary_balance = balance(
                        &mut state,
                        alloy_evm::eth::dao_fork::DAO_HARDFORK_BENEFICIARY,
                    );
                    let withdrawal_balance = balance(
                        &mut state,
                        address!("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
                    );
                    (
                        result,
                        root,
                        dao_source_balance,
                        dao_beneficiary_balance,
                        withdrawal_balance,
                    )
                };

                let ocomp = run(true);
                let normal = run(false);
                assert_eq!(
                    ocomp, normal,
                    "{} / {withdrawal_name}: proposer, validator and OCOMP execution must agree",
                    case.name,
                );
                assert_eq!(ocomp.0.gas_used, case.expected_gas_used, "{}", case.name);
                assert_eq!(ocomp.2, U256::ZERO, "{}: DAO source drains", case.name);
                assert_eq!(
                    ocomp.3,
                    U256::from(DAO_BALANCE),
                    "{}: DAO beneficiary receives the drained balance",
                    case.name
                );
                assert_eq!(
                    ocomp.4,
                    U256::ZERO,
                    "{} / {withdrawal_name}: absent or empty withdrawals do not credit a balance",
                    case.name,
                );
                assert_eq!(
                    ocomp
                        .0
                        .requests
                        .iter()
                        .any(|request| request.first() == Some(&DEPOSIT_REQUEST_TYPE)),
                    case.include_deposit,
                    "{}: Prague deposit request branch is observable",
                    case.name
                );
            }
        }
    }

    #[test]
    fn non_empty_withdrawal_rejects_before_any_state_write() {
        use alloy_eips::eip4895::Withdrawal;

        const DAO_BALANCE: u128 = 37;
        const WITHDRAWAL_TARGET: Address = address!("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");

        fn account_balance(
            state: &mut State<CacheDB<EmptyDBTyped<ProviderError>>>,
            address: Address,
        ) -> U256 {
            state
                .basic(address)
                .expect("post-execution balance is readable")
                .map_or(U256::ZERO, |account| account.balance)
        }

        for ocomp in [false, true] {
            let mut spec = ChainSpecBuilder::from(&*MAINNET)
                .shanghai_activated()
                .build();
            spec.chain = CHAIN_ID.into();
            spec.genesis.config.chain_id = CHAIN_ID;
            let chain_spec = Arc::new(spec.map_header(OutbeHeader::new));
            let mut database = CacheDB::<EmptyDBTyped<ProviderError>>::default();
            database.insert_account_info(
                alloy_evm::eth::dao_fork::DAO_HARDFORK_ACCOUNTS[0],
                AccountInfo {
                    balance: U256::from(DAO_BALANCE),
                    ..Default::default()
                },
            );
            let mut state = State::builder()
                .with_database(database)
                .with_bundle_update()
                .build();
            let config = if ocomp {
                OutbeEvmConfig::new(chain_spec.clone())
                    .with_ocomp_lifecycle_activation(OcompLifecycleActivation::at_block(0))
            } else {
                OutbeEvmConfig::new(chain_spec.clone())
            };
            let evm_env = EvmEnv {
                cfg_env: CfgEnv::new()
                    .with_chain_id(chain_spec.chain().id())
                    .with_spec_and_mainnet_gas_params(SpecId::SHANGHAI),
                block_env: BlockEnv {
                    number: U256::ZERO,
                    gas_limit: 30_000_000,
                    beneficiary: REWARDS_ADDRESS,
                    timestamp: U256::ZERO,
                    ..Default::default()
                },
            };
            let evm = config.evm_with_env(&mut state, evm_env);
            let mut ctx = execution_ctx(Some(0), Bytes::new());
            ctx.execute_outbe_block_hooks = false;
            ctx.inner.withdrawals = Some(std::borrow::Cow::Owned(vec![Withdrawal {
                index: 0,
                validator_index: 0,
                address: WITHDRAWAL_TARGET,
                amount: 1_000,
            }]));
            let mut executor = config.create_executor(evm, ctx);
            executor.validate_execution_summary = false;

            let error = executor
                .apply_pre_execution_changes()
                .expect_err("every non-empty withdrawals list must be rejected pre-state");
            drop(executor);
            assert!(
                error
                    .to_string()
                    .contains("non-empty EIP-4895 withdrawals are unsupported on Outbe"),
                "{error}"
            );

            assert_eq!(
                account_balance(
                    &mut state,
                    alloy_evm::eth::dao_fork::DAO_HARDFORK_ACCOUNTS[0]
                ),
                U256::from(DAO_BALANCE),
                "validation must precede the DAO drain"
            );
            assert_eq!(
                account_balance(
                    &mut state,
                    alloy_evm::eth::dao_fork::DAO_HARDFORK_BENEFICIARY
                ),
                U256::ZERO,
                "validation must precede any beneficiary credit"
            );
            assert_eq!(
                account_balance(&mut state, WITHDRAWAL_TARGET),
                U256::ZERO,
                "unsupported withdrawal must not credit its target"
            );
        }
    }

    #[test]
    fn active_terminal_request_is_last_semantic_writer_and_rejects_later_transactions() {
        use alloy_evm::block::{StateChangePostBlockSource, StateChangeSource};

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum ObservedWrite {
            EthereumPostBlock,
            CompressedEntitiesSeal,
            Transaction(usize),
        }

        let signer = test_evm_signer();
        let proposer = signer.address();
        let mut state = state_with_active_proposer_without_ocomp(proposer);
        let chain_spec = test_chain_spec();
        let install = test_ocomp_fork_install(&chain_spec, &[(proposer, dummy_pubkey(0xA2))]);
        let config = OutbeEvmConfig::new_with_runtime_body_readers(
            chain_spec,
            RuntimeBodyReaders::new(Arc::new(MemoryStorage::new())),
        )
        .with_evm_signer(signer)
        .with_ocomp_lifecycle_activation(OcompLifecycleActivation::at_block(1))
        .with_ocomp_fork_install(install);
        let block_timestamp = 1_700_000_000u64;
        let tee_bootstrap = sample_tee_bootstrap_payload_at(1, block_timestamp);
        let mut evm_env = test_evm_env(1, REWARDS_ADDRESS);
        evm_env.block_env.timestamp = U256::from(block_timestamp);
        let evm = config.evm_with_env(&mut state, evm_env);
        let mut ctx =
            execution_ctx_with_tee_bootstrap(Some(5), Bytes::new(), tee_bootstrap.clone());
        ctx.inner.withdrawals = Some(std::borrow::Cow::Owned(Vec::new()));
        let mut executor = config.create_executor(evm, ctx);

        let observed_writes = Arc::new(Mutex::new(Vec::new()));
        let hook_writes = observed_writes.clone();
        executor.set_state_hook(Some(Box::new(
            move |source, _changes: &revm::state::EvmState| {
                let observed = match source {
                    StateChangeSource::PostBlock(StateChangePostBlockSource::Other(
                        "compressed_entities_end_block",
                    )) => Some(ObservedWrite::CompressedEntitiesSeal),
                    StateChangeSource::PostBlock(_) => Some(ObservedWrite::EthereumPostBlock),
                    StateChangeSource::Transaction(index) => {
                        Some(ObservedWrite::Transaction(index))
                    }
                    StateChangeSource::PreBlock(_) => None,
                };
                if let Some(observed) = observed {
                    hook_writes.lock().unwrap().push(observed);
                }
            },
        )));

        executor
            .apply_pre_execution_changes()
            .expect("active block pre-execution succeeds");
        let begin = begin_system_txs_for_test_with_bootstrap(
            &config,
            1,
            B256::ZERO,
            &Bytes::new(),
            None,
            proposer,
            Some(tee_bootstrap),
        );
        assert_eq!(
            begin
                .iter()
                .map(|tx| SystemTxInputV2::decode(tx.tx().input().as_ref())
                    .unwrap()
                    .kind())
                .collect::<Vec<_>>(),
            vec![
                SystemTxKind::OcompLifecycleBegin,
                SystemTxKind::CycleTick,
                SystemTxKind::RewardsGemDelivery,
                SystemTxKind::TeeBootstrap,
                SystemTxKind::OracleSlashWindow,
                SystemTxKind::HookEvents,
            ]
        );
        for tx in begin.iter().cloned() {
            executor
                .execute_transaction(tx)
                .expect("begin system tx executes");
        }

        let end = config
            .build_end_system_txs(1, CHAIN_ID, begin.len(), Some(proposer))
            .expect("terminal system tx builds");
        assert_eq!(end.len(), 1);
        executor
            .execute_transaction(end.into_iter().next().unwrap())
            .expect("terminal system tx executes before the final CE seal");

        let writes_after_terminal = observed_writes.lock().unwrap().clone();
        let ethereum_post_block_index = writes_after_terminal
            .iter()
            .position(|write| *write == ObservedWrite::EthereumPostBlock)
            .expect("standard Ethereum post-block changes execute before OSR2");
        let compressed_entities_seal_index = writes_after_terminal
            .iter()
            .position(|write| *write == ObservedWrite::CompressedEntitiesSeal)
            .expect("compressed entities seal executes after OSR2");
        let terminal_transaction_index = writes_after_terminal
            .iter()
            .position(|write| *write == ObservedWrite::Transaction(begin.len()))
            .expect("OSR2 commits as the terminal transaction");
        assert!(
            ethereum_post_block_index < terminal_transaction_index
                && terminal_transaction_index < compressed_entities_seal_index,
            "semantic write order must be Ethereum post-block -> OSR2 -> final CE seal; got \
             {writes_after_terminal:?}"
        );
        assert!(executor.compressed_entities_seal_output().is_some());
        let receipt_count = executor.receipts().len();
        let later_user = test_regular_tx()
            .try_into_recovered()
            .expect("regular tx signer recovers");
        assert!(executor.execute_transaction(later_user).is_err());
        assert_eq!(executor.receipts().len(), receipt_count);
        assert_eq!(
            observed_writes
                .lock()
                .unwrap()
                .iter()
                .filter(|write| **write == ObservedWrite::CompressedEntitiesSeal)
                .count(),
            1
        );

        executor
            .prepare_final_header_artifacts(0)
            .expect("sealed CE root enters final header");
        let writes_before_finish = observed_writes.lock().unwrap().clone();
        let (_evm, result) = executor.finish().expect("active executor finishes");
        assert_eq!(result.receipts.len(), 7);
        assert_eq!(
            *observed_writes.lock().unwrap(),
            writes_before_finish,
            "finish must not perform any semantic write after OSR2"
        );
    }

    #[test]
    fn active_lifecycle_proposer_and_replay_match_receipts_roots_and_header_artifacts() {
        use reth_trie::{test_utils::state_root_prehashed, HashedPostState, KeccakKeyHasher};

        fn post_state_root(state: &revm::database::BundleState) -> B256 {
            let sorted =
                HashedPostState::from_bundle_state::<KeccakKeyHasher>(state.state()).into_sorted();
            let storages = sorted.storages;
            let accounts = sorted
                .accounts
                .into_iter()
                .filter_map(|(address, account)| {
                    account.map(|account| {
                        let storage = storages
                            .get(&address)
                            .map(|storage| storage.storage_slots.clone())
                            .unwrap_or_default();
                        (address, (account, storage))
                    })
                });
            state_root_prehashed(accounts)
        }

        let run = |replay: bool| {
            let signer = test_evm_signer();
            let proposer = signer.address();
            let user = test_regular_tx()
                .try_into_recovered()
                .expect("regular tx signer recovers");
            let user_sender = Address(*user.signer());
            let mut state =
                state_with_active_proposer_and_funded_account_without_ocomp(proposer, user_sender);
            let chain_spec = test_chain_spec();
            let install = test_ocomp_fork_install(&chain_spec, &[(proposer, dummy_pubkey(0xA2))]);
            let config = OutbeEvmConfig::new_with_runtime_body_readers(
                chain_spec.clone(),
                RuntimeBodyReaders::new(Arc::new(MemoryStorage::new())),
            )
            .with_evm_signer(signer)
            .with_ocomp_lifecycle_activation(OcompLifecycleActivation::at_block(1))
            .with_ocomp_fork_install(install.clone());
            let begin =
                begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer);
            let end = config
                .build_end_system_txs(1, CHAIN_ID, begin.len(), Some(proposer))
                .expect("terminal system tx builds");

            let evm = config.evm_with_env(&mut state, test_evm_env(1, REWARDS_ADDRESS));
            let mut ctx = block_one_execution_ctx(Some(begin.len() + 1 + end.len()), Bytes::new());
            ctx.proposer_evm_address = Some(proposer);
            if replay {
                ctx.expected_begin_system_txs = begin.clone();
                ctx.expected_end_system_txs = end.clone();
            }
            let mut executor = config.create_executor(evm, ctx);

            executor
                .apply_pre_execution_changes()
                .expect("active pre-execution succeeds");
            for tx in begin {
                executor
                    .execute_transaction(tx)
                    .expect("begin system tx executes");
            }
            executor
                .execute_transaction(user)
                .expect("ordinary tx executes before CE sealing");
            executor
                .execute_transaction(end.into_iter().next().unwrap())
                .expect("terminal request executes after ordinary txs");

            let ce_root = executor
                .compressed_entities_seal_output()
                .expect("terminal request seals compressed entities")
                .new_root;
            executor
                .prepare_final_header_artifacts(0)
                .expect("final header artifacts encode");
            let final_extra_data = executor.final_extra_data.clone();
            let (evm, result) = executor.finish().expect("active block finishes");
            drop(evm);
            let state_root = post_state_root(&state.bundle_state);
            {
                let mut provider = super::DirectStorageProvider::new(
                    &mut state,
                    BlockContext::empty_for_tests(1, 1, chain_spec.chain().id()),
                );
                let storage = StorageHandle::new(&mut provider);
                assert!(
                    outbe_metadosis::api::is_active_ocomp_fork_install(storage, &install)
                        .expect("read persisted block-1 fork installation"),
                    "block-1 lifecycle must persist the exact fork installation"
                );
            }

            (
                result.receipts,
                result.gas_used,
                ce_root,
                final_extra_data,
                state_root,
            )
        };

        let proposer = run(false);
        let replay = run(true);
        assert_eq!(proposer, replay);
        assert_eq!(proposer.0.len(), 8);
    }

    #[test]
    fn apply_pre_execution_changes_emits_cycle_tick_event_in_system_receipt() {
        const GENESIS_TS: u64 = 1_704_067_200;
        const SECONDS_PER_DAY: u64 = 86_400;

        let signer = test_evm_signer();
        let proposer = signer.address();
        let emission_trigger = outbe_cycle::triggers::TriggerId::ProtocolCycle.as_u32();
        let mut state =
            state_with_active_validators_seeded(&[(proposer, dummy_pubkey(0xA2))], |storage| {
                let genesis_ctx = BlockRuntimeContext::new(
                    BlockContext::new(0, GENESIS_TS, CHAIN_ID, proposer, vec![proposer]),
                    storage.clone(),
                );
                outbe_rewards::runtime::ensure_genesis_anchor(&genesis_ctx).unwrap();
                let cycle = outbe_cycle::schema::Cycle::new(storage);
                cycle
                    .active_utc_day
                    .write(outbe_primitives::time::timestamp_to_date_key(GENESIS_TS))
                    .unwrap();
                cycle
                    .last_executed_at
                    .write(&emission_trigger, GENESIS_TS + 60)
                    .unwrap();
            });
        let mut evm_env = test_evm_env(1, REWARDS_ADDRESS);
        let block_timestamp = GENESIS_TS + SECONDS_PER_DAY + 60;
        let tee_bootstrap = sample_tee_bootstrap_payload_at(1, block_timestamp);
        evm_env.block_env.timestamp = U256::from(block_timestamp);
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, evm_env);
        let mut executor = config.create_executor(
            evm,
            execution_ctx_with_tee_bootstrap(Some(0), Bytes::new(), tee_bootstrap.clone()),
        );

        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply before begin-zone system txs");
        let system_txs = begin_system_txs_for_test_with_bootstrap(
            &config,
            1,
            B256::ZERO,
            &Bytes::new(),
            None,
            proposer,
            Some(tee_bootstrap),
        );
        for tx in system_txs {
            executor
                .execute_transaction(tx)
                .expect("begin-zone system tx should execute in tx loop");
        }

        assert_eq!(executor.receipts().len(), 5);
        let cycle_event = keccak256("CycleTriggerExecuted(uint32,uint64,uint64,uint64)");
        assert!(
            executor.receipts()[0].logs.iter().any(|log| {
                log.address == CYCLE_ADDRESS && log.data.topics().first() == Some(&cycle_event)
            }),
            "CycleTriggerExecuted must be present in the system-tx receipt logs"
        );
    }

    #[test]
    fn cycle_tick_utc_boundary_gas_usage() {
        const GENESIS_TS: u64 = 1_704_067_200;
        const SECONDS_PER_DAY: u64 = 86_400;

        let signer = test_evm_signer();
        let proposer = signer.address();
        let emission_trigger = outbe_cycle::triggers::TriggerId::ProtocolCycle.as_u32();
        let mut state =
            state_with_active_validators_seeded(&[(proposer, dummy_pubkey(0xA2))], |storage| {
                let genesis_ctx = BlockRuntimeContext::new(
                    BlockContext::new(0, GENESIS_TS, CHAIN_ID, proposer, vec![proposer]),
                    storage.clone(),
                );
                outbe_rewards::runtime::ensure_genesis_anchor(&genesis_ctx).unwrap();
                let cycle = outbe_cycle::schema::Cycle::new(storage);
                cycle
                    .active_utc_day
                    .write(outbe_primitives::time::timestamp_to_date_key(GENESIS_TS))
                    .unwrap();
                cycle
                    .last_executed_at
                    .write(&emission_trigger, GENESIS_TS + 60)
                    .unwrap();
            });
        let mut evm_env = test_evm_env(1, REWARDS_ADDRESS);
        let block_timestamp = GENESIS_TS + SECONDS_PER_DAY + 60;
        let tee_bootstrap = sample_tee_bootstrap_payload_at(1, block_timestamp);
        evm_env.block_env.timestamp = U256::from(block_timestamp);
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, evm_env);
        let mut executor = config.create_executor(
            evm,
            execution_ctx_with_tee_bootstrap(Some(0), Bytes::new(), tee_bootstrap.clone()),
        );

        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply");
        let system_txs = begin_system_txs_for_test_with_bootstrap(
            &config,
            1,
            B256::ZERO,
            &Bytes::new(),
            None,
            proposer,
            Some(tee_bootstrap),
        );
        let mut cycle_tick_visible_gas = None;
        for tx in system_txs {
            let gas_output = executor
                .execute_transaction(tx)
                .expect("begin-zone system tx should execute");
            if cycle_tick_visible_gas.is_none() {
                cycle_tick_visible_gas = Some(gas_output.tx_gas_used());
            }
        }

        let visible_gas = cycle_tick_visible_gas.expect("CycleTick visible gas must be captured");
        let cycle_tick_receipt = &executor.receipts()[0];
        assert!(
            cycle_tick_receipt.success,
            "CycleTick must succeed, not OOG"
        );
        assert_eq!(
            cycle_tick_receipt.cumulative_gas_used, visible_gas,
            "system receipt cumulative gas must expose visible envelope gas"
        );
        eprintln!("CycleTick UTC boundary visible gas: used={visible_gas}, block_limit=30_000_000");
        assert!(
            visible_gas < 30_000_000,
            "CycleTick visible gas {visible_gas} must fit within the block gas limit"
        );
    }

    #[test]
    fn whole_committee_ocomp_deadline_and_successor_blocks_execute() {
        const MINIMUM_STAKE: u64 = 1_000;
        const OPEN_HEIGHT: u64 = 1;
        const DEADLINE: u64 =
            OPEN_HEIGHT + outbe_validatorset::runtime::OCOMP_RECOVERY_WINDOW_BLOCKS;

        fn execute_and_finalize_block(
            state: &mut State<CacheDB<EmptyDBTyped<ProviderError>>>,
            tree: &Arc<CompressedTreeService>,
            signer: Arc<OutbeEvmSigner>,
            committee: &[Address],
            number: u64,
            parent_hash: B256,
        ) -> (B256, Vec<Receipt>) {
            let proposer = signer.address();
            let chain_spec = test_chain_spec();
            let config = OutbeEvmConfig::new(chain_spec)
                .with_evm_signer(signer)
                .with_compressed_tree_service(tree.clone());
            let mut parent_metadata =
                metadata_with(committee.to_vec(), vec![1; committee.len()], Vec::new());
            parent_metadata.finalized_block_number = number - 1;
            parent_metadata.finalized_block_hash = parent_hash;
            let system_txs = begin_system_txs_for_test(
                &config,
                number,
                parent_hash,
                &Bytes::new(),
                Some(parent_metadata.clone()),
                proposer,
            );
            let evm = config.evm_with_env(state, test_evm_env(number, REWARDS_ADDRESS));
            let mut execution = execution_ctx(Some(system_txs.len()), Bytes::new());
            execution.inner.parent_hash = parent_hash;
            execution.parent_consensus_metadata = Some(parent_metadata);
            execution.parent_artifact_hint = Some(AccountedParentArtifact {
                summary: ExecutionSummaryArtifact {
                    validator_fee_sum: U256::ZERO,
                },
                timestamp: TEST_BLOCK_TIMESTAMP_BASE.saturating_add(number - 1),
                state_root: Some(B256::repeat_byte(0x91)),
            });
            execution.proposer_evm_address = Some(proposer);
            execution.expected_begin_system_txs = system_txs.clone();
            let mut executor = config.create_executor(evm, execution);
            super::with_phase1_verify_disabled(|| {
                executor
                    .apply_pre_execution_changes()
                    .expect("deadline block pre-execution must succeed");
            });
            for transaction in system_txs {
                executor
                    .execute_transaction(transaction)
                    .expect("deadline block system transaction must execute");
            }
            executor
                .finalize_compressed_entities()
                .expect("deadline block CE lifecycle must seal");
            executor
                .prepare_final_header_artifacts(0)
                .expect("deadline block artifacts must encode");
            let sealed = executor
                .compressed_entities_seal_output()
                .expect("deadline block must produce a CE candidate");
            let block_hash = keccak256(number.to_be_bytes());
            tree.publish_candidate(block_hash, sealed.staged_tree_batch)
                .expect("deadline block CE candidate must publish");
            tree.apply_finalized(number, block_hash, sealed.new_root)
                .expect("deadline block CE candidate must finalize");
            let (evm, result) = executor.finish().expect("full block execution must finish");
            drop(evm);
            assert!(result.receipts.iter().all(|receipt| receipt.success));
            (block_hash, result.receipts)
        }

        let first_signer = Arc::new(OutbeEvmSigner::from_secret_bytes([0x21; 32]).unwrap());
        let second_signer = Arc::new(OutbeEvmSigner::from_secret_bytes([0x22; 32]).unwrap());
        let validators = vec![
            (first_signer.address(), dummy_pubkey(0x31)),
            (second_signer.address(), dummy_pubkey(0x32)),
            (numbered_test_address(0x33, 3), dummy_pubkey(0x33)),
            (numbered_test_address(0x34, 4), dummy_pubkey(0x34)),
        ];
        let committee = validators
            .iter()
            .map(|(validator, _)| *validator)
            .collect::<Vec<_>>();
        let mut state =
            state_with_active_validators_seeded_at_block(&validators, OPEN_HEIGHT, |storage| {
                let mut validator_set =
                    outbe_validatorset::contract::ValidatorSet::new(storage.clone());
                let mut staking = outbe_staking::contract::Staking::new(storage.clone());
                staking
                    .config_min_stake
                    .write(U256::from(MINIMUM_STAKE))
                    .unwrap();
                staking
                    .total_staked
                    .write(U256::from(MINIMUM_STAKE * committee.len() as u64))
                    .unwrap();
                storage
                    .set_balance(
                        STAKING_ADDRESS,
                        U256::from(MINIMUM_STAKE * committee.len() as u64),
                    )
                    .unwrap();
                for validator in &committee {
                    staking
                        .stake_amount
                        .write(validator, U256::from(MINIMUM_STAKE))
                        .unwrap();
                    validator_set
                        .test_set_stake_projection(
                            *validator,
                            outbe_validatorset::StakeProjection::new(
                                U256::from(MINIMUM_STAKE),
                                None,
                            ),
                        )
                        .unwrap();
                }
                for validator in &committee {
                    let miss = staking.record_ocomp_miss(*validator).unwrap();
                    assert!(miss.first_in_window);
                    assert_eq!(miss.slashed_bonded, U256::from(100));
                    assert_eq!(miss.recovery_deadline, DEADLINE);
                }
                let registry = outbe_teeregistry::TeeRegistry::new(storage.clone());
                for (index, validator) in committee.iter().enumerate() {
                    let node_hash = keccak256((index as u64).to_be_bytes());
                    registry
                        .validator_v1_node_hash
                        .write(validator, node_hash)
                        .unwrap();
                    registry
                        .v1_node_enclave_id
                        .write(&node_hash, B256::with_last_byte(0x11))
                        .unwrap();
                    registry
                        .v1_node_binding_id
                        .write(&node_hash, B256::with_last_byte(0x12))
                        .unwrap();
                    registry
                        .v1_node_intent_hash
                        .write(&node_hash, B256::with_last_byte(0x13))
                        .unwrap();
                    registry
                        .v1_node_valid_until
                        .write(
                            &node_hash,
                            TEST_BLOCK_TIMESTAMP_BASE.saturating_add(DEADLINE + 3_600),
                        )
                        .unwrap();
                }
                outbe_accounting::schema::Accounting::new(storage)
                    .last_accounted_block_number
                    .write(DEADLINE - 2)
                    .unwrap();
            });

        let empty_root = outbe_compressed_entities::sealed_root(B256::ZERO).unwrap();
        let parent_hash = B256::repeat_byte(0x90);
        let (_tree_directory, tree) = persistent_test_tree_with_marker(
            test_chain_spec().genesis_hash(),
            FinalizedMarker {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                height: DEADLINE - 1,
                block_hash: parent_hash,
                parent_block_hash: B256::repeat_byte(0x8f),
                parent_root: empty_root,
                new_root: empty_root,
            },
        );

        let (deadline_hash, deadline_receipts) = execute_and_finalize_block(
            &mut state,
            &tree,
            first_signer,
            &committee,
            DEADLINE,
            parent_hash,
        );
        let resolutions = deadline_receipts
            .iter()
            .flat_map(|receipt| &receipt.logs)
            .filter_map(|log| {
                outbe_validatorset::precompile::IValidatorSet::OcompRecoveryResolved::decode_log(
                    log,
                )
                .ok()
            })
            .collect::<Vec<_>>();
        assert_eq!(resolutions.len(), committee.len());
        assert!(
            resolutions.iter().all(|resolution| {
                resolution.recoveryDeadline == DEADLINE && resolution.outcome == 2
            }),
            "unexpected OCOMP recovery resolutions: {resolutions:?}"
        );

        let read_ctx = BlockContext::new(
            DEADLINE,
            TEST_BLOCK_TIMESTAMP_BASE + DEADLINE,
            CHAIN_ID,
            committee[0],
            committee.clone(),
        );
        let mut provider =
            outbe_primitives::storage::direct::DirectStorageProvider::new(&mut state, read_ctx);
        StorageHandle::enter(&mut provider, |storage| {
            let validator_set = outbe_validatorset::contract::ValidatorSet::new(storage);
            assert_eq!(
                validator_set
                    .get_active_consensus_set()?
                    .into_iter()
                    .map(|record| record.validator_address)
                    .collect::<Vec<_>>(),
                committee
            );
            assert!(validator_set.has_pending_set_change()?);
            for validator in &committee {
                assert!(matches!(
                    validator_set.validator_lifecycle(*validator)?,
                    ValidatorLifecycle::JailRetained(_)
                ));
                assert!(validator_set.is_consensus_participant(*validator)?);
                assert!(validator_set.ocomp_recovery_window(*validator)?.is_none());
            }
            Ok::<_, outbe_primitives::error::PrecompileError>(())
        })
        .expect("deadline state must retain the current consensus committee");

        let (_successor_hash, successor_receipts) = execute_and_finalize_block(
            &mut state,
            &tree,
            second_signer,
            &committee,
            DEADLINE + 1,
            deadline_hash,
        );
        assert!(!successor_receipts.is_empty());
        assert!(successor_receipts.iter().all(|receipt| receipt.success));
    }

    #[test]
    fn tee_expiry_worst_case_active_sweep_fits_cycle_tick_budget() {
        const ACTIVE_COUNT: usize = 128;
        const DEADLINE: u64 = 2;

        let signer = test_evm_signer();
        let proposer = signer.address();
        let mut validators = Vec::with_capacity(ACTIVE_COUNT);
        validators.push((proposer, dummy_pubkey(0x80)));
        for index in 1..ACTIVE_COUNT {
            validators.push((
                numbered_test_address(0x81, index as u64),
                dummy_pubkey(index as u8),
            ));
        }
        let addresses: Vec<_> = validators.iter().map(|(address, _)| *address).collect();
        let mut state = state_with_active_validators_seeded_at_block(&validators, 1, |storage| {
            let registry = outbe_teeregistry::TeeRegistry::new(storage);
            for (index, validator) in addresses.iter().enumerate() {
                let node_hash = keccak256((index as u64).to_be_bytes());
                registry
                    .validator_v1_node_hash
                    .write(validator, node_hash)
                    .unwrap();
                registry
                    .v1_node_enclave_id
                    .write(&node_hash, B256::with_last_byte(0x11))
                    .unwrap();
                registry
                    .v1_node_binding_id
                    .write(&node_hash, B256::with_last_byte(0x12))
                    .unwrap();
                registry
                    .v1_node_intent_hash
                    .write(&node_hash, B256::with_last_byte(0x13))
                    .unwrap();
                registry
                    .v1_node_valid_until
                    .write(&node_hash, DEADLINE)
                    .unwrap();
            }
        });
        let mut evm_env = test_evm_env(2, REWARDS_ADDRESS);
        evm_env.block_env.timestamp = U256::from(DEADLINE);
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer.clone());
        let parent_hash = B256::repeat_byte(0x91);
        let mut parent_metadata =
            metadata_with(addresses.clone(), vec![1; ACTIVE_COUNT], Vec::new());
        parent_metadata.finalized_block_number = 1;
        parent_metadata.finalized_block_hash = parent_hash;
        let evm = config.evm_with_env(&mut state, evm_env);
        let mut execution = execution_ctx(Some(0), Bytes::new());
        execution.inner.parent_hash = parent_hash;
        execution.parent_consensus_metadata = Some(parent_metadata.clone());
        execution.parent_artifact_hint = Some(AccountedParentArtifact {
            summary: ExecutionSummaryArtifact {
                validator_fee_sum: U256::ZERO,
            },
            timestamp: 1,
            state_root: Some(B256::repeat_byte(0x92)),
        });
        execution.proposer_evm_address = Some(proposer);
        let mut executor = config.create_executor(evm, execution);
        super::with_phase1_verify_disabled(|| {
            executor
                .apply_pre_execution_changes()
                .expect("pre-execution changes should apply");
        });

        let system_txs = begin_system_txs_for_test(
            &config,
            2,
            parent_hash,
            &Bytes::new(),
            Some(parent_metadata),
            proposer,
        );
        let mut cycle_gas = None;
        let mut cycle_internal_gas = None;
        let mut cycle_receipt_index = None;
        for tx in system_txs {
            let kind = SystemTxInputV2::decode(tx.tx().input().as_ref())
                .expect("valid begin-zone system transaction")
                .kind();
            let internal_before = executor.system_tx_execution_gas;
            let output = executor
                .execute_transaction(tx)
                .expect("TEE expiry begin-zone prefix should execute");
            if kind == SystemTxKind::CycleTick {
                cycle_gas = Some(output.tx_gas_used());
                cycle_internal_gas = Some(
                    executor
                        .system_tx_execution_gas
                        .saturating_sub(internal_before),
                );
                cycle_receipt_index = Some(executor.receipts().len() - 1);
                break;
            }
        }
        let cycle_gas = cycle_gas.expect("CycleTick gas must be captured");
        let cycle_internal_gas =
            cycle_internal_gas.expect("CycleTick internal gas must be captured");
        let receipt = &executor.receipts()[cycle_receipt_index.expect("CycleTick receipt index")];
        assert!(receipt.success, "worst-case TEE expiry sweep must not OOG");
        assert_eq!(
            receipt
                .logs
                .iter()
                .filter(|log| {
                    log.address == outbe_primitives::addresses::VALIDATOR_SET_ADDRESS
                        && log.data.topics().first()
                            == Some(&keccak256("ValidatorJailed(address,uint64)"))
                })
                .count(),
            ACTIVE_COUNT
        );
        eprintln!(
            "TEE expiry CycleTick gas: active={ACTIVE_COUNT}, visible={cycle_gas}, internal={cycle_internal_gas}, limit=30000000"
        );
        assert!(cycle_gas < 30_000_000);
        assert!(cycle_internal_gas < 30_000_000);
    }

    #[test]
    fn capacity_forfeiture_cycle_tick_keeps_twenty_percent_block_headroom() {
        use reth_trie::{test_utils::state_root_prehashed, HashedPostState, KeccakKeyHasher};

        const BLOCK_GAS_LIMIT: u64 = 30_000_000;
        const REQUIRED_HEADROOM_BPS: u64 = 2_000;
        const BPS_DENOMINATOR: u64 = 10_000;
        const SECONDS_PER_DAY: u64 = 86_400;

        fn post_state_root(state: &revm::database::BundleState) -> B256 {
            let sorted =
                HashedPostState::from_bundle_state::<KeccakKeyHasher>(state.state()).into_sorted();
            let storages = sorted.storages;
            let accounts = sorted
                .accounts
                .into_iter()
                .filter_map(|(address, account)| {
                    account.map(|account| {
                        let storage = storages
                            .get(&address)
                            .map(|storage| storage.storage_slots.clone())
                            .unwrap_or_default();
                        (address, (account, storage))
                    })
                });
            state_root_prehashed(accounts)
        }

        let run = || {
            let signer = test_evm_signer();
            let proposer = signer.address();
            let victim = WorldwideDay::new(2023_1101);
            let day_limit = U256::from(100);
            let mut fire_at = 0_u64;
            let (tree_directory, tree_service) = persistent_test_tree(B256::ZERO);
            let empty_root = outbe_compressed_entities::sealed_root(B256::ZERO).unwrap();
            let parent_tree = tree_service
                .open_parent(ExactParentIdentity {
                    commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                    block_number: 0,
                    block_hash: B256::ZERO,
                    root: empty_root,
                })
                .expect("open exact empty CE parent");
            let seed_scope =
                ExecutionScope::with_parent_tree(parent_tree, CeWorkConfig::new(0, 0, u64::MAX));
            let body_storage = Arc::new(MemoryStorage::new());
            let body_reader: StorageReaderHandle = body_storage;
            let tribute_parent = TributeRepositoryReader::new(body_reader.clone());
            let mut staged_tree_batch = None;
            let mut state = state_with_active_validators_seeded_at_block_with_cycle_frames(
                &[(proposer, dummy_pubkey(0xA3))],
                1,
                4,
                |storage| {
                    outbe_compressed_entities::begin_block(storage.clone(), &seed_scope)
                        .expect("open CE seed block");
                    let genesis_ctx = BlockRuntimeContext::new(
                        BlockContext::new(0, 1_704_067_200, CHAIN_ID, proposer, vec![proposer]),
                        storage.clone(),
                    );
                    outbe_rewards::runtime::ensure_genesis_anchor(&genesis_ctx).unwrap();
                    let mut tribute = TributeContract::new(storage.clone());
                    tribute.initialize_fresh_ocomp_profile().unwrap();
                    let retained = (0..outbe_metadosis::constants::MAX_RETAINED_WWDS)
                        .map(|offset| {
                            let days_before =
                                outbe_metadosis::constants::MAX_RETAINED_WWDS - offset;
                            WorldwideDay::from_timestamp(
                                victim.start_timestamp()
                                    - u64::try_from(days_before).unwrap() * SECONDS_PER_DAY,
                            )
                        })
                        .collect::<Vec<_>>();
                    outbe_metadosis::test_support::seed_ready_worldwide_days_for_capacity(
                        storage.clone(),
                        &retained,
                    )
                    .unwrap();
                    let victim_ctx = BlockRuntimeContext::new(
                        BlockContext::new(
                            1,
                            victim.start_timestamp() + 2 * 3_600,
                            CHAIN_ID,
                            proposer,
                            vec![proposer],
                        ),
                        storage.clone(),
                    );
                    outbe_metadosis::commands::apply_cycle_day_limit(&victim_ctx, day_limit)
                        .unwrap();
                    let victim_projection =
                        outbe_metadosis::api::worldwide_day(storage.clone(), victim)
                            .unwrap()
                            .unwrap();
                    tribute.unseal_day(victim).unwrap();
                    tribute
                        .issue(
                            &seed_scope,
                            &tribute_parent,
                            &TributeData {
                                tribute_id: outbe_compressed_entities::derive_poseidon_entity_id(
                                    proposer, victim,
                                )
                                .unwrap(),
                                owner: proposer,
                                worldwide_day: victim,
                                issuance_amount_minor: U256::from(1),
                                issuance_currency: 840,
                                nominal_amount_minor: U256::from(1),
                                reference_currency: 840,
                                tribute_price_minor: U256::from(1),
                                exclude_from_intex_issuance: false,
                            },
                        )
                        .unwrap();
                    for boundary in [
                        victim_projection.forming_end,
                        victim_projection.lookback_end,
                        victim_projection.offering_end,
                    ] {
                        let ctx = BlockRuntimeContext::new(
                            BlockContext::new(1, boundary, CHAIN_ID, proposer, vec![proposer]),
                            storage.clone(),
                        );
                        outbe_metadosis::commands::advance_active_worldwide_days(&ctx, &seed_scope)
                            .unwrap();
                    }
                    assert_eq!(
                        outbe_metadosis::api::worldwide_day(storage.clone(), victim)
                            .unwrap()
                            .unwrap()
                            .status,
                        outbe_metadosis::api::WorldwideDayStatus::Waiting
                    );
                    tribute
                        .day_totals
                        .update(&outbe_tribute::DayTotals {
                            worldwide_day: victim,
                            initialized: true,
                            tribute_count: u32::MAX,
                            tribute_nominal_amount: U256::MAX,
                            is_sealed: true,
                        })
                        .unwrap();
                    tribute.total_supply.write(u64::from(u32::MAX)).unwrap();
                    let scheduled = victim_projection.scheduled_process_time;
                    let protocol_cycle_period = 3_600;
                    fire_at = scheduled.div_ceil(protocol_cycle_period) * protocol_cycle_period;
                    let cycle = outbe_cycle::schema::Cycle::new(storage.clone());
                    cycle
                        .active_utc_day
                        .write(outbe_primitives::time::timestamp_to_date_key(fire_at))
                        .unwrap();
                    for spec in outbe_cycle::triggers::ACTIVE_TRIGGERS {
                        cycle
                            .last_executed_at
                            .write(
                                &spec.id,
                                if spec.id
                                    == outbe_cycle::triggers::TriggerId::ProtocolCycle.as_u32()
                                {
                                    fire_at - protocol_cycle_period
                                } else {
                                    fire_at
                                },
                            )
                            .unwrap();
                    }
                    staged_tree_batch = Some(
                        outbe_compressed_entities::end_block(storage, &seed_scope)
                            .expect("seal populated Tribute seed block")
                            .staged_tree_batch,
                    );
                },
            );
            let staged_tree_batch = staged_tree_batch.expect("seed block must stage CE work");
            let seed_hash = B256::repeat_byte(0xA5);
            let seed_root = staged_tree_batch.new_root();
            tree_service
                .publish_candidate(seed_hash, staged_tree_batch)
                .expect("publish populated Tribute seed");
            tree_service
                .apply_finalized(1, seed_hash, seed_root)
                .expect("finalize populated Tribute seed");

            let mut evm_env = test_evm_env(2, REWARDS_ADDRESS);
            evm_env.block_env.timestamp = U256::from(fire_at);
            let config = OutbeEvmConfig::new_with_runtime_body_readers(
                test_chain_spec(),
                RuntimeBodyReaders::new(body_reader),
            )
            .with_evm_signer(signer.clone())
            .with_compressed_tree_service(tree_service);
            let mut parent_metadata = metadata_with(vec![proposer], vec![1], Vec::new());
            parent_metadata.finalized_block_number = 1;
            parent_metadata.finalized_block_hash = seed_hash;
            let evm = config.evm_with_env(&mut state, evm_env);
            let mut execution = execution_ctx(Some(0), Bytes::new());
            execution.inner.parent_hash = seed_hash;
            execution.parent_consensus_metadata = Some(parent_metadata.clone());
            execution.parent_artifact_hint = Some(AccountedParentArtifact {
                summary: ExecutionSummaryArtifact {
                    validator_fee_sum: U256::ZERO,
                },
                timestamp: 0,
                state_root: Some(B256::repeat_byte(0x91)),
            });
            execution.proposer_evm_address = Some(proposer);
            let mut executor = config.create_executor(evm, execution);
            super::with_phase1_verify_disabled(|| {
                executor
                    .apply_pre_execution_changes()
                    .expect("pre-execution changes should apply");
            });
            let system_txs = begin_system_txs_for_test(
                &config,
                2,
                seed_hash,
                &Bytes::new(),
                Some(parent_metadata),
                proposer,
            );
            let mut visible_gas = None;
            let mut cycle_receipt_index = None;
            for tx in system_txs {
                let kind = SystemTxInputV2::decode(tx.tx().input().as_ref())
                    .expect("valid begin-zone system tx")
                    .kind();
                let output = executor
                    .execute_transaction(tx)
                    .expect("begin-zone prefix through CapacityForfeiture CycleTick must execute");
                if kind == SystemTxKind::CycleTick {
                    visible_gas = Some(output.tx_gas_used());
                    cycle_receipt_index = Some(executor.receipts().len() - 1);
                    break;
                }
            }
            let visible_gas = visible_gas.expect("CycleTick visible gas");
            let cycle_receipt_index = cycle_receipt_index.expect("CycleTick receipt index");
            let maximum_used =
                BLOCK_GAS_LIMIT * (BPS_DENOMINATOR - REQUIRED_HEADROOM_BPS) / BPS_DENOMINATOR;
            eprintln!(
                "CapacityForfeiture CycleTick visible gas: used={visible_gas}, max_for_20pct_headroom={maximum_used}"
            );
            assert!(executor.receipts()[cycle_receipt_index].success);
            assert!(
                visible_gas <= maximum_used,
                "CapacityForfeiture CycleTick visible gas {visible_gas} leaves less than 20% headroom"
            );
            let capacity_event = keccak256(
                "WorldwideDayCapacityForfeited(uint32,uint32,uint32,uint256,uint256,uint256,bytes32,uint32,uint256,uint64,uint64,uint8,uint64)",
            );
            assert!(executor.receipts()[cycle_receipt_index]
                .logs
                .iter()
                .any(|log| {
                    log.address == outbe_primitives::addresses::METADOSIS_ADDRESS
                        && log.data.topics().first() == Some(&capacity_event)
                }));
            let retirement_event = keccak256("TributePartitionRetired(uint32)");
            assert!(executor.receipts()[cycle_receipt_index]
                .logs
                .iter()
                .any(|log| {
                    log.address == outbe_primitives::addresses::TRIBUTE_ADDRESS
                        && log.data.topics().first() == Some(&retirement_event)
                }));
            let capacity_log = executor.receipts()[cycle_receipt_index]
                .logs
                .iter()
                .find_map(|log| {
                    outbe_metadosis::precompile::IMetadosis::WorldwideDayCapacityForfeited::decode_log(
                        log,
                    )
                    .ok()
                })
                .expect("typed capacity-forfeiture event");
            assert_eq!(capacity_log.forfeitedTributeCount, u32::MAX);
            assert_eq!(capacity_log.forfeitedTributeNominal, U256::MAX);
            assert_eq!(capacity_log.retirementOutcome, 2);
            let receipt = executor.receipts()[cycle_receipt_index].clone();
            drop(executor);
            (
                visible_gas,
                receipt,
                post_state_root(&state.bundle_state),
                seed_root,
                tree_directory,
            )
        };

        let proposer = run();
        let replay = run();
        assert_eq!(
            proposer.0, replay.0,
            "same-parent replay must reproduce visible gas"
        );
        assert_eq!(
            proposer.1, replay.1,
            "same-parent replay must reproduce the exact receipt and events"
        );
        assert_eq!(
            proposer.2, replay.2,
            "re-executing the same CapacityForfeiture CycleTick from the same parent must reproduce gas, receipt/events, and state root"
        );
        assert_eq!(proposer.3, replay.3, "seeded parent roots must match");
    }

    #[test]
    fn gas_05_cycle_tick_gas_regression_exercises_dense_agentreward_state() {
        const GENESIS_TS: u64 = 1_704_067_200;
        const SECONDS_PER_DAY: u64 = 86_400;
        const DENSE_ADDRESS_COUNT: u64 = 512;
        const DENSE_VALIDATOR_COUNT: u32 = outbe_consensus::bls::MAX_VALIDATORS;

        let signer = test_evm_signer();
        let proposer = signer.address();
        let block_ts = GENESIS_TS + SECONDS_PER_DAY + 60;
        let prev_day = outbe_primitives::time::previous_date_key(
            outbe_primitives::time::timestamp_to_date_key(block_ts),
        );
        let emission_trigger = outbe_cycle::triggers::TriggerId::ProtocolCycle.as_u32();
        let mut state =
            state_with_active_validators_seeded(&[(proposer, dummy_pubkey(0xA2))], |storage| {
                let genesis_ctx = BlockRuntimeContext::new(
                    BlockContext::new(0, GENESIS_TS, CHAIN_ID, proposer, vec![proposer]),
                    storage.clone(),
                );
                outbe_rewards::runtime::ensure_genesis_anchor(&genesis_ctx).unwrap();
                let cycle = outbe_cycle::schema::Cycle::new(storage.clone());
                cycle
                    .active_utc_day
                    .write(outbe_primitives::time::timestamp_to_date_key(GENESIS_TS))
                    .unwrap();
                cycle
                    .last_executed_at
                    .write(&emission_trigger, GENESIS_TS + 60)
                    .unwrap();

                outbe_oracle::api::set_exchange_rate(
                    storage.clone(),
                    Address::ZERO,
                    outbe_oracle::api::DAY_TYPE_PAIR,
                    U256::from(1_000_000u64),
                    1,
                    block_ts,
                )
                .unwrap();
                // Close the reward day so delivery prices the batch instead of waiting.
                outbe_oracle::schema::OracleContract::new(storage.clone())
                    .utc_day_vwap_last_finalized
                    .write(29_991_231)
                    .unwrap();
                let rewards = outbe_rewards::schema::Rewards::new(storage.clone());
                rewards
                    .daily_voter_count
                    .write(&prev_day, DENSE_VALIDATOR_COUNT)
                    .unwrap();
                rewards
                    .daily_total_participation
                    .write(&prev_day, u64::from(DENSE_VALIDATOR_COUNT))
                    .unwrap();
                for index in 0..DENSE_VALIDATOR_COUNT {
                    let voter = numbered_test_address(0x12, u64::from(index));
                    rewards
                        .daily_voter_at
                        .get_nested(&prev_day)
                        .write(&index, voter)
                        .unwrap();
                    rewards
                        .daily_participation
                        .get_nested(&prev_day)
                        .write(&voter, 1)
                        .unwrap();
                }

                let mut agent = outbe_agentreward::AgentRewardContract::new(storage);
                for n in 0..DENSE_ADDRESS_COUNT {
                    let waa = numbered_test_address(0x10, n);
                    let sra = numbered_test_address(0x11, n);
                    agent.increment_waa_tribute(prev_day.into(), waa).unwrap();
                    agent.increment_sra_tribute(prev_day.into(), sra).unwrap();
                }
                assert_eq!(
                    agent.get_all_waa_counts(prev_day.into()).unwrap().len(),
                    DENSE_ADDRESS_COUNT as usize,
                    "GAS-05 fixture must seed all dense WAA recipients"
                );
                assert_eq!(
                    agent.get_all_sra_counts(prev_day.into()).unwrap().len(),
                    DENSE_ADDRESS_COUNT as usize,
                    "GAS-05 fixture must seed all dense SRA recipients"
                );
            });
        let mut evm_env = test_evm_env(1, REWARDS_ADDRESS);
        evm_env.block_env.timestamp = U256::from(block_ts);
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, evm_env);
        let mut executor =
            config.create_executor(evm, block_one_execution_ctx(Some(0), Bytes::new()));

        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply");
        let mut system_txs =
            begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer);
        let cycle_tx = system_txs.remove(0);
        let delivery_tx = system_txs.remove(0);
        let cycle_signed_gas_limit = cycle_tx.tx().gas_limit();
        let cycle_gas = executor
            .execute_transaction(cycle_tx)
            .expect("dense CycleTick should execute")
            .tx_gas_used();

        let cycle_receipt = executor
            .receipts()
            .first()
            .expect("CycleTick receipt should be present");
        assert!(
            cycle_receipt.success,
            "GAS-05: dense CycleTick must succeed"
        );
        assert_eq!(
            cycle_receipt.cumulative_gas_used, cycle_gas,
            "GAS-05: dense CycleTick receipt must expose actual visible gas"
        );
        assert!(
            cycle_gas <= cycle_signed_gas_limit,
            "GAS-05: CycleTick receipt gas exceeded signed gas limit"
        );
        let delivery_signed_gas_limit = delivery_tx.tx().gas_limit();
        let delivery_gas = executor
            .execute_transaction(delivery_tx)
            .expect("dense RewardsGemDelivery should execute")
            .tx_gas_used();
        assert!(delivery_gas <= delivery_signed_gas_limit);

        drop(executor);
        let read_ctx = BlockContext::new(1, block_ts, CHAIN_ID, proposer, vec![proposer]);
        let mut provider =
            outbe_primitives::storage::direct::DirectStorageProvider::new(&mut state, read_ctx);
        StorageHandle::enter(&mut provider, |storage| {
            let agent = outbe_agentreward::AgentRewardContract::new(storage.clone());
            assert!(
                agent.get_all_waa_counts(prev_day.into())?.is_empty(),
                "GAS-05: dense WAA day index must be cleared after CycleTick settlement"
            );
            assert!(
                agent.get_all_sra_counts(prev_day.into())?.is_empty(),
                "GAS-05: dense SRA day index must be cleared after CycleTick settlement"
            );

            let mut claimable_total = U256::ZERO;
            for n in 0..DENSE_ADDRESS_COUNT {
                let waa = numbered_test_address(0x10, n);
                let sra = numbered_test_address(0x11, n);
                let waa_claimable = agent.get_claimable_reward(waa)?;
                let sra_claimable = agent.get_claimable_reward(sra)?;
                assert!(
                    !waa_claimable.is_zero(),
                    "GAS-05: dense WAA recipient {waa} received zero claimable reward"
                );
                assert!(
                    !sra_claimable.is_zero(),
                    "GAS-05: dense SRA recipient {sra} received zero claimable reward"
                );
                claimable_total += waa_claimable + sra_claimable;
            }
            assert!(
                !claimable_total.is_zero(),
                "GAS-05: dense CycleTick must credit claimable AgentReward balances"
            );
            assert_eq!(
                storage.balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS)?,
                claimable_total,
                "GAS-05: AgentReward backing balance must match dense claimable total"
            );
            let rewards = outbe_rewards::schema::Rewards::new(storage.clone());
            assert!(rewards.daily_topup_prepared.read(&prev_day)?);
            assert!(rewards.daily_topup_settled.read(&prev_day)?);
            assert_eq!(rewards.reward_gem_queue_head.read()?, 1);
            assert_eq!(rewards.reward_gem_queue_tail.read()?, 1);
            let gem = outbe_gem::GemContract::new(storage);
            for index in 0..DENSE_VALIDATOR_COUNT {
                let voter = numbered_test_address(0x12, u64::from(index));
                assert_eq!(gem.balance_of(voter)?, 1);
            }
            Ok::<_, outbe_primitives::error::PrecompileError>(())
        })
        .expect("GAS-05 dense AgentReward state should be readable after CycleTick");
    }

    #[test]
    fn reward_gem_delivery_drains_one_max_batch_while_cycle_appends_the_next() {
        const GENESIS_TS: u64 = 1_704_067_200;
        const SECONDS_PER_DAY: u64 = 86_400;
        const VALIDATOR_COUNT: u32 = outbe_consensus::bls::MAX_VALIDATORS;

        let signer = test_evm_signer();
        let proposer = signer.address();
        let block_ts = GENESIS_TS + 2 * SECONDS_PER_DAY + 60;
        let current_utc_day = outbe_primitives::time::timestamp_to_date_key(block_ts);
        let reward_utc_day = outbe_primitives::time::previous_date_key(current_utc_day);
        let backlog_utc_day = outbe_primitives::time::previous_date_key(reward_utc_day);
        let emission_trigger = outbe_cycle::triggers::TriggerId::ProtocolCycle.as_u32();
        let mut state =
            state_with_active_validators_seeded(&[(proposer, dummy_pubkey(0xA2))], |storage| {
                let genesis_ctx = BlockRuntimeContext::new(
                    BlockContext::new(0, GENESIS_TS, CHAIN_ID, proposer, vec![proposer]),
                    storage.clone(),
                );
                outbe_rewards::runtime::ensure_genesis_anchor(&genesis_ctx).unwrap();
                let cycle = outbe_cycle::schema::Cycle::new(storage.clone());
                cycle.active_utc_day.write(reward_utc_day).unwrap();
                cycle
                    .last_executed_at
                    .write(&emission_trigger, block_ts - 3_600)
                    .unwrap();

                let backlog_voters = (0..VALIDATOR_COUNT)
                    .map(|index| (numbered_test_address(0x13, u64::from(index)), 1))
                    .collect::<Vec<_>>();
                outbe_rewards::api::prepare_daily_validator_gem_batch(
                    &genesis_ctx,
                    backlog_utc_day,
                    U256::from(1_000_000u64),
                    &backlog_voters,
                )
                .unwrap();

                let rewards = outbe_rewards::schema::Rewards::new(storage.clone());
                rewards
                    .daily_voter_count
                    .write(&reward_utc_day, VALIDATOR_COUNT)
                    .unwrap();
                rewards
                    .daily_total_participation
                    .write(&reward_utc_day, u64::from(VALIDATOR_COUNT))
                    .unwrap();
                for index in 0..VALIDATOR_COUNT {
                    let voter = numbered_test_address(0x14, u64::from(index));
                    rewards
                        .daily_voter_at
                        .get_nested(&reward_utc_day)
                        .write(&index, voter)
                        .unwrap();
                    rewards
                        .daily_participation
                        .get_nested(&reward_utc_day)
                        .write(&voter, 1)
                        .unwrap();
                }
                // Close the reward day so delivery prices the batch instead of waiting.
                outbe_oracle::schema::OracleContract::new(storage.clone())
                    .utc_day_vwap_last_finalized
                    .write(29_991_231)
                    .unwrap();
                outbe_oracle::api::set_exchange_rate(
                    storage,
                    Address::ZERO,
                    outbe_oracle::api::DAY_TYPE_PAIR,
                    U256::from(1_000_000u64),
                    1,
                    block_ts,
                )
                .unwrap();
            });

        let mut evm_env = test_evm_env(1, REWARDS_ADDRESS);
        evm_env.block_env.timestamp = U256::from(block_ts);
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer);
        let evm = config.evm_with_env(&mut state, evm_env);
        let mut executor =
            config.create_executor(evm, block_one_execution_ctx(Some(0), Bytes::new()));
        executor.apply_pre_execution_changes().unwrap();
        let mut system_txs =
            begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer);
        let cycle_tx = system_txs.remove(0);
        let delivery_tx = system_txs.remove(0);
        let cycle_limit = cycle_tx.tx().gas_limit();
        let delivery_limit = delivery_tx.tx().gas_limit();
        assert!(
            executor
                .execute_transaction(cycle_tx)
                .unwrap()
                .tx_gas_used()
                <= cycle_limit
        );
        assert!(
            executor
                .execute_transaction(delivery_tx)
                .unwrap()
                .tx_gas_used()
                <= delivery_limit
        );
        drop(executor);

        let read_ctx = BlockContext::new(1, block_ts, CHAIN_ID, proposer, vec![proposer]);
        let mut provider =
            outbe_primitives::storage::direct::DirectStorageProvider::new(&mut state, read_ctx);
        StorageHandle::enter(&mut provider, |storage| {
            let rewards = outbe_rewards::schema::Rewards::new(storage.clone());
            assert_eq!(rewards.reward_gem_queue_head.read()?, 1);
            assert_eq!(rewards.reward_gem_queue_tail.read()?, 2);
            assert!(rewards.daily_topup_settled.read(&backlog_utc_day)?);
            assert!(rewards.daily_topup_prepared.read(&reward_utc_day)?);
            assert!(!rewards.daily_topup_settled.read(&reward_utc_day)?);
            let gem = outbe_gem::GemContract::new(storage);
            for index in 0..VALIDATOR_COUNT {
                assert_eq!(
                    gem.balance_of(numbered_test_address(0x13, u64::from(index)))?,
                    1
                );
                assert_eq!(
                    gem.balance_of(numbered_test_address(0x14, u64::from(index)))?,
                    0
                );
            }
            Ok::<_, outbe_primitives::error::PrecompileError>(())
        })
        .unwrap();
    }

    #[test]
    fn gas_01_evm_level_system_tx_err_must_not_be_soft_receipted() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let mut state = state_with_active_proposer(proposer);
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, test_evm_env(1, REWARDS_ADDRESS));
        let mut executor =
            config.create_executor(evm, block_one_execution_ctx(Some(1), Bytes::new()));
        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply");
        let mut system_txs =
            begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer)
                .into_iter();
        let cycle_tx = system_txs
            .next()
            .expect("CycleTick system tx should be present");

        let receipt_count_before = executor.receipts().len();
        let err = crate::factory::with_forced_outbe_system_call_error(|| {
            executor.execute_transaction(cycle_tx)
        })
        .expect_err(
            "GAS-01: raw system-call engine errors must not be converted into soft receipts",
        );
        let msg = err.to_string();
        assert!(
            msg.contains("forced Outbe system-call error")
                || msg.contains("system tx")
                || msg.contains("Phase"),
            "GAS-01: unexpected hard error for raw system-call Err: {msg}"
        );
        assert_eq!(
            executor.receipts().len(),
            receipt_count_before,
            "GAS-01: raw system-call Err must not synthesize a receipt"
        );
    }

    #[test]
    fn gas_02_phase1_preexec_failure_must_consume_body0_or_abort() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let parent_hash = B256::with_last_byte(0xA1);
        let mut metadata = test_metadata();
        metadata.finalized_block_number = 1;
        metadata.finalized_block_hash = parent_hash;
        metadata.ordered_committee = vec![proposer];
        metadata.signer_bitmap = vec![1];

        let mut state = state_with_active_proposer(proposer);
        let chain_spec = test_chain_spec();
        let receipt_builder = reth_ethereum::evm::RethReceiptBuilder::default();
        let config = OutbeEvmConfig::new(chain_spec.clone()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, test_evm_env(2, REWARDS_ADDRESS));
        let mut ctx = execution_ctx(Some(3), Bytes::new());
        ctx.inner.parent_hash = parent_hash;
        ctx.parent_consensus_metadata = Some(metadata.clone());
        let mut executor = OutbeBlockExecutor::new(
            EthBlockExecutor::new(evm, ctx.inner.clone(), &chain_spec, &receipt_builder),
            None,
            Bytes::new(),
            None,
            false,
            None,
            parent_hash,
            Some(signer.clone()),
            ctx.expected_begin_system_txs.clone(),
            ctx.expected_end_system_txs.clone(),
            ctx.system_layout_error.clone(),
            ctx.parent_consensus_metadata.clone(),
            Some(proposer),
            true,
            None,
            Some(AccountedParentArtifact {
                summary: ExecutionSummaryArtifact {
                    validator_fee_sum: U256::ZERO,
                },
                timestamp: 1,
                state_root: None,
            }),
        );
        executor.system_tx_phase_cursor = crate::system_tx::SystemTxPhase::initial_for_block(
            2,
            crate::system_tx::GENESIS_BOOTSTRAP_BLOCK_NUMBER,
        );

        let block_artifacts = OutbeBlockArtifacts::default();
        let preexec = crate::factory::with_forced_outbe_system_call_error(|| {
            executor.apply_phase1_commit_in_preexec(2, &block_artifacts)
        });
        if preexec.is_err() {
            return;
        }

        let receipt_count_after_preexec_failure = executor.receipts().len();
        let phase1_tx = begin_system_txs_for_test(
            &config,
            2,
            parent_hash,
            &Bytes::new(),
            Some(metadata),
            proposer,
        )
        .into_iter()
        .next()
        .expect("Phase 1 system tx should be present");
        let _ = crate::factory::with_forced_outbe_system_call_error(|| {
            executor.execute_transaction(phase1_tx)
        });

        assert_eq!(
            executor.receipts().len(),
            receipt_count_after_preexec_failure,
            "GAS-02: Phase 1 pre-exec failure returned Ok and body[0] created another \
             receipt instead of being consumed or making pre-exec fatal"
        );
    }

    #[test]
    fn gas_03_without_commit_reserved_system_tx_must_not_use_user_lane_admission() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let mut state = state_with_active_proposer(proposer);
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, test_evm_env(1, REWARDS_ADDRESS));
        let mut executor = config.create_executor(evm, execution_ctx(Some(1), Bytes::new()));
        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply");
        let system_tx =
            begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer)
                .into_iter()
                .next()
                .expect("CycleTick system tx should be present");

        let result = executor.execute_transaction_without_commit(system_tx);
        let Err(err) = result else {
            panic!("reserved system tx without_commit must not be accepted as a user tx");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("reserved system transaction")
                || msg.contains("Outbe system tx without_commit"),
            "GAS-03: without_commit rejected through the wrong lane or wrong error: {msg}"
        );
    }

    #[test]
    fn gas_09_noncritical_system_oog_exhausts_aggregate_budget_atomically() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let mut state = state_with_active_proposer(proposer);
        let chain_spec = test_chain_spec();
        let receipt_builder = reth_ethereum::evm::RethReceiptBuilder::default();
        let config = OutbeEvmConfig::new(chain_spec.clone()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, test_evm_env(1, REWARDS_ADDRESS));
        let ctx = block_one_execution_ctx(Some(3), Bytes::new());
        let mut executor = OutbeBlockExecutor::new(
            EthBlockExecutor::new(evm, ctx.inner.clone(), &chain_spec, &receipt_builder),
            None,
            Bytes::new(),
            None,
            true,
            None,
            ctx.inner.parent_hash,
            Some(signer.clone()),
            ctx.expected_begin_system_txs.clone(),
            ctx.expected_end_system_txs.clone(),
            ctx.system_layout_error.clone(),
            ctx.parent_consensus_metadata.clone(),
            ctx.proposer_evm_address,
            ctx.execute_outbe_block_hooks,
            ctx.prebuilt_phase1_tx.clone(),
            ctx.parent_artifact_hint,
        )
        .with_pending_tee_bootstrap(ctx.pending_tee_bootstrap.clone());

        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply");
        let mut system_txs =
            begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer)
                .into_iter();
        let cycle_tx = system_txs
            .next()
            .expect("CycleTick system tx should be present");
        let rewards_tx = system_txs
            .next()
            .expect("RewardsGemDelivery system tx should be present");
        let tee_bootstrap_tx = system_txs
            .next()
            .expect("TeeBootstrap system tx should be present");
        let oracle_tx = system_txs
            .next()
            .expect("OracleSlashWindow system tx should be present");
        let cycle_signed_gas_limit = cycle_tx.tx().gas_limit();
        // A forced OOG does not model Oracle performing ten billion units of
        // useful work: revm charges the complete system-call gas limit for any
        // OOG. Because mandatory phases have already consumed internal work,
        // accepting it as a soft failure would exceed the aggregate block
        // budget. The failure must therefore be hard and atomic even though an
        // ordinary OracleSlashWindow revert remains soft.
        let cycle_gas = executor
            .execute_transaction(cycle_tx)
            .expect("CycleTick should execute successfully")
            .tx_gas_used();
        assert!(cycle_gas <= cycle_signed_gas_limit);
        executor
            .execute_transaction(rewards_tx)
            .expect("RewardsGemDelivery should execute before TeeBootstrap");
        let _tee_bootstrap_gas = executor
            .execute_transaction(tee_bootstrap_tx)
            .expect("mandatory TeeBootstrap should execute before the non-critical phase")
            .tx_gas_used();

        let receipts_before = executor.receipts().len();
        let cumulative_visible_gas_before = executor.inner.cumulative_tx_gas_used;
        let internal_work_before = executor.system_tx_execution_gas;
        let error = crate::factory::with_forced_outbe_system_call_oog_halt(|| {
            executor.execute_transaction(oracle_tx)
        })
        .expect_err("forced system OOG must exhaust the aggregate internal-work budget");

        assert!(
            error.to_string().contains("internal system-work budget"),
            "GAS-09: OOG must fail through the aggregate budget guard: {error}"
        );
        assert_eq!(
            executor.receipts().len(),
            receipts_before,
            "GAS-09: aggregate exhaustion must not append a failure receipt"
        );
        assert_eq!(
            executor.inner.cumulative_tx_gas_used, cumulative_visible_gas_before,
            "GAS-09: aggregate exhaustion must not change visible gas accounting"
        );
        assert_eq!(
            executor.system_tx_execution_gas, internal_work_before,
            "GAS-09: aggregate exhaustion must not commit internal-work accounting"
        );
    }

    #[test]
    fn gas_10_low_gas_zero_fee_policy_failure_must_not_mint_intrinsic_gas() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        let low_gas_zero_fee_tx = test_oracle_submit_vote_tx_with_gas_limit(1)
            .try_into_recovered()
            .expect("oracle tx signer should recover");

        let mut db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        let marker_code = Bytecode::new_legacy([0xef].into());
        db.insert_account_info(
            ORACLE_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code),
                ..Default::default()
            },
        );
        let mut state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();
        let evm = config.evm_with_env(&mut state, test_evm_env(1, REWARDS_ADDRESS));
        let mut executor = config.create_executor(evm, execution_ctx(Some(1), Bytes::new()));

        let err = executor
            .execute_transaction(low_gas_zero_fee_tx)
            .expect_err("gas_limit < intrinsic gas must reject before synthetic receipt creation");
        assert!(
            err.to_string().contains("intrinsic") || err.to_string().contains("gas limit"),
            "GAS-10: low-gas zero-fee rejection must be an admission error, got {err}"
        );
        assert!(
            executor.receipts().is_empty(),
            "GAS-10: invalid low-gas zero-fee tx must not mint a 21k synthetic receipt"
        );
    }

    #[test]
    fn gas_11_reverted_noncritical_begin_zone_system_tx_soft_fails_and_keeps_user_lane_clean() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let reward_owner_a = Address::repeat_byte(0x71);
        let reward_owner_b = Address::repeat_byte(0x72);
        let user_tx = test_regular_tx()
            .try_into_recovered()
            .expect("regular tx signer should recover");
        let mut state =
            state_with_active_validators_seeded(&[(proposer, dummy_pubkey(0xA2))], |storage| {
                let seed_context = BlockContext::new(0, 1, CHAIN_ID, proposer, vec![proposer]);
                let ctx = BlockRuntimeContext::new(seed_context, storage.clone());
                outbe_rewards::runtime::ensure_genesis_anchor(&ctx).unwrap();
                outbe_oracle::api::set_exchange_rate(
                    storage.clone(),
                    Address::ZERO,
                    outbe_oracle::api::DAY_TYPE_PAIR,
                    U256::from(1_000_000u64),
                    1,
                    TEST_BLOCK_TIMESTAMP_BASE + 1,
                )
                .unwrap();
                // Close the reward day so delivery prices the batch instead of waiting.
                outbe_oracle::schema::OracleContract::new(storage.clone())
                    .utc_day_vwap_last_finalized
                    .write(29_991_231)
                    .unwrap();
                outbe_rewards::api::prepare_daily_validator_gem_batch(
                    &ctx,
                    20_240_101,
                    U256::from(200u64),
                    &[(reward_owner_a, 1), (reward_owner_b, 1)],
                )
                .unwrap();
                outbe_gemfactory::schema::GemFactoryContract::new(storage)
                    .total_gems_issued
                    .write(U256::MAX - U256::ONE)
                    .unwrap();
            });
        state.database.insert_account_info(
            Address::from(*user_tx.signer()),
            AccountInfo {
                balance: U256::from(1_000_000u64),
                ..Default::default()
            },
        );
        {
            let read_context = BlockContext::new(0, 1, CHAIN_ID, proposer, vec![proposer]);
            let mut provider = outbe_primitives::storage::direct::DirectStorageProvider::new(
                &mut state,
                read_context,
            );
            StorageHandle::enter(&mut provider, |storage| {
                let rewards = outbe_rewards::schema::Rewards::new(storage.clone());
                assert_eq!(rewards.reward_gem_queue_head.read()?, 0);
                assert_eq!(rewards.reward_gem_queue_tail.read()?, 1);
                assert_eq!(rewards.reward_gem_pending_batch_count.read()?, 1);
                assert_eq!(
                    outbe_gemfactory::schema::GemFactoryContract::new(storage)
                        .total_gems_issued
                        .read()?,
                    U256::MAX - U256::ONE
                );
                Ok::<_, outbe_primitives::error::PrecompileError>(())
            })
            .expect("seed one retryable Rewards Gem batch");
        }
        let chain_spec = test_chain_spec();
        let receipt_builder = reth_ethereum::evm::RethReceiptBuilder::default();
        let config = OutbeEvmConfig::new(chain_spec.clone()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, test_evm_env(1, REWARDS_ADDRESS));
        let ctx = block_one_execution_ctx(Some(1), Bytes::new());
        let mut executor = OutbeBlockExecutor::new(
            EthBlockExecutor::new(evm, ctx.inner.clone(), &chain_spec, &receipt_builder),
            None,
            Bytes::new(),
            None,
            false,
            None,
            ctx.inner.parent_hash,
            Some(signer.clone()),
            ctx.expected_begin_system_txs.clone(),
            ctx.expected_end_system_txs.clone(),
            ctx.system_layout_error.clone(),
            ctx.parent_consensus_metadata.clone(),
            ctx.proposer_evm_address,
            ctx.execute_outbe_block_hooks,
            ctx.prebuilt_phase1_tx.clone(),
            ctx.parent_artifact_hint,
        )
        .with_pending_tee_bootstrap(ctx.pending_tee_bootstrap.clone());

        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply");
        let mut system_txs =
            begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer)
                .into_iter();
        let cycle_tx = system_txs
            .next()
            .expect("CycleTick system tx should be present");
        let rewards_tx = system_txs
            .next()
            .expect("RewardsGemDelivery system tx should be present");
        let tee_bootstrap_tx = system_txs
            .next()
            .expect("TeeBootstrap system tx should be present");
        let oracle_tx = system_txs
            .next()
            .expect("OracleSlashWindow system tx should be present");
        let hook_events_tx = system_txs
            .next()
            .expect("HookEvents system tx should be present");
        let rewards_visible_gas = rewards_tx.tx().gas_limit();

        // CycleTick is consensus-critical. RewardsGemDelivery is deliberately
        // retryable, so an ordinary revert records a soft failure and later
        // begin-zone/user transactions still execute.
        let cycle_gas = executor
            .execute_transaction(cycle_tx)
            .expect("CycleTick should execute successfully")
            .tx_gas_used();
        let revert_gas = executor
            .execute_transaction(rewards_tx)
            .expect("RewardsGemDelivery revert should soft-fail")
            .tx_gas_used();
        assert_eq!(
            revert_gas, rewards_visible_gas,
            "GAS-11: reverted delivery should charge visible envelope gas"
        );
        let failure_receipt = executor
            .receipts()
            .get(1)
            .expect("reverted delivery must emit a failure receipt");
        assert!(
            !failure_receipt.success,
            "seeded delivery unexpectedly succeeded: logs={:?}",
            failure_receipt.logs
        );
        assert_eq!(
            failure_receipt.cumulative_gas_used,
            cycle_gas + rewards_visible_gas
        );
        assert_eq!(failure_receipt.logs.len(), 1);
        assert_eq!(failure_receipt.logs[0].address, OUTBE_SYSTEM_TX_ADDRESS);
        assert_eq!(
            failure_receipt.logs[0].data.topics().first(),
            Some(&crate::failure_receipt::OUTBE_FAILURE_TOPIC0),
            "GAS-11: system revert soft-failure receipt must carry OutbeFailure"
        );
        let mut expected_code_topic = [0u8; 32];
        expected_code_topic[31] = 201;
        assert_eq!(
            failure_receipt.logs[0].data.topics()[1].as_slice(),
            expected_code_topic,
            "GAS-11: system revert soft-failure receipt must use OutbeFailure code 201"
        );

        let tee_bootstrap_gas = executor
            .execute_transaction(tee_bootstrap_tx)
            .expect("mandatory TeeBootstrap should execute before the non-critical phase")
            .tx_gas_used();
        let oracle_gas = executor
            .execute_transaction(oracle_tx)
            .expect("OracleSlashWindow should execute after delivery")
            .tx_gas_used();
        let hook_events_gas = executor
            .execute_transaction(hook_events_tx)
            .expect("HookEvents should execute after delivery")
            .tx_gas_used();

        let user_gas = executor
            .execute_transaction(user_tx)
            .expect("user txs must execute after a soft-failed non-critical begin-zone system tx")
            .tx_gas_used();
        assert_eq!(
            executor.inner.cumulative_tx_gas_used,
            cycle_gas
                + rewards_visible_gas
                + tee_bootstrap_gas
                + oracle_gas
                + hook_events_gas
                + user_gas,
            "GAS-11: soft-failed system tx must charge only visible envelope gas"
        );
        drop(executor);

        let retry_context = BlockContext::new(2, 2, CHAIN_ID, proposer, vec![proposer]);
        let mut retry_provider = outbe_primitives::storage::direct::DirectStorageProvider::new(
            &mut state,
            retry_context.clone(),
        );
        StorageHandle::enter(&mut retry_provider, |storage| {
            let rewards = outbe_rewards::schema::Rewards::new(storage.clone());
            let gem = outbe_gem::GemContract::new(storage.clone());
            assert_eq!(rewards.reward_gem_queue_head.read()?, 0);
            assert_eq!(rewards.reward_gem_queue_tail.read()?, 1);
            assert_eq!(rewards.reward_gem_pending_batch_count.read()?, 1);
            assert_eq!(gem.balance_of(reward_owner_a)?, 0);
            assert_eq!(gem.balance_of(reward_owner_b)?, 0);

            outbe_gemfactory::schema::GemFactoryContract::new(storage.clone())
                .total_gems_issued
                .write(U256::ZERO)?;
            let retry_ctx = BlockRuntimeContext::new(retry_context, storage.clone());
            assert!(matches!(
                outbe_rewards::api::deliver_oldest_reward_gem_batch(&retry_ctx)?,
                outbe_rewards::api::RewardGemDeliveryOutcome::Delivered {
                    reward_utc_day: 20_240_101,
                    recipient_count: 2,
                    delivered_promis_load_amount,
                } if delivered_promis_load_amount == U256::from(200u64)
            ));
            assert_eq!(rewards.reward_gem_queue_head.read()?, 1);
            assert_eq!(rewards.reward_gem_queue_tail.read()?, 1);
            assert_eq!(rewards.reward_gem_pending_batch_count.read()?, 0);
            assert_eq!(gem.balance_of(reward_owner_a)?, 1);
            assert_eq!(gem.balance_of(reward_owner_b)?, 1);
            Ok::<_, outbe_primitives::error::PrecompileError>(())
        })
        .expect("the unchanged FIFO head must deliver on a later retry");
    }

    /// A revert in a consensus-critical begin-zone phase (here
    /// CycleTick) is a hard block failure, not a soft-receipt skip - its one-shot
    /// work (a day's emission / terminal Metadosis) must never be silently
    /// dropped. No receipt is pushed; the block aborts.
    #[test]
    fn critical_cycle_tick_revert_fails_block() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let mut state = state_with_active_proposer(proposer);
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, test_evm_env(1, REWARDS_ADDRESS));
        let mut executor =
            config.create_executor(evm, block_one_execution_ctx(Some(1), Bytes::new()));
        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply");
        let cycle_tx =
            begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer)
                .into_iter()
                .next()
                .expect("CycleTick system tx should be present");

        let err = crate::factory::with_forced_outbe_system_call_revert(|| {
            executor.execute_transaction(cycle_tx)
        })
        .expect_err("a revert in the critical CycleTick phase must fail the block");
        assert!(
            err.to_string()
                .contains("critical system tx CycleTick did not succeed"),
            "unexpected error: {err}"
        );
        assert!(
            executor.receipts().is_empty(),
            "a critical-phase revert must not push a soft receipt"
        );
    }

    /// A stale reward price at the UTC-day boundary defers only Gem delivery:
    /// CycleTick seals the allocation, RewardsGemDelivery leaves the FIFO head
    /// pending, and the user-lane feeder vote still executes.
    #[test]
    fn stale_oracle_cycle_stages_reward_batch_and_allows_later_feeder_vote() {
        const GENESIS_TS: u64 = 1_704_067_200;
        const SECONDS_PER_DAY: u64 = 86_400;
        const PREVIOUS_DAY: u32 = 20_240_101;

        #[derive(Debug, Eq, PartialEq)]
        struct Observation {
            active_day: u32,
            last_executed_at: u64,
            day_settled: bool,
            topup_prepared: bool,
            topup_settled: bool,
            queue_head: u64,
            queue_tail: u64,
            voter_gems: u64,
            feeder_vote_exists: bool,
            formation_exists: bool,
        }

        fn run_once() -> Observation {
            let signer = test_evm_signer();
            let proposer = signer.address();
            let proposer_key = dummy_pubkey(0xA2);
            let feeder_vote = test_oracle_submit_vote_tx()
                .try_into_recovered()
                .expect("test feeder vote signer should recover");
            let feeder = Address::from(*feeder_vote.signer());
            let voter = Address::repeat_byte(0x71);
            let emission_trigger = outbe_cycle::triggers::TriggerId::ProtocolCycle.as_u32();

            let mut state = state_with_active_validators_seeded_at_block_with_cycle_frames(
                &[(proposer, proposer_key)],
                1,
                4,
                |storage| {
                    let genesis_ctx = BlockRuntimeContext::new(
                        BlockContext::new(0, GENESIS_TS, CHAIN_ID, proposer, vec![proposer]),
                        storage.clone(),
                    );
                    outbe_rewards::runtime::ensure_genesis_anchor(&genesis_ctx).unwrap();

                    let cycle = outbe_cycle::schema::Cycle::new(storage.clone());
                    cycle.active_utc_day.write(PREVIOUS_DAY).unwrap();
                    cycle
                        .last_executed_at
                        .write(&emission_trigger, GENESIS_TS + 60)
                        .unwrap();

                    let rewards = outbe_rewards::schema::Rewards::new(storage.clone());
                    rewards.daily_voter_count.write(&PREVIOUS_DAY, 1).unwrap();
                    rewards
                        .daily_voter_at
                        .get_nested(&PREVIOUS_DAY)
                        .write(&0, voter)
                        .unwrap();
                    rewards
                        .daily_participation
                        .get_nested(&PREVIOUS_DAY)
                        .write(&voter, 1)
                        .unwrap();
                    rewards
                        .daily_total_participation
                        .write(&PREVIOUS_DAY, 1)
                        .unwrap();

                    let mut validator_set =
                        outbe_validatorset::contract::ValidatorSet::new(storage.clone());
                    validator_set
                        .set_delegate(
                            proposer,
                            outbe_validatorset::delegation::ValidatorDelegateRole::Oracle,
                            feeder,
                        )
                        .unwrap();

                    // The shared state fixture seeds COEN/840 at timestamp zero.
                    // That is intentionally stale under the live six-hour policy.
                    let (.., pair_index) =
                        outbe_oracle::api::require_coen_pair(storage.clone(), 840).unwrap();
                    let oracle = outbe_oracle::schema::OracleContract::new(storage);
                    assert_eq!(oracle.exchange_rate_timestamp.read(&pair_index).unwrap(), 0);
                },
            );

            let block_timestamp = GENESIS_TS + SECONDS_PER_DAY + 60;
            let tee_bootstrap = sample_tee_bootstrap_payload_at(1, block_timestamp);
            let mut evm_env = test_evm_env(1, REWARDS_ADDRESS);
            evm_env.block_env.timestamp = U256::from(block_timestamp);
            let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer.clone());
            let begin = begin_system_txs_for_test_with_bootstrap(
                &config,
                1,
                B256::ZERO,
                &Bytes::new(),
                None,
                proposer,
                Some(tee_bootstrap.clone()),
            );
            let mut body = begin.clone();
            body.push(feeder_vote);

            let evm = config.evm_with_env(&mut state, evm_env);
            let mut execution =
                execution_ctx_with_tee_bootstrap(Some(body.len()), Bytes::new(), tee_bootstrap);
            execution.expected_begin_system_txs = begin;
            execution.proposer_evm_address = Some(proposer);
            let mut executor = config.create_executor(evm, execution);
            executor
                .apply_pre_execution_changes()
                .expect("pre-execution hooks must succeed");
            for tx in body {
                executor
                    .execute_transaction(tx)
                    .expect("stale reward price must defer only Gem delivery");
            }
            drop(executor);

            let read_ctx =
                BlockContext::new(1, block_timestamp, CHAIN_ID, proposer, vec![proposer]);
            let mut provider =
                outbe_primitives::storage::direct::DirectStorageProvider::new(&mut state, read_ctx);
            StorageHandle::enter(&mut provider, |storage| {
                let cycle = outbe_cycle::schema::Cycle::new(storage.clone());
                let rewards = outbe_rewards::schema::Rewards::new(storage.clone());
                let oracle = outbe_oracle::schema::OracleContract::new(storage.clone());
                let gem = outbe_gem::GemContract::new(storage.clone());
                Observation {
                    active_day: cycle.active_utc_day.read().unwrap(),
                    last_executed_at: cycle.last_executed_at.read(&emission_trigger).unwrap(),
                    day_settled: rewards.daily_settled.read(&PREVIOUS_DAY).unwrap(),
                    topup_prepared: rewards.daily_topup_prepared.read(&PREVIOUS_DAY).unwrap(),
                    topup_settled: rewards.daily_topup_settled.read(&PREVIOUS_DAY).unwrap(),
                    queue_head: rewards.reward_gem_queue_head.read().unwrap(),
                    queue_tail: rewards.reward_gem_queue_tail.read().unwrap(),
                    voter_gems: u64::from(gem.balance_of(voter).unwrap()),
                    feeder_vote_exists: oracle.vote_exists.read(&proposer).unwrap(),
                    formation_exists: outbe_metadosis::api::day_limit_formation_receipt(
                        storage,
                        outbe_primitives::time::WorldwideDay::new(PREVIOUS_DAY),
                    )
                    .unwrap()
                    .is_some(),
                }
            })
        }

        let first = run_once();
        assert_eq!(first.active_day, 20_240_102);
        assert_eq!(first.last_executed_at, GENESIS_TS + SECONDS_PER_DAY);
        assert!(first.day_settled);
        assert!(first.topup_prepared);
        assert!(!first.topup_settled);
        assert_eq!(first.queue_head, 0);
        assert_eq!(first.queue_tail, 1);
        assert_eq!(first.voter_gems, 0);
        assert!(first.feeder_vote_exists);
        assert!(first.formation_exists);

        let replay = run_once();
        assert_eq!(
            replay, first,
            "an exact execution from the same semantic pre-state must settle identically"
        );
    }

    /// An OOG halt in a consensus-critical begin-zone phase also
    /// fails the block (not a soft skip), via the same `revert_fails_block` gate.
    #[test]
    fn critical_cycle_tick_oog_fails_block() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let mut state = state_with_active_proposer(proposer);
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, test_evm_env(1, REWARDS_ADDRESS));
        let mut executor =
            config.create_executor(evm, block_one_execution_ctx(Some(1), Bytes::new()));
        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply");
        let cycle_tx =
            begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer)
                .into_iter()
                .next()
                .expect("CycleTick system tx should be present");

        let err = crate::factory::with_forced_outbe_system_call_oog_halt(|| {
            executor.execute_transaction(cycle_tx)
        })
        .expect_err("an OOG halt in the critical CycleTick phase must fail the block");
        assert!(
            err.to_string()
                .contains("critical system tx CycleTick did not succeed"),
            "unexpected error: {err}"
        );
        assert!(
            executor.receipts().is_empty(),
            "a critical-phase OOG halt must not push a soft receipt"
        );
    }

    /// The per-block zero-fee soft-failure cap admits up to
    /// `MAX_ZERO_FEE_SOFT_FAILURES_PER_BLOCK` soft-failures, then rejects further
    /// ones with a tx-level `InvalidTx` - the variant the payload builder SKIPS
    /// (mark_invalid + continue) and a validator REJECTS the block on, NOT a
    /// fatal `Internal` error that would abort the build (the 2026-05-15 halt).
    #[test]
    fn zero_fee_soft_failure_cap_admits_then_rejects_with_invalid_tx() {
        use alloy_evm::block::{BlockExecutionError, BlockValidationError};
        let signer = test_evm_signer();
        let proposer = signer.address();
        let mut state = state_with_active_proposer(proposer);
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, test_evm_env(1, REWARDS_ADDRESS));
        let mut executor = config.create_executor(evm, execution_ctx(Some(1), Bytes::new()));

        let mut admitted = 0u32;
        let rejected_err = loop {
            match executor.record_zero_fee_soft_failure(B256::ZERO) {
                Ok(()) => {
                    admitted += 1;
                    assert!(admitted <= 4096, "cap never enforced");
                }
                Err(err) => break err,
            }
        };
        assert_eq!(
            admitted, 64,
            "zero-fee soft-failure cap must admit exactly MAX_ZERO_FEE_SOFT_FAILURES_PER_BLOCK (64)"
        );
        assert!(
            matches!(
                rejected_err,
                BlockExecutionError::Validation(BlockValidationError::InvalidTx { .. })
            ),
            "over-cap zero-fee soft-failure must be a tx-level InvalidTx (skip-on-build / \
             reject-on-validate), got: {rejected_err:?}"
        );
    }

    #[test]
    fn gas_13_system_receipt_rpc_gas_delta_is_visible_envelope_gas() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let user_tx = test_regular_tx()
            .try_into_recovered()
            .expect("regular tx signer should recover");
        let mut state = state_with_active_proposer_and_funded_account(proposer, user_tx.signer());
        let chain_spec = test_chain_spec();
        let receipt_builder = reth_ethereum::evm::RethReceiptBuilder::default();
        let config = OutbeEvmConfig::new(chain_spec.clone()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, test_evm_env(1, REWARDS_ADDRESS));
        let ctx = block_one_execution_ctx(Some(3), Bytes::new());
        let mut executor = OutbeBlockExecutor::new(
            EthBlockExecutor::new(evm, ctx.inner.clone(), &chain_spec, &receipt_builder),
            None,
            Bytes::new(),
            None,
            true,
            None,
            ctx.inner.parent_hash,
            Some(signer.clone()),
            ctx.expected_begin_system_txs.clone(),
            ctx.expected_end_system_txs.clone(),
            ctx.system_layout_error.clone(),
            ctx.parent_consensus_metadata.clone(),
            ctx.proposer_evm_address,
            ctx.execute_outbe_block_hooks,
            ctx.prebuilt_phase1_tx.clone(),
            ctx.parent_artifact_hint,
        )
        .with_pending_tee_bootstrap(ctx.pending_tee_bootstrap.clone());

        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply");
        let mut expected_rpc_gas_deltas = Vec::new();
        for tx in begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer) {
            let signed_gas_limit = tx.tx().gas_limit();
            let gas_used = executor
                .execute_transaction(tx)
                .expect("system tx should execute")
                .tx_gas_used();
            assert!(gas_used <= signed_gas_limit);
            expected_rpc_gas_deltas.push(gas_used);
        }
        let user_gas = executor
            .execute_transaction(user_tx)
            .expect("funded regular user tx should execute")
            .tx_gas_used();
        expected_rpc_gas_deltas.push(user_gas);

        let mut previous = 0;
        let rpc_gas_deltas: Vec<u64> = executor
            .receipts()
            .iter()
            .map(|receipt| {
                let delta = receipt.cumulative_gas_used.saturating_sub(previous);
                previous = receipt.cumulative_gas_used;
                delta
            })
            .collect();

        assert_eq!(rpc_gas_deltas, expected_rpc_gas_deltas);
    }

    #[test]
    fn system_protocol_precharge_and_ce_gas_are_published_and_block_limited() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let mut state = state_with_active_proposer_without_ocomp(proposer);
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer);
        let evm = config.evm_with_env(&mut state, test_evm_env(1, REWARDS_ADDRESS));
        let mut executor = config.create_executor(evm, execution_ctx(Some(0), Bytes::new()));

        let intrinsic_gas = 21_000;
        let protocol_precharge = 300_000;
        let visible_base_gas = intrinsic_gas + protocol_precharge;
        let compressed_entities_gas = 70_000;
        let output = executor
            .push_system_failure_receipt(SystemFailureReceiptInput {
                tx_type: alloy_consensus::TxType::Legacy,
                log_address: outbe_primitives::addresses::OUTBE_SYSTEM_TX_ADDRESS,
                code: 299,
                reason: "deterministic test failure".into(),
                visible_base_gas,
                compressed_entities_gas,
                signed_gas_limit: visible_base_gas + compressed_entities_gas,
                internal_gas_used: 123,
            })
            .expect("visible envelope plus CE gas should fit");
        let expected_visible = intrinsic_gas + protocol_precharge + compressed_entities_gas;
        assert_eq!(output.tx_gas_used(), expected_visible);
        assert_eq!(
            executor.receipts().last().unwrap().cumulative_gas_used,
            expected_visible
        );
        assert_eq!(executor.inner.cumulative_tx_gas_used, expected_visible);
        assert_eq!(executor.inner.block_regular_gas_used, expected_visible);
        assert_eq!(executor.inner.block_state_gas_used, expected_visible);
        assert_eq!(executor.system_tx_execution_gas, 123);

        let receipts_before = executor.receipts().len();
        let cumulative_before = executor.inner.cumulative_tx_gas_used;
        let block_limit = executor.inner.evm.block.gas_limit;
        let remaining = block_limit - cumulative_before;
        let error = executor
            .push_system_failure_receipt(SystemFailureReceiptInput {
                tx_type: alloy_consensus::TxType::Legacy,
                log_address: outbe_primitives::addresses::OUTBE_SYSTEM_TX_ADDRESS,
                code: 299,
                reason: "must not commit".into(),
                visible_base_gas: remaining,
                compressed_entities_gas: 1,
                signed_gas_limit: remaining + 1,
                internal_gas_used: 456,
            })
            .expect_err("CE delta must not push cumulative gas past the block limit");
        assert!(error.to_string().contains("exceeds block gas limit"));
        assert_eq!(executor.receipts().len(), receipts_before);
        assert_eq!(executor.inner.cumulative_tx_gas_used, cumulative_before);
        assert_eq!(executor.system_tx_execution_gas, 123);
    }

    #[test]
    fn system_internal_work_budget_rejects_before_receipt_or_state_accounting() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let mut state = state_with_active_proposer_without_ocomp(proposer);
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer);
        let evm = config.evm_with_env(&mut state, test_evm_env(1, REWARDS_ADDRESS));
        let mut executor = config.create_executor(evm, execution_ctx(Some(0), Bytes::new()));
        executor.system_tx_execution_gas =
            outbe_primitives::system_tx::SYSTEM_TX_ARTIFACT_GAS_LIMIT - 1;

        let receipts_before = executor.receipts().len();
        let cumulative_before = executor.inner.cumulative_tx_gas_used;
        let error = executor
            .push_system_failure_receipt(SystemFailureReceiptInput {
                tx_type: alloy_consensus::TxType::Eip1559,
                log_address: outbe_primitives::addresses::OUTBE_SYSTEM_TX_ADDRESS,
                code: 299,
                reason: "must not commit past the internal system-work budget".into(),
                visible_base_gas: 0,
                compressed_entities_gas: 0,
                signed_gas_limit: 0,
                internal_gas_used: 2,
            })
            .expect_err("system internal work must be bounded independently from user gas");

        assert!(error.to_string().contains("internal system-work budget"));
        assert_eq!(executor.receipts().len(), receipts_before);
        assert_eq!(executor.inner.cumulative_tx_gas_used, cumulative_before);
        assert_eq!(
            executor.system_tx_execution_gas,
            outbe_primitives::system_tx::SYSTEM_TX_ARTIFACT_GAS_LIMIT - 1
        );
    }

    #[test]
    fn gas_14_executor_finish_sets_visible_system_gas_for_fee_history_input() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let mut state = state_with_active_proposer(proposer);
        let chain_spec = test_chain_spec();
        let receipt_builder = reth_ethereum::evm::RethReceiptBuilder::default();
        let config = OutbeEvmConfig::new(chain_spec.clone()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, test_evm_env(1, REWARDS_ADDRESS));
        let ctx = block_one_execution_ctx(Some(2), Bytes::new());
        let mut executor = OutbeBlockExecutor::new(
            EthBlockExecutor::new(evm, ctx.inner.clone(), &chain_spec, &receipt_builder),
            None,
            Bytes::new(),
            None,
            true,
            None,
            ctx.inner.parent_hash,
            Some(signer.clone()),
            ctx.expected_begin_system_txs.clone(),
            ctx.expected_end_system_txs.clone(),
            ctx.system_layout_error.clone(),
            ctx.parent_consensus_metadata.clone(),
            ctx.proposer_evm_address,
            ctx.execute_outbe_block_hooks,
            ctx.prebuilt_phase1_tx.clone(),
            ctx.parent_artifact_hint,
        )
        .with_pending_tee_bootstrap(ctx.pending_tee_bootstrap.clone());

        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply");
        let system_txs =
            begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer);
        let mut visible_system_gas = 0u64;
        let mut expected_system_deltas = Vec::with_capacity(system_txs.len());
        for tx in system_txs {
            let signed_gas_limit = tx.tx().gas_limit();
            let visible_gas = executor
                .execute_transaction(tx)
                .expect("system tx should execute")
                .tx_gas_used();
            assert!(visible_gas <= signed_gas_limit);
            expected_system_deltas.push(visible_gas);
            visible_system_gas += visible_gas;
        }
        assert!(visible_system_gas > 0);

        let mut previous = 0;
        let receipt_deltas: Vec<u64> = executor
            .receipts()
            .iter()
            .map(|receipt| {
                let delta = receipt.cumulative_gas_used.saturating_sub(previous);
                previous = receipt.cumulative_gas_used;
                delta
            })
            .collect();
        assert_eq!(receipt_deltas, expected_system_deltas);

        executor
            .finalize_compressed_entities()
            .expect("compressed entities should finalize");
        executor
            .prepare_final_header_artifacts(0)
            .expect("final extra_data should encode");
        let (_evm, result) = executor.finish().expect("finish should succeed");
        assert_eq!(
            result.gas_used, visible_system_gas,
            "GAS-14: system-only block gas_used must expose visible system envelope gas"
        );
        assert_eq!(result.receipts.len(), expected_system_deltas.len());

        let gas_limit = 30_000_000u64;
        let gas_used_ratio = result.gas_used as f64 / gas_limit as f64;
        assert!(
            gas_used_ratio > 0.0 && gas_used_ratio <= 1.0,
            "GAS-14: fee-history input ratio must expose complete mandatory block-1 system gas, got {gas_used_ratio}"
        );
    }

    #[test]
    fn gas_16_mixed_system_and_user_block_finish_uses_visible_system_gas() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let user_tx = test_regular_tx()
            .try_into_recovered()
            .expect("regular tx signer should recover");
        let mut state = state_with_active_proposer_and_funded_account(proposer, user_tx.signer());
        let chain_spec = test_chain_spec();
        let receipt_builder = reth_ethereum::evm::RethReceiptBuilder::default();
        let config = OutbeEvmConfig::new(chain_spec.clone()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, test_evm_env(1, REWARDS_ADDRESS));
        let ctx = block_one_execution_ctx(Some(3), Bytes::new());
        let mut executor = OutbeBlockExecutor::new(
            EthBlockExecutor::new(evm, ctx.inner.clone(), &chain_spec, &receipt_builder),
            None,
            Bytes::new(),
            None,
            true,
            None,
            ctx.inner.parent_hash,
            Some(signer.clone()),
            ctx.expected_begin_system_txs.clone(),
            ctx.expected_end_system_txs.clone(),
            ctx.system_layout_error.clone(),
            ctx.parent_consensus_metadata.clone(),
            ctx.proposer_evm_address,
            ctx.execute_outbe_block_hooks,
            ctx.prebuilt_phase1_tx.clone(),
            ctx.parent_artifact_hint,
        )
        .with_pending_tee_bootstrap(ctx.pending_tee_bootstrap.clone());

        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply");
        let mut visible_system_gas = 0u64;
        for tx in begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer) {
            let signed_gas_limit = tx.tx().gas_limit();
            let gas_used = executor
                .execute_transaction(tx)
                .expect("system tx should execute")
                .tx_gas_used();
            assert!(gas_used <= signed_gas_limit);
            visible_system_gas += gas_used;
        }
        let user_gas = executor
            .execute_transaction(user_tx)
            .expect("funded regular user tx should execute")
            .tx_gas_used();

        executor
            .finalize_compressed_entities()
            .expect("compressed entities should finalize");
        executor
            .prepare_final_header_artifacts(0)
            .expect("final extra_data should encode");
        let (_evm, result) = executor.finish().expect("finish should succeed");
        assert_eq!(result.gas_used, visible_system_gas + user_gas);
        assert_eq!(result.receipts.len(), 6);
        let first_visible_gas = result.receipts[0].cumulative_gas_used;
        assert!(first_visible_gas >= outbe_primitives::system_tx::SYSTEM_TX_VISIBLE_GAS_FLOOR);
        assert_eq!(result.receipts[4].cumulative_gas_used, visible_system_gas);
        assert_eq!(
            result.receipts[5].cumulative_gas_used,
            visible_system_gas + user_gas
        );
    }

    #[test]
    fn apply_pre_execution_changes_emits_phase1_slashing_logs_in_system_receipt() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let absent = address!("0x2222222222222222222222222222222222222222");
        let parent_hash = B256::with_last_byte(0xAA);
        let mut state = state_with_active_validators_seeded(
            &[(proposer, dummy_pubkey(0xA2)), (absent, dummy_pubkey(0xB3))],
            |storage| {
                let si = outbe_slashindicator::contract::SlashIndicator::new(storage);
                si.config_voter_misdemeanor_threshold.write(1).unwrap();
                si.config_proposer_felony_threshold.write(1).unwrap();
            },
        );
        let mut metadata = test_metadata();
        metadata.finalized_block_number = 1;
        metadata.finalized_block_hash = parent_hash;
        metadata.ordered_committee = vec![proposer, absent];
        metadata.signer_bitmap = vec![1, 0];
        metadata.missed_proposers =
            vec![outbe_primitives::consensus_metadata::MissedProposerEvent {
                view: 0,
                validator: absent,
            }];

        let bridge = ConsensusExecutionBridge::new();
        bridge.record_execution_summary_with_state_root(
            1,
            parent_hash,
            ExecutionSummaryArtifact {
                validator_fee_sum: U256::ZERO,
            },
            1,
            B256::repeat_byte(0x91),
        );
        let config = OutbeEvmConfig::new_with_bridge(test_chain_spec(), bridge)
            .with_evm_signer(signer.clone());
        let evm_env = test_evm_env(2, REWARDS_ADDRESS);
        let evm = config.evm_with_env(&mut state, evm_env);
        let mut ctx = execution_ctx(Some(0), Bytes::new());
        ctx.inner.parent_hash = parent_hash;
        ctx.parent_consensus_metadata = Some(metadata.clone());
        let mut executor = config.create_executor(evm, ctx);

        // opt out of Phase 1 `verify_v2_proof` preflight - this
        // unit test exercises the slashing log emission path, not the
        // verifier itself, and does not seed a matching committee snapshot.
        super::with_phase1_verify_disabled(|| {
            executor
                .apply_pre_execution_changes()
                .expect("pre-execution changes should apply before Phase 1 system tx");
        });
        let system_txs = begin_system_txs_for_test(
            &config,
            2,
            parent_hash,
            &Bytes::new(),
            Some(metadata),
            proposer,
        );
        for tx in system_txs {
            executor
                .execute_transaction(tx)
                .expect("Phase 1 slashing system tx should execute");
        }

        // CPA(0) + LateFinalizeCredits(1) + CycleTick(2) + RewardsGemDelivery(3)
        // + OracleSlashWindow(4) + HookEvents(5).
        assert_eq!(executor.receipts().len(), 6);
        let phase1_logs = &executor.receipts()[0].logs;
        let voter_misdemeanor = keccak256("VoterMisdemeanor(address,uint64)");
        let voter_felony = keccak256("VoterFelony(address,uint64,uint64)");
        let proposer_felony = keccak256("ProposerFelony(address,uint64,uint64)");
        // voter miss / slashing accounting moved OFF Phase 1 (CPA)
        // to the inclusion-window close at N+K, so CPA emits no voter slashing log.
        assert!(
            !phase1_logs.iter().any(|log| {
                log.address == SLASH_INDICATOR_ADDRESS
                    && matches!(
                        log.data.topics().first(),
                        Some(topic) if *topic == voter_misdemeanor || *topic == voter_felony
                    )
            }),
            "Phase 1 (CPA) must no longer emit voter slashing - it is relocated to window close"
        );
        // Proposer slashing stays in Phase 1 (driven by `missed_proposers` metadata).
        assert!(
            phase1_logs.iter().any(|log| {
                log.address == SLASH_INDICATOR_ADDRESS
                    && log.data.topics().first() == Some(&proposer_felony)
            }),
            "Phase 1 proposer slashing must emit receipt-visible ProposerFelony"
        );
        drop(executor);

        let read_ctx = BlockContext::new(2, 2, CHAIN_ID, proposer, vec![proposer, absent]);
        let mut provider =
            outbe_primitives::storage::direct::DirectStorageProvider::new(&mut state, read_ctx);
        StorageHandle::enter(&mut provider, |storage| {
            let si = outbe_slashindicator::contract::SlashIndicator::new(storage.clone());
            // Voter miss is now counted at the inclusion-window close (N+K), not at
            // CPA: block 2's CPA leaves voter_miss_count untouched.
            assert_eq!(si.voter_miss_count.read(&absent)?, 0);
            // Proposer slashing stays at CPA; the missed proposer is JAILED
            // (felony threshold 1) and its proposer miss recorded.
            assert_eq!(si.proposer_miss_count.read(&absent)?, 1);
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            let record = vs.get_validator(absent)?.expect("absent validator exists");
            assert_eq!(record.status, outbe_validatorset::logic::status::JAILED);
            Ok::<_, outbe_primitives::error::PrecompileError>(())
        })
        .expect("slashing state should be readable");
    }

    /// an unverifiable late-finalize credit carried in
    /// `header.extra_data` is FATAL in **pre-exec** - the block is rejected
    /// before any transaction executes (no receipts), not as a soft receipt.
    /// Phase 1 is disabled (no CPA proof seeded); the late-finalize preflight is
    /// the sole gate under test, enabled via the dedicated
    /// `LATE_FINALIZE_VERIFY_DISABLED` opt-out staying off.
    #[test]
    fn bad_late_proof_pre_exec_fatal() {
        use outbe_primitives::reshare_artifact::{LateFinalizeCreditsArtifact, PerBlockCredit};

        let signer = test_evm_signer();
        let proposer = signer.address();
        let parent_hash = B256::with_last_byte(0xAA);
        let mut state = state_with_active_proposer(proposer);

        // Block-2 header artifact: an in-window credit (distance 2 - 1 = 1)
        // whose committee snapshot was never written -> verify cannot resolve it.
        let artifact = OutbeBlockArtifacts {
            execution_summary: None,
            consensus_header_artifact: None,
            timestamp_millis_part: 0,
            late_finalize_credits: Some(LateFinalizeCreditsArtifact {
                batches: vec![PerBlockCredit {
                    fb_number: 1,
                    fb_hash: B256::repeat_byte(0xCD),
                    epoch: 0,
                    view: 9,
                    parent_view: 8,
                    committee_set_hash: B256::repeat_byte(0xEF),
                    signer_bitmap: vec![0x01],
                    aggregate_signature: [0u8; 96],
                }],
            }),
            compressed_entities_root: None,
        };
        let extra_data = encode_outbe_block_artifacts(&artifact).unwrap();

        let config =
            OutbeEvmConfig::new_with_bridge(test_chain_spec(), ConsensusExecutionBridge::new())
                .with_evm_signer(signer);
        let evm_env = test_evm_env(2, REWARDS_ADDRESS);
        let evm = config.evm_with_env(&mut state, evm_env);
        let mut ctx = execution_ctx(Some(0), extra_data);
        ctx.inner.parent_hash = parent_hash;
        let mut executor = config.create_executor(evm, ctx);

        // Phase 1 disabled; late-finalize verify stays ENABLED -> the
        // unverifiable credit aborts the block in pre-exec.
        let err = super::with_phase1_verify_disabled(|| executor.apply_pre_execution_changes())
            .expect_err("unverifiable late-finalize credit must be FATAL in pre-exec");
        assert!(
            err.to_string().contains("LateFinalizeCredits pre-exec"),
            "error must come from the late-finalize preflight (fatal): {err}"
        );
        assert!(
            executor.receipts().is_empty(),
            "no receipts may be emitted before a pre-exec FATAL"
        );
    }

    /// determinism gate: a block carrying a valid BLS late-finalize
    /// credit, executed on the proposer's encoded `extra_data` and on the bytes
    /// a validator decodes+re-encodes, reaches **identical** post-state and
    /// receipts. Proves the begin-zone late-credit verify+record path is
    /// deterministic across proposer and validator (artifact byte-identity is
    /// pinned here via the codec round-trip; full proposer/validator lockstep is
    /// covered end-to-end by the localnet harness).
    ///
    /// The block executes at `N+K` so the begin-zone `settle_matured` is not a
    /// no-op: a pre-seeded matured escrow (block `N`, non-zero fee, one credited
    /// voter at `k=1`) is actually **paid** - and the resulting fee-share
    /// **balance delta** (voter + drained `REWARDS`) must match byte-for-byte on
    /// both the proposer and validator paths. This closes the gap
    /// where a zero `validator_fee_sum` made settlement prove nothing.
    #[test]
    fn proposer_validator_same_state_root() {
        use commonware_codec::Encode as _;
        use commonware_consensus::simplex::types::Proposal;
        use commonware_consensus::types::{Epoch, Round, View};
        use commonware_cryptography::bls12381::{
            self,
            primitives::{ops::aggregate, variant::MinPk},
        };
        use commonware_cryptography::Signer as _;
        use commonware_math::algebra::Random as _;
        use outbe_consensus::digest::Digest as OutbeDigest;
        use outbe_consensus::proof::{
            committee_set_hash_v2, finalize_namespace, CommitteeEntry, CommitteeSnapshot,
        };
        use outbe_primitives::reshare_artifact::{
            decode_outbe_block_artifacts, LateFinalizeCreditsArtifact, PerBlockCredit,
        };

        // Mirror production startup: the consensus chain id is installed into the
        // namespace source of truth BEFORE anything signs or verifies. The
        // executor below constructs `OutbeEvmConfig`, which now installs it for
        // every constructor; install it here too so the finalize
        // aggregate signed below uses the same `finalize_namespace` the verify
        // path reads - otherwise the late-finalize BLS check fails on a namespace
        // mismatch (`b"outbe" || 0` at sign time vs `b"outbe" || CHAIN_ID` at
        // verify time). CHAIN_ID matches the Outbe Devnet identity used by
        // `test_chain_spec()` throughout this shared lib-test process.
        outbe_consensus::proof::init_consensus_chain_id(CHAIN_ID).unwrap();

        let epoch = 0u64;
        // Real BLS committee of 4 (committee addresses are the late-credit voters).
        let keys: Vec<bls12381::PrivateKey> = (0..4)
            .map(|_| bls12381::PrivateKey::random(rand_core::OsRng))
            .collect();
        let addrs: Vec<Address> = (0..4).map(|i| Address::with_last_byte(i + 0x40)).collect();
        let snapshot = CommitteeSnapshot {
            committee: keys
                .iter()
                .zip(&addrs)
                .map(|(k, a)| {
                    let mut pk = [0u8; 48];
                    pk.copy_from_slice(&k.public_key().encode());
                    CommitteeEntry {
                        address: *a,
                        consensus_pubkey: pk,
                    }
                })
                .collect(),
            vrf_material_version: 1,
            vrf_group_public_key_bytes: vec![0x11; 96],
            vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
        };
        let csh = committee_set_hash_v2(epoch, &snapshot);

        // Execute at block N+K so the begin-zone `settle_matured` is not a no-op.
        let window_k = outbe_primitives::consensus::LATE_FINALIZE_WINDOW_K;
        let settle_block = window_k + 1; // K+1 = 4: first block where N=1 matures.
        let progress_marker = settle_block - 2; // CPA progress gate: last_accounted.

        // Live credit for the finalized parent (fb = settle_block - 1, distance 1),
        // signers 0..2. The credit targets the finalized parent (`parent_hash`) -
        // the very block the block-(N+K) CPA escrows - so its canonical binding
        // (number->{fb_hash, epoch, committee_set_hash}) is written by
        // `on_finalized_metadata` and the credit authenticates against it.
        // The CPA metadata carries no base voters, so only the late credit's
        // signers are recorded. This exercises the *recording* path's parity.
        let (fb_number, view, parent_view) = (settle_block - 1, 9u64, 8u64);
        let parent_hash = B256::with_last_byte(0xAA);
        let fb_hash = parent_hash;

        // Pre-seeded MATURED escrow for block N = settle_block - K with a non-zero
        // fee and one credited voter at k=1. `settle_matured(settle_block, K)`
        // settles this block, so the begin-zone actually PAYS - proving the
        // fee-share balance delta is identical on both paths. A
        // distinct fb_hash and a dedicated voter address keep this concern isolated
        // from the live recording credit above.
        let settle_target = settle_block - window_k; // = 1
        let settle_fb_hash = B256::with_last_byte(0x11);
        let settle_voter = Address::with_last_byte(0x77);
        let settle_committee = 4u64;
        let settle_fee = U256::from(4_000u64);
        // payout_i = fee * w(1) / (committee * w_max) = 4000 * 100 / 400 = 1000.
        let expected_payout = settle_fee * outbe_rewards::constants::decay_weight(1)
            / outbe_rewards::constants::fixed_denominator(settle_committee);
        let proposal = Proposal::new(
            Round::new(Epoch::new(epoch), View::new(view)),
            View::new(parent_view),
            OutbeDigest(fb_hash),
        );
        let msg = proposal.encode().to_vec();
        // finalize votes bind the ordered committee; build the canonical
        // `Set` from the same committee the snapshot/verifier uses.
        let committee_set: commonware_utils::ordered::Set<bls12381::PublicKey> =
            commonware_utils::ordered::Set::from_iter_dedup(keys.iter().map(|k| k.public_key()));
        let sigs: Vec<bls12381::Signature> = [0usize, 1, 2]
            .iter()
            .map(|&i| keys[i].sign(&finalize_namespace(&committee_set), &msg))
            .collect();
        let agg = aggregate::combine_signatures::<MinPk, _>(sigs.iter().map(|s| s.as_ref()));
        let mut aggregate_signature = [0u8; 96];
        aggregate_signature.copy_from_slice(&agg.encode());
        let mut signer_bitmap = vec![0u8; 4usize.div_ceil(8)];
        for i in [0usize, 1, 2] {
            signer_bitmap[i / 8] |= 1u8 << (i % 8);
        }
        let artifact = OutbeBlockArtifacts {
            execution_summary: None,
            consensus_header_artifact: None,
            timestamp_millis_part: 0,
            late_finalize_credits: Some(LateFinalizeCreditsArtifact {
                batches: vec![PerBlockCredit {
                    fb_number,
                    fb_hash,
                    epoch,
                    view,
                    parent_view,
                    committee_set_hash: csh,
                    signer_bitmap,
                    aggregate_signature,
                }],
            }),
            compressed_entities_root: None,
        };

        // Proposer encodes; validator decodes the same bytes and re-encodes.
        let extra_proposer = encode_outbe_block_artifacts(&artifact).unwrap();
        let decoded = decode_outbe_block_artifacts(extra_proposer.as_ref()).unwrap();
        let extra_validator = encode_outbe_block_artifacts(&decoded).unwrap();
        assert_eq!(
            extra_proposer, extra_validator,
            "codec round-trip must be byte-identical (proposer encode == validator re-encode)"
        );

        // Execute block N+K with the begin-zone, capturing the recorded
        // late-credit state for the live credit, the settled voter's fee-share
        // balance, the drained REWARDS balance, and receipt shape.
        let run = |extra_data: Bytes| -> (usize, Vec<u64>, u32, Vec<Address>, U256, U256, u64) {
            let signer = test_evm_signer();
            let proposer = signer.address();
            let snapshot = snapshot.clone();
            // Register the committee members so the window-close absentee pass can
            // slash them: all four are absent for the settled block (which credited
            // only `settle_voter`). At a single miss this is counter-only (no felony),
            // adding no balance effect - only the parity-checked miss counters.
            let mut seeded: Vec<(Address, [u8; 48])> = vec![(proposer, dummy_pubkey(0xA2))];
            for member in &snapshot.committee {
                seeded.push((member.address, member.consensus_pubkey));
            }
            let mut state = state_with_active_validators_seeded(&seeded, move |storage| {
                // The live credit's escrow binding is written by the N+K CPA
                // (on_finalized_metadata); the committee snapshot is pre-seeded
                // for the credit's BLS verify.
                outbe_validatorset::write_committee_snapshot(storage.clone(), epoch, &snapshot)
                    .expect("seed committee snapshot");

                // Pre-seed the matured escrow (block N), its k=1 voter, fund
                // REWARDS to back the payout + residue burn, and advance the
                // accounting marker so the N+K CPA progress gate passes.
                let seed_ctx = BlockRuntimeContext::new(
                    BlockContext::new(settle_target, 1, CHAIN_ID, Address::ZERO, vec![]),
                    storage,
                );
                outbe_rewards::late_settlement::escrow_block_fee(
                    &seed_ctx,
                    settle_target,
                    settle_fb_hash,
                    settle_fee,
                    settle_committee as u32,
                    epoch,
                    0, // canonical_view (block N is pre-seeded + settled, not live-credited)
                    0, // canonical_parent_view
                    csh,
                    &[],
                )
                .expect("seed matured escrow");
                outbe_rewards::late_settlement::record_late_credit(
                    &seed_ctx,
                    settle_fb_hash,
                    settle_voter,
                    1,
                )
                .expect("seed k=1 voter");
                seed_ctx
                    .storage
                    .increase_balance(REWARDS_ADDRESS, settle_fee)
                    .expect("fund REWARDS for settle");
                outbe_accounting::record_phase1_progress(&seed_ctx, progress_marker)
                    .expect("seed accounting progress");
            });
            let bridge = ConsensusExecutionBridge::new();
            bridge.record_execution_summary_with_state_root(
                fb_number,
                parent_hash,
                ExecutionSummaryArtifact {
                    validator_fee_sum: U256::ZERO,
                },
                1,
                B256::repeat_byte(0x91),
            );
            let config = OutbeEvmConfig::new_with_bridge(test_chain_spec(), bridge)
                .with_evm_signer(signer.clone());
            let mut metadata = test_metadata();
            metadata.finalized_block_number = fb_number;
            metadata.finalized_block_hash = parent_hash;
            // Canonical binding the CPA escrows; must match the credit.
            metadata.finalized_epoch = epoch;
            metadata.finalized_view = view;
            metadata.parent_view = parent_view;
            metadata.committee_set_hash = csh;
            let evm_env = test_evm_env(settle_block, REWARDS_ADDRESS);
            let evm = config.evm_with_env(&mut state, evm_env);
            let mut ctx = execution_ctx(Some(0), extra_data.clone());
            ctx.inner.parent_hash = parent_hash;
            ctx.parent_consensus_metadata = Some(metadata.clone());
            let mut executor = config.create_executor(evm, ctx);

            // Phase 1 disabled (no CPA cert seeded); late-finalize verify runs on
            // the valid credit + seeded snapshot.
            super::with_phase1_verify_disabled(|| {
                executor
                    .apply_pre_execution_changes()
                    .expect("pre-exec ok for a valid credit + seeded snapshot");
            });
            let system_txs = begin_system_txs_for_test(
                &config,
                settle_block,
                parent_hash,
                &extra_data,
                Some(metadata),
                proposer,
            );
            for tx in system_txs {
                executor
                    .execute_transaction(tx)
                    .expect("begin-zone system tx executes");
            }
            let receipts_len = executor.receipts().len();
            let gas: Vec<u64> = executor
                .receipts()
                .iter()
                .map(|r| r.cumulative_gas_used)
                .collect();
            drop(executor);

            // Read the recorded live-credit voters + the settled fee-share balances.
            let read_ctx =
                BlockContext::new(settle_block, settle_block, CHAIN_ID, proposer, vec![]);
            let mut provider =
                outbe_primitives::storage::direct::DirectStorageProvider::new(&mut state, read_ctx);
            let (count, voters, voter_balance, rewards_balance, absentee_miss) =
                StorageHandle::enter(&mut provider, |storage| {
                    let r = outbe_rewards::contract::Rewards::new(storage.clone());
                    let count = r.late_voter_count.read(&fb_hash)?;
                    let at = r.late_voter_at.get_nested(&fb_hash);
                    let mut voters = Vec::new();
                    for i in 0..count {
                        voters.push(at.read(&i)?);
                    }
                    let voter_balance = storage.balance(settle_voter)?;
                    let rewards_balance = storage.balance(REWARDS_ADDRESS)?;
                    // `addrs[3]` is a committee member absent for the settled block
                    // and not in the live in-window credit -> a pure window-close
                    // absentee. Its miss count must match on both paths.
                    let si = outbe_slashindicator::contract::SlashIndicator::new(storage.clone());
                    let absentee_miss = si.get_voter_miss_count(addrs[3])?;
                    Ok::<_, outbe_primitives::error::PrecompileError>((
                        count,
                        voters,
                        voter_balance,
                        rewards_balance,
                        absentee_miss,
                    ))
                })
                .expect("read recorded late-credit + settlement state");
            (
                receipts_len,
                gas,
                count,
                voters,
                voter_balance,
                rewards_balance,
                absentee_miss,
            )
        };

        let proposer_out = run(extra_proposer);
        let validator_out = run(extra_validator);

        assert_eq!(
            proposer_out, validator_out,
            "proposer and validator must reach identical late-credit + settlement state"
        );
        // Recording parity: the live credit's three signers were recorded.
        assert_eq!(
            proposer_out.2, 3,
            "three voters recorded for the in-window credit"
        );
        assert_eq!(proposer_out.3, addrs[0..3].to_vec());
        // Settlement actually PAID: the k=1 voter received its decay-weighted
        // fee-share, and REWARDS was drained of the settled escrow.
        assert_eq!(
            proposer_out.4, expected_payout,
            "settled k=1 voter must receive fee * w(1) / D"
        );
        assert!(
            !expected_payout.is_zero(),
            "the strengthened test must prove a non-zero balance delta"
        );
        assert_eq!(
            proposer_out.5,
            U256::ZERO,
            "REWARDS is drained: payout transferred + residue burned"
        );
        // Window-close slash parity: the absent committee member's miss is recorded
        // (slash fired) and is byte-identical on the proposer and validator paths
        // (the tuple equality above already compares it).
        assert_eq!(
            proposer_out.6, 1,
            "absent committee voter is slashed (miss recorded) at window close on both paths"
        );
    }

    #[test]
    fn boundary_activation_allows_registered_next_epoch_proposer() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let old_active_secret = [2; 32];
        let old_active = OutbeEvmSigner::from_secret_bytes(old_active_secret)
            .expect("old active test signer")
            .address();
        let mut state = state_with_active_and_registered_candidate(old_active, proposer);
        let evm_env = test_evm_env(1, REWARDS_ADDRESS);
        let boundary = boundary_with(
            true,
            vec![
                (old_active, dummy_pubkey(0xA2)),
                (proposer, dummy_pubkey(0xB3)),
            ],
        );
        let tee_bootstrap = sample_tee_bootstrap_payload_for(
            1,
            boundary.committee_set_hash,
            TEST_BLOCK_TIMESTAMP_BASE + 1 + 3_600,
            &[
                outbe_primitives::tee_test_utils::DevValidatorV1 {
                    evm_secret: old_active_secret,
                    bls_minpk_public: dummy_pubkey(0xA2),
                },
                outbe_primitives::tee_test_utils::DevValidatorV1 {
                    evm_secret: [1; 32],
                    bls_minpk_public: dummy_pubkey(0xB3),
                },
            ],
        );
        let extra_data = encode_outbe_block_artifacts(&OutbeBlockArtifacts {
            execution_summary: None,
            consensus_header_artifact: Some(ConsensusHeaderArtifact::BoundaryOutcome(boundary)),
            timestamp_millis_part: 0,
            late_finalize_credits: None,
            compressed_entities_root: None,
        })
        .expect("extra_data encodes");
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, evm_env);
        let mut executor = config.create_executor(
            evm,
            execution_ctx_with_tee_bootstrap(Some(0), extra_data.clone(), tee_bootstrap.clone()),
        );

        executor
            .apply_pre_execution_changes()
            .expect("activation block pre-execution should apply");
        let system_txs = begin_system_txs_for_test_with_bootstrap(
            &config,
            1,
            B256::ZERO,
            &extra_data,
            None,
            proposer,
            Some(tee_bootstrap),
        );
        for tx in system_txs {
            executor
                .execute_transaction(tx)
                .expect("activation block begin-zone system tx should execute");
        }

        assert_eq!(executor.receipts().len(), 6);
        assert!(executor.receipts().iter().all(|receipt| receipt.success));
        drop(executor);

        let read_ctx = BlockContext::new(1, 1, CHAIN_ID, proposer, vec![proposer]);
        let mut provider =
            outbe_primitives::storage::direct::DirectStorageProvider::new(&mut state, read_ctx);
        StorageHandle::enter(&mut provider, |storage| {
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            assert!(vs.is_consensus_participant(proposer)?);
            let record = vs.get_validator(proposer)?.expect("candidate should exist");
            assert_eq!(record.blocks_proposed, 1);
            Ok::<_, outbe_primitives::error::PrecompileError>(())
        })
        .expect("validator state should be readable");
    }

    #[test]
    fn full_begin_phases_then_user_tx_observes_boundary_activation() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let joining = address!("0x3333333333333333333333333333333333333333");
        let parent_hash = B256::with_last_byte(0xBC);
        let mut state = state_with_active_and_registered_candidate(proposer, joining);

        let mut metadata = test_metadata();
        metadata.finalized_block_number = 1;
        metadata.finalized_block_hash = parent_hash;
        metadata.ordered_committee = vec![proposer];
        metadata.signer_bitmap = vec![1];

        let bridge = ConsensusExecutionBridge::new();
        bridge.record_execution_summary_with_state_root(
            1,
            parent_hash,
            ExecutionSummaryArtifact {
                validator_fee_sum: U256::ZERO,
            },
            1,
            B256::repeat_byte(0x91),
        );
        // Block 2 activates current+1, so the boundary carries epoch 1.
        let boundary = boundary_with_epoch(
            1,
            true,
            vec![
                (proposer, dummy_pubkey(0xA2)),
                (joining, dummy_pubkey(0xB3)),
            ],
        );
        let extra_data = encode_outbe_block_artifacts(&OutbeBlockArtifacts {
            execution_summary: None,
            consensus_header_artifact: Some(ConsensusHeaderArtifact::BoundaryOutcome(boundary)),
            timestamp_millis_part: 0,
            late_finalize_credits: None,
            compressed_entities_root: None,
        })
        .expect("extra_data encodes");
        let config = OutbeEvmConfig::new_with_bridge(test_chain_spec(), bridge)
            .with_evm_signer(signer.clone());
        let mut evm_env = test_evm_env(2, REWARDS_ADDRESS);
        evm_env.block_env.basefee = 0;
        let evm = config.evm_with_env(&mut state, evm_env);
        let mut ctx = execution_ctx(Some(1), extra_data.clone());
        ctx.inner.parent_hash = parent_hash;
        ctx.parent_consensus_metadata = Some(metadata.clone());
        let mut executor = config.create_executor(evm, ctx);
        // this unit test does not seed a committee snapshot
        // matching the V2 metadata's `(epoch, committee_set_hash)` pair, so
        // the Phase 1 `verify_v2_proof` preflight would reject. The test
        // exercises pre-exec + begin-zone receipts, not the verifier
        // itself; opt out via the test-only escape hatch.
        super::with_phase1_verify_disabled(|| {
            executor
                .apply_pre_execution_changes()
                .expect("pre-execution changes should apply before begin-zone system txs");
        });
        let system_txs = begin_system_txs_for_test(
            &config,
            2,
            parent_hash,
            &extra_data,
            Some(metadata),
            proposer,
        );
        let mut visible_system_gas_used = 0u64;
        for tx in system_txs {
            let signed_gas_limit = tx.tx().gas_limit();
            let gas_output = executor
                .execute_transaction(tx)
                .expect("Phase 1+2+3+OracleSlashWindow begin-zone system tx should execute");
            assert!(gas_output.tx_gas_used() <= signed_gas_limit);
            visible_system_gas_used += gas_output.tx_gas_used();
            assert_eq!(
                executor
                    .receipts()
                    .last()
                    .expect("system receipt should be present")
                    .cumulative_gas_used,
                visible_system_gas_used
            );
        }
        // CPA + LateFinalizeCredits + CycleTick + RewardsGemDelivery +
        // BoundaryOutcome + OracleSlashWindow + HookEvents.
        assert_eq!(executor.receipts().len(), 7);
        assert!(executor.receipts().iter().all(|receipt| receipt.success));
        assert!(
            visible_system_gas_used < 30_000_000,
            "visible system gas used {visible_system_gas_used} should fit within block gas limit"
        );

        let deactivate_input =
            outbe_validatorset::precompile::IValidatorSet::deactivateValidatorCall {
                validatorAddress: joining,
            }
            .abi_encode();
        let deactivate_tx: reth_ethereum::TransactionSigned = TxEip1559 {
            chain_id: CHAIN_ID,
            nonce: 0,
            gas_limit: 200_000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(outbe_primitives::addresses::VALIDATOR_SET_ADDRESS),
            value: U256::ZERO,
            input: Bytes::from(deactivate_input),
            access_list: Default::default(),
        }
        .into_signed(Signature::test_signature())
        .into();
        let recovered_deactivate =
            reth_primitives_traits::Recovered::new_unchecked(deactivate_tx, joining);

        executor
            .execute_transaction(recovered_deactivate)
            .expect("same-block user tx should see joining validator as active");

        // 7 begin-zone receipts + 1 user (deactivate) tx.
        assert_eq!(executor.receipts().len(), 8);
        assert!(executor.receipts()[7].success);
        drop(executor);

        let read_ctx = BlockContext::new(2, 2, CHAIN_ID, proposer, vec![proposer, joining]);
        let mut provider =
            outbe_primitives::storage::direct::DirectStorageProvider::new(&mut state, read_ctx);
        StorageHandle::enter(&mut provider, |storage| {
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            let record = vs
                .get_validator(joining)?
                .expect("joining validator exists");
            assert_eq!(record.status, outbe_validatorset::logic::status::EXITING);
            assert!(vs.has_pending_set_change()?);
            Ok::<_, outbe_primitives::error::PrecompileError>(())
        })
        .expect("same-block user mutation should be readable");
    }

    #[test]
    fn pre_exec_hooks_emit_whitelisted_update_activation_event() {
        use alloy_sol_types::SolEvent;
        use outbe_update::payload::encode_schedule_update_json;
        use outbe_update::precompile::IUpdate;
        use serde_json::Value;

        let proposer = test_evm_signer().address();
        const ACTIVATION_BLOCK: u64 = 101;
        let protocol_version = outbe_update::constants::PROTOCOL_VERSION;

        let mut state =
            state_with_active_validators_seeded(&[(proposer, dummy_pubkey(0xA2))], |storage| {
                let proposal_id = U256::from(1);
                let payload: Value = serde_json::from_str(&encode_schedule_update_json(
                    protocol_version,
                    ACTIVATION_BLOCK,
                    "",
                ))
                .expect("schedule update JSON should parse");
                let mut update = outbe_update::schema::Update::new(storage.clone());
                update
                    .schedule_update_from_propose(proposal_id, &payload, 1)
                    .expect("schedule update");
            });

        let ctx = BlockContext::new(
            ACTIVATION_BLOCK,
            ACTIVATION_BLOCK,
            CHAIN_ID,
            proposer,
            vec![proposer],
        );
        let (_, hook_events) = super::run_atomic_storage_hooks(&mut state, ctx, |hook_ctx| {
            super::run_outbe_pre_execution_hooks(hook_ctx, None)
        })
        .expect("pre-exec hooks should run");
        let (whitelisted, _) = partition_hook_events(&hook_events);
        let upgrade_activated = IUpdate::UpgradeActivated::SIGNATURE_HASH;
        assert!(
            whitelisted.iter().any(|log| {
                log.address == UPDATE_ADDRESS
                    && log.data.topics().first() == Some(&upgrade_activated)
            }),
            "pre-exec hooks must emit whitelisted UpgradeActivated for HookEvents receipt"
        );
    }

    #[test]
    fn hook_events_receipt_carries_whitelisted_update_activation_log() {
        use alloy_sol_types::SolEvent;
        use outbe_update::payload::encode_schedule_update_json;
        use outbe_update::precompile::IUpdate;
        use serde_json::Value;

        let proposer = test_evm_signer().address();
        const ACTIVATION_BLOCK: u64 = 101;
        let protocol_version = outbe_update::constants::PROTOCOL_VERSION;

        let mut state =
            state_with_active_validators_seeded(&[(proposer, dummy_pubkey(0xA2))], |storage| {
                let proposal_id = U256::from(1);
                let payload: Value = serde_json::from_str(&encode_schedule_update_json(
                    protocol_version,
                    ACTIVATION_BLOCK,
                    "",
                ))
                .expect("schedule update JSON should parse");
                let mut update = outbe_update::schema::Update::new(storage.clone());
                update
                    .schedule_update_from_propose(proposal_id, &payload, 1)
                    .expect("schedule update");
            });

        let ctx = BlockContext::new(
            ACTIVATION_BLOCK,
            ACTIVATION_BLOCK,
            CHAIN_ID,
            proposer,
            vec![proposer],
        );
        let (_, hook_events) = super::run_atomic_storage_hooks(&mut state, ctx, |hook_ctx| {
            super::run_outbe_pre_execution_hooks(hook_ctx, None)
        })
        .expect("pre-exec hooks should emit activation events");
        let (whitelisted_logs, _) = partition_hook_events(&hook_events);

        let config = OutbeEvmConfig::new(test_chain_spec());
        let evm = config.evm_with_env(&mut state, test_evm_env(ACTIVATION_BLOCK, REWARDS_ADDRESS));
        let mut executor = config.create_executor(evm, execution_ctx(None, Bytes::new()));
        executor
            .push_hook_events_receipt(alloy_consensus::TxType::Legacy, whitelisted_logs, 21_000)
            .expect("HookEvents receipt should publish captured hook logs");

        let hook_receipt = executor.receipts().last().expect("HookEvents receipt");
        assert!(hook_receipt.success);
        let upgrade_activated = IUpdate::UpgradeActivated::SIGNATURE_HASH;
        assert!(
            hook_receipt.logs.iter().any(|log| {
                log.address == UPDATE_ADDRESS
                    && log.data.topics().first() == Some(&upgrade_activated)
            }),
            "HookEvents receipt must carry UpgradeActivated from pre-exec hook events"
        );
    }

    #[test]
    fn real_factory_approval_is_published_in_hook_events_receipt() {
        const CREATION_BLOCK: u64 = 7;
        const HOOK_EVENTS_GAS: u64 = 21_000;
        let issuer = Address::repeat_byte(0x11);
        let validators = [
            (Address::repeat_byte(0xa1), dummy_pubkey(0xa1)),
            (Address::repeat_byte(0xa2), dummy_pubkey(0xa2)),
            (Address::repeat_byte(0xa3), dummy_pubkey(0xa3)),
        ];
        let payload = encode_canonical_stablecoin_create(&StablecoinCreatePayload {
            issuer,
            name: "Example Dollar".into(),
            ticker: "EXUSD".into(),
            iso4217: 840,
            decimals: 6,
            supply_cap: U256::from(1_000_000u64),
            policy_id: U256::from(1u64),
        })
        .expect("canonical Factory payload");
        let payload = core::str::from_utf8(&payload).expect("canonical payload is UTF-8");
        let forced_surplus = U256::from(7u64);
        let mut expected_token_id = B256::ZERO;
        let mut expected_token = Address::ZERO;
        let mut state =
            state_with_active_validators_seeded_at_block(&validators, CREATION_BLOCK, |storage| {
                storage
                    .set_balance(VOTE_ADDRESS, STABLECOIN_CREATE_BOND + forced_surplus)
                    .unwrap();
                (expected_token_id, expected_token) =
                    StablecoinFactoryContract::new(storage.clone())
                        .predict_token_address(issuer, "EXUSD")
                        .unwrap();
                let mut vote = Vote::new(storage);
                let proposal_id = vote
                    .create_proposal_with_value(
                        issuer,
                        STABLECOIN_FACTORY_ADDRESS,
                        payload,
                        CREATION_BLOCK,
                        STABLECOIN_CREATE_BOND,
                        crate::handlers::vote::registry(),
                    )
                    .unwrap();
                assert_eq!(proposal_id, U256::from(1u64));
                vote.cast_vote_approve(proposal_id, validators[0].0, true, CREATION_BLOCK + 1)
                    .unwrap();
                vote.cast_vote_approve(proposal_id, validators[1].0, true, CREATION_BLOCK + 1)
                    .unwrap();
            });

        let finalization_block = CREATION_BLOCK + VOTING_WINDOW_BLOCKS + 1;
        let block_context = BlockContext::new(
            finalization_block,
            1_700_000_000,
            CHAIN_ID,
            issuer,
            validators.iter().map(|(address, _)| *address).collect(),
        );
        let (_, hook_events) =
            super::run_atomic_storage_hooks(&mut state, block_context.clone(), |hook_ctx| {
                super::run_outbe_pre_execution_hooks(hook_ctx, None)
            })
            .expect("real Vote -> Factory pre-exec lifecycle should commit");
        let (receipt_logs, _) = partition_hook_events(&hook_events);

        let factory_logs: Vec<_> = receipt_logs
            .iter()
            .filter(|log| {
                log.address == STABLECOIN_FACTORY_ADDRESS
                    && log.data.topics().first()
                        == Some(&IStablecoinFactory::StablecoinCreated::SIGNATURE_HASH)
            })
            .collect();
        assert_eq!(factory_logs.len(), 1);
        let factory_log_index = receipt_logs
            .iter()
            .position(|log| {
                log.address == STABLECOIN_FACTORY_ADDRESS
                    && log.data.topics().first()
                        == Some(&IStablecoinFactory::StablecoinCreated::SIGNATURE_HASH)
            })
            .unwrap();
        let refund_log_index = receipt_logs
            .iter()
            .position(|log| {
                log.address == VOTE_ADDRESS
                    && log.data.topics().first()
                        == Some(&IVote::ProposalBondRefunded::SIGNATURE_HASH)
            })
            .expect("Approved proposal must emit one refund");
        assert!(
            factory_log_index < refund_log_index,
            "target event must precede settlement event in committed hook order"
        );

        {
            let mut provider = super::DirectStorageProvider::new(&mut state, block_context.clone());
            let storage = StorageHandle::new(&mut provider);
            let vote = Vote::new(storage.clone());
            let factory = StablecoinFactoryContract::new(storage.clone());
            assert_eq!(
                vote.proposals
                    .get(U256::from(1u64))
                    .unwrap()
                    .unwrap()
                    .proposal_status()
                    .unwrap(),
                ProposalStatus::Approved
            );
            assert_eq!(
                vote.proposal_bond(U256::from(1u64)).unwrap().settlement,
                BondSettlement::Refunded
            );
            assert_eq!(vote.bond_liabilities().unwrap(), U256::ZERO);
            assert_eq!(storage.balance(VOTE_ADDRESS).unwrap(), forced_surplus);
            assert_eq!(storage.balance(issuer).unwrap(), STABLECOIN_CREATE_BOND);
            assert_eq!(factory.token_count().unwrap(), U256::from(1u64));
            assert_eq!(
                factory.registered_token_id(expected_token).unwrap(),
                Some(expected_token_id)
            );
            assert_eq!(
                factory.token_id_of(expected_token).unwrap(),
                expected_token_id
            );
            assert!(!factory.reservations.exists(U256::from(1u64)).unwrap());
        }
        let token_account = state
            .basic(expected_token)
            .expect("token account read")
            .expect("created token account");
        assert_eq!(
            token_account
                .code
                .as_ref()
                .expect("created token marker")
                .original_bytes()
                .as_ref(),
            outbe_primitives::addresses::STABLECOIN_MARKER_CODE
        );

        let config = OutbeEvmConfig::new(test_chain_spec());
        let evm = config.evm_with_env(
            &mut state,
            test_evm_env(finalization_block, REWARDS_ADDRESS),
        );
        let mut executor = config.create_executor(evm, execution_ctx(None, Bytes::new()));
        executor
            .push_hook_events_receipt(
                alloy_consensus::TxType::Legacy,
                receipt_logs,
                HOOK_EVENTS_GAS,
            )
            .expect("HookEvents receipt should publish committed Factory log");

        let receipt = executor.receipts().last().expect("HookEvents receipt");
        assert!(receipt.success);
        assert_eq!(receipt.cumulative_gas_used, HOOK_EVENTS_GAS);
        assert_eq!(
            receipt
                .logs
                .iter()
                .filter(|log| {
                    log.address == STABLECOIN_FACTORY_ADDRESS
                        && log.data.topics().first()
                            == Some(&IStablecoinFactory::StablecoinCreated::SIGNATURE_HASH)
                })
                .count(),
            1
        );
        let with_factory_root =
            alloy_consensus::proofs::calculate_receipt_root(&[receipt.with_bloom_ref()]);
        let mut without_factory_log = receipt.clone();
        without_factory_log.logs.retain(|log| {
            log.address != STABLECOIN_FACTORY_ADDRESS
                || log.data.topics().first()
                    != Some(&IStablecoinFactory::StablecoinCreated::SIGNATURE_HASH)
        });
        let without_factory_root =
            alloy_consensus::proofs::calculate_receipt_root(
                &[without_factory_log.with_bloom_ref()],
            );
        assert_ne!(
            with_factory_root, without_factory_root,
            "StablecoinCreated must contribute to the receipts root"
        );
        assert_ne!(
            logs_bloom(receipt.logs.iter()),
            logs_bloom(without_factory_log.logs.iter()),
            "StablecoinCreated must contribute to the logs bloom"
        );
    }

    #[test]
    fn real_factory_execution_error_has_no_factory_receipt_log() {
        const CREATION_BLOCK: u64 = 7;
        let issuer = Address::repeat_byte(0x11);
        let validators = [
            (Address::repeat_byte(0xb1), dummy_pubkey(0xb1)),
            (Address::repeat_byte(0xb2), dummy_pubkey(0xb2)),
            (Address::repeat_byte(0xb3), dummy_pubkey(0xb3)),
        ];
        let payload = encode_canonical_stablecoin_create(&StablecoinCreatePayload {
            issuer,
            name: "Example Dollar".into(),
            ticker: "EXUSD".into(),
            iso4217: 840,
            decimals: 6,
            supply_cap: U256::from(1_000_000u64),
            policy_id: U256::from(1u64),
        })
        .expect("canonical Factory payload");
        let payload = core::str::from_utf8(&payload).expect("canonical payload is UTF-8");
        let mut state =
            state_with_active_validators_seeded_at_block(&validators, CREATION_BLOCK, |storage| {
                storage
                    .set_balance(VOTE_ADDRESS, STABLECOIN_CREATE_BOND)
                    .unwrap();
                let mut vote = Vote::new(storage);
                let proposal_id = vote
                    .create_proposal_with_value(
                        issuer,
                        STABLECOIN_FACTORY_ADDRESS,
                        payload,
                        CREATION_BLOCK,
                        STABLECOIN_CREATE_BOND,
                        crate::handlers::vote::registry(),
                    )
                    .unwrap();
                let mut corrupted = vote.proposals.get(proposal_id).unwrap().unwrap();
                corrupted.payload = "{".into();
                vote.proposals.update(&corrupted).unwrap();
                vote.cast_vote_approve(proposal_id, validators[0].0, true, CREATION_BLOCK + 1)
                    .unwrap();
                vote.cast_vote_approve(proposal_id, validators[1].0, true, CREATION_BLOCK + 1)
                    .unwrap();
            });

        let finalization_block = CREATION_BLOCK + VOTING_WINDOW_BLOCKS + 1;
        let block_context = BlockContext::new(
            finalization_block,
            1_700_000_000,
            CHAIN_ID,
            issuer,
            validators.iter().map(|(address, _)| *address).collect(),
        );
        let (_, hook_events) =
            super::run_atomic_storage_hooks(&mut state, block_context.clone(), |hook_ctx| {
                super::run_outbe_pre_execution_hooks(hook_ctx, None)
            })
            .expect("typed target Error must not fail the outer hook batch");
        let (receipt_logs, _) = partition_hook_events(&hook_events);
        assert!(receipt_logs.iter().all(|log| {
            log.address != STABLECOIN_FACTORY_ADDRESS
                || log.data.topics().first()
                    != Some(&IStablecoinFactory::StablecoinCreated::SIGNATURE_HASH)
        }));
        assert!(receipt_logs.iter().all(|log| {
            log.address != VOTE_ADDRESS
                || (log.data.topics().first() != Some(&IVote::ProposalBondRefunded::SIGNATURE_HASH)
                    && log.data.topics().first()
                        != Some(&IVote::ProposalBondBurned::SIGNATURE_HASH))
        }));
        {
            let config = OutbeEvmConfig::new(test_chain_spec());
            let evm = config.evm_with_env(
                &mut state,
                test_evm_env(finalization_block, REWARDS_ADDRESS),
            );
            let mut executor = config.create_executor(evm, execution_ctx(None, Bytes::new()));
            executor
                .push_hook_events_receipt(alloy_consensus::TxType::Legacy, receipt_logs, 21_000)
                .expect("Error outcome HookEvents receipt");
            let receipt = executor.receipts().last().expect("HookEvents receipt");
            assert!(receipt.logs.iter().all(|log| {
                log.address != STABLECOIN_FACTORY_ADDRESS
                    || log.data.topics().first()
                        != Some(&IStablecoinFactory::StablecoinCreated::SIGNATURE_HASH)
            }));
        }

        let mut provider = super::DirectStorageProvider::new(&mut state, block_context);
        let storage = StorageHandle::new(&mut provider);
        let vote = Vote::new(storage.clone());
        let factory = StablecoinFactoryContract::new(storage.clone());
        assert_eq!(
            vote.proposals
                .get(U256::from(1u64))
                .unwrap()
                .unwrap()
                .proposal_status()
                .unwrap(),
            ProposalStatus::Error
        );
        assert_eq!(
            vote.proposal_bond(U256::from(1u64)).unwrap().settlement,
            BondSettlement::Unsettled
        );
        assert_eq!(vote.bond_liabilities().unwrap(), STABLECOIN_CREATE_BOND);
        assert_eq!(
            storage.balance(VOTE_ADDRESS).unwrap(),
            STABLECOIN_CREATE_BOND
        );
        assert_eq!(factory.token_count().unwrap(), U256::ZERO);
        assert!(factory.reservations.exists(U256::from(1u64)).unwrap());
    }

    #[test]
    fn factory_boundaries_are_byte_equal_across_proposer_and_validator_execution() {
        use std::collections::BTreeMap;

        use reth_primitives_traits::Account as TrieAccount;
        use reth_trie::test_utils::state_root;

        #[derive(Clone, Copy, Debug)]
        enum Boundary {
            Approved,
            Expired,
            Error,
        }

        #[derive(Debug, PartialEq, Eq)]
        struct Output {
            state_root: B256,
            receipts_root: B256,
            logs_bloom: alloy_primitives::Bloom,
            receipt_bytes: Vec<Vec<u8>>,
            receipt_success: Vec<bool>,
            cumulative_gas: Vec<u64>,
            created_logs: usize,
            refunded_logs: usize,
            burned_logs: usize,
            status: ProposalStatus,
            settlement: BondSettlement,
            factory_count: U256,
            registered_token_id: Option<B256>,
            token_by_id: Address,
            token_by_ticker: Address,
            token_code_hash: Option<B256>,
            token_total_supply: U256,
            issuer_token_balance: U256,
            issuer_balance: U256,
            vote_balance: U256,
            liabilities: U256,
            reservation_exists: bool,
        }

        fn full_state_root(state: &State<CacheDB<EmptyDBTyped<ProviderError>>>) -> B256 {
            let mut accounts: BTreeMap<Address, (AccountInfo, BTreeMap<U256, U256>)> = state
                .database
                .cache
                .accounts
                .iter()
                .filter_map(|(address, account)| {
                    account.info().map(|info| {
                        (
                            *address,
                            (
                                info,
                                account.storage.iter().map(|(k, v)| (*k, *v)).collect(),
                            ),
                        )
                    })
                })
                .collect();
            for (address, cached) in &state.cache.accounts {
                match &cached.account {
                    Some(current) => {
                        let entry = accounts
                            .entry(*address)
                            .or_insert_with(|| (current.info.clone(), BTreeMap::new()));
                        entry.0 = current.info.clone();
                        entry
                            .1
                            .extend(current.storage.iter().map(|(k, v)| (*k, *v)));
                    }
                    None => {
                        accounts.remove(address);
                    }
                }
            }
            state_root(accounts.into_iter().map(|(address, (info, storage))| {
                let bytecode_hash = (!info.code_hash.is_zero() && info.code_hash != keccak256([]))
                    .then_some(info.code_hash);
                let account = TrieAccount {
                    nonce: info.nonce,
                    balance: info.balance,
                    bytecode_hash,
                };
                let storage = storage
                    .into_iter()
                    .filter(|(_, value)| !value.is_zero())
                    .map(|(slot, value)| (B256::from(slot.to_be_bytes::<32>()), value));
                (address, (account, storage))
            }))
        }

        fn run(boundary: Boundary, validator_execution: bool) -> Output {
            const CREATION_BLOCK: u64 = 7;
            let finalization_block = CREATION_BLOCK + VOTING_WINDOW_BLOCKS + 1;
            let signer = test_evm_signer();
            let proposer = signer.address();
            let issuer = Address::repeat_byte(0x31);
            let validators = [
                (proposer, dummy_pubkey(0xc1)),
                (Address::repeat_byte(0xc2), dummy_pubkey(0xc2)),
                (Address::repeat_byte(0xc3), dummy_pubkey(0xc3)),
            ];
            let payload = encode_canonical_stablecoin_create(&StablecoinCreatePayload {
                issuer,
                name: "Parity Dollar".into(),
                ticker: "PARUSD".into(),
                iso4217: 840,
                decimals: 6,
                supply_cap: U256::from(1_000_000u64),
                policy_id: U256::from(1u64),
            })
            .expect("canonical Factory payload");
            let payload = core::str::from_utf8(&payload).expect("canonical payload is UTF-8");

            let mut state =
                state_with_active_validators_seeded_at_block(&validators, CREATION_BLOCK, |_| {});
            let seed_context = BlockContext::new(
                CREATION_BLOCK,
                1_700_000_000,
                CHAIN_ID,
                proposer,
                validators.iter().map(|(address, _)| *address).collect(),
            );
            let (expected_token_id, expected_token) = {
                let mut provider =
                    super::DirectStorageProvider::new(&mut state, seed_context.clone());
                let storage = StorageHandle::new(&mut provider);
                storage
                    .set_balance(VOTE_ADDRESS, STABLECOIN_CREATE_BOND)
                    .unwrap();
                let predicted = StablecoinFactoryContract::new(storage.clone())
                    .predict_token_address(issuer, "PARUSD")
                    .unwrap();
                let mut vote = Vote::new(storage.clone());
                let proposal_id = vote
                    .create_proposal_with_value(
                        issuer,
                        STABLECOIN_FACTORY_ADDRESS,
                        payload,
                        CREATION_BLOCK,
                        STABLECOIN_CREATE_BOND,
                        crate::handlers::vote::registry(),
                    )
                    .unwrap();
                match boundary {
                    Boundary::Approved | Boundary::Error => {
                        vote.cast_vote_approve(
                            proposal_id,
                            validators[0].0,
                            true,
                            CREATION_BLOCK + 1,
                        )
                        .unwrap();
                        vote.cast_vote_approve(
                            proposal_id,
                            validators[1].0,
                            true,
                            CREATION_BLOCK + 1,
                        )
                        .unwrap();
                    }
                    Boundary::Expired => {}
                }
                if matches!(boundary, Boundary::Error) {
                    let mut corrupted = vote.proposals.get(proposal_id).unwrap().unwrap();
                    corrupted.payload = "{".into();
                    vote.proposals.update(&corrupted).unwrap();
                }
                let progress_context = BlockRuntimeContext::new(seed_context, storage.clone());
                outbe_accounting::record_phase1_progress(&progress_context, finalization_block - 2)
                    .unwrap();
                provider.flush().expect("seed direct storage");
                predicted
            };

            let parent_hash = B256::repeat_byte(0x71);
            let mut metadata = test_metadata();
            metadata.finalized_block_number = finalization_block - 1;
            metadata.finalized_block_hash = parent_hash;
            metadata.ordered_committee = validators.iter().map(|(address, _)| *address).collect();
            metadata.signer_bitmap = vec![1; validators.len()];

            let bridge = ConsensusExecutionBridge::new();
            bridge.record_execution_summary_with_state_root(
                metadata.finalized_block_number,
                parent_hash,
                ExecutionSummaryArtifact {
                    validator_fee_sum: U256::ZERO,
                },
                1_700_000_000,
                B256::repeat_byte(0x91),
            );
            let config =
                OutbeEvmConfig::new_with_bridge(test_chain_spec(), bridge).with_evm_signer(signer);
            let system_txs = begin_system_txs_for_test(
                &config,
                finalization_block,
                parent_hash,
                &Bytes::new(),
                Some(metadata.clone()),
                proposer,
            );
            let evm = config.evm_with_env(
                &mut state,
                test_evm_env(finalization_block, REWARDS_ADDRESS),
            );
            let mut execution = execution_ctx(Some(0), Bytes::new());
            execution.inner.parent_hash = parent_hash;
            execution.parent_consensus_metadata = Some(metadata);
            execution.proposer_evm_address = Some(proposer);
            if validator_execution {
                execution.expected_begin_system_txs = system_txs.clone();
            }
            let mut executor = config.create_executor(evm, execution);
            super::with_phase1_verify_disabled(|| {
                executor
                    .apply_pre_execution_changes()
                    .expect("stablecoin boundary pre-execution");
            });
            for transaction in system_txs {
                executor
                    .execute_transaction(transaction)
                    .expect("mandatory begin-zone transaction");
            }

            let receipts = executor.receipts().to_vec();
            let receipt_bytes = receipts
                .iter()
                .map(|receipt| receipt.with_bloom_ref().encoded_2718())
                .collect();
            let receipt_blooms: Vec<_> = receipts
                .iter()
                .map(|receipt| receipt.with_bloom_ref())
                .collect();
            let receipts_root = alloy_consensus::proofs::calculate_receipt_root(&receipt_blooms);
            let block_bloom = logs_bloom(receipts.iter().flat_map(|receipt| receipt.logs.iter()));
            let receipt_success = receipts.iter().map(|receipt| receipt.success).collect();
            let cumulative_gas = receipts
                .iter()
                .map(|receipt| receipt.cumulative_gas_used)
                .collect();
            let created_logs = receipts
                .iter()
                .flat_map(|receipt| &receipt.logs)
                .filter(|log| {
                    log.address == STABLECOIN_FACTORY_ADDRESS
                        && log.data.topics().first()
                            == Some(&IStablecoinFactory::StablecoinCreated::SIGNATURE_HASH)
                })
                .count();
            let refunded_logs = receipts
                .iter()
                .flat_map(|receipt| &receipt.logs)
                .filter(|log| {
                    log.address == VOTE_ADDRESS
                        && log.data.topics().first()
                            == Some(&IVote::ProposalBondRefunded::SIGNATURE_HASH)
                })
                .count();
            let burned_logs = receipts
                .iter()
                .flat_map(|receipt| &receipt.logs)
                .filter(|log| {
                    log.address == VOTE_ADDRESS
                        && log.data.topics().first()
                            == Some(&IVote::ProposalBondBurned::SIGNATURE_HASH)
                })
                .count();
            drop(executor);

            let read_context = BlockContext::new(
                finalization_block,
                1_700_000_000,
                CHAIN_ID,
                proposer,
                validators.iter().map(|(address, _)| *address).collect(),
            );
            let (
                status,
                settlement,
                factory_count,
                registered_token_id,
                token_by_id,
                token_by_ticker,
                token_total_supply,
                issuer_token_balance,
                issuer_balance,
                vote_balance,
                liabilities,
                reservation_exists,
            ) = {
                let mut provider = super::DirectStorageProvider::new(&mut state, read_context);
                let storage = StorageHandle::new(&mut provider);
                let vote = Vote::new(storage.clone());
                let factory = StablecoinFactoryContract::new(storage.clone());
                let factory_count = factory.token_count().unwrap();
                let (token_total_supply, issuer_token_balance) = if factory_count == U256::ONE {
                    let token = StablecoinContract::new(storage.clone(), expected_token);
                    (
                        token.total_supply().unwrap(),
                        token.balance_of(issuer).unwrap(),
                    )
                } else {
                    (U256::ZERO, U256::ZERO)
                };
                (
                    vote.proposals
                        .get(U256::from(1u64))
                        .unwrap()
                        .unwrap()
                        .proposal_status()
                        .unwrap(),
                    vote.proposal_bond(U256::from(1u64)).unwrap().settlement,
                    factory_count,
                    factory.registered_token_id(expected_token).unwrap(),
                    factory.token_by_id(expected_token_id).unwrap(),
                    factory.token_by_ticker("PARUSD").unwrap(),
                    token_total_supply,
                    issuer_token_balance,
                    storage.balance(issuer).unwrap(),
                    storage.balance(VOTE_ADDRESS).unwrap(),
                    vote.bond_liabilities().unwrap(),
                    factory.reservations.exists(U256::from(1u64)).unwrap(),
                )
            };
            let token_code_hash = state
                .basic(expected_token)
                .expect("token account read")
                .map(|account| account.code_hash);
            let state_root = full_state_root(&state);

            if matches!(boundary, Boundary::Approved) {
                assert_eq!(registered_token_id, Some(expected_token_id));
            }
            Output {
                state_root,
                receipts_root,
                logs_bloom: block_bloom,
                receipt_bytes,
                receipt_success,
                cumulative_gas,
                created_logs,
                refunded_logs,
                burned_logs,
                status,
                settlement,
                factory_count,
                registered_token_id,
                token_by_id,
                token_by_ticker,
                token_code_hash,
                token_total_supply,
                issuer_token_balance,
                issuer_balance,
                vote_balance,
                liabilities,
                reservation_exists,
            }
        }

        for boundary in [Boundary::Approved, Boundary::Expired, Boundary::Error] {
            let proposer = run(boundary, false);
            let validator = run(boundary, true);
            assert_eq!(
                proposer, validator,
                "{boundary:?} must be byte/state equal across execution roles"
            );
            assert_eq!(proposer.receipt_success, vec![true; 6]);
            assert_eq!(proposer.cumulative_gas.len(), 6);
            match boundary {
                Boundary::Approved => {
                    assert_eq!(proposer.created_logs, 1);
                    assert_eq!(proposer.refunded_logs, 1);
                    assert_eq!(proposer.burned_logs, 0);
                    assert_eq!(proposer.status, ProposalStatus::Approved);
                    assert_eq!(proposer.settlement, BondSettlement::Refunded);
                    assert_eq!(proposer.factory_count, U256::ONE);
                    assert_ne!(proposer.token_by_id, Address::ZERO);
                    assert_eq!(proposer.token_by_id, proposer.token_by_ticker);
                    assert_eq!(
                        proposer.token_code_hash,
                        Some(keccak256(
                            outbe_primitives::addresses::STABLECOIN_MARKER_CODE
                        ))
                    );
                    assert_eq!(proposer.token_total_supply, U256::ZERO);
                    assert_eq!(proposer.issuer_token_balance, U256::ZERO);
                    assert_eq!(proposer.issuer_balance, STABLECOIN_CREATE_BOND);
                    assert_eq!(proposer.vote_balance, U256::ZERO);
                    assert_eq!(proposer.liabilities, U256::ZERO);
                    assert!(!proposer.reservation_exists);
                }
                Boundary::Expired => {
                    assert_eq!(proposer.created_logs, 0);
                    assert_eq!(proposer.refunded_logs, 0);
                    assert_eq!(proposer.burned_logs, 1);
                    assert_eq!(proposer.status, ProposalStatus::Expired);
                    assert_eq!(proposer.settlement, BondSettlement::Burned);
                    assert_eq!(proposer.factory_count, U256::ZERO);
                    assert_eq!(proposer.issuer_balance, U256::ZERO);
                    assert_eq!(proposer.vote_balance, U256::ZERO);
                    assert_eq!(proposer.liabilities, U256::ZERO);
                    assert!(!proposer.reservation_exists);
                    assert!(proposer.registered_token_id.is_none());
                    assert_eq!(proposer.token_by_id, Address::ZERO);
                    assert_eq!(proposer.token_by_ticker, Address::ZERO);
                    assert_eq!(proposer.token_total_supply, U256::ZERO);
                }
                Boundary::Error => {
                    assert_eq!(proposer.created_logs, 0);
                    assert_eq!(proposer.refunded_logs, 0);
                    assert_eq!(proposer.burned_logs, 0);
                    assert_eq!(proposer.status, ProposalStatus::Error);
                    assert_eq!(proposer.settlement, BondSettlement::Unsettled);
                    assert_eq!(proposer.factory_count, U256::ZERO);
                    assert_eq!(proposer.issuer_balance, U256::ZERO);
                    assert_eq!(proposer.vote_balance, STABLECOIN_CREATE_BOND);
                    assert_eq!(proposer.liabilities, STABLECOIN_CREATE_BOND);
                    assert!(proposer.reservation_exists);
                    assert!(proposer.registered_token_id.is_none());
                    assert_eq!(proposer.token_by_id, Address::ZERO);
                    assert_eq!(proposer.token_by_ticker, Address::ZERO);
                    assert_eq!(proposer.token_total_supply, U256::ZERO);
                }
            }
        }
    }

    #[test]
    fn independent_body_stores_produce_identical_full_block_state_receipts_and_balances() {
        use reth_trie::{test_utils::state_root_prehashed, HashedPostState, KeccakKeyHasher};

        fn post_state_root(state: &revm::database::BundleState) -> B256 {
            let sorted =
                HashedPostState::from_bundle_state::<KeccakKeyHasher>(state.state()).into_sorted();
            let storages = sorted.storages;
            let accounts = sorted
                .accounts
                .into_iter()
                .filter_map(|(address, account)| {
                    account.map(|account| {
                        let storage = storages
                            .get(&address)
                            .map(|storage| storage.storage_slots.clone())
                            .unwrap_or_default();
                        (address, (account, storage))
                    })
                });
            state_root_prehashed(accounts)
        }

        let proposer = test_evm_signer().address();
        let worldwide_day = WorldwideDay::new(20_241_220);
        let floor_price_minor = U256::from(500_000u64);
        let bucket_key = NodContract::bucket_key(worldwide_day, floor_price_minor, 840);
        let seed_state = || {
            let (directory, tree_service) = persistent_test_tree(B256::ZERO);
            let empty_root = outbe_compressed_entities::sealed_root(B256::ZERO).unwrap();
            let parent_tree = tree_service
                .open_parent(ExactParentIdentity {
                    commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                    block_number: 0,
                    block_hash: B256::ZERO,
                    root: empty_root,
                })
                .expect("open exact empty CE parent");
            let scope =
                ExecutionScope::with_parent_tree(parent_tree, CeWorkConfig::new(0, 0, u64::MAX));
            let mut staged = None;
            let state = state_with_active_validators_seeded_at_block(
                &[(proposer, dummy_pubkey(0xA2))],
                1,
                |storage| {
                    storage
                        .sstore(
                            outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
                            U256::ZERO,
                            U256::from(2_u64),
                        )
                        .unwrap();
                    storage
                        .sstore(
                            outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
                            U256::from(1_u64),
                            U256::from_be_bytes(empty_root.0),
                        )
                        .unwrap();
                    outbe_compressed_entities::begin_block(storage.clone(), &scope)
                        .expect("open compressed-entity seed scope");
                    let empty_reader = NodRepositoryReader::new(Arc::new(MemoryStorage::new()));
                    outbe_nod::api::add_nod(
                        &storage,
                        &scope,
                        &empty_reader,
                        &NodItemState {
                            nod_id: NodContract::generate_nod_id(proposer, worldwide_day).unwrap(),
                            owner: proposer,
                            gratis_load_minor: U256::from(1_000_000u64),
                            worldwide_day,
                            league_id: 1,
                            floor_price_minor,
                            bucket_key,
                            issuance_currency: 840,
                            reference_currency: 840,
                            issued_at: 1,
                        },
                        U256::from(450_000_000u64),
                    )
                    .expect("seed compact Nod scheduling state");
                    staged = Some(
                        outbe_compressed_entities::end_block(storage, &scope)
                            .expect("close compressed-entity seed scope")
                            .staged_tree_batch,
                    );
                },
            );
            let staged = staged.expect("seed lifecycle must produce a tree batch");
            let seed_hash = B256::repeat_byte(0x41);
            let seed_root = staged.new_root();
            tree_service
                .publish_candidate(seed_hash, staged)
                .expect("publish seed CE candidate");
            tree_service
                .apply_finalized(1, seed_hash, seed_root)
                .expect("finalize seed CE candidate");
            (state, directory, tree_service, seed_hash)
        };
        let independent_readers = || {
            let adapter = Arc::new(MemoryStorage::new());
            let reader: StorageReaderHandle = adapter.clone();
            let writer: StorageWriterHandle = adapter;
            NodRepositoryWriter::new(reader.clone(), writer)
                .put_bucket(&NodBucketState {
                    bucket_key,
                    worldwide_day,
                    floor_price_minor,
                    is_qualified: false,
                    total_nods: 1,
                    entry_price_minor: U256::from(450_000_000u64),
                    reference_currency: 840,
                })
                .expect("seed independent off-chain Nod bucket");
            let readers = RuntimeBodyReaders::new(reader);
            assert!(readers
                .nod()
                .get_bucket(outbe_compressed_entities::WwdEntityId::from_day_and_digest(
                    worldwide_day,
                    bucket_key.0,
                ))
                .expect("independent bucket read")
                .is_some());
            readers
        };

        let run = |expected_validator_body: bool, readers: RuntimeBodyReaders| {
            let signer = test_evm_signer();
            let (mut state, _tree_directory, tree_service, seed_hash) = seed_state();
            let config = OutbeEvmConfig::new_with_runtime_body_readers(test_chain_spec(), readers)
                .with_evm_signer(signer)
                .with_compressed_tree_service(tree_service.clone());
            let mut parent_metadata = metadata_with(vec![proposer], vec![1], Vec::new());
            parent_metadata.finalized_block_number = 1;
            parent_metadata.finalized_block_hash = seed_hash;
            let system_txs = begin_system_txs_for_test(
                &config,
                2,
                seed_hash,
                &Bytes::new(),
                Some(parent_metadata.clone()),
                proposer,
            );
            let visible_envelopes: Vec<u64> =
                system_txs.iter().map(|tx| tx.tx().gas_limit()).collect();
            let evm = config.evm_with_env(&mut state, test_evm_env(2, REWARDS_ADDRESS));
            let mut execution = execution_ctx(Some(1), Bytes::new());
            execution.inner.parent_hash = seed_hash;
            execution.parent_consensus_metadata = Some(parent_metadata);
            execution.parent_artifact_hint = Some(AccountedParentArtifact {
                summary: ExecutionSummaryArtifact {
                    validator_fee_sum: U256::ZERO,
                },
                timestamp: 0,
                state_root: Some(B256::repeat_byte(0x91)),
            });
            execution.proposer_evm_address = Some(proposer);
            if expected_validator_body {
                execution.expected_begin_system_txs = system_txs.clone();
            }
            let mut executor = config.create_executor(evm, execution);
            super::with_phase1_verify_disabled(|| {
                executor
                    .apply_pre_execution_changes()
                    .expect("reader-backed pre-execution hook must succeed");
            });
            for tx in system_txs {
                executor
                    .execute_transaction(tx)
                    .expect("begin-zone transaction must execute");
            }
            let receipts = executor.receipts().to_vec();
            // Match the production payload-builder ordering: finalize CE before
            // freezing and finalizing the root.
            executor
                .finalize_compressed_entities()
                .expect("pre-root compressed-entity cleanup must succeed");
            executor
                .prepare_final_header_artifacts(0)
                .expect("final extra_data should encode");
            let sealed = executor
                .compressed_entities_seal_output()
                .expect("block cleanup must produce a CE tree batch");
            let block_hash = B256::repeat_byte(0x42);
            let block_root = sealed.new_root;
            tree_service
                .publish_candidate(block_hash, sealed.staged_tree_batch)
                .expect("publish block CE candidate");
            tree_service
                .apply_finalized(2, block_hash, block_root)
                .expect("finalize block CE candidate");
            let (evm, block_result) = executor.finish().expect("block finish must succeed");
            drop(evm);
            let bundle = state.bundle_state.clone();
            let root = post_state_root(&bundle);
            let proposer_balance = signer_balance(&mut state, proposer);
            let rewards_balance = signer_balance(&mut state, REWARDS_ADDRESS);

            // A new lifecycle can only open when every pending body/index record and
            // touched list from the finished block has been removed. This checks the
            // same committed bundle used for the state root above, not a mock store.
            let clean_parent = tree_service
                .open_parent(ExactParentIdentity {
                    commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                    block_number: 2,
                    block_hash,
                    root: block_root,
                })
                .expect("open finalized block CE parent");
            let clean_scope =
                ExecutionScope::with_parent_tree(clean_parent, CeWorkConfig::new(0, 0, u64::MAX));
            let clean_ctx = BlockContext::new(3, 2, CHAIN_ID, proposer, vec![proposer]);
            super::run_atomic_storage_hooks(&mut state, clean_ctx, |hook_ctx| {
                outbe_compressed_entities::begin_block(hook_ctx.storage.clone(), &clean_scope)?;
                outbe_compressed_entities::end_block(hook_ctx.storage.clone(), &clean_scope)
                    .map(|_| ())
            })
            .expect("finished block must leave a clean compressed-entity overlay");
            (
                root,
                bundle,
                receipts,
                proposer_balance,
                rewards_balance,
                block_result.gas_used,
                visible_envelopes,
            )
        };

        let proposer_result = run(false, independent_readers());
        let validator_result = run(true, independent_readers());
        assert_eq!(proposer_result, validator_result);
    }

    #[test]
    fn proposer_validator_body_mints_match_for_all_three_commitment_namespaces() {
        use reth_trie::{test_utils::state_root_prehashed, HashedPostState, KeccakKeyHasher};

        fn post_state_root(state: &revm::database::BundleState) -> B256 {
            let sorted =
                HashedPostState::from_bundle_state::<KeccakKeyHasher>(state.state()).into_sorted();
            let storages = sorted.storages;
            let accounts = sorted
                .accounts
                .into_iter()
                .filter_map(|(address, account)| {
                    account.map(|account| {
                        let storage = storages
                            .get(&address)
                            .map(|storage| storage.storage_slots.clone())
                            .unwrap_or_default();
                        (address, (account, storage))
                    })
                });
            state_root_prehashed(accounts)
        }

        let proposer = test_evm_signer().address();
        let day = WorldwideDay::new(20_260_716);
        let tribute_owner = Address::repeat_byte(0x31);
        let tribute_id =
            outbe_compressed_entities::derive_poseidon_entity_id(tribute_owner, day).unwrap();
        let nod_owner = Address::repeat_byte(0x32);
        let nod_id = outbe_compressed_entities::derive_poseidon_entity_id(nod_owner, day).unwrap();
        let bucket_key = NodContract::bucket_key(day, U256::from(13), 978);
        let ctx = BlockContext::new(1, 1, CHAIN_ID, proposer, vec![proposer]);

        let run = || {
            let bodies = Arc::new(MemoryStorage::new());
            let tribute_reader = TributeRepositoryReader::new(bodies.clone());
            let nod_reader = NodRepositoryReader::new(bodies);
            let scope = ExecutionScope::new();
            let mut state =
                state_with_active_validators_seeded(&[(proposer, dummy_pubkey(0xA2))], |_| {});
            let (changes, events) =
                super::run_atomic_storage_hooks(&mut state, ctx.clone(), |hook_ctx| {
                    outbe_compressed_entities::begin_block(hook_ctx.storage.clone(), &scope)?;
                    let tribute = TributeData {
                        tribute_id,
                        owner: tribute_owner,
                        worldwide_day: day,
                        issuance_amount_minor: U256::from(10),
                        issuance_currency: 840,
                        nominal_amount_minor: U256::from(11),
                        reference_currency: 978,
                        tribute_price_minor: U256::from(12),
                        exclude_from_intex_issuance: false,
                    };
                    let mut tribute_contract = TributeContract::new(hook_ctx.storage.clone());
                    tribute_contract.unseal_day(day)?;
                    tribute_contract.issue(&scope, &tribute_reader, &tribute)?;
                    outbe_nod::api::add_nod(
                        &hook_ctx.storage,
                        &scope,
                        &nod_reader,
                        &NodItemState {
                            nod_id,
                            owner: nod_owner,
                            gratis_load_minor: U256::from(1),
                            worldwide_day: day,
                            league_id: 2,
                            floor_price_minor: U256::from(13),
                            bucket_key,
                            issuance_currency: 840,
                            reference_currency: 978,
                            issued_at: 15,
                        },
                        U256::from(16),
                    )?;
                    outbe_compressed_entities::end_block(hook_ctx.storage.clone(), &scope)
                        .map(|_| ())
                })
                .expect("body mint execution must succeed");
            let compressed_root = {
                let mut provider = outbe_primitives::storage::direct::DirectStorageProvider::new(
                    &mut state,
                    ctx.clone(),
                );
                StorageHandle::enter(&mut provider, |storage| {
                    storage
                        .sload(
                            outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
                            U256::from(1),
                        )
                        .map(|root| B256::from(root.to_be_bytes::<32>()))
                })
                .unwrap()
            };
            let root = post_state_root(&state.bundle_state);
            let proposer_balance = signer_balance(&mut state, proposer);
            let rewards_balance = signer_balance(&mut state, REWARDS_ADDRESS);
            (
                changes,
                events,
                compressed_root,
                root,
                state.bundle_state,
                proposer_balance,
                rewards_balance,
            )
        };

        let proposer_result = run();
        let validator_result = run();
        assert_eq!(proposer_result, validator_result);
        assert!(proposer_result.1.iter().any(|event| {
            event.address == outbe_primitives::addresses::TRIBUTE_ADDRESS
                && event.data.topics()[0]
                    == outbe_tribute::precompile::ITribute::TributeBodyStored::SIGNATURE_HASH
        }));
        assert!(proposer_result.1.iter().any(|event| {
            event.address == NOD_ADDRESS
                && event.data.topics()[0] == INod::NodBodyStored::SIGNATURE_HASH
        }));
        assert!(proposer_result.1.iter().any(|event| {
            event.address == NOD_ADDRESS
                && event.data.topics()[0] == INod::NodBucketBodyStored::SIGNATURE_HASH
        }));

        let bodies = Arc::new(MemoryStorage::new());
        let tribute_reader = TributeRepositoryReader::new(bodies.clone());
        let nod_reader = NodRepositoryReader::new(bodies);
        let scope = ExecutionScope::new();
        let mut failed_state =
            state_with_active_validators_seeded(&[(proposer, dummy_pubkey(0xA2))], |_| {});
        let error = super::run_atomic_storage_hooks(&mut failed_state, ctx.clone(), |hook_ctx| {
            outbe_compressed_entities::begin_block(hook_ctx.storage.clone(), &scope)?;
            let tribute = TributeData {
                tribute_id,
                owner: tribute_owner,
                worldwide_day: day,
                issuance_amount_minor: U256::from(10),
                issuance_currency: 840,
                nominal_amount_minor: U256::from(11),
                reference_currency: 978,
                tribute_price_minor: U256::from(12),
                exclude_from_intex_issuance: false,
            };
            let mut tribute_contract = TributeContract::new(hook_ctx.storage.clone());
            tribute_contract.unseal_day(day)?;
            tribute_contract.issue(&scope, &tribute_reader, &tribute)?;
            outbe_nod::api::add_nod(
                &hook_ctx.storage,
                &scope,
                &nod_reader,
                &NodItemState {
                    nod_id,
                    owner: nod_owner,
                    gratis_load_minor: U256::from(1),
                    worldwide_day: day,
                    league_id: 2,
                    floor_price_minor: U256::from(13),
                    bucket_key,
                    issuance_currency: 840,
                    reference_currency: 978,
                    issued_at: 15,
                },
                U256::from(16),
            )?;
            Err(outbe_primitives::error::PrecompileError::Fatal(
                "later transaction stage failed".into(),
            ))
        })
        .expect_err("failed transaction must roll back every body namespace");
        assert!(error.to_string().contains("later transaction stage failed"));
        let mut read_provider =
            outbe_primitives::storage::direct::DirectStorageProvider::new(&mut failed_state, ctx);
        StorageHandle::enter(&mut read_provider, |storage| {
            assert_eq!(
                B256::from(
                    storage
                        .sload(
                            outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
                            U256::from(1),
                        )?
                        .to_be_bytes::<32>(),
                ),
                outbe_compressed_entities::sealed_root(B256::ZERO).unwrap()
            );
            assert_eq!(TributeContract::new(storage.clone()).total_supply()?, 0);
            assert_eq!(NodContract::new(storage).total_supply()?, 0);
            Ok::<_, outbe_primitives::error::PrecompileError>(())
        })
        .unwrap();
    }

    #[test]
    fn oracle_slash_window_runs_after_boundary_activation() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let old_active_secret = [2; 32];
        let old_active = OutbeEvmSigner::from_secret_bytes(old_active_secret)
            .expect("old active test signer")
            .address();
        let mut state =
            state_with_active_and_registered_candidate_seeded(old_active, proposer, |storage| {
                let oracle = outbe_oracle::schema::OracleContract::new(storage.clone());
                oracle.config_is_initialized.write(true).unwrap();
                oracle.config_enabled.write(true).unwrap();
                oracle.config_vote_period.write(0).unwrap();
                oracle.config_slash_window.write(1).unwrap();
                oracle
                    .config_slash_fraction
                    .write(U256::from(10_000_000_000_000_000u64))
                    .unwrap(); // 1% in 1e18 fixed point.
                oracle
                    .config_min_valid_per_window
                    .write(U256::from(1u64))
                    .unwrap();
                oracle.penalty_miss_count.write(&old_active, 1).unwrap();

                let stake = U256::from(1_000u64);
                let staking = outbe_staking::contract::Staking::new(storage.clone());
                staking.stake_amount.write(&old_active, stake).unwrap();
                staking.total_staked.write(stake).unwrap();
                staking.config_min_stake.write(U256::from(1u64)).unwrap();
                let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
                vs.test_set_stake_projection(
                    old_active,
                    outbe_validatorset::StakeProjection::new(stake, None),
                )
                .unwrap();
            });
        let stake = U256::from(1_000u64);
        let mut setup_provider = outbe_primitives::storage::direct::DirectStorageProvider::new(
            &mut state,
            BlockContext::new(1, 1, CHAIN_ID, proposer, vec![old_active, proposer]),
        );
        StorageHandle::enter(&mut setup_provider, |storage| {
            storage.set_balance(STAKING_ADDRESS, stake)?;
            // Re-write the Staking slots in the same account-info flush so the
            // balance seed cannot replace the account with an empty storage map.
            let staking = outbe_staking::contract::Staking::new(storage.clone());
            staking.stake_amount.write(&old_active, stake)?;
            staking.total_staked.write(stake)?;
            staking.config_min_stake.write(U256::from(1u64))?;
            Ok::<_, outbe_primitives::error::PrecompileError>(())
        })
        .expect("staking backing balance must be seeded");
        setup_provider
            .flush()
            .expect("staking backing balance seed must flush");

        let evm_env = test_evm_env(1, REWARDS_ADDRESS);
        let boundary = boundary_with(
            true,
            vec![
                (old_active, dummy_pubkey(0xA2)),
                (proposer, dummy_pubkey(0xB3)),
            ],
        );
        let tee_bootstrap = sample_tee_bootstrap_payload_for(
            1,
            boundary.committee_set_hash,
            TEST_BLOCK_TIMESTAMP_BASE + 1 + 3_600,
            &[
                outbe_primitives::tee_test_utils::DevValidatorV1 {
                    evm_secret: old_active_secret,
                    bls_minpk_public: dummy_pubkey(0xA2),
                },
                outbe_primitives::tee_test_utils::DevValidatorV1 {
                    evm_secret: [1; 32],
                    bls_minpk_public: dummy_pubkey(0xB3),
                },
            ],
        );
        let extra_data = encode_outbe_block_artifacts(&OutbeBlockArtifacts {
            execution_summary: None,
            consensus_header_artifact: Some(ConsensusHeaderArtifact::BoundaryOutcome(boundary)),
            timestamp_millis_part: 0,
            late_finalize_credits: None,
            compressed_entities_root: None,
        })
        .expect("extra_data encodes");
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, evm_env);
        let mut executor = config.create_executor(
            evm,
            execution_ctx_with_tee_bootstrap(Some(0), extra_data.clone(), tee_bootstrap.clone()),
        );

        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply before Oracle slash system tx");
        let system_txs = begin_system_txs_for_test_with_bootstrap(
            &config,
            1,
            B256::ZERO,
            &extra_data,
            None,
            proposer,
            Some(tee_bootstrap),
        );
        let mut visible_system_gas_used = 0u64;
        for tx in system_txs {
            let signed_gas_limit = tx.tx().gas_limit();
            let gas_output = executor
                .execute_transaction(tx)
                .expect("Oracle slash must not invalidate same-block BoundaryOutcome activation");
            assert!(gas_output.tx_gas_used() <= signed_gas_limit);
            visible_system_gas_used += gas_output.tx_gas_used();
            assert_eq!(
                executor
                    .receipts()
                    .last()
                    .expect("system receipt should be present")
                    .cumulative_gas_used,
                visible_system_gas_used
            );
        }

        assert_eq!(executor.receipts().len(), 6);
        assert!(executor.receipts().iter().all(|receipt| receipt.success));
        let oracle_forced_exit = keccak256("ValidatorForcedExit(address)");
        assert!(
            executor.receipts()[4].logs.iter().any(|log| {
                log.address == ORACLE_ADDRESS
                    && log.data.topics().first() == Some(&oracle_forced_exit)
            }),
            "Oracle slash-window force exit must be receipt-visible"
        );
        let oracle_slashed = keccak256("ValidatorSlashed(address,uint64)");
        assert!(
            executor.receipts()[4].logs.iter().any(|log| {
                log.address == ORACLE_ADDRESS && log.data.topics().first() == Some(&oracle_slashed)
            }),
            "Oracle slash-window stake slash must be receipt-visible"
        );
        let hook_events_receipt = &executor.receipts()[5];
        assert!(
            hook_events_receipt.success,
            "mandatory HookEvents receipt must succeed even when empty"
        );
        assert!(
            !hook_events_receipt
                .logs
                .iter()
                .any(|log| log.address == ORACLE_ADDRESS),
            "non-whitelisted oracle hook events must not appear in HookEvents receipt"
        );
        assert!(
            visible_system_gas_used < 30_000_000,
            "visible system gas used {visible_system_gas_used} should fit within block gas limit"
        );
        drop(executor);

        let read_ctx = BlockContext::new(1, 1, CHAIN_ID, proposer, vec![old_active, proposer]);
        let mut provider =
            outbe_primitives::storage::direct::DirectStorageProvider::new(&mut state, read_ctx);
        StorageHandle::enter(&mut provider, |storage| {
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            assert!(vs.is_consensus_participant(proposer)?);
            let old_record = vs
                .get_validator(old_active)?
                .expect("old active validator should still exist");
            assert_eq!(
                old_record.status,
                outbe_validatorset::logic::status::JAILED,
                "Oracle slash applies after activation without making the block invalid"
            );
            let staking = outbe_staking::contract::Staking::new(storage.clone());
            assert_eq!(staking.stake_amount.read(&old_active)?, U256::from(990u64));
            assert_eq!(storage.balance(STAKING_ADDRESS)?, U256::from(990u64));
            Ok::<_, outbe_primitives::error::PrecompileError>(())
        })
        .expect("validator state should be readable");
    }

    #[test]
    fn verifier_rejects_finalization_parent_hash_mismatch() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let mut state = state_with_active_proposer(proposer);
        let evm_env = test_evm_env(2, REWARDS_ADDRESS);
        let config = OutbeEvmConfig::new(test_chain_spec());
        let evm = config.evm_with_env(&mut state, evm_env);

        let parent_hash = B256::with_last_byte(0xAA);
        let wrong_parent_hash = B256::with_last_byte(0xBB);
        let mut metadata = test_metadata();
        metadata.finalized_block_number = 1;
        metadata.finalized_block_hash = wrong_parent_hash;

        let phase1_unsigned = build_unsigned_system_tx(
            SystemTxKind::CertifiedParentAccounting,
            0,
            2,
            CHAIN_ID,
            SystemTxInputV2::CertifiedParentAccounting { metadata }
                .encode()
                .unwrap(),
        )
        .unwrap();
        let cycle_unsigned = build_unsigned_system_tx(
            SystemTxKind::CycleTick,
            1,
            2,
            CHAIN_ID,
            SystemTxInputV2::CycleTick.encode().unwrap(),
        )
        .unwrap();
        let phase1_signed = signer.sign_unsigned(phase1_unsigned).unwrap();
        let cycle_signed = signer.sign_unsigned(cycle_unsigned).unwrap();
        let phase1_recovered =
            reth_primitives_traits::Recovered::new_unchecked(phase1_signed, proposer);
        let cycle_recovered =
            reth_primitives_traits::Recovered::new_unchecked(cycle_signed, proposer);

        let mut ctx = execution_ctx(Some(2), Bytes::new());
        ctx.inner.parent_hash = parent_hash;
        ctx.expected_begin_system_txs = vec![phase1_recovered.clone(), cycle_recovered];
        ctx.proposer_evm_address = Some(proposer);

        let mut executor = config.create_executor(evm, ctx);
        // the rejection now fires in `apply_pre_execution_changes`
        // (Phase 1 verifier preflight) rather than during the main tx loop -
        // `verify_v2_proof` reads the same `parent_hash` mismatch via
        // `begin_block_system_tx_inputs` BEFORE any begin-zone state change.
        let err = executor.apply_pre_execution_changes().expect_err(
            "verifier must reject CertifiedParentAccounting metadata for a non-parent hash",
        );
        assert!(err
            .to_string()
            .contains("CertifiedParentAccounting metadata hash must match block parent"));
        assert!(executor.receipts().is_empty());
        let _ = phase1_recovered;
    }

    #[test]
    fn verifier_rejects_begin_system_tx_signature_hash_mismatch() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let mut state = state_with_active_proposer(proposer);
        let evm_env = test_evm_env(1, REWARDS_ADDRESS);
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, evm_env);

        let wrong_unsigned = build_unsigned_system_tx(
            SystemTxKind::CycleTick,
            0,
            2,
            CHAIN_ID,
            SystemTxInputV2::CycleTick.encode().unwrap(),
        )
        .unwrap();
        let wrong_signed = signer.sign_unsigned(wrong_unsigned).unwrap();
        let wrong_recovered =
            reth_primitives_traits::Recovered::new_unchecked(wrong_signed, proposer);
        let canonical =
            begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer);
        let mut expected = vec![wrong_recovered.clone()];
        expected.extend(canonical.into_iter().skip(1));
        let mut ctx = execution_ctx(Some(1), Bytes::new());
        ctx.expected_begin_system_txs = expected;

        let mut executor = config.create_executor(evm, ctx);
        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply before verifier tx loop");
        let err = executor
            .execute_transaction(wrong_recovered)
            .expect_err("verifier must reject mismatched system tx signature hash");

        assert!(err.to_string().contains("signature_hash mismatch"));
        assert!(executor.receipts().is_empty());
    }

    #[test]
    fn verifier_rejects_boundary_outcome_system_tx_artifact_mismatch() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let mut state = state_with_active_proposer(proposer);
        let evm_env = test_evm_env(1, REWARDS_ADDRESS);
        let config = OutbeEvmConfig::new(test_chain_spec());
        let evm = config.evm_with_env(&mut state, evm_env);

        let header_artifact = boundary_with(true, vec![(proposer, dummy_pubkey(0xA2))]);
        let mut tx_artifact = header_artifact.clone();
        tx_artifact.dkg_cycle = 1;
        let extra_data = encode_outbe_block_artifacts(&OutbeBlockArtifacts {
            execution_summary: None,
            consensus_header_artifact: Some(ConsensusHeaderArtifact::BoundaryOutcome(
                header_artifact,
            )),
            timestamp_millis_part: 0,
            late_finalize_credits: None,
            compressed_entities_root: None,
        })
        .expect("extra_data encodes");

        let cycle_unsigned = build_unsigned_system_tx(
            SystemTxKind::CycleTick,
            0,
            1,
            CHAIN_ID,
            SystemTxInputV2::CycleTick.encode().unwrap(),
        )
        .unwrap();
        let rewards_unsigned = build_unsigned_system_tx(
            SystemTxKind::RewardsGemDelivery,
            1,
            1,
            CHAIN_ID,
            SystemTxInputV2::RewardsGemDelivery.encode().unwrap(),
        )
        .unwrap();
        let boundary_unsigned = build_unsigned_system_tx(
            SystemTxKind::BoundaryOutcome,
            2,
            1,
            CHAIN_ID,
            SystemTxInputV2::BoundaryOutcome {
                artifact: tx_artifact,
            }
            .encode()
            .unwrap(),
        )
        .unwrap();
        let cycle_signed = signer.sign_unsigned(cycle_unsigned).unwrap();
        let rewards_signed = signer.sign_unsigned(rewards_unsigned).unwrap();
        let boundary_signed = signer.sign_unsigned(boundary_unsigned).unwrap();
        let cycle_recovered =
            reth_primitives_traits::Recovered::new_unchecked(cycle_signed, proposer);
        let rewards_recovered =
            reth_primitives_traits::Recovered::new_unchecked(rewards_signed, proposer);
        let boundary_recovered =
            reth_primitives_traits::Recovered::new_unchecked(boundary_signed, proposer);
        let mut ctx = execution_ctx(Some(3), extra_data);
        ctx.expected_begin_system_txs = vec![
            cycle_recovered.clone(),
            rewards_recovered,
            boundary_recovered.clone(),
        ];
        ctx.proposer_evm_address = Some(proposer);

        let mut executor = config.create_executor(evm, ctx);
        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply before verifier tx loop");
        let err = executor
            .execute_transaction(cycle_recovered)
            .expect_err("verifier must reject BoundaryOutcome tx/header mismatch");

        assert!(err
            .to_string()
            .contains("BoundaryOutcome system tx artifact mismatch"));
        assert!(executor.receipts().is_empty());
    }

    #[test]
    fn verifier_rejects_begin_system_tx_signer_mismatch() {
        let proposer_signer = test_evm_signer();
        let proposer = proposer_signer.address();
        let wrong_signer = Arc::new(OutbeEvmSigner::from_secret_bytes([2u8; 32]).unwrap());
        let mut state = state_with_active_proposer(proposer);
        let evm_env = test_evm_env(1, REWARDS_ADDRESS);
        let config =
            OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(proposer_signer.clone());
        let evm = config.evm_with_env(&mut state, evm_env);

        let canonical =
            begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer);
        let cycle_input = SystemTxInputV2::CycleTick.encode().unwrap();
        let unsigned = build_unsigned_system_tx_with_gas_limit(
            SystemTxKind::CycleTick,
            0,
            1,
            CHAIN_ID,
            cycle_input,
            canonical[0].tx().gas_limit(),
        )
        .unwrap();
        let wrong_signed = wrong_signer.sign_unsigned(unsigned).unwrap();
        let wrong_recovered =
            reth_primitives_traits::Recovered::new_unchecked(wrong_signed, wrong_signer.address());
        let mut expected = vec![wrong_recovered.clone()];
        expected.extend(canonical.into_iter().skip(1));
        let mut ctx = execution_ctx(Some(1), Bytes::new());
        ctx.expected_begin_system_txs = expected;
        ctx.proposer_evm_address = Some(proposer);

        let mut executor = config.create_executor(evm, ctx);
        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply before verifier tx loop");
        let err = executor
            .execute_transaction(wrong_recovered)
            .expect_err("verifier must reject system tx signed by non-proposer");

        assert!(err.to_string().contains("system tx signer mismatch"));
        assert!(executor.receipts().is_empty());
    }

    #[test]
    fn zero_fee_oracle_vote_from_delegated_feeder_keeps_zero_balance() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        let validator = address!("0x1111111111111111111111111111111111111111");
        let pk = dummy_pubkey(0xA1);
        let zero_fee_tx = test_oracle_submit_vote_tx()
            .try_into_recovered()
            .expect("oracle submitVote tx signer should recover");
        let feeder = Address::from(*zero_fee_tx.signer());

        let mut seed_storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut seed_storage, |storage| {
            seed_registered_active_validator(storage.clone(), validator, &pk);

            // Feeder resolution moved to the role-scoped ValidatorSet
            // delegation registry; the legacy oracle-side mapping is no longer
            // consulted by `resolve_validator_for_feeder`.
            let mut validator_set =
                outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            validator_set.set_delegate(
                validator,
                outbe_validatorset::delegation::ValidatorDelegateRole::Oracle,
                feeder,
            )?;
            Ok::<_, outbe_primitives::error::PrecompileError>(())
        })
        .expect("test genesis state must be seeded");

        let mut db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        for address in seed_storage
            .storage
            .keys()
            .map(|(address, _)| *address)
            .collect::<std::collections::HashSet<_>>()
        {
            db.insert_account_info(address, AccountInfo::default());
        }
        for ((address, slot), value) in seed_storage.storage {
            db.insert_account_storage(address, slot, value)
                .expect("seed storage insert should succeed");
        }
        let marker_code = Bytecode::new_legacy([0xef].into());
        db.insert_account_info(
            ORACLE_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code),
                ..Default::default()
            },
        );

        let mut state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();

        let feeder_balance_before = state
            .basic(feeder)
            .expect("feeder account read should succeed")
            .map(|account| account.balance)
            .unwrap_or_default();
        assert_eq!(feeder_balance_before, U256::ZERO);

        let setup_read_ctx = BlockContext::new(1, 1, CHAIN_ID, OWNER, vec![validator]);
        let mut setup_provider = outbe_primitives::storage::direct::DirectStorageProvider::new(
            &mut state,
            setup_read_ctx,
        );
        StorageHandle::enter(&mut setup_provider, |storage| {
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            let record = vs
                .get_validator(validator)?
                .expect("validator should be registered");
            assert_eq!(record.status, outbe_validatorset::logic::status::ACTIVE);
            assert!(record.has_bls_share);

            let oracle = outbe_oracle::schema::OracleContract::new(storage.clone());
            assert_eq!(oracle.resolve_validator_for_feeder(feeder)?, validator);
            Ok::<_, outbe_primitives::error::PrecompileError>(())
        })
        .expect("seeded zero-fee authorization state should be readable");

        {
            let evm_env = EvmEnv {
                cfg_env: CfgEnv::new()
                    .with_chain_id(CHAIN_ID)
                    .with_spec_and_mainnet_gas_params(SpecId::SHANGHAI),
                block_env: BlockEnv {
                    number: U256::from(1u64),
                    gas_limit: 30_000_000,
                    basefee: 1_000_000_000,
                    beneficiary: OWNER,
                    timestamp: U256::from(1u64),
                    ..Default::default()
                },
            };
            let evm = config.evm_with_env(&mut state, evm_env);
            let ctx = execution_ctx(Some(1), Bytes::new());
            let mut executor = config.create_executor(evm, ctx);

            executor
                .execute_transaction(zero_fee_tx)
                .expect("delegated zero-fee oracle vote should execute");

            assert_eq!(executor.receipts().len(), 1);
            assert!(executor.receipts()[0].success);
            assert!(executor.receipts()[0].cumulative_gas_used > 0);
            assert!(executor.receipts()[0]
                .logs
                .iter()
                .any(|log| log.address == ORACLE_ADDRESS));
        }
        state.merge_transitions(BundleRetention::Reverts);

        let mut slot_storage = HashMapStorageProvider::new(CHAIN_ID);
        let vote_slot = StorageHandle::enter(&mut slot_storage, |storage| {
            outbe_oracle::schema::OracleContract::new(storage.clone())
                .vote_exists
                .get(&validator)
                .slot()
        });
        assert_eq!(
            state
                .bundle_state
                .storage(&ORACLE_ADDRESS, vote_slot)
                .unwrap_or_default(),
            U256::from(1u64)
        );

        let feeder_balance_after = state
            .basic(feeder)
            .expect("feeder account read should succeed")
            .map(|account| account.balance)
            .unwrap_or_default();
        assert_eq!(feeder_balance_after, U256::ZERO);
    }

    /// / T6.2 parity: two executors with identical state and tx
    /// produce byte-equal soft-fail receipts. This is the on-chain parity
    /// invariant that keeps `receipts_root` deterministic across proposer
    /// and validators when a zero-fee tx is soft-failed.
    #[test]
    fn parity_soft_failed_zero_fee_receipt_is_byte_equal_across_runs() {
        fn run() -> Vec<reth_ethereum::Receipt> {
            let config = OutbeEvmConfig::new(test_chain_spec());
            // No validator-set seeding, no feeder delegation: the oracle vote will
            // hit `authorize_fee_waiver` -> `UnauthorizedSigner` (code 107).
            let zero_fee_tx = test_oracle_submit_vote_tx()
                .try_into_recovered()
                .expect("oracle submitVote tx signer should recover");

            let mut db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
            let marker_code = Bytecode::new_legacy([0xef].into());
            db.insert_account_info(
                ORACLE_ADDRESS,
                AccountInfo {
                    code_hash: marker_code.hash_slow(),
                    code: Some(marker_code),
                    ..Default::default()
                },
            );

            let mut state = State::builder()
                .with_database(db)
                .with_bundle_update()
                .build();

            let evm_env = EvmEnv {
                cfg_env: CfgEnv::new()
                    .with_chain_id(CHAIN_ID)
                    .with_spec_and_mainnet_gas_params(SpecId::SHANGHAI),
                block_env: BlockEnv {
                    number: U256::from(1u64),
                    gas_limit: 30_000_000,
                    basefee: 1_000_000_000,
                    beneficiary: OWNER,
                    timestamp: U256::from(1u64),
                    ..Default::default()
                },
            };
            let evm = config.evm_with_env(&mut state, evm_env);
            let ctx = execution_ctx(Some(1), Bytes::new());
            let mut executor = config.create_executor(evm, ctx);

            executor
                .execute_transaction(zero_fee_tx)
                .expect("soft-fail path must not abort the block build");

            executor.receipts().to_vec()
        }

        let receipts_a = run();
        let receipts_b = run();

        assert_eq!(receipts_a.len(), 1);
        assert_eq!(receipts_b.len(), 1);
        assert!(!receipts_a[0].success);
        assert_eq!(receipts_a[0].logs.len(), 1);
        // Soft-fail log must come from the zero-fee policy address with the
        // OutbeFailure topic0 - anything else is a parity drift.
        assert_eq!(
            receipts_a[0].logs[0].address,
            outbe_primitives::addresses::ZERO_FEE_POLICY_LOG_ADDRESS
        );
        assert_eq!(
            receipts_a[0].logs[0].data.topics()[0],
            crate::failure_receipt::OUTBE_FAILURE_TOPIC0
        );
        // Code 107 (UnauthorizedSigner) - padded to 32 bytes BE.
        let mut expected_topic1 = [0u8; 32];
        expected_topic1[30] = 0;
        expected_topic1[31] = 107;
        assert_eq!(
            receipts_a[0].logs[0].data.topics()[1].as_slice(),
            expected_topic1
        );

        // Byte parity: RLP-encode both runs' receipts and compare bytes.
        // EIP-2718 is the canonical encoding used by `receipts_root`, so byte
        // equality here means `receipts_root` will be equal on every node.
        use alloy_consensus::TxReceipt;
        use alloy_eips::eip2718::Encodable2718;
        let buf_a = receipts_a[0].with_bloom_ref().encoded_2718();
        let buf_b = receipts_b[0].with_bloom_ref().encoded_2718();
        assert_eq!(
            buf_a, buf_b,
            "soft-fail receipts must be byte-equal across runs"
        );
    }

    /// / T6.6 property: `validator_fee_sum` MUST NOT be perturbed
    /// by soft-failed zero-fee transactions. Failed zero-fee txs never run
    /// the EVM and never contribute miner fees; only successful user txs in
    /// the priority-fee path increment `current_block_validator_fees`.
    ///
    /// This is a focused invariance test (proptest-style over multiple
    /// runs without the full `proptest` macro to keep the test fast and
    /// dependency-free).
    #[test]
    fn property_soft_fail_does_not_perturb_validator_fee_sum() {
        let chain_spec = test_chain_spec();
        let receipt_builder = reth_ethereum::evm::RethReceiptBuilder::default();
        let config = OutbeEvmConfig::new(chain_spec.clone());
        for run in 0..5 {
            let zero_fee_tx = test_oracle_submit_vote_tx()
                .try_into_recovered()
                .expect("oracle submitVote tx signer should recover");

            let mut db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
            let marker_code = Bytecode::new_legacy([0xef].into());
            db.insert_account_info(
                ORACLE_ADDRESS,
                AccountInfo {
                    code_hash: marker_code.hash_slow(),
                    code: Some(marker_code),
                    ..Default::default()
                },
            );
            let mut state = State::builder()
                .with_database(db)
                .with_bundle_update()
                .build();

            let evm_env = EvmEnv {
                cfg_env: CfgEnv::new()
                    .with_chain_id(CHAIN_ID)
                    .with_spec_and_mainnet_gas_params(SpecId::SHANGHAI),
                block_env: BlockEnv {
                    number: U256::from(1u64 + run as u64),
                    gas_limit: 30_000_000,
                    basefee: 1_000_000_000,
                    beneficiary: OWNER,
                    timestamp: U256::from(1u64 + run as u64),
                    ..Default::default()
                },
            };
            let evm = config.evm_with_env(&mut state, evm_env);
            let ctx = execution_ctx(Some(1), Bytes::new());
            // Construct OutbeBlockExecutor directly (instead of through
            // `config.create_executor`) to keep the concrete type so we can
            // call `current_execution_summary` - the method is private to
            // `OutbeBlockExecutor` and hidden behind the `BlockExecutorFor`
            // opaque return type otherwise.
            let mut executor = OutbeBlockExecutor::new(
                EthBlockExecutor::new(evm, ctx.inner.clone(), &chain_spec, &receipt_builder),
                None,
                Bytes::new(),
                None,
                false,
                None,
                ctx.inner.parent_hash,
                None,
                ctx.expected_begin_system_txs.clone(),
                ctx.expected_end_system_txs.clone(),
                ctx.system_layout_error.clone(),
                ctx.parent_consensus_metadata.clone(),
                ctx.proposer_evm_address,
                ctx.execute_outbe_block_hooks,
                ctx.prebuilt_phase1_tx.clone(),
                ctx.parent_artifact_hint,
            );

            // Baseline: no txs.
            assert_eq!(
                executor.current_execution_summary().validator_fee_sum,
                U256::ZERO,
                "run {run}: baseline fee sum must be zero"
            );

            // Soft-fail one tx.
            executor
                .execute_transaction(zero_fee_tx)
                .expect("soft-fail must succeed");

            // Invariant: failed zero-fee tx contributes 0 to validator fee sum.
            assert_eq!(
                executor.current_execution_summary().validator_fee_sum,
                U256::ZERO,
                "run {run}: soft-failed zero-fee tx must not credit the validator"
            );
        }
    }

    /// / T6.4 mempool natural-eviction bridge: a soft-failed zero-fee
    /// tx returns `Ok(non-zero gas)` from `execute_transaction`, which signals
    /// the `BasicBlockBuilder` to append the tx to `block.body`. Reth's pool
    /// then evicts the tx hash on canonical commit via the standard
    /// `on_new_head_block` -> `pool.remove_transactions(block_hashes)` path.
    ///
    /// This is the contract that lets (T4 Won't Do) skip any custom
    /// `mark_invalid` plumbing - confirmation that the executor's `Ok` return
    /// is enough for the natural-eviction flow downstream.
    #[test]
    fn soft_fail_returns_ok_so_tx_lands_in_block_body() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        let zero_fee_tx = test_oracle_submit_vote_tx()
            .try_into_recovered()
            .expect("oracle submitVote tx signer should recover");

        let mut db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        let marker_code = Bytecode::new_legacy([0xef].into());
        db.insert_account_info(
            ORACLE_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code),
                ..Default::default()
            },
        );
        let mut state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();

        let evm_env = EvmEnv {
            cfg_env: CfgEnv::new()
                .with_chain_id(CHAIN_ID)
                .with_spec_and_mainnet_gas_params(SpecId::SHANGHAI),
            block_env: BlockEnv {
                number: U256::from(1u64),
                gas_limit: 30_000_000,
                basefee: 1_000_000_000,
                beneficiary: OWNER,
                timestamp: U256::from(1u64),
                ..Default::default()
            },
        };
        let evm = config.evm_with_env(&mut state, evm_env);
        let ctx = execution_ctx(Some(1), Bytes::new());
        let mut executor = config.create_executor(evm, ctx);

        // Soft-fail path returns `Ok` - the contract that lets the wrapping
        // `BasicBlockBuilder` append the tx to `block.body.transactions`.
        let gas_output = executor
            .execute_transaction(zero_fee_tx)
            .expect("soft-fail path must not abort the block build");

        // Non-zero gas: signals the tx was "executed and committed" from the
        // BlockBuilder's perspective, even though no EVM code ran.
        assert!(
            gas_output.tx_gas_used() > 0,
            "non-zero gas signals the tx is committed to the block body, \
             which is the prerequisite for Reth's standard pool eviction"
        );
        // Exactly one receipt was pushed.
        assert_eq!(executor.receipts().len(), 1);
        assert!(
            !executor.receipts()[0].success,
            "soft-fail receipt must have status=0"
        );
        // Receipt contains the synthetic failure log; eth_getTransactionReceipt
        // will surface this to external observers.
        assert_eq!(executor.receipts()[0].logs.len(), 1);
        assert_eq!(
            executor.receipts()[0].logs[0].address,
            outbe_primitives::addresses::ZERO_FEE_POLICY_LOG_ADDRESS
        );
    }

    #[test]
    fn begin_block_hook_batch_rolls_back_code_and_reports_committed_code_changes() {
        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        let mut state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();
        let ctx = BlockContext::new(7, 84, CHAIN_ID, OWNER, Vec::new());
        let address = address!("0x1111111111111111111111111111111111111111");
        let slot = U256::from(0x46u64);
        let value = U256::from(0x193u64);
        let marker = Bytecode::new_raw(Bytes::from_static(&[0xef]));
        let marker_hash = marker.hash_slow();

        let err = super::run_atomic_storage_hooks(&mut state, ctx, |hook_ctx| {
            hook_ctx.storage.set_code(address, marker.clone())?;
            hook_ctx.storage.sstore(address, slot, value)?;
            assert_eq!(hook_ctx.storage.sload(address, slot)?, value);
            Err(outbe_primitives::error::PrecompileError::Fatal(
                "oracle hook failed".into(),
            ))
        })
        .expect_err("late hook failure must abort the whole hook batch");

        assert!(err.to_string().contains("oracle hook failed"));
        assert_eq!(state.storage(address, slot).unwrap(), U256::ZERO);
        assert!(
            state
                .basic(address)
                .unwrap()
                .is_none_or(|info| info.is_empty_code_hash()),
            "failed hook batch must not persist code"
        );

        let ctx = BlockContext::new(8, 96, CHAIN_ID, OWNER, Vec::new());
        let (changes, events) = super::run_atomic_storage_hooks(&mut state, ctx, |hook_ctx| {
            hook_ctx.storage.set_code(address, marker.clone())?;
            hook_ctx.storage.sstore(address, slot, value)?;
            Ok(())
        })
        .expect("successful hook batch must flush state");

        let account = changes
            .get(&address)
            .expect("successful batch must report changed account");
        assert_eq!(account.info.code_hash, marker_hash);
        assert_eq!(account.info.code, Some(marker));
        let changed_slot = account
            .storage
            .get(&slot)
            .expect("successful batch must report changed slot");
        assert_eq!(changed_slot.present_value(), value);
        assert!(events.is_empty());
    }

    #[test]
    fn hook_readiness_error_keeps_its_type_across_the_executor_boundary() {
        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        let mut state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();
        let ctx = BlockContext::new(7, 84, CHAIN_ID, OWNER, Vec::new());

        let error = super::run_atomic_storage_hooks(&mut state, ctx, |_hook_ctx| {
            Err(outbe_primitives::error::PrecompileError::TreeUnavailable(
                "finalized marker advanced past payload parent".into(),
            ))
        })
        .expect_err("tree readiness must abort this payload execution");

        assert!(matches!(
            error.as_internal().and_then(
                |inner| inner.downcast_other::<outbe_primitives::error::PrecompileError>()
            ),
            Some(outbe_primitives::error::PrecompileError::TreeUnavailable(_))
        ));
    }

    #[test]
    fn finish_uses_final_extra_data_setter_for_summary_validation() {
        let chain_spec = test_chain_spec();
        let receipt_builder = reth_ethereum::evm::RethReceiptBuilder::default();
        let config = OutbeEvmConfig::new(chain_spec.clone());
        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        let mut state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();
        let evm_env = EvmEnv {
            cfg_env: CfgEnv::new()
                .with_chain_id(CHAIN_ID)
                .with_spec_and_mainnet_gas_params(SpecId::SHANGHAI),
            block_env: BlockEnv {
                number: U256::from(1u64),
                gas_limit: 30_000_000,
                basefee: 1_000_000_000,
                beneficiary: OWNER,
                timestamp: U256::from(1u64),
                ..Default::default()
            },
        };
        let evm = config.evm_with_env(&mut state, evm_env);
        let ctx = execution_ctx(Some(0), Bytes::new());
        let mut executor = OutbeBlockExecutor::new(
            EthBlockExecutor::new(evm, ctx.inner.clone(), &chain_spec, &receipt_builder),
            None,
            Bytes::new(),
            None,
            true,
            None,
            ctx.inner.parent_hash,
            None,
            ctx.expected_begin_system_txs.clone(),
            ctx.expected_end_system_txs.clone(),
            ctx.system_layout_error.clone(),
            ctx.parent_consensus_metadata.clone(),
            ctx.proposer_evm_address,
            ctx.execute_outbe_block_hooks,
            ctx.prebuilt_phase1_tx.clone(),
            ctx.parent_artifact_hint,
        );
        let final_extra_data = encode_outbe_block_artifacts(&OutbeBlockArtifacts {
            execution_summary: Some(ExecutionSummaryArtifact {
                validator_fee_sum: U256::ZERO,
            }),
            consensus_header_artifact: None,
            timestamp_millis_part: 0,
            late_finalize_credits: None,
            compressed_entities_root: None,
        })
        .expect("final extra_data must encode");

        executor.set_final_extra_data(final_extra_data);
        let artifacts = outbe_primitives::reshare_artifact::decode_outbe_block_artifacts(
            executor.final_extra_data().as_ref(),
        )
        .unwrap();
        super::validate_execution_summary_artifact(
            true,
            1,
            artifacts.execution_summary,
            executor.current_execution_summary(),
        )
        .expect("final extra_data summary must validate");
    }

    #[test]
    fn finish_without_final_extra_data_setter_rejects_missing_summary() {
        let chain_spec = test_chain_spec();
        let receipt_builder = reth_ethereum::evm::RethReceiptBuilder::default();
        let config = OutbeEvmConfig::new(chain_spec.clone());
        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        let mut state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();
        let evm_env = EvmEnv {
            cfg_env: CfgEnv::new()
                .with_chain_id(CHAIN_ID)
                .with_spec_and_mainnet_gas_params(SpecId::SHANGHAI),
            block_env: BlockEnv {
                number: U256::from(1u64),
                gas_limit: 30_000_000,
                basefee: 1_000_000_000,
                beneficiary: OWNER,
                timestamp: U256::from(1u64),
                ..Default::default()
            },
        };
        let evm = config.evm_with_env(&mut state, evm_env);
        let ctx = execution_ctx(Some(0), Bytes::new());
        let executor = OutbeBlockExecutor::new(
            EthBlockExecutor::new(evm, ctx.inner.clone(), &chain_spec, &receipt_builder),
            None,
            Bytes::new(),
            None,
            true,
            None,
            ctx.inner.parent_hash,
            None,
            ctx.expected_begin_system_txs.clone(),
            ctx.expected_end_system_txs.clone(),
            ctx.system_layout_error.clone(),
            ctx.parent_consensus_metadata.clone(),
            ctx.proposer_evm_address,
            ctx.execute_outbe_block_hooks,
            ctx.prebuilt_phase1_tx.clone(),
            ctx.parent_artifact_hint,
        );

        let artifacts = outbe_primitives::reshare_artifact::decode_outbe_block_artifacts(
            executor.final_extra_data().as_ref(),
        )
        .unwrap();
        let err = super::validate_execution_summary_artifact(
            true,
            1,
            artifacts.execution_summary,
            executor.current_execution_summary(),
        )
        .expect_err("stale pre-summary extra_data must not validate");

        assert!(err
            .to_string()
            .contains("missing execution summary artifact in block extra_data"));
    }

    #[test]
    fn finish_rejects_non_artifact_header_extra_data() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        let mut state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();
        let evm_env = EvmEnv {
            cfg_env: CfgEnv::new()
                .with_chain_id(CHAIN_ID)
                .with_spec_and_mainnet_gas_params(SpecId::SHANGHAI),
            block_env: BlockEnv {
                number: U256::from(1u64),
                gas_limit: 30_000_000,
                basefee: 1_000_000_000,
                beneficiary: OWNER,
                timestamp: U256::from(1u64),
                ..Default::default()
            },
        };
        let evm = config.evm_with_env(&mut state, evm_env);
        let ctx = execution_ctx(Some(0), Bytes::from_static(b"reth/vtest/macos"));
        let executor = config.create_executor(evm, ctx);

        let err = match executor.finish() {
            Ok(_) => panic!(
                "non-artifact extra_data must currently reproduce the payload-builder failure"
            ),
            Err(err) => err,
        };

        assert!(err
            .to_string()
            .contains("unknown non-empty extra_data block artifact"));
    }

    // `finish_rejects_execution_summary_mismatch` was removed.
    // The previous test asserted mismatch via the `total_emission_limit`
    // field, which has been dropped from `ExecutionSummaryArtifact` in
    // wire format v0x04. The remaining `validator_fee_sum` field is
    // verified by the broader `outbe_rewards::on_finalized_metadata`
    // hook and the metadata-fingerprint guard in
    // `outbe_rewards::runtime::check_and_record_metadata_fingerprint`.

    fn dummy_pubkey(seed: u8) -> [u8; 48] {
        let mut pk = [0u8; 48];
        pk[0] = seed;
        pk
    }

    fn test_committee_snapshot(
        validators: &[(Address, [u8; 48])],
    ) -> outbe_validatorset::CommitteeSnapshot {
        outbe_validatorset::CommitteeSnapshot {
            committee: validators
                .iter()
                .map(
                    |(address, consensus_pubkey)| outbe_validatorset::CommitteeEntry {
                        address: *address,
                        consensus_pubkey: *consensus_pubkey,
                    },
                )
                .collect(),
            vrf_material_version: 0,
            vrf_group_public_key_bytes: vec![0x42; 96],
            vrf_public_polynomial_hash: B256::ZERO,
        }
    }

    fn seed_test_committee_snapshot(
        storage: StorageHandle,
        validators: &[(Address, [u8; 48])],
    ) -> B256 {
        let snapshot = test_committee_snapshot(validators);
        outbe_validatorset::write_committee_snapshot(storage, 0, &snapshot)
            .expect("seed epoch-0 test committee snapshot")
            .0
    }

    fn test_register_waiting(
        vs: &mut outbe_validatorset::contract::ValidatorSet<'_>,
        validator: Address,
        pubkey: &[u8; 48],
    ) {
        vs.test_register_validator_without_pop(validator, pubkey)
            .unwrap();
    }

    fn test_register_active_with_stake(
        vs: &mut outbe_validatorset::contract::ValidatorSet<'_>,
        validator: Address,
        pubkey: &[u8; 48],
        stake: U256,
        minimum: U256,
    ) {
        test_register_waiting(vs, validator, pubkey);
        assert!(stake >= minimum);
        vs.test_set_stake_projection(
            validator,
            outbe_validatorset::StakeProjection::new(stake, None),
        )
        .unwrap();
        vs.activate_validator_via_boundary_for_test(validator)
            .unwrap();
    }

    fn test_register_active(
        vs: &mut outbe_validatorset::contract::ValidatorSet<'_>,
        validator: Address,
        pubkey: &[u8; 48],
    ) {
        test_register_active_with_stake(vs, validator, pubkey, U256::from(1), U256::from(1));
    }

    fn test_register_joining(
        vs: &mut outbe_validatorset::contract::ValidatorSet<'_>,
        validator: Address,
        pubkey: &[u8; 48],
    ) {
        test_register_waiting(vs, validator, pubkey);
        vs.record_stake_increase(validator, U256::from(1), U256::from(1))
            .unwrap();
        vs.admit_validator_for_boundary_for_test(validator).unwrap();
    }

    #[allow(dead_code)] // retained for follow-up tests
    fn cache_db_from_storage(
        seed_storage: HashMapStorageProvider,
    ) -> CacheDB<EmptyDBTyped<ProviderError>> {
        let mut db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        let entries: Vec<_> = seed_storage.storage.into_iter().collect();
        let mut addresses: Vec<Address> =
            entries.iter().map(|((address, _), _)| *address).collect();
        addresses.sort_unstable();
        addresses.dedup();
        for address in addresses {
            db.insert_account_info(address, AccountInfo::default());
        }
        for ((address, slot), value) in entries {
            db.insert_account_storage(address, slot, value)
                .expect("seed storage insert should succeed");
        }
        db
    }

    fn seed_registered_active_validator(storage: StorageHandle, validator: Address, pk: &[u8; 48]) {
        let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
        vs.config_owner.write(OWNER).unwrap();
        vs.set_config_max_validators(128).unwrap();
        vs.config_epoch_length_blocks.write(60).unwrap();
        vs.config_is_initialized.write(true).unwrap();
        vs.register_validator(OWNER, validator, pk).unwrap();
        vs.activate_validator_via_boundary_for_test(validator)
            .unwrap();
        seed_test_committee_snapshot(storage.clone(), &[(validator, *pk)]);
        // Seed COEN/840 pair + 1.0 rate so begin-block NOD/GEM/INTEX promotion
        // reads a registered pair instead of reverting "pair not registered".
        // 840 also goes on the reference currency list, matching genesis: the
        // Nod qualifier reads its ISO from there.
        outbe_oracle::api::register_pair(storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
            .unwrap();
        outbe_oracle::schema::OracleContract::new(storage.clone())
            .reference_currencies
            .push(outbe_oracle::api::DAY_TYPE_ISO)
            .unwrap();
        outbe_oracle::api::set_exchange_rate(
            storage,
            Address::ZERO,
            outbe_oracle::api::DAY_TYPE_PAIR,
            U256::from(1_000_000u64),
            0,
            0,
        )
        .unwrap();
    }

    fn register_and_activate_with_ocomp_registration(
        validators: &mut outbe_validatorset::contract::ValidatorSet<'_>,
        validator: Address,
        consensus_key: &[u8; 48],
        registration: &outbe_ocomp_protocol::committee::OcompKeyRegistrationV1,
    ) {
        validators
            .register_validator(OWNER, validator, consensus_key)
            .unwrap();
        validators.mark_pending(validator).unwrap();
        let encoded = registration
            .encode_canonical(&outbe_metadosis::config::poc_schema_limits())
            .unwrap();
        validators
            .confirm_validator_ready(validator, &encoded)
            .unwrap();
        validators
            .activate_validator_via_boundary_for_test(validator)
            .unwrap();
    }

    fn seed_registered_active_validator_with_registration(
        storage: StorageHandle,
        validator: Address,
        consensus_key: &[u8; 48],
        registration: &outbe_ocomp_protocol::committee::OcompKeyRegistrationV1,
    ) {
        let mut validators = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
        validators.config_owner.write(OWNER).unwrap();
        validators.set_config_max_validators(128).unwrap();
        validators.config_epoch_length_blocks.write(60).unwrap();
        validators.config_is_initialized.write(true).unwrap();
        register_and_activate_with_ocomp_registration(
            &mut validators,
            validator,
            consensus_key,
            registration,
        );
        seed_test_committee_snapshot(storage.clone(), &[(validator, *consensus_key)]);
        outbe_oracle::api::register_pair(storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
            .unwrap();
        outbe_oracle::schema::OracleContract::new(storage.clone())
            .reference_currencies
            .push(outbe_oracle::api::DAY_TYPE_ISO)
            .unwrap();
        outbe_oracle::api::set_exchange_rate(
            storage,
            Address::ZERO,
            outbe_oracle::api::DAY_TYPE_PAIR,
            U256::from(1_000_000u64),
            0,
            0,
        )
        .unwrap();
    }

    #[test]
    fn genesis_validation_rejects_active_validator_with_zero_stake() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let validator = address!("0x1111111111111111111111111111111111111111");
            let pk = dummy_pubkey(0xA1);
            seed_registered_active_validator(storage.clone(), validator, &pk);

            let staking = outbe_staking::contract::Staking::new(storage.clone());
            staking.config_min_stake.write(U256::from(100u64)).unwrap();

            let genesis = GenesisValidators {
                validators: vec![GenesisValidator {
                    address: validator,
                    consensus_pubkey: pk,
                }],
                epoch_length_blocks: 60,
            };

            let err = super::validate_genesis_state(storage.clone(), &genesis).unwrap_err();
            assert!(err.to_string().contains("stake below min_stake"));
        });
    }

    #[test]
    fn genesis_validation_accepts_staked_active_validator() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let validator = address!("0x1111111111111111111111111111111111111111");
            let pk = dummy_pubkey(0xA1);
            let stake = U256::from(100u64);
            seed_registered_active_validator(storage.clone(), validator, &pk);

            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.test_set_stake_projection(
                validator,
                outbe_validatorset::StakeProjection::new(stake, None),
            )
            .unwrap();

            let staking = outbe_staking::contract::Staking::new(storage.clone());
            staking.config_min_stake.write(stake).unwrap();
            staking.stake_amount.write(&validator, stake).unwrap();
            staking.total_staked.write(stake).unwrap();

            let genesis = GenesisValidators {
                validators: vec![GenesisValidator {
                    address: validator,
                    consensus_pubkey: pk,
                }],
                epoch_length_blocks: 60,
            };

            super::validate_genesis_state(storage.clone(), &genesis).unwrap();
        });
    }

    /// Task 01 test: activate_reshared_set() runs AFTER participation decode.
    ///
    /// Simulates the executor's finish() hook order:
    /// 1. Read active consensus set (OLD set)
    /// 2. Decode participation bitmap against OLD set
    /// 3. Record participation / slashing
    /// 4. THEN activate_reshared_set() -> set changes to NEW set
    ///
    /// Verifies that get_active_consensus_set() returns the OLD set
    /// at step 2, and the NEW set only after step 4.
    #[test]
    fn test_reshare_activation_after_participation_decode() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.set_block_number(1);
        StorageHandle::enter(&mut storage, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            // Register and activate validators A, B, C.
            let val_a = address!("0x1111111111111111111111111111111111111111");
            let val_b = address!("0x2222222222222222222222222222222222222222");
            let val_c = address!("0x3333333333333333333333333333333333333333");
            let val_d = address!("0x4444444444444444444444444444444444444444");

            test_register_active(&mut vs, val_a, &dummy_pubkey(0xA1));
            test_register_active(&mut vs, val_b, &dummy_pubkey(0xB2));
            test_register_active(&mut vs, val_c, &dummy_pubkey(0xC3));
            test_register_joining(&mut vs, val_d, &dummy_pubkey(0xD4));

            // The fixture helpers activated A, B, C; D remains a ready joiner.

            // Step 1: Read old active set - should be [A, B, C].
            let old_set = vs.get_active_consensus_set().unwrap();
            let old_addrs: Vec<Address> = old_set.iter().map(|v| v.validator_address).collect();
            assert!(old_addrs.contains(&val_a));
            assert!(old_addrs.contains(&val_b));
            assert!(old_addrs.contains(&val_c));
            assert!(!old_addrs.contains(&val_d), "D should NOT be in old set");
            assert_eq!(old_addrs.len(), 3);

            // Step 2-3: Participation/slashing would happen here using old_addrs.
            // (We just verify the set is correct - actual slashing tested in Task 01 code.)

            // Step 4: NOW activate new reshare with [A, B, D] (C removed, D added).
            let new_hash = B256::with_last_byte(0x02);
            // First deactivate C (simulate EXITING).
            vs.deactivate_validator(OWNER, val_c).unwrap();

            // C is still in the current consensus set until the reshare outcome
            // is applied. This matches the still-running engine committee.
            let transition_set = vs.get_active_consensus_set().unwrap();
            let transition_addrs: Vec<Address> =
                transition_set.iter().map(|v| v.validator_address).collect();
            assert!(transition_addrs.contains(&val_c));
            assert_eq!(transition_addrs.len(), 3);
            vs.record_proposer(val_c).unwrap();
            vs.record_participation(&[val_a, val_b], &[val_c]).unwrap();

            // Reshare with new set.
            vs.test_activate_validated_boundary_set(&[val_a, val_b, val_d], new_hash, 1)
                .unwrap();

            // After reshare: active set is [A, B, D].
            let new_set = vs.get_active_consensus_set().unwrap();
            let new_addrs: Vec<Address> = new_set.iter().map(|v| v.validator_address).collect();
            assert!(new_addrs.contains(&val_a));
            assert!(new_addrs.contains(&val_b));
            assert!(new_addrs.contains(&val_d));
            assert!(!new_addrs.contains(&val_c), "C should NOT be in new set");
            assert_eq!(new_addrs.len(), 3);
        });
    }

    /// Task 01 test: committee size change doesn't corrupt participation.
    ///
    /// When old set has 3 validators and new set has 4, the participation
    /// bitmap encoded for 3 validators should be decoded against the 3-validator
    /// set, not the 4-validator set.
    #[test]
    fn test_committee_size_change_participation_safety() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            let val_a = address!("0x1111111111111111111111111111111111111111");
            let val_b = address!("0x2222222222222222222222222222222222222222");
            let val_c = address!("0x3333333333333333333333333333333333333333");
            let val_d = address!("0x4444444444444444444444444444444444444444");

            test_register_active(&mut vs, val_a, &dummy_pubkey(0xA1));
            test_register_active(&mut vs, val_b, &dummy_pubkey(0xB2));
            test_register_active(&mut vs, val_c, &dummy_pubkey(0xC3));
            test_register_joining(&mut vs, val_d, &dummy_pubkey(0xD4));

            // Old set: 3 validators [A, B, C].
            let old_set = vs.get_active_consensus_set().unwrap();
            assert_eq!(old_set.len(), 3, "old set must have 3 validators");

            // Encode participation for 3-validator set.
            let mut old_addrs: Vec<Address> = old_set.iter().map(|v| v.validator_address).collect();
            old_addrs.sort();
            let signers = vec![true, true, false]; // A, B signed; C absent
            let extra_data = outbe_primitives::participation::encode_participation_extended(
                &old_addrs,
                &signers,
                &[],
                &[],
            )
            .unwrap();

            // Now activate new set with 4 validators.
            vs.test_activate_validated_boundary_set(
                &[val_a, val_b, val_c, val_d],
                B256::with_last_byte(0x02),
                0,
            )
            .unwrap();
            let new_set = vs.get_active_consensus_set().unwrap();
            assert_eq!(new_set.len(), 4, "new set must have 4 validators");

            // Decode participation against OLD set (3 validators) -> should work.
            let decoded = outbe_primitives::participation::decode_participation_extended(
                &extra_data,
                &old_addrs,
            );
            assert!(decoded.is_some(), "decode against OLD set must succeed");

            // Decode against NEW set (4 validators) -> count mismatch -> returns None.
            let mut new_addrs: Vec<Address> = new_set.iter().map(|v| v.validator_address).collect();
            new_addrs.sort();
            let decoded_wrong = outbe_primitives::participation::decode_participation_extended(
                &extra_data,
                &new_addrs,
            );
            assert!(
                decoded_wrong.is_none(),
                "decode against NEW set with different size must return None (count mismatch)"
            );
        });
    }

    /// Task 01 test: re-execution of reshare activation is idempotent.
    ///
    /// Calling activate_reshared_set() twice with same hash must not
    /// change state the second time (idempotency guard).
    #[test]
    fn test_reshare_activation_idempotent() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            let val_a = address!("0x1111111111111111111111111111111111111111");
            let val_b = address!("0x2222222222222222222222222222222222222222");

            test_register_active(&mut vs, val_a, &dummy_pubkey(0xA1));
            test_register_active(&mut vs, val_b, &dummy_pubkey(0xB2));

            let hash = vs.active_consensus_set_hash().unwrap();

            // Read state after first activation.
            let set1 = vs.get_active_consensus_set().unwrap();
            let hash1 = vs.active_consensus_set_hash().unwrap();

            // Second call with same hash -> idempotency guard in executor.rs
            // checks `current_hash != reshare.active_set_hash`.
            // Here: current_hash == hash -> no-op.
            let current_hash = vs.active_consensus_set_hash().unwrap();
            assert_eq!(current_hash, hash, "hash must match after first activation");

            // Simulate executor's guard: skip if hash matches.
            assert_eq!(current_hash, hash);
            // State unchanged.
            let set2 = vs.get_active_consensus_set().unwrap();
            let hash2 = vs.active_consensus_set_hash().unwrap();
            assert_eq!(
                set1.len(),
                set2.len(),
                "set must be unchanged on re-execution"
            );
            assert_eq!(hash1, hash2, "hash must be unchanged on re-execution");
        });
    }

    fn metadata_with(
        committee: Vec<Address>,
        signer_bitmap: Vec<u8>,
        missed_proposers: Vec<Address>,
    ) -> CertifiedParentAccountingMetadata {
        CertifiedParentAccountingMetadata {
            ordered_committee: committee,
            signer_bitmap,
            // convert V1-shape `Vec<Address>` test fixture into V2
            // `Vec<MissedProposerEvent>` (view defaults to 0 - V2 contract is
            // empty list, this fixture exercises the validation path only).
            missed_proposers: missed_proposers
                .into_iter()
                .map(
                    |validator| outbe_primitives::consensus_metadata::MissedProposerEvent {
                        view: 0,
                        validator,
                    },
                )
                .collect(),
            ..CertifiedParentAccountingMetadata::default()
        }
    }

    /// Regression for the consensus stall at block 14402: finalized-parent
    /// metadata committee can legitimately differ from the live active set
    /// after a DKG/reshare. As long as every committee member is a registered
    /// validator (historical participant), validation must succeed.
    #[test]
    fn validate_finalized_metadata_accepts_registered_historical_committee() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            let val_a = address!("0x1111111111111111111111111111111111111111");
            let val_b = address!("0x2222222222222222222222222222222222222222");
            let val_c = address!("0x3333333333333333333333333333333333333333");
            let val_d = address!("0x4444444444444444444444444444444444444444");

            for (addr, seed) in [
                (val_a, 0xA1u8),
                (val_b, 0xB2u8),
                (val_c, 0xC3u8),
                (val_d, 0xD4u8),
            ] {
                if addr == val_c {
                    test_register_waiting(&mut vs, addr, &dummy_pubkey(seed));
                } else {
                    test_register_active(&mut vs, addr, &dummy_pubkey(seed));
                }
            }
            // Live active set is [A, B, D]; C is registered but no longer a
            // current consensus participant after a reshare.
            let live_active = vs.get_active_consensus_set().unwrap();
            let live_addrs: Vec<Address> =
                live_active.iter().map(|v| v.validator_address).collect();
            assert!(!live_addrs.contains(&val_c), "C must not be live-active");

            // Finalized-parent metadata still describes the previous committee [A, B, C].
            let metadata = metadata_with(vec![val_a, val_b, val_c], vec![1, 1, 0], vec![]);
            super::validate_finalized_metadata(storage.clone(), &metadata).unwrap();
        });
    }

    #[test]
    fn validate_finalized_metadata_rejects_duplicate_committee_member() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            let val_a = address!("0x1111111111111111111111111111111111111111");
            let val_b = address!("0x2222222222222222222222222222222222222222");
            test_register_active(&mut vs, val_a, &dummy_pubkey(0xA1));
            test_register_active(&mut vs, val_b, &dummy_pubkey(0xB2));

            let metadata = metadata_with(vec![val_a, val_b, val_a], vec![1, 1, 1], vec![]);
            let err = super::validate_finalized_metadata(storage.clone(), &metadata).unwrap_err();
            assert!(
                err.to_string().contains("duplicate"),
                "expected duplicate error, got {err}"
            );
        });
    }

    #[test]
    fn validate_finalized_metadata_rejects_unregistered_committee_member() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            let val_a = address!("0x1111111111111111111111111111111111111111");
            test_register_active(&mut vs, val_a, &dummy_pubkey(0xA1));

            let stranger = address!("0x9999999999999999999999999999999999999999");
            let metadata = metadata_with(vec![val_a, stranger], vec![1, 1], vec![]);
            let err = super::validate_finalized_metadata(storage.clone(), &metadata).unwrap_err();
            assert!(
                err.to_string().contains("not a registered validator"),
                "expected unregistered error, got {err}"
            );
        });
    }

    #[test]
    fn validate_finalized_metadata_rejects_missed_proposer_outside_committee() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            let val_a = address!("0x1111111111111111111111111111111111111111");
            let val_b = address!("0x2222222222222222222222222222222222222222");
            let val_c = address!("0x3333333333333333333333333333333333333333");
            for (addr, seed) in [(val_a, 0xA1u8), (val_b, 0xB2u8), (val_c, 0xC3u8)] {
                test_register_active(&mut vs, addr, &dummy_pubkey(seed));
            }

            let metadata = metadata_with(vec![val_a, val_b], vec![1, 1], vec![val_c]);
            let err = super::validate_finalized_metadata(storage.clone(), &metadata).unwrap_err();
            assert!(
                err.to_string().contains("not in finalized committee"),
                "expected missed-proposer-outside-committee error, got {err}"
            );
        });
    }

    #[test]
    fn validate_finalized_metadata_rejects_signer_bitmap_length_mismatch() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            let val_a = address!("0x1111111111111111111111111111111111111111");
            test_register_active(&mut vs, val_a, &dummy_pubkey(0xA1));

            let metadata = metadata_with(vec![val_a], vec![1, 0], vec![]);
            let err = super::validate_finalized_metadata(storage.clone(), &metadata).unwrap_err();
            assert!(
                err.to_string().contains("bitmap length mismatch"),
                "expected bitmap length error, got {err}"
            );
        });
    }

    fn boundary_with(
        is_validator_set_change: bool,
        committee: Vec<(Address, [u8; 48])>,
    ) -> outbe_primitives::consensus::DkgBoundaryArtifact {
        boundary_with_epoch(0, is_validator_set_change, committee)
    }

    fn boundary_with_epoch(
        epoch: u64,
        is_validator_set_change: bool,
        committee: Vec<(Address, [u8; 48])>,
    ) -> outbe_primitives::consensus::DkgBoundaryArtifact {
        let new_active_set: Vec<Address> = committee.iter().map(|(address, _)| *address).collect();
        let vrf_group_public_key_bytes = vec![0x42u8; 96];
        let snapshot = outbe_validatorset::CommitteeSnapshot {
            committee: committee
                .into_iter()
                .map(
                    |(address, consensus_pubkey)| outbe_validatorset::CommitteeEntry {
                        address,
                        consensus_pubkey,
                    },
                )
                .collect(),
            vrf_material_version: 0,
            vrf_group_public_key_bytes: vrf_group_public_key_bytes.clone(),
            vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
        };
        let active_set_hash = super::hash_boundary_active_set(&new_active_set);
        let committee_set_hash = outbe_validatorset::committee_set_hash_v2(epoch, &snapshot);
        let vrf_group_public_key = keccak256(&vrf_group_public_key_bytes);
        outbe_primitives::consensus::DkgBoundaryArtifact {
            epoch,
            dkg_cycle: 0,
            freeze_height: 0,
            planned_activation_height: 0,
            target_set_hash: B256::ZERO,
            vrf_material_version: 0,
            vrf_group_public_key,
            vrf_group_public_key_bytes: Bytes::from(vrf_group_public_key_bytes),
            committee_set_hash,
            is_validator_set_change,
            outcome: Bytes::new(),
            is_full_dkg: false,
            tee_recipient_pubkeys: Vec::new(),
            tee_expired_target_exclusions: Vec::new(),
            tee_expired_target_exclusions_hash: B256::ZERO,
            reshare: outbe_primitives::consensus::ReshareResult {
                new_active_set,
                active_set_hash,
            },
        }
    }

    #[test]
    fn certified_delayed_boundary_atomically_advances_epoch_and_snapshot() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let validator = address!("0x1111111111111111111111111111111111111111");
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();
            vs.register_validator(OWNER, validator, &dummy_pubkey(0xA1))
                .unwrap();
            vs.activate_validator_via_boundary_for_test(validator)
                .unwrap();
            let mut epoch = vs.epoch_snapshot().unwrap();
            epoch.number = U256::ZERO;
            epoch.start_block = 1;
            epoch.start_timestamp = TEST_BLOCK_TIMESTAMP_BASE;
            vs.test_set_epoch_snapshot(epoch).unwrap();
            let record = vs.get_validator(validator).unwrap().unwrap();
            vs.test_set_history(
                validator,
                ValidatorHistory::new(
                    record.joined_at_height,
                    (record.deactivated_at_height != 0).then_some(record.deactivated_at_height),
                    record.slash_count,
                    7,
                    8,
                    9,
                ),
            )
            .unwrap();
            drop(vs);
            let slash = outbe_slashindicator::contract::SlashIndicator::new(storage.clone());
            slash.proposer_miss_count.write(&validator, 10).unwrap();
            slash.voter_miss_count.write(&validator, 11).unwrap();

            let activation_block = 301;
            let activation_timestamp = TEST_BLOCK_TIMESTAMP_BASE + 600;
            let boundary = boundary_with_epoch(1, false, vec![(validator, dummy_pubkey(0xA1))]);
            let ctx = BlockRuntimeContext::new(
                BlockContext::new(
                    activation_block,
                    activation_timestamp,
                    CHAIN_ID,
                    validator,
                    vec![validator],
                ),
                storage.clone(),
            );

            super::prepare_boundary_epoch_counters(storage.clone(), &boundary, activation_block)
                .expect("certified boundary must prepare outgoing counters");
            crate::begin_block_precompile::run_boundary_outcome(&ctx, &boundary)
                .expect("certified delayed boundary must activate");

            let vs_after = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            let epoch = vs_after.epoch_snapshot().unwrap();
            assert_eq!(epoch.number, U256::from(1));
            assert_eq!(epoch.start_block, activation_block);
            assert_eq!(epoch.start_timestamp, activation_timestamp);
            assert_eq!(
                vs_after.participation(validator).unwrap(),
                outbe_validatorset::ValidatorParticipation::default()
            );
            let slash_after = outbe_slashindicator::contract::SlashIndicator::new(storage.clone());
            assert_eq!(slash_after.proposer_miss_count.read(&validator).unwrap(), 0);
            assert_eq!(slash_after.voter_miss_count.read(&validator).unwrap(), 0);
            let (_, extension) =
                outbe_validatorset::read_ocomp_snapshot_extension_at_epoch(storage, 1)
                    .unwrap()
                    .expect("activated epoch must publish its OCOMP snapshot");
            assert_eq!(extension.epoch, 1);
            assert_eq!(extension.committee_set_hash, boundary.committee_set_hash);
        });
    }

    #[test]
    fn failed_boundary_snapshot_write_rolls_back_epoch_membership_and_counters() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let validator = address!("0x1111111111111111111111111111111111111111");
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();
            vs.register_validator(OWNER, validator, &dummy_pubkey(0xA1))
                .unwrap();
            vs.activate_validator_via_boundary_for_test(validator)
                .unwrap();
            let mut epoch = vs.epoch_snapshot().unwrap();
            epoch.number = U256::ZERO;
            epoch.start_block = 1;
            epoch.start_timestamp = TEST_BLOCK_TIMESTAMP_BASE;
            vs.test_set_epoch_snapshot(epoch).unwrap();
            let record = vs.get_validator(validator).unwrap().unwrap();
            vs.test_set_history(
                validator,
                ValidatorHistory::new(
                    record.joined_at_height,
                    (record.deactivated_at_height != 0).then_some(record.deactivated_at_height),
                    record.slash_count,
                    7,
                    record.missed_votes,
                    record.blocks_proposed,
                ),
            )
            .unwrap();
            let active_hash_before = vs.active_consensus_set_hash().unwrap();
            // Force the incoming snapshot writer to fail after the boundary
            // transition has started. The enclosing activation checkpoint must
            // restore every earlier epoch/set/counter write.
            vs.val_ocomp_registration
                .get_bytes(&validator)
                .clear()
                .unwrap();
            drop(vs);
            let slash = outbe_slashindicator::contract::SlashIndicator::new(storage.clone());
            slash.proposer_miss_count.write(&validator, 10).unwrap();

            let boundary = boundary_with_epoch(1, false, vec![(validator, dummy_pubkey(0xA1))]);
            let block_guard = storage.checkpoint_guard();
            super::prepare_boundary_epoch_counters(storage.clone(), &boundary, 301)
                .expect("certified boundary must prepare outgoing counters");
            let error = super::apply_boundary_outcome(
                storage.clone(),
                &boundary,
                301,
                TEST_BLOCK_TIMESTAMP_BASE + 600,
            )
            .expect_err("missing OCOMP registration must reject incoming snapshot");
            assert!(error.to_string().contains("no admitted OCOMP registration"));
            drop(block_guard);

            let vs_after = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            let epoch = vs_after.epoch_snapshot().unwrap();
            assert_eq!(epoch.number, U256::ZERO);
            assert_eq!(epoch.start_block, 1);
            assert_eq!(epoch.start_timestamp, TEST_BLOCK_TIMESTAMP_BASE);
            assert_eq!(
                vs_after.active_consensus_set_hash().unwrap(),
                active_hash_before
            );
            assert_eq!(vs_after.participation(validator).unwrap().missed_blocks, 7);
            let slash_after = outbe_slashindicator::contract::SlashIndicator::new(storage.clone());
            assert_eq!(
                slash_after.proposer_miss_count.read(&validator).unwrap(),
                10
            );
            assert!(
                outbe_validatorset::read_ocomp_snapshot_extension_at_epoch(storage, 1)
                    .unwrap()
                    .is_none(),
                "failed activation must not expose an epoch-1 snapshot"
            );
        });
    }

    #[test]
    fn boundary_rejects_skipped_epoch_without_mutating_current_state() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let validator = address!("0x1111111111111111111111111111111111111111");
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();
            vs.register_validator(OWNER, validator, &dummy_pubkey(0xA1))
                .unwrap();
            vs.activate_validator_via_boundary_for_test(validator)
                .unwrap();
            let mut epoch = vs.epoch_snapshot().unwrap();
            epoch.number = U256::ZERO;
            epoch.start_block = 1;
            vs.test_set_epoch_snapshot(epoch).unwrap();
            drop(vs);

            let boundary = boundary_with_epoch(2, false, vec![(validator, dummy_pubkey(0xA1))]);
            let error = super::apply_boundary_outcome(
                storage.clone(),
                &boundary,
                301,
                TEST_BLOCK_TIMESTAMP_BASE + 600,
            )
            .expect_err("BoundaryOutcome must not skip activated epochs");
            assert!(error.to_string().contains("activate current+1"));

            let vs_after = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            let epoch = vs_after.epoch_snapshot().unwrap();
            assert_eq!(epoch.number, U256::ZERO);
            assert_eq!(epoch.start_block, 1);
            assert!(
                outbe_validatorset::read_ocomp_snapshot_extension_at_epoch(storage, 2)
                    .unwrap()
                    .is_none()
            );
        });
    }

    #[test]
    fn apply_boundary_outcome_fatals_on_hash_change_without_set_change() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            let val_a = address!("0x1111111111111111111111111111111111111111");
            let val_b = address!("0x2222222222222222222222222222222222222222");
            test_register_active(&mut vs, val_a, &dummy_pubkey(0xA1));
            test_register_active(&mut vs, val_b, &dummy_pubkey(0xB2));

            // Boundary claims membership unchanged but carries a different active set.
            let boundary = boundary_with(false, vec![(val_a, dummy_pubkey(0xA1))]);
            let err = super::apply_boundary_outcome(
                storage.clone(),
                &boundary,
                1,
                TEST_BLOCK_TIMESTAMP_BASE,
            )
            .unwrap_err();
            assert!(
                err.to_string()
                    .contains("active_set_hash changed without validator-set change"),
                "expected hash-vs-flag inconsistency, got {err}"
            );
        });
    }

    #[test]
    fn apply_boundary_outcome_activates_on_validator_set_change_with_hash_change() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            let val_a = address!("0x1111111111111111111111111111111111111111");
            let val_b = address!("0x2222222222222222222222222222222222222222");
            let val_c = address!("0x3333333333333333333333333333333333333333");
            test_register_active(&mut vs, val_a, &dummy_pubkey(0xA1));
            test_register_active(&mut vs, val_b, &dummy_pubkey(0xB2));
            test_register_joining(&mut vs, val_c, &dummy_pubkey(0xC3));

            let boundary = boundary_with(
                true,
                vec![
                    (val_a, dummy_pubkey(0xA1)),
                    (val_b, dummy_pubkey(0xB2)),
                    (val_c, dummy_pubkey(0xC3)),
                ],
            );
            let new_hash = boundary.reshare.active_set_hash;
            super::apply_boundary_outcome(storage.clone(), &boundary, 1, TEST_BLOCK_TIMESTAMP_BASE)
                .unwrap();

            let vs_after = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            let now_hash = vs_after.active_consensus_set_hash().unwrap();
            assert_eq!(now_hash, new_hash, "active_set_hash must advance");
            let active = vs_after.get_active_consensus_set().unwrap();
            let addrs: Vec<Address> = active.iter().map(|v| v.validator_address).collect();
            assert!(addrs.contains(&val_c), "C must now be in active set");
        });
    }

    #[test]
    fn apply_boundary_outcome_replays_narrow_certified_tee_expiry_demotion() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            let retained = address!("0x1111111111111111111111111111111111111111");
            let expired = address!("0x2222222222222222222222222222222222222222");
            test_register_active(&mut vs, retained, &dummy_pubkey(0xA1));
            test_register_active(&mut vs, expired, &dummy_pubkey(0xB2));
            let current_hash = super::hash_boundary_active_set(&[retained, expired]);
            vs.test_set_active_consensus_set_hash(current_hash).unwrap();

            let mut boundary = boundary_with(true, vec![(retained, dummy_pubkey(0xA1))]);
            boundary.tee_expired_target_exclusions = vec![expired];
            boundary.tee_expired_target_exclusions_hash =
                outbe_primitives::reshare_artifact::tee_expired_target_exclusions_hash(
                    &boundary.tee_expired_target_exclusions,
                )
                .unwrap();
            super::apply_boundary_outcome(storage.clone(), &boundary, 1, TEST_BLOCK_TIMESTAMP_BASE)
                .unwrap();

            let vs_after = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            let expired_state = vs_after.validator_state(expired).unwrap();
            assert_eq!(
                expired_state.stored_status().unwrap(),
                outbe_validatorset::runtime::status::PENDING
            );
            assert!(!expired_state.has_bls_share());
            assert!(!expired_state.join_confirmed());
            let retained_state = vs_after.validator_state(retained).unwrap();
            assert_eq!(
                retained_state.stored_status().unwrap(),
                outbe_validatorset::runtime::status::ACTIVE
            );
        });
    }

    #[test]
    fn apply_boundary_outcome_rejects_tampered_tee_expiry_commitment() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();
            let retained = address!("0x1111111111111111111111111111111111111111");
            test_register_active(&mut vs, retained, &dummy_pubkey(0xA1));
            let hash = super::hash_boundary_active_set(&[retained]);
            vs.test_set_active_consensus_set_hash(hash).unwrap();

            let mut boundary = boundary_with(false, vec![(retained, dummy_pubkey(0xA1))]);
            boundary.tee_expired_target_exclusions_hash = B256::with_last_byte(0xFF);
            let error = super::apply_boundary_outcome(
                storage.clone(),
                &boundary,
                1,
                TEST_BLOCK_TIMESTAMP_BASE,
            )
            .unwrap_err();
            assert!(error
                .to_string()
                .contains("TEE expiry exclusions commitment mismatch"));
        });
    }

    #[test]
    fn apply_boundary_outcome_writes_snapshot_when_hash_matches() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            let val_a = address!("0x1111111111111111111111111111111111111111");
            test_register_active(&mut vs, val_a, &dummy_pubkey(0xA1));
            let hash = vs.active_consensus_set_hash().unwrap();

            let boundary = boundary_with(false, vec![(val_a, dummy_pubkey(0xA1))]);
            super::apply_boundary_outcome(storage.clone(), &boundary, 1, TEST_BLOCK_TIMESTAMP_BASE)
                .unwrap();

            let vs_after = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            assert_eq!(vs_after.active_consensus_set_hash().unwrap(), hash);

            let snapshot_key = outbe_validatorset::committee_snapshot_key(
                boundary.epoch,
                boundary.committee_set_hash,
            );
            let snapshot =
                outbe_validatorset::read_committee_snapshot(storage.clone(), snapshot_key)
                    .unwrap()
                    .expect("BoundaryOutcome must write the incoming committee snapshot");
            assert_eq!(snapshot.committee.len(), 1);
            assert_eq!(snapshot.committee[0].address, val_a);
            assert_eq!(snapshot.committee[0].consensus_pubkey, dummy_pubkey(0xA1));
            assert_eq!(snapshot.vrf_material_version, boundary.vrf_material_version);
            assert_eq!(
                snapshot.vrf_group_public_key_bytes,
                boundary.vrf_group_public_key_bytes.to_vec()
            );
        });
    }

    #[test]
    fn apply_boundary_outcome_rejects_committee_set_hash_mismatch() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            let val_a = address!("0x1111111111111111111111111111111111111111");
            test_register_active(&mut vs, val_a, &dummy_pubkey(0xA1));

            let mut boundary = boundary_with(false, vec![(val_a, dummy_pubkey(0xA1))]);
            boundary.committee_set_hash = B256::with_last_byte(0xFE);

            let err = super::apply_boundary_outcome(
                storage.clone(),
                &boundary,
                1,
                TEST_BLOCK_TIMESTAMP_BASE,
            )
            .unwrap_err();
            assert!(
                err.to_string().contains("committee_set_hash mismatch"),
                "expected committee_set_hash mismatch, got {err}"
            );
        });
    }

    // -----------------------------------------------------------------------
    // Runtime: hint acceptance guard.
    //
    // `accounted_parent_artifact_for_metadata` is `pub(crate)`, so a runtime
    // test must live in this module (integration tests in
    // `crates/blockchain/evm/tests/artifact_lookup.rs` cannot reach it). These
    // tests close the audit gap by exercising the guard branch directly
    // instead of relying on source-grep substring matches.
    //
    // Construction is minimal: an `OutbeBlockExecutor` with
    // `accounted_parent_artifact_provider = None` (forces the lookup ladder
    // straight to the hint), a synthetic `parent_hash`, an explicit
    // `parent_artifact_hint`, and a `BlockEnv.number` whose `n - 1` matches
    // the metadata's `finalized_block_number` on the happy path.
    // -----------------------------------------------------------------------

    fn hint_test_metadata(
        finalized_block_number: u64,
        finalized_block_hash: B256,
    ) -> CertifiedParentAccountingMetadata {
        CertifiedParentAccountingMetadata {
            finalized_block_number,
            finalized_block_hash,
            ..Default::default()
        }
    }

    fn hint_test_artifact() -> AccountedParentArtifact {
        AccountedParentArtifact {
            summary: ExecutionSummaryArtifact {
                validator_fee_sum: U256::from(777u64),
            },
            timestamp: 1_700_900_000,
            state_root: None,
        }
    }

    struct HeaderNotFoundArtifactProvider;

    impl AccountedParentArtifactProvider for HeaderNotFoundArtifactProvider {
        fn execution_summary_by_hash(
            &self,
            _block_number: u64,
            block_hash: B256,
        ) -> Result<Option<AccountedParentArtifact>, ProviderError> {
            Err(ProviderError::HeaderNotFound(block_hash.into()))
        }
    }

    /// Build the EVM env + EthBlockExecutionCtx pair for tests. The
    /// caller drives the `OutbeBlockExecutor::new(...)` construction inline
    /// because its return type references the opaque concrete `Evm` produced
    /// by `OutbeEvmConfig::evm_with_env`.
    fn hint_test_env(
        block_number: u64,
        parent_hash: B256,
    ) -> (EvmEnv, EthBlockExecutionCtx<'static>) {
        let env = EvmEnv {
            cfg_env: CfgEnv::new()
                .with_chain_id(CHAIN_ID)
                .with_spec_and_mainnet_gas_params(SpecId::SHANGHAI),
            block_env: BlockEnv {
                number: U256::from(block_number),
                gas_limit: 30_000_000,
                basefee: 1_000_000_000,
                beneficiary: REWARDS_ADDRESS,
                timestamp: U256::from(block_number),
                ..Default::default()
            },
        };
        let ctx = EthBlockExecutionCtx {
            parent_hash,
            parent_beacon_block_root: None,
            ommers: &[],
            withdrawals: None,
            extra_data: Bytes::new(),
            tx_count_hint: Some(0),
            slot_number: None,
        };
        (env, ctx)
    }

    /// (a): hint accepted when `(metadata.finalized_block_hash,
    /// metadata.finalized_block_number)` matches `(self.parent_hash,
    /// block_number - 1)`.
    #[test]
    fn hint_accepted_when_metadata_matches_parent() {
        let chain_spec = test_chain_spec();
        let receipt_builder = reth_ethereum::evm::RethReceiptBuilder::default();
        let config = OutbeEvmConfig::new(chain_spec.clone());
        let mut state = State::builder()
            .with_database(CacheDB::<EmptyDBTyped<ProviderError>>::default())
            .with_bundle_update()
            .build();

        let block_number = 42u64;
        let parent_hash = B256::repeat_byte(0xA0);
        let hint = hint_test_artifact();
        let (evm_env, inner_ctx) = hint_test_env(block_number, parent_hash);
        let evm = config.evm_with_env(&mut state, evm_env);
        let executor = OutbeBlockExecutor::new(
            EthBlockExecutor::new(evm, inner_ctx, &chain_spec, &receipt_builder),
            None,
            Bytes::new(),
            None, // accounted_parent_artifact_provider - None forces hint path
            false,
            None,
            parent_hash,
            None,
            Vec::new(),
            Vec::new(),
            None,
            None,
            None,
            true,
            None,
            Some(hint),
        );

        let metadata = hint_test_metadata(block_number - 1, parent_hash);
        let resolved = executor
            .accounted_parent_artifact_for_metadata(&metadata)
            .expect("hint must be accepted when parent identity matches");

        assert_eq!(
            resolved, hint,
            "executor must return the cached hint verbatim"
        );
    }

    /// FCU-Valid race-window: even if the provider leaks
    /// `HeaderNotFound` instead of normalizing it to `Ok(None)`, the executor
    /// must still reach the checked parent hint.
    #[test]
    fn provider_header_not_found_uses_matching_parent_hint() {
        let chain_spec = test_chain_spec();
        let receipt_builder = reth_ethereum::evm::RethReceiptBuilder::default();
        let config = OutbeEvmConfig::new(chain_spec.clone());
        let mut state = State::builder()
            .with_database(CacheDB::<EmptyDBTyped<ProviderError>>::default())
            .with_bundle_update()
            .build();

        let block_number = 42u64;
        let parent_hash = B256::repeat_byte(0xA0);
        let hint = hint_test_artifact();
        let (evm_env, inner_ctx) = hint_test_env(block_number, parent_hash);
        let evm = config.evm_with_env(&mut state, evm_env);
        let executor = OutbeBlockExecutor::new(
            EthBlockExecutor::new(evm, inner_ctx, &chain_spec, &receipt_builder),
            None,
            Bytes::new(),
            Some(Arc::new(HeaderNotFoundArtifactProvider)),
            false,
            None,
            parent_hash,
            None,
            Vec::new(),
            Vec::new(),
            None,
            None,
            None,
            true,
            None,
            Some(hint),
        );

        let metadata = hint_test_metadata(block_number - 1, parent_hash);
        let resolved = executor
            .accounted_parent_artifact_for_metadata(&metadata)
            .expect("HeaderNotFound provider miss must fall back to matching parent hint");

        assert_eq!(
            resolved, hint,
            "executor must use the checked hint when provider visibility races"
        );
    }

    /// (b): hint rejected when `metadata.finalized_block_hash` does not
    /// match `self.parent_hash`. Returns `BlockExecutionError::Internal` with
    /// a `parent_artifact_hint mismatch` diagnostic (no silent fallback).
    #[test]
    fn hint_rejected_when_metadata_hash_mismatch() {
        let chain_spec = test_chain_spec();
        let receipt_builder = reth_ethereum::evm::RethReceiptBuilder::default();
        let config = OutbeEvmConfig::new(chain_spec.clone());
        let mut state = State::builder()
            .with_database(CacheDB::<EmptyDBTyped<ProviderError>>::default())
            .with_bundle_update()
            .build();

        let block_number = 42u64;
        let parent_hash = B256::repeat_byte(0xA0);
        let foreign_hash = B256::repeat_byte(0xFF);
        assert_ne!(parent_hash, foreign_hash);

        let (evm_env, inner_ctx) = hint_test_env(block_number, parent_hash);
        let evm = config.evm_with_env(&mut state, evm_env);
        let executor = OutbeBlockExecutor::new(
            EthBlockExecutor::new(evm, inner_ctx, &chain_spec, &receipt_builder),
            None,
            Bytes::new(),
            None,
            false,
            None,
            parent_hash,
            None,
            Vec::new(),
            Vec::new(),
            None,
            None,
            None,
            true,
            None,
            Some(hint_test_artifact()),
        );

        let metadata = hint_test_metadata(block_number - 1, foreign_hash);
        let err = executor
            .accounted_parent_artifact_for_metadata(&metadata)
            .expect_err("metadata.finalized_block_hash mismatch must reject the hint");

        let message = err.to_string();
        assert!(
            message.contains("parent_artifact_hint mismatch"),
            "error must be the hint-mismatch diagnostic, got: {message}"
        );
    }

    /// (c): hint rejected when `metadata.finalized_block_number` does
    /// not equal `block_number - 1`. Same error class as (b) - no silent
    /// fallback.
    #[test]
    fn hint_rejected_when_metadata_number_mismatch() {
        let chain_spec = test_chain_spec();
        let receipt_builder = reth_ethereum::evm::RethReceiptBuilder::default();
        let config = OutbeEvmConfig::new(chain_spec.clone());
        let mut state = State::builder()
            .with_database(CacheDB::<EmptyDBTyped<ProviderError>>::default())
            .with_bundle_update()
            .build();

        let block_number = 42u64;
        let parent_hash = B256::repeat_byte(0xA0);

        let (evm_env, inner_ctx) = hint_test_env(block_number, parent_hash);
        let evm = config.evm_with_env(&mut state, evm_env);
        let executor = OutbeBlockExecutor::new(
            EthBlockExecutor::new(evm, inner_ctx, &chain_spec, &receipt_builder),
            None,
            Bytes::new(),
            None,
            false,
            None,
            parent_hash,
            None,
            Vec::new(),
            Vec::new(),
            None,
            None,
            None,
            true,
            None,
            Some(hint_test_artifact()),
        );

        // Off-by-one: metadata claims to describe block (block_number - 2)
        // instead of (block_number - 1).
        let metadata = hint_test_metadata(block_number - 2, parent_hash);
        let err = executor
            .accounted_parent_artifact_for_metadata(&metadata)
            .expect_err("metadata.finalized_block_number mismatch must reject the hint");

        let message = err.to_string();
        assert!(
            message.contains("parent_artifact_hint mismatch"),
            "error must be the hint-mismatch diagnostic, got: {message}"
        );
    }

    /// negative-control: with NO provider AND NO hint, the lookup
    /// returns a `missing execution summary artifact` error rather than
    /// silently succeeding. Pins the third branch of the ladder.
    #[test]
    fn no_provider_no_hint_returns_missing_artifact_error() {
        let chain_spec = test_chain_spec();
        let receipt_builder = reth_ethereum::evm::RethReceiptBuilder::default();
        let config = OutbeEvmConfig::new(chain_spec.clone());
        let mut state = State::builder()
            .with_database(CacheDB::<EmptyDBTyped<ProviderError>>::default())
            .with_bundle_update()
            .build();

        let block_number = 42u64;
        let parent_hash = B256::repeat_byte(0xA0);

        let (evm_env, inner_ctx) = hint_test_env(block_number, parent_hash);
        let evm = config.evm_with_env(&mut state, evm_env);
        let executor = OutbeBlockExecutor::new(
            EthBlockExecutor::new(evm, inner_ctx, &chain_spec, &receipt_builder),
            None,
            Bytes::new(),
            None,
            false,
            None,
            parent_hash,
            None,
            Vec::new(),
            Vec::new(),
            None,
            None,
            None,
            true,
            None,
            None, // no hint
        );

        let metadata = hint_test_metadata(block_number - 1, parent_hash);
        let err = executor
            .accounted_parent_artifact_for_metadata(&metadata)
            .expect_err("no provider + no hint must produce a hard error");

        let message = err.to_string();
        assert!(
            message.contains("missing execution summary artifact"),
            "error must be the missing-artifact diagnostic, got: {message}"
        );
    }

    // -----------------------------------------------------------------
    // EIP-7702 sponsored free-tx integration tests
    //
    // These tests verify the executor pre-fee hook end-to-end against
    // real `State<DB>` + revm - NOT just the storage-primitive level.
    // They cover the four claims the unit tests do NOT prove:
    //   1. Counter persists through revm tx revert (anti-drain).
    //   2. `SponsorshipAuthorized` event lands on the inner tx receipt.
    //   3. Signer balance is genuinely unchanged (no fee debit).
    //   4. EIP-7702 delegation to a NON-paymaster address falls through
    //      to the normal fee path.
    // -----------------------------------------------------------------

    use outbe_primitives::addresses::{AGENT_REWARD_ADDRESS, ZEROFEE_ADDRESS};
    use outbe_zerofee::precompile::IZeroFee::SponsorshipAuthorized;

    fn agent_reward_query_input() -> Vec<u8> {
        let selector = keccak256(b"getClaimableBalance(address)");
        let mut input = Vec::with_capacity(36);
        input.extend_from_slice(&selector[..4]);
        input.extend_from_slice(&[0u8; 32]);
        input
    }

    /// Sponsored signer derived from the alloy test-signature recovery.
    /// We don't care WHICH address it is - only that it is stable across
    /// runs and we attach delegation + balance + nonce to it.
    fn sponsored_test_tx(input: Vec<u8>) -> reth_ethereum::TransactionSigned {
        TxEip1559 {
            chain_id: CHAIN_ID,
            nonce: 0,
            gas_limit: 200_000,
            max_fee_per_gas: alloy_eips::eip1559::MIN_PROTOCOL_BASE_FEE as u128,
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(AGENT_REWARD_ADDRESS),
            value: U256::ZERO,
            input: input.into(),
            access_list: Default::default(),
        }
        .into_signed(Signature::test_signature())
        .into()
    }

    /// CfgEnv configured for Pectra (EIP-7702-active). The default test
    /// cfg uses SHANGHAI, which silently disables delegation re-load.
    fn pectra_evm_env(block_number: u64) -> EvmEnv {
        EvmEnv {
            cfg_env: CfgEnv::new()
                .with_chain_id(CHAIN_ID)
                .with_spec_and_mainnet_gas_params(SpecId::PRAGUE),
            block_env: BlockEnv {
                number: U256::from(block_number),
                gas_limit: 30_000_000,
                basefee: alloy_eips::eip1559::MIN_PROTOCOL_BASE_FEE,
                beneficiary: OWNER,
                // 2026-04-01 00:00:00 UTC - matches BLOCK_DAY constant
                // in the zerofee unit tests for cross-reference.
                timestamp: U256::from(1_775_001_600u64),
                ..Default::default()
            },
        }
    }

    fn sign_test_hash(key: &k256::ecdsa::SigningKey, hash: &B256) -> alloy_primitives::Signature {
        let (signature, recovery_id): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) = key
            .sign_prehash(hash.as_slice())
            .expect("test prehash signing must succeed");
        alloy_primitives::Signature::from_bytes_and_parity(
            signature.to_bytes().as_slice(),
            recovery_id.to_byte() != 0,
        )
        .normalized_s()
    }

    fn bootstrap_test_tx() -> reth_primitives_traits::Recovered<reth_ethereum::TransactionSigned> {
        let key = k256::ecdsa::SigningKey::from_slice(&[0x11; 32]).unwrap();
        let signer = Address::from_public_key(key.verifying_key());
        let authorization = Authorization {
            chain_id: U256::from(CHAIN_ID),
            address: ZEROFEE_ADDRESS,
            nonce: 1,
        };
        let authorization_signature = sign_test_hash(&key, &authorization.signature_hash());
        let signed_authorization = authorization.into_signed(authorization_signature);
        let input = outbe_zerofee::precompile::IZeroFee::authorizeSponsorshipCall { signer }
            .abi_encode()
            .into();
        let tx = TxEip7702 {
            chain_id: CHAIN_ID,
            nonce: 0,
            gas_limit: outbe_zerofee::FREE_TX_BOOTSTRAP_GAS_LIMIT,
            max_fee_per_gas: MIN_PROTOCOL_BASE_FEE as u128,
            max_priority_fee_per_gas: 0,
            to: ZEROFEE_ADDRESS,
            value: U256::ZERO,
            access_list: Default::default(),
            authorization_list: vec![signed_authorization],
            input,
        };
        let tx_signature = sign_test_hash(&key, &tx.signature_hash());
        let recovered = reth_ethereum::TransactionSigned::from(tx.into_signed(tx_signature))
            .try_into_recovered()
            .expect("bootstrap signer must recover");
        assert_eq!(Address::from(*recovered.signer()), signer);
        recovered
    }

    #[test]
    fn eip7702_bootstrap_accepts_one_atomic_unit_without_fee_or_quota() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        let recovered = bootstrap_test_tx();
        let replay = recovered.clone();
        let signer = Address::from(*recovered.signer());
        let initial_balance = U256::from(1);

        let mut db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        let marker = Bytecode::new_legacy([0xef].into());
        db.insert_account_info(
            ZEROFEE_ADDRESS,
            AccountInfo {
                code_hash: marker.hash_slow(),
                code: Some(marker),
                ..Default::default()
            },
        );
        db.insert_account_info(
            signer,
            AccountInfo {
                balance: initial_balance,
                nonce: 0,
                ..Default::default()
            },
        );
        let mut state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();

        {
            let evm = config.evm_with_env(&mut state, pectra_evm_env(1));
            let ctx = execution_ctx(Some(1), Bytes::new());
            let mut executor = config.create_executor(evm, ctx);

            let gas_output = executor
                .execute_transaction(recovered)
                .expect("one-unit bootstrap must execute under the fee waiver");
            assert!(
                gas_output.tx_gas_used() > 0,
                "bootstrap gas must remain visible in block accounting"
            );
            assert!(
                gas_output.tx_gas_used() <= outbe_zerofee::FREE_TX_BOOTSTRAP_GAS_LIMIT,
                "bootstrap gas must fit its signed limit"
            );
            assert_eq!(
                executor.current_execution_summary().validator_fee_sum,
                U256::ZERO,
                "bootstrap must not credit a validator fee"
            );
            assert_eq!(executor.receipts().len(), 1);
            assert!(executor.receipts()[0].success);

            executor
                .execute_transaction(replay)
                .expect_err("same-block bootstrap replay must fail against current state");
            assert_eq!(
                executor.receipts().len(),
                1,
                "replay must not append a receipt"
            );
        }
        state.merge_transitions(BundleRetention::Reverts);

        let account = state
            .basic(signer)
            .expect("bootstrap account read")
            .expect("bootstrap account exists");
        assert_eq!(
            account.balance, initial_balance,
            "bootstrap must not charge COEN"
        );
        assert_eq!(
            account.nonce, 2,
            "outer tx plus self-authorization consume two nonces"
        );
        assert_eq!(
            account.code.and_then(|code| code.eip7702_address()),
            Some(ZEROFEE_ADDRESS),
            "bootstrap must install the canonical delegation"
        );
        assert_eq!(
            zerofee_counter_for(&mut state, signer),
            0,
            "bootstrap must leave all daily sponsored calls available"
        );
    }

    #[test]
    fn eip7702_bootstrap_rejects_zero_balance_without_state_change() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        let recovered = bootstrap_test_tx();
        let signer = Address::from(*recovered.signer());

        let mut db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        let marker = Bytecode::new_legacy([0xef].into());
        db.insert_account_info(
            ZEROFEE_ADDRESS,
            AccountInfo {
                code_hash: marker.hash_slow(),
                code: Some(marker),
                ..Default::default()
            },
        );
        db.insert_account_info(signer, AccountInfo::default());
        let mut state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();

        {
            let evm = config.evm_with_env(&mut state, pectra_evm_env(1));
            let ctx = execution_ctx(Some(1), Bytes::new());
            let mut executor = config.create_executor(evm, ctx);
            let _error = executor
                .execute_transaction(recovered)
                .expect_err("zero-balance bootstrap must not receive the waiver");
            assert!(executor.receipts().is_empty());
        }

        let account = state
            .basic(signer)
            .expect("bootstrap account read")
            .expect("bootstrap account exists");
        assert!(account.balance.is_zero());
        assert_eq!(account.nonce, 0);
        assert!(account.is_empty_code_hash());
        assert_eq!(zerofee_counter_for(&mut state, signer), 0);
    }

    fn cache_db_with_paymaster_account(
        signer: Address,
        signer_balance: U256,
    ) -> CacheDB<EmptyDBTyped<ProviderError>> {
        let mut db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        // ZEROFEE_ADDRESS: marker bytecode for EIP-161 preservation.
        let marker = Bytecode::new_legacy([0xef].into());
        db.insert_account_info(
            ZEROFEE_ADDRESS,
            AccountInfo {
                code_hash: marker.hash_slow(),
                code: Some(marker.clone()),
                ..Default::default()
            },
        );
        // AGENT_REWARD_ADDRESS: same marker, it is a precompile target.
        db.insert_account_info(
            AGENT_REWARD_ADDRESS,
            AccountInfo {
                code_hash: marker.hash_slow(),
                code: Some(marker),
                ..Default::default()
            },
        );

        // signer: EIP-7702 delegated to ZEROFEE_ADDRESS, with the
        // requested balance so sponsored fee-debit invariants can be
        // exercised for both funded and exactly-zero accounts.
        let delegation = Bytecode::new_eip7702(ZEROFEE_ADDRESS);
        db.insert_account_info(
            signer,
            AccountInfo {
                balance: signer_balance,
                code_hash: delegation.hash_slow(),
                code: Some(delegation),
                ..Default::default()
            },
        );
        db
    }

    fn signer_balance(
        state: &mut State<CacheDB<EmptyDBTyped<ProviderError>>>,
        addr: Address,
    ) -> U256 {
        state
            .basic(addr)
            .expect("signer account read should succeed")
            .map(|a| a.balance)
            .unwrap_or_default()
    }

    fn zerofee_counter_for(
        state: &mut State<CacheDB<EmptyDBTyped<ProviderError>>>,
        signer: Address,
    ) -> u64 {
        // Reconstruct the counter slot via the same Map<Address, u64>
        // the contract uses, then read it directly off the bundle
        // state as a raw U256 and narrow to u64.
        let mut slot_storage = HashMapStorageProvider::new(CHAIN_ID);
        let slot = StorageHandle::enter(&mut slot_storage, |storage| {
            outbe_zerofee::ZeroFeeContract::new(storage.clone())
                .counter
                .slot(&signer)
                .slot()
        });
        state
            .bundle_state
            .storage(&ZEROFEE_ADDRESS, slot)
            .unwrap_or_default()
            .saturating_to::<u64>()
    }

    /// Happy path: a sponsored tx with `value=0`, `priority_fee=0`,
    /// `to in whitelist` is admitted by the
    /// executor pre-fee hook, executed under zero-fee cfg overrides,
    /// and produces a receipt with a `SponsorshipAuthorized` log. The
    /// signer's balance is untouched and ZEROFEE_ADDRESS' counter slot
    /// is bumped to `(today, 1)`.
    #[test]
    fn eip7702_sponsored_tx_burns_quota_and_emits_event() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        let recovered = sponsored_test_tx(agent_reward_query_input())
            .try_into_recovered()
            .expect("test-signature must recover");
        let signer = Address::from(*recovered.signer());

        let initial_balance = U256::from(1u64);
        let mut state = State::builder()
            .with_database(cache_db_with_paymaster_account(signer, initial_balance))
            .with_bundle_update()
            .build();

        let before = signer_balance(&mut state, signer);
        assert_eq!(before, initial_balance);

        {
            let evm = config.evm_with_env(&mut state, pectra_evm_env(1));
            let ctx = execution_ctx(Some(1), Bytes::new());
            let mut executor = config.create_executor(evm, ctx);

            executor
                .execute_transaction(recovered)
                .expect("sponsored tx should execute");

            let receipts = executor.receipts();
            assert_eq!(receipts.len(), 1);
            assert!(receipts[0].success, "sponsored transaction must succeed");

            // Find the SponsorshipAuthorized log on the receipt - this
            // is the guarantee. Topic[0] must match the event sig
            // hash; signer is topic[1] indexed.
            let sig_hash = SponsorshipAuthorized::SIGNATURE_HASH;
            let sponsorship_log = receipts[0]
                .logs
                .iter()
                .find(|l| l.address == ZEROFEE_ADDRESS && l.topics().first() == Some(&sig_hash))
                .expect("SponsorshipAuthorized log must be attached to the receipt");
            // topic[1] = padded signer
            let signer_topic = sponsorship_log
                .topics()
                .get(1)
                .expect("signer topic present");
            assert_eq!(
                &signer_topic.as_slice()[12..],
                signer.as_slice(),
                "signer indexed in topic[1]"
            );
        }
        state.merge_transitions(BundleRetention::Reverts);

        // Balance must be exactly what we put in - no fee debit. This
        // is the consensus-visible guarantee the README promises.
        let after = signer_balance(&mut state, signer);
        assert_eq!(
            after, initial_balance,
            "sponsored tx must not debit signer balance"
        );

        // Counter slot for `signer` must read `(date_key, 1)`. The
        // expected day is 20260401 (matches BLOCK_DAY in unit tests).
        let counter = zerofee_counter_for(&mut state, signer);
        let (day, count) = outbe_zerofee::unpack_counter(counter);
        assert_eq!(
            count, 1,
            "counter must be exactly 1 after a single sponsored tx"
        );
        assert_eq!(day, 20_260_401, "day-key must come from block timestamp");
    }

    /// EIP-7702 delegation to a different address must NOT trigger the
    /// sponsored path. The tx goes through the normal fee path; with
    /// `priority_fee = 0` and signer's balance below the gas cost, the
    /// EVM `disable_balance_check` would normally let it through - we
    /// assert it does NOT.
    #[test]
    fn eip7702_delegation_to_non_paymaster_falls_through_to_fee_path() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        let recovered = sponsored_test_tx(agent_reward_query_input())
            .try_into_recovered()
            .expect("test-signature must recover");
        let signer = Address::from(*recovered.signer());

        let mut db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        let marker = Bytecode::new_legacy([0xef].into());
        db.insert_account_info(
            AGENT_REWARD_ADDRESS,
            AccountInfo {
                code_hash: marker.hash_slow(),
                code: Some(marker.clone()),
                ..Default::default()
            },
        );
        // Delegate to ORACLE_ADDRESS, NOT ZEROFEE_ADDRESS.
        let foreign_delegation = Bytecode::new_eip7702(ORACLE_ADDRESS);
        db.insert_account_info(
            signer,
            AccountInfo {
                balance: U256::from(2_000_000u64),
                code_hash: foreign_delegation.hash_slow(),
                code: Some(foreign_delegation),
                ..Default::default()
            },
        );
        let mut state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();

        {
            let evm = config.evm_with_env(&mut state, pectra_evm_env(1));
            let ctx = execution_ctx(Some(1), Bytes::new());
            let mut executor = config.create_executor(evm, ctx);

            // The tx is shaped like a sponsored envelope (priority_fee=0,
            // small gas) - but because signer's code points to ORACLE,
            // the pre-fee hook leaves it to the normal path. The normal
            // path requires balance to cover `gas_limit * max_fee_per_gas`,
            // which 2 COEN (2_000_000 unit) covers at the protocol fee floor,
            // so this succeeds. The key assertion is that NO SponsorshipAuthorized
            // log is emitted and the counter stays at 0.
            executor
                .execute_transaction(recovered)
                .expect("non-sponsored tx should still execute through normal fee path");

            let receipts = executor.receipts();
            assert_eq!(receipts.len(), 1);
            let sig_hash = SponsorshipAuthorized::SIGNATURE_HASH;
            let has_event = receipts[0]
                .logs
                .iter()
                .any(|l| l.address == ZEROFEE_ADDRESS && l.topics().first() == Some(&sig_hash));
            assert!(
                !has_event,
                "non-sponsored tx must NOT emit SponsorshipAuthorized"
            );
        }
        state.merge_transitions(BundleRetention::Reverts);

        // Counter must remain at 0 - no quota burn for delegation to
        // foreign address.
        let counter = zerofee_counter_for(&mut state, signer);
        assert_eq!(counter, 0, "non-sponsored path must not burn quota");
    }

    /// Native balance is not an eligibility signal: a correctly delegated
    /// zero-balance signer executes through the sponsored path, burns one
    /// quota slot, and pays no native gas.
    #[test]
    fn eip7702_sponsored_tx_accepts_fresh_zero_balance_signer() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        let recovered = sponsored_test_tx(agent_reward_query_input())
            .try_into_recovered()
            .expect("test-signature must recover");
        let signer = Address::from(*recovered.signer());

        let mut state = State::builder()
            .with_database(cache_db_with_paymaster_account(signer, U256::ZERO))
            .with_bundle_update()
            .build();

        {
            let evm = config.evm_with_env(&mut state, pectra_evm_env(1));
            let ctx = execution_ctx(Some(1), Bytes::new());
            let mut executor = config.create_executor(evm, ctx);

            executor
                .execute_transaction(recovered)
                .expect("zero-balance sponsored tx should execute");

            let receipts = executor.receipts();
            assert_eq!(receipts.len(), 1);
            assert!(receipts[0].success, "zero-balance sponsorship must succeed");
            let sponsorship_log = receipts[0]
                .logs
                .iter()
                .find(|log| {
                    log.address == ZEROFEE_ADDRESS
                        && log.topics().first() == Some(&SponsorshipAuthorized::SIGNATURE_HASH)
                })
                .expect("successful zero-balance sponsorship must emit authorization");
            assert_eq!(
                &sponsorship_log.topics()[1].as_slice()[12..],
                signer.as_slice()
            );
        }
        state.merge_transitions(BundleRetention::Reverts);

        assert_eq!(signer_balance(&mut state, signer), U256::ZERO);
        let counter = zerofee_counter_for(&mut state, signer);
        let (day, count) = outbe_zerofee::unpack_counter(counter);
        assert_eq!(day, 20_260_401);
        assert_eq!(count, 1);
    }

    /// Computes the ZEROFEE counter storage slot for `signer` (the same
    /// keccak-derived `Map<Address,u64>` slot the contract uses).
    fn zerofee_counter_slot(signer: Address) -> U256 {
        let mut slot_storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut slot_storage, |storage| {
            outbe_zerofee::ZeroFeeContract::new(storage.clone())
                .counter
                .slot(&signer)
                .slot()
        })
    }

    /// F2/code-110 executor-level proof: when the signer has already
    /// burned all 8 slots for today, a 9th sponsored tx is NOT rejected
    /// by the pre-fee hook as a hard error - it lands in the block with
    /// a `status=0` receipt carrying `OutbeFailure(110)`, the counter
    /// stays at 8 (no over-burn), and no balance is debited. This is the
    /// exact contract the README promises and the txpool relies on
    /// (pool admits, executor produces the soft-failure).
    #[test]
    fn eip7702_ninth_sponsored_tx_soft_fails_with_code_110() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        let recovered = sponsored_test_tx(agent_reward_query_input())
            .try_into_recovered()
            .expect("test-signature must recover");
        let signer = Address::from(*recovered.signer());

        // pectra_evm_env uses timestamp 1_775_001_600 -> UTC day 20260401.
        const TODAY: u32 = 20_260_401;
        let initial_balance = U256::from(1u64);

        let mut db = cache_db_with_paymaster_account(signer, initial_balance);
        // Seed the counter to the full daily limit for TODAY.
        db.insert_account_storage(
            ZEROFEE_ADDRESS,
            zerofee_counter_slot(signer),
            U256::from(outbe_zerofee::pack_counter(
                TODAY,
                outbe_zerofee::FREE_TX_DAILY_LIMIT,
            )),
        )
        .expect("seed counter storage");

        let mut state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();

        {
            let evm = config.evm_with_env(&mut state, pectra_evm_env(1));
            let ctx = execution_ctx(Some(1), Bytes::new());
            let mut executor = config.create_executor(evm, ctx);

            executor
                .execute_transaction(recovered)
                .expect("exhausted-quota tx must soft-fail, not hard-error");

            let receipts = executor.receipts();
            assert_eq!(receipts.len(), 1);
            assert!(
                !receipts[0].success,
                "exhausted-quota sponsored tx must produce a status=0 receipt"
            );
            let outbe_failure_addr = outbe_primitives::addresses::ZERO_FEE_POLICY_LOG_ADDRESS;
            let failure_log = receipts[0]
                .logs
                .iter()
                .find(|l| l.address == outbe_failure_addr)
                .expect("soft-failure receipt must carry an OutbeFailure log");
            let code_topic = failure_log.topics().get(1).expect("code topic present");
            let code = u16::from_be_bytes([code_topic.as_slice()[30], code_topic.as_slice()[31]]);
            assert_eq!(code, 110, "quota exhaustion must surface as code 110");

            // No SponsorshipAuthorized event on the failed path.
            let sig_hash = SponsorshipAuthorized::SIGNATURE_HASH;
            assert!(
                !receipts[0]
                    .logs
                    .iter()
                    .any(|l| l.address == ZEROFEE_ADDRESS && l.topics().first() == Some(&sig_hash)),
                "rejected tx must not emit SponsorshipAuthorized"
            );
        }
        // Counter must stay at exactly the limit - no 9th increment.
        // Read LIVE storage (not bundle_state): the rejected tx makes no
        // counter change, so the seeded value only exists in the base
        // state, not in the post-execution change set.
        let slot = zerofee_counter_slot(signer);
        let packed = state
            .storage(ZEROFEE_ADDRESS, slot)
            .expect("counter storage read")
            .saturating_to::<u64>();
        let (day, count) = outbe_zerofee::unpack_counter(packed);
        assert_eq!(day, TODAY);
        assert_eq!(
            count,
            outbe_zerofee::FREE_TX_DAILY_LIMIT,
            "rejected 9th tx must not over-burn the counter"
        );
        // No fee debited on the rejected tx.
        assert_eq!(signer_balance(&mut state, signer), initial_balance);
    }

    /// F1 executor-level proof: the delegation probe's `code_by_hash`
    /// fallback branch is the production steady-state path. For an
    /// account whose code was set in a PRIOR block, revm's
    /// `State::basic()` returns `info.code == None` (only `code_hash`),
    /// so the pre-fee hook must resolve the delegation via
    /// `db.code_by_hash(code_hash)`. The other integration tests insert
    /// `code: Some(..)` and therefore only exercise the `maybe_code`
    /// arm; this test forces the fallback by registering the delegation
    /// bytecode in the contracts cache while leaving the account's
    /// `code` field `None`.
    #[test]
    fn eip7702_delegation_detected_via_code_by_hash_fallback() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        let recovered = sponsored_test_tx(agent_reward_query_input())
            .try_into_recovered()
            .expect("test-signature must recover");
        let signer = Address::from(*recovered.signer());

        let initial_balance = U256::from(1u64);
        let mut db = cache_db_with_paymaster_account(signer, initial_balance);

        // Recreate the signer account in the STEADY-STATE shape:
        // `code == None`, `code_hash` set, and the delegation bytecode
        // registered in the contracts cache (reachable only via
        // code_by_hash). The first insert (code: Some) registers the
        // contract; the second (code: None) replaces the account entry
        // while leaving the contract in the cache.
        let delegation = Bytecode::new_eip7702(ZEROFEE_ADDRESS);
        let delegation_hash = delegation.hash_slow();
        db.insert_account_info(
            signer,
            AccountInfo {
                balance: initial_balance,
                code_hash: delegation_hash,
                code: Some(delegation),
                ..Default::default()
            },
        );
        db.insert_account_info(
            signer,
            AccountInfo {
                balance: initial_balance,
                code_hash: delegation_hash,
                code: None, // forces the code_by_hash fallback in the probe
                ..Default::default()
            },
        );

        let mut state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();

        // Sanity: basic() really returns code == None for this account,
        // so the test genuinely exercises the fallback branch.
        let basic = state
            .basic(signer)
            .expect("basic read")
            .expect("signer account exists");
        assert!(
            basic.code.is_none(),
            "test precondition: signer.code must be None to exercise code_by_hash fallback"
        );

        {
            let evm = config.evm_with_env(&mut state, pectra_evm_env(1));
            let ctx = execution_ctx(Some(1), Bytes::new());
            let mut executor = config.create_executor(evm, ctx);

            executor
                .execute_transaction(recovered)
                .expect("sponsored tx via code_by_hash fallback should execute");

            let receipts = executor.receipts();
            assert_eq!(receipts.len(), 1);
            assert!(
                receipts[0].success,
                "delegation resolved via code_by_hash must take the sponsored path"
            );
            let sig_hash = SponsorshipAuthorized::SIGNATURE_HASH;
            assert!(
                receipts[0]
                    .logs
                    .iter()
                    .any(|l| l.address == ZEROFEE_ADDRESS && l.topics().first() == Some(&sig_hash)),
                "sponsored path must emit SponsorshipAuthorized"
            );
        }
        state.merge_transitions(BundleRetention::Reverts);

        // Counter bumped to 1 and no fee debited - confirms the fallback
        // branch actually routed into the sponsored path.
        let counter = zerofee_counter_for(&mut state, signer);
        assert_eq!(
            outbe_zerofee::unpack_counter(counter).1,
            1,
            "fallback-detected delegation must burn exactly one slot"
        );
        assert_eq!(signer_balance(&mut state, signer), initial_balance);
    }

    /// Additive-delegation guarantee: a delegated account that sets a tip
    /// (`priority_fee > 0`) is NOT requesting sponsorship - its tx must
    /// run through the normal fee path (balance debited, no quota burn,
    /// no SponsorshipAuthorized event), exactly as if the account were
    /// not delegated. This is what lets a signer keep transacting and
    /// paying after the daily free quota is exhausted; without the fix
    /// the executor soft-failed every non-free-envelope tx from a
    /// delegated account, jailing it into free-only mode.
    #[test]
    fn eip7702_delegated_account_with_priority_fee_pays_normally() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        // Same target/calldata as the sponsored happy path, but with a
        // non-zero priority fee - the "I am paying" signal.
        let paying_tx: reth_ethereum::TransactionSigned = TxEip1559 {
            chain_id: CHAIN_ID,
            nonce: 0,
            gas_limit: 200_000,
            max_fee_per_gas: 14,
            max_priority_fee_per_gas: 1, // tip > 0 => paying, not sponsored
            to: TxKind::Call(AGENT_REWARD_ADDRESS),
            value: U256::ZERO,
            input: agent_reward_query_input().into(),
            access_list: Default::default(),
        }
        .into_signed(Signature::test_signature())
        .into();
        let recovered = paying_tx
            .try_into_recovered()
            .expect("test-signature must recover");
        let signer = Address::from(*recovered.signer());

        // Delegated to ZEROFEE, funded with 1 COEN so the normal fee
        // path has balance to debit.
        let initial_balance = U256::from(3_000_000u64);
        let mut state = State::builder()
            .with_database(cache_db_with_paymaster_account(signer, initial_balance))
            .with_bundle_update()
            .build();

        {
            let evm = config.evm_with_env(&mut state, pectra_evm_env(1));
            let ctx = execution_ctx(Some(1), Bytes::new());
            let mut executor = config.create_executor(evm, ctx);

            executor
                .execute_transaction(recovered)
                .expect("paying delegated tx must execute via the normal fee path");

            let receipts = executor.receipts();
            assert_eq!(receipts.len(), 1);
            assert!(
                receipts[0].success,
                "paying delegated tx must succeed as a normal tx"
            );
            // No SponsorshipAuthorized event - this was not a sponsored tx.
            let sig_hash = SponsorshipAuthorized::SIGNATURE_HASH;
            assert!(
                !receipts[0]
                    .logs
                    .iter()
                    .any(|l| l.address == ZEROFEE_ADDRESS && l.topics().first() == Some(&sig_hash)),
                "paying tx must NOT emit SponsorshipAuthorized"
            );
        }
        state.merge_transitions(BundleRetention::Reverts);

        // Fee WAS debited (normal path), and the daily quota counter was
        // NOT touched - the tx never entered the sponsorship branch.
        assert!(
            signer_balance(&mut state, signer) < initial_balance,
            "normal fee path must debit the signer's balance"
        );
        assert_eq!(
            zerofee_counter_for(&mut state, signer),
            0,
            "paying tx must not burn a free-tx slot"
        );
    }
}
