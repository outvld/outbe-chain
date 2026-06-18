//! Outbe block executor.
//!
//! Wraps [`EthBlockExecutor`] and adds Outbe-specific block hooks in
//! [`apply_pre_execution_changes`](OutbeBlockExecutor::apply_pre_execution_changes).

use alloy_consensus::SignableTransaction as _;
use alloy_consensus::Transaction as _;
use alloy_evm::{
    block::{
        BlockExecutionError, BlockExecutor, BlockValidationError, CommitChanges, ExecutableTx,
        GasOutput, InternalBlockExecutionError, OnStateHook, StateDB,
    },
    eth::{EthBlockExecutor, EthTxResult},
    revm::context::Block as _,
    Database, RecoveredTx,
};
use alloy_primitives::{keccak256, map::AddressMap, Address, Bytes, Log, B256, U256};
use outbe_primitives::{
    block::{BlockContext, BlockLifecycle, BlockRuntimeContext},
    consensus::{ConsensusExecutionBridge, GenesisValidators},
    consensus_metadata::CertifiedParentAccountingMetadata,
    error::{PrecompileError, Result as OutbeResult},
    reshare_artifact::{
        decode_outbe_block_artifacts, ConsensusHeaderArtifact, ExecutionSummaryArtifact,
    },
    storage::{direct::DirectStorageProvider, StorageHandle},
    OutbeHeader,
};
use outbe_zerofee::ZeroFeeTransaction;
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
        build_unsigned_system_tx, expected_begin_block_kinds, is_reserved_system_tx,
        validate_phase1_witness_against, SystemTxInputV2, SystemTxKind,
    },
};
use reth_ethereum::chainspec::ChainSpec;

/// Outbe runtime addresses that receive `0xEF` EIP-161 marker bytecode in every
/// block's pre-execution step ([`OutbeBlockExecutor::apply_pre_execution_changes`])
/// so their persistent EVM storage survives state-root computation — EIP-161
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

    pub const OUTBE_RUNTIME_MARKER_ADDRESSES: [Address; 35] = [
        GRATIS_ADDRESS,
        GRATIS_FACTORY_ADDRESS,
        GRATIS_POOL_ADDRESS,
        CREDIS_ADDRESS,
        CREDIS_FACTORY_ADDRESS,
        PROMIS_ADDRESS,
        // PromisFactory is a live stateful precompile (in
        // `outbe_precompile_addresses`) and is NOT genesis-seeded, so this
        // per-block runtime marker is its only EIP-161 preservation path —
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
        MERCHANT_ADDRESS,
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
        UPDATE_ADDRESS,
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
/// - `current_hash == reshare.active_set_hash` → write incoming snapshot and
///   re-activate the same active set atomically.
/// - mismatch + `is_validator_set_change == true` → apply boundary activation
///   and write incoming snapshot atomically.
/// - mismatch + `is_validator_set_change == false` → fatal.
pub(crate) fn apply_boundary_outcome(
    storage: StorageHandle,
    boundary: &outbe_primitives::consensus::DkgBoundaryArtifact,
) -> outbe_primitives::error::Result<()> {
    let reshare = &boundary.reshare;

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
    let current_hash = vs_check.active_consensus_set_hash.read()?;

    if current_hash != reshare.active_set_hash && !boundary.is_validator_set_change {
        return Err(PrecompileError::Fatal(format!(
            "boundary active_set_hash changed without validator-set change: current={current_hash}, boundary={}",
            reshare.active_set_hash
        )));
    }

    let inputs = outbe_validatorset::hooks::BoundaryActivationInputs {
        outgoing: None,
        incoming_epoch: boundary.epoch,
        incoming: incoming_snapshot,
        new_active_set: reshare.new_active_set.clone(),
        active_set_hash: reshare.active_set_hash,
    };
    outbe_validatorset::hooks::activate_boundary_atomic(storage, &inputs)?;
    Ok(())
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
        let Some(record) = vs.get_validator(*address)? else {
            return Err(PrecompileError::Fatal(format!(
                "boundary active set contains unregistered validator {address}"
            )));
        };
        committee.push(outbe_validatorset::CommitteeEntry {
            address: *address,
            consensus_pubkey: record.consensus_pubkey,
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
///   current consensus participant — historical EXITING/UNBONDING is fine)
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
/// finalized — it only needs to be the certified-parent of the block
/// being executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountedParentArtifact {
    pub summary: ExecutionSummaryArtifact,
    pub timestamp: u64,
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
struct ZeroFeeCfgSnapshot {
    disable_balance_check: bool,
    disable_base_fee: bool,
    disable_fee_charge: bool,
}

trait ZeroFeeCfgAccess {
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

/// Runs the Outbe pre-execution hook chain against a pre-built runtime context.
///
/// Exercised by `OutbeBlockExecutor::apply_pre_execution_changes` against a Reth
/// `StateDB` wrapped in `DirectStorageProvider`, and by lifecycle-level tests
/// against `HashMapStorageProvider`. Ordering is load-bearing:
///
/// 1. Genesis-state validation (blocks 0/1 only, if consensus config was supplied).
/// 2. `UpdateLifecycle::begin_block` — tally expired proposals and activate approved ones.
/// 3. `RewardsLifecycle::begin_block` — locks in `genesis_utc_day` on
///    block 0; the per-block emission and per-day settle paths have
///    moved to the Cycle module.
/// 3. Validator-set epoch boundary: reset slash indicator counters, transition
///    epoch, cleanup stale INACTIVE validators (cap 16/epoch).
/// 4. Metadosis WWD state machine has moved to the Cycle handler at
///    UTC midnight; no per-block hook here anymore.
/// 5. Staking matured-unbonding processing.
/// 6. `OracleLifecycle::begin_block` — tally + daily S-curve only.
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
    let block_number = hook_ctx.block.block_number;
    let timestamp = hook_ctx.block.timestamp;

    // Genesis state must be present in genesis.json. The executor only
    // verifies the local validators config against that canonical state.
    if block_number <= 1 {
        if let Some(genesis) = genesis_validators {
            validate_genesis_state(hook_ctx.storage.clone(), genesis)?;
        }
    }

    <outbe_update::lifecycle::UpdateLifecycle as BlockLifecycle>::begin_block(hook_ctx)?;

    // EmissionLimit no longer participates in pre-execution lifecycle.
    // Per-block emission dispatch was removed (Phase 4 of
    // the Cycle epic) — the closed-form daily cap, sink allocation,
    // and AgentReward / Metadosis dispatch all run from the Cycle
    // module's UTC-midnight handler instead.

    // Rewards lifecycle: locks in `genesis_utc_day` on block 0. Day-
    // boundary settle moved out of Rewards (Phase 3); the
    // Cycle handler now owns the daily orchestration.
    <outbe_rewards::lifecycle::RewardsLifecycle as BlockLifecycle>::begin_block(hook_ctx)?;

    if outbe_validatorset::hooks::is_epoch_boundary(hook_ctx.storage.clone(), block_number)? {
        // Reset slash indicator per-epoch counters.
        let vs = outbe_validatorset::contract::ValidatorSet::new(hook_ctx.storage.clone());
        let all = vs.get_all_validators()?;
        let addrs: Vec<Address> = all.iter().map(|v| v.validator_address).collect();
        let mut si = outbe_slashindicator::contract::SlashIndicator::new(hook_ctx.storage.clone());
        si.reset_epoch_counters(&addrs)?;

        // Transition epoch (resets validator counters, increments epoch number).
        outbe_validatorset::hooks::transition_epoch(
            hook_ctx.storage.clone(),
            timestamp,
            block_number,
        )?;

        // Cleanup stale INACTIVE validator entries (cap 16 per epoch).
        let mut vs_cleanup =
            outbe_validatorset::contract::ValidatorSet::new(hook_ctx.storage.clone());
        vs_cleanup.cleanup_inactive_validators(16)?;
    }

    // Metadosis WWD state machine + lysis distribution moved to the
    // Cycle handler. The
    // legacy `MetadosisLifecycle::begin_block` lifecycle hook used to
    // run here on every block; it is now invoked once per UTC midnight
    // by `outbe_cycle::handler::run_emission_limit_daily` after
    // `dispatch_terminal_remainder_at` writes the day_metadosis_limit.

    // Staking: process matured unbonding entries.
    outbe_staking::hooks::process_unbonding(hook_ctx.storage.clone(), timestamp)?;

    // Oracle: tally at vote period boundary and run daily S-curve. Slash-window
    // force-exits run later in the receipt-visible OracleSlashWindow system phase
    // so Phase 3 BoundaryOutcome can activate its target set before Oracle marks
    // underperformers EXITING.
    <outbe_oracle::hooks::OracleLifecycle as BlockLifecycle>::begin_block(hook_ctx)?;

    // NOD: promote unqualified buckets whose floor_price <= current COEN/0xUSD
    // exchange rate. Runs after Oracle so it observes the just-tallied rate.
    <outbe_nod::hooks::NodLifecycle as BlockLifecycle>::begin_block(hook_ctx)?;

    // GEM: promote unqualified gems whose floor_price < current COEN/<reference>
    // exchange rate AND whose maturity has elapsed. Reads the same Oracle
    // surface, so it must run after Oracle.
    <outbe_gem::GemLifecycle as BlockLifecycle>::begin_block(hook_ctx)?;

    // INTEX: qualify matured Issued series whose floor < current COEN/0xUSD
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
    let mut provider = DirectStorageProvider::new(db, ctx.clone());
    let storage = StorageHandle::new(&mut provider);
    let runtime_ctx = BlockRuntimeContext::new(ctx, storage.clone());

    let result = storage.with_checkpoint(|| hooks(&runtime_ctx));

    result.map_err(|e| {
        BlockExecutionError::Internal(InternalBlockExecutionError::Other(
            format!("outbe hook: {e}").into(),
        ))
    })?;

    provider.flush().map_err(|e| {
        BlockExecutionError::Internal(InternalBlockExecutionError::Other(
            format!("outbe hook flush: {e}").into(),
        ))
    })?;

    let changes = provider.take_committed_changes();
    let events = provider.take_events();
    Ok((changes, events))
}

fn build_block_context<DB>(
    db: &mut DB,
    block_number: u64,
    timestamp: u64,
    chain_id: u64,
    proposer: Address,
) -> Result<BlockContext, BlockExecutionError>
where
    DB: StateDB,
    DB::Error: std::fmt::Display,
{
    let mut provider = DirectStorageProvider::new(
        db,
        BlockContext::new(block_number, timestamp, chain_id, proposer, Vec::new()),
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

    Ok(BlockContext::new(
        block_number,
        timestamp,
        chain_id,
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
        let Some(record) = vs.get_validator(validator.address)? else {
            return Err(PrecompileError::Fatal(format!(
                "genesis validator {} is missing from ValidatorSet",
                validator.address
            )));
        };

        if record.consensus_pubkey != validator.consensus_pubkey {
            return Err(PrecompileError::Fatal(format!(
                "genesis validator {} consensus pubkey mismatch",
                validator.address
            )));
        }
        if record.status != outbe_validatorset::logic::status::ACTIVE || !record.has_bls_share {
            return Err(PrecompileError::Fatal(format!(
                "genesis validator {} must be active with a BLS share",
                validator.address
            )));
        }
        if record.stake < min_stake {
            return Err(PrecompileError::Fatal(format!(
                "genesis validator {} stake below min_stake",
                validator.address
            )));
        }

        let staking_amount = staking.stake_amount.read(&validator.address)?;
        if staking_amount != record.stake {
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
    #[allow(dead_code)]
    expected_end_system_txs: Vec<Recovered<TransactionSigned>>,
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
    /// tx after `BoundaryOutcome` — identically to `build_begin_system_txs` so the
    /// body the proposer signs and the inputs the executor expects match. `None`
    /// on the validator path (the body carries it via `expected_begin_system_txs`)
    /// and until the tribute-DKG bootstrap producer supplies a payload.
    pending_tee_bootstrap: Option<outbe_primitives::tee_bootstrap::TeeBootstrapPayload>,
    /// Number of zero-fee soft-failure receipts emitted in THIS
    /// block. Bounds block-stuffing by zero-cost 21k soft-failures (see
    /// [`Self::record_zero_fee_soft_failure`]). The executor is constructed
    /// fresh per block, so this resets per block; it is identical on the
    /// proposer (build) and validator (re-execution) paths.
    zero_fee_soft_failures: u32,
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
        Self {
            inner,
            bridge,
            final_extra_data: block_extra_data.clone(),
            block_extra_data,
            accounted_parent_artifact_provider,
            validate_execution_summary,
            block_hash,
            parent_hash,
            current_block_validator_fees: U256::ZERO,
            system_tx_execution_gas: 0,
            evm_signer,
            expected_begin_system_txs,
            expected_end_system_txs,
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
            zero_fee_soft_failures: 0,
        }
    }

    /// Proposer-path builder: attach the one-time `TeeBootstrap` payload the
    /// executor injects after `BoundaryOutcome`. No-op (stays `None`) on the
    /// validator path. Mirrors `OutbeEvmConfig::build_begin_system_txs`.
    pub(crate) fn with_pending_tee_bootstrap(
        mut self,
        pending_tee_bootstrap: Option<outbe_primitives::tee_bootstrap::TeeBootstrapPayload>,
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

    #[cfg(test)]
    pub(crate) fn force_preexecuted_phase1_witness_for_test(&mut self, tx_hash: B256) {
        self.system_tx_phase_cursor = crate::system_tx::SystemTxPhase::Phase1Preexecuted {
            body_index: 0,
            tx_hash,
            receipt_index: 0,
        };
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
    /// per block, yet caps stuffing at `64 * 21k ≈ 1.34M` gas — under ~5% of a
    /// 30M-gas block. Protocol constant: both the proposer (build) and validator
    /// (re-execution) read it, so they agree on the bound.
    const MAX_ZERO_FEE_SOFT_FAILURES_PER_BLOCK: u32 = 64;

    /// Account for one zero-fee soft-failure and enforce the
    /// per-block cap.
    ///
    /// Returns `Ok(())` when the soft-failure is within the per-block budget (and
    /// records it); past [`Self::MAX_ZERO_FEE_SOFT_FAILURES_PER_BLOCK`] it
    /// returns `Err(BlockValidationError::InvalidTx)`, which the payload builder
    /// SKIPS (`mark_invalid` + continue — the tx is excluded from the block and
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

    /// Pushes a `status=0` system synthetic receipt with exactly one
    /// `OutbeFailure(code, reason)` log, charges the visible system tx gas to
    /// the public block gas lane, and leaves EVM state untouched.
    pub(crate) fn push_system_failure_receipt(
        &mut self,
        tx_type: alloy_consensus::TxType,
        log_address: Address,
        code: u16,
        reason: String,
        visible_gas_used: u64,
        internal_gas_used: u64,
    ) {
        let log = crate::failure_receipt::build_outbe_failure_log(log_address, code, reason);
        let system_cumulative_gas_used = self
            .system_tx_execution_gas
            .saturating_add(internal_gas_used);
        let user_cumulative_gas_used = self
            .inner
            .cumulative_tx_gas_used
            .saturating_add(visible_gas_used);
        self.inner.receipts.push(Receipt {
            tx_type,
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
}

/// Maps an `ExecutionResult` (from a Phase 1-4 system tx that produced
/// `!is_success`) to a stable `u16` `OutbeFailure` code in the 200-299
/// band reserved for `outbe-evm` phase failures. The exhaustive `match`
/// makes adding a new revm variant a compile error.
///
/// Codes:
/// - 201 — explicit revert (Solidity `require`, `revert`, etc.)
/// - 202 — out-of-gas (any `OutOfGasError` variant)
/// - 299 — other halt reasons (precompile error, opcode not found, …)
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
    /// Commits an Outbe begin-zone system transaction with separate internal
    /// and visible gas accounting.
    ///
    /// The precompile executes under the internal 100M system-call budget.
    /// The public Ethereum block gas lane charges only the signed envelope's
    /// visible intrinsic gas, keeping system transactions replay/import
    /// compatible without exposing the 100M execution lane.
    fn commit_system_transaction(
        &mut self,
        output: EthTxResult<E::HaltReason, alloy_consensus::TxType>,
        visible_gas_used: u64,
    ) -> Result<GasOutput, BlockExecutionError> {
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

        let gas_output = self.inner.commit_transaction(output);
        self.system_tx_execution_gas = self
            .system_tx_execution_gas
            .checked_add(gas_output.tx_gas_used())
            .ok_or_else(|| {
                BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                    "system tx execution gas overflow".into(),
                ))
            })?;

        if let Some(receipt) = self.inner.receipts.last_mut() {
            receipt.cumulative_gas_used = visible_cumulative_tx_gas;
        }

        self.inner.cumulative_tx_gas_used = visible_cumulative_tx_gas;
        self.inner.block_regular_gas_used = user_regular_gas.saturating_add(visible_gas_used);
        self.inner.block_state_gas_used = user_state_gas.saturating_add(visible_gas_used);

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
        let ctx = BlockContext::new(block_number, timestamp, chain_id, proposer, Vec::new());
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
    ///    `(block_number - 1, self.parent_hash)` — i.e., the hint must be for
    ///    the actual parent of the block being executed. The proposer payload
    ///    builder decodes this from `parent_header.extra_data` at build time,
    ///    so the hint inherits the integrity of the parent block hash chain.
    ///
    /// Returns an error only on real provider I/O failure. `HeaderNotFound`
    /// is a visibility miss (e.g. the FCU-Valid → MDBX-commit race), so the
    /// executor treats it like `Ok(None)` and lets the checked
    /// `parent_artifact_hint` fallback engage. A provider miss with no usable
    /// hint is fatal — the executor never silently accepts a
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
        // `pending_tee_bootstrap` is set — never inject a begin-zone tx at genesis.
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
        // verifier mode re-derives it from the body and the header↔calldata
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
        // (begin_order 3) and `OracleSlashWindow` (begin_order 4).
        // Verifier mode: include it iff the body carries it at this ordinal.
        // Proposer mode: inject the `pending_tee_bootstrap` payload supplied by
        // the bootstrap producer — identically to `build_begin_system_txs` so the
        // proposer's signed body and the executor's expected inputs match.
        if verifier_mode {
            if let Ok(SystemTxInputV2::TeeBootstrap { payload }) =
                self.expected_begin_input(ordinal)
            {
                system_txs.push((
                    SystemTxKind::TeeBootstrap,
                    SystemTxInputV2::TeeBootstrap { payload },
                    None,
                ));
                ordinal += 1;
            }
        } else if let Some(payload) = self.pending_tee_bootstrap.clone() {
            system_txs.push((
                SystemTxKind::TeeBootstrap,
                SystemTxInputV2::TeeBootstrap { payload },
                None,
            ));
            ordinal += 1;
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
        ),
        BlockExecutionError,
    > {
        let system_txs = self.begin_block_system_tx_inputs(block_number, block_artifacts)?;
        system_txs.into_iter().nth(body_index).ok_or_else(|| {
            let has_boundary_outcome = matches!(
                block_artifacts.consensus_header_artifact,
                Some(ConsensusHeaderArtifact::BoundaryOutcome(_))
            );
            let has_tee_bootstrap = self.block_has_tee_bootstrap();
            let expected = expected_begin_block_kinds(
                block_number,
                has_boundary_outcome,
                has_tee_bootstrap,
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
            let ctx = BlockContext::new(block_number, timestamp, chain_id, proposer, Vec::new());
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
    /// pre-exec path as [`Self::verify_phase1_in_preexec`] — synchronous, no
    /// state mutation, `Err` aborts the block before any begin-zone state diff
    /// reaches Reth's state-root task — and enforces, for every batch:
    ///
    /// - the target sits inside the inclusion window: `1 ≤ block − fb ≤ K`;
    /// - the committee snapshot for `(epoch, committee_set_hash)` exists;
    /// - the aggregate verifies against that snapshot (no quorum/VRF floor —
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
            // The escrow for the closest in-window target (block N−1) is written
            // by THIS block's CPA, which runs in the body AFTER this pre-exec
            // gate — so the binding is not yet present at pre-exec. The
            // authentication therefore lives in the begin-zone body
            // (`run_late_finalize_credits`, after the CPA), where a mismatch is
            // FATAL and aborts the block. This pre-exec gate covers the BLS proof
            // (committee snapshot exists from the epoch boundary).
            let snapshot_key = committee_snapshot_key(credit.epoch, credit.committee_set_hash);
            let snapshot = {
                let db = self.inner.evm.db_mut();
                let ctx =
                    BlockContext::new(block_number, timestamp, chain_id, proposer, Vec::new());
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
    /// same code path the main tx loop uses for system txs — it pushes the
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
    /// without re-executing or re-committing — receipt and state are
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

        // Resolve proposer first — `begin_zone_proposer` is `Option`-aware
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
        let (cached_tx_hash, visible_gas_used) = if let Some(prebuilt) = &self.prebuilt_phase1_tx {
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
            let visible_gas_used = signed.gas_limit();
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
            (tx_hash, visible_gas_used)
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

        // Execute Phase 1 precompile.
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
        if !result.result.is_success() {
            // Phase 1 (CertifiedParentAccounting) is consensus-critical
            // (`SystemTxKind::revert_fails_block()` is true for it), so a revert here
            // is a hard block failure, not a soft-receipt skip — its finalized-parent
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
        self.commit_system_transaction(output, visible_gas_used)?;

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
    /// that body index (e.g. block 1 + Phase 1 cursor — a programmer
    /// invariant violation).
    fn expected_system_tx_for_cursor(
        &self,
        block_number: u64,
        block_artifacts: &outbe_primitives::reshare_artifact::OutbeBlockArtifacts,
    ) -> Result<
        (
            usize,
            SystemTxKind,
            SystemTxInputV2,
            Option<AccountedParentArtifact>,
        ),
        BlockExecutionError,
    > {
        let cursor = self.system_tx_phase_cursor;
        let Some(body_index) = cursor.body_index() else {
            // Cursor=UserTxs: all begin-zone system txs are consumed.
            // Encountering a reserved system transaction address here is
            // either an unsolicited user-tx attempt at the reserved
            // address or a duplicate / out-of-band system tx — both fatal.
            return Err(BlockExecutionError::Internal(
                InternalBlockExecutionError::Other(
                    "tx to reserved system transaction address after begin-zone system txs are consumed"
                        .into(),
                ),
            ));
        };
        let body_index_usize = usize::from(body_index);
        let (resolved_kind, input, finalized_summary) =
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
        Ok((body_index_usize, resolved_kind, input, finalized_summary))
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
        let block_number = self.inner.evm.block().number().saturating_to::<u64>();
        let beneficiary = self.inner.evm.block().beneficiary();
        // initialise the begin-zone phase cursor for this block
        // BEFORE any pre-exec mutation that could affect routing. Block 1
        // (genesis bootstrap) skips Phase 1 and starts at CycleTick; block
        // `n` with `n > GENESIS_BOOTSTRAP_BLOCK_NUMBER` enters Phase 1 with
        // a zero placeholder tx_hash that the Phase 1 preflight (Batch 3)
        // overwrites once `verify_v2_proof` returns Ok and the system tx
        // is committed in pre-execution.
        self.system_tx_phase_cursor = crate::system_tx::SystemTxPhase::initial_for_block(
            block_number,
            crate::system_tx::GENESIS_BOOTSTRAP_BLOCK_NUMBER,
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

        // Local pending-block RPC construction does not have consensus-only
        // parent certificate or proposer context. Keep the standard Ethereum
        // pre-execution + account-preservation marker updates above, but skip
        // consensus-critical Outbe hooks and synthetic system phases. This path
        // is never used for sealed consensus payload validation or proposal.
        if !self.execute_outbe_block_hooks {
            return Ok(());
        }

        // 3. Extract block context before taking a mutable DB borrow.
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
        // skipped (validate-without-reexec) — receipt + state are already
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
            let ctx = build_block_context(db, block_number, timestamp, chain_id, proposer)?;
            run_atomic_storage_hooks(db, ctx, |hook_ctx| -> outbe_primitives::error::Result<()> {
                run_outbe_pre_execution_hooks(hook_ctx, genesis_validators.as_ref())
            })?
        };
        // Provider dropped here — mutable DB borrow released.

        // Log hook events via tracing for operator observability.
        // These events are emitted during tally/slash/S-curve hooks and are not
        // part of EVM transaction receipts.
        for event in &hook_events {
            tracing::info!(
                target: "outbe::hooks",
                address = %event.address,
                topics = event.data.topics().len(),
                data_len = event.data.data.len(),
                "hook event emitted"
            );
        }

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
        let tx = recovered.tx();
        let signer = *recovered.signer();

        if is_reserved_system_tx(tx) {
            let block_number = self.inner.evm.block().number().saturating_to::<u64>();
            let block_artifacts = decode_outbe_block_artifacts(self.block_extra_data.as_ref())
                .map_err(|error| BlockExecutionError::msg(error.to_string()))?;

            // Witness validate-without-reexec: if Phase 1
            // was already committed in `apply_pre_execution_changes::apply_phase1_commit_in_preexec`,
            // the cursor carries the cached witness `tx_hash`. Body[0] in the
            // main tx loop is the proposer-supplied Phase 1 tx — validate it
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
                    self.system_tx_phase_cursor = self
                        .system_tx_phase_cursor
                        .advance_after_commit(has_boundary_outcome, has_tee_bootstrap);
                    // Ok(None) signals "no further commit" — pre-exec already
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
            let (body_index, expected_phase, expected_input, finalized_summary) =
                self.expected_system_tx_for_cursor(block_number, &block_artifacts)?;
            let actual_input = SystemTxInputV2::decode(tx.input().as_ref()).map_err(|error| {
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
            let unsigned = build_unsigned_system_tx(
                expected_phase,
                ordinal,
                block_number,
                self.inner.evm.chain_id(),
                tx.input().clone(),
            )
            .map_err(|error| {
                BlockExecutionError::Internal(InternalBlockExecutionError::Other(
                    format!("build expected system tx at body_index={body_index}: {error}").into(),
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
            let visible_gas_used = tx.gas_limit();

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

            let phase_context = PreloadedSystemTxContext {
                proposer,
                finalized_summary,
                allow_boundary_proposer: self.boundary_allows_proposer(&block_artifacts, proposer),
                // same VRF-proof-hash plumbing as the
                // pre-exec commit path. Cached by the preflight; falls
                // back to `B256::ZERO` only when the preflight was
                // skipped (which never co-occurs with this main-loop
                // path entering Phase 1 in production).
                canonical_vrf_proof_hash: self.verified_phase1_vrf_proof_hash.unwrap_or(B256::ZERO),
            };
            // Phase 1-4 EVM result failures (`Revert` / `Halt`) are converted
            // into a `status=0` synthetic receipt with one `OutbeFailure(code, reason)`
            // log emitted from `OUTBE_SYSTEM_TX_ADDRESS`; revm did not commit the call so no
            // state change leaks. Raw `Err` from the system-call engine remains fatal because
            // upstream revm documents that the journal may be inconsistent on that path.
            // Body-parity validation above (decode / phase / calldata / signature / signer)
            // also remains fatal: those are validator-side checks that the proposer never
            // produces for itself.
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
                // validator rejects the same block identically — no state-root
                // split. Non-critical phases (OracleSlashWindow, TeeBootstrap)
                // keep the soft-receipt skip.
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
                self.push_system_failure_receipt(
                    tx_type,
                    outbe_primitives::addresses::OUTBE_SYSTEM_TX_ADDRESS,
                    code,
                    reason,
                    visible_gas_used,
                    result.result.tx_gas_used(),
                );
                self.system_tx_phase_cursor = self
                    .system_tx_phase_cursor
                    .advance_after_commit(has_boundary_outcome, has_tee_bootstrap);
                return Ok(Some(GasOutput::new(visible_gas_used)));
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
                .commit_system_transaction(output, visible_gas_used)
                .map(Some);
            if commit_outcome.is_ok() {
                self.system_tx_phase_cursor = self
                    .system_tx_phase_cursor
                    .advance_after_commit(has_boundary_outcome, has_tee_bootstrap);
            }
            return commit_outcome;
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
        // aborted block build — see EPIC for the halt of 2026-05-15. The tx is now
        // included with a `status=0` synthetic receipt carrying an `OutbeFailure(code, reason)`
        // log. Mempool eviction happens via Reth's standard `on_canonical_state_change` once
        // the block becomes canonical (`pool.remove_transactions(block.body)`), so no custom
        // side-channel is required (см. Won't Do).
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
            let ctx = BlockContext::new(block_number, timestamp, chain_id, proposer, Vec::new());

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
        // waivers — EOAs that have delegated to [`outbe_zerofee::ZEROFEE_ADDRESS`]
        // via a Pectra set-code authorization. The same `disable_balance_check
        // + disable_base_fee + disable_fee_charge` cfg snapshot is applied;
        // the counter increment is committed to the persistent state through
        // `DirectStorageProvider::flush` BEFORE the inner tx runs, so a
        // revert inside the tx does not un-burn the daily slot.
        let block_number = self.inner.evm.block().number().saturating_to::<u64>();
        let timestamp = self.inner.evm.block().timestamp().saturating_to::<u64>();
        let chain_id = self.inner.evm.chain_id();
        let proposer = self.inner.evm.block().beneficiary();

        // Pull `(balance, nonce, code_hash, maybe_code)` from the
        // provider. `State<DB>::basic()` (the underlying source) only
        // populates `info.code` for accounts that have had recent
        // changes; otherwise the bytecode lives behind `code_by_hash`
        // and `info.code` is None. The fix below performs the second
        // lookup when needed so the EIP-7702 delegation probe sees the
        // real bytecode in steady state.
        let signer_state = {
            let db = self.inner.evm.db_mut();
            let ctx = BlockContext::new(block_number, timestamp, chain_id, proposer, Vec::new());
            let mut provider = DirectStorageProvider::new(db, ctx);
            let storage = StorageHandle::new(&mut provider);
            storage.with_account_info(signer, |info| {
                Ok((info.balance, info.nonce, info.code_hash, info.code.clone()))
            })
        };

        let (signer_balance, _signer_nonce, code_hash, maybe_code) = match signer_state {
            Ok(quad) => quad,
            Err(err) => {
                return Err(BlockExecutionError::Internal(
                    InternalBlockExecutionError::Other(
                        format!("free-tx signer account read failed: {err}").into(),
                    ),
                ));
            }
        };

        let delegated_to = if let Some(code) = maybe_code {
            code.eip7702_address()
        } else if code_hash != revm::primitives::KECCAK_EMPTY {
            // basic() did not populate `code` — fetch bytecode by
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
        // whitelist). If the envelope does not match — most importantly
        // `priority_fee > 0` ("I am paying") — the transaction is NOT a
        // sponsorship request and falls through to the normal fee path
        // below, even though the account is delegated. This keeps
        // EIP-7702 delegation ADDITIVE: delegating to the paymaster never
        // jails an account into free-only mode, and once a signer's daily
        // quota is exhausted they simply set a tip and pay as usual.
        //
        // The stateful `authorize_sponsorship` inside the branch still
        // soft-fails a correctly-shaped attempt with code 110 (quota
        // exhausted), 111 (anti-sybil: balance 0), or 107 (self) — those
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
                let ctx =
                    BlockContext::new(block_number, timestamp, chain_id, proposer, Vec::new());
                let mut provider = DirectStorageProvider::new(db, ctx);
                let outcome = {
                    let storage = StorageHandle::new(&mut provider);
                    outbe_zerofee::authorize_sponsorship(
                        storage.clone(),
                        signer,
                        signer_balance,
                        timestamp,
                    )
                    .and_then(|auth| {
                        outbe_zerofee::record_sponsorship_use(storage, signer, auth.current_day)
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
                // recompute at block close — correctness is preserved
                // because the final root walks the full bundle state,
                // but the parallel optimisation is lost.
                let changes = provider.take_committed_changes();
                (result, events, changes)
            };

            // Notify the parallel state-root task about the counter
            // write committed via the provider above. The pre-fee
            // counter increment is logically part of THIS transaction's
            // processing — `Transaction(idx)` is the canonical variant
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

    fn finish(self) -> Result<(Self::Evm, BlockExecutionResult<Receipt>), BlockExecutionError> {
        let current_summary = self.current_execution_summary();
        let block_number = self.inner.evm.block().number().saturating_to::<u64>();
        let block_timestamp = self.inner.evm.block().timestamp().saturating_to::<u64>();
        let block_artifacts = decode_outbe_block_artifacts(self.final_extra_data().as_ref())
            .map_err(|error| BlockExecutionError::msg(error.to_string()))?;
        if self.validate_execution_summary && block_number > 0 {
            let Some(header_summary) = block_artifacts.execution_summary else {
                return Err(BlockExecutionError::msg(
                    "missing execution summary artifact in block extra_data",
                ));
            };
            if header_summary != current_summary {
                return Err(BlockExecutionError::msg(format!(
                    "execution summary artifact mismatch: header={header_summary:?}, local={current_summary:?}"
                )));
            }
        }

        // proposer recording, finalized-parent settlement,
        // slashing, Cycle, and BoundaryOutcome now execute as receipt-visible
        // begin-zone system transactions in the normal tx loop. `finish` only
        // validates header artifacts, finalizes the wrapped Ethereum executor,
        // and records the committed execution summary.

        let (evm, result) = self.inner.finish()?;
        if let (Some(bridge), Some(block_hash), Some(summary)) = (
            self.bridge.as_ref(),
            self.block_hash,
            block_artifacts.execution_summary,
        ) {
            bridge.record_execution_summary(block_number, block_hash, summary, block_timestamp);
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
    use std::sync::Arc;

    use alloy_consensus::{SignableTransaction as _, Transaction as _, TxEip1559};
    use alloy_eips::eip2718::Encodable2718;
    use alloy_evm::{
        eth::{EthBlockExecutionCtx, EthBlockExecutor},
        RecoveredTx as _,
    };
    use alloy_primitives::{address, keccak256, Address, Bytes, Signature, TxKind, B256, U256};
    use alloy_sol_types::SolCall;
    use outbe_primitives::addresses::{
        CYCLE_ADDRESS, ORACLE_ADDRESS, OUTBE_SYSTEM_TX_ADDRESS, REWARDS_ADDRESS,
        SLASH_INDICATOR_ADDRESS, STAKING_ADDRESS,
    };
    use outbe_primitives::block::{BlockContext, BlockRuntimeContext};
    use outbe_primitives::consensus::{
        ConsensusExecutionBridge, GenesisValidator, GenesisValidators,
    };
    use outbe_primitives::consensus_metadata::CertifiedParentAccountingMetadata;
    use outbe_primitives::reshare_artifact::{
        encode_outbe_block_artifacts, ConsensusHeaderArtifact, ExecutionSummaryArtifact,
        OutbeBlockArtifacts,
    };
    use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};
    use outbe_primitives::OutbeHeader;
    use reth_ethereum::chainspec::ChainSpec;
    use reth_ethereum::chainspec::MAINNET;
    use reth_ethereum::evm::revm::db::State;
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

    use super::{AccountedParentArtifact, AccountedParentArtifactProvider, OutbeBlockExecutor};
    use crate::{
        config::{OutbeBlockExecutionCtx, OutbeEvmConfig},
        signer::OutbeEvmSigner,
        system_tx::{build_unsigned_system_tx, SystemTxInputV2, SystemTxKind},
    };

    const CHAIN_ID: u64 = 1;
    const OWNER: Address = address!("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    /// reth22-1 regression: the per-block EIP-161 marker list MUST cover every
    /// *stateful* dispatch-registered precompile, or that account is pruned at
    /// state-root time and its storage is silently lost (GEM/GEM_FACTORY were
    /// missing). The marker list, the dispatch list, and genesis seeding are
    /// three separate sources of truth; this pins marker ⊇ stateful-dispatch.
    #[test]
    fn marker_list_covers_stateful_precompiles() {
        use crate::executor::marker_addresses::OUTBE_RUNTIME_MARKER_ADDRESSES;
        use crate::precompiles::outbe_precompile_addresses;
        use outbe_primitives::addresses::{
            ZEROFEE_ADDRESS, ZKPROOF_GROTH16_ADDRESS, ZKPROOF_POSEIDON_ADDRESS,
        };

        // Dispatch-registered precompiles that legitimately need NO runtime 0xEF
        // marker. Each exemption is justified; adding a stateful precompile here
        // instead of to the marker list would re-open reth22-1.
        const MARKER_EXEMPT: [Address; 3] = [
            // Stateless verifiers — no EVM storage to preserve.
            ZKPROOF_POSEIDON_ADDRESS,
            ZKPROOF_GROTH16_ADDRESS,
            // Seeded with genesis bytecode + storage (scripts/seed_genesis.py
            // ALL_PRECOMPILE_ADDRESSES), so its account is never EIP-161-empty.
            ZEROFEE_ADDRESS,
        ];

        for addr in outbe_precompile_addresses() {
            if MARKER_EXEMPT.contains(addr) {
                continue;
            }
            assert!(
                OUTBE_RUNTIME_MARKER_ADDRESSES.contains(addr),
                "stateful dispatch-registered precompile {addr} is missing from the EIP-161 \
                 runtime marker list (OUTBE_RUNTIME_MARKER_ADDRESSES) — its storage would be \
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
        MAINNET.as_ref().clone().map_header(OutbeHeader::new).into()
    }

    fn test_evm_signer() -> Arc<OutbeEvmSigner> {
        Arc::new(OutbeEvmSigner::from_secret_bytes([1u8; 32]).unwrap())
    }

    fn test_evm_env(block_number: u64, beneficiary: Address) -> EvmEnv {
        EvmEnv {
            cfg_env: CfgEnv::new()
                .with_chain_id(MAINNET.chain().id())
                .with_spec_and_mainnet_gas_params(SpecId::SHANGHAI),
            block_env: BlockEnv {
                number: U256::from(block_number),
                gas_limit: 30_000_000,
                basefee: 1_000_000_000,
                beneficiary,
                timestamp: U256::from(block_number),
                ..Default::default()
            },
        }
    }

    fn state_with_active_proposer(
        proposer: Address,
    ) -> State<CacheDB<EmptyDBTyped<ProviderError>>> {
        let mut seed_storage = HashMapStorageProvider::new(outbe_primitives::chain::CHAIN_ID);
        StorageHandle::enter(&mut seed_storage, |storage| {
            seed_registered_active_validator(storage.clone(), proposer, &dummy_pubkey(0xA2));
        });

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
        let mut seed_storage = HashMapStorageProvider::new(outbe_primitives::chain::CHAIN_ID);
        StorageHandle::enter(&mut seed_storage, |storage| {
            seed_registered_active_validator(storage.clone(), proposer, &dummy_pubkey(0xA2));
        });

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
                code: Some(marker_code),
                ..Default::default()
            },
        );
        db.insert_account_info(
            funded,
            AccountInfo {
                balance: U256::from(1_000_000_000_000_000_000u128),
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
        let mut seed_storage = HashMapStorageProvider::new(outbe_primitives::chain::CHAIN_ID);
        StorageHandle::enter(&mut seed_storage, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.config_max_validators.write(128).unwrap();
            vs.config_epoch_length_blocks.write(60).unwrap();
            vs.config_is_initialized.write(true).unwrap();
            for (validator, pk) in validators {
                vs.register_validator(OWNER, *validator, pk).unwrap();
            }
            let active: Vec<Address> = validators.iter().map(|(validator, _)| *validator).collect();
            vs.activate_reshared_set(&active, B256::ZERO).unwrap();
            // Seed the COEN/0xUSD oracle pair + a 1.0 rate so begin-block NOD/GEM/INTEX
            // floor-price promotion reads a registered pair instead of reverting
            // "pair not registered".
            let mut oracle = outbe_oracle::contract::OracleContract::new(storage.clone());
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
            seed_extra(storage);
        });

        let marker_addresses = [
            outbe_primitives::addresses::VALIDATOR_SET_ADDRESS,
            outbe_primitives::addresses::ORACLE_ADDRESS,
            CYCLE_ADDRESS,
            SLASH_INDICATOR_ADDRESS,
            outbe_primitives::addresses::STAKING_ADDRESS,
            outbe_primitives::addresses::REWARDS_ADDRESS,
            outbe_primitives::addresses::AGENT_REWARD_ADDRESS,
            outbe_primitives::addresses::METADOSIS_ADDRESS,
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
        let mut seed_storage = HashMapStorageProvider::new(outbe_primitives::chain::CHAIN_ID);
        StorageHandle::enter(&mut seed_storage, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.config_max_validators.write(128).unwrap();
            vs.config_epoch_length_blocks.write(60).unwrap();
            vs.config_is_initialized.write(true).unwrap();
            vs.register_validator(OWNER, active, &dummy_pubkey(0xA2))
                .unwrap();
            vs.register_validator(OWNER, candidate, &dummy_pubkey(0xB3))
                .unwrap();
            vs.activate_reshared_set(&[active], B256::with_last_byte(0x01))
                .unwrap();
            // Seed the COEN/0xUSD oracle pair + a 1.0 rate so begin-block NOD/GEM/INTEX
            // floor-price promotion reads a registered pair instead of reverting
            // "pair not registered".
            let mut oracle = outbe_oracle::contract::OracleContract::new(storage.clone());
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
            seed_extra(storage);
        });

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
            expected_begin_system_txs: Vec::new(),
            expected_end_system_txs: Vec::new(),
            system_layout_error: None,
            parent_consensus_metadata: None,
            proposer_evm_address: None,
            execute_outbe_block_hooks: true,
            prebuilt_phase1_tx: None,
            parent_artifact_hint: None,
            pending_tee_bootstrap: None,
        }
    }

    fn begin_system_txs_for_test(
        config: &OutbeEvmConfig,
        block_number: u64,
        parent_hash: B256,
        extra_data: &Bytes,
        parent_consensus_metadata: Option<CertifiedParentAccountingMetadata>,
        proposer: Address,
    ) -> Vec<reth_primitives_traits::Recovered<reth_ethereum::TransactionSigned>> {
        begin_system_txs_for_test_with_bootstrap(
            config,
            block_number,
            parent_hash,
            extra_data,
            parent_consensus_metadata,
            proposer,
            None,
        )
    }

    fn begin_system_txs_for_test_with_bootstrap(
        config: &OutbeEvmConfig,
        block_number: u64,
        parent_hash: B256,
        extra_data: &Bytes,
        parent_consensus_metadata: Option<CertifiedParentAccountingMetadata>,
        proposer: Address,
        pending_tee_bootstrap: Option<outbe_primitives::tee_bootstrap::TeeBootstrapPayload>,
    ) -> Vec<reth_primitives_traits::Recovered<reth_ethereum::TransactionSigned>> {
        config
            .build_begin_system_txs(
                block_number,
                MAINNET.chain().id(),
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
    ) -> outbe_primitives::tee_bootstrap::TeeBootstrapPayload {
        outbe_primitives::tee_bootstrap::TeeBootstrapPayload {
            policy_hash: B256::ZERO,
            committee_snapshot_hash: B256::ZERO,
            committee_snapshot_block: block_number,
            key_epoch: 0,
            tribute_offer_epoch: 0,
            dkg_transcript_hash: B256::ZERO,
            tribute_offer_public_key: B256::ZERO,
            tribute_offer_group_public_key: alloy_primitives::Bytes::new(),
            registrations: Vec::new(),
            policy: outbe_primitives::tee_bootstrap::TeePolicy::default(),
            validator_signatures: Vec::new(),
        }
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

        // Block 1, empty extra_data: begin-zone is CycleTick + OracleSlashWindow.
        // A pending bootstrap is injected between them (begin_order 3, before the
        // OracleSlashWindow at begin_order 4).
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
                SystemTxKind::TeeBootstrap,
                SystemTxKind::OracleSlashWindow,
            ],
            "proposer must inject TeeBootstrap before OracleSlashWindow",
        );

        // Without a pending payload, the begin-zone is unchanged.
        let without_bootstrap =
            begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer);
        assert_eq!(
            begin_system_tx_kinds(&without_bootstrap),
            vec![SystemTxKind::CycleTick, SystemTxKind::OracleSlashWindow],
            "no bootstrap is injected when no payload is pending",
        );

        // Block 0 (genesis) has no begin-zone txs even with a pending bootstrap;
        // the executor's `begin_block_system_tx_inputs` mirrors this guard so the
        // two deterministic paths agree at genesis.
        let block_zero = begin_system_txs_for_test_with_bootstrap(
            &config,
            0,
            B256::ZERO,
            &Bytes::new(),
            None,
            proposer,
            Some(sample_tee_bootstrap_payload(0)),
        );
        assert!(
            block_zero.is_empty(),
            "block 0 must carry no begin-zone system txs",
        );
    }

    #[allow(dead_code)] // retained for follow-up tests
    fn test_regular_tx() -> reth_ethereum::TransactionSigned {
        TxEip1559 {
            chain_id: CHAIN_ID,
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: 1_000_000_000,
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
            max_fee_per_gas: 1_000_000_000,
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
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
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
            max_fee_per_gas: 1_000_000_000,
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
                base: "COEN".to_string(),
                quote: "0xUSD".to_string(),
                exchangeRate: U256::from(1_000_000_000_000_000_000u128),
                volume: U256::from(10_000_000_000_000_000_000_000u128),
            }],
        }
        .abi_encode();

        TxEip1559 {
            chain_id: CHAIN_ID,
            nonce: 0,
            gas_limit,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(ORACLE_ADDRESS),
            value: U256::ZERO,
            input: input.into(),
            access_list: Default::default(),
        }
        .into_signed(Signature::test_signature())
        .into()
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
                balance: U256::from(1_000_000_000_000_000_000u128),
                ..Default::default()
            },
        );

        let mut state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();
        let evm_env = EvmEnv {
            cfg_env: CfgEnv::new()
                .with_chain_id(MAINNET.chain().id())
                .with_spec_and_mainnet_gas_params(SpecId::SHANGHAI),
            block_env: BlockEnv {
                number: U256::from(1u64),
                gas_limit: 30_000_000,
                basefee: 1_000_000_000,
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
            1_000_000_000,
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
                balance: U256::from(1_000_000_000_000_000_000u128),
                ..Default::default()
            },
        );

        let mut state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();
        let evm_env = EvmEnv {
            cfg_env: CfgEnv::new()
                .with_chain_id(MAINNET.chain().id())
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
                balance: U256::from(1_000_000_000_000_000_000u128),
                ..Default::default()
            },
        );

        let mut state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();
        let evm_env = EvmEnv {
            cfg_env: CfgEnv::new()
                .with_chain_id(MAINNET.chain().id())
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
    fn pending_rpc_context_skips_outbe_hooks_without_proposer_or_parent_cert() {
        let mut state = State::builder()
            .with_database(CacheDB::<EmptyDBTyped<ProviderError>>::default())
            .with_bundle_update()
            .build();
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
        let ctx = execution_ctx(Some(0), Bytes::new());
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
        );

        executor
            .apply_pre_execution_changes()
            .expect("block 1 pre-execution changes should apply");
        let system_txs =
            begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer);
        let mut visible_system_gas_used = 0u64;
        for tx in system_txs.clone() {
            let visible_gas = tx.tx().gas_limit();
            let gas_used = executor
                .execute_transaction(tx)
                .expect("begin-zone system tx should execute in tx loop");
            assert_eq!(
                gas_used.tx_gas_used(),
                visible_gas,
                "system tx must return Ethereum-visible envelope gas"
            );
            visible_system_gas_used += visible_gas;
            assert_eq!(
                executor
                    .receipts()
                    .last()
                    .expect("system tx receipt must be present")
                    .cumulative_gas_used,
                visible_system_gas_used
            );
        }

        assert_eq!(executor.receipts().len(), 2);
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
            executor.receipts()[0].cumulative_gas_used,
            system_txs[0].tx().gas_limit()
        );
        assert_eq!(
            executor.receipts()[1].cumulative_gas_used,
            visible_system_gas_used
        );

        assert_eq!(system_txs.len(), 2);
        assert_eq!(Address::from(*system_txs[0].signer()), proposer);
        assert_eq!(system_txs[0].tx().chain_id(), Some(MAINNET.chain().id()));
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
            SystemTxInputV2::OracleSlashWindow
        ));
        drop(executor);

        let read_ctx = BlockContext::new(
            1,
            1,
            outbe_primitives::chain::CHAIN_ID,
            proposer,
            vec![proposer],
        );
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
        let ctx = execution_ctx(Some(3), Bytes::new());
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
        );

        executor
            .apply_pre_execution_changes()
            .expect("block 1 pre-execution changes should apply");
        let mut visible_system_gas = 0u64;
        for tx in begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer) {
            visible_system_gas += tx.tx().gas_limit();
            executor
                .execute_transaction(tx)
                .expect("begin-zone system tx should execute");
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

        let (_evm, block_result) = executor.finish().expect("executor finish should succeed");
        assert_eq!(
            block_result.gas_used,
            visible_system_gas + user_gas.tx_gas_used(),
            "block header gas_used must include visible system envelope gas"
        );
    }

    #[test]
    fn apply_pre_execution_changes_emits_cycle_tick_event_in_system_receipt() {
        const GENESIS_TS: u64 = 1_704_067_200;
        const SECONDS_PER_DAY: u64 = 86_400;

        let signer = test_evm_signer();
        let proposer = signer.address();
        let emission_trigger = outbe_cycle::triggers::TriggerId::EmissionLimit1.as_u32();
        let mut state =
            state_with_active_validators_seeded(&[(proposer, dummy_pubkey(0xA2))], |storage| {
                let genesis_ctx = BlockRuntimeContext::new(
                    BlockContext::new(0, GENESIS_TS, CHAIN_ID, proposer, vec![proposer]),
                    storage.clone(),
                );
                outbe_rewards::runtime::ensure_genesis_anchor(&genesis_ctx).unwrap();
                let cycle = outbe_cycle::schema::Cycle::new(storage);
                cycle
                    .last_executed_at
                    .write(&emission_trigger, GENESIS_TS + 60)
                    .unwrap();
            });
        let mut evm_env = test_evm_env(1, REWARDS_ADDRESS);
        evm_env.block_env.timestamp = U256::from(GENESIS_TS + SECONDS_PER_DAY + 60);
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, evm_env);
        let mut executor = config.create_executor(evm, execution_ctx(Some(0), Bytes::new()));

        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply before begin-zone system txs");
        let system_txs =
            begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer);
        for tx in system_txs {
            executor
                .execute_transaction(tx)
                .expect("begin-zone system tx should execute in tx loop");
        }

        assert_eq!(executor.receipts().len(), 2);
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
        let emission_trigger = outbe_cycle::triggers::TriggerId::EmissionLimit1.as_u32();
        let mut state =
            state_with_active_validators_seeded(&[(proposer, dummy_pubkey(0xA2))], |storage| {
                let genesis_ctx = BlockRuntimeContext::new(
                    BlockContext::new(0, GENESIS_TS, CHAIN_ID, proposer, vec![proposer]),
                    storage.clone(),
                );
                outbe_rewards::runtime::ensure_genesis_anchor(&genesis_ctx).unwrap();
                let cycle = outbe_cycle::schema::Cycle::new(storage);
                cycle
                    .last_executed_at
                    .write(&emission_trigger, GENESIS_TS + 60)
                    .unwrap();
            });
        let mut evm_env = test_evm_env(1, REWARDS_ADDRESS);
        evm_env.block_env.timestamp = U256::from(GENESIS_TS + SECONDS_PER_DAY + 60);
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, evm_env);
        let mut executor = config.create_executor(evm, execution_ctx(Some(0), Bytes::new()));

        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply");
        let system_txs =
            begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer);
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
    fn gas_05_cycle_tick_gas_regression_exercises_dense_agentreward_state() {
        const GENESIS_TS: u64 = 1_704_067_200;
        const SECONDS_PER_DAY: u64 = 86_400;
        const DENSE_ADDRESS_COUNT: u64 = 512;

        let signer = test_evm_signer();
        let proposer = signer.address();
        let block_ts = GENESIS_TS + SECONDS_PER_DAY + 60;
        let prev_day = outbe_primitives::time::previous_date_key(
            outbe_primitives::time::timestamp_to_date_key(block_ts),
        );
        let emission_trigger = outbe_cycle::triggers::TriggerId::EmissionLimit1.as_u32();
        let mut state =
            state_with_active_validators_seeded(&[(proposer, dummy_pubkey(0xA2))], |storage| {
                let genesis_ctx = BlockRuntimeContext::new(
                    BlockContext::new(0, GENESIS_TS, CHAIN_ID, proposer, vec![proposer]),
                    storage.clone(),
                );
                outbe_rewards::runtime::ensure_genesis_anchor(&genesis_ctx).unwrap();
                let cycle = outbe_cycle::schema::Cycle::new(storage.clone());
                cycle
                    .last_executed_at
                    .write(&emission_trigger, GENESIS_TS + 60)
                    .unwrap();

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
        let mut executor = config.create_executor(evm, execution_ctx(Some(0), Bytes::new()));

        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply");
        let system_txs =
            begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer);
        let cycle_tx = system_txs
            .into_iter()
            .next()
            .expect("CycleTick system tx should be first");
        let cycle_visible_gas = cycle_tx.tx().gas_limit();
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
            cycle_receipt.cumulative_gas_used, cycle_visible_gas,
            "GAS-05: dense CycleTick receipt must expose only visible envelope gas"
        );
        assert_eq!(cycle_gas, cycle_visible_gas);
        assert!(
            cycle_visible_gas < 30_000_000,
            "GAS-05: dense CycleTick visible gas exceeded block gas limit: {cycle_visible_gas}"
        );

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
            Ok::<_, outbe_primitives::error::PrecompileError>(())
        })
        .expect("GAS-05 dense AgentReward state should be readable after CycleTick");
    }

    #[test]
    fn gas_01_evm_level_system_tx_err_must_not_be_soft_receipted() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let mut state = state_with_active_proposer(proposer);
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, test_evm_env(1, REWARDS_ADDRESS));
        let mut executor = config.create_executor(evm, execution_ctx(Some(1), Bytes::new()));
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
    fn gas_09_noncritical_system_oog_failure_is_soft_and_keeps_user_gas_lane_clean() {
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
        let ctx = execution_ctx(Some(3), Bytes::new());
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
        );

        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply");
        let mut system_txs =
            begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer)
                .into_iter();
        let cycle_tx = system_txs
            .next()
            .expect("CycleTick system tx should be present");
        let oracle_tx = system_txs
            .next()
            .expect("OracleSlashWindow system tx should be present");
        let cycle_visible_gas = cycle_tx.tx().gas_limit();
        let oracle_visible_gas = oracle_tx.tx().gas_limit();

        // CycleTick is consensus-critical (a revert/OOG there fails the
        // block), so the soft-receipt path is exercised against
        // OracleSlashWindow, a non-critical begin-zone phase whose OOG still
        // soft-fails and keeps the user gas lane clean. CycleTick executes
        // successfully first (receipt 0).
        let cycle_gas = executor
            .execute_transaction(cycle_tx)
            .expect("CycleTick should execute successfully")
            .tx_gas_used();
        assert_eq!(cycle_gas, cycle_visible_gas);

        let failure_gas = crate::factory::with_forced_outbe_system_call_oog_halt(|| {
            executor.execute_transaction(oracle_tx)
        })
        .expect("forced non-critical system OOG must become a soft-failure receipt")
        .tx_gas_used();
        assert_eq!(
            failure_gas, oracle_visible_gas,
            "GAS-09: soft-failed OOG system tx should return visible envelope gas"
        );

        let failure_receipt = executor
            .receipts()
            .get(1)
            .expect("soft-failed oracle tx must emit a receipt");
        assert!(!failure_receipt.success);
        assert_eq!(
            failure_receipt.cumulative_gas_used,
            cycle_visible_gas + oracle_visible_gas
        );
        assert_eq!(failure_receipt.logs.len(), 1);
        assert_eq!(failure_receipt.logs[0].address, OUTBE_SYSTEM_TX_ADDRESS);
        assert_eq!(
            failure_receipt.logs[0].data.topics().first(),
            Some(&crate::failure_receipt::OUTBE_FAILURE_TOPIC0),
            "GAS-09: system OOG soft-failure receipt must carry OutbeFailure"
        );
        let mut expected_code_topic = [0u8; 32];
        expected_code_topic[31] = 202;
        assert_eq!(
            failure_receipt.logs[0].data.topics()[1].as_slice(),
            expected_code_topic,
            "GAS-09: system OOG soft-failure receipt must use OutbeFailure code 202"
        );

        let user_gas = executor
            .execute_transaction(user_tx)
            .expect("user tx must execute after OOG soft failure")
            .tx_gas_used();
        let expected_system_visible_gas = cycle_visible_gas + oracle_visible_gas;
        assert_eq!(
            executor.inner.cumulative_tx_gas_used,
            expected_system_visible_gas + user_gas,
            "GAS-09: OOG soft failure must charge only visible system envelope gas"
        );

        let final_extra_data = encode_outbe_block_artifacts(&OutbeBlockArtifacts {
            execution_summary: Some(executor.current_execution_summary()),
            consensus_header_artifact: None,
            timestamp_millis_part: 0,
            late_finalize_credits: None,
        })
        .expect("final extra_data should encode");
        executor.set_final_extra_data(final_extra_data);
        let (_evm, result) = executor.finish().expect("finish should succeed");
        assert_eq!(
            result.gas_used,
            expected_system_visible_gas + user_gas,
            "GAS-09: block/header gas must include only visible system envelope gas plus user gas"
        );
        assert_eq!(result.receipts.len(), 3);
        assert_eq!(result.receipts[0].cumulative_gas_used, cycle_visible_gas);
        assert_eq!(
            result.receipts[1].cumulative_gas_used,
            expected_system_visible_gas
        );
        assert_eq!(
            result.receipts[2].cumulative_gas_used,
            expected_system_visible_gas + user_gas
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
        let user_tx = test_regular_tx()
            .try_into_recovered()
            .expect("regular tx signer should recover");
        let mut state = state_with_active_proposer_and_funded_account(proposer, user_tx.signer());
        let chain_spec = test_chain_spec();
        let receipt_builder = reth_ethereum::evm::RethReceiptBuilder::default();
        let config = OutbeEvmConfig::new(chain_spec.clone()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, test_evm_env(1, REWARDS_ADDRESS));
        let ctx = execution_ctx(Some(1), Bytes::new());
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
        );

        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply");
        let mut system_txs =
            begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer)
                .into_iter();
        let cycle_tx = system_txs
            .next()
            .expect("CycleTick system tx should be present");
        let oracle_tx = system_txs
            .next()
            .expect("OracleSlashWindow system tx should be present");
        let cycle_visible_gas = cycle_tx.tx().gas_limit();
        let oracle_visible_gas = oracle_tx.tx().gas_limit();

        // CycleTick is consensus-critical (a revert there fails the block),
        // so the soft-receipt path is exercised against OracleSlashWindow, a
        // non-critical begin-zone phase. CycleTick executes successfully first.
        executor
            .execute_transaction(cycle_tx)
            .expect("CycleTick should execute successfully");

        let revert_gas = crate::factory::with_forced_outbe_system_call_revert(|| {
            executor.execute_transaction(oracle_tx)
        })
        .expect("EVM-level non-critical system tx revert should soft-fail")
        .tx_gas_used();
        assert_eq!(
            revert_gas, oracle_visible_gas,
            "GAS-11: reverted system tx should charge visible envelope gas"
        );
        let failure_receipt = executor
            .receipts()
            .get(1)
            .expect("reverted system tx must emit a failure receipt");
        assert!(!failure_receipt.success);
        assert_eq!(
            failure_receipt.cumulative_gas_used,
            cycle_visible_gas + oracle_visible_gas
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

        let user_gas = executor
            .execute_transaction(user_tx)
            .expect("user txs must execute after a soft-failed non-critical begin-zone system tx")
            .tx_gas_used();
        assert_eq!(
            executor.inner.cumulative_tx_gas_used,
            cycle_visible_gas + oracle_visible_gas + user_gas,
            "GAS-11: soft-failed system tx must charge only visible envelope gas"
        );
    }

    /// A revert in a consensus-critical begin-zone phase (here
    /// CycleTick) is a hard block failure, not a soft-receipt skip — its one-shot
    /// work (a day's emission / terminal Metadosis) must never be silently
    /// dropped. No receipt is pushed; the block aborts.
    #[test]
    fn critical_cycle_tick_revert_fails_block() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let mut state = state_with_active_proposer(proposer);
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, test_evm_env(1, REWARDS_ADDRESS));
        let mut executor = config.create_executor(evm, execution_ctx(Some(1), Bytes::new()));
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

    /// An OOG halt in a consensus-critical begin-zone phase also
    /// fails the block (not a soft skip), via the same `revert_fails_block` gate.
    #[test]
    fn critical_cycle_tick_oog_fails_block() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let mut state = state_with_active_proposer(proposer);
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, test_evm_env(1, REWARDS_ADDRESS));
        let mut executor = config.create_executor(evm, execution_ctx(Some(1), Bytes::new()));
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
    /// ones with a tx-level `InvalidTx` — the variant the payload builder SKIPS
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
        let ctx = execution_ctx(Some(3), Bytes::new());
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
        );

        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply");
        let mut expected_rpc_gas_deltas = Vec::new();
        for tx in begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer) {
            expected_rpc_gas_deltas.push(tx.tx().gas_limit());
            executor
                .execute_transaction(tx)
                .expect("system tx should execute");
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
    fn gas_14_executor_finish_sets_visible_system_gas_for_fee_history_input() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let mut state = state_with_active_proposer(proposer);
        let chain_spec = test_chain_spec();
        let receipt_builder = reth_ethereum::evm::RethReceiptBuilder::default();
        let config = OutbeEvmConfig::new(chain_spec.clone()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, test_evm_env(1, REWARDS_ADDRESS));
        let ctx = execution_ctx(Some(2), Bytes::new());
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
        );

        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply");
        let system_txs =
            begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer);
        let mut visible_system_gas = 0u64;
        let mut expected_system_deltas = Vec::with_capacity(system_txs.len());
        for tx in system_txs {
            let visible_gas = tx.tx().gas_limit();
            expected_system_deltas.push(visible_gas);
            visible_system_gas += visible_gas;
            executor
                .execute_transaction(tx)
                .expect("system tx should execute");
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

        let final_extra_data = encode_outbe_block_artifacts(&OutbeBlockArtifacts {
            execution_summary: Some(executor.current_execution_summary()),
            consensus_header_artifact: None,
            timestamp_millis_part: 0,
            late_finalize_credits: None,
        })
        .expect("final extra_data should encode");
        executor.set_final_extra_data(final_extra_data);
        let (_evm, result) = executor.finish().expect("finish should succeed");
        assert_eq!(
            result.gas_used, visible_system_gas,
            "GAS-14: system-only block gas_used must expose visible system envelope gas"
        );
        assert_eq!(result.receipts.len(), expected_system_deltas.len());

        let gas_limit = 30_000_000u64;
        let gas_used_ratio = result.gas_used as f64 / gas_limit as f64;
        assert!(
            gas_used_ratio > 0.0 && gas_used_ratio < 0.01,
            "GAS-14: fee-history input ratio must expose small visible system gas, got {gas_used_ratio}"
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
        let ctx = execution_ctx(Some(3), Bytes::new());
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
        );

        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply");
        let mut visible_system_gas = 0u64;
        for tx in begin_system_txs_for_test(&config, 1, B256::ZERO, &Bytes::new(), None, proposer) {
            visible_system_gas += tx.tx().gas_limit();
            executor
                .execute_transaction(tx)
                .expect("system tx should execute");
        }
        let user_gas = executor
            .execute_transaction(user_tx)
            .expect("funded regular user tx should execute")
            .tx_gas_used();

        let final_extra_data = encode_outbe_block_artifacts(&OutbeBlockArtifacts {
            execution_summary: Some(executor.current_execution_summary()),
            consensus_header_artifact: None,
            timestamp_millis_part: 0,
            late_finalize_credits: None,
        })
        .expect("final extra_data should encode");
        executor.set_final_extra_data(final_extra_data);
        let (_evm, result) = executor.finish().expect("finish should succeed");
        assert_eq!(result.gas_used, visible_system_gas + user_gas);
        assert_eq!(result.receipts.len(), 3);
        let first_visible_gas = result.receipts[0].cumulative_gas_used;
        assert!(first_visible_gas >= outbe_primitives::system_tx::SYSTEM_TX_VISIBLE_GAS_FLOOR);
        assert_eq!(result.receipts[1].cumulative_gas_used, visible_system_gas);
        assert_eq!(
            result.receipts[2].cumulative_gas_used,
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
        bridge.record_execution_summary(
            1,
            parent_hash,
            ExecutionSummaryArtifact {
                validator_fee_sum: U256::ZERO,
            },
            1,
        );
        let config = OutbeEvmConfig::new_with_bridge(test_chain_spec(), bridge)
            .with_evm_signer(signer.clone());
        let evm_env = test_evm_env(2, REWARDS_ADDRESS);
        let evm = config.evm_with_env(&mut state, evm_env);
        let mut ctx = execution_ctx(Some(0), Bytes::new());
        ctx.inner.parent_hash = parent_hash;
        ctx.parent_consensus_metadata = Some(metadata.clone());
        let mut executor = config.create_executor(evm, ctx);

        // opt out of Phase 1 `verify_v2_proof` preflight — this
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

        // CPA(0) + LateFinalizeCredits(1) + CycleTick(2) + OracleSlashWindow(3).
        assert_eq!(executor.receipts().len(), 4);
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
            "Phase 1 (CPA) must no longer emit voter slashing — it is relocated to window close"
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
    /// `header.extra_data` is FATAL in **pre-exec** — the block is rejected
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
        // whose committee snapshot was never written → verify cannot resolve it.
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

        // Phase 1 disabled; late-finalize verify stays ENABLED → the
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
    /// voter at `k=1`) is actually **paid** — and the resulting fee-share
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
        // path reads — otherwise the late-finalize BLS check fails on a namespace
        // mismatch (`b"outbe" || 0` at sign time vs `b"outbe" || CHAIN_ID` at
        // verify time). CHAIN_ID matches `test_chain_spec()` (MAINNET id 1).
        outbe_consensus::proof::init_consensus_chain_id(CHAIN_ID);

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
        // signers 0..2. The credit targets the finalized parent (`parent_hash`) —
        // the very block the block-(N+K) CPA escrows — so its canonical binding
        // (number→{fb_hash, epoch, committee_set_hash}) is written by
        // `on_finalized_metadata` and the credit authenticates against it.
        // The CPA metadata carries no base voters, so only the late credit's
        // signers are recorded. This exercises the *recording* path's parity.
        let (fb_number, view, parent_view) = (settle_block - 1, 9u64, 8u64);
        let parent_hash = B256::with_last_byte(0xAA);
        let fb_hash = parent_hash;

        // Pre-seeded MATURED escrow for block N = settle_block - K with a non-zero
        // fee and one credited voter at k=1. `settle_matured(settle_block, K)`
        // settles this block, so the begin-zone actually PAYS — proving the
        // fee-share balance delta is identical on both paths. A
        // distinct fb_hash and a dedicated voter address keep this concern isolated
        // from the live recording credit above.
        let settle_target = settle_block - window_k; // = 1
        let settle_fb_hash = B256::with_last_byte(0x11);
        let settle_voter = Address::with_last_byte(0x77);
        let settle_committee = 4u64;
        let settle_fee = U256::from(4_000u64);
        // payout_i = fee · w(1) / (committee · w_max) = 4000 · 100 / 400 = 1000.
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
            // adding no balance effect — only the parity-checked miss counters.
            let mut seeded: Vec<(Address, [u8; 48])> = vec![(proposer, dummy_pubkey(0xA2))];
            for (i, a) in addrs.iter().enumerate() {
                seeded.push((*a, dummy_pubkey(0x50u8 + i as u8)));
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
            bridge.record_execution_summary(
                fb_number,
                parent_hash,
                ExecutionSummaryArtifact {
                    validator_fee_sum: U256::ZERO,
                },
                1,
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
                    // and not in the live in-window credit → a pure window-close
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
            "settled k=1 voter must receive fee · w(1) / D"
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
        let old_active = address!("0x1010101010101010101010101010101010101010");
        let mut state = state_with_active_and_registered_candidate(old_active, proposer);
        let evm_env = test_evm_env(1, REWARDS_ADDRESS);
        let boundary = boundary_with(true, vec![(proposer, dummy_pubkey(0xB3))]);
        let extra_data = encode_outbe_block_artifacts(&OutbeBlockArtifacts {
            execution_summary: None,
            consensus_header_artifact: Some(ConsensusHeaderArtifact::BoundaryOutcome(boundary)),
            timestamp_millis_part: 0,
            late_finalize_credits: None,
        })
        .expect("extra_data encodes");
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, evm_env);
        let mut executor = config.create_executor(evm, execution_ctx(Some(0), extra_data.clone()));

        executor
            .apply_pre_execution_changes()
            .expect("activation block pre-execution should apply");
        let system_txs =
            begin_system_txs_for_test(&config, 1, B256::ZERO, &extra_data, None, proposer);
        for tx in system_txs {
            executor
                .execute_transaction(tx)
                .expect("activation block begin-zone system tx should execute");
        }

        assert_eq!(executor.receipts().len(), 3);
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
        bridge.record_execution_summary(
            1,
            parent_hash,
            ExecutionSummaryArtifact {
                validator_fee_sum: U256::ZERO,
            },
            1,
        );
        let boundary = boundary_with(
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
            let visible_gas = tx.tx().gas_limit();
            let gas_output = executor
                .execute_transaction(tx)
                .expect("Phase 1+2+3+OracleSlashWindow begin-zone system tx should execute");
            assert_eq!(gas_output.tx_gas_used(), visible_gas);
            visible_system_gas_used += visible_gas;
            assert_eq!(
                executor
                    .receipts()
                    .last()
                    .expect("system receipt should be present")
                    .cumulative_gas_used,
                visible_system_gas_used
            );
        }
        // CPA + LateFinalizeCredits + CycleTick + BoundaryOutcome + OracleSlashWindow.
        assert_eq!(executor.receipts().len(), 5);
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

        // 5 begin-zone receipts + 1 user (deactivate) tx.
        assert_eq!(executor.receipts().len(), 6);
        assert!(executor.receipts()[5].success);
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
    fn oracle_slash_window_runs_after_boundary_activation() {
        let signer = test_evm_signer();
        let proposer = signer.address();
        let old_active = address!("0x1010101010101010101010101010101010101010");
        let mut state =
            state_with_active_and_registered_candidate_seeded(old_active, proposer, |storage| {
                let oracle = outbe_oracle::contract::OracleContract::new(storage.clone());
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
                let vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
                vs.val_stake.write(&old_active, stake).unwrap();
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
        let extra_data = encode_outbe_block_artifacts(&OutbeBlockArtifacts {
            execution_summary: None,
            consensus_header_artifact: Some(ConsensusHeaderArtifact::BoundaryOutcome(boundary)),
            timestamp_millis_part: 0,
            late_finalize_credits: None,
        })
        .expect("extra_data encodes");
        let config = OutbeEvmConfig::new(test_chain_spec()).with_evm_signer(signer.clone());
        let evm = config.evm_with_env(&mut state, evm_env);
        let mut executor = config.create_executor(evm, execution_ctx(Some(0), extra_data.clone()));

        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes should apply before Oracle slash system tx");
        let system_txs =
            begin_system_txs_for_test(&config, 1, B256::ZERO, &extra_data, None, proposer);
        let mut visible_system_gas_used = 0u64;
        for tx in system_txs {
            let visible_gas = tx.tx().gas_limit();
            let gas_output = executor
                .execute_transaction(tx)
                .expect("Oracle slash must not invalidate same-block BoundaryOutcome activation");
            assert_eq!(gas_output.tx_gas_used(), visible_gas);
            visible_system_gas_used += visible_gas;
            assert_eq!(
                executor
                    .receipts()
                    .last()
                    .expect("system receipt should be present")
                    .cumulative_gas_used,
                visible_system_gas_used
            );
        }

        assert_eq!(executor.receipts().len(), 3);
        assert!(executor.receipts().iter().all(|receipt| receipt.success));
        let oracle_forced_exit = keccak256("ValidatorForcedExit(address)");
        assert!(
            executor.receipts()[2].logs.iter().any(|log| {
                log.address == ORACLE_ADDRESS
                    && log.data.topics().first() == Some(&oracle_forced_exit)
            }),
            "Oracle slash-window force exit must be receipt-visible"
        );
        let oracle_slashed = keccak256("ValidatorSlashed(address,uint64)");
        assert!(
            executor.receipts()[2].logs.iter().any(|log| {
                log.address == ORACLE_ADDRESS && log.data.topics().first() == Some(&oracle_slashed)
            }),
            "Oracle slash-window stake slash must be receipt-visible"
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
            MAINNET.chain().id(),
            SystemTxInputV2::CertifiedParentAccounting { metadata }
                .encode()
                .unwrap(),
        )
        .unwrap();
        let cycle_unsigned = build_unsigned_system_tx(
            SystemTxKind::CycleTick,
            1,
            2,
            MAINNET.chain().id(),
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
        // (Phase 1 verifier preflight) rather than during the main tx loop —
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
        let config = OutbeEvmConfig::new(test_chain_spec());
        let evm = config.evm_with_env(&mut state, evm_env);

        let wrong_unsigned = build_unsigned_system_tx(
            SystemTxKind::CycleTick,
            0,
            2,
            outbe_primitives::chain::CHAIN_ID,
            SystemTxInputV2::CycleTick.encode().unwrap(),
        )
        .unwrap();
        let oracle_unsigned = build_unsigned_system_tx(
            SystemTxKind::OracleSlashWindow,
            1,
            1,
            MAINNET.chain().id(),
            SystemTxInputV2::OracleSlashWindow.encode().unwrap(),
        )
        .unwrap();
        let wrong_signed = signer.sign_unsigned(wrong_unsigned).unwrap();
        let oracle_signed = signer.sign_unsigned(oracle_unsigned).unwrap();
        let wrong_recovered =
            reth_primitives_traits::Recovered::new_unchecked(wrong_signed, proposer);
        let oracle_recovered =
            reth_primitives_traits::Recovered::new_unchecked(oracle_signed, proposer);
        let mut ctx = execution_ctx(Some(1), Bytes::new());
        ctx.expected_begin_system_txs = vec![wrong_recovered.clone(), oracle_recovered];

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
        })
        .expect("extra_data encodes");

        let cycle_unsigned = build_unsigned_system_tx(
            SystemTxKind::CycleTick,
            0,
            1,
            MAINNET.chain().id(),
            SystemTxInputV2::CycleTick.encode().unwrap(),
        )
        .unwrap();
        let boundary_unsigned = build_unsigned_system_tx(
            SystemTxKind::BoundaryOutcome,
            1,
            1,
            MAINNET.chain().id(),
            SystemTxInputV2::BoundaryOutcome {
                artifact: tx_artifact,
            }
            .encode()
            .unwrap(),
        )
        .unwrap();
        let cycle_signed = signer.sign_unsigned(cycle_unsigned).unwrap();
        let boundary_signed = signer.sign_unsigned(boundary_unsigned).unwrap();
        let cycle_recovered =
            reth_primitives_traits::Recovered::new_unchecked(cycle_signed, proposer);
        let boundary_recovered =
            reth_primitives_traits::Recovered::new_unchecked(boundary_signed, proposer);
        let mut ctx = execution_ctx(Some(2), extra_data);
        ctx.expected_begin_system_txs = vec![cycle_recovered.clone(), boundary_recovered.clone()];
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
        let config = OutbeEvmConfig::new(test_chain_spec());
        let evm = config.evm_with_env(&mut state, evm_env);

        let unsigned = build_unsigned_system_tx(
            SystemTxKind::CycleTick,
            0,
            1,
            MAINNET.chain().id(),
            SystemTxInputV2::CycleTick.encode().unwrap(),
        )
        .unwrap();
        let oracle_unsigned = build_unsigned_system_tx(
            SystemTxKind::OracleSlashWindow,
            1,
            1,
            MAINNET.chain().id(),
            SystemTxInputV2::OracleSlashWindow.encode().unwrap(),
        )
        .unwrap();
        let wrong_signed = wrong_signer.sign_unsigned(unsigned).unwrap();
        let oracle_signed = proposer_signer.sign_unsigned(oracle_unsigned).unwrap();
        let wrong_recovered =
            reth_primitives_traits::Recovered::new_unchecked(wrong_signed, wrong_signer.address());
        let oracle_recovered =
            reth_primitives_traits::Recovered::new_unchecked(oracle_signed, proposer);
        let mut ctx = execution_ctx(Some(1), Bytes::new());
        ctx.expected_begin_system_txs = vec![wrong_recovered.clone(), oracle_recovered];
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

            let oracle = outbe_oracle::contract::OracleContract::new(storage.clone());
            oracle.feeder_delegation.write(&validator, feeder)?;
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

            let oracle = outbe_oracle::contract::OracleContract::new(storage.clone());
            assert_eq!(oracle.resolve_validator_for_feeder(feeder)?, validator);
            Ok::<_, outbe_primitives::error::PrecompileError>(())
        })
        .expect("seeded zero-fee authorization state should be readable");

        {
            let evm_env = EvmEnv {
                cfg_env: CfgEnv::new()
                    .with_chain_id(MAINNET.chain().id())
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
            outbe_oracle::contract::OracleContract::new(storage.clone())
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
            // hit `authorize_fee_waiver` → `UnauthorizedSigner` (code 107).
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
                    .with_chain_id(MAINNET.chain().id())
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
        // OutbeFailure topic0 — anything else is a parity drift.
        assert_eq!(
            receipts_a[0].logs[0].address,
            outbe_primitives::addresses::ZERO_FEE_POLICY_LOG_ADDRESS
        );
        assert_eq!(
            receipts_a[0].logs[0].data.topics()[0],
            crate::failure_receipt::OUTBE_FAILURE_TOPIC0
        );
        // Code 107 (UnauthorizedSigner) — padded to 32 bytes BE.
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
                    .with_chain_id(MAINNET.chain().id())
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
            // call `current_execution_summary` — the method is private to
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
    /// `on_new_head_block` → `pool.remove_transactions(block_hashes)` path.
    ///
    /// This is the contract that lets (T4 Won't Do) skip any custom
    /// `mark_invalid` plumbing — confirmation that the executor's `Ok` return
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
                .with_chain_id(MAINNET.chain().id())
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

        // Soft-fail path returns `Ok` — the contract that lets the wrapping
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
    fn begin_block_hook_batch_error_rolls_back_prior_hook_writes() {
        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        let mut state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();
        let ctx = BlockContext::new(7, 84, CHAIN_ID, OWNER, Vec::new());
        let address = address!("0x1111111111111111111111111111111111111111");
        let slot = U256::from(0x46u64);
        let value = U256::from(0x193u64);

        let err = super::run_atomic_storage_hooks(&mut state, ctx, |hook_ctx| {
            hook_ctx.storage.sstore(address, slot, value)?;
            assert_eq!(hook_ctx.storage.sload(address, slot)?, value);
            Err(outbe_primitives::error::PrecompileError::Fatal(
                "oracle hook failed".into(),
            ))
        })
        .expect_err("late hook failure must abort the whole hook batch");

        assert!(err.to_string().contains("oracle hook failed"));
        assert_eq!(state.storage(address, slot).unwrap(), U256::ZERO);

        let ctx = BlockContext::new(8, 96, CHAIN_ID, OWNER, Vec::new());
        let (changes, events) = super::run_atomic_storage_hooks(&mut state, ctx, |hook_ctx| {
            hook_ctx.storage.sstore(address, slot, value)?;
            Ok(())
        })
        .expect("successful hook batch must flush state");

        let account = changes
            .get(&address)
            .expect("successful batch must report changed account");
        let changed_slot = account
            .storage
            .get(&slot)
            .expect("successful batch must report changed slot");
        assert_eq!(changed_slot.present_value(), value);
        assert!(events.is_empty());
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
                .with_chain_id(MAINNET.chain().id())
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
        })
        .expect("final extra_data must encode");

        executor.set_final_extra_data(final_extra_data);

        executor
            .finish()
            .expect("executor finish must validate against final extra_data");
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
                .with_chain_id(MAINNET.chain().id())
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

        let err = match executor.finish() {
            Ok(_) => panic!("stale pre-summary extra_data must not validate"),
            Err(err) => err,
        };

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
                .with_chain_id(MAINNET.chain().id())
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
        vs.config_max_validators.write(128).unwrap();
        vs.config_epoch_length_blocks.write(60).unwrap();
        vs.config_is_initialized.write(true).unwrap();
        vs.register_validator(OWNER, validator, pk).unwrap();
        vs.activate_reshared_set(&[validator], B256::ZERO).unwrap();
        // Seed COEN/0xUSD pair + 1.0 rate so begin-block NOD/GEM/INTEX promotion
        // reads a registered pair instead of reverting "pair not registered".
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

            let vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.val_stake.write(&validator, stake).unwrap();

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
    /// 4. THEN activate_reshared_set() → set changes to NEW set
    ///
    /// Verifies that get_active_consensus_set() returns the OLD set
    /// at step 2, and the NEW set only after step 4.
    #[test]
    fn test_reshare_activation_after_participation_decode() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.config_max_validators.write(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            // Register and activate validators A, B, C.
            let val_a = address!("0x1111111111111111111111111111111111111111");
            let val_b = address!("0x2222222222222222222222222222222222222222");
            let val_c = address!("0x3333333333333333333333333333333333333333");
            let val_d = address!("0x4444444444444444444444444444444444444444");

            vs.register_validator(OWNER, val_a, &dummy_pubkey(0xA1))
                .unwrap();
            vs.register_validator(OWNER, val_b, &dummy_pubkey(0xB2))
                .unwrap();
            vs.register_validator(OWNER, val_c, &dummy_pubkey(0xC3))
                .unwrap();
            vs.register_validator(OWNER, val_d, &dummy_pubkey(0xD4))
                .unwrap();

            // Initial reshare: activate A, B, C (not D).
            let old_hash = B256::with_last_byte(0x01);
            vs.activate_reshared_set(&[val_a, val_b, val_c], old_hash)
                .unwrap();

            // Step 1: Read old active set — should be [A, B, C].
            let old_set = vs.get_active_consensus_set().unwrap();
            let old_addrs: Vec<Address> = old_set.iter().map(|v| v.validator_address).collect();
            assert!(old_addrs.contains(&val_a));
            assert!(old_addrs.contains(&val_b));
            assert!(old_addrs.contains(&val_c));
            assert!(!old_addrs.contains(&val_d), "D should NOT be in old set");
            assert_eq!(old_addrs.len(), 3);

            // Step 2-3: Participation/slashing would happen here using old_addrs.
            // (We just verify the set is correct — actual slashing tested in Task 01 code.)

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

            // Activate D.
            vs.activate_validator(val_d).unwrap();
            // Reshare with new set.
            vs.activate_reshared_set(&[val_a, val_b, val_d], new_hash)
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
            vs.config_max_validators.write(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            let val_a = address!("0x1111111111111111111111111111111111111111");
            let val_b = address!("0x2222222222222222222222222222222222222222");
            let val_c = address!("0x3333333333333333333333333333333333333333");
            let val_d = address!("0x4444444444444444444444444444444444444444");

            vs.register_validator(OWNER, val_a, &dummy_pubkey(0xA1))
                .unwrap();
            vs.register_validator(OWNER, val_b, &dummy_pubkey(0xB2))
                .unwrap();
            vs.register_validator(OWNER, val_c, &dummy_pubkey(0xC3))
                .unwrap();
            vs.register_validator(OWNER, val_d, &dummy_pubkey(0xD4))
                .unwrap();

            // Old set: 3 validators [A, B, C].
            vs.activate_reshared_set(&[val_a, val_b, val_c], B256::with_last_byte(0x01))
                .unwrap();
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
            vs.activate_validator(val_d).unwrap();
            vs.activate_reshared_set(&[val_a, val_b, val_c, val_d], B256::with_last_byte(0x02))
                .unwrap();
            let new_set = vs.get_active_consensus_set().unwrap();
            assert_eq!(new_set.len(), 4, "new set must have 4 validators");

            // Decode participation against OLD set (3 validators) → should work.
            let decoded = outbe_primitives::participation::decode_participation_extended(
                &extra_data,
                &old_addrs,
            );
            assert!(decoded.is_some(), "decode against OLD set must succeed");

            // Decode against NEW set (4 validators) → count mismatch → returns None.
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
            vs.config_max_validators.write(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            let val_a = address!("0x1111111111111111111111111111111111111111");
            let val_b = address!("0x2222222222222222222222222222222222222222");

            vs.register_validator(OWNER, val_a, &dummy_pubkey(0xA1))
                .unwrap();
            vs.register_validator(OWNER, val_b, &dummy_pubkey(0xB2))
                .unwrap();

            let hash = B256::with_last_byte(0x42);
            vs.activate_reshared_set(&[val_a, val_b], hash).unwrap();

            // Read state after first activation.
            let set1 = vs.get_active_consensus_set().unwrap();
            let hash1 = vs.active_consensus_set_hash.read().unwrap();

            // Second call with same hash → idempotency guard in executor.rs
            // checks `current_hash != reshare.active_set_hash`.
            // Here: current_hash == hash → no-op.
            let current_hash = vs.active_consensus_set_hash.read().unwrap();
            assert_eq!(current_hash, hash, "hash must match after first activation");

            // Simulate executor's guard: skip if hash matches.
            if current_hash != hash {
                vs.activate_reshared_set(&[val_a, val_b], hash).unwrap();
            }
            // State unchanged.
            let set2 = vs.get_active_consensus_set().unwrap();
            let hash2 = vs.active_consensus_set_hash.read().unwrap();
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
            // `Vec<MissedProposerEvent>` (view defaults to 0 — V2 contract is
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
            vs.config_max_validators.write(128).unwrap();
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
                vs.register_validator(OWNER, addr, &dummy_pubkey(seed))
                    .unwrap();
            }
            // Live active set is [A, B, D]; C is registered but no longer a
            // current consensus participant after a reshare.
            vs.activate_reshared_set(&[val_a, val_b, val_d], B256::with_last_byte(0x02))
                .unwrap();
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
            vs.config_max_validators.write(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            let val_a = address!("0x1111111111111111111111111111111111111111");
            let val_b = address!("0x2222222222222222222222222222222222222222");
            vs.register_validator(OWNER, val_a, &dummy_pubkey(0xA1))
                .unwrap();
            vs.register_validator(OWNER, val_b, &dummy_pubkey(0xB2))
                .unwrap();
            vs.activate_reshared_set(&[val_a, val_b], B256::with_last_byte(0x01))
                .unwrap();

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
            vs.config_max_validators.write(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            let val_a = address!("0x1111111111111111111111111111111111111111");
            vs.register_validator(OWNER, val_a, &dummy_pubkey(0xA1))
                .unwrap();
            vs.activate_reshared_set(&[val_a], B256::with_last_byte(0x01))
                .unwrap();

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
            vs.config_max_validators.write(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            let val_a = address!("0x1111111111111111111111111111111111111111");
            let val_b = address!("0x2222222222222222222222222222222222222222");
            let val_c = address!("0x3333333333333333333333333333333333333333");
            for (addr, seed) in [(val_a, 0xA1u8), (val_b, 0xB2u8), (val_c, 0xC3u8)] {
                vs.register_validator(OWNER, addr, &dummy_pubkey(seed))
                    .unwrap();
            }
            vs.activate_reshared_set(&[val_a, val_b, val_c], B256::with_last_byte(0x01))
                .unwrap();

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
            vs.config_max_validators.write(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            let val_a = address!("0x1111111111111111111111111111111111111111");
            vs.register_validator(OWNER, val_a, &dummy_pubkey(0xA1))
                .unwrap();
            vs.activate_reshared_set(&[val_a], B256::with_last_byte(0x01))
                .unwrap();

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
        let committee_set_hash = outbe_validatorset::committee_set_hash_v2(0, &snapshot);
        let vrf_group_public_key = keccak256(&vrf_group_public_key_bytes);
        outbe_primitives::consensus::DkgBoundaryArtifact {
            epoch: 0,
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
            tee_reshare_registrations: Vec::new(),
            endorsement_signature: alloy_primitives::Bytes::new(),
            reshare: outbe_primitives::consensus::ReshareResult {
                new_active_set,
                active_set_hash,
            },
        }
    }

    #[test]
    fn apply_boundary_outcome_fatals_on_hash_change_without_set_change() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.config_max_validators.write(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            let val_a = address!("0x1111111111111111111111111111111111111111");
            let val_b = address!("0x2222222222222222222222222222222222222222");
            vs.register_validator(OWNER, val_a, &dummy_pubkey(0xA1))
                .unwrap();
            vs.register_validator(OWNER, val_b, &dummy_pubkey(0xB2))
                .unwrap();
            let current_hash = super::hash_boundary_active_set(&[val_a, val_b]);
            vs.activate_reshared_set(&[val_a, val_b], current_hash)
                .unwrap();

            // Boundary claims membership unchanged but carries a different active set.
            let boundary = boundary_with(false, vec![(val_a, dummy_pubkey(0xA1))]);
            let err = super::apply_boundary_outcome(storage.clone(), &boundary).unwrap_err();
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
            vs.config_max_validators.write(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            let val_a = address!("0x1111111111111111111111111111111111111111");
            let val_b = address!("0x2222222222222222222222222222222222222222");
            let val_c = address!("0x3333333333333333333333333333333333333333");
            for (addr, seed) in [(val_a, 0xA1u8), (val_b, 0xB2u8), (val_c, 0xC3u8)] {
                vs.register_validator(OWNER, addr, &dummy_pubkey(seed))
                    .unwrap();
            }
            let current_hash = super::hash_boundary_active_set(&[val_a, val_b]);
            vs.activate_reshared_set(&[val_a, val_b], current_hash)
                .unwrap();

            let boundary = boundary_with(
                true,
                vec![
                    (val_a, dummy_pubkey(0xA1)),
                    (val_b, dummy_pubkey(0xB2)),
                    (val_c, dummy_pubkey(0xC3)),
                ],
            );
            let new_hash = boundary.reshare.active_set_hash;
            super::apply_boundary_outcome(storage.clone(), &boundary).unwrap();

            let vs_after = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            let now_hash = vs_after.active_consensus_set_hash.read().unwrap();
            assert_eq!(now_hash, new_hash, "active_set_hash must advance");
            let active = vs_after.get_active_consensus_set().unwrap();
            let addrs: Vec<Address> = active.iter().map(|v| v.validator_address).collect();
            assert!(addrs.contains(&val_c), "C must now be in active set");
        });
    }

    #[test]
    fn apply_boundary_outcome_writes_snapshot_when_hash_matches() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.config_max_validators.write(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            let val_a = address!("0x1111111111111111111111111111111111111111");
            vs.register_validator(OWNER, val_a, &dummy_pubkey(0xA1))
                .unwrap();
            let hash = super::hash_boundary_active_set(&[val_a]);
            vs.activate_reshared_set(&[val_a], hash).unwrap();

            let boundary = boundary_with(false, vec![(val_a, dummy_pubkey(0xA1))]);
            super::apply_boundary_outcome(storage.clone(), &boundary).unwrap();

            let vs_after = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            assert_eq!(vs_after.active_consensus_set_hash.read().unwrap(), hash);

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
            vs.config_max_validators.write(128).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            let val_a = address!("0x1111111111111111111111111111111111111111");
            vs.register_validator(OWNER, val_a, &dummy_pubkey(0xA1))
                .unwrap();
            let hash = super::hash_boundary_active_set(&[val_a]);
            vs.activate_reshared_set(&[val_a], hash).unwrap();

            let mut boundary = boundary_with(false, vec![(val_a, dummy_pubkey(0xA1))]);
            boundary.committee_set_hash = B256::with_last_byte(0xFE);

            let err = super::apply_boundary_outcome(storage.clone(), &boundary).unwrap_err();
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
                .with_chain_id(MAINNET.chain().id())
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
            None, // accounted_parent_artifact_provider — None forces hint path
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
    /// not equal `block_number - 1`. Same error class as (b) — no silent
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
    // real `State<DB>` + revm — NOT just the storage-primitive level.
    // They cover the four claims the unit tests do NOT prove:
    //   1. Counter persists through revm tx revert (anti-drain).
    //   2. `SponsorshipAuthorized` event lands on the inner tx receipt.
    //   3. Signer balance is genuinely unchanged (no fee debit).
    //   4. EIP-7702 delegation to a NON-paymaster address falls through
    //      to the normal fee path.
    // -----------------------------------------------------------------

    use alloy_sol_types::SolEvent as _;
    use outbe_primitives::addresses::{AGENT_REWARD_ADDRESS, ZEROFEE_ADDRESS};
    use outbe_zerofee::precompile::IZeroFee::SponsorshipAuthorized;

    /// Sponsored signer derived from the alloy test-signature recovery.
    /// We don't care WHICH address it is — only that it is stable across
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
                .with_chain_id(MAINNET.chain().id())
                .with_spec_and_mainnet_gas_params(SpecId::PRAGUE),
            block_env: BlockEnv {
                number: U256::from(block_number),
                gas_limit: 30_000_000,
                basefee: alloy_eips::eip1559::MIN_PROTOCOL_BASE_FEE,
                beneficiary: OWNER,
                // 2026-04-01 00:00:00 UTC — matches BLOCK_DAY constant
                // in the zerofee unit tests for cross-reference.
                timestamp: U256::from(1_775_001_600u64),
                ..Default::default()
            },
        }
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
        // requested balance so the anti-sybil gate (`balance > 0`,
        // balance-only — nonce is not a gate) can be exercised.
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
    /// `to ∈ whitelist`, signer with `balance > 0` is admitted by the
    /// executor pre-fee hook, executed under zero-fee cfg overrides,
    /// and produces a receipt with a `SponsorshipAuthorized` log. The
    /// signer's balance is untouched and ZEROFEE_ADDRESS' counter slot
    /// is bumped to `(today, 1)`.
    #[test]
    fn eip7702_sponsored_tx_burns_quota_and_emits_event() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        let mut input = vec![0xae, 0x16, 0x9a, 0x50];
        input.extend_from_slice(&[0u8; 32]); // pad selector to selector+32-byte uint256 arg
        let recovered = sponsored_test_tx(input)
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

            // Find the SponsorshipAuthorized log on the receipt — this
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

        // Balance must be exactly what we put in — no fee debit. This
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
    /// EVM `disable_balance_check` would normally let it through — we
    /// assert it does NOT.
    #[test]
    fn eip7702_delegation_to_non_paymaster_falls_through_to_fee_path() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        let mut input = vec![0xae, 0x16, 0x9a, 0x50];
        input.extend_from_slice(&[0u8; 32]);
        let recovered = sponsored_test_tx(input)
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
                balance: U256::from(10u64.pow(18)),
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
            // small gas) — but because signer's code points to ORACLE,
            // the pre-fee hook leaves it to the normal path. The normal
            // path requires balance to cover `gas_limit * max_fee_per_gas`,
            // which 1 COEN (1e18 wei) easily covers, so this should
            // succeed. The key assertion is that NO SponsorshipAuthorized
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

        // Counter must remain at 0 — no quota burn for delegation to
        // foreign address.
        let counter = zerofee_counter_for(&mut state, signer);
        assert_eq!(counter, 0, "non-sponsored path must not burn quota");
    }

    /// Anti-sybil V2: `balance == 0` blocks the sponsored path
    /// regardless of nonce. EIP-7702 set-code transactions bump the
    /// authority's nonce as part of auth processing (25 k gas per
    /// auth, paid by the sponsor), so a fresh EOA can reach nonce > 0
    /// without spending any of its own wei. Only positive balance is
    /// a real economic gate — the pre-fee hook returns
    /// `FreeTxDailyNoExistingAccount` (code 111) and pushes a
    /// soft-failure receipt.
    #[test]
    fn eip7702_sponsored_tx_rejects_fresh_zero_balance_signer() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        let mut input = vec![0xae, 0x16, 0x9a, 0x50];
        input.extend_from_slice(&[0u8; 32]);
        let recovered = sponsored_test_tx(input)
            .try_into_recovered()
            .expect("test-signature must recover");
        let signer = Address::from(*recovered.signer());

        // balance = 0 → anti-sybil trigger, regardless of nonce.
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
                .expect("soft-failure path must not surface as a hard error");

            let receipts = executor.receipts();
            assert_eq!(receipts.len(), 1);
            assert!(
                !receipts[0].success,
                "anti-sybil rejection produces a status=0 receipt"
            );
            // The single log on a soft-failure receipt is the
            // `OutbeFailure(code, reason)` emitted at
            // `ZERO_FEE_POLICY_LOG_ADDRESS`. We only check the address +
            // that code 111 appears in the indexed topic.
            let outbe_failure_addr = outbe_primitives::addresses::ZERO_FEE_POLICY_LOG_ADDRESS;
            let failure_log = receipts[0]
                .logs
                .iter()
                .find(|l| l.address == outbe_failure_addr)
                .expect("soft-failure receipt must carry OutbeFailure log");
            // topic[1] is the indexed `code: uint16` — 32-byte BE.
            let code_topic = failure_log.topics().get(1).expect("code topic present");
            let code = u16::from_be_bytes([code_topic.as_slice()[30], code_topic.as_slice()[31]]);
            assert_eq!(code, 111, "anti-sybil rejection must surface as code 111");
        }
        state.merge_transitions(BundleRetention::Reverts);

        // No quota burn on a rejected admission.
        let counter = zerofee_counter_for(&mut state, signer);
        assert_eq!(counter, 0);
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
    /// by the pre-fee hook as a hard error — it lands in the block with
    /// a `status=0` receipt carrying `OutbeFailure(110)`, the counter
    /// stays at 8 (no over-burn), and no balance is debited. This is the
    /// exact contract the README promises and the txpool relies on
    /// (pool admits, executor produces the soft-failure).
    #[test]
    fn eip7702_ninth_sponsored_tx_soft_fails_with_code_110() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        let mut input = vec![0xae, 0x16, 0x9a, 0x50];
        input.extend_from_slice(&[0u8; 32]);
        let recovered = sponsored_test_tx(input)
            .try_into_recovered()
            .expect("test-signature must recover");
        let signer = Address::from(*recovered.signer());

        // pectra_evm_env uses timestamp 1_775_001_600 → UTC day 20260401.
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
        // Counter must stay at exactly the limit — no 9th increment.
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
        let mut input = vec![0xae, 0x16, 0x9a, 0x50];
        input.extend_from_slice(&[0u8; 32]);
        let recovered = sponsored_test_tx(input)
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

        // Counter bumped to 1 and no fee debited — confirms the fallback
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
    /// (`priority_fee > 0`) is NOT requesting sponsorship — its tx must
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
        // non-zero priority fee — the "I am paying" signal.
        let mut input = vec![0xae, 0x16, 0x9a, 0x50];
        input.extend_from_slice(&[0u8; 32]);
        let paying_tx: reth_ethereum::TransactionSigned = TxEip1559 {
            chain_id: CHAIN_ID,
            nonce: 0,
            gas_limit: 200_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000, // tip > 0 => paying, not sponsored
            to: TxKind::Call(AGENT_REWARD_ADDRESS),
            value: U256::ZERO,
            input: input.into(),
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
        let initial_balance = U256::from(1_000_000_000_000_000_000u128);
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
            // No SponsorshipAuthorized event — this was not a sponsored tx.
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
        // NOT touched — the tx never entered the sponsorship branch.
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
