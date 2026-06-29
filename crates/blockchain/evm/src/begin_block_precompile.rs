//! Begin-block orchestration precompile system transactions.
//!
//! The precompile is called through `transact_system_call` with
//! `SYSTEM_ADDRESS` as the EVM caller. It decodes a versioned
//! [`SystemTxInputV2`](crate::system_tx::SystemTxInputV2) payload and routes to
//! the begin_block system tx body so runtime events are emitted through the
//! EVM journal and become receipt-visible.

use alloy_primitives::{Address, Bytes, B256, U256};
use outbe_primitives::{
    addresses::SYSTEM_ADDRESS,
    block::{BlockContext, BlockLifecycle, BlockRuntimeContext},
    consensus::{DkgBoundaryArtifact, LATE_FINALIZE_WINDOW_K},
    consensus_metadata::CertifiedParentAccountingMetadata,
    error::{PrecompileError, Result},
    reshare_artifact::{LateFinalizeCreditsArtifact, PerBlockCredit},
    storage::StorageHandle,
};

use crate::{
    executor::{apply_boundary_outcome, validate_finalized_metadata, AccountedParentArtifact},
    system_tx::SystemTxInputV2,
};

/// Execution context preloaded by the executor before calling the
/// begin-block precompile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreloadedSystemTxContext {
    pub proposer: Address,
    pub finalized_summary: Option<AccountedParentArtifact>,
    /// True only for a block carrying a validator-set-changing BoundaryOutcome
    /// whose target set includes `proposer`. This lets the activation block be
    /// produced by a next-epoch leader before BoundaryOutcome updates parent-state
    /// consensus membership.
    pub allow_boundary_proposer: bool,
    /// canonical hash of the VRF proof carried in the verified
    /// parent certificate (`keccak256(VrfProof::encode())`). Derived by
    /// the executor's Phase 1 preflight from
    /// `outbe_consensus::proof::VerifiedProof::vrf_proof_hash` and fed
    /// into the V3 Rewards fingerprint so that two parent certificates
    /// with different VRF proofs cannot collide. `B256::ZERO` when the
    /// preflight was skipped (genesis bootstrap / test-only opt-out).
    pub canonical_vrf_proof_hash: B256,
}

thread_local! {
    static PRELOADED_SYSTEM_TX_CONTEXT: std::cell::RefCell<Option<PreloadedSystemTxContext>> =
        const { std::cell::RefCell::new(None) };
}

/// Runs `f` with explicit non-calldata context visible to the system
/// precompile on the current thread.
///
/// This keeps CertifiedParentAccounting money fields out of signed calldata while
/// still giving the precompile an explicit deterministic data path for the
/// parent block's committed execution summary. The executor sets this only
/// around a single `transact_system_call`, and the guard restores the previous
/// value on exit.
pub(crate) fn with_preloaded_system_tx_context<R>(
    context: PreloadedSystemTxContext,
    f: impl FnOnce() -> R,
) -> R {
    struct Reset(Option<PreloadedSystemTxContext>);

    impl Drop for Reset {
        fn drop(&mut self) {
            PRELOADED_SYSTEM_TX_CONTEXT.with(|slot| {
                *slot.borrow_mut() = self.0;
            });
        }
    }

    let previous = PRELOADED_SYSTEM_TX_CONTEXT.with(|slot| slot.replace(Some(context)));
    let _reset = Reset(previous);
    f()
}

fn current_preloaded_system_tx_context() -> Option<PreloadedSystemTxContext> {
    PRELOADED_SYSTEM_TX_CONTEXT.with(|slot| *slot.borrow())
}

/// Dispatch entrypoint registered at [`OUTBE_SYSTEM_TX_ADDRESS`].
pub fn dispatch(
    storage: StorageHandle,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    if caller != SYSTEM_ADDRESS {
        return Err(PrecompileError::Revert(
            "system precompile can only be called by SYSTEM_ADDRESS".into(),
        ));
    }
    if !value.is_zero() {
        return Err(PrecompileError::Revert(
            "system precompile does not accept native token value".into(),
        ));
    }

    let input = SystemTxInputV2::decode(data)
        .map_err(|error| PrecompileError::Fatal(format!("invalid system tx input: {error}")))?;

    match input {
        SystemTxInputV2::CertifiedParentAccounting { metadata } => {
            let ctx = block_runtime_context_from_storage(storage, true)?;
            run_finalization_and_slashing(&ctx, &metadata)?;
        }
        SystemTxInputV2::LateFinalizeCredits { artifact } => {
            let ctx = block_runtime_context_from_storage(storage, false)?;
            run_late_finalize_credits(&ctx, &artifact)?;
        }
        SystemTxInputV2::CycleTick => {
            let ctx = block_runtime_context_from_storage(storage, true)?;
            run_cycle_tick(&ctx)?;
        }
        SystemTxInputV2::BoundaryOutcome { artifact } => {
            let ctx = block_runtime_context_from_storage(storage, true)?;
            run_boundary_outcome(&ctx, &artifact)?;
        }
        SystemTxInputV2::TeeBootstrap { payload } => {
            let ctx = block_runtime_context_from_storage(storage, true)?;
            run_tee_bootstrap(&ctx, &payload)?;
        }
        SystemTxInputV2::OracleSlashWindow => {
            let ctx = block_runtime_context_from_storage(storage, false)?;
            run_oracle_slash_window(&ctx)?;
        }
        SystemTxInputV2::HookEvents => {
            let ctx = block_runtime_context_from_storage(storage, false)?;
            run_hook_events(&ctx)?;
        }
    }

    Ok(Bytes::new())
}

/// Phase 3b: one-time TEE registry bootstrap. Authenticates the payload against
/// the active consensus committee, then writes `TeeRegistry` (read-only
/// thereafter for clients).
///
/// Enforced here (consensus-critical, identical on proposer and verifier paths):
///
/// - the registry is still empty (idempotent one-shot);
/// - `committee_snapshot_block` is this block (Phase 3a's `BoundaryOutcome` wrote
///   the committee snapshot earlier in the same block);
/// - every registration's `keys_hash` recomputes from its own key material;
/// - every registration's validator is in the active consensus set, with no
///   duplicates;
/// - every `validator_signatures` entry recovers (recoverable secp256k1 ECDSA
///   over [`TeeBootstrapPayload::signing_hash`]) to its declared validator, which
///   is in the active consensus set, with no duplicates;
/// - registrations and signatures cover exactly the same validator set (1:1);
/// - the signers form a strict supermajority (`> 2/3`) of the active consensus
///   set.
/// - the payload's signed `policy` allowlist commits to its `policy_hash`,
///   and — when a genesis `teePolicy` is seeded (`TeeRegistry.policy_hash` slot 2
///   != ZERO) — the allowlist matches that genesis hash and every registration's
///   MRSIGNER/MRENCLAVE/isv_svn satisfies the AND-policy. The policy hash is read
///   from EVM storage so the gate is deterministic on proposer + verifier.
/// - `committee_snapshot_hash` binds the bootstrap to the epoch-0
///   `CommitteeSnapshotStore` that Phase 3's `BoundaryOutcome` wrote earlier in
///   this block: the gate recomputes `committee_set_hash_v2(0, snapshot)`, stores
///   it as the authoritative value, and rejects a non-zero payload value that
///   disagrees. Resolves `arch_debt` `tee_bootstrap_policy_and_snapshot_binding`
///   (commit `af7cdb8`); the producer still sends `ZERO`, which the verifier
///   recompute accepts and overwrites — cosmetic, not a binding gap.
pub(crate) fn run_tee_bootstrap(
    ctx: &BlockRuntimeContext,
    payload: &outbe_primitives::tee_bootstrap::TeeBootstrapPayload,
) -> Result<()> {
    use outbe_primitives::tee_bootstrap::recover_signer;
    use outbe_teeregistry::{TeeBootstrapData, TeeRegistration, TeeRegistry};
    use std::collections::BTreeSet;

    // Idempotency: the one-time bootstrap is valid only while the registry is
    // empty. This durable lock makes the tx un-repeatable.
    let mut registry = TeeRegistry::new(ctx.storage.clone());
    if registry.is_bootstrapped()? {
        return Err(PrecompileError::Revert(
            "TeeBootstrap: registry already bootstrapped".to_string(),
        ));
    }

    // The snapshot the payload binds to must be this block's (Phase 3a wrote the
    // CommitteeSnapshotStore earlier in the same block).
    if payload.committee_snapshot_block != ctx.block.block_number {
        return Err(PrecompileError::Revert(format!(
            "TeeBootstrap: committee_snapshot_block {} != current block {}",
            payload.committee_snapshot_block, ctx.block.block_number
        )));
    }

    // The active consensus set at this block is the authority that may bootstrap
    // the TEE registry. EXITING members retain current-epoch accountability and
    // are included by `get_active_consensus_set`.
    let committee: BTreeSet<Address> =
        outbe_validatorset::contract::ValidatorSet::new(ctx.storage.clone())
            .get_active_consensus_set()?
            .into_iter()
            .map(|record| record.validator_address)
            .collect();
    if committee.is_empty() {
        return Err(PrecompileError::Revert(
            "TeeBootstrap: no active consensus committee to authorize bootstrap".to_string(),
        ));
    }

    // Registrations: key-material integrity + committee membership + uniqueness.
    let mut registrants: BTreeSet<Address> = BTreeSet::new();
    for reg in &payload.registrations {
        if reg.computed_keys_hash() != reg.keys_hash {
            return Err(PrecompileError::Revert(format!(
                "TeeBootstrap: keys_hash mismatch for registration {}",
                reg.validator
            )));
        }
        if !committee.contains(&reg.validator) {
            return Err(PrecompileError::Revert(format!(
                "TeeBootstrap: registration for non-committee validator {}",
                reg.validator
            )));
        }
        if !registrants.insert(reg.validator) {
            return Err(PrecompileError::Revert(format!(
                "TeeBootstrap: duplicate registration for validator {}",
                reg.validator
            )));
        }
    }

    // Signatures: each must recover to its declared, committee-member validator,
    // with no duplicates. All signatures cover the same domain-separated digest.
    let signing_hash = payload.signing_hash();
    let mut signers: BTreeSet<Address> = BTreeSet::new();
    for sig in &payload.validator_signatures {
        let recovered = recover_signer(&signing_hash, &sig.signature)?;
        if recovered != sig.validator {
            return Err(PrecompileError::Revert(format!(
                "TeeBootstrap: signature signer {recovered} does not match declared validator {}",
                sig.validator
            )));
        }
        if !committee.contains(&sig.validator) {
            return Err(PrecompileError::Revert(format!(
                "TeeBootstrap: signature from non-committee validator {}",
                sig.validator
            )));
        }
        if !signers.insert(sig.validator) {
            return Err(PrecompileError::Revert(format!(
                "TeeBootstrap: duplicate signature for validator {}",
                sig.validator
            )));
        }
    }

    // Registrations and signatures must describe exactly the same participant
    // set: a registration without a signature is unauthorized; a signature
    // without a registration commits to keys that were never recorded.
    if registrants != signers {
        return Err(PrecompileError::Revert(
            "TeeBootstrap: registrations and signatures cover different validator sets".to_string(),
        ));
    }

    // Strict supermajority (> 2/3) of the active consensus set must authorize the
    // one-time bootstrap. `signers.len() * 3 > committee.len() * 2`, computed with
    // saturating multiplication (bounded by `MAX_TEE_REGISTRATIONS`).
    if signers.len().saturating_mul(3) <= committee.len().saturating_mul(2) {
        return Err(PrecompileError::Revert(format!(
            "TeeBootstrap: insufficient validator signatures: {} of {} (need > 2/3)",
            signers.len(),
            committee.len()
        )));
    }

    // Policy enforcement. The payload carries the signed attestation
    // allowlist; bind it to its committed `policy_hash`, then — when a genesis
    // policy is seeded (TeeRegistry slot 2 != ZERO) — require the allowlist to
    // hash to the genesis-committed value and enforce the AND-policy against
    // every registration's measurements. The policy hash is read from EVM storage
    // (not node config), so the gate is identical on proposer and verifier.
    let computed_policy_hash = payload.policy.compute_hash();
    if payload.policy_hash != computed_policy_hash {
        return Err(PrecompileError::Revert(
            "TeeBootstrap: policy_hash does not commit to the payload policy allowlist".to_string(),
        ));
    }
    let genesis_policy_hash = registry.policy_hash()?;
    if genesis_policy_hash != B256::ZERO {
        if payload.policy_hash != genesis_policy_hash {
            return Err(PrecompileError::Revert(format!(
                "TeeBootstrap: payload policy_hash {} does not match genesis teePolicy {genesis_policy_hash}",
                payload.policy_hash
            )));
        }
        for reg in &payload.registrations {
            if !payload
                .policy
                .admits(reg.mrsigner, reg.mrenclave, reg.isv_svn)
            {
                return Err(PrecompileError::Revert(format!(
                    "TeeBootstrap: registration {} fails genesis teePolicy (mrsigner {} / mrenclave {} / isv_svn {})",
                    reg.validator, reg.mrsigner, reg.mrenclave, reg.isv_svn
                )));
            }
        }
    } else {
        tracing::warn!(
            target: "outbe::system_tx",
            block_number = ctx.block.block_number,
            "TeeBootstrap: no genesis teePolicy seeded (TeeRegistry.policy_hash == 0); enclave measurements UNCHECKED (PoC/dev)"
        );
    }

    let registrations = payload
        .registrations
        .iter()
        .map(|reg| TeeRegistration {
            validator: reg.validator,
            recipient_x25519: reg.recipient_x25519,
            attestation_pub: reg.attestation_pub,
            noise_static_pub: reg.noise_static_pub,
            mrenclave: reg.mrenclave,
            mrsigner: reg.mrsigner,
            isv_svn: u64::from(reg.isv_svn),
            keys_hash: reg.keys_hash,
        })
        .collect();

    // B2: bind the bootstrap to the on-chain committee snapshot. Block 1's mandatory
    // BoundaryOutcome (Phase 3) runs before this Phase 3b tx and is the single writer
    // of the epoch-0 CommitteeSnapshotStore, so recompute that committee's canonical
    // V2 identity hash and bind it as the source of truth. Genesis-safe: a ZERO payload
    // value (the producer does not yet compute it) is accepted; a non-zero payload value
    // must match the on-chain snapshot, so a forged committee binding is rejected.
    let committee_snapshot_hash =
        match outbe_validatorset::state::read_committee_snapshot_for_epoch(ctx.storage.clone(), 0)?
        {
            Some(snapshot) => {
                let recomputed = outbe_validatorset::committee_set_hash_v2(0, &snapshot);
                if payload.committee_snapshot_hash != B256::ZERO
                    && payload.committee_snapshot_hash != recomputed
                {
                    return Err(PrecompileError::Revert(
                        "TeeBootstrap committee_snapshot_hash does not match the on-chain \
                         committee snapshot"
                            .to_string(),
                    ));
                }
                recomputed
            }
            None => payload.committee_snapshot_hash,
        };

    registry.write_bootstrap(&TeeBootstrapData {
        tribute_offer_public_key: payload.tribute_offer_public_key,
        policy_hash: payload.policy_hash,
        key_epoch: payload.key_epoch,
        tribute_offer_epoch: payload.tribute_offer_epoch,
        dkg_transcript_hash: payload.dkg_transcript_hash,
        committee_snapshot_block: payload.committee_snapshot_block,
        committee_snapshot_hash,
        tribute_offer_group_public_key: payload.tribute_offer_group_public_key.clone(),
        registrations,
    })
}

/// CertifiedParentAccounting system tx: apply the immediate parent's finalization
/// facts, participation, fee settlement, and deterministic slashing.
pub(crate) fn run_finalization_and_slashing(
    ctx: &BlockRuntimeContext,
    metadata: &CertifiedParentAccountingMetadata,
) -> Result<()> {
    if ctx.block.block_number < 2 {
        return Err(PrecompileError::Fatal(
            "CertifiedParentAccounting system tx requires block_number >= 2".into(),
        ));
    }
    let expected_parent_number = ctx
        .block
        .block_number
        .checked_sub(1)
        .ok_or_else(|| PrecompileError::Fatal("block number underflow".into()))?;
    if metadata.finalized_block_number != expected_parent_number {
        return Err(PrecompileError::Fatal(format!(
            "CertifiedParentAccounting metadata must target immediate parent: expected {}, got {}",
            expected_parent_number, metadata.finalized_block_number
        )));
    }
    if metadata.finalized_block_hash.is_zero() {
        return Err(PrecompileError::Fatal(
            "CertifiedParentAccounting metadata has zero finalized block hash".into(),
        ));
    }

    validate_finalized_metadata(ctx.storage.clone(), metadata)?;

    let finalized = read_preloaded_finalized_summary(&ctx.storage)?.ok_or_else(|| {
        PrecompileError::Fatal(format!(
            "missing preloaded execution summary for finalized block {} ({})",
            metadata.finalized_block_number, metadata.finalized_block_hash
        ))
    })?;

    // the V3 Rewards fingerprint binds the canonical VRF proof
    // hash from the verified parent certificate. The executor's Phase 1
    // preflight (`apply_pre_execution_changes::verify_phase1_in_preexec`)
    // captured this value from `outbe_consensus::proof::VerifiedProof::vrf_proof_hash`
    // and stashed it in the preloaded context. A zero hash here would
    // pass the gate but produces a degenerate fingerprint; in production
    // the preflight always populates a real value for `block_number >= 2`.
    let canonical_vrf_proof_hash = current_preloaded_system_tx_context()
        .map(|context| context.canonical_vrf_proof_hash)
        .unwrap_or(B256::ZERO);

    let last_accounted = outbe_accounting::read_last_accounted_block_number(ctx)?;
    match outbe_rewards::runtime::check_and_record_metadata_fingerprint(
        ctx,
        metadata,
        finalized.summary.validator_fee_sum,
        canonical_vrf_proof_hash,
    )? {
        outbe_rewards::runtime::MetadataFingerprintOutcome::IdenticalReplay => {
            if last_accounted != expected_parent_number {
                return Err(PrecompileError::Fatal(format!(
                    "CertifiedParentAccounting identical replay at unexpected progress: last_accounted={last_accounted}, expected={expected_parent_number}"
                )));
            }
            tracing::warn!(
                target: "outbe::system_tx",
                block_number = ctx.block.block_number,
                parent_block_number = expected_parent_number,
                "CertifiedParentAccounting identical replay accepted",
            );
            return Ok(());
        }
        outbe_rewards::runtime::MetadataFingerprintOutcome::Fresh => {
            let required_previous = expected_parent_number.saturating_sub(1);
            if last_accounted != required_previous {
                return Err(PrecompileError::Fatal(format!(
                    "CertifiedParentAccounting progress gap: last_accounted={last_accounted}, expected_previous={required_previous}, accounting_parent={expected_parent_number}"
                )));
            }
        }
    }

    // Base voters = the k=0 quorum (direct-parent signers); they seed the fee
    // escrow at k=0. The FULL absentee set and its miss / slashing accounting are
    // deferred to the inclusion-window close at N+K (`record_window_close_absentees`
    // in the LateFinalizeCredits phase), so a slow-but-honest validator credited at
    // k=1..K is not counted "missed" or slashed.
    let mut voters = Vec::new();
    for (addr, did_sign) in metadata
        .ordered_committee
        .iter()
        .copied()
        .zip(metadata.signer_bitmap.iter().copied())
    {
        if did_sign == 1 {
            voters.push(addr);
        }
    }

    outbe_rewards::finalized_metadata_hook::on_finalized_metadata(
        ctx,
        metadata,
        finalized.summary.validator_fee_sum,
        finalized.timestamp,
        &voters,
    )?;

    // Missed-proposer slashing: idempotent + bounded via the per-`fb_hash`
    // `proposer_window_slashed` guard. The whole event list for this
    // finalized parent is processed atomically; duplicate proposers across
    // skipped views are each slashed within the one pass.
    let missed_validators: Vec<Address> = metadata
        .missed_proposers
        .iter()
        .map(|m| m.validator)
        .collect();
    outbe_slashindicator::hooks::slash_window_proposers(
        ctx.storage.clone(),
        metadata.finalized_block_hash,
        &missed_validators,
    )?;

    // advance the slash-guard prune ring once per finalized block. Phase 1
    // sees every finalized block exactly once (as a direct parent), so this
    // bounds both window guards to the last SLASH_GUARD_RETAIN finalized blocks.
    outbe_slashindicator::hooks::prune_slash_guards(
        ctx.storage.clone(),
        metadata.finalized_block_hash,
    )?;

    outbe_accounting::record_phase1_progress(ctx, expected_parent_number)?;

    Ok(())
}

/// CycleTick system tx: record the proposer identity and run the Cycle begin-block tick.
pub(crate) fn run_cycle_tick(ctx: &BlockRuntimeContext) -> Result<()> {
    let allow_boundary_proposer = current_preloaded_system_tx_context()
        .map(|context| context.allow_boundary_proposer)
        .unwrap_or(false);
    let mut vs = outbe_validatorset::contract::ValidatorSet::new(ctx.storage.clone());
    if vs.is_consensus_participant(ctx.block.proposer)? {
        vs.record_proposer(ctx.block.proposer)?;
    } else if allow_boundary_proposer && vs.is_validator(ctx.block.proposer)? {
        // The block is the activation block for a validator-set-changing
        // BoundaryOutcome and was proposed by a next-epoch validator. The
        // proposer becomes a consensus participant in BoundaryOutcome, at which
        // point `run_boundary_outcome` records this proposal exactly once.
    } else {
        return Err(PrecompileError::Fatal(format!(
            "proposer is not a current consensus participant: {}",
            ctx.block.proposer
        )));
    }
    <outbe_cycle::lifecycle::CycleLifecycle as BlockLifecycle>::begin_block(ctx)
}

/// BoundaryOutcome system tx: activate a DKG/reshare boundary before user transactions.
pub(crate) fn run_boundary_outcome(
    ctx: &BlockRuntimeContext,
    artifact: &DkgBoundaryArtifact,
) -> Result<()> {
    let was_participant = outbe_validatorset::contract::ValidatorSet::new(ctx.storage.clone())
        .is_consensus_participant(ctx.block.proposer)?;
    apply_boundary_outcome(ctx.storage.clone(), artifact)?;
    if !was_participant {
        let mut vs = outbe_validatorset::contract::ValidatorSet::new(ctx.storage.clone());
        if vs.is_consensus_participant(ctx.block.proposer)? {
            vs.record_proposer(ctx.block.proposer)?;
        }
    }
    // Record the TEE recipient X25519 pubkeys announced through this boundary
    // (the `BoundaryOutcome` key-delivery channel — README "Consensus Artifact
    // Transport"). These ride in `header.extra_data` and are part of the
    // hash-committed `OutbeBlockArtifacts`, so every validator records the same
    // ordered set deterministically. Empty for boundaries that announce none.
    if !artifact.tee_recipient_pubkeys.is_empty() {
        outbe_teeregistry::TeeRegistry::new(ctx.storage.clone())
            .record_boundary_recipient_keys(&artifact.tee_recipient_pubkeys)?;
    }
    // R5: re-register the new committee's per-validator TEE keys after a
    // tribute-offer reshare. These ride in the hash-committed `OutbeBlockArtifacts`
    // (same bytes on every validator), so every node writes the same registry
    // state deterministically. The offer key itself is preserved across the
    // reshare, so it is NOT touched here. Empty for non-reshare boundaries.
    if !artifact.tee_reshare_registrations.is_empty() {
        // Reshare authority (membership gate): every re-registered enclave key must
        // belong to a validator in the committee this boundary activates. The host
        // relays the artifact; an injected registration for a non-member would
        // otherwise place an attacker-controlled enclave key into the registry (and
        // let it request the offer-key handoff). `new_active_set` is part of the
        // hash-committed artifact, so this gate is byte-deterministic across
        // validators. This bounds a malicious host / below-quorum collusion; the
        // prior-committee endorsement below is still required to bound a malicious
        // supermajority of the new committee itself.
        let authorized: std::collections::BTreeSet<alloy_primitives::Address> =
            artifact.reshare.new_active_set.iter().copied().collect();
        for r in &artifact.tee_reshare_registrations {
            if !authorized.contains(&r.validator) {
                return Err(PrecompileError::Revert(format!(
                    "reshare TEE registration for validator {} is not in the activated committee",
                    r.validator
                )));
            }
        }
        // Reshare authority (prior-committee endorsement): the OUTGOING committee must
        // have threshold-signed this incoming committee + the preserved offer key.
        // This is the only check a malicious supermajority of the NEW committee cannot
        // forge (the membership gate above is self-certifying for a >2/3-new attacker).
        // Verified against the stored prior group public key via deterministic plain
        // pairing, so every validator reaches the same verdict.
        let registry = outbe_teeregistry::TeeRegistry::new(ctx.storage.clone());
        let prior_group_pub = registry.prior_group_public_key()?;
        let offer_pub = registry.offer_public_key()?;
        let chain_id = alloy_primitives::B256::left_padding_from(&ctx.block.chain_id.to_be_bytes());
        let endorsement_msg = outbe_tee::endorsement::reshare_endorsement_message(
            chain_id,
            artifact.committee_set_hash,
            offer_pub.0,
        );
        if !outbe_consensus::proof::seed_partial::verify_group_signature(
            &prior_group_pub,
            outbe_tee::endorsement::TEE_ENDORSE_NAMESPACE,
            endorsement_msg.as_slice(),
            &artifact.endorsement_signature,
        ) {
            return Err(PrecompileError::Revert(
                "reshare TEE registrations lack a valid prior-committee endorsement".to_string(),
            ));
        }
        let regs: Vec<(
            alloy_primitives::Address,
            alloy_primitives::B256,
            alloy_primitives::B256,
            alloy_primitives::B256,
        )> = artifact
            .tee_reshare_registrations
            .iter()
            .map(|r| {
                (
                    r.validator,
                    r.recipient_x25519,
                    r.attestation_pub,
                    r.noise_static_pub,
                )
            })
            .collect();
        outbe_teeregistry::TeeRegistry::new(ctx.storage.clone())
            .record_reshare_registrations(&regs)?;
    }
    Ok(())
}

/// authentication: verify a late-finalize `credit`'s
/// proposer-supplied `fb_number`/`epoch`/`committee_set_hash` against the
/// canonical binding escrowed for that finalized block (keyed by `fb_number` in
/// `Rewards`). The BLS proof binds only `fb_hash`, so this is what prevents a
/// proposer from spoofing `fb_number` (to shrink the inclusion distance `k` and
/// inflate decay weight) or referencing a wrong committee. FATAL on a missing
/// escrow or any mismatch. Shared by the begin-zone body and the pre-exec gate.
pub(crate) fn authenticate_late_credit(
    storage: &StorageHandle,
    credit: &PerBlockCredit,
) -> Result<()> {
    let rewards = storage.contract::<outbe_rewards::contract::Rewards<'_>>();
    let escrowed_hash = rewards.pending_fb_hash_at.read(&credit.fb_number)?;
    if escrowed_hash == B256::ZERO {
        return Err(PrecompileError::Fatal(format!(
            "LateFinalizeCredits: no escrow for fb_number {} (credit fb_hash {})",
            credit.fb_number, credit.fb_hash
        )));
    }
    if escrowed_hash != credit.fb_hash {
        return Err(PrecompileError::Fatal(format!(
            "LateFinalizeCredits: fb_hash mismatch for fb_number {} (escrow {escrowed_hash}, credit {})",
            credit.fb_number, credit.fb_hash
        )));
    }
    let escrowed_epoch = rewards.pending_epoch_at.read(&credit.fb_number)?;
    if escrowed_epoch != credit.epoch {
        return Err(PrecompileError::Fatal(format!(
            "LateFinalizeCredits: epoch mismatch for fb_number {} (escrow {escrowed_epoch}, credit {})",
            credit.fb_number, credit.epoch
        )));
    }
    let escrowed_csh = rewards
        .pending_committee_set_hash_at
        .read(&credit.fb_number)?;
    if escrowed_csh != credit.committee_set_hash {
        return Err(PrecompileError::Fatal(format!(
            "LateFinalizeCredits: committee_set_hash mismatch for fb_number {} (escrow {escrowed_csh}, credit {})",
            credit.fb_number, credit.committee_set_hash
        )));
    }
    // Pin the rest of the signed binding (view, parent_view) to the canonical
    // certificate, so a credit whose aggregate is over a non-canonical view of the
    // same fb_hash (cross-view equivocation) is rejected here, not only by the
    // pre-exec BLS verify (which ties the credit's view to its signatures, not to
    // the finalized view). full binding.
    let escrowed_view = rewards.pending_view_at.read(&credit.fb_number)?;
    if escrowed_view != credit.view {
        return Err(PrecompileError::Fatal(format!(
            "LateFinalizeCredits: view mismatch for fb_number {} (escrow {escrowed_view}, credit {})",
            credit.fb_number, credit.view
        )));
    }
    let escrowed_parent_view = rewards.pending_parent_view_at.read(&credit.fb_number)?;
    if escrowed_parent_view != credit.parent_view {
        return Err(PrecompileError::Fatal(format!(
            "LateFinalizeCredits: parent_view mismatch for fb_number {} (escrow {escrowed_parent_view}, credit {})",
            credit.fb_number, credit.parent_view
        )));
    }
    Ok(())
}

/// LateFinalizeCredits system tx: record the verified
/// late-finalize voters of each in-window batch at their inclusion distance
/// `k`, then close the window that just matured (`settle_matured` for block
/// `N − K`). The escrow residue is burned for mint/burn parity inside
/// `settle_window`; here we additionally route that same residue to terminal
/// Metadosis emission headroom (`emission_sink::apply`), recycling unpaid fees
/// instead of permanently destroying them.
///
/// Determinism: every batch's BLS aggregate was already FATAL-verified in the
/// executor's pre-exec preflight (`verify_late_finalize_credits_in_preexec`),
/// proposer and validator alike. This body re-resolves the committee snapshot
/// only to map the verified signer indices to addresses; the re-`verify`
/// is the single source of truth for the bitmap→index decoding and yields the
/// same indices on every node. Empty artifacts (no gathered credits) reduce to
/// the window-close `settle_matured`, which is a no-op until block `K+1`.
pub(crate) fn run_late_finalize_credits(
    ctx: &BlockRuntimeContext,
    artifact: &LateFinalizeCreditsArtifact,
) -> Result<()> {
    use outbe_consensus::proof::verify_late_finalize_proof;
    use outbe_validatorset::state::{committee_snapshot_key, read_committee_snapshot};

    let block_number = ctx.block.block_number;

    for credit in &artifact.batches {
        // Inclusion distance k = block_number − fb_number, range-checked
        // `1 ≤ k ≤ K` on the *executed body* artifact (the pre-exec preflight
        // range-checks the header; the stateless validator binds header↔body —
        // but this path must stand on its own: a credit outside the window must
        // never be recorded). Checked FIRST, before the expensive snapshot read
        // + BLS verify, so an out-of-window credit is rejected cheaply.
        let k_u64 = block_number.checked_sub(credit.fb_number).ok_or_else(|| {
            PrecompileError::Fatal(format!(
                "LateFinalizeCredits: fb_number {} >= block {block_number}",
                credit.fb_number
            ))
        })?;
        if k_u64 == 0 || k_u64 > LATE_FINALIZE_WINDOW_K {
            return Err(PrecompileError::Fatal(format!(
                "LateFinalizeCredits: fb_number {} outside inclusion window \
                 (distance {k_u64}, K={LATE_FINALIZE_WINDOW_K}) for block {block_number}",
                credit.fb_number
            )));
        }
        let k = u8::try_from(k_u64).map_err(|_| {
            PrecompileError::Fatal(format!(
                "LateFinalizeCredits: inclusion distance {k_u64} exceeds u8 for block {block_number}"
            ))
        })?;

        // bind the proposer-supplied
        // fb_number/epoch/committee_set_hash to the escrowed canonical binding for
        // this finalized block before recording. The BLS proof binds only fb_hash,
        // so without this a proposer could spoof fb_number (shrink k → inflate
        // weight) or reference a wrong committee.
        authenticate_late_credit(&ctx.storage, credit)?;

        // Re-resolve the epoch committee the proof was produced for, to map
        // verified signer indices → addresses, and re-verify the BLS aggregate
        // (FATAL on failure — never a soft receipt). The snapshot must exist (the
        // pre-exec preflight already read and verified against it).
        let snapshot_key = committee_snapshot_key(credit.epoch, credit.committee_set_hash);
        let snapshot = read_committee_snapshot(ctx.storage.clone(), snapshot_key)?.ok_or_else(
            || {
                PrecompileError::Fatal(format!(
                    "LateFinalizeCredits: missing committee snapshot for epoch={} key={snapshot_key}",
                    credit.epoch
                ))
            },
        )?;

        let signer_indices = verify_late_finalize_proof(&snapshot, credit).map_err(|error| {
            PrecompileError::Fatal(format!(
                "LateFinalizeCredits: proof verify failed for fb={}: {error}",
                credit.fb_hash
            ))
        })?;

        for idx in signer_indices {
            let voter = snapshot
                .committee
                .get(idx)
                .map(|entry| entry.address)
                .ok_or_else(|| {
                    PrecompileError::Fatal(format!(
                        "LateFinalizeCredits: signer index {idx} out of committee range"
                    ))
                })?;
            outbe_rewards::late_settlement::record_late_credit(ctx, credit.fb_hash, voter, k)?;
        }
    }

    // Window-close miss & slashing pass: record misses and apply
    // punitive slashing for every committee member who never voted within K, using
    // the FINAL credited set. Must run BEFORE `settle_matured`, which frees the
    // `late_voter_*` credited set.
    record_window_close_absentees(ctx, block_number)?;

    // Window close: settle block N − K (the window that just matured). No-op
    // before block K+1 or when nothing was escrowed at that number. The residue
    // burn + terminal-Metadosis recycle and the per-window state cleanup happen
    // inside `settle_window`; nothing further is needed here.
    outbe_rewards::late_settlement::settle_matured(ctx, block_number, LATE_FINALIZE_WINDOW_K)?;

    Ok(())
}

/// Window-close miss & slashing pass. For the
/// window maturing at this block (`fb_number = block_number − K`), every committee
/// member that never voted within `K` — `committee(fb_number) \ credited` — has its
/// finalized-participation miss recorded and `slash_voter` applied (force-exit +
/// stake slash once the felony threshold is crossed).
///
/// Determinism: the committee snapshot and credited set are committed chain state;
/// absentees are emitted in committee order. Idempotent via the per-`fb_hash`
/// guards inside the validatorset / slashindicator hooks. The committee snapshot
/// is written at the epoch boundary and never pruned, so it is always present in
/// production; a missing snapshot fails open (skip) rather than halting the block.
///
/// Runs BEFORE `settle_matured`, which frees the `late_voter_*` credited set.
fn record_window_close_absentees(ctx: &BlockRuntimeContext, block_number: u64) -> Result<()> {
    use outbe_validatorset::state::{committee_snapshot_key, read_committee_snapshot};
    use std::collections::BTreeSet;

    let Some(fb_number) = block_number.checked_sub(LATE_FINALIZE_WINDOW_K) else {
        return Ok(());
    };
    if fb_number == 0 {
        return Ok(());
    }
    let Some(info) = outbe_rewards::late_settlement::window_close_credited(ctx, fb_number)? else {
        return Ok(());
    };

    let snapshot_key = committee_snapshot_key(info.epoch, info.committee_set_hash);
    let Some(snapshot) = read_committee_snapshot(ctx.storage.clone(), snapshot_key)? else {
        // Always present in production (written at the epoch boundary, never
        // pruned). Fail open rather than halt the block on a slashing-accounting
        // input that is missing only in degenerate/under-seeded states.
        tracing::warn!(
            target: "outbe::slashing",
            fb_number,
            epoch = info.epoch,
            "window-close absentee pass: committee snapshot missing; skipping",
        );
        return Ok(());
    };

    let credited: BTreeSet<Address> = info.credited.into_iter().collect();
    // Absentees = committee members who never voted within `K`, restricted to
    // currently-registered validators. Committee members are always registered in
    // production (the snapshot IS the validator set, and none can fully deregister
    // within `K` blocks), so the filter is a no-op there; it only guards a stray
    // non-registered binding from reverting the whole settlement phase via
    // `record_finalized_participation`'s strict registered-validator contract.
    let vs = outbe_validatorset::contract::ValidatorSet::new(ctx.storage.clone());
    let mut absentees: Vec<Address> = Vec::new();
    for entry in &snapshot.committee {
        if credited.contains(&entry.address) {
            continue;
        }
        if vs.is_validator(entry.address)? {
            absentees.push(entry.address);
        }
    }
    if absentees.is_empty() {
        return Ok(());
    }

    // Metric (E8 relocation): count val_missed_votes against the true absentee set
    // at window close. Idempotent via `finalized_participation_recorded[fb_hash]`.
    outbe_validatorset::hooks::record_finalized_participation(
        ctx.storage.clone(),
        info.fb_hash,
        &[],
        &absentees,
    )?;

    // Punitive: increment voter_miss_count and force-exit + slash at the felony
    // threshold. Idempotent + bounded via the per-`fb_hash` `voter_window_slashed`
    // guard; this whole absentee pass is atomic per finalized block.
    outbe_slashindicator::hooks::slash_window_voters(
        ctx.storage.clone(),
        info.fb_hash,
        &absentees,
    )?;

    Ok(())
}

/// OracleSlashWindow system tx: run Oracle slash-window penalties after any
/// same-block boundary activation but before user transactions observe state.
pub(crate) fn run_oracle_slash_window(ctx: &BlockRuntimeContext) -> Result<()> {
    outbe_oracle::hooks::run_slash_window(ctx)
}

/// HookEvents system tx: no-op marker. Whitelisted pre-exec hook logs are
/// attached to this phase's receipt by the executor without re-running hooks.
pub(crate) fn run_hook_events(_ctx: &BlockRuntimeContext) -> Result<()> {
    Ok(())
}

fn block_runtime_context_from_storage(
    storage: StorageHandle,
    include_validator_snapshot: bool,
) -> Result<BlockRuntimeContext> {
    let block_number = storage.block_number()?;
    let timestamp = u256_to_u64("block timestamp", storage.timestamp()?)?;
    let chain_id = storage.chain_id()?;
    let proposer = current_preloaded_system_tx_context()
        .map(|context| context.proposer)
        .unwrap_or(storage.beneficiary()?);

    let validators = if include_validator_snapshot {
        let vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
        let mut validators: Vec<Address> = vs
            .get_active_consensus_set()?
            .into_iter()
            .map(|record| record.validator_address)
            .collect();
        validators.sort();
        validators
    } else {
        // OracleSlashWindow only uses block number/timestamp plus storage. Avoid
        // charging a mandatory no-op system tx for an unrelated active-set snapshot.
        Vec::new()
    };

    Ok(BlockRuntimeContext::new(
        BlockContext::new(block_number, timestamp, chain_id, proposer, validators),
        storage,
    ))
}

fn read_preloaded_finalized_summary(
    _storage: &StorageHandle<'_>,
) -> Result<Option<AccountedParentArtifact>> {
    Ok(current_preloaded_system_tx_context().and_then(|context| context.finalized_summary))
}

fn u256_to_u64(name: &str, value: U256) -> Result<u64> {
    if value > U256::from(u64::MAX) {
        return Err(PrecompileError::Fatal(format!(
            "{name} exceeds u64 range: {value}"
        )));
    }
    Ok(value.to::<u64>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, keccak256, B256};
    use outbe_primitives::{consensus::ReshareResult, storage::hashmap::HashMapStorageProvider};

    const CHAIN_ID: u64 = 2026;
    const OWNER: Address = address!("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    const VALIDATOR: Address = address!("0x1111111111111111111111111111111111111111");

    fn metadata() -> CertifiedParentAccountingMetadata {
        CertifiedParentAccountingMetadata {
            finalized_block_number: 1,
            finalized_block_hash: B256::repeat_byte(0x11),
            finalized_epoch: 1,
            finalized_view: 2,
            parent_view: 1,
            ordered_committee: vec![VALIDATOR],
            signer_bitmap: vec![1],
            proof: Bytes::from_static(b"cert"),
            committee_set_hash: B256::ZERO,
            vrf_material_version: 0,
            vrf_group_public_key_hash: B256::ZERO,
            proof_kind:
                outbe_primitives::consensus_metadata::ParentParticipationProof::Finalization,
            missed_proposers: Vec::new(),
        }
    }

    fn metadata_for_parent(
        parent_number: u64,
        parent_hash: B256,
    ) -> CertifiedParentAccountingMetadata {
        let mut metadata = metadata();
        metadata.finalized_block_number = parent_number;
        metadata.finalized_block_hash = parent_hash;
        metadata.finalized_view = parent_number.saturating_add(1);
        metadata.parent_view = parent_number;
        metadata
    }

    fn active_set_hash(addresses: &[Address]) -> B256 {
        let mut bytes = Vec::with_capacity(8 + addresses.len() * 20);
        bytes.extend_from_slice(&(addresses.len() as u64).to_be_bytes());
        for address in addresses {
            bytes.extend_from_slice(address.as_slice());
        }
        keccak256(bytes)
    }

    fn boundary_noop() -> DkgBoundaryArtifact {
        let vrf_group_public_key_bytes = vec![0x42u8; 96];
        let snapshot = outbe_validatorset::CommitteeSnapshot {
            committee: vec![outbe_validatorset::CommitteeEntry {
                address: VALIDATOR,
                consensus_pubkey: [7u8; 48],
            }],
            vrf_material_version: 1,
            vrf_group_public_key_bytes: vrf_group_public_key_bytes.clone(),
            vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
        };
        DkgBoundaryArtifact {
            epoch: 1,
            dkg_cycle: 1,
            freeze_height: 1,
            planned_activation_height: 2,
            target_set_hash: B256::ZERO,
            vrf_material_version: 1,
            vrf_group_public_key: keccak256(&vrf_group_public_key_bytes),
            vrf_group_public_key_bytes: Bytes::from(vrf_group_public_key_bytes),
            committee_set_hash: outbe_validatorset::committee_set_hash_v2(1, &snapshot),
            is_validator_set_change: false,
            outcome: Bytes::new(),
            is_full_dkg: false,
            tee_recipient_pubkeys: Vec::new(),
            tee_reshare_registrations: Vec::new(),
            endorsement_signature: alloy_primitives::Bytes::new(),
            reshare: ReshareResult {
                new_active_set: vec![VALIDATOR],
                active_set_hash: active_set_hash(&[VALIDATOR]),
            },
        }
    }

    fn configured_storage(block_number: u64, timestamp: u64) -> HashMapStorageProvider {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        provider.set_block_number(block_number);
        provider.set_timestamp(U256::from(timestamp));
        provider.set_beneficiary(VALIDATOR);
        provider.enter(|storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.config_max_validators.write(128).unwrap();
            vs.config_epoch_length_blocks.write(10).unwrap();
            vs.register_validator(OWNER, VALIDATOR, &[7u8; 48]).unwrap();
            vs.activate_validator(VALIDATOR).unwrap();
            vs.val_has_bls_share.write(&VALIDATOR, true).unwrap();
            vs.active_consensus_set_hash
                .write(active_set_hash(&[VALIDATOR]))
                .unwrap();
        });
        provider
    }

    fn provider_from_storage(
        block_number: u64,
        timestamp: u64,
        storage: std::collections::HashMap<(Address, U256), U256>,
    ) -> HashMapStorageProvider {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        provider.set_block_number(block_number);
        provider.set_timestamp(U256::from(timestamp));
        provider.set_beneficiary(VALIDATOR);
        provider.storage = storage;
        provider
    }

    fn runtime_ctx(storage: StorageHandle<'_>) -> BlockRuntimeContext<'_> {
        BlockRuntimeContext::new(
            BlockContext::new(
                storage.block_number().unwrap(),
                storage.timestamp().unwrap().to::<u64>(),
                storage.chain_id().unwrap(),
                VALIDATOR,
                vec![VALIDATOR],
            ),
            storage,
        )
    }

    fn read_progress(provider: &mut HashMapStorageProvider) -> u64 {
        provider.enter(|storage| {
            let ctx = runtime_ctx(storage);
            outbe_accounting::read_last_accounted_block_number(&ctx).unwrap()
        })
    }

    fn record_progress(provider: &mut HashMapStorageProvider, block_number: u64) {
        provider.enter(|storage| {
            let ctx = runtime_ctx(storage);
            outbe_accounting::record_phase1_progress(&ctx, block_number).unwrap();
        });
    }

    fn dispatch_phase1(
        provider: &mut HashMapStorageProvider,
        metadata: CertifiedParentAccountingMetadata,
    ) -> Result<Bytes> {
        provider.enter(|storage| {
            let input = SystemTxInputV2::CertifiedParentAccounting { metadata }
                .encode()
                .unwrap();
            with_preloaded_system_tx_context(
                PreloadedSystemTxContext {
                    proposer: VALIDATOR,
                    finalized_summary: Some(AccountedParentArtifact {
                        summary: outbe_primitives::reshare_artifact::ExecutionSummaryArtifact {
                            validator_fee_sum: U256::ZERO,
                        },
                        timestamp: 1_699_999_990,
                    }),
                    allow_boundary_proposer: false,
                    canonical_vrf_proof_hash: B256::repeat_byte(0xEF),
                },
                || dispatch(storage, &input, SYSTEM_ADDRESS, U256::ZERO),
            )
        })
    }

    #[test]
    fn dispatch_rejects_external_caller_before_state_mutation() {
        let mut provider = configured_storage(1, 1);
        provider.enter(|storage| {
            let input = SystemTxInputV2::CycleTick.encode().unwrap();
            let err = dispatch(storage, &input, VALIDATOR, U256::ZERO).unwrap_err();
            assert!(matches!(err, PrecompileError::Revert(_)));
        });
    }

    #[test]
    fn dispatch_rejects_native_value() {
        let mut provider = configured_storage(1, 1);
        provider.enter(|storage| {
            let input = SystemTxInputV2::CycleTick.encode().unwrap();
            let err = dispatch(storage, &input, SYSTEM_ADDRESS, U256::from(1u64)).unwrap_err();
            assert!(matches!(err, PrecompileError::Revert(_)));
        });
    }

    #[test]
    fn dispatch_rejects_unknown_selector() {
        let mut provider = configured_storage(1, 1);
        provider.enter(|storage| {
            let input = [
                0xff,
                0xff,
                0xff,
                0xff,
                crate::system_tx::SYSTEM_TX_INPUT_VERSION,
            ];
            let err = dispatch(storage, &input, SYSTEM_ADDRESS, U256::ZERO).unwrap_err();
            assert!(matches!(err, PrecompileError::Fatal(_)));
            assert!(err.to_string().contains("unknown system tx selector"));
        });
    }

    #[test]
    fn dispatch_rejects_wrong_version() {
        let mut provider = configured_storage(1, 1);
        provider.enter(|storage| {
            let mut input = SystemTxInputV2::CycleTick.encode().unwrap().to_vec();
            input[4] = crate::system_tx::SYSTEM_TX_INPUT_VERSION.saturating_add(1);
            let err = dispatch(storage, &input, SYSTEM_ADDRESS, U256::ZERO).unwrap_err();
            assert!(matches!(err, PrecompileError::Fatal(_)));
            assert!(err
                .to_string()
                .contains("unsupported system tx input version"));
        });
    }

    #[test]
    fn dispatch_cycle_tick_records_preloaded_proposer() {
        let mut provider = configured_storage(1, 1);
        provider.enter(|storage| {
            let input = SystemTxInputV2::CycleTick.encode().unwrap();
            with_preloaded_system_tx_context(
                PreloadedSystemTxContext {
                    proposer: VALIDATOR,
                    finalized_summary: None,
                    allow_boundary_proposer: false,
                    canonical_vrf_proof_hash: B256::ZERO,
                },
                || dispatch(storage, &input, SYSTEM_ADDRESS, U256::ZERO),
            )
            .unwrap();
        });

        provider.enter(|storage| {
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            let record = vs.get_validator(VALIDATOR).unwrap().unwrap();
            assert_eq!(record.blocks_proposed, 1);
        });
    }

    #[test]
    fn dispatch_boundary_outcome_roundtrip_noop() {
        let mut provider = configured_storage(2, 2);
        provider.enter(|storage| {
            let input = SystemTxInputV2::BoundaryOutcome {
                artifact: boundary_noop(),
            }
            .encode()
            .unwrap();
            dispatch(storage, &input, SYSTEM_ADDRESS, U256::ZERO).unwrap();
        });
    }

    #[test]
    fn boundary_outcome_records_announced_tee_recipient_pubkeys() {
        let mut provider = configured_storage(2, 2);
        let recipient = B256::repeat_byte(0x7A);

        provider.enter(|storage| {
            // Before the boundary, no recipient key is announced.
            let reg = outbe_teeregistry::TeeRegistry::new(storage.clone());
            assert_eq!(reg.announced_recipient_key(VALIDATOR).unwrap(), B256::ZERO);

            let mut artifact = boundary_noop();
            artifact.tee_recipient_pubkeys = vec![(VALIDATOR, recipient)];
            let input = SystemTxInputV2::BoundaryOutcome { artifact }
                .encode()
                .unwrap();
            dispatch(storage, &input, SYSTEM_ADDRESS, U256::ZERO).unwrap();
        });

        // The boundary-announced recipient key is now readable from the registry.
        provider.enter(|storage| {
            let reg = outbe_teeregistry::TeeRegistry::new(storage);
            assert_eq!(reg.announced_recipient_key(VALIDATOR).unwrap(), recipient);
        });
    }

    fn reshare_registration(
        validator: alloy_primitives::Address,
    ) -> outbe_primitives::consensus::TeeReshareRegistration {
        outbe_primitives::consensus::TeeReshareRegistration {
            validator,
            recipient_x25519: B256::repeat_byte(0x01),
            attestation_pub: B256::repeat_byte(0x02),
            noise_static_pub: B256::repeat_byte(0x03),
        }
    }

    #[test]
    fn boundary_outcome_rejects_reshare_registration_for_non_committee_validator() {
        // `boundary_noop` activates new_active_set = [VALIDATOR]; a registration for
        // any other address is not authorized by the committee and must revert.
        let mut provider = configured_storage(2, 2);
        provider.enter(|storage| {
            let outsider = alloy_primitives::Address::repeat_byte(0xBE);
            let mut artifact = boundary_noop();
            artifact.tee_reshare_registrations = vec![reshare_registration(outsider)];
            let input = SystemTxInputV2::BoundaryOutcome { artifact }
                .encode()
                .unwrap();
            assert!(
                dispatch(storage, &input, SYSTEM_ADDRESS, U256::ZERO).is_err(),
                "reshare registration for a non-committee validator must be rejected"
            );
        });
    }

    #[test]
    fn boundary_outcome_rejects_reshare_registration_without_endorsement() {
        // Even for a committee member (VALIDATOR is in `new_active_set`, so the
        // membership gate passes), a reshare registration is rejected unless the
        // artifact carries a valid prior-committee endorsement (B3). Here no group key
        // is stored and the endorsement is empty, so the authority check fails closed.
        // The happy path (a real recovered group signature) is exercised end-to-end on
        // the SGX localnet, since constructing a threshold group signature needs the
        // DKG primitives, not a unit fixture.
        let mut provider = configured_storage(2, 2);
        provider.enter(|storage| {
            let mut artifact = boundary_noop();
            artifact.tee_reshare_registrations = vec![reshare_registration(VALIDATOR)];
            let input = SystemTxInputV2::BoundaryOutcome { artifact }
                .encode()
                .unwrap();
            let err = dispatch(storage, &input, SYSTEM_ADDRESS, U256::ZERO)
                .expect_err("a reshare registration without an endorsement must be rejected");
            assert!(
                format!("{err:?}").contains("endorsement"),
                "must fail on the missing prior-committee endorsement, got: {err:?}"
            );
        });
    }

    #[test]
    fn dispatch_finalization_uses_preloaded_summary_not_calldata_money() {
        let mut provider = configured_storage(2, 1_700_000_000);
        provider.enter(|storage| {
            let input = SystemTxInputV2::CertifiedParentAccounting {
                metadata: metadata(),
            }
            .encode()
            .unwrap();
            with_preloaded_system_tx_context(
                PreloadedSystemTxContext {
                    proposer: VALIDATOR,
                    finalized_summary: Some(AccountedParentArtifact {
                        summary: outbe_primitives::reshare_artifact::ExecutionSummaryArtifact {
                            validator_fee_sum: U256::ZERO,
                        },
                        timestamp: 1_699_999_990,
                    }),
                    allow_boundary_proposer: false,
                    canonical_vrf_proof_hash: B256::ZERO,
                },
                || dispatch(storage, &input, SYSTEM_ADDRESS, U256::ZERO),
            )
            .unwrap();
        });
    }

    #[test]
    fn phase1_reorg_same_height_uses_parent_state_progress_not_abandoned_post_state() {
        const CHILD_BLOCK: u64 = 27;
        const PARENT_BLOCK: u64 = CHILD_BLOCK - 1;
        const REQUIRED_PREVIOUS: u64 = PARENT_BLOCK - 1;

        let mut base = configured_storage(CHILD_BLOCK, 1_700_000_000);
        record_progress(&mut base, REQUIRED_PREVIOUS);
        let parent_state = base.storage.clone();

        let mut branch_a = provider_from_storage(CHILD_BLOCK, 1_700_000_000, parent_state.clone());
        dispatch_phase1(
            &mut branch_a,
            metadata_for_parent(PARENT_BLOCK, B256::repeat_byte(0xA1)),
        )
        .expect("branch A phase1 commits");
        assert_eq!(read_progress(&mut branch_a), PARENT_BLOCK);

        let mut branch_b_from_parent =
            provider_from_storage(CHILD_BLOCK, 1_700_000_000, parent_state);
        dispatch_phase1(
            &mut branch_b_from_parent,
            metadata_for_parent(PARENT_BLOCK, B256::repeat_byte(0xB2)),
        )
        .expect("same-height branch B must commit from its own parent state");
        assert_eq!(read_progress(&mut branch_b_from_parent), PARENT_BLOCK);

        let mut branch_b_from_abandoned_post_state =
            provider_from_storage(CHILD_BLOCK, 1_700_000_000, branch_a.storage.clone());
        let err = dispatch_phase1(
            &mut branch_b_from_abandoned_post_state,
            metadata_for_parent(PARENT_BLOCK, B256::repeat_byte(0xB2)),
        )
        .expect_err("branch B must not use abandoned branch A post-state");
        assert!(
            err.to_string()
                .contains("CertifiedParentAccounting progress gap"),
            "expected progress-gap failure, got {err}"
        );
    }

    #[test]
    fn dispatch_finalization_counts_duplicate_missed_proposer_events_by_index() {
        let mut provider = configured_storage(2, 1_700_000_000);
        provider.enter(|storage| {
            let mut metadata = metadata();
            metadata.missed_proposers = vec![
                outbe_primitives::consensus_metadata::MissedProposerEvent {
                    view: 1,
                    validator: VALIDATOR,
                },
                outbe_primitives::consensus_metadata::MissedProposerEvent {
                    view: 2,
                    validator: VALIDATOR,
                },
            ];
            let input = SystemTxInputV2::CertifiedParentAccounting { metadata }
                .encode()
                .unwrap();
            with_preloaded_system_tx_context(
                PreloadedSystemTxContext {
                    proposer: VALIDATOR,
                    finalized_summary: Some(AccountedParentArtifact {
                        summary: outbe_primitives::reshare_artifact::ExecutionSummaryArtifact {
                            validator_fee_sum: U256::ZERO,
                        },
                        timestamp: 1_699_999_990,
                    }),
                    allow_boundary_proposer: false,
                    canonical_vrf_proof_hash: B256::ZERO,
                },
                || dispatch(storage, &input, SYSTEM_ADDRESS, U256::ZERO),
            )
            .unwrap();
        });

        provider.enter(|storage| {
            let si = outbe_slashindicator::contract::SlashIndicator::new(storage);
            assert_eq!(si.proposer_miss_count.read(&VALIDATOR).unwrap(), 2);
        });
    }

    #[test]
    fn finalization_rejects_non_parent_metadata_before_summary_use() {
        let mut provider = configured_storage(3, 1_700_000_000);
        provider.enter(|storage| {
            let input = SystemTxInputV2::CertifiedParentAccounting {
                metadata: metadata(),
            }
            .encode()
            .unwrap();
            let err = dispatch(storage, &input, SYSTEM_ADDRESS, U256::ZERO).unwrap_err();
            assert!(err
                .to_string()
                .contains("CertifiedParentAccounting metadata must target immediate parent"));
        });
    }

    // ---- Phase 3b: TeeBootstrap handler verification ----

    use outbe_primitives::tee_bootstrap::{
        TeeBootstrapPayload, TeePolicy, TeeRegistrationBundle, TeeValidatorSignature,
    };

    fn tee_signing_key(seed: u8) -> k256::ecdsa::SigningKey {
        k256::ecdsa::SigningKey::from_slice(&[seed; 32]).expect("non-zero scalar")
    }

    fn tee_evm_address(key: &k256::ecdsa::SigningKey) -> Address {
        let point = key.verifying_key().to_encoded_point(false);
        Address::from_slice(&keccak256(&point.as_bytes()[1..])[12..])
    }

    fn tee_sign(key: &k256::ecdsa::SigningKey, prehash: &B256) -> [u8; 65] {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let (sig, recid): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
            key.sign_prehash(prehash.as_slice()).expect("sign prehash");
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(sig.to_bytes().as_slice());
        out[64] = recid.to_byte();
        out
    }

    /// Storage seeded with `members` as ACTIVE consensus participants (status
    /// ACTIVE + BLS share present), which is exactly `get_active_consensus_set`.
    fn tee_committee_storage(block_number: u64, members: &[Address]) -> HashMapStorageProvider {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        provider.set_block_number(block_number);
        provider.set_timestamp(U256::from(block_number.max(1)));
        provider.set_beneficiary(members[0]);
        provider.enter(|storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.config_max_validators.write(128).unwrap();
            vs.config_epoch_length_blocks.write(10).unwrap();
            for (i, member) in members.iter().enumerate() {
                // Distinct consensus pubkey per member (uniqueness is enforced).
                let mut pubkey = [7u8; 48];
                pubkey[0] = i as u8;
                vs.register_validator(OWNER, *member, &pubkey).unwrap();
                vs.activate_validator(*member).unwrap();
                vs.val_has_bls_share.write(member, true).unwrap();
            }
        });
        provider
    }

    fn tee_registration(validator: Address, salt: u8) -> TeeRegistrationBundle {
        let mut reg = TeeRegistrationBundle {
            validator,
            recipient_x25519: B256::repeat_byte(salt),
            attestation_pub: B256::repeat_byte(salt.wrapping_add(1)),
            noise_static_pub: B256::repeat_byte(salt.wrapping_add(2)),
            mrenclave: B256::repeat_byte(0x50),
            mrsigner: B256::repeat_byte(0x60),
            isv_svn: 1,
            keys_hash: B256::ZERO,
        };
        reg.keys_hash = reg.computed_keys_hash();
        reg
    }

    /// A payload registering and signed by exactly `signers`. Signatures are
    /// produced over `signing_hash()` after the body is final, so they validate.
    fn tee_payload(block_number: u64, signers: &[k256::ecdsa::SigningKey]) -> TeeBootstrapPayload {
        let registrations = signers
            .iter()
            .enumerate()
            .map(|(i, key)| tee_registration(tee_evm_address(key), 0x20 + i as u8))
            .collect();
        // Default (unconfigured) policy; `policy_hash` derives from it so the
        // handler's consistency check passes. With no genesis policy_hash seeded
        // (slot 2 == ZERO) the handler skips measurement enforcement.
        let policy = TeePolicy::default();
        let mut payload = TeeBootstrapPayload {
            policy_hash: policy.compute_hash(),
            committee_snapshot_hash: B256::repeat_byte(0x71),
            committee_snapshot_block: block_number,
            key_epoch: 0,
            tribute_offer_epoch: 0,
            dkg_transcript_hash: B256::repeat_byte(0x72),
            tribute_offer_public_key: B256::repeat_byte(0x73),
            tribute_offer_group_public_key: alloy_primitives::Bytes::new(),
            registrations,
            policy,
            validator_signatures: Vec::new(),
        };
        let signing_hash = payload.signing_hash();
        payload.validator_signatures = signers
            .iter()
            .map(|key| TeeValidatorSignature {
                validator: tee_evm_address(key),
                signature: tee_sign(key, &signing_hash),
            })
            .collect();
        payload
    }

    fn run_bootstrap(
        provider: &mut HashMapStorageProvider,
        payload: &TeeBootstrapPayload,
    ) -> Result<()> {
        provider.enter(|storage| {
            let ctx = runtime_ctx(storage);
            run_tee_bootstrap(&ctx, payload)
        })
    }

    fn is_bootstrapped(provider: &mut HashMapStorageProvider) -> bool {
        provider.enter(|storage| {
            outbe_teeregistry::TeeRegistry::new(storage)
                .is_bootstrapped()
                .unwrap()
        })
    }

    fn keys(seeds: &[u8]) -> Vec<k256::ecdsa::SigningKey> {
        seeds.iter().map(|s| tee_signing_key(*s)).collect()
    }

    fn members(keys: &[k256::ecdsa::SigningKey]) -> Vec<Address> {
        keys.iter().map(tee_evm_address).collect()
    }

    #[test]
    fn tee_bootstrap_accepts_supermajority_and_writes_registry() {
        let ks = keys(&[0x11, 0x22, 0x33, 0x44]);
        let mut provider = tee_committee_storage(5, &members(&ks));
        // 3 of 4 sign: 3*3 = 9 > 4*2 = 8.
        let payload = tee_payload(5, &ks[..3]);
        run_bootstrap(&mut provider, &payload).expect("supermajority accepted");
        assert!(is_bootstrapped(&mut provider));
    }

    /// Write an epoch-0 `CommitteeSnapshot` (as block 1's `BoundaryOutcome` would)
    /// and return its canonical V2 identity hash.
    fn write_epoch0_snapshot(provider: &mut HashMapStorageProvider, members: &[Address]) -> B256 {
        use outbe_consensus::proof::{CommitteeEntry, CommitteeSnapshot};
        let snapshot = CommitteeSnapshot {
            committee: members
                .iter()
                .enumerate()
                .map(|(i, a)| {
                    let mut pk = [7u8; 48];
                    pk[0] = i as u8;
                    CommitteeEntry {
                        address: *a,
                        consensus_pubkey: pk,
                    }
                })
                .collect(),
            vrf_material_version: 1,
            vrf_group_public_key_bytes: vec![0x11; 96],
            vrf_public_polynomial_hash: B256::ZERO,
        };
        provider.enter(|storage| {
            outbe_validatorset::state::write_committee_snapshot(storage, 0, &snapshot).unwrap();
        });
        outbe_validatorset::committee_set_hash_v2(0, &snapshot)
    }

    /// B2: a non-zero `committee_snapshot_hash` that disagrees with the on-chain
    /// epoch-0 snapshot must revert (forged committee binding rejected).
    #[test]
    fn tee_bootstrap_rejects_committee_snapshot_hash_mismatch() {
        let ks = keys(&[0x11, 0x22, 0x33, 0x44]);
        let mut provider = tee_committee_storage(5, &members(&ks));
        write_epoch0_snapshot(&mut provider, &members(&ks));
        // `tee_payload` sets committee_snapshot_hash = 0x71, which cannot equal the
        // recomputed snapshot hash, so the bind must reject.
        let payload = tee_payload(5, &ks[..3]);
        let err = run_bootstrap(&mut provider, &payload).expect_err(
            "a committee_snapshot_hash disagreeing with the on-chain snapshot must revert",
        );
        assert!(
            format!("{err:?}").contains("committee_snapshot_hash does not match"),
            "must reject on the snapshot bind, got: {err:?}"
        );
        assert!(!is_bootstrapped(&mut provider));
    }

    /// B2: a `committee_snapshot_hash` equal to the recomputed on-chain snapshot
    /// hash is accepted and the bootstrap completes.
    #[test]
    fn tee_bootstrap_accepts_matching_committee_snapshot_hash() {
        let ks = keys(&[0x11, 0x22, 0x33, 0x44]);
        let mut provider = tee_committee_storage(5, &members(&ks));
        let csh = write_epoch0_snapshot(&mut provider, &members(&ks));
        let mut payload = tee_payload(5, &ks[..3]);
        payload.committee_snapshot_hash = csh;
        // Re-sign: committee_snapshot_hash is part of the signed body.
        let signing_hash = payload.signing_hash();
        payload.validator_signatures = ks[..3]
            .iter()
            .map(|key| TeeValidatorSignature {
                validator: tee_evm_address(key),
                signature: tee_sign(key, &signing_hash),
            })
            .collect();
        run_bootstrap(&mut provider, &payload).expect("matching snapshot hash accepted");
        assert!(is_bootstrapped(&mut provider));
    }

    /// Seed the genesis teePolicy hash into `TeeRegistry` slot 2 (simulating
    /// `scripts/seed_genesis.py`), so Phase 3b enforces the allowlist.
    fn seed_genesis_policy(provider: &mut HashMapStorageProvider, policy: &TeePolicy) {
        provider.enter(|storage| {
            let reg = outbe_teeregistry::TeeRegistry::new(storage);
            reg.policy_hash.write(policy.compute_hash()).unwrap();
        });
    }

    /// A supermajority-signed payload carrying `policy` (policy_hash derived from
    /// it). The registrations use the fixed test measurements (mrsigner 0x60,
    /// mrenclave 0x50, isv_svn 1) from [`tee_registration`].
    fn tee_payload_with_policy(
        block_number: u64,
        signers: &[k256::ecdsa::SigningKey],
        policy: TeePolicy,
    ) -> TeeBootstrapPayload {
        let registrations = signers
            .iter()
            .enumerate()
            .map(|(i, key)| tee_registration(tee_evm_address(key), 0x20 + i as u8))
            .collect();
        let mut payload = TeeBootstrapPayload {
            policy_hash: policy.compute_hash(),
            committee_snapshot_hash: B256::repeat_byte(0x71),
            committee_snapshot_block: block_number,
            key_epoch: 0,
            tribute_offer_epoch: 0,
            dkg_transcript_hash: B256::repeat_byte(0x72),
            tribute_offer_public_key: B256::repeat_byte(0x73),
            tribute_offer_group_public_key: alloy_primitives::Bytes::new(),
            registrations,
            policy,
            validator_signatures: Vec::new(),
        };
        let signing_hash = payload.signing_hash();
        payload.validator_signatures = signers
            .iter()
            .map(|key| TeeValidatorSignature {
                validator: tee_evm_address(key),
                signature: tee_sign(key, &signing_hash),
            })
            .collect();
        payload
    }

    /// The policy that admits the fixed test registration measurements.
    fn matching_policy(min_isv_svn: u16) -> TeePolicy {
        TeePolicy {
            allowed_mrsigner: vec![B256::repeat_byte(0x60)],
            allowed_mrenclave: vec![B256::repeat_byte(0x50)],
            min_isv_svn,
        }
    }

    #[test]
    fn tee_bootstrap_enforces_genesis_policy_accepts_matching() {
        let ks = keys(&[0x11, 0x22, 0x33, 0x44]);
        let mut provider = tee_committee_storage(5, &members(&ks));
        let policy = matching_policy(1); // floor 1 == registration isv_svn
        seed_genesis_policy(&mut provider, &policy);
        let payload = tee_payload_with_policy(5, &ks[..3], policy);
        run_bootstrap(&mut provider, &payload).expect("policy-compliant payload accepted");
        assert!(is_bootstrapped(&mut provider));
    }

    #[test]
    fn tee_bootstrap_rejects_registration_below_isv_floor() {
        let ks = keys(&[0x11, 0x22, 0x33, 0x44]);
        let mut provider = tee_committee_storage(5, &members(&ks));
        // Floor 5 > the registration's isv_svn (1): the AND-policy must reject.
        let policy = matching_policy(5);
        seed_genesis_policy(&mut provider, &policy);
        let payload = tee_payload_with_policy(5, &ks[..3], policy);
        let err = run_bootstrap(&mut provider, &payload).unwrap_err();
        assert!(err.to_string().contains("fails genesis teePolicy"), "{err}");
        assert!(!is_bootstrapped(&mut provider));
    }

    #[test]
    fn tee_bootstrap_rejects_mrsigner_not_in_genesis_allowlist() {
        let ks = keys(&[0x11, 0x22, 0x33, 0x44]);
        let mut provider = tee_committee_storage(5, &members(&ks));
        // Genesis allows a different MRSIGNER than the registrations carry (0x60).
        let policy = TeePolicy {
            allowed_mrsigner: vec![B256::repeat_byte(0xAA)],
            allowed_mrenclave: vec![B256::repeat_byte(0x50)],
            min_isv_svn: 0,
        };
        seed_genesis_policy(&mut provider, &policy);
        let payload = tee_payload_with_policy(5, &ks[..3], policy);
        let err = run_bootstrap(&mut provider, &payload).unwrap_err();
        assert!(err.to_string().contains("fails genesis teePolicy"), "{err}");
        assert!(!is_bootstrapped(&mut provider));
    }

    #[test]
    fn tee_bootstrap_rejects_policy_hash_not_matching_genesis() {
        let ks = keys(&[0x11, 0x22, 0x33, 0x44]);
        let mut provider = tee_committee_storage(5, &members(&ks));
        // Genesis seeds policy A; the payload carries (and is signed over) policy B.
        seed_genesis_policy(&mut provider, &matching_policy(1));
        let payload = tee_payload_with_policy(5, &ks[..3], matching_policy(9));
        let err = run_bootstrap(&mut provider, &payload).unwrap_err();
        assert!(
            err.to_string().contains("does not match genesis teePolicy"),
            "{err}"
        );
        assert!(!is_bootstrapped(&mut provider));
    }

    #[test]
    fn tee_bootstrap_skips_enforcement_when_no_genesis_policy() {
        // No seeded policy (slot 2 == ZERO): a payload whose registrations carry
        // any measurements is accepted (backward-compatible PoC/dev path).
        let ks = keys(&[0x11, 0x22, 0x33, 0x44]);
        let mut provider = tee_committee_storage(5, &members(&ks));
        let payload = tee_payload_with_policy(5, &ks[..3], matching_policy(99));
        run_bootstrap(&mut provider, &payload).expect("unconfigured policy accepts");
        assert!(is_bootstrapped(&mut provider));
    }

    #[test]
    fn tee_bootstrap_rejects_below_supermajority() {
        let ks = keys(&[0x11, 0x22, 0x33, 0x44]);
        let mut provider = tee_committee_storage(5, &members(&ks));
        // 2 of 4: 2*3 = 6 <= 4*2 = 8.
        let payload = tee_payload(5, &ks[..2]);
        let err = run_bootstrap(&mut provider, &payload).unwrap_err();
        assert!(
            err.to_string()
                .contains("insufficient validator signatures"),
            "{err}"
        );
        assert!(!is_bootstrapped(&mut provider));
    }

    #[test]
    fn tee_bootstrap_rejects_tampered_signature() {
        let ks = keys(&[0x11, 0x22, 0x33]);
        let mut provider = tee_committee_storage(5, &members(&ks));
        let mut payload = tee_payload(5, &ks);
        payload.validator_signatures[0].signature[10] ^= 0xFF;
        let err = run_bootstrap(&mut provider, &payload).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("does not match declared validator")
                || msg.contains("signature recovery failed")
                || msg.contains("non-committee"),
            "{msg}"
        );
        assert!(!is_bootstrapped(&mut provider));
    }

    #[test]
    fn tee_bootstrap_rejects_non_committee_signer() {
        let ks = keys(&[0x11, 0x22, 0x33]);
        // Only the first two are registered; the third is an outsider.
        let mut provider = tee_committee_storage(5, &members(&ks[..2]));
        let payload = tee_payload(5, &ks);
        let err = run_bootstrap(&mut provider, &payload).unwrap_err();
        assert!(err.to_string().contains("non-committee"), "{err}");
        assert!(!is_bootstrapped(&mut provider));
    }

    #[test]
    fn tee_bootstrap_rejects_keys_hash_mismatch() {
        let ks = keys(&[0x11, 0x22, 0x33]);
        let mut provider = tee_committee_storage(5, &members(&ks));
        let mut payload = tee_payload(5, &ks);
        payload.registrations[1].keys_hash = B256::repeat_byte(0xAB);
        let err = run_bootstrap(&mut provider, &payload).unwrap_err();
        assert!(err.to_string().contains("keys_hash mismatch"), "{err}");
        assert!(!is_bootstrapped(&mut provider));
    }

    #[test]
    fn tee_bootstrap_rejects_registration_signature_set_mismatch() {
        let ks = keys(&[0x11, 0x22, 0x33, 0x44]);
        let mut provider = tee_committee_storage(5, &members(&ks));
        // 4 registrations + 4 valid signatures, then drop one signature so the
        // registrant set (4) and signer set (3) differ. The remaining signatures
        // stay valid (the body, hence signing_hash, is unchanged by the drop).
        let mut payload = tee_payload(5, &ks);
        payload.validator_signatures.pop();
        let err = run_bootstrap(&mut provider, &payload).unwrap_err();
        assert!(
            err.to_string().contains("cover different validator sets"),
            "{err}"
        );
        assert!(!is_bootstrapped(&mut provider));
    }

    #[test]
    fn tee_bootstrap_is_idempotent_one_shot() {
        let ks = keys(&[0x11, 0x22, 0x33]);
        let mut provider = tee_committee_storage(5, &members(&ks));
        let payload = tee_payload(5, &ks);
        run_bootstrap(&mut provider, &payload).expect("first bootstrap accepted");
        assert!(is_bootstrapped(&mut provider));
        let err = run_bootstrap(&mut provider, &payload).unwrap_err();
        assert!(err.to_string().contains("already bootstrapped"), "{err}");
    }

    #[test]
    fn tee_bootstrap_rejects_wrong_snapshot_block() {
        let ks = keys(&[0x11, 0x22, 0x33]);
        let mut provider = tee_committee_storage(5, &members(&ks));
        // Body binds committee_snapshot_block = 99, but the current block is 5.
        let payload = tee_payload(99, &ks);
        let err = run_bootstrap(&mut provider, &payload).unwrap_err();
        assert!(
            err.to_string().contains("committee_snapshot_block"),
            "{err}"
        );
        assert!(!is_bootstrapped(&mut provider));
    }

    #[test]
    fn tee_bootstrap_rejects_empty_committee() {
        let ks = keys(&[0x11, 0x22, 0x33]);
        // Config present but no registered validators -> empty consensus set.
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        provider.set_block_number(5);
        provider.set_timestamp(U256::from(5u64));
        provider.set_beneficiary(OWNER);
        provider.enter(|storage| {
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            vs.config_owner.write(OWNER).unwrap();
            vs.config_max_validators.write(128).unwrap();
            vs.config_epoch_length_blocks.write(10).unwrap();
        });
        let payload = tee_payload(5, &ks);
        let err = run_bootstrap(&mut provider, &payload).unwrap_err();
        assert!(
            err.to_string().contains("no active consensus committee"),
            "{err}"
        );
        assert!(!is_bootstrapped(&mut provider));
    }

    /// Phase 7b glue: `run_late_finalize_credits` at block `N+K` closes the
    /// matured window — pays the escrowed voters, marks `fee_settled`, and routes
    /// the unpaid residue to terminal Metadosis emission headroom.
    /// Uses an empty credit artifact so the assertion isolates the
    /// `settle_matured` + residue-recycle wiring (the BLS batch path is covered
    /// by the verifier and `late_settlement` unit tests).
    #[test]
    fn late_finalize_window_close_settles_and_recycles_residue() {
        use outbe_primitives::addresses::REWARDS_ADDRESS;

        const V0: Address = address!("0x00000000000000000000000000000000000000A0");
        const V1: Address = address!("0x00000000000000000000000000000000000000A1");
        const V2: Address = address!("0x00000000000000000000000000000000000000A2");
        const V3: Address = address!("0x00000000000000000000000000000000000000A3");
        let fb_hash = B256::repeat_byte(0xAB);
        let timestamp = 1_700_000_000u64;

        // Block N+K = 13 settles block N = 10 (K = LATE_FINALIZE_WINDOW_K = 3).
        let mut provider = configured_storage(13, timestamp);
        provider.enter(|storage| {
            let ctx = runtime_ctx(storage);

            let committee_size = 4u32;
            let pool = U256::from(4_000u64); // divisible by committee
            ctx.storage.increase_balance(REWARDS_ADDRESS, pool).unwrap();
            // Escrow block 10; only 3 of 4 voters credited at k=0 (one absent).
            outbe_rewards::late_settlement::escrow_block_fee(
                &ctx,
                10,
                fb_hash,
                pool,
                committee_size,
                0, // epoch
                0, // view
                0, // parent_view
                B256::ZERO,
                &[V0, V1, V2],
            )
            .unwrap();

            // Empty artifact: the mandatory phase still closes block 10's window.
            run_late_finalize_credits(&ctx, &LateFinalizeCreditsArtifact::default()).unwrap();

            let each = pool / U256::from(committee_size); // 1000, unchanged by exclusion
            assert_eq!(ctx.storage.balance(V0).unwrap(), each);
            assert_eq!(ctx.storage.balance(V1).unwrap(), each);
            assert_eq!(ctx.storage.balance(V2).unwrap(), each);
            assert_eq!(
                ctx.storage.balance(V3).unwrap(),
                U256::ZERO,
                "absent voter earns nothing"
            );
            // distributed (3·each) left REWARDS; residue (each) burned for parity.
            assert_eq!(
                ctx.storage.balance(REWARDS_ADDRESS).unwrap(),
                U256::ZERO,
                "REWARDS fully drained (3 paid + residue burned)"
            );
            assert!(
                ctx.storage
                    .contract::<outbe_rewards::schema::Rewards>()
                    .fee_settled
                    .read(&fb_hash)
                    .unwrap(),
                "window marked settled"
            );

            // Residue recycled into terminal Metadosis emission headroom. The
            // terminal sink now keys the credit on the WorldwideDay record
            // (UTC+14) for the block timestamp, i.e. date_key(timestamp + UTC+14).
            use outbe_metadosis::schema::WorldwideDayEntryExt;
            let wwd = outbe_metadosis::runtime::timestamp_to_date_key(
                timestamp + outbe_metadosis::constants::UTC_PLUS_14_OFFSET,
            );
            let recorded = ctx
                .contract::<outbe_metadosis::schema::MetadosisContract>()
                .worldwide_days
                .entry(wwd.into())
                .metadosis_limit_amount()
                .read()
                .unwrap();
            assert_eq!(recorded, each, "residue routed to terminal Metadosis");
        });
    }

    /// at the inclusion-window close, a registered committee member
    /// that never voted within `K` (`committee \ credited`) gets a voter miss
    /// recorded in BOTH counters; a credited member does not. Proves the relocated,
    /// now-punitive miss accounting runs against the FINAL credited set.
    #[test]
    fn window_close_records_miss_for_absent_committee_voter_only() {
        use outbe_validatorset::{CommitteeEntry, CommitteeSnapshot};

        const V0: Address = address!("0x00000000000000000000000000000000000000B0");
        const V1: Address = address!("0x00000000000000000000000000000000000000B1");
        let timestamp = 1_700_000_000u64;
        let epoch = 0u64;
        let fb_hash = B256::repeat_byte(0xE8);

        // Block N+K = 13 closes block N = 10 (K = LATE_FINALIZE_WINDOW_K = 3).
        let mut provider = configured_storage(13, timestamp);
        provider.enter(|storage| {
            // Register both committee members so the strict registered-validator
            // contract of `record_finalized_participation` accepts them.
            {
                let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
                vs.register_validator(OWNER, V0, &[0xB0; 48]).unwrap();
                vs.activate_validator(V0).unwrap();
                vs.register_validator(OWNER, V1, &[0xB1; 48]).unwrap();
                vs.activate_validator(V1).unwrap();
            }

            // Committee snapshot [V0, V1] under (epoch, csh); escrow must bind csh.
            let snapshot = CommitteeSnapshot {
                committee: vec![
                    CommitteeEntry {
                        address: V0,
                        consensus_pubkey: [0xC0; 48],
                    },
                    CommitteeEntry {
                        address: V1,
                        consensus_pubkey: [0xC1; 48],
                    },
                ],
                vrf_material_version: 1,
                vrf_group_public_key_bytes: vec![0x11; 96],
                vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
            };
            let csh = outbe_validatorset::committee_set_hash_v2(epoch, &snapshot);
            outbe_validatorset::write_committee_snapshot(storage.clone(), epoch, &snapshot)
                .unwrap();

            let ctx = runtime_ctx(storage);
            // Escrow block 10: committee of 2; only V0 credited at k=0 (V1 absent).
            ctx.storage
                .increase_balance(
                    outbe_primitives::addresses::REWARDS_ADDRESS,
                    U256::from(2_000u64),
                )
                .unwrap();
            outbe_rewards::late_settlement::escrow_block_fee(
                &ctx,
                10,
                fb_hash,
                U256::from(2_000u64),
                2,
                epoch,
                0,
                0,
                csh,
                &[V0],
            )
            .unwrap();

            // Close block 10's window: the absentee pass runs before settle.
            run_late_finalize_credits(&ctx, &LateFinalizeCreditsArtifact::default()).unwrap();

            let si = outbe_slashindicator::contract::SlashIndicator::new(ctx.storage.clone());
            assert_eq!(
                si.get_voter_miss_count(V1).unwrap(),
                1,
                "absent committee voter is counted missed at window close"
            );
            assert_eq!(
                si.get_voter_miss_count(V0).unwrap(),
                0,
                "credited voter is not counted missed"
            );
            let vs = outbe_validatorset::contract::ValidatorSet::new(ctx.storage.clone());
            assert_eq!(vs.val_missed_votes.read(&V1).unwrap(), 1);
            assert_eq!(vs.val_missed_votes.read(&V0).unwrap(), 0);

            // Replay the closed window: settle freed the escrow and the per-fb_hash
            // guards short-circuit, so re-running must not double-count.
            run_late_finalize_credits(&ctx, &LateFinalizeCreditsArtifact::default()).unwrap();
            assert_eq!(
                si.get_voter_miss_count(V1).unwrap(),
                1,
                "replay must not double-count the absentee miss"
            );
            assert_eq!(vs.val_missed_votes.read(&V1).unwrap(), 1);
        });
    }

    /// Determinism: the window-close absentee pass is computed purely from committed
    /// chain state (committee snapshot + `late_voter_*`) in committee order, with no
    /// proposer-chosen input — so two independent executions of the same closed
    /// window reach byte-identical slashing state (the proposer/validator guarantee).
    /// Multiple absentees exercise ordering.
    #[test]
    fn window_close_absentee_pass_is_deterministic_and_correct() {
        use outbe_validatorset::{CommitteeEntry, CommitteeSnapshot};

        const C0: Address = address!("0x00000000000000000000000000000000000000C0");
        const C1: Address = address!("0x00000000000000000000000000000000000000C1");
        const C2: Address = address!("0x00000000000000000000000000000000000000C2");
        const C3: Address = address!("0x00000000000000000000000000000000000000C3");
        let epoch = 0u64;
        let fb_hash = B256::repeat_byte(0xD7);
        let members = [C0, C1, C2, C3];

        let run = || -> Vec<(u64, u64)> {
            let mut provider = configured_storage(13, 1_700_000_000);
            let mut out = Vec::new();
            provider.enter(|storage| {
                {
                    let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
                    for (i, a) in members.iter().enumerate() {
                        vs.register_validator(OWNER, *a, &[0xC0u8 + i as u8; 48])
                            .unwrap();
                        vs.activate_validator(*a).unwrap();
                    }
                }
                let snapshot = CommitteeSnapshot {
                    committee: members
                        .iter()
                        .enumerate()
                        .map(|(i, a)| CommitteeEntry {
                            address: *a,
                            consensus_pubkey: [0xD0u8 + i as u8; 48],
                        })
                        .collect(),
                    vrf_material_version: 1,
                    vrf_group_public_key_bytes: vec![0x11; 96],
                    vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
                };
                let csh = outbe_validatorset::committee_set_hash_v2(epoch, &snapshot);
                outbe_validatorset::write_committee_snapshot(storage.clone(), epoch, &snapshot)
                    .unwrap();

                let ctx = runtime_ctx(storage);
                ctx.storage
                    .increase_balance(
                        outbe_primitives::addresses::REWARDS_ADDRESS,
                        U256::from(4_000u64),
                    )
                    .unwrap();
                // Credit C0 and C2 at k=0; C1 and C3 absent.
                outbe_rewards::late_settlement::escrow_block_fee(
                    &ctx,
                    10,
                    fb_hash,
                    U256::from(4_000u64),
                    4,
                    epoch,
                    0,
                    0,
                    csh,
                    &[C0, C2],
                )
                .unwrap();

                run_late_finalize_credits(&ctx, &LateFinalizeCreditsArtifact::default()).unwrap();

                let si = outbe_slashindicator::contract::SlashIndicator::new(ctx.storage.clone());
                let vs = outbe_validatorset::contract::ValidatorSet::new(ctx.storage.clone());
                for a in members {
                    out.push((
                        si.get_voter_miss_count(a).unwrap(),
                        vs.val_missed_votes.read(&a).unwrap(),
                    ));
                }
            });
            out
        };

        let first = run();
        let second = run();
        assert_eq!(
            first, second,
            "window-close absentee pass must be deterministic across executions"
        );
        // C0, C2 credited → no miss; C1, C3 absent → miss in both counters.
        assert_eq!(
            first,
            vec![(0, 0), (1, 1), (0, 0), (1, 1)],
            "only the two absent committee members are missed"
        );
    }

    /// Epoch-boundary ordering: the per-epoch reset runs in
    /// `apply_pre_execution_changes` (pre-block hooks, executor.rs:2204) BEFORE the
    /// begin-zone `LateFinalizeCredits` body tx (executor.rs: "begin-zone phases
    /// execute when their body transaction reaches the loop"). This test mirrors
    /// that order — reset, then window close — and proves the absentee's window-close
    /// miss is recorded in the new epoch (NOT wiped); a prior epoch's accumulation is
    /// reset first.
    #[test]
    fn window_close_miss_survives_epoch_boundary_reset() {
        use outbe_validatorset::{CommitteeEntry, CommitteeSnapshot};

        const A: Address = address!("0x00000000000000000000000000000000000000E0"); // credited
        const B: Address = address!("0x00000000000000000000000000000000000000E1"); // absent
        let epoch = 0u64;
        let fb_hash = B256::repeat_byte(0xE9);

        // Block 13 is an epoch boundary: configured_storage sets epoch_length=10,
        // epoch_start=0, so `is_epoch_boundary(13)` is true (13 >= 0 + 10).
        let mut provider = configured_storage(13, 1_700_000_000);
        provider.enter(|storage| {
            {
                let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
                vs.register_validator(OWNER, A, &[0xE0; 48]).unwrap();
                vs.activate_validator(A).unwrap();
                vs.register_validator(OWNER, B, &[0xE1; 48]).unwrap();
                vs.activate_validator(B).unwrap();
            }
            let snapshot = CommitteeSnapshot {
                committee: vec![
                    CommitteeEntry {
                        address: A,
                        consensus_pubkey: [0xF0; 48],
                    },
                    CommitteeEntry {
                        address: B,
                        consensus_pubkey: [0xF1; 48],
                    },
                ],
                vrf_material_version: 1,
                vrf_group_public_key_bytes: vec![0x11; 96],
                vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
            };
            let csh = outbe_validatorset::committee_set_hash_v2(epoch, &snapshot);
            outbe_validatorset::write_committee_snapshot(storage.clone(), epoch, &snapshot)
                .unwrap();

            let ctx = runtime_ctx(storage);
            ctx.storage
                .increase_balance(
                    outbe_primitives::addresses::REWARDS_ADDRESS,
                    U256::from(2_000u64),
                )
                .unwrap();
            outbe_rewards::late_settlement::escrow_block_fee(
                &ctx,
                10,
                fb_hash,
                U256::from(2_000u64),
                2,
                epoch,
                0,
                0,
                csh,
                &[A],
            )
            .unwrap();

            // B carries 5 misses accumulated earlier in the epoch.
            {
                let si = outbe_slashindicator::contract::SlashIndicator::new(ctx.storage.clone());
                si.voter_miss_count.write(&B, 5).unwrap();
            }

            // Real begin-zone order at an epoch-boundary block: pre-block reset first…
            {
                let mut si =
                    outbe_slashindicator::contract::SlashIndicator::new(ctx.storage.clone());
                si.reset_epoch_counters(&[A, B]).unwrap();
            }
            // …then the begin-zone window-close increments.
            run_late_finalize_credits(&ctx, &LateFinalizeCreditsArtifact::default()).unwrap();

            let si = outbe_slashindicator::contract::SlashIndicator::new(ctx.storage.clone());
            assert_eq!(
                si.get_voter_miss_count(B).unwrap(),
                1,
                "absentee miss is recorded AFTER the reset (survives), not lost"
            );
            assert_eq!(si.get_voter_miss_count(A).unwrap(), 0);
        });
    }

    fn dummy_credit(fb_number: u64) -> outbe_primitives::reshare_artifact::PerBlockCredit {
        outbe_primitives::reshare_artifact::PerBlockCredit {
            fb_number,
            fb_hash: B256::repeat_byte(0xCD),
            epoch: 0,
            view: 9,
            parent_view: 8,
            committee_set_hash: B256::repeat_byte(0xEF),
            signer_bitmap: vec![0x01],
            aggregate_signature: [0u8; 96],
        }
    }

    /// #2 defense-in-depth: a body credit whose target is outside the K-block
    /// inclusion window is FATAL (rejected before the snapshot read / BLS verify,
    /// so no snapshot seeding is needed). distance = 13 - 5 = 8 > K = 3.
    #[test]
    fn late_finalize_out_of_window_credit_is_fatal() {
        let mut provider = configured_storage(13, 1_700_000_000);
        provider.enter(|storage| {
            let ctx = runtime_ctx(storage);
            let artifact = LateFinalizeCreditsArtifact {
                batches: vec![dummy_credit(5)],
            };
            let err = run_late_finalize_credits(&ctx, &artifact).unwrap_err();
            assert!(
                matches!(err, PrecompileError::Fatal(_)),
                "out-of-window credit must be Fatal, got {err:?}"
            );
            assert!(
                err.to_string().contains("outside inclusion window"),
                "{err}"
            );
        });
    }

    /// bad/unverifiable proof: an in-window, escrow-authenticated credit whose
    /// committee snapshot does not exist is FATAL (the block aborts — never a soft
    /// receipt). distance = 13 - 11 = 2 (in window); the escrow binding matches so
    /// authentication passes and the snapshot lookup is reached and fails.
    #[test]
    fn late_finalize_unverifiable_credit_is_fatal() {
        let mut provider = configured_storage(13, 1_700_000_000);
        provider.enter(|storage| {
            let ctx = runtime_ctx(storage);
            let credit = dummy_credit(11);
            // Seed an escrow binding that matches the credit so it passes
            // authentication and reaches the (missing) snapshot lookup.
            outbe_rewards::late_settlement::escrow_block_fee(
                &ctx,
                credit.fb_number,
                credit.fb_hash,
                U256::from(1_000u64),
                4,
                credit.epoch,
                credit.view,
                credit.parent_view,
                credit.committee_set_hash,
                &[],
            )
            .unwrap();
            let artifact = LateFinalizeCreditsArtifact {
                batches: vec![credit],
            };
            let err = run_late_finalize_credits(&ctx, &artifact).unwrap_err();
            assert!(
                matches!(err, PrecompileError::Fatal(_)),
                "unverifiable credit must be Fatal, got {err:?}"
            );
            assert!(
                err.to_string().contains("missing committee snapshot"),
                "{err}"
            );
        });
    }

    /// a credit referencing a finalized block with no
    /// escrow is rejected (the in-window distance passes, but there is nothing to
    /// authenticate against).
    #[test]
    fn no_escrow_credit_rejected() {
        let mut provider = configured_storage(13, 1_700_000_000);
        provider.enter(|storage| {
            let ctx = runtime_ctx(storage);
            let artifact = LateFinalizeCreditsArtifact {
                batches: vec![dummy_credit(11)], // in window, but no escrow seeded
            };
            let err = run_late_finalize_credits(&ctx, &artifact).unwrap_err();
            assert!(err.to_string().contains("no escrow for fb_number"), "{err}");
        });
    }

    /// Seed an escrow binding `(11 -> fb_hash 0xCD, epoch 7, csh 0xEF)` and run a
    /// credit that mismatches one field — each must be FATAL.
    fn assert_auth_mismatch_fatal(
        mut mutate: impl FnMut(&mut outbe_primitives::reshare_artifact::PerBlockCredit),
        needle: &str,
    ) {
        let mut provider = configured_storage(13, 1_700_000_000);
        provider.enter(|storage| {
            let ctx = runtime_ctx(storage);
            // Canonical escrow for fb_number 11 (view/parent_view match dummy_credit).
            outbe_rewards::late_settlement::escrow_block_fee(
                &ctx,
                11,
                B256::repeat_byte(0xCD),
                U256::from(1_000u64),
                4,
                7, // epoch
                9, // view (dummy_credit default)
                8, // parent_view (dummy_credit default)
                B256::repeat_byte(0xEF),
                &[],
            )
            .unwrap();
            // Also escrow fb_number 12 (a different block) so a spoofed fb_number
            // hits a populated-but-wrong binding rather than an empty one.
            outbe_rewards::late_settlement::escrow_block_fee(
                &ctx,
                12,
                B256::repeat_byte(0xAA),
                U256::from(1_000u64),
                4,
                7, // epoch
                9, // view
                8, // parent_view
                B256::repeat_byte(0xEF),
                &[],
            )
            .unwrap();
            let mut credit = dummy_credit(11); // fb_hash 0xCD, epoch 0, csh 0xEF
            credit.epoch = 7; // match canonical unless the test overrides
            mutate(&mut credit);
            let artifact = LateFinalizeCreditsArtifact {
                batches: vec![credit],
            };
            let err = run_late_finalize_credits(&ctx, &artifact).unwrap_err();
            assert!(err.to_string().contains(needle), "{err}");
        });
    }

    /// BUG-2: spoofing `fb_number` (to shrink `k`) hits a wrong fb_hash binding.
    #[test]
    fn fb_number_mismatch_rejected() {
        // Real block (fb_hash 0xCD) is escrowed at 11; proposer claims fb_number
        // 12 (in window, distance 1) where a different block (0xAA) is escrowed.
        assert_auth_mismatch_fatal(|c| c.fb_number = 12, "fb_hash mismatch");
    }

    /// BUG-5: wrong epoch is rejected.
    #[test]
    fn wrong_epoch_rejected() {
        assert_auth_mismatch_fatal(|c| c.epoch = 9, "epoch mismatch");
    }

    /// BUG-5: wrong committee_set_hash is rejected.
    #[test]
    fn wrong_committee_set_hash_rejected() {
        assert_auth_mismatch_fatal(
            |c| c.committee_set_hash = B256::repeat_byte(0x99),
            "committee_set_hash mismatch",
        );
    }

    /// Review #1b (full binding): a credit with correct fb_number/fb_hash/epoch/
    /// committee_set_hash but a non-canonical `view` is rejected at body auth —
    /// closing the cross-view equivocation credit the pre-exec BLS verify (which
    /// only ties the credit's view to its signatures) would otherwise let through.
    #[test]
    fn wrong_view_rejected() {
        assert_auth_mismatch_fatal(|c| c.view = 99, "view mismatch");
    }

    /// Review #1b (full binding): a non-canonical `parent_view` is rejected.
    #[test]
    fn wrong_parent_view_rejected() {
        assert_auth_mismatch_fatal(|c| c.parent_view = 99, "parent_view mismatch");
    }
}
