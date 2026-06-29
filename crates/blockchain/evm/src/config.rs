//! Outbe EVM config — wraps `EthEvmConfig<ChainSpec, OutbeEvmFactory>` and
//! replaces the executor factory so that every block goes through
//! [`OutbeBlockExecutor`] instead of [`EthBlockExecutor`] directly.

use alloy_consensus::Transaction as _;
use alloy_evm::{
    block::{BlockExecutorFactory, StateDB},
    eth::{EthBlockExecutionCtx, NextEvmEnvAttributes},
    EvmEnv, RecoveredTx,
};
use alloy_primitives::{Address, Bytes, B256};
use reth_ethereum::evm::revm::inspector::Inspector;
use reth_ethereum::{
    chainspec::{ChainSpec, EthChainSpec},
    evm::{
        primitives::{Database, EvmEnvFor, ExecutionCtxFor, InspectorFor, NextBlockEnvAttributes},
        revm::{db::State, primitives::hardfork::SpecId},
        EthBlockAssembler, EthEvmConfig,
    },
    node::{
        api::{ConfigureEngineEvm, ConfigureEvm, ExecutableTxIterator, FullNodeTypes, NodeTypes},
        builder::{components::ExecutorBuilder, BuilderContext},
    },
    Receipt, TransactionSigned,
};
use reth_evm::{
    execute::{BlockAssembler, BlockAssemblerInput, BlockBuilder, BlockExecutionError},
    EvmFor,
};
use reth_primitives_traits::{
    AlloyBlockHeader as _, Recovered, SealedBlock, SealedHeader, SignedTransaction as _,
};
use reth_provider::HeaderProvider;
use reth_rpc_eth_api::helpers::pending_block::BuildPendingEnv;
use std::{convert::Infallible, sync::Arc};

use outbe_primitives::{
    consensus::ConsensusExecutionBridge,
    consensus_metadata::CertifiedParentAccountingMetadata,
    reshare_artifact::{
        decode_outbe_block_artifacts, encode_outbe_block_artifacts, ConsensusHeaderArtifact,
        OutbeBlockArtifacts,
    },
    OutbeBlock, OutbeExecutionData, OutbeHeader, OutbePrimitives,
};

use crate::{
    builder::OutbeBlockBuilder,
    executor::{AccountedParentArtifact, AccountedParentArtifactProvider, OutbeBlockExecutor},
    factory::OutbeEvmFactory,
    signer::SharedOutbeEvmSigner,
    system_tx::{
        build_unsigned_system_tx, split_system_layout, validate_active_system_tx_set,
        SystemTxInputV2, SystemTxKind,
    },
};

/// cache-side helper. Pulls an exact `(block_number, block_hash)`
/// entry from the consensus bridge's execution-summary cache.
fn cached_accounted_parent_artifact(
    summary_cache: &ConsensusExecutionBridge,
    block_number: u64,
    block_hash: B256,
) -> Option<AccountedParentArtifact> {
    summary_cache
        .cached_execution_summary(block_number, block_hash)
        .map(|cached| AccountedParentArtifact {
            summary: cached.summary,
            timestamp: cached.timestamp,
        })
}

/// bridge-only [`AccountedParentArtifactProvider`]. Returns the
/// cached `(block_number, block_hash)` entry from the consensus bridge.
/// Used in proposer/validator modes where the bridge is available but no
/// Reth provider has been wired (legacy `new_with_bridge` constructor).
#[derive(Clone)]
struct BridgeAccountedParentArtifactProvider {
    summary_cache: ConsensusExecutionBridge,
}

impl BridgeAccountedParentArtifactProvider {
    fn new(summary_cache: ConsensusExecutionBridge) -> Self {
        Self { summary_cache }
    }
}

impl AccountedParentArtifactProvider for BridgeAccountedParentArtifactProvider {
    fn execution_summary_by_hash(
        &self,
        block_number: u64,
        block_hash: B256,
    ) -> Result<Option<AccountedParentArtifact>, reth_evm::execute::ProviderError> {
        Ok(cached_accounted_parent_artifact(
            &self.summary_cache,
            block_number,
            block_hash,
        ))
    }
}

/// composite [`AccountedParentArtifactProvider`] backed by a Reth
/// [`HeaderProvider`] with an optional consensus-bridge cache layered on top.
///
/// Lookup order (per trait contract):
/// 1. Exact `(block_number, block_hash)` cache hit (when `summary_cache` is
///    present).
/// 2. `provider.sealed_header_by_hash(block_hash)` — exact-hash, tree-state
///    aware. Caller of [`HeaderProvider::sealed_header_by_hash`] sees both
///    canonical AND unfinalized side-chain headers, so this branch is the
///    primary V2 path and resolves correctly across reorgs.
/// 3. Canonical-by-number `sealed_header(block_number)` ONLY when its hash
///    equals `block_hash` (explicit double-check). This is a defence-in-depth
///    branch for providers whose `sealed_header_by_hash` default impl is
///    overridden to return `None` for canonical entries.
///
/// **Visibility-miss normalization**: the trait contract for
/// `execution_summary_by_hash` says `Ok(None)` means "I do not currently have
/// this parent". Reth's `HeaderProvider` surfaces a not-yet-visible header as
/// `Err(ProviderError::HeaderNotFound)` (e.g. during the FCU-Valid → MDBX-commit
/// race, when consensus has finalized the parent but Reth has not persisted
/// the sealed header yet). Both provider branches normalize that variant to
/// `Ok(None)` so the executor's checked `parent_artifact_hint` fallback can
/// engage. Other `Err` variants (real I/O / database corruption) propagate.
///
/// Construction: pass `Some(cache)` to keep the bridge fast-path, or `None`
/// for full-node mode (no consensus bridge, provider-backed only).
#[derive(Clone)]
pub struct RethAccountedParentArtifactProvider<P> {
    provider: P,
    summary_cache: Option<ConsensusExecutionBridge>,
}

impl<P> RethAccountedParentArtifactProvider<P> {
    pub fn new(provider: P, summary_cache: Option<ConsensusExecutionBridge>) -> Self {
        Self {
            provider,
            summary_cache,
        }
    }

    fn cached_artifact(
        &self,
        block_number: u64,
        block_hash: B256,
    ) -> Option<AccountedParentArtifact> {
        self.summary_cache
            .as_ref()
            .and_then(|cache| cached_accounted_parent_artifact(cache, block_number, block_hash))
    }
}

impl<P> AccountedParentArtifactProvider for RethAccountedParentArtifactProvider<P>
where
    P: HeaderProvider<Header = OutbeHeader> + Clone + Send + Sync + 'static,
{
    fn execution_summary_by_hash(
        &self,
        block_number: u64,
        block_hash: B256,
    ) -> Result<Option<AccountedParentArtifact>, reth_evm::execute::ProviderError> {
        // (1) Cache hit — exact `(block_number, block_hash)` only.
        if let Some(cached) = self.cached_artifact(block_number, block_hash) {
            return Ok(Some(cached));
        }

        // (2) Exact-hash provider lookup. Sees tree-state, so unfinalized
        // side-chain parents are resolvable as long as the import path has
        // already inserted the header. During the FCU-Valid → MDBX-commit
        // race the provider may surface `HeaderNotFound`; the trait
        // contract treats that as a visibility miss (`Ok(None)`), letting
        // the executor fall through to its checked `parent_artifact_hint`.
        match self.provider.sealed_header_by_hash(block_hash) {
            Ok(Some(sealed)) => {
                // `(block_number, block_hash)` must match the resolved
                // header. A header whose number diverges from the metadata is
                // a protocol violation — reject loudly rather than silently
                // using a wrong block. This is NOT a visibility miss.
                if sealed.header().number() != block_number {
                    return Err(reth_evm::execute::ProviderError::HeaderNotFound(
                        block_hash.into(),
                    ));
                }
                return Ok(decode_accounted_parent_artifact(sealed.header()));
            }
            Ok(None) => {}
            Err(reth_evm::execute::ProviderError::HeaderNotFound(_)) => {}
            Err(error) => return Err(error),
        }

        // (3) Canonical-by-number fallback — gated by explicit hash equality
        //. If the canonical entry at `block_number` does not hash to
        // `block_hash`, return `Ok(None)`. The caller (executor) maps `None`
        // to a `BlockExecutionError` — never a silent wrong-parent acceptance.
        // `HeaderNotFound` here is also a visibility miss; other `Err`
        // variants propagate.
        match self.provider.sealed_header(block_number) {
            Ok(Some(sealed)) => {
                if sealed.hash() == block_hash {
                    return Ok(decode_accounted_parent_artifact(sealed.header()));
                }
            }
            Ok(None) => {}
            Err(reth_evm::execute::ProviderError::HeaderNotFound(_)) => {}
            Err(error) => return Err(error),
        }

        Ok(None)
    }
}

/// decode `OutbeBlockArtifacts.execution_summary` from
/// `header.extra_data` and pair it with the header timestamp. Returns
/// `None` if the artifact bytes don't decode (invalid header) or if the
/// header carries no `execution_summary` field.
fn decode_accounted_parent_artifact(header: &OutbeHeader) -> Option<AccountedParentArtifact> {
    let artifacts = decode_outbe_block_artifacts(header.extra_data().as_ref()).ok()?;
    artifacts
        .execution_summary
        .map(|summary| AccountedParentArtifact {
            summary,
            timestamp: header.timestamp(),
        })
}

/// Execution context for an Outbe block. The inner Ethereum context keeps the
/// EVM path unchanged; the millis remainder is only used when assembling the
/// Outbe header.
#[derive(Debug, Clone)]
pub struct OutbeBlockExecutionCtx<'a> {
    pub inner: EthBlockExecutionCtx<'a>,
    pub timestamp_millis_part: u64,
    pub block_hash: Option<B256>,
    pub expected_begin_system_txs: Vec<Recovered<TransactionSigned>>,
    pub expected_end_system_txs: Vec<Recovered<TransactionSigned>>,
    pub system_layout_error: Option<String>,
    pub parent_consensus_metadata: Option<CertifiedParentAccountingMetadata>,
    pub proposer_evm_address: Option<Address>,
    /// Whether Outbe consensus-critical block hooks and system txs should run.
    /// Disabled only for Reth's local pending-block RPC construction, which lacks
    /// consensus-only parent certificate and proposer context.
    pub execute_outbe_block_hooks: bool,
    /// proposer-side Phase 1 (CertifiedParentAccounting) body[0] tx
    /// signed by the payload builder BEFORE `apply_pre_execution_changes`. When
    /// set, the executor reuses it byte-for-byte as the Phase 1 commit witness
    /// (so the pre-exec receipt and the body[0] tx are guaranteed identical).
    /// `None` on the validator path (body[0] arrives through
    /// `expected_begin_system_txs`) and for `block_number <= GENESIS_BOOTSTRAP_BLOCK_NUMBER`.
    pub prebuilt_phase1_tx: Option<Recovered<TransactionSigned>>,
    /// optional accounted-parent artifact hint supplied by the
    /// payload builder (or import driver) when the executor's
    /// [`AccountedParentArtifactProvider`] cannot see the parent header in
    /// tree state. The executor accepts the hint ONLY when the metadata's
    /// `(finalized_block_number, finalized_block_hash)` matches
    /// `(self.parent_block_number, self.parent_hash)` and the artifact bytes
    /// decode cleanly. `None` on the validator path (provider always
    /// has the sealed block) and on the proposer path when the bridge cache
    /// already holds the artifact.
    pub parent_artifact_hint: Option<crate::executor::AccountedParentArtifact>,
    /// optional one-time Phase 3b `TeeBootstrap` payload supplied by the
    /// proposer's tribute-DKG bootstrap producer once the ceremony completes and
    /// the `TeeRegistry` is still empty. `None` on every block until then and on
    /// the validator path (the body carries the bootstrap, read via
    /// `expected_begin_system_txs`). Flows into the executor and into
    /// `build_begin_system_txs` so both proposer paths inject it identically.
    pub pending_tee_bootstrap: Option<outbe_primitives::tee_bootstrap::TeeBootstrapPayload>,
}

/// Attributes needed to construct the next Outbe block.
#[derive(Debug, Clone)]
pub struct OutbeNextBlockEnvAttributes {
    pub inner: NextBlockEnvAttributes,
    pub timestamp_millis_part: u64,
    pub parent_consensus_metadata: Option<CertifiedParentAccountingMetadata>,
    pub proposer_evm_address: Option<Address>,
    /// False only for local pending-block RPC construction.
    pub execute_outbe_block_hooks: bool,
    /// optional prebuilt Phase 1 tx supplied by the proposer payload
    /// builder. Flows into [`OutbeBlockExecutionCtx::prebuilt_phase1_tx`].
    pub prebuilt_phase1_tx: Option<Recovered<TransactionSigned>>,
    /// optional accounted-parent artifact hint. Flows into
    /// [`OutbeBlockExecutionCtx::parent_artifact_hint`]; see field docs there
    /// for executor-side acceptance rules.
    pub parent_artifact_hint: Option<crate::executor::AccountedParentArtifact>,
    /// optional one-time Phase 3b `TeeBootstrap` payload from the proposer's
    /// tribute-DKG bootstrap producer. Flows into
    /// [`OutbeBlockExecutionCtx::pending_tee_bootstrap`].
    pub pending_tee_bootstrap: Option<outbe_primitives::tee_bootstrap::TeeBootstrapPayload>,
}

impl BuildPendingEnv<OutbeHeader> for OutbeNextBlockEnvAttributes {
    fn build_pending_env(parent: &SealedHeader<OutbeHeader>) -> Self {
        let mut inner = NextBlockEnvAttributes::build_pending_env(parent);
        inner.suggested_fee_recipient = outbe_primitives::addresses::REWARDS_ADDRESS;
        Self {
            inner,
            timestamp_millis_part: parent.timestamp_millis_part(),
            parent_consensus_metadata: None,
            proposer_evm_address: None,
            execute_outbe_block_hooks: false,
            prebuilt_phase1_tx: None,
            parent_artifact_hint: None,
            pending_tee_bootstrap: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutbeBlockAssembler {
    inner: EthBlockAssembler<ChainSpec<OutbeHeader>>,
}

impl OutbeBlockAssembler {
    pub fn new(chain_spec: Arc<ChainSpec<OutbeHeader>>) -> Self {
        Self {
            inner: EthBlockAssembler::new(chain_spec),
        }
    }
}

impl BlockAssembler<OutbeEvmConfig> for OutbeBlockAssembler {
    type Block = OutbeBlock;

    fn assemble_block(
        &self,
        input: BlockAssemblerInput<'_, '_, OutbeEvmConfig, OutbeHeader>,
    ) -> Result<Self::Block, BlockExecutionError> {
        let BlockAssemblerInput {
            evm_env,
            execution_ctx,
            parent,
            transactions,
            output,
            bundle_state,
            state_provider,
            state_root,
            ..
        } = input;

        let parent = SealedHeader::new_unhashed(parent.clone().into_header().into_inner());

        let block = self.inner.assemble_block(BlockAssemblerInput::<
            alloy_evm::eth::EthBlockExecutorFactory<
                reth_ethereum::evm::RethReceiptBuilder,
                Arc<ChainSpec<OutbeHeader>>,
                OutbeEvmFactory,
            >,
        >::new(
            evm_env,
            execution_ctx.inner,
            &parent,
            transactions,
            output,
            bundle_state,
            state_provider,
            state_root,
        ))?;

        // `inner.extra_data` already encodes `timestamp_millis_part`
        // (under tag 0x05) — see `OutbeBlockBuilder::finish` in
        // `crates/blockchain/evm/src/builder.rs`. The wrapper carries
        // no extra RLP fields, so the resulting block hash is exactly
        // `keccak256(rlp(standard_ethereum_header))`.
        Ok(block.map_header(OutbeHeader::new))
    }
}

/// Outbe EVM configuration.
///
/// Wraps [`EthEvmConfig`] parametrised with [`OutbeEvmFactory`] and overrides
/// the block executor factory so that every block is processed by
/// [`OutbeBlockExecutor`], including reserved-address system tx verification in
/// the normal ordered transaction loop.
#[derive(Clone)]
pub struct OutbeEvmConfig {
    pub(crate) inner: EthEvmConfig<ChainSpec<OutbeHeader>, OutbeEvmFactory>,
    block_assembler: OutbeBlockAssembler,
    /// Optional bridge to the consensus layer for finalization data.
    pub bridge: Option<ConsensusExecutionBridge>,
    accounted_parent_artifact_provider: Option<Arc<dyn AccountedParentArtifactProvider>>,
    /// Validator-mode EVM signer used to authenticate system-tx artifacts.
    evm_signer: Option<SharedOutbeEvmSigner>,
}

impl std::fmt::Debug for OutbeEvmConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutbeEvmConfig")
            .field("inner", &self.inner)
            .field("block_assembler", &self.block_assembler)
            .field("bridge", &self.bridge)
            .field(
                "accounted_parent_artifact_provider",
                &self.accounted_parent_artifact_provider.is_some(),
            )
            .field(
                "evm_signer",
                &self.evm_signer.as_ref().map(|signer| signer.address()),
            )
            .finish()
    }
}

impl OutbeEvmConfig {
    /// Install the genesis-fixed consensus chain id into the process-wide
    /// consensus-namespace source of truth BEFORE any block
    /// execution or proof verification.
    ///
    /// Called from EVERY `OutbeEvmConfig` constructor so the binding is live no
    /// matter which one the running node uses: `new_with_bridge` for the offline
    /// reth subcommands, and `new_with_bridge_and_summary_provider` /
    /// `new_with_provider_only` via [`OutbeExecutorBuilder::build_evm`] for the
    /// live validator and full node. Previously only `::new` installed it, but
    /// production never builds via `::new`, so `consensus_chain_id()` stayed at
    /// its default `0` and the signing namespace collapsed to `b"outbe" || 0` on
    /// every chain — silently disabling the cross-chain-replay binding.
    ///
    /// Idempotent: the first value wins (the chain id is genesis-fixed and
    /// constant for the process), so duplicate constructions are no-ops.
    fn install_consensus_chain_id(chain_spec: &Arc<ChainSpec<OutbeHeader>>) {
        outbe_consensus::proof::init_consensus_chain_id(chain_spec.chain().id());
        // Surface the actually-bound id exactly once so operators can confirm the
        // namespace is chain-separated (a `0` here would mean it is degenerate).
        static LOG_ONCE: std::sync::Once = std::sync::Once::new();
        LOG_ONCE.call_once(|| {
            tracing::info!(
                target: "outbe::evm",
                chain_id = outbe_consensus::proof::consensus_chain_id(),
                "consensus chain id bound into the signing namespace"
            );
        });
    }

    /// Creates a new [`OutbeEvmConfig`] with the given chain spec.
    pub fn new(chain_spec: Arc<ChainSpec<OutbeHeader>>) -> Self {
        Self::install_consensus_chain_id(&chain_spec);
        Self {
            inner: EthEvmConfig::new_with_evm_factory(chain_spec.clone(), OutbeEvmFactory::new()),
            block_assembler: OutbeBlockAssembler::new(chain_spec),
            bridge: None,
            accounted_parent_artifact_provider: None,
            evm_signer: None,
        }
    }

    /// Creates a new [`OutbeEvmConfig`] with a consensus bridge.
    pub fn new_with_bridge(
        chain_spec: Arc<ChainSpec<OutbeHeader>>,
        bridge: ConsensusExecutionBridge,
    ) -> Self {
        Self::install_consensus_chain_id(&chain_spec);
        let summary_cache = bridge.clone();
        Self {
            inner: EthEvmConfig::new_with_evm_factory(chain_spec.clone(), OutbeEvmFactory::new()),
            block_assembler: OutbeBlockAssembler::new(chain_spec),
            bridge: Some(bridge),
            accounted_parent_artifact_provider: Some(Arc::new(
                BridgeAccountedParentArtifactProvider::new(summary_cache),
            )),
            evm_signer: None,
        }
    }

    fn new_with_bridge_and_summary_provider(
        chain_spec: Arc<ChainSpec<OutbeHeader>>,
        bridge: ConsensusExecutionBridge,
        accounted_parent_artifact_provider: Arc<dyn AccountedParentArtifactProvider>,
    ) -> Self {
        Self::install_consensus_chain_id(&chain_spec);
        Self {
            inner: EthEvmConfig::new_with_evm_factory(chain_spec.clone(), OutbeEvmFactory::new()),
            block_assembler: OutbeBlockAssembler::new(chain_spec),
            bridge: Some(bridge),
            accounted_parent_artifact_provider: Some(accounted_parent_artifact_provider),
            evm_signer: None,
        }
    }

    /// full-node constructor. Installs an
    /// [`AccountedParentArtifactProvider`] backed solely by a Reth
    /// [`HeaderProvider`] (no consensus bridge / proof cache). Used by
    /// `OutbeExecutorBuilder` when the node runs without a consensus bridge —
    /// e.g., a full node syncing the chain. Without this path the executor's
    /// Phase 1 lookup would fail with "missing provider" on every block, and
    /// full nodes would be unable to re-execute the chain.
    pub fn new_with_provider_only(
        chain_spec: Arc<ChainSpec<OutbeHeader>>,
        accounted_parent_artifact_provider: Arc<dyn AccountedParentArtifactProvider>,
    ) -> Self {
        Self::install_consensus_chain_id(&chain_spec);
        Self {
            inner: EthEvmConfig::new_with_evm_factory(chain_spec.clone(), OutbeEvmFactory::new()),
            block_assembler: OutbeBlockAssembler::new(chain_spec),
            bridge: None,
            accounted_parent_artifact_provider: Some(accounted_parent_artifact_provider),
            evm_signer: None,
        }
    }

    pub fn with_evm_signer(mut self, signer: SharedOutbeEvmSigner) -> Self {
        self.evm_signer = Some(signer);
        self
    }

    pub fn evm_signer(&self) -> Option<&SharedOutbeEvmSigner> {
        self.evm_signer.as_ref()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_begin_system_txs(
        &self,
        block_number: u64,
        chain_id: u64,
        parent_hash: B256,
        extra_data: &Bytes,
        parent_consensus_metadata: Option<CertifiedParentAccountingMetadata>,
        proposer_evm_address: Option<Address>,
        prebuilt_phase1_tx: Option<Recovered<TransactionSigned>>,
        pending_tee_bootstrap: Option<outbe_primitives::tee_bootstrap::TeeBootstrapPayload>,
    ) -> Result<Vec<Recovered<TransactionSigned>>, BlockExecutionError> {
        if block_number == 0 {
            return Ok(Vec::new());
        }

        let signer = self.evm_signer.as_ref().ok_or_else(|| {
            BlockExecutionError::Internal(alloy_evm::block::InternalBlockExecutionError::Other(
                "missing EVM signer for proposer system tx".into(),
            ))
        })?;
        let proposer = proposer_evm_address.unwrap_or_else(|| signer.address());
        if signer.address() != proposer {
            return Err(BlockExecutionError::Internal(
                alloy_evm::block::InternalBlockExecutionError::Other(
                    format!(
                        "configured EVM signer {} does not match proposer {proposer}",
                        signer.address()
                    )
                    .into(),
                ),
            ));
        }

        let artifacts = decode_outbe_block_artifacts(extra_data.as_ref())
            .map_err(|error| BlockExecutionError::msg(error.to_string()))?;
        let mut inputs = Vec::new();
        if block_number >= 2 {
            let metadata = parent_consensus_metadata.ok_or_else(|| {
                BlockExecutionError::Internal(alloy_evm::block::InternalBlockExecutionError::Other(
                    "missing parent consensus metadata for CertifiedParentAccounting".into(),
                ))
            })?;
            if metadata.finalized_block_hash != parent_hash {
                return Err(BlockExecutionError::Internal(
                    alloy_evm::block::InternalBlockExecutionError::Other(
                        format!(
                            "CertifiedParentAccounting metadata hash must match block parent: expected {parent_hash}, got {}",
                            metadata.finalized_block_hash
                        )
                        .into(),
                    ),
                ));
            }
            inputs.push(SystemTxInputV2::CertifiedParentAccounting { metadata });
        }
        if block_number >= 2 {
            // mandatory inclusion-window phase after Phase 1. The
            // gathered credits ride in the header artifact (empty until Phase 7);
            // executor parity re-derives the same input on the verifier path.
            inputs.push(SystemTxInputV2::LateFinalizeCredits {
                artifact: artifacts.late_finalize_credits.clone().unwrap_or_default(),
            });
        }
        if block_number >= 1 {
            inputs.push(SystemTxInputV2::CycleTick);
        }
        if let Some(ConsensusHeaderArtifact::BoundaryOutcome(artifact)) =
            artifacts.consensus_header_artifact
        {
            inputs.push(SystemTxInputV2::BoundaryOutcome { artifact });
        }
        // Optional Phase 3b: one-time `TeeBootstrap`, after `BoundaryOutcome`
        // (begin_order 3) and before `OracleSlashWindow` (begin_order 4). The
        // payload is supplied by the proposer's tribute-DKG bootstrap producer
        // once the ceremony completes; `None` for every block otherwise. Must
        // match the executor's `begin_block_system_tx_inputs` proposer branch
        // exactly so the proposer does not reject its own block.
        if let Some(payload) = pending_tee_bootstrap {
            inputs.push(SystemTxInputV2::TeeBootstrap { payload });
        }
        if block_number >= 1 {
            inputs.push(SystemTxInputV2::OracleSlashWindow);
        }
        if block_number >= 1 {
            inputs.push(SystemTxInputV2::HookEvents);
        }

        inputs
            .into_iter()
            .enumerate()
            .map(|(ordinal, input)| {
                let kind = input.kind();
                let calldata = input.encode().map_err(|error| {
                    BlockExecutionError::Internal(
                        alloy_evm::block::InternalBlockExecutionError::Other(
                            format!("encode system tx input: {error}").into(),
                        ),
                    )
                })?;

                // for body[0] (Phase 1
                // CertifiedParentAccounting on block_number >= 2) reuse the
                // prebuilt tx supplied by the payload builder. The defensive
                // calldata equality check guarantees the tx fed to pre-exec
                // and the tx going into body[0] are byte-identical even if
                // the calldata derivation ever diverges.
                if ordinal == 0
                    && matches!(kind, crate::system_tx::SystemTxKind::CertifiedParentAccounting)
                {
                    if let Some(prebuilt) = prebuilt_phase1_tx.as_ref() {
                        if prebuilt.tx().input() != &calldata {
                            return Err(BlockExecutionError::Internal(
                                alloy_evm::block::InternalBlockExecutionError::Other(
                                    "prebuilt Phase 1 tx calldata diverges from re-derived input"
                                        .into(),
                                ),
                            ));
                        }
                        if Address::from(*prebuilt.signer()) != proposer {
                            return Err(BlockExecutionError::Internal(
                                alloy_evm::block::InternalBlockExecutionError::Other(
                                    format!(
                                        "prebuilt Phase 1 signer {} does not match proposer {proposer}",
                                        Address::from(*prebuilt.signer())
                                    )
                                    .into(),
                                ),
                            ));
                        }
                        return Ok(prebuilt.clone());
                    }
                }

                let unsigned = build_unsigned_system_tx(
                    kind,
                    ordinal.try_into().map_err(|_| {
                        BlockExecutionError::Internal(
                            alloy_evm::block::InternalBlockExecutionError::Other(
                                format!("system tx ordinal {ordinal} exceeds u8 range").into(),
                            ),
                        )
                    })?,
                    block_number,
                    chain_id,
                    calldata,
                )
                .map_err(|error| {
                    BlockExecutionError::Internal(
                        alloy_evm::block::InternalBlockExecutionError::Other(
                            format!("build unsigned system tx: {error}").into(),
                        ),
                    )
                })?;
                let signed = signer.sign_unsigned(unsigned).map_err(|error| {
                    BlockExecutionError::Internal(
                        alloy_evm::block::InternalBlockExecutionError::Other(
                            format!("sign system tx: {error}").into(),
                        ),
                    )
                })?;
                Ok(Recovered::new_unchecked(signed, proposer))
            })
            .collect()
    }

    /// build and sign a single Phase 1 (`CertifiedParentAccounting`)
    /// body[0] tx for the next block in proposer mode. Returns `None` for
    /// `block_number <= OutbeProtocolSchedule.genesis_bootstrap_block_number`
    /// (genesis bootstrap skips Phase 1 entirely).
    ///
    /// The returned `Recovered<TransactionSigned>` is the canonical witness:
    /// the payload builder caches it in [`OutbeBlockExecutionCtx::prebuilt_phase1_tx`]
    /// for the executor's pre-exec Phase 1 commit, and reuses it byte-for-byte
    /// in the main `build_begin_system_txs` call so the body[0] tx and the
    /// pre-exec witness share the same `signature_hash`.
    pub fn build_signed_phase1_tx(
        &self,
        block_number: u64,
        chain_id: u64,
        parent_hash: B256,
        parent_consensus_metadata: Option<CertifiedParentAccountingMetadata>,
        proposer_evm_address: Option<Address>,
    ) -> Result<Option<Recovered<TransactionSigned>>, BlockExecutionError> {
        use outbe_primitives::protocol_schedule::OutbeProtocolSchedule;

        // / gate on the protocol-schedule field rather than a
        // magic literal `1`. The schedule is the single source of truth.
        let schedule = OutbeProtocolSchedule::default();
        if block_number <= schedule.genesis_bootstrap_block_number {
            return Ok(None);
        }

        let signer = self.evm_signer.as_ref().ok_or_else(|| {
            BlockExecutionError::Internal(alloy_evm::block::InternalBlockExecutionError::Other(
                "missing EVM signer for proposer Phase 1 prebuild".into(),
            ))
        })?;
        let proposer = proposer_evm_address.unwrap_or_else(|| signer.address());
        if signer.address() != proposer {
            return Err(BlockExecutionError::Internal(
                alloy_evm::block::InternalBlockExecutionError::Other(
                    format!(
                        "configured EVM signer {} does not match proposer {proposer}",
                        signer.address()
                    )
                    .into(),
                ),
            ));
        }

        let metadata = parent_consensus_metadata.ok_or_else(|| {
            BlockExecutionError::Internal(alloy_evm::block::InternalBlockExecutionError::Other(
                "missing parent consensus metadata for Phase 1 prebuild".into(),
            ))
        })?;
        if metadata.finalized_block_hash != parent_hash {
            return Err(BlockExecutionError::Internal(
                alloy_evm::block::InternalBlockExecutionError::Other(
                    format!(
                        "Phase 1 prebuild: metadata hash must match block parent: expected {parent_hash}, got {}",
                        metadata.finalized_block_hash
                    )
                    .into(),
                ),
            ));
        }

        let input = SystemTxInputV2::CertifiedParentAccounting { metadata };
        let kind = input.kind();
        let calldata = input.encode().map_err(|error| {
            BlockExecutionError::Internal(alloy_evm::block::InternalBlockExecutionError::Other(
                format!("Phase 1 prebuild: encode SystemTxInputV2: {error}").into(),
            ))
        })?;
        let unsigned = build_unsigned_system_tx(kind, 0, block_number, chain_id, calldata)
            .map_err(|error| {
                BlockExecutionError::Internal(alloy_evm::block::InternalBlockExecutionError::Other(
                    format!("Phase 1 prebuild: build unsigned tx: {error}").into(),
                ))
            })?;
        let signed = signer.sign_unsigned(unsigned).map_err(|error| {
            BlockExecutionError::Internal(alloy_evm::block::InternalBlockExecutionError::Other(
                format!("Phase 1 prebuild: sign tx: {error}").into(),
            ))
        })?;
        Ok(Some(Recovered::new_unchecked(signed, proposer)))
    }

    fn sanitize_next_block_extra_data(extra_data: Bytes) -> Bytes {
        if extra_data.is_empty() {
            return extra_data;
        }

        match decode_outbe_block_artifacts(extra_data.as_ref()) {
            // `execution_summary` is recomputed by the executor
            // on the next block and must be `None` here. Exact-parent
            // finalization metadata now travels through payload attributes
            // into the CertifiedParentAccounting system tx body, so header
            // attestation tags are dropped. `timestamp_millis_part` is
            // overwritten downstream by `context_for_next_block` from the
            // next-block attributes, so we drop it here (default = 0).
            Ok(artifacts) => encode_outbe_block_artifacts(&OutbeBlockArtifacts {
                execution_summary: None,
                consensus_header_artifact: artifacts.consensus_header_artifact,
                timestamp_millis_part: 0,
                // Preserve the proposer's gathered late-finalize credits across
                // the next-block seed sanitize (like consensus_header_artifact);
                // dropping them here would lose them on re-proposal/validation.
                late_finalize_credits: artifacts.late_finalize_credits,
            })
            .unwrap_or_default(),
            Err(_) => Bytes::new(),
        }
    }
}

type SystemTxExpectations = (
    Vec<Recovered<TransactionSigned>>,
    Vec<Recovered<TransactionSigned>>,
    Option<String>,
    Option<Address>,
);

fn system_tx_expectations_for_block(block: &SealedBlock<OutbeBlock>) -> SystemTxExpectations {
    let has_boundary_outcome =
        match decode_outbe_block_artifacts(block.header().extra_data().as_ref()) {
            Ok(artifacts) => matches!(
                artifacts.consensus_header_artifact,
                Some(ConsensusHeaderArtifact::BoundaryOutcome(_))
            ),
            Err(error) => {
                return (
                    Vec::new(),
                    Vec::new(),
                    Some(format!(
                        "decode Outbe block artifacts for system tx validation: {error}"
                    )),
                    None,
                );
            }
        };

    let layout = match split_system_layout(&block.body().transactions) {
        Ok(layout) => layout,
        Err(error) => return (Vec::new(), Vec::new(), Some(error.to_string()), None),
    };

    let has_tee_bootstrap = layout.has_begin_kind(SystemTxKind::TeeBootstrap);
    if let Err(error) = validate_active_system_tx_set(
        &layout,
        block.header().number(),
        has_boundary_outcome,
        has_tee_bootstrap,
    ) {
        return (Vec::new(), Vec::new(), Some(error.to_string()), None);
    }

    let recover = |tx: &TransactionSigned| -> Result<Recovered<TransactionSigned>, String> {
        let signer = tx
            .try_recover()
            .map_err(|error| format!("recover system tx signer: {error}"))?;
        Ok(Recovered::new_unchecked(tx.clone(), signer))
    };

    let mut begin = Vec::with_capacity(layout.begin.len());
    for tx in layout.begin {
        match recover(tx) {
            Ok(recovered) => begin.push(recovered),
            Err(error) => return (Vec::new(), Vec::new(), Some(error), None),
        }
    }

    let mut end = Vec::with_capacity(layout.end.len());
    for tx in layout.end {
        match recover(tx) {
            Ok(recovered) => end.push(recovered),
            Err(error) => return (Vec::new(), Vec::new(), Some(error), None),
        }
    }

    let proposer = begin
        .first()
        .or_else(|| end.first())
        .map(|tx| Address::from(*tx.signer()));
    (begin, end, None, proposer)
}

// ---------------------------------------------------------------------------
// BlockExecutorFactory
// ---------------------------------------------------------------------------

impl BlockExecutorFactory for OutbeEvmConfig {
    /// We keep the same EVM factory as the inner config: it creates
    /// `OutbeEvm<DB, I, PrecompilesMap>` with Outbe precompiles registered.
    type EvmFactory = OutbeEvmFactory;
    type ExecutionCtx<'a> = OutbeBlockExecutionCtx<'a>;
    type Transaction = TransactionSigned;
    type Receipt = Receipt;
    /// Per-tx execution result. `OutbeBlockExecutor` wraps reth's
    /// `EthBlockExecutor`, so this is the same `EthTxResult` reth produces:
    /// `EvmFactory = OutbeEvmFactory`, `Transaction = TransactionSigned`
    /// (`TxType` resolves to `reth_ethereum::TxType`).
    type TxExecutionResult = alloy_evm::eth::EthTxResult<
        <OutbeEvmFactory as alloy_evm::EvmFactory>::HaltReason,
        reth_ethereum::TxType,
    >;
    /// Concrete executor type returned by `create_executor`. `OutbeBlockExecutor<'a, E>`
    /// is parameterized by the raw EVM (`BlockExecutor::Evm = E`), which the trait
    /// constrains to `<Self::EvmFactory>::Evm<DB, I>` (i.e. `EvmFor<Self, DB, I>`). The
    /// `EthBlockExecutor` wrapper with `&Arc<ChainSpec<OutbeHeader>>` and
    /// `&RethReceiptBuilder` lives inside `OutbeBlockExecutor`, not in this type param.
    type Executor<
        'a,
        DB: StateDB,
        I: Inspector<<Self::EvmFactory as alloy_evm::EvmFactory>::Context<DB>>,
    > = OutbeBlockExecutor<'a, EvmFor<Self, DB, I>>;

    fn evm_factory(&self) -> &Self::EvmFactory {
        // `ConfigureEvm::evm_factory()` delegates to
        // `block_executor_factory().evm_factory()` which returns `&OutbeEvmFactory`.
        self.inner.executor_factory.evm_factory()
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: EvmFor<Self, DB, I>,
        ctx: OutbeBlockExecutionCtx<'a>,
    ) -> Self::Executor<'a, DB, I>
    where
        DB: StateDB,
        I: Inspector<<Self::EvmFactory as alloy_evm::EvmFactory>::Context<DB>>,
    {
        use alloy_evm::eth::EthBlockExecutor;
        let block_extra_data = ctx.inner.extra_data.clone();
        let block_hash = ctx.block_hash;
        let parent_hash = ctx.inner.parent_hash;
        let expected_begin_system_txs = ctx.expected_begin_system_txs.clone();
        let expected_end_system_txs = ctx.expected_end_system_txs.clone();
        let system_layout_error = ctx.system_layout_error.clone();
        let parent_consensus_metadata = ctx.parent_consensus_metadata.clone();
        let proposer_evm_address = ctx.proposer_evm_address;
        let execute_outbe_block_hooks = ctx.execute_outbe_block_hooks;
        let prebuilt_phase1_tx = ctx.prebuilt_phase1_tx.clone();
        let parent_artifact_hint = ctx.parent_artifact_hint;
        let pending_tee_bootstrap = ctx.pending_tee_bootstrap.clone();

        OutbeBlockExecutor::new(
            EthBlockExecutor::new(
                evm,
                ctx.inner,
                self.inner.chain_spec(),
                self.inner.executor_factory.receipt_builder(),
            ),
            self.bridge.clone(),
            block_extra_data,
            self.accounted_parent_artifact_provider.clone(),
            true,
            block_hash,
            parent_hash,
            self.evm_signer.clone(),
            expected_begin_system_txs,
            expected_end_system_txs,
            system_layout_error,
            parent_consensus_metadata,
            proposer_evm_address,
            execute_outbe_block_hooks,
            prebuilt_phase1_tx,
            parent_artifact_hint,
        )
        .with_pending_tee_bootstrap(pending_tee_bootstrap)
    }
}

// ---------------------------------------------------------------------------
// ConfigureEvm
// ---------------------------------------------------------------------------

impl ConfigureEvm for OutbeEvmConfig {
    type Primitives = OutbePrimitives;
    type Error = Infallible;
    type NextBlockEnvCtx = OutbeNextBlockEnvAttributes;
    /// The block executor factory IS `OutbeEvmConfig` itself — it creates
    /// `OutbeBlockExecutor` instances.
    type BlockExecutorFactory = Self;
    type BlockAssembler = OutbeBlockAssembler;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        self
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.block_assembler
    }

    fn evm_env(&self, header: &OutbeHeader) -> Result<EvmEnv<SpecId>, Self::Error> {
        Ok(EvmEnv::for_eth_block(
            header,
            self.inner.chain_spec(),
            self.inner.chain_spec().chain().id(),
            self.inner
                .chain_spec()
                .blob_params_at_timestamp(header.timestamp()),
        ))
    }

    fn next_evm_env(
        &self,
        parent: &OutbeHeader,
        attributes: &OutbeNextBlockEnvAttributes,
    ) -> Result<EvmEnv<SpecId>, Self::Error> {
        Ok(EvmEnv::for_eth_next_block(
            parent,
            NextEvmEnvAttributes {
                timestamp: attributes.inner.timestamp,
                suggested_fee_recipient: attributes.inner.suggested_fee_recipient,
                prev_randao: attributes.inner.prev_randao,
                gas_limit: attributes.inner.gas_limit,
                slot_number: attributes.inner.slot_number,
            },
            self.inner
                .chain_spec()
                .next_block_base_fee(parent, attributes.inner.timestamp)
                .unwrap_or_default(),
            self.inner.chain_spec(),
            self.inner.chain_spec().chain().id(),
            self.inner
                .chain_spec()
                .blob_params_at_timestamp(attributes.inner.timestamp),
        ))
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<OutbeBlock>,
    ) -> Result<OutbeBlockExecutionCtx<'a>, Self::Error> {
        let (
            expected_begin_system_txs,
            expected_end_system_txs,
            system_layout_error,
            recovered_proposer,
        ) = system_tx_expectations_for_block(block);

        Ok(OutbeBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                tx_count_hint: Some(block.body().transactions.len()),
                parent_hash: block.header().parent_hash(),
                parent_beacon_block_root: block.header().parent_beacon_block_root(),
                ommers: &[],
                withdrawals: block
                    .body()
                    .withdrawals
                    .as_ref()
                    .map(|w| std::borrow::Cow::Borrowed(w.as_slice())),
                extra_data: block.header().extra_data().clone(),
                slot_number: block.header().slot_number(),
            },
            timestamp_millis_part: block.header().timestamp_millis_part(),
            block_hash: Some(block.hash()),
            expected_begin_system_txs,
            expected_end_system_txs,
            system_layout_error,
            parent_consensus_metadata: None,
            proposer_evm_address: recovered_proposer,
            execute_outbe_block_hooks: true,
            // Validator path: body[0] arrives through `expected_begin_system_txs`.
            prebuilt_phase1_tx: None,
            // Validator path: the parent block is sealed and in MDBX by the
            // time the executor runs (validation happens after import), so
            // `sealed_header_by_hash` resolves the artifact via the provider
            // (lookup ladder step 2 in `RethAccountedParentArtifactProvider`).
            // The FCU-Valid → MDBX-commit race is a proposer-side window only;
            // validators do not need the in-memory `parent_artifact_hint`
            // fallback here.
            parent_artifact_hint: None,
            // Validator path: a `TeeBootstrap` in the body is read via
            // `expected_begin_system_txs`, not injected here.
            pending_tee_bootstrap: None,
        })
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader<OutbeHeader>,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<OutbeBlockExecutionCtx<'_>, Self::Error> {
        Ok(OutbeBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                tx_count_hint: None,
                parent_hash: parent.hash(),
                parent_beacon_block_root: attributes.inner.parent_beacon_block_root,
                ommers: &[],
                withdrawals: attributes
                    .inner
                    .withdrawals
                    .map(|w| std::borrow::Cow::Owned(w.into_inner())),
                extra_data: Self::sanitize_next_block_extra_data(attributes.inner.extra_data),
                slot_number: attributes.inner.slot_number,
            },
            timestamp_millis_part: attributes.timestamp_millis_part,
            block_hash: None,
            expected_begin_system_txs: Vec::new(),
            expected_end_system_txs: Vec::new(),
            system_layout_error: None,
            parent_consensus_metadata: attributes.parent_consensus_metadata,
            proposer_evm_address: attributes.proposer_evm_address,
            execute_outbe_block_hooks: attributes.execute_outbe_block_hooks,
            prebuilt_phase1_tx: attributes.prebuilt_phase1_tx,
            parent_artifact_hint: attributes.parent_artifact_hint,
            pending_tee_bootstrap: attributes.pending_tee_bootstrap,
        })
    }

    #[allow(refining_impl_trait)]
    fn create_block_builder<'a, DB, I>(
        &'a self,
        evm: EvmFor<Self, &'a mut State<DB>, I>,
        parent: &'a SealedHeader<OutbeHeader>,
        ctx: OutbeBlockExecutionCtx<'a>,
    ) -> impl BlockBuilder<
        Primitives = Self::Primitives,
        Executor = OutbeBlockExecutor<'a, EvmFor<Self, &'a mut State<DB>, I>>,
    >
    where
        DB: Database,
        I: InspectorFor<Self, &'a mut State<DB>> + 'a,
    {
        use alloy_evm::eth::EthBlockExecutor;

        let expected_begin_system_txs = ctx.expected_begin_system_txs.clone();
        let expected_end_system_txs = ctx.expected_end_system_txs.clone();
        let system_layout_error = ctx.system_layout_error.clone();
        let parent_consensus_metadata = ctx.parent_consensus_metadata.clone();
        let proposer_evm_address = ctx.proposer_evm_address;
        let execute_outbe_block_hooks = ctx.execute_outbe_block_hooks;
        let parent_hash = ctx.inner.parent_hash;
        let prebuilt_phase1_tx = ctx.prebuilt_phase1_tx.clone();
        let parent_artifact_hint = ctx.parent_artifact_hint;
        let pending_tee_bootstrap = ctx.pending_tee_bootstrap.clone();

        OutbeBlockBuilder::new(
            OutbeBlockExecutor::new(
                EthBlockExecutor::new(
                    evm,
                    ctx.inner.clone(),
                    self.inner.chain_spec(),
                    self.inner.executor_factory.receipt_builder(),
                ),
                self.bridge.clone(),
                ctx.inner.extra_data.clone(),
                self.accounted_parent_artifact_provider.clone(),
                false,
                None,
                parent_hash,
                self.evm_signer.clone(),
                expected_begin_system_txs,
                expected_end_system_txs,
                system_layout_error,
                parent_consensus_metadata,
                proposer_evm_address,
                execute_outbe_block_hooks,
                prebuilt_phase1_tx,
                parent_artifact_hint,
            )
            .with_pending_tee_bootstrap(pending_tee_bootstrap),
            ctx,
            self.bridge.clone(),
            self.block_assembler(),
            parent,
        )
    }
}

// ---------------------------------------------------------------------------
// ConfigureEngineEvm
// ---------------------------------------------------------------------------

impl ConfigureEngineEvm<OutbeExecutionData> for OutbeEvmConfig {
    fn evm_env_for_payload(
        &self,
        payload: &OutbeExecutionData,
    ) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.evm_env(payload.block.header())
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a OutbeExecutionData,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        self.context_for_block(&payload.block)
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &OutbeExecutionData,
    ) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        let txs = payload.block.body().transactions.clone();
        let convert = |tx: TransactionSigned| {
            let signer = tx.try_recover()?;
            Ok::<Recovered<TransactionSigned>, alloy_consensus::crypto::RecoveryError>(
                Recovered::new_unchecked(tx, signer),
            )
        };

        Ok((txs, convert))
    }
}

// ---------------------------------------------------------------------------
// ExecutorBuilder
// ---------------------------------------------------------------------------

/// Executor builder that wires up [`OutbeEvmConfig`] as the node's EVM config.
#[derive(Clone, Default)]
pub struct OutbeExecutorBuilder {
    /// Optional bridge to the consensus layer, injected by the node binary.
    pub bridge: Option<ConsensusExecutionBridge>,
    /// Optional validator EVM signer, injected by the node binary in validator mode.
    pub evm_signer: Option<SharedOutbeEvmSigner>,
}

impl std::fmt::Debug for OutbeExecutorBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutbeExecutorBuilder")
            .field("bridge", &self.bridge)
            .field(
                "evm_signer",
                &self.evm_signer.as_ref().map(|signer| signer.address()),
            )
            .finish()
    }
}

impl OutbeExecutorBuilder {
    /// Creates a new builder with a consensus bridge.
    pub fn with_bridge(bridge: ConsensusExecutionBridge) -> Self {
        Self {
            bridge: Some(bridge),
            evm_signer: None,
        }
    }

    pub fn with_evm_signer(mut self, signer: SharedOutbeEvmSigner) -> Self {
        self.evm_signer = Some(signer);
        self
    }
}

impl<Node> ExecutorBuilder<Node> for OutbeExecutorBuilder
where
    Node: FullNodeTypes<
        Types: NodeTypes<ChainSpec = ChainSpec<OutbeHeader>, Primitives = OutbePrimitives>,
    >,
    Node::Provider: HeaderProvider<Header = OutbeHeader> + Clone + Send + Sync + 'static,
{
    type EVM = OutbeEvmConfig;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        // always install a provider-backed
        // `AccountedParentArtifactProvider` so the executor can resolve the
        // parent artifact in both bridge mode (cache + provider) and full-node
        // mode (provider only).
        let config = match self.bridge {
            Some(bridge) => {
                let summary_cache = bridge.clone();
                OutbeEvmConfig::new_with_bridge_and_summary_provider(
                    ctx.chain_spec(),
                    bridge,
                    Arc::new(RethAccountedParentArtifactProvider::new(
                        ctx.provider().clone(),
                        Some(summary_cache),
                    )),
                )
            }
            None => OutbeEvmConfig::new_with_provider_only(
                ctx.chain_spec(),
                Arc::new(RethAccountedParentArtifactProvider::new(
                    ctx.provider().clone(),
                    None,
                )),
            ),
        };

        Ok(match self.evm_signer {
            Some(signer) => config.with_evm_signer(signer),
            None => config,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::ops::RangeBounds;

    use alloy_primitives::{Address, Bytes, B256, U256};
    use outbe_primitives::{
        consensus::{ConsensusExecutionBridge, DkgBoundaryArtifact, ReshareResult},
        reshare_artifact::{
            decode_outbe_block_artifacts, encode_consensus_header_artifact,
            encode_outbe_block_artifacts, ConsensusHeaderArtifact, ExecutionSummaryArtifact,
            LateFinalizeCreditsArtifact, OutbeBlockArtifacts, PerBlockCredit,
        },
        OutbeHeader,
    };
    use reth_ethereum::chainspec::ChainSpec;
    use reth_ethereum::{
        chainspec::MAINNET,
        primitives::{Header, SealedHeader},
    };
    #[test]
    fn new_with_bridge_installs_cache_summary_provider() {
        let bridge = ConsensusExecutionBridge::new();
        let summary = test_summary();
        let block_hash = B256::repeat_byte(0x52);
        bridge.record_execution_summary(8, block_hash, summary, 456);
        let config = OutbeEvmConfig::new_with_bridge(test_chain_spec(), bridge);

        let provider = config
            .accounted_parent_artifact_provider
            .as_ref()
            .expect("bridge config must install summary provider");
        let resolved = provider
            .execution_summary_by_hash(8, block_hash)
            .expect("cache provider must not fail")
            .expect("bridge cache must resolve summary");

        assert_eq!(resolved.summary, summary);
        assert_eq!(resolved.timestamp, 456);
    }

    use reth_evm::{ConfigureEvm, NextBlockEnvAttributes};
    use reth_provider::{HeaderProvider, ProviderResult};
    use reth_rpc_eth_api::helpers::pending_block::BuildPendingEnv;

    use super::{
        AccountedParentArtifactProvider, OutbeEvmConfig, OutbeNextBlockEnvAttributes,
        RethAccountedParentArtifactProvider,
    };

    #[derive(Clone, Default)]
    struct TestHeaderProvider {
        sealed: Option<SealedHeader<OutbeHeader>>,
    }

    impl HeaderProvider for TestHeaderProvider {
        type Header = OutbeHeader;

        fn header(&self, block_hash: B256) -> ProviderResult<Option<Self::Header>> {
            Ok(self
                .sealed
                .as_ref()
                .filter(|sealed| sealed.hash() == block_hash)
                .map(|sealed| sealed.header().clone()))
        }

        fn header_by_number(&self, num: u64) -> ProviderResult<Option<Self::Header>> {
            Ok(self
                .sealed
                .as_ref()
                .filter(|sealed| sealed.header().inner.number == num)
                .map(|sealed| sealed.header().clone()))
        }

        fn headers_range(
            &self,
            _range: impl RangeBounds<u64>,
        ) -> ProviderResult<Vec<Self::Header>> {
            Ok(Vec::new())
        }

        fn sealed_header(&self, number: u64) -> ProviderResult<Option<SealedHeader<Self::Header>>> {
            Ok(self
                .sealed
                .as_ref()
                .filter(|sealed| sealed.header().inner.number == number)
                .cloned())
        }

        fn sealed_headers_while(
            &self,
            _range: impl RangeBounds<u64>,
            _predicate: impl FnMut(&SealedHeader<Self::Header>) -> bool,
        ) -> ProviderResult<Vec<SealedHeader<Self::Header>>> {
            Ok(Vec::new())
        }
    }

    fn test_chain_spec() -> std::sync::Arc<ChainSpec<OutbeHeader>> {
        MAINNET.as_ref().clone().map_header(OutbeHeader::new).into()
    }

    fn test_parent() -> SealedHeader<OutbeHeader> {
        SealedHeader::seal_slow(OutbeHeader::new(Header::default()))
    }

    fn test_parent_with_millis_part(timestamp_millis_part: u64) -> SealedHeader<OutbeHeader> {
        let extra_data = encode_outbe_block_artifacts(&OutbeBlockArtifacts {
            timestamp_millis_part,
            ..Default::default()
        })
        .expect("encode artifacts for test parent");
        let inner = Header {
            extra_data,
            ..Default::default()
        };
        SealedHeader::seal_slow(OutbeHeader::new(inner))
    }

    fn test_summary() -> ExecutionSummaryArtifact {
        ExecutionSummaryArtifact {
            validator_fee_sum: U256::from(33u64),
        }
    }

    fn next_block_attrs(extra_data: Bytes) -> OutbeNextBlockEnvAttributes {
        OutbeNextBlockEnvAttributes {
            inner: NextBlockEnvAttributes {
                timestamp: 1,
                suggested_fee_recipient: Address::ZERO,
                prev_randao: B256::ZERO,
                gas_limit: 30_000_000,
                parent_beacon_block_root: None,
                withdrawals: None,
                extra_data,
                slot_number: None,
            },
            timestamp_millis_part: 0,
            parent_consensus_metadata: None,
            proposer_evm_address: None,
            execute_outbe_block_hooks: true,
            prebuilt_phase1_tx: None,
            parent_artifact_hint: None,
            pending_tee_bootstrap: None,
        }
    }

    #[test]
    fn pending_env_disables_outbe_hooks_and_uses_rewards_beneficiary() {
        let parent = test_parent_with_millis_part(321);

        let attrs = OutbeNextBlockEnvAttributes::build_pending_env(&parent);

        assert_eq!(
            attrs.inner.suggested_fee_recipient,
            outbe_primitives::addresses::REWARDS_ADDRESS
        );
        assert_eq!(attrs.timestamp_millis_part, 321);
        assert!(attrs.parent_consensus_metadata.is_none());
        assert!(attrs.proposer_evm_address.is_none());
        assert!(!attrs.execute_outbe_block_hooks);
    }

    #[test]
    fn context_for_next_block_strips_plain_builder_extra_data() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        let parent = test_parent();

        let ctx = config
            .context_for_next_block(
                &parent,
                next_block_attrs(Bytes::from_static(b"reth/vtest/macos")),
            )
            .expect("context construction must succeed");

        assert!(
            ctx.inner.extra_data.is_empty(),
            "plain reth builder extra_data must not enter Outbe header artifact path"
        );
    }

    #[test]
    fn context_for_next_block_uses_outbe_parent_hash() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        let parent = test_parent_with_millis_part(7);
        // Post-refactor (sub-second timestamp moved into `extra_data`)
        // the wrapper hash and the inner Ethereum hash are identical
        // by design — that is the Ethereum-spec compatibility this
        // refactor guarantees. The test still verifies that
        // `context_for_next_block` propagates the sealed parent hash
        // unchanged.
        let inner_parent_hash = parent.header().inner.hash_slow();

        let ctx = config
            .context_for_next_block(&parent, next_block_attrs(Bytes::new()))
            .expect("context construction must succeed");

        assert_eq!(ctx.inner.parent_hash, parent.hash());
        assert_eq!(ctx.inner.parent_hash, inner_parent_hash);
    }

    #[test]
    fn context_for_next_block_preserves_valid_consensus_header_artifact() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        let parent = test_parent();
        let artifact = encode_consensus_header_artifact(&ConsensusHeaderArtifact::BoundaryOutcome(
            DkgBoundaryArtifact {
                epoch: 7,
                dkg_cycle: 1,
                freeze_height: 100,
                planned_activation_height: 200,
                target_set_hash: B256::repeat_byte(0x21),
                vrf_material_version: 1,
                vrf_group_public_key: B256::repeat_byte(0x22),
                vrf_group_public_key_bytes: Bytes::from_static(&[0x22u8; 96]),
                committee_set_hash: B256::repeat_byte(0x23),
                is_validator_set_change: true,
                outcome: Bytes::from_static(b"outcome"),
                is_full_dkg: true,
                tee_recipient_pubkeys: Vec::new(),
                tee_reshare_registrations: Vec::new(),
                endorsement_signature: alloy_primitives::Bytes::new(),
                reshare: ReshareResult {
                    new_active_set: vec![Address::repeat_byte(0x11)],
                    active_set_hash: B256::repeat_byte(0x21),
                },
            },
        ))
        .expect("artifact encoding must succeed");

        let ctx = config
            .context_for_next_block(&parent, next_block_attrs(artifact.clone()))
            .expect("context construction must succeed");

        assert_eq!(ctx.inner.extra_data, artifact);
    }

    #[test]
    fn context_for_next_block_drops_legacy_finalization_header_tag() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        let parent = test_parent();
        let extra_data = Bytes::from_static(b"OART\x05\x01\x04\x00\x00");

        let ctx = config
            .context_for_next_block(&parent, next_block_attrs(extra_data))
            .expect("context construction must succeed");

        assert!(
            ctx.inner.extra_data.is_empty(),
            "legacy finalized-parent header tag must not survive into next-block context"
        );
    }

    /// `sanitize_next_block_extra_data` must PRESERVE a non-empty
    /// `late_finalize_credits` artifact (while resetting `execution_summary` and
    /// `timestamp_millis_part`, which the payload builder recomputes) — otherwise
    /// the proposer-packed late credits would be silently dropped before sealing.
    #[test]
    fn sanitizer_preserves_late_credits() {
        let config = OutbeEvmConfig::new(test_chain_spec());
        let parent = test_parent();
        let credits = LateFinalizeCreditsArtifact {
            batches: vec![PerBlockCredit {
                fb_number: 9,
                fb_hash: B256::repeat_byte(0x4b),
                epoch: 2,
                view: 11,
                parent_view: 10,
                committee_set_hash: B256::repeat_byte(0xEF),
                signer_bitmap: vec![0x05],
                aggregate_signature: [7u8; 96],
            }],
        };
        let extra_data = encode_outbe_block_artifacts(&OutbeBlockArtifacts {
            execution_summary: Some(ExecutionSummaryArtifact {
                validator_fee_sum: U256::from(123u64),
            }),
            consensus_header_artifact: None,
            timestamp_millis_part: 777,
            late_finalize_credits: Some(credits.clone()),
        })
        .expect("encode");

        let ctx = config
            .context_for_next_block(&parent, next_block_attrs(extra_data))
            .expect("context construction must succeed");

        let decoded =
            decode_outbe_block_artifacts(ctx.inner.extra_data.as_ref()).expect("decode sanitized");
        assert_eq!(
            decoded.late_finalize_credits,
            Some(credits),
            "late_finalize_credits must survive the next-block sanitizer"
        );
        assert!(
            decoded.execution_summary.is_none(),
            "execution_summary is reset by the sanitizer (payload builder recomputes it)"
        );
        assert_eq!(
            decoded.timestamp_millis_part, 0,
            "timestamp_millis_part is reset by the sanitizer"
        );
    }

    /// cache-first lookup. When the bridge cache holds an entry
    /// keyed by exact `(block_number, block_hash)`, the provider must return
    /// it even if no Reth header is reachable yet. This is the proposer/
    /// validator fast-path before the import pipeline has indexed the parent.
    #[test]
    fn accounted_parent_artifact_provider_uses_cache_when_provider_header_is_not_visible_yet() {
        let bridge = ConsensusExecutionBridge::new();
        let summary = test_summary();
        let block_hash = B256::repeat_byte(0x42);
        bridge.record_execution_summary(7, block_hash, summary, 123);
        let provider = RethAccountedParentArtifactProvider::new(
            TestHeaderProvider::default(),
            Some(bridge.clone()),
        );

        let resolved = provider
            .execution_summary_by_hash(7, block_hash)
            .expect("provider read must not fail")
            .expect("cache must bridge provider visibility race");

        assert_eq!(resolved.summary, summary);
        assert_eq!(resolved.timestamp, 123);
    }
}
