//! Outbe RPC server implementation.
//!
//! TODO(future): Full nodes could verify finality proofs from block headers
//! (BLS threshold signature in extra_data) without running full consensus.
//! This would provide light-client-grade trust: verify that 2/3+1 validators
//! signed each block using the group public key from the ValidatorSet contract.

use alloy_primitives::{Address, B256, U256};
use jsonrpsee::core::RpcResult;
use outbe_primitives::header::OutbeHeader;
use outbe_primitives::{
    consensus::ConsensusExecutionBridge,
    storage::{
        readonly::{ReadOnlyStorageProvider, StorageReader},
        StorageHandle,
    },
};
use reth_ethereum::primitives::AlloyBlockHeader as _;
use reth_ethereum::storage::{
    BlockNumReader, HeaderProvider, StateProvider as _, StateProviderBox, StateProviderFactory,
};
use std::sync::Arc;

use crate::api::{
    ConsensusStatusInfo, EmissionInfo, EpochInfo, FinalizationProof, OutbeApiServer,
    ParticipationInfo, Phase1VerificationMode, SlashConfig, SlashInfo, SyncStatusInfo,
    ValidatorDetailInfo, ValidatorInfo,
};

/// Bridge from Reth's `StateProvider` to outbe's `StorageReader` trait.
struct RethStateReader<'a> {
    state: &'a StateProviderBox,
}

impl StorageReader for RethStateReader<'_> {
    fn read_storage(&self, address: Address, key: B256) -> outbe_primitives::error::Result<U256> {
        self.state
            .storage(address, key)
            .map(|opt| opt.unwrap_or(U256::ZERO))
            .map_err(|e| {
                outbe_primitives::error::PrecompileError::Storage(format!("state read failed: {e}"))
            })
    }
}

/// RPC handler for the `outbe_*` namespace.
#[derive(Debug, Clone)]
pub struct OutbeApiHandler<P> {
    provider: Arc<P>,
    bridge: Option<ConsensusExecutionBridge>,
    /// Whether this node runs consensus as a VALIDATOR. A `--upstream` follower
    /// also holds a bridge (to serve `outbe_getFinalization` to downstream
    /// followers) but must report itself as a non-validator / TrustedFinality
    /// node. This flag, NOT `bridge.is_some()`, drives validator-status fields.
    is_validator: bool,
}

impl<P> OutbeApiHandler<P> {
    /// Create a new handler backed by the given state provider factory (no
    /// bridge; plain EL full node).
    pub fn new(provider: Arc<P>) -> Self {
        Self {
            provider,
            bridge: None,
            is_validator: false,
        }
    }

    /// Create a validator handler with full access to the consensus bridge.
    pub fn with_bridge(provider: Arc<P>, bridge: ConsensusExecutionBridge) -> Self {
        Self {
            provider,
            bridge: Some(bridge),
            is_validator: true,
        }
    }

    /// Create a `--upstream` follower handler: it holds the bridge so it can
    /// serve `outbe_getFinalization` (chaining followers), but reports itself as
    /// a non-validator (TrustedFinality) node, not a validator.
    pub fn with_follower_bridge(provider: Arc<P>, bridge: ConsensusExecutionBridge) -> Self {
        Self {
            provider,
            bridge: Some(bridge),
            is_validator: false,
        }
    }
}

impl<P> OutbeApiHandler<P>
where
    P: StateProviderFactory + 'static,
{
    /// Read precompile state at the latest block using a closure.
    fn with_latest_state<R>(
        &self,
        f: impl FnOnce(StorageHandle) -> Result<R, outbe_primitives::error::PrecompileError>,
    ) -> RpcResult<R> {
        let state = self
            .provider
            .latest()
            .map_err(|e| internal_err(format!("failed to get latest state: {e}")))?;

        let reader = RethStateReader { state: &state };
        let mut provider = ReadOnlyStorageProvider::new(reader);
        let storage = StorageHandle::new(&mut provider);

        f(storage).map_err(|e| internal_err(format!("precompile error: {e}")))
    }
}

#[jsonrpsee::core::async_trait]
impl<P> OutbeApiServer for OutbeApiHandler<P>
where
    P: StateProviderFactory
        + HeaderProvider<Header = OutbeHeader>
        + BlockNumReader
        + Send
        + Sync
        + 'static,
{
    async fn get_validators(&self) -> RpcResult<Vec<ValidatorInfo>> {
        self.with_latest_state(|storage| {
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            let records = vs.get_active_validators()?;

            let staking = outbe_staking::contract::Staking::new(storage);

            let mut result = Vec::with_capacity(records.len());
            for r in &records {
                let stake = staking.get_stake(r.validator_address).unwrap_or(U256::ZERO);
                result.push(ValidatorInfo {
                    address: r.validator_address,
                    consensus_pubkey: hex::encode(r.consensus_pubkey),
                    status: r.status,
                    stake,
                });
            }
            Ok(result)
        })
    }

    async fn get_validator(&self, address: Address) -> RpcResult<Option<ValidatorDetailInfo>> {
        self.with_latest_state(|storage| {
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            match vs.get_validator(address)? {
                Some(r) => Ok(Some(ValidatorDetailInfo {
                    address: r.validator_address,
                    consensus_pubkey: hex::encode(r.consensus_pubkey),
                    status: r.status,
                    stake: r.stake,
                    slash_count: r.slash_count,
                    missed_blocks: r.missed_blocks,
                    missed_votes: r.missed_votes,
                    blocks_proposed: r.blocks_proposed,
                    joined_at_height: r.joined_at_height,
                    deactivated_at_height: r.deactivated_at_height,
                    unbonding_end: r.unbonding_end,
                    has_bls_share: r.has_bls_share,
                })),
                None => Ok(None),
            }
        })
    }

    async fn get_epoch_info(&self) -> RpcResult<EpochInfo> {
        self.with_latest_state(|storage| {
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            let epoch_number = vs.epoch_number.read()?;
            let epoch_start_timestamp = vs.epoch_start_timestamp.read()?;
            let epoch_start_block = vs.epoch_start_block.read()?;
            let epoch_length_blocks = vs.config_epoch_length_blocks.read()?;
            let active_count = vs.active_validator_count()?;

            let staking = outbe_staking::contract::Staking::new(storage);
            let total_staked = staking.get_total_staked()?;

            Ok(EpochInfo {
                epoch_number,
                epoch_start_timestamp,
                epoch_start_block,
                epoch_length_blocks,
                active_validator_count: active_count,
                total_staked,
            })
        })
    }

    async fn get_stake(&self, address: Address) -> RpcResult<U256> {
        self.with_latest_state(|storage| {
            let staking = outbe_staking::contract::Staking::new(storage);
            staking.get_stake(address)
        })
    }

    async fn get_slash_info(&self, address: Address) -> RpcResult<SlashInfo> {
        self.with_latest_state(|storage| {
            let si = outbe_slashindicator::contract::SlashIndicator::new(storage);
            Ok(SlashInfo {
                proposer_miss_count: si.proposer_miss_count.read(&address)?,
                voter_miss_count: si.voter_miss_count.read(&address)?,
                felony_count: si.felony_count.read(&address)?,
            })
        })
    }

    async fn consensus_status(&self) -> RpcResult<ConsensusStatusInfo> {
        let is_validator = self.is_validator;
        let status = self
            .bridge
            .as_ref()
            .map(|b| b.consensus_status())
            .unwrap_or_default();

        Ok(ConsensusStatusInfo {
            current_view: status.current_view,
            connected_peers: status.connected_peers,
            is_active: status.is_active(),
            has_threshold_shares: status.has_threshold_shares(),
            last_finalized_block: status.last_finalized_block,
            last_vrf_seed: status.last_vrf_seed,
            randomness_status: status.randomness_status,
            vrf_material_version: status.vrf_material_version,
            last_dkg_activation_height: status.last_dkg_activation_height,
            next_planned_activation_height: status.next_planned_activation_height,
            vrf_expiry_height: status.vrf_expiry_height,
            is_validator,
            phase1_verification_mode: if is_validator {
                Phase1VerificationMode::ValidatorEnforced
            } else {
                Phase1VerificationMode::TrustedFinality
            },
        })
    }

    async fn get_vrf_seed(&self, block_number: Option<u64>) -> RpcResult<Option<B256>> {
        // read the committed VRF seed from the target block header's
        // `mixHash` (prev_randao) via the provider, honoring `block_number`.
        // This is the authoritative, per-node-consistent committed value — not
        // the process-local in-memory consensus seed (which a full node never
        // has and which can diverge between nodes). `None` resolves to the
        // latest canonical block, which under Outbe's fast finality is the
        // latest finalized block.
        let target = match block_number {
            Some(n) => n,
            None => self
                .provider
                .best_block_number()
                .map_err(|e| internal_err(format!("failed to read latest block number: {e}")))?,
        };
        let header = self
            .provider
            .header_by_number(target)
            .map_err(|e| internal_err(format!("failed to read header for block {target}: {e}")))?;
        // `mix_hash()` is itself `Option<B256>`; a missing block also yields None.
        Ok(header.and_then(|h| h.mix_hash()))
    }

    async fn get_emission_info(&self) -> RpcResult<EmissionInfo> {
        Ok(EmissionInfo {
            validator_reward_percent: outbe_rewards::logic::VALIDATOR_REWARD_PERCENT,
            fee_escrow_address: outbe_primitives::addresses::REWARDS_ADDRESS,
        })
    }

    async fn get_slash_config(&self) -> RpcResult<SlashConfig> {
        self.with_latest_state(|storage| {
            let si = outbe_slashindicator::contract::SlashIndicator::new(storage);
            Ok(SlashConfig {
                proposer_misdemeanor_threshold: si.config_proposer_misdemeanor_threshold.read()?,
                proposer_felony_threshold: si.config_proposer_felony_threshold.read()?,
                voter_misdemeanor_threshold: si.config_voter_misdemeanor_threshold.read()?,
                slash_amount_percent: si.config_slash_amount_percent.read()?,
                evidence_reward_percent: si.config_evidence_reward_percent.read()?,
            })
        })
    }

    async fn get_participation(&self, address: Address) -> RpcResult<ParticipationInfo> {
        self.with_latest_state(|storage| {
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            Ok(ParticipationInfo {
                address,
                blocks_proposed: vs.val_blocks_proposed.read(&address)?,
                missed_blocks: vs.val_missed_blocks.read(&address)?,
                missed_votes: vs.val_missed_votes.read(&address)?,
            })
        })
    }

    async fn sync_status(&self) -> RpcResult<SyncStatusInfo> {
        match &self.bridge {
            Some(b) => {
                let consensus = b.consensus_status();
                Ok(SyncStatusInfo {
                    is_syncing: !consensus.is_active(),
                    current_block: consensus.last_finalized_block,
                    highest_block: consensus.last_finalized_block,
                    consensus_active: consensus.is_active(),
                    connected_peers: consensus.connected_peers,
                })
            }
            None => {
                // Full-node mode: sync is handled by DevP2P (eth_syncing).
                // Report not syncing since we have no consensus bridge.
                Ok(SyncStatusInfo {
                    is_syncing: false,
                    current_block: 0,
                    highest_block: 0,
                    consensus_active: false,
                    connected_peers: 0,
                })
            }
        }
    }

    async fn get_finalization(&self, height: u64) -> RpcResult<FinalizationProof> {
        // Only nodes running consensus (or a follower that has itself synced the
        // height) can serve this — both install a finalization fetcher on the
        // bridge at marshal-start. A node without a bridge (pure EL full node)
        // has no marshal and cannot answer.
        let bridge = self.bridge.as_ref().ok_or_else(|| {
            internal_err("node is not serving consensus finalizations".to_string())
        })?;
        let proof = bridge.request_finalization(height).await.ok_or_else(|| {
            internal_err(format!(
                "no finalization available for height {height} (not finalized locally or pruned)"
            ))
        })?;
        Ok(FinalizationProof {
            finalization_hex: format!("0x{}", hex::encode(&proof.finalization)),
            block_hex: format!("0x{}", hex::encode(&proof.block)),
        })
    }
}

/// Create an internal JSON-RPC error.
fn internal_err(msg: String) -> jsonrpsee::types::ErrorObject<'static> {
    jsonrpsee::types::ErrorObject::owned(
        jsonrpsee::types::error::INTERNAL_ERROR_CODE,
        msg,
        None::<()>,
    )
}
