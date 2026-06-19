//! Outbe RPC API trait definition.

use alloy_primitives::{Address, B256, U256};
use jsonrpsee::proc_macros::rpc;
use outbe_primitives::consensus::RandomnessStatus;

/// Response type for validator information.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatorInfo {
    pub address: Address,
    pub consensus_pubkey: String,
    pub status: u8,
    pub stake: U256,
}

/// Response type for epoch information.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpochInfo {
    pub epoch_number: U256,
    pub epoch_start_timestamp: u64,
    pub epoch_start_block: u64,
    pub epoch_length_blocks: u32,
    pub active_validator_count: u32,
    pub total_staked: U256,
}

/// Response type for slash information.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlashInfo {
    pub proposer_miss_count: u64,
    pub voter_miss_count: u64,
    pub felony_count: u64,
}

/// Response type for consensus status.
///
/// **Note:** This is a finalized snapshot, not real-time consensus state.
/// Fields are updated by the reporter on each finalization event.
/// - `current_view`: last *finalized* Simplex view (not the live voting view)
/// - `connected_peers`: number of signers in the last certificate bitmap
///   (not the actual number of P2P connections)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsensusStatusInfo {
    /// Last finalized Simplex view (updated on finalization, not real-time).
    pub current_view: u64,
    /// Number of signers in the last finalized certificate (not live P2P peers).
    pub connected_peers: u32,
    pub is_active: bool,
    pub has_threshold_shares: bool,
    pub last_finalized_block: u64,
    pub last_vrf_seed: Option<B256>,
    pub randomness_status: RandomnessStatus,
    pub vrf_material_version: u64,
    pub last_dkg_activation_height: u64,
    pub next_planned_activation_height: u64,
    pub vrf_expiry_height: u64,
    pub is_validator: bool,
    /// Phase-1 finalized-parent certificate verification policy for this node.
    pub phase1_verification_mode: Phase1VerificationMode,
}

/// Operator-visible Phase-1 finalized-parent verification boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Phase1VerificationMode {
    /// Validator-mode node: consensus layer validates the exact parent
    /// certificate before it is accepted into payload attributes / proposals.
    ValidatorEnforced,
    /// Full-node mode: no consensus bridge or private BLS material is loaded;
    /// the node imports already-finalized EL blocks under trusted-finality semantics.
    TrustedFinality,
}

/// Response type for reward emission parameters.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmissionInfo {
    pub validator_reward_percent: u64,
    pub fee_escrow_address: Address,
}

/// Response type for slashing configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlashConfig {
    pub proposer_misdemeanor_threshold: u64,
    pub proposer_felony_threshold: u64,
    pub voter_misdemeanor_threshold: u64,
    pub slash_amount_percent: u64,
    pub evidence_reward_percent: u64,
}

/// Detailed validator information returned by `getValidator`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatorDetailInfo {
    pub address: Address,
    pub consensus_pubkey: String,
    pub status: u8,
    pub stake: U256,
    pub slash_count: u64,
    pub missed_blocks: u64,
    pub missed_votes: u64,
    pub blocks_proposed: u64,
    pub joined_at_height: u64,
    pub deactivated_at_height: u64,
    pub unbonding_end: u64,
    pub has_bls_share: bool,
}

/// Response type for validator participation statistics.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParticipationInfo {
    pub address: Address,
    pub blocks_proposed: u64,
    pub missed_blocks: u64,
    pub missed_votes: u64,
}

/// Response type for node sync status.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatusInfo {
    pub is_syncing: bool,
    pub current_block: u64,
    pub highest_block: u64,
    pub consensus_active: bool,
    pub connected_peers: u32,
}

/// Response type for `getFinalization`: the finalized certificate + block for a
/// height, as hex of their commonware-codec encodings. A follower's resolver
/// reconstructs the marshal delivery as the decoded `finalizationHex` followed
/// by the decoded `blockHex`, then verifies the certificate against the epoch
/// committee. Hex (0x-prefixed) keeps the wire JSON-friendly; the bytes are NOT
/// trusted by the caller — verification happens against the committee, not this
/// RPC.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalizationProof {
    /// Hex of the `commonware_codec::Encode` finalization certificate.
    pub finalization_hex: String,
    /// Hex of the `commonware_codec::Encode` finalized `ConsensusBlock`.
    pub block_hex: String,
}
/// Lifecycle status of an upgrade proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UpdateProposalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
    Activated,
    Cancelled,
}

/// Yes/no vote counters for an upgrade proposal.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateVoteTallyInfo {
    pub yes: u64,
    pub no: u64,
}

/// Active on-chain protocol version.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateActiveVersionInfo {
    pub version: u32,
    pub major: u8,
    pub minor: u32,
    pub activation_height: u64,
}

/// Upgrade proposal details.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProposalInfo {
    pub proposal_id: U256,
    pub proposer: Address,
    pub proposed_at_height: u64,
    pub activation_height: u64,
    pub voting_deadline_height: u64,
    pub version: u32,
    pub major: u8,
    pub minor: u32,
    pub info: String,
    pub status: UpdateProposalStatus,
    pub state: UpdateVoteTallyInfo,
}

/// Point lookup for a validator vote on a proposal.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateVoteInfo {
    pub proposal_id: U256,
    pub voter: Address,
    pub approve: bool,
    pub block_number: u64,
}

impl From<outbe_update::state::ProposalStatus> for UpdateProposalStatus {
    fn from(status: outbe_update::state::ProposalStatus) -> Self {
        match status {
            outbe_update::state::ProposalStatus::Pending => Self::Pending,
            outbe_update::state::ProposalStatus::Approved => Self::Approved,
            outbe_update::state::ProposalStatus::Rejected => Self::Rejected,
            outbe_update::state::ProposalStatus::Expired => Self::Expired,
            outbe_update::state::ProposalStatus::Activated => Self::Activated,
            outbe_update::state::ProposalStatus::Cancelled => Self::Cancelled,
        }
    }
}

impl From<&outbe_update::state::ProposalInfo> for UpdateVoteTallyInfo {
    fn from(proposal: &outbe_update::state::ProposalInfo) -> Self {
        Self {
            yes: proposal.yes_votes,
            no: proposal.no_votes,
        }
    }
}

impl From<outbe_update::state::ProposalInfo> for UpdateProposalInfo {
    fn from(proposal: outbe_update::state::ProposalInfo) -> Self {
        Self {
            proposal_id: proposal.id,
            proposer: proposal.proposer,
            proposed_at_height: proposal.proposed_at_height,
            activation_height: proposal.activation_height,
            voting_deadline_height: proposal.voting_deadline_height,
            version: proposal.version,
            major: outbe_update::state::protocol_version_major(proposal.version),
            minor: outbe_update::state::protocol_version_minor(proposal.version),
            info: hex::encode(&proposal.info),
            status: proposal.status.into(),
            state: (&proposal).into(),
        }
    }
}

impl From<outbe_update::state::VoteInfo> for UpdateVoteInfo {
    fn from(vote: outbe_update::state::VoteInfo) -> Self {
        Self {
            proposal_id: vote.proposal_id,
            voter: vote.voter,
            approve: vote.vote_kind.to_approve(),
            block_number: vote.block_number,
        }
    }
}

impl From<(outbe_update::ProtocolVersion, u64)> for UpdateActiveVersionInfo {
    fn from((version, activation_height): (outbe_update::ProtocolVersion, u64)) -> Self {
        Self {
            version,
            major: outbe_update::state::protocol_version_major(version),
            minor: outbe_update::state::protocol_version_minor(version),
            activation_height,
        }
    }
}

/// Outbe custom RPC namespace.
///
/// Provides read-only access to validator infrastructure state.
/// Enable with `--http.api outbe`.
#[rpc(server, namespace = "outbe")]
pub trait OutbeApi {
    /// Returns information about all active validators.
    #[method(name = "getValidators")]
    async fn get_validators(&self) -> jsonrpsee::core::RpcResult<Vec<ValidatorInfo>>;

    /// Returns detailed information about a single validator by address.
    #[method(name = "getValidator")]
    async fn get_validator(
        &self,
        address: Address,
    ) -> jsonrpsee::core::RpcResult<Option<ValidatorDetailInfo>>;

    /// Returns current epoch information.
    #[method(name = "getEpochInfo")]
    async fn get_epoch_info(&self) -> jsonrpsee::core::RpcResult<EpochInfo>;

    /// Returns the stake amount for a validator address.
    #[method(name = "getStake")]
    async fn get_stake(&self, address: Address) -> jsonrpsee::core::RpcResult<U256>;

    /// Returns slash counters for a validator.
    #[method(name = "getSlashInfo")]
    async fn get_slash_info(&self, address: Address) -> jsonrpsee::core::RpcResult<SlashInfo>;

    /// Returns finalized consensus snapshot (view, certificate signers, shares, is_validator).
    #[method(name = "consensusStatus")]
    async fn consensus_status(&self) -> jsonrpsee::core::RpcResult<ConsensusStatusInfo>;

    /// Returns the committed VRF seed (block header `mixHash` / prev_randao) for
    /// the given block number, or for the latest canonical block when omitted
    /// (which, under Outbe's fast finality, is the latest finalized block).
    /// Reads the authoritative committed header via the provider, so the answer
    /// is identical on validators and full nodes. `None` if the block does not
    /// exist or carries no `mixHash`.
    #[method(name = "getVrfSeed")]
    async fn get_vrf_seed(
        &self,
        block_number: Option<u64>,
    ) -> jsonrpsee::core::RpcResult<Option<B256>>;

    /// Returns current reward emission parameters.
    #[method(name = "getEmissionInfo")]
    async fn get_emission_info(&self) -> jsonrpsee::core::RpcResult<EmissionInfo>;

    /// Returns slashing configuration parameters.
    #[method(name = "getSlashConfig")]
    async fn get_slash_config(&self) -> jsonrpsee::core::RpcResult<SlashConfig>;

    /// Returns participation statistics for a validator address.
    #[method(name = "getParticipation")]
    async fn get_participation(
        &self,
        address: Address,
    ) -> jsonrpsee::core::RpcResult<ParticipationInfo>;

    /// Returns the node's sync status.
    #[method(name = "syncStatus")]
    async fn sync_status(&self) -> jsonrpsee::core::RpcResult<SyncStatusInfo>;

    /// Returns the finalized certificate + block at `height` (hex-encoded), for
    /// `--upstream` followers to backfill and verify. Served only by nodes
    /// running consensus (validators) or a follower that has itself synced the
    /// height; otherwise errors. The caller verifies the certificate against the
    /// epoch committee — this RPC is a bytes transport, not a trust root.
    #[method(name = "getFinalization")]
    async fn get_finalization(&self, height: u64) -> jsonrpsee::core::RpcResult<FinalizationProof>;

    /// Returns the active on-chain protocol version.
    #[method(name = "getUpdateActiveVersion")]
    async fn get_update_active_version(
        &self,
    ) -> jsonrpsee::core::RpcResult<UpdateActiveVersionInfo>;

    /// Returns upgrade proposal details, or `null` when the id was never allocated.
    #[method(name = "getUpdateProposal")]
    async fn get_update_proposal(
        &self,
        proposal_id: U256,
    ) -> jsonrpsee::core::RpcResult<Option<UpdateProposalInfo>>;

    /// Returns proposals currently in the voting phase.
    #[method(name = "listUpdatePendingProposals")]
    async fn list_update_pending_proposals(
        &self,
    ) -> jsonrpsee::core::RpcResult<Vec<UpdateProposalInfo>>;

    /// Returns approved proposals waiting for activation height.
    #[method(name = "listUpdateWaitingProposals")]
    async fn list_update_waiting_proposals(
        &self,
    ) -> jsonrpsee::core::RpcResult<Vec<UpdateProposalInfo>>;

    /// Returns a validator vote on a proposal, or `null` when absent.
    #[method(name = "getUpdateVote")]
    async fn get_update_vote(
        &self,
        proposal_id: U256,
        voter: Address,
    ) -> jsonrpsee::core::RpcResult<Option<UpdateVoteInfo>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consensus_status_info_serialization_camel_case() {
        let info = ConsensusStatusInfo {
            current_view: 42,
            connected_peers: 3,
            is_active: true,
            has_threshold_shares: true,
            last_finalized_block: 41,
            last_vrf_seed: Some(B256::ZERO),
            randomness_status: RandomnessStatus::Healthy,
            vrf_material_version: 2,
            last_dkg_activation_height: 21,
            next_planned_activation_height: 21021,
            vrf_expiry_height: 21621,
            is_validator: true,
            phase1_verification_mode: Phase1VerificationMode::ValidatorEnforced,
        };

        let json = serde_json::to_string(&info).unwrap();

        // Verify camelCase field names (not snake_case).
        assert!(
            json.contains("\"currentView\""),
            "must use camelCase: {json}"
        );
        assert!(
            json.contains("\"connectedPeers\""),
            "must use camelCase: {json}"
        );
        assert!(json.contains("\"isActive\""), "must use camelCase: {json}");
        assert!(
            json.contains("\"hasThresholdShares\""),
            "must use camelCase: {json}"
        );
        assert!(
            json.contains("\"lastFinalizedBlock\""),
            "must use camelCase: {json}"
        );
        assert!(
            json.contains("\"lastVrfSeed\""),
            "must use camelCase: {json}"
        );
        assert!(
            json.contains("\"randomnessStatus\""),
            "must use camelCase: {json}"
        );
        assert!(
            json.contains("\"vrfMaterialVersion\""),
            "must use camelCase: {json}"
        );
        assert!(
            json.contains("\"lastDkgActivationHeight\""),
            "must use camelCase: {json}"
        );
        assert!(
            json.contains("\"nextPlannedActivationHeight\""),
            "must use camelCase: {json}"
        );
        assert!(
            json.contains("\"vrfExpiryHeight\""),
            "must use camelCase: {json}"
        );
        assert!(
            json.contains("\"isValidator\""),
            "must use camelCase: {json}"
        );
        assert!(
            json.contains("\"phase1VerificationMode\""),
            "must use camelCase: {json}"
        );
        assert!(
            json.contains("\"validatorEnforced\""),
            "validator-mode status must expose enforced Phase-1 verification: {json}"
        );

        // Must NOT contain snake_case.
        assert!(!json.contains("current_view"), "must not use snake_case");
        assert!(!json.contains("connected_peers"), "must not use snake_case");
    }

    #[test]
    fn test_consensus_status_info_roundtrip() {
        let info = ConsensusStatusInfo {
            current_view: 100,
            connected_peers: 5,
            is_active: false,
            has_threshold_shares: false,
            last_finalized_block: 99,
            last_vrf_seed: None,
            randomness_status: RandomnessStatus::Expired,
            vrf_material_version: 5,
            last_dkg_activation_height: 100,
            next_planned_activation_height: 21100,
            vrf_expiry_height: 21700,
            is_validator: false,
            phase1_verification_mode: Phase1VerificationMode::TrustedFinality,
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: ConsensusStatusInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.current_view, 100);
        assert_eq!(deserialized.connected_peers, 5);
        assert!(!deserialized.is_active);
        assert!(!deserialized.has_threshold_shares);
        assert_eq!(deserialized.last_finalized_block, 99);
        assert!(deserialized.last_vrf_seed.is_none());
        assert_eq!(deserialized.randomness_status, RandomnessStatus::Expired);
        assert_eq!(deserialized.vrf_material_version, 5);
        assert_eq!(deserialized.last_dkg_activation_height, 100);
        assert_eq!(deserialized.next_planned_activation_height, 21100);
        assert_eq!(deserialized.vrf_expiry_height, 21700);
        assert!(!deserialized.is_validator);
        assert_eq!(
            deserialized.phase1_verification_mode,
            Phase1VerificationMode::TrustedFinality
        );
    }

    #[test]
    fn test_sync_status_info_full_node_semantics() {
        // Full node: is_syncing may be true, consensus_active = false.
        let info = SyncStatusInfo {
            is_syncing: true,
            current_block: 50,
            highest_block: 100,
            consensus_active: false,
            connected_peers: 3,
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: SyncStatusInfo = serde_json::from_str(&json).unwrap();

        assert!(!deserialized.consensus_active);
        assert!(deserialized.is_syncing);
    }

    #[test]
    fn test_update_proposal_info_serialization_camel_case() {
        use super::{UpdateProposalInfo, UpdateProposalStatus, UpdateVoteTallyInfo};

        let info = UpdateProposalInfo {
            proposal_id: U256::from(1),
            proposer: Address::ZERO,
            proposed_at_height: 10,
            activation_height: 1000,
            voting_deadline_height: 500,
            version: 65538,
            major: 1,
            minor: 2,
            info: "6869".to_string(),
            status: UpdateProposalStatus::Pending,
            state: UpdateVoteTallyInfo { yes: 2, no: 1 },
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"proposalId\""));
        assert!(json.contains("\"votingDeadlineHeight\""));
        assert!(json.contains("\"pending\""));
    }
}
