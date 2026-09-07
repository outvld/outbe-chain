use alloy_primitives::{B256, U256};
use outbe_ocomp_protocol::{
    generated_shape::OCOMP_POC_CANDIDATE_LIMITS_V1,
    profile::{CapacityProfileV1, ProtocolBundleV1},
};
use outbe_ocompregistry::{
    poc_schema_limits, OcompProtocolAuthorityV1, OcompRequestProfile, OcompSuccessorV1,
};

use outbe_primitives::block::{BlockContext, BlockRuntimeContext};
use outbe_primitives::chain::DEVNET_CHAIN_ID;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;

use crate::constants::{MIN_ACTIVATION_BUFFER, PROTOCOL_VERSION};
use crate::handlers::UpgradeHandlerRegistry;
use crate::payload::encode_schedule_update_json;
use crate::schema::Update;
use crate::{encode_protocol_version, ProtocolVersion};
use outbe_primitives::error::Result;
use serde_json::Value;

mod events;
mod handlers;
mod lifecycle;
mod precompile;
mod records;
mod scheduled;
mod unset_version;
mod vote_dispatch;

static EMPTY_UPGRADE_HANDLER_REGISTRY: UpgradeHandlerRegistry = UpgradeHandlerRegistry::new(&[]);

/// Binary protocol version - safe to activate in tests.
pub(super) const PV: ProtocolVersion = PROTOCOL_VERSION;
pub(super) const CHAIN_ID: u64 = DEVNET_CHAIN_ID;

pub(super) const V1_2: ProtocolVersion = encode_protocol_version(1, 2);
pub(super) const V1_3: ProtocolVersion = encode_protocol_version(1, 3);
pub(super) const V1_5: ProtocolVersion = encode_protocol_version(1, 5);
pub(super) const V2_0: ProtocolVersion = encode_protocol_version(2, 0);
pub(super) const V3_0: ProtocolVersion = encode_protocol_version(3, 0);
pub(super) const V3_1: ProtocolVersion = encode_protocol_version(3, 1);
pub(super) const V9_8: ProtocolVersion = encode_protocol_version(9, 8);

pub(super) fn with_update<F: FnOnce(StorageHandle)>(f: F) {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let storage = StorageHandle::new(&mut provider);
    f(storage);
}

pub(super) fn with_update_provider<F: FnOnce(StorageHandle)>(f: F) -> HashMapStorageProvider {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let storage = StorageHandle::new(&mut provider);
    f(storage);
    provider
}

pub(super) fn block_ctx(storage: StorageHandle, block_number: u64) -> BlockRuntimeContext {
    BlockRuntimeContext::new(
        BlockContext::empty_for_tests(block_number, 0, CHAIN_ID),
        storage,
    )
}

pub(super) fn min_activation(current: u64) -> u64 {
    current.saturating_add(MIN_ACTIVATION_BUFFER)
}

pub(super) fn ocomp_authority(genesis_hash: B256) -> OcompProtocolAuthorityV1 {
    let hash = B256::repeat_byte;
    let generated = OCOMP_POC_CANDIDATE_LIMITS_V1;
    let protocol_bundle = ProtocolBundleV1 {
        protocol_version: 1,
        fork_id: hash(21),
        intent_codec_id: hash(2),
        finalized_intent_proof_codec_id: hash(3),
        tribute_body_codec_id: outbe_ocomp_protocol::registry::TRIBUTE_BODY_CODEC_ID,
        fidelity_opening_codec_id: outbe_ocomp_protocol::registry::FIDELITY_OPENING_CODEC_ID,
        oracle_opening_codec_id: outbe_ocomp_protocol::registry::ORACLE_OPENING_CODEC_ID,
        result_codec_id: hash(4),
        action_codec_id: hash(5),
        activation_codec_id: hash(6),
        evidence_codec_id: hash(7),
        request_semantics_version: 1,
        lysis_program_semantics_hash: hash(8),
        planner_spec_version: 1,
        reducer_spec_version: 1,
        activation_apply_semantics_hash: hash(9),
        effect_contract_registry_hash: hash(10),
        object_codec_registry_hash: hash(11),
        correctness_profile_id: hash(12),
        capacity_profile_id: hash(13),
        result_signature_profile_id: hash(14),
        finality_verifier_and_vote_domain_id: hash(15),
        consensus_committee_history_schema_version: 1,
        ocomp_committee_schema_version: 1,
        proof_system_and_verifier_key_id: None,
        da_codec_and_binding_verifier_id: None,
        anti_equivocation_journal_schema_hash: hash(16),
        mode_pause_revocation_semantics_hash: hash(17),
        upgrade_fsm_semantics_hash: hash(18),
        release_requirement_catalog_sequence: 1,
        release_requirement_catalog_hash: hash(19),
        release_requirement_catalog_parent_hash: hash(20),
        release_gate_authority_envelope_hash: hash(22),
        release_approval_policy_hash: hash(24),
        release_validator_command_artifact_hash: hash(25),
        consensus_state_schema_version: 1,
        migration_manifest_hash: hash(26),
        required_upgrade_handler_set_hash: hash(27),
    };
    let protocol_bundle_hash = protocol_bundle
        .protocol_bundle_hash(&poc_schema_limits())
        .unwrap();
    OcompProtocolAuthorityV1 {
        request_profile: OcompRequestProfile {
            chain_id: CHAIN_ID,
            genesis_hash,
            fork_id: protocol_bundle.fork_id,
            protocol_bundle_hash,
            correctness_profile_id: protocol_bundle.correctness_profile_id,
            capacity_profile: CapacityProfileV1 {
                profile_id: hash(13),
                max_tributes_per_work_shard: u32::try_from(generated.max_tributes_per_work_shard)
                    .unwrap(),
                max_workers_per_domain: 4,
                max_intents_per_block: 1,
                max_activations_per_block: 1,
                max_ready_inspections_per_block: 1,
                max_expirations_per_block: 1,
                ready_backoff_blocks: 1,
                max_reference_currencies: 1,
                max_oracle_wwd_pair_entries: 1,
                max_active_scurve_entries: 1,
                result_deadline_blocks: 10,
                source_retention_after_terminal_blocks: generated
                    .source_retention_after_terminal_blocks,
                generated_limits_manifest_hash: hash(30),
            },
            source_availability_policy_id: hash(44),
        },
        protocol_bundle,
    }
}

pub(super) fn ocomp_successor(genesis_hash: B256, activation_height: u64) -> OcompSuccessorV1 {
    let predecessor = ocomp_authority(genesis_hash);
    let mut protocol_bundle = predecessor.protocol_bundle.clone();
    protocol_bundle.protocol_version += 1;
    protocol_bundle.fork_id = B256::repeat_byte(61);
    protocol_bundle.request_semantics_version += 1;
    protocol_bundle.lysis_program_semantics_hash = B256::repeat_byte(62);
    let protocol_bundle_hash = protocol_bundle
        .protocol_bundle_hash(&poc_schema_limits())
        .unwrap();
    OcompSuccessorV1 {
        activation_height,
        predecessor_protocol_bundle_hash: predecessor.request_profile.protocol_bundle_hash,
        authority: OcompProtocolAuthorityV1 {
            request_profile: OcompRequestProfile {
                fork_id: protocol_bundle.fork_id,
                protocol_bundle_hash,
                correctness_profile_id: protocol_bundle.correctness_profile_id,
                ..predecessor.request_profile
            },
            protocol_bundle,
        },
    }
}

pub(super) fn schedule_update(
    update: &mut Update<'_>,
    proposal_id: U256,
    version: ProtocolVersion,
    activation_height: u64,
    info: &str,
    current_height: u64,
) -> Result<()> {
    let payload: Value = serde_json::from_str(&encode_schedule_update_json(
        version,
        activation_height,
        info,
    ))
    .expect("schedule update JSON should parse");
    update.schedule_update_from_propose(proposal_id, &payload, current_height)
}

/// Test-only helper: runs begin-block processing with an empty handler registry.
pub(super) trait UpdateTestExt {
    fn process_begin_block_test(&mut self, block_number: u64) -> Result<()>;
}

impl UpdateTestExt for Update<'_> {
    fn process_begin_block_test(&mut self, block_number: u64) -> Result<()> {
        let ctx = block_ctx(self.storage.clone(), block_number);
        self.process_begin_block_with_handlers(&ctx, &EMPTY_UPGRADE_HANDLER_REGISTRY)
    }
}
