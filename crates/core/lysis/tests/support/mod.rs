use alloy_primitives::{B256, U256};
use outbe_ocomp_protocol::{
    hash::hash_framed,
    intent::{
        ActivationPreconditionsV1, AuctionEntryPriceSource, ContributorTargetPreconditionV1,
        DayType, FrozenMetadosisValuesV1, JobIntentV1, MetadosisAttemptPreconditionV1,
        MetadosisExpectedStatus, NodTargetPreconditionV1, ReferenceEntryPriceV1,
        TributeInputBindingV1,
    },
    profile::poc_schema_limits,
    receipts::{desis_request_brief_hash, BudgetSplitDestination, RequestBudgetSplitReceiptV1},
    registry::HashDomain,
    result::{
        lysis_v1_empty_semantic_event_root, ActivationPayloadV1, CarryOverCreditActionV1,
        CarryOverReason, CompletionStatus, ConservationTotalsV1, ExactCountsV1,
        LysisArithmeticSummaryV1, LysisResultV1, MetadosisCompletionSummaryV1, ResultRootsV1,
    },
    SchemaLimits,
};

pub struct ActivationFixtureV1 {
    pub limits: SchemaLimits,
    pub intent_id: B256,
    pub job_id: B256,
    pub intent: JobIntentV1,
    pub payload: ActivationPayloadV1,
    pub result: LysisResultV1,
    pub request_receipt: RequestBudgetSplitReceiptV1,
}

pub fn hash(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}

pub fn activation_fixture(day_type: DayType) -> ActivationFixtureV1 {
    let limits = poc_schema_limits();
    let job_id = hash(59);
    let request_receipt = request_receipt(day_type);
    let request_receipt_hash = request_receipt.receipt_hash(&limits).unwrap();
    let intent = intent(day_type, request_receipt_hash);
    let intent_id = intent.intent_id(&limits).unwrap();
    let result = result(day_type, job_id, &limits);
    let payload = result.activation_payload(&limits).unwrap();
    ActivationFixtureV1 {
        limits,
        intent_id,
        job_id,
        intent,
        payload,
        result,
        request_receipt,
    }
}

pub fn recommit_result(result: &mut LysisResultV1, limits: &SchemaLimits) {
    result.arithmetic_commitment = hash_framed(
        HashDomain::LysisArithmetic,
        &result
            .arithmetic_summary()
            .encode_canonical(limits)
            .unwrap(),
    )
    .unwrap();
}

fn request_receipt(day_type: DayType) -> RequestBudgetSplitReceiptV1 {
    let protocol_bundle_hash = hash(41);
    let wwd = 7;
    let auction_base = U256::from(40);
    let auction_entry_prices = vec![ReferenceEntryPriceV1 {
        reference_currency: outbe_oracle::constants::DAY_TYPE_ISO,
        entry_price_minor: U256::from(9),
        source: AuctionEntryPriceSource::LastClosedDayVwap,
        source_day: 6,
    }];
    let logical_anchor = 1_000;
    let green = day_type == DayType::Green;
    RequestBudgetSplitReceiptV1 {
        protocol_bundle_hash,
        wwd,
        pending_nonce: 0,
        day_type,
        day_limit: U256::from(100),
        lysis_budget: U256::from(60),
        auction_base,
        destination: if green {
            BudgetSplitDestination::DesisAuction
        } else {
            BudgetSplitDestination::CarryOver
        },
        desis_brief_hash: Some(
            desis_request_brief_hash(
                protocol_bundle_hash,
                wwd,
                if green { auction_base } else { U256::ZERO },
                &auction_entry_prices,
                logical_anchor,
            )
            .unwrap(),
        ),
        carry_over_credit: if green { U256::ZERO } else { auction_base },
        auction_entry_prices,
        logical_anchor,
    }
}

fn intent(day_type: DayType, request_receipt_hash: B256) -> JobIntentV1 {
    JobIntentV1 {
        chain_id: 42,
        genesis_hash: hash(40),
        fork_id: hash(1),
        wwd: 7,
        pending_nonce: 0,
        attempt: 0,
        protocol_bundle_hash: hash(41),
        ce_sealed_root: hash(42),
        sealed_tribute_collection_key: hash(30),
        sealed_tribute_collection_root: hash(31),
        authenticated_day_count: 2,
        authenticated_day_nominal: U256::from(1_000),
        pre_admission_envelope_hash: hash(43),
        source_availability_policy_id: hash(44),
        frozen_metadosis_values: FrozenMetadosisValuesV1 {
            day_type,
            day_limit: U256::from(100),
            previous_vwap: U256::from(8),
            current_vwap: U256::from(10),
            gratis_demand: U256::from(60),
            gratis_supply: U256::from(60),
            lysis_budget: U256::from(60),
            auction_base: U256::from(40),
            auction_entry_prices: vec![ReferenceEntryPriceV1 {
                reference_currency: outbe_oracle::constants::DAY_TYPE_ISO,
                entry_price_minor: U256::from(9),
                source: AuctionEntryPriceSource::LastClosedDayVwap,
                source_day: 6,
            }],
            request_budget_split_receipt_hash: request_receipt_hash,
        },
        logical_evaluation_height: 100,
        logical_evaluation_time: 1_000,
        activation_preconditions: ActivationPreconditionsV1 {
            tribute: TributeInputBindingV1 {
                wwd: 7,
                source_generation: 3,
                collection_key: hash(30),
                sealed_collection_root: hash(31),
                exact_count: 2,
                exact_nominal_total: U256::from(1_000),
            },
            nod: NodTargetPreconditionV1 {
                wwd: 7,
                target_generation: 5,
                namespace_root_before: hash(32),
                max_nod_count: 2,
            },
            contributors: ContributorTargetPreconditionV1 {
                worldwide_day: 7,
                expected_series_version: 8,
                max_contributor_count: 2,
                max_eligible_nominal_total: U256::from(1_000),
            },
            metadosis: MetadosisAttemptPreconditionV1 {
                wwd: 7,
                pending_nonce: 0,
                expected_status: MetadosisExpectedStatus::OffchainPending,
                state_version: 12,
            },
        },
        result_validator_set_epoch: 2,
        result_committee_set_hash: hash(45),
        result_ocomp_binding_hash: hash(46),
        result_member_count: 4,
        result_quorum_threshold: 3,
        custody_committee_epoch_hash: None,
    }
}

fn result(day_type: DayType, job_id: B256, limits: &SchemaLimits) -> LysisResultV1 {
    let roots = ResultRootsV1 {
        nod_root: hash(50),
        bucket_root: hash(51),
        contributor_root: hash(52),
        output_manifest_root: hash(53),
    };
    let counts = ExactCountsV1 {
        tribute_count: 2,
        nod_count: 2,
        bucket_count: 1,
        contributor_count: 1,
        semantic_event_count: 0,
    };
    let conservation = ConservationTotalsV1 {
        tribute_nominal_total: U256::from(1_000),
        eligible_nominal_total: U256::from(600),
        day_limit: U256::from(100),
        gratis_demand: U256::from(60),
        gratis_supply: U256::from(60),
        lysis_budget: U256::from(60),
        auction_base: U256::from(40),
        nod_gratis_consumed: U256::from(45),
        unused_lysis: U256::from(15),
        carry_over_credit: U256::from(15),
        nod_cost_total: U256::from(300),
    };
    let summary = LysisArithmeticSummaryV1 {
        input_manifest_hash: hash(54),
        plan_hash: hash(55),
        unit_artifact_root: hash(56),
        fidelity_fraction_root: hash(57),
        gratis_prefix_root: hash(58),
        roots: roots.clone(),
        counts: counts.clone(),
        conservation: conservation.clone(),
        first_error_ordinal: None,
    };
    LysisResultV1 {
        protocol_bundle_hash: hash(41),
        job_id,
        attempt: 0,
        input_manifest_hash: summary.input_manifest_hash,
        plan_hash: summary.plan_hash,
        unit_artifact_root: summary.unit_artifact_root,
        fidelity_fraction_root: summary.fidelity_fraction_root,
        gratis_prefix_root: summary.gratis_prefix_root,
        result_chunk_count: 2,
        result_chunk_list_root: hash(61),
        carry_over_credit: CarryOverCreditActionV1 {
            source_wwd: 7,
            reason: CarryOverReason::UnusedLysis,
            amount: U256::from(15),
        },
        metadosis_completion_summary: MetadosisCompletionSummaryV1 {
            wwd: 7,
            pending_nonce: 0,
            day_type,
            tribute_nominal_total: U256::from(1_000),
            day_limit: U256::from(100),
            gratis_demand: U256::from(60),
            gratis_supply: U256::from(60),
            lysis_budget: U256::from(60),
            auction_base: U256::from(40),
            nod_gratis_consumed: U256::from(45),
            unused_lysis: U256::from(15),
            carry_over_credit: U256::from(15),
            status: CompletionStatus::Completed,
            logical_evaluation_height: 100,
            logical_evaluation_time: 1_000,
        },
        tribute_count: 2,
        tribute_nominal_total: U256::from(1_000),
        unused_lysis: U256::from(15),
        roots,
        counts,
        conservation,
        arithmetic_commitment: hash_framed(
            HashDomain::LysisArithmetic,
            &summary.encode_canonical(limits).unwrap(),
        )
        .unwrap(),
        event_summary_hash: lysis_v1_empty_semantic_event_root().unwrap(),
    }
}
