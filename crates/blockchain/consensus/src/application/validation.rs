//! Pure block-acceptance rules for the application handler.
//!
//! These are the deterministic "what makes a proposed block invalid?" checks,
//! lifted out of `handler.rs`'s propose/verify event loop. They take an
//! immutable block plus the scheme/committee providers and return a `Result` —
//! no clock, no marshal, no runtime state — so they read and test as a
//! standalone validation layer. `handler` calls them; the tests below exercise
//! them directly.

use alloy_consensus::{BlockHeader as _, SignableTransaction as _, Transaction as _};
use alloy_primitives::{Address, B256};
use commonware_consensus::types::Round;
use commonware_cryptography::{
    bls12381::{primitives::variant::MinSig, PublicKey},
    certificate::{Provider as _, Scheme as _},
};
use commonware_utils::ordered::Quorum as _;
use outbe_primitives::addresses::REWARDS_ADDRESS;
use reth_ethereum::primitives::SignedTransaction as _;

use crate::block::ConsensusBlock;
use crate::committee_provider::CommitteeProvider;
use crate::digest::Digest;
use crate::hybrid::HybridSchemeProvider;

/// Resolve the EVM address of the consensus leader for `round`: map the
/// proposer's BLS key to its participant index, then to the ordered EVM
/// committee entry.
fn consensus_leader_evm_address(
    round: Round,
    proposer: &PublicKey,
    certificate_scheme_provider: &HybridSchemeProvider<MinSig>,
    committee_provider: &CommitteeProvider,
) -> Result<Address, String> {
    let epoch = round.epoch();
    let scheme = certificate_scheme_provider
        .scoped(epoch)
        .ok_or_else(|| format!("missing certificate scheme for epoch {epoch}"))?;
    let participant = scheme.participants().index(proposer).ok_or_else(|| {
        format!("consensus leader public key is not in epoch {epoch} participant set")
    })?;
    let index: usize = participant
        .get()
        .try_into()
        .map_err(|_| format!("participant index {} does not fit usize", participant.get()))?;
    let committee = committee_provider
        .ordered_committee(epoch)
        .ok_or_else(|| format!("missing ordered EVM committee for epoch {epoch}"))?;

    committee.get(index).copied().ok_or_else(|| {
        format!("ordered EVM committee for epoch {epoch} is missing participant index {index}")
    })
}

/// A non-genesis block's beneficiary must be the protocol `REWARDS_ADDRESS`.
pub(crate) fn validate_rewards_beneficiary(block: &ConsensusBlock) -> Result<(), String> {
    if block.number() > 0 && block.header().beneficiary() != REWARDS_ADDRESS {
        return Err(format!(
            "non-genesis block beneficiary must be REWARDS_ADDRESS {}: got {}",
            REWARDS_ADDRESS,
            block.header().beneficiary()
        ));
    }
    Ok(())
}

/// The proposed block must extend the Simplex context parent: matching parent
/// digest and height (`parent.number() + 1`, or `1` at genesis).
pub(crate) fn validate_context_parent_binding(
    block: &ConsensusBlock,
    parent_block: Option<&ConsensusBlock>,
    context_parent_digest: Digest,
    genesis_hash: B256,
) -> Result<(), String> {
    if block.parent_digest() != context_parent_digest {
        return Err(format!(
            "proposed block parent digest {} does not match Simplex context parent {}",
            block.parent_digest().0,
            context_parent_digest.0
        ));
    }

    let expected_number = if context_parent_digest.0 == genesis_hash {
        1
    } else {
        let parent = parent_block.ok_or_else(|| {
            "non-genesis Simplex context parent was not resolved for height validation".to_string()
        })?;
        if parent.digest() != context_parent_digest {
            return Err(format!(
                "resolved parent digest {} does not match Simplex context parent {}",
                parent.digest().0,
                context_parent_digest.0
            ));
        }
        parent.number().checked_add(1).ok_or_else(|| {
            "parent block number overflow while validating proposal height".to_string()
        })?
    };

    if block.number() != expected_number {
        return Err(format!(
            "proposed block number {} does not extend Simplex parent height {}",
            block.number(),
            expected_number.saturating_sub(1)
        ));
    }

    Ok(())
}

/// Validate the begin/end system-transaction set: layout, the mandatory
/// CertifiedParentAccounting parent-hash binding, BoundaryOutcome consistency
/// with the header artifact, per-tx signature-hash binding, and that every
/// system tx is signed by the consensus leader's EVM address.
pub(crate) fn validate_system_tx_leader_binding(
    block: &ConsensusBlock,
    round: Round,
    proposer: &PublicKey,
    chain_id: u64,
    certificate_scheme_provider: &HybridSchemeProvider<MinSig>,
    committee_provider: &CommitteeProvider,
) -> Result<(), String> {
    let raw_block = block.clone().into_inner().into_block();
    let artifacts = outbe_primitives::reshare_artifact::decode_outbe_block_artifacts(
        raw_block.header.extra_data().as_ref(),
    )
    .map_err(|error| format!("decode Outbe block artifacts for system tx validation: {error}"))?;

    let layout = outbe_primitives::system_tx::split_system_layout(&raw_block.body.transactions)
        .map_err(|error| format!("invalid system tx layout for leader binding: {error}"))?;
    let has_boundary_outcome = matches!(
        &artifacts.consensus_header_artifact,
        Some(outbe_primitives::reshare_artifact::ConsensusHeaderArtifact::BoundaryOutcome(_))
    );
    let has_tee_bootstrap =
        layout.has_begin_kind(outbe_primitives::system_tx::SystemTxKind::TeeBootstrap);
    outbe_primitives::system_tx::validate_active_system_tx_set(
        &layout,
        raw_block.header.number(),
        has_boundary_outcome,
        has_tee_bootstrap,
    )
    .map_err(|error| format!("invalid system tx set: {error}"))?;

    if layout.system_tx_count() == 0 {
        return Ok(());
    }

    if raw_block.header.number() >= 2 {
        let finalization_tx = *layout
            .begin
            .first()
            .ok_or_else(|| "missing CertifiedParentAccounting system tx".to_string())?;
        let input =
            outbe_primitives::system_tx::SystemTxInputV2::decode(finalization_tx.input().as_ref())
                .map_err(|error| {
                    format!("decode CertifiedParentAccounting system tx input: {error}")
                })?;
        let outbe_primitives::system_tx::SystemTxInputV2::CertifiedParentAccounting { metadata } =
            input
        else {
            return Err("expected CertifiedParentAccounting system tx at begin ordinal 0".into());
        };
        if metadata.finalized_block_hash != raw_block.header.parent_hash() {
            return Err(format!(
                "CertifiedParentAccounting metadata hash must match block parent: expected {}, got {}",
                raw_block.header.parent_hash(),
                metadata.finalized_block_hash
            ));
        }
    }

    if let Some(outbe_primitives::reshare_artifact::ConsensusHeaderArtifact::BoundaryOutcome(
        header_artifact,
    )) = artifacts.consensus_header_artifact.as_ref()
    {
        let mut found = false;
        for tx in layout.begin.iter().chain(layout.end.iter()) {
            let tx = *tx;
            let input = outbe_primitives::system_tx::SystemTxInputV2::decode(tx.input().as_ref())
                .map_err(|error| format!("decode system transaction input: {error}"))?;
            if let outbe_primitives::system_tx::SystemTxInputV2::BoundaryOutcome { artifact } =
                input
            {
                if &artifact != header_artifact {
                    return Err("BoundaryOutcome system tx artifact mismatch".into());
                }
                found = true;
            }
        }
        if !found {
            return Err("missing BoundaryOutcome system tx for header artifact".into());
        }
    }

    for (ordinal, tx) in layout.begin.iter().chain(layout.end.iter()).enumerate() {
        let tx = *tx;
        let input = outbe_primitives::system_tx::SystemTxInputV2::decode(tx.input().as_ref())
            .map_err(|error| format!("decode system transaction input: {error}"))?;
        let ordinal: u8 = ordinal
            .try_into()
            .map_err(|_| format!("system tx ordinal {ordinal} exceeds u8 range"))?;
        let unsigned = outbe_primitives::system_tx::build_unsigned_system_tx(
            input.kind(),
            ordinal,
            raw_block.header.number(),
            chain_id,
            input.encode().map_err(|error| error.to_string())?,
        )
        .map_err(|error| format!("build unsigned system transaction: {error}"))?;
        if tx.signature_hash() != unsigned.signature_hash() {
            return Err(format!(
                "system tx signature_hash mismatch for {:?} at ordinal {}",
                input.kind(),
                ordinal
            ));
        }
    }

    let expected = consensus_leader_evm_address(
        round,
        proposer,
        certificate_scheme_provider,
        committee_provider,
    )?;
    for tx in layout.begin.iter().chain(layout.end.iter()) {
        let signer = tx
            .try_recover()
            .map_err(|error| format!("recover system tx signer for leader binding: {error}"))?;
        if signer != expected {
            return Err(format!(
                "system tx signer {signer} does not match consensus leader EVM address {expected}"
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        validate_context_parent_binding, validate_rewards_beneficiary,
        validate_system_tx_leader_binding,
    };
    use crate::digest::Digest;
    use crate::dkg_manager;
    use crate::test_fixtures::*;
    use alloy_primitives::{Bytes, B256};
    use commonware_consensus::types::{Epoch, Round, View};
    use commonware_cryptography::Signer as _;
    use outbe_primitives::reshare_artifact::{
        encode_consensus_header_artifact, ConsensusHeaderArtifact,
    };
    use outbe_primitives::signer::OutbeEvmSigner;
    use outbe_primitives::system_tx::SystemTxInputV2;

    #[test]
    fn rewards_beneficiary_rejects_non_genesis_mismatch() {
        let block = block_with_number_and_parent(1, B256::ZERO);
        let error = validate_rewards_beneficiary(&block)
            .expect_err("non-genesis beneficiary must be rewards escrow");
        assert!(error.contains("beneficiary must be REWARDS_ADDRESS"));
    }

    #[test]
    fn context_parent_binding_accepts_direct_child() {
        let parent = block_with_number(7);
        let child = block_with_number_and_parent(8, parent.block_hash());

        validate_context_parent_binding(&child, Some(&parent), parent.digest(), B256::ZERO)
            .expect("direct child extends Simplex context parent");
    }

    #[test]
    fn context_parent_binding_rejects_wrong_parent_digest() {
        let parent = block_with_number(7);
        let child = block_with_number_and_parent(8, B256::from([0x44; 32]));

        let error =
            validate_context_parent_binding(&child, Some(&parent), parent.digest(), B256::ZERO)
                .expect_err("child must bind header parent to Simplex context parent");
        assert!(error.contains("does not match Simplex context parent"));
    }

    #[test]
    fn context_parent_binding_rejects_height_gap() {
        let parent = block_with_number(7);
        let child = block_with_number_and_parent(9, parent.block_hash());

        let error =
            validate_context_parent_binding(&child, Some(&parent), parent.digest(), B256::ZERO)
                .expect_err("child height must be parent height plus one");
        assert!(error.contains("does not extend Simplex parent height"));
    }

    #[test]
    fn context_parent_binding_accepts_genesis_parent_for_block_one() {
        let genesis_hash = B256::from([0x55; 32]);
        let child = block_with_number_and_parent(1, genesis_hash);

        validate_context_parent_binding(&child, None, Digest(genesis_hash), genesis_hash)
            .expect("block 1 extends genesis parent");
    }

    #[test]
    fn system_tx_validation_rejects_missing_mandatory_kind_before_engine_status() {
        let (keys, _) = participants();
        let validator_set = validator_set_from_keys(&keys);
        let (scheme_provider, committee_provider) =
            leader_binding_providers(Epoch::new(0), &validator_set);
        let block = block_with_number(1);

        let error = validate_system_tx_leader_binding(
            &block,
            Round::new(Epoch::new(0), View::new(1)),
            &keys[0].public_key(),
            outbe_primitives::chain::CHAIN_ID,
            &scheme_provider,
            &committee_provider,
        )
        .expect_err("block 1 must carry mandatory CycleTick system tx");

        assert!(error.contains("invalid system tx set"));
    }

    #[test]
    fn system_tx_leader_binding_accepts_consensus_leader_address() {
        let (keys, _) = participants();
        let signer = OutbeEvmSigner::from_secret_bytes([7u8; 32]).unwrap();
        let mut validator_set = validator_set_from_keys(&keys);
        validator_set.addresses[0] = signer.address();
        let (scheme_provider, committee_provider) =
            leader_binding_providers(Epoch::new(0), &validator_set);
        let block = block_with_system_tx(&signer);

        validate_system_tx_leader_binding(
            &block,
            Round::new(Epoch::new(0), View::new(1)),
            &keys[0].public_key(),
            outbe_primitives::chain::CHAIN_ID,
            &scheme_provider,
            &committee_provider,
        )
        .expect("system tx signer matches consensus leader EVM address");
    }

    #[test]
    fn system_tx_leader_binding_uses_epoch_registered_committee() {
        let (keys, _) = participants();
        let signer = OutbeEvmSigner::from_secret_bytes([9u8; 32]).unwrap();
        let mut validator_set = validator_set_from_keys(&keys);
        validator_set.addresses[1] = signer.address();
        let (scheme_provider, committee_provider) =
            leader_binding_providers(Epoch::new(1), &validator_set);
        let block = block_with_system_tx(&signer);

        validate_system_tx_leader_binding(
            &block,
            Round::new(Epoch::new(1), View::new(1)),
            &keys[1].public_key(),
            outbe_primitives::chain::CHAIN_ID,
            &scheme_provider,
            &committee_provider,
        )
        .expect("epoch-scoped committee maps current leader to EVM signer");
    }

    #[test]
    fn system_tx_leader_binding_rejects_non_leader_signer() {
        let (keys, _) = participants();
        let leader_signer = OutbeEvmSigner::from_secret_bytes([7u8; 32]).unwrap();
        let non_leader_signer = OutbeEvmSigner::from_secret_bytes([8u8; 32]).unwrap();
        let mut validator_set = validator_set_from_keys(&keys);
        validator_set.addresses[0] = leader_signer.address();
        validator_set.addresses[1] = non_leader_signer.address();
        let (scheme_provider, committee_provider) =
            leader_binding_providers(Epoch::new(0), &validator_set);
        let block = block_with_system_tx(&non_leader_signer);

        let error = validate_system_tx_leader_binding(
            &block,
            Round::new(Epoch::new(0), View::new(1)),
            &keys[0].public_key(),
            outbe_primitives::chain::CHAIN_ID,
            &scheme_provider,
            &committee_provider,
        )
        .expect_err("non-leader system tx signer must be rejected");
        assert!(error.contains("does not match consensus leader EVM address"));
    }

    #[test]
    fn system_tx_validation_rejects_wrong_chain_id_before_engine_status() {
        let (keys, _) = participants();
        let signer = OutbeEvmSigner::from_secret_bytes([7u8; 32]).unwrap();
        let mut validator_set = validator_set_from_keys(&keys);
        validator_set.addresses[0] = signer.address();
        let (scheme_provider, committee_provider) =
            leader_binding_providers(Epoch::new(0), &validator_set);
        let block = block_with_system_tx(&signer);

        let error = validate_system_tx_leader_binding(
            &block,
            Round::new(Epoch::new(0), View::new(1)),
            &keys[0].public_key(),
            outbe_primitives::chain::CHAIN_ID + 1,
            &scheme_provider,
            &committee_provider,
        )
        .expect_err("wrong active chain id must be rejected before Engine status");
        assert!(error.contains("system tx signature_hash mismatch"));
    }

    #[test]
    fn system_tx_validation_rejects_finalization_parent_hash_mismatch_before_engine_status() {
        let (keys, _) = participants();
        let signer = OutbeEvmSigner::from_secret_bytes([7u8; 32]).unwrap();
        let mut validator_set = validator_set_from_keys(&keys);
        validator_set.addresses[0] = signer.address();
        let (scheme_provider, committee_provider) =
            leader_binding_providers(Epoch::new(0), &validator_set);
        let parent_hash = B256::from([0x11; 32]);
        let wrong_hash = B256::from([0x22; 32]);
        let block = block_with_system_inputs(
            &signer,
            2,
            parent_hash,
            Bytes::new(),
            vec![
                SystemTxInputV2::CertifiedParentAccounting {
                    metadata: finalized_metadata(wrong_hash),
                },
                SystemTxInputV2::LateFinalizeCredits {
                    artifact: Default::default(),
                },
                SystemTxInputV2::CycleTick,
                SystemTxInputV2::OracleSlashWindow,
                SystemTxInputV2::HookEvents,
            ],
            outbe_primitives::chain::CHAIN_ID,
        );

        let error = validate_system_tx_leader_binding(
            &block,
            Round::new(Epoch::new(0), View::new(1)),
            &keys[0].public_key(),
            outbe_primitives::chain::CHAIN_ID,
            &scheme_provider,
            &committee_provider,
        )
        .expect_err(
            "CertifiedParentAccounting metadata must bind to header parent hash before Engine status",
        );
        assert!(error.contains("CertifiedParentAccounting metadata hash must match block parent"));
    }

    #[test]
    fn system_tx_validation_rejects_boundary_calldata_mismatch_before_engine_status() {
        let (keys, _participants, output, _polynomial, _dealer_log) = dkg_runtime_artifacts();
        let signer = OutbeEvmSigner::from_secret_bytes([7u8; 32]).unwrap();
        let mut validator_set = validator_set_from_keys(&keys);
        validator_set.addresses[0] = signer.address();
        let header_artifact =
            dkg_manager::build_boundary_artifact(dkg_manager::BoundaryArtifactInput {
                epoch: Epoch::new(0),
                validator_set: &validator_set,
                output: &output,
                is_full_dkg: true,
                dkg_cycle: 0,
                freeze_height: 0,
                planned_activation_height: 0,
                vrf_material_version: 0,
                is_validator_set_change: true,
                tee_reshare_registrations: Vec::new(),
            })
            .unwrap();
        let mut tx_artifact = header_artifact.clone();
        tx_artifact.planned_activation_height =
            tx_artifact.planned_activation_height.saturating_add(1);

        let (scheme_provider, committee_provider) =
            leader_binding_providers(Epoch::new(0), &validator_set);
        let parent_hash = B256::from([0x33; 32]);
        let block = block_with_system_inputs(
            &signer,
            2,
            parent_hash,
            encode_consensus_header_artifact(&ConsensusHeaderArtifact::BoundaryOutcome(
                header_artifact,
            ))
            .expect("header artifact encodes"),
            vec![
                SystemTxInputV2::CertifiedParentAccounting {
                    metadata: finalized_metadata(parent_hash),
                },
                SystemTxInputV2::LateFinalizeCredits {
                    artifact: Default::default(),
                },
                SystemTxInputV2::CycleTick,
                SystemTxInputV2::BoundaryOutcome {
                    artifact: tx_artifact,
                },
                SystemTxInputV2::OracleSlashWindow,
                SystemTxInputV2::HookEvents,
            ],
            outbe_primitives::chain::CHAIN_ID,
        );

        let error = validate_system_tx_leader_binding(
            &block,
            Round::new(Epoch::new(0), View::new(1)),
            &keys[0].public_key(),
            outbe_primitives::chain::CHAIN_ID,
            &scheme_provider,
            &committee_provider,
        )
        .expect_err("BoundaryOutcome calldata must bind to header artifact before Engine status");
        assert!(error.contains("BoundaryOutcome system tx artifact mismatch"));
    }
}
