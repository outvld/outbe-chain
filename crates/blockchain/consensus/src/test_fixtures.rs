//! Shared unit-test fixtures used by more than one module's `#[cfg(test)]`
//! tests.
//!
//! These builders were originally local to `application::handler`'s test
//! module. The DKG boundary-resolution tests moved to `dkg_manager::tests`
//! (where the logic now lives), and both test modules need the same
//! `ConsensusBlock` builders, validator-set helper, deterministic DKG runtime
//! artifacts, and the in-memory `AncestryReader`. Promoting them here keeps a
//! single definition instead of duplicating across modules.

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use alloy_primitives::{address, Address, Bytes, B256};
use commonware_codec::Encode as _;
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::{
        self,
        dkg::feldman_desmedt::{Dealer, Info, Logs, Output, Player},
        primitives::{
            sharing::{Mode, Sharing},
            variant::MinSig,
        },
        Batch,
    },
    Signer as _,
};
use commonware_math::algebra::Random;
use commonware_parallel::Sequential;
use commonware_utils::{ordered::Set, N3f1, TryCollect as _};
use outbe_primitives::consensus_metadata::CertifiedParentAccountingMetadata;
use outbe_primitives::reshare_artifact::{
    encode_consensus_header_artifact, ConsensusHeaderArtifact,
};
use outbe_primitives::signer::OutbeEvmSigner;
use outbe_primitives::system_tx::{build_unsigned_system_tx, SystemTxInputV2};
use outbe_primitives::OutbeHeader;
use reth_ethereum::{primitives::SealedBlock, Block, TransactionSigned};

use crate::block::ConsensusBlock;
use crate::committee_provider::CommitteeProvider;
use crate::dkg_manager::{AncestryReader, BlockLookupFuture};
use crate::hybrid::{HybridScheme, HybridSchemeProvider};

pub(crate) const V1: Address = address!("0x1111111111111111111111111111111111111111");
pub(crate) const V2: Address = address!("0x2222222222222222222222222222222222222222");
pub(crate) const V3: Address = address!("0x3333333333333333333333333333333333333333");
pub(crate) const V4: Address = address!("0x4444444444444444444444444444444444444444");

/// In-memory [`AncestryReader`] for tests: serves blocks by height/hash from
/// preloaded maps and counts lookups so tests can assert ancestry was (not)
/// consulted.
#[derive(Clone, Default)]
pub(crate) struct TestAncestryReader {
    blocks_by_height: BTreeMap<u64, ConsensusBlock>,
    blocks_by_hash: BTreeMap<B256, ConsensusBlock>,
    ready: bool,
    height_lookups: Arc<AtomicUsize>,
    hash_lookups: Arc<AtomicUsize>,
}

impl TestAncestryReader {
    pub(crate) fn ready() -> Self {
        Self {
            blocks_by_height: BTreeMap::new(),
            blocks_by_hash: BTreeMap::new(),
            ready: true,
            height_lookups: Arc::new(AtomicUsize::new(0)),
            hash_lookups: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(crate) fn not_ready() -> Self {
        Self {
            blocks_by_height: BTreeMap::new(),
            blocks_by_hash: BTreeMap::new(),
            ready: false,
            height_lookups: Arc::new(AtomicUsize::new(0)),
            hash_lookups: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(crate) fn with_block(mut self, block: ConsensusBlock) -> Self {
        self.blocks_by_height.insert(block.number(), block);
        self
    }

    pub(crate) fn with_hash_block(mut self, block: ConsensusBlock) -> Self {
        self.blocks_by_hash.insert(block.block_hash(), block);
        self
    }

    pub(crate) fn lookup_count(&self) -> usize {
        self.height_lookups.load(Ordering::SeqCst) + self.hash_lookups.load(Ordering::SeqCst)
    }
}

impl AncestryReader for TestAncestryReader {
    fn get_block_by_height<'a>(&'a self, height: u64) -> BlockLookupFuture<'a> {
        self.height_lookups.fetch_add(1, Ordering::SeqCst);
        let block = self.blocks_by_height.get(&height).cloned();
        Box::pin(async move { block })
    }

    fn get_block_by_hash<'a>(&'a self, hash: B256) -> BlockLookupFuture<'a> {
        self.hash_lookups.fetch_add(1, Ordering::SeqCst);
        let block = self.blocks_by_hash.get(&hash).cloned().or_else(|| {
            self.blocks_by_height
                .values()
                .find(|block| block.block_hash() == hash)
                .cloned()
        });
        Box::pin(async move { block })
    }

    fn is_ready(&self) -> bool {
        self.ready
    }
}

pub(crate) fn validator_set_from_keys(
    keys: &[bls12381::PrivateKey],
) -> crate::validators::ValidatorSet {
    let addresses = [V1, V2, V3, V4];
    crate::validators::ValidatorSet {
        public_keys: keys.iter().map(|key| key.public_key()).collect(),
        addresses: addresses[..keys.len()].to_vec(),
        p2p_addresses: vec![crate::validators::ValidatorP2pAddress::Missing; keys.len()],
    }
}

pub(crate) fn block_with_header_artifact(artifact: &ConsensusHeaderArtifact) -> ConsensusBlock {
    let mut block = Block::default();
    block.header.extra_data = encode_consensus_header_artifact(artifact).unwrap();
    let block = block.map_header(OutbeHeader::new);
    ConsensusBlock::from_sealed(SealedBlock::seal_slow(block))
}

pub(crate) fn block_with_number_parent_and_header_artifact(
    number: u64,
    parent_hash: B256,
    artifact: &ConsensusHeaderArtifact,
) -> ConsensusBlock {
    let mut block = Block::default();
    block.header.number = number;
    block.header.parent_hash = parent_hash;
    block.header.extra_data = encode_consensus_header_artifact(artifact).unwrap();
    let block = block.map_header(OutbeHeader::new);
    ConsensusBlock::from_sealed(SealedBlock::seal_slow(block))
}

pub(crate) fn block_with_number(number: u64) -> ConsensusBlock {
    block_with_number_and_parent(number, B256::ZERO)
}

pub(crate) fn block_with_number_and_parent(number: u64, parent_hash: B256) -> ConsensusBlock {
    let mut block = Block::default();
    block.header.number = number;
    block.header.parent_hash = parent_hash;
    let block = block.map_header(OutbeHeader::new);
    ConsensusBlock::from_sealed(SealedBlock::seal_slow(block))
}

#[allow(clippy::type_complexity)]
pub(crate) fn dkg_runtime_artifacts() -> (
    Vec<bls12381::PrivateKey>,
    Set<bls12381::PublicKey>,
    Output<MinSig, bls12381::PublicKey>,
    Sharing<MinSig>,
    Bytes,
) {
    let mut keys: Vec<bls12381::PrivateKey> = (0..3)
        .map(|_| bls12381::PrivateKey::random(rand_core::OsRng))
        .collect();
    keys.sort_by_key(|a| a.public_key().encode());

    let participants: Set<bls12381::PublicKey> =
        keys.iter().map(|k| k.public_key()).try_collect().unwrap();

    let info = Info::<MinSig, bls12381::PublicKey>::new::<N3f1>(
        &crate::config::outbe_app_namespace(),
        7,
        None,
        Mode::NonZeroCounter,
        participants.clone(),
        participants.clone(),
    )
    .unwrap();

    let mut dealers = Vec::new();
    let mut pub_msgs = Vec::new();
    let mut all_priv_msgs = Vec::new();

    for key in &keys {
        let (dealer, pub_msg, priv_msgs) = Dealer::<MinSig, bls12381::PrivateKey>::start::<N3f1>(
            rand_core::OsRng,
            info.clone(),
            key.clone(),
            None,
        )
        .unwrap();
        dealers.push(dealer);
        pub_msgs.push(pub_msg);
        all_priv_msgs.push(priv_msgs);
    }

    let mut players: Vec<Player<MinSig, bls12381::PrivateKey>> = keys
        .iter()
        .map(|k| Player::new(info.clone(), k.clone()).unwrap())
        .collect();

    for (dealer_idx, (pub_msg, priv_msgs)) in pub_msgs.iter().zip(all_priv_msgs.iter()).enumerate()
    {
        let dealer_pk = keys[dealer_idx].public_key();
        for (player_pk, priv_msg) in priv_msgs {
            let player_idx = keys
                .iter()
                .position(|k| &k.public_key() == player_pk)
                .unwrap();
            if let Some(ack) = players[player_idx].dealer_message::<N3f1>(
                dealer_pk.clone(),
                pub_msg.clone(),
                priv_msg.clone(),
            ) {
                dealers[dealer_idx]
                    .receive_player_ack(player_pk.clone(), ack)
                    .unwrap();
            }
        }
    }

    let mut logs = std::collections::BTreeMap::new();
    let mut first_log = None;
    for dealer in dealers {
        let signed_log = dealer.finalize::<N3f1>();
        if first_log.is_none() {
            first_log = Some(Bytes::from(signed_log.encode()));
        }
        if let Some((pk, log)) = signed_log.check(&info) {
            logs.insert(pk, log);
        }
    }

    let mut dkg_logs = Logs::<MinSig, bls12381::PublicKey, N3f1>::new(info.clone());
    for (dealer_pk, log) in logs {
        dkg_logs.record(dealer_pk, log);
    }
    let (output, _share) = players
        .remove(0)
        .finalize::<N3f1, Batch>(&mut rand_core::OsRng, dkg_logs, &Sequential)
        .unwrap();
    let polynomial = output.public().clone();

    (keys, participants, output, polynomial, first_log.unwrap())
}

// ---- Promoted from application::handler test module (shared system-tx fixtures) ----

pub(crate) fn leader_binding_providers(
    epoch: Epoch,
    validator_set: &crate::validators::ValidatorSet,
) -> (HybridSchemeProvider<MinSig>, CommitteeProvider) {
    let participants: Set<bls12381::PublicKey> = validator_set
        .public_keys
        .iter()
        .cloned()
        .try_collect()
        .expect("participants should build");
    let dkg = crate::bls::bootstrap_dkg(
        validator_set
            .public_keys
            .len()
            .try_into()
            .expect("validator count fits u32"),
    )
    .expect("bootstrap dkg should succeed");
    let verifier = HybridScheme::<MinSig>::verifier(
        &crate::config::outbe_app_namespace(),
        participants.clone(),
        dkg.polynomial,
    )
    .expect("verifier scheme should build");
    let ordered_committee = participants
        .iter()
        .map(|public_key| {
            let index = validator_set
                .public_keys
                .iter()
                .position(|candidate| candidate == public_key)
                .expect("participant exists in validator set");
            validator_set.addresses[index]
        })
        .collect();

    let scheme_provider = HybridSchemeProvider::new();
    let committee_provider = CommitteeProvider::new();
    assert!(scheme_provider.register(epoch, verifier));
    assert!(committee_provider.register(epoch, ordered_committee));
    (scheme_provider, committee_provider)
}

pub(crate) fn participants_with_count(
    n: u64,
) -> (Vec<bls12381::PrivateKey>, Set<bls12381::PublicKey>) {
    let keys: Vec<bls12381::PrivateKey> = (0..n)
        .map(|i| bls12381::PrivateKey::from_seed(i + 1))
        .collect();
    let participants: Set<bls12381::PublicKey> = keys
        .iter()
        .map(|sk| bls12381::PublicKey::from(sk.clone()))
        .try_collect()
        .expect("participants should build");
    (keys, participants)
}

pub(crate) fn participants() -> (Vec<bls12381::PrivateKey>, Set<bls12381::PublicKey>) {
    participants_with_count(3)
}

pub(crate) fn sign_system_input(
    signer: &OutbeEvmSigner,
    input: SystemTxInputV2,
    ordinal: u8,
    block_number: u64,
    chain_id: u64,
) -> TransactionSigned {
    let unsigned = build_unsigned_system_tx(
        input.kind(),
        ordinal,
        block_number,
        chain_id,
        input.encode().expect("input encodes"),
    )
    .expect("system tx builds");
    signer.sign_unsigned(unsigned).expect("system tx signs")
}

pub(crate) fn finalized_metadata(finalized_block_hash: B256) -> CertifiedParentAccountingMetadata {
    CertifiedParentAccountingMetadata {
        finalized_block_number: 1,
        finalized_block_hash,
        finalized_view: 1,
        ..Default::default()
    }
}

pub(crate) fn block_with_system_inputs(
    signer: &OutbeEvmSigner,
    block_number: u64,
    parent_hash: B256,
    extra_data: Bytes,
    inputs: Vec<SystemTxInputV2>,
    chain_id: u64,
) -> ConsensusBlock {
    let mut block = Block::default();
    block.header.number = block_number;
    block.header.parent_hash = parent_hash;
    block.header.extra_data = extra_data;
    for (ordinal, input) in inputs.into_iter().enumerate() {
        block.body.transactions.push(sign_system_input(
            signer,
            input,
            ordinal.try_into().expect("test ordinal fits"),
            block_number,
            chain_id,
        ));
    }
    let block = block.map_header(OutbeHeader::new);
    ConsensusBlock::from_sealed(SealedBlock::seal_slow(block))
}

pub(crate) fn block_with_system_tx(signer: &OutbeEvmSigner) -> ConsensusBlock {
    // block 1 mandatorily carries a BoundaryOutcome under V2,
    // so the minimum-shape "block with system txs" test fixture moved to
    // block 2 where the canonical layout is
    // `[CertifiedParentAccounting, LateFinalizeCredits, CycleTick,
    // OracleSlashWindow, HookEvents]`.
    let parent_hash = B256::ZERO;
    block_with_system_inputs(
        signer,
        2,
        parent_hash,
        Bytes::new(),
        vec![
            SystemTxInputV2::CertifiedParentAccounting {
                metadata: finalized_metadata(parent_hash),
            },
            SystemTxInputV2::LateFinalizeCredits {
                artifact: Default::default(),
            },
            SystemTxInputV2::CycleTick,
            SystemTxInputV2::OracleSlashWindow,
            SystemTxInputV2::HookEvents,
        ],
        outbe_primitives::chain::CHAIN_ID,
    )
}
