// OCOMP-TEST-ID: OCM-REQ-001

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use alloy_consensus::{Block, Header, SignableTransaction, Transaction as _, TxEip1559};
use alloy_eips::{BlockId, BlockNumHash, BlockNumberOrTag};
use alloy_primitives::{address, keccak256, Address, Bytes, TxKind, B256, U256};
use alloy_rpc_types_engine::PayloadId;
use alloy_sol_types::{SolCall, SolEvent};
use commonware_codec::Encode;
use commonware_consensus::{
    simplex::types::{Finalization, Proposal},
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    bls12381::{
        primitives::{
            ops::{aggregate, keypair, sign_message},
            variant::{MinPk, MinSig, Variant},
        },
        PrivateKey, PublicKey,
    },
    certificate::Signers,
    sha256::Digest as Sha256Digest,
    Signer,
};
use commonware_utils::Participant;
use outbe_compressed_entities::{
    begin_block, end_block, CandidateCacheLimits, CeMdbx, CeTopologyV1, CeWorkConfig,
    CompressedTreeService, EnvironmentIdentity, ExactParentIdentity, ExecutionScope,
    FinalizedMarker, ACTIVE_COMMITMENT_SCHEME, LOCAL_STORAGE_SCHEMA_VERSION,
};
use outbe_consensus::{
    hybrid::HybridScheme,
    proof::{
        constants::finalize_namespace, hybrid_seed_namespace, CommitteeEntry, CommitteeSnapshot,
        HybridCertificate, VrfProof,
    },
};
use outbe_cycle::schema::Cycle;
use outbe_desis::{AuctionStage, DesisContract};
use outbe_evm::{
    system_tx::{split_system_layout, OcompLifecycleActivation, SystemTxInputV2, SystemTxKind},
    OutbeEvmConfig, OutbeEvmSigner, RethAccountedParentArtifactProvider,
};
use outbe_intex::IntexContract;
use outbe_metadosis::{
    config::poc_schema_limits,
    constants::{
        FORMING_PERIOD_HOURS, LOOKBACK_DELAY_HOURS, OFFERING_PERIOD_HOURS, SECONDS_PER_HOUR,
        WAITING_PERIOD_HOURS,
    },
    genesis::{FreshDevnetGenesisBuilder, GenesisWorldwideDay},
    precompile::IMetadosis,
    test_support::{ForkInstallScenario, ResultVotingScenario},
    WwdDayType,
};
use outbe_nod::NodContract;
use outbe_node::OutbePayloadBuilder;
use outbe_ocomp_protocol::{
    abi::encode_submit_lysis_result_calldata,
    state::{OcompJobRecordV1, OcompJobStatus, OcompTerminalOutcome},
};
use outbe_offchain_data::RuntimeBodyReaders;
use outbe_offchain_storage::{MemoryStorage, StorageReaderHandle};
use outbe_oracle::schema::OracleContract;
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    addresses::{
        COMPRESSED_ENTITIES_ADDRESS, METADOSIS_ADDRESS, REWARDS_ADDRESS, TRIBUTE_FACTORY_ADDRESS,
        VALIDATOR_SET_ADDRESS,
    },
    block::{BlockContext, BlockRuntimeContext},
    consensus_metadata::{CertifiedParentAccountingMetadata, ParentParticipationProof},
    projection::ExecutionReadBudget,
    reshare_artifact::{
        decode_outbe_block_artifacts, encode_outbe_block_artifacts, CompressedEntitiesRootArtifact,
        ExecutionSummaryArtifact, OutbeBlockArtifacts,
    },
    storage::{
        direct::DirectStorageProvider, hashmap::HashMapStorageProvider,
        MetadosisMutationPurposeTag, StorageHandle,
    },
    OutbeHeader, OutbePayloadAttributes, OutbePrimitives,
};
use outbe_tribute::{TributeContract, TributeData};
use outbe_txpool::OutbeTransactionOrdering;
use outbe_update::{schema::Update, ProtocolVersion};
use outbe_validatorset::{
    committee_snapshot_key, contract::ValidatorSet, read_committee_snapshot,
    write_committee_snapshot, CommitteeSnapshot as StoredCommitteeSnapshot,
};
use rand_core::OsRng;
use reth_basic_payload_builder::{BuildArguments, PayloadBuilder, PayloadConfig};
use reth_chainspec::{ChainInfo, ChainSpec, ChainSpecBuilder, ChainSpecProvider};
use reth_ethereum::{Transaction, TransactionSigned};
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_evm::{execute::Executor as _, ConfigureEvm, RecoveredTx};
use reth_payload_primitives::BuiltPayload as _;
use reth_primitives_traits::{
    crypto::secp256k1::sign_message as sign_secp256k1_message, Account, AlloyBlockHeader as _,
    Bytecode, SealedHeader, SignedTransaction,
};
use reth_provider::{
    test_utils::{ExtendedAccount, MockEthProvider},
    AccountReader, BlockHashReader, BlockIdReader, BlockNumReader, BytecodeReader,
    HashedPostStateProvider, ProviderResult, StateProofProvider, StateProvider, StateProviderBox,
    StateProviderFactory, StateRootProvider, StorageRootProvider,
};
use reth_revm::database::StateProviderDatabase;
use reth_transaction_pool::{
    blobstore::InMemoryBlobStore, noop::MockTransactionValidator, EthPooledTransaction, Pool,
    PoolConfig, PoolTransaction, TransactionOrigin, TransactionPool,
};
use reth_trie::{
    test_utils::{state_root_prehashed, storage_root_prehashed},
    updates::TrieUpdates,
    AccountProof, ExecutionWitnessMode, HashedPostState, HashedStorage, KeccakKeyHasher,
    MultiProof, MultiProofTargets, StorageMultiProof, StorageProof, TrieInput,
};
use revm::Database;

const CHAIN_ID: u64 = 1;
const PARENT_HEIGHT: u64 = 1;
const REQUEST_HEIGHT: u64 = 2;
const BLOCK_GAS_LIMIT: u64 = 30_000_000;
const FINALIZED_EPOCH: u64 = 3;
const FINALIZED_VIEW: u64 = 100;
const PARENT_VIEW: u64 = 99;
const VRF_MATERIAL_VERSION: u64 = 5;
const VALIDATOR_OWNER: Address = address!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

type TestPool = Pool<
    MockTransactionValidator<EthPooledTransaction>,
    OutbeTransactionOrdering<EthPooledTransaction>,
    InMemoryBlobStore,
>;
type InnerTestProvider = MockEthProvider<OutbePrimitives, ChainSpec<OutbeHeader>>;
type HashedAccountState = BTreeMap<B256, (Account, BTreeMap<B256, U256>)>;

fn test_pool(transactions: Vec<EthPooledTransaction>) -> TestPool {
    let pool = Pool::new(
        MockTransactionValidator::default(),
        OutbeTransactionOrdering::default(),
        InMemoryBlobStore::default(),
        PoolConfig::default(),
    );
    for transaction in transactions {
        futures::executor::block_on(pool.add_transaction(TransactionOrigin::Local, transaction))
            .expect("fixture vote enters the production transaction pool");
    }
    pool
}

fn validator_secret(validator_index: u8) -> B256 {
    B256::repeat_byte(validator_index.saturating_add(1))
}

fn validator_sender(validator_index: u8) -> Address {
    OutbeEvmSigner::from_secret_bytes(validator_secret(validator_index).0)
        .expect("fixture validator EVM key is valid")
        .address()
}

fn pooled_vote_transaction(input: Bytes, validator_index: u8) -> EthPooledTransaction {
    let transaction: Transaction = TxEip1559 {
        chain_id: CHAIN_ID,
        nonce: 0,
        gas_limit: 30_000,
        max_fee_per_gas: 1_000_000_000,
        max_priority_fee_per_gas: 0,
        to: TxKind::Call(METADOSIS_ADDRESS),
        value: U256::ZERO,
        access_list: Default::default(),
        input,
    }
    .into();
    let signature = sign_secp256k1_message(
        validator_secret(validator_index),
        transaction.signature_hash(),
    )
    .expect("fixture EVM vote signer");
    let signed = TransactionSigned::new_unhashed(transaction, signature);
    EthPooledTransaction::try_from_consensus(
        signed
            .try_into_recovered()
            .expect("fixture EVM vote sender recovers"),
    )
    .expect("fixture EVM vote converts to pooled transaction")
}

fn vote_sender_balance() -> U256 {
    U256::from(100_000_000_000_000_000_000u128)
}

#[derive(Clone, Debug)]
struct TestProvider {
    inner: InnerTestProvider,
    base_state: Arc<HashedAccountState>,
}

impl TestProvider {
    fn state_root_for(&self, post_state: HashedPostState) -> B256 {
        state_root_with_overlay(self.base_state.as_ref(), post_state)
    }
}

impl ChainSpecProvider for TestProvider {
    type ChainSpec = ChainSpec<OutbeHeader>;

    fn chain_spec(&self) -> Arc<Self::ChainSpec> {
        self.inner.chain_spec()
    }
}

impl BlockHashReader for TestProvider {
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        self.inner.block_hash(number)
    }

    fn canonical_hashes_range(&self, start: u64, end: u64) -> ProviderResult<Vec<B256>> {
        self.inner.canonical_hashes_range(start, end)
    }
}

impl BlockNumReader for TestProvider {
    fn chain_info(&self) -> ProviderResult<ChainInfo> {
        self.inner.chain_info()
    }

    fn best_block_number(&self) -> ProviderResult<u64> {
        self.inner.best_block_number()
    }

    fn last_block_number(&self) -> ProviderResult<u64> {
        self.inner.last_block_number()
    }

    fn block_number(&self, hash: B256) -> ProviderResult<Option<u64>> {
        self.inner.block_number(hash)
    }
}

impl BlockIdReader for TestProvider {
    fn pending_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        Ok(None)
    }

    fn safe_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        Ok(None)
    }

    fn finalized_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        Ok(None)
    }
}

impl AccountReader for TestProvider {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        self.inner.basic_account(address)
    }
}

impl BytecodeReader for TestProvider {
    fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        self.inner.bytecode_by_hash(code_hash)
    }
}

impl HashedPostStateProvider for TestProvider {
    fn hashed_post_state(&self, state: &revm::database::BundleState) -> HashedPostState {
        HashedPostState::from_bundle_state::<KeccakKeyHasher>(state.state())
    }
}

impl StateRootProvider for TestProvider {
    fn state_root(&self, post_state: HashedPostState) -> ProviderResult<B256> {
        Ok(self.state_root_for(post_state))
    }

    fn state_root_from_nodes(&self, input: TrieInput) -> ProviderResult<B256> {
        Ok(self.state_root_for(input.state))
    }

    fn state_root_with_updates(
        &self,
        post_state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        Ok((self.state_root_for(post_state), TrieUpdates::default()))
    }

    fn state_root_from_nodes_with_updates(
        &self,
        input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        Ok((self.state_root_for(input.state), TrieUpdates::default()))
    }
}

impl StorageRootProvider for TestProvider {
    fn storage_root(&self, address: Address, post_state: HashedStorage) -> ProviderResult<B256> {
        let hashed_address = keccak256(address);
        let mut storage = self
            .base_state
            .get(&hashed_address)
            .map(|(_, storage)| storage.clone())
            .unwrap_or_default();
        apply_storage_overlay(&mut storage, post_state);
        Ok(storage_root_prehashed(storage))
    }

    fn storage_proof(
        &self,
        address: Address,
        slot: B256,
        post_state: HashedStorage,
    ) -> ProviderResult<StorageProof> {
        self.inner.storage_proof(address, slot, post_state)
    }

    fn storage_multiproof(
        &self,
        address: Address,
        slots: &[B256],
        post_state: HashedStorage,
    ) -> ProviderResult<StorageMultiProof> {
        self.inner.storage_multiproof(address, slots, post_state)
    }
}

impl StateProofProvider for TestProvider {
    fn proof(
        &self,
        input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        self.inner.proof(input, address, slots)
    }

    fn multiproof(
        &self,
        input: TrieInput,
        targets: MultiProofTargets,
    ) -> ProviderResult<MultiProof> {
        self.inner.multiproof(input, targets)
    }

    fn witness(
        &self,
        input: TrieInput,
        target: HashedPostState,
        mode: ExecutionWitnessMode,
    ) -> ProviderResult<Vec<Bytes>> {
        self.inner.witness(input, target, mode)
    }
}

impl StateProvider for TestProvider {
    fn storage(&self, account: Address, storage_key: B256) -> ProviderResult<Option<U256>> {
        self.inner.storage(account, storage_key)
    }
}

impl StateProviderFactory for TestProvider {
    fn latest(&self) -> ProviderResult<StateProviderBox> {
        Ok(Box::new(self.clone()))
    }

    fn state_by_block_number_or_tag(
        &self,
        _number_or_tag: BlockNumberOrTag,
    ) -> ProviderResult<StateProviderBox> {
        self.latest()
    }

    fn history_by_block_number(&self, _block: u64) -> ProviderResult<StateProviderBox> {
        self.latest()
    }

    fn history_by_block_hash(&self, _block: B256) -> ProviderResult<StateProviderBox> {
        self.latest()
    }

    fn state_by_block_hash(&self, _block: B256) -> ProviderResult<StateProviderBox> {
        self.latest()
    }

    fn pending(&self) -> ProviderResult<StateProviderBox> {
        self.latest()
    }

    fn pending_state_by_hash(&self, _block_hash: B256) -> ProviderResult<Option<StateProviderBox>> {
        self.latest().map(Some)
    }

    fn maybe_pending(&self) -> ProviderResult<Option<StateProviderBox>> {
        self.latest().map(Some)
    }

    fn state_by_block_id(&self, _block_id: BlockId) -> ProviderResult<StateProviderBox> {
        self.latest()
    }
}

struct Dkg {
    keys: Vec<PrivateKey>,
    public_keys: Vec<PublicKey>,
    vrf_group_public_key: <MinSig as Variant>::Public,
    vrf_threshold_private: commonware_cryptography::bls12381::primitives::group::Private,
}

struct PreparedParent {
    _tree_directory: tempfile::TempDir,
    tree_service: Arc<CompressedTreeService>,
    parent: Arc<SealedHeader<OutbeHeader>>,
    parent_storage: HashMap<(Address, U256), U256>,
    wwd: WorldwideDay,
    nominal: U256,
    request_time: u64,
}

#[test]
fn real_payload_builder_commits_atomic_request_and_single_attempt_expiry() {
    let chain_spec: Arc<ChainSpec<OutbeHeader>> = ChainSpecBuilder::mainnet()
        .reset()
        .paris_activated()
        .build()
        .map_header(OutbeHeader::new)
        .into();
    outbe_consensus::proof::init_consensus_chain_id(CHAIN_ID).unwrap();
    let signer =
        Arc::new(OutbeEvmSigner::from_secret_bytes([1u8; 32]).expect("test proposer key is valid"));
    let proposer = signer.address();
    let dkg = build_dkg();
    let snapshot = build_snapshot(&dkg);
    let genesis_hash = chain_spec.genesis_hash();
    let founder_validators = snapshot
        .committee
        .iter()
        .map(|entry| (entry.address, entry.consensus_pubkey))
        .collect::<Vec<_>>();
    let mut fork_install =
        ForkInstallScenario::measurement_at(PARENT_HEIGHT, CHAIN_ID, genesis_hash)
            .unwrap()
            .with_founder_validators(&founder_validators)
            .unwrap()
            .into_install();
    fork_install
        .request_profile
        .capacity_profile
        .result_deadline_blocks = 8;
    fork_install
        .validate_for_chain(CHAIN_ID, genesis_hash, &poc_schema_limits())
        .expect("short measurement response window remains production-valid");
    let prepared = prepare_parent(&snapshot, genesis_hash, &fork_install);
    let fork_install = Arc::new(fork_install);
    let metadata =
        finalized_parent_metadata(&dkg, &snapshot, PARENT_HEIGHT, prepared.parent.hash());
    let provider = mock_provider(&chain_spec, &prepared.parent_storage);
    provider.inner.add_block(
        prepared.parent.hash(),
        Block::new(prepared.parent.header().clone(), Default::default()),
    );
    assert_provider_snapshot(
        &provider,
        &prepared.parent_storage,
        &snapshot,
        metadata.committee_set_hash,
    );
    assert_provider_activated_ocomp_inputs(&provider, prepared.wwd, prepared.nominal);
    let body_storage: StorageReaderHandle = Arc::new(MemoryStorage::new());
    let runtime_body_readers = RuntimeBodyReaders::new(body_storage);
    let evm_config = OutbeEvmConfig::new_with_provider_and_runtime_body_readers(
        chain_spec.clone(),
        Arc::new(RethAccountedParentArtifactProvider::new(
            provider.inner.clone(),
            None,
        )),
        runtime_body_readers.clone(),
    )
    .with_evm_signer(signer.clone())
    .with_compressed_tree_service(prepared.tree_service.clone())
    .with_ocomp_lifecycle_activation(OcompLifecycleActivation::at_block(PARENT_HEIGHT))
    .with_ocomp_fork_install(fork_install.clone());
    let phase1 = evm_config
        .build_signed_phase1_tx(
            REQUEST_HEIGHT,
            CHAIN_ID,
            prepared.parent.hash(),
            Some(metadata.clone()),
            Some(proposer),
        )
        .unwrap()
        .expect("block 2 has a Phase 1 transaction");
    let decoded_metadata = match SystemTxInputV2::decode(phase1.tx().input().as_ref()).unwrap() {
        SystemTxInputV2::CertifiedParentAccounting { metadata } => metadata,
        other => panic!("expected Phase 1 metadata, got {other:?}"),
    };
    assert_eq!(decoded_metadata, metadata);
    outbe_consensus::proof::verify_v2_proof(
        &decoded_metadata,
        &snapshot,
        decoded_metadata.proof.as_ref(),
        prepared.parent.hash(),
    )
    .expect("signed Phase 1 transaction preserves the valid proof");
    let payload_builder = OutbePayloadBuilder::new(
        provider.clone(),
        test_pool(Vec::new()),
        evm_config.clone(),
        EthereumBuilderConfig::new().with_gas_limit(BLOCK_GAS_LIMIT),
    );
    let attributes = OutbePayloadAttributes::new(
        REWARDS_ADDRESS,
        prepared.request_time * 1_000,
        B256::repeat_byte(0x44),
        Some(B256::repeat_byte(0x45)),
        Bytes::new(),
        Some(metadata),
        Some(proposer),
    )
    .with_execution_read_budget(ExecutionReadBudget::new());
    let payload = payload_builder
        .build_empty_payload(PayloadConfig::new(
            prepared.parent.clone(),
            attributes,
            PayloadId::new([0x08; 8]),
        ))
        .expect("production payload builder must create the request block");

    let body = &payload.block().body().transactions;
    let layout = split_system_layout(body).expect("request block has canonical system layout");
    assert_eq!(
        layout
            .begin_block_kinds()
            .expect("begin-zone inputs decode"),
        vec![
            SystemTxKind::CertifiedParentAccounting,
            SystemTxKind::LateFinalizeCredits,
            SystemTxKind::OcompLifecycleBegin,
            SystemTxKind::CycleTick,
            SystemTxKind::RewardsGemDelivery,
            SystemTxKind::OracleSlashWindow,
            SystemTxKind::HookEvents,
        ]
    );
    assert!(layout.user.is_empty());
    assert_eq!(
        layout.end_block_kinds().expect("end-zone inputs decode"),
        vec![SystemTxKind::OcompTerminalRequest]
    );

    let executed = payload
        .executed_block()
        .expect("builder exposes its exact production execution");
    let receipts = &executed.execution_output.result.receipts;
    assert_eq!(receipts.len(), body.len());
    let cycle_receipt = &receipts[3];
    assert!(cycle_receipt.success);
    let accumulation = cycle_receipt
        .logs
        .iter()
        .find_map(|log| IMetadosis::MetadosisAccumulation::decode_log(log).ok())
        .expect("CycleTick receipt exposes MetadosisAccumulation");
    let expected_cycle_day = outbe_primitives::time::previous_date_key(
        outbe_primitives::time::timestamp_to_date_key(prepared.request_time),
    );
    assert_eq!(accumulation.data.date, expected_cycle_day);
    assert!(
        !accumulation.data.dayMetadosisLimitAmount.is_zero(),
        "production CycleTick must route a non-zero allocation"
    );
    let terminal_receipt = receipts.last().expect("terminal request receipt");
    assert!(terminal_receipt.success);
    let requested = terminal_receipt
        .logs
        .iter()
        .find_map(|log| IMetadosis::OffchainJobRequested::decode_log(log).ok())
        .expect("terminal receipt exposes OffchainJobRequested");
    assert_eq!(requested.data.wwd, prepared.wwd.value());
    assert_eq!(requested.data.pendingNonce, 0);
    assert_eq!(requested.data.attempt, 0);

    let replay = evm_config
        .executor(StateProviderDatabase::new(&provider))
        .execute(executed.recovered_block.as_ref())
        .expect("validator replay succeeds through the production executor");
    assert_eq!(
        replay, *executed.execution_output,
        "proposer and validator must agree on receipts, requests and post-state"
    );

    let artifacts = decode_outbe_block_artifacts(payload.block().header().extra_data().as_ref())
        .expect("request header artifacts decode");
    let ce_artifact = artifacts
        .compressed_entities_root
        .expect("request header carries the completed CE seal");
    assert_eq!(
        ce_artifact.commitment_scheme_version,
        ACTIVE_COMMITMENT_SCHEME
    );
    let exact_post_state = provider.hashed_post_state(&executed.execution_output.state);
    let expected_state_root = provider.state_root_for(exact_post_state.clone());
    assert_eq!(
        payload.block().header().state_root(),
        expected_state_root,
        "header state root must be derived from the real execution BundleState"
    );
    let mutated_state_root = provider.state_root_for(mutate_one_storage_value(exact_post_state));
    assert_ne!(
        mutated_state_root, expected_state_root,
        "the independent root oracle must be sensitive to a real post-state mutation"
    );
    assert_ne!(
        payload.block().header().state_root(),
        prepared.parent.header().state_root(),
        "request execution must produce an observable state-root transition"
    );
    prepared
        .tree_service
        .apply_finalized(REQUEST_HEIGHT, payload.block().hash(), ce_artifact.r_sealed)
        .expect("production CE finalizer applies the exact built candidate");
    assert_eq!(
        prepared.tree_service.finalized_marker().unwrap().new_root,
        ce_artifact.r_sealed
    );

    let mut post_state = HashMapStorageProvider::new(CHAIN_ID);
    post_state.storage = prepared.parent_storage;
    apply_bundle(&mut post_state, executed.execution_output.state.state());
    StorageHandle::enter(&mut post_state, |storage| {
        let update = Update::new(storage.clone());
        assert_eq!(update.get_active_version().unwrap(), ProtocolVersion::ZERO);
        assert_eq!(update.get_active_version_height().unwrap(), 0);
        assert_eq!(
            update.version_at_height(REQUEST_HEIGHT).unwrap(),
            ProtocolVersion::ZERO
        );

        assert!(
            outbe_metadosis::api::is_active_ocomp_fork_install(storage.clone(), &fork_install,)
                .unwrap(),
            "fork block installs the exact complete activation authority"
        );

        let public_call = IMetadosis::getOffchainJobCall {
            intentId: requested.data.intentId,
        };
        let encoded = outbe_metadosis::precompile::dispatch(
            storage.clone(),
            &public_call.abi_encode(),
            proposer,
            U256::ZERO,
        )
        .unwrap();
        let public_bytes = IMetadosis::getOffchainJobCall::abi_decode_returns(&encoded).unwrap();
        let record =
            OcompJobRecordV1::decode_canonical(public_bytes.as_ref(), &poc_schema_limits())
                .unwrap();
        assert_eq!(record.status, OcompJobStatus::AwaitingFinality);
        assert!(
            record.finalized.is_none(),
            "request block cannot invent a response window before finality"
        );
        assert_eq!(record.intent.wwd, prepared.wwd.value());
        assert_eq!(record.intent.pending_nonce, 0);
        assert_eq!(record.intent.authenticated_day_count, 1);
        assert_eq!(record.intent.authenticated_day_nominal, prepared.nominal);
        assert_eq!(record.intent.ce_sealed_root, ce_artifact.r_sealed);
        assert_eq!(
            record
                .intent
                .activation_preconditions
                .metadosis
                .expected_status,
            outbe_ocomp_protocol::intent::MetadosisExpectedStatus::OffchainPending
        );
        let frozen = &record.intent.frozen_metadosis_values;
        let base_limit = outbe_metadosis::api::worldwide_day(storage.clone(), prepared.wwd)
            .unwrap()
            .unwrap()
            .metadosis_limit_amount;
        // The effective ceiling is the day's own emission plus what it drew from the accumulator.
        assert_eq!(
            frozen.day_limit,
            base_limit.checked_add(frozen.auction_base).unwrap()
        );
        // The auction never asks for more than the nominal beyond the symbolic share.
        assert!(
            frozen.auction_base
                <= prepared
                    .nominal
                    .checked_sub(frozen.lysis_budget)
                    .expect("Lysis cannot exceed the day's nominal")
        );
        // Lysis took this day's whole emission, so it credited nothing and the auction, with an
        // empty accumulator behind it, had nothing to draw.
        assert_eq!(frozen.lysis_budget, base_limit);
        assert_eq!(frozen.auction_base, U256::ZERO);
        assert_eq!(
            outbe_promislimit::PromisLimitContract::new(storage.clone())
                .get_total_unallocated()
                .unwrap(),
            U256::ZERO,
            "nothing was credited and nothing was drawn"
        );
        assert!(!record.intent.frozen_metadosis_values.lysis_budget.is_zero());
        assert_ne!(
            record
                .intent
                .frozen_metadosis_values
                .request_budget_split_receipt_hash,
            B256::ZERO
        );
        // The brief waits for the Lysis deadline, so the request leaves Desis untouched.
        assert_eq!(
            DesisContract::new(storage.clone())
                .auction_stage
                .read(&prepared.wwd)
                .unwrap(),
            AuctionStage::None as u8
        );
        assert_eq!(
            DesisContract::new(storage.clone())
                .pending_supply_promis
                .read(&prepared.wwd)
                .unwrap(),
            record.intent.frozen_metadosis_values.auction_base
        );

        assert_eq!(NodContract::new(storage.clone()).total_supply().unwrap(), 0);
        assert_eq!(
            IntexContract::new(storage.clone())
                .total_series
                .read()
                .unwrap(),
            0
        );
        assert_eq!(
            IntexContract::new(storage.clone())
                .contributor_count
                .read(&prepared.wwd)
                .unwrap(),
            0
        );
        let tribute = TributeContract::new(storage);
        assert_eq!(tribute.total_supply().unwrap(), 1);
        let totals = tribute.get_day_totals(prepared.wwd).unwrap();
        assert_eq!(totals.tribute_count, 1);
        assert_eq!(totals.tribute_nominal_amount, prepared.nominal);
    });

    let request_hash = payload.block().hash();
    let request_state_root = payload.block().header().state_root();
    let request_parent = Arc::new(SealedHeader::new(
        payload.block().header().clone(),
        request_hash,
    ));
    let successor_provider = mock_provider(&chain_spec, &post_state.storage);
    successor_provider.inner.add_block(
        request_hash,
        Block::new(request_parent.header().clone(), Default::default()),
    );
    let successor_metadata =
        finalized_parent_metadata(&dkg, &snapshot, REQUEST_HEIGHT, request_hash);
    let successor_builder = OutbePayloadBuilder::new(
        successor_provider.clone(),
        test_pool(Vec::new()),
        evm_config.clone(),
        EthereumBuilderConfig::new().with_gas_limit(BLOCK_GAS_LIMIT),
    );
    let successor_attributes = OutbePayloadAttributes::new(
        REWARDS_ADDRESS,
        (prepared.request_time + 1) * 1_000,
        B256::repeat_byte(0x54),
        Some(B256::repeat_byte(0x55)),
        Bytes::new(),
        Some(successor_metadata),
        Some(proposer),
    )
    .with_execution_read_budget(ExecutionReadBudget::new());
    let successor = successor_builder
        .build_empty_payload(PayloadConfig::new(
            request_parent,
            successor_attributes,
            PayloadId::new([0x09; 8]),
        ))
        .expect("the certified successor records request finality");
    let successor_execution = successor
        .executed_block()
        .expect("successor exposes its production execution");
    let mut finalized_state = HashMapStorageProvider::new(CHAIN_ID);
    finalized_state.storage = post_state.storage;
    apply_bundle(
        &mut finalized_state,
        successor_execution.execution_output.state.state(),
    );
    StorageHandle::enter(&mut finalized_state, |storage| {
        let record = OcompJobRecordV1::decode_canonical(
            &outbe_metadosis::api::get_offchain_job(storage, requested.data.intentId).unwrap(),
            &poc_schema_limits(),
        )
        .expect("certified successor preserves the request record");
        let finalized = record
            .finalized
            .expect("actual parent finalization must bind the request on-chain");
        assert_eq!(record.status, OcompJobStatus::AwaitingFinality);
        assert_eq!(finalized.finalized_request_block_hash, request_hash);
        assert_eq!(finalized.finalized_request_state_root, request_state_root);
        assert_eq!(finalized.finality_recorded_height, REQUEST_HEIGHT + 1);
        assert_eq!(finalized.open_height, REQUEST_HEIGHT + 5);
        assert_eq!(
            finalized.job_id,
            record
                .intent
                .job_id(request_hash, request_state_root, &poc_schema_limits())
                .unwrap()
        );
    });

    let finalized_record = StorageHandle::enter(&mut finalized_state, |storage| {
        let encoded =
            outbe_metadosis::api::get_offchain_job(storage, requested.data.intentId).unwrap();
        OcompJobRecordV1::decode_canonical(&encoded, &poc_schema_limits()).unwrap()
    });
    let finalized = finalized_record.finalized.as_ref().unwrap();
    let open_height = finalized.open_height;
    let successor_artifacts =
        decode_outbe_block_artifacts(successor.block().header().extra_data().as_ref()).unwrap();
    let successor_ce = successor_artifacts
        .compressed_entities_root
        .expect("certified successor carries its completed CE seal");
    prepared
        .tree_service
        .apply_finalized(
            REQUEST_HEIGHT + 1,
            successor.block().hash(),
            successor_ce.r_sealed,
        )
        .expect("certified successor CE candidate finalizes before its child");

    let mut canonical_parent = Arc::new(SealedHeader::new(
        successor.block().header().clone(),
        successor.block().hash(),
    ));
    let mut canonical_storage = finalized_state.storage;
    for height in (REQUEST_HEIGHT + 2)..open_height {
        let built = build_canonical_ocomp_successor(
            &chain_spec,
            &prepared.tree_service,
            &signer,
            &runtime_body_readers,
            &fork_install,
            &dkg,
            &snapshot,
            proposer,
            canonical_parent,
            &canonical_storage,
            height,
            prepared.request_time + (height - REQUEST_HEIGHT),
            requested.data.intentId,
            Vec::new(),
        );
        assert_eq!(
            built.record.status,
            OcompJobStatus::AwaitingFinality,
            "pre-open production lifecycle must preserve AwaitingFinality"
        );
        assert!(built.requested_intents.is_empty());
        canonical_parent = built.header;
        canonical_storage = built.storage;
    }

    let voting_open = build_canonical_ocomp_successor(
        &chain_spec,
        &prepared.tree_service,
        &signer,
        &runtime_body_readers,
        &fork_install,
        &dkg,
        &snapshot,
        proposer,
        canonical_parent,
        &canonical_storage,
        open_height,
        prepared.request_time + (open_height - REQUEST_HEIGHT),
        requested.data.intentId,
        Vec::new(),
    );
    assert_eq!(voting_open.record.status, OcompJobStatus::VotingOpen);

    let initial_deadline = voting_open
        .record
        .finalized
        .as_ref()
        .expect("initial voting-open record remains finalized")
        .deadline_height;
    let initial_voting =
        ResultVotingScenario::for_intent(&finalized_record.intent, finalized.job_id);
    let initial_votes = (0_u8..2)
        .map(|validator_index| {
            let vote = initial_voting.signed_vote(validator_index);
            let calldata = encode_submit_lysis_result_calldata(&vote, &poc_schema_limits())
                .expect("canonical non-quorum vote calldata");
            pooled_vote_transaction(Bytes::from(calldata), validator_index)
        })
        .collect::<Vec<_>>();
    let no_quorum = build_canonical_ocomp_successor(
        &chain_spec,
        &prepared.tree_service,
        &signer,
        &runtime_body_readers,
        &fork_install,
        &dkg,
        &snapshot,
        proposer,
        voting_open.header,
        &voting_open.storage,
        open_height + 1,
        prepared.request_time + (open_height + 1 - REQUEST_HEIGHT),
        requested.data.intentId,
        initial_votes,
    );
    assert_eq!(no_quorum.record.status, OcompJobStatus::VotingOpen);
    assert!(no_quorum
        .record
        .finalized
        .as_ref()
        .is_some_and(|record| record.quorum.is_none()));

    let mut retry_parent = no_quorum.header;
    let mut retry_storage = no_quorum.storage;
    let mut initial_terminal = no_quorum.record;
    for height in (open_height + 2)..=initial_deadline {
        let built = build_canonical_ocomp_successor(
            &chain_spec,
            &prepared.tree_service,
            &signer,
            &runtime_body_readers,
            &fork_install,
            &dkg,
            &snapshot,
            proposer,
            retry_parent,
            &retry_storage,
            height,
            prepared.request_time + (height - REQUEST_HEIGHT),
            requested.data.intentId,
            Vec::new(),
        );
        retry_parent = built.header;
        retry_storage = built.storage;
        initial_terminal = built.record;
    }
    assert_eq!(initial_terminal.status, OcompJobStatus::Expired);
    let initial_terminal_evidence = initial_terminal
        .terminal
        .as_ref()
        .expect("deadline retains the initial terminal evidence");
    assert_eq!(
        initial_terminal_evidence.outcome,
        OcompTerminalOutcome::Expired
    );
    assert_eq!(initial_terminal_evidence.terminal_height, initial_deadline);
    assert!(initial_terminal_evidence.completed_binding.is_none());

    let retry_request_height = initial_deadline + 1;
    let retry_request = build_canonical_ocomp_successor(
        &chain_spec,
        &prepared.tree_service,
        &signer,
        &runtime_body_readers,
        &fork_install,
        &dkg,
        &snapshot,
        proposer,
        retry_parent,
        &retry_storage,
        retry_request_height,
        prepared.request_time + (retry_request_height - REQUEST_HEIGHT),
        requested.data.intentId,
        Vec::new(),
    );
    assert_eq!(retry_request.record.status, OcompJobStatus::Expired);
    assert!(
        retry_request.requested_intents.is_empty(),
        "an expired single-attempt request must not be retried"
    );

    assert_ne!(requested.data.intentId, B256::ZERO);
    assert_eq!(
        terminal_receipt
            .logs
            .iter()
            .filter(|log| {
                log.address == METADOSIS_ADDRESS
                    && IMetadosis::OffchainJobRequested::decode_log(log).is_ok()
            })
            .count(),
        1
    );
    assert!(terminal_receipt
        .logs
        .iter()
        .all(|log| log.address != TRIBUTE_FACTORY_ADDRESS));
}

struct CanonicalOcompSuccessor {
    header: Arc<SealedHeader<OutbeHeader>>,
    storage: HashMap<(Address, U256), U256>,
    record: OcompJobRecordV1,
    requested_intents: Vec<B256>,
}

#[allow(clippy::too_many_arguments)]
fn build_canonical_ocomp_successor(
    chain_spec: &Arc<ChainSpec<OutbeHeader>>,
    tree_service: &Arc<CompressedTreeService>,
    signer: &Arc<OutbeEvmSigner>,
    runtime_body_readers: &RuntimeBodyReaders,
    fork_install: &Arc<outbe_metadosis::config::OcompForkInstallV1>,
    dkg: &Dkg,
    snapshot: &CommitteeSnapshot,
    proposer: Address,
    parent: Arc<SealedHeader<OutbeHeader>>,
    parent_storage: &HashMap<(Address, U256), U256>,
    height: u64,
    timestamp: u64,
    intent_id: B256,
    user_transactions: Vec<EthPooledTransaction>,
) -> CanonicalOcompSuccessor {
    assert_eq!(height, parent.number() + 1);
    let provider = mock_provider(chain_spec, parent_storage);
    provider.inner.add_block(
        parent.hash(),
        Block::new(parent.header().clone(), Default::default()),
    );
    let evm_config = OutbeEvmConfig::new_with_provider_and_runtime_body_readers(
        chain_spec.clone(),
        Arc::new(RethAccountedParentArtifactProvider::new(
            provider.inner.clone(),
            None,
        )),
        runtime_body_readers.clone(),
    )
    .with_evm_signer(signer.clone())
    .with_compressed_tree_service(tree_service.clone())
    .with_ocomp_lifecycle_activation(OcompLifecycleActivation::at_block(PARENT_HEIGHT))
    .with_ocomp_fork_install(fork_install.clone());
    let metadata = finalized_parent_metadata(dkg, snapshot, height - 1, parent.hash());
    let user_transaction_count = user_transactions.len();
    let transaction_pool = test_pool(user_transactions);
    let pool_size = transaction_pool.pool_size();
    assert_eq!(
        pool_size.total, user_transaction_count,
        "canonical OCOMP model pool must retain every supplied public vote: {pool_size:?}"
    );
    assert_eq!(
        pool_size.pending, user_transaction_count,
        "canonical OCOMP model pool must make every supplied public vote executable: {pool_size:?}"
    );
    let builder = OutbePayloadBuilder::new(
        provider.clone(),
        transaction_pool,
        evm_config.clone(),
        EthereumBuilderConfig::new().with_gas_limit(BLOCK_GAS_LIMIT),
    );
    let attributes = OutbePayloadAttributes::new(
        REWARDS_ADDRESS,
        timestamp * 1_000,
        B256::from(U256::from(height).to_be_bytes::<32>()),
        Some(B256::from(
            U256::from(height.saturating_add(1)).to_be_bytes::<32>(),
        )),
        Bytes::new(),
        Some(metadata),
        Some(proposer),
    )
    .with_execution_read_budget(ExecutionReadBudget::new());
    let payload_config = PayloadConfig::new(
        parent,
        attributes,
        PayloadId::new([u8::try_from(height).unwrap_or(u8::MAX); 8]),
    );
    let payload = if user_transaction_count == 0 {
        builder
            .build_empty_payload(payload_config)
            .expect("canonical OCOMP model successor builds")
    } else {
        builder
            .try_build(BuildArguments::new(
                Default::default(),
                Default::default(),
                None,
                payload_config,
                Default::default(),
                None,
            ))
            .expect("canonical OCOMP model successor with public votes builds")
            .into_payload()
            .expect("canonical OCOMP model public-vote build returns a payload")
    };
    let layout = split_system_layout(&payload.block().body().transactions)
        .expect("canonical OCOMP model block has a system layout");
    assert!(layout
        .begin_block_kinds()
        .expect("canonical OCOMP model begin zone decodes")
        .contains(&SystemTxKind::OcompLifecycleBegin));
    assert!(
        layout.user.len() <= user_transaction_count,
        "payload cannot include more public transactions than the supplied pool"
    );
    let executed = payload
        .executed_block()
        .expect("canonical OCOMP model block exposes execution");
    if !layout.user.is_empty() {
        let user_receipts = &executed.execution_output.result.receipts
            [layout.begin.len()..layout.begin.len() + layout.user.len()];
        let mut prior_cumulative_gas = executed.execution_output.result.receipts
            [layout.begin.len().saturating_sub(1)]
        .cumulative_gas_used;
        for (transaction, receipt) in layout.user.iter().zip(user_receipts) {
            let transaction = *transaction;
            if transaction.to() == Some(METADOSIS_ADDRESS) {
                assert_eq!(
                    TransactionSigned::gas_limit(transaction),
                    30_000,
                    "every OCOMP system carrier preserves the canonical signed gas limit"
                );
                assert_eq!(
                    receipt.cumulative_gas_used, prior_cumulative_gas,
                    "OCOMP system carrier must not consume ordinary user-lane gas"
                );
            }
            prior_cumulative_gas = receipt.cumulative_gas_used;
        }
    }
    let import = evm_config
        .executor(StateProviderDatabase::new(&provider))
        .execute(executed.recovered_block.as_ref())
        .expect("canonical OCOMP model block imports through the production executor");
    assert_eq!(
        import, *executed.execution_output,
        "proposer/import must agree at OCOMP model height {height}"
    );
    let historical_replay = evm_config
        .executor(StateProviderDatabase::new(&provider))
        .execute(executed.recovered_block.as_ref())
        .expect("canonical OCOMP model block replays from historical parent state");
    assert_eq!(
        historical_replay, *executed.execution_output,
        "proposer/historical replay must agree at OCOMP model height {height}"
    );
    let exact_post_state = provider.hashed_post_state(&executed.execution_output.state);
    assert_eq!(
        payload.block().header().state_root(),
        provider.state_root_for(exact_post_state),
        "canonical OCOMP block state root must match its exact production state"
    );

    let mut state = HashMapStorageProvider::new(CHAIN_ID);
    state.storage = parent_storage.clone();
    apply_bundle(&mut state, executed.execution_output.state.state());
    let record = StorageHandle::enter(&mut state, |storage| {
        let encoded = outbe_metadosis::api::get_offchain_job(storage, intent_id)
            .expect("canonical public OCOMP job query");
        OcompJobRecordV1::decode_canonical(&encoded, &poc_schema_limits())
            .expect("canonical public OCOMP job decodes")
    });
    let requested_intents = executed
        .execution_output
        .result
        .receipts
        .iter()
        .flat_map(|receipt| &receipt.logs)
        .filter_map(|log| IMetadosis::OffchainJobRequested::decode_log(log).ok())
        .map(|event| event.data.intentId)
        .collect::<Vec<_>>();
    let artifacts =
        decode_outbe_block_artifacts(payload.block().header().extra_data().as_ref()).unwrap();
    let ce = artifacts
        .compressed_entities_root
        .expect("canonical OCOMP model block carries its completed CE seal");
    tree_service
        .apply_finalized(height, payload.block().hash(), ce.r_sealed)
        .expect("canonical OCOMP model CE candidate finalizes before its child");
    CanonicalOcompSuccessor {
        header: Arc::new(SealedHeader::new(
            payload.block().header().clone(),
            payload.block().hash(),
        )),
        storage: state.storage,
        record,
        requested_intents,
    }
}

fn prepare_parent(
    snapshot: &StoredCommitteeSnapshot,
    genesis_hash: B256,
    fork_install: &outbe_metadosis::config::OcompForkInstallV1,
) -> PreparedParent {
    let directory = tempfile::tempdir().unwrap();
    let db = CeMdbx::open(
        directory.path(),
        EnvironmentIdentity {
            local_storage_schema_version: LOCAL_STORAGE_SCHEMA_VERSION,
            chain_id: CHAIN_ID,
            genesis_hash,
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            topology: CeTopologyV1.encode(),
            tree_format: "ckb-smt-v0.6.1-poseidon-catalog-v3".to_owned(),
            vendor_revision: "ad555350c866b2265d87d2d7fbd146fbc918bfe5".to_owned(),
        },
        FinalizedMarker {
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            height: 0,
            block_hash: genesis_hash,
            parent_block_hash: B256::ZERO,
            parent_root: B256::ZERO,
            new_root: outbe_compressed_entities::sealed_root(B256::ZERO).unwrap(),
        },
    )
    .unwrap();
    let tree_service = Arc::new(
        CompressedTreeService::new(
            db,
            CandidateCacheLimits {
                max_candidates: 4,
                max_encoded_bytes: 1_000_000,
            },
        )
        .unwrap(),
    );
    let marker = tree_service.finalized_marker().unwrap();
    let parent_tree = tree_service
        .open_parent(ExactParentIdentity {
            commitment_scheme_version: marker.commitment_scheme_version,
            block_number: marker.height,
            block_hash: marker.block_hash,
            root: marker.new_root,
        })
        .unwrap();
    let scope = ExecutionScope::with_parent_tree(parent_tree, CeWorkConfig::new(0, 0, u64::MAX));
    let mut seed = HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, genesis_hash);
    seed.set_block_number(PARENT_HEIGHT);
    seed.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::ForkProfile);
    let wwd = WorldwideDay::new(2026_0710);
    let parent_time = wwd.start_timestamp();
    let request_time = parent_time
        + FORMING_PERIOD_HOURS * SECONDS_PER_HOUR
        + LOOKBACK_DELAY_HOURS * SECONDS_PER_HOUR
        + OFFERING_PERIOD_HOURS * SECONDS_PER_HOUR
        + WAITING_PERIOD_HOURS * SECONDS_PER_HOUR;
    let nominal = U256::from(1_000);
    let owner = address!("7300000000000000000000000000000000000073");
    let seal = StorageHandle::enter(&mut seed, |storage| {
        seed_ce_genesis(&storage);
        begin_block(storage.clone(), &scope).unwrap();
        let nod = NodContract::new(storage.clone());
        nod.ocomp_materialization_head_sequence.write(1).unwrap();
        nod.ocomp_materialization_tail_sequence.write(1).unwrap();

        let mut validators = ValidatorSet::new(storage.clone());
        validators.config_owner.write(VALIDATOR_OWNER).unwrap();
        validators.set_config_max_validators(128).unwrap();
        validators.config_epoch_length_blocks.write(60).unwrap();
        validators.config_is_initialized.write(true).unwrap();
        for (entry, registration) in snapshot
            .committee
            .iter()
            .zip(&fork_install.founder_registrations)
        {
            validators
                .register_validator(VALIDATOR_OWNER, entry.address, &entry.consensus_pubkey)
                .unwrap();
            validators.mark_pending(entry.address).unwrap();
            validators
                .confirm_validator_ready(
                    entry.address,
                    &registration.encode_canonical(&poc_schema_limits()).unwrap(),
                )
                .unwrap();
            validators
                .activate_validator_via_boundary_for_test(entry.address)
                .unwrap();
        }
        write_committee_snapshot(storage.clone(), FINALIZED_EPOCH, snapshot).unwrap();

        let mut oracle = OracleContract::new(storage.clone());
        let mut oracle_genesis = outbe_oracle::genesis::OracleGenesisConfig::default_config();
        oracle_genesis.initial_rates.push((
            outbe_oracle::api::COEN_ASSET,
            outbe_oracle::api::currency_address(840),
            U256::from(2_000_000_000_000_000_000u128),
        ));
        outbe_oracle::genesis::init_from_genesis(&mut oracle, &oracle_genesis).unwrap();

        let activation_ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(PARENT_HEIGHT, parent_time, CHAIN_ID),
            storage.clone(),
        );
        outbe_metadosis::commands::install_fork_profile(&activation_ctx, fork_install).unwrap();

        let forming_start = wwd.start_timestamp();
        let forming_end = forming_start + FORMING_PERIOD_HOURS * SECONDS_PER_HOUR;
        let lookback_end = forming_end + LOOKBACK_DELAY_HOURS * SECONDS_PER_HOUR;
        let offering_end = lookback_end + OFFERING_PERIOD_HOURS * SECONDS_PER_HOUR;
        FreshDevnetGenesisBuilder::new()
            .seed_active_worldwide_day(GenesisWorldwideDay {
                worldwide_day: wwd,
                status: outbe_metadosis::WwdStatus::Ready,
                day_type: WwdDayType::Green,
                forming_start,
                forming_end,
                lookback_end,
                offering_end,
                scheduled_process_time: request_time,
                metadosis_limit_amount: U256::from(100),
                previous_vwap: U256::ZERO,
                current_vwap: U256::from(2),
            })
            .apply(storage.clone())
            .unwrap();
        let mut tribute = TributeContract::new(storage.clone());
        tribute.unseal_day(wwd).unwrap();
        tribute
            .issue(
                &scope,
                &EmptyParent,
                &TributeData {
                    tribute_id: NodContract::generate_nod_id(owner, wwd).unwrap(),
                    owner,
                    worldwide_day: wwd,
                    issuance_amount_minor: nominal,
                    issuance_currency: 840,
                    nominal_amount_minor: nominal,
                    reference_currency: 840,
                    exclude_from_intex_issuance: false,
                    tribute_price_minor: U256::from(2),
                },
            )
            .unwrap();
        tribute.seal_day(wwd).unwrap();

        let parent_ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(PARENT_HEIGHT, parent_time, CHAIN_ID),
            storage.clone(),
        );
        outbe_rewards::runtime::ensure_genesis_anchor(&parent_ctx).unwrap();
        Cycle::new(storage.clone())
            .active_utc_day
            .write(outbe_primitives::time::timestamp_to_date_key(parent_time))
            .unwrap();
        outbe_cycle::runtime::dispatch_triggers(&parent_ctx, &scope, &EmptyParent).unwrap();
        // This focused fixture jumps directly from the seeded WWD start to its
        // processing time. Model the intervening canonical daily advances so
        // the request block exercises a contiguous settlement, not SkipMissed.
        Cycle::new(storage.clone())
            .active_utc_day
            .write(outbe_primitives::time::previous_date_key(
                outbe_primitives::time::timestamp_to_date_key(request_time),
            ))
            .unwrap();
        end_block(storage, &scope).unwrap()
    });

    let parent_extra_data = encode_outbe_block_artifacts(&OutbeBlockArtifacts {
        execution_summary: Some(ExecutionSummaryArtifact {
            validator_fee_sum: U256::ZERO,
        }),
        consensus_header_artifact: None,
        timestamp_millis_part: 0,
        late_finalize_credits: None,
        compressed_entities_root: Some(CompressedEntitiesRootArtifact {
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            r_sealed: seal.new_root,
        }),
    })
    .unwrap();
    let parent_state_root = state_root_prehashed(hashed_marker_state(&seed.storage));
    let parent = Arc::new(SealedHeader::seal_slow(OutbeHeader::new(Header {
        parent_hash: genesis_hash,
        beneficiary: REWARDS_ADDRESS,
        state_root: parent_state_root,
        number: PARENT_HEIGHT,
        gas_limit: BLOCK_GAS_LIMIT,
        timestamp: parent_time,
        base_fee_per_gas: Some(1_000_000_000),
        extra_data: parent_extra_data,
        ..Default::default()
    })));
    tree_service
        .publish_candidate(parent.hash(), seal.staged_tree_batch)
        .unwrap();
    tree_service
        .apply_finalized(PARENT_HEIGHT, parent.hash(), seal.new_root)
        .unwrap();

    PreparedParent {
        _tree_directory: directory,
        tree_service,
        parent,
        parent_storage: seed.storage,
        wwd,
        nominal,
        request_time,
    }
}

#[derive(Debug)]
struct EmptyParent;

impl outbe_compressed_entities::ParentBodySource for EmptyParent {
    fn get(
        &self,
        _entity: outbe_compressed_entities::EntityRef,
    ) -> Result<
        Option<outbe_compressed_entities::StoredBody>,
        outbe_compressed_entities::ParentBodySourceError,
    > {
        Ok(None)
    }

    fn list(
        &self,
        _query: outbe_compressed_entities::QueryRef,
        _request: outbe_compressed_entities::IdPageRequest,
    ) -> Result<outbe_compressed_entities::IdPage, outbe_compressed_entities::ParentBodySourceError>
    {
        Ok(outbe_compressed_entities::IdPage {
            ids: Vec::new(),
            next_after: None,
        })
    }
}

fn mock_provider(
    chain_spec: &Arc<ChainSpec<OutbeHeader>>,
    storage: &HashMap<(Address, U256), U256>,
) -> TestProvider {
    let inner =
        MockEthProvider::<OutbePrimitives>::new().with_chain_spec(chain_spec.as_ref().clone());
    let mut accounts: BTreeMap<Address, Vec<(B256, U256)>> = BTreeMap::new();
    for ((account, slot), value) in storage {
        accounts
            .entry(*account)
            .or_default()
            .push((B256::from(slot.to_be_bytes::<32>()), *value));
    }
    for (account, account_storage) in accounts {
        inner.add_account(
            account,
            ExtendedAccount::new(0, U256::ZERO)
                .with_bytecode(Bytes::from_static(&[0xef]))
                .extend_storage(account_storage),
        );
    }
    for validator_index in 0_u8..4 {
        inner.add_account(
            validator_sender(validator_index),
            ExtendedAccount::new(0, vote_sender_balance()),
        );
    }
    TestProvider {
        inner,
        base_state: Arc::new(hashed_marker_state(storage)),
    }
}

fn hashed_marker_state(storage: &HashMap<(Address, U256), U256>) -> HashedAccountState {
    let marker_code_hash = keccak256([0xef]);
    let mut accounts = HashedAccountState::new();
    for validator_index in 0_u8..4 {
        accounts.insert(
            keccak256(validator_sender(validator_index)),
            (
                Account {
                    nonce: 0,
                    balance: vote_sender_balance(),
                    bytecode_hash: None,
                },
                BTreeMap::new(),
            ),
        );
    }
    for ((address, slot), value) in storage {
        let (_, account_storage) = accounts.entry(keccak256(address)).or_insert_with(|| {
            (
                Account {
                    nonce: 0,
                    balance: U256::ZERO,
                    bytecode_hash: Some(marker_code_hash),
                },
                BTreeMap::new(),
            )
        });
        if !value.is_zero() {
            account_storage.insert(keccak256(B256::from(slot.to_be_bytes::<32>())), *value);
        }
    }
    accounts
}

fn apply_storage_overlay(storage: &mut BTreeMap<B256, U256>, post_state: HashedStorage) {
    if post_state.wiped {
        storage.clear();
    }
    for (slot, value) in post_state.storage {
        if value.is_zero() {
            storage.remove(&slot);
        } else {
            storage.insert(slot, value);
        }
    }
}

fn state_root_with_overlay(base_state: &HashedAccountState, post_state: HashedPostState) -> B256 {
    let mut state = base_state.clone();
    for (address, account) in post_state.accounts {
        match account {
            Some(account) => {
                let storage = state
                    .remove(&address)
                    .map(|(_, storage)| storage)
                    .unwrap_or_default();
                state.insert(address, (account, storage));
            }
            None => {
                state.remove(&address);
            }
        }
    }
    for (address, storage_overlay) in post_state.storages {
        let Some((_, storage)) = state.get_mut(&address) else {
            assert!(
                storage_overlay.wiped && storage_overlay.storage.values().all(U256::is_zero),
                "post-state storage exists without a live account"
            );
            continue;
        };
        apply_storage_overlay(storage, storage_overlay);
    }
    state_root_prehashed(state)
}

fn mutate_one_storage_value(mut post_state: HashedPostState) -> HashedPostState {
    let value = post_state
        .storages
        .values_mut()
        .flat_map(|storage| storage.storage.values_mut())
        .next()
        .expect("request execution changes at least one storage value");
    *value = if *value == U256::MAX {
        value.checked_sub(U256::from(1)).unwrap()
    } else {
        value.checked_add(U256::from(1)).unwrap()
    };
    post_state
}

fn apply_bundle(
    target: &mut HashMapStorageProvider,
    state: &revm::primitives::AddressMap<revm::database::states::BundleAccount>,
) {
    for (address, account) in state {
        for (slot, value) in &account.storage {
            target
                .storage
                .insert((*address, *slot), value.present_value());
        }
    }
}

fn assert_provider_snapshot(
    provider: &TestProvider,
    parent_storage: &HashMap<(Address, U256), U256>,
    expected: &StoredCommitteeSnapshot,
    committee_set_hash: B256,
) {
    let mut database = StateProviderDatabase::new(provider);
    let mut mirror = HashMapStorageProvider::new(CHAIN_ID);
    for ((address, slot), expected_value) in parent_storage
        .iter()
        .filter(|((address, _), _)| *address == VALIDATOR_SET_ADDRESS)
    {
        let actual = database.storage(*address, *slot).unwrap();
        assert_eq!(actual, *expected_value);
        mirror.storage.insert((*address, *slot), actual);
    }
    StorageHandle::enter(&mut mirror, |storage| {
        assert_eq!(
            read_committee_snapshot(
                storage,
                committee_snapshot_key(FINALIZED_EPOCH, committee_set_hash),
            )
            .unwrap(),
            Some(expected.clone())
        );
    });

    let context = BlockContext::empty_for_tests(REQUEST_HEIGHT, 0, CHAIN_ID);
    let mut state = reth_revm::db::State::builder()
        .with_database(database)
        .with_bundle_update()
        .build();
    let mut direct = DirectStorageProvider::new(&mut state, context);
    let storage = StorageHandle::new(&mut direct);
    assert_eq!(
        read_committee_snapshot(
            storage,
            committee_snapshot_key(FINALIZED_EPOCH, committee_set_hash),
        )
        .unwrap(),
        Some(expected.clone())
    );
}

fn assert_provider_activated_ocomp_inputs(
    provider: &TestProvider,
    wwd: WorldwideDay,
    expected_nominal: U256,
) {
    let database = StateProviderDatabase::new(provider);
    let context = BlockContext::empty_for_tests(REQUEST_HEIGHT, 0, CHAIN_ID);
    let mut state = reth_revm::db::State::builder()
        .with_database(database)
        .with_bundle_update()
        .build();
    let mut direct = DirectStorageProvider::new(&mut state, context);
    let storage = StorageHandle::new(&mut direct);
    let update = Update::new(storage.clone());
    assert_eq!(update.get_active_version().unwrap(), ProtocolVersion::ZERO);
    assert_eq!(update.get_active_version_height().unwrap(), 0);

    assert!(outbe_metadosis::api::has_active_ocomp_profile(storage.clone()).unwrap());
    let days = outbe_metadosis::api::worldwide_days(storage.clone()).unwrap();
    assert_eq!(days.len(), 1);
    let projection = outbe_metadosis::api::worldwide_day(storage.clone(), wwd)
        .unwrap()
        .unwrap();
    assert_eq!(projection.status, outbe_metadosis::WwdStatus::Ready);
    assert_eq!(
        projection.membership,
        outbe_metadosis::WwdMembership::Active
    );
    assert_eq!(projection.day_type, WwdDayType::Green);
    assert_eq!(projection.metadosis_limit_amount, U256::from(100));
    let totals = TributeContract::new(storage).get_day_totals(wwd).unwrap();
    assert_eq!(totals.tribute_count, 1);
    assert_eq!(totals.tribute_nominal_amount, expected_nominal);
}

fn seed_ce_genesis(storage: &StorageHandle<'_>) {
    storage
        .sstore(COMPRESSED_ENTITIES_ADDRESS, U256::ZERO, U256::from(4))
        .unwrap();
    storage
        .sstore(
            COMPRESSED_ENTITIES_ADDRESS,
            U256::from(1),
            U256::from_be_slice(
                outbe_compressed_entities::sealed_root(B256::ZERO)
                    .unwrap()
                    .as_slice(),
            ),
        )
        .unwrap();
}

fn build_dkg() -> Dkg {
    let keys = (0..4)
        .map(|index| PrivateKey::from_seed(index + 1))
        .collect::<Vec<_>>();
    let public_keys = keys
        .iter()
        .cloned()
        .map(PublicKey::from)
        .collect::<Vec<_>>();
    let mut rng = OsRng;
    let (vrf_threshold_private, vrf_group_public_key) = keypair::<_, MinSig>(&mut rng);
    Dkg {
        keys,
        public_keys,
        vrf_group_public_key,
        vrf_threshold_private,
    }
}

fn build_snapshot(dkg: &Dkg) -> CommitteeSnapshot {
    let mut public_keys = dkg.public_keys.iter().collect::<Vec<_>>();
    public_keys.sort_by_key(|public_key| public_key.encode().to_vec());
    CommitteeSnapshot {
        committee: public_keys
            .into_iter()
            .enumerate()
            .map(|(index, public_key)| {
                let mut consensus_pubkey = [0u8; 48];
                consensus_pubkey.copy_from_slice(public_key.encode().as_ref());
                CommitteeEntry {
                    address: validator_sender(
                        u8::try_from(index).expect("fixture validator index fits u8"),
                    ),
                    consensus_pubkey,
                }
            })
            .collect(),
        vrf_material_version: VRF_MATERIAL_VERSION,
        vrf_group_public_key_bytes: dkg.vrf_group_public_key.encode().to_vec(),
        vrf_public_polynomial_hash: B256::ZERO,
    }
}

fn finalized_parent_metadata(
    dkg: &Dkg,
    snapshot: &CommitteeSnapshot,
    finalized_block_number: u64,
    parent_hash: B256,
) -> CertifiedParentAccountingMetadata {
    let round = Round::new(Epoch::new(FINALIZED_EPOCH), View::new(FINALIZED_VIEW));
    let proposal =
        Proposal::<Sha256Digest>::new(round, View::new(PARENT_VIEW), Sha256Digest(parent_hash.0));
    let vote_message = proposal.encode().to_vec();
    let seed_message = round.encode().to_vec();
    let committee_set = commonware_utils::ordered::Set::from_iter_dedup(
        dkg.keys.iter().map(|key| key.public_key()),
    );
    let namespace = finalize_namespace(&committee_set);
    let signatures = dkg
        .keys
        .iter()
        .map(|key| key.sign(&namespace, &vote_message))
        .collect::<Vec<_>>();
    let certificate = HybridCertificate::<MinSig> {
        signers: Signers::from(
            dkg.keys.len(),
            (0..u32::try_from(dkg.keys.len()).unwrap()).map(Participant::new),
        ),
        bls_aggregated_vote: aggregate::combine_signatures::<MinPk, _>(
            signatures.iter().map(|signature| signature.as_ref()),
        ),
        vrf_proof: VrfProof::<MinSig> {
            material_version: VRF_MATERIAL_VERSION,
            threshold_signature: sign_message::<MinSig>(
                &dkg.vrf_threshold_private,
                &hybrid_seed_namespace(),
                &seed_message,
            ),
        },
    };
    let proof = Finalization::<HybridScheme<MinSig>, Sha256Digest> {
        proposal,
        certificate,
    }
    .encode()
    .to_vec();
    let committee_set_hash =
        outbe_consensus::proof::committee_set_hash_v2(FINALIZED_EPOCH, snapshot);
    let metadata = CertifiedParentAccountingMetadata {
        finalized_block_number,
        finalized_block_hash: parent_hash,
        finalized_epoch: FINALIZED_EPOCH,
        finalized_view: FINALIZED_VIEW,
        parent_view: PARENT_VIEW,
        ordered_committee: snapshot
            .committee
            .iter()
            .map(|entry| entry.address)
            .collect(),
        signer_bitmap: vec![1; snapshot.committee.len()],
        proof: Bytes::from(proof),
        committee_set_hash,
        vrf_material_version: VRF_MATERIAL_VERSION,
        vrf_group_public_key_hash: keccak256(&snapshot.vrf_group_public_key_bytes),
        proof_kind: ParentParticipationProof::Finalization,
        missed_proposers: Vec::new(),
    };
    outbe_consensus::proof::verify_v2_proof(
        &metadata,
        snapshot,
        metadata.proof.as_ref(),
        parent_hash,
    )
    .expect("real finalized-parent proof fixture verifies before execution");
    metadata
}
