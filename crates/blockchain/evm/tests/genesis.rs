//! Genesis V2 bootstrap regressions.
//!
//! These tests pin three independent contracts for the V2 greenfield genesis:
//!
//! 1. `scripts/seed_genesis.py` writes `ACCOUNTING_PROGRESS_ADDRESS = 0xEE04`
//!    with the canonical `0xef` marker bytecode and `slot 0 = 0`.
//! 2. The Python seeder must not write any `ValidatorSet` storage entry at
//!    the direct slots 31..40 — those are reserved for the runtime
//!    `CommitteeSnapshotStore` whose first writer is block 1's
//!    `BoundaryOutcome` system transaction.
//! 3. The genesis JSON produced by the seeder must not embed private DKG
//!    share material in any path; private keys live exclusively in the
//!    per-validator directories under the operator filesystem.
//!
//! Tests `T-3..T-9` live in [`mod runtime`] and exercise the begin-zone
//! system-transaction layout contract (`outbe_evm::system_tx`) for the
//! genesis bootstrap: block 0 has no begin-zone txs, block 1 mandatorily
//! carries `BoundaryOutcome`, block 2+ requires `CertifiedParentAccounting`
//! before any user transaction reads `last_accounted_block_number`.

use std::path::{Path, PathBuf};
use std::process::Command;

use alloy_primitives::U256;
use outbe_evm::system_tx::{expected_begin_block_kinds, SystemTxKind};
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;
use outbe_validatorset::contract::ValidatorSet;
use serde_json::Value;
use tempfile::TempDir;

const ACCOUNTING_PROGRESS_ADDRESS_HEX: &str = "000000000000000000000000000000000000ee04";
const VALIDATOR_SET_ADDRESS_HEX: &str = "000000000000000000000000000000000000ee00";

/// `0xef` marker bytecode, mirroring `MARKER_CODE` in `scripts/seed_genesis.py`
/// and the executor's marker-bytecode allowlist in
/// `crates/blockchain/evm/src/executor.rs`.
const MARKER_BYTECODE_HEX: &str = "0xef";

const ZERO_WORD_HEX: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

const FIXTURE_GENESIS: &str = r#"{
  "config": { "chainId": 512215, "epochLengthBlocks": 120 },
  "timestamp": "0x6800000",
  "alloc": {}
}"#;

const FIXTURE_SEED: &str = "{}";

// 96-hex-char (48-byte) placeholder BLS MinPk public keys; matches the
// length check in `scripts/seed_genesis.py::pubkey_bytes`.
const FIXTURE_VALIDATORS_4_PUBLIC_ONLY: &str = r#"[
  { "address": "0x1111111111111111111111111111111111111111",
    "public_key": "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" },
  { "address": "0x2222222222222222222222222222222222222222",
    "public_key": "222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222" },
  { "address": "0x3333333333333333333333333333333333333333",
    "public_key": "333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333" },
  { "address": "0x4444444444444444444444444444444444444444",
    "public_key": "444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" }
]"#;

fn repo_root() -> PathBuf {
    // `CARGO_MANIFEST_DIR` is `crates/blockchain/evm`. Walk up three levels to
    // reach the workspace root that owns `scripts/seed_genesis.py`.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn seed_genesis_script() -> PathBuf {
    repo_root().join("scripts").join("seed_genesis.py")
}

/// Run `scripts/seed_genesis.py` against the supplied fixtures inside a fresh
/// temp directory and return the parsed JSON plus the raw text. The text is
/// kept verbatim so DKG-share scans operate on the on-disk representation,
/// not the serde-roundtripped one.
fn run_seed_genesis(
    genesis_json: &str,
    seed_json: &str,
    validators_json: &str,
) -> (TempDir, Value, String) {
    let tmp = TempDir::new().expect("tempdir");
    let genesis_path = tmp.path().join("genesis.json");
    let seed_path = tmp.path().join("seed.json");
    let validators_path = tmp.path().join("validators.json");
    let out_path = tmp.path().join("out.json");
    std::fs::write(&genesis_path, genesis_json).expect("write genesis fixture");
    std::fs::write(&seed_path, seed_json).expect("write seed fixture");
    std::fs::write(&validators_path, validators_json).expect("write validators fixture");

    let status = Command::new("python3")
        .arg(seed_genesis_script())
        .arg("--genesis")
        .arg(&genesis_path)
        .arg("--seed")
        .arg(&seed_path)
        .arg("--validators")
        .arg(&validators_path)
        .arg("--output")
        .arg(&out_path)
        .status()
        .expect("invoke python3 scripts/seed_genesis.py");
    assert!(
        status.success(),
        "seed_genesis.py exited non-zero: {status:?}"
    );

    let raw = std::fs::read_to_string(&out_path).expect("read seeded genesis");
    let parsed: Value = serde_json::from_str(&raw).expect("seeded genesis is valid JSON");
    (tmp, parsed, raw)
}

fn alloc_entry<'a>(genesis: &'a Value, addr_hex: &str) -> &'a Value {
    let alloc = genesis
        .get("alloc")
        .and_then(Value::as_object)
        .expect("alloc object present in seeded genesis");
    alloc
        .get(addr_hex)
        .unwrap_or_else(|| panic!("alloc entry for 0x{addr_hex} missing from seeded genesis"))
}

fn storage_keys(entry: &Value) -> Vec<String> {
    entry
        .get("storage")
        .and_then(Value::as_object)
        .map(|m| m.keys().map(|s| s.to_lowercase()).collect())
        .unwrap_or_default()
}

/// the Python seeder writes `ACCOUNTING_PROGRESS_ADDRESS` with
/// marker bytecode `0xef` and explicit `slot 0 = 0`.
#[test]
fn accounting_progress_address_seeded_with_marker_and_zero_slot0() {
    let (_tmp, genesis, _raw) = run_seed_genesis(
        FIXTURE_GENESIS,
        FIXTURE_SEED,
        FIXTURE_VALIDATORS_4_PUBLIC_ONLY,
    );
    let entry = alloc_entry(&genesis, ACCOUNTING_PROGRESS_ADDRESS_HEX);

    let code = entry
        .get("code")
        .and_then(Value::as_str)
        .expect("EE04 entry has `code` field");
    assert_eq!(
        code, MARKER_BYTECODE_HEX,
        "EE04 must carry the `{MARKER_BYTECODE_HEX}` marker bytecode so slot 0 \
         survives EIP-161 cleanup (executor allowlist guarantees no dispatch)"
    );

    let storage = entry
        .get("storage")
        .and_then(Value::as_object)
        .expect("EE04 entry has `storage` map");
    let slot0 = storage
        .get(ZERO_WORD_HEX)
        .and_then(Value::as_str)
        .expect("EE04 storage maps slot 0 to a value");
    assert_eq!(
        slot0, ZERO_WORD_HEX,
        "EE04 slot 0 (last_accounted_block_number) must be zero at genesis"
    );
}

/// `seed_genesis.py` does not write any direct-slot
/// storage entry at `ValidatorSet` slots 31..40, matching the Rust schema in
/// `crates/system/validatorset/src/schema.rs` (slots 31..39 are mappings
/// with no base-slot value, slot 40 is a reserved `Slot<B256>` that must be
/// zero at genesis).
///
/// This protects the invariant that genesis carries no committee-snapshot
/// material; block 1's `BoundaryOutcome` system tx is the first writer.
#[test]
fn seed_genesis_writes_committee_snapshot_slots_31_to_40_matching_rust_schema() {
    // 1. Rust-schema sanity: the slot indices on the contract facade must be
    //    exactly 31..40. If schema drift moves them, this test fails loudly.
    let mut storage = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut storage, |storage| {
        let vs = ValidatorSet::new(storage);
        assert_eq!(vs.committee_snapshot_exists.base_slot(), U256::from(31u64));
        assert_eq!(vs.committee_snapshot_len.base_slot(), U256::from(32u64));
        assert_eq!(
            vs.committee_snapshot_address_at.base_slot(),
            U256::from(33u64)
        );
        assert_eq!(
            vs.committee_snapshot_pubkey_lo_at.base_slot(),
            U256::from(34u64)
        );
        assert_eq!(
            vs.committee_snapshot_pubkey_hi_at.base_slot(),
            U256::from(35u64)
        );
        assert_eq!(
            vs.committee_snapshot_vrf_material_version.base_slot(),
            U256::from(36u64)
        );
        assert_eq!(
            vs.committee_snapshot_vrf_group_public_key_hash.base_slot(),
            U256::from(37u64)
        );
        assert_eq!(
            vs.committee_snapshot_vrf_group_public_key_len.base_slot(),
            U256::from(38u64)
        );
        assert_eq!(
            vs.committee_snapshot_vrf_group_public_key_chunk_at
                .base_slot(),
            U256::from(39u64)
        );
        assert_eq!(
            vs._reserved_committee_snapshot_slot_40.slot(),
            U256::from(40u64)
        );
    });

    // 2. Python-output check: for each slot in 31..=40, the corresponding
    //    direct slot key (`hex32(N)`) must be absent from the seeded
    //    `VALIDATOR_SET_ADDRESS` storage. Mappings (slots 31..39) write at
    //    keccak-derived keys and never the base slot itself; the reserved
    //    `Slot<B256>` at 40 must be untouched.
    let (_tmp, genesis, _raw) = run_seed_genesis(
        FIXTURE_GENESIS,
        FIXTURE_SEED,
        FIXTURE_VALIDATORS_4_PUBLIC_ONLY,
    );
    let entry = alloc_entry(&genesis, VALIDATOR_SET_ADDRESS_HEX);
    let keys = storage_keys(entry);
    for slot in 31u64..=40 {
        let hex = format!("0x{:064x}", slot);
        assert!(
            !keys.iter().any(|k| k == &hex),
            "seed_genesis.py wrote direct-slot entry at ValidatorSet slot {slot} \
             ({hex}); slots 31..40 are reserved for runtime CommitteeSnapshotStore"
        );
    }
}

/// reth22-2: three-way bind of the EIP-161 preservation contract. Every
/// *stateful* dispatch-registered precompile (`outbe_precompile_addresses`)
/// must be preserved across state-root computation by EITHER the executor's
/// runtime `0xEF` marker list (`OUTBE_RUNTIME_MARKER_ADDRESSES`) OR genesis
/// `0xEF` bytecode seeded by `scripts/seed_genesis.py`. reth22-1 unified the
/// marker list into one const and pinned marker ⊇ stateful-dispatch; this test
/// binds the genesis seed list as the third source of truth so a precompile
/// that is neither marked nor seeded fails loudly instead of silently pruning.
///
/// The two STATELESS verifiers (`ZKPROOF_POSEIDON_ADDRESS`,
/// `ZKPROOF_GROTH16_ADDRESS`) are skipped: they hold no EVM storage to
/// preserve, exactly matching the `MARKER_EXEMPT` rationale in the executor's
/// `marker_list_covers_stateful_precompiles` unit test.
#[test]
fn every_stateful_precompile_preserved_by_marker_or_genesis() {
    use outbe_evm::executor::marker_addresses::OUTBE_RUNTIME_MARKER_ADDRESSES;
    use outbe_primitives::addresses::{ZKPROOF_GROTH16_ADDRESS, ZKPROOF_POSEIDON_ADDRESS};

    let (_tmp, genesis, _raw) = run_seed_genesis(
        FIXTURE_GENESIS,
        FIXTURE_SEED,
        FIXTURE_VALIDATORS_4_PUBLIC_ONLY,
    );

    // Stateless verifiers have no storage to preserve, so neither the marker
    // list nor genesis bytecode needs to cover them.
    let stateless: [alloy_primitives::Address; 2] =
        [ZKPROOF_POSEIDON_ADDRESS, ZKPROOF_GROTH16_ADDRESS];

    let mut checked = 0usize;
    for addr in outbe_evm::precompiles::outbe_precompile_addresses() {
        if stateless.contains(addr) {
            continue;
        }
        checked += 1;

        let in_marker = OUTBE_RUNTIME_MARKER_ADDRESSES.contains(addr);

        // Match the alloc key format used by `alloc_entry` / `seed_genesis.py`:
        // lowercase 40-hex chars, NO `0x` prefix (`address_bytes(addr).hex()`).
        let hex = format!("{:x}", addr);
        let in_genesis = genesis["alloc"][&hex]["code"].as_str() == Some(MARKER_BYTECODE_HEX);

        assert!(
            in_marker || in_genesis,
            "stateful precompile {addr} is EIP-161-preserved by neither the executor marker \
             list nor genesis 0xEF bytecode — its storage would be pruned at state-root"
        );
    }

    assert!(
        checked > 0,
        "no stateful precompiles were checked — the iteration covered nothing, \
         which would make this test vacuously pass"
    );
}

/// reth22-2 focused companion: `ZEROFEE_ADDRESS` is the one address the
/// reth22-1 marker test (`marker_list_covers_stateful_precompiles`) exempts
/// from the marker list "on the grounds it is genesis-seeded". This verifies
/// that exemption is real: the seeder must actually write `0xEF` code at
/// `ZEROFEE_ADDRESS`, otherwise the marker exemption would silently lose its
/// storage.
#[test]
fn zerofee_precompile_is_genesis_seeded_with_marker_bytecode() {
    use outbe_primitives::addresses::ZEROFEE_ADDRESS;

    let (_tmp, genesis, _raw) = run_seed_genesis(
        FIXTURE_GENESIS,
        FIXTURE_SEED,
        FIXTURE_VALIDATORS_4_PUBLIC_ONLY,
    );

    let hex = format!("{:x}", ZEROFEE_ADDRESS);
    let entry = alloc_entry(&genesis, &hex);
    let code = entry
        .get("code")
        .and_then(Value::as_str)
        .expect("ZEROFEE_ADDRESS entry has `code` field in seeded genesis");
    assert_eq!(
        code, MARKER_BYTECODE_HEX,
        "ZEROFEE_ADDRESS must carry `{MARKER_BYTECODE_HEX}` genesis bytecode — it is the \
         marker-list exemption in marker_list_covers_stateful_precompiles, so its EIP-161 \
         preservation depends entirely on this genesis seed"
    );
}

/// the seeded `genesis.json` must not contain any
/// substring that would identify a private DKG share, polynomial scalar, or
/// dealer secret. Public keys (BLS MinPk pubkeys, hex-encoded) and validator
/// EVM addresses are permitted because they are explicitly public.
#[test]
fn genesis_json_does_not_contain_private_dkg_shares() {
    let (_tmp, _genesis, raw) = run_seed_genesis(
        FIXTURE_GENESIS,
        FIXTURE_SEED,
        FIXTURE_VALIDATORS_4_PUBLIC_ONLY,
    );

    let haystack = raw.to_ascii_lowercase();
    let forbidden_substrings: &[&str] = &[
        "share",
        "signing_share",
        "private_key",
        "private-key",
        "privatekey",
        "secret",
        "dkg_share",
        "dealer_secret",
        "polynomial_secret",
        "evm_key",
        "consensus_share",
        "signing-key",
    ];
    for needle in forbidden_substrings {
        assert!(
            !haystack.contains(needle),
            "seeded genesis.json must not contain `{needle}` — DKG / private \
             key material is the runtime's responsibility, not genesis"
        );
    }
}

// ---------------------------------------------------------------------------
// Runtime begin-zone ordering invariants.
//
// These tests pin the V2 system-transaction layout contract surfaced through
// `outbe_evm::system_tx::expected_begin_block_kinds`. The contract is the
// single source of truth for which kinds appear in which order at each
// block height; the executor and the block builder both consume it. Pinning
// it here keeps the genesis-bootstrap requirements (block 1 BoundaryOutcome
// before block 2 CertifiedParentAccounting) visible alongside the genesis
// seeder regressions above.
// ---------------------------------------------------------------------------

// T-3 / used to live here as a source-text grep of
// `engine/src/stack.rs::validate_recovered_vrf_material`. Source-grep tests
// drift the moment anyone renames a local, so the behavioural assertion
// belongs next to the function. The DKG-share / VRF-group-key mismatch
// rejection is exercised end-to-end by `outbe-engine`'s stack tests
// (`stack::tests::*_dkg_*` family) and by the localnet restart smoke harness.

/// T-4 (runtime semantic) / block 1's begin-zone layout under V2
/// includes `BoundaryOutcome`, which carries the genesis `DkgManager` output
/// and seeds the epoch-0 `CommitteeSnapshotStore`. Without this entry the
/// CommitteeSnapshot at slots 31..40 never gets written and block 2 cannot
/// look up the active committee.
#[test]
fn genesis_seeds_epoch0_committee_snapshot() {
    let block1 = expected_begin_block_kinds(1, true, false);
    assert!(
        block1.contains(&SystemTxKind::BoundaryOutcome),
        "block 1 begin-zone must include BoundaryOutcome under V2 genesis \
         bootstrap (epoch-0 CommitteeSnapshotStore writer); got {block1:?}"
    );
    // Genesis V2 carries no VRF material in `genesis.json`.
    // The same `expected_begin_block_kinds(1, false, false)` must reject the
    // layout via the V2-specific block-1 missing-BoundaryOutcome error,
    // proven separately in `system_tx_layout.rs`.
}

/// T-5 / block 1's `BoundaryOutcome` runs before any block 2
/// begin-zone tx. Phase 1 (`CertifiedParentAccounting`) at block 2 reads the
/// snapshot written by Phase 3 (`BoundaryOutcome`) at block 1.
#[test]
fn genesis_committee_snapshot_exists_before_block2_accounting() {
    let block1 = expected_begin_block_kinds(1, true, false);
    let block2 = expected_begin_block_kinds(2, false, false);
    assert!(
        block1.contains(&SystemTxKind::BoundaryOutcome),
        "block 1 must seed the epoch-0 snapshot before block 2 reads it"
    );
    assert_eq!(
        block2.first(),
        Some(&SystemTxKind::CertifiedParentAccounting),
        "block 2's first begin-zone tx must be CertifiedParentAccounting, the \
         first reader of the snapshot seeded at block 1"
    );
}

/// T-6 / block 1 emits `BoundaryOutcome` strictly before any block 2
/// activity. Block ordering is monotonic (`finalization is monotonic`), so a successful BoundaryOutcome
/// at block 1 is observable to any block N ≥ 2 via the
/// `CommitteeSnapshotStore`.
#[test]
fn block1_boundary_outcome_writes_epoch0_snapshot_before_block2() {
    let block1 = expected_begin_block_kinds(1, true, false);
    let boundary_position = block1
        .iter()
        .position(|kind| *kind == SystemTxKind::BoundaryOutcome)
        .expect("block 1 must contain BoundaryOutcome");
    assert!(
        boundary_position < block1.len(),
        "BoundaryOutcome must appear inside the block 1 begin-zone (any \
         position) so the snapshot write happens before block 1 finalizes"
    );
    // No CertifiedParentAccounting at block 1 — the snapshot must be readable
    // by block 2's Phase 1, not consumed in-block.
    assert!(
        !block1.contains(&SystemTxKind::CertifiedParentAccounting),
        "block 1 must not run CertifiedParentAccounting; the writer (block 1) \
         and the first reader (block 2) live in different blocks"
    );
}

/// T-7 / same ordering invariant approached from the
/// `runtime_genesis_dkg_boundary` angle. The runtime `DkgManager` (consensus
/// crate) produces the `DkgBoundaryArtifact` consumed by the V2
/// `BoundaryOutcome` system tx at block 1; verifying the expected kind set
/// pins the genesis-DKG → epoch-0-snapshot path.
#[test]
fn runtime_genesis_dkg_boundary_seeds_epoch0_vrf_snapshot_before_block2() {
    let block1 = expected_begin_block_kinds(1, true, false);
    let expected_block1 = vec![
        SystemTxKind::CycleTick,
        SystemTxKind::BoundaryOutcome,
        SystemTxKind::OracleSlashWindow,
        SystemTxKind::HookEvents,
    ];
    assert_eq!(
        block1, expected_block1,
        "block 1 V2 layout pins to [CycleTick, BoundaryOutcome, \
         OracleSlashWindow]; BoundaryOutcome is the genesis DKG VRF \
         snapshot writer"
    );
}

/// T-8 / block N ≥ 2 mandatorily carries
/// `CertifiedParentAccounting` as its first begin-zone tx. This is the V2
/// replacement for the legacy exact-parent finalization invariant per Epic
#[test]
fn block2_requires_v2_parent_accounting() {
    let block2_without_boundary = expected_begin_block_kinds(2, false, false);
    let block2_with_boundary = expected_begin_block_kinds(2, true, false);
    assert_eq!(
        block2_without_boundary.first(),
        Some(&SystemTxKind::CertifiedParentAccounting)
    );
    assert_eq!(
        block2_with_boundary.first(),
        Some(&SystemTxKind::CertifiedParentAccounting)
    );

    // Higher blocks (e.g. 100) keep the same requirement; the V2 contract is
    // not localized to block 2.
    let block100 = expected_begin_block_kinds(100, false, false);
    assert_eq!(
        block100.first(),
        Some(&SystemTxKind::CertifiedParentAccounting),
        "every block N >= 2 must run CertifiedParentAccounting first"
    );
}

/// T-9 / blocks 0 and 1 must not include `CertifiedParentAccounting`.
/// Block 0 is genesis (no parent); block 1's parent is genesis (no Phase 1
/// state to import). The ignored builder test
/// `locally_built_genesis_block_reexecutes_with_same_state_root` exists
/// because of this exact invariant.
#[test]
fn block0_and_block1_do_not_require_parent_accounting() {
    let block0_no_boundary = expected_begin_block_kinds(0, false, false);
    let block0_with_boundary = expected_begin_block_kinds(0, true, false);
    let block1_with_boundary = expected_begin_block_kinds(1, true, false);

    assert!(
        block0_no_boundary.is_empty(),
        "block 0 must have no begin-zone txs; got {block0_no_boundary:?}"
    );
    assert!(
        block0_with_boundary.is_empty(),
        "block 0 with header artifact still has no begin-zone txs (Phase 3 \
         requires block_number > 0); got {block0_with_boundary:?}"
    );
    assert!(
        !block1_with_boundary.contains(&SystemTxKind::CertifiedParentAccounting),
        "block 1 must not run CertifiedParentAccounting; the V2 contract \
         starts Phase 1 at block N >= 2"
    );
}
