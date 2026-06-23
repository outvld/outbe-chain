use alloy_primitives::{address, Address};

/// Gratis token precompile address.
pub const GRATIS_ADDRESS: Address = address!("0x0000000000000000000000000000000000001003");

/// Gratis factory precompile address.
pub const GRATIS_FACTORY_ADDRESS: Address = address!("0x0000000000000000000000000000000000002003");

/// Gratis shielded-pool precompile address (Tornado-style commitment pool).
///
/// Owns the per-denomination Merkle tree of commitments + per-denomination
/// nullifier set + recent-roots window backing shielded Gratis pledges.
pub const GRATIS_POOL_ADDRESS: Address = address!("0x0000000000000000000000000000000000002004");

/// Promis token precompile address.
pub const PROMIS_ADDRESS: Address = address!("0x0000000000000000000000000000000000001337");

/// Promis factory precompile address (orchestrator: mint/burn orchestration via
/// cross-module API, `mineCoen` on the ABI). Wraps the Promis token at
/// [`PROMIS_ADDRESS`], records Fidelity cohorts, and mints native COEN on
/// `mineCoen`. Carries no persistent storage of its own.
pub const PROMIS_FACTORY_ADDRESS: Address = address!("0x0000000000000000000000000000000000002337");

/// Tribute NFT precompile address.
pub const TRIBUTE_ADDRESS: Address = address!("0x0000000000000000000000000000000000001101");

/// Nod NFT precompile address.
pub const NOD_ADDRESS: Address = address!("0x0000000000000000000000000000000000001006");

/// Nod factory precompile address (orchestrator: issuance via cross-module
/// API, `mineGratis` ABI). State lives in the Nod entity store at
/// [`NOD_ADDRESS`]; NodFactory carries no persistent storage of its own.
pub const NOD_FACTORY_ADDRESS: Address = address!("0x0000000000000000000000000000000000001007");

/// Gem NFT precompile address. ERC-721 non-transferable registry.
pub const GEM_ADDRESS: Address = address!("0x0000000000000000000000000000000000001013");

/// Intex address. Canonical, cross-chain Intex series ledger
/// (identity + lifecycle). Writes are Rust-to-Rust only (IntexFactory); the
/// precompile at this address dispatches read-only series views for off-chain
/// observability.
pub const INTEX_ADDRESS: Address = address!("0x0000000000000000000000000000000000001014");

/// IntexFactory address. Drives Intex issuance, the autonomous
/// Issued→Qualified→Called lifecycle, and two-step settlement; series state is
/// written to [`INTEX_ADDRESS`].
pub const INTEX_FACTORY_ADDRESS: Address = address!("0x0000000000000000000000000000000000001015");

/// Gem factory precompile address (orchestrator: `mint_gem` via cross-module
/// API, `settleGem` / `mineGemPromis` on the ABI). Per-Gem state lives at
/// [`GEM_ADDRESS`]; GemFactory carries module-stats storage.
pub const GEM_FACTORY_ADDRESS: Address = address!("0x0000000000000000000000000000000000002013");

/// Credis precompile address.
pub const CREDIS_ADDRESS: Address = address!("0x000000000000000000000000000000000000100A");

/// Credis factory precompile address (write/orchestrator: requestCredis, payAnadosis).
pub const CREDIS_FACTORY_ADDRESS: Address = address!("0x0000000000000000000000000000000000001009");

/// Tribute factory precompile address.
pub const TRIBUTE_FACTORY_ADDRESS: Address = address!("0x0000000000000000000000000000000000001100");

/// Agent reward precompile address.
pub const AGENT_REWARD_ADDRESS: Address = address!("0x000000000000000000000000000000000000100B");

/// Fidelity precompile address.
pub const FIDELITY_ADDRESS: Address = address!("0x000000000000000000000000000000000000100C");

/// Emission limit precompile address (system-only, no user-facing precompile).
pub const EMISSION_LIMIT_ADDRESS: Address = address!("0x000000000000000000000000000000000000100D");

/// Metadosis precompile address (system-only, no user-facing precompile).
pub const METADOSIS_ADDRESS: Address = address!("0x000000000000000000000000000000000000100E");

/// Promis limit precompile address (system-only, no user-facing precompile).
pub const PROMIS_LIMIT_ADDRESS: Address = address!("0x000000000000000000000000000000000000100F");

/// Cycle precompile address (system-only). Hosts the per-day trigger
/// registry that drives `EmissionLimit.cycle_handler::run_daily_dispatch`
/// at UTC midnight. See epic, Phase 5.
pub const CYCLE_ADDRESS: Address = address!("0x0000000000000000000000000000000000001010");

pub const CCA_ADDRESS: Address = address!("0x0000000000000000000000000000000000001011");

/// Merchant pool accumulator address. Receives the 4 % Merchant slice of
pub const MERCHANT_ADDRESS: Address = address!("0x0000000000000000000000000000000000001012");

// ---------------------------------------------------------------------------
// Validator infrastructure precompiles (0xEE00 range)
// ---------------------------------------------------------------------------

/// Validator set management precompile address.
pub const VALIDATOR_SET_ADDRESS: Address = address!("0x000000000000000000000000000000000000EE00");

/// Slash indicator precompile address.
pub const SLASH_INDICATOR_ADDRESS: Address = address!("0x000000000000000000000000000000000000EE01");

/// Staking precompile address.
pub const STAKING_ADDRESS: Address = address!("0x000000000000000000000000000000000000EE02");

/// Rewards precompile address.
pub const REWARDS_ADDRESS: Address = address!("0x000000000000000000000000000000000000EE03");

/// Accounting progress marker address.
///
/// Holds persistent V2 Phase 1 accounting progress (slot 0 =
/// `last_accounted_block_number: u64`). System-only: there is **no** EVM
/// precompile dispatch registered at this address, so user transactions
/// CALLing it execute as no-op accounts. Only the V2 executor Phase 1 path
/// may write slot 0. The address is included in the executor's EIP-161
/// marker-bytecode allowlist so the slot survives state-root computation
/// across all blocks.
pub const ACCOUNTING_PROGRESS_ADDRESS: Address =
    address!("0x000000000000000000000000000000000000EE04");

/// Oracle precompile address.
pub const ORACLE_ADDRESS: Address = address!("0x000000000000000000000000000000000000EE05");

/// Log emitter address for zero-fee policy rejections.
///
/// When the executor rejects a zero-fee user transaction (e.g.
/// `Oracle.submitVote`) at stateless classification or stateful
/// authorization time, it includes the transaction in the block with a
/// `status=0` receipt carrying one `OutbeFailure(code, reason)` log
/// emitted from this address. No EVM execution and no state mutation
/// happen at this address — it is purely a logical namespace for
/// `eth_getLogs` filtering. The matching log builder, the `OutbeFailure`
/// event definition, and the zero-fee error → code mapping live in
/// `outbe-evm` and `outbe-zerofee` respectively. See EPIC.
pub const ZERO_FEE_POLICY_LOG_ADDRESS: Address =
    address!("0x000000000000000000000000000000000000EE06");

/// Poseidon-BN254 hash precompile address (stateless).
///
/// Raw byte ABI: input is `N×32` BE-encoded field elements (`1 ≤ N ≤ 12`,
/// each mod-reduced to BN254 Fr); output is the 32-byte BE-encoded
/// Poseidon hash. Matches `outbe-poseidon`'s Circom parameter set, so a
/// hash computed by a wallet and the precompile agree byte-for-byte.
pub const ZKPROOF_POSEIDON_ADDRESS: Address =
    address!("0x000000000000000000000000000000000000EE07");

/// Groth16 / UltraHonkKeccak proof verifier precompile address (stateless).
///
/// Input is `abi.encode(bytes32 circuit_hash, bytes proof)`; the
/// precompile looks `circuit_hash` up against the canonical-circuit
/// table from `outbe-zk-canonical` and dispatches verification to the
/// Barretenberg FFI vendored by `outbe-zk-circuit-noir`. Output is 32
/// bytes: `0x..01` on a valid proof, `0x..00` otherwise (including
/// unknown circuit hashes).
pub const ZKPROOF_GROTH16_ADDRESS: Address = address!("0x000000000000000000000000000000000000EE08");

/// ZeroFee paymaster precompile address (stateful).
///
/// Acts as the EIP-7702 delegation target for "void sponsorship" — users
/// who delegate their EOA to this address may submit up to
/// `FREE_TX_DAILY_LIMIT` (8) free transactions per UTC day, each capped by
/// hard envelope limits (`gas_limit`, `calldata_size`, `value == 0`,
/// `to ∈ SPONSORED_TARGET_WHITELIST`). The contract holds a single
/// `Mapping<Address, u64>` packing `(date_key: u32, count: u32)` per
/// signer; lazy reset on day flip.
///
/// View ABI (see `interfaces/IZeroFee.sol` for the authoritative
/// definition) — two methods, both anchored to the current block's
/// UTC day so callers never supply or reconcile the day themselves:
///   - `authorizeSponsorship(address signer) view returns (bool)` —
///     `true` if `signer` would be admitted to the sponsored path for
///     this block (mirrors the executor pre-fee gate: not self,
///     `balance > 0`, `count < FREE_TX_DAILY_LIMIT` for today).
///   - `getCounter(address signer) view returns (uint32 day, uint32 count)` —
///     the effective `(day, count)` for today with the lazy day-reset
///     already applied (`day` = today, `count` = 0 if the stored slot
///     is from an earlier day).
///
/// The raw packed slot (`date_key << 32 | count`) is readable via
/// `eth_getStorageAt(ZEROFEE_ADDRESS, slot)` for anyone who needs the
/// pre-reset value; it is not a precompile method. The mutating
/// `record_use` is invoked only by the executor pre-fee hook and is
/// deliberately not exposed through ABI so an attacker cannot burn
/// their own quota via an unrelated sub-call.
///
/// No native balance is held at this address; fee debit is simply skipped
/// when the executor's pre-fee hook detects EIP-7702 delegation to it.
pub const ZEROFEE_ADDRESS: Address = address!("0x000000000000000000000000000000000000EE09");

/// TEE Registry precompile (storage-backed KV).
///
/// Records the per-validator TEE registration bundle and the global
/// `tribute_offer_public_key` written once by the `TeeBootstrap` system
/// transaction (Phase 3b). The public ABI is read-only (clients fetch the offer
/// key via `eth_call`); the initial write is performed natively by the system-tx
/// handler through `StorageHandle::contract`, not via the public ABI.
pub const TEE_REGISTRY_ADDRESS: Address = address!("0x000000000000000000000000000000000000EE0A");

/// On-chain upgrade governance precompile address.
///
/// Hosts proposal/vote state and the active protocol version. Callable
/// dispatch is registered at `UPDATE_ADDRESS`; lifecycle activation is wired later.
pub const UPDATE_ADDRESS: Address = address!("0x000000000000000000000000000000000000EE0B");

/// Generic on-chain governance precompile address.
///
/// Hosts reusable proposal/voting state. Callable dispatch will be registered
/// at `GOVERNANCE_ADDRESS` in Phase 2 after runtime extraction from `update`.
pub const GOVERNANCE_ADDRESS: Address = address!("0x000000000000000000000000000000000000EE0C");

/// Whitelist of `to` addresses accepted on the EIP-7702 sponsored
/// (zero-fee) path enabled by [`ZEROFEE_ADDRESS`].
///
/// Sponsored transactions are restricted to protocol-defined system
/// precompiles — they cannot enter arbitrary EVM execution. The
/// whitelist replaces a global per-block sponsored-tx cap by
/// structurally limiting the reachable code paths: an attacker with N
/// pre-funded addresses can still burn 8 free txs each, but each tx
/// can only invoke one of these audited entrypoints. The set is a
/// strict subset of the registered outbe precompile table because
/// validator-only entrypoints (rewards/staking/oracle) are not
/// reachable through the sponsored path — those have dedicated
/// authorization flows. Editing this list is part of the protocol
/// contract.
pub const SPONSORED_TARGET_WHITELIST: &[Address] = &[
    GRATIS_ADDRESS,
    GRATIS_FACTORY_ADDRESS,
    PROMIS_ADDRESS,
    PROMIS_FACTORY_ADDRESS,
    TRIBUTE_ADDRESS,
    NOD_ADDRESS,
    NOD_FACTORY_ADDRESS,
    CREDIS_ADDRESS,
    CREDIS_FACTORY_ADDRESS,
    TRIBUTE_FACTORY_ADDRESS,
    AGENT_REWARD_ADDRESS,
    FIDELITY_ADDRESS,
];

/// Compile-time uniqueness check on [`SPONSORED_TARGET_WHITELIST`].
///
/// A duplicate would let the `O(n)` `contains` check silently accept
/// the same address twice and waste cycles, but more importantly
/// flag that an editor has copy-pasted a row by mistake. Anchoring
/// this at compile time makes the protocol contract self-policing.
const _: () = {
    let list = SPONSORED_TARGET_WHITELIST;
    let mut i = 0;
    while i < list.len() {
        let mut j = i + 1;
        while j < list.len() {
            // Compare the underlying 20-byte arrays — `Address` is
            // `repr(transparent)` over `[u8; 20]`.
            let a = list[i].0 .0;
            let b = list[j].0 .0;
            let mut k = 0;
            let mut eq = true;
            while k < 20 {
                if a[k] != b[k] {
                    eq = false;
                    break;
                }
                k += 1;
            }
            if eq {
                panic!("SPONSORED_TARGET_WHITELIST contains a duplicate address");
            }
            j += 1;
        }
        i += 1;
    }
};

/// System address used for system-only calls (block hooks).
pub const SYSTEM_ADDRESS: Address = Address::ZERO;

/// Reserved sender/recipient address for signed system-transaction artifacts.
///
/// System transactions are first-class block-body transactions used to expose
/// begin-block runtime effects through normal Ethereum receipts. They are
/// authenticated by the proposer signature but executed in EVM system mode via
/// [`SYSTEM_ADDRESS`], so this address must remain distinct from both the fee
/// recipient and any user-facing precompile account.
pub const OUTBE_SYSTEM_TX_ADDRESS: Address = address!("0xff00000000000000000000000000000000000001");

// ---------------------------------------------------------------------------
// Pre-deployed external standard contracts (no precompile dispatch)
// ---------------------------------------------------------------------------
//
// These addresses hold canonical third-party runtime bytecode pre-allocated at
// genesis. They execute as ordinary EVM accounts under standard semantics; the
// precompile lookup in `OutbeEvmFactory::create_evm` does not intercept them.

/// Arachnid deterministic CREATE2 deployer.
///
/// Accepts calldata `salt(32) || initcode` and forwards via CREATE2, producing
/// a contract at `keccak256(0xff || deployer || salt || keccak256(initcode))[12:]`.
/// Source: `Arachnid/deterministic-deployment-proxy`.
pub const CREATE2_DEPLOYER_ADDRESS: Address =
    address!("0x4e59b44847b379578588920cA78FbF26c0B4956C");

/// ERC-4337 EntryPoint v0.7.
///
/// Canonical bundler entry point for account-abstraction `UserOperation`s.
/// Source: `eth-infinitism/account-abstraction@v0.7.0`.
pub const ENTRY_POINT_V07_ADDRESS: Address = address!("0x0000000071727De22E5E9d8BAf0edAc6f37da032");

/// ERC-4337 SenderCreator v0.7.
///
/// Helper invoked by EntryPoint v0.7 to deploy AA accounts from factory
/// `initCode`. Address is the deterministic CREATE address from EntryPoint's
/// constructor: `keccak256(rlp([entrypoint, 1]))[12:]`. Pre-deployed at genesis
/// because Outbe skips the EntryPoint constructor (which would otherwise emit
/// `new SenderCreator()`).
pub const SENDER_CREATOR_V07_ADDRESS: Address =
    address!("0xEFC2c1444eBCC4Db75e7613d20C6a62fF67A167C");

///
/// Test-only stateful precompile that exercises the production sub-call path
/// end-to-end. Calldata: `(address target, int256 x)` ABI-encoded. The
/// precompile constructs `inc(int256 x)` calldata for the user-supplied
/// `target` Solidity contract address and invokes it via
/// `storage.sub_call`, logging every step through `tracing::info!`. Errors
/// returned by the target (e.g. `NegativeNotAllowed(x)` on `x < 0`)
/// propagate back as `PrecompileError::RevertBytes`.
///
/// A genesis-deployed `Counter` fixture at
/// `0x000000000000000000000000000000000000C0DE` (see
/// `scripts/contracts/counter.code.hex` and `e2e/evm/README.md`) is the
/// canonical target for the localnet smoke flow, but the precompile is
/// target-agnostic — any contract implementing `inc(int256)` works.
pub const DEBUG_SUBCALL_PRECOMPILE_ADDRESS: Address =
    address!("0x000000000000000000000000000000000000F999");

/// Desis precompile address. Runs the Intex auction and clearing engine
/// (bid ingestion, reveal, clearing, issuance handoff to IntexFactory).
pub const DESIS_ADDRESS: Address = address!("0x0000000000000000000000000000000000001016");

/// VaultProvider precompile address. Reserve liquidity router: registers
/// ERC-4626 vaults per asset.
pub const VAULT_PROVIDER_ADDRESS: Address = address!("0x0000000000000000000000000000000000001017");
