# Outbe Chain

Public EVM-compatible blockchain built on [Reth](https://github.com/paradigmxyz/reth) (execution) + [Commonware Simplex](https://github.com/commonwarexyz/monorepo) (consensus) in a single Rust binary.

```
~2s blocks | Instant BFT finality | Built-in VRF | BLS hybrid signing | Full EVM
```

No HTTP Engine API split: consensus and execution run in one process and talk through in-process Reth engine handles (`fork_choice_updated`, `new_payload`, payload builder). Validator lifecycle, staking, rewards, slashing, voting, protocol updates, and business logic are stateful Rust precompiles; protocol updates are coordinated by validator vote plus binary rollout, with no proxy-admin model.

## Architecture

```
outbe-chain (single binary)
├── Reth SDK ─────────────── Execution Layer
│   ├── Native EVM (Solidity, MetaMask, ethers.js)
│   ├── ZeroFee txpool admission + deterministic priority classes
│   ├── Stateful Rust precompiles (system 0xEE.. / business 0x10.., 0x11.., 0x20..)
│   └── Begin/end-block hooks + OutbeBlockArtifacts in header.extra_data
└── Commonware Simplex ───── Consensus Layer
    ├── BLS-only hybrid scheme (multisig + threshold) → voter attribution + VRF
    ├── VRF leader election; deterministic degraded fallback only when no usable
    │   VRF seed exists (genesis view 1, or a missing prior certificate)
    ├── Chain-id-bound vote/handshake namespaces (no cross-chain replay)
    ├── Two-sided block-timestamp drift band vs parent: each non-genesis block
    │   must advance chain time by [1 s, 1 h] (deterministic, chain-state only)
    └── Height-periodic DKG / reshare; validator-set changes activate at the
        next epoch boundary (no on-demand reshare request)
```

## Consensus

Commonware Simplex with a BLS-only hybrid scheme: MinPk multisignature votes
provide per-validator attribution, and a MinSig threshold signature over the
prior finalized certificate provides the VRF seed. All vote and P2P-handshake
namespaces are bound to `chain_id` (`b"outbe" || chain_id_be`), so signatures
cannot cross-verify or replay across deployments.

Self-registration requires a BLS proof-of-possession over the validator address.
The MinPk aggregate uses a same-message construction, so its rogue-key
resistance depends on every committee key being possession-verified: owner- and
genesis-supplied keys are trusted, and the owner must verify proof-of-possession
out-of-band for any externally-supplied consensus key (an owner registration
without a PoP signature is permitted for bootstrapping but logged at `WARN`).

**Leader election.** Each view's leader is selected from a VRF seed derived from
the prior finalized certificate. When no usable VRF seed exists — genesis view 1,
or a missing/unverifiable prior certificate after a partition or restart —
election degrades deterministically to `bootstrap_seed || round` and then to
round-robin `(epoch + view) % n`. Degraded election is deterministic across
honest nodes (no state split). Invalid threshold-VRF seed partials are verified
and sanitized before recovery, so a single byzantine validator cannot force
permanent degraded mode; degraded fallback is not adversarially reachable.

**Reshare cadence.** DKG and reshare are height-periodic. Validator-set changes
(joins, exits) are frozen at an epoch boundary and activated at the next one —
there is no on-demand reshare request. An `EXITING` validator stays accountable
in the current consensus set until `activateResharedSet()` completes. A live-chain
reshare completes on threshold participation, so an unreachable validator does not
block it. The one exception is the **genesis bootstrap DKG**, which requires all
`n` genesis dealer logs and fail-fast aborts if a genesis validator is unreachable
— a one-time coordinated launch where every genesis validator is up by
construction, operator-recoverable by restarting the launch.

**Revealed-share exposure.** A validator that is offline during its DKG/reshare
has its individual share evaluation publicly revealed (so the ceremony can
complete) and permanently committed on-chain in the `DealerLog` artifact. A
revealed share makes that validator's VRF threshold partial forgeable — bounded,
because VRF drives leader election/fairness, not BFT safety (the BLS individual
aggregate stays authoritative, and the group secret is safe up to `f` reveals).
Operators must rotate the consensus key of any revealed validator; the set is
surfaced at `WARN` on the `outbe::dkg` log target and via the
`outbe_dkg_revealed_shares` metric.

**TEE key authority.** The shared tribute-offer key is established by an
in-enclave DKG and registered on-chain in a one-time block-1 `TeeBootstrap`
system transaction. The host relaying that transaction is untrusted, so the
registration is bound to consensus state by three deterministic gates, identical
on every validator:

- *Bootstrap supermajority + snapshot binding.* The payload must be signed by a
  strict `> 2/3` of the active consensus set, and its `committee_snapshot_hash`
  is bound to the epoch-0 committee snapshot that the same block's
  `BoundaryOutcome` wrote: the gate recomputes `committee_set_hash_v2` from
  on-chain state and rejects a value that disagrees.
- *Reshare membership gate.* When a reshare re-registers per-validator enclave
  keys, every re-registered validator must belong to the committee that boundary
  activates, so a malicious host cannot inject a key for a non-member.
- *Reshare prior-committee endorsement.* The re-registrations must additionally
  carry a threshold group signature from the **outgoing** committee over the
  incoming committee's identity and the preserved offer key. This is the only
  check a malicious supermajority of the *new* committee cannot forge by itself.

The offer key is preserved across a reshare (key-handoff, not a fresh DKG), and
the enclave binds each X25519 share-encryption key to its BLS identity so the
host cannot mispair or duplicate ceremony inputs.

Current implementation note(s): the reshare key re-registration path is not yet
wired end-to-end, so the membership and endorsement gates are enforced but
dormant (every produced boundary artifact currently carries no re-registrations);
they activate with the reshare re-registration feature.

**Block-timestamp drift band.** A normative consensus rule: every validator
rejects a non-genesis block whose `timestamp_millis` advances its parent by less
than `MIN_BLOCK_TIMESTAMP_ADVANCE_MILLIS` (1 s) or more than
`MAX_BLOCK_TIMESTAMP_DRIFT_MILLIS` (1 h). The lower bound stops a colluding
leader majority from freezing chain time (which would stall day-indexed emission
and unbonding maturity); the upper bound stops a single byzantine leader from
ratcheting chain time forward to bypass the unbonding lock and slashing window.
The proposer clamps its assigned timestamp into the same band, so honest blocks
are never rejected and a long stall self-heals. The genesis child (block 1) is
monotonic-only.

**Artifact transport.** Per-block execution data that affects the block hash
rides in `header.extra_data` as `OutbeBlockArtifacts` (active codec `VERSION
0x08`, within a 64 KiB budget). Finalized-parent certified-accounting facts ride
as begin-zone system-transaction input, not in `extra_data`. Begin-zone phases
run before user transactions; a revert in a consensus- or economic-critical
phase (parent accounting, late-finalize-credit settlement, daily emission,
reshare activation) fails the block rather than being silently skipped.

## EVM

Native EVM (Solidity, MetaMask, ethers.js) over the Reth SDK. Stateful Rust
precompiles occupy system addresses `0xEE..` and business addresses `0x10..`,
`0x11..`, `0x20..`; their accounts are marked touched before state-root
computation so they are preserved under EIP-161. `mixHash` / `prev_randao` is the
VRF seed (or the genesis round-robin exception), not Ethereum's default
randomness. The txpool uses ZeroFee admission with deterministic priority
classes.

## Stateful Runtime Module Contract

Stateful runtime modules (validator set, staking, rewards, slashing, emission,
business orchestrators) hook into block boundaries through one canonical
contract, not ad-hoc per-module APIs:

- The executor builds a single `BlockContext` from the block/header, chain spec,
  proposer, and validator-set state, then wraps it in a `BlockRuntimeContext`
  carrying the current scoped `StorageHandle` (`outbe_primitives::block`).
- Each module's block-boundary entrypoints implement `BlockLifecycle` on a
  zero-sized marker type (`XxxLifecycle`); the executor calls them as
  `<XxxLifecycle as BlockLifecycle>::begin_block(&ctx)` / `end_block(&ctx)`.
- Lifecycle ordering is explicit in the executor and hard-fork governed — there
  is no runtime plugin registration and no positional `(timestamp, block_number)`
  block-boundary API.
- Persistent state is reached only through the explicit scoped `StorageHandle`
  (`storage.contract::<T>()` / `ctx.contract::<T>()`), never implicit context or
  process globals; facades are short-lived and never escape the execution scope.

## Emission Model

Validator daily emission is delivered as **gems** (`Genesis` gems for the first
21 days from genesis, `Validator` gems thereafter), distributed proportionally to
voting participation — there is no claimable native `pending_rewards` balance.
Per-block fees are escrowed and settled at `N+K` across the late-finalize
inclusion window. Dust from fee and emission splits routes deterministically to
terminal Metadosis. Block 0 produces no validator rewards.

WorldwideDay lifecycle statuses (FORMING → LOOKBACK_DELAY → OFFERING → WAITING
→ READY) advance on two daily begin-zone Cycle ticks: 00:00 UTC
(`emission_limit_1`, which also creates the next day and settles READY days)
and 12:00 UTC (`wwd_advance_noon`, status advancement only). The 12:00 tick
exists because the forming/offering window edges land at 12:00 UTC; without it
every offering window opened ~12 hours late.

## RPC

The `outbe_*` namespace exposes read-only views over committed chain state:
`getValidators`, `getValidator`, `getEpochInfo`, `getStake`, `getSlashInfo`,
`consensusStatus`, `getVrfSeed`, `getEmissionInfo`, `getSlashConfig`,
`getParticipation`, `syncStatus`. They register through Reth's RPC extension
surface, not a parallel router.

**Operator hardening.** The default HTTP/WS module set is the standard
`eth,net,web3`; `admin` and `debug` are not enabled by default. If you enable
them, keep them on a local IPC socket or behind authentication — never expose
`admin`/`debug` unauthenticated on a public interface. Bind RPC examples to
`127.0.0.1`; use `0.0.0.0` only behind a firewall that restricts access to
trusted operators. `outbe-cli` never transmits key material to a remote RPC.

## Becoming a Validator

Register (BLS proof-of-key, no stake) → stake at least the configured minimum
(`config_min_stake`) to enter `PENDING` → activate at the next reshare boundary
to become `ACTIVE`. Current consensus signers are validators that still hold a
BLS share (`ACTIVE`, `EXITING`, and temporarily `JAILED` until the next reshare
clears the share). Non-voting consensus followers may include `REGISTERED`,
`PENDING`, and `JAILED` validators so they can sync, recover, or rejoin.

## Upgrades

Protocol updates are proposed through the reusable vote module and scheduled by
the update module after quorum. Operators still roll out binaries before the
activation height; the on-chain vote decides when the protocol version becomes
active.

Operator flow:

```bash
UPDATE_ADDR=0x000000000000000000000000000000000000EE0B
PAYLOAD='{"version":4,"activationHeight":12345,"info":"v1.2 rollout"}'

outbe-cli --private-key "$VALIDATOR_KEY" vote propose \
  --target-module "$UPDATE_ADDR" \
  --payload "$PAYLOAD"

outbe-cli --private-key "$VALIDATOR_KEY" vote cast --proposal-id 1 --yes
outbe-cli vote status --proposal-id 1
```

Before consensus/RPC startup, the node checks the on-chain active protocol
version. If the local binary protocol version is older than `active_version`, the
node refuses to start and the operator must upgrade the binary.

Handler details:

- [`crates/system/vote/README.md`](crates/system/vote/README.md) — proposal/voting flow and target handlers.
- [`crates/system/update/README.md`](crates/system/update/README.md) — active-version API, update target handler,
  migration handlers, update precompile reads/events, and startup gate.

## Repository Layout

```
outbe-chain/
├── bin/
│   ├── outbe-chain/        # Node binary (validator / full-node modes)
│   ├── outbe-cli/          # Operator CLI (validator, staking, rewards, monitor)
│   ├── outbe-keygen/       # Offline BLS / EVM key generation
│   ├── outbe-feeder/       # Oracle price feeder
│   └── outbe-tee-enclave/  # TEE enclave binary
├── crates/
│   ├── blockchain/         # consensus, engine, evm, node, primitives, rpc, txpool, macros
│   ├── system/             # validatorset, staking, rewards, slashindicator, oracle, ...
│   └── core/               # core modules: tribute, gratis, nod, credis, metadosis, ...
├── contracts/              # Solidity interfaces for precompiles + external contracts
├── scripts/                # genesis seeding, testnet bootstrap
└── deploy/                 # systemd units, monitoring
```

## Quick Start

Prerequisites: [`mise`](https://mise.jdx.dev) (provisions the Rust toolchain, Foundry, and cargo tools from `mise.toml`). Run `mise install` once, then `mise tasks` to list every task.

```bash
# 4-validator localnet
mise run build-release
mise run localnet-bootstrap     # BLS keys + genesis.json
mise run localnet-start
mise run localnet-status        # all 4 nodes should advance past block 0

# Verify via RPC
curl -s -X POST http://localhost:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# Tests
mise run test                   # cargo nextest run --workspace + doctests
mise run test-consensus         # consensus crate only
```

## CLI Tools

```bash
outbe-chain node [flags]                      # run validator or full node
outbe-keygen generate --output-dir <dir>      # BLS12-381 MinPk keypair (offline)
outbe-cli validator register|info|list        # validator lifecycle
outbe-cli staking stake|unstake|claim         # staking flow
outbe-cli rewards emission|history            # emission params (validator emission is paid in gems)
```

Full nodes sync and serve RPC without consensus key material; validators additionally pass `--validator --consensus.signing-key <path>`.

## Documentation

- `docs/becoming-a-validator.md` — validator lifecycle and operator flow.
- `docs/launching-with-sgx.md` — running the TEE localnet under real gramine-sgx
  (self-generated enclave keys, sealing, offer-key verification).
- `docker-compose.yml`, `deploy/` — local testnet and deployment
