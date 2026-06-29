# e2e.md scenario suite (S1–S7)

Shell e2e tests for the scenarios in `e2e.md`, run against a **gramine-mock TEE
localnet** (no real SGX/DCAP). Each script bootstraps a fresh 4-validator chain
(`scripts/seed-testnet-lowstake.json`, `min_stake = 1000`), drives the scenario,
and tallies PASS/FAIL assertions. Adapted to the **actual** protocol where
`e2e.md` diverges — divergences are listed below, not silently dropped.

## Run

```sh
# build first (or: mise run e2e — builds and runs the full suite)
# cargo build -p outbe-chain --bin outbe-chain
# cargo build --bin outbe-cli
# cargo build --release -p outbe-tee-enclave --features mock --bin outbe-tee-enclave-mock
sudo true                       # scripts use sudo for run-testnet.sh / docker
scripts/e2e/s1_s2_s6_s3_lifecycle.sh   # S1 + S2 + S6 + S3 on one chain
scripts/e2e/s4_restart_active.sh       # S4
scripts/e2e/s5_dkg_failure.sh          # S5
scripts/e2e/s7a_downtime_slash.sh      # S7 (slashing)
scripts/e2e/s7b_stale_join.sh          # S7 (stale join)
scripts/e2e/update_operator_flow.sh    # update propose/vote/status smoke
```

Each prints `<NAME> SCENARIO_PASS` / `SCENARIO_FAIL` and an `N passed, M failed`
tally. `lib.sh` holds the shared harness (bootstrap, joiner provisioning, RPC/
state readers, assertions). Ports: committee http `8545+i`; joiner v5 http `8549`,
consensus `30404`, tee `7004`.

## Two protocol gaps this suite drove (now implemented, commit `bea1a24a`)

- **S3 demotion** — an exited validator's node used to die at VRF expiry after its
  dealer duties. It now **demotes to a share-less verifier-follower** of the
  resharded (N−1) committee and stays online following finality
  (`crates/blockchain/engine/src/stack.rs`, dealer-only activation).
- **S7b stale-join guard** — a staked PENDING joiner was flipped ACTIVE regardless
  of sync. New `confirmValidatorReady()` precompile + `val_join_confirmed` flag
  (slot 41) gate inclusion in the reshare target; `outbe-cli validator confirm-ready`.
  Join contract is now **stake → PENDING → confirm-ready → reshare → ACTIVE**.

## Spec ↔ reality adaptations (the assertions reflect the right column)

| `e2e.md` assumption | Actual behavior | Where |
|---|---|---|
| BLS threshold share generated/held inside the enclave (TCB) | Share lives in the **node process / `keys-dir` files**; the enclave holds only the **tribute offer key**. S4 asserts "share recovered from `keys-dir`", not from the TCB. | confirmed by user; `run-testnet.sh` |
| Offer submission flips wwd status (offering → next) | Offer only **reads** OFFERING as a gate; wwd transitions are **time/CycleTick-driven**. S1 asserts wwd status is **invariant** across an offer. | `tributefactory/runtime.rs`, `metadosis/state.rs` |
| Certificate ≈ 162 B | `Finalization = Proposal + HybridCertificate` (bitmap + 96 B MinPk aggregate), **variable ~130–300 B**. Not asserted as a fixed size. | `marshal_types.rs`, `proof/hybrid_wire.rs` |
| DCAP attestation, MRENCLAVE assertable | `verify_enclave_registration` is a stub on a gramine-**direct** mock; no MRENCLAVE/quote is assertable. S1 asserts the testable TEE facts (`isBootstrapped`, offer-key parity via supply). | `teeregistry/runtime.rs` |
| DKG failure → "24 retries hourly → hard halt" | **No** retry counter / hard-halt. Bound is **VRF expiry** (`planned_activation + activation_grace_blocks`); old committee keeps finalizing until then; retry is per-finalized-height. S5 asserts that model. | `stack.rs`, `vrf_safety.rs` |
| Exited node "уходит в fullnode-режим" | Now true (S3 demotion). Committee-side shrink (EXITING→UNBONDING, N→N−1) already worked. | `stack.rs`, `validatorset/runtime.rs` |
| SLASHED status | No SLASHED status; a felony now JAILS (ACTIVE→JAILED, slash, frozen) — the validator can later unjail (→PENDING→ACTIVE) or unstake out, rather than being force-exited. | `validatorset/runtime.rs` (status enum) |
| Equivocation auto-slashed on-chain | Detection exists but is **logged-and-dropped**; operator-submitted evidence precompiles slash with real BLS verify (unit-tested; BLS fabrication out of shell scope). S7a uses **downtime felony** as the shell-testable slash. | `reporter.rs`, `slashindicator/` |
| Stale joiner blocked from activation | Was not implemented; now the **stale-join guard** (S7b). | this PR |

## Scenario → script → key assertions

- **S1** (`s1_s2_s6_s3_lifecycle.sh`): cold full-node sync; offer executes in the
  full-node's own enclave (supply parity); **state-root parity**; full-node stays
  non-participant; wwd status invariant.
- **S2** (same): stake → PENDING (asserts not-yet-participant pre-confirm) →
  confirm-ready → reshare → ACTIVE at the epoch boundary; **lockstep past
  activation** proves the share works (not voteless); `activeCount 4→5`.
- **S6** (same): offer submitted in the reshare window lands **exactly once**
  (supply +1), parity on the joiner's own RPC.
- **S3** (same): deactivate → EXITING (immediate, still accountable) → reshare →
  UNBONDING, `activeCount 5→4`; node logs **"demoting to verifier-follower"** and
  keeps following finality; post-demotion offer parity.
- **S4** (`s4_restart_active.sh`): restart an ACTIVE validator (enclave stays up);
  resume signing **without a reshare** (share from `keys-dir`); no new ceremony; no
  equivocation; enclave still serves offers.
- **S5** (`s5_dkg_failure.sh`): freeze a 4→5 target, drop online acking players
  below `player_threshold`; retry repeats, old committee stays live (3-of-4), no
  hard-halt; restore the participant → ceremony completes, set reaches 5.
- **S7a** (`s7a_downtime_slash.sh`): a felony JAILS + slashes (no longer force-exit);
  asserts liveness (3-of-4 quorum survives a node loss). Downtime slashing is
  fee-settlement-gated so a bare kill cannot trip a felony on the ZeroFee localnet;
  the jail/slash/unjail mechanism is unit-tested.
- **S7b** (`s7b_stale_join.sh`): unconfirmed PENDING joiner stays out of a full
  reshare cycle; confirm-ready → next reshare activates it.
- **Update operator** (`update_operator_flow.sh`): `outbe-cli update propose/vote/status`
  on a 4-validator TEE localnet; proposal visible while pending, yes-vote tally,
  state-root parity. Does not wait through the voting window or activation (Rust e2e).

## Caveats

- gramine-**direct** mock (no SGX/DCAP sealing); `min_stake = 1000` (not prod 100k);
  single joiner 4↔5 on loopback. State parity is asserted at `totalSupply` and at
  `stateRoot` for a common finalized height (not a full per-block replay).
- Restarting an enclave **in place** re-derives a new offer key under the mock, so
  scenarios re-bootstrap cleanly rather than restart enclaves (S4 restarts only the
  node, keeping the enclave container up).
