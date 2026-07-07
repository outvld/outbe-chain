# outbe-e2e-harness

A Rust [cucumber](https://crates.io/crates/cucumber) harness for the outbe-chain
e2e suite. Scenarios are Gherkin fixtures under [`features/`](./features); the
step code behind them (`src/flows/`) drives typed handles (`src/world/`) that
shell out — via `xshell` — to the **same** orchestration the bash suite uses.

This crate **replaces only the glue and assertions** that lived in
`scripts/e2e/lib.sh` and the scenario scripts. It does **not** reimplement node
launch, the docker/Gramine TEE enclave, or the DKG bootstrap — those stay in
`scripts/bootstrap-testnet.sh` and `scripts/run-testnet.sh`, invoked as
subprocesses.

## Model: environment (CLI) vs. requirements (tags)

The **CLI defines the environment** — how many validators to bootstrap, the TEE
mode, and whether we have `sudo`. Each **scenario declares its requirements** via
Gherkin tags. The runner matches the two:

- requirement met → the scenario runs;
- requirement unmet → the scenario is **skipped** (a `SKIPPED:` line prints, exit 0);
- with `--all`, an unmet scenario is a **failure** instead (non-zero exit).

Requirement tags (`@`-less in code): `needs-tee`, `min-validators-N`, `needs-sudo`,
and `todo` (an unimplemented stub — always skipped).

## Layout

- `features/` — Gherkin fixtures. `update_operator.feature` is wired end-to-end;
  the `s*` features are `@todo` stubs.
- `src/env.rs` — `TeeMode`, the `EnvCli` clap flags, `Environment`, and the
  requirement/skip logic.
- `src/world/` — encapsulated handles with verb APIs: `localnet.start(opts)`,
  `rpc.send_propose(...)`, `rpc.wait_block(...)`, `validators.operator(...)`.
- `src/flows/` — step definitions (the code behind the fixtures).
- `src/internal/` — private plumbing: `Config`, the `xshell` wrapper, precompile
  addresses, output parsers.

## Running

The entrypoint is the `outbe-e2e` binary. **All configuration is via CLI flags —
the harness reads no configuration from the environment.** Flags:

- `--validators <N>` — committee size to bootstrap (default 4).
- `--tee <real|mock|none>` — enclave mode (default `none` = tee-less).
- `--no-sudo` — run scripts/docker without `sudo`.
- `--all` — treat an unsatisfiable scenario as a failure instead of skipping it.
- `--debug` — stream localnet setup output (bootstrap / run-testnet / docker) live;
  off by default (that output is captured and shown only if a step fails).
- path overrides (optional, default relative to `--repo`): `--repo`, `--data-dir`,
  `--chain-bin`, `--cli-bin`, `--keygen-bin`, `--mock-bin`, `--seed`.
- plus cucumber's own `--tags`, `--name`, `--input`.

Actually executing a scenario needs a Linux box with `sudo` + `docker` + `gramine`
(same prerequisites as `mise run e2e`). First build the binaries the steps call:

```sh
cargo build -p outbe-chain --bin outbe-chain
cargo build --bin outbe-cli
cargo build --release -p outbe-tee-enclave --features mock --bin outbe-tee-enclave-mock
```

Then, e.g.:

```sh
# tee-less run of the update flow
cargo run -p outbe-e2e-harness --bin outbe-e2e -- --tee none --validators 4
# through the mock enclave
cargo run -p outbe-e2e-harness --bin outbe-e2e -- --tee mock --validators 4
# a fully-capable box: everything must run (unmet ⇒ fail, not skip)
cargo run -p outbe-e2e-harness --bin outbe-e2e -- --tee mock --validators 5 --all
```

The skip/fail *logic* is verifiable anywhere (no localnet needed): e.g.
`--validators 2` prints `SKIPPED: … needs >=4 validators, have 2` and exits 0,
while `--validators 2 --all` exits non-zero.

`--debug` streams the localnet setup output live; without it, that output is
captured and only printed if a setup step fails.

## Status

Ported: `update_operator` (from `scripts/e2e/update_operator_flow.sh`).
Stubbed (`@todo`, see `src/flows/{lifecycle,dkg}.rs`): `s1_s2_s6_s3`, `s4`, `s5`,
`s7a`, `s7b`. Wiring this into `mise run e2e` is a follow-up once more flows land.

## Ide support

Cucumber framework provides support for VSCode.
Add extension "cucumberopen.cucumber-official", and set the following "Glue" in settings:

```json
{
    "cucumber.glues": [
        "**/src/features/**/*.rs", // To support any crate with cucumber framework.
        // ..
    ]
}
```