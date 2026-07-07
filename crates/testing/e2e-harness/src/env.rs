//! Test **environment** (from the CLI) vs. scenario **requirements** (from tags).
//!
//! The binary's clap flags describe the box we're running on — how many
//! validators to bootstrap, which enclave mode, whether we have `sudo`. Each
//! Gherkin scenario declares what it *needs* via tags. The runner matches the
//! two: a scenario the environment can't satisfy is **skipped**, or — with
//! `--all` — turned into a **failure**.
//!
//! Every requirement is a **tag** (matched on merged feature + scenario tags,
//! `@`-less), so the Given text stays purely descriptive:
//!   - `min-validators-N` → requires `--validators >= N` (N parsed from the tag).
//!   - `tee`              → requires `--tee` is `real` or `mock`.
//!   - `sudo`             → requires `sudo` (no `--no-sudo`).
//!   - `todo`             → always skipped (unimplemented stub), regardless of `--all`.

use std::path::PathBuf;
use std::sync::OnceLock;

use cucumber::gherkin::{Feature, Scenario};

use crate::internal::ports::Ports;

/// Enclave mode the localnet runs with (the `--tee` flag).
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TeeMode {
    /// Real SGX under `gramine-sgx` (needs SGX hardware).
    Real,
    /// Mock enclave under `gramine-direct` (no SGX).
    Mock,
    /// No enclave at all — the chain runs tee-less.
    #[default]
    None,
}

impl TeeMode {
    /// Whether an enclave is launched (mock or real).
    pub fn enabled(self) -> bool {
        !matches!(self, TeeMode::None)
    }
}

/// The clap arguments that define the environment (merged with cucumber's own
/// `--tags`/`--name`/`--input` via [`cucumber::cli::Opts`]).
///
/// Everything is a CLI flag — the harness reads no configuration from the
/// environment. Path flags are optional and default relative to `--repo`.
#[derive(clap::Args, Clone, Debug)]
pub struct EnvCli {
    /// Number of committee validators to bootstrap.
    #[arg(long, default_value_t = 4)]
    pub validators: usize,

    /// Don't probe for free ports — take each node's block verbatim.
    ///
    /// By default every node's block of 7 ports (rpc, tee, p2p, discv5, authrpc,
    /// metrics, consensus) is scanned for: the allocator walks forward past any
    /// busy port, so a parallel or coexisting run finds a free set. (Each parallel
    /// run still needs its own `--data-dir`.) With this flag the blocks are the
    /// static `8545 + i * 7` layout and a busy port surfaces as a launch failure.
    #[arg(long)]
    pub no_resolve_ports: bool,

    /// Enclave mode for the localnet.
    #[arg(long, value_enum, default_value_t = TeeMode::None)]
    pub tee: TeeMode,

    /// Run docker/process/script steps without `sudo`.
    #[arg(long)]
    pub no_sudo: bool,

    /// Treat a scenario the environment can't satisfy as a FAILURE instead of
    /// skipping it.
    #[arg(long)]
    pub all: bool,

    /// Stream localnet setup output (bootstrap / node launch / docker) live.
    /// Off by default: that output is captured and only surfaced on failure.
    #[arg(long)]
    pub debug: bool,

    /// Repo root (working dir for scripts/binaries). Defaults to this crate's
    /// workspace root.
    #[arg(long)]
    pub repo: Option<PathBuf>,

    /// Base localnet data dir (defaults to `/tmp/outbe-e2e-harness`). Each run
    /// lands in a unique `run-<secs>-<pid>` subdir under it, so concurrent runs
    /// self-isolate (own data + docker names + teardown scope).
    #[arg(long)]
    pub data_dir: Option<PathBuf>,

    /// `outbe-chain` binary. Defaults to `<repo>/target/debug/outbe-chain`.
    #[arg(long)]
    pub chain_bin: Option<PathBuf>,

    /// `outbe-cli` binary. Defaults to `<repo>/target/debug/outbe-cli`.
    #[arg(long)]
    pub cli_bin: Option<PathBuf>,

    /// `outbe-keygen` binary. Defaults to `<repo>/target/debug/outbe-keygen`.
    #[arg(long)]
    pub keygen_bin: Option<PathBuf>,

    /// Mock enclave binary. Defaults to
    /// `<repo>/target/release/outbe-tee-enclave-mock`.
    #[arg(long)]
    pub mock_bin: Option<PathBuf>,

    /// Genesis seed file. Defaults to
    /// `<repo>/scripts/seed-testnet-lowstake.json`.
    #[arg(long)]
    pub seed: Option<PathBuf>,
}

/// The resolved environment: every knob and path the harness needs, sourced
/// entirely from the CLI.
#[derive(Clone, Debug)]
pub struct Environment {
    pub validators: usize,
    /// Per-node port blocks. The committee's are allocated up front (their
    /// consensus/p2p ports get baked into genesis); the joiner and followers
    /// take the next block on first use.
    pub(crate) ports: Ports,
    pub tee_mode: TeeMode,
    pub sudo: bool,
    pub all: bool,
    /// Stream localnet setup output live (else capture, show only on failure).
    pub debug: bool,
    pub repo: PathBuf,
    pub data_dir: PathBuf,
    pub chain_bin: PathBuf,
    pub cli_bin: PathBuf,
    pub keygen_bin: PathBuf,
    pub mock_bin: PathBuf,
    pub seed: PathBuf,
}

impl Environment {
    /// Resolve from the parsed CLI. Unset path flags default relative to the
    /// repo root. No environment variables are consulted.
    pub fn from_cli(cli: &EnvCli) -> Self {
        let repo = cli.repo.clone().unwrap_or_else(default_repo);
        Self {
            validators: cli.validators,
            ports: Ports::new(cli.validators, !cli.no_resolve_ports)
                .expect("allocate localnet port blocks"),
            tee_mode: cli.tee,
            sudo: !cli.no_sudo,
            all: cli.all,
            debug: cli.debug,
            data_dir: cli
                .data_dir
                .clone()
                .unwrap_or_else(|| PathBuf::from("/tmp/outbe-e2e-harness")),
            chain_bin: cli
                .chain_bin
                .clone()
                .unwrap_or_else(|| repo.join("target/debug/outbe-chain")),
            cli_bin: cli
                .cli_bin
                .clone()
                .unwrap_or_else(|| repo.join("target/debug/outbe-cli")),
            keygen_bin: cli
                .keygen_bin
                .clone()
                .unwrap_or_else(|| repo.join("target/debug/outbe-keygen")),
            mock_bin: cli
                .mock_bin
                .clone()
                .unwrap_or_else(|| repo.join("target/release/outbe-tee-enclave-mock")),
            seed: cli
                .seed
                .clone()
                .unwrap_or_else(|| repo.join("scripts/seed-testnet-lowstake.json")),
            repo,
        }
    }
}

impl Default for Environment {
    fn default() -> Self {
        Self::from_cli(&EnvCli {
            validators: 4,
            // Unlike the CLI default, don't scan: a `Default` environment must be
            // deterministic and must not bind sockets (it is used by unit tests).
            no_resolve_ports: true,
            tee: TeeMode::None,
            no_sudo: false,
            all: false,
            debug: false,
            repo: None,
            data_dir: None,
            chain_bin: None,
            cli_bin: None,
            keygen_bin: None,
            mock_bin: None,
            seed: None,
        })
    }
}

/// Default repo root: three levels up from this crate (`crates/testing/e2e-harness`).
fn default_repo() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for _ in 0..3 {
        p.pop();
    }
    p
}

static ENV: OnceLock<Environment> = OnceLock::new();

/// Install the resolved environment (called once by `run()` before cucumber
/// constructs any `World`).
pub fn set_environment(env: Environment) {
    let _ = ENV.set(env);
}

/// The active environment, or a sensible default (used by lib unit tests that
/// never call [`set_environment`]).
pub fn environment() -> Environment {
    ENV.get().cloned().unwrap_or_default()
}

/// Whether the scenario is an unimplemented stub (`@todo`).
pub fn is_todo(feature: &Feature, scenario: &Scenario) -> bool {
    has_tag(feature, scenario, "todo")
}

/// Why the environment can't satisfy this scenario, or `None` if it can.
///
/// Every requirement is declared as a tag (`@tee`, `@min-validators-N`, `@sudo`),
/// so the Given text stays purely descriptive — nothing here reparses step prose.
pub fn unmet(feature: &Feature, scenario: &Scenario, env: &Environment) -> Option<String> {
    if let Some(n) = required_validators(feature, scenario) {
        if env.validators < n {
            return Some(format!("needs >={n} validators, have {}", env.validators));
        }
    }
    if requires_tee(feature, scenario) && !env.tee_mode.enabled() {
        return Some("needs a TEE enclave (@tee), but --tee none".to_string());
    }
    if has_tag(feature, scenario, "sudo") && !env.sudo {
        return Some("needs sudo (@sudo), but --no-sudo".to_string());
    }
    None
}

/// The minimum validator count from a `@min-validators-N` tag, if present.
pub fn required_validators(feature: &Feature, scenario: &Scenario) -> Option<usize> {
    feature
        .tags
        .iter()
        .chain(scenario.tags.iter())
        .find_map(|tag| parse_min_validators_tag(tag))
}

/// Whether the scenario requires an enclave (`@tee`).
pub fn requires_tee(feature: &Feature, scenario: &Scenario) -> bool {
    has_tag(feature, scenario, "tee")
}

/// Parse `N` out of a `min-validators-<N>` tag (tags are `@`-less here).
fn parse_min_validators_tag(tag: &str) -> Option<usize> {
    tag.strip_prefix("min-validators-")?.parse().ok()
}

/// What to do with a scenario given the environment.
pub enum Decision {
    Run,
    Skip(String),
}

/// Decide run vs skip. `@todo` always skips; an unmet requirement skips unless
/// `--all` (then it runs so the `before` hook can fail it).
pub fn decide(feature: &Feature, scenario: &Scenario, env: &Environment) -> Decision {
    if is_todo(feature, scenario) {
        return Decision::Skip("not implemented (@todo)".to_string());
    }
    match unmet(feature, scenario, env) {
        None => Decision::Run,
        Some(reason) if env.all => {
            // Run it; the `before` hook panics so it counts as a failure.
            let _ = reason;
            Decision::Run
        }
        Some(reason) => Decision::Skip(reason),
    }
}

fn has_tag(feature: &Feature, scenario: &Scenario, tag: &str) -> bool {
    feature
        .tags
        .iter()
        .chain(scenario.tags.iter())
        .any(|t| t == tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_min_validators_tag() {
        assert_eq!(parse_min_validators_tag("min-validators-4"), Some(4));
        assert_eq!(parse_min_validators_tag("min-validators-12"), Some(12));
        assert_eq!(parse_min_validators_tag("tee"), None);
        assert_eq!(parse_min_validators_tag("min-validators-"), None);
        assert_eq!(parse_min_validators_tag("min-validators-x"), None);
    }
}
