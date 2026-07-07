//! CLI-derived configuration for the harness.
//!
//! Paths/toggles ported from `scripts/e2e/lib.sh` (lines 11-14, 17-41) and
//! `update_operator_flow.sh`. Every value comes from the CLI [`Environment`] — the
//! harness reads no configuration from the process environment. (`PATH`/`HOME`
//! are only read to build the child's `PATH` so `cast` resolves.)

use std::path::{Path, PathBuf};

use crate::env::{Environment, TeeMode};
use crate::internal::ports::{Ports, Service};

#[derive(Clone, Debug)]
pub(crate) struct Config {
    /// Repo root (`--repo`); working dir for every script/binary we invoke.
    pub repo: PathBuf,
    /// Localnet data dir (`--data-dir`).
    pub dir: PathBuf,
    /// `outbe-chain` node binary (`--chain-bin`).
    pub bin_chain: PathBuf,
    /// `outbe-cli` client binary (`--cli-bin`).
    pub bin_cli: PathBuf,
    /// `outbe-keygen` binary (`--keygen-bin`). Used by the joiner flow.
    pub bin_keygen: PathBuf,
    /// Mock enclave binary (`--mock-bin`).
    pub bin_mock: PathBuf,
    /// Genesis seed file (`--seed`).
    pub seed: PathBuf,
    /// Primary RPC url (validator-0).
    pub rpc0: String,
    /// `PATH` with `~/.foundry/bin` appended so `cast` resolves (lib.sh:20).
    pub path: String,

    // ---- resolved from the CLI [`Environment`] ----
    /// Committee size (`--validators`). The joiner and the followers live at
    /// indices beyond it, so it can't be recovered from [`Config::ports`].
    pub validators: usize,
    /// Per-node port blocks. A node's block is allocated on first use, so indices
    /// past the committee (joiner, followers) resolve without pre-declaration.
    pub ports: Ports,
    /// A stable, data-dir-derived tag that scopes this run's enclave containers
    /// (`outbe-tee-gramine-<tag>-<i>`) and teardown sweep — independent of ports.
    pub run_tag: String,
    /// Enclave mode the localnet runs with.
    pub tee_mode: TeeMode,
    /// Whether script/docker/process steps run under `sudo`.
    pub sudo: bool,
    /// Stream localnet setup output live (else capture, show only on failure).
    pub debug: bool,
}

impl Config {
    /// Build config entirely from the resolved CLI [`Environment`].
    pub fn resolve(env: &Environment) -> Self {
        Self {
            repo: env.repo.clone(),
            dir: env.data_dir.clone(),
            bin_chain: env.chain_bin.clone(),
            bin_cli: env.cli_bin.clone(),
            bin_keygen: env.keygen_bin.clone(),
            bin_mock: env.mock_bin.clone(),
            seed: env.seed.clone(),
            rpc0: format!("http://localhost:{}", env.ports.port(Service::Http, 0)),
            path: path_with_foundry(),
            validators: env.validators,
            ports: env.ports.clone(),
            run_tag: dir_tag(&env.data_dir),
            tee_mode: env.tee_mode,
            sudo: env.sudo,
            debug: env.debug,
        }
    }

    /// HTTP RPC port for validator index `i`.
    pub fn http_port(&self, i: usize) -> u16 {
        self.ports.port(Service::Http, i)
    }

    /// HTTP RPC port of the primary node (validator-0).
    pub fn primary_port(&self) -> u16 {
        self.http_port(0)
    }

    /// HTTP RPC url for validator index `i`.
    #[allow(dead_code)] // convenience for future flows
    pub fn rpc_url(&self, i: usize) -> String {
        format!("http://localhost:{}", self.http_port(i))
    }

    /// reth p2p (TCP+UDP) port for validator index `i`.
    pub fn p2p_port(&self, i: usize) -> u16 {
        self.ports.port(Service::P2p, i)
    }

    /// discv5 discovery port for validator index `i`.
    pub fn discv5_port(&self, i: usize) -> u16 {
        self.ports.port(Service::Discv5, i)
    }

    /// Engine auth-RPC port for validator index `i`.
    pub fn authrpc_port(&self, i: usize) -> u16 {
        self.ports.port(Service::Authrpc, i)
    }

    /// Prometheus metrics port for validator index `i`.
    pub fn metrics_port(&self, i: usize) -> u16 {
        self.ports.port(Service::Metrics, i)
    }

    /// Consensus listen port for validator index `i`.
    pub fn consensus_port(&self, i: usize) -> u16 {
        self.ports.port(Service::Consensus, i)
    }

    /// TEE enclave socket port for validator index `i`.
    pub fn tee_port(&self, i: usize) -> u16 {
        self.ports.port(Service::Tee, i)
    }

    /// Enclave container name for validator index `i`. Tagged by the data-dir run
    /// tag (not a port offset) so the teardown sweep can reconstruct it.
    pub fn tee_container(&self, i: usize) -> String {
        format!("outbe-tee-gramine-{}-{}", self.run_tag, i)
    }

    /// Per-validator data dir: `<dir>/validator-<i>`.
    pub fn validator_dir(&self, i: usize) -> PathBuf {
        self.dir.join(format!("validator-{i}"))
    }
}

/// A stable, docker-name-safe slug derived from the data dir, used to scope this
/// run's enclave containers so parallel localnets on other `--data-dir`s don't
/// collide and teardown can match by name without knowing the resolved ports.
fn dir_tag(dir: &Path) -> String {
    let mut tag = String::new();
    let mut prev_dash = false;
    for c in dir.display().to_string().chars() {
        if c.is_ascii_alphanumeric() {
            tag.push(c.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            tag.push('-');
            prev_dash = true;
        }
    }
    let tag = tag.trim_matches('-').to_string();
    if tag.is_empty() {
        "localnet".to_string()
    } else {
        tag
    }
}

fn path_with_foundry() -> String {
    let base = std::env::var("PATH").unwrap_or_default();
    match std::env::var("HOME") {
        Ok(home) if !home.is_empty() => format!("{base}:{home}/.foundry/bin"),
        _ => base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_tag_is_docker_safe() {
        assert_eq!(dir_tag(Path::new("/tmp/outbe-e2e-harness")), "tmp-outbe-e2e-harness");
        assert_eq!(dir_tag(Path::new("/tmp/Foo_Bar/x")), "tmp-foo-bar-x");
        assert_eq!(dir_tag(Path::new("/")), "localnet");
    }

    /// The accessors the joiner (`index == validators`) and the followers (slots
    /// 14/15) reach for. These used to index a length-`validators` vec and panic.
    /// Blocks follow allocation order, so the joiner takes the one after the
    /// committee's and each follower the one after that.
    #[test]
    fn accessors_serve_nodes_past_the_committee() {
        let env = Environment::default(); // 4 validators, no port scan
        let cfg = Config::resolve(&env);
        let joiner = cfg.validators;

        assert_eq!(cfg.primary_port(), 8545);
        assert_eq!(cfg.tee_port(joiner), 8574);
        assert_eq!(cfg.http_port(14), 8580);
        assert_eq!(cfg.consensus_port(15), 8593);

        // The committee size never moves, however many nodes are added.
        assert_eq!(cfg.validators, env.validators);
    }
}
