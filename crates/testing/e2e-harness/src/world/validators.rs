//! Validator / operator handles: key material and identity for committee nodes.
//!
//! Replaces the `e2e_vkey`/`e2e_v0key` key readers and the address helpers in
//! `scripts/e2e/lib.sh:141-142` (and `95-101` for on-chain status, wired as the
//! lifecycle flows land). A validator is addressed by index (`validator-<i>`);
//! an `Operator` is just an active validator acting as proposer/voter.

use std::path::PathBuf;

use eyre::{eyre, Result, WrapErr};

use crate::internal::config::Config;

/// A committee validator, identified by its 0-based index and data dir.
#[derive(Debug, Clone)]
pub struct Validator {
    pub index: usize,
    key_path: PathBuf,
}

impl Validator {
    /// The EOA private key (`validator-<i>/evm-key.hex`), `0x`-prefixed — matches
    /// the shell `"0x$(tr -d '[:space:]' < evm-key.hex)"`.
    pub fn evm_key(&self) -> Result<String> {
        let raw = std::fs::read_to_string(&self.key_path)
            .wrap_err_with(|| format!("reading evm key {:?}", self.key_path))?;
        let hex: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
        Ok(if hex.starts_with("0x") {
            hex
        } else {
            format!("0x{hex}")
        })
    }
}

/// An operator role — a thin wrapper over the validator that proposes/casts.
#[derive(Debug, Clone)]
pub struct Operator(pub Validator);

impl Operator {
    pub fn evm_key(&self) -> Result<String> {
        self.0.evm_key()
    }
}

/// Accessor for the committee's validators/operators and its size.
#[derive(Debug, Clone)]
pub struct Validators {
    cfg: Config,
    /// Committee size the environment bootstraps (`--validators`).
    size: usize,
}

impl Validators {
    pub(crate) fn new(cfg: Config, size: usize) -> Self {
        Self { cfg, size }
    }

    /// Committee size the environment bootstraps.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Validator by 0-based index.
    pub fn get(&self, i: usize) -> Validator {
        Validator {
            index: i,
            key_path: self.cfg.validator_dir(i).join("evm-key.hex"),
        }
    }

    /// Validator by `"validator-<N>"` name (as used in the feature files).
    pub fn by_name(&self, name: &str) -> Result<Validator> {
        Ok(self.get(parse_index(name)?))
    }

    /// Operator by `"validator-<N>"` name.
    pub fn operator(&self, name: &str) -> Result<Operator> {
        Ok(Operator(self.by_name(name)?))
    }

    /// HTTP RPC port of the primary committee node (validator-0). Each peer's
    /// ports live in its own block — see [`crate::internal::ports`].
    pub fn primary_port(&self) -> u16 {
        self.cfg.primary_port()
    }

    /// HTTP RPC port of validator index `i` (committee or joiner).
    pub fn http_port(&self, i: usize) -> u16 {
        self.cfg.http_port(i)
    }

    /// The joiner's index (one past the committee, e.g. `validator-4` for N=4).
    pub fn joiner_index(&self) -> usize {
        self.size
    }

    /// The joiner validator handle (its key material lives at `validator-<N>/`).
    pub fn joiner(&self) -> Validator {
        self.get(self.size)
    }

    /// HTTP RPC ports of every committee node (validator-0..N-1).
    pub fn committee_ports(&self) -> Vec<u16> {
        (0..self.size).map(|i| self.cfg.http_port(i)).collect()
    }

    /// HTTP RPC ports of the non-primary committee nodes (validators 1..N-1).
    pub fn peer_ports(&self) -> Vec<u16> {
        (1..self.size).map(|i| self.cfg.http_port(i)).collect()
    }
}

fn parse_index(name: &str) -> Result<usize> {
    name.strip_prefix("validator-")
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| eyre!("expected 'validator-<N>', got '{name}'"))
}
