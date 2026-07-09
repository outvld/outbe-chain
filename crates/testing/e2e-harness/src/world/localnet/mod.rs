//! Localnet: the whole network in one handle — bootstrap plus every owned node
//! (committee validators, joiner, followers) and their enclaves.
//!
//! A localnet *is* its set of nodes, so adding/removing a validator, attaching a
//! joiner, or launching a follower are all node operations on this one handle
//! rather than a separate object. Every launched process is **owned** via the
//! guards in [`crate::internal::proc`] (nodes killed on drop, enclave containers
//! `docker rm -f`ed on drop); a dropped `World` tears everything down, with a
//! stateless datadir/run-tag sweep as the SIGINT backstop. The distinct
//! lifecycles live in submodules over this one struct:
//!
//! - [`bootstrap`] — genesis/key generation glue (`dkg bootstrap` + `seed_genesis.py`).
//! - [`committee`] — the bootstrapped validator set (start/stop/restart/kill).
//! - [`joiner`] — a validator that joins a running localnet (index = committee size).
//! - [`follower`] — full-execution follower nodes (`--upstream`).
//! - [`probes`] — datadir moves + node-log inspection.

mod bootstrap;
mod committee;
mod follower;
mod joiner;
mod probes;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eyre::{bail, Result, WrapErr};

use crate::internal::config::Config;
use crate::internal::proc::{args, ChildGuard, EnclaveGuard};
use crate::internal::shell::Sh;

/// Test-provided knobs for a localnet start. The **enclave mode** is NOT here —
/// it's an environment decision read from [`Config::tee_mode`]. Only per-scenario
/// parameters live on this struct.
#[derive(Debug, Clone, Default)]
pub struct StartOpts {
    /// Shorten the governance voting window to N blocks (test hook,
    /// `OUTBE_TEST_VOTING_WINDOW_BLOCKS`).
    pub voting_window: Option<u64>,
}

impl StartOpts {
    /// A start with a shortened voting window.
    pub fn with_voting_window(window: u64) -> Self {
        Self {
            voting_window: Some(window),
        }
    }
}

#[derive(Debug)]
pub struct Localnet {
    cfg: Config,
    /// Owned validator-indexed nodes — the committee (`0..n`) and, when attached,
    /// the joiner (index = committee size).
    validators: HashMap<usize, ChildGuard>,
    /// Owned follower nodes, keyed by name (`follower`, `follower2`).
    followers: HashMap<String, ChildGuard>,
    /// Owned validator-indexed enclave containers (committee + joiner).
    enclaves: HashMap<usize, EnclaveGuard>,
    /// The options the last committee `start` ran with, replayed by `restart`.
    start_opts: StartOpts,
}

impl Localnet {
    pub(crate) fn new(cfg: Config) -> Self {
        Self {
            cfg,
            validators: HashMap::new(),
            followers: HashMap::new(),
            enclaves: HashMap::new(),
            start_opts: StartOpts::default(),
        }
    }

    fn sh(&self) -> Sh<'_> {
        Sh::new(&self.cfg)
    }

    fn dir(&self) -> String {
        self.cfg.dir.display().to_string()
    }

    /// Absolute path of a file directly under the data dir.
    fn data_path(&self, name: &str) -> String {
        self.cfg.dir.join(name).display().to_string()
    }

    /// Committee size (`--validators`). Not derivable from the port map: the
    /// joiner and followers own blocks past the committee's.
    fn committee_size(&self) -> usize {
        self.cfg.validators
    }

    /// Whether the environment runs an enclave (mock or real) vs. tee-less.
    pub fn tee_enabled(&self) -> bool {
        self.cfg.tee_mode.enabled()
    }

    /// The flags common to every node process (committee, joiner, follower):
    /// reth http/p2p/discovery/authrpc/ipc/log for port index `i`, rooted at
    /// `node_dir`. Callers `.extend(args![…])` with their role-specific tail.
    fn reth_base_args(&self, node_dir: &Path, i: usize) -> Vec<String> {
        let data = node_dir.join("data");
        args![
            "node",
            "--chain",
            self.data_path("genesis.json"),
            "--datadir",
            data.display(),
            "--http",
            "--http.addr",
            "0.0.0.0",
            "--http.port",
            self.cfg.http_port(i),
            "--http.api",
            "eth,net,web3,outbe",
            "--port",
            self.cfg.p2p_port(i),
            "--discovery.port",
            self.cfg.p2p_port(i),
            "--discovery.v5.addr",
            "127.0.0.1",
            "--discovery.v5.port",
            self.cfg.discv5_port(i),
            "--authrpc.port",
            self.cfg.authrpc_port(i),
            "--ipcpath",
            data.join("reth.ipc").display(),
            "--log.file.directory",
            node_dir.join("logs").display(),
        ]
    }

    /// Comma-joined reth bootnodes from `reth-bootnodes.txt` (comments stripped).
    fn bootnodes(&self) -> Option<String> {
        let raw = fs::read_to_string(self.cfg.dir.join("reth-bootnodes.txt")).ok()?;
        let joined = raw
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect::<Vec<_>>()
            .join(",");
        (!joined.is_empty()).then_some(joined)
    }

    /// Run a one-shot setup subprocess (`dkg bootstrap`, `seed_genesis.py`).
    /// Quiet by default — stdout/stderr are captured and only surfaced when the
    /// command fails; under `--debug` it streams live so the full DKG/seed
    /// progress (`balance: … entries`, `Total storage entries: …`, …) is shown.
    fn run_setup(&self, cmd: &mut Command, label: &str) -> Result<()> {
        if self.cfg.debug {
            let status = cmd.status().wrap_err_with(|| format!("run {label}"))?;
            if !status.success() {
                bail!("{label} failed");
            }
        } else {
            let out = cmd.output().wrap_err_with(|| format!("run {label}"))?;
            if !out.status.success() {
                bail!("{label} failed: {}", String::from_utf8_lossy(&out.stderr));
            }
        }
        Ok(())
    }

    /// Spawn an owned node process, logging its launch **metadata** (command,
    /// PID, log path) under `--debug`. The node's own runtime stdout/stderr are
    /// already attached to `<node_dir>/node.log` by the caller (via
    /// [`attach_log`](crate::internal::proc::attach_log)) — we don't stream those
    /// live, since interleaving several running nodes would be unreadable.
    fn spawn_node(&self, label: &str, node_dir: &Path, cmd: Command) -> Result<ChildGuard> {
        if self.cfg.debug {
            let prog = cmd.get_program().to_string_lossy().into_owned();
            let rest: Vec<String> = cmd
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            eprintln!("[localnet] launch {label}: {prog} {}", rest.join(" "));
            eprintln!("           log: {}", node_dir.join("node.log").display());
        }
        let guard = ChildGuard::spawn(label, cmd)?;
        if self.cfg.debug {
            eprintln!("[localnet] {label} pid {}", guard.pid());
        }
        Ok(guard)
    }

    // ---- teardown ------------------------------------------------------------

    /// Drop the owned node handles (killing nodes + `docker rm -f`ing enclaves),
    /// then run a stateless backstop sweep. Its primary role is the SIGINT path,
    /// where the `World` is never dropped so the guards never fire (plus
    /// intra-run belt-and-suspenders between scenarios). It is scoped to this
    /// run's unique data subdir + enclave run tag, so it never touches another
    /// run's nodes/containers.
    fn shutdown(&mut self) {
        // Nodes first (release MDBX locks), then their enclaves — matching the
        // stop-nodes-then-teardown-enclaves ordering `run-testnet.sh` used.
        self.validators.clear();
        self.followers.clear();
        self.enclaves.clear();
        // No settle needed here: clearing the maps dropped every guard, which
        // synchronously `kill()`s + `wait()`s the owned nodes/enclaves, and the
        // sweep below is a fire-and-forget backstop.

        let nodes = format!("outbe-chain node.*{}", self.dir());
        self.sh().sudo_best_effort("pkill", &["-9", "-f", &nodes]);
        let tee_sweep = format!(
            "docker ps -aq --filter name=outbe-tee-gramine-{}- | xargs -r docker rm -f",
            self.cfg.run_tag
        );
        self.sh().sudo_best_effort("bash", &["-c", &tee_sweep]);
    }

    /// Remove `cfg.dir` (this localnet's scenario dir, or the whole run dir when
    /// built from the run-level [`Config`]). Already-gone is success.
    ///
    /// `validator-<i>/tee` is the enclave container's only writable mount
    /// (`proc::spawn_enclave`), so under `--sudo` it is the only thing this user
    /// can't unlink — drop those with `sudo rm` first. Everything else the
    /// harness created itself, and a failure to remove it is a real error.
    pub fn wipe(&self) -> Result<()> {
        if !self.cfg.dir.exists() {
            return Ok(());
        }
        if self.cfg.sudo {
            for tee in sealed_dirs(&self.cfg.dir) {
                self.sh()
                    .sudo_best_effort("rm", &["-rf", &tee.display().to_string()]);
            }
        }
        fs::remove_dir_all(&self.cfg.dir)
            .wrap_err_with(|| format!("wiping data dir {}", self.dir()))
    }

    /// Pre-run reset: shut everything down AND wipe the data dir so the next
    /// bootstrap starts from a clean slate.
    pub fn cleanup(&mut self) -> Result<()> {
        // Only a prior scenario on this run's (unique) subdir can leave state that
        // a same-port rebind must wait out (TIME_WAIT). On a run's first boot the
        // subdir doesn't exist yet, so there is nothing to settle for.
        let reclaiming = self.cfg.dir.exists();
        self.shutdown();
        self.wipe()?;
        if reclaiming {
            sleep(Duration::from_secs(1));
        }
        Ok(())
    }

    /// Post-run teardown: shut down all nodes + enclave containers, leaving the
    /// data dir (logs/chain state) intact for inspection. Invoked from the
    /// cucumber `after` hook (and the SIGINT handler).
    pub fn teardown(&mut self) {
        self.shutdown();
    }

    /// Stop the localnet (alias for [`teardown`](Self::teardown)).
    pub fn stop(&mut self) -> Result<()> {
        self.shutdown();
        Ok(())
    }
}

/// The sealed-state dirs under `root` — the only paths the (root) enclave
/// container writes. `root` is either a scenario dir (`validator-<i>/tee`) or a
/// run dir (`scenario-<n>/validator-<i>/tee`); both shapes are checked.
///
/// Deliberately not a recursive walk: `validator-<i>/data` holds the reth MDBX
/// store, and descending into it would cost far more than the two `read_dir`s
/// this needs.
fn sealed_dirs(root: &Path) -> Vec<PathBuf> {
    fn push_validator_tee(base: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(base) else {
            return;
        };
        for e in entries.flatten() {
            if e.file_name().to_string_lossy().starts_with("validator-") {
                let tee = e.path().join("tee");
                if tee.is_dir() {
                    out.push(tee);
                }
            }
        }
    }

    let mut out = Vec::new();
    push_validator_tee(root, &mut out);
    if let Ok(entries) = fs::read_dir(root) {
        for e in entries.flatten() {
            if e.file_name().to_string_lossy().starts_with("scenario-") {
                push_validator_tee(&e.path(), &mut out);
            }
        }
    }
    out
}

/// The chain's current worldwide-day key (`YYYYMMDD`), matching how
/// `bootstrap-testnet.sh` seeds genesis: `date_key(now + UTC_PLUS_14_OFFSET)`
/// (lib.sh:33-34). Pure-Rust civil-date conversion so no `date(1)` shell-out.
pub fn worldwide_day() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    ymd_utc(now + 50_400)
}

/// `YYYYMMDD` for a UTC epoch second (Howard Hinnant's `civil_from_days`).
fn ymd_utc(secs: u64) -> String {
    let z = (secs / 86_400) as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}{m:02}{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both layouts, and nothing else — in particular not `validator-*/data`.
    #[test]
    fn sealed_dirs_finds_only_enclave_mounts() {
        let root = std::env::temp_dir().join(format!("outbe-sealed-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        // run-dir shape
        fs::create_dir_all(root.join("scenario-1/validator-0/tee")).expect("mk");
        fs::create_dir_all(root.join("scenario-1/validator-0/data")).expect("mk");
        // scenario-dir shape (a Localnet wiping its own dir)
        fs::create_dir_all(root.join("validator-7/tee")).expect("mk");
        fs::create_dir_all(root.join("validator-7/logs")).expect("mk");

        let mut found = sealed_dirs(&root);
        found.sort();
        assert_eq!(
            found,
            vec![
                root.join("scenario-1/validator-0/tee"),
                root.join("validator-7/tee"),
            ]
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn worldwide_day_is_eight_digits() {
        assert_eq!(ymd_utc(0), "19700101");
        let wd = worldwide_day();
        assert_eq!(wd.len(), 8);
        assert!(wd.chars().all(|c| c.is_ascii_digit()));
    }
}
