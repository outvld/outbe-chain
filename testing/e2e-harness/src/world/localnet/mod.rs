//! Localnet: the whole network in one handle - bootstrap plus every owned node
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
//! - [`bootstrap`] - genesis/key generation glue (`dkg bootstrap` + `seed_genesis.py`).
//! - [`committee`] - the bootstrapped validator set (start/stop/restart/kill).
//! - [`joiner`] - a validator that joins a running localnet (index = committee size).
//! - [`follower`] - full-execution follower nodes (`--upstream`).
//! - [`log_audit`] - runtime-log normalization, policy, and evidence.
//! - [`probes`] - datadir, compressed-entity, and timing observations.

mod bootstrap;
mod committee;
mod follower;
mod joiner;
mod log_audit;
mod probes;
mod radicle;

pub use bootstrap::BootstrapProfile;
pub(crate) use log_audit::LogAudit;
pub use probes::{CeStartupReplayObservationV1, OcompRuntimeTraceMarkerV1};
#[cfg(feature = "ocomp-integration")]
pub(crate) use radicle::RadicleRepositoryFixtureV1;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use eyre::{bail, Result, WrapErr};

use crate::internal::config::Config;
use crate::internal::launch_log::LaunchLog;
use crate::internal::proc::{
    self, args, redact_args_for_log, ChildGuard, DockerImageId, EnclaveGuard,
};
use crate::internal::shell::Sh;
use crate::world::state::DkgExpiryExpectedExit;

/// Per-node execution cache for validators co-located by the devnet harness.
/// The upstream 4 GiB default is a single-node deployment default; applying it
/// to every local validator would consume the process budget before OCOMP begins.
const CO_LOCATED_DEVNET_CROSS_BLOCK_CACHE_MIB: u64 = 512;

/// Test-provided knobs for a localnet start. The **enclave mode** is NOT here -
/// it's an environment decision read from [`Config::tee_mode`]. Only per-scenario
/// parameters live on this struct.
#[derive(Debug, Clone, Default)]
pub struct StartOpts {
    /// Shorten the governance voting window to N blocks (test hook,
    /// `OUTBE_TEST_VOTING_WINDOW_BLOCKS`).
    pub voting_window: Option<u64>,
    /// Signed wall-clock offset used only by debug-node day-boundary E2E.
    pub unix_time_offset_secs: Option<i64>,
    /// The scenario already shifted `genesis.json` before deriving another
    /// immutable manifest binding from it. Nodes still receive the clock
    /// offset, but the common start path must not shift genesis a second time.
    pub genesis_timestamp_pre_shifted: bool,
    /// Short-lived pool policy used only by the dedicated eviction scenario.
    pub is_txpool_eviction_profile: bool,
}

impl StartOpts {
    /// A start with a shortened voting window.
    pub fn with_voting_window(window: u64) -> Self {
        Self {
            voting_window: Some(window),
            unix_time_offset_secs: None,
            genesis_timestamp_pre_shifted: false,
            is_txpool_eviction_profile: false,
        }
    }

    pub fn with_txpool_eviction_profile(window: u64) -> Self {
        Self {
            voting_window: Some(window),
            is_txpool_eviction_profile: true,
            ..Self::default()
        }
    }

    pub fn near_next_utc_day(window: u64, now_secs: u64) -> Self {
        const BOUNDARY_LEAD_SECS: u64 = 120;
        Self::near_next_utc_day_with_lead(window, now_secs, BOUNDARY_LEAD_SECS)
    }

    /// Position the debug-node clock an exact number of seconds before the next
    /// UTC day boundary. Capacity scenarios need a wider lead than the ordinary
    /// one-item lifecycle because every input must first be finalized through
    /// the public transaction path.
    pub fn near_next_utc_day_with_lead(
        window: u64,
        now_secs: u64,
        boundary_lead_secs: u64,
    ) -> Self {
        const SECONDS_PER_DAY: u64 = 86_400;
        let next_day = now_secs - (now_secs % SECONDS_PER_DAY) + SECONDS_PER_DAY;
        let target = next_day.saturating_sub(boundary_lead_secs);
        Self {
            voting_window: Some(window),
            unix_time_offset_secs: Some(target as i64 - now_secs as i64),
            genesis_timestamp_pre_shifted: false,
            is_txpool_eviction_profile: false,
        }
    }
}

#[derive(Debug)]
pub struct Localnet {
    cfg: Config,
    /// Owned validator-indexed nodes - the committee (`0..n`) and, when attached,
    /// the joiner (index = committee size).
    validators: HashMap<usize, ChildGuard>,
    /// Only the latest common-spawn incarnation for each node index. Callers
    /// supply an independently checked owned PID before using its log evidence.
    node_launch_logs: HashMap<usize, (u32, LaunchLog)>,
    /// Operator-owned validator-indexed Radicle sidecars.
    radicle_sidecars: HashMap<usize, ChildGuard>,
    /// Independent non-validator source node used only by the Radicle E2E.
    user_radicle: Option<ChildGuard>,
    /// Owned follower nodes, keyed by name (`follower`, `follower2`).
    followers: HashMap<String, ChildGuard>,
    follower_startup_probes: HashMap<
        String,
        (
            usize,
            crate::internal::startup_rejection::StartupRejectionProbe,
        ),
    >,
    /// Owned validator-indexed enclave containers (committee + joiner).
    enclaves: HashMap<usize, EnclaveGuard>,
    /// Exact Gramine image used by every enclave in this scenario.
    enclave_image_id: Option<DockerImageId>,
    /// Scenario-only chain-manifest overrides used to prove that a validator
    /// with a different immutable fork install cannot join the canonical
    /// consensus namespace. All ordinary validators use `genesis.json`.
    validator_chain_manifests: HashMap<usize, PathBuf>,
    /// Exact last-launched argv for each validator. Recovery derives its
    /// authority-free follower argv from this snapshot and later restores it.
    validator_argv: HashMap<usize, Vec<String>>,
    /// Validator argv retained across one or more interrupted recovery-follower
    /// runs until the original validator role is relaunched.
    validator_recovery_original_argv: HashMap<usize, Vec<String>>,
    /// The options the last committee `start` ran with, replayed by `restart`.
    start_opts: StartOpts,
    scenario_deadline: Option<std::time::Instant>,
}

// Consensus-affecting test environment belongs to every node in this localnet,
// including keyless, cold and recovery followers. A missing override must also
// clear inherited values rather than depend on the harness shell environment.
fn configure_node_protocol_environment(opts: &StartOpts, command: &mut Command) {
    match opts.voting_window {
        Some(window) => {
            command.env("OUTBE_TEST_VOTING_WINDOW_BLOCKS", window.to_string());
        }
        None => {
            command.env_remove("OUTBE_TEST_VOTING_WINDOW_BLOCKS");
        }
    }
}

impl Localnet {
    pub(crate) fn new(cfg: Config) -> Self {
        Self {
            cfg,
            validators: HashMap::new(),
            node_launch_logs: HashMap::new(),
            radicle_sidecars: HashMap::new(),
            user_radicle: None,
            followers: HashMap::new(),
            follower_startup_probes: HashMap::new(),
            enclaves: HashMap::new(),
            enclave_image_id: None,
            validator_chain_manifests: HashMap::new(),
            validator_argv: HashMap::new(),
            validator_recovery_original_argv: HashMap::new(),
            start_opts: StartOpts::default(),
            scenario_deadline: None,
        }
    }

    pub(crate) fn set_scenario_deadline(&mut self, deadline: std::time::Instant) {
        self.scenario_deadline = Some(deadline);
    }

    fn enclave_startup_deadline(&self, nonhardware_seconds: u64) -> std::time::Instant {
        let now = std::time::Instant::now();
        let seconds = if self.cfg.tee_mode.passes_sgx_devices() {
            crate::env::CO_LOCATED_HARDWARE_SGX_TIMEOUT_SECS
        } else {
            nonhardware_seconds
        };
        let deadline = now + std::time::Duration::from_secs(seconds);
        // Leave the existing watchdog time for diagnostics and owned teardown.
        self.scenario_deadline.map_or(deadline, |outer| {
            deadline.min(
                outer
                    .checked_sub(std::time::Duration::from_secs(20))
                    .unwrap_or(now),
            )
        })
    }

    fn retain_enclave_image_id(&mut self, image_id: DockerImageId) -> Result<()> {
        match &self.enclave_image_id {
            Some(established) if established != &image_id => {
                bail!("Gramine Docker image identity changed during the scenario");
            }
            Some(_) => Ok(()),
            None => {
                self.enclave_image_id = Some(image_id);
                Ok(())
            }
        }
    }

    fn ensure_enclave_image_once_with<F>(&mut self, resolve: F) -> Result<()>
    where
        F: FnOnce() -> Result<DockerImageId>,
    {
        if self.enclave_image_id.is_some() {
            return Ok(());
        }
        self.retain_enclave_image_id(resolve()?)
    }

    fn ensure_enclave_image_once(&mut self) -> Result<()> {
        // The native profile runs no container, so it must not build, resolve or
        // retain an image identity: `enclave_image_id()` stays `None` and the
        // evidence records no Gramine image for a run that never used one.
        if self.cfg.tee_mode.runs_native_host_enclave() {
            return Ok(());
        }
        let repo = self.cfg.repo.clone();
        let sudo = self.cfg.sudo;
        let signing_key = self.cfg.dir.join("test-sgx-signing-key.pem");
        self.ensure_enclave_image_once_with(|| {
            proc::ensure_enclave_image(&repo, sudo, &signing_key, None)
        })
    }

    /// The execution profile every enclave in this scenario runs under.
    fn enclave_launch(&self) -> Result<proc::EnclaveLaunch> {
        if self.cfg.tee_mode.runs_native_host_enclave() {
            return Ok(proc::EnclaveLaunch::NativeHost);
        }
        Ok(proc::EnclaveLaunch::Gramine {
            image_id: self
                .enclave_image_id
                .clone()
                .ok_or_else(|| eyre::eyre!("Gramine Docker image identity was not resolved"))?,
        })
    }

    pub(crate) fn enclave_image_id(&self) -> Option<&str> {
        self.enclave_image_id.as_ref().map(DockerImageId::as_str)
    }

    fn sh(&self) -> Sh<'_> {
        Sh::new(&self.cfg)
    }

    fn dir(&self) -> String {
        self.cfg.dir.display().to_string()
    }

    /// Committee size (`--validators`). Not derivable from the port map: the
    /// joiner and followers own blocks past the committee's.
    pub(crate) fn committee_size(&self) -> usize {
        self.cfg.validators
    }

    /// Every reachable harness mode runs an enclave.
    pub fn tee_enabled(&self) -> bool {
        self.cfg.tee_mode.enabled()
    }

    /// Canonical ValidatorSet epoch length authored into this scenario's
    /// ChainSpec. Admission scheduling must derive its boundary window from
    /// this value rather than duplicating a devnet literal.
    pub fn epoch_length_blocks(&self) -> Result<u64> {
        let genesis: serde_json::Value =
            serde_json::from_slice(&fs::read(self.cfg.dir.join("genesis.json"))?)?;
        genesis
            .pointer("/config/epochLengthBlocks")
            .and_then(serde_json::Value::as_u64)
            .filter(|epoch| *epoch > 0)
            .ok_or_else(|| eyre::eyre!("genesis config has no positive epochLengthBlocks"))
    }

    /// Five-second RPC polls allowed for block-1 TEE bootstrap. Consecutive
    /// four-enclave real-SGX evidence exceeded the production-oriented node and
    /// per-request deadlines. A host with 187.5 MiB EPC needed more than ten
    /// minutes while all enclave calls still made progress, so keep the harness
    /// outside its thirty-minute co-located-EPC allowance and let it observe the
    /// node's verdict.
    pub fn tee_bootstrap_wait_attempts(&self) -> u32 {
        if self.cfg.tee_mode.passes_sgx_devices() {
            372
        } else {
            18
        }
    }

    /// OS pid of one owned committee validator. Used only for runtime process
    /// boundary evidence; callers cannot mutate the process through this API.
    pub fn validator_pid(&self, validator_index: usize) -> Result<u32> {
        self.validators
            .get(&validator_index)
            .map(ChildGuard::pid)
            .ok_or_else(|| eyre::eyre!("validator-{validator_index} is not running"))
    }

    /// Exact owned validator-role nodes, including admitted joiners, not FullNodes.
    pub(crate) fn owned_validator_indices(&self) -> Vec<usize> {
        let mut indices = self.validators.keys().copied().collect::<Vec<_>>();
        indices.sort_unstable();
        indices
    }

    /// Observe both owned children, propagating wait errors instead of treating
    /// an unobservable process as live.
    pub(crate) fn live_validator_and_enclave_pids(&mut self, index: usize) -> Result<(u32, u32)> {
        let node = self
            .validators
            .get_mut(&index)
            .ok_or_else(|| eyre::eyre!("validator-{index} has no owned node"))?;
        eyre::ensure!(
            node.exit_status()?.is_none(),
            "validator-{index} node exited"
        );
        let node_pid = node.pid();
        Ok((node_pid, self.live_enclave_pid(index)?))
    }

    /// The owned foreground enclave launcher must remain observable and live.
    pub(crate) fn live_enclave_pid(&mut self, index: usize) -> Result<u32> {
        let enclave = self
            .enclaves
            .get_mut(&index)
            .ok_or_else(|| eyre::eyre!("validator-{index} has no owned enclave"))?;
        eyre::ensure!(
            enclave.exit_status()?.is_none(),
            "validator-{index} enclave exited"
        );
        Ok(enclave.pid())
    }

    /// Co-located hardware enclaves have an E2E-only startup allowance. The
    /// node's production/testnet default remains unchanged and must be chosen
    /// for the deployment topology by its operator.
    fn extend_real_sgx_startup_timeout(&self, args: &mut Vec<String>) {
        if self.cfg.tee_mode.passes_sgx_devices() {
            args.extend(args![
                "--tee-bootstrap-timeout-secs",
                crate::env::CO_LOCATED_HARDWARE_SGX_TIMEOUT_SECS
            ]);
        }
    }

    /// The flags common to every node process (committee, joiner, follower):
    /// reth http/p2p/discovery/authrpc/ipc/log for port index `i`, rooted at
    /// `node_dir`. Callers `.extend(args![...])` with their role-specific tail.
    fn reth_base_args(&self, node_dir: &Path, i: usize) -> Vec<String> {
        let data = node_dir.join("data");
        let chain_manifest = self
            .validator_chain_manifests
            .get(&i)
            .cloned()
            .unwrap_or_else(|| self.cfg.dir.join("genesis.json"));
        let mut args = args![
            "node",
            "--chain",
            chain_manifest.display(),
            "--datadir",
            data.display(),
            "--http",
            "--http.addr",
            "0.0.0.0",
            "--http.port",
            self.cfg.http_port(i),
            // `txpool` is required by the pool-eviction scenarios: the pool's
            // real contents are only observable through `txpool_content` /
            // `txpool_status` (`eth_pendingTransactions` does not reflect them).
            "--http.api",
            "eth,net,web3,outbe,txpool",
            "--rpc.eth-proof-window",
            1868,
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
            crate::internal::config::node_ipc_path(node_dir).display(),
            "--engine.persistence-threshold",
            0,
            "--engine.cross-block-cache-size",
            CO_LOCATED_DEVNET_CROSS_BLOCK_CACHE_MIB,
            "--log.file.directory",
            node_dir.join("logs").display(),
            "--color",
            "never",
        ];
        if matches!(self.cfg.tee_mode, crate::env::TeeMode::SgxNoAttest) {
            args.extend(args!["--tee-session-mode", "production-node-host"]);
        }
        args
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
    /// Quiet by default - stdout/stderr are captured and only surfaced when the
    /// command fails; under `--debug` it streams live so the full DKG/seed
    /// progress (`balance: ... entries`, `Total storage entries: ...`, ...) is shown.
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
    /// [`attach_log`](crate::internal::proc::attach_log)) - we don't stream those
    /// live, since interleaving several running nodes would be unreadable.
    fn spawn_node(
        &mut self,
        label: &str,
        index: usize,
        node_dir: &Path,
        mut cmd: Command,
    ) -> Result<ChildGuard> {
        crate::internal::config::validate_node_ipc_path(node_dir)?;
        let node_args = cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        ensure_manual_tee_lease_node_args(&node_args)?;
        extend_real_sgx_process_environment(self.cfg.tee_mode, &mut cmd);
        configure_node_protocol_environment(&self.start_opts, &mut cmd);
        crate::world::projection::configure_node_command(&self.cfg, index, &mut cmd)?;
        if self.cfg.debug {
            let prog = cmd.get_program().to_string_lossy().into_owned();
            let rest: Vec<String> = cmd
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            let rest = redact_args_for_log(&rest);
            eprintln!("[localnet] launch {label}: {prog} {}", rest.join(" "));
            eprintln!("           log: {}", node_dir.join("node.log").display());
        }
        // A failed replacement must not leave the previous incarnation usable
        // as evidence for this launch attempt. Capture before any child writes.
        self.node_launch_logs.remove(&index);
        let launch_log = LaunchLog::arm(&node_dir.join("node.log"))
            .wrap_err_with(|| format!("capture node-{index} launch log before spawn"))?;
        let guard = ChildGuard::spawn(label, cmd)?;
        self.node_launch_logs
            .insert(index, (guard.pid(), launch_log));
        if self.cfg.debug {
            eprintln!("[localnet] {label} pid {}", guard.pid());
        }
        Ok(guard)
    }

    /// Read only this incarnation's output, including messages emitted before
    /// the caller began polling. This binds the launch, not liveness: callers
    /// must separately verify the expected PID is their current owned process.
    #[cfg(any(test, feature = "ocomp-integration"))]
    pub(crate) fn node_launch_log(&mut self, index: usize, expected_pid: u32) -> Result<String> {
        let (pid, log) = self
            .node_launch_logs
            .get_mut(&index)
            .ok_or_else(|| eyre::eyre!("node-{index} has no captured launch log"))?;
        eyre::ensure!(
            *pid == expected_pid,
            "node-{index} launch PID mismatch: expected {expected_pid}, captured {pid}"
        );
        log.read()
            .wrap_err_with(|| format!("read node-{index} launch log for PID {expected_pid}"))
    }

    // ---- teardown ------------------------------------------------------------

    fn clear_owned_nodes(&mut self) {
        self.validators.clear();
        self.followers.clear();
        self.follower_startup_probes.clear();
        self.node_launch_logs.clear();
    }

    /// Drop the owned node handles (killing nodes + `docker rm -f`ing enclaves),
    /// then run a stateless backstop sweep. Its primary role is the SIGINT path,
    /// where the `World` is never dropped so the guards never fire (plus
    /// intra-run belt-and-suspenders between scenarios). It is scoped to this
    /// run's unique data subdir + enclave run tag, so it never touches another
    /// run's nodes/containers.
    fn shutdown(&mut self) -> Result<()> {
        self.shutdown_with_expected_exits(&[], &[])
    }

    fn stop_owned_nodes(
        &mut self,
        expected_failed_slots: &[usize],
        expected_dkg_expiry_exits: &[DkgExpiryExpectedExit],
    ) -> Result<()> {
        let mut failures = Vec::new();
        // Check every retained slot, including missing handles that the stop
        // loop cannot visit. A replacement launch cannot inherit this proof.
        for proof in expected_dkg_expiry_exits {
            let owned_pid = self.validators.get(&proof.slot).map(ChildGuard::pid);
            let launch_pid = self.node_launch_logs.get(&proof.slot).map(|(pid, _)| *pid);
            if proof.node_pid == 0
                || owned_pid != Some(proof.node_pid)
                || launch_pid != Some(proof.node_pid)
            {
                failures.push(format!(
                    "DKG expiry slot {} expected PID {}, owned {owned_pid:?}, launch {launch_pid:?}",
                    proof.slot, proof.node_pid
                ));
            }
        }
        for (slot, child) in self
            .validators
            .iter_mut()
            .map(|(slot, child)| (Some(*slot), child))
            .chain(self.followers.values_mut().map(|child| (None, child)))
        {
            let pid = child.pid();
            let expiry = expected_dkg_expiry_exits
                .iter()
                .find(|proof| Some(proof.slot) == slot);
            let expected = self.node_launch_logs.iter().any(|(slot, (owned_pid, _))| {
                *owned_pid == pid && expected_failed_slots.contains(slot)
            });
            let result = (|| -> Result<()> {
                let before = child.exit_status()?;
                let status = child.stop_and_reap()?;
                if let Some(proof) = expiry {
                    eyre::ensure!(
                        proof.node_pid == pid
                            && before.is_some_and(|status| status.code() == Some(1))
                            && status.code() == Some(1),
                        "DKG expiry slot {} PID {pid} did not retain its witnessed natural exit 1 before cleanup: before={before:?}, after={status}",
                        proof.slot
                    );
                    return Ok(());
                }
                // An intentional protocol rejection must have happened before
                // cleanup. The after-hook independently requires its exact
                // cause in both runtime log sinks; this is not a log waiver.
                eyre::ensure!(
                    status.success() || (expected && before.is_some() && status.code() == Some(1)),
                    "owned node PID {pid} exited with {status}"
                );
                Ok(())
            })();
            if let Err(error) = result {
                failures.push(format!("{error:#}"));
            }
        }
        self.clear_owned_nodes();
        eyre::ensure!(
            failures.is_empty(),
            "node teardown failed: {}",
            failures.join("; ")
        );
        Ok(())
    }

    fn shutdown_with_expected_exits(
        &mut self,
        expected_failed_slots: &[usize],
        expected_dkg_expiry_exits: &[DkgExpiryExpectedExit],
    ) -> Result<()> {
        // Stateless signal-path backstop for the harness-owned price feeder.
        // Its config argv is rooted under this run/scenario directory.
        let feeder = format!("outbe-feeder.*{}", self.dir());
        self.sh().sudo_best_effort("pkill", &["-9", "-f", &feeder]);
        // Nodes first (release MDBX locks), then their enclaves - matching the
        // stop-nodes-then-teardown-enclaves ordering `run-testnet.sh` used.
        let node_result = self.stop_owned_nodes(expected_failed_slots, expected_dkg_expiry_exits);
        self.radicle_sidecars.clear();
        self.user_radicle = None;
        self.enclaves.clear();
        // No settle needed here: clearing the maps dropped every guard, which
        // synchronously `kill()`s + `wait()`s the owned nodes/enclaves, and the
        // sweep below is a fire-and-forget backstop.

        let nodes = format!("outbe-chain node.*{}", self.dir());
        self.sh().sudo_best_effort("pkill", &["-9", "-f", &nodes]);
        let radicle = format!("outbe-radicle.*{}", self.dir());
        self.sh().sudo_best_effort("pkill", &["-9", "-f", &radicle]);
        if self.cfg.tee_mode.runs_native_host_enclave() {
            // Native enclaves are processes, not containers. Their `--tee-dir`
            // argv carries this run's dir, so the pattern is run-scoped exactly
            // like the node sweep above.
            let enclaves = format!("outbe-tee-enclave.*{}", self.dir());
            self.sh()
                .sudo_best_effort("pkill", &["-9", "-f", &enclaves]);
        } else {
            let tee_sweep = format!(
                "docker ps -aq --filter name=outbe-tee-gramine-{}- | xargs -r docker rm -f",
                self.cfg.run_tag
            );
            self.sh().sudo_best_effort("bash", &["-c", &tee_sweep]);
        }
        let runtime_result = self.cleanup_radicle_runtime();
        node_result.and(runtime_result)
    }

    /// Remove `cfg.dir` (this localnet's scenario dir, or the whole run dir when
    /// built from the run-level [`Config`]). Already-gone is success.
    ///
    /// `validator-<i>/tee` is the enclave container's only writable mount
    /// (`proc::spawn_enclave`), so under `--sudo` it is the only thing this user
    /// can't unlink - drop those with `sudo rm` first. Everything else the
    /// harness created itself, and a failure to remove it is a real error.
    pub fn wipe(&self) -> Result<()> {
        self.cleanup_radicle_runtime()?;
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

    /// Post-run teardown: shut down all nodes + enclave containers, leaving the
    /// data dir (logs/chain state) intact for inspection. Invoked from the
    /// cucumber `after` hook (and the SIGINT handler).
    pub fn teardown(&mut self) -> Result<()> {
        self.shutdown()
    }

    /// Expected exit-1 slots still require the after-hook's exact fault audit;
    /// DKG expiry additionally requires its retained slot/PID halt evidence.
    pub(crate) fn teardown_with_expected_exits(
        &mut self,
        slots: &[usize],
        dkg_expiry_exits: &[DkgExpiryExpectedExit],
    ) -> Result<()> {
        self.shutdown_with_expected_exits(slots, dkg_expiry_exits)
    }

    /// Stop the localnet (alias for [`teardown`](Self::teardown)).
    pub fn stop(&mut self) -> Result<()> {
        self.shutdown()
    }
}

fn ensure_manual_tee_lease_node_args(args: &[String]) -> Result<()> {
    if let Some(option) = args.iter().find(|arg| {
        arg.as_str() == "--node-evm-key"
            || arg.starts_with("--node-evm-key=")
            || arg.starts_with("--tee-renewal.")
    }) {
        bail!("generated node command contains removed TEE renewal option {option}");
    }
    Ok(())
}

/// Co-located real enclaves share one physical EPC. A request can therefore
/// complete in the enclave after the production-oriented 30-second host timeout:
/// the enclave then observes a broken pipe even though it produced and sealed the
/// result. Widen only the hardware E2E lane; production/testnet retain their
/// explicit operator-selected/default deadline.
fn extend_real_sgx_process_environment(mode: crate::env::TeeMode, cmd: &mut Command) {
    if mode.passes_sgx_devices() {
        cmd.env(
            "OUTBE_TEE_IO_TIMEOUT_SECS",
            crate::env::CO_LOCATED_HARDWARE_SGX_TIMEOUT_SECS.to_string(),
        );
    }
}

/// The sealed-state dirs under `root` - the only paths the (root) enclave
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
pub(crate) fn ymd_utc(secs: u64) -> String {
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
    use crate::env::Environment;
    use std::ffi::OsStr;

    #[test]
    fn node_ipc_preflight_rejects_dynamic_node_before_spawning() {
        let env = Environment::default();
        let mut localnet = Localnet::new(Config::resolve(&env));
        let node_dir = PathBuf::from("/tmp").join("long-node-directory-".repeat(10));
        let error = localnet
            .spawn_node(
                "unstarted-follower",
                15,
                &node_dir,
                Command::new("/nonexistent/e2e-node"),
            )
            .expect_err("invalid IPC path must precede executable lookup");
        assert!(error.to_string().contains("invalid node IPC socket path"));
        assert!(error.to_string().contains(&node_dir.display().to_string()));
    }

    fn launch_log_fixture(localnet: &mut Localnet, index: usize, marker: &str) -> u32 {
        use std::time::{Duration, Instant};

        let node_dir = localnet.cfg.validator_dir(index);
        fs::create_dir_all(&node_dir).unwrap();
        let mut command = Command::new("sh");
        command.args(["-c", "printf '%s\\n' \"$1\"", "node-log-fixture", marker]);
        proc::attach_log(&mut command, &node_dir).unwrap();
        let mut child = localnet
            .spawn_node("node-log-fixture", index, &node_dir, command)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(status) = child.exit_status().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "log fixture did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
        let pid = child.pid();
        localnet.validators.insert(index, child);
        pid
    }

    #[test]
    fn owned_node_cleanup_rejects_silent_failure_and_checks_expected_slot() {
        for (code, expected_slots, accepted) in [
            (0, vec![], true),
            (1, vec![], false),
            (1, vec![0], true),
            (1, vec![1], false),
            (2, vec![0], false),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let env = Environment {
                data_dir: dir.path().canonicalize().unwrap(),
                ..Environment::default()
            };
            let mut localnet = Localnet::new(Config::resolve(&env));
            let node_dir = localnet.cfg.validator_dir(0);
            fs::create_dir_all(&node_dir).unwrap();
            let mut command = Command::new("sh");
            command.args(["-c", &format!("exit {code}")]);
            proc::attach_log(&mut command, &node_dir).unwrap();
            let mut child = localnet
                .spawn_node("exit-fixture", 0, &node_dir, command)
                .unwrap();
            child.reap_fault(std::time::Duration::from_secs(2)).unwrap();
            localnet.validators.insert(0, child);
            assert_eq!(
                localnet.stop_owned_nodes(&expected_slots, &[]).is_ok(),
                accepted,
                "exit {code}, expected {expected_slots:?}"
            );
            assert!(localnet.validators.is_empty());
            assert!(localnet.node_launch_logs.is_empty());
        }
    }

    fn expiry_cleanup_fixture(script: &str, exited: bool) -> (tempfile::TempDir, Localnet, u32) {
        let dir = tempfile::tempdir().unwrap();
        let env = Environment {
            data_dir: dir.path().canonicalize().unwrap(),
            ..Environment::default()
        };
        let mut localnet = Localnet::new(Config::resolve(&env));
        let node_dir = localnet.cfg.validator_dir(0);
        fs::create_dir_all(&node_dir).unwrap();
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        proc::attach_log(&mut command, &node_dir).unwrap();
        // attach_log defaults stdin to null; this fixture must keep `read`
        // blocked until cleanup signals it instead of exiting on immediate EOF.
        command.stdin(std::process::Stdio::piped());
        let mut child = localnet
            .spawn_node("expiry-exit-fixture", 0, &node_dir, command)
            .unwrap();
        if exited {
            child.reap_fault(std::time::Duration::from_secs(2)).unwrap();
        } else {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !localnet
                .node_launch_log(0, child.pid())
                .unwrap()
                .contains("ready\n")
            {
                assert!(
                    std::time::Instant::now() < deadline,
                    "live fixture not ready"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(child.exit_status().unwrap().is_none());
        }
        let pid = child.pid();
        localnet.validators.insert(0, child);
        (dir, localnet, pid)
    }

    #[test]
    fn dkg_expiry_cleanup_requires_exact_owned_and_launch_pid() {
        for damage in [
            "none",
            "witness_pid",
            "zero_pid",
            "witness_slot",
            "launch_pid",
            "missing_launch",
            "missing_owner",
            "missing_proof",
        ] {
            let (_dir, mut localnet, pid) = expiry_cleanup_fixture("exit 1", true);
            let mut proofs = vec![DkgExpiryExpectedExit {
                slot: 0,
                node_pid: pid,
            }];
            match damage {
                "none" => {}
                "witness_pid" => proofs[0].node_pid += 1,
                "zero_pid" => proofs[0].node_pid = 0,
                "witness_slot" => proofs[0].slot = 1,
                "launch_pid" => localnet.node_launch_logs.get_mut(&0).unwrap().0 += 1,
                "missing_launch" => {
                    localnet.node_launch_logs.remove(&0);
                }
                "missing_owner" => {
                    localnet.validators.remove(&0);
                }
                "missing_proof" => proofs.clear(),
                _ => unreachable!(),
            }
            assert_eq!(
                localnet.stop_owned_nodes(&[], &proofs).is_ok(),
                damage == "none",
                "accepted damaged DKG expiry evidence: {damage}"
            );
            assert!(localnet.validators.is_empty());
            assert!(localnet.node_launch_logs.is_empty());
        }
    }

    #[test]
    fn dkg_expiry_cleanup_rejects_success_other_errors_signals_and_live_children() {
        for (script, exited, accepted) in [
            ("exit 1", true, true),
            ("exit 0", true, false),
            ("exit 2", true, false),
            ("kill -KILL $$", true, false),
            // Readiness is emitted after installing the trap. Cleanup itself
            // will produce exit 1, which must not count as a natural halt.
            (
                "trap 'exit 1' TERM; printf 'ready\\n'; read unused",
                false,
                false,
            ),
        ] {
            let (_dir, mut localnet, pid) = expiry_cleanup_fixture(script, exited);
            let proof = DkgExpiryExpectedExit {
                slot: 0,
                node_pid: pid,
            };
            // Even an existing slot allowance cannot bypass the exact proof.
            assert_eq!(
                localnet.stop_owned_nodes(&[0], &[proof]).is_ok(),
                accepted,
                "script {script}, exited before cleanup {exited}"
            );
            assert!(localnet.validators.is_empty());
        }
    }

    #[test]
    fn node_launch_log_excludes_prior_incarnation_and_rejects_stale_pid() {
        let dir = tempfile::tempdir().unwrap();
        let env = Environment {
            data_dir: dir.path().canonicalize().unwrap(),
            ..Environment::default()
        };
        let mut localnet = Localnet::new(Config::resolve(&env));
        let node_dir = localnet.cfg.validator_dir(0);
        fs::create_dir_all(&node_dir).unwrap();
        fs::write(node_dir.join("node.log"), "earlier matching marker\n").unwrap();
        let first = launch_log_fixture(&mut localnet, 0, "first launch");
        assert_eq!(
            localnet.node_launch_log(0, first).unwrap(),
            "first launch\n"
        );
        localnet.validators.remove(&0);
        let second = launch_log_fixture(&mut localnet, 0, "second launch");
        assert_eq!(
            localnet.node_launch_log(0, second).unwrap(),
            "second launch\n"
        );
        assert!(localnet.node_launch_log(0, first).is_err());
        assert!(localnet.node_launch_log(1, second).is_err());
    }

    #[test]
    fn node_launch_log_rejects_missing_replaced_and_truncated_log() {
        for damage in ["missing", "replaced", "truncated"] {
            let dir = tempfile::tempdir().unwrap();
            let env = Environment {
                data_dir: dir.path().canonicalize().unwrap(),
                ..Environment::default()
            };
            let mut localnet = Localnet::new(Config::resolve(&env));
            let pid = launch_log_fixture(&mut localnet, 0, "current matching marker");
            assert_eq!(
                localnet.node_launch_log(0, pid).unwrap(),
                "current matching marker\n"
            );
            let path = localnet.cfg.validator_dir(0).join("node.log");
            match damage {
                "missing" => fs::remove_file(&path).unwrap(),
                "replaced" => {
                    fs::rename(&path, path.with_extension("previous")).unwrap();
                    fs::write(&path, "current matching marker\n").unwrap();
                }
                "truncated" => fs::write(&path, "").unwrap(),
                _ => unreachable!(),
            }
            assert!(localnet.node_launch_log(0, pid).is_err(), "{damage}");
        }
    }

    #[test]
    fn node_launch_log_failed_spawn_discards_previous_capture() {
        let dir = tempfile::tempdir().unwrap();
        let env = Environment {
            data_dir: dir.path().canonicalize().unwrap(),
            ..Environment::default()
        };
        let mut localnet = Localnet::new(Config::resolve(&env));
        let pid = launch_log_fixture(&mut localnet, 0, "previous launch");
        localnet.validators.remove(&0);
        let node_dir = localnet.cfg.validator_dir(0);
        assert!(localnet
            .spawn_node(
                "missing-node",
                0,
                &node_dir,
                Command::new(dir.path().join("nonexistent-node"))
            )
            .is_err());
        assert!(localnet.node_launch_log(0, pid).is_err());
        assert!(localnet.node_launch_logs.is_empty());
    }

    #[test]
    fn node_launch_log_cleanup_drops_capture_but_retains_diagnostics() {
        let dir = tempfile::tempdir().unwrap();
        let env = Environment {
            data_dir: dir.path().canonicalize().unwrap(),
            ..Environment::default()
        };
        let mut localnet = Localnet::new(Config::resolve(&env));
        let pid = launch_log_fixture(&mut localnet, 0, "retained diagnostics");
        localnet.clear_owned_nodes();
        assert!(localnet.node_launch_logs.is_empty());
        assert!(localnet.validators.is_empty());
        assert!(localnet.node_launch_log(0, pid).is_err());
        assert_eq!(
            fs::read_to_string(localnet.cfg.validator_dir(0).join("node.log")).unwrap(),
            "retained diagnostics\n"
        );
    }

    #[test]
    fn node_ipc_preflight_rejects_bootstrap_before_files_or_subprocesses() {
        let directory = tempfile::tempdir().expect("test directory");
        let env = Environment {
            data_dir: directory.path().join("long-scenario-directory-".repeat(6)),
            seed: directory.path().join("nonexistent-seed.json"),
            chain_bin: directory.path().join("nonexistent-node"),
            ..Environment::default()
        };
        let localnet = Localnet::new(Config::resolve(&env));
        let error = localnet
            .bootstrap_with_profile(4, &BootstrapProfile::default())
            .expect_err("path validation must precede seed reads and bootstrap");
        assert!(error.to_string().contains("invalid node IPC socket path"));
        assert!(
            !env.data_dir.exists(),
            "failed preflight must not create scenario state"
        );
    }

    fn configured_timeout(mode: crate::env::TeeMode) -> Option<String> {
        let mut cmd = Command::new("outbe-chain");
        extend_real_sgx_process_environment(mode, &mut cmd);
        cmd.get_envs()
            .find(|(key, _)| *key == OsStr::new("OUTBE_TEE_IO_TIMEOUT_SECS"))
            .and_then(|(_, value)| value)
            .map(|value| value.to_string_lossy().into_owned())
    }

    #[test]
    fn co_located_hardware_lane_alone_widens_enclave_io_timeout() {
        use crate::env::TeeMode;

        let expected = Some(crate::env::CO_LOCATED_HARDWARE_SGX_TIMEOUT_SECS.to_string());
        assert_eq!(configured_timeout(TeeMode::Real), expected);
        assert_eq!(configured_timeout(TeeMode::SgxNoAttest), expected);
        assert_eq!(configured_timeout(TeeMode::Mock), None);
        assert_eq!(configured_timeout(TeeMode::GramineDirect), None);
    }

    #[test]
    fn enclave_startup_budget_is_profile_aware_and_never_extends_scenario() {
        use crate::env::TeeMode;
        use std::time::{Duration, Instant};
        for mode in [
            TeeMode::Real,
            TeeMode::SgxNoAttest,
            TeeMode::GramineDirect,
            TeeMode::Mock,
            TeeMode::MockNative,
        ] {
            let env = Environment {
                tee_mode: mode,
                ..Environment::default()
            };
            let mut localnet = Localnet::new(Config::resolve(&env));
            for seconds in [10, 20] {
                let before = Instant::now();
                let deadline = localnet.enclave_startup_deadline(seconds);
                let budget = if mode.passes_sgx_devices() {
                    crate::env::CO_LOCATED_HARDWARE_SGX_TIMEOUT_SECS
                } else {
                    seconds
                };
                assert!(deadline >= before + Duration::from_secs(budget));
                assert!(deadline <= Instant::now() + Duration::from_secs(budget));
            }
            let outer = Instant::now() + Duration::from_secs(21);
            localnet.set_scenario_deadline(outer);
            assert_eq!(
                localnet.enclave_startup_deadline(20),
                outer - Duration::from_secs(20)
            );
        }
    }

    #[test]
    fn sgx_no_attest_selects_production_node_host_session() {
        let env = Environment {
            tee_mode: crate::env::TeeMode::SgxNoAttest,
            ..Environment::default()
        };
        env.ports
            .start_scenario(env.validators)
            .expect("allocate deterministic scenario ports");
        let localnet = Localnet::new(Config::for_scenario(&env, 1));
        let args = localnet.reth_base_args(Path::new("/tmp/outbe-e2e-node"), 0);

        assert!(args
            .windows(2)
            .any(|pair| { pair[0] == "--tee-session-mode" && pair[1] == "production-node-host" }));
    }

    #[test]
    fn sgx_no_attest_uses_the_hardware_bootstrap_allowance() {
        let env = Environment {
            tee_mode: crate::env::TeeMode::SgxNoAttest,
            ..Environment::default()
        };
        env.ports
            .start_scenario(env.validators)
            .expect("allocate deterministic scenario ports");
        let localnet = Localnet::new(Config::for_scenario(&env, 1));

        assert_eq!(localnet.tee_bootstrap_wait_attempts(), 372);
        let mut args = Vec::new();
        localnet.extend_real_sgx_startup_timeout(&mut args);
        let bootstrap_timeout = args[1]
            .parse::<u64>()
            .expect("numeric hardware-SGX bootstrap timeout");
        let io_timeout = configured_timeout(crate::env::TeeMode::SgxNoAttest)
            .expect("hardware-SGX enclave I/O override")
            .parse::<u64>()
            .expect("numeric hardware-SGX enclave I/O timeout");
        assert_eq!(
            args,
            vec![
                "--tee-bootstrap-timeout-secs".to_owned(),
                crate::env::CO_LOCATED_HARDWARE_SGX_TIMEOUT_SECS.to_string()
            ],
            "the node deadline must stay inside the harness observation envelope"
        );
        assert!(
            io_timeout >= bootstrap_timeout,
            "an individual SGX request must not expire before the enclosing bootstrap budget"
        );
    }

    #[test]
    fn co_located_devnet_bounds_each_nodes_cross_block_cache() {
        let env = Environment::default();
        env.ports
            .start_scenario(env.validators)
            .expect("allocate deterministic scenario ports");
        let localnet = Localnet::new(Config::for_scenario(&env, 1));
        let args = localnet.reth_base_args(Path::new("/tmp/outbe-e2e-node"), 0);
        let cache_size = args
            .windows(2)
            .find(|pair| pair[0] == "--engine.cross-block-cache-size")
            .map(|pair| pair[1].as_str());

        assert_eq!(cache_size, Some("512"));
    }

    #[test]
    fn every_localnet_node_retains_the_ocomp_exact_state_proof_window() {
        let env = Environment::default();
        env.ports
            .start_scenario(env.validators)
            .expect("allocate deterministic scenario ports");
        let localnet = Localnet::new(Config::for_scenario(&env, 1));
        let args = localnet.reth_base_args(Path::new("/tmp/outbe-e2e-node"), 0);
        let proof_window = args
            .windows(2)
            .find(|pair| pair[0] == "--rpc.eth-proof-window")
            .map(|pair| pair[1].as_str());

        assert_eq!(proof_window, Some("1868"));
    }

    #[test]
    fn runtime_audit_stdout_is_free_of_ansi_formatting() {
        let env = Environment::default();
        env.ports
            .start_scenario(env.validators)
            .expect("allocate deterministic scenario ports");
        let localnet = Localnet::new(Config::for_scenario(&env, 1));
        let args = localnet.reth_base_args(Path::new("/tmp/outbe-e2e-node"), 0);

        assert!(args
            .windows(2)
            .any(|pair| pair[0] == "--color" && pair[1] == "never"));
    }

    #[test]
    fn generated_node_commands_reject_removed_tee_renewal_key_options() {
        let ordinary = vec!["node".to_owned(), "--validator".to_owned()];
        assert!(ensure_manual_tee_lease_node_args(&ordinary).is_ok());

        for removed in [
            "--node-evm-key",
            "--node-evm-key=/tmp/evm-key.hex",
            "--tee-renewal.relay-key",
            "--tee-renewal.rpc-url=http://127.0.0.1:8545",
            "--tee-renewal.poll-secs",
            "--tee-renewal.warning-blocks",
            "--tee-renewal.critical-blocks",
        ] {
            assert!(
                ensure_manual_tee_lease_node_args(&[removed.to_owned()]).is_err(),
                "removed option still accepted: {removed}"
            );
        }
    }

    /// Both layouts, and nothing else - in particular not `validator-*/data`.
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

    #[test]
    fn custom_day_boundary_lead_is_reflected_exactly_in_the_node_clock_offset() {
        const NOW: u64 = 1_700_000_000;
        const LEAD: u64 = 240;
        const SECONDS_PER_DAY: u64 = 86_400;

        let opts = StartOpts::near_next_utc_day_with_lead(6, NOW, LEAD);
        let next_day = NOW - (NOW % SECONDS_PER_DAY) + SECONDS_PER_DAY;

        assert_eq!(opts.voting_window, Some(6));
        assert_eq!(
            opts.unix_time_offset_secs,
            Some((next_day - LEAD) as i64 - NOW as i64)
        );
        assert!(!opts.genesis_timestamp_pre_shifted);
        assert!(!opts.is_txpool_eviction_profile);
    }

    #[test]
    fn shortened_txpool_policy_is_an_explicit_scenario_profile() {
        let ordinary = StartOpts::with_voting_window(6);
        let eviction = StartOpts::with_txpool_eviction_profile(6);

        assert!(!ordinary.is_txpool_eviction_profile);
        assert!(eviction.is_txpool_eviction_profile);
        assert_eq!(eviction.voting_window, Some(6));
        assert_eq!(eviction.unix_time_offset_secs, None);
    }
}
