//! Operator-owned Radicle sidecars for release LocalNet scenarios.

use std::fs::{self, OpenOptions};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use eyre::{bail, ensure, eyre, Result, WrapErr};
use outbe_radicle::endpoint::EndpointAddress;
use outbe_radicle::integration::query_sidecar;
use outbe_radicle::manager::{ControlSession, HeartwoodControl, NativeHeartwoodControl};
use radicle::cob::store::access::ReadOnly;
use radicle::node::policy::{Scope, SeedingPolicy};
use radicle::storage::ReadRepository as _;

use crate::internal::eth::block_on;
use crate::internal::proc::{args, ChildGuard};

use super::Localnet;

const VALIDATOR_SET_ALLOC_ADDRESS: &str = "000000000000000000000000000000000000ee00";
const VALIDATOR_SET_MAX_VALIDATORS_SLOT: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000001";
const PORTABLE_UNIX_SOCKET_PATH_LIMIT: usize = 104;
const NATIVE_CONTROL_DEADLINE: Duration = Duration::from_secs(5);
const RADICLE_READY_TIMEOUT: Duration = Duration::from_secs(10);
const RADICLE_READY_POLL: Duration = Duration::from_millis(100);
const RADICLE_SOURCE_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(180);
const HEARTWOOD_REVISION: &str = "b76a17801329291153585ed31db61ee3c658046e";

#[derive(Clone, Debug)]
pub struct RadicleRepositoryFixtureV1 {
    pub home: PathBuf,
    pub worktree: PathBuf,
    pub repo_id: String,
    pub repo_id_hex: String,
    pub issue_id: String,
    pub patch_id: String,
    pub pushed_commit: Option<String>,
}

/// Decode only the provisioned OpenSSH public file, without a CLI profile or
/// any fallback to the private key. Metadata errors and symlinks fail closed.
fn provisioned_radicle_node_id(home: &Path) -> Result<[u8; 32]> {
    let public = home.join("keys/radicle.pub");
    let metadata = fs::symlink_metadata(&public)
        .wrap_err_with(|| format!("inspect Radicle public identity {}", public.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "Radicle public identity must be a regular non-symlink file: {}",
        public.display()
    );
    radicle::crypto::ssh::Keystore::new(&home.join("keys"))
        .public_key()
        .wrap_err_with(|| format!("decode Radicle public identity {}", public.display()))?
        .map(radicle::crypto::PublicKey::into_inner)
        .ok_or_else(|| eyre!("Radicle public identity disappeared: {}", public.display()))
}

/// A TCP listener alone is not readiness. Retain ownership in the caller until
/// native identity/config, status TCP and the final child observation succeed.
/// Each blocking observation consumes the same deadline; no per-probe reset.
fn wait_radicle_ready(
    guard: &mut ChildGuard,
    expected_node_id: [u8; 32],
    control_socket: &Path,
    peer: SocketAddr,
    status: SocketAddr,
    log: &Path,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let pid = guard.pid();
    let result = (|| -> Result<()> {
        let mut last_error = "native control not yet observed".to_owned();
        loop {
            if let Some(exit) = guard.exit_status()? {
                bail!("owned Radicle child exited: {exit}; last observation: {last_error}");
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            ensure!(
                !remaining.is_zero(),
                "Radicle readiness deadline: {last_error}"
            );
            let native = block_on(query_sidecar(
                control_socket.to_path_buf(),
                remaining.min(NATIVE_CONTROL_DEADLINE),
            ));
            let ready = match native {
                Ok(info) => {
                    ensure!(
                        info.node_id == expected_node_id,
                        "native Radicle NodeId differs from the provisioned public identity"
                    );
                    let addresses = info
                        .addresses
                        .iter()
                        .map(native_address)
                        .collect::<Result<Vec<_>>>()?;
                    ensure!(
                        addresses == [peer.to_string()],
                        "native Radicle advertised addresses differ from the requested listen endpoint"
                    );
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        last_error =
                            "native observation exhausted the readiness deadline".to_owned();
                        false
                    } else {
                        match TcpStream::connect_timeout(&status, remaining.min(RADICLE_READY_POLL))
                        {
                            Ok(_) => true,
                            Err(error) => {
                                last_error = format!("status TCP observation failed: {error}");
                                false
                            }
                        }
                    }
                }
                Err(error) => {
                    last_error = format!("native control observation failed: {error}");
                    false
                }
            };
            if let Some(exit) = guard.exit_status()? {
                bail!("owned Radicle child exited during readiness: {exit}; last observation: {last_error}");
            }
            ensure!(
                Instant::now() < deadline,
                "Radicle readiness deadline: {last_error}"
            );
            if ready {
                return Ok(());
            }
            std::thread::sleep(
                RADICLE_READY_POLL.min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    })();
    result.wrap_err_with(|| {
        let exit = guard.exit_status();
        format!(
            "Radicle readiness failed: pid={pid}, node_id={}, peer={peer}, status={status}, control={}, log={}, exit={exit:?}",
            native_node_id(expected_node_id), control_socket.display(), log.display()
        )
    })
}

impl Localnet {
    pub(crate) fn radicle_control_socket(&self, index: usize) -> std::path::PathBuf {
        self.cfg.radicle_control_socket(index)
    }

    /// Start the operator-owned foreground sidecar before its validator node.
    pub(crate) fn start_radicle(&mut self, index: usize) -> Result<()> {
        self.start_radicle_at(index, self.cfg.radicle_port(index))
    }

    fn start_radicle_at(&mut self, index: usize, peer_port: u16) -> Result<()> {
        if let Some(guard) = self.radicle_sidecars.get_mut(&index) {
            if guard.exit_status()?.is_none() {
                return Ok(());
            }
        }
        self.radicle_sidecars.remove(&index);

        let validator_dir = self.cfg.validator_dir(index);
        let home = validator_dir.join("radicle");
        let key = home.join("keys/radicle");
        if !key.is_file() {
            bail!(
                "validator-{index} has no Radicle key at {}; bootstrap or install the identity first",
                key.display()
            );
        }
        let node_id = provisioned_radicle_node_id(&home)?;
        fs::create_dir_all(validator_dir.join("logs"))?;

        let script = self.cfg.repo.join("scripts/run-radicle.sh");
        let listen = format!("127.0.0.1:{peer_port}");
        let status = format!("127.0.0.1:{}", self.cfg.radicle_status_port(index));
        let advertise = listen.clone();
        let max_validators = materialized_max_validators(&self.cfg.dir.join("genesis.json"))?;
        let control_socket = self.radicle_control_socket(index);
        prepare_private_socket_parent(
            &self.cfg.radicle_runtime_root,
            &control_socket,
            &validator_dir,
        )?;
        let mut command = Command::new(&script);
        command
            .env("OUTBE_RADICLE_BINARY", &self.cfg.bin_radicle)
            .env("OUTBE_RADICLE_CONTROL_SOCKET", &control_socket)
            .args(args![
                home.display(),
                listen,
                status,
                max_validators,
                advertise,
            ]);
        let log_path = validator_dir.join("radicle.log");
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;
        command
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .stdin(Stdio::null());

        let label = format!("radicle-{index}");
        let mut guard = ChildGuard::spawn(&label, command)
            .wrap_err_with(|| format!("start {label} through {}", script.display()))?;
        wait_radicle_ready(
            &mut guard,
            node_id,
            &control_socket,
            ([127, 0, 0, 1], peer_port).into(),
            ([127, 0, 0, 1], self.cfg.radicle_status_port(index)).into(),
            &log_path,
            RADICLE_READY_TIMEOUT,
        )?;
        self.radicle_sidecars.insert(index, guard);
        Ok(())
    }

    /// Stop only the selected sidecar; consensus ownership remains with the node.
    pub fn stop_radicle(&mut self, index: usize) -> Result<()> {
        self.radicle_sidecars
            .remove(&index)
            .ok_or_else(|| eyre!("radicle-{index} is not running"))?;
        Ok(())
    }

    /// Restart one sidecar with the same key and persistent home.
    pub fn restart_radicle(&mut self, index: usize) -> Result<()> {
        self.radicle_sidecars.remove(&index);
        self.start_radicle(index)
    }

    /// Restart one sidecar on a new peer port without restarting outbe-chain.
    pub fn restart_radicle_at_port(&mut self, index: usize, peer_port: u16) -> Result<()> {
        self.radicle_sidecars.remove(&index);
        self.start_radicle_at(index, peer_port)
    }

    /// Use a disjoint harness port block for endpoint-replacement evidence.
    pub fn restart_radicle_on_alternate_port(&mut self, index: usize) -> Result<u16> {
        let peer_port = self.cfg.radicle_port(index + 64);
        self.restart_radicle_at_port(index, peer_port)?;
        Ok(peer_port)
    }

    pub fn radicle_pid(&self, index: usize) -> Result<u32> {
        self.radicle_sidecars
            .get(&index)
            .map(ChildGuard::pid)
            .ok_or_else(|| eyre!("radicle-{index} is not running"))
    }

    pub fn validator_radicle_addresses(&self, index: usize) -> Result<Vec<String>> {
        let socket = self.radicle_control_socket(index);
        let info = block_on(query_sidecar(socket, NATIVE_CONTROL_DEADLINE))
            .wrap_err_with(|| format!("query validator-{index} native Radicle identity/config"))?;
        info.addresses
            .iter()
            .map(|address| {
                Ok(format!(
                    "{}@{}",
                    native_node_id(info.node_id),
                    native_address(address)?
                ))
            })
            .collect()
    }

    /// Create a public source repository while its non-validator sidecar is offline.
    pub fn prepare_user_radicle_repository(&self) -> Result<RadicleRepositoryFixtureV1> {
        for (name, binary) in [
            ("rad", &self.cfg.bin_rad),
            ("git-remote-rad", &self.cfg.bin_git_remote_rad),
        ] {
            let mut command = Command::new(binary);
            command.arg("--version");
            verify_user_tool_version(name, &output(command, name)?)
                .wrap_err_with(|| format!("verify user Radicle tool {}", binary.display()))?;
        }
        let home = self.cfg.dir.join("user-radicle");
        if !home.exists() {
            let output = Command::new(&self.cfg.bin_keygen)
                .args(["radicle", "--output-dir"])
                .arg(&home)
                .output()
                .wrap_err("generate independent user Radicle key")?;
            if !output.status.success() {
                bail!(
                    "generate independent user Radicle key failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        for dir in ["storage", "node", "cobs"] {
            let path = home.join(dir);
            fs::create_dir_all(&path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        write_outbe_profile(
            &home,
            &format!(
                "127.0.0.1:{}",
                self.cfg.radicle_port(self.committee_size() + 32)
            ),
            materialized_max_validators(&self.cfg.dir.join("genesis.json"))?,
        )?;

        let worktree = self.cfg.dir.join("user-repository");
        fs::create_dir_all(&worktree)?;
        self.git(&worktree, &["init", "--initial-branch", "master"])?;
        self.git(&worktree, &["config", "user.name", "Outbe E2E"])?;
        self.git(
            &worktree,
            &["config", "user.email", "radicle-e2e@outbe.test"],
        )?;
        fs::write(worktree.join("README.md"), "# Outbe Radicle E2E\n")?;
        self.git(&worktree, &["add", "README.md"])?;
        self.git(&worktree, &["commit", "-m", "Initial source"])?;
        self.rad(
            &home,
            &self.cfg.user_radicle_control_socket(),
            Some(&worktree),
            &[
                "init",
                "--name",
                "outbe-radicle-e2e",
                "--description",
                "Outbe validator replication fixture",
                "--no-confirm",
                "--public",
                "--no-seed",
            ],
        )?;
        let mut initializer = self.spawn_user_radicle(&home)?;
        initializer.stop();
        self.rad(
            &home,
            &self.cfg.user_radicle_control_socket(),
            Some(&worktree),
            &["cob", "migrate"],
        )?;

        let remote = self.git(&worktree, &["config", "--get", "remote.rad.url"])?;
        let repo_id = remote
            .trim()
            .strip_prefix("rad://")
            .and_then(|remote| remote.split('/').next())
            .map(str::to_owned)
            .ok_or_else(|| eyre!("rad init installed an invalid remote URL: {remote}"))?;
        let repo_id_hex = hex::encode(decode_repo_id(&repo_id)?);
        let repo_id = format!("rad:{repo_id}");
        let issue = self.rad(
            &home,
            &self.cfg.user_radicle_control_socket(),
            Some(&worktree),
            &[
                "issue",
                "open",
                "--title",
                "Validator replication evidence",
                "--description",
                "Created before the source sidecar starts",
                "--no-announce",
            ],
        )?;
        let issue_id = first_hex40(&issue).ok_or_else(|| eyre!("rad issue returned no ID"))?;

        self.git(&worktree, &["checkout", "-b", "radicle-e2e-patch"])?;
        fs::write(
            worktree.join("PATCH-EVIDENCE.md"),
            "This change must replicate through validator storage.\n",
        )?;
        self.git(&worktree, &["add", "PATCH-EVIDENCE.md"])?;
        self.git(&worktree, &["commit", "-m", "Add replication evidence"])?;
        let patch = self.git_env(
            &home,
            &self.cfg.user_radicle_control_socket(),
            &worktree,
            &[
                "push",
                "-o",
                "patch.message=Outbe replication patch",
                "rad",
                "HEAD:refs/patches",
            ],
        )?;
        let patch_id = first_hex40(&patch).ok_or_else(|| eyre!("git push returned no patch ID"))?;

        Ok(RadicleRepositoryFixtureV1 {
            home,
            worktree,
            repo_id,
            repo_id_hex,
            issue_id,
            patch_id,
            pushed_commit: None,
        })
    }

    /// Start the independent source and explicitly connect it to every validator.
    pub fn start_user_radicle(&mut self, fixture: &RadicleRepositoryFixtureV1) -> Result<()> {
        require_public_source_repository(fixture)?;
        if let Some(guard) = self.user_radicle.as_mut() {
            if guard.exit_status()?.is_none() {
                return Ok(());
            }
        }
        self.user_radicle = None;
        // Retain local ownership until all setup succeeds. Validators' policies
        // remain manager-owned; only this independent source is explicitly seeded.
        let guard = self.spawn_user_radicle(&fixture.home)?;
        configure_user_radicle(
            self.cfg.user_radicle_control_socket(),
            decode_repo_id(&fixture.repo_id)?,
            (0..self.committee_size())
                .map(|index| self.radicle_control_socket(index))
                .collect(),
        )?;
        self.user_radicle = Some(guard);
        Ok(())
    }

    fn spawn_user_radicle(&self, home: &Path) -> Result<ChildGuard> {
        let node_id = provisioned_radicle_node_id(home)?;
        let slot = self.committee_size() + 32;
        let listen = format!("127.0.0.1:{}", self.cfg.radicle_port(slot));
        let status = format!("127.0.0.1:{}", self.cfg.radicle_status_port(slot));
        let script = self.cfg.repo.join("scripts/run-radicle.sh");
        let max_validators = materialized_max_validators(&self.cfg.dir.join("genesis.json"))?;
        let control_socket = self.cfg.user_radicle_control_socket();
        prepare_private_socket_parent(&self.cfg.radicle_runtime_root, &control_socket, home)?;
        let mut command = Command::new(&script);
        command
            .env("OUTBE_RADICLE_BINARY", &self.cfg.bin_radicle)
            .env("OUTBE_RADICLE_CONTROL_SOCKET", &control_socket)
            .args(args![
                home.display(),
                listen,
                status,
                max_validators,
                format!("127.0.0.1:{}", self.cfg.radicle_port(slot)),
            ]);
        let log_path = self.cfg.dir.join("user-radicle.log");
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;
        command
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .stdin(Stdio::null());
        let mut guard = ChildGuard::spawn("radicle-user", command)?;
        wait_radicle_ready(
            &mut guard,
            node_id,
            &control_socket,
            ([127, 0, 0, 1], self.cfg.radicle_port(slot)).into(),
            ([127, 0, 0, 1], self.cfg.radicle_status_port(slot)).into(),
            &log_path,
            RADICLE_READY_TIMEOUT,
        )?;
        Ok(guard)
    }

    /// Publish one ordinary Git update after the source node is online.
    pub fn push_user_radicle_update(&self, fixture: &mut RadicleRepositoryFixtureV1) -> Result<()> {
        fs::write(
            fixture.worktree.join("README.md"),
            "# Outbe Radicle E2E\n\nReplicated through the validator mesh.\n",
        )?;
        self.git(&fixture.worktree, &["add", "README.md"])?;
        self.git(
            &fixture.worktree,
            &["commit", "-m", "Publish validator mesh evidence"],
        )?;
        self.git_env(
            &fixture.home,
            &self.cfg.user_radicle_control_socket(),
            &fixture.worktree,
            &["push", "rad", "HEAD:refs/heads/master"],
        )?;
        fixture.pushed_commit = Some(
            self.git(&fixture.worktree, &["rev-parse", "HEAD"])?
                .trim()
                .to_owned(),
        );
        Ok(())
    }

    pub fn radicle_repo_visible(
        &self,
        validator: usize,
        fixture: &RadicleRepositoryFixtureV1,
    ) -> Result<bool> {
        let home = self.cfg.validator_dir(validator).join("radicle");
        repository_visible(&home, fixture)
            .wrap_err_with(|| format!("observe validator-{validator} replicated repository"))
    }

    pub fn radicle_node_status(&self, index: usize) -> Result<String> {
        let sessions = native_sessions(self.radicle_control_socket(index))?;
        let sessions = sessions
            .iter()
            .map(|session| {
                Ok(serde_json::json!({
                    "nodeId": native_node_id(session.node_id),
                    "address": native_address(&session.address)?,
                    "connected": session.connected,
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(serde_json::to_string(&sessions)?)
    }

    /// Exact connected native Heartwood peers from typed UDS control responses.
    pub fn radicle_connected_session_node_ids(&self, index: usize) -> Result<Vec<String>> {
        Ok(
            connected_sessions(native_sessions(self.radicle_control_socket(index))?)?
                .into_iter()
                .map(|(node_id, _)| node_id)
                .collect(),
        )
    }

    /// Connected native Heartwood address for one exact peer NodeId.
    pub fn radicle_connected_session_address(&self, index: usize, node_id: &str) -> Result<String> {
        connected_sessions(native_sessions(self.radicle_control_socket(index))?)?
            .into_iter()
            .find_map(|(observed, address)| (observed == node_id).then_some(address))
            .ok_or_else(|| eyre!("validator-{index} has no connected session for {node_id}"))
    }

    /// Native persistent policy proof that the manager applied Seed Scope::All.
    pub fn radicle_seed_scope_all(&self, index: usize, repo_id: &str) -> Result<bool> {
        let home = self.cfg.validator_dir(index).join("radicle");
        seed_scope_all(&home, repo_id)
            .wrap_err_with(|| format!("observe validator-{index} persistent seeding policy"))
    }

    fn rad(
        &self,
        home: &Path,
        control_socket: &Path,
        cwd: Option<&Path>,
        args: &[&str],
    ) -> Result<String> {
        let mut command = Command::new(&self.cfg.bin_rad);
        command
            .env("RAD_HOME", home)
            .env("RAD_SOCKET", control_socket)
            .env("PATH", self.radicle_path())
            .args(args);
        if let Some(cwd) = cwd {
            command.current_dir(cwd);
        }
        output(command, "rad")
    }

    fn git(&self, cwd: &Path, args: &[&str]) -> Result<String> {
        let mut command = Command::new("git");
        command.current_dir(cwd).args(args);
        output(command, "git")
    }

    fn git_env(
        &self,
        home: &Path,
        control_socket: &Path,
        cwd: &Path,
        args: &[&str],
    ) -> Result<String> {
        let mut command = Command::new("git");
        command
            .current_dir(cwd)
            .env("RAD_HOME", home)
            .env("RAD_SOCKET", control_socket)
            .env("PATH", self.radicle_path())
            .args(args);
        output(command, "git")
    }

    fn radicle_path(&self) -> std::ffi::OsString {
        let helper_dir = self
            .cfg
            .bin_git_remote_rad
            .parent()
            .unwrap_or_else(|| Path::new("."));
        let mut paths = vec![helper_dir.to_path_buf()];
        paths.extend(std::env::split_paths(&self.cfg.path));
        std::env::join_paths(paths).unwrap_or_else(|_| self.cfg.path.clone().into())
    }

    pub(crate) fn cleanup_radicle_runtime(&self) -> Result<()> {
        let target = if self.cfg.scenario == 0 {
            self.cfg.radicle_runtime_root.clone()
        } else {
            self.cfg.radicle_scenario_runtime_dir()
        };
        if !target.starts_with(&self.cfg.radicle_runtime_root) {
            bail!("refusing to clean Radicle runtime path outside its run root");
        }
        let metadata = match fs::symlink_metadata(&target) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).wrap_err("inspect Radicle runtime directory"),
        };
        let expected_uid = fs::symlink_metadata(&self.cfg.dir)
            .wrap_err_with(|| format!("inspect localnet directory {}", self.cfg.dir.display()))?
            .uid();
        validate_private_owned_dir(&target, &metadata, expected_uid)?;
        fs::remove_dir_all(&target)
            .wrap_err_with(|| format!("remove Radicle runtime directory {}", target.display()))
    }
}

fn prepare_private_socket_parent(
    runtime_root: &Path,
    socket: &Path,
    owner_anchor: &Path,
) -> Result<()> {
    if socket.as_os_str().as_bytes().len() >= PORTABLE_UNIX_SOCKET_PATH_LIMIT {
        bail!(
            "Radicle control socket path must be shorter than {PORTABLE_UNIX_SOCKET_PATH_LIMIT} bytes: {}",
            socket.display()
        );
    }
    let parent = socket
        .parent()
        .ok_or_else(|| eyre!("Radicle control socket has no parent"))?;
    if !parent.starts_with(runtime_root) {
        bail!("Radicle control socket escaped its run-scoped runtime root");
    }
    let expected_uid = fs::symlink_metadata(owner_anchor)
        .wrap_err_with(|| format!("inspect Radicle owner anchor {}", owner_anchor.display()))?
        .uid();
    ensure_private_owned_dir(runtime_root, expected_uid)?;
    ensure_private_owned_dir(parent, expected_uid)
}

fn ensure_private_owned_dir(path: &Path, expected_uid: u32) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error)
                .wrap_err_with(|| format!("create Radicle runtime directory {}", path.display()));
        }
    }
    let metadata = fs::symlink_metadata(path)
        .wrap_err_with(|| format!("inspect Radicle runtime directory {}", path.display()))?;
    validate_private_owned_dir(path, &metadata, expected_uid)
}

fn validate_private_owned_dir(
    path: &Path,
    metadata: &fs::Metadata,
    expected_uid: u32,
) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "Radicle runtime path must be a non-symlink directory: {}",
            path.display()
        );
    }
    let mode = metadata.mode() & 0o777;
    if metadata.uid() != expected_uid || mode != 0o700 {
        bail!(
            "Radicle runtime directory {} must be owned by uid {expected_uid} with mode 700 (found uid {}, mode {mode:o})",
            path.display(),
            metadata.uid()
        );
    }
    Ok(())
}

fn output(mut command: Command, label: &str) -> Result<String> {
    let result = command.output().wrap_err_with(|| format!("run {label}"))?;
    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);
    if !result.status.success() {
        bail!("{label} failed: {stderr}{stdout}");
    }
    Ok(format!("{stdout}{stderr}"))
}

fn first_hex40(value: &str) -> Option<String> {
    value
        .split(|character: char| !character.is_ascii_hexdigit())
        .find(|token| token.len() == 40)
        .map(str::to_owned)
}

fn decode_repo_id(value: &str) -> Result<[u8; 20]> {
    let canonical = value.strip_prefix("rad:").unwrap_or(value);
    let (base, bytes) = multibase::decode(canonical).wrap_err("decode canonical Radicle RepoId")?;
    if base != multibase::Base::Base58Btc {
        bail!("Radicle RepoId must use base58btc multibase encoding");
    }
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| eyre!("Radicle RepoId must be 20 bytes, got {}", bytes.len()))
}

fn native_node_id(node_id: [u8; 32]) -> String {
    let mut bytes = [0; 34];
    bytes[..2].copy_from_slice(&[0xed, 0x01]);
    bytes[2..].copy_from_slice(&node_id);
    multibase::encode(multibase::Base::Base58Btc, bytes)
}

fn verify_user_tool_version(name: &str, version: &str) -> Result<()> {
    let version = version.trim();
    let commit = version
        .strip_prefix(&format!("{name} "))
        .and_then(|value| value.rsplit_once(" ("))
        .and_then(|(_, commit)| commit.strip_suffix(')'))
        .filter(|commit| commit.len() >= 7 && commit.bytes().all(|byte| byte.is_ascii_hexdigit()));
    if !commit.is_some_and(|commit| HEARTWOOD_REVISION.starts_with(commit)) {
        bail!("{name} must come from pinned Outbe Heartwood {HEARTWOOD_REVISION}; observed {version:?}");
    }
    Ok(())
}

fn native_address(address: &EndpointAddress) -> Result<String> {
    let encoded = address.encode();
    match encoded.as_slice() {
        [0, a, b, c, d, ..] => Ok(format!("{a}.{b}.{c}.{d}:{}", address.port())),
        [1, octets @ .., _, _] if octets.len() == 16 => {
            let octets: [u8; 16] = octets
                .try_into()
                .map_err(|_| eyre!("invalid IPv6 endpoint"))?;
            Ok(format!(
                "[{}]:{}",
                std::net::Ipv6Addr::from(octets),
                address.port()
            ))
        }
        _ => address
            .host()
            .map(|host| format!("{host}:{}", address.port()))
            .ok_or_else(|| eyre!("invalid native Radicle endpoint")),
    }
}

fn native_sessions(socket: PathBuf) -> Result<Vec<ControlSession>> {
    block_on(async move {
        NativeHeartwoodControl::new(socket, NATIVE_CONTROL_DEADLINE)
            .sessions()
            .await
    })
    .wrap_err("query native Radicle sessions")
}

fn configure_user_radicle(socket: PathBuf, repo: [u8; 20], peers: Vec<PathBuf>) -> Result<()> {
    ensure!(!peers.is_empty(), "source setup requires validator peers");
    let control_socket = socket.clone();
    let expected = block_on(async move {
        let control = NativeHeartwoodControl::new(control_socket, NATIVE_CONTROL_DEADLINE);
        control
            .seed(repo.into())
            .await
            .wrap_err("seed independent user repository through native control")?;
        let mut expected = Vec::with_capacity(peers.len());
        for (index, socket) in peers.into_iter().enumerate() {
            let info = query_sidecar(socket, NATIVE_CONTROL_DEADLINE)
                .await
                .wrap_err_with(|| format!("query validator-{index} before user connection"))?;
            ensure!(
                !expected.contains(&info.node_id),
                "duplicate validator identity in source discovery cohort"
            );
            control
                .connect(info.node_id, &info.addresses)
                .await
                .wrap_err_with(|| {
                    format!("connect user to validator-{index} through native control")
                })?;
            expected.push(info.node_id);
        }
        Ok::<_, eyre::Report>(expected)
    })?;
    let rid = format!(
        "rad:{}",
        multibase::encode(multibase::Base::Base58Btc, repo)
    )
    .parse::<radicle::identity::RepoId>()
    .wrap_err("parse source inventory RepoId")?;
    // Native Seed changes policy, but unlike `rad seed` does not publish a
    // locally held public repository. An unchanged inventory is idempotent,
    // not a failure: the caller already verified the local public identity.
    let publication = source_control_response::<InventoryPublication>(
        &socket,
        radicle::node::Command::AddInventory { rid },
        Instant::now() + NATIVE_CONTROL_DEADLINE,
    )
    .wrap_err("publish independent source inventory")?;
    eprintln!(
        "[e2e] independent source inventory published rid={rid} updated={}",
        publication.updated
    );
    wait_for_source_seeds(&socket, rid, &expected, RADICLE_SOURCE_DISCOVERY_TIMEOUT)
}

/// Keep the pinned native protocol, but bound the entire exchange rather than
/// the SDK's individual reads. Cancellation drops the socket; no blocking I/O
/// or detached task survives a timed-out control operation.
fn source_control_response<T: serde::de::DeserializeOwned + Send + 'static>(
    socket: &Path,
    command: radicle::node::Command,
    deadline: Instant,
) -> Result<T> {
    let socket = socket.to_path_buf();
    block_on(async move {
        use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
        ensure!(
            Instant::now() < deadline,
            "source control deadline exceeded"
        );
        let response = tokio::time::timeout_at(deadline.into(), async {
            let mut stream = tokio::net::UnixStream::connect(&socket)
                .await
                .wrap_err("connect source control socket")?;
            let mut request = Vec::new();
            command.to_writer(&mut request)?;
            stream
                .write_all(&request)
                .await
                .wrap_err("write source control command")?;
            let mut response = Vec::new();
            BufReader::new(stream)
                .read_until(b'\n', &mut response)
                .await
                .wrap_err("read source control response")?;
            ensure!(
                response.last() == Some(&b'\n'),
                "source control response incomplete"
            );
            Ok::<_, eyre::Report>(response)
        })
        .await
        .wrap_err("source control deadline exceeded")??;
        let decoded = serde_json::from_slice::<radicle::node::CommandResult<T>>(&response)
            .wrap_err("decode native source control response")?;
        // Tokio may poll a ready operation before an already elapsed timer.
        // Completion (including decoding) must still meet the original deadline.
        ensure!(
            Instant::now() < deadline,
            "source control deadline exceeded"
        );
        match decoded {
            radicle::node::CommandResult::Okay(value) => Ok(value),
            radicle::node::CommandResult::Error { reason } => {
                bail!("source control: {reason}");
            }
        }
    })
}

// The native untagged CommandResult tries its success variant first. Reject
// unknown fields here so an {"error": ...} cannot deserialize as updated=false.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryPublication {
    #[serde(default)]
    updated: bool,
}

fn require_public_source_repository(fixture: &RadicleRepositoryFixtureV1) -> Result<()> {
    decode_repo_id(&fixture.repo_id)?;
    let rid = fixture
        .repo_id
        .parse()
        .wrap_err("parse public source RepoId")?;
    let path = fixture
        .home
        .join("storage")
        .join(fixture.repo_id.trim_start_matches("rad:"));
    let repository = radicle::storage::git::Repository::open(&path, rid)
        .wrap_err("open existing independent source repository")?;
    ensure!(
        repository.identity_doc()?.is_public(),
        "independent source inventory must contain a public repository"
    );
    Ok(())
}

fn wait_for_source_seeds(
    socket: &Path,
    rid: radicle::identity::RepoId,
    expected: &[[u8; 32]],
    timeout: Duration,
) -> Result<()> {
    ensure!(
        !expected.is_empty(),
        "source discovery requires validator peers"
    );
    let deadline = Instant::now() + timeout;
    let mut missing = expected
        .iter()
        .copied()
        .map(native_node_id)
        .collect::<Vec<_>>();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "source repository {rid} discovery deadline; missing connected validator seeds: {missing:?}"
        );
        // Discovery observes routing and connected identities, not synchronization
        // of the future update. The subsequent ordinary Git push must announce
        // that update itself; no forced refs announcement or validator fetch.
        let seeds = source_control_response::<radicle::node::Seeds>(
            socket,
            radicle::node::Command::SeedsFor {
                rid,
                namespaces: Default::default(),
            },
            deadline.min(Instant::now() + NATIVE_CONTROL_DEADLINE),
        )
        .wrap_err("observe source repository seeds")?;
        ensure!(
            Instant::now() < deadline,
            "source discovery deadline exceeded"
        );
        missing = expected
            .iter()
            .copied()
            .filter(|peer| !seeds.is_connected(&radicle::crypto::PublicKey::from(*peer)))
            .map(native_node_id)
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        std::thread::sleep(
            RADICLE_READY_POLL.min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

fn connected_sessions(sessions: Vec<ControlSession>) -> Result<Vec<(String, String)>> {
    let mut sessions = sessions
        .into_iter()
        .filter(|session| session.connected)
        .map(|session| {
            Ok((
                native_node_id(session.node_id),
                native_address(&session.address)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    sessions.sort();
    sessions.dedup();
    Ok(sessions)
}

fn seed_scope_all(home: &Path, repo_id: &str) -> Result<bool> {
    let repo_id: radicle::identity::RepoId = repo_id.parse().wrap_err("parse seed RepoId")?;
    let store = radicle::node::policy::store::StoreReader::reader(
        home.join("node").join(radicle::node::POLICIES_DB_FILE),
    )
    .wrap_err("open read-only native seeding policy store")?;
    // Iterate with error propagation: missing policy is pending, failed storage
    // observation is an error. Never seed a validator to make this assertion pass.
    for policy in store
        .seed_policies()
        .wrap_err("read native seeding policies")?
    {
        let policy = policy.wrap_err("decode native seeding policy")?;
        if policy.rid == repo_id {
            return Ok(matches!(
                policy.policy,
                SeedingPolicy::Allow { scope: Scope::All }
            ));
        }
    }
    Ok(false)
}

fn repository_visible(home: &Path, fixture: &RadicleRepositoryFixtureV1) -> Result<bool> {
    let repo_id: radicle::identity::RepoId =
        fixture.repo_id.parse().wrap_err("parse repository ID")?;
    // Parse before constructing the storage path; no Profile load or key access.
    decode_repo_id(&fixture.repo_id)?;
    let path = home
        .join("storage")
        .join(fixture.repo_id.trim_start_matches("rad:"));
    if !path
        .try_exists()
        .wrap_err("inspect replicated repository path")?
    {
        return Ok(false);
    }
    let repository = radicle::storage::git::Repository::open(&path, repo_id)
        .wrap_err("open replicated native repository")?;
    repository
        .identity_doc()
        .wrap_err("read replicated repository identity")?;
    let issue_id = fixture.issue_id.parse().wrap_err("parse issue ID")?;
    let patch_id = fixture.patch_id.parse().wrap_err("parse patch ID")?;
    let issue = radicle::issue::Issues::open(&repository, ReadOnly)
        .wrap_err("open read-only issue store")?
        .get(&issue_id)
        .wrap_err("read replicated issue COB")?;
    let patch = radicle::patch::Patches::open(&repository, ReadOnly)
        .wrap_err("open read-only patch store")?
        .get(&patch_id)
        .wrap_err("read replicated patch COB")?;
    if issue.is_none() || patch.is_none() {
        return Ok(false);
    }
    if let Some(expected) = &fixture.pushed_commit {
        return pushed_commit_visible(&repository, expected);
    }
    Ok(true)
}

fn pushed_commit_visible(
    repository: &radicle::storage::git::Repository,
    expected: &str,
) -> Result<bool> {
    let expected = expected.parse().wrap_err("parse pushed commit ID")?;
    let (name, head) = repository.head().wrap_err("read replicated Git head")?;
    if name.as_str() != "refs/heads/master" || head != expected {
        return Ok(false);
    }
    repository
        .commit(expected)
        .wrap_err("read replicated pushed Git commit")?;
    Ok(true)
}

fn write_outbe_profile(home: &Path, listen: &str, max_validators: usize) -> Result<()> {
    let managed_peers = max_validators.saturating_sub(1);
    let profile = serde_json::json!({
        "preferredSeeds": [],
        "node": {
            "alias": "outbe",
            "listen": [listen],
            "peers": { "type": "static" },
            "connect": [],
            "externalAddresses": [listen],
            "network": "outbe",
            "relay": "always",
            "limits": {
                "connection": {
                    "inbound": managed_peers + 16,
                    "outbound": managed_peers,
                }
            },
            "seedingPolicy": { "default": "block" },
        }
    });
    let path = home.join("config.json");
    fs::write(&path, serde_json::to_vec_pretty(&profile)?)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn materialized_max_validators(genesis_path: &Path) -> Result<usize> {
    let genesis: serde_json::Value = serde_json::from_slice(
        &fs::read(genesis_path)
            .wrap_err_with(|| format!("read materialized genesis {}", genesis_path.display()))?,
    )
    .wrap_err_with(|| format!("decode materialized genesis {}", genesis_path.display()))?;
    let alloc = genesis
        .get("alloc")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| eyre!("materialized genesis has no alloc object"))?;
    let account = alloc
        .get(VALIDATOR_SET_ALLOC_ADDRESS)
        .or_else(|| alloc.get(&format!("0x{VALIDATOR_SET_ALLOC_ADDRESS}")))
        .ok_or_else(|| eyre!("materialized genesis has no ValidatorSet alloc"))?;
    let storage = account
        .get("storage")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| eyre!("materialized ValidatorSet alloc has no storage"))?;
    let encoded = storage
        .get(VALIDATOR_SET_MAX_VALIDATORS_SLOT)
        .or_else(|| storage.get(VALIDATOR_SET_MAX_VALIDATORS_SLOT.trim_start_matches("0x")))
        .ok_or_else(|| eyre!("materialized ValidatorSet has no maxValidators slot"))?;
    let max_validators = encoded
        .as_u64()
        .or_else(|| {
            encoded
                .as_str()
                .and_then(|raw| u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok())
        })
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| eyre!("materialized ValidatorSet maxValidators is not positive"))?;
    Ok(max_validators)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Read as _,
        os::unix::fs::{symlink, MetadataExt as _, PermissionsExt as _},
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        thread::sleep,
        time::Duration,
    };

    use super::{
        block_on, configure_user_radicle, connected_sessions, decode_repo_id,
        materialized_max_validators, native_address, native_node_id, native_sessions,
        prepare_private_socket_parent, provisioned_radicle_node_id, pushed_commit_visible,
        query_sidecar, repository_visible, require_public_source_repository, seed_scope_all,
        source_control_response, verify_user_tool_version, wait_for_source_seeds,
        wait_radicle_ready, write_outbe_profile, ChildGuard, InventoryPublication,
        RadicleRepositoryFixtureV1, NATIVE_CONTROL_DEADLINE,
    };

    struct KillOnDrop(Child);

    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn readiness_child() -> ChildGuard {
        let mut command = Command::new("sleep");
        command
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        ChildGuard::spawn("radicle-readiness-fixture", command).unwrap()
    }

    #[test]
    fn readiness_public_identity_needs_no_private_key_or_profile() {
        let root = tempfile::tempdir().unwrap();
        assert!(provisioned_radicle_node_id(root.path()).is_err());
        let keys = root.path().join("keys");
        fs::create_dir(&keys).unwrap();
        let public = keys.join("radicle.pub");
        fs::write(&public, "malformed public fixture").unwrap();
        assert!(provisioned_radicle_node_id(root.path()).is_err());
        // OpenSSH encoding of public bytes [7; 32], not a generated secret.
        fs::write(&public, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH fixture\n").unwrap();
        assert_eq!(provisioned_radicle_node_id(root.path()).unwrap(), [7; 32]);
        assert!(!keys.join("radicle").exists());
        assert!(!root.path().join("config.json").exists());
        fs::rename(&public, keys.join("public-fixture")).unwrap();
        symlink(keys.join("public-fixture"), &public).unwrap();
        assert!(provisioned_radicle_node_id(root.path()).is_err());
    }

    #[test]
    fn readiness_accepts_owned_live_native_identity_without_changing_endpoints() {
        for peer_port in [8776, 9776] {
            let peer: std::net::SocketAddr = ([127, 0, 0, 1], peer_port).into();
            let status = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let status_addr = status.local_addr().unwrap();
            let (root, socket, server) = native_control_fixture(vec![
                serde_json::json!(native_node_id([7; 32])),
                serde_json::json!({"externalAddresses": [peer.to_string()]}),
            ]);
            let mut guard = readiness_child();
            let pid = guard.pid();
            wait_radicle_ready(
                &mut guard,
                [7; 32],
                &socket,
                peer,
                status_addr,
                &root.path().join("radicle.log"),
                Duration::from_secs(2),
            )
            .unwrap();
            assert_eq!(guard.pid(), pid);
            assert!(guard.exit_status().unwrap().is_none());
            assert_eq!(status.local_addr().unwrap(), status_addr);
            assert_eq!(server.join().unwrap().len(), 2);
            assert!(!root.path().join("config.json").exists());
            assert!(!root.path().join("keys").exists());
        }
    }

    #[test]
    fn readiness_foreign_status_listener_cannot_replace_missing_native_control() {
        let root = tempfile::tempdir().unwrap();
        let status = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = root.path().join("missing.sock");
        let log = root.path().join("radicle.log");
        let mut guard = readiness_child();
        let error = wait_radicle_ready(
            &mut guard,
            [7; 32],
            &socket,
            ([127, 0, 0, 1], 8776).into(),
            status.local_addr().unwrap(),
            &log,
            Duration::from_millis(50),
        )
        .unwrap_err();
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("native control observation failed"));
        assert!(diagnostic.contains(&format!("pid={}", guard.pid())));
        assert!(diagnostic.contains(&socket.display().to_string()));
        assert!(diagnostic.contains(&log.display().to_string()));
        assert!(guard.exit_status().unwrap().is_none());
        assert!(std::net::TcpStream::connect(status.local_addr().unwrap()).is_ok());
    }

    #[test]
    fn readiness_rejects_wrong_native_identity_and_advertised_listen_endpoint() {
        for (nid, addresses, expected_error) in [
            (
                native_node_id([8; 32]),
                vec!["127.0.0.1:8776"],
                "NodeId differs",
            ),
            (
                native_node_id([7; 32]),
                vec!["127.0.0.1:9776"],
                "advertised addresses differ",
            ),
            (
                native_node_id([7; 32]),
                vec!["127.0.0.1:8776", "127.0.0.1:9776"],
                "advertised addresses differ",
            ),
        ] {
            let (root, socket, server) = native_control_fixture(vec![
                serde_json::json!(nid),
                serde_json::json!({"externalAddresses": addresses}),
            ]);
            let status = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let mut guard = readiness_child();
            let error = wait_radicle_ready(
                &mut guard,
                [7; 32],
                &socket,
                ([127, 0, 0, 1], 8776).into(),
                status.local_addr().unwrap(),
                &root.path().join("radicle.log"),
                Duration::from_secs(2),
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains(expected_error));
            server.join().unwrap();
            assert!(guard.exit_status().unwrap().is_none());
        }
    }

    #[test]
    fn readiness_exited_owner_fails_even_with_a_foreign_status_listener() {
        let root = tempfile::tempdir().unwrap();
        let status = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut command = Command::new("sh");
        command.args(["-c", "exit 7"]);
        let mut guard = ChildGuard::spawn("exited-radicle-fixture", command).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while guard.exit_status().unwrap().is_none() {
            assert!(std::time::Instant::now() < deadline);
            sleep(Duration::from_millis(1));
        }
        let error = wait_radicle_ready(
            &mut guard,
            [7; 32],
            &root.path().join("control.sock"),
            ([127, 0, 0, 1], 8776).into(),
            status.local_addr().unwrap(),
            &root.path().join("radicle.log"),
            Duration::from_secs(2),
        )
        .unwrap_err();
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("owned Radicle child exited"));
        assert!(diagnostic.contains("exit status: 7"));
        assert_eq!(guard.exit_status().unwrap().unwrap().code(), Some(7));
        assert!(std::net::TcpStream::connect(status.local_addr().unwrap()).is_ok());
    }

    #[test]
    fn readiness_native_identity_does_not_replace_status_tcp() {
        let (root, socket, server) = native_control_fixture(vec![
            serde_json::json!(native_node_id([7; 32])),
            serde_json::json!({"externalAddresses": ["127.0.0.1:8776"]}),
        ]);
        let mut guard = readiness_child();
        // Port zero cannot be a listening TCP endpoint; avoid a release/rebind
        // race in this negative fixture by not selecting an ephemeral port.
        assert!(wait_radicle_ready(
            &mut guard,
            [7; 32],
            &socket,
            ([127, 0, 0, 1], 8776).into(),
            ([127, 0, 0, 1], 0).into(),
            &root.path().join("radicle.log"),
            Duration::from_millis(100),
        )
        .is_err());
        server.join().unwrap();
        assert!(guard.exit_status().unwrap().is_none());
    }

    #[test]
    fn native_observations_need_no_profile_and_follow_endpoint_replacement() {
        let nid = native_node_id([7; 32]);
        let peer = native_node_id([8; 32]);
        let (root, socket, server) = native_control_fixture(vec![
            serde_json::json!(nid),
            serde_json::json!({"externalAddresses": ["127.0.0.1:8776"]}),
            serde_json::json!(nid),
            serde_json::json!({"externalAddresses": ["127.0.0.1:9776"]}),
            serde_json::json!([
                {"nid": peer, "addr": "127.0.0.1:8777", "link": "outbound", "state": {"connected": {}}},
                {"nid": nid, "addr": "127.0.0.1:9776", "link": "inbound", "state": {"disconnected": {}}}
            ]),
        ]);
        let before = block_on(query_sidecar(socket.clone(), NATIVE_CONTROL_DEADLINE)).unwrap();
        let after = block_on(query_sidecar(socket.clone(), NATIVE_CONTROL_DEADLINE)).unwrap();
        assert_eq!(before.node_id, after.node_id);
        assert_eq!(
            native_address(&before.addresses[0]).unwrap(),
            "127.0.0.1:8776"
        );
        assert_eq!(
            native_address(&after.addresses[0]).unwrap(),
            "127.0.0.1:9776"
        );
        assert_eq!(
            connected_sessions(native_sessions(socket).unwrap()).unwrap(),
            vec![(peer, "127.0.0.1:8777".to_owned())]
        );
        let commands = server.join().unwrap();
        assert_eq!(
            commands,
            vec![
                serde_json::json!({"command": "nodeId"}),
                serde_json::json!({"command": "config"}),
                serde_json::json!({"command": "nodeId"}),
                serde_json::json!({"command": "config"}),
                serde_json::json!({"command": "sessions"}),
            ]
        );
        assert!(!root.path().join("config.json").exists());
        assert!(!root.path().join("keys").exists());
    }

    #[test]
    fn native_session_errors_are_not_an_empty_mesh() {
        for response in [
            serde_json::json!({"error": "sidecar unavailable"}),
            serde_json::json!([{"nid": "invalid"}]),
        ] {
            let (_root, socket, server) = native_control_fixture(vec![response]);
            assert!(native_sessions(socket).is_err());
            server.join().unwrap();
        }
    }

    #[test]
    fn native_user_setup_publishes_inventory_and_discovers_live_validator_seeds() {
        let nid = native_node_id([7; 32]);
        let repo = [5; 20];
        for result in [
            serde_json::json!({"status": "connected"}),
            serde_json::json!({"status": "disconnected", "reason": "rejected"}),
        ] {
            let success = result["status"] == "connected";
            let mut responses = vec![serde_json::json!({"updated": true}), result];
            if success {
                responses.extend([
                    serde_json::json!({"updated": true}),
                    serde_json::json!([{
                        "nid": nid, "addrs": [],
                        "state": {"connected": {"since": 0}}
                    }]),
                ]);
            }
            let (_user_root, user, user_server) = native_control_fixture(responses);
            let (_validator_root, validator, validator_server) = native_control_fixture(vec![
                serde_json::json!(nid),
                serde_json::json!({"externalAddresses": ["127.0.0.1:9776"]}),
            ]);
            assert_eq!(
                configure_user_radicle(user, repo, vec![validator]).is_ok(),
                success
            );
            let commands = user_server.join().unwrap();
            assert_eq!(
                commands[0],
                serde_json::json!({
                    "command": "seed", "scope": "all",
                    "rid": format!("rad:{}", multibase::encode(multibase::Base::Base58Btc, repo)),
                })
            );
            assert_eq!(commands[1]["command"], "connect");
            assert_eq!(commands[1]["addr"], format!("{nid}@127.0.0.1:9776"));
            assert_eq!(commands[1]["opts"]["persistent"], false);
            if success {
                assert_eq!(commands[2]["command"], "addInventory");
                assert_eq!(commands[2]["rid"], commands[0]["rid"]);
                assert_eq!(commands[3]["command"], "seedsFor");
                assert_eq!(commands[3]["rid"], commands[0]["rid"]);
            }
            assert_eq!(
                validator_server.join().unwrap(),
                vec![
                    serde_json::json!({"command": "nodeId"}),
                    serde_json::json!({"command": "config"}),
                ]
            );
        }
    }

    #[test]
    fn native_user_publication_is_idempotent_but_errors_are_not_acknowledgements() {
        let nid = native_node_id([7; 32]);
        for publication in [
            serde_json::json!({}),
            serde_json::json!({"updated": false}),
            serde_json::json!({"error": "inventory rejected"}),
        ] {
            let rejected = publication.get("error").is_some();
            let mut responses = vec![
                serde_json::json!({"updated": false}),
                serde_json::json!({"status": "connected"}),
                publication,
            ];
            if !rejected {
                responses.push(serde_json::json!([{
                    "nid": nid, "addrs": [], "state": {"connected": {"since": 0}}
                }]));
            }
            let (_user_root, user, user_server) = native_control_fixture(responses);
            let (_validator_root, validator, validator_server) = native_control_fixture(vec![
                serde_json::json!(nid),
                serde_json::json!({"externalAddresses": ["127.0.0.1:9776"]}),
            ]);
            let result = configure_user_radicle(user, [5; 20], vec![validator]);
            if rejected {
                let error = format!("{:#}", result.unwrap_err());
                assert!(error.contains("inventory rejected"), "{error}");
                assert!(
                    error.contains("publish independent source inventory"),
                    "{error}"
                );
            } else {
                result.unwrap();
            }
            assert_eq!(
                user_server.join().unwrap().len(),
                if rejected { 3 } else { 4 }
            );
            assert_eq!(validator_server.join().unwrap().len(), 2);
        }
    }

    #[test]
    fn native_source_discovery_requires_every_expected_connected_seed() {
        let rid = format!(
            "rad:{}",
            multibase::encode(multibase::Base::Base58Btc, [5; 20])
        );
        let first = native_node_id([7; 32]);
        let second = native_node_id([8; 32]);
        let foreign = native_node_id([9; 32]);
        let (_root, socket, server) = native_control_fixture(vec![
            serde_json::json!([
                {"nid": first, "addrs": [], "state": {"connected": {"since": 0}}},
                {"nid": second, "addrs": []},
                {"nid": foreign, "addrs": [], "state": {"connected": {"since": 0}}}
            ]),
            serde_json::json!([
                {"nid": first, "addrs": [], "state": {"connected": {"since": 0}}},
                {"nid": second, "addrs": [], "state": {"connected": {"since": 0}}}
            ]),
        ]);
        wait_for_source_seeds(
            &socket,
            rid.parse().unwrap(),
            &[[7; 32], [8; 32]],
            Duration::from_secs(5),
        )
        .unwrap();
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests
            .iter()
            .all(|request| request["command"] == "seedsFor" && request["rid"] == rid));
    }

    #[test]
    fn native_source_discovery_rejects_errors_empty_cohorts_and_elapsed_deadlines() {
        let rid = format!(
            "rad:{}",
            multibase::encode(multibase::Base::Base58Btc, [5; 20])
        );
        let (_root, socket, server) =
            native_control_fixture(vec![serde_json::json!({"error": "routing unavailable"})]);
        let error = wait_for_source_seeds(
            &socket,
            rid.parse().unwrap(),
            &[[7; 32]],
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("routing unavailable"));
        assert_eq!(server.join().unwrap().len(), 1);
        assert!(
            wait_for_source_seeds(&socket, rid.parse().unwrap(), &[], Duration::from_secs(5))
                .is_err()
        );
        let error =
            wait_for_source_seeds(&socket, rid.parse().unwrap(), &[[7; 32]], Duration::ZERO)
                .unwrap_err();
        assert!(error.to_string().contains("discovery deadline"));
        assert!(error.to_string().contains(&native_node_id([7; 32])));
    }

    #[test]
    fn source_control_decoded_success_after_deadline_is_rejected() {
        static DECODED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        struct SlowReply;
        impl<'de> serde::Deserialize<'de> for SlowReply {
            fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
                let _ = <bool as serde::Deserialize>::deserialize(decoder)?;
                DECODED.store(true, std::sync::atomic::Ordering::SeqCst);
                sleep(Duration::from_millis(150));
                Ok(Self)
            }
        }
        let (_root, socket, server) = native_control_fixture(vec![serde_json::json!(true)]);
        let result = source_control_response::<SlowReply>(
            &socket,
            radicle::node::Command::NodeId,
            std::time::Instant::now() + Duration::from_millis(100),
        );
        server.join().unwrap();
        assert!(DECODED.load(std::sync::atomic::Ordering::SeqCst));
        let error = result.err().expect("expired decoded success must fail");
        assert!(format!("{error:#}").contains("deadline exceeded"));
    }

    #[test]
    fn source_control_stall_and_truncated_reply_fail_and_close_the_socket() {
        use std::io::{BufRead as _, Write as _};
        for truncated in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let socket = root.path().join("control.sock");
            let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
            listener.set_nonblocking(true).unwrap();
            let server = std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(std::time::Instant::now() < deadline, "missing request");
                            sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("accept source request: {error}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = String::new();
                std::io::BufReader::new(&stream)
                    .read_line(&mut request)
                    .unwrap();
                if truncated {
                    stream.write_all(b"{}").unwrap();
                    stream.shutdown(std::net::Shutdown::Write).unwrap();
                }
                // The client must drop the timed-out/incomplete exchange, not
                // leave a detached blocking operation waiting for this server.
                assert_eq!(stream.read(&mut [0]).unwrap(), 0);
            });
            let rid = format!(
                "rad:{}",
                multibase::encode(multibase::Base::Base58Btc, [5; 20])
            );
            let result = source_control_response::<InventoryPublication>(
                &socket,
                radicle::node::Command::AddInventory {
                    rid: rid.parse().unwrap(),
                },
                std::time::Instant::now() + Duration::from_millis(100),
            );
            server.join().unwrap();
            let error = format!("{:#}", result.err().expect("response must fail"));
            assert!(
                error.contains(if truncated {
                    "response incomplete"
                } else {
                    "deadline exceeded"
                }),
                "{error}"
            );
        }
    }

    #[test]
    fn native_source_discovery_partial_response_cannot_extend_deadline() {
        use std::io::{BufRead as _, Write as _};
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("control.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(std::time::Instant::now() < deadline, "missing request");
                        sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept source request: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = String::new();
            std::io::BufReader::new(&stream)
                .read_line(&mut request)
                .unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&request).unwrap()["command"],
                "seedsFor"
            );
            // Each byte arrives within the old per-read timeout, but the complete
            // valid response arrives after the discovery's absolute deadline.
            for _ in 0..20 {
                if stream.write_all(b" ").is_err() {
                    return;
                }
                sleep(Duration::from_millis(20));
            }
            let response = serde_json::json!([{
                "nid": native_node_id([7; 32]), "addrs": [],
                "state": {"connected": {"since": 0}}
            }]);
            if serde_json::to_writer(&mut stream, &response).is_ok() {
                let _ = stream.write_all(b"\n");
            }
        });
        let rid = format!(
            "rad:{}",
            multibase::encode(multibase::Base::Base58Btc, [5; 20])
        );
        let result = wait_for_source_seeds(
            &socket,
            rid.parse().unwrap(),
            &[[7; 32]],
            Duration::from_millis(100),
        );
        server.join().unwrap();
        assert!(
            result.is_err(),
            "late partial response must not satisfy discovery"
        );
    }

    #[test]
    fn native_endpoint_format_preserves_ipv6_and_dns() {
        use outbe_radicle::endpoint::EndpointAddress;
        let ipv6 = EndpointAddress::ipv6(std::net::Ipv6Addr::LOCALHOST.octets(), 8776).unwrap();
        assert_eq!(native_address(&ipv6).unwrap(), "[::1]:8776");
        let dns = EndpointAddress::dns("peer.example", 8777).unwrap();
        assert_eq!(native_address(&dns).unwrap(), "peer.example:8777");
    }

    #[test]
    fn user_tools_must_match_the_pinned_fork() {
        for name in ["rad", "git-remote-rad"] {
            assert!(verify_user_tool_version(name, &format!("{name} 1.0 (b76a178)\n")).is_ok());
            assert!(verify_user_tool_version(name, &format!("{name} 1.0 (deadbee)")).is_err());
            assert!(verify_user_tool_version(name, &format!("{name} 1.0 (b76)")).is_err());
            assert!(
                verify_user_tool_version(name, &format!("{name} 1.0 (b76a178-dirty)")).is_err()
            );
        }
    }

    #[test]
    fn seeding_observation_requires_exact_persisted_allow_all_without_a_profile() {
        use radicle::node::policy::{store::StoreWriter, Policy, Scope};
        let root = tempfile::tempdir().unwrap();
        let node = root.path().join("node");
        fs::create_dir(&node).unwrap();
        let database = node.join(radicle::node::POLICIES_DB_FILE);
        let repo = format!(
            "rad:{}",
            multibase::encode(multibase::Base::Base58Btc, [5; 20])
        );
        let other = format!(
            "rad:{}",
            multibase::encode(multibase::Base::Base58Btc, [6; 20])
        );
        let rid = repo.parse().unwrap();
        let mut writer = StoreWriter::open(&database).unwrap();
        writer.seed(&other.parse().unwrap(), Scope::All).unwrap();
        assert!(!seed_scope_all(root.path(), &repo).unwrap());
        writer.seed(&rid, Scope::Followed).unwrap();
        assert!(!seed_scope_all(root.path(), &repo).unwrap());
        writer.seed(&rid, Scope::All).unwrap();
        assert!(seed_scope_all(root.path(), &repo).unwrap());
        writer.set_seed_policy(&rid, Policy::Block).unwrap();
        assert!(!seed_scope_all(root.path(), &repo).unwrap());
        drop(writer);
        assert!(!seed_scope_all(root.path(), &repo).unwrap());
        assert!(!root.path().join("config.json").exists());
        assert!(!root.path().join("keys").exists());
    }

    #[test]
    fn seeding_observation_preserves_missing_and_corrupt_store_errors() {
        let root = tempfile::tempdir().unwrap();
        let repo = format!(
            "rad:{}",
            multibase::encode(multibase::Base::Base58Btc, [5; 20])
        );
        assert!(seed_scope_all(root.path(), &repo).is_err());
        assert!(!root.path().join("node").exists());
        fs::create_dir(root.path().join("node")).unwrap();
        let database = root
            .path()
            .join("node")
            .join(radicle::node::POLICIES_DB_FILE);
        fs::write(&database, "not a sqlite database").unwrap();
        assert!(seed_scope_all(root.path(), &repo).is_err());
        assert_eq!(fs::read(&database).unwrap(), b"not a sqlite database");
    }

    #[test]
    fn repository_absence_is_pending_but_corruption_is_an_error() {
        let root = tempfile::tempdir().unwrap();
        let canonical = multibase::encode(multibase::Base::Base58Btc, [5; 20]);
        let fixture = RadicleRepositoryFixtureV1 {
            home: root.path().join("source"),
            worktree: root.path().join("worktree"),
            repo_id: format!("rad:{canonical}"),
            repo_id_hex: hex::encode([5; 20]),
            issue_id: "11".repeat(20),
            patch_id: "22".repeat(20),
            pushed_commit: Some("33".repeat(20)),
        };
        assert!(!repository_visible(root.path(), &fixture).unwrap());
        assert!(require_public_source_repository(&fixture).is_err());
        assert!(!fixture.home.exists());
        assert!(!root.path().join("storage").exists());
        fs::create_dir_all(root.path().join("storage").join(canonical)).unwrap();
        assert!(repository_visible(root.path(), &fixture).is_err());
        assert!(!root.path().join("config.json").exists());
    }

    #[test]
    fn pushed_commit_requires_the_exact_master_ref_and_commit_object() {
        use radicle::git::raw;
        let root = tempfile::tempdir().unwrap();
        let git = raw::Repository::init_bare(root.path()).unwrap();
        let tree_id = git.treebuilder(None).unwrap().write().unwrap();
        let tree = git.find_tree(tree_id).unwrap();
        let signature = raw::Signature::now("Fixture", "fixture@example.test").unwrap();
        let commit = git
            .commit(
                Some("refs/heads/master"),
                &signature,
                &signature,
                "replicated update",
                &tree,
                &[],
            )
            .unwrap();
        git.set_head("refs/heads/master").unwrap();
        let rid = format!(
            "rad:{}",
            multibase::encode(multibase::Base::Base58Btc, [5; 20])
        );
        let repository =
            radicle::storage::git::Repository::open(root.path(), rid.parse().unwrap()).unwrap();
        assert!(pushed_commit_visible(&repository, &commit.to_string()).unwrap());
        assert!(!pushed_commit_visible(&repository, &"11".repeat(20)).unwrap());
        assert!(pushed_commit_visible(&repository, "not-an-oid").is_err());
        // The object still exists, but an unrelated branch must not prove the push.
        git.reference("refs/heads/other", commit, false, "fixture branch")
            .unwrap();
        git.set_head("refs/heads/other").unwrap();
        assert!(!pushed_commit_visible(&repository, &commit.to_string()).unwrap());
    }

    fn native_control_fixture(
        responses: Vec<serde_json::Value>,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        std::thread::JoinHandle<Vec<serde_json::Value>>,
    ) {
        use std::io::{BufRead as _, Write as _};
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("control.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let mut commands = Vec::new();
            for response in responses {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "missing control request"
                            );
                            sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("accept native control request: {error}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut line = String::new();
                std::io::BufReader::new(&stream)
                    .read_line(&mut line)
                    .unwrap();
                commands.push(serde_json::from_str(&line).unwrap());
                serde_json::to_writer(&mut stream, &response).unwrap();
                stream.write_all(b"\n").unwrap();
            }
            commands
        });
        (root, socket, server)
    }

    #[test]
    fn canonical_repo_id_decodes_to_registry_bytes() {
        let expected = [0x5a; 20];
        let canonical = format!(
            "rad:{}",
            multibase::encode(multibase::Base::Base58Btc, expected)
        );
        assert_eq!(decode_repo_id(&canonical).unwrap(), expected);
        assert!(decode_repo_id("rad:f0011").is_err());
    }

    #[test]
    fn materialized_genesis_drives_radicle_capacity() {
        let root = tempfile::tempdir().expect("create capacity fixture");
        let genesis = root.path().join("genesis.json");
        fs::write(
            &genesis,
            serde_json::to_vec(&serde_json::json!({
                "alloc": {
                    "000000000000000000000000000000000000ee00": {
                        "storage": {
                            "0x0000000000000000000000000000000000000000000000000000000000000001":
                                "0x0000000000000000000000000000000000000000000000000000000000000080"
                        }
                    }
                }
            }))
            .expect("encode genesis fixture"),
        )
        .expect("write genesis fixture");

        let max_validators = materialized_max_validators(&genesis).expect("read capacity");
        assert_eq!(max_validators, 128);
        write_outbe_profile(root.path(), "127.0.0.1:8776", max_validators).expect("write profile");
        let profile: serde_json::Value = serde_json::from_slice(
            &fs::read(root.path().join("config.json")).expect("read profile"),
        )
        .expect("decode profile");
        assert_eq!(
            profile.pointer("/node/limits/connection/outbound"),
            Some(&serde_json::json!(127))
        );
        assert_eq!(
            profile.pointer("/node/limits/connection/inbound"),
            Some(&serde_json::json!(143))
        );
    }

    #[test]
    fn short_socket_runtime_is_private_and_rejects_symlink_parents() {
        let fixture = tempfile::tempdir().expect("create runtime fixture");
        let runtime = fixture.path().join("runtime");
        let socket = runtime.join("scenario-1/v0.sock");
        prepare_private_socket_parent(&runtime, &socket, fixture.path())
            .expect("prepare private runtime");
        let expected_uid = fs::symlink_metadata(fixture.path())
            .expect("inspect fixture owner")
            .uid();

        for directory in [&runtime, socket.parent().unwrap()] {
            let metadata = fs::symlink_metadata(directory).expect("inspect private runtime");
            assert!(metadata.is_dir());
            assert!(!metadata.file_type().is_symlink());
            assert_eq!(metadata.uid(), expected_uid);
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        }

        let external = fixture.path().join("external");
        fs::create_dir(&external).expect("create external directory");
        let linked_runtime = fixture.path().join("linked-runtime");
        symlink(&external, &linked_runtime).expect("link runtime directory");
        let linked_socket = linked_runtime.join("scenario-1/v0.sock");
        assert!(
            prepare_private_socket_parent(&linked_runtime, &linked_socket, fixture.path()).is_err()
        );
    }

    #[test]
    fn launcher_rejects_second_home_owner() {
        let fixture = launcher_fixture();
        let mut first = KillOnDrop(
            launcher_command(&fixture.home, &fixture.binary)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("start first launcher"),
        );
        wait_for_launcher(&mut first.0, &fixture.home);

        let second = launcher_command(&fixture.home, &fixture.binary)
            .output()
            .expect("run competing launcher");
        assert!(!second.status.success());
        assert!(
            String::from_utf8_lossy(&second.stderr).contains("a live sidecar already owns"),
            "unexpected competing-launcher error: {}",
            String::from_utf8_lossy(&second.stderr)
        );
    }

    #[test]
    fn launcher_rejects_managed_directory_symlink() {
        let fixture = launcher_fixture();
        let external = fixture.root.path().join("external-storage");
        fs::create_dir(&external).expect("create external storage");
        fs::set_permissions(&external, fs::Permissions::from_mode(0o700))
            .expect("protect external storage");
        symlink(&external, fixture.home.join("storage")).expect("link managed storage");

        let output = launcher_command(&fixture.home, &fixture.binary)
            .output()
            .expect("run launcher with symlink");
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("expected non-symlink directory"),
            "unexpected symlink error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    struct LauncherFixture {
        root: tempfile::TempDir,
        home: PathBuf,
        binary: PathBuf,
    }

    fn launcher_fixture() -> LauncherFixture {
        let root = tempfile::tempdir().expect("create launcher fixture");
        let home = root.path().join("radicle");
        let keys = home.join("keys");
        fs::create_dir_all(&keys).expect("create key directory");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("protect home");
        fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).expect("protect keys");
        for name in ["radicle", "radicle.pub"] {
            let path = keys.join(name);
            fs::write(&path, "fixture\n").expect("write fixture key");
            fs::set_permissions(
                &path,
                fs::Permissions::from_mode(if name == "radicle" { 0o600 } else { 0o644 }),
            )
            .expect("set fixture key mode");
        }
        let binary = root.path().join("outbe-radicle-fixture");
        fs::write(
            &binary,
            concat!(
                "#!/usr/bin/env python3\n",
                "import socket\n",
                "import sys\n",
                "path = sys.argv[sys.argv.index('--control-socket') + 1]\n",
                "listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n",
                "listener.bind(path)\n",
                "listener.listen()\n",
                "with open(path + '.ready', 'x', encoding='utf-8') as marker:\n",
                "    marker.write('ready\\n')\n",
                "while True:\n",
                "    connection, _ = listener.accept()\n",
                "    connection.close()\n",
            ),
        )
        .expect("write fake sidecar");
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))
            .expect("make fake sidecar executable");
        LauncherFixture { root, home, binary }
    }

    fn launcher_command(home: &Path, binary: &Path) -> Command {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/run-radicle.sh");
        let mut command = Command::new(script);
        command
            .env("OUTBE_RADICLE_BINARY", binary)
            .env(
                "OUTBE_RADICLE_CONTROL_SOCKET",
                home.join("node/outbe-control.sock"),
            )
            .args([
                home.as_os_str(),
                "127.0.0.1:18776".as_ref(),
                "127.0.0.1:18777".as_ref(),
                "4".as_ref(),
                "127.0.0.1:18776".as_ref(),
            ]);
        command
    }

    /// Waits until the launcher has taken ownership of the home.
    ///
    /// The managed directories are created just before the script execs the
    /// sidecar, so their presence is the last observable step of setup. It
    /// used to wait on `config.json`, but the launcher no longer writes one -
    /// the sidecar builds its runtime config from its command line and never
    /// reads that file.
    fn wait_for_launcher(child: &mut Child, home: &Path) {
        let control_socket = home.join("node/outbe-control.sock");
        let readiness_marker = control_socket.with_extension("sock.ready");
        for _ in 0..100 {
            if let Some(status) = child.try_wait().expect("poll launcher") {
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    pipe.read_to_string(&mut stderr)
                        .expect("read failed launcher stderr");
                }
                panic!("first launcher exited early with {status}: {stderr}");
            }
            if readiness_marker.is_file() {
                return;
            }
            sleep(Duration::from_millis(10));
        }
        panic!(
            "first launcher did not publish readiness for its control socket at {}",
            readiness_marker.display()
        );
    }
}
