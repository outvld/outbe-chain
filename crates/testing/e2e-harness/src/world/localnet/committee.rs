//! The bootstrapped committee: start/stop/restart the validator set and its
//! enclaves (ported `run-testnet.sh` start), owned as Rust child processes.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use eyre::{bail, Result};

use crate::env::TeeMode;
use crate::internal::proc::{self, args, attach_log, read_trimmed, wait_tcp, SealSpec};

use super::{Localnet, StartOpts};

impl Localnet {
    /// Start the committee (and, when TEE is enabled, its enclaves). Idempotent:
    /// indices whose owned node is still alive are skipped, so [`restart`] only
    /// relaunches the ones that died.
    pub fn start(&mut self, opts: &StartOpts) -> Result<()> {
        self.start_opts = opts.clone();
        let n = self.committee_size();
        if self.tee_enabled() {
            proc::ensure_enclave_image(&self.cfg.repo, self.cfg.sudo)?;
        }
        let bootnodes = self.bootnodes();
        let chain_id_hex = if self.tee_enabled() {
            Some(self.chain_id_hex()?)
        } else {
            None
        };

        let mut launched = Vec::new();
        for i in 0..n {
            if self.validators.get_mut(&i).is_some_and(|g| !g.exited()) {
                continue; // already running
            }
            self.validators.remove(&i); // clear a dead handle if present

            if self.tee_enabled() && !self.enclaves.contains_key(&i) {
                self.start_enclave(i, chain_id_hex.as_deref().unwrap_or_default())?;
            }
            self.launch_validator(i, opts, bootnodes.as_deref())?;
            launched.push(i);
        }

        // Survival check: a node that dies in the first couple seconds is a
        // config error — surface it with its log tail (`run-testnet.sh:386-407`).
        sleep(Duration::from_secs(2));
        for &i in &launched {
            if self.validators.get_mut(&i).is_some_and(|g| g.exited()) {
                let tail = self.tail_log(i, 20);
                self.validators.remove(&i);
                bail!("validator-{i} exited during startup:\n{tail}");
            }
        }
        Ok(())
    }

    /// Relaunch any committee validator whose node died (e.g. one killed in the
    /// DKG-failure recovery), reusing the last start's options. Live nodes and
    /// still-running enclaves are left in place.
    pub fn restart(&mut self) -> Result<()> {
        let opts = self.start_opts.clone();
        self.start(&opts)
    }

    /// Kill committee validator `i` so it stays down, leaving its enclave up (a
    /// later [`restart`] reconnects to it). Port of `e2e_kill_validator`.
    pub fn kill_validator(&mut self, i: usize) -> Result<()> {
        self.validators.remove(&i); // Drop → SIGKILL + reap
        // Backstop in case the owned handle was ever lost.
        let pat = format!("outbe-chain node.*validator-{i}/data");
        self.sh().sudo_best_effort("pkill", &["-9", "-f", &pat]);
        Ok(())
    }

    /// Launch one committee validator as an owned child (`run-testnet.sh:317-349`):
    /// `--consensus.use-local-defaults`, signing-key + evm-key only (peers come
    /// from the on-chain ValidatorSet), no `run-supervised` wrapper.
    fn launch_validator(&mut self, i: usize, opts: &StartOpts, bootnodes: Option<&str>) -> Result<()> {
        let vd = self.cfg.validator_dir(i);
        fs::create_dir_all(vd.join("data"))?;
        fs::create_dir_all(vd.join("logs"))?;
        // A prior SIGKILL can leave the MDBX lock behind; clear it before relaunch.
        let _ = fs::remove_file(vd.join("data/db/lock"));

        let mut a = self.reth_base_args(&vd, i);
        if let Some(bn) = bootnodes.filter(|b| !b.is_empty()) {
            a.extend(args!["--bootnodes", bn]);
        }
        let secret = vd.join("reth-p2p-secret.hex");
        if secret.exists() {
            a.extend(args!["--p2p-secret-key-hex", read_trimmed(&secret)?]);
        }
        a.extend(args![
            "--validator",
            "--metrics",
            format!("0.0.0.0:{}", self.cfg.metrics_port(i)),
            "--consensus.signing-key",
            vd.join("signing-key.hex").display(),
            "--validator.evm-key",
            vd.join("evm-key.hex").display(),
            "--consensus.listen-addr",
            format!("127.0.0.1:{}", self.cfg.consensus_port(i)),
            "--consensus.use-local-defaults",
        ]);
        if self.tee_enabled() {
            a.extend(args![
                "--tee-enclave-socket",
                format!("127.0.0.1:{}", self.cfg.tee_port(i))
            ]);
        }

        let mut cmd = Command::new(&self.cfg.bin_chain);
        cmd.env("RUST_MIN_STACK", "16777216");
        if let Some(w) = opts.voting_window {
            cmd.env("OUTBE_TEST_VOTING_WINDOW_BLOCKS", w.to_string());
        }
        cmd.args(&a);
        attach_log(&mut cmd, &vd)?;
        let guard = self.spawn_node(&format!("validator-{i}"), &vd, cmd)?;
        self.validators.insert(i, guard);
        Ok(())
    }

    /// Launch validator `i`'s enclave container (`run-testnet.sh:215-293`), owned
    /// and foreground (no `-d`), and wait for its socket.
    fn start_enclave(&mut self, i: usize, chain_id_hex: &str) -> Result<()> {
        let vd = self.cfg.validator_dir(i);
        fs::create_dir_all(&vd)?;
        let port = self.cfg.tee_port(i);
        let mock = matches!(self.cfg.tee_mode, TeeMode::Mock);
        let enclave_bin = if mock {
            self.cfg.bin_mock.clone()
        } else {
            self.real_enclave_bin()?
        };
        // The harness always seals (localnet start sets OUTBE_TEE_SEAL); the host
        // dkg-seed is passed except for real+seal, where the enclave self-seals.
        let seal = Some(SealSpec {
            tee_dir: vd.join("tee"),
            chain_id_hex: chain_id_hex.to_string(),
        });
        let dkg_seed = mock.then(|| format!("{:064x}", i + 1));

        let guard = proc::spawn_enclave(proc::EnclaveSpec {
            name: self.cfg.tee_container(i),
            tee_port: port,
            enclave_bin,
            sudo: self.cfg.sudo,
            mock,
            dkg_seed,
            seal,
            log_path: vd.join("enclave.log"),
            debug: self.cfg.debug,
        })?;
        self.enclaves.insert(i, guard);
        if !wait_tcp(port, 200) {
            self.enclaves.remove(&i);
            bail!("enclave socket 127.0.0.1:{port} never came up for validator-{i}");
        }
        Ok(())
    }

    /// The genesis chain id as `0x`-padded 64-hex (enclave seal `--chain-id`).
    fn chain_id_hex(&self) -> Result<String> {
        let g: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(self.cfg.dir.join("genesis.json"))?)?;
        let id = g
            .get("config")
            .and_then(|c| c.get("chainId"))
            .and_then(|x| x.as_u64())
            .ok_or_else(|| eyre::eyre!("no chainId in genesis.json"))?;
        Ok(format!("0x{id:064x}"))
    }

    /// Resolve the real (non-mock) enclave binary from the build tree.
    fn real_enclave_bin(&self) -> Result<PathBuf> {
        for rel in [
            "target/debug/outbe-tee-enclave",
            "target/release/outbe-tee-enclave",
        ] {
            let p = self.cfg.repo.join(rel);
            if p.exists() {
                return Ok(p);
            }
        }
        bail!("real enclave binary `outbe-tee-enclave` not found under target/{{debug,release}}")
    }

    /// Last `n` lines of validator `i`'s `node.log`.
    fn tail_log(&self, i: usize, n: usize) -> String {
        let s = fs::read_to_string(self.cfg.validator_dir(i).join("node.log")).unwrap_or_default();
        let lines: Vec<&str> = s.lines().collect();
        lines[lines.len().saturating_sub(n)..].join("\n")
    }
}
