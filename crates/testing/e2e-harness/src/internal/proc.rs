//! Owned processes and containers, plus the small IO helpers the node/enclave
//! launchers share.
//!
//! Every process the harness launches is **owned**: nodes are held as
//! [`ChildGuard`]s (killed + reaped on drop, no `nohup`/pid-files) and enclave
//! containers as [`EnclaveGuard`]s — the `docker run` runs in the **foreground**
//! (no `-d`) as an owned child, with a `docker rm -f` backstop on drop. Because a
//! fresh `World` is built per scenario, dropping it tears everything down; the
//! `Localnet`/`Nodes` handles that hold these guards are non-`Clone`.

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

use alloy_primitives::hex;
use eyre::{bail, eyre, Result, WrapErr};

/// Build a `Vec<String>` of process arguments from `Display` tokens.
///
/// Every argument is stringified once (`to_string`), so callers write clean
/// literals, ports, and paths — pass a path's `.display()` — without sprinkling
/// `.into()` / `.to_string()` / `.display().to_string()`. `.extend(args![…])` a
/// base list with conditional or role-specific tails.
macro_rules! args {
    ($($x:expr),* $(,)?) => {
        ::std::vec![$($x.to_string()),*]
    };
}
pub(crate) use args;

/// An owned child process: killed and reaped on drop.
#[derive(Debug)]
pub(crate) struct ChildGuard {
    #[allow(dead_code)] // retained for Debug / future diagnostics
    label: String,
    child: Child,
}

impl ChildGuard {
    pub(crate) fn spawn(label: impl Into<String>, mut cmd: Command) -> Result<Self> {
        let label = label.into();
        let child = cmd.spawn().wrap_err_with(|| format!("spawn {label}"))?;
        Ok(Self { label, child })
    }

    /// Whether the child has already exited (non-blocking).
    pub(crate) fn exited(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(Some(_)))
    }

    /// The OS process id (for `--debug` launch logging).
    pub(crate) fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// An owned docker container: `docker rm -f` on drop.
#[derive(Debug)]
pub(crate) struct DockerGuard {
    name: String,
    sudo: bool,
}

impl DockerGuard {
    pub(crate) fn new(name: impl Into<String>, sudo: bool) -> Self {
        Self {
            name: name.into(),
            sudo,
        }
    }
}

impl Drop for DockerGuard {
    fn drop(&mut self) {
        docker_rm(&self.name, self.sudo);
    }
}

/// An owned enclave: the foreground `docker run` child (killed on drop) plus a
/// `docker rm -f` backstop for the container itself. Field order matters — the
/// `docker run` client is dropped first, then the container is force-removed.
#[derive(Debug)]
pub(crate) struct EnclaveGuard {
    #[allow(dead_code)] // owned for its Drop (kills the `docker run` client)
    child: ChildGuard,
    #[allow(dead_code)] // owned for its Drop (`docker rm -f`)
    docker: DockerGuard,
}

/// Optional sealed-restart parameters (persistent `/tee` mount + chain-id).
pub(crate) struct SealSpec {
    pub tee_dir: PathBuf,
    pub chain_id_hex: String,
}

/// Everything needed to launch one enclave container (mirrors `run-testnet.sh:215-293`).
pub(crate) struct EnclaveSpec {
    pub name: String,
    pub tee_port: u16,
    /// Host enclave binary bind-mounted read-only at `/app/outbe-tee-enclave`.
    pub enclave_bin: PathBuf,
    pub sudo: bool,
    /// Mock enclave (`gramine-direct`) — when false, real SGX device passthrough
    /// is attempted if the host exposes the device nodes.
    pub mock: bool,
    /// `--dkg-seed <hex>` for the container, or `None` (real+seal self-generates).
    pub dkg_seed: Option<String>,
    pub seal: Option<SealSpec>,
    /// Where the container's stdout/stderr are streamed (`<node>/enclave.log`).
    pub log_path: PathBuf,
    /// Log the built `docker` command + container/port under `--debug`.
    pub debug: bool,
}

/// Build the `outbe-tee-enclave-gramine` image if it isn't present
/// (`run-testnet.sh:170-176`).
pub(crate) fn ensure_enclave_image(repo: &Path, sudo: bool) -> Result<()> {
    let present = base_cmd("docker", sudo)
        .args(["image", "inspect", "outbe-tee-enclave-gramine"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if present {
        return Ok(());
    }
    let ctx = repo.join("bin/outbe-tee-enclave/gramine");
    let status = base_cmd("docker", sudo)
        .args([
            "build",
            "-t",
            "outbe-tee-enclave-gramine",
            &ctx.display().to_string(),
        ])
        .status()
        .wrap_err("docker build outbe-tee-enclave-gramine")?;
    if !status.success() {
        bail!("docker build outbe-tee-enclave-gramine failed");
    }
    Ok(())
}

/// `docker run` the enclave in the **foreground** (no `-d`) as an owned child,
/// returning a guard that kills the client + `docker rm -f`s the container on drop.
/// The caller waits on socket readiness with [`wait_tcp`].
pub(crate) fn spawn_enclave(spec: EnclaveSpec) -> Result<EnclaveGuard> {
    // Remove any stale container of the same name first.
    docker_rm(&spec.name, spec.sudo);

    let mut cmd = base_cmd("docker", spec.sudo);
    cmd.args([
        "run",
        "--name",
        &spec.name,
        "--security-opt",
        "seccomp=unconfined",
        "--network",
        "host",
    ]);

    // Real SGX: pass through the device nodes when present (mock stays emulated).
    if !spec.mock && Path::new("/dev/sgx_enclave").exists() {
        cmd.args(["--device", "/dev/sgx_enclave"]);
        if Path::new("/dev/sgx_provision").exists() {
            cmd.args(["--device", "/dev/sgx_provision"]);
        }
        if Path::new("/var/run/aesmd/aesm.socket").exists() {
            cmd.args([
                "-v",
                "/var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket",
            ]);
        }
    }

    // Sealed-restart persistent mount.
    if let Some(seal) = &spec.seal {
        fs::create_dir_all(&seal.tee_dir)?;
        let tee_dir = seal.tee_dir.canonicalize().unwrap_or(seal.tee_dir.clone());
        cmd.args(["-v", &format!("{}:/tee", tee_dir.display())]);
    }

    // Host enclave binary (canonicalized so docker gets an absolute path).
    let bin = spec
        .enclave_bin
        .canonicalize()
        .unwrap_or_else(|_| spec.enclave_bin.clone());
    cmd.args([
        "-v",
        &format!("{}:/app/outbe-tee-enclave:ro", bin.display()),
        "outbe-tee-enclave-gramine",
        "--socket",
        &format!("127.0.0.1:{}", spec.tee_port),
    ]);
    if let Some(seed) = &spec.dkg_seed {
        cmd.args(["--dkg-seed", seed]);
    }
    if let Some(seal) = &spec.seal {
        cmd.args(["--tee-dir", "/tee", "--chain-id", &seal.chain_id_hex]);
    }

    // Foreground: own the `docker run` child, stream its logs to <node>/enclave.log.
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&spec.log_path)
        .wrap_err_with(|| format!("open {}", spec.log_path.display()))?;
    let log2 = log.try_clone()?;
    cmd.stdout(Stdio::from(log))
        .stderr(Stdio::from(log2))
        .stdin(Stdio::null());

    if spec.debug {
        let prog = cmd.get_program().to_string_lossy().into_owned();
        let rest: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        eprintln!(
            "[localnet] enclave {} (tee {}): {prog} {}",
            spec.name,
            spec.tee_port,
            rest.join(" ")
        );
        eprintln!("           log: {}", spec.log_path.display());
    }

    let child = ChildGuard::spawn(format!("enclave {}", spec.name), cmd)?;
    Ok(EnclaveGuard {
        child,
        docker: DockerGuard::new(spec.name, spec.sudo),
    })
}

/// A `Command` for `program`, `sudo`-wrapped when requested.
pub(crate) fn base_cmd(program: &str, sudo: bool) -> Command {
    if sudo {
        let mut c = Command::new("sudo");
        c.arg(program);
        c
    } else {
        Command::new(program)
    }
}

/// Best-effort `docker rm -f <name>`.
pub(crate) fn docker_rm(name: &str, sudo: bool) {
    let _ = base_cmd("docker", sudo)
        .args(["rm", "-f", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Redirect a spawned node's stdout+stderr to `<node_dir>/node.log` (append),
/// with no stdin — the owned-process analogue of the shell `>> node.log 2>&1`.
pub(crate) fn attach_log(cmd: &mut Command, node_dir: &Path) -> Result<()> {
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(node_dir.join("node.log"))?;
    let log2 = log.try_clone()?;
    cmd.stdout(Stdio::from(log))
        .stderr(Stdio::from(log2))
        .stdin(Stdio::null());
    Ok(())
}

/// Whitespace-stripped file contents (`tr -d '[:space:]'`).
pub(crate) fn read_trimmed(path: &Path) -> Result<String> {
    Ok(fs::read_to_string(path)?
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect())
}

/// The `0x`-prefixed EVM key from `<vd>/evm-key.hex`.
pub(crate) fn read_evm_key(vd: &Path) -> Result<String> {
    let hex = read_trimmed(&vd.join("evm-key.hex"))?;
    Ok(if hex.starts_with("0x") {
        hex
    } else {
        format!("0x{hex}")
    })
}

/// 32 random bytes as hex (was `python3 secrets.token_hex(32)` / `openssl rand`).
pub(crate) fn random_hex_32() -> Result<String> {
    let mut buf = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(hex::encode(buf))
}

/// The first run of `>= min_len` hex digits in `s` (keygen pubkey/signature).
pub(crate) fn first_hex(s: &str, min_len: usize) -> Option<String> {
    let mut cur = String::new();
    for c in s.chars() {
        if c.is_ascii_hexdigit() {
            cur.push(c);
        } else {
            if cur.len() >= min_len {
                return Some(cur);
            }
            cur.clear();
        }
    }
    (cur.len() >= min_len).then_some(cur)
}

/// Wait for a TCP listener on `127.0.0.1:port` (enclave socket readiness).
pub(crate) fn wait_tcp(port: u16, tries: u32) -> bool {
    let addr = format!("127.0.0.1:{port}");
    for _ in 0..tries {
        if TcpStream::connect(&addr).is_ok() {
            return true;
        }
        sleep(Duration::from_millis(100));
    }
    false
}

/// Run `program args…`, returning stdout on success or an error carrying stderr.
pub(crate) fn run_capture(program: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .wrap_err_with(|| format!("run {}", program.display()))?;
    if !out.status.success() {
        return Err(eyre!(
            "{} {:?} failed: {}",
            program.display(),
            args,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_hex_runs() {
        assert_eq!(
            first_hex("pub: abcdef0123", 6),
            Some("abcdef0123".to_string())
        );
        assert_eq!(first_hex("0xDEAD 12", 4), Some("DEAD".to_string()));
        assert_eq!(first_hex("short ab", 4), None);
    }

    #[test]
    fn args_stringifies_display_tokens() {
        let port: u16 = 8545;
        let path = PathBuf::from("/tmp/x/data");
        let a = args!["node", "--http.port", port, "--datadir", path.display()];
        assert_eq!(a, vec!["node", "--http.port", "8545", "--datadir", "/tmp/x/data"]);
    }
}
