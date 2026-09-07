use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::ValueEnum;
use cucumber::gherkin::{Feature, Scenario};
use eyre::{bail, ensure, Result, WrapErr};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::env::{Environment, TeeMode};
use crate::ocomp_evidence::{hash_file, MemberDigestV1};

const BUILD_MANIFEST_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum BuildLane {
    Mock,
    MockNative,
    SgxNoAttest,
    Dcap,
    GramineDirect,
    RadicleSgx,
}

impl BuildLane {
    fn accepts(self, tee: TeeMode) -> bool {
        matches!(
            (self, tee),
            (Self::Mock, TeeMode::Mock)
                | (Self::MockNative, TeeMode::MockNative)
                | (Self::SgxNoAttest | Self::RadicleSgx, TeeMode::SgxNoAttest)
                | (Self::Dcap, TeeMode::Real)
                | (Self::GramineDirect, TeeMode::GramineDirect)
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFingerprintV1 {
    git_sha: String,
    workspace_sha256: String,
    cargo_lock_sha256: String,
    rust_toolchain_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentity {
    requested_path: PathBuf,
    canonical_path: PathBuf,
    digest: MemberDigestV1,
    executable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildManifestV1 {
    schema_version: u32,
    lane: BuildLane,
    source: SourceFingerprintV1,
    cargo_commands: Vec<Vec<String>>,
    artifacts: BTreeMap<String, ArtifactIdentity>,
}

#[derive(Debug)]
pub struct ArtifactLedger {
    manifest_path: Option<PathBuf>,
    manifest: Option<BuildManifestV1>,
}

impl ArtifactLedger {
    pub(crate) fn new(env: &Environment) -> Self {
        Self {
            manifest_path: env.artifact_manifest.clone(),
            manifest: None,
        }
    }

    fn load(&mut self, env: &Environment) -> Result<&BuildManifestV1> {
        if self.manifest.is_none() {
            let manifest_path = env.artifact_manifest.as_ref().ok_or_else(|| {
                eyre::eyre!(
                    "--artifact-manifest is required; build the lane with outbe-e2e-build first"
                )
            })?;
            let bytes = fs::read(manifest_path)
                .wrap_err_with(|| format!("read E2E build manifest {}", manifest_path.display()))?;
            let manifest: BuildManifestV1 = serde_json::from_slice(&bytes).wrap_err_with(|| {
                format!("decode E2E build manifest {}", manifest_path.display())
            })?;
            ensure!(
                manifest.schema_version == BUILD_MANIFEST_SCHEMA_VERSION,
                "unsupported E2E build manifest schema {}",
                manifest.schema_version
            );
            ensure!(
                manifest.lane.accepts(env.tee_mode),
                "E2E build lane {:?} cannot run TEE profile {}",
                manifest.lane,
                env.tee_mode.evidence_name()
            );
            ensure!(
                source_fingerprint(&env.repo)? == manifest.source,
                "E2E build manifest source differs from the current checkout"
            );
            self.manifest = Some(manifest);
        }
        Ok(self.manifest.as_ref().expect("manifest loaded"))
    }

    pub(crate) fn preflight_scenario(
        &mut self,
        env: &Environment,
        feature: &Feature,
        scenario: &Scenario,
    ) -> Result<()> {
        self.load(env)?;
        let manifest = self.manifest.as_ref().expect("manifest loaded");
        for spec in required_artifacts(env, feature, scenario)? {
            let expected = manifest.artifacts.get(spec.name).ok_or_else(|| {
                eyre::eyre!(
                    "E2E build manifest for {:?} does not contain required artifact {}",
                    manifest.lane,
                    spec.name
                )
            })?;
            let actual = identify(&spec.path, spec.executable)
                .wrap_err_with(|| format!("preflight required E2E artifact {}", spec.name))?;
            ensure!(
                *expected == actual,
                "E2E artifact {} differs from build manifest: expected {expected:?}, actual {actual:?}",
                spec.name
            );
        }
        Ok(())
    }

    pub(crate) fn snapshot(&self, env: &Environment) -> Result<serde_json::Value> {
        let Some(manifest) = &self.manifest else {
            return Ok(serde_json::json!({ "status": "not-loaded" }));
        };
        ensure!(
            source_fingerprint(&env.repo)? == manifest.source,
            "source checkout changed during the E2E run"
        );
        for (name, expected) in &manifest.artifacts {
            let actual = identify(&expected.requested_path, expected.executable)
                .wrap_err_with(|| format!("finalize E2E artifact {name}"))?;
            ensure!(
                *expected == actual,
                "E2E artifact {name} changed during the run: expected {expected:?}, actual {actual:?}"
            );
        }
        let manifest_path = self
            .manifest_path
            .as_deref()
            .expect("loaded manifest has a path");
        Ok(serde_json::json!({
            "build_manifest": identify(manifest_path, false)?,
            "lane": manifest.lane,
            "source": manifest.source,
            "cargo_commands": manifest.cargo_commands,
            "members": manifest.artifacts,
        }))
    }
}

#[derive(Clone, Debug)]
struct ArtifactSpec {
    name: &'static str,
    path: PathBuf,
    executable: bool,
}

pub fn build_lane(repo: &Path, lane: BuildLane, jobs: usize, output: &Path) -> Result<()> {
    ensure!((1..=8).contains(&jobs), "--jobs must be between 1 and 8");
    let repo = repo
        .canonicalize()
        .wrap_err_with(|| format!("canonicalize repository {}", repo.display()))?;
    let source_before = source_fingerprint(&repo)?;
    let commands = build_commands(lane, jobs);
    for arguments in &commands {
        run_cargo(&repo, arguments)?;
    }
    let source_after = source_fingerprint(&repo)?;
    ensure!(
        source_before == source_after,
        "source checkout changed while the E2E artifact set was being built"
    );

    let mut artifacts = BTreeMap::new();
    for spec in lane_artifacts(&repo, lane) {
        let identity = identify(&spec.path, spec.executable)
            .wrap_err_with(|| format!("record built E2E artifact {}", spec.name))?;
        ensure!(
            artifacts.insert(spec.name.to_owned(), identity).is_none(),
            "duplicate E2E artifact name {}",
            spec.name
        );
    }
    let manifest = BuildManifestV1 {
        schema_version: BUILD_MANIFEST_SCHEMA_VERSION,
        lane,
        source: source_after,
        cargo_commands: commands,
        artifacts,
    };
    publish_manifest(output, &manifest)?;
    eprintln!(
        "outbe-e2e-build: published {:?} artifact manifest {}",
        lane,
        output.display()
    );
    Ok(())
}

fn build_commands(lane: BuildLane, jobs: usize) -> Vec<Vec<String>> {
    let jobs = jobs.to_string();
    let mut commands = vec![strings(&[
        "build",
        "--locked",
        "--release",
        "-j",
        &jobs,
        "-p",
        "outbe-chain",
        "--features",
        "e2e-test,test-protocol-overrides",
        "--bin",
        "outbe-chain",
    ])];

    if !matches!(lane, BuildLane::Dcap) {
        commands.push(strings(&[
            "build",
            "--locked",
            "--release",
            "-j",
            &jobs,
            "-p",
            "outbe-ocomp",
            "--bin",
            "outbe-ocomp",
            "-p",
            "outbe-feeder",
            "--bin",
            "outbe-feeder",
        ]));
    }
    // Every validator launches this host sidecar, independently of TEE mode
    // and whether a scenario exercises repository publication.
    commands.push(strings(&[
        "build",
        "--locked",
        "--release",
        "-j",
        &jobs,
        "-p",
        "outbe-radicle-sidecar",
        "--bin",
        "outbe-radicle",
    ]));
    commands.push(strings(&[
        "build",
        "--locked",
        "--release",
        "-j",
        &jobs,
        "--bin",
        "outbe-cli",
        "--bin",
        "outbe-keygen",
    ]));

    let mut enclave = strings(&[
        "build",
        "--locked",
        "--release",
        "-j",
        &jobs,
        "-p",
        "outbe-tee-enclave",
    ]);
    match lane {
        BuildLane::Mock | BuildLane::MockNative => enclave.extend(strings(&[
            "--features",
            "mock",
            "--bin",
            "outbe-tee-enclave-mock",
        ])),
        BuildLane::Dcap => enclave.extend(strings(&[
            "--features",
            "production-dcap-release",
            "--bin",
            "outbe-tee-enclave",
        ])),
        _ => enclave.extend(strings(&["--bin", "outbe-tee-enclave"])),
    }
    commands.push(enclave);

    if matches!(
        lane,
        BuildLane::Mock | BuildLane::SgxNoAttest | BuildLane::RadicleSgx
    ) {
        commands.push(strings(&[
            "build",
            "--locked",
            "--release",
            "-j",
            &jobs,
            "--manifest-path",
            "../outbe-heartwood/Cargo.toml",
            "--bin",
            "rad",
            "--bin",
            "git-remote-rad",
        ]));
    }
    commands.push(strings(&[
        "build",
        "--locked",
        "--release",
        "-j",
        &jobs,
        "-p",
        "outbe-e2e-harness",
        "--features",
        "ocomp-integration",
        "--bin",
        "outbe-e2e",
    ]));
    commands
}

fn run_cargo(repo: &Path, arguments: &[String]) -> Result<()> {
    eprintln!("+ cargo {}", arguments.join(" "));
    let status = Command::new("cargo")
        .args(arguments)
        .current_dir(repo)
        .status()
        .wrap_err_with(|| format!("start cargo {}", arguments.join(" ")))?;
    ensure!(
        status.success(),
        "cargo {} failed with {status}",
        arguments.join(" ")
    );
    Ok(())
}

fn lane_artifacts(repo: &Path, lane: BuildLane) -> Vec<ArtifactSpec> {
    let release = repo.join("target/release");
    let mut artifacts = vec![
        artifact("outbe_e2e", release.join("outbe-e2e"), true),
        artifact("outbe_chain", release.join("outbe-chain"), true),
        artifact("outbe_cli", release.join("outbe-cli"), true),
        artifact("outbe_keygen", release.join("outbe-keygen"), true),
        artifact("outbe_radicle", release.join("outbe-radicle"), true),
        artifact(
            "genesis_seed",
            repo.join("scripts/seed-testnet-lowstake.json"),
            false,
        ),
    ];
    artifacts.push(match lane {
        BuildLane::Mock | BuildLane::MockNative => artifact(
            "outbe_tee_enclave_mock",
            release.join("outbe-tee-enclave-mock"),
            true,
        ),
        _ => artifact("outbe_tee_enclave", release.join("outbe-tee-enclave"), true),
    });
    if !matches!(lane, BuildLane::Dcap) {
        artifacts.extend([
            artifact("outbe_ocomp", release.join("outbe-ocomp"), true),
            artifact("outbe_feeder", release.join("outbe-feeder"), true),
        ]);
    }
    if matches!(
        lane,
        BuildLane::Mock | BuildLane::SgxNoAttest | BuildLane::RadicleSgx
    ) {
        let heartwood = repo
            .parent()
            .unwrap_or(repo)
            .join("outbe-heartwood/target/release");
        artifacts.extend([
            artifact("rad", heartwood.join("rad"), true),
            artifact("git_remote_rad", heartwood.join("git-remote-rad"), true),
        ]);
    }
    artifacts
}

fn required_artifacts(
    env: &Environment,
    feature: &Feature,
    scenario: &Scenario,
) -> Result<Vec<ArtifactSpec>> {
    let current_exe = std::env::current_exe().wrap_err("resolve exact outbe-e2e binary")?;
    let mut artifacts = vec![
        artifact("outbe_e2e", current_exe, true),
        artifact("outbe_chain", env.chain_bin.clone(), true),
        artifact("outbe_cli", env.cli_bin.clone(), true),
        artifact("outbe_keygen", env.keygen_bin.clone(), true),
        artifact(
            "outbe_radicle",
            env.repo.join("target/release/outbe-radicle"),
            true,
        ),
        artifact(
            if env.tee_mode.uses_mock_binary() {
                "outbe_tee_enclave_mock"
            } else {
                "outbe_tee_enclave"
            },
            env.selected_enclave_bin().to_path_buf(),
            true,
        ),
        artifact("genesis_seed", env.seed.clone(), false),
    ];
    if tagged(feature, scenario, "ocomp") {
        artifacts.push(artifact("outbe_ocomp", env.ocomp_bin.clone(), true));
    }
    if tagged(feature, scenario, "price-oracle") {
        artifacts.push(artifact("outbe_feeder", env.feeder_bin.clone(), true));
    }
    if tagged(feature, scenario, "radicle") {
        let heartwood = env
            .repo
            .parent()
            .unwrap_or(&env.repo)
            .join("outbe-heartwood/target/release");
        artifacts.extend([
            artifact("rad", heartwood.join("rad"), true),
            artifact("git_remote_rad", heartwood.join("git-remote-rad"), true),
        ]);
    }
    if let Some(upgraded) = &env.upgraded_chain_bin {
        artifacts.push(artifact("outbe_chain_upgraded", upgraded.clone(), true));
    }
    Ok(artifacts)
}

fn artifact(name: &'static str, path: PathBuf, executable: bool) -> ArtifactSpec {
    ArtifactSpec {
        name,
        path,
        executable,
    }
}

fn tagged(feature: &Feature, scenario: &Scenario, tag: &str) -> bool {
    feature
        .tags
        .iter()
        .chain(&scenario.tags)
        .any(|value| value == tag)
}

fn identify(path: &Path, executable: bool) -> Result<ArtifactIdentity> {
    let metadata = fs::symlink_metadata(path)
        .wrap_err_with(|| format!("inspect requested path {}", path.display()))?;
    ensure!(
        metadata.is_file(),
        "{} is not a regular file",
        path.display()
    );
    if executable {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            ensure!(
                metadata.permissions().mode() & 0o111 != 0,
                "{} is not executable",
                path.display()
            );
        }
    }
    let canonical_path = path
        .canonicalize()
        .wrap_err_with(|| format!("canonicalize {}", path.display()))?;
    let digest = hash_file(&canonical_path)?;
    Ok(ArtifactIdentity {
        requested_path: path.to_path_buf(),
        canonical_path,
        digest,
        executable,
    })
}

fn source_fingerprint(repo: &Path) -> Result<SourceFingerprintV1> {
    let git_sha = command_stdout(repo, "git", &["rev-parse", "HEAD"])?;
    let diff = command_output(repo, "git", &["diff", "--binary", "HEAD", "--", "."])?;
    let untracked = command_output(
        repo,
        "git",
        &["ls-files", "--others", "--exclude-standard", "-z"],
    )?;
    let mut hasher = Sha256::new();
    hash_component(&mut hasher, git_sha.as_bytes());
    hash_component(&mut hasher, &diff);
    for relative in untracked
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let relative = Path::new(OsStr::from_bytes(relative));
        hash_component(&mut hasher, relative.as_os_str().as_encoded_bytes());
        let path = repo.join(relative);
        let metadata = fs::symlink_metadata(&path)
            .wrap_err_with(|| format!("inspect untracked source {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            hash_component(
                &mut hasher,
                fs::read_link(&path)
                    .wrap_err_with(|| format!("read untracked symlink {}", path.display()))?
                    .as_os_str()
                    .as_encoded_bytes(),
            );
        } else if metadata.is_file() {
            hash_component(
                &mut hasher,
                &fs::read(&path)
                    .wrap_err_with(|| format!("read untracked source {}", path.display()))?,
            );
        } else {
            bail!("untracked source is not a file: {}", path.display());
        }
    }
    Ok(SourceFingerprintV1 {
        git_sha,
        workspace_sha256: hex::encode(hasher.finalize()),
        cargo_lock_sha256: hash_file(&repo.join("Cargo.lock"))?.sha256,
        rust_toolchain_sha256: hash_file(&repo.join("rust-toolchain.toml"))?.sha256,
    })
}

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;

fn hash_component(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

fn command_stdout(repo: &Path, program: &str, arguments: &[&str]) -> Result<String> {
    let bytes = command_output(repo, program, arguments)?;
    let output =
        String::from_utf8(bytes).wrap_err_with(|| format!("{program} output is not UTF-8"))?;
    let output = output.trim();
    ensure!(!output.is_empty(), "{program} produced empty output");
    Ok(output.to_owned())
}

fn command_output(repo: &Path, program: &str, arguments: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new(program)
        .args(arguments)
        .current_dir(repo)
        .output()
        .wrap_err_with(|| format!("run {program} {}", arguments.join(" ")))?;
    ensure!(
        output.status.success(),
        "{program} {} failed: {}",
        arguments.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output.stdout)
}

fn publish_manifest(path: &Path, manifest: &BuildManifestV1) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .wrap_err_with(|| format!("create E2E manifest directory {}", parent.display()))?;
    let mut bytes = serde_json::to_vec_pretty(manifest)?;
    bytes.push(b'\n');
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(OsStr::to_str)
            .unwrap_or("manifest"),
        std::process::id()
    ));
    fs::write(&temporary, bytes)
        .wrap_err_with(|| format!("write temporary E2E manifest {}", temporary.display()))?;
    fs::rename(&temporary, path)
        .wrap_err_with(|| format!("publish E2E manifest {}", path.display()))?;
    Ok(())
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cucumber::gherkin::GherkinEnv;

    #[test]
    fn missing_artifact_fails_closed() {
        let error = identify(Path::new("/definitely/missing/outbe-e2e-artifact"), true)
            .expect_err("missing binary must fail preflight");
        assert!(error.to_string().contains("inspect requested path"));
    }

    #[cfg(unix)]
    #[test]
    fn non_executable_binary_fails_closed() {
        let directory = tempfile::tempdir().expect("temporary artifact directory");
        let path = directory.path().join("binary");
        fs::write(&path, b"not executable").expect("write artifact");
        let error = identify(&path, true).expect_err("non-executable binary must fail preflight");
        assert!(error.to_string().contains("not executable"));
    }

    #[test]
    fn lane_and_tee_profiles_are_not_interchangeable() {
        assert!(BuildLane::SgxNoAttest.accepts(TeeMode::SgxNoAttest));
        assert!(BuildLane::RadicleSgx.accepts(TeeMode::SgxNoAttest));
        assert!(!BuildLane::Dcap.accepts(TeeMode::SgxNoAttest));
        assert!(!BuildLane::SgxNoAttest.accepts(TeeMode::Real));
        assert!(!BuildLane::Mock.accepts(TeeMode::MockNative));
        assert!(BuildLane::MockNative.accepts(TeeMode::MockNative));
        assert!(!BuildLane::MockNative.accepts(TeeMode::GramineDirect));
        assert!(!BuildLane::MockNative.accepts(TeeMode::Real));
    }

    #[test]
    fn every_lane_builds_and_records_the_validator_sidecar() {
        for &lane in BuildLane::value_variants() {
            let commands = build_commands(lane, 4);
            assert_eq!(
                commands
                    .iter()
                    .filter(|args| args
                        .windows(2)
                        .any(|pair| pair == ["--bin", "outbe-radicle"]))
                    .count(),
                1,
                "{lane:?} must build the sidecar exactly once"
            );
            let artifacts = lane_artifacts(Path::new("/fixture/repo"), lane);
            assert_eq!(
                artifacts
                    .iter()
                    .filter(|spec| spec.name == "outbe_radicle")
                    .count(),
                1,
                "{lane:?} must record the sidecar exactly once"
            );
            let repository_tools = matches!(
                lane,
                BuildLane::Mock | BuildLane::SgxNoAttest | BuildLane::RadicleSgx
            );
            for name in ["rad", "git_remote_rad"] {
                assert_eq!(
                    artifacts.iter().any(|spec| spec.name == name),
                    repository_tools,
                    "{lane:?} repository tool {name}"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_scenarios_require_the_configured_sidecar_but_not_repository_tools() {
        let (_directory, mut env, mut feature, _) = manifest_fixture();
        for tee in [
            TeeMode::Mock,
            TeeMode::MockNative,
            TeeMode::GramineDirect,
            TeeMode::SgxNoAttest,
            TeeMode::Real,
        ] {
            env.tee_mode = tee;
            let specs = required_artifacts(&env, &feature, &feature.scenarios[0])
                .expect("ordinary scenario artifacts");
            let sidecar = specs
                .iter()
                .find(|spec| spec.name == "outbe_radicle")
                .expect("validators always launch a sidecar");
            assert_eq!(
                sidecar.path,
                crate::internal::config::Config::resolve(&env).bin_radicle
            );
            assert!(sidecar.executable);
            assert!(!specs
                .iter()
                .any(|spec| matches!(spec.name, "rad" | "git_remote_rad")));
        }
        for feature_tag in [true, false] {
            feature.tags.clear();
            feature.scenarios[0].tags.clear();
            if feature_tag {
                feature.tags.push("radicle".to_owned());
            } else {
                feature.scenarios[0].tags.push("radicle".to_owned());
            }
            let specs = required_artifacts(&env, &feature, &feature.scenarios[0])
                .expect("repository scenario artifacts");
            for name in ["outbe_radicle", "rad", "git_remote_rad"] {
                assert_eq!(specs.iter().filter(|spec| spec.name == name).count(), 1);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn untagged_scenario_rejects_missing_or_changed_sidecar_before_execution() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        for mutation in ["member", "file", "bytes", "permissions", "symlink", "path"] {
            let (directory, mut env, feature, mut manifest) = manifest_fixture();
            let sidecar = crate::internal::config::Config::resolve(&env).bin_radicle;
            match mutation {
                "member" => {
                    manifest.artifacts.remove("outbe_radicle");
                }
                "file" => fs::remove_file(&sidecar).expect("remove fixture sidecar"),
                "bytes" => fs::write(&sidecar, b"stale sidecar").expect("replace sidecar bytes"),
                "permissions" => fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o644))
                    .expect("remove execute permission"),
                "symlink" => {
                    let target = directory.path().join("sidecar-target");
                    fs::rename(&sidecar, &target).expect("move fixture sidecar");
                    symlink(&target, &sidecar).expect("replace fixture with symlink");
                }
                "path" => {
                    let other = directory.path().join("other-sidecar");
                    fs::copy(&sidecar, &other).expect("copy identical bytes to another path");
                    manifest.artifacts.insert(
                        "outbe_radicle".to_owned(),
                        identify(&other, true).expect("identify alternative sidecar"),
                    );
                }
                _ => unreachable!(),
            }
            let manifest_path = directory.path().join("artifacts.json");
            publish_manifest(&manifest_path, &manifest).expect("publish fixture manifest");
            env.artifact_manifest = Some(manifest_path);
            let error = ArtifactLedger::new(&env)
                .preflight_scenario(&env, &feature, &feature.scenarios[0])
                .expect_err("untagged scenario must reject invalid sidecar before execution");
            assert!(
                error.to_string().contains("outbe_radicle"),
                "{mutation}: {error:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn untagged_sidecar_is_rechecked_before_final_evidence() {
        let (directory, mut env, feature, manifest) = manifest_fixture();
        let manifest_path = directory.path().join("artifacts.json");
        publish_manifest(&manifest_path, &manifest).expect("publish fixture manifest");
        env.artifact_manifest = Some(manifest_path);
        let sidecar = crate::internal::config::Config::resolve(&env).bin_radicle;
        let mut ledger = ArtifactLedger::new(&env);
        ledger
            .preflight_scenario(&env, &feature, &feature.scenarios[0])
            .expect("exact untagged scenario accepted without repository tools");
        let snapshot = ledger.snapshot(&env).expect("unchanged final evidence");
        assert_eq!(
            snapshot["members"]["outbe_radicle"],
            serde_json::to_value(identify(&sidecar, true).expect("exact sidecar identity"))
                .expect("serialize identity")
        );
        fs::write(&sidecar, b"changed after preflight").expect("tamper sidecar after preflight");
        let error = ledger
            .snapshot(&env)
            .expect_err("finalization must reject changed sidecar");
        assert!(error
            .to_string()
            .contains("outbe_radicle changed during the run"));
    }

    #[test]
    fn source_fingerprint_detects_tracked_and_untracked_changes() {
        let directory = tempfile::tempdir().expect("temporary git repository");
        let repo = directory.path();
        git(repo, &["init"]);
        git(repo, &["config", "user.email", "e2e@example.invalid"]);
        git(repo, &["config", "user.name", "E2E Test"]);
        fs::write(repo.join("Cargo.lock"), b"lock-v1").expect("write Cargo.lock");
        fs::write(repo.join("rust-toolchain.toml"), b"toolchain-v1").expect("write toolchain");
        fs::write(repo.join("source.rs"), b"source-v1").expect("write source");
        git(repo, &["add", "."]);
        git(repo, &["commit", "-m", "fixture"]);

        let clean = source_fingerprint(repo).expect("clean source fingerprint");
        fs::write(repo.join("source.rs"), b"source-v2").expect("modify tracked source");
        let tracked = source_fingerprint(repo).expect("tracked source fingerprint");
        assert_ne!(clean, tracked);

        fs::write(repo.join("source.rs"), b"source-v1").expect("restore tracked source");
        fs::write(repo.join("new.rs"), b"untracked").expect("write untracked source");
        let untracked = source_fingerprint(repo).expect("untracked source fingerprint");
        assert_ne!(clean, untracked);
    }

    #[cfg(unix)]
    #[test]
    fn scenario_preflight_accepts_exact_manifest_then_rejects_binary_tampering() {
        let (directory, mut env, feature, manifest) = manifest_fixture();
        let manifest_path = directory.path().join("artifacts.json");
        publish_manifest(&manifest_path, &manifest).expect("publish fixture manifest");
        env.artifact_manifest = Some(manifest_path);

        let mut ledger = ArtifactLedger::new(&env);
        ledger
            .preflight_scenario(&env, &feature, &feature.scenarios[0])
            .expect("exact manifest accepted");

        fs::write(&env.chain_bin, b"tampered executable").expect("tamper executable");
        let error = ledger
            .preflight_scenario(&env, &feature, &feature.scenarios[0])
            .expect_err("tampered executable must be rejected");
        assert!(error.to_string().contains("differs from build manifest"));
    }

    #[cfg(unix)]
    #[test]
    fn scenario_preflight_rejects_foreign_source_fingerprint() {
        let (directory, mut env, feature, mut manifest) = manifest_fixture();
        manifest.source.workspace_sha256 = "00".repeat(32);
        let manifest_path = directory.path().join("artifacts.json");
        publish_manifest(&manifest_path, &manifest).expect("publish fixture manifest");
        env.artifact_manifest = Some(manifest_path);

        let error = ArtifactLedger::new(&env)
            .preflight_scenario(&env, &feature, &feature.scenarios[0])
            .expect_err("foreign source fingerprint must be rejected");
        assert!(error
            .to_string()
            .contains("source differs from the current checkout"));
    }

    #[cfg(unix)]
    fn manifest_fixture() -> (tempfile::TempDir, Environment, Feature, BuildManifestV1) {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("temporary artifact set");
        let repo = directory.path().join("repo");
        fs::create_dir_all(repo.join("target/release")).expect("fixture release directory");
        git(&repo, &["init"]);
        git(&repo, &["config", "user.email", "e2e@example.invalid"]);
        git(&repo, &["config", "user.name", "E2E Test"]);
        for (name, bytes) in [
            ("Cargo.lock", "lock"),
            ("rust-toolchain.toml", "toolchain"),
            (".gitignore", "/target/\n"),
        ] {
            fs::write(repo.join(name), bytes).expect("write fixture source");
        }
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-m", "fixture"]);
        let sidecar = repo.join("target/release/outbe-radicle");
        fs::write(&sidecar, b"sidecar").expect("write fixture sidecar");
        fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o755))
            .expect("make sidecar executable");
        let mut env = Environment {
            repo,
            ..Environment::default()
        };
        for (path, file_name, bytes) in [
            (&mut env.chain_bin, "chain", b"chain".as_slice()),
            (&mut env.cli_bin, "cli", b"cli".as_slice()),
            (&mut env.keygen_bin, "keygen", b"keygen".as_slice()),
            (&mut env.mock_bin, "enclave", b"enclave".as_slice()),
        ] {
            *path = directory.path().join(file_name);
            fs::write(&*path, bytes).expect("write executable fixture");
            fs::set_permissions(&*path, fs::Permissions::from_mode(0o755))
                .expect("make fixture executable");
        }
        env.seed = directory.path().join("seed.json");
        fs::write(&env.seed, b"seed").expect("write seed fixture");

        let feature = Feature::parse(
            "Feature: artifact preflight\n  Scenario: exact binaries\n    Given a runtime\n",
            GherkinEnv::default(),
        )
        .expect("parse artifact fixture feature");
        let artifacts = required_artifacts(&env, &feature, &feature.scenarios[0])
            .expect("resolve required fixture artifacts")
            .into_iter()
            .map(|spec| {
                let identity =
                    identify(&spec.path, spec.executable).expect("identify fixture artifact");
                (spec.name.to_owned(), identity)
            })
            .collect();
        let manifest = BuildManifestV1 {
            schema_version: BUILD_MANIFEST_SCHEMA_VERSION,
            lane: BuildLane::Mock,
            source: source_fingerprint(&env.repo).expect("source fingerprint"),
            cargo_commands: Vec::new(),
            artifacts,
        };
        (directory, env, feature, manifest)
    }

    fn git(repo: &Path, arguments: &[&str]) {
        let output = Command::new("git")
            .args(["-c", "commit.gpgsign=false"])
            .args(arguments)
            .current_dir(repo)
            .output()
            .expect("start git fixture command");
        assert!(
            output.status.success(),
            "git fixture command failed: {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
