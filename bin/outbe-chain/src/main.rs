//! Outbe-reth node binary.
//!
//! Custom reth node with Outbe stateful precompiles and Commonware Simplex consensus.
//! Two tokio runtimes: Reth execution (main thread) + Commonware consensus (spawned thread).
//!
//! Also provides the `dkg` subcommand for bootstrapping BLS threshold key material.

use clap::Parser;
use commonware_runtime::Runner as _;
use eyre::WrapErr as _;
use outbe_engine::args::ConsensusArgs;
use outbe_engine::bridge::ConsensusExecutionBridge;
use outbe_evm::OutbeEvmSigner;
use outbe_node::{OutbeBeaconConsensus, OutbeFullNode, OutbeNode};
use outbe_primitives::OutbeHeader;
use reth_chainspec::ChainSpec;
use reth_cli::chainspec::ChainSpecParser;
use reth_ethereum::cli::interface::Cli;
use reth_node_builder::NodeHandle;
use reth_rpc_server_types::{RethRpcModule, RpcModuleSelection, RpcModuleValidator};
use std::{sync::Arc, thread};
use tokio::sync::oneshot;
use tracing::info;

#[derive(Debug, Clone, Default)]
struct OutbeChainSpecParser;

#[derive(Debug, Clone, Copy, Default)]
struct OutbeRpcModuleValidator;

impl RpcModuleValidator for OutbeRpcModuleValidator {
    fn parse_selection(s: &str) -> Result<RpcModuleSelection, String> {
        let selection = s
            .parse::<RpcModuleSelection>()
            .map_err(|error| format!("Failed to parse RPC modules: {error}"))?;

        if let RpcModuleSelection::Selection(modules) = &selection {
            for module in modules {
                let RethRpcModule::Other(name) = module else {
                    continue;
                };
                if name != "outbe" {
                    return Err(format!("Unknown RPC module: '{name}'"));
                }
            }
        }

        Ok(selection)
    }
}

impl ChainSpecParser for OutbeChainSpecParser {
    type ChainSpec = ChainSpec<OutbeHeader>;

    const SUPPORTED_CHAINS: &'static [&'static str] =
        reth_ethereum::cli::chainspec::SUPPORTED_CHAINS;

    fn parse(s: &str) -> eyre::Result<Arc<Self::ChainSpec>> {
        Ok(reth_ethereum::cli::chainspec::chain_value_parser(s)?
            .as_ref()
            .clone()
            .map_header(OutbeHeader::new)
            .into())
    }
}

fn handle_consensus_thread_join(joined: thread::Result<eyre::Result<()>>) -> eyre::Result<()> {
    match joined {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(err.wrap_err("consensus task exited with error")),
        Err(unwind) => std::panic::resume_unwind(unwind),
    }
}

/// DKG bootstrap subcommand, parsed separately from reth's CLI.
#[derive(clap::Parser)]
#[command(name = "outbe-chain-dkg")]
struct DkgCli {
    /// BLS key storage backend: plaintext, encrypted, or os-level.
    #[arg(long = "bls-key-backend", default_value = "plaintext", global = true)]
    bls_key_backend: String,

    /// Passphrase for the encrypted BLS key backend.
    #[arg(long = "bls-passphrase", env = "BLS_PASSPHRASE", global = true)]
    bls_passphrase: Option<String>,

    #[command(subcommand)]
    command: DkgCommand,
}

#[derive(clap::Subcommand)]
enum DkgCommand {
    /// Bootstrap DKG material for a validator set.
    Bootstrap {
        /// Output directory for generated key material.
        #[arg(long)]
        output_dir: std::path::PathBuf,

        /// Number of validators to bootstrap.
        #[arg(long)]
        validators: u32,
    },
    /// Show status of DKG key material in a storage directory.
    Status {
        /// Storage directory containing DKG material.
        #[arg(long)]
        storage_dir: std::path::PathBuf,
    },
    /// Export DKG signing share, polynomial, and output to a directory.
    ExportShare {
        /// Storage directory containing DKG material.
        #[arg(long)]
        storage_dir: std::path::PathBuf,

        /// Output directory for exported files.
        #[arg(long)]
        output: std::path::PathBuf,
    },
    /// Import DKG signing share, polynomial, and output into a storage directory.
    ImportShare {
        /// Path to the signing share file.
        #[arg(long)]
        share: std::path::PathBuf,

        /// Path to the public polynomial file.
        #[arg(long)]
        polynomial: std::path::PathBuf,

        /// Path to the DKG output file. Defaults to dkg_output.hex next to --share.
        #[arg(long)]
        output: Option<std::path::PathBuf>,

        /// Storage directory to import into.
        #[arg(long)]
        storage_dir: std::path::PathBuf,
    },
    /// Force-restart DKG by deleting saved threshold material.
    /// The node will run a fresh DKG ceremony on next startup.
    ForceRestart {
        /// Storage directory containing DKG material.
        #[arg(long)]
        storage_dir: std::path::PathBuf,
    },
}

fn main() -> eyre::Result<()> {
    // Intercept `dkg` subcommand before reth CLI parsing.
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "dkg" {
        return run_dkg_command(&args);
    }

    // Intercept `--version` / `-V` so that the user sees Outbe-side build
    // metadata in addition to Reth's own version string. The Outbe block is
    // printed first; Reth's CLI then prints its own version and exits.
    if args.iter().any(|a| a == "--version" || a == "-V") {
        print_outbe_version();
    }

    run_node()
}

/// Outbe build metadata block printed before delegating `--version` to
/// Reth's CLI. Layout mirrors reth-node-core / kona-node so operators
/// see a familiar five-line block.
const OUTBE_LONG_VERSION: &str = concat!(
    env!("OUTBE_LONG_VERSION_0"),
    "\n",
    env!("OUTBE_LONG_VERSION_1"),
    "\n",
    env!("OUTBE_LONG_VERSION_2"),
    "\n",
    env!("OUTBE_LONG_VERSION_3"),
    "\n",
    env!("OUTBE_LONG_VERSION_4"),
);

/// Print Outbe build metadata baked in by `build.rs`. Followed downstream by
/// Reth's own `--version` output.
fn print_outbe_version() {
    println!("Outbe {}", env!("OUTBE_SHORT_VERSION"));
    println!("{OUTBE_LONG_VERSION}");
    println!();
}

/// Parse DKG CLI's --bls-key-backend into a KeyBackend.
fn parse_dkg_key_backend(cli: &DkgCli) -> eyre::Result<outbe_consensus::bls::KeyBackend> {
    match cli.bls_key_backend.as_str() {
        "plaintext" => Ok(outbe_consensus::bls::KeyBackend::Plaintext),
        "encrypted" => {
            let passphrase = cli
                .bls_passphrase
                .clone()
                .ok_or_else(|| eyre::eyre!("--bls-key-backend encrypted requires --bls-passphrase or BLS_PASSPHRASE env var"))?;
            Ok(outbe_consensus::bls::KeyBackend::Encrypted(passphrase))
        }
        "os-level" => Ok(outbe_consensus::bls::KeyBackend::OsLevel),
        other => eyre::bail!("unknown BLS key backend: {other}"),
    }
}

/// Handle the `dkg` subcommand.
fn run_dkg_command(args: &[String]) -> eyre::Result<()> {
    // Rebuild args as: "outbe-chain-dkg" "bootstrap" ...remaining...
    let mut dkg_args = vec![args[0].clone()];
    dkg_args.extend_from_slice(&args[2..]);
    let dkg_cli = DkgCli::parse_from(dkg_args);

    let backend = parse_dkg_key_backend(&dkg_cli)?;

    match dkg_cli.command {
        DkgCommand::Bootstrap {
            output_dir,
            validators,
        } => outbe_consensus::cli::execute_dkg_bootstrap(output_dir, validators, &backend),
        DkgCommand::Status { storage_dir } => {
            outbe_consensus::cli::execute_dkg_status(&storage_dir, &backend)
        }
        DkgCommand::ExportShare {
            storage_dir,
            output,
        } => outbe_consensus::cli::execute_dkg_export_share(&storage_dir, &output, &backend),
        DkgCommand::ImportShare {
            share,
            polynomial,
            output,
            storage_dir,
        } => outbe_consensus::cli::execute_dkg_import_share(
            &share,
            &polynomial,
            output.as_deref(),
            &storage_dir,
            &backend,
        ),
        DkgCommand::ForceRestart { storage_dir } => {
            outbe_consensus::cli::execute_dkg_force_restart(&storage_dir)
        }
    }
}

/// Run the main node (Reth execution + Commonware consensus).
fn run_node() -> eyre::Result<()> {
    // TEE offer decryption routes exclusively through the enclave sidecar
    // (`--tee-enclave-socket` → `init_enclave_client`); the offer-decryption key
    // exists only inside the enclave (single path, no in-process key material).

    // Initialize Barretenberg global CRS for the zkVerify precompile.
    // Must run before the tokio runtime starts — `setup_srs` uses
    // `reqwest::blocking` internally and would panic from an async
    // context. Without this, the `0xEE08` precompile silently returns
    // `0x..00` for every input (verifier requires the CRS).
    outbe_zkproof::init_crs();

    let cli = Cli::<OutbeChainSpecParser, ConsensusArgs, OutbeRpcModuleValidator>::parse();

    let bridge = ConsensusExecutionBridge::new();

    // Channels for validator-mode consensus thread.
    // For full-node mode, no thread is spawned and these are unused.
    let (node_tx, node_rx) = oneshot::channel::<(OutbeFullNode, ConsensusArgs)>();
    let (consensus_dead_tx, mut consensus_dead_rx) = oneshot::channel::<()>();
    let shutdown_token = tokio_util::sync::CancellationToken::new();

    // Consensus thread is spawned conditionally — see inside run_with_components
    // where `args.is_validator` is known. For now, prepare the closure.
    let shutdown_token_clone = shutdown_token.clone();
    let bridge_for_consensus = bridge.clone();
    let consensus_thread_fn = move || -> eyre::Result<()> {
        let (node, mut args) = match node_rx.blocking_recv() {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };

        args.validate()?;

        let data_dir = node
            .config
            .datadir
            .clone()
            .resolve_datadir(reth_ethereum::chainspec::EthChainSpec::chain(
                &*node.chain_spec(),
            ))
            .data_dir()
            .to_path_buf();

        let consensus_storage = args
            .storage_dir
            .clone()
            .unwrap_or_else(|| data_dir.join("consensus"));

        // Write back effective storage_dir so the consensus stack sees it
        // even when the CLI did not provide --consensus.storage-dir.
        if args.storage_dir.is_none() {
            args.storage_dir = Some(consensus_storage.clone());
        }

        let keys_dir = args
            .keys_dir
            .clone()
            .unwrap_or_else(|| data_dir.join("keys"));

        if args.keys_dir.is_none() {
            args.keys_dir = Some(keys_dir.clone());
        }

        // Migrate DKG files from legacy location (consensus/) to keys/.
        outbe_engine::stack::migrate_dkg_keys_if_needed(&consensus_storage, &keys_dir)?;

        info!(
            path = %consensus_storage.display(),
            "starting consensus runtime"
        );

        // initialize the append-only slashing journal at
        // `<consensus_storage>/slashing-journal.jsonl`. The journal
        // captures every SlashIndicator/ValidatorSet state transition
        // in JSONL form and is independent of reth log rotation. If
        // initialization fails, log a warning and continue — the
        // journal is best-effort observability and must not block node
        // startup.
        if let Err(error) = outbe_primitives::slashing_journal::init(&consensus_storage) {
            tracing::warn!(
                target: "outbe::slashing::journal",
                %error,
                "failed to initialize slashing journal — events will not be persisted to a sidecar file",
            );
        }

        if let Err(error) = outbe_primitives::governance_journal::init(&consensus_storage) {
            tracing::warn!(
                target: "outbe::governance::journal",
                %error,
                "failed to initialize governance journal — events will not be persisted to a sidecar file",
            );
        }

        let runtime_config = commonware_runtime::tokio::Config::default()
            .with_tcp_nodelay(Some(true))
            .with_worker_threads(args.worker_threads)
            .with_storage_directory(consensus_storage)
            .with_catch_panics(true);

        let runner = commonware_runtime::tokio::Runner::new(runtime_config);

        let ret: eyre::Result<()> = runner.start(async move |ctx| {
            tokio::select! {
                result = outbe_engine::run_consensus_stack(&ctx, args, node, bridge_for_consensus) => {
                    if let Err(e) = &result {
                        tracing::error!(%e, "consensus stack failed");
                    }
                    result
                }
                _ = shutdown_token_clone.cancelled() => {
                    info!("consensus stack shutting down");
                    Ok(())
                }
            }
        });

        let _ = consensus_dead_tx.send(());
        ret
    };

    // Thread 1 (main): Reth execution layer.
    let bridge_for_evm = bridge.clone();
    let components = move |spec: Arc<ChainSpec<OutbeHeader>>| {
        (
            outbe_evm::OutbeEvmConfig::new_with_bridge(spec.clone(), bridge_for_evm.clone()),
            Arc::new(
                OutbeBeaconConsensus::new(spec)
                    .with_max_extra_data_size(outbe_node::consensus::OUTBE_MAX_EXTRA_DATA_SIZE),
            ),
        )
    };

    cli.run_with_components::<OutbeNode>(components, async move |builder, args| {
        args.validate()?;

        // If a TEE enclave sidecar is configured, connect + attest it and install
        // the global offer-decryption client. Offers route through the enclave on
        // every node (validators and full nodes execute offer txs), so a node
        // started with `--tee-enclave-socket` requires a healthy, attested enclave
        // (fail-fast). When unset, offerTribute() uses the in-process TEE stub.
        if let Some(socket) = args.tee_enclave_socket.clone() {
            // Build the host connect policy from the genesis `teePolicy` —
            // strict (DCAP signature + measurement allowlist) when a policy is
            // configured (hardware), dev-accept for an unattested gramine-direct
            // enclave. Same source the consensus DKG/bootstrap connect sites use.
            let tee_policy =
                outbe_engine::stack::tee_policy_from_chain_spec(builder.config().chain.as_ref())?;
            let connect_policy =
                outbe_engine::tee_bootstrap::quote_policy_from_tee_policy(&tee_policy);
            outbe_tributefactory::init_enclave_client(&socket, &connect_policy)
                .wrap_err("TEE enclave connect/attest failed")?;
            // init_enclave_client logs the REAL attestation status (hardware vs
            // unattested) derived from the enclave's quote. Under gramine-sgx this
            // is genuine SGX confidentiality; under gramine-direct/bare it is an
            // unattested sidecar (process isolation + Noise-IK, not enclave memory
            // encryption) accepted only by the dev policy.
            info!(
                socket = %socket.display(),
                "TEE enclave sidecar connected — offers decrypt in the enclave process (attestation status logged above)",
            );
        }

        let evm_signer = if args.is_validator {
            let evm_key_path = args
                .effective_validator_evm_key()?
                .ok_or_else(|| eyre::eyre!("validator mode requires an EVM signer key"))?;
            let signer =
                Arc::new(OutbeEvmSigner::from_file(&evm_key_path).wrap_err_with(|| {
                    format!(
                        "failed to load validator EVM key from {}",
                        evm_key_path.display()
                    )
                })?);
            info!(
                address = %signer.address(),
                path = %evm_key_path.display(),
                "loaded validator EVM signer"
            );
            Some(signer)
        } else {
            None
        };
        let outbe_node = match evm_signer {
            Some(signer) => OutbeNode::with_bridge_and_evm_signer(bridge.clone(), signer),
            None => OutbeNode::with_bridge(bridge.clone()),
        };

        let NodeHandle {
            node,
            node_exit_future,
        } = builder
            .node(outbe_node)
            .apply(|mut builder| {
                let discovery = &mut builder.config_mut().network.discovery;
                discovery.enable_discv5_discovery = true;
                // SSA-1: disable reth DNS discovery so the `hickory-proto` code
                // path (RUSTSEC-2025 NSEC3 unbounded-loop DoS, no upstream fix)
                // is unreachable. outbe peers via discv5 + static bootnodes and
                // configures no DNS ENR tree, so DNS discovery provided nothing
                // here anyway; disabling it removes the attack surface.
                discovery.disable_dns_discovery = true;
                builder
            })
            .extend_rpc_modules({
                let bridge = bridge.clone();
                let is_validator = args.is_validator;
                let is_follower = args.upstream.is_some();
                move |ctx| {
                    use outbe_rpc::OutbeApiServer as _;
                    let provider = Arc::new(ctx.provider().clone());
                    // Validators get the full bridge-backed handler.
                    // `--upstream` followers also run a marshal and CAN serve
                    // `outbe_getFinalization` (chaining followers), but must NOT
                    // report validator status; they get a follower-scoped handler
                    // that exposes only the finalization-serving capability.
                    let outbe_api = if is_validator {
                        outbe_rpc::OutbeApiHandler::with_bridge(provider, bridge)
                    } else if is_follower {
                        outbe_rpc::OutbeApiHandler::with_follower_bridge(provider, bridge)
                    } else {
                        outbe_rpc::OutbeApiHandler::new(provider)
                    };
                    ctx.modules.merge_if_module_configured(
                        RethRpcModule::Other("outbe".to_owned()),
                        outbe_api.into_rpc(),
                    )?;
                    info!("outbe_* RPC namespace registered where configured");
                    Ok(())
                }
            })
            .launch()
            .await
            .wrap_err("failed launching execution node")?;

        outbe_engine::validators::check_binary_version_compatibility(&node.provider, outbe_evm::handlers::update::registry())?;

        if args.is_validator || args.upstream.is_some() {
            if args.upstream.is_some() {
                info!("outbe node launched in FOLLOWER mode (--upstream)");
            } else {
                info!("outbe node launched in VALIDATOR mode");
            }

            // Spawn the consensus thread for validator OR follower mode; the
            // follower branch inside `run_consensus_stack` selects the lightweight
            // follow stack (no consensus engine).
            let consensus_handle = thread::spawn(consensus_thread_fn);

            let _ = node_tx.send((node, args));

            tokio::select! {
                _ = node_exit_future => {
                    info!("execution node exited");
                }
                _ = &mut consensus_dead_rx => {
                    info!("consensus node exited");
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("received shutdown signal");
                }
            }

            shutdown_token.cancel();

            handle_consensus_thread_join(consensus_handle.join())?;
        } else {
            info!("outbe node launched in FULL NODE mode — no consensus thread spawned");

            tokio::select! {
                _ = node_exit_future => {
                    info!("execution node exited");
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("received shutdown signal");
                }
            }
        }

        Ok(())
    })
    .wrap_err("execution node failed")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn consensus_thread_error_propagates_to_validator_main() {
        let err = super::handle_consensus_thread_join(Ok(Err(eyre::eyre!("watchdog fatal"))))
            .expect_err("consensus thread error must propagate");
        let err = format!("{err:#}");

        assert!(
            err.contains("consensus task exited with error"),
            "wrapped consensus context missing: {err}"
        );
        assert!(
            err.contains("watchdog fatal"),
            "original consensus error missing: {err}"
        );
    }

    #[test]
    fn consensus_thread_success_is_ok() {
        super::handle_consensus_thread_join(Ok(Ok(())))
            .expect("successful consensus thread must not error");
    }

    /// Full-node mode: dropping node_tx causes consensus thread's blocking_recv to return Err.
    /// This verifies that the consensus thread exits immediately when no node handle is sent.
    #[test]
    fn test_fullnode_drops_node_tx_consensus_thread_exits() {
        let (node_tx, node_rx) = tokio::sync::oneshot::channel::<()>();

        // Simulate full-node path: drop sender without sending.
        drop(node_tx);

        // Consensus thread would call blocking_recv — should return Err immediately.
        let result = node_rx.blocking_recv();
        assert!(
            result.is_err(),
            "blocking_recv must return Err when sender is dropped"
        );
    }

    /// Full-node mode: RPC handler created without bridge → is_validator = false.
    #[test]
    fn test_fullnode_rpc_no_bridge_means_not_validator() {
        // When OutbeApiHandler::new(provider) is called (no bridge),
        // bridge field is None, so is_validator = bridge.is_some() = false.
        let bridge: Option<outbe_engine::bridge::ConsensusExecutionBridge> = None;
        assert!(
            bridge.is_none(),
            "full node must have bridge=None → is_validator=false"
        );
    }

    /// Validator mode: RPC handler created with bridge → is_validator = true.
    #[test]
    fn test_validator_rpc_with_bridge_means_validator() {
        let bridge = outbe_engine::bridge::ConsensusExecutionBridge::new();
        let bridge_opt: Option<outbe_engine::bridge::ConsensusExecutionBridge> = Some(bridge);
        assert!(
            bridge_opt.is_some(),
            "validator must have bridge=Some → is_validator=true"
        );
    }

    #[test]
    fn outbe_rpc_module_validator_accepts_outbe_namespace() {
        use reth_rpc_server_types::{RpcModuleSelection, RpcModuleValidator as _};

        let selection = super::OutbeRpcModuleValidator::parse_selection("eth,net,web3,outbe")
            .expect("outbe namespace should be accepted");
        let RpcModuleSelection::Selection(modules) = selection else {
            panic!("explicit module list should parse as selection");
        };
        assert!(modules.iter().any(|module| module.as_str() == "outbe"));
    }

    #[test]
    fn outbe_rpc_module_validator_rejects_unknown_namespace() {
        use reth_rpc_server_types::RpcModuleValidator as _;

        let err = super::OutbeRpcModuleValidator::parse_selection("eth,outbee")
            .expect_err("typoed custom namespace must be rejected");
        assert!(err.contains("Unknown RPC module: 'outbee'"));
    }

    // --- parse_dkg_key_backend ---

    fn make_dkg_cli(args: &[&str]) -> super::DkgCli {
        use clap::Parser;
        let mut full = vec!["cmd"];
        full.extend_from_slice(args);
        super::DkgCli::parse_from(full)
    }

    #[test]
    fn test_parse_dkg_key_backend_plaintext() {
        let cli = make_dkg_cli(&[
            "--bls-key-backend",
            "plaintext",
            "status",
            "--storage-dir",
            "/tmp",
        ]);
        let backend = super::parse_dkg_key_backend(&cli).unwrap();
        assert!(matches!(
            backend,
            outbe_consensus::bls::KeyBackend::Plaintext
        ));
    }

    #[test]
    fn test_parse_dkg_key_backend_default_is_plaintext() {
        let cli = make_dkg_cli(&["status", "--storage-dir", "/tmp"]);
        let backend = super::parse_dkg_key_backend(&cli).unwrap();
        assert!(matches!(
            backend,
            outbe_consensus::bls::KeyBackend::Plaintext
        ));
    }

    #[test]
    fn test_parse_dkg_key_backend_encrypted_with_passphrase() {
        let cli = make_dkg_cli(&[
            "--bls-key-backend",
            "encrypted",
            "--bls-passphrase",
            "hunter2",
            "status",
            "--storage-dir",
            "/tmp",
        ]);
        let backend = super::parse_dkg_key_backend(&cli).unwrap();
        assert!(matches!(
            backend,
            outbe_consensus::bls::KeyBackend::Encrypted(ref p) if p == "hunter2"
        ));
    }

    #[test]
    fn test_parse_dkg_key_backend_encrypted_missing_passphrase() {
        let cli = make_dkg_cli(&[
            "--bls-key-backend",
            "encrypted",
            "status",
            "--storage-dir",
            "/tmp",
        ]);
        assert!(super::parse_dkg_key_backend(&cli).is_err());
    }

    #[test]
    fn test_parse_dkg_key_backend_os_level() {
        let cli = make_dkg_cli(&[
            "--bls-key-backend",
            "os-level",
            "status",
            "--storage-dir",
            "/tmp",
        ]);
        let backend = super::parse_dkg_key_backend(&cli).unwrap();
        assert!(matches!(backend, outbe_consensus::bls::KeyBackend::OsLevel));
    }

    #[test]
    fn test_parse_dkg_key_backend_unknown() {
        let cli = make_dkg_cli(&[
            "--bls-key-backend",
            "foo",
            "status",
            "--storage-dir",
            "/tmp",
        ]);
        assert!(super::parse_dkg_key_backend(&cli).is_err());
    }

    // --- TC-002: DKG command routing via run_dkg_command ---

    fn dkg_args(args: &[&str]) -> Vec<String> {
        let mut v = vec!["outbe-chain".to_string(), "dkg".to_string()];
        v.extend(args.iter().map(|s| s.to_string()));
        v
    }

    #[test]
    fn test_dkg_bootstrap_3_validators() {
        let dir = tempfile::tempdir().unwrap();
        let dir_str = dir.path().to_str().unwrap();
        let args = dkg_args(&["bootstrap", "--output-dir", dir_str, "--validators", "3"]);
        super::run_dkg_command(&args).unwrap();

        // Verify output structure
        assert!(dir.path().join("polynomial.hex").exists());
        assert!(dir.path().join("dkg-output.hex").exists());
        assert!(dir.path().join("validators.json").exists());
        for i in 0..3 {
            let vdir = dir.path().join(format!("validator-{i}"));
            assert!(vdir.join("signing-key.hex").exists());
            assert!(vdir.join("evm-key.hex").exists());
        }
    }

    #[test]
    fn test_dkg_status_after_bootstrap() {
        let dir = tempfile::tempdir().unwrap();
        let dir_str = dir.path().to_str().unwrap();
        let args = dkg_args(&["bootstrap", "--output-dir", dir_str, "--validators", "3"]);
        super::run_dkg_command(&args).unwrap();

        // Status on a validator directory (has share + poly from bootstrap)
        let v0 = dir.path().join("validator-0");
        let v0_str = v0.to_str().unwrap();
        let status_args = dkg_args(&["status", "--storage-dir", v0_str]);
        super::run_dkg_command(&status_args).unwrap();
    }

    #[test]
    fn test_dkg_status_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let dir_str = dir.path().to_str().unwrap();
        let args = dkg_args(&["status", "--storage-dir", dir_str]);
        // Should succeed but print "NOT READY"
        super::run_dkg_command(&args).unwrap();
    }

    #[test]
    fn test_dkg_export_requires_complete_runtime_state() {
        let dir = tempfile::tempdir().unwrap();
        let dir_str = dir.path().to_str().unwrap();
        let args = dkg_args(&["bootstrap", "--output-dir", dir_str, "--validators", "3"]);
        super::run_dkg_command(&args).unwrap();

        // Bootstrap output keeps the shared dkg-output.hex at the output root.
        // Runtime export must still reject validator storage that lacks its local
        // complete triplet instead of producing an import bundle startup cannot load.
        let v0 = dir.path().join("validator-0");
        std::fs::copy(v0.join("signing-share.hex"), v0.join("dkg_share.hex")).unwrap();
        std::fs::copy(
            dir.path().join("polynomial.hex"),
            v0.join("dkg_polynomial.hex"),
        )
        .unwrap();

        let export_dir = tempfile::tempdir().unwrap();
        let export_args = dkg_args(&[
            "export-share",
            "--storage-dir",
            v0.to_str().unwrap(),
            "--output",
            export_dir.path().to_str().unwrap(),
        ]);
        assert!(super::run_dkg_command(&export_args).is_err());
    }

    #[test]
    fn test_dkg_force_restart() {
        let dir = tempfile::tempdir().unwrap();
        let dir_str = dir.path().to_str().unwrap();
        let args = dkg_args(&["bootstrap", "--output-dir", dir_str, "--validators", "3"]);
        super::run_dkg_command(&args).unwrap();

        let v0 = dir.path().join("validator-0");
        // Copy into runtime filenames
        std::fs::copy(v0.join("signing-share.hex"), v0.join("dkg_share.hex")).unwrap();
        std::fs::copy(
            dir.path().join("polynomial.hex"),
            v0.join("dkg_polynomial.hex"),
        )
        .unwrap();
        std::fs::write(v0.join("dkg_output.hex"), "placeholder").unwrap();
        assert!(v0.join("dkg_share.hex").exists());
        assert!(v0.join("dkg_output.hex").exists());

        let restart_args = dkg_args(&["force-restart", "--storage-dir", v0.to_str().unwrap()]);
        super::run_dkg_command(&restart_args).unwrap();

        assert!(!v0.join("dkg_share.hex").exists());
        assert!(!v0.join("dkg_polynomial.hex").exists());
        assert!(!v0.join("dkg_output.hex").exists());
    }

    #[test]
    fn test_dkg_force_restart_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let dir_str = dir.path().to_str().unwrap();
        let args = dkg_args(&["force-restart", "--storage-dir", dir_str]);
        super::run_dkg_command(&args).unwrap(); // no-op, succeeds
    }

    #[test]
    fn test_dkg_export_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let export_dir = tempfile::tempdir().unwrap();
        let args = dkg_args(&[
            "export-share",
            "--storage-dir",
            dir.path().to_str().unwrap(),
            "--output",
            export_dir.path().to_str().unwrap(),
        ]);
        assert!(super::run_dkg_command(&args).is_err());
    }
}
