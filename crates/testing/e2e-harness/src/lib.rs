//! Rust cucumber harness for the outbe-chain e2e suite.
//!
//! The scenarios live as Gherkin fixtures under `features/`; the step code
//! behind them ([`features`]) drives typed handles ([`world`]). Chain reads and
//! sends are native (alloy [`Provider`]/`sol!`, see `internal::eth`); the
//! committee validators, joiner, followers, and their enclave containers are all
//! launched as Rust-owned processes by one handle ([`world::localnet`], via
//! [`internal::proc`]) — no `run-testnet.sh`/`nohup`. Bootstrap keeps only two
//! one-shot subprocesses (`outbe-chain dkg bootstrap` + `python3 seed_genesis.py`);
//! governance/tribute sends still go through `outbe-cli`.
//!
//! [`Provider`]: https://docs.rs/alloy-provider
//!
//! The [`run`] entry point is driven by the `outbe-e2e` binary: the CLI defines
//! the [`env::Environment`] (validators / TEE mode / sudo), and Gherkin tags
//! define each scenario's requirements.

pub mod env;
pub mod features;
pub mod world;

mod internal;

use cucumber::cli;
use cucumber::World as _;
use futures::FutureExt as _;

use crate::env::{decide, unmet, Decision, EnvCli, Environment};
use crate::internal::config::Config;
use crate::world::localnet::Localnet;
use crate::world::World;

/// Tear the localnet down and exit when the process is interrupted
/// (Ctrl-C / SIGINT or SIGTERM).
///
/// Cucumber's per-scenario `after` hook only runs on normal completion, so a
/// signal would otherwise leave the running scenario's committee validators and
/// enclave containers orphaned. On the signal path the `World` is never dropped,
/// so the owned process/enclave guards never fire — we reconstruct the teardown
/// target from the resolved environment (the same data-dir every `World` uses)
/// and run the stateless datadir-scoped sweep before exiting `130` (SIGINT).
async fn teardown_on_signal(env: Environment) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            // If we can't install the SIGTERM handler, still honour Ctrl-C.
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                shutdown_and_exit(&env);
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    shutdown_and_exit(&env);
}

/// Run the shared localnet teardown for `env` and exit the process. Never
/// returns.
fn shutdown_and_exit(env: &Environment) -> ! {
    eprintln!("\noutbe-e2e: interrupted — tearing down the localnet…");
    // Best-effort: the shutdown is itself best-effort (ignores already-stopped
    // nodes / missing containers), so a partially-started run is safe to tear
    // down too.
    Localnet::new(Config::resolve(env)).teardown();
    std::process::exit(130);
}

/// Parse the CLI, install the environment, and run the cucumber suite over
/// `features/`.
///
/// A scenario whose requirements the environment can't satisfy is **skipped**
/// (a `SKIPPED:` line is printed and it is filtered out). With `--all`, such a
/// scenario instead **fails** — a `before` hook panics so it counts as a hook
/// error. Only one scenario runs at a time (the localnet is a single shared
/// resource). Exits non-zero on any failure.
pub async fn run() {
    // Parse cucumber's built-in flags (--tags/--name/--input) plus our EnvCli.
    let opts = cli::Opts::<_, _, _, EnvCli>::parsed();
    let mut environment = Environment::from_cli(&opts.custom);

    // Give each run its own data subdir under the base `--data-dir`. The enclave
    // container tag and the teardown sweep both derive from the data dir, so this
    // one move also makes this run's docker names + sweep scope unique — two runs
    // (or a prior crashed one) never touch each other's nodes/containers, with no
    // manual `--data-dir` juggling.
    let run_id = {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format!("run-{secs}-{}", std::process::id())
    };
    environment.data_dir = environment.data_dir.join(run_id);
    eprintln!("outbe-e2e: data dir {}", environment.data_dir.display());

    env::set_environment(environment.clone());

    // Tear the localnet down on Ctrl-C / SIGTERM so an interrupted run never
    // leaves committee validators or enclave containers orphaned (the cucumber
    // `after` hook only fires on normal completion).
    tokio::spawn(teardown_on_signal(environment.clone()));

    // Hand an owned clone to each `'static` closure.
    let env_hook = environment.clone();
    let env_filter = environment;

    World::cucumber()
        .max_concurrent_scenarios(1)
        .before(move |feature, _rule, scenario, _world| {
            // Only reachable for unmet scenarios in `--all` mode (the filter
            // excludes them otherwise); panic so they count as failures.
            let reason = if env_hook.all {
                unmet(feature, scenario, &env_hook)
            } else {
                None
            };
            async move {
                if let Some(reason) = reason {
                    panic!("environment cannot satisfy this scenario: {reason}");
                }
            }
            .boxed_local()
        })
        // Tear the localnet down after every scenario (pass or fail) so the
        // network/enclave containers never outlive the run. Skipped scenarios
        // build no `World`, so there is nothing to stop.
        .after(|_feature, _rule, _scenario, _event, world| {
            if let Some(world) = world {
                world.localnet.teardown();
            }
            async move {}.boxed_local()
        })
        .with_cli(opts)
        // Absolute path so the runner finds fixtures regardless of CWD (cargo
        // run executes from the workspace root).
        .filter_run_and_exit(
            concat!(env!("CARGO_MANIFEST_DIR"), "/features"),
            move |feature, _rule, scenario| match decide(feature, scenario, &env_filter) {
                Decision::Run => true,
                Decision::Skip(reason) => {
                    println!("SKIPPED: {} — {reason}", scenario.name);
                    false
                }
            },
        )
        .await;
}
