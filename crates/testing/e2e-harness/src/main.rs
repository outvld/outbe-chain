//! `outbe-e2e` — the e2e runner binary.
//!
//! The CLI defines the *environment* (`--validators`, `--tee`, `--no-sudo`) and
//! the run policy (`--all`); Gherkin tags define each scenario's *requirements*.
//! All the wiring lives in [`outbe_e2e_harness::run`].

#[tokio::main]
async fn main() {
    outbe_e2e_harness::run().await;
}
