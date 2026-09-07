use std::{
    fs::{File, OpenOptions},
    io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

use eyre::{bail, ensure, Context, Result};
use outbe_e2e_harness::ocomp_evidence::run_command_lane;

use super::registry;

const PUBLIC_SCENARIO_TAGS: [&str; 3] = [
    "@ocomp-public-apply",
    "@ocomp-public-expiry",
    "@ocomp-public-mutation",
];

const E2E_SCENARIO_TAGS: [&str; 2] = ["@ocomp-e2e-001", "@ocomp-e2e-007"];

pub fn run(repository_root: &Path, task: &str) -> Result<()> {
    match task {
        "OCM-00" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-lysis",
                    "--test",
                    "program_v1_reference",
                ],
            )?;
            task_progress(repository_root, task, &["OCM-EVD-001", "OCM-SEM-001"])?;
        }
        "OCM-01" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            cargo(repository_root, &["test", "--locked", "-p", "outbe-lysis"])?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-lysis",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(repository_root, task, &["OCM-EVD-001", "OCM-SEM-001"])?;
        }
        "OCM-02" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-lysis",
                    "--test",
                    "program_v1_reference",
                ],
            )?;
            registry::run(repository_root, true)?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "xtask", "ocomp::registry"],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "xtask",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-ocomp-protocol"],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-ocomp-protocol",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(repository_root, task, &["OCM-EVD-001", "OCM-SEM-001"])?;
        }
        "OCM-03" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            registry::run(repository_root, true)?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-ocomp-protocol",
                    "--test",
                    "foundation_vectors",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-ocomp-protocol",
                    "--test",
                    "typed_protocol",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-ocomp-protocol",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "xtask",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(repository_root, task, &["OCM-EVD-001", "OCM-SEM-001"])?;
        }
        "OCM-04" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            registry::run(repository_root, true)?;
            super::shape::run(repository_root, true)?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "xtask", "ocomp::shape"],
            )?;
            for test in [
                "golden_vectors",
                "abi_and_system_tx",
                "bounded_decode",
                "typed_protocol",
            ] {
                cargo(
                    repository_root,
                    &[
                        "test",
                        "--locked",
                        "-p",
                        "outbe-ocomp-protocol",
                        "--test",
                        test,
                    ],
                )?;
            }
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-ocomp-protocol",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "xtask",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                ],
            )?;
        }
        "OCM-05" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            registry::run(repository_root, true)?;
            super::shape::run(repository_root, true)?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-ocomp-protocol"],
            )?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-promislimit",
                    "-p",
                    "outbe-desis",
                    "-p",
                    "outbe-metadosis",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-promislimit",
                    "-p",
                    "outbe-desis",
                    "-p",
                    "outbe-metadosis",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "xtask",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                ],
            )?;
        }
        "OCM-06" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            registry::run(repository_root, true)?;
            super::shape::run(repository_root, true)?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-ocomp-protocol"],
            )?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-compressed-entities",
                    "-p",
                    "outbe-tribute",
                    "-p",
                    "outbe-fidelity",
                    "-p",
                    "outbe-oracle",
                    "-p",
                    "outbe-metadosis",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-evm",
                    "handlers::update::tests",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-compressed-entities",
                    "-p",
                    "outbe-tribute",
                    "-p",
                    "outbe-fidelity",
                    "-p",
                    "outbe-oracle",
                    "-p",
                    "outbe-metadosis",
                    "-p",
                    "outbe-evm",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "xtask",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                ],
            )?;
        }
        "OCM-07" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            registry::run(repository_root, true)?;
            super::shape::run(repository_root, true)?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-primitives"],
            )?;
            for integration_test in [
                "system_tx_layout",
                "e2e_system_tx",
                "phase1_safety_verification",
            ] {
                cargo(
                    repository_root,
                    &[
                        "test",
                        "--locked",
                        "-p",
                        "outbe-evm",
                        "--test",
                        integration_test,
                    ],
                )?;
            }
            for test in [
                "ethereum_post_execution_copy_matches_upstream_behavior_matrix",
                "active_terminal_request_is_last_semantic_writer_and_rejects_later_transactions",
                "active_lifecycle_proposer_and_replay_match_receipts_roots_and_header_artifacts",
            ] {
                cargo(
                    repository_root,
                    &["test", "--locked", "-p", "outbe-evm", "--lib", test],
                )?;
            }
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-node",
                    "--test",
                    "consensus_stateless",
                ],
            )?;
            for test in [
                "active_payload_builder_preserves_terminal_reservation_and_replays_exactly",
                "active_payload_builder_rejects_a_user_that_spends_one_unit_of_terminal_reserve",
            ] {
                cargo(
                    repository_root,
                    &["test", "--locked", "-p", "outbe-node", "--lib", test],
                )?;
            }
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-node", "--lib"],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-primitives",
                    "-p",
                    "outbe-evm",
                    "-p",
                    "outbe-node",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "xtask",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                ],
            )?;
        }
        "OCM-08" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-lysis",
                    "--test",
                    "program_v1_reference",
                ],
            )?;
            registry::run(repository_root, true)?;
            super::shape::run(repository_root, true)?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-ocomp-protocol"],
            )?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-compressed-entities"],
            )?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-metadosis"],
            )?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-evm", "--lib"],
            )?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-evm",
                    "--test",
                    "ocomp_request_lifecycle",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-compressed-entities",
                    "-p",
                    "outbe-metadosis",
                    "-p",
                    "outbe-evm",
                    "-p",
                    "outbe-node",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "xtask",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                    "OCM-FSM-001",
                    "OCM-REQ-001",
                ],
            )?;
        }
        "OCM-09" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            registry::run(repository_root, true)?;
            super::shape::run(repository_root, true)?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-ocomp-protocol"],
            )?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-compressed-entities"],
            )?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-metadosis"],
            )?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-evm", "--lib"],
            )?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-evm",
                    "--test",
                    "ocomp_request_lifecycle",
                ],
            )?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-consensus"],
            )?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-node", "ocm_pin_001"],
            )?;
            cargo(repository_root, &["test", "--locked", "-p", "outbe-engine"])?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-compressed-entities",
                    "-p",
                    "outbe-metadosis",
                    "-p",
                    "outbe-evm",
                    "-p",
                    "outbe-consensus",
                    "-p",
                    "outbe-node",
                    "-p",
                    "outbe-engine",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "xtask",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                    "OCM-FSM-001",
                    "OCM-REQ-001",
                    "OCM-FIN-001",
                    "OCM-PIN-001",
                ],
            )?;
        }
        "OCM-10" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            registry::run(repository_root, true)?;
            super::shape::run(repository_root, true)?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-ocomp-protocol"],
            )?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-compressed-entities",
                    "-p",
                    "outbe-tribute",
                    "-p",
                    "outbe-fidelity",
                    "-p",
                    "outbe-oracle",
                    "-p",
                    "outbe-offchain-data",
                ],
            )?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-node", "--lib"],
            )?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-e2e-harness",
                    "--features",
                    "ocomp-integration",
                    "--test",
                    "ocomp_checkpoint_handoff",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-compressed-entities",
                    "-p",
                    "outbe-tribute",
                    "-p",
                    "outbe-fidelity",
                    "-p",
                    "outbe-oracle",
                    "-p",
                    "outbe-offchain-data",
                    "-p",
                    "outbe-node",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "outbe-e2e-harness",
                    "-p",
                    "xtask",
                    "--all-targets",
                    "--features",
                    "outbe-e2e-harness/ocomp-integration",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                    "OCM-FSM-001",
                    "OCM-REQ-001",
                    "OCM-FIN-001",
                    "OCM-PIN-001",
                ],
            )?;
        }
        "OCM-11" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            registry::run(repository_root, true)?;
            super::shape::run(repository_root, true)?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-ocomp-protocol"],
            )?;
            cargo(repository_root, &["test", "--locked", "-p", "outbe-ocomp"])?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-ocomp",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "xtask",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                    "OCM-FSM-001",
                    "OCM-REQ-001",
                    "OCM-FIN-001",
                    "OCM-PIN-001",
                    "OCM-CTL-001",
                ],
            )?;
        }
        "OCM-12" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            registry::run(repository_root, true)?;
            super::shape::run(repository_root, true)?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-ocomp-protocol"],
            )?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-node", "ocm_pin_001"],
            )?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-ocomp",
                    "--",
                    "--test-threads=1",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-node",
                    "-p",
                    "outbe-ocomp",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "xtask",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                    "OCM-FSM-001",
                    "OCM-REQ-001",
                    "OCM-FIN-001",
                    "OCM-PIN-001",
                    "OCM-CTL-001",
                    "OCM-DIS-001",
                ],
            )?;
        }
        "OCM-13" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            registry::run(repository_root, true)?;
            super::shape::run(repository_root, true)?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-lysis",
                    "--test",
                    "planner_reducer_vectors",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-ocomp-protocol",
                    "--test",
                    "input_codec_bindings",
                ],
            )?;
            for integration_test in [
                "cas_atomicity",
                "input_artifact_closure",
                "protocol_bundle",
                "worker_one_unit",
                "finalized_export",
                "deterministic_schedules",
            ] {
                cargo(
                    repository_root,
                    &[
                        "test",
                        "--locked",
                        "-p",
                        "outbe-ocomp",
                        "--test",
                        integration_test,
                        "--",
                        "--test-threads=1",
                    ],
                )?;
            }
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-node",
                    "-p",
                    "outbe-ocomp",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "outbe-e2e-harness",
                    "-p",
                    "xtask",
                    "--all-targets",
                    "--features",
                    "outbe-e2e-harness/ocomp-integration",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                    "OCM-FSM-001",
                    "OCM-REQ-001",
                    "OCM-FIN-001",
                    "OCM-PIN-001",
                    "OCM-CTL-001",
                    "OCM-DIS-001",
                    "OCM-EXP-001",
                    "OCM-CAS-001",
                    "OCM-SEM-002",
                    "OCM-DET-001",
                ],
            )?;
        }
        "OCM-14" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            registry::run(repository_root, true)?;
            super::shape::run(repository_root, true)?;
            cargo(repository_root, &["test", "--locked", "-p", "outbe-lysis"])?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-ocomp",
                    "--tests",
                    "--",
                    "--test-threads=1",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-lysis",
                    "-p",
                    "outbe-ocomp",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-SEM-002",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                    "OCM-FSM-001",
                    "OCM-REQ-001",
                    "OCM-FIN-001",
                    "OCM-PIN-001",
                    "OCM-CTL-001",
                    "OCM-DIS-001",
                    "OCM-EXP-001",
                    "OCM-CAS-001",
                    "OCM-DET-001",
                ],
            )?;
        }
        "OCM-15" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            registry::run(repository_root, true)?;
            super::shape::run(repository_root, true)?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-ocomp-protocol",
                    "--test",
                    "typed_protocol",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-node",
                    "ocm_sig_001",
                    "--",
                    "--test-threads=1",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-keygen",
                    "ocm_sig_001",
                    "--",
                    "--test-threads=1",
                ],
            )?;
            for integration_test in ["finalized_export", "deterministic_schedules"] {
                cargo(
                    repository_root,
                    &[
                        "test",
                        "--locked",
                        "-p",
                        "outbe-ocomp",
                        "--test",
                        integration_test,
                        "--",
                        "--test-threads=1",
                    ],
                )?;
            }
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-node",
                    "-p",
                    "outbe-keygen",
                    "-p",
                    "outbe-ocomp",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "xtask",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-SEM-002",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                    "OCM-FSM-001",
                    "OCM-REQ-001",
                    "OCM-FIN-001",
                    "OCM-PIN-001",
                    "OCM-CTL-001",
                    "OCM-DIS-001",
                    "OCM-EXP-001",
                    "OCM-CAS-001",
                    "OCM-DET-001",
                    "OCM-SIG-001",
                ],
            )?;
        }
        "OCM-16" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            registry::run(repository_root, true)?;
            super::shape::run(repository_root, true)?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-ocomp-protocol"],
            )?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-metadosis",
                    "--lib",
                    "ocomp_semantic_migrations",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-consensus",
                    "-p",
                    "outbe-node",
                    "-p",
                    "outbe-ocomp",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "outbe-e2e-harness",
                    "-p",
                    "xtask",
                    "--all-targets",
                    "--features",
                    "outbe-e2e-harness/ocomp-integration",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-SEM-002",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                    "OCM-FSM-001",
                    "OCM-REQ-001",
                    "OCM-FIN-001",
                    "OCM-PIN-001",
                    "OCM-CTL-001",
                    "OCM-DIS-001",
                    "OCM-EXP-001",
                    "OCM-CAS-001",
                    "OCM-DET-001",
                    "OCM-SIG-001",
                    "OCM-VOT-001",
                ],
            )?;
        }
        "OCM-17" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            registry::run(repository_root, true)?;
            super::shape::run(repository_root, true)?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "outbe-primitives",
                    "-p",
                    "outbe-lysis",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "outbe-primitives",
                    "-p",
                    "outbe-lysis",
                    "-p",
                    "xtask",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-SEM-002",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                    "OCM-FSM-001",
                    "OCM-REQ-001",
                    "OCM-FIN-001",
                    "OCM-PIN-001",
                    "OCM-CTL-001",
                    "OCM-DIS-001",
                    "OCM-EXP-001",
                    "OCM-CAS-001",
                    "OCM-DET-001",
                    "OCM-SIG-001",
                    "OCM-VOT-001",
                    "OCM-APL-001",
                    "OCM-BND-001",
                    "OCM-BND-002",
                    "OCM-TIM-001",
                ],
            )?;
        }
        "OCM-18" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            registry::run(repository_root, true)?;
            super::shape::run(repository_root, true)?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "outbe-primitives",
                    "-p",
                    "outbe-nod",
                    "-p",
                    "outbe-nodfactory",
                    "-p",
                    "outbe-metadosis",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "outbe-primitives",
                    "-p",
                    "outbe-nod",
                    "-p",
                    "outbe-nodfactory",
                    "-p",
                    "outbe-metadosis",
                    "-p",
                    "xtask",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-SEM-002",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                    "OCM-FSM-001",
                    "OCM-REQ-001",
                    "OCM-FIN-001",
                    "OCM-PIN-001",
                    "OCM-CTL-001",
                    "OCM-DIS-001",
                    "OCM-EXP-001",
                    "OCM-CAS-001",
                    "OCM-DET-001",
                    "OCM-SIG-001",
                    "OCM-VOT-001",
                    "OCM-APL-001",
                    "OCM-BND-002",
                    "OCM-BND-001",
                    "OCM-APL-002",
                    "OCM-TIM-001",
                ],
            )?;
        }
        "OCM-19" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            registry::run(repository_root, true)?;
            super::shape::run(repository_root, true)?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "outbe-primitives",
                    "-p",
                    "outbe-intex",
                    "-p",
                    "outbe-intexfactory",
                    "-p",
                    "outbe-metadosis",
                    "-p",
                    "outbe-lysis",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "outbe-primitives",
                    "-p",
                    "outbe-intex",
                    "-p",
                    "outbe-intexfactory",
                    "-p",
                    "outbe-metadosis",
                    "-p",
                    "outbe-lysis",
                    "-p",
                    "xtask",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-SEM-002",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                    "OCM-FSM-001",
                    "OCM-REQ-001",
                    "OCM-FIN-001",
                    "OCM-PIN-001",
                    "OCM-CTL-001",
                    "OCM-DIS-001",
                    "OCM-EXP-001",
                    "OCM-CAS-001",
                    "OCM-DET-001",
                    "OCM-SIG-001",
                    "OCM-VOT-001",
                    "OCM-APL-001",
                    "OCM-BND-002",
                    "OCM-BND-001",
                    "OCM-APL-002",
                    "OCM-TIM-001",
                ],
            )?;
        }
        "OCM-20" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            registry::run(repository_root, true)?;
            super::shape::run(repository_root, true)?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-compressed-entities",
                    "--",
                    "--test-threads=1",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "outbe-primitives",
                    "-p",
                    "outbe-tribute",
                    "-p",
                    "outbe-offchain-data",
                    "-p",
                    "outbe-metadosis",
                    "-p",
                    "outbe-lysis",
                ],
            )?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-node", "ocm_pin_001"],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "outbe-primitives",
                    "-p",
                    "outbe-compressed-entities",
                    "-p",
                    "outbe-tribute",
                    "-p",
                    "outbe-offchain-data",
                    "-p",
                    "outbe-metadosis",
                    "-p",
                    "outbe-lysis",
                    "-p",
                    "outbe-node",
                    "-p",
                    "xtask",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-SEM-002",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                    "OCM-FSM-001",
                    "OCM-REQ-001",
                    "OCM-FIN-001",
                    "OCM-PIN-001",
                    "OCM-CTL-001",
                    "OCM-DIS-001",
                    "OCM-EXP-001",
                    "OCM-CAS-001",
                    "OCM-DET-001",
                    "OCM-SIG-001",
                    "OCM-VOT-001",
                    "OCM-APL-001",
                    "OCM-BND-002",
                    "OCM-BND-001",
                    "OCM-APL-002",
                    "OCM-TIM-001",
                ],
            )?;
        }
        "OCM-21" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            registry::run(repository_root, true)?;
            super::shape::run(repository_root, true)?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-promislimit",
                    "-p",
                    "outbe-metadosis",
                    "-p",
                    "outbe-emissionlimit",
                    "-p",
                    "outbe-cycle",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-evm",
                    "--test",
                    "ocomp_request_lifecycle",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-promislimit",
                    "-p",
                    "outbe-metadosis",
                    "-p",
                    "outbe-emissionlimit",
                    "-p",
                    "outbe-cycle",
                    "-p",
                    "outbe-evm",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "xtask",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-SEM-002",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                    "OCM-FSM-001",
                    "OCM-REQ-001",
                    "OCM-FIN-001",
                    "OCM-PIN-001",
                    "OCM-CTL-001",
                    "OCM-DIS-001",
                    "OCM-EXP-001",
                    "OCM-CAS-001",
                    "OCM-DET-001",
                    "OCM-SIG-001",
                    "OCM-VOT-001",
                    "OCM-APL-001",
                    "OCM-BND-002",
                    "OCM-BND-001",
                    "OCM-APL-002",
                    "OCM-TIM-001",
                ],
            )?;
        }
        "OCM-22" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            registry::run(repository_root, true)?;
            super::shape::run(repository_root, true)?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-promislimit",
                    "-p",
                    "outbe-lysis",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "outbe-primitives",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-promislimit",
                    "-p",
                    "outbe-lysis",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "outbe-primitives",
                    "-p",
                    "xtask",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-SEM-002",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                    "OCM-FSM-001",
                    "OCM-REQ-001",
                    "OCM-FIN-001",
                    "OCM-PIN-001",
                    "OCM-CTL-001",
                    "OCM-DIS-001",
                    "OCM-EXP-001",
                    "OCM-CAS-001",
                    "OCM-DET-001",
                    "OCM-SIG-001",
                    "OCM-VOT-001",
                    "OCM-APL-001",
                    "OCM-BND-002",
                    "OCM-BND-001",
                    "OCM-APL-002",
                    "OCM-TIM-001",
                ],
            )?;
        }
        "OCM-23" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            registry::run(repository_root, true)?;
            super::shape::run(repository_root, true)?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-metadosis",
                    "-p",
                    "outbe-nodfactory",
                    "-p",
                    "outbe-intex",
                    "-p",
                    "outbe-tribute",
                    "-p",
                    "outbe-promislimit",
                    "-p",
                    "outbe-ocomp-protocol",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-primitives",
                    "--test",
                    "trybuild",
                ],
            )?;
            for test in ["activation_receipt_vectors", "certified_boundary"] {
                cargo(
                    repository_root,
                    &["test", "--locked", "-p", "outbe-lysis", "--test", test],
                )?;
            }
            cargo(
                repository_root,
                &["test", "--locked", "-p", "outbe-txpool", "ocomp_", "--lib"],
            )?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-evm",
                    "production_finality_wrapper_requires_node_owned_canonical_finalized_anchor",
                    "--lib",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-metadosis",
                    "-p",
                    "outbe-nodfactory",
                    "-p",
                    "outbe-intex",
                    "-p",
                    "outbe-tribute",
                    "-p",
                    "outbe-promislimit",
                    "-p",
                    "outbe-lysis",
                    "-p",
                    "outbe-primitives",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "outbe-evm",
                    "-p",
                    "outbe-node",
                    "-p",
                    "outbe-txpool",
                    "-p",
                    "xtask",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-SEM-002",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                    "OCM-FSM-001",
                    "OCM-REQ-001",
                    "OCM-FIN-001",
                    "OCM-PIN-001",
                    "OCM-CTL-001",
                    "OCM-DIS-001",
                    "OCM-EXP-001",
                    "OCM-CAS-001",
                    "OCM-DET-001",
                    "OCM-SIG-001",
                    "OCM-VOT-001",
                    "OCM-APL-001",
                    "OCM-BND-002",
                    "OCM-BND-001",
                    "OCM-APL-002",
                    "OCM-TIM-001",
                ],
            )?;
        }
        "OCM-24" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            registry::run(repository_root, true)?;
            super::shape::run(repository_root, true)?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-e2e-harness",
                    "--features",
                    "ocomp-integration",
                    "--lib",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-e2e-harness",
                    "--test",
                    "ocomp_harness_contract",
                ],
            )?;
            cargo(repository_root, &["test", "--locked", "-p", "outbe-ocomp"])?;
            cargo(repository_root, &["test", "--locked", "-p", "outbe-engine"])?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-chain",
                    "-p",
                    "outbe-engine",
                    "-p",
                    "outbe-node",
                    "-p",
                    "outbe-ocomp",
                    "-p",
                    "outbe-e2e-harness",
                    "--features",
                    "outbe-e2e-harness/ocomp-integration",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            build_ocomp_e2e_binaries(repository_root)?;
            cargo(
                repository_root,
                &[
                    "run",
                    "--locked",
                    "-p",
                    "outbe-e2e-harness",
                    "--features",
                    "ocomp-integration",
                    "--bin",
                    "outbe-e2e",
                    "--",
                    "--tags",
                    "@ocomp",
                    "--no-sudo",
                    "--tee",
                    "gramine-direct",
                ],
            )?;
            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-SEM-002",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                    "OCM-FSM-001",
                    "OCM-REQ-001",
                    "OCM-FIN-001",
                    "OCM-PIN-001",
                    "OCM-CTL-001",
                    "OCM-DIS-001",
                    "OCM-EXP-001",
                    "OCM-CAS-001",
                    "OCM-DET-001",
                    "OCM-SIG-001",
                    "OCM-VOT-001",
                    "OCM-APL-001",
                    "OCM-BND-002",
                    "OCM-BND-001",
                    "OCM-APL-002",
                    "OCM-TIM-001",
                ],
            )?;
        }
        "OCM-25" => {
            evidence_verifier(repository_root)?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-e2e-harness",
                    "--test",
                    "ocomp_harness_contract",
                ],
            )?;
            build_ocomp_e2e_binaries(repository_root)?;
            let run_root = fresh_task_output_dir("ocm25")?;
            let artifact_set = snapshot_ocomp_artifact_set(repository_root, &run_root)?;
            let evidence_dir = run_root.join("lanes").join("OCM-PUBLIC");
            run_exact_scenario_set(
                repository_root,
                &artifact_set,
                &evidence_dir,
                &PUBLIC_SCENARIO_TAGS,
            )?;
            run_evidence_binary(
                repository_root,
                &artifact_set,
                &[
                    "lane",
                    "OCM-PUBLIC",
                    "--evidence-dir",
                    path_str(&evidence_dir)?,
                ],
            )?;
            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-SEM-002",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                    "OCM-FSM-001",
                    "OCM-REQ-001",
                    "OCM-FIN-001",
                    "OCM-PIN-001",
                    "OCM-WRK-001",
                    "OCM-WTR-001",
                    "OCM-WOBS-001",
                    "OCM-CAS-001",
                    "OCM-DET-001",
                    "OCM-SIG-001",
                    "OCM-VOT-001",
                    "OCM-APL-001",
                    "OCM-BND-002",
                    "OCM-BND-001",
                    "OCM-APL-002",
                    "OCM-TIM-001",
                    "OCM-PUB-001",
                    "OCM-PUB-002",
                    "OCM-PUB-003",
                    "OCM-PUB-004",
                ],
            )?;
        }
        "OCM-26" => {
            evidence_verifier(repository_root)?;
            reference(repository_root)?;
            registry::run(repository_root, true)?;
            super::shape::run(repository_root, true)?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "xtask", "ocomp::capacity"],
            )?;
            cargo(
                repository_root,
                &["test", "--locked", "-p", "xtask", "ocomp::finalize"],
            )?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-ocomp-protocol",
                    "--test",
                    "generated_capacity",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-e2e-harness",
                    "--features",
                    "ocomp-integration",
                    "--test",
                    "ocomp_capacity_resources",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "test",
                    "--locked",
                    "-p",
                    "outbe-e2e-harness",
                    "--features",
                    "ocomp-integration",
                    "--test",
                    "ocomp_final_fixture",
                ],
            )?;
            cargo(
                repository_root,
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "outbe-ocomp-protocol",
                    "-p",
                    "outbe-node",
                    "-p",
                    "outbe-e2e-harness",
                    "-p",
                    "xtask",
                    "--features",
                    "outbe-e2e-harness/ocomp-integration",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;

            let fixture = repository_root.join("testing/e2e-harness/fixtures/ocomp-final-v1");
            let checked_artifacts = fixture.join("artifacts");
            let base = fixture.join("base");
            let checked_capacity = checked_artifacts.join("generated-capacity-v1.json");
            super::finalize::run(
                repository_root,
                &checked_capacity,
                &base.join("genesis.json"),
                &base.join("validators.json"),
                super::finalize::FinalArtifactOverrides::default(),
                &checked_artifacts,
                true,
            )?;

            let run_root = fresh_task_output_dir("ocm26")?;
            let generated_capacity = run_root.join("generated-capacity-v1.json");
            super::capacity::measure(
                repository_root,
                &run_root,
                &repository_root
                    .join("crates/system/ocomp-protocol/registry/generated-shape-manifest.json"),
                &generated_capacity,
            )?;
            let generated_artifacts = run_root.join("final-artifacts");
            super::finalize::run(
                repository_root,
                &generated_capacity,
                &base.join("genesis.json"),
                &base.join("validators.json"),
                super::finalize::FinalArtifactOverrides::default(),
                &generated_artifacts,
                false,
            )?;
            require_matching_final_consensus_artifacts(&generated_artifacts, &checked_artifacts)?;

            eprintln!(
                "OCM-26 immutable evidence retained at {}",
                run_root.display()
            );

            task_progress(
                repository_root,
                task,
                &[
                    "OCM-EVD-001",
                    "OCM-SEM-001",
                    "OCM-SEM-002",
                    "OCM-BYT-001",
                    "OCM-BYT-002",
                    "OCM-BND-003",
                    "OCM-FSM-001",
                    "OCM-REQ-001",
                    "OCM-FIN-001",
                    "OCM-PIN-001",
                    "OCM-WRK-001",
                    "OCM-WTR-001",
                    "OCM-WOBS-001",
                    "OCM-CAS-001",
                    "OCM-DET-001",
                    "OCM-SIG-001",
                    "OCM-VOT-001",
                    "OCM-APL-001",
                    "OCM-BND-002",
                    "OCM-BND-001",
                    "OCM-APL-002",
                    "OCM-TIM-001",
                    "OCM-PUB-001",
                    "OCM-PUB-002",
                    "OCM-PUB-003",
                    "OCM-PUB-004",
                    "OCM-CAP-001",
                ],
            )?;
        }
        "OCM-27" => {
            run_closure(repository_root, None)?;
        }
        _ => {
            cargo(
                repository_root,
                &[
                    "run",
                    "--locked",
                    "-p",
                    "outbe-e2e-harness",
                    "--bin",
                    "outbe-e2e-evidence",
                    "--",
                    "discover",
                ],
            )?;
            bail!("{task} is MISSING: its implementation gate has not been wired yet");
        }
    }
    Ok(())
}

pub fn run_closure(repository_root: &Path, requested_output: Option<&Path>) -> Result<PathBuf> {
    let run_root = match requested_output {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => repository_root.join(path),
        None => fresh_task_output_dir("ocm27")?,
    };
    if run_root.exists() {
        bail!(
            "exact closure output root already exists: {}",
            run_root.display()
        );
    }
    build_ocomp_e2e_binaries(repository_root)?;
    let artifact_set = snapshot_ocomp_artifact_set(repository_root, &run_root)?;
    let ledger = outbe_e2e_harness::ocomp_evidence::PlanningLedger::parse(
        &repository_root.join("outbe-plan/off-chain-poc-evidence-ledger.yaml"),
    )?;

    for lane in ["OCM-FAST", "OCM-INT"] {
        let evidence_dir = run_root.join("lanes").join(lane);
        run_command_lane(repository_root, &ledger, lane, &artifact_set, &evidence_dir)?;
        run_evidence_binary(
            repository_root,
            &artifact_set,
            &["lane", lane, "--evidence-dir", path_str(&evidence_dir)?],
        )?;
    }

    let public_evidence_dir = run_root.join("lanes").join("OCM-PUBLIC");
    run_exact_scenario_set(
        repository_root,
        &artifact_set,
        &public_evidence_dir,
        &PUBLIC_SCENARIO_TAGS,
    )?;
    run_evidence_binary(
        repository_root,
        &artifact_set,
        &[
            "lane",
            "OCM-PUBLIC",
            "--evidence-dir",
            path_str(&public_evidence_dir)?,
        ],
    )?;

    let e2e_evidence_dir = run_root.join("lanes").join("OCM-E2E");
    run_exact_scenario_set(
        repository_root,
        &artifact_set,
        &e2e_evidence_dir,
        &E2E_SCENARIO_TAGS,
    )?;
    run_evidence_binary(
        repository_root,
        &artifact_set,
        &[
            "lane",
            "OCM-E2E",
            "--evidence-dir",
            path_str(&e2e_evidence_dir)?,
        ],
    )?;

    run_evidence_binary(
        repository_root,
        &artifact_set,
        &["closure", "--evidence-dir", path_str(&run_root)?],
    )?;
    eprintln!(
        "OCM-27 exact immutable closure retained at {}",
        run_root.display()
    );
    Ok(run_root)
}

pub fn run_lane(repository_root: &Path, lane: &str, requested_output: Option<&Path>) -> Result<()> {
    let run_root = match requested_output {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => repository_root.join(path),
        None => fresh_task_output_dir(&lane.to_ascii_lowercase().replace('-', "_"))?,
    };
    if run_root.exists() {
        bail!(
            "exact lane output root already exists: {}",
            run_root.display()
        );
    }
    build_ocomp_e2e_binaries(repository_root)?;
    let artifact_set = snapshot_ocomp_artifact_set(repository_root, &run_root)?;
    let ledger = outbe_e2e_harness::ocomp_evidence::PlanningLedger::parse(
        &repository_root.join("outbe-plan/off-chain-poc-evidence-ledger.yaml"),
    )?;
    let evidence_dir = run_root.join("lanes").join(lane);
    match lane {
        "OCM-FAST" | "OCM-INT" => {
            run_command_lane(repository_root, &ledger, lane, &artifact_set, &evidence_dir)?;
        }
        "OCM-PUBLIC" => run_exact_scenario_set(
            repository_root,
            &artifact_set,
            &evidence_dir,
            &PUBLIC_SCENARIO_TAGS,
        )?,
        "OCM-E2E" => run_exact_scenario_set(
            repository_root,
            &artifact_set,
            &evidence_dir,
            &E2E_SCENARIO_TAGS,
        )?,
        _ => {
            bail!("unsupported exact OCOMP execution lane {lane}");
        }
    }
    run_evidence_binary(
        repository_root,
        &artifact_set,
        &["lane", lane, "--evidence-dir", path_str(&evidence_dir)?],
    )?;
    eprintln!(
        "{lane} exact immutable evidence retained at {}",
        run_root.display()
    );
    Ok(())
}

fn reference(repository_root: &Path) -> Result<()> {
    cargo(
        repository_root,
        &["test", "--locked", "-p", "outbe-lysis-v1-reference"],
    )?;
    cargo(
        repository_root,
        &[
            "run",
            "--locked",
            "-p",
            "outbe-lysis-v1-reference",
            "--",
            "--mode",
            "check",
        ],
    )?;
    cargo(
        repository_root,
        &[
            "clippy",
            "--locked",
            "-p",
            "outbe-lysis-v1-reference",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )
}

fn evidence_verifier(repository_root: &Path) -> Result<()> {
    cargo(
        repository_root,
        &[
            "test",
            "--locked",
            "-p",
            "outbe-e2e-harness",
            "--test",
            "ocomp_evidence_verifier",
        ],
    )
}

const OCOMP_E2E_HARNESS_BUILD_ARGS: &[&str] = &[
    "build",
    "--locked",
    "--release",
    "-p",
    "outbe-e2e-harness",
    "--features",
    "ocomp-integration",
    "--bins",
];

fn build_ocomp_e2e_binaries(repository_root: &Path) -> Result<()> {
    cargo(
        repository_root,
        &[
            "build",
            "--locked",
            "--release",
            "-p",
            "outbe-chain",
            "--bin",
            "outbe-chain",
            "-p",
            "outbe-ocomp",
            "--bin",
            "outbe-ocomp",
            "-p",
            "outbe-cli",
            "--bin",
            "outbe-cli",
            "-p",
            "outbe-keygen",
            "--bin",
            "outbe-keygen",
            "--features",
            "outbe-chain/test-protocol-overrides",
        ],
    )?;
    cargo(repository_root, OCOMP_E2E_HARNESS_BUILD_ARGS)?;
    cargo(
        repository_root,
        &[
            "build",
            "--locked",
            "--release",
            "-p",
            "outbe-tee-enclave",
            "--bin",
            "outbe-tee-enclave",
        ],
    )
}

fn snapshot_ocomp_artifact_set(repository_root: &Path, run_root: &Path) -> Result<PathBuf> {
    let artifact_set = run_root.join("artifact-set");
    std::fs::create_dir_all(&artifact_set)
        .wrap_err_with(|| format!("create exact artifact set {}", artifact_set.display()))?;
    for (source, name) in exact_artifact_sources() {
        let source = repository_root.join(source);
        let destination = artifact_set.join(name);
        copy_immutable_artifact(&source, &destination)?;
    }
    std::fs::set_permissions(&artifact_set, std::fs::Permissions::from_mode(0o555))
        .wrap_err_with(|| format!("seal exact artifact set {}", artifact_set.display()))?;
    Ok(artifact_set)
}

fn exact_artifact_sources() -> [(&'static str, &'static str); 7] {
    [
        ("target/release/outbe-chain", "outbe-chain"),
        ("target/release/outbe-cli", "outbe-cli"),
        ("target/release/outbe-e2e", "outbe-e2e"),
        ("target/release/outbe-e2e-evidence", "outbe-e2e-evidence"),
        ("target/release/outbe-keygen", "outbe-keygen"),
        ("target/release/outbe-ocomp", "outbe-ocomp"),
        ("target/release/outbe-tee-enclave", "outbe-tee-enclave"),
    ]
}

fn copy_immutable_artifact(source: &Path, destination: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(source)
        .wrap_err_with(|| format!("inspect exact artifact {}", source.display()))?;
    ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "exact artifact is not a real file: {}",
        source.display()
    );
    let mut input =
        File::open(source).wrap_err_with(|| format!("open exact artifact {}", source.display()))?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .wrap_err_with(|| format!("create exact artifact {}", destination.display()))?;
    io::copy(&mut input, &mut output)
        .wrap_err_with(|| format!("copy exact artifact {}", source.display()))?;
    output
        .sync_all()
        .wrap_err_with(|| format!("sync exact artifact {}", destination.display()))?;
    std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o555))
        .wrap_err_with(|| format!("seal exact artifact {}", destination.display()))
}

fn fresh_task_output_dir(task: &str) -> Result<std::path::PathBuf> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .wrap_err("system clock precedes Unix epoch")?
        .as_millis();
    // Keep the task root compact: the E2E harness adds run/scenario/validator
    // components before creating reth.ipc, whose Linux sun_path is limited to
    // 107 pathname bytes plus the terminating NUL.
    let path = std::env::temp_dir().join(format!("{task}-{:x}{timestamp:x}", std::process::id()));
    if path.exists() {
        bail!("fresh task output already exists: {}", path.display());
    }
    Ok(path)
}

fn require_matching_final_consensus_artifacts(generated: &Path, checked: &Path) -> Result<()> {
    for name in [
        "capacity-profile-v1.ocb1",
        "correctness-profile-v1.ocb1",
        "fork-install-v1.ocb1",
        "genesis-final.json",
        "protocol-bundle-v1.ocb1",
        "semantic-artifacts-v1.json",
    ] {
        let generated_bytes = std::fs::read(generated.join(name))
            .wrap_err_with(|| format!("read generated Final artifact {name}"))?;
        let checked_bytes = std::fs::read(checked.join(name))
            .wrap_err_with(|| format!("read checked-in Final artifact {name}"))?;
        if generated_bytes != checked_bytes {
            bail!("fresh OCM-26 measurement changes consensus-critical Final artifact {name}");
        }
    }
    Ok(())
}

fn run_exact_scenario_set(
    repository_root: &Path,
    artifact_set: &Path,
    evidence_dir: &Path,
    tags: &[&str],
) -> Result<()> {
    ensure!(!tags.is_empty(), "exact scenario set must not be empty");
    if evidence_dir.exists() {
        bail!(
            "exact scenario-set evidence directory already exists: {}",
            evidence_dir.display()
        );
    }
    std::fs::create_dir_all(evidence_dir).wrap_err_with(|| {
        format!(
            "create exact scenario-set evidence directory {}",
            evidence_dir.display()
        )
    })?;

    for (index, tag) in tags.iter().enumerate() {
        let ordinal = index + 1;
        let isolated_evidence_dir = evidence_dir.join(format!(".scenario-run-{ordinal:03}"));
        run_exact_scenario(repository_root, artifact_set, &isolated_evidence_dir, tag)?;
        promote_exact_scenario_evidence(&isolated_evidence_dir, evidence_dir, ordinal)?;
    }
    Ok(())
}

fn promote_exact_scenario_evidence(
    isolated_evidence_dir: &Path,
    lane_evidence_dir: &Path,
    ordinal: usize,
) -> Result<()> {
    let entries = std::fs::read_dir(isolated_evidence_dir)
        .wrap_err_with(|| {
            format!(
                "read isolated scenario evidence {}",
                isolated_evidence_dir.display()
            )
        })?
        .collect::<std::io::Result<Vec<_>>>()
        .wrap_err_with(|| {
            format!(
                "enumerate isolated scenario evidence {}",
                isolated_evidence_dir.display()
            )
        })?;
    ensure!(
        entries.len() == 1,
        "isolated scenario run must publish exactly one record, found {} in {}",
        entries.len(),
        isolated_evidence_dir.display()
    );
    let entry = &entries[0];
    let file_type = entry
        .file_type()
        .wrap_err_with(|| format!("inspect scenario evidence {}", entry.path().display()))?;
    let name = entry
        .file_name()
        .into_string()
        .map_err(|_| eyre::eyre!("scenario evidence file name is not UTF-8"))?;
    ensure!(
        file_type.is_file() && name.starts_with("scenario-") && name.ends_with(".json"),
        "isolated scenario run published unexpected member {}",
        entry.path().display()
    );

    let destination = lane_evidence_dir.join(format!("scenario-{ordinal:03}.json"));
    std::fs::hard_link(entry.path(), &destination).wrap_err_with(|| {
        format!(
            "atomically promote scenario evidence {} to unused destination {}",
            entry.path().display(),
            destination.display()
        )
    })?;
    std::fs::remove_file(entry.path()).wrap_err_with(|| {
        format!(
            "remove isolated scenario evidence after promotion {}",
            entry.path().display()
        )
    })?;
    std::fs::remove_dir(isolated_evidence_dir).wrap_err_with(|| {
        format!(
            "remove empty isolated scenario evidence directory {}",
            isolated_evidence_dir.display()
        )
    })?;
    Ok(())
}

fn run_exact_scenario(
    repository_root: &Path,
    artifact_set: &Path,
    evidence_dir: &Path,
    tag: &str,
) -> Result<()> {
    if evidence_dir.exists() {
        bail!(
            "Final scenario evidence directory already exists: {}",
            evidence_dir.display()
        );
    }
    let arguments = exact_scenario_arguments(repository_root, artifact_set, evidence_dir, tag)?;
    eprintln!(
        "+ {} {}",
        artifact_set.join("outbe-e2e").display(),
        arguments.join(" ")
    );
    let status = Command::new(artifact_set.join("outbe-e2e"))
        .args(arguments)
        .current_dir(repository_root)
        .status()
        .wrap_err_with(|| format!("start exact scenario tag {tag}"))?;
    if !status.success() {
        bail!(
            "exact scenario tag {tag} failed with {} (evidence {})",
            status
                .code()
                .map_or_else(|| "signal".to_owned(), |code| code.to_string()),
            evidence_dir.display()
        );
    }
    Ok(())
}

fn exact_scenario_arguments(
    repository_root: &Path,
    artifact_set: &Path,
    evidence_dir: &Path,
    tag: &str,
) -> Result<Vec<String>> {
    let tee_mode = "sgx-no-attest";
    let mut arguments = vec![
        "--tags".to_owned(),
        tag.to_owned(),
        "--concurrency".to_owned(),
        "1".to_owned(),
        "--no-resolve-ports".to_owned(),
        "--tee".to_owned(),
        tee_mode.to_owned(),
        "--sudo".to_owned(),
        "--all".to_owned(),
        "--repo".to_owned(),
        path_str(repository_root)?.to_owned(),
        "--evidence-dir".to_owned(),
        path_str(evidence_dir)?.to_owned(),
    ];
    for (flag, binary) in [
        ("--chain-bin", "outbe-chain"),
        ("--ocomp-bin", "outbe-ocomp"),
        ("--cli-bin", "outbe-cli"),
        ("--keygen-bin", "outbe-keygen"),
        ("--enclave-bin", "outbe-tee-enclave"),
    ] {
        arguments.push(flag.to_owned());
        arguments.push(path_str(&artifact_set.join(binary))?.to_owned());
    }
    Ok(arguments)
}

fn run_evidence_binary(
    repository_root: &Path,
    artifact_set: &Path,
    arguments: &[&str],
) -> Result<()> {
    let binary = artifact_set.join("outbe-e2e-evidence");
    eprintln!("+ {} {}", binary.display(), arguments.join(" "));
    let status = Command::new(&binary)
        .arg("--repo")
        .arg(repository_root)
        .args(arguments)
        .current_dir(repository_root)
        .status()
        .wrap_err_with(|| format!("start exact evidence binary {}", binary.display()))?;
    if status.success() {
        Ok(())
    } else {
        bail!(
            "exact evidence binary failed with {}",
            status
                .code()
                .map_or_else(|| "signal".to_owned(), |code| code.to_string())
        );
    }
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| eyre::eyre!("path is not UTF-8: {}", path.display()))
}

fn task_progress(repository_root: &Path, task: &str, passed: &[&str]) -> Result<()> {
    let mut arguments = vec![
        "run",
        "--locked",
        "-p",
        "outbe-e2e-harness",
        "--bin",
        "outbe-e2e-evidence",
        "--",
        "task-progress",
        task,
    ];
    for test_id in passed {
        arguments.push("--passed");
        arguments.push(test_id);
    }
    cargo(repository_root, &arguments)
}

fn cargo(repository_root: &Path, arguments: &[&str]) -> Result<()> {
    eprintln!("+ cargo {}", arguments.join(" "));
    let status = Command::new("cargo")
        .args(arguments)
        .current_dir(repository_root)
        .status()
        .wrap_err_with(|| format!("failed starting cargo {}", arguments.join(" ")))?;
    require_success(status, arguments)
}

fn require_success(status: ExitStatus, arguments: &[&str]) -> Result<()> {
    if status.success() {
        Ok(())
    } else {
        bail!(
            "cargo {} exited with {}",
            arguments.join(" "),
            status
                .code()
                .map_or_else(|| "signal".to_owned(), |code| code.to_string())
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        copy_immutable_artifact, exact_artifact_sources, exact_scenario_arguments,
        fresh_task_output_dir, promote_exact_scenario_evidence, OCOMP_E2E_HARNESS_BUILD_ARGS,
    };
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    #[test]
    fn ocm26_output_root_leaves_room_for_the_reth_ipc_socket() {
        let output = fresh_task_output_dir("ocm26").expect("fresh OCM-26 output root");
        let ipc =
            output.join("run-01/data/run-1786339127-4194304/scenario-1/validator-0/data/reth.ipc");

        assert!(
            ipc.as_os_str().len() <= 107,
            "OCM-26 reth IPC path exceeds Linux sun_path capacity: {} bytes at {}",
            ipc.as_os_str().len(),
            ipc.display()
        );
    }

    #[test]
    fn exact_lane_artifact_snapshot_is_an_independent_read_only_copy() {
        let root = tempfile::tempdir().expect("temporary artifact root");
        let source = root.path().join("source");
        let destination = root.path().join("artifact-set").join("binary");
        fs::create_dir(destination.parent().expect("artifact-set parent"))
            .expect("artifact-set directory");
        fs::write(&source, b"first").expect("source binary");

        copy_immutable_artifact(&source, &destination).expect("immutable artifact copy");
        fs::write(&source, b"changed").expect("mutate source");

        assert_eq!(
            fs::read(&destination).expect("snapshotted binary"),
            b"first"
        );
        assert_eq!(
            fs::metadata(&destination)
                .expect("snapshot metadata")
                .permissions()
                .mode()
                & 0o222,
            0
        );
    }

    #[test]
    fn exact_lane_snapshots_only_release_binaries() {
        for (source, _) in exact_artifact_sources() {
            assert!(
                source.starts_with("target/release/"),
                "exact lane source is not release: {source}"
            );
        }
    }

    #[test]
    fn exact_lane_rebuilds_the_harness_in_release_profile_before_snapshot() {
        assert!(
            OCOMP_E2E_HARNESS_BUILD_ARGS.contains(&"--release"),
            "exact closure would copy a stale target/release harness"
        );
    }

    #[test]
    fn exact_ocomp_e2e_scenario_uses_release_sgx_without_attestation_and_sudo() {
        let arguments = exact_scenario_arguments(
            Path::new("/repo"),
            Path::new("/artifact-set"),
            Path::new("/evidence"),
            "@ocomp-e2e-001",
        )
        .expect("exact scenario arguments");

        assert!(arguments
            .windows(2)
            .any(|pair| pair == ["--tee", "sgx-no-attest"]));
        assert!(arguments
            .windows(2)
            .any(|pair| { pair == ["--enclave-bin", "/artifact-set/outbe-tee-enclave",] }));
        assert!(!arguments.iter().any(|argument| argument == "--mock-bin"));
        assert!(arguments.iter().any(|argument| argument == "--sudo"));
        assert!(!arguments.iter().any(|argument| argument == "--no-sudo"));
    }

    #[test]
    fn exact_ocomp_public_scenario_uses_production_sgx_without_attestation() {
        let arguments = exact_scenario_arguments(
            Path::new("/repo"),
            Path::new("/artifact-set"),
            Path::new("/evidence"),
            "@ocomp-public-apply",
        )
        .expect("exact scenario arguments");

        assert!(arguments
            .windows(2)
            .any(|pair| pair == ["--tee", "sgx-no-attest"]));
        assert!(arguments
            .windows(2)
            .any(|pair| { pair == ["--enclave-bin", "/artifact-set/outbe-tee-enclave",] }));
        assert!(!arguments.iter().any(|argument| argument == "--mock-bin"));
        assert!(arguments.iter().any(|argument| argument == "--sudo"));
        assert!(!arguments.iter().any(|argument| argument == "--no-sudo"));
    }

    #[test]
    fn exact_scenario_evidence_is_promoted_without_overwriting_another_run() {
        let root = tempfile::tempdir().expect("temporary evidence root");
        let lane = root.path().join("OCM-PUBLIC");
        let isolated = root.path().join("scenario-run-002");
        std::fs::create_dir_all(&lane).expect("lane directory");
        std::fs::create_dir_all(&isolated).expect("isolated scenario directory");
        std::fs::write(lane.join("scenario-001.json"), b"{\"run\":1}\n")
            .expect("previous scenario evidence");
        std::fs::write(
            isolated.join("scenario-001.json"),
            b"{\"result\":\"passed\"}\n",
        )
        .expect("scenario evidence");

        promote_exact_scenario_evidence(&isolated, &lane, 2).expect("promote evidence");

        assert_eq!(
            std::fs::read(lane.join("scenario-001.json")).expect("previous scenario"),
            b"{\"run\":1}\n"
        );
        assert_eq!(
            std::fs::read(lane.join("scenario-002.json")).expect("promoted scenario"),
            b"{\"result\":\"passed\"}\n"
        );
        assert!(!isolated.exists());
    }

    #[test]
    fn exact_scenario_evidence_never_replaces_an_existing_destination() {
        let root = tempfile::tempdir().expect("temporary evidence root");
        let lane = root.path().join("OCM-PUBLIC");
        let isolated = root.path().join("scenario-run-002");
        std::fs::create_dir_all(&lane).expect("lane directory");
        std::fs::create_dir_all(&isolated).expect("isolated scenario directory");
        std::fs::write(lane.join("scenario-002.json"), b"{\"existing\":true}\n")
            .expect("existing lane evidence");
        std::fs::write(isolated.join("scenario-001.json"), b"{\"new\":true}\n")
            .expect("new isolated evidence");

        assert!(promote_exact_scenario_evidence(&isolated, &lane, 2).is_err());
        assert_eq!(
            std::fs::read(lane.join("scenario-002.json")).expect("existing lane evidence"),
            b"{\"existing\":true}\n"
        );
        assert_eq!(
            std::fs::read(isolated.join("scenario-001.json")).expect("isolated evidence"),
            b"{\"new\":true}\n"
        );
    }
}
