use std::{collections::BTreeMap, fs, io::Cursor, process::Command};

use alloy_primitives::{keccak256, B256, U256};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use outbe_consensus::storage_identity::bind_consensus_storage_identity;
use outbe_evm::tee_attestation_activation::DcapChainSpecBindingV1;
use outbe_primitives::{
    chain::TESTNET_CHAIN_ID,
    tee_attestation_v1::{
        AttestationMode, NetworkBindingV1, TeePolicyScheduleEntryV1, TeePolicyScheduleV1,
        TeePolicyV1, TrustedNetworkDescriptorV1,
    },
    tee_genesis_v1::{
        initial_tee_policy_v1, tee_attestation_v1_genesis_field, InitialTeeProfileV1,
        ProductionSgxMeasurementV1,
    },
};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use xtask::release::sgx::{
    build_bundle_manifest, build_release_manifest_candidate, canonical_json,
    compare_unsigned_trees, normalize_cosign_json_output, parse_oci_descriptor,
    parse_sigstruct_view, verify_signed_bundle, write_deterministic_bundle_archive, BundleSpec,
    SgxReleaseNetwork, SourceIdentity, VerifiedReleaseInputs,
};

const SIGSTRUCT: &str = "Attributes:\n\
    mr_signer: dee850fda5f2fe2b157dbea629d5182e9d3bfef43b0d00ec13e71d500656589f\n\
    mr_enclave: c6f76b702ccb4764f5583bd9ea13c9d2464a90f6513d4931d4674baad816eedf\n\
    isv_prod_id: 1\n\
    isv_svn: 2\n\
    debug_enclave: False\n";
const PCK_CRL_BYTES: &[u8] = b"synthetic Processor CRL boundary fixture";
const ROOT_CRL_BYTES: &[u8] = b"synthetic root CRL boundary fixture";

fn repo_spec() -> BundleSpec {
    BundleSpec::read(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../release/testnet-sgx-bundle-v1.json"),
    )
    .expect("repository bundle spec")
}

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives under repository root")
        .to_owned()
}

#[test]
fn release_network_profiles_are_canonical_and_closed() {
    assert_eq!(SgxReleaseNetwork::Testnet.chain_id(), 54_322_345);
    assert_eq!(SgxReleaseNetwork::Testnet.chain_name(), "outbe-testnet-1");
    assert_eq!(SgxReleaseNetwork::Mainnet.chain_id(), 676);
    assert_eq!(SgxReleaseNetwork::Mainnet.chain_name(), "outbe-mainnet-1");
    assert_eq!(SgxReleaseNetwork::Mainnet.authorization_scope(), "mainnet");
}

#[test]
fn mainnet_and_testnet_specs_share_physical_sgx_policy_but_not_identity() {
    let root = repo_root();
    let testnet = BundleSpec::read(&root.join("release/testnet-sgx-bundle-v1.json")).unwrap();
    let mainnet = BundleSpec::read(&root.join("release/mainnet-sgx-bundle-v1.json")).unwrap();

    assert_eq!(testnet.gramine, mainnet.gramine);
    assert_eq!(testnet.install_root, mainnet.install_root);
    assert_eq!(testnet.platform, mainnet.platform);
    assert_eq!(testnet.project_toolchain, mainnet.project_toolchain);
    assert_eq!(testnet.sealed_state_schema, mainnet.sealed_state_schema);
    assert_eq!(testnet.sgx, mainnet.sgx);
    assert_ne!(testnet.authorization_scope, mainnet.authorization_scope);
    assert_ne!(testnet.chain_id, mainnet.chain_id);
    assert_ne!(testnet.network_name, mainnet.network_name);
}

#[test]
fn repository_default_testnet_genesis_is_dcap_required_but_not_release_authority() {
    let binding = DcapChainSpecBindingV1::from_genesis_path(
        &repo_root().join("release/testnet-genesis.json"),
    )
    .expect("repository default testnet genesis must be a valid DCAP ChainSpec");

    assert_eq!(binding.chain_id, TESTNET_CHAIN_ID);
    assert_eq!(
        binding.genesis_hash,
        "0x5d3cffd449afeed2edbbaa6423588c1df2545ebce56bb92a494f9ae0495fa345"
            .parse::<B256>()
            .unwrap()
    );
    assert_eq!(binding.activation_height, 1);
    assert_eq!(
        binding.policy.attestation_mode,
        AttestationMode::DcapRequired
    );
    assert_eq!(binding.policy.measurement_rules.len(), 1);
    assert_eq!(binding.policy.minimum_tcb_evaluation_data_number, 1);
    assert_eq!(binding.policy.maximum_lease, 2_592_000);
    let genesis: serde_json::Value = serde_json::from_slice(
        &fs::read(repo_root().join("release/testnet-genesis.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(genesis["baseFeePerGas"], "0x7");
    for rule in &binding.policy.measurement_rules {
        assert_eq!(rule.mrenclave, B256::from([0x11; 32]));
        assert_eq!(rule.mrsigner, B256::from([0x22; 32]));
        assert_eq!(rule.isv_prod_id, u16::MAX);
        assert_eq!(rule.minimum_isv_svn, u16::MAX);
    }
    let signed = parse_sigstruct_view(SIGSTRUCT).expect("test SIGSTRUCT");
    let measurement = |value: &str| {
        B256::from_slice(&hex::decode(value).expect("32-byte hexadecimal SGX measurement"))
    };
    let error = binding
        .ensure_exact_release_measurements(
            measurement(&signed.mrenclave),
            measurement(&signed.mrsigner),
            signed.isv_prod_id,
            signed.isv_svn,
        )
        .expect_err("placeholder genesis must not authorize the signed test release");
    assert!(error.contains("does not exactly bind the signed bundle measurement"));
}

fn processor_dcap_artifact_fixtures(
    network: SgxReleaseNetwork,
    genesis: &[u8],
    policy: &[u8],
    policy_schedule: &[u8],
) -> BTreeMap<String, Vec<u8>> {
    let mut artifacts = network
        .dcap_artifact_set()
        .paths()
        .into_iter()
        .map(|name| {
            (
                name.to_owned(),
                format!("synthetic {name} boundary fixture").into_bytes(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    artifacts.insert("collateral/pck.crl.der".to_owned(), PCK_CRL_BYTES.to_vec());
    artifacts.insert(
        "collateral/root-ca.crl.der".to_owned(),
        ROOT_CRL_BYTES.to_vec(),
    );
    artifacts.insert("policy-v1.bin".to_owned(), policy.to_vec());
    artifacts.insert(
        "policy-schedule-v1.bin".to_owned(),
        policy_schedule.to_vec(),
    );
    artifacts.insert(network.genesis_artifact_name().to_owned(), genesis.to_vec());
    artifacts
}

fn write_processor_dcap_archive(
    path: &std::path::Path,
    evidence: &[u8],
    network: SgxReleaseNetwork,
    genesis: &[u8],
    policy: &[u8],
    policy_schedule: &[u8],
    source_date_epoch: i64,
) {
    let output = fs::File::create(path).expect("create Processor DCAP evidence archive");
    let mut archive = tar::Builder::new(output);
    let mut directory = tar::Header::new_gnu();
    directory.set_entry_type(tar::EntryType::Directory);
    directory.set_mode(0o755);
    directory.set_uid(0);
    directory.set_gid(0);
    directory.set_mtime(source_date_epoch as u64);
    directory.set_size(0);
    directory.set_cksum();
    archive
        .append_data(&mut directory, "collateral", Cursor::new([]))
        .expect("append Processor DCAP collateral directory");
    let mut artifacts = processor_dcap_artifact_fixtures(network, genesis, policy, policy_schedule);
    artifacts.insert("hardware-dcap-evidence.json".to_owned(), evidence.to_vec());
    for (name, bytes) in artifacts {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(source_date_epoch as u64);
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        archive
            .append_data(&mut header, name, Cursor::new(bytes))
            .expect("append Processor DCAP evidence member");
    }
    archive
        .finish()
        .expect("finish Processor DCAP evidence archive");
}

fn write_release_genesis(
    root: &std::path::Path,
    network: SgxReleaseNetwork,
    mrenclave: &str,
    mrsigner: &str,
    isv_prod_id: u16,
    isv_svn: u16,
) -> (
    std::path::PathBuf,
    std::path::PathBuf,
    TeePolicyV1,
    TeePolicyScheduleV1,
) {
    let path = root.join(network.genesis_artifact_name());
    let seeded_path = root.join(format!(
        "{}-seeded-genesis.json",
        network.authorization_scope()
    ));
    let mut genesis = serde_json::json!({
        "config": {
            "chainId": network.chain_id(),
            "homesteadBlock": 0,
            "eip150Block": 0,
            "eip155Block": 0,
            "eip158Block": 0,
            "byzantiumBlock": 0,
            "constantinopleBlock": 0,
            "petersburgBlock": 0,
            "istanbulBlock": 0,
            "berlinBlock": 0,
            "londonBlock": 0,
            "terminalTotalDifficultyPassed": true
        },
        "nonce": "0x0",
        "timestamp": "0x0",
        "extraData": "0x",
        "gasLimit": "0x1c9c380",
        "difficulty": "0x0",
        "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "coinbase": "0x0000000000000000000000000000000000000000",
        "alloc": {}
    });
    let direct_slot = |slot: u64| U256::from(slot).to_be_bytes::<32>();
    let mapping_slot = |key: [u8; 32], slot: u64| {
        let mut preimage = [0_u8; 64];
        preimage[..32].copy_from_slice(&key);
        preimage[32..].copy_from_slice(&direct_slot(slot));
        keccak256(preimage).0
    };
    let storage_word = |word: [u8; 32]| format!("0x{}", hex::encode(word));
    let validator_address = [0x77_u8; 20];
    let mut validator_word = [0_u8; 32];
    validator_word[12..].copy_from_slice(&validator_address);
    let consensus_key = test_consensus_key(network);
    let mut consensus_hi = [0_u8; 32];
    consensus_hi[..16].copy_from_slice(&consensus_key[32..]);
    let storage = serde_json::Map::from_iter(
        [
            (storage_word(direct_slot(20)), storage_word(direct_slot(1))),
            (
                storage_word(mapping_slot(direct_slot(1), 17)),
                storage_word(validator_word),
            ),
            (
                storage_word(mapping_slot(validator_word, 5)),
                storage_word(consensus_key[..32].try_into().unwrap()),
            ),
            (
                storage_word(mapping_slot(validator_word, 6)),
                storage_word(consensus_hi),
            ),
            (
                storage_word(mapping_slot(validator_word, 8)),
                storage_word(direct_slot(2)),
            ),
            (
                storage_word(mapping_slot(validator_word, 24)),
                storage_word(direct_slot(1)),
            ),
        ]
        .map(|(key, value)| (key, serde_json::Value::String(value))),
    );
    genesis["alloc"] = serde_json::json!({
        "000000000000000000000000000000000000ee00": {
            "balance": "0x0",
            "storage": storage
        }
    });
    fs::write(&seeded_path, canonical_json(&genesis).unwrap()).unwrap();
    let base =
        reth_ethereum::cli::chainspec::chain_value_parser(seeded_path.to_str().unwrap()).unwrap();
    let parse = |value: &str| {
        let value = value.strip_prefix("0x").unwrap_or(value);
        B256::from_slice(&hex::decode(value).unwrap())
    };
    let policy = initial_tee_policy_v1(
        InitialTeeProfileV1::DcapRequired(ProductionSgxMeasurementV1 {
            mrenclave: parse(mrenclave),
            mrsigner: parse(mrsigner),
            isv_prod_id,
            minimum_isv_svn: isv_svn,
            minimum_tcb_evaluation_data_number: 1,
        }),
        network.chain_id(),
        base.genesis_hash(),
    )
    .unwrap();
    let schedule = TeePolicyScheduleV1 {
        chain_id: policy.chain_id,
        genesis_hash: policy.genesis_hash,
        entries: vec![TeePolicyScheduleEntryV1 {
            activation_height: policy.activation_height,
            policy: policy.clone(),
        }],
    };
    genesis["config"]["teeAttestationV1"] = tee_attestation_v1_genesis_field(&policy).unwrap();
    fs::write(&path, canonical_json(&genesis).unwrap()).unwrap();
    (seeded_path, path, policy, schedule)
}

fn test_file_digest(path: &std::path::Path) -> serde_json::Value {
    let bytes = fs::read(path).expect("read digest input");
    serde_json::json!({
        "algorithm": "sha256",
        "value": hex::encode(Sha256::digest(bytes))
    })
}

fn write_network_binding_evidence(
    path: &std::path::Path,
    network: SgxReleaseNetwork,
    seeded_genesis: &std::path::Path,
    final_genesis: &std::path::Path,
    bundle: &std::path::Path,
    manifest: &xtask::release::sgx::BundleManifest,
    policy: &TeePolicyV1,
) {
    let binding = DcapChainSpecBindingV1::from_genesis_path(final_genesis)
        .expect("parse final release binding");
    let evidence = serde_json::json!({
        "schema": "outbe-sgx-final-genesis-evidence-v1",
        "network": network.authorization_scope(),
        "chain_id": binding.chain_id,
        "genesis_hash": format!("{:#x}", binding.genesis_hash),
        "seeded_genesis": test_file_digest(seeded_genesis),
        "final_genesis": test_file_digest(final_genesis),
        "bundle_manifest": test_file_digest(&bundle.join(network.bundle_manifest_path())),
        "measured_descriptor": test_file_digest(&bundle.join("metadata/network-descriptor-v1.bin")),
        "measurements": manifest.measurements,
        "minimum_tcb_evaluation_data_number": policy.minimum_tcb_evaluation_data_number,
        "mutation": "insert-config-teeAttestationV1-only",
        "result": "passed"
    });
    fs::write(
        path,
        canonical_json(&evidence).expect("canonical binding evidence"),
    )
    .expect("write binding evidence");
}

#[test]
fn repository_contract_has_no_runtime_signing_or_direct_fallback() {
    let root = repo_root();
    let entrypoint = fs::read_to_string(root.join("bin/outbe-tee-enclave/gramine/entrypoint.sh"))
        .expect("release entrypoint");
    assert!(!entrypoint.contains("gramine-sgx-sign"));
    assert!(!entrypoint.contains("gramine-sgx-gen-private-key"));
    assert!(!entrypoint.contains("gramine-direct"));
    assert!(!entrypoint.contains("enclave-key.pem"));
    assert!(entrypoint.contains("exec"));

    let dockerfile = fs::read_to_string(root.join("bin/outbe-tee-enclave/gramine/Dockerfile"))
        .expect("release Dockerfile");
    assert!(!dockerfile.contains("gramine-sgx-gen-private-key"));
    assert!(dockerfile.contains("@sha256:"));

    let test_dockerfile =
        fs::read_to_string(root.join("bin/outbe-tee-enclave/gramine/Dockerfile.test"))
            .expect("test Dockerfile");
    assert!(!test_dockerfile.contains("gramine-sgx-gen-private-key"));
    let test_entrypoint =
        fs::read_to_string(root.join("bin/outbe-tee-enclave/gramine/entrypoint.test.sh"))
            .expect("test entrypoint");
    assert!(test_entrypoint.contains("/run/secrets/outbe-test-sgx-key.pem"));
    assert!(test_entrypoint.contains("gramine-sgx-sign"));

    let template = fs::read_to_string(
        root.join("bin/outbe-tee-enclave/gramine/outbe-tee-enclave.release.manifest.template"),
    )
    .expect("release manifest template");
    assert!(template.contains("sgx.debug = false"));
    assert!(template.contains("sgx.remote_attestation = \"dcap\""));
    assert!(!template.contains("gramine-direct"));
    assert!(template.contains("loader.env.LD_LIBRARY_PATH = \"/qvl:/lib\""));
    for trusted_qvl_file in [
        "file:{{ install_root }}/gramine/runtime/qvl/libsgx_dcap_quoteverify.so.1",
        "file:{{ install_root }}/gramine/runtime/qvl/libstdc++.so.6",
        "file:{{ install_root }}/gramine/runtime/qvl/libgcc_s.so.1",
    ] {
        assert!(
            template.contains(trusted_qvl_file),
            "release manifest does not pin {trusted_qvl_file}"
        );
    }

    let adapter = fs::read_to_string(root.join("scripts/release/build-sgx-bundle-in-container.sh"))
        .expect("Gramine container adapter");
    assert!(adapter.contains("--chroot \"${bundle_root}\""));
    assert!(adapter.contains("verify_dcap_native_qvl.py"));
    assert!(adapter.contains("--install-dir"));

    let sgx_release = fs::read_to_string(root.join("xtask/src/release/sgx.rs"))
        .expect("SGX release implementation");
    assert!(sgx_release.contains("Dockerfile.project-toolchain"));
    assert!(sgx_release.contains("[\"--target\", \"toolchain\", \"--tag\", &image]"));
    assert!(sgx_release.contains("build project toolchain image"));
    assert!(!sgx_release.contains(".arg(&spec.gramine.builder_image)"));
    assert_eq!(sgx_release.matches(".arg(&toolchain_image)").count(), 3);

    let bundle_spec: serde_json::Value = serde_json::from_slice(
        &fs::read(root.join("release/testnet-sgx-bundle-v1.json")).expect("bundle spec"),
    )
    .expect("valid bundle spec JSON");
    let inputs = bundle_spec["inputs"]
        .as_array()
        .expect("bundle spec inputs")
        .iter()
        .map(|value| value.as_str().expect("string input"))
        .collect::<Vec<_>>();
    assert!(inputs.contains(&"release/dcap-native-qvl-v1.json"));
    assert_eq!(bundle_spec["sgx"]["remote_attestation"], "dcap");
    assert_eq!(
        bundle_spec["project_toolchain"],
        "release/project-toolchain-v1.json"
    );
    assert!(inputs.contains(&"scripts/release/verify_dcap_native_qvl.py"));
}

#[test]
fn bundle_spec_rejects_pre_activation_attestation_mode() {
    let mut spec = repo_spec();
    spec.sgx.remote_attestation = "none".to_owned();

    let error = spec.validate().expect_err("none must fail closed");
    assert!(error.to_string().contains("must enable DCAP"));
}

#[test]
fn bundle_spec_rejects_sealed_state_schema_drift() {
    let mut spec = repo_spec();
    spec.sealed_state_schema = u32::from(outbe_tee::SEALED_STATE_SCHEMA_V1) + 1;

    let error = spec
        .validate()
        .expect_err("sealed-state schema drift must fail closed");
    assert!(error.to_string().contains("sealed-state schema"));
}

#[test]
fn cli_exposes_typed_sgx_release_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["release", "sgx", "--help"])
        .output()
        .expect("run xtask help");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 help");
    for command in [
        "prepare", "compare", "sign", "verify", "archive", "image", "manifest",
    ] {
        assert!(
            stdout.contains(command),
            "missing command {command}: {stdout}"
        );
    }

    let manifest = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["release", "sgx", "manifest", "--help"])
        .output()
        .expect("run manifest help");
    assert!(manifest.status.success());
    let manifest_help = String::from_utf8(manifest.stdout).expect("UTF-8 manifest help");
    assert!(manifest_help.contains("--processor-dcap-archive"));
    assert!(manifest_help.contains("--processor-dcap-evidence"));
    assert!(manifest_help.contains("--network"));
    assert!(manifest_help.contains("--seeded-genesis"));
    assert!(manifest_help.contains("--network-binding-evidence"));
    assert!(manifest_help.contains("--genesis"));
    assert!(!manifest_help.contains("--testnet-genesis"));
    assert!(!manifest_help.contains("--platform-dcap-evidence"));
}

#[test]
fn privileged_release_workflow_pins_source_and_never_replaces_assets() {
    let root = repo_root();
    let workflow = fs::read_to_string(root.join(".github/workflows/testnet-release.yml"))
        .expect("testnet release workflow");
    assert_eq!(
        workflow.matches("ref: ${{ inputs.release_tag }}").count(),
        1,
        "only the initial unprivileged build may resolve the input tag"
    );
    assert!(
        workflow
            .matches("ref: ${{ needs.build-and-compare.outputs.verified_commit }}")
            .count()
            >= 4
    );
    assert!(!workflow.contains("--clobber"));
    assert!(!workflow.contains("gh release upload"));
    assert!(workflow.contains("release ${RELEASE_TAG} already exists"));
    assert!(workflow.contains(".verification.verified == true"));
    assert!(workflow.contains("verified_tag_object"));
    assert!(workflow.contains("[.tag, .object.sha] | @tsv"));
    assert!(workflow.contains("test \"${signed_tag_name}\" = \"${RELEASE_TAG}\""));
    assert!(workflow.contains("runs-on: testnet-release-sgx"));
    assert_eq!(workflow.matches("--network testnet").count(), 10);
    assert!(workflow.contains("--genesis \"${TESTNET_SEEDED_GENESIS}\""));
    assert!(workflow.contains("--expected-pck-ca processor"));
    assert!(workflow.contains("--processor-dcap-archive"));
    assert!(workflow.contains("--processor-dcap-evidence"));
    assert!(workflow.contains("seeded_genesis_url:"));
    assert!(workflow.contains("seeded_genesis_sha256:"));
    assert!(workflow.contains("Fetch and pin the approved seeded Testnet genesis"));
    assert!(workflow.contains("OUTBE_GENESIS_URL"));
    assert!(workflow.contains("OUTBE_GENESIS_SHA256"));
    assert_eq!(
        workflow
            .matches("--genesis \"${TESTNET_SEEDED_GENESIS}\"")
            .count(),
        2,
        "both reproducible bundle builds must consume the immutable seeded Testnet genesis"
    );
    assert!(workflow.contains(
        "--seeded-genesis \"${RUNNER_TEMP}/release-inputs/testnet-seeded-genesis.json\""
    ));
    assert!(workflow.contains(
        "--network-binding-evidence \\\n              \"${RUNNER_TEMP}/published/testnet-genesis-binding-evidence.json\""
    ));
    assert!(!workflow.contains("git ls-files --error-unmatch \"${TESTNET_SEEDED_GENESIS}\""));
    assert!(workflow.contains("outbe-release-dcap-evidence"));
    assert!(workflow.contains("hardware-dcap-processor-evidence"));
    assert!(!workflow.contains("testnet-release-sgx-platform"));
    assert!(!workflow.contains("--expected-pck-ca platform"));
    assert!(!workflow.contains("--platform-dcap-evidence"));
    assert!(!workflow.contains("hardware-dcap-platform-evidence"));
    assert!(!workflow.contains("runs-on: [self-hosted, sgx]"));
    assert!(!workflow.contains("git ls-remote --exit-code origin"));
    assert!(workflow.contains("--draft --prerelease"));
    assert!(workflow.contains("cmp --silent"));
    assert!(workflow.contains("gh release edit \"${RELEASE_TAG}\" --draft=false"));
    assert!(workflow.contains("cosign-image-verification.json"));
    assert!(workflow.contains("cosign-sbom-verification.json"));
    assert!(workflow.contains("cosign-provenance-verification.json"));
    let release_assets = workflow
        .split_once("          assets=(")
        .expect("release asset list")
        .1
        .split_once("\n          )")
        .expect("end of release asset list")
        .0;
    assert!(
        release_assets.contains("\"${RUNNER_TEMP}/release-inputs/testnet-seeded-genesis.json\"")
            && release_assets.contains("\"${RUNNER_TEMP}/published/testnet-genesis.json\"")
            && release_assets
                .contains("\"${RUNNER_TEMP}/published/testnet-genesis-binding-evidence.json\""),
        "the seeded genesis, final genesis and their binding evidence must be release assets"
    );
    let package_job = workflow
        .split_once("  package-and-sign-image:")
        .expect("OCI package job")
        .1
        .split_once("\n  hardware-smoke:")
        .expect("hardware job follows OCI package job")
        .0;
    let buildx_setup = package_job
        .find("docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c # v4")
        .expect("pinned Buildx setup action in OCI package job");
    let image_build = package_job
        .find("cargo xtask release sgx image")
        .expect("OCI image build command");
    assert!(buildx_setup < image_build);
    assert!(package_job.contains("version: v0.35.0"));
    assert!(package_job.contains("driver: docker-container"));
    assert!(package_job.contains(
        "image=moby/buildkit@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec"
    ));
    assert!(!workflow.contains("buildkit-provenance.txt"));

    let cargo_config =
        fs::read_to_string(root.join(".cargo/config.toml")).expect("Cargo configuration");
    assert!(cargo_config.contains("xtask = \"run --locked --package xtask --\""));
}

#[test]
fn mainnet_release_workflow_requires_a_pinned_genesis_and_closed_profile() {
    let root = repo_root();
    let workflow = fs::read_to_string(root.join(".github/workflows/mainnet-release.yml"))
        .expect("mainnet release workflow");
    for required in [
        "seeded_genesis_url:",
        "seeded_genesis_sha256:",
        "environment: mainnet-release",
        "runs-on: mainnet-release-sgx",
        "OUTBE_MAINNET_SGX_SIGNING_KEY_B64",
        "--network mainnet",
        "--seeded-genesis \"${RUNNER_TEMP}/release-inputs/mainnet-seeded-genesis.json\"",
        "--network-binding-evidence \\\n              \"${RUNNER_TEMP}/published/mainnet-genesis-binding-evidence.json\"",
        "--genesis \"${RUNNER_TEMP}/published/mainnet-genesis.json\"",
        "outbe-tee-enclave-mainnet",
    ] {
        assert!(workflow.contains(required), "missing {required}");
    }
    assert!(workflow.contains("sha256sum --check"));
    assert!(workflow.contains(concat!(
        "test \"$(jq -er '.config.chainId' \\\n",
        "            \"${RUNNER_TEMP}/release-inputs/mainnet-seeded-genesis.json\")\" = '676'"
    )));
    assert!(!workflow.contains("--clobber"));
    assert!(!workflow.contains("gh release upload"));
    assert!(workflow.contains("--draft --prerelease"));
    assert!(workflow.contains("cmp --silent"));
    assert_eq!(workflow.matches("--network mainnet").count(), 10);

    let release_assets = workflow
        .split_once("          assets=(")
        .expect("release asset list")
        .1
        .split_once("\n          )")
        .expect("end of release asset list")
        .0;
    assert!(
        release_assets.contains("\"${RUNNER_TEMP}/release-inputs/mainnet-seeded-genesis.json\"")
            && release_assets.contains("\"${RUNNER_TEMP}/published/mainnet-genesis.json\"")
            && release_assets
                .contains("\"${RUNNER_TEMP}/published/mainnet-genesis-binding-evidence.json\""),
        "the seeded genesis, final genesis and their binding evidence must be release assets"
    );

    let dispatcher =
        fs::read_to_string(root.join(".github/workflows/release.yml")).expect("release dispatcher");
    assert!(dispatcher.contains("!contains(github.ref_name, '-mainnet.')"));
    assert!(dispatcher.contains("gh workflow run mainnet-release.yml"));
    assert!(dispatcher.contains(
        "OUTBE_MAINNET_SEEDED_GENESIS_URL: ${{ vars.OUTBE_MAINNET_SEEDED_GENESIS_URL }}"
    ));
    assert!(dispatcher.contains(
        "OUTBE_MAINNET_SEEDED_GENESIS_SHA256: ${{ vars.OUTBE_MAINNET_SEEDED_GENESIS_SHA256 }}"
    ));
}

#[test]
fn parses_buildkit_oci_descriptor_and_rejects_missing_digest() {
    let descriptor = parse_oci_descriptor(
        r#"{
          "containerimage.descriptor": {
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "size": 856
          },
          "containerimage.digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        }"#,
    )
    .expect("valid BuildKit metadata");
    assert_eq!(descriptor.size, 856);
    assert_eq!(descriptor.digest.value.len(), 64);
    assert_eq!(
        descriptor.media_type,
        "application/vnd.oci.image.index.v1+json"
    );

    let error = parse_oci_descriptor(r#"{"containerimage.descriptor": {}}"#)
        .expect_err("missing digest must fail");
    assert!(error.to_string().contains("OCI descriptor digest"));
}

#[test]
fn normalizes_cosign_array_and_ndjson_output() {
    let normalized =
        normalize_cosign_json_output("[{\"critical\":1}]\n{\"payload\":\"abc\"}\n", "fixture")
            .expect("normalize Cosign output");
    assert_eq!(
        normalized,
        serde_json::json!([{"critical": 1}, {"payload": "abc"}])
    );
    assert!(normalize_cosign_json_output("", "fixture").is_err());
}

fn write_network_descriptor(
    root: &std::path::Path,
    network: SgxReleaseNetwork,
    genesis_hash: B256,
) {
    let genesis_consensus_key = test_consensus_key(network);
    let descriptor = TrustedNetworkDescriptorV1 {
        network_binding: NetworkBindingV1 {
            chain_id: U256::from(network.chain_id()).to_be_bytes(),
            genesis_hash,
            attestation_mode: AttestationMode::DcapRequired,
        },
        genesis_consensus_keys: vec![genesis_consensus_key],
    }
    .encode_canonical()
    .expect("canonical network descriptor");
    for relative in [
        "metadata/network-descriptor-v1.bin",
        "rootfs/opt/outbe/sgx/network-descriptor-v1.bin",
    ] {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("descriptor parent")).expect("descriptor dirs");
        fs::write(path, &descriptor).expect("write network descriptor");
    }
}

fn test_consensus_key(network: SgxReleaseNetwork) -> [u8; 48] {
    blst::min_pk::SecretKey::key_gen(&[network.chain_id() as u8; 32], &[])
        .expect("deterministic test MinPk secret")
        .sk_to_pk()
        .to_bytes()
}

fn signed_fixture(network: SgxReleaseNetwork) -> TempDir {
    let temp = tempfile::tempdir().expect("tempdir");
    for relative in [
        "rootfs/opt/outbe/sgx/bin/outbe-tee-enclave",
        "rootfs/opt/outbe/sgx/gramine/libpal.so",
        "rootfs/opt/outbe/sgx/gramine/loader",
        "rootfs/opt/outbe/sgx/outbe-tee-enclave.manifest",
        "rootfs/opt/outbe/sgx/outbe-tee-enclave.manifest.sgx",
        "rootfs/opt/outbe/sgx/outbe-tee-enclave.sig",
    ] {
        let path = temp.path().join(relative);
        fs::create_dir_all(path.parent().expect("parent")).expect("create fixture dirs");
        fs::write(path, relative.as_bytes()).expect("write fixture");
    }
    write_network_descriptor(temp.path(), network, B256::from([0x41; 32]));
    temp
}

#[test]
fn parses_sigstruct_into_typed_measurements() {
    let measurements = parse_sigstruct_view(SIGSTRUCT).expect("valid SIGSTRUCT");
    assert!(!measurements.debug);
    assert_eq!(measurements.isv_prod_id, 1);
    assert_eq!(measurements.isv_svn, 2);
    assert_eq!(
        measurements.mrenclave,
        "c6f76b702ccb4764f5583bd9ea13c9d2464a90f6513d4931d4674baad816eedf"
    );
}

#[test]
fn compares_independent_unsigned_trees_and_rejects_drift() {
    let first = tempfile::tempdir().expect("first");
    let second = tempfile::tempdir().expect("second");
    fs::create_dir(first.path().join("rootfs")).expect("first rootfs");
    fs::create_dir(second.path().join("rootfs")).expect("second rootfs");
    fs::write(first.path().join("rootfs/enclave"), b"same").expect("first artifact");
    fs::write(second.path().join("rootfs/enclave"), b"same").expect("second artifact");

    let evidence = compare_unsigned_trees(first.path(), second.path()).expect("identical");
    assert_eq!(evidence.result, "identical");
    assert_eq!(evidence.entry_count, 2);
    assert_eq!(evidence.tree_digest.algorithm, "sha256");

    fs::write(second.path().join("rootfs/enclave"), b"changed").expect("change artifact");
    let error = compare_unsigned_trees(first.path(), second.path()).expect_err("must differ");
    assert!(error.to_string().contains("unsigned SGX bundle mismatch"));
}

#[test]
fn canonical_manifest_binds_identity_measurements_and_every_bundle_file() {
    let fixture = signed_fixture(SgxReleaseNetwork::Testnet);
    let manifest = build_bundle_manifest(
        fixture.path(),
        &repo_spec(),
        &SourceIdentity {
            source_commit: "a".repeat(40),
            source_date_epoch: 1_784_636_360,
            release_tag: "v0.1.1-testnet.1".to_owned(),
        },
        SIGSTRUCT,
    )
    .expect("build manifest");

    assert_eq!(manifest.authorization_scope, "testnet");
    assert_eq!(manifest.sigstruct_date, "2026-07-21");
    assert_eq!(manifest.files.len(), 8);
    let bytes = canonical_json(&manifest).expect("canonical JSON");
    assert_eq!(bytes.last(), Some(&b'\n'));
    verify_signed_bundle(fixture.path(), &manifest, &repo_spec(), SIGSTRUCT)
        .expect("valid signed fixture");
}

#[test]
fn signed_bundle_identity_is_not_transferable_between_testnet_and_mainnet() {
    let fixture = signed_fixture(SgxReleaseNetwork::Mainnet);
    let root = repo_root();
    let testnet = BundleSpec::read(&root.join("release/testnet-sgx-bundle-v1.json")).unwrap();
    let mainnet = BundleSpec::read(&root.join("release/mainnet-sgx-bundle-v1.json")).unwrap();
    let source = SourceIdentity {
        source_commit: "a".repeat(40),
        source_date_epoch: 1_784_636_360,
        release_tag: "v0.1.1-mainnet.1".to_owned(),
    };
    let manifest = build_bundle_manifest(fixture.path(), &mainnet, &source, SIGSTRUCT).unwrap();

    assert_eq!(manifest.authorization_scope, "mainnet");
    assert_eq!(manifest.chain_id, 676);
    assert_eq!(manifest.network_name, "outbe-mainnet-1");
    verify_signed_bundle(fixture.path(), &manifest, &mainnet, SIGSTRUCT).unwrap();
    let error = verify_signed_bundle(fixture.path(), &manifest, &testnet, SIGSTRUCT)
        .expect_err("Mainnet bundle must not verify under Testnet profile");
    assert!(error.to_string().contains("network contract"));
}

#[test]
fn verification_rejects_artifact_substitution() {
    let fixture = signed_fixture(SgxReleaseNetwork::Testnet);
    let spec = repo_spec();
    let manifest = build_bundle_manifest(
        fixture.path(),
        &spec,
        &SourceIdentity {
            source_commit: "a".repeat(40),
            source_date_epoch: 1_784_636_360,
            release_tag: "v0.1.1-testnet.1".to_owned(),
        },
        SIGSTRUCT,
    )
    .expect("build manifest");
    fs::write(
        fixture
            .path()
            .join("rootfs/opt/outbe/sgx/outbe-tee-enclave.sig"),
        b"substituted",
    )
    .expect("substitute signature");

    let error = verify_signed_bundle(fixture.path(), &manifest, &spec, SIGSTRUCT)
        .expect_err("substitution must fail");
    assert!(error.to_string().contains("bundle file matrix mismatch"));
}

#[test]
fn release_manifest_candidate_binds_one_identity_through_the_mainnet_pipeline() {
    let root = tempfile::tempdir().expect("tempdir");
    let fixture = signed_fixture(SgxReleaseNetwork::Testnet);
    let source = SourceIdentity {
        source_commit: "a".repeat(40),
        source_date_epoch: 1_784_636_360,
        release_tag: "v0.1.1-testnet.1".to_owned(),
    };
    let measurements = parse_sigstruct_view(SIGSTRUCT).expect("test SIGSTRUCT");
    let (testnet_seeded_genesis, testnet_genesis, testnet_policy, testnet_policy_schedule) =
        write_release_genesis(
            root.path(),
            SgxReleaseNetwork::Testnet,
            &measurements.mrenclave,
            &measurements.mrsigner,
            measurements.isv_prod_id,
            measurements.isv_svn,
        );
    let testnet_binding =
        DcapChainSpecBindingV1::from_genesis_path(&testnet_genesis).expect("testnet binding");
    write_network_descriptor(
        fixture.path(),
        SgxReleaseNetwork::Testnet,
        testnet_binding.genesis_hash,
    );
    let bundle_manifest = build_bundle_manifest(fixture.path(), &repo_spec(), &source, SIGSTRUCT)
        .expect("bundle manifest");
    let testnet_genesis_bytes = fs::read(&testnet_genesis).unwrap();
    let testnet_policy_bytes = testnet_policy.encode_canonical().unwrap();
    let testnet_policy_schedule_bytes = testnet_policy_schedule.encode_canonical().unwrap();
    fs::create_dir_all(fixture.path().join("metadata")).expect("metadata");
    fs::write(
        fixture.path().join("metadata/testnet-sgx-bundle.json"),
        canonical_json(&bundle_manifest).expect("canonical bundle manifest"),
    )
    .expect("write bundle manifest");
    let testnet_network_binding_evidence =
        root.path().join("testnet-genesis-binding-evidence.json");
    write_network_binding_evidence(
        &testnet_network_binding_evidence,
        SgxReleaseNetwork::Testnet,
        &testnet_seeded_genesis,
        &testnet_genesis,
        fixture.path(),
        &bundle_manifest,
        &testnet_policy,
    );
    let bundle_manifest_digest = hex::encode(Sha256::digest(
        fs::read(fixture.path().join("metadata/testnet-sgx-bundle.json"))
            .expect("read bundle manifest"),
    ));

    let elf_manifest = root.path().join("release-manifest.json");
    let elf = serde_json::json!({
        "$schema": "https://outbe.io/schemas/release-manifest-v1.json",
        "artifacts": [{
            "classification": "production",
            "digest": {"algorithm": "sha256", "value": "a".repeat(64)},
            "features": [],
            "install_profiles": ["full-node", "validator"],
            "kind": "elf",
            "media_type": "application/vnd.outbe.elf",
            "name": "outbe-tee-enclave",
            "network_compatibility": "network-manifest-required",
            "package": "outbe-tee-enclave",
            "path": "bin/outbe-tee-enclave",
            "platform": {"architecture": "x86_64", "os": "linux", "target": "x86_64-unknown-linux-gnu"},
            "role": "tee-enclave",
            "size": 1,
            "tee": {"mock": false, "stage": "unsigned-bare-elf"}
        }],
        "build": {
            "provenance": {"entrypoint": "scripts/release/reproducible-build.sh", "mode": "local-container"},
            "source_date_epoch": source.source_date_epoch
        },
        "canonicalization": {},
        "inputs": [],
        "release": {
            "lifecycle": "build-candidate",
            "source": {"clean_tree_policy": "required", "commit": source.source_commit, "tree_state": "clean"},
            "tag": source.release_tag
        },
        "schema_version": "1.0.0",
        "verification_gates": []
    });
    fs::write(
        &elf_manifest,
        canonical_json(&elf).expect("canonical ELF manifest"),
    )
    .expect("write ELF manifest");

    let oci_evidence = root.path().join("oci.json");
    let oci = serde_json::json!({
        "bundle_manifest_digest": {"algorithm": "sha256", "value": bundle_manifest_digest},
        "image": {
            "digest": {"algorithm": "sha256", "value": "c".repeat(64)},
            "media_type": "application/vnd.oci.image.index.v1+json",
            "size": 856
        },
        "image_reference": "ghcr.io/outbe/outbe-tee-enclave-testnet:v0.1.1-testnet.1",
        "measurements": bundle_manifest.measurements,
        "platform": "linux/amd64",
        "provenance_attestation": true,
        "sbom_attestation": true,
        "schema_version": "1.0.0",
        "source": bundle_manifest.source
    });
    fs::write(
        &oci_evidence,
        canonical_json(&oci).expect("canonical OCI evidence"),
    )
    .expect("write OCI evidence");

    let bundle_archive = root.path().join("outbe-tee-enclave-sgx.tar");
    let cosign_image_verification = root.path().join("cosign-image-verification.json");
    let cosign_provenance_verification = root.path().join("cosign-provenance-verification.json");
    let cosign_sbom_verification = root.path().join("cosign-sbom-verification.json");
    let sbom = root.path().join("outbe-tee-enclave.spdx.json");
    let elf_evidence = root.path().join("elf-reproducibility.json");
    let sgx_evidence = root.path().join("sgx-reproducibility.json");
    let hardware_evidence = root.path().join("hardware-sgx.json");
    let processor_dcap_evidence = root.path().join("hardware-dcap-processor.json");
    let processor_dcap_archive = root.path().join("hardware-dcap-processor.tar");
    write_deterministic_bundle_archive(fixture.path(), &bundle_archive, source.source_date_epoch)
        .expect("archive bundle fixture");
    let sbom_value = serde_json::json!({"spdxVersion": "SPDX-2.3"});
    fs::write(&sbom, canonical_json(&sbom_value).expect("canonical SBOM")).expect("SBOM");
    let image_digest = format!("sha256:{}", "c".repeat(64));
    fs::write(
        &cosign_image_verification,
        canonical_json(&serde_json::json!([{
            "critical": {
                "identity": {"docker-reference": "ghcr.io/outbe/outbe-tee-enclave-testnet"},
                "image": {"docker-manifest-digest": image_digest},
                "type": "cosign container image signature"
            },
            "optional": null
        }]))
        .expect("canonical image verification"),
    )
    .expect("image verification");
    let attestation = |predicate_type: &str, predicate: serde_json::Value| {
        let statement = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": predicate_type,
            "subject": [{"name": "ghcr.io/outbe/outbe-tee-enclave-testnet", "digest": {"sha256": "c".repeat(64)}}],
            "predicate": predicate
        });
        serde_json::json!([{
            "payload": BASE64.encode(canonical_json(&statement).expect("canonical statement")),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"sig": "verified-by-cosign"}]
        }])
    };
    fs::write(
        &cosign_sbom_verification,
        canonical_json(&attestation("https://spdx.dev/Document", sbom_value))
            .expect("canonical SBOM verification"),
    )
    .expect("SBOM verification");
    fs::write(
        &cosign_provenance_verification,
        canonical_json(&attestation(
            "https://slsa.dev/provenance/v0.2",
            serde_json::json!({
                "buildType": "https://mobyproject.org/buildkit@v1",
                "builder": {"id": ""},
                "materials": [{
                    "uri": "pkg:docker/gramineproject/gramine@1.8.1",
                    "digest": {"sha256": "d".repeat(64)}
                }]
            }),
        ))
        .expect("canonical provenance verification"),
    )
    .expect("provenance verification");
    fs::write(&elf_evidence, b"{\"result\":\"passed\"}\n").expect("ELF evidence");
    fs::write(&sgx_evidence, b"{\"result\":\"identical\"}\n").expect("SGX evidence");
    let hardware = serde_json::json!({
        "environment": {"backend": "gramine-sgx", "hardware_sgx": true},
        "image": {"digest": {"algorithm": "sha256", "value": "c".repeat(64)}},
        "measurements": bundle_manifest.measurements,
        "result": "passed"
    });
    fs::write(
        &hardware_evidence,
        canonical_json(&hardware).expect("canonical hardware evidence"),
    )
    .expect("hardware evidence");
    let fresh_dcap = |pck_ca: &str, physical_package_count: u64| {
        let pck_crl_issuer = if pck_ca == "processor" {
            "Intel SGX PCK Processor CA"
        } else {
            "Intel SGX PCK Platform CA"
        };
        let artifacts = processor_dcap_artifact_fixtures(
            SgxReleaseNetwork::Testnet,
            &testnet_genesis_bytes,
            &testnet_policy_bytes,
            &testnet_policy_schedule_bytes,
        )
        .into_iter()
        .map(|(name, bytes)| {
            (
                name,
                serde_json::json!({
                    "sha256": hex::encode(Sha256::digest(&bytes)),
                    "size": bytes.len()
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
        serde_json::json!({
            "artifacts": artifacts,
            "attestation": {
                "collateral_valid_until": 1787808799_u64,
                "pck_ca": pck_ca,
                "platform_tcb_status": "configuration-and-sw-hardening-needed",
                "public_verifier": "enclave-resident-begin-chunk-finish-v1"
            },
            "collateral": {
                "component_count": 8,
                "pck_crl": {
                    "issuer": pck_crl_issuer,
                    "kind": pck_ca,
                    "next_update": "2026-08-27T05:33:19Z",
                    "path": "collateral/pck.crl.der",
                    "size": PCK_CRL_BYTES.len(),
                    "sha256": hex::encode(Sha256::digest(PCK_CRL_BYTES)),
                    "this_update": "2026-07-28T05:33:19Z"
                },
                "root_crl": {
                    "issuer": "Intel SGX Root CA",
                    "kind": "root",
                    "next_update": "2027-02-26T13:04:00Z",
                    "path": "collateral/root-ca.crl.der",
                    "size": ROOT_CRL_BYTES.len(),
                    "sha256": hex::encode(Sha256::digest(ROOT_CRL_BYTES)),
                    "this_update": "2026-02-26T13:04:00Z"
                }
            },
            "environment": {
                "architecture": "x86_64",
                "backend": "gramine-sgx",
                "dcap": true,
                "hardware_sgx": true,
                "physical_package_count": physical_package_count
            },
            "freshness": {
                "binding_id_nonzero": true,
                "collateral_completed_at": 1785542403_u64,
                "collateral_started_at": 1785542402_u64,
                "consensus_timestamp": 1785542404_u64,
                "quote_generated_at": 1785542401_u64,
                "run_started_at": 1785542400_u64,
                "verified_at": 1785542405_u64
            },
            "image": {"digest": {"algorithm": "sha256", "value": "c".repeat(64)}},
            "measurements": bundle_manifest.measurements,
            "policy": {
                "activation_height": 1,
                "chain_id": TESTNET_CHAIN_ID,
                "genesis_hash": hex::encode(testnet_policy.genesis_hash),
                "policy_hash": hex::encode(testnet_policy.policy_hash().unwrap()),
                "policy_schedule_hash": hex::encode(testnet_policy_schedule.schedule_hash().unwrap()),
                "policy_schedule_sha256": hex::encode(Sha256::digest(&testnet_policy_schedule_bytes)),
                "policy_version": 1,
                "sha256": hex::encode(Sha256::digest(&testnet_policy_bytes))
            },
            "result": "passed",
            "schema_version": "1.0.0",
            "source_commit": source.source_commit
        })
    };
    let processor_evidence =
        canonical_json(&fresh_dcap("processor", 1)).expect("processor DCAP evidence");
    fs::write(&processor_dcap_evidence, &processor_evidence).expect("processor DCAP evidence");
    write_processor_dcap_archive(
        &processor_dcap_archive,
        &processor_evidence,
        SgxReleaseNetwork::Testnet,
        &testnet_genesis_bytes,
        &testnet_policy_bytes,
        &testnet_policy_schedule_bytes,
        source.source_date_epoch,
    );
    let inputs = VerifiedReleaseInputs {
        network: SgxReleaseNetwork::Testnet,
        bundle: fixture.path().to_owned(),
        bundle_archive,
        cosign_image_verification,
        cosign_provenance_verification,
        cosign_sbom_verification,
        elf_evidence,
        elf_manifest,
        hardware_evidence,
        processor_dcap_archive,
        processor_dcap_evidence,
        oci_evidence,
        sbom,
        sgx_evidence,
        seeded_genesis: testnet_seeded_genesis,
        network_binding_evidence: testnet_network_binding_evidence,
        genesis: testnet_genesis,
    };
    let manifest = build_release_manifest_candidate(&inputs).expect("release manifest candidate");

    assert_eq!(manifest["release"]["lifecycle"], "build-candidate");
    assert_eq!(manifest["build"]["provenance"]["mode"], "github-actions");
    assert_eq!(
        manifest["build"]["provenance"]["certificate_workflow_sha"],
        source.source_commit
    );
    assert_eq!(
        manifest["artifacts"].as_array().expect("artifacts").len(),
        4
    );
    let signed = &manifest["artifacts"][1];
    assert_eq!(signed["tee"]["stage"], "signed");
    assert_eq!(
        signed["tee"]["mrsigner"],
        bundle_manifest.measurements.mrsigner
    );
    let gates = manifest["verification_gates"].as_array().expect("gates");
    assert_eq!(gates.len(), 8);
    assert!(gates.iter().all(|gate| gate["status"] == "passed"));
    assert!(gates
        .iter()
        .any(|gate| gate["name"] == "fresh-accepted-processor-dcap"));
    let genesis_binding_gate = gates
        .iter()
        .find(|gate| gate["name"] == "seeded-genesis-to-signed-enclave-policy")
        .expect("seeded-genesis binding gate");
    assert_eq!(
        genesis_binding_gate["evidence"]
            .as_array()
            .expect("seeded-genesis gate evidence")
            .len(),
        2
    );
    let processor_gate = gates
        .iter()
        .find(|gate| gate["name"] == "fresh-accepted-processor-dcap")
        .expect("Processor DCAP gate");
    assert_eq!(
        processor_gate["evidence"]
            .as_array()
            .expect("Processor gate evidence")
            .len(),
        2,
        "the signed gate must bind both the summary and full retained evidence archive"
    );
    assert!(!gates
        .iter()
        .any(|gate| gate["name"] == "fresh-accepted-platform-dcap"));
    let oci_gate = gates
        .iter()
        .find(|gate| gate["name"] == "immutable-oci-sbom-and-provenance")
        .expect("OCI gate");
    assert_eq!(oci_gate["evidence"].as_array().expect("evidence").len(), 4);

    let original_final_genesis = fs::read(&inputs.genesis).expect("read original final genesis");
    let original_binding_evidence =
        fs::read(&inputs.network_binding_evidence).expect("read original network-binding evidence");
    let mut substituted_final: serde_json::Value =
        serde_json::from_slice(&original_final_genesis).expect("parse final genesis");
    substituted_final["unapprovedReleaseMetadata"] = serde_json::json!(true);
    fs::write(
        &inputs.genesis,
        canonical_json(&substituted_final).expect("canonical substituted final genesis"),
    )
    .expect("write substituted final genesis");
    let mut substituted_evidence: serde_json::Value =
        serde_json::from_slice(&original_binding_evidence).expect("parse binding evidence");
    substituted_evidence["final_genesis"] = test_file_digest(&inputs.genesis);
    fs::write(
        &inputs.network_binding_evidence,
        canonical_json(&substituted_evidence).expect("canonical substituted binding evidence"),
    )
    .expect("write substituted binding evidence");
    let error = build_release_manifest_candidate(&inputs)
        .expect_err("a final genesis with an additional mutation must fail");
    assert!(
        error
            .to_string()
            .contains("exact allowed seeded-genesis policy insertion"),
        "unexpected rejection: {error:?}"
    );
    fs::write(&inputs.genesis, original_final_genesis).expect("restore final genesis");
    fs::write(&inputs.network_binding_evidence, &original_binding_evidence)
        .expect("restore network-binding evidence");

    let mut forged_binding_evidence: serde_json::Value =
        serde_json::from_slice(&original_binding_evidence).expect("parse binding evidence");
    forged_binding_evidence["seeded_genesis"]["value"] = serde_json::json!("00".repeat(32));
    fs::write(
        &inputs.network_binding_evidence,
        canonical_json(&forged_binding_evidence).expect("canonical forged binding evidence"),
    )
    .expect("write forged binding evidence");
    let error = build_release_manifest_candidate(&inputs)
        .expect_err("network-binding evidence with a forged seed digest must fail");
    assert!(
        error
            .to_string()
            .contains("does not exactly bind the seed, final genesis and signed bundle"),
        "unexpected rejection: {error:?}"
    );
    fs::write(&inputs.network_binding_evidence, original_binding_evidence)
        .expect("restore network-binding evidence");

    let mainnet_spec = BundleSpec::read(&repo_root().join("release/mainnet-sgx-bundle-v1.json"))
        .expect("Mainnet bundle spec");
    let mainnet_source = SourceIdentity {
        source_commit: source.source_commit.clone(),
        source_date_epoch: source.source_date_epoch,
        release_tag: "v0.1.1-mainnet.1".to_owned(),
    };
    let mainnet_measurements = parse_sigstruct_view(SIGSTRUCT).expect("Mainnet measurements");
    let (mainnet_seeded_genesis, mainnet_genesis, mainnet_policy, mainnet_policy_schedule) =
        write_release_genesis(
            root.path(),
            SgxReleaseNetwork::Mainnet,
            &mainnet_measurements.mrenclave,
            &mainnet_measurements.mrsigner,
            mainnet_measurements.isv_prod_id,
            mainnet_measurements.isv_svn,
        );
    let mainnet_binding = DcapChainSpecBindingV1::from_genesis_path(&mainnet_genesis)
        .expect("parse Mainnet DCAP ChainSpec binding");
    write_network_descriptor(
        fixture.path(),
        SgxReleaseNetwork::Mainnet,
        mainnet_binding.genesis_hash,
    );
    let mainnet_bundle_manifest =
        build_bundle_manifest(fixture.path(), &mainnet_spec, &mainnet_source, SIGSTRUCT)
            .expect("Mainnet bundle manifest");
    let mainnet_bundle_manifest_path = fixture
        .path()
        .join(SgxReleaseNetwork::Mainnet.bundle_manifest_path());
    fs::write(
        &mainnet_bundle_manifest_path,
        canonical_json(&mainnet_bundle_manifest).expect("canonical Mainnet bundle manifest"),
    )
    .expect("write Mainnet bundle manifest");
    let mainnet_network_binding_evidence =
        root.path().join("mainnet-genesis-binding-evidence.json");
    write_network_binding_evidence(
        &mainnet_network_binding_evidence,
        SgxReleaseNetwork::Mainnet,
        &mainnet_seeded_genesis,
        &mainnet_genesis,
        fixture.path(),
        &mainnet_bundle_manifest,
        &mainnet_policy,
    );
    let mainnet_bundle_manifest_digest = hex::encode(Sha256::digest(
        fs::read(&mainnet_bundle_manifest_path).expect("read Mainnet bundle manifest"),
    ));
    assert_eq!(mainnet_binding.chain_id, 676);
    let consensus_storage = root.path().join("mainnet-consensus");
    bind_consensus_storage_identity(
        &consensus_storage,
        mainnet_binding.chain_id,
        mainnet_binding.genesis_hash,
    )
    .expect("bind fresh Mainnet consensus storage");
    bind_consensus_storage_identity(
        &consensus_storage,
        mainnet_binding.chain_id,
        mainnet_binding.genesis_hash,
    )
    .expect("reopen exact Mainnet consensus storage");
    assert!(bind_consensus_storage_identity(
        &consensus_storage,
        mainnet_binding.chain_id,
        B256::repeat_byte(0xff),
    )
    .is_err());
    let mainnet_genesis_bytes = fs::read(&mainnet_genesis).unwrap();
    let mainnet_policy_bytes = mainnet_policy.encode_canonical().unwrap();
    let mainnet_policy_schedule_bytes = mainnet_policy_schedule.encode_canonical().unwrap();

    let mut mainnet_elf = elf.clone();
    mainnet_elf["release"]["tag"] = serde_json::json!(mainnet_source.release_tag.clone());
    let mainnet_elf_manifest = root.path().join("mainnet-release-manifest.json");
    fs::write(
        &mainnet_elf_manifest,
        canonical_json(&mainnet_elf).expect("canonical Mainnet ELF manifest"),
    )
    .expect("write Mainnet ELF manifest");
    let mut mainnet_oci = oci.clone();
    mainnet_oci["bundle_manifest_digest"]["value"] =
        serde_json::json!(mainnet_bundle_manifest_digest);
    mainnet_oci["image_reference"] =
        serde_json::json!("ghcr.io/outbe/outbe-tee-enclave-mainnet:v0.1.1-mainnet.1");
    mainnet_oci["source"] = serde_json::to_value(&mainnet_bundle_manifest.source).unwrap();
    let mainnet_oci_evidence = root.path().join("mainnet-oci.json");
    fs::write(
        &mainnet_oci_evidence,
        canonical_json(&mainnet_oci).expect("canonical Mainnet OCI evidence"),
    )
    .expect("write Mainnet OCI evidence");

    let mut mainnet_dcap = fresh_dcap("processor", 1);
    mainnet_dcap["artifacts"] = serde_json::Value::Object(
        processor_dcap_artifact_fixtures(
            SgxReleaseNetwork::Mainnet,
            &mainnet_genesis_bytes,
            &mainnet_policy_bytes,
            &mainnet_policy_schedule_bytes,
        )
        .into_iter()
        .map(|(name, bytes)| {
            (
                name,
                serde_json::json!({
                    "sha256": hex::encode(Sha256::digest(&bytes)),
                    "size": bytes.len()
                }),
            )
        })
        .collect(),
    );
    mainnet_dcap["policy"] = serde_json::json!({
        "activation_height": 1,
        "chain_id": SgxReleaseNetwork::Mainnet.chain_id(),
        "genesis_hash": hex::encode(mainnet_policy.genesis_hash),
        "policy_hash": hex::encode(mainnet_policy.policy_hash().unwrap()),
        "policy_schedule_hash": hex::encode(mainnet_policy_schedule.schedule_hash().unwrap()),
        "policy_schedule_sha256": hex::encode(Sha256::digest(&mainnet_policy_schedule_bytes)),
        "policy_version": 1,
        "sha256": hex::encode(Sha256::digest(&mainnet_policy_bytes))
    });
    let mainnet_processor_evidence = root.path().join("mainnet-hardware-dcap-processor.json");
    let mainnet_processor_evidence_bytes =
        canonical_json(&mainnet_dcap).expect("canonical Mainnet Processor evidence");
    fs::write(
        &mainnet_processor_evidence,
        &mainnet_processor_evidence_bytes,
    )
    .expect("write Mainnet Processor evidence");
    let mainnet_processor_archive = root.path().join("mainnet-hardware-dcap-processor.tar");
    write_processor_dcap_archive(
        &mainnet_processor_archive,
        &mainnet_processor_evidence_bytes,
        SgxReleaseNetwork::Mainnet,
        &mainnet_genesis_bytes,
        &mainnet_policy_bytes,
        &mainnet_policy_schedule_bytes,
        mainnet_source.source_date_epoch,
    );
    let mainnet_bundle_archive = root.path().join("mainnet-outbe-tee-enclave-sgx.tar");
    write_deterministic_bundle_archive(
        fixture.path(),
        &mainnet_bundle_archive,
        mainnet_source.source_date_epoch,
    )
    .expect("archive Mainnet bundle fixture");
    let mainnet_inputs = VerifiedReleaseInputs {
        network: SgxReleaseNetwork::Mainnet,
        bundle_archive: mainnet_bundle_archive,
        elf_manifest: mainnet_elf_manifest,
        oci_evidence: mainnet_oci_evidence,
        processor_dcap_archive: mainnet_processor_archive,
        processor_dcap_evidence: mainnet_processor_evidence.clone(),
        seeded_genesis: mainnet_seeded_genesis,
        network_binding_evidence: mainnet_network_binding_evidence,
        genesis: mainnet_genesis,
        ..inputs.clone()
    };
    let mainnet_manifest = build_release_manifest_candidate(&mainnet_inputs)
        .expect("Mainnet release manifest candidate");
    assert_eq!(mainnet_manifest["network"]["chain_id"], 676);
    assert_eq!(mainnet_manifest["network"]["chain_name"], "outbe-mainnet-1");
    assert_eq!(
        mainnet_manifest["network"]["genesis_hash"],
        format!("{:#x}", mainnet_binding.genesis_hash)
    );
    assert_eq!(
        mainnet_manifest["network"]["genesis_file"]["path"],
        "mainnet-genesis.json"
    );
    assert_eq!(
        mainnet_manifest["artifacts"][1]["tee"]["authorization_scope"],
        "mainnet"
    );

    for foreign_member in ["testnet-genesis.json", "mainnet-genesis.json"] {
        let mut invalid = mainnet_dcap.clone();
        let artifacts = invalid["artifacts"].as_object_mut().unwrap();
        if foreign_member == "testnet-genesis.json" {
            let mainnet_record = artifacts.remove("mainnet-genesis.json").unwrap();
            artifacts.insert(foreign_member.to_owned(), mainnet_record);
        } else {
            artifacts.remove(foreign_member);
        }
        fs::write(
            &mainnet_processor_evidence,
            canonical_json(&invalid).expect("canonical invalid Mainnet evidence"),
        )
        .expect("write invalid Mainnet evidence");
        let error = build_release_manifest_candidate(&mainnet_inputs)
            .expect_err("foreign or missing Mainnet genesis member must fail");
        assert!(
            error.to_string().contains("release ChainSpec binding")
                || error.to_string().contains("exact canonical artifact set"),
            "unexpected rejection: {error:?}"
        );
    }
    let mut dual = mainnet_dcap.clone();
    let record = dual["artifacts"]["mainnet-genesis.json"].clone();
    dual["artifacts"]
        .as_object_mut()
        .unwrap()
        .insert("testnet-genesis.json".to_owned(), record);
    fs::write(
        &mainnet_processor_evidence,
        canonical_json(&dual).expect("canonical dual-network evidence"),
    )
    .expect("write dual-network evidence");
    let error = build_release_manifest_candidate(&mainnet_inputs)
        .expect_err("dual-network genesis members must fail");
    assert!(
        error.to_string().contains("exact canonical artifact set"),
        "unexpected rejection: {error:?}"
    );
    fs::remove_file(mainnet_bundle_manifest_path).expect("remove Mainnet bundle metadata");
    write_network_descriptor(
        fixture.path(),
        SgxReleaseNetwork::Testnet,
        testnet_binding.genesis_hash,
    );

    let mut substituted_retained_policy = testnet_policy_bytes.clone();
    substituted_retained_policy[0] ^= 1;
    write_processor_dcap_archive(
        &inputs.processor_dcap_archive,
        &processor_evidence,
        SgxReleaseNetwork::Testnet,
        &testnet_genesis_bytes,
        &substituted_retained_policy,
        &testnet_policy_schedule_bytes,
        source.source_date_epoch,
    );
    let error = build_release_manifest_candidate(&inputs)
        .expect_err("substituted retained policy must not pass finalization");
    assert!(
        error.to_string().contains("archive member digest mismatch"),
        "unexpected rejection: {error:?}"
    );
    write_processor_dcap_archive(
        &inputs.processor_dcap_archive,
        &processor_evidence,
        SgxReleaseNetwork::Testnet,
        &testnet_genesis_bytes,
        &testnet_policy_bytes,
        &testnet_policy_schedule_bytes,
        source.source_date_epoch,
    );

    let mut truncated_artifact_set = fresh_dcap("processor", 1);
    truncated_artifact_set["artifacts"]
        .as_object_mut()
        .expect("artifact records")
        .remove("intent-v1.bin");
    let truncated_artifact_set =
        canonical_json(&truncated_artifact_set).expect("truncated artifact set evidence");
    fs::write(&inputs.processor_dcap_evidence, &truncated_artifact_set)
        .expect("replace exact Processor artifact set");
    write_processor_dcap_archive(
        &inputs.processor_dcap_archive,
        &truncated_artifact_set,
        SgxReleaseNetwork::Testnet,
        &testnet_genesis_bytes,
        &testnet_policy_bytes,
        &testnet_policy_schedule_bytes,
        source.source_date_epoch,
    );
    let error = build_release_manifest_candidate(&inputs)
        .expect_err("truncated Processor artifact set must not pass finalization");
    assert!(error.to_string().contains("exact canonical artifact set"));
    fs::write(&inputs.processor_dcap_evidence, &processor_evidence)
        .expect("restore exact Processor evidence");
    write_processor_dcap_archive(
        &inputs.processor_dcap_archive,
        &processor_evidence,
        SgxReleaseNetwork::Testnet,
        &testnet_genesis_bytes,
        &testnet_policy_bytes,
        &testnet_policy_schedule_bytes,
        source.source_date_epoch,
    );

    let mut disconnected_pck_crl = fresh_dcap("processor", 1);
    disconnected_pck_crl["collateral"]["pck_crl"]["sha256"] = serde_json::json!("ff".repeat(32));
    let disconnected_pck_crl =
        canonical_json(&disconnected_pck_crl).expect("disconnected PCK CRL provenance");
    fs::write(&inputs.processor_dcap_evidence, &disconnected_pck_crl)
        .expect("replace PCK CRL provenance");
    write_processor_dcap_archive(
        &inputs.processor_dcap_archive,
        &disconnected_pck_crl,
        SgxReleaseNetwork::Testnet,
        &testnet_genesis_bytes,
        &testnet_policy_bytes,
        &testnet_policy_schedule_bytes,
        source.source_date_epoch,
    );
    let error = build_release_manifest_candidate(&inputs)
        .expect_err("CRL provenance disconnected from retained bytes must not pass");
    assert!(error.to_string().contains("retained PCK CRL"));
    fs::write(&inputs.processor_dcap_evidence, &processor_evidence)
        .expect("restore exact Processor evidence");
    write_processor_dcap_archive(
        &inputs.processor_dcap_archive,
        &processor_evidence,
        SgxReleaseNetwork::Testnet,
        &testnet_genesis_bytes,
        &testnet_policy_bytes,
        &testnet_policy_schedule_bytes,
        source.source_date_epoch,
    );

    let mut pre_collateral_consensus_time = fresh_dcap("processor", 1);
    pre_collateral_consensus_time["freshness"]["consensus_timestamp"] =
        serde_json::json!(1785542401_u64);
    let pre_collateral_consensus_time = canonical_json(&pre_collateral_consensus_time)
        .expect("pre-collateral consensus timestamp evidence");
    fs::write(
        &inputs.processor_dcap_evidence,
        &pre_collateral_consensus_time,
    )
    .expect("replace consensus timestamp provenance");
    write_processor_dcap_archive(
        &inputs.processor_dcap_archive,
        &pre_collateral_consensus_time,
        SgxReleaseNetwork::Testnet,
        &testnet_genesis_bytes,
        &testnet_policy_bytes,
        &testnet_policy_schedule_bytes,
        source.source_date_epoch,
    );
    let error = build_release_manifest_candidate(&inputs)
        .expect_err("pre-collateral consensus timestamp must not pass finalization");
    assert!(error.to_string().contains("freshness order"));
    fs::write(&inputs.processor_dcap_evidence, &processor_evidence)
        .expect("restore exact Processor evidence");
    write_processor_dcap_archive(
        &inputs.processor_dcap_archive,
        &processor_evidence,
        SgxReleaseNetwork::Testnet,
        &testnet_genesis_bytes,
        &testnet_policy_bytes,
        &testnet_policy_schedule_bytes,
        source.source_date_epoch,
    );

    let zero_topology_evidence =
        canonical_json(&fresh_dcap("processor", 0)).expect("zero-topology evidence");
    fs::write(&inputs.processor_dcap_evidence, &zero_topology_evidence)
        .expect("replace Processor evidence with untrusted guest topology");
    write_processor_dcap_archive(
        &inputs.processor_dcap_archive,
        &zero_topology_evidence,
        SgxReleaseNetwork::Testnet,
        &testnet_genesis_bytes,
        &testnet_policy_bytes,
        &testnet_policy_schedule_bytes,
        source.source_date_epoch,
    );
    build_release_manifest_candidate(&inputs)
        .expect("guest topology provenance must not decide DCAP acceptance");
    fs::write(&inputs.processor_dcap_evidence, &processor_evidence)
        .expect("restore exact Processor evidence");
    write_processor_dcap_archive(
        &inputs.processor_dcap_archive,
        &processor_evidence,
        SgxReleaseNetwork::Testnet,
        &testnet_genesis_bytes,
        &testnet_policy_bytes,
        &testnet_policy_schedule_bytes,
        source.source_date_epoch,
    );

    fs::write(
        &inputs.processor_dcap_evidence,
        canonical_json(&fresh_dcap("platform", 1)).expect("wrong-CA evidence"),
    )
    .expect("replace Processor evidence with Platform evidence");
    let error = build_release_manifest_candidate(&inputs)
        .expect_err("Platform evidence must not satisfy the Processor gate");
    assert!(error.to_string().contains("processor DCAP evidence"));

    let mut stale = fresh_dcap("processor", 1);
    stale["freshness"]["collateral_started_at"] = serde_json::json!(100);
    fs::write(
        &inputs.processor_dcap_evidence,
        canonical_json(&stale).expect("stale evidence"),
    )
    .expect("replace Processor evidence with stale ordering");
    let error = build_release_manifest_candidate(&inputs)
        .expect_err("pre-run collateral must not satisfy the Processor gate");
    assert!(error.to_string().contains("freshness order"));

    fs::write(
        &inputs.processor_dcap_evidence,
        canonical_json(&fresh_dcap("processor", 1)).expect("restored Processor evidence"),
    )
    .expect("restore Processor evidence");

    let mut wrong_testnet_binding = fresh_dcap("processor", 1);
    wrong_testnet_binding["policy"]["genesis_hash"] = serde_json::json!("00".repeat(32));
    fs::write(
        &inputs.processor_dcap_evidence,
        canonical_json(&wrong_testnet_binding).expect("wrong testnet binding"),
    )
    .expect("replace Processor evidence with wrong testnet binding");
    let error = build_release_manifest_candidate(&inputs)
        .expect_err("wrong testnet ChainSpec binding must not pass finalization");
    assert!(error.to_string().contains("release ChainSpec binding"));

    fs::write(
        &inputs.processor_dcap_evidence,
        canonical_json(&fresh_dcap("processor", 1)).expect("restored Processor evidence"),
    )
    .expect("restore Processor evidence");

    let mut wrong_policy_bytes = fresh_dcap("processor", 1);
    wrong_policy_bytes["policy"]["sha256"] = serde_json::json!("00".repeat(32));
    fs::write(
        &inputs.processor_dcap_evidence,
        canonical_json(&wrong_policy_bytes).expect("wrong policy bytes binding"),
    )
    .expect("replace Processor evidence with wrong policy bytes binding");
    let error = build_release_manifest_candidate(&inputs)
        .expect_err("substituted policy bytes must not pass finalization");
    assert!(error.to_string().contains("release ChainSpec binding"));

    fs::write(
        &inputs.processor_dcap_evidence,
        canonical_json(&fresh_dcap("processor", 1)).expect("restored Processor evidence"),
    )
    .expect("restore Processor evidence");

    let mut wrong_schedule_bytes = fresh_dcap("processor", 1);
    wrong_schedule_bytes["policy"]["policy_schedule_sha256"] = serde_json::json!("00".repeat(32));
    fs::write(
        &inputs.processor_dcap_evidence,
        canonical_json(&wrong_schedule_bytes).expect("wrong policy schedule bytes binding"),
    )
    .expect("replace Processor evidence with wrong policy schedule bytes binding");
    let error = build_release_manifest_candidate(&inputs)
        .expect_err("substituted policy schedule bytes must not pass finalization");
    assert!(error.to_string().contains("release ChainSpec binding"));

    fs::write(
        &inputs.processor_dcap_evidence,
        canonical_json(&fresh_dcap("processor", 1)).expect("restored Processor evidence"),
    )
    .expect("restore Processor evidence");

    let mut substituted_testnet_genesis = testnet_genesis_bytes.clone();
    substituted_testnet_genesis.push(b'\n');
    fs::write(&inputs.genesis, substituted_testnet_genesis)
        .expect("substitute testnet genesis bytes");
    let error = build_release_manifest_candidate(&inputs)
        .expect_err("substituted testnet genesis bytes must not pass finalization");
    assert!(
        error
            .to_string()
            .contains("exact allowed seeded-genesis policy insertion"),
        "unexpected rejection: {error:?}"
    );
    fs::write(&inputs.genesis, &testnet_genesis_bytes)
        .expect("restore exact testnet genesis bytes");

    let mut incomplete_crl = fresh_dcap("processor", 1);
    incomplete_crl["collateral"]["pck_crl"]
        .as_object_mut()
        .expect("PCK CRL object")
        .remove("next_update");
    fs::write(
        &inputs.processor_dcap_evidence,
        canonical_json(&incomplete_crl).expect("incomplete CRL provenance"),
    )
    .expect("replace Processor evidence with incomplete CRL provenance");
    let error = build_release_manifest_candidate(&inputs)
        .expect_err("CRL provenance without validity must not pass");
    assert!(error.to_string().contains("next_update"));

    fs::write(
        &inputs.processor_dcap_evidence,
        canonical_json(&fresh_dcap("processor", 1)).expect("restored Processor evidence"),
    )
    .expect("restore Processor evidence");

    fs::write(
        &inputs.cosign_sbom_verification,
        canonical_json(&attestation(
            "https://spdx.dev/Document",
            serde_json::json!({"spdxVersion": "SPDX-2.2"}),
        ))
        .expect("mismatched verification"),
    )
    .expect("replace verification");
    let error = build_release_manifest_candidate(&inputs)
        .expect_err("attested SBOM substitution must fail");
    assert!(error.to_string().contains("attested SBOM"));
}
