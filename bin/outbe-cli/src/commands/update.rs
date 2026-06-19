//! Upgrade governance commands.

use alloy_primitives::U256;
use alloy_sol_types::SolCall;
use clap::Subcommand;
use eyre::{Result, WrapErr};
use outbe_update::constants::PROTOCOL_VERSION;
use outbe_update::state::version_gt;
use serde_json::Value;

use crate::abi::{IUpdate, UPDATE_ADDRESS};
use crate::rpc::Rpc;

const PROTOCOL_VERSION_MINOR_BITS: u32 = 24;
const MAX_PROTOCOL_VERSION_MINOR: u32 = (1u32 << PROTOCOL_VERSION_MINOR_BITS) - 1;

#[derive(Subcommand)]
pub enum UpdateCmd {
    /// Create an upgrade proposal (active validator only).
    Propose {
        /// Protocol version as `major.minor` or raw `u32`. Defaults to this binary's version.
        #[arg(long)]
        version: Option<String>,
        /// Block height at which the proposal should activate.
        #[arg(long)]
        activation_height: u64,
        /// Optional proposal metadata (UTF-8 text or `0x` hex).
        #[arg(long)]
        info: Option<String>,
        /// Skip local version compatibility checks.
        #[arg(long)]
        force: bool,
    },
    /// Cast a vote on a pending proposal (active validator only).
    Vote {
        /// Proposal id.
        #[arg(long)]
        proposal_id: U256,
        /// Vote yes.
        #[arg(long, group = "vote")]
        yes: bool,
        /// Vote no.
        #[arg(long, group = "vote")]
        no: bool,
        /// Skip local version compatibility checks for `--yes` votes.
        #[arg(long)]
        force: bool,
    },
    /// Show active version and proposal status.
    Status {
        /// Optional proposal id for detailed status.
        #[arg(long)]
        proposal_id: Option<U256>,
    },
}

impl UpdateCmd {
    pub async fn run(self, client: &(impl Rpc + Sync), private_key: Option<&str>) -> Result<()> {
        match self {
            Self::Propose {
                version,
                activation_height,
                info,
                force,
            } => propose(client, private_key, version, activation_height, info, force).await,
            Self::Vote {
                proposal_id,
                yes,
                no,
                force,
            } => {
                let approve = match (yes, no) {
                    (true, false) => true,
                    (false, true) => false,
                    (true, true) => eyre::bail!("specify either --yes or --no, not both"),
                    (false, false) => eyre::bail!("specify --yes or --no"),
                };
                vote(client, private_key, proposal_id, approve, force).await
            }
            Self::Status { proposal_id } => status(client, proposal_id).await,
        }
    }
}

fn encode_protocol_version(major: u8, minor: u32) -> u32 {
    ((major as u32) << PROTOCOL_VERSION_MINOR_BITS) | minor
}

fn parse_protocol_version(input: &str) -> Result<u32> {
    if let Some((major, minor)) = input.split_once('.') {
        let major = major
            .parse::<u8>()
            .wrap_err_with(|| format!("invalid major version in '{input}'"))?;
        let minor = minor
            .parse::<u32>()
            .wrap_err_with(|| format!("invalid minor version in '{input}'"))?;
        if minor > MAX_PROTOCOL_VERSION_MINOR {
            eyre::bail!("minor version exceeds max {MAX_PROTOCOL_VERSION_MINOR}");
        }
        return Ok(encode_protocol_version(major, minor));
    }

    let raw = input.parse::<u32>().wrap_err_with(|| {
        format!("invalid protocol version '{input}', expected major.minor or u32")
    })?;
    Ok(raw)
}

fn resolve_proposal_version(version: Option<String>) -> Result<u32> {
    match version {
        Some(value) => parse_protocol_version(&value),
        None => Ok(PROTOCOL_VERSION),
    }
}

fn parse_info_bytes(info: Option<String>) -> Result<Vec<u8>> {
    let Some(info) = info else {
        return Ok(Vec::new());
    };
    if let Some(hex_str) = info.strip_prefix("0x") {
        return hex::decode(hex_str).wrap_err("invalid --info hex");
    }
    Ok(info.into_bytes())
}

fn format_protocol_version(version: u32) -> String {
    let major = (version >> PROTOCOL_VERSION_MINOR_BITS) as u8;
    let minor = version & MAX_PROTOCOL_VERSION_MINOR;
    format!("v{major}.{minor} ({version})")
}

fn active_version_from_rpc(active: &Value) -> u32 {
    active["version"].as_u64().unwrap_or(0) as u32
}

fn proposal_version_from_rpc(proposal: &Value) -> Result<u32> {
    proposal["version"]
        .as_u64()
        .map(|version| version as u32)
        .ok_or_else(|| eyre::eyre!("proposal response missing version field"))
}

async fn fetch_active_version(client: &(impl Rpc + Sync)) -> Result<u32> {
    let active = client.outbe_get_update_active_version().await?;
    Ok(active_version_from_rpc(&active))
}

fn ensure_propose_version_compatible(proposed: u32, active: u32, binary: u32) -> Result<()> {
    if !version_gt(proposed, active) {
        eyre::bail!(
            "proposed version {} must be greater than active on-chain version {}; use --force to override",
            format_protocol_version(proposed),
            format_protocol_version(active)
        );
    }
    if proposed > binary {
        eyre::bail!(
            "proposed version {} exceeds binary protocol version {}; use --force to override",
            format_protocol_version(proposed),
            format_protocol_version(binary)
        );
    }
    Ok(())
}

fn ensure_approve_version_compatible(proposal_version: u32, binary: u32) -> Result<()> {
    if proposal_version > binary {
        eyre::bail!(
            "proposal version {} exceeds binary protocol version {}; upgrade the binary or use --force",
            format_protocol_version(proposal_version),
            format_protocol_version(binary)
        );
    }
    Ok(())
}

async fn propose(
    client: &(impl Rpc + Sync),
    private_key: Option<&str>,
    version: Option<String>,
    activation_height: u64,
    info: Option<String>,
    force: bool,
) -> Result<()> {
    let signer = super::require_signer(private_key)?;
    let version = resolve_proposal_version(version)?;
    if !force {
        let active = fetch_active_version(client).await?;
        ensure_propose_version_compatible(version, active, PROTOCOL_VERSION)?;
    }
    let info_bytes = parse_info_bytes(info)?;

    let call = IUpdate::createProposalCall {
        version,
        activationHeight: activation_height,
        info: info_bytes.into(),
    };
    let tx_hash = signer
        .send_tx(client, UPDATE_ADDRESS, call.abi_encode(), U256::ZERO)
        .await?;
    println!(
        "Proposal transaction sent: {tx_hash} (version {})",
        format_protocol_version(version)
    );
    Ok(())
}

async fn vote(
    client: &(impl Rpc + Sync),
    private_key: Option<&str>,
    proposal_id: U256,
    approve: bool,
    force: bool,
) -> Result<()> {
    if approve && !force {
        let proposal = client
            .outbe_get_update_proposal(proposal_id)
            .await?
            .ok_or_else(|| eyre::eyre!("proposal {proposal_id} not found"))?;
        let proposal_version = proposal_version_from_rpc(&proposal)?;
        ensure_approve_version_compatible(proposal_version, PROTOCOL_VERSION)?;
    }

    let signer = super::require_signer(private_key)?;
    let call = IUpdate::castVoteCall {
        proposalId: proposal_id,
        approve,
    };
    let tx_hash = signer
        .send_tx(client, UPDATE_ADDRESS, call.abi_encode(), U256::ZERO)
        .await?;
    println!(
        "Vote transaction sent: {tx_hash} (proposal {proposal_id}, approve={approve})"
    );
    Ok(())
}

async fn status(client: &(impl Rpc + Sync), proposal_id: Option<U256>) -> Result<()> {
    if let Some(proposal_id) = proposal_id {
        let proposal = client
            .outbe_get_update_proposal(proposal_id)
            .await?
            .ok_or_else(|| eyre::eyre!("proposal {proposal_id} not found"))?;
        print_proposal("Proposal", &proposal);
        return Ok(());
    }

    let active = client.outbe_get_update_active_version().await?;
    println!(
        "Active version: {} (activation height {})",
        format_protocol_version(active["version"].as_u64().unwrap_or(0) as u32),
        active["activationHeight"].as_u64().unwrap_or(0)
    );
    println!(
        "Binary version: {}",
        format_protocol_version(PROTOCOL_VERSION)
    );

    let pending = client.outbe_list_update_pending_proposals().await?;
    println!(
        "Pending proposals: {}",
        pending.as_array().map_or(0, |v| v.len())
    );
    for proposal in pending.as_array().into_iter().flatten() {
        print_proposal("  Pending", proposal);
    }

    let waiting = client.outbe_list_update_waiting_proposals().await?;
    println!(
        "Waiting for activation: {}",
        waiting.as_array().map_or(0, |v| v.len())
    );
    for proposal in waiting.as_array().into_iter().flatten() {
        print_proposal("  Waiting", proposal);
    }

    Ok(())
}

fn print_proposal(label: &str, proposal: &Value) {
    let proposal_id = proposal["proposalId"]
        .as_str()
        .map(str::to_string)
        .or_else(|| proposal["proposalId"].as_u64().map(|n| n.to_string()))
        .unwrap_or_else(|| "?".to_string());
    let version = proposal["version"].as_u64().unwrap_or(0) as u32;
    let status = proposal["status"].as_str().unwrap_or("unknown");
    let activation = proposal["activationHeight"].as_u64().unwrap_or(0);
    let deadline = proposal["votingDeadlineHeight"].as_u64().unwrap_or(0);
    let yes = proposal["state"]["yes"].as_u64().unwrap_or(0);
    let no = proposal["state"]["no"].as_u64().unwrap_or(0);

    println!(
        "{label} #{proposal_id}: {} status={status} activation={activation} deadline={deadline} votes={yes}/{no}",
        format_protocol_version(version)
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::mock::{recording_send_tx_rpc, MockRpc};

    #[test]
    fn parse_protocol_version_major_minor() {
        assert_eq!(
            parse_protocol_version("1.2").unwrap(),
            encode_protocol_version(1, 2)
        );
    }

    #[test]
    fn parse_protocol_version_raw_u32() {
        assert_eq!(parse_protocol_version("65536").unwrap(), 65536);
    }

    #[test]
    fn resolve_proposal_version_defaults_to_binary() {
        assert_eq!(resolve_proposal_version(None).unwrap(), PROTOCOL_VERSION);
    }

    #[test]
    fn propose_version_must_be_greater_than_active() {
        let err = ensure_propose_version_compatible(PROTOCOL_VERSION, PROTOCOL_VERSION, PROTOCOL_VERSION)
            .unwrap_err();
        assert!(err.to_string().contains("must be greater than active"));
    }

    #[test]
    fn propose_version_must_not_exceed_binary() {
        let err = ensure_propose_version_compatible(
            encode_protocol_version(9, 0),
            0,
            PROTOCOL_VERSION,
        )
        .unwrap_err();
        assert!(err.to_string().contains("exceeds binary protocol version"));
    }

    #[test]
    fn approve_version_must_not_exceed_binary() {
        let err = ensure_approve_version_compatible(encode_protocol_version(9, 0), PROTOCOL_VERSION)
            .unwrap_err();
        assert!(err.to_string().contains("exceeds binary protocol version"));
    }

    #[test]
    fn test_cli_parse_update_status() {
        use crate::Cli;
        use clap::Parser;
        let cli = Cli::try_parse_from(["outbe-cli", "update", "status"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_update_propose_without_version() {
        use crate::Cli;
        use clap::Parser;
        let cli = Cli::try_parse_from([
            "outbe-cli",
            "update",
            "propose",
            "--activation-height",
            "1000",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_update_propose_with_force() {
        use crate::Cli;
        use clap::Parser;
        let cli = Cli::try_parse_from([
            "outbe-cli",
            "update",
            "propose",
            "--version",
            "9.0",
            "--activation-height",
            "1000",
            "--force",
        ]);
        assert!(cli.is_ok());
    }

    #[tokio::test]
    async fn propose_sends_create_proposal_tx() {
        let private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let call = IUpdate::createProposalCall {
            version: encode_protocol_version(1, 2),
            activationHeight: 1000,
            info: b"notes".to_vec().into(),
        };
        let rpc = recording_send_tx_rpc(private_key, UPDATE_ADDRESS, call.abi_encode(), U256::ZERO)
            .unwrap();
        UpdateCmd::Propose {
            version: Some("1.2".to_string()),
            activation_height: 1000,
            info: Some("notes".to_string()),
            force: true,
        }
        .run(&rpc, Some(private_key))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn propose_rejects_incompatible_version_without_force() {
        let mock = MockRpc {
            update_active_version: Ok(serde_json::json!({
                "version": PROTOCOL_VERSION,
                "major": 0,
                "minor": 1,
                "activationHeight": 1
            })),
            ..MockRpc::default()
        };
        let err = UpdateCmd::Propose {
            version: Some("0.1".to_string()),
            activation_height: 1000,
            info: None,
            force: false,
        }
        .run(&mock, Some("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"))
        .await
        .unwrap_err();
        assert!(err.to_string().contains("must be greater than active"));
    }

    #[tokio::test]
    async fn vote_rejects_approve_when_binary_is_too_old() {
        let mock = MockRpc {
            update_proposal: Ok(Some(serde_json::json!({
                "proposalId": 1,
                "version": encode_protocol_version(9, 0),
                "status": "pending",
                "state": { "yes": 0, "no": 0 }
            }))),
            ..MockRpc::default()
        };
        let err = UpdateCmd::Vote {
            proposal_id: U256::from(1),
            yes: true,
            no: false,
            force: false,
        }
        .run(&mock, Some("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"))
        .await
        .unwrap_err();
        assert!(err.to_string().contains("exceeds binary protocol version"));
    }

    #[tokio::test]
    async fn status_reads_update_rpc_methods() {
        let active = serde_json::json!({
            "version": 65538,
            "major": 1,
            "minor": 2,
            "activationHeight": 500
        });
        let pending = serde_json::json!([]);
        let waiting = serde_json::json!([]);
        let mock = MockRpc {
            update_active_version: Ok(active),
            update_pending_proposals: Ok(pending),
            update_waiting_proposals: Ok(waiting),
            ..MockRpc::default()
        };
        UpdateCmd::Status { proposal_id: None }
            .run(&mock, None)
            .await
            .unwrap();
    }
}
