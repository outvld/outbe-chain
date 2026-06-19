//! Upgrade governance commands.

use alloy_primitives::U256;
use alloy_sol_types::SolCall;
use clap::Subcommand;
use eyre::{Result, WrapErr};
use serde_json::Value;

use crate::abi::{IUpdate, UPDATE_ADDRESS};
use crate::rpc::Rpc;

const PROTOCOL_VERSION_MINOR_BITS: u32 = 24;
const MAX_PROTOCOL_VERSION_MINOR: u32 = (1u32 << PROTOCOL_VERSION_MINOR_BITS) - 1;

#[derive(Subcommand)]
pub enum UpdateCmd {
    /// Create an upgrade proposal (active validator only).
    Propose {
        /// Protocol version as `major.minor` or raw `u32`.
        #[arg(long)]
        version: String,
        /// Block height at which the proposal should activate.
        #[arg(long)]
        activation_height: u64,
        /// Optional proposal metadata (UTF-8 text or `0x` hex).
        #[arg(long)]
        info: Option<String>,
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
            } => propose(client, private_key, version, activation_height, info).await,
            Self::Vote {
                proposal_id,
                yes,
                no,
            } => {
                let approve = match (yes, no) {
                    (true, false) => true,
                    (false, true) => false,
                    (true, true) => eyre::bail!("specify either --yes or --no, not both"),
                    (false, false) => eyre::bail!("specify --yes or --no"),
                };
                vote(client, private_key, proposal_id, approve).await
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

async fn propose(
    client: &(impl Rpc + Sync),
    private_key: Option<&str>,
    version: String,
    activation_height: u64,
    info: Option<String>,
) -> Result<()> {
    let signer = super::require_signer(private_key)?;
    let version = parse_protocol_version(&version)?;
    let info_bytes = parse_info_bytes(info)?;

    let call = IUpdate::createProposalCall {
        version,
        activationHeight: activation_height,
        info: info_bytes.into(),
    };
    let tx_hash = signer
        .send_tx(client, UPDATE_ADDRESS, call.abi_encode(), U256::ZERO)
        .await?;
    println!("Proposal transaction sent: {tx_hash}");
    Ok(())
}

async fn vote(
    client: &(impl Rpc + Sync),
    private_key: Option<&str>,
    proposal_id: U256,
    approve: bool,
) -> Result<()> {
    let signer = super::require_signer(private_key)?;
    let call = IUpdate::castVoteCall {
        proposalId: proposal_id,
        approve,
    };
    let tx_hash = signer
        .send_tx(client, UPDATE_ADDRESS, call.abi_encode(), U256::ZERO)
        .await?;
    println!("Vote transaction sent: {tx_hash} (proposal {proposal_id}, approve={approve})");
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
    fn test_cli_parse_update_status() {
        use crate::Cli;
        use clap::Parser;
        let cli = Cli::try_parse_from(["outbe-cli", "update", "status"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_update_propose() {
        use crate::Cli;
        use clap::Parser;
        let cli = Cli::try_parse_from([
            "outbe-cli",
            "update",
            "propose",
            "--version",
            "1.2",
            "--activation-height",
            "1000",
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
            version: "1.2".to_string(),
            activation_height: 1000,
            info: Some("notes".to_string()),
        }
        .run(&rpc, Some(private_key))
        .await
        .unwrap();
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
