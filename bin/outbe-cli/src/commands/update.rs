//! Upgrade operator commands: vote writes, update reads.

use alloy_primitives::U256;
use alloy_sol_types::SolCall;
use clap::Subcommand;
use eyre::{Result, WrapErr};
use outbe_primitives::addresses::UPDATE_ADDRESS;
use outbe_update::constants::PROTOCOL_VERSION;
use outbe_update::payload::{decode_schedule_update_json, encode_schedule_update_json};
use outbe_update::version::{format_protocol_version, try_parse_protocol_version};
use outbe_update::ProtocolVersion;
use serde_json::Value;

use crate::abi::{IVote, VOTE_ADDRESS};
use crate::rpc::Rpc;

#[derive(Subcommand)]
pub enum UpdateCmd {
    /// Create an upgrade proposal via vote (active validator only).
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
    /// Show active version and proposal / scheduled-update status.
    Status {
        /// Optional vote proposal id for detailed status.
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

fn resolve_proposal_version(version: Option<String>) -> Result<ProtocolVersion> {
    match version {
        Some(value) => try_parse_protocol_version(&value)
            .map_err(|err| eyre::eyre!("invalid protocol version '{value}': {err}")),
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

fn active_version_from_rpc(active: &Value) -> ProtocolVersion {
    ProtocolVersion::from(active["version"].as_u64().unwrap_or(0) as u32)
}

async fn fetch_active_version(client: &(impl Rpc + Sync)) -> Result<ProtocolVersion> {
    let active = client.outbe_get_update_active_version().await?;
    Ok(active_version_from_rpc(&active))
}

fn ensure_propose_version_compatible(
    proposed: ProtocolVersion,
    active: ProtocolVersion,
    binary: ProtocolVersion,
) -> Result<()> {
    if proposed <= active {
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

fn ensure_approve_version_compatible(
    proposal_version: ProtocolVersion,
    binary: ProtocolVersion,
) -> Result<()> {
    if proposal_version > binary {
        eyre::bail!(
            "proposal version {} exceeds binary protocol version {}; upgrade the binary or use --force",
            format_protocol_version(proposal_version),
            format_protocol_version(binary)
        );
    }
    Ok(())
}

fn decode_update_fields_from_proposal(
    proposal: &IVote::ProposalInfo,
) -> Result<(ProtocolVersion, u64, String)> {
    if proposal.targetModule != UPDATE_ADDRESS {
        eyre::bail!("proposal is not an update scheduling action");
    }
    let value: Value = serde_json::from_str(&proposal.payload)
        .map_err(|err| eyre::eyre!("invalid update payload in proposal: {err}"))?;
    let (version, activation_height, info) = decode_schedule_update_json(&value)
        .map_err(|err| eyre::eyre!("invalid update payload in proposal: {err}"))?;
    Ok((version, activation_height, info))
}

async fn fetch_vote_proposal(
    client: &(impl Rpc + Sync),
    proposal_id: U256,
) -> Result<IVote::ProposalInfo> {
    let call = IVote::getProposalCall {
        proposalId: proposal_id,
    };
    let ret = client
        .eth_call(VOTE_ADDRESS, &call.abi_encode())
        .await
        .wrap_err("vote getProposal eth_call failed")?;
    IVote::getProposalCall::abi_decode_returns(&ret).wrap_err("failed to decode vote proposal")
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
    let info_text = match parse_info_bytes(info)? {
        bytes if bytes.is_empty() => String::new(),
        bytes => match String::from_utf8(bytes.clone()) {
            Ok(text) => text,
            Err(_) => hex::encode(bytes),
        },
    };
    let payload = encode_schedule_update_json(version, activation_height, &info_text);

    let call = IVote::createProposalCall {
        targetModule: UPDATE_ADDRESS,
        payload,
    };
    let tx_hash = signer
        .send_tx(client, VOTE_ADDRESS, call.abi_encode(), U256::ZERO)
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
        let proposal = fetch_vote_proposal(client, proposal_id).await?;
        let (proposal_version, _, _) = decode_update_fields_from_proposal(&proposal)?;
        ensure_approve_version_compatible(proposal_version, PROTOCOL_VERSION)?;
    }

    let signer = super::require_signer(private_key)?;
    let call = IVote::castVoteCall {
        proposalId: proposal_id,
        approve,
    };
    let tx_hash = signer
        .send_tx(client, VOTE_ADDRESS, call.abi_encode(), U256::ZERO)
        .await?;
    println!("Vote transaction sent: {tx_hash} (proposal {proposal_id}, approve={approve})");
    Ok(())
}

async fn status(client: &(impl Rpc + Sync), proposal_id: Option<U256>) -> Result<()> {
    if let Some(proposal_id) = proposal_id {
        let proposal = fetch_vote_proposal(client, proposal_id).await?;
        print_vote_proposal("Proposal", &proposal);

        if let Some(scheduled) = client
            .outbe_get_update_scheduled_update(proposal_id)
            .await?
        {
            print_scheduled_update("Scheduled update", &scheduled);
        }
        return Ok(());
    }

    let active = client.outbe_get_update_active_version().await?;
    println!(
        "Active version: {} (activation height {})",
        format_protocol_version(active_version_from_rpc(&active)),
        active["activationHeight"].as_u64().unwrap_or(0)
    );
    println!(
        "Binary version: {}",
        format_protocol_version(PROTOCOL_VERSION)
    );

    let waiting = client.outbe_list_update_waiting_for_activation().await?;
    println!(
        "Waiting for activation: {}",
        waiting.as_array().map_or(0, |v| v.len())
    );
    for scheduled in waiting.as_array().into_iter().flatten() {
        print_scheduled_update("  Waiting", scheduled);
    }

    Ok(())
}

fn proposal_status_label(status: IVote::ProposalStatus) -> &'static str {
    match status {
        IVote::ProposalStatus::Pending => "pending",
        IVote::ProposalStatus::Approved => "approved",
        IVote::ProposalStatus::Rejected => "rejected",
        IVote::ProposalStatus::Expired => "expired",
        _ => "unknown",
    }
}

fn print_vote_proposal(label: &str, proposal: &IVote::ProposalInfo) {
    let proposal_id = proposal.proposalId;
    let status = proposal_status_label(proposal.status);
    let deadline = proposal.votingDeadlineHeight;
    let yes = proposal.state.yes;
    let no = proposal.state.no;

    match decode_update_fields_from_proposal(proposal) {
        Ok((version, activation, _)) => {
            println!(
                "{label} #{proposal_id}: {} status={status} activation={activation} deadline={deadline} votes={yes}/{no}",
                format_protocol_version(version)
            );
        }
        Err(_) => {
            println!(
                "{label} #{proposal_id}: status={status} deadline={deadline} votes={yes}/{no} (non-update payload)"
            );
        }
    }
}

fn print_scheduled_update(label: &str, scheduled: &Value) {
    let proposal_id = scheduled["proposalId"]
        .as_str()
        .map(str::to_string)
        .or_else(|| scheduled["proposalId"].as_u64().map(|n| n.to_string()))
        .unwrap_or_else(|| "?".to_string());
    let version = ProtocolVersion::from(scheduled["version"].as_u64().unwrap_or(0) as u32);
    let status = scheduled["status"].as_str().unwrap_or("unknown");
    let activation = scheduled["activationHeight"].as_u64().unwrap_or(0);

    println!(
        "{label} #{proposal_id}: {} status={status} activation={activation}",
        format_protocol_version(version)
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::VOTE_ADDRESS;
    use crate::rpc::mock::{call_map, recording_send_tx_rpc, MockRpc};
    use crate::Cli;
    use alloy_primitives::Address;
    use alloy_sol_types::SolCall;
    use clap::Parser;
    use outbe_update::{encode_protocol_version, version::ProtocolVersionParseError};
    use std::collections::HashMap;

    #[test]
    fn parse_protocol_version_major_minor() {
        assert_eq!(
            try_parse_protocol_version("1.2").unwrap(),
            encode_protocol_version(1, 2)
        );
    }

    #[test]
    fn parse_protocol_version_raw_u32() {
        assert_eq!(try_parse_protocol_version("65536").unwrap().raw(), 65536);
    }

    #[test]
    fn parse_protocol_version_rejects_invalid() {
        assert!(matches!(
            try_parse_protocol_version("1.2.3"),
            Err(ProtocolVersionParseError::TooManyComponents)
        ));
    }

    #[test]
    fn test_cli_parse_update_status() {
        let cli = Cli::try_parse_from(["outbe-cli", "update", "status"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_update_status_with_proposal_id() {
        let cli = Cli::try_parse_from(["outbe-cli", "update", "status", "--proposal-id", "1"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_update_propose() {
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

    #[test]
    fn test_cli_parse_update_propose_without_version() {
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
    fn test_cli_parse_update_vote_yes() {
        let cli =
            Cli::try_parse_from(["outbe-cli", "update", "vote", "--proposal-id", "1", "--yes"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_update_vote_no() {
        let cli =
            Cli::try_parse_from(["outbe-cli", "update", "vote", "--proposal-id", "1", "--no"]);
        assert!(cli.is_ok());
    }

    fn mock_proposal_info(proposal_id: U256, version: ProtocolVersion) -> IVote::ProposalInfo {
        let payload = encode_schedule_update_json(version, 1000, "notes");
        IVote::ProposalInfo {
            proposalId: proposal_id,
            proposer: Address::ZERO,
            targetModule: UPDATE_ADDRESS,
            payload,
            createdHeight: 10,
            votingDeadlineHeight: 100,
            status: IVote::ProposalStatus::Pending,
            state: IVote::VoteTally { yes: 0, no: 0 },
            votersCount: U256::ZERO,
        }
    }

    #[tokio::test]
    async fn propose_sends_vote_create_proposal_tx() {
        let private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let version = encode_protocol_version(1, 2);
        let payload = encode_schedule_update_json(version, 1000, "notes");
        let call = IVote::createProposalCall {
            targetModule: UPDATE_ADDRESS,
            payload,
        };
        let rpc = recording_send_tx_rpc(private_key, VOTE_ADDRESS, call.abi_encode(), U256::ZERO)
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
    async fn vote_sends_vote_cast_vote_tx() {
        let private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let proposal_id = U256::from(1);
        let call = IVote::castVoteCall {
            proposalId: proposal_id,
            approve: true,
        };
        let rpc = recording_send_tx_rpc(private_key, VOTE_ADDRESS, call.abi_encode(), U256::ZERO)
            .unwrap();
        UpdateCmd::Vote {
            proposal_id,
            yes: true,
            no: false,
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
                "version": PROTOCOL_VERSION.raw(),
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
        .run(
            &mock,
            Some("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("must be greater than active"));
    }

    #[tokio::test]
    async fn vote_rejects_approve_when_binary_is_too_old() {
        let proposal_id = U256::from(1);
        let proposal = mock_proposal_info(proposal_id, encode_protocol_version(9, 0));
        let mut map = HashMap::new();
        map.insert(
            (VOTE_ADDRESS, IVote::getProposalCall::SELECTOR),
            IVote::getProposalCall::abi_encode_returns(&proposal),
        );
        let mock = MockRpc {
            eth_call_map: Some(call_map(map)),
            ..MockRpc::default()
        };
        let err = UpdateCmd::Vote {
            proposal_id,
            yes: true,
            no: false,
            force: false,
        }
        .run(
            &mock,
            Some("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"),
        )
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
        let waiting = serde_json::json!([]);
        let mock = MockRpc {
            update_active_version: Ok(active),
            update_waiting_for_activation: Ok(waiting),
            ..MockRpc::default()
        };
        UpdateCmd::Status { proposal_id: None }
            .run(&mock, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn status_with_proposal_id_reads_vote_and_scheduled_update() {
        let proposal_id = U256::from(1);
        let version = encode_protocol_version(1, 2);
        let proposal = mock_proposal_info(proposal_id, version);
        let scheduled = serde_json::json!({
            "proposalId": 1,
            "version": version.raw(),
            "activationHeight": 1000,
            "status": "pending"
        });

        let mut map = HashMap::new();
        map.insert(
            (VOTE_ADDRESS, IVote::getProposalCall::SELECTOR),
            IVote::getProposalCall::abi_encode_returns(&proposal),
        );

        let mock = MockRpc {
            eth_call_map: Some(call_map(map)),
            update_scheduled_update: Ok(Some(scheduled)),
            ..MockRpc::default()
        };

        UpdateCmd::Status {
            proposal_id: Some(proposal_id),
        }
        .run(&mock, None)
        .await
        .unwrap();
    }
}
