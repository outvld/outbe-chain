//! Generic on-chain vote proposal commands.

use alloy_primitives::{Address, U256};
use alloy_sol_types::SolCall;
use clap::Subcommand;
use eyre::{Result, WrapErr};

use crate::abi::{IVote, VOTE_ADDRESS};
use crate::rpc::Rpc;

#[derive(Subcommand)]
pub enum VoteCmd {
    /// Create a proposal (active validator only).
    Propose {
        /// Target system module precompile address.
        #[arg(long)]
        target_module: Address,
        /// JSON payload decoded by the target module.
        #[arg(long)]
        payload: String,
    },
    /// Cast a vote on a pending proposal (active validator only).
    Cast {
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
    /// Show proposal status.
    Status {
        /// Vote proposal id.
        #[arg(long)]
        proposal_id: U256,
    },
}

impl VoteCmd {
    pub async fn run(self, client: &(impl Rpc + Sync), private_key: Option<&str>) -> Result<()> {
        match self {
            Self::Propose {
                target_module,
                payload,
            } => propose(client, private_key, target_module, payload).await,
            Self::Cast {
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
                cast_vote(client, private_key, proposal_id, approve).await
            }
            Self::Status { proposal_id } => status(client, proposal_id).await,
        }
    }
}

fn validate_json_payload(payload: &str) -> Result<()> {
    serde_json::from_str::<serde_json::Value>(payload)
        .wrap_err("payload must be valid JSON")
        .map(|_| ())
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
    target_module: Address,
    payload: String,
) -> Result<()> {
    validate_json_payload(&payload)?;
    let signer = super::require_signer(private_key)?;

    let call = IVote::createProposalCall {
        targetModule: target_module,
        payload,
    };
    let tx_hash = signer
        .send_tx(client, VOTE_ADDRESS, call.abi_encode(), U256::ZERO)
        .await?;
    println!("Proposal transaction sent: {tx_hash} (target {target_module:?})");
    Ok(())
}

async fn cast_vote(
    client: &(impl Rpc + Sync),
    private_key: Option<&str>,
    proposal_id: U256,
    approve: bool,
) -> Result<()> {
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

async fn status(client: &(impl Rpc + Sync), proposal_id: U256) -> Result<()> {
    let proposal = fetch_vote_proposal(client, proposal_id).await?;
    print_vote_proposal("Proposal", &proposal);
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

    println!(
        "{label} #{proposal_id}: target={:?} status={status} deadline={deadline} votes={yes}/{no}",
        proposal.targetModule
    );
    println!("  payload: {}", proposal.payload);
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
    use outbe_primitives::addresses::UPDATE_ADDRESS;
    use std::collections::HashMap;

    const SAMPLE_PAYLOAD: &str = r#"{"version":"1.2","activationHeight":1000,"info":"notes"}"#;

    #[test]
    fn test_cli_parse_vote_status() {
        let cli = Cli::try_parse_from(["outbe-cli", "vote", "status", "--proposal-id", "1"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_vote_propose_flags() {
        let cli = Cli::try_parse_from([
            "outbe-cli",
            "vote",
            "propose",
            "--target-module",
            "0x000000000000000000000000000000000000EE0D",
            "--payload",
            SAMPLE_PAYLOAD,
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_vote_cast_yes() {
        let cli = Cli::try_parse_from(["outbe-cli", "vote", "cast", "--proposal-id", "1", "--yes"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_vote_cast_no() {
        let cli = Cli::try_parse_from(["outbe-cli", "vote", "cast", "--proposal-id", "1", "--no"]);
        assert!(cli.is_ok());
    }

    fn mock_proposal_info(proposal_id: U256) -> IVote::ProposalInfo {
        IVote::ProposalInfo {
            proposalId: proposal_id,
            proposer: Address::ZERO,
            targetModule: UPDATE_ADDRESS,
            payload: SAMPLE_PAYLOAD.to_string(),
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
        let call = IVote::createProposalCall {
            targetModule: UPDATE_ADDRESS,
            payload: SAMPLE_PAYLOAD.to_string(),
        };
        let rpc = recording_send_tx_rpc(private_key, VOTE_ADDRESS, call.abi_encode(), U256::ZERO)
            .unwrap();
        VoteCmd::Propose {
            target_module: UPDATE_ADDRESS,
            payload: SAMPLE_PAYLOAD.to_string(),
        }
        .run(&rpc, Some(private_key))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cast_sends_vote_cast_vote_tx() {
        let private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let proposal_id = U256::from(1);
        let call = IVote::castVoteCall {
            proposalId: proposal_id,
            approve: true,
        };
        let rpc = recording_send_tx_rpc(private_key, VOTE_ADDRESS, call.abi_encode(), U256::ZERO)
            .unwrap();
        VoteCmd::Cast {
            proposal_id,
            yes: true,
            no: false,
        }
        .run(&rpc, Some(private_key))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn propose_rejects_invalid_json_payload() {
        let mock = MockRpc::default();
        let err = VoteCmd::Propose {
            target_module: UPDATE_ADDRESS,
            payload: "not-json".to_string(),
        }
        .run(
            &mock,
            Some("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("valid JSON"));
    }

    #[tokio::test]
    async fn status_reads_vote_proposal() {
        let proposal_id = U256::from(1);
        let proposal = mock_proposal_info(proposal_id);
        let mut map = HashMap::new();
        map.insert(
            (VOTE_ADDRESS, IVote::getProposalCall::SELECTOR),
            IVote::getProposalCall::abi_encode_returns(&proposal),
        );

        let mock = MockRpc {
            eth_call_map: Some(call_map(map)),
            ..MockRpc::default()
        };

        VoteCmd::Status { proposal_id }
            .run(&mock, None)
            .await
            .unwrap();
    }
}
