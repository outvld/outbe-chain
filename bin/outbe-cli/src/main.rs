//! Outbe chain management CLI.
//!
//! Client-side tool for interacting with a running outbe-chain node via JSON-RPC.
//! Supports validator management, staking, rewards, slashing evidence, and monitoring.

use clap::{Parser, Subcommand};
use eyre::Result;

mod abi;
mod commands;
mod rpc;
mod tx;

#[derive(Parser)]
#[command(name = "outbe-cli", about = "Outbe chain management CLI")]
struct Cli {
    /// JSON-RPC endpoint URL
    #[arg(long, default_value = "http://localhost:8545", global = true)]
    rpc_url: String,

    /// Private key for signing transactions (hex, with or without 0x prefix)
    #[arg(long, global = true)]
    private_key: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validator management
    Validator {
        #[command(subcommand)]
        cmd: commands::validator::ValidatorCmd,
    },
    /// Staking operations
    Staking {
        #[command(subcommand)]
        cmd: commands::staking::StakingCmd,
    },
    /// Rewards management
    Rewards {
        #[command(subcommand)]
        cmd: commands::rewards::RewardsCmd,
    },
    /// Epoch information
    Epoch {
        #[command(subcommand)]
        cmd: commands::epoch::EpochCmd,
    },
    /// Slash information and evidence submission
    Slash {
        #[command(subcommand)]
        cmd: commands::slash::SlashCmd,
    },
    /// Chain information
    Chain {
        #[command(subcommand)]
        cmd: commands::chain::ChainCmd,
    },
    /// Monitor node status, health checks, and readiness probes.
    Monitor {
        #[command(subcommand)]
        cmd: commands::monitor::MonitorCmd,
    },
    /// Oracle: exchange rates, VWAP, voting, feeder delegation.
    Oracle {
        #[command(subcommand)]
        cmd: commands::oracle::OracleCmd,
    },
    /// Tribute: metadata and day-level reporting.
    Tribute {
        #[command(subcommand)]
        cmd: commands::tribute::TributeCmd,
    },
    /// ZeroFee paymaster: EIP-7702 authorization signing.
    ZeroFee {
        #[command(subcommand)]
        cmd: commands::zerofee::ZeroFeeCmd,
    },
    /// TEE: register a joining validator's enclave and install the offer key.
    Tee {
        #[command(subcommand)]
        cmd: commands::tee::TeeCmd,
    },
    /// On-chain upgrade governance.
    Update {
        #[command(subcommand)]
        cmd: commands::update::UpdateCmd,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = rpc::RpcClient::new(&cli.rpc_url);

    match cli.command {
        Commands::Validator { cmd } => cmd.run(&client, cli.private_key.as_deref()).await,
        Commands::Staking { cmd } => cmd.run(&client, cli.private_key.as_deref()).await,
        Commands::Rewards { cmd } => cmd.run(&client, cli.private_key.as_deref()).await,
        Commands::Epoch { cmd } => cmd.run(&client).await,
        Commands::Slash { cmd } => cmd.run(&client, cli.private_key.as_deref()).await,
        Commands::Chain { cmd } => cmd.run(&client).await,
        Commands::Monitor { cmd } => cmd.run(&client).await,
        Commands::Oracle { cmd } => cmd.run(&client, cli.private_key.as_deref()).await,
        Commands::Tribute { cmd } => cmd.run(&client, cli.private_key.as_deref()).await,
        Commands::ZeroFee { cmd } => cmd.run(&client, cli.private_key.as_deref()).await,
        Commands::Tee { cmd } => cmd.run(&client, cli.private_key.as_deref()).await,
        Commands::Update { cmd } => cmd.run(&client, cli.private_key.as_deref()).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_cli_parse_chain_info() {
        let cli = Cli::try_parse_from(["outbe-cli", "chain", "info"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_validator_list() {
        let cli = Cli::try_parse_from(["outbe-cli", "validator", "list"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_staking_info() {
        let cli = Cli::try_parse_from([
            "outbe-cli",
            "staking",
            "info",
            "0x1111111111111111111111111111111111111111",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_rewards_emission() {
        // `rewards emission` is a remaining valid subcommand.
        let cli = Cli::try_parse_from(["outbe-cli", "rewards", "emission"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_rejects_removed_rewards_claim_and_pending() {
        // Validator emission is paid in gems; the dead `claim` / `pending`
        // subcommands were removed and must no longer parse.
        assert!(Cli::try_parse_from(["outbe-cli", "rewards", "claim"]).is_err());
        assert!(Cli::try_parse_from([
            "outbe-cli",
            "rewards",
            "pending",
            "0x1111111111111111111111111111111111111111",
        ])
        .is_err());
    }

    #[test]
    fn test_cli_parse_tee_join() {
        let cli = Cli::try_parse_from([
            "outbe-cli",
            "tee",
            "join",
            "--enclave-socket",
            "/tmp/enclave.sock",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_monitor_health() {
        let cli = Cli::try_parse_from(["outbe-cli", "monitor", "health"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_epoch_info() {
        let cli = Cli::try_parse_from(["outbe-cli", "epoch", "info"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_slash_config() {
        let cli = Cli::try_parse_from(["outbe-cli", "slash", "config"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_oracle_params() {
        let cli = Cli::try_parse_from(["outbe-cli", "oracle", "params"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_tribute_show() {
        let cli = Cli::try_parse_from([
            "outbe-cli",
            "tribute",
            "show",
            "0x1111111111111111111111111111111111111111111111111111111111111111",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_tribute_day_totals() {
        let cli = Cli::try_parse_from(["outbe-cli", "tribute", "day-totals", "20241220"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_update_status() {
        let cli = Cli::try_parse_from(["outbe-cli", "update", "status"]);
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
    fn test_cli_parse_update_vote_yes() {
        let cli = Cli::try_parse_from([
            "outbe-cli",
            "update",
            "vote",
            "--proposal-id",
            "1",
            "--yes",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_custom_rpc_url() {
        let cli = Cli::try_parse_from([
            "outbe-cli",
            "--rpc-url",
            "http://localhost:9545",
            "chain",
            "info",
        ])
        .unwrap();
        assert_eq!(cli.rpc_url, "http://localhost:9545");
    }

    #[test]
    fn test_cli_parse_invalid_command() {
        let cli = Cli::try_parse_from(["outbe-cli", "bogus"]);
        assert!(cli.is_err());
    }

    #[test]
    fn test_cli_default_rpc_url() {
        let cli = Cli::try_parse_from(["outbe-cli", "chain", "info"]).unwrap();
        assert_eq!(cli.rpc_url, "http://localhost:8545");
    }
}
