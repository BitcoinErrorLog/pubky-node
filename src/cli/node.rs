//! `pubky-node node` — control a running node (restart, shutdown).

use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct NodeArgs {
    /// Dashboard URL
    #[arg(long, default_value = "http://localhost:9090", global = true)]
    pub url: String,

    #[command(subcommand)]
    pub command: NodeCommand,
}

#[derive(Subcommand, Debug)]
pub enum NodeCommand {
    /// Gracefully shut down the running node
    Shutdown,
    /// Restart the running node
    Restart,
}

pub async fn execute(args: NodeArgs) -> anyhow::Result<()> {
    let base = args.url.trim_end_matches('/').to_string();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let (path, label) = match args.command {
        NodeCommand::Shutdown => ("/api/node/shutdown", "shutdown"),
        NodeCommand::Restart => ("/api/node/restart", "restart"),
    };

    let resp = client.post(format!("{}{}", base, path))
        .send().await
        .map_err(|_| anyhow::anyhow!("Could not connect to {}. Is pubky-node running?", base))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Node {} failed: {}", label, body);
    }

    println!("✓ Node {} initiated", label);
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[derive(clap::Parser)]
    struct TestCli {
        #[command(subcommand)]
        cmd: super::NodeCommand,
    }

    #[test]
    fn test_parse_shutdown() {
        let cli = TestCli::try_parse_from(["node", "shutdown"]).unwrap();
        assert!(matches!(cli.cmd, super::NodeCommand::Shutdown));
    }

    #[test]
    fn test_parse_restart() {
        let cli = TestCli::try_parse_from(["node", "restart"]).unwrap();
        assert!(matches!(cli.cmd, super::NodeCommand::Restart));
    }

    #[test]
    fn test_unknown_subcommand_fails() {
        let result = TestCli::try_parse_from(["node", "explode"]);
        assert!(result.is_err());
    }
}

