//! `pubky-node relay-tunnel` — manage the relay Cloudflare tunnel on a running node.

use clap::{Args, Subcommand};
use super::helpers::{build_client, get, post, print_json_or};

#[derive(Args, Debug)]
pub struct RelayTunnelArgs {
    /// Dashboard URL
    #[arg(long, default_value = "http://localhost:9090", global = true)]
    pub url: String,
    /// Dashboard password
    #[arg(long, global = true)]
    pub password: Option<String>,
    #[command(subcommand)]
    pub command: RelayTunnelCommand,
}

#[derive(Subcommand, Debug)]
pub enum RelayTunnelCommand {
    /// Show relay tunnel status and URL
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Start the relay Cloudflare tunnel
    Start,
    /// Stop the relay Cloudflare tunnel
    Stop,
}

pub async fn execute(args: RelayTunnelArgs) -> anyhow::Result<()> {
    let base = args.url.trim_end_matches('/').to_string();
    let client = build_client(&args.password)?;

    match args.command {
        RelayTunnelCommand::Status { json } => {
            let resp = get(&client, &format!("{}/api/relay-tunnel/status", base)).await?;
            let data: serde_json::Value = resp.json().await?;
            print_json_or(&data, json, |d| {
                let state = d.get("state").and_then(|v| v.as_str()).unwrap_or("Unknown");
                println!("Relay Tunnel: {}", state);
                if let Some(url) = d.get("public_url").and_then(|v| v.as_str()) {
                    println!("  URL: {}", url);
                }
            });
        }
        RelayTunnelCommand::Start => {
            post(&client, &format!("{}/api/relay-tunnel/start", base)).await?;
            println!("✓ Relay tunnel starting — use `pubky-node relay-tunnel status` to get the URL");
        }
        RelayTunnelCommand::Stop => {
            post(&client, &format!("{}/api/relay-tunnel/stop", base)).await?;
            println!("✓ Relay tunnel stopped");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    #[derive(clap::Parser)]
    struct TestCli { #[command(subcommand)] cmd: super::RelayTunnelCommand }

    #[test] fn test_parse_status() {
        let cli = TestCli::try_parse_from(["rt", "status"]).unwrap();
        assert!(matches!(cli.cmd, super::RelayTunnelCommand::Status { json: false }));
    }
    #[test] fn test_parse_start() {
        let cli = TestCli::try_parse_from(["rt", "start"]).unwrap();
        assert!(matches!(cli.cmd, super::RelayTunnelCommand::Start));
    }
}
