//! `pubky-node tunnel` — manage the Cloudflare quick-tunnel on a running node.

use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct TunnelArgs {
    /// Dashboard URL
    #[arg(long, default_value = "http://localhost:9090", global = true)]
    pub url: String,

    #[command(subcommand)]
    pub command: TunnelCommand,
}

#[derive(Subcommand, Debug)]
pub enum TunnelCommand {
    /// Show tunnel status and current URL
    Status {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Start the Cloudflare quick-tunnel
    Start,
    /// Stop the Cloudflare quick-tunnel
    Stop,
    /// Check whether cloudflared binary is available
    Check,
}

pub async fn execute(args: TunnelArgs) -> anyhow::Result<()> {
    let base = args.url.trim_end_matches('/').to_string();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    match args.command {
        TunnelCommand::Status { json } => {
            let resp = client.get(format!("{}/api/tunnel/status", base))
                .send().await
                .map_err(|_| anyhow::anyhow!("Could not connect to node. Is pubky-node running?"))?;
            if !resp.status().is_success() {
                anyhow::bail!("Tunnel status request failed: {}", resp.status());
            }
            let data: serde_json::Value = resp.json().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&data)?);
            } else {
                let state = data.get("state").and_then(|v| v.as_str()).unwrap_or("Unknown");
                println!("Tunnel: {}", state);
                if let Some(url) = data.get("url").and_then(|v| v.as_str()) {
                    println!("  URL: {}", url);
                }
            }
        }

        TunnelCommand::Start => {
            let resp = client.post(format!("{}/api/tunnel/start", base))
                .send().await
                .map_err(|_| anyhow::anyhow!("Could not connect to node. Is pubky-node running?"))?;
            if !resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("Tunnel start failed: {}", body);
            }
            println!("✓ Tunnel starting — use `pubky-node tunnel status` to get the URL");
        }

        TunnelCommand::Stop => {
            let resp = client.post(format!("{}/api/tunnel/stop", base))
                .send().await
                .map_err(|_| anyhow::anyhow!("Could not connect to node. Is pubky-node running?"))?;
            if !resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("Tunnel stop failed: {}", body);
            }
            println!("✓ Tunnel stopped");
        }

        TunnelCommand::Check => {
            let resp = client.get(format!("{}/api/tunnel/check", base))
                .send().await
                .map_err(|_| anyhow::anyhow!("Could not connect to node. Is pubky-node running?"))?;
            if !resp.status().is_success() {
                anyhow::bail!("Request failed: {}", resp.status());
            }
            let data: serde_json::Value = resp.json().await?;
            let available = data.get("available").and_then(|v| v.as_bool()).unwrap_or(false);
            if available {
                println!("✓ cloudflared binary found");
            } else {
                println!("✗ cloudflared binary not found — download from https://github.com/cloudflare/cloudflared/releases/latest");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[derive(clap::Parser)]
    struct TestCli {
        #[command(subcommand)]
        cmd: super::TunnelCommand,
    }

    #[test]
    fn test_parse_status() {
        let cli = TestCli::try_parse_from(["tunnel", "status"]).unwrap();
        assert!(matches!(cli.cmd, super::TunnelCommand::Status { json: false }));
    }

    #[test]
    fn test_parse_status_json() {
        let cli = TestCli::try_parse_from(["tunnel", "status", "--json"]).unwrap();
        assert!(matches!(cli.cmd, super::TunnelCommand::Status { json: true }));
    }

    #[test]
    fn test_parse_start() {
        let cli = TestCli::try_parse_from(["tunnel", "start"]).unwrap();
        assert!(matches!(cli.cmd, super::TunnelCommand::Start));
    }

    #[test]
    fn test_parse_stop() {
        let cli = TestCli::try_parse_from(["tunnel", "stop"]).unwrap();
        assert!(matches!(cli.cmd, super::TunnelCommand::Stop));
    }

    #[test]
    fn test_parse_check() {
        let cli = TestCli::try_parse_from(["tunnel", "check"]).unwrap();
        assert!(matches!(cli.cmd, super::TunnelCommand::Check));
    }
}

