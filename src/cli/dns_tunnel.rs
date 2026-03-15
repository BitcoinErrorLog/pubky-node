//! `pubky-node dns-tunnel` — manage the DNS (DoH) Cloudflare tunnel on a running node.

use clap::{Args, Subcommand};
use super::helpers::{build_client, get, post, print_json_or};

#[derive(Args, Debug)]
pub struct DnsTunnelArgs {
    /// Dashboard URL
    #[arg(long, default_value = "http://localhost:9090", global = true)]
    pub url: String,
    /// Dashboard password
    #[arg(long, global = true)]
    pub password: Option<String>,
    #[command(subcommand)]
    pub command: DnsTunnelCommand,
}

#[derive(Subcommand, Debug)]
pub enum DnsTunnelCommand {
    /// Show DNS tunnel status and DoH URL
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Start the DNS (DoH) Cloudflare tunnel
    Start,
    /// Stop the DNS (DoH) Cloudflare tunnel
    Stop,
}

pub async fn execute(args: DnsTunnelArgs) -> anyhow::Result<()> {
    let base = args.url.trim_end_matches('/').to_string();
    let client = build_client(&args.password)?;

    match args.command {
        DnsTunnelCommand::Status { json } => {
            let resp = get(&client, &format!("{}/api/dns-tunnel/status", base)).await?;
            let data: serde_json::Value = resp.json().await?;
            print_json_or(&data, json, |d| {
                let state = d.get("state").and_then(|v| v.as_str()).unwrap_or("Unknown");
                println!("DNS Tunnel (DoH): {}", state);
                if let Some(url) = d.get("public_url").and_then(|v| v.as_str()) {
                    println!("  DoH URL: {}/dns-query", url);
                }
                if let Some(port) = d.get("doh_port").and_then(|v| v.as_u64()) {
                    println!("  Local port: {}", port);
                }
            });
        }
        DnsTunnelCommand::Start => {
            post(&client, &format!("{}/api/dns-tunnel/start", base)).await?;
            println!("✓ DNS tunnel starting — use `pubky-node dns-tunnel status` to get the DoH URL");
        }
        DnsTunnelCommand::Stop => {
            post(&client, &format!("{}/api/dns-tunnel/stop", base)).await?;
            println!("✓ DNS tunnel stopped");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    #[derive(clap::Parser)]
    struct TestCli { #[command(subcommand)] cmd: super::DnsTunnelCommand }

    #[test] fn test_parse_status() {
        let cli = TestCli::try_parse_from(["dt", "status"]).unwrap();
        assert!(matches!(cli.cmd, super::DnsTunnelCommand::Status { json: false }));
    }
    #[test] fn test_parse_start() {
        let cli = TestCli::try_parse_from(["dt", "start"]).unwrap();
        assert!(matches!(cli.cmd, super::DnsTunnelCommand::Start));
    }
}
