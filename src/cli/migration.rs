//! `pubky-node migration` — manage homeserver migration on a running node.

use clap::{Args, Subcommand};
use super::helpers::{build_client, get, post_json, print_json_or};

#[derive(Args, Debug)]
pub struct MigrationArgs {
    /// Dashboard URL
    #[arg(long, default_value = "http://localhost:9090", global = true)]
    pub url: String,
    /// Dashboard password
    #[arg(long, global = true)]
    pub password: Option<String>,
    #[command(subcommand)]
    pub command: MigrationCommand,
}

#[derive(Subcommand, Debug)]
pub enum MigrationCommand {
    /// Run a preflight check before migration
    Preflight {
        /// Public key to migrate
        #[arg(long)]
        pubkey: String,
        /// Target homeserver URL
        #[arg(long)]
        target: String,
        /// Data source: "backup" or snapshot name
        #[arg(long, default_value = "backup")]
        source: String,
        /// Signup token for target server
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Execute the migration
    Execute {
        /// Public key to migrate
        #[arg(long)]
        pubkey: String,
        /// Target homeserver URL
        #[arg(long)]
        target: String,
        /// Data source
        #[arg(long, default_value = "backup")]
        source: String,
        /// Signup token for target server
        #[arg(long)]
        token: Option<String>,
    },
    /// Check migration progress/status
    Status {
        #[arg(long)]
        json: bool,
    },
}

pub async fn execute(args: MigrationArgs) -> anyhow::Result<()> {
    let base = args.url.trim_end_matches('/').to_string();
    let client = build_client(&args.password)?;

    match args.command {
        MigrationCommand::Preflight { pubkey, target, source, token, json } => {
            let mut body = serde_json::json!({
                "pubkey": pubkey,
                "target_url": target,
                "source": source,
            });
            if let Some(t) = token { body["token"] = serde_json::json!(t); }
            let resp = post_json(&client, &format!("{}/api/migration/preflight", base), &body).await?;
            let data: serde_json::Value = resp.json().await?;
            print_json_or(&data, json, |d| {
                let ok = d.get("ready").and_then(|v| v.as_bool()).unwrap_or(false);
                println!("Preflight: {}", if ok { "✓ Ready to migrate" } else { "✗ Not ready" });
                if let Some(issues) = d.get("issues").and_then(|v| v.as_array()) {
                    for issue in issues {
                        println!("  ⚠ {}", issue.as_str().unwrap_or("?"));
                    }
                }
            });
        }
        MigrationCommand::Execute { pubkey, target, source, token } => {
            let mut body = serde_json::json!({
                "pubkey": pubkey,
                "target_url": target,
                "source": source,
            });
            if let Some(t) = token { body["token"] = serde_json::json!(t); }
            post_json(&client, &format!("{}/api/migration/execute", base), &body).await?;
            println!("✓ Migration started — use `pubky-node migration status` to track progress");
        }
        MigrationCommand::Status { json } => {
            let resp = get(&client, &format!("{}/api/migration/status", base)).await?;
            let data: serde_json::Value = resp.json().await?;
            print_json_or(&data, json, |d| {
                let state = d.get("state").and_then(|v| v.as_str()).unwrap_or("idle");
                println!("Migration: {}", state);
                if let Some(progress) = d.get("progress").and_then(|v| v.as_f64()) {
                    println!("  Progress: {:.1}%", progress * 100.0);
                }
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    #[derive(clap::Parser)]
    struct TestCli { #[command(subcommand)] cmd: super::MigrationCommand }

    #[test] fn test_parse_status() {
        let cli = TestCli::try_parse_from(["m", "status"]).unwrap();
        assert!(matches!(cli.cmd, super::MigrationCommand::Status { json: false }));
    }
}
