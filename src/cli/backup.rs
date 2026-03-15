//! `pubky-node backup` — manage data backup on a running node.

use clap::{Args, Subcommand};
use super::helpers::{build_client, get, post, post_json, print_json_or};

#[derive(Args, Debug)]
pub struct BackupArgs {
    /// Dashboard URL
    #[arg(long, default_value = "http://localhost:9090", global = true)]
    pub url: String,
    /// Dashboard password
    #[arg(long, global = true)]
    pub password: Option<String>,
    #[command(subcommand)]
    pub command: BackupCommand,
}

#[derive(Subcommand, Debug)]
pub enum BackupCommand {
    /// Show backup status
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Start backup for a pubkey
    Start {
        /// Public key (zbase32) to back up
        #[arg(long)]
        pubkey: String,
    },
    /// Stop backup for a pubkey
    Stop {
        /// Public key (zbase32)
        #[arg(long)]
        pubkey: String,
    },
    /// Force sync all active backups now
    SyncAll,
    /// List backed-up identities
    List {
        #[arg(long)]
        json: bool,
    },
    /// Verify backup integrity
    Verify {
        /// Public key (zbase32) to verify
        #[arg(long)]
        pubkey: String,
        #[arg(long)]
        json: bool,
    },
    /// Export backup data to a file
    Export {
        /// Public key (zbase32)
        #[arg(long)]
        pubkey: String,
        /// Output directory
        #[arg(long)]
        output: Option<String>,
    },
    /// Create a point-in-time snapshot
    Snapshot {
        /// Snapshot label (optional)
        #[arg(long)]
        label: Option<String>,
    },
    /// List available snapshots
    Snapshots {
        #[arg(long)]
        json: bool,
    },
    /// Restore from a snapshot
    Restore {
        /// Snapshot name/ID
        snapshot: String,
    },
    /// Delete a snapshot
    DeleteSnapshot {
        /// Snapshot name/ID
        snapshot: String,
    },
}

pub async fn execute(args: BackupArgs) -> anyhow::Result<()> {
    let base = args.url.trim_end_matches('/').to_string();
    let client = build_client(&args.password)?;

    match args.command {
        BackupCommand::Status { json } => {
            let resp = get(&client, &format!("{}/api/backup/status", base)).await?;
            let data: serde_json::Value = resp.json().await?;
            print_json_or(&data, json, |d| {
                let active = d.get("active_backups").and_then(|v| v.as_u64()).unwrap_or(0);
                let syncs = d.get("active_syncs").and_then(|v| v.as_u64()).unwrap_or(0);
                let size = d.get("total_size").and_then(|v| v.as_u64()).unwrap_or(0);
                println!("Backup Status:");
                println!("  Active backups: {}", active);
                println!("  Active syncs:   {}", syncs);
                println!("  Total size:     {} bytes", size);
            });
        }
        BackupCommand::Start { pubkey } => {
            let body = serde_json::json!({ "pubkey": pubkey });
            post_json(&client, &format!("{}/api/backup/start", base), &body).await?;
            println!("✓ Backup started for {}", pubkey);
        }
        BackupCommand::Stop { pubkey } => {
            let body = serde_json::json!({ "pubkey": pubkey });
            post_json(&client, &format!("{}/api/backup/stop", base), &body).await?;
            println!("✓ Backup stopped for {}", pubkey);
        }
        BackupCommand::SyncAll => {
            post(&client, &format!("{}/api/backup/sync-all", base)).await?;
            println!("✓ Sync all triggered");
        }
        BackupCommand::List { json } => {
            let resp = get(&client, &format!("{}/api/backup/list", base)).await?;
            let data: serde_json::Value = resp.json().await?;
            print_json_or(&data, json, |d| {
                let empty = vec![];
                let items = d.as_array().unwrap_or(&empty);
                if items.is_empty() {
                    println!("No active backups.");
                } else {
                    println!("Backed-up identities ({}):", items.len());
                    for item in items {
                        let pk = item.get("pubkey").and_then(|v| v.as_str()).unwrap_or("?");
                        println!("  {}", pk);
                    }
                }
            });
        }
        BackupCommand::Verify { pubkey, json } => {
            let body = serde_json::json!({ "pubkey": pubkey });
            let resp = post_json(&client, &format!("{}/api/backup/verify", base), &body).await?;
            let data: serde_json::Value = resp.json().await?;
            print_json_or(&data, json, |d| {
                let ok = d.get("valid").and_then(|v| v.as_bool()).unwrap_or(false);
                println!("Backup integrity: {}", if ok { "✓ Valid" } else { "✗ Issues found" });
            });
        }
        BackupCommand::Export { pubkey, output } => {
            let mut body = serde_json::json!({ "pubkey": pubkey });
            if let Some(o) = output { body["output"] = serde_json::json!(o); }
            let resp = post_json(&client, &format!("{}/api/backup/export", base), &body).await?;
            let data: serde_json::Value = resp.json().await?;
            println!("✓ Export: {}", data.get("path").and_then(|v| v.as_str()).unwrap_or("done"));
        }
        BackupCommand::Snapshot { label } => {
            let body = serde_json::json!({ "label": label.unwrap_or_default() });
            let resp = post_json(&client, &format!("{}/api/backup/snapshot", base), &body).await?;
            let data: serde_json::Value = resp.json().await?;
            println!("✓ Snapshot created: {}", data.get("name").and_then(|v| v.as_str()).unwrap_or("ok"));
        }
        BackupCommand::Snapshots { json } => {
            let resp = get(&client, &format!("{}/api/backup/snapshots", base)).await?;
            let data: serde_json::Value = resp.json().await?;
            print_json_or(&data, json, |d| {
                let empty = vec![];
                let snaps = d.as_array().unwrap_or(&empty);
                if snaps.is_empty() {
                    println!("No snapshots.");
                } else {
                    println!("Snapshots ({}):", snaps.len());
                    for s in snaps {
                        let name = s.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                        let files = s.get("file_count").and_then(|v| v.as_u64()).unwrap_or(0);
                        println!("  {} ({} files)", name, files);
                    }
                }
            });
        }
        BackupCommand::Restore { snapshot } => {
            let body = serde_json::json!({ "snapshot": snapshot });
            post_json(&client, &format!("{}/api/backup/snapshot/restore", base), &body).await?;
            println!("✓ Restoring from snapshot: {}", snapshot);
        }
        BackupCommand::DeleteSnapshot { snapshot } => {
            let body = serde_json::json!({ "snapshot": snapshot });
            post_json(&client, &format!("{}/api/backup/snapshot/delete", base), &body).await?;
            println!("✓ Deleted snapshot: {}", snapshot);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    #[derive(clap::Parser)]
    struct TestCli { #[command(subcommand)] cmd: super::BackupCommand }

    #[test] fn test_parse_status() {
        let cli = TestCli::try_parse_from(["b", "status"]).unwrap();
        assert!(matches!(cli.cmd, super::BackupCommand::Status { json: false }));
    }
    #[test] fn test_parse_sync_all() {
        let cli = TestCli::try_parse_from(["b", "sync-all"]).unwrap();
        assert!(matches!(cli.cmd, super::BackupCommand::SyncAll));
    }
    #[test] fn test_parse_snapshot() {
        let cli = TestCli::try_parse_from(["b", "snapshot"]).unwrap();
        assert!(matches!(cli.cmd, super::BackupCommand::Snapshot { .. }));
    }
}
