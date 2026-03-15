//! `pubky-node vault` — manage the encrypted key vault on a running node.

use clap::{Args, Subcommand};
use super::helpers::{build_client, get, post_json, post, delete, print_json_or};

#[derive(Args, Debug)]
pub struct VaultArgs {
    /// Dashboard URL
    #[arg(long, default_value = "http://localhost:9090", global = true)]
    pub url: String,

    /// Dashboard password
    #[arg(long, global = true)]
    pub password: Option<String>,

    #[command(subcommand)]
    pub command: VaultCommand,
}

#[derive(Subcommand, Debug)]
pub enum VaultCommand {
    /// Create a new vault with a password
    Create {
        /// Vault password
        #[arg(long)]
        vault_password: String,
    },
    /// Unlock the vault
    Unlock {
        /// Vault password
        #[arg(long)]
        vault_password: String,
    },
    /// Lock the vault
    Lock,
    /// Show vault lock status
    Status {
        #[arg(long)]
        json: bool,
    },
    /// List all keys in the vault
    Keys {
        #[arg(long)]
        json: bool,
    },
    /// Generate a new random keypair in the vault
    Generate {
        /// Optional label for the key
        #[arg(long)]
        label: Option<String>,
    },
    /// Add an existing secret key to the vault
    Add {
        /// Hex-encoded 32-byte Ed25519 secret key
        #[arg(long)]
        secret: String,
        /// Optional label
        #[arg(long)]
        label: Option<String>,
    },
    /// Export a key's secret (hex)
    Export {
        /// Public key (zbase32)
        pubkey: String,
    },
    /// Export all keys as JSON
    ExportAll {
        #[arg(long)]
        json: bool,
    },
    /// Import keys from JSON
    Import {
        /// Path to JSON file or "-" for stdin
        file: String,
    },
    /// Rename a key's label
    Rename {
        /// Public key (zbase32)
        pubkey: String,
        /// New label
        label: String,
    },
    /// Delete a key from the vault
    Delete {
        /// Public key (zbase32)
        pubkey: String,
    },
}

pub async fn execute(args: VaultArgs) -> anyhow::Result<()> {
    let base = args.url.trim_end_matches('/').to_string();
    let client = build_client(&args.password)?;

    match args.command {
        VaultCommand::Create { vault_password } => {
            let body = serde_json::json!({ "password": vault_password });
            let resp = post_json(&client, &format!("{}/api/vault/create", base), &body).await?;
            let data: serde_json::Value = resp.json().await?;
            println!("✓ Vault created: {}", data.get("status").and_then(|v| v.as_str()).unwrap_or("ok"));
        }
        VaultCommand::Unlock { vault_password } => {
            let body = serde_json::json!({ "password": vault_password });
            let resp = post_json(&client, &format!("{}/api/vault/unlock", base), &body).await?;
            let data: serde_json::Value = resp.json().await?;
            println!("✓ Vault unlocked: {}", data.get("status").and_then(|v| v.as_str()).unwrap_or("ok"));
        }
        VaultCommand::Lock => {
            post(&client, &format!("{}/api/vault/lock", base)).await?;
            println!("✓ Vault locked");
        }
        VaultCommand::Status { json } => {
            let resp = get(&client, &format!("{}/api/vault/status", base)).await?;
            let data: serde_json::Value = resp.json().await?;
            print_json_or(&data, json, |d| {
                let locked = d.get("locked").and_then(|v| v.as_bool()).unwrap_or(true);
                let exists = d.get("exists").and_then(|v| v.as_bool()).unwrap_or(false);
                println!("Vault: {}", if !exists { "Not created" } else if locked { "Locked" } else { "Unlocked" });
            });
        }
        VaultCommand::Keys { json } => {
            let resp = get(&client, &format!("{}/api/vault/keys", base)).await?;
            let data: serde_json::Value = resp.json().await?;
            print_json_or(&data, json, |d| {
                let empty = vec![];
                let keys = d.as_array().unwrap_or(&empty);
                if keys.is_empty() {
                    println!("No keys in vault.");
                } else {
                    println!("Keys ({}):", keys.len());
                    for k in keys {
                        let pk = k.get("pubkey").and_then(|v| v.as_str()).unwrap_or("?");
                        let label = k.get("label").and_then(|v| v.as_str()).unwrap_or("");
                        if label.is_empty() {
                            println!("  {}", pk);
                        } else {
                            println!("  {} ({})", pk, label);
                        }
                    }
                }
            });
        }
        VaultCommand::Generate { label } => {
            let body = serde_json::json!({ "label": label.unwrap_or_default() });
            let resp = post_json(&client, &format!("{}/api/vault/generate", base), &body).await?;
            let data: serde_json::Value = resp.json().await?;
            let pk = data.get("pubkey").and_then(|v| v.as_str()).unwrap_or("?");
            println!("✓ Generated key: {}", pk);
        }
        VaultCommand::Add { secret, label } => {
            let body = serde_json::json!({ "secret": secret, "label": label.unwrap_or_default() });
            let resp = post_json(&client, &format!("{}/api/vault/add", base), &body).await?;
            let data: serde_json::Value = resp.json().await?;
            let pk = data.get("pubkey").and_then(|v| v.as_str()).unwrap_or("?");
            println!("✓ Added key: {}", pk);
        }
        VaultCommand::Export { pubkey } => {
            let body = serde_json::json!({ "pubkey": pubkey });
            let resp = post_json(&client, &format!("{}/api/vault/export", base), &body).await?;
            let data: serde_json::Value = resp.json().await?;
            let secret = data.get("secret").and_then(|v| v.as_str()).unwrap_or("?");
            println!("{}", secret);
        }
        VaultCommand::ExportAll { json } => {
            let resp = get(&client, &format!("{}/api/vault/export-all", base)).await?;
            let data: serde_json::Value = resp.json().await?;
            print_json_or(&data, json, |d| {
                println!("{}", serde_json::to_string_pretty(d).unwrap_or_default());
            });
        }
        VaultCommand::Import { file } => {
            let contents = if file == "-" {
                use std::io::Read;
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                buf
            } else {
                std::fs::read_to_string(&file)?
            };
            let body: serde_json::Value = serde_json::from_str(&contents)?;
            let resp = post_json(&client, &format!("{}/api/vault/import", base), &body).await?;
            let data: serde_json::Value = resp.json().await?;
            println!("✓ Import: {}", data.get("imported").and_then(|v| v.as_u64()).unwrap_or(0));
        }
        VaultCommand::Rename { pubkey, label } => {
            let body = serde_json::json!({ "pubkey": pubkey, "label": label });
            post_json(&client, &format!("{}/api/vault/rename", base), &body).await?;
            println!("✓ Renamed key {}", pubkey);
        }
        VaultCommand::Delete { pubkey } => {
            delete(&client, &format!("{}/api/vault/delete/{}", base, pubkey)).await?;
            println!("✓ Deleted key {}", pubkey);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    #[derive(clap::Parser)]
    struct TestCli { #[command(subcommand)] cmd: super::VaultCommand }

    #[test] fn test_parse_status() {
        let cli = TestCli::try_parse_from(["v", "status"]).unwrap();
        assert!(matches!(cli.cmd, super::VaultCommand::Status { json: false }));
    }
    #[test] fn test_parse_keys_json() {
        let cli = TestCli::try_parse_from(["v", "keys", "--json"]).unwrap();
        assert!(matches!(cli.cmd, super::VaultCommand::Keys { json: true }));
    }
    #[test] fn test_parse_generate() {
        let cli = TestCli::try_parse_from(["v", "generate"]).unwrap();
        assert!(matches!(cli.cmd, super::VaultCommand::Generate { .. }));
    }
    #[test] fn test_parse_delete() {
        let cli = TestCli::try_parse_from(["v", "delete", "abc123"]).unwrap();
        assert!(matches!(cli.cmd, super::VaultCommand::Delete { .. }));
    }
    #[test] fn test_parse_export() {
        let cli = TestCli::try_parse_from(["v", "export", "abc123"]).unwrap();
        assert!(matches!(cli.cmd, super::VaultCommand::Export { .. }));
    }
}
