//! `pubky-node profile` — manage public profiles on a running node.

use clap::{Args, Subcommand};
use super::helpers::{build_client, get, put_json, print_json_or};

#[derive(Args, Debug)]
pub struct ProfileArgs {
    /// Dashboard URL
    #[arg(long, default_value = "http://localhost:9090", global = true)]
    pub url: String,
    /// Dashboard password
    #[arg(long, global = true)]
    pub password: Option<String>,
    #[command(subcommand)]
    pub command: ProfileCommand,
}

#[derive(Subcommand, Debug)]
pub enum ProfileCommand {
    /// Get a profile by public key
    Get {
        /// Public key (zbase32)
        pubkey: String,
        #[arg(long)]
        json: bool,
    },
    /// Update a profile
    Set {
        /// Public key (zbase32)
        pubkey: String,
        /// Display name
        #[arg(long)]
        name: Option<String>,
        /// Bio text
        #[arg(long)]
        bio: Option<String>,
        /// Profile image URL
        #[arg(long)]
        image: Option<String>,
    },
    /// Check Nexus indexing status for a pubkey
    Nexus {
        /// Public key (zbase32)
        pubkey: String,
        #[arg(long)]
        json: bool,
    },
    /// Verify a profile's PKARR record
    Verify {
        /// Public key (zbase32)
        pubkey: String,
        #[arg(long)]
        json: bool,
    },
}

pub async fn execute(args: ProfileArgs) -> anyhow::Result<()> {
    let base = args.url.trim_end_matches('/').to_string();
    let client = build_client(&args.password)?;

    match args.command {
        ProfileCommand::Get { pubkey, json } => {
            let resp = get(&client, &format!("{}/api/profile/{}", base, pubkey)).await?;
            let data: serde_json::Value = resp.json().await?;
            print_json_or(&data, json, |d| {
                let name = d.get("name").and_then(|v| v.as_str()).unwrap_or("(unnamed)");
                let bio = d.get("bio").and_then(|v| v.as_str()).unwrap_or("");
                println!("Profile: {}", name);
                if !bio.is_empty() { println!("  Bio: {}", bio); }
                if let Some(img) = d.get("image").and_then(|v| v.as_str()) {
                    println!("  Image: {}", img);
                }
            });
        }
        ProfileCommand::Set { pubkey, name, bio, image } => {
            let mut body = serde_json::json!({});
            if let Some(n) = name { body["name"] = serde_json::json!(n); }
            if let Some(b) = bio { body["bio"] = serde_json::json!(b); }
            if let Some(i) = image { body["image"] = serde_json::json!(i); }
            put_json(&client, &format!("{}/api/profile/{}", base, pubkey), &body).await?;
            println!("✓ Profile updated for {}", pubkey);
        }
        ProfileCommand::Nexus { pubkey, json } => {
            let resp = get(&client, &format!("{}/api/profile/{}/nexus", base, pubkey)).await?;
            let data: serde_json::Value = resp.json().await?;
            print_json_or(&data, json, |d| {
                let indexed = d.get("indexed").and_then(|v| v.as_bool()).unwrap_or(false);
                println!("Nexus: {}", if indexed { "✓ Indexed" } else { "✗ Not indexed" });
            });
        }
        ProfileCommand::Verify { pubkey, json } => {
            let resp = get(&client, &format!("{}/api/profile/{}/verify", base, pubkey)).await?;
            let data: serde_json::Value = resp.json().await?;
            print_json_or(&data, json, |d| {
                println!("{}", serde_json::to_string_pretty(d).unwrap_or_default());
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    #[derive(clap::Parser)]
    struct TestCli { #[command(subcommand)] cmd: super::ProfileCommand }

    #[test] fn test_parse_get() {
        let cli = TestCli::try_parse_from(["p", "get", "abc123"]).unwrap();
        assert!(matches!(cli.cmd, super::ProfileCommand::Get { .. }));
    }
    #[test] fn test_parse_nexus() {
        let cli = TestCli::try_parse_from(["p", "nexus", "abc123"]).unwrap();
        assert!(matches!(cli.cmd, super::ProfileCommand::Nexus { .. }));
    }
}
