//! `pubky-node identity` — manage identities on a running node.

use clap::{Args, Subcommand};
use super::helpers::{build_client, get, post_json, print_json_or};

#[derive(Args, Debug)]
pub struct IdentityArgs {
    /// Dashboard URL
    #[arg(long, default_value = "http://localhost:9090", global = true)]
    pub url: String,
    /// Dashboard password
    #[arg(long, global = true)]
    pub password: Option<String>,
    #[command(subcommand)]
    pub command: IdentityCommand,
}

#[derive(Subcommand, Debug)]
pub enum IdentityCommand {
    /// Sign up a new identity on the homeserver
    Signup {
        /// Public key (zbase32) from vault
        #[arg(long)]
        pubkey: String,
        /// Signup token (if required)
        #[arg(long)]
        token: Option<String>,
    },
    /// Sign in with an existing identity
    Signin {
        /// Public key (zbase32) from vault
        #[arg(long)]
        pubkey: String,
    },
    /// List registered identities
    List {
        #[arg(long)]
        json: bool,
    },
}

pub async fn execute(args: IdentityArgs) -> anyhow::Result<()> {
    let base = args.url.trim_end_matches('/').to_string();
    let client = build_client(&args.password)?;

    match args.command {
        IdentityCommand::Signup { pubkey, token } => {
            let mut body = serde_json::json!({ "pubkey": pubkey });
            if let Some(t) = token { body["token"] = serde_json::json!(t); }
            let resp = post_json(&client, &format!("{}/api/identity/signup", base), &body).await?;
            let data: serde_json::Value = resp.json().await?;
            println!("✓ Signed up: {}", data.get("pubkey").and_then(|v| v.as_str()).unwrap_or(&pubkey));
        }
        IdentityCommand::Signin { pubkey } => {
            let body = serde_json::json!({ "pubkey": pubkey });
            let resp = post_json(&client, &format!("{}/api/identity/signin", base), &body).await?;
            let data: serde_json::Value = resp.json().await?;
            println!("✓ Signed in: {}", data.get("pubkey").and_then(|v| v.as_str()).unwrap_or(&pubkey));
        }
        IdentityCommand::List { json } => {
            let resp = get(&client, &format!("{}/api/identity/list", base)).await?;
            let data: serde_json::Value = resp.json().await?;
            print_json_or(&data, json, |d| {
                let empty = vec![];
                let ids = d.as_array().unwrap_or(&empty);
                if ids.is_empty() {
                    println!("No identities registered.");
                } else {
                    println!("Identities ({}):", ids.len());
                    for id in ids {
                        let pk = id.get("pubkey").and_then(|v| v.as_str()).unwrap_or("?");
                        println!("  {}", pk);
                    }
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
    struct TestCli { #[command(subcommand)] cmd: super::IdentityCommand }

    #[test] fn test_parse_list() {
        let cli = TestCli::try_parse_from(["id", "list"]).unwrap();
        assert!(matches!(cli.cmd, super::IdentityCommand::List { json: false }));
    }
    #[test] fn test_parse_signup() {
        let cli = TestCli::try_parse_from(["id", "signup", "--pubkey", "abc"]).unwrap();
        assert!(matches!(cli.cmd, super::IdentityCommand::Signup { .. }));
    }
}
