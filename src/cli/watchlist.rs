//! `pubky-node watchlist` — manage the identity watchlist on a running node.

use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct WatchlistArgs {
    /// Dashboard URL
    #[arg(long, default_value = "http://localhost:9090", global = true)]
    pub url: String,

    #[command(subcommand)]
    pub command: WatchlistCommand,
}

#[derive(Subcommand, Debug)]
pub enum WatchlistCommand {
    /// List all watched keys
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Add a public key to the watchlist
    Add {
        /// z-base-32 public key to watch
        key: String,
    },
    /// Remove a public key from the watchlist
    Remove {
        /// z-base-32 public key to unwatch
        key: String,
    },
}

pub async fn execute(args: WatchlistArgs) -> anyhow::Result<()> {
    let base = args.url.trim_end_matches('/').to_string();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    match args.command {
        WatchlistCommand::List { json } => {
            let resp = client.get(format!("{}/api/watchlist", base))
                .send().await
                .map_err(|_| anyhow::anyhow!("Could not connect to {}. Is pubky-node running?", base))?;
            if !resp.status().is_success() {
                anyhow::bail!("Watchlist endpoint returned {}", resp.status());
            }
            let data: serde_json::Value = resp.json().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&data)?);
            } else {
                let empty = vec![];
                let keys = data.as_array().unwrap_or(&empty);
                if keys.is_empty() {
                    println!("Watchlist is empty.");
                } else {
                    println!("Watched keys ({}):", keys.len());
                    for k in keys {
                        println!("  {}", k.as_str().unwrap_or("?"));
                    }
                }
            }
        }

        WatchlistCommand::Add { key } => {
            let resp = client.post(format!("{}/api/watchlist", base))
                .json(&serde_json::json!({ "key": key }))
                .send().await
                .map_err(|_| anyhow::anyhow!("Could not connect to {}. Is pubky-node running?", base))?;
            if !resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("Failed to add key: {}", body);
            }
            println!("✓ Added {} to watchlist", key);
        }

        WatchlistCommand::Remove { key } => {
            let resp = client.delete(format!("{}/api/watchlist/{}", base, key))
                .send().await
                .map_err(|_| anyhow::anyhow!("Could not connect to {}. Is pubky-node running?", base))?;
            if !resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("Failed to remove key: {}", body);
            }
            println!("✓ Removed {} from watchlist", key);
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
        cmd: super::WatchlistCommand,
    }

    #[test]
    fn test_parse_list_command() {
        let cli = TestCli::try_parse_from(["watchlist", "list"]).unwrap();
        assert!(matches!(cli.cmd, super::WatchlistCommand::List { json: false }));
    }

    #[test]
    fn test_parse_list_json() {
        let cli = TestCli::try_parse_from(["watchlist", "list", "--json"]).unwrap();
        assert!(matches!(cli.cmd, super::WatchlistCommand::List { json: true }));
    }

    #[test]
    fn test_parse_add_command() {
        let cli = TestCli::try_parse_from(["watchlist", "add", "mykey123"]).unwrap();
        match cli.cmd {
            super::WatchlistCommand::Add { key } => assert_eq!(key, "mykey123"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_remove_command() {
        let cli = TestCli::try_parse_from(["watchlist", "remove", "mykey456"]).unwrap();
        match cli.cmd {
            super::WatchlistCommand::Remove { key } => assert_eq!(key, "mykey456"),
            _ => panic!("wrong variant"),
        }
    }
}

