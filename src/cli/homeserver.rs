//! `pubky-node homeserver` — manage the built-in homeserver on a running node.

use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct HomeserverArgs {
    /// Dashboard URL
    #[arg(long, default_value = "http://localhost:9090", global = true)]
    pub url: String,

    #[command(subcommand)]
    pub command: HomeserverCommand,
}

#[derive(Subcommand, Debug)]
pub enum HomeserverCommand {
    /// Show homeserver status and runtime info
    Status {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Start the homeserver
    Start,
    /// Stop the homeserver
    Stop,
    /// Run prerequisites check (PostgreSQL, binary, config)
    Check {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Generate a signup invite token
    Token {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// List users registered on this homeserver
    Users {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Publish PKARR record for the homeserver key
    PublishPkarr,
    /// Stream recent homeserver logs
    Logs {
        /// Number of recent lines to show
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,
    },
}

pub async fn execute(args: HomeserverArgs) -> anyhow::Result<()> {
    let base = args.url.trim_end_matches('/').to_string();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    match args.command {
        HomeserverCommand::Status { json } => {
            let resp = get(&client, &format!("{}/api/homeserver/status", base)).await?;
            let data: serde_json::Value = resp.json().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&data)?);
            } else {
                let state = data.get("state").and_then(|v| v.as_str()).unwrap_or("Unknown");
                println!("Homeserver: {}", state);
                if let Some(pid) = data.get("pid").and_then(|v| v.as_u64()) {
                    println!("  PID:     {}", pid);
                }
                if let Some(uptime) = data.get("uptime").and_then(|v| v.as_str()) {
                    println!("  Uptime:  {}", uptime);
                }
                if let Some(port) = data.get("icann_port").and_then(|v| v.as_u64()) {
                    println!("  HTTP:    127.0.0.1:{}", port);
                }
                if let Some(port) = data.get("pubky_port").and_then(|v| v.as_u64()) {
                    println!("  Pubky:   127.0.0.1:{}", port);
                }
                if let Some(port) = data.get("admin_port").and_then(|v| v.as_u64()) {
                    println!("  Admin:   127.0.0.1:{}", port);
                }
            }
        }

        HomeserverCommand::Start => {
            let resp = post(&client, &format!("{}/api/homeserver/start", base)).await?;
            let data: serde_json::Value = resp.json().await.unwrap_or_default();
            println!("✓ Homeserver starting: {}",
                data.get("status").and_then(|v| v.as_str()).unwrap_or("ok"));
        }

        HomeserverCommand::Stop => {
            let resp = post(&client, &format!("{}/api/homeserver/stop", base)).await?;
            let data: serde_json::Value = resp.json().await.unwrap_or_default();
            println!("✓ Homeserver stopping: {}",
                data.get("status").and_then(|v| v.as_str()).unwrap_or("ok"));
        }

        HomeserverCommand::Check { json } => {
            let resp = get(&client, &format!("{}/api/homeserver/setup-check", base)).await?;
            let data: serde_json::Value = resp.json().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&data)?);
            } else {
                println!("Homeserver Prerequisites:");
                let checks = [("postgresql", "PostgreSQL"), ("database", "Database"),
                              ("binary", "Binary"), ("config", "Config")];
                for (key, label) in &checks {
                    let status = data.get(*key).and_then(|v| v.as_str()).unwrap_or("?");
                    let icon = if status.contains("OK") || status.contains("Found") || status.contains("Running") { "✓" } else { "✗" };
                    println!("  {} {:<12} {}", icon, label, status);
                }
            }
        }

        HomeserverCommand::Token { json } => {
            let resp = get(&client, &format!("{}/api/homeserver/signup-token", base)).await?;
            let data: serde_json::Value = resp.json().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&data)?);
            } else {
                let token = data.get("token").and_then(|v| v.as_str()).unwrap_or("?");
                println!("Signup token: {}", token);
            }
        }

        HomeserverCommand::Users { json } => {
            let resp = get(&client, &format!("{}/api/homeserver/users", base)).await?;
            let data: serde_json::Value = resp.json().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&data)?);
            } else {
                let empty = vec![];
                let users = data.as_array().unwrap_or(&empty);
                if users.is_empty() {
                    println!("No users registered.");
                } else {
                    println!("Users ({}):", users.len());
                    for u in users {
                        let pubkey = u.get("pubkey").and_then(|v| v.as_str()).unwrap_or("?");
                        println!("  {}", pubkey);
                    }
                }
            }
        }

        HomeserverCommand::PublishPkarr => {
            let resp = post(&client, &format!("{}/api/homeserver/publish-pkarr", base)).await?;
            let data: serde_json::Value = resp.json().await.unwrap_or_default();
            println!("✓ PKARR published: {}",
                data.get("status").and_then(|v| v.as_str()).unwrap_or("ok"));
        }

        HomeserverCommand::Logs { lines } => {
            let url = format!("{}/api/homeserver/logs?lines={}", base, lines);
            let resp = get(&client, &url).await?;
            let data: serde_json::Value = resp.json().await?;
            let empty = vec![];
            let log_lines = data.as_array().unwrap_or(&empty);
            for line in log_lines {
                println!("{}", line.as_str().unwrap_or(""));
            }
        }
    }

    Ok(())
}

async fn get(client: &reqwest::Client, url: &str) -> anyhow::Result<reqwest::Response> {
    let resp = client.get(url).send().await
        .map_err(|_| anyhow::anyhow!("Could not connect to node. Is pubky-node running?"))?;
    if !resp.status().is_success() {
        anyhow::bail!("Request failed: {}", resp.status());
    }
    Ok(resp)
}

async fn post(client: &reqwest::Client, url: &str) -> anyhow::Result<reqwest::Response> {
    let resp = client.post(url).send().await
        .map_err(|_| anyhow::anyhow!("Could not connect to node. Is pubky-node running?"))?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Request failed: {}", body);
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[derive(clap::Parser)]
    struct TestCli {
        #[command(subcommand)]
        cmd: super::HomeserverCommand,
    }

    #[test]
    fn test_parse_status() {
        let cli = TestCli::try_parse_from(["hs", "status"]).unwrap();
        assert!(matches!(cli.cmd, super::HomeserverCommand::Status { json: false }));
    }

    #[test]
    fn test_parse_status_json() {
        let cli = TestCli::try_parse_from(["hs", "status", "--json"]).unwrap();
        assert!(matches!(cli.cmd, super::HomeserverCommand::Status { json: true }));
    }

    #[test]
    fn test_parse_start() {
        let cli = TestCli::try_parse_from(["hs", "start"]).unwrap();
        assert!(matches!(cli.cmd, super::HomeserverCommand::Start));
    }

    #[test]
    fn test_parse_stop() {
        let cli = TestCli::try_parse_from(["hs", "stop"]).unwrap();
        assert!(matches!(cli.cmd, super::HomeserverCommand::Stop));
    }

    #[test]
    fn test_parse_check() {
        let cli = TestCli::try_parse_from(["hs", "check"]).unwrap();
        assert!(matches!(cli.cmd, super::HomeserverCommand::Check { json: false }));
    }

    #[test]
    fn test_parse_token() {
        let cli = TestCli::try_parse_from(["hs", "token"]).unwrap();
        assert!(matches!(cli.cmd, super::HomeserverCommand::Token { json: false }));
    }

    #[test]
    fn test_parse_users() {
        let cli = TestCli::try_parse_from(["hs", "users"]).unwrap();
        assert!(matches!(cli.cmd, super::HomeserverCommand::Users { json: false }));
    }

    #[test]
    fn test_parse_publish_pkarr() {
        let cli = TestCli::try_parse_from(["hs", "publish-pkarr"]).unwrap();
        assert!(matches!(cli.cmd, super::HomeserverCommand::PublishPkarr));
    }

    #[test]
    fn test_parse_logs_default() {
        let cli = TestCli::try_parse_from(["hs", "logs"]).unwrap();
        match cli.cmd {
            super::HomeserverCommand::Logs { lines } => assert_eq!(lines, 50),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_logs_custom_n() {
        let cli = TestCli::try_parse_from(["hs", "logs", "-n", "100"]).unwrap();
        match cli.cmd {
            super::HomeserverCommand::Logs { lines } => assert_eq!(lines, 100),
            _ => panic!("wrong variant"),
        }
    }
}

