//! `pubky-node status` — query a running node's status endpoint.

use clap::Args;

#[derive(Args, Debug)]
pub struct StatusArgs {
    /// Dashboard URL to query
    #[arg(long, default_value = "http://localhost:9090")]
    pub url: String,

    /// Output raw JSON instead of formatted
    #[arg(long)]
    pub json: bool,
}

pub async fn execute(args: StatusArgs) -> anyhow::Result<()> {
    let status_url = format!("{}/api/status", args.url.trim_end_matches('/'));

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let resp = client.get(&status_url).send().await
        .map_err(|_| anyhow::anyhow!(
            "Could not connect to {}. Is pubky-node running?", args.url
        ))?;

    if !resp.status().is_success() {
        anyhow::bail!("Status endpoint returned {}", resp.status());
    }

    let data: serde_json::Value = resp.json().await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&data)?);
    } else {
        println!("Pubky Node Status");
        println!("{}", "=".repeat(40));

        if let Some(uptime) = data.get("uptime_secs").and_then(|v| v.as_u64()) {
            let hours = uptime / 3600;
            let mins = (uptime % 3600) / 60;
            println!("Uptime:       {}h {}m", hours, mins);
        }

        if let Some(dht) = data.get("dht") {
            if let Some(size) = dht.get("network_size_estimate").and_then(|v| v.as_u64()) {
                println!("DHT Peers:    ~{}", format_number(size));
            }
            if let Some(mode) = dht.get("mode").and_then(|v| v.as_str()) {
                println!("DHT Mode:     {}", mode);
            }
            if let Some(fw) = dht.get("firewalled").and_then(|v| v.as_bool()) {
                println!("Firewalled:   {}", if fw { "Yes" } else { "No" });
            }
        }

        if let Some(relay) = data.get("relay") {
            if let Some(url) = relay.get("url").and_then(|v| v.as_str()) {
                println!("Relay:        {}", url);
            }
        }

        if let Some(upnp) = data.get("upnp") {
            if let Some(status) = upnp.get("status").and_then(|v| v.as_str()) {
                let detail = match (upnp.get("external_ip"), upnp.get("port")) {
                    (Some(ip), Some(port)) => format!(" ({}:{})", ip, port),
                    _ => String::new(),
                };
                println!("UPnP:         {}{}", status, detail);
            }
        }

        if let Some(wl) = data.get("watchlist") {
            if let Some(count) = wl.get("key_count").and_then(|v| v.as_u64()) {
                println!("Watchlist:    {} key(s)", count);
            }
        }
    }

    Ok(())
}

fn format_number(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{}K", n / 1_000)
    } else {
        n.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_number_millions() {
        assert_eq!(format_number(3_300_000), "3.3M");
    }

    #[test]
    fn test_format_number_thousands() {
        assert_eq!(format_number(5_500), "5K");
    }

    #[test]
    fn test_format_number_small() {
        assert_eq!(format_number(42), "42");
    }
}
