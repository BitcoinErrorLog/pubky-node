//! Shared helpers for CLI subcommands that talk to the running node's HTTP API.

use reqwest::header::HeaderMap;

/// Build a reqwest client with optional auth password.
pub fn build_client(password: &Option<String>) -> anyhow::Result<reqwest::Client> {
    let mut headers = HeaderMap::new();
    if let Some(pw) = password {
        headers.insert("X-Auth-Password", pw.parse()?);
    } else if let Ok(pw) = std::env::var("PUBKY_NODE_PASSWORD") {
        headers.insert("X-Auth-Password", pw.parse()?);
    }
    Ok(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .default_headers(headers)
        .build()?)
}

/// GET request with error handling.
pub async fn get(client: &reqwest::Client, url: &str) -> anyhow::Result<reqwest::Response> {
    let resp = client.get(url).send().await
        .map_err(|_| anyhow::anyhow!("Could not connect to node. Is pubky-node running?"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Request failed ({}): {}", status, body);
    }
    Ok(resp)
}

/// POST request with error handling.
pub async fn post(client: &reqwest::Client, url: &str) -> anyhow::Result<reqwest::Response> {
    let resp = client.post(url).send().await
        .map_err(|_| anyhow::anyhow!("Could not connect to node. Is pubky-node running?"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Request failed ({}): {}", status, body);
    }
    Ok(resp)
}

/// POST request with JSON body.
pub async fn post_json(client: &reqwest::Client, url: &str, body: &serde_json::Value) -> anyhow::Result<reqwest::Response> {
    let resp = client.post(url).json(body).send().await
        .map_err(|_| anyhow::anyhow!("Could not connect to node. Is pubky-node running?"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Request failed ({}): {}", status, body);
    }
    Ok(resp)
}

/// DELETE request with error handling.
pub async fn delete(client: &reqwest::Client, url: &str) -> anyhow::Result<reqwest::Response> {
    let resp = client.delete(url).send().await
        .map_err(|_| anyhow::anyhow!("Could not connect to node. Is pubky-node running?"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Request failed ({}): {}", status, body);
    }
    Ok(resp)
}

/// PUT request with JSON body.
pub async fn put_json(client: &reqwest::Client, url: &str, body: &serde_json::Value) -> anyhow::Result<reqwest::Response> {
    let resp = client.put(url).json(body).send().await
        .map_err(|_| anyhow::anyhow!("Could not connect to node. Is pubky-node running?"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Request failed ({}): {}", status, body);
    }
    Ok(resp)
}

/// Print JSON or formatted output.
pub fn print_json_or(data: &serde_json::Value, json: bool, formatter: impl FnOnce(&serde_json::Value)) {
    if json {
        println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
    } else {
        formatter(data);
    }
}
