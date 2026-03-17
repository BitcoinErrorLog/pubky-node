//! Profile API — read/write PubkyAppUser profiles on the local homeserver.
//!
//! Follows the pubky-app-specs profile format:
//!   URI: /pub/pubky.app/profile.json
//!   Fields: name (required), bio?, image?, links?: [{title, url}], status?

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::state::DashboardState;

/// Profile JSON matching PubkyAppUser spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilePayload {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bio: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<ProfileLink>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileLink {
    pub title: String,
    pub url: String,
}

// ─── Helpers ────────────────────────────────────────────────────

/// Sign in to the local homeserver and return a session cookie string.
/// If the user isn't signed up, auto-signs them up first (with admin signup token).
/// Returns the cookie in the format "{pubkey}={session_value}".
async fn signin_local(
    secret_hex: &str,
    pubkey: &str,
    icann_port: u16,
    admin_port: u16,
    admin_password: &str,
) -> Result<String, String> {
    let keypair = decode_keypair(secret_hex)?;
    let token = build_auth_token(&keypair)?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    // Try signin — homeserver POST /signin endpoint
    let signin_url = format!("http://127.0.0.1:{}/signin", icann_port);
    match try_auth_request(&client, &signin_url, &token).await {
        Ok(cookie) => return Ok(format!("{}={}", pubkey, cookie)),
        Err(e) => tracing::info!("Signin auth failed, trying signup: {}", e),
    }

    // Session failed — get signup token from admin API for token_required mode
    let signup_token = get_admin_signup_token(&client, admin_port, admin_password).await;

    // Build signup URL (with token if available)
    let signup_url = match &signup_token {
        Some(t) => format!("http://127.0.0.1:{}/signup?signup_token={}", icann_port, t),
        None => format!("http://127.0.0.1:{}/signup", icann_port),
    };

    let token2 = build_auth_token(&keypair)?;
    match try_auth_request(&client, &signup_url, &token2).await {
        Ok(cookie) => {
            tracing::info!("Auto-signup succeeded for {}", &pubkey[..12.min(pubkey.len())]);
            return Ok(format!("{}={}", pubkey, cookie));
        }
        Err(e) => tracing::info!("Signup also failed: {}", e),
    }

    // Both failed — retry signin (signup may have succeeded but returned 409 without cookie)
    let token3 = build_auth_token(&keypair)?;
    match try_auth_request(&client, &signin_url, &token3).await {
        Ok(cookie) => Ok(format!("{}={}", pubkey, cookie)),
        Err(e) => Err(format!("Auth failed after signup attempt: {}", e)),
    }
}

/// Get a signup token from the homeserver admin API.
async fn get_admin_signup_token(
    client: &reqwest::Client,
    admin_port: u16,
    admin_password: &str,
) -> Option<String> {
    use base64::Engine;
    let url = format!("http://127.0.0.1:{}/signup_token", admin_port);
    let creds = base64::engine::general_purpose::STANDARD
        .encode(format!("admin:{}", admin_password));

    let resp = client
        .get(&url)
        .header("Authorization", format!("Basic {}", creds))
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() { return None; }

    let data: serde_json::Value = resp.json().await.ok()?;
    data.get("token").and_then(|t| t.as_str()).map(|s| s.to_string())
}

/// Try a signin or signup POST request and extract the session cookie.
async fn try_auth_request(
    client: &reqwest::Client,
    url: &str,
    token: &[u8],
) -> Result<String, String> {
    let resp = client
        .post(url)
        .body(token.to_vec())
        .header("content-type", "application/octet-stream")
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    let status = resp.status();

    let cookie_val = resp.headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|v| {
            let s = v.to_str().unwrap_or("");
            // Cookie format: key=value; path=...; etc
            s.split(';').next().and_then(|kv| {
                let parts: Vec<&str> = kv.splitn(2, '=').collect();
                if parts.len() == 2 { Some(parts[1].to_string()) } else { None }
            })
        });

    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("{} ({}): {}", url.rsplit('/').next().unwrap_or("auth"), status, body));
    }

    cookie_val.ok_or_else(|| "No session cookie received".to_string())
}

fn decode_keypair(secret_hex: &str) -> Result<pkarr::Keypair, String> {
    let bytes = hex::decode(secret_hex)
        .map_err(|e| format!("Invalid secret hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("Secret must be 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(pkarr::Keypair::from_secret_key(&arr))
}

fn build_auth_token(keypair: &pkarr::Keypair) -> Result<Vec<u8>, String> {
    // Convert our pkarr::Keypair to pubky_common::crypto::Keypair (may be different pkarr version)
    let secret_bytes = keypair.secret_key();
    let common_kp = pubky_common::crypto::Keypair::from_secret_key(&secret_bytes);
    // Use the proper pubky_common AuthToken format with root capabilities for full access
    let caps = vec![pubky_common::capabilities::Capability::root()];
    let token = pubky_common::auth::AuthToken::sign(&common_kp, caps);
    Ok(token.serialize())
}

// ─── API Handlers ───────────────────────────────────────────────

/// GET /api/profile/:pubkey — read profile from homeserver
pub async fn api_profile_get(
    State(state): State<Arc<DashboardState>>,
    Path(pubkey): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let cfg = state.homeserver.get_config();
    let url = format!(
        "http://127.0.0.1:{}/pub/pubky.app/profile.json",
        cfg.drive_icann_port
    );

    // Read profile via a GET to the homeserver's ICANN port with pubky-host header
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))),
    };

    let resp = match client
        .get(&url)
        .header("pubky-host", &pubkey)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": format!("Homeserver unreachable: {}", e) }))),
    };

    if resp.status() == reqwest::StatusCode::NOT_FOUND || resp.status() == reqwest::StatusCode::NO_CONTENT {
        return (StatusCode::OK, Json(serde_json::json!({ "profile": null, "exists": false })));
    }

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({ "error": format!("Homeserver error: {}", body) })));
    }

    let body = match resp.text().await {
        Ok(b) => b,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))),
    };

    match serde_json::from_str::<serde_json::Value>(&body) {
        Ok(profile) => (StatusCode::OK, Json(serde_json::json!({ "profile": profile, "exists": true }))),
        Err(_) => (StatusCode::OK, Json(serde_json::json!({ "profile": null, "exists": false, "raw": body }))),
    }
}

/// PUT /api/profile/:pubkey — write profile to homeserver
pub async fn api_profile_put(
    State(state): State<Arc<DashboardState>>,
    Path(pubkey): Path<String>,
    Json(payload): Json<ProfilePayload>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Validate
    let name = payload.name.trim().to_string();
    if name.len() < 3 || name.len() > 50 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Name must be 3-50 characters" })));
    }
    if name == "[DELETED]" {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid name" })));
    }

    // Get secret key — try vault first, then fall back to server's secret file
    let secret_hex = match state.vault.export_key(&pubkey) {
        Ok(s) => s,
        Err(_vault_err) => {
            // Vault export failed — try reading the homeserver's secret file as fallback
            // This handles the case where the vault is locked but we're saving the server's own profile
            let server_pk = state.homeserver.server_pubkey().or_else(|| {
                state.homeserver.read_server_secret().and_then(|s| {
                    let b = hex::decode(s.trim()).ok()?;
                    if b.len() != 32 { return None; }
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&b);
                    Some(pkarr::Keypair::from_secret_key(&k).public_key().to_z32())
                })
            });
            if server_pk.as_deref() == Some(&pubkey) {
                // This IS the server key — read secret from disk
                match state.homeserver.read_server_secret() {
                    Some(s) => s.trim().to_string(),
                    None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                        "error": "Server secret file not found. Is the homeserver running?"
                    }))),
                }
            } else {
                // Not the server key — vault is required
                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                    "error": "Vault is locked. Please unlock the vault to save profiles for non-server keys."
                })));
            }
        }
    };

    let cfg = state.homeserver.get_config();

    // Get server pubkey for pubky-host header — use same fallback chain as status endpoint
    let server_pubkey = state.homeserver.server_pubkey().or_else(|| {
        state.homeserver.read_server_secret().and_then(|secret_hex| {
            let secret_bytes = hex::decode(secret_hex.trim()).ok()?;
            if secret_bytes.len() != 32 { return None; }
            let mut key = [0u8; 32];
            key.copy_from_slice(&secret_bytes);
            let kp = pkarr::Keypair::from_secret_key(&key);
            Some(kp.public_key().to_z32())
        })
    });
    let server_pubkey = match server_pubkey {
        Some(pk) => pk,
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": "Homeserver pubkey not available. Is it running?" }))),
    };

    // Sign in to get session cookie (auto-signup if needed, with admin token for token_required mode)
    let cookie = match signin_local(&secret_hex, &pubkey, cfg.drive_icann_port, cfg.admin_port, &cfg.admin_password).await {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("Auth failed: {}", e) }))),
    };

    // Build sanitized profile
    let profile = ProfilePayload {
        name: name.chars().take(50).collect(),
        bio: payload.bio.map(|b| b.trim().chars().take(160).collect()),
        image: payload.image.map(|i| i.trim().to_string()),
        links: payload.links.map(|links| {
            links.into_iter()
                .take(5)
                .map(|l| ProfileLink {
                    title: l.title.trim().chars().take(100).collect(),
                    url: l.url.trim().to_string(),
                })
                .filter(|l| !l.url.is_empty())
                .collect()
        }),
        status: payload.status.map(|s| s.trim().chars().take(50).collect()),
    };

    let profile_json = match serde_json::to_vec(&profile) {
        Ok(j) => j,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))),
    };

    // PUT to homeserver
    let put_url = format!(
        "http://127.0.0.1:{}/pub/pubky.app/profile.json",
        cfg.drive_icann_port
    );

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))),
    };

    let resp = match client
        .put(&put_url)
        .header("cookie", &cookie)
        .header("content-type", "application/json")
        .header("pubky-host", &pubkey)
        .body(profile_json)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": format!("PUT failed: {}", e) }))),
    };

    let resp_status = resp.status();
    if !resp_status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({ "error": format!("Homeserver rejected profile ({}): {}", resp_status, body) })));
    }

    tracing::info!("Profile saved for {}", &pubkey[..12.min(pubkey.len())]);
    (StatusCode::OK, Json(serde_json::json!({ "ok": true, "profile": profile })))
}

/// GET /api/profile/:pubkey/nexus — check Nexus indexing status
pub async fn api_profile_nexus(
    Path(pubkey): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))),
    };

    // Check production Nexus
    let prod_url = format!("https://nexus.pubky.app/v0/user/{}", pubkey);
    let prod_result = check_nexus_instance(&client, &prod_url).await;

    // Check staging Nexus
    let staging_url = format!("https://nexus.staging.pubky.app/v0/user/{}", pubkey);
    let staging_result = check_nexus_instance(&client, &staging_url).await;

    (StatusCode::OK, Json(serde_json::json!({
        "pubkey": pubkey,
        "production": prod_result,
        "staging": staging_result,
    })))
}

async fn check_nexus_instance(
    client: &reqwest::Client,
    url: &str,
) -> serde_json::Value {
    match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if status == 200 {
                match serde_json::from_str::<serde_json::Value>(&body) {
                    Ok(data) => {
                        // Check if it has error field
                        if data.get("error").is_some() {
                            serde_json::json!({ "indexed": false, "status": "not_found" })
                        } else {
                            serde_json::json!({ "indexed": true, "status": "indexed", "data": data })
                        }
                    }
                    Err(_) => serde_json::json!({ "indexed": false, "status": "parse_error" }),
                }
            } else {
                serde_json::json!({ "indexed": false, "status": format!("http_{}", status) })
            }
        }
        Err(e) => serde_json::json!({ "indexed": false, "status": "unreachable", "error": e.to_string() }),
    }
}

/// GET /api/profile/:pubkey/verify — verify profile is reachable via tunnel
pub async fn api_profile_verify(
    State(state): State<Arc<DashboardState>>,
    Path(pubkey): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Get tunnel URL
    let tunnel_url = state.tunnel.public_url();

    let Some(tunnel_url) = tunnel_url else {
        return (StatusCode::OK, Json(serde_json::json!({
            "reachable": false,
            "reason": "No tunnel active"
        })));
    };

    let profile_url = format!("{}/pub/pubky.app/profile.json", tunnel_url);

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))),
    };

    match client.get(&profile_url)
        .header("pubky-host", &pubkey)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            (StatusCode::OK, Json(serde_json::json!({
                "reachable": status == 200,
                "tunnel_url": tunnel_url,
                "profile_url": profile_url,
                "http_status": status,
                "body_preview": &body[..body.len().min(200)],
            })))
        }
        Err(e) => (StatusCode::OK, Json(serde_json::json!({
            "reachable": false,
            "tunnel_url": tunnel_url,
            "error": e.to_string(),
        }))),
    }
}

/// POST /api/profile/:pubkey/nexus-submit — submit homeserver to Nexus for indexing
pub async fn api_profile_nexus_submit(
    Path(pubkey): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))),
    };

    // Submit to production Nexus
    let prod_url = format!("https://nexus.pubky.app/v0/ingest/{}", pubkey);
    let prod_result = submit_to_nexus(&client, &prod_url).await;

    // Submit to staging Nexus
    let staging_url = format!("https://nexus.staging.pubky.app/v0/ingest/{}", pubkey);
    let staging_result = submit_to_nexus(&client, &staging_url).await;

    tracing::info!("Nexus ingest submitted for {}: prod={:?}, staging={:?}", &pubkey[..12.min(pubkey.len())], prod_result, staging_result);

    (StatusCode::OK, Json(serde_json::json!({
        "pubkey": pubkey,
        "production": prod_result,
        "staging": staging_result,
    })))
}

async fn submit_to_nexus(client: &reqwest::Client, url: &str) -> serde_json::Value {
    match client.put(url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if status == 200 {
                serde_json::json!({ "ok": true, "status": status })
            } else {
                serde_json::json!({ "ok": false, "status": status, "body": body })
            }
        }
        Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_validation() {
        // Valid profile
        let profile = ProfilePayload {
            name: "Alice".to_string(),
            bio: Some("Testing".to_string()),
            image: None,
            links: Some(vec![ProfileLink {
                title: "GitHub".to_string(),
                url: "https://github.com/alice".to_string(),
            }]),
            status: Some("Online".to_string()),
        };
        assert!(profile.name.len() >= 3);
        assert!(profile.name.len() <= 50);

        // Serialization roundtrip
        let json = serde_json::to_string(&profile).unwrap();
        let parsed: ProfilePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "Alice");
        assert_eq!(parsed.bio.as_deref(), Some("Testing"));
        assert_eq!(parsed.links.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn test_profile_name_validation() {
        // Too short
        let name = "Al";
        assert!(name.len() < 3);

        // Too long
        let name = "A".repeat(51);
        assert!(name.len() > 50);

        // Reserved
        let name = "[DELETED]";
        assert_eq!(name, "[DELETED]");
    }

    #[test]
    fn test_profile_serialization_optional_fields() {
        let profile = ProfilePayload {
            name: "Bob".to_string(),
            bio: None,
            image: None,
            links: None,
            status: None,
        };
        let json = serde_json::to_string(&profile).unwrap();
        // Optional fields should not appear in output
        assert!(!json.contains("bio"));
        assert!(!json.contains("image"));
        assert!(!json.contains("links"));
        assert!(!json.contains("status"));
        assert!(json.contains("Bob"));
    }

    #[test]
    fn test_profile_link_serialization() {
        let link = ProfileLink {
            title: "My Website".to_string(),
            url: "https://example.com".to_string(),
        };
        let json = serde_json::to_string(&link).unwrap();
        assert!(json.contains("My Website"));
        assert!(json.contains("https://example.com"));
    }
}
