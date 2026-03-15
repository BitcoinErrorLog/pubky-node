//! Homeserver API handlers.
//!
//! Manages homeserver lifecycle, config, users, PKARR publishing, and ICANN proxy.

use super::state::DashboardState;
use axum::{
    extract::{Path, State},
    http::{StatusCode, HeaderValue},
    response::{IntoResponse, Json, Response},
};
use std::sync::Arc;
use tracing::info;

/// Helper: GET request to admin API (uses HTTP Basic Auth).
pub async fn admin_fetch_get(url: &str, password: &str) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.get(url)
        .header("X-Admin-Password", password)
        .send()
        .await
        .map_err(|e| format!("Admin API error: {}", e))?;
    let body = resp.text().await.map_err(|e| e.to_string())?;
    serde_json::from_str(&body).map_err(|_| body)
}

/// Helper: POST JSON body to admin API.
pub async fn admin_fetch_post_json(url: &str, password: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.post(url)
        .header("X-Admin-Password", password)
        .json(body)
        .send()
        .await
        .map_err(|e| format!("Admin API error: {}", e))?;
    let body = resp.text().await.map_err(|e| e.to_string())?;
    serde_json::from_str(&body).map_err(|_| body)
}

/// Shared helper: publish homeserver PKARR record to DHT.
pub async fn publish_homeserver_pkarr(
    secret_hex: &str,
    icann_domain: &str,
    state: &Arc<DashboardState>,
) -> Result<(), String> {
    // If icann_domain is empty or "localhost", check tunnel URL as override
    let domain = if icann_domain.is_empty() || icann_domain == "localhost" {
        state.tunnel.public_url()
            .unwrap_or_else(|| icann_domain.to_string())
    } else {
        icann_domain.to_string()
    };

    let secret_bytes = hex::decode(secret_hex)
        .map_err(|e| format!("hex decode: {}", e))?;
    if secret_bytes.len() != 32 {
        return Err(format!("Expected 32-byte key, got {}", secret_bytes.len()));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&secret_bytes);
    let keypair = pkarr::Keypair::from_secret_key(&key_bytes);

    let records = vec![crate::config::RecordConfig {
        record_type: "HTTPS".to_string(),
        name: "@".to_string(),
        value: domain.clone(),
        ttl: Some(7200),
    }];

    let signed_packet = crate::publisher::build_signed_packet(&keypair, &records)
        .map_err(|e| format!("Build packet: {}", e))?;

    let client = state.client.as_ref()
        .ok_or("DHT client not available")?;
    client.publish(&signed_packet, None).await
        .map_err(|e| format!("Publish: {}", e))?;

    info!("Published PKARR for homeserver: {} → {}", keypair.public_key(), domain);
    Ok(())
}

/// POST /api/homeserver/set-key — assign a vault key as the homeserver's identity.
pub async fn api_hs_set_key(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let pubkey = match body.get("pubkey").and_then(|v| v.as_str()) {
        Some(pk) => pk,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Missing 'pubkey' field"}))),
    };

    // Export the secret from vault
    let secret_hex = match state.vault.export_key(pubkey) {
        Ok(s) => s,
        Err(e) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": format!("Key not found in vault: {}", e)
        }))),
    };

    // Write to homeserver's secret file
    match state.homeserver.set_server_key(&secret_hex) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({
            "success": true,
            "pubkey": pubkey,
            "message": "Server key set. Restart homeserver to apply."
        }))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Failed to set key: {}", e)
        }))),
    }
}

// ─── Homeserver Handlers ────────────────────────────────────────

/// GET /api/homeserver/status
pub async fn api_hs_status(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    state.homeserver.check_process();
    let hs_state = state.homeserver.state();
    let cfg = state.homeserver.get_config();
    // Get pubkey: from in-memory cache, or derive from secret file on disk
    let pubkey = state.homeserver.server_pubkey().or_else(|| {
        state.homeserver.read_server_secret().and_then(|secret_hex| {
            let secret_bytes = hex::decode(secret_hex.trim()).ok()?;
            if secret_bytes.len() != 32 { return None; }
            let mut key = [0u8; 32];
            key.copy_from_slice(&secret_bytes);
            let kp = pkarr::Keypair::from_secret_key(&key);
            Some(kp.public_key().to_z32())
        })
    });
    Json(serde_json::json!({
        "state": hs_state.as_str(),
        "error": if let crate::homeserver::HomeserverState::Error(ref e) = hs_state { Some(e.as_str()) } else { None::<&str> },
        "uptime_secs": state.homeserver.uptime_secs(),
        "pid": state.homeserver.pid(),
        "pubkey": pubkey,
        "ports": {
            "icann": cfg.drive_icann_port,
            "pubky": cfg.drive_pubky_port,
            "admin": cfg.admin_port,
            "metrics": cfg.metrics_port,
        }
    }))
}

/// POST /api/homeserver/start
pub async fn api_hs_start(
    State(state): State<Arc<DashboardState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.homeserver.start().await {
        Ok(msg) => {
            // Spawn background task: wait for homeserver to boot, then auto-publish its PKARR record
            let state_clone = state.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                let cfg = state_clone.homeserver.get_config();
                let info_url = format!("http://127.0.0.1:{}/info", cfg.admin_port);
                let password = cfg.admin_password.clone();
                let icann_domain = cfg.icann_domain.clone();
                drop(cfg);

                use base64::Engine;
                let creds = base64::engine::general_purpose::STANDARD
                    .encode(format!("admin:{}", password));

                let http_client = match reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!("Homeserver auto-PKARR: failed to build HTTP client: {}", e);
                        return;
                    }
                };

                let info_resp = match http_client
                    .get(&info_url)
                    .header("Authorization", format!("Basic {}", creds))
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("Homeserver auto-PKARR: info request failed: {}", e);
                        return;
                    }
                };

                if let Ok(text) = info_resp.text().await {
                    if let Ok(info) = serde_json::from_str::<serde_json::Value>(&text) {
                        if let Some(pubkey_str) = info.get("public_key").and_then(|v| v.as_str()) {
                            if let Ok(mut guard) = state_clone.homeserver.server_pubkey.write() {
                                *guard = Some(pubkey_str.to_string());
                            }

                            if let Ok(secret) = state_clone.vault.export_key(pubkey_str) {
                                if let Err(e) = publish_homeserver_pkarr(&secret, &icann_domain, &state_clone).await {
                                    tracing::warn!("Homeserver auto-PKARR publish failed: {}", e);
                                } else {
                                    tracing::info!("Homeserver PKARR published on start for {}", pubkey_str);
                                }
                            }
                        }
                    }
                }
            });

            (StatusCode::OK, Json(serde_json::json!({ "success": true, "message": msg })))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))),
    }
}

/// POST /api/homeserver/stop
pub async fn api_hs_stop(
    State(state): State<Arc<DashboardState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.homeserver.stop() {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "success": true }))),
        Err(e) => (StatusCode::OK, Json(serde_json::json!({ "success": true, "message": e }))),
    }
}

/// GET /api/homeserver/info — proxy admin /info
pub async fn api_hs_info(
    State(state): State<Arc<DashboardState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let cfg = state.homeserver.get_config();
    let url = format!("http://127.0.0.1:{}/info", cfg.admin_port);
    let password = cfg.admin_password.clone();

    match admin_fetch_get(&url, &password).await {
        Ok(info) => (StatusCode::OK, Json(info)),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": e }))),
    }
}

/// GET /api/homeserver/signup-token
pub async fn api_hs_signup_token(
    State(state): State<Arc<DashboardState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let cfg = state.homeserver.get_config();
    let url = format!("http://127.0.0.1:{}/generate_signup_token", cfg.admin_port);
    let password = cfg.admin_password.clone();

    match admin_fetch_get(&url, &password).await {
        Ok(resp) => {
            let token = resp.get("token")
                .or(resp.get("signup_token"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            (StatusCode::OK, Json(serde_json::json!({ "token": token })))
        }
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": e }))),
    }
}

/// GET /api/homeserver/setup-check
pub async fn api_hs_setup_check(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    let check = state.homeserver.check_setup();
    Json(serde_json::to_value(check).unwrap_or_default())
}

/// GET /api/homeserver/config
pub async fn api_hs_config(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    let cfg = state.homeserver.get_config();
    Json(serde_json::json!({
        "database_url": cfg.database_url,
        "signup_mode": cfg.signup_mode,
        "admin_password": cfg.admin_password,
        "public_ip": cfg.public_ip,
        "icann_domain": cfg.icann_domain,
        "storage_quota_mb": cfg.storage_quota_mb,
        "admin_port": cfg.admin_port,
        "drive_icann_port": cfg.drive_icann_port,
        "drive_pubky_port": cfg.drive_pubky_port,
        "metrics_port": cfg.metrics_port,
    }))
}

/// POST /api/homeserver/config — save config changes
pub async fn api_hs_config_save(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.homeserver.update_config(body) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "success": true }))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))),
    }
}

/// POST /api/homeserver/generate-config
pub async fn api_hs_generate_config(
    State(state): State<Arc<DashboardState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.homeserver.generate_config() {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "success": true, "message": "Config generated." }))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))),
    }
}

/// POST /api/homeserver/fix — auto-fix all prerequisites
pub async fn api_hs_fix(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    let log = state.homeserver.auto_fix().await;
    Json(serde_json::json!({ "log": log }))
}

/// GET /api/homeserver/logs
pub async fn api_hs_logs(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    let logs = state.homeserver.get_logs(100);
    Json(serde_json::json!({ "lines": logs }))
}

/// GET /api/homeserver/proxy-url
pub async fn api_hs_proxy_url(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    let cfg = state.homeserver.get_config();
    let running = state.homeserver.state() == crate::homeserver::HomeserverState::Running;
    Json(serde_json::json!({
        "url": format!("http://127.0.0.1:{}", cfg.drive_icann_port),
        "port": cfg.drive_icann_port,
        "running": running,
    }))
}

/// POST /api/homeserver/publish-pkarr — manually trigger PKARR publish.
pub async fn api_hs_publish_pkarr(
    State(state): State<Arc<DashboardState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let pubkey_opt = state.homeserver.server_pubkey().or_else(|| {
        state.homeserver.read_server_secret().and_then(|secret_hex| {
            let secret_bytes = hex::decode(secret_hex.trim()).ok()?;
            if secret_bytes.len() != 32 { return None; }
            let mut key = [0u8; 32];
            key.copy_from_slice(&secret_bytes);
            let kp = pkarr::Keypair::from_secret_key(&key);
            Some(kp.public_key().to_z32())
        })
    });

    let pubkey = match pubkey_opt {
        Some(pk) => pk,
        None => {
            let cfg = state.homeserver.get_config();
            let url = format!("http://127.0.0.1:{}/info", cfg.admin_port);
            match admin_fetch_get(&url, &cfg.admin_password).await {
                Ok(info) => {
                    match info.get("public_key").and_then(|v| v.as_str()) {
                        Some(pk) => {
                            if let Ok(mut guard) = state.homeserver.server_pubkey.write() {
                                *guard = Some(pk.to_string());
                            }
                            pk.to_string()
                        }
                        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
                            "error": "Could not determine homeserver public key. Is it running?"
                        }))),
                    }
                }
                Err(e) => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
                    "error": format!("Homeserver not reachable: {}", e)
                }))),
            }
        }
    };

    let cfg = state.homeserver.get_config();
    // Try vault first, then fallback to reading server secret file directly
    let secret_hex = match state.vault.export_key(&pubkey) {
        Ok(s) => s,
        Err(_) => {
            // Vault doesn't have the key — try reading from homeserver's secret file
            match state.homeserver.read_server_secret() {
                Some(s) => s,
                None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
                    "error": "Homeserver secret key not found in vault or data directory. Use 'Set Key' in the wizard to assign a vault key.",
                    "pubkey": pubkey
                }))),
            }
        }
    };

    match publish_homeserver_pkarr(&secret_hex, &cfg.icann_domain, &state).await {
        Ok(()) => {
            let state_clone = state.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(4 * 3600)).await;
                let pubkey_now = state_clone.homeserver.server_pubkey();
                if let Some(pk) = pubkey_now {
                    let sec = state_clone.vault.export_key(&pk)
                        .ok()
                        .or_else(|| state_clone.homeserver.read_server_secret());
                    if let Some(secret) = sec {
                        let cfg = state_clone.homeserver.get_config();
                        let _ = publish_homeserver_pkarr(&secret, &cfg.icann_domain, &state_clone).await;
                        tracing::info!("Homeserver PKARR: 4h republish complete");
                    }
                }
            });
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "pubkey": pubkey,
                "message": "PKARR record published. Next auto-publish in 4 hours."
            })))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Publish failed: {}", e)
        }))),
    }
}

/// GET /api/homeserver/users — list all users with storage usage.
pub async fn api_hs_users(
    State(state): State<Arc<DashboardState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let cfg = state.homeserver.get_config();
    let url = format!("http://127.0.0.1:{}/users", cfg.admin_port);
    match admin_fetch_get(&url, &cfg.admin_password).await {
        Ok(resp) => (StatusCode::OK, Json(resp)),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": e }))),
    }
}

/// POST /api/homeserver/users/{pubkey}/quota — set per-user storage quota.
pub async fn api_hs_set_user_quota(
    State(state): State<Arc<DashboardState>>,
    Path(pubkey): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let quota_mb = match body.get("quota_mb").and_then(|v| v.as_u64()) {
        Some(q) => q,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "quota_mb required" }))),
    };
    let cfg = state.homeserver.get_config();
    let url = format!("http://127.0.0.1:{}/users/{}/quota", cfg.admin_port, pubkey);
    let body_json = serde_json::json!({ "quota_mb": quota_mb });
    match admin_fetch_post_json(&url, &cfg.admin_password, &body_json).await {
        Ok(resp) => (StatusCode::OK, Json(resp)),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": e }))),
    }
}

/// POST /api/homeserver/user-action/disable
#[allow(dead_code)]
pub async fn api_hs_disable_user(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let pubkey = body.get("pubkey").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if pubkey.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "pubkey required" })));
    }
    match state.homeserver.disable_user(&pubkey).await {
        Ok(resp) => (StatusCode::OK, Json(resp)),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": e }))),
    }
}

/// POST /api/homeserver/user-action/enable
#[allow(dead_code)]
pub async fn api_hs_enable_user(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let pubkey = body.get("pubkey").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if pubkey.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "pubkey required" })));
    }
    match state.homeserver.enable_user(&pubkey).await {
        Ok(resp) => (StatusCode::OK, Json(resp)),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": e }))),
    }
}

/// ANY /hs/{*path} — transparent proxy to the homeserver's ICANN HTTP endpoint.
pub async fn api_hs_icann_proxy(
    State(state): State<Arc<DashboardState>>,
    request: axum::extract::Request,
) -> Response {
    let cfg = state.homeserver.get_config();
    let icann_port = cfg.drive_icann_port;
    drop(cfg);

    let original_uri = request.uri();
    let path_and_query = original_uri
        .path()
        .strip_prefix("/hs")
        .unwrap_or("/");
    let path_and_query = if let Some(q) = original_uri.query() {
        format!("{}?{}", path_and_query, q)
    } else {
        path_and_query.to_string()
    };
    let path_and_query = if path_and_query.is_empty() { "/".to_string() } else { path_and_query };

    let target_url = format!("http://127.0.0.1:{}{}", icann_port, path_and_query);

    let method = request.method().clone();
    let body_bytes = match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("Failed to read body: {}", e)).into_response();
        }
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("HTTP client error: {}", e)).into_response();
        }
    };

    let req = client
        .request(reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET), &target_url)
        .body(body_bytes);

    match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = resp.bytes().await.unwrap_or_default();

            let mut builder = axum::http::Response::builder()
                .status(status.as_u16());

            for header_name in &["content-type", "content-length", "cache-control", "etag", "last-modified"] {
                if let Some(val) = headers.get(*header_name) {
                    if let Ok(v) = HeaderValue::from_bytes(val.as_bytes()) {
                        builder = builder.header(*header_name, v);
                    }
                }
            }
            builder = builder
                .header("access-control-allow-origin", "*")
                .header("access-control-allow-methods", "GET, POST, PUT, DELETE, OPTIONS")
                .header("access-control-allow-headers", "content-type, authorization");

            builder
                .body(axum::body::Body::from(body))
                .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Response build failed").into_response())
        }
        Err(e) => {
            let msg = if e.is_connect() {
                "Homeserver is not running or not reachable on the configured port.".to_string()
            } else {
                format!("Proxy error: {}", e)
            };
            (StatusCode::BAD_GATEWAY, msg).into_response()
        }
    }
}
