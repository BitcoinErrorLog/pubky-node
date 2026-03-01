//! Web dashboard and REST API server.
//!
//! Provides a real-time monitoring UI, key explorer, user guide,
//! and JSON API endpoints for node status and DHT key resolution.
//! Includes security headers, rate limiting, authentication, key vault, and a health check endpoint.

use crate::keyvault::{KeyVault, VaultKey};
use crate::homeserver::HomeserverManager;
use crate::tunnel::TunnelManager;
use crate::identity::IdentityManager;

use std::path::PathBuf;
use std::sync::{Arc, RwLock, atomic::{AtomicU64, AtomicBool, Ordering}};

use axum::{
    extract::{Path, State, Extension},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Response},
    routing::{get, post, delete},
    Router,
};
use pkarr::{Client, Keypair, PublicKey};
use serde::{Serialize, Deserialize};
use tokio::task::JoinHandle;
use tokio::sync::{Mutex, broadcast};
use tracing::info;

use crate::config::WatchlistConfig;
use crate::upnp::UpnpStatus;

// ─── Auth helpers ───────────────────────────────────────────────

/// Auth configuration stored on disk at `~/.pubky-node/auth.json`
#[derive(Serialize, Deserialize)]
struct AuthConfig {
    password_hash: String,
}

fn auth_config_path(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("auth.json")
}

fn load_auth_config(data_dir: &std::path::Path) -> Option<AuthConfig> {
    let path = auth_config_path(data_dir);
    let data = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&data).ok()
}

fn save_auth_config(data_dir: &std::path::Path, config: &AuthConfig) -> Result<(), String> {
    let path = auth_config_path(data_dir);
    let data = serde_json::to_string_pretty(config).map_err(|e| e.to_string())?;
    std::fs::write(&path, data).map_err(|e| e.to_string())
}

fn hash_password(password: &str) -> Result<String, String> {
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::{Argon2, PasswordVerifier, PasswordHash};
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

/// Extract Basic Auth credentials from request header.
fn extract_basic_auth(req: &axum::extract::Request) -> Option<(String, String)> {
    let header_val = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = header_val.strip_prefix("Basic ")?;
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    let (user, pass) = decoded_str.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// Shared mutable list of watchlist public keys.
pub type SharedWatchlistKeys = Arc<RwLock<Vec<String>>>;

/// State shared with dashboard route handlers.
struct DashboardState {
    client: Option<Client>,
    watchlist_config: WatchlistConfig,
    shared_keys: SharedWatchlistKeys,
    data_dir: PathBuf,
    start_time: std::time::Instant,
    relay_port: u16,
    upnp_status: UpnpStatus,
    dns_status: String,
    dns_socket: String,
    dns_forward: String,
    /// Simple rate limiter: epoch millis of last resolve request.
    resolve_last_request: AtomicU64,
    /// Vanity key generator state.
    vanity: Mutex<VanityState>,
    /// HTTP proxy running flag.
    proxy_running: AtomicBool,
    proxy_port: u16,
    proxy_requests: AtomicU64,
    /// Dashboard password hash (argon2). None = no password set yet.
    /// Shared with auth middleware via Extension.
    auth_hash: Arc<RwLock<Option<String>>>,
    /// Encrypted key vault.
    vault: KeyVault,
    /// Homeserver process manager.
    homeserver: HomeserverManager,
    /// Cloudflare tunnel manager (homeserver).
    tunnel: TunnelManager,
    /// Cloudflare tunnel manager (relay HTTP API).
    relay_tunnel: TunnelManager,
    /// Identity manager (signup/signin tracking).
    identity: IdentityManager,
    /// Broadcast channel for log streaming (homeserver stdout lines).
    log_tx: broadcast::Sender<String>,
}

/// Load watchlist keys from disk, falling back to config keys.
pub fn load_watchlist_keys(data_dir: &std::path::Path, config_keys: &[String]) -> Vec<String> {
    let path = data_dir.join("watchlist_keys.json");
    if path.exists() {
        if let Ok(data) = std::fs::read_to_string(&path) {
            if let Ok(keys) = serde_json::from_str::<Vec<String>>(&data) {
                info!("Loaded {} watchlist key(s) from {}", keys.len(), path.display());
                return keys;
            }
        }
    }
    config_keys.to_vec()
}

fn save_watchlist_keys(data_dir: &std::path::Path, keys: &[String]) {
    let path = data_dir.join("watchlist_keys.json");
    if let Ok(json) = serde_json::to_string_pretty(keys) {
        if let Err(e) = std::fs::write(&path, json) {
            tracing::warn!("Failed to save watchlist keys to {}: {}", path.display(), e);
        }
    }
}

/// Starts the web dashboard HTTP server.
/// Returns the join handle for the server task.
pub fn start_dashboard(
    port: u16,
    bind_addr: [u8; 4],
    relay_port: u16,
    client: Option<Client>,
    watchlist_config: WatchlistConfig,
    shared_keys: SharedWatchlistKeys,
    data_dir: PathBuf,
    upnp_status: UpnpStatus,
    dns_status: String,
    dns_socket: String,
    dns_forward: String,
) -> JoinHandle<()> {
    // Load existing auth config if present
    let loaded_hash = load_auth_config(&data_dir).map(|c| c.password_hash);
    if loaded_hash.is_some() {
        info!("Dashboard auth: password configured");
    } else {
        info!("Dashboard auth: no password set — setup required on first visit");
    }
    // Shared auth hash — same Arc used in both DashboardState and Extension middleware
    let auth_hash: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(loaded_hash));

    let vault = KeyVault::new(&data_dir);
    let homeserver = HomeserverManager::new(&data_dir);
    let tunnel = TunnelManager::new(homeserver.get_config().drive_icann_port);
    let relay_tunnel = TunnelManager::new(relay_port);
    let identity = IdentityManager::new(&data_dir);
    let (log_tx, _) = broadcast::channel::<String>(1000);

    let state = Arc::new(DashboardState {
        client,
        watchlist_config,
        shared_keys,
        data_dir,
        start_time: std::time::Instant::now(),
        relay_port,
        upnp_status,
        dns_status,
        dns_socket,
        dns_forward,
        resolve_last_request: AtomicU64::new(0),
        vanity: Mutex::new(VanityState::default()),
        proxy_running: AtomicBool::new(false),
        proxy_port: 9091,
        proxy_requests: AtomicU64::new(0),
        auth_hash: auth_hash.clone(),
        vault,
        homeserver,
        tunnel,
        relay_tunnel,
        identity,
        log_tx,
    });

    // Wire log broadcast into homeserver so stdout/stderr reach SSE clients
    *state.homeserver.log_tx.write().unwrap() = Some(state.log_tx.clone());

    // Start HTTP proxy for .pkarr domains
    let proxy_state = state.clone();
    tokio::spawn(async move {
        start_http_proxy(proxy_state).await;
    });

    // Shared auth hash ref for Extension middleware (same Arc as in DashboardState)
    let shared_auth = auth_hash;

    // Single router — auth middleware checks path and skips public routes
    let app = Router::new()
        .route("/", get(serve_dashboard))
        .route("/health", get(health_check))
        .route("/api/auth/check", get(api_auth_check))
        .route("/api/auth/setup", post(api_auth_setup))
        .route("/api/auth/login", post(api_auth_login))
        .route("/api/auth/change-password", post(api_auth_change_password))
        .route("/api/settings", get(api_settings))
        .route("/api/vault/create", post(api_vault_create))
        .route("/api/vault/unlock", post(api_vault_unlock))
        .route("/api/vault/lock", post(api_vault_lock))
        .route("/api/vault/keys", get(api_vault_keys))
        .route("/api/vault/add", post(api_vault_add))
        .route("/api/vault/export", post(api_vault_export))
        .route("/api/vault/export-all", get(api_vault_export_all))
        .route("/api/vault/import", post(api_vault_import))
        .route("/api/vault/rename", post(api_vault_rename))
        .route("/api/vault/delete/{pubkey}", delete(api_vault_delete))
        .route("/api/vault/status", get(api_vault_status))
        .route("/api/homeserver/status", get(api_hs_status))
        .route("/api/homeserver/start", post(api_hs_start))
        .route("/api/homeserver/stop", post(api_hs_stop))
        .route("/api/homeserver/info", get(api_hs_info))
        .route("/api/homeserver/signup-token", get(api_hs_signup_token))
        .route("/api/homeserver/setup-check", get(api_hs_setup_check))
        .route("/api/homeserver/config", get(api_hs_config).post(api_hs_config_save))
        .route("/api/homeserver/generate-config", post(api_hs_generate_config))
        .route("/api/homeserver/logs", get(api_hs_logs))
        .route("/api/homeserver/fix", post(api_hs_fix))
        .route("/api/homeserver/proxy-url", get(api_hs_proxy_url))
        .route("/api/homeserver/publish-pkarr", post(api_hs_publish_pkarr))
        .route("/api/homeserver/users", get(api_hs_users))
        .route("/api/homeserver/users/{pubkey}/quota", post(api_hs_set_user_quota))
        // .route("/api/homeserver/user-action/disable", post(api_hs_disable_user))
        // .route("/api/homeserver/user-action/enable", post(api_hs_enable_user))
        .route("/hs", get(api_hs_icann_proxy))
        .route("/hs/", get(api_hs_icann_proxy))
        .route("/hs/{*path}", get(api_hs_icann_proxy).post(api_hs_icann_proxy).put(api_hs_icann_proxy).delete(api_hs_icann_proxy))
        .route("/api/identity/signup", post(api_identity_signup))
        .route("/api/identity/signin", post(api_identity_signin))
        .route("/api/identity/list", get(api_identity_list))
        .route("/api/tunnel/status", get(api_tunnel_status))
        .route("/api/tunnel/start", post(api_tunnel_start))
        .route("/api/tunnel/stop", post(api_tunnel_stop))
        .route("/api/tunnel/check", get(api_tunnel_check))
        .route("/api/relay-tunnel/status", get(api_relay_tunnel_status))
        .route("/api/relay-tunnel/start", post(api_relay_tunnel_start))
        .route("/api/relay-tunnel/stop", post(api_relay_tunnel_stop))
        .route("/api/logs/stream", get(api_logs_stream))
        .route("/api/status", get(api_status))
        .route("/api/resolve/{public_key}", get(api_resolve))
        .route("/api/watchlist", post(api_watchlist_add).get(api_watchlist_list))
        .route("/api/watchlist/{key}", delete(api_watchlist_remove))
        .route("/api/dns/toggle", post(api_dns_toggle))
        .route("/api/dns/set-system", post(api_dns_set_system))
        .route("/api/dns/reset-system", post(api_dns_reset_system))
        .route("/api/node/shutdown", post(api_shutdown))
        .route("/api/node/restart", post(api_restart))
        .route("/api/keys/vanity/start", post(api_vanity_start))
        .route("/api/keys/vanity/status", get(api_vanity_status))
        .route("/api/keys/vanity/stop", post(api_vanity_stop))
        .route("/api/proxy/setup-hosts", post(api_proxy_setup_hosts))
        .route("/api/proxy/reset-hosts", post(api_proxy_reset_hosts))
        .route("/api/proxy/hosts-status", get(api_proxy_hosts_status))
        .route("/api/publish", post(api_publish))
        .route("/dashboard.js", get(serve_js))
        .route("/dashboard.css", get(serve_css))
        .route("/qrcode.min.js", get(serve_qr_js))
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn(auth_check))
        .layer(Extension(shared_auth))
        .with_state(state);

    let addr = std::net::SocketAddr::from((bind_addr, port));

    info!("Dashboard listening on http://{}:{}/", 
        if bind_addr == [127, 0, 0, 1] { "localhost" } else { "0.0.0.0" },
        port
    );

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .expect("Failed to bind dashboard port");
        axum::serve(listener, app)
            .await
            .expect("Dashboard server error");
    })
}

// ─── Auth middleware & handlers ─────────────────────────────────

/// Middleware: check auth on protected routes.
/// Supports Basic Auth (curl) and X-Auth-Password header (dashboard JS).
/// Public paths (root page, auth endpoints, static assets) always allowed.
async fn auth_check(
    request: axum::extract::Request,
    next: Next,
) -> Response {
    // Skip auth for public routes — root page must always load for Tauri webview
    let path = request.uri().path();
    if path == "/"
        || path == "/health"
        || path.starts_with("/api/auth/")
        || path == "/dashboard.js"
        || path == "/dashboard.css"
        || path == "/qrcode.min.js"
        || path.starts_with("/hs") // homeserver ICANN proxy — accessible without auth
    {
        return next.run(request).await;
    }

    // Get auth hash from Extension
    let hash_opt = request.extensions()
        .get::<Arc<RwLock<Option<String>>>>()
        .and_then(|h| h.read().ok())
        .and_then(|guard| guard.clone());

    let hash = match hash_opt {
        Some(h) => h,
        None => {
            // No password set — allow through, dashboard JS will show setup
            return next.run(request).await;
        }
    };

    // Check X-Auth-Password header (dashboard JS sends password with every API call)
    if let Some(pw) = request.headers().get("X-Auth-Password").and_then(|v| v.to_str().ok()) {
        if verify_password(pw, &hash) {
            return next.run(request).await;
        }
    }

    // Check Basic Auth header (curl/API clients)
    if let Some((_user, pass)) = extract_basic_auth(&request) {
        if verify_password(&pass, &hash) {
            return next.run(request).await;
        }
    }

    // 401 — return JSON error
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from("{\"error\":\"Unauthorized\"}"))
        .unwrap()
}

/// GET /api/auth/check — returns whether a password is configured.
/// Public route (no auth needed).
async fn api_auth_check(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    let has_password = state.auth_hash.read().unwrap().is_some();
    Json(serde_json::json!({
        "has_password": has_password
    }))
}

/// POST /api/auth/setup — set the dashboard password (first-run only).
/// Rejects if a password is already set.
async fn api_auth_setup(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Reject if password already set
    if state.auth_hash.read().unwrap().is_some() {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": "Password already configured. Use change-password instead."
        })));
    }

    let password = match body.get("password").and_then(|v| v.as_str()) {
        Some(p) if p.len() >= 4 => p,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Password must be at least 4 characters."
        }))),
    };

    // Hash and save
    let hash = match hash_password(password) {
        Ok(h) => h,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Failed to hash password: {}", e)
        }))),
    };

    let config = AuthConfig { password_hash: hash.clone() };
    if let Err(e) = save_auth_config(&state.data_dir, &config) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Failed to save auth config: {}", e)
        })));
    }

    // Update in-memory state
    *state.auth_hash.write().unwrap() = Some(hash);
    info!("Dashboard password set successfully");

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "message": "Password set. The dashboard now requires authentication."
    })))
}

/// POST /api/auth/login — validate password.
/// JS calls this to verify the password, then stores it in memory for API calls.
async fn api_auth_login(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let password = match body.get("password").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Password required."
        }))),
    };

    let hash = state.auth_hash.read().unwrap();
    match hash.as_ref() {
        Some(h) if verify_password(password, h) => {
            (StatusCode::OK, Json(serde_json::json!({
                "success": true
            })))
        }
        _ => {
            (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
                "error": "Invalid password."
            })))
        }
    }
}

/// POST /api/auth/change-password — change the dashboard password.
/// Requires the current password for verification.
async fn api_auth_change_password(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let current_pw = match body.get("current_password").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Current password required."
        }))),
    };
    let new_pw = match body.get("new_password").and_then(|v| v.as_str()) {
        Some(p) if p.len() >= 4 => p,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "New password must be at least 4 characters."
        }))),
    };

    // Verify current password
    let hash_guard = state.auth_hash.read().unwrap();
    match hash_guard.as_ref() {
        Some(h) if verify_password(current_pw, h) => {},
        _ => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Current password is incorrect."
        }))),
    }
    drop(hash_guard);

    // Hash new password and save
    let new_hash = match hash_password(new_pw) {
        Ok(h) => h,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Failed to hash password: {}", e)
        }))),
    };

    let config = AuthConfig { password_hash: new_hash.clone() };
    if let Err(e) = save_auth_config(&state.data_dir, &config) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Failed to save auth config: {}", e)
        })));
    }

    *state.auth_hash.write().unwrap() = Some(new_hash);
    info!("Dashboard password changed successfully");

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "message": "Password changed successfully."
    })))
}

/// GET /api/settings — return data directory paths and platform info.
async fn api_settings(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    let data_dir = state.data_dir.display().to_string();
    let config_file = state.data_dir.join("config.toml").display().to_string();
    let auth_file = state.data_dir.join("auth.json").display().to_string();

    Json(serde_json::json!({
        "data_dir": data_dir,
        "config_file": config_file,
        "auth_file": auth_file,
        "dashboard_port": 9090,
        "platform": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
    }))
}

// ─── Key Vault API handlers ────────────────────────────────────

/// GET /api/vault/status — check if vault exists and is unlocked.
async fn api_vault_status(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "exists": state.vault.exists(),
        "unlocked": state.vault.is_unlocked(),
    }))
}

/// POST /api/vault/create — create a new vault with password.
async fn api_vault_create(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let password = match body.get("password").and_then(|v| v.as_str()) {
        Some(p) if p.len() >= 4 => p,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Password must be at least 4 characters."
        }))),
    };

    match state.vault.create(password) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({
            "success": true,
            "message": "Vault created and unlocked."
        }))),
        Err(e) => (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": e
        }))),
    }
}

/// POST /api/vault/unlock — unlock vault with password.
async fn api_vault_unlock(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let password = match body.get("password").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Password required."
        }))),
    };

    match state.vault.unlock(password) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({
            "success": true
        }))),
        Err(e) => (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": e
        }))),
    }
}

/// POST /api/vault/lock — lock the vault (clear in-memory keys).
async fn api_vault_lock(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    state.vault.lock();
    Json(serde_json::json!({ "success": true }))
}

/// GET /api/vault/keys — list keys (public info, no secrets).
async fn api_vault_keys(
    State(state): State<Arc<DashboardState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.vault.list_keys() {
        Ok(keys) => (StatusCode::OK, Json(serde_json::json!({ "keys": keys }))),
        Err(e) => (StatusCode::LOCKED, Json(serde_json::json!({ "error": e }))),
    }
}

/// POST /api/vault/add — add a key to the vault.
async fn api_vault_add(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("Unnamed Key");
    let secret_hex = match body.get("secret_hex").and_then(|v| v.as_str()) {
        Some(s) if s.len() == 64 || s.len() == 128 => s,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "secret_hex must be a 64 or 128-character hex string."
        }))),
    };
    let key_type = body.get("key_type").and_then(|v| v.as_str()).unwrap_or("manual");
    let pubkey = match body.get("pubkey").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "pubkey is required."
        }))),
    };

    match state.vault.add_key(name, secret_hex, key_type, pubkey) {
        Ok(info) => (StatusCode::OK, Json(serde_json::json!({
            "success": true,
            "key": info
        }))),
        Err(e) => (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": e
        }))),
    }
}

/// POST /api/vault/export — export a key's secret hex.
async fn api_vault_export(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let pubkey = match body.get("pubkey").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "pubkey is required."
        }))),
    };

    match state.vault.export_key(pubkey) {
        Ok(secret_hex) => (StatusCode::OK, Json(serde_json::json!({
            "secret_hex": secret_hex
        }))),
        Err(e) => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": e
        }))),
    }
}

/// DELETE /api/vault/delete/{pubkey} — remove a key from the vault.
async fn api_vault_delete(
    State(state): State<Arc<DashboardState>>,
    Path(pubkey): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.vault.delete_key(&pubkey) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({
            "success": true
        }))),
        Err(e) => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": e
        }))),
    }
}

/// POST /api/vault/rename — rename a key's label.
async fn api_vault_rename(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let pubkey = match body.get("pubkey").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "pubkey is required."
        }))),
    };
    let name = match body.get("name").and_then(|v| v.as_str()) {
        Some(n) if !n.trim().is_empty() => n.trim(),
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "name is required."
        }))),
    };

    match state.vault.rename_key(pubkey, name) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "success": true }))),
        Err(e) => (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": e }))),
    }
}

/// GET /api/vault/export-all — export all keys with secrets (for backup).
async fn api_vault_export_all(
    State(state): State<Arc<DashboardState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.vault.export_all_keys() {
        Ok(keys) => (StatusCode::OK, Json(serde_json::json!({
            "keys": keys,
            "exported_at": chrono_now_utc(),
            "format": "pubky-vault-backup-v1"
        }))),
        Err(e) => (StatusCode::LOCKED, Json(serde_json::json!({ "error": e }))),
    }
}

/// POST /api/vault/import — import keys from a backup file.
async fn api_vault_import(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let keys_val = match body.get("keys") {
        Some(v) => v,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "keys array is required."
        }))),
    };

    let keys: Vec<VaultKey> = match serde_json::from_value(keys_val.clone()) {
        Ok(k) => k,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("Invalid key data: {}", e)
        }))),
    };

    match state.vault.import_keys(keys) {
        Ok(count) => (StatusCode::OK, Json(serde_json::json!({
            "success": true,
            "imported": count
        }))),
        Err(e) => (StatusCode::CONFLICT, Json(serde_json::json!({ "error": e }))),
    }
}

/// Simple UTC timestamp for export metadata.
fn chrono_now_utc() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}", secs)
}

// ─── Homeserver API Handlers ────────────────────────────────────

/// GET /api/homeserver/status
async fn api_hs_status(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    state.homeserver.check_process();
    let hs_state = state.homeserver.state();
    let cfg = state.homeserver.get_config();
    Json(serde_json::json!({
        "state": hs_state.as_str(),
        "error": if let crate::homeserver::HomeserverState::Error(ref e) = hs_state { Some(e.as_str()) } else { None::<&str> },
        "uptime_secs": state.homeserver.uptime_secs(),
        "pid": state.homeserver.pid(),
        "pubkey": state.homeserver.server_pubkey(),
        "ports": {
            "icann": cfg.drive_icann_port,
            "pubky": cfg.drive_pubky_port,
            "admin": cfg.admin_port,
            "metrics": cfg.metrics_port,
        }
    }))
}

/// POST /api/homeserver/start
async fn api_hs_start(
    State(state): State<Arc<DashboardState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.homeserver.start().await {
        Ok(msg) => {
            // Spawn background task: wait for homeserver to boot, then auto-publish its PKARR record
            let state_clone = state.clone();
            tokio::spawn(async move {
                // Give the homeserver time to initialize
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                // Fetch homeserver info (admin API)
                let cfg = state_clone.homeserver.get_config();
                let info_url = format!("http://127.0.0.1:{}/info", cfg.admin_port);
                let password = cfg.admin_password.clone();
                let icann_domain = cfg.icann_domain.clone();
                drop(cfg);

                // Build admin auth credentials
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
                        tracing::warn!("Homeserver auto-PKARR: /info request failed: {}", e);
                        return;
                    }
                };

                let info: serde_json::Value = match info_resp.json().await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("Homeserver auto-PKARR: failed to parse /info: {}", e);
                        return;
                    }
                };

                // Get the homeserver's public key (z-base-32 Ed25519 pubkey)
                let pubkey_str = match info.get("public_key").and_then(|v| v.as_str()) {
                    Some(pk) => pk.to_string(),
                    None => {
                        tracing::warn!("Homeserver auto-PKARR: no public_key in /info response");
                        return;
                    }
                };

                // Store the public key in the homeserver manager
                *state_clone.homeserver.server_pubkey.write().unwrap() = Some(pubkey_str.clone());
                tracing::info!("Homeserver public key: {}", pubkey_str);

                // Now we need the homeserver's secret key to sign the PKARR record.
                // The homeserver manages its own key — we can only publish if we have it.
                // Check if it's stored in our key vault.
                if let Ok(secret_hex) = state_clone.vault.export_key(&pubkey_str) {
                    match publish_homeserver_pkarr(&secret_hex, &icann_domain, &state_clone).await {
                        Ok(()) => tracing::info!("Homeserver auto-PKARR: published HTTPS record for {}", icann_domain),
                        Err(e) => tracing::warn!("Homeserver auto-PKARR: publish failed: {}", e),
                    }
                } else {
                    tracing::info!(
                        "Homeserver auto-PKARR: key {} not in vault — skipping auto-publish. \
                         Import the homeserver key to enable auto-publish on start.",
                        &pubkey_str[..8.min(pubkey_str.len())]
                    );
                }
            });

            (StatusCode::OK, Json(serde_json::json!({ "success": true, "message": msg })))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))),
    }
}

/// Publish an HTTPS `_pubky` PKARR record pointing to the homeserver's ICANN domain.
async fn publish_homeserver_pkarr(
    secret_hex: &str,
    icann_domain: &str,
    state: &DashboardState,
) -> Result<(), String> {
    use pkarr::Keypair;
    use crate::publisher::{build_signed_packet, RecordConfig};

    // Decode 32-byte secret key from hex
    let secret_bytes = hex::decode(secret_hex)
        .map_err(|e| format!("Invalid secret hex: {}", e))?;
    if secret_bytes.len() != 32 {
        return Err(format!("Secret key must be 32 bytes, got {}", secret_bytes.len()));
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&secret_bytes);
    let keypair = Keypair::from_secret_key(&key_arr);

    // Build HTTPS record: `_pubky` → icann_domain (e.g. "myserver.com" or "localhost")
    let records = vec![RecordConfig {
        record_type: "HTTPS".to_string(),
        name: "_pubky".to_string(),
        value: format!("{}.", icann_domain.trim_end_matches('.')), // must end with dot
        ttl: Some(3600),
    }];

    let signed = build_signed_packet(&keypair, &records)
        .map_err(|e| format!("Failed to build PKARR packet: {}", e))?;

    // Publish using the dashboard's pkarr client
    let client = state.client.as_ref().ok_or("No pkarr client available")?;
    client.publish(&signed, None)
        .await
        .map_err(|e| format!("Publish failed: {}", e))?;

    Ok(())
}

/// POST /api/homeserver/stop
async fn api_hs_stop(
    State(state): State<Arc<DashboardState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.homeserver.stop() {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "success": true }))),
        Err(e) => (StatusCode::OK, Json(serde_json::json!({ "success": true, "message": e }))),
    }
}

/// GET /api/homeserver/info — proxy admin /info
async fn api_hs_info(
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
async fn api_hs_signup_token(
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

/// Helper: GET request to admin API (uses HTTP Basic Auth).
async fn admin_fetch_get(url: &str, password: &str) -> Result<serde_json::Value, String> {
    use base64::Engine;
    let credentials = base64::engine::general_purpose::STANDARD.encode(format!("admin:{}", password));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.get(url)
        .header("Authorization", format!("Basic {}", credentials))
        .send()
        .await
        .map_err(|e| format!("Admin API error: {}", e))?;
    let body = resp.text().await.map_err(|e| e.to_string())?;
    serde_json::from_str(&body).map_err(|_| body)
}

/// GET /api/homeserver/setup-check
async fn api_hs_setup_check(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    let check = state.homeserver.check_setup();
    Json(serde_json::to_value(check).unwrap_or_default())
}

/// GET /api/homeserver/config
async fn api_hs_config(
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
async fn api_hs_config_save(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.homeserver.update_config(body) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "success": true }))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))),
    }
}

/// POST /api/homeserver/generate-config
async fn api_hs_generate_config(
    State(state): State<Arc<DashboardState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.homeserver.generate_config() {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "success": true, "message": "Config generated." }))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))),
    }
}

/// POST /api/homeserver/fix — auto-fix all prerequisites
async fn api_hs_fix(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    let log = state.homeserver.auto_fix().await;
    Json(serde_json::json!({ "log": log }))
}

/// GET /api/homeserver/logs
async fn api_hs_logs(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    let logs = state.homeserver.get_logs(100);
    Json(serde_json::json!({ "lines": logs }))
}

/// GET /api/homeserver/proxy-url — returns the base URL of the homeserver's ICANN endpoint.
async fn api_hs_proxy_url(
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
/// Requires the homeserver key to be in the vault.
async fn api_hs_publish_pkarr(
    State(state): State<Arc<DashboardState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let pubkey_opt = state.homeserver.server_pubkey();

    // Try to get pubkey — if not set, fetch from admin /info first
    let pubkey = match pubkey_opt {
        Some(pk) => pk,
        None => {
            // Try fetching from admin API
            let cfg = state.homeserver.get_config();
            let url = format!("http://127.0.0.1:{}/info", cfg.admin_port);
            match admin_fetch_get(&url, &cfg.admin_password).await {
                Ok(info) => {
                    match info.get("public_key").and_then(|v| v.as_str()) {
                        Some(pk) => {
                            *state.homeserver.server_pubkey.write().unwrap() = Some(pk.to_string());
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
    match state.vault.export_key(&pubkey) {
        Ok(secret_hex) => {
            match publish_homeserver_pkarr(&secret_hex, &cfg.icann_domain, &state).await {
                Ok(()) => {
                    // Schedule 4h republish
                    let state_clone = state.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_secs(4 * 3600)).await;
                        let pubkey_now = state_clone.homeserver.server_pubkey();
                        if let Some(pk) = pubkey_now {
                            if let Ok(sec) = state_clone.vault.export_key(&pk) {
                                let cfg = state_clone.homeserver.get_config();
                                let _ = publish_homeserver_pkarr(&sec, &cfg.icann_domain, &state_clone).await;
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
        Err(_) => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "Homeserver secret key not found in vault. Import it via the Keys tab first.",
            "pubkey": pubkey
        }))),
    }
}

/// GET /api/homeserver/users — list all users with storage usage.
async fn api_hs_users(
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
async fn api_hs_set_user_quota(
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
async fn api_hs_disable_user(
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
async fn api_hs_enable_user(
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

#[allow(dead_code)]
fn extract_path_segment(path: &str, idx: i32) -> String {
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    let i = if idx < 0 {
        (parts.len() as i32 + idx).max(0) as usize
    } else {
        idx as usize
    };
    parts.get(i).unwrap_or(&"").to_string()
}

// ─── Identity API Handlers ─────────────────────────────────────

/// POST /api/identity/signup
async fn api_identity_signup(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let pubkey = match body.get("pubkey").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "pubkey required" }))),
    };
    let homeserver_pubkey = match body.get("homeserver_pubkey").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "homeserver_pubkey required" }))),
    };
    let signup_token = body.get("signup_token").and_then(|v| v.as_str());

    let secret_hex = match state.vault.export_key(pubkey) {
        Ok(s) => s,
        Err(_) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "Key not found in vault. Unlock the vault and ensure this key is stored."
        }))),
    };

    let icann_port = state.homeserver.get_config().drive_icann_port;

    match state.identity.signup(&secret_hex, homeserver_pubkey, signup_token, icann_port).await {
        Ok(info) => (StatusCode::OK, Json(serde_json::to_value(info).unwrap_or_default())),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))),
    }
}

/// POST /api/identity/signin
async fn api_identity_signin(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let pubkey = match body.get("pubkey").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "pubkey required" }))),
    };

    let secret_hex = match state.vault.export_key(pubkey) {
        Ok(s) => s,
        Err(_) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "Key not found in vault."
        }))),
    };

    let icann_port = state.homeserver.get_config().drive_icann_port;

    match state.identity.signin(&secret_hex, icann_port).await {
        Ok(info) => (StatusCode::OK, Json(serde_json::to_value(info).unwrap_or_default())),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))),
    }
}

/// GET /api/identity/list
async fn api_identity_list(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    let ids = state.identity.list();
    Json(serde_json::json!({ "identities": ids }))
}

// ─── Cloudflare Tunnel API ────────────────────────────────────

/// GET /api/tunnel/status
async fn api_tunnel_status(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    state.tunnel.check_process();
    let tunnel_state = state.tunnel.state();
    Json(serde_json::json!({
        "state": tunnel_state.as_str(),
        "error": if let crate::tunnel::TunnelState::Error(ref e) = tunnel_state { Some(e.as_str()) } else { None::<&str> },
        "public_url": state.tunnel.public_url(),
        "binary_available": crate::tunnel::TunnelManager::binary_available(),
    }))
}

/// POST /api/tunnel/start
async fn api_tunnel_start(
    State(state): State<Arc<DashboardState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.tunnel.start() {
        Ok(()) => {
            // After the tunnel URL is resolved, auto-update icann_domain and re-publish PKARR
            let state_clone = state.clone();
            tokio::spawn(async move {
                // Poll until URL appears (up to 30s)
                for _ in 0..30 {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    if let Some(url) = state_clone.tunnel.public_url() {
                        // Strip https:// for the domain
                        let domain = url.trim_start_matches("https://").trim_start_matches("http://").to_string();
                        tracing::info!("Tunnel active: {} — updating homeserver config", domain);

                        // Update icann_domain in homeserver config
                        let update = serde_json::json!({ "icann_domain": domain });
                        if let Err(e) = state_clone.homeserver.update_config(update) {
                            tracing::warn!("Failed to update icann_domain with tunnel URL: {}", e);
                        }

                        // Re-publish PKARR with new domain
                        if let Some(pk) = state_clone.homeserver.server_pubkey() {
                            if let Ok(secret) = state_clone.vault.export_key(&pk) {
                                let _ = publish_homeserver_pkarr(&secret, &domain, &state_clone).await;
                                tracing::info!("PKARR republished with tunnel domain: {}", domain);
                            }
                        }
                        break;
                    }
                }
            });
            (StatusCode::OK, Json(serde_json::json!({ "success": true, "message": "Tunnel starting..." })))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))),
    }
}

/// POST /api/tunnel/stop
async fn api_tunnel_stop(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    state.tunnel.stop();
    Json(serde_json::json!({ "success": true }))
}

/// GET /api/tunnel/check — is cloudflared binary available?
async fn api_tunnel_check(
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "available": crate::tunnel::TunnelManager::binary_available(),
        "download_url": "https://github.com/cloudflare/cloudflared/releases/latest"
    }))
}

// ─── Relay Tunnel API Handlers ────────────────────────────────

/// GET /api/relay-tunnel/status
async fn api_relay_tunnel_status(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    state.relay_tunnel.check_process();
    let tunnel_state = state.relay_tunnel.state();
    Json(serde_json::json!({
        "state": tunnel_state.as_str(),
        "error": if let crate::tunnel::TunnelState::Error(ref e) = tunnel_state { Some(e.as_str()) } else { None::<&str> },
        "public_url": state.relay_tunnel.public_url(),
        "relay_port": state.relay_port,
    }))
}

/// POST /api/relay-tunnel/start
async fn api_relay_tunnel_start(
    State(state): State<Arc<DashboardState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.relay_tunnel.start() {
        Ok(()) => {
            (StatusCode::OK, Json(serde_json::json!({ "success": true, "message": "Relay tunnel starting..." })))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))),
    }
}

/// POST /api/relay-tunnel/stop
async fn api_relay_tunnel_stop(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    state.relay_tunnel.stop();
    Json(serde_json::json!({ "success": true }))
}

// ─── SSE Log Stream ───────────────────────────────────────────

/// GET /api/logs/stream — Server-Sent Events stream of homeserver stdout.
async fn api_logs_stream(
    State(state): State<Arc<DashboardState>>,
) -> impl IntoResponse {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use tokio_stream::wrappers::BroadcastStream;
    use tokio_stream::StreamExt as _;

    let rx = state.log_tx.subscribe();
    let live_stream = BroadcastStream::new(rx)
        .filter_map(|msg| {
            msg.ok().map(|line| {
                Ok::<Event, std::convert::Infallible>(Event::default().data(line))
            })
        });

    // Seed with last 50 buffered lines as historic events
    let historic: Vec<Result<Event, std::convert::Infallible>> = state.homeserver.get_logs(50)
        .into_iter()
        .map(|line| Ok(Event::default().data(line)))
        .collect();
    let historic_stream = tokio_stream::iter(historic);
    let combined = historic_stream.chain(live_stream);

    Sse::new(combined).keep_alive(KeepAlive::default())
}

/// Helper: POST JSON body to admin API.
async fn admin_fetch_post_json(url: &str, password: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    use base64::Engine;
    let credentials = base64::engine::general_purpose::STANDARD.encode(format!("admin:{}", password));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.post(url)
        .header("Authorization", format!("Basic {}", credentials))
        .json(body)
        .send()
        .await
        .map_err(|e| format!("Admin API error: {}", e))?;
    let body = resp.text().await.map_err(|e| e.to_string())?;
    serde_json::from_str(&body).map_err(|_| body)
}

/// ANY /hs/{*path} — transparent proxy to the homeserver's ICANN HTTP endpoint.
/// 
/// Use this to access homeserver endpoints from the dashboard without CORS issues.
/// Example: GET /hs/pub/pubky.app/profile.json  →  GET http://127.0.0.1:6286/pub/pubky.app/profile.json
async fn api_hs_icann_proxy(
    State(state): State<Arc<DashboardState>>,
    request: axum::extract::Request,
) -> Response {
    use axum::http::StatusCode;

    let cfg = state.homeserver.get_config();
    let icann_port = cfg.drive_icann_port;
    drop(cfg);

    // Extract path/query from the incoming request, stripping the /hs prefix
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

            // Forward select response headers
            for header_name in &["content-type", "content-length", "cache-control", "etag", "last-modified"] {
                if let Some(val) = headers.get(*header_name) {
                    if let Ok(v) = axum::http::HeaderValue::from_bytes(val.as_bytes()) {
                        builder = builder.header(*header_name, v);
                    }
                }
            }
            // Allow CORS for browser access
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

/// Middleware that adds security headers to all responses.
async fn security_headers(
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        "X-Frame-Options",
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static(
            "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self'; connect-src 'self'"
        ),
    );
    headers.insert(
        "Referrer-Policy",
        HeaderValue::from_static("no-referrer"),
    );
    response
}

/// JSON API endpoint: returns node status.
async fn api_status(
    State(state): State<Arc<DashboardState>>,
) -> Json<NodeStatus> {
    let uptime_secs = state.start_time.elapsed().as_secs();

    let dht_info = state.client.as_ref().and_then(|c| {
        c.dht().map(|dht| {
            let info = dht.info();
            let (size_estimate, _accuracy) = info.dht_size_estimate();
            DhtStatus {
                local_addr: info.local_addr().to_string(),
                id: format!("{}", info.id()),
                firewalled: info.firewalled(),
                server_mode: info.server_mode(),
                dht_size_estimate: size_estimate,
            }
        })
    });

    let key_count = state.shared_keys.read().unwrap().len();
    let watchlist = WatchlistStatus {
        enabled: key_count > 0,
        key_count,
        republish_interval_secs: state.watchlist_config.republish_interval_secs,
    };

    let upnp = UpnpApiStatus {
        status: state.upnp_status.label().to_string(),
        external_ip: match &state.upnp_status {
            UpnpStatus::Mapped { external_ip, .. } => Some(external_ip.clone()),
            _ => None,
        },
        port: match &state.upnp_status {
            UpnpStatus::Mapped { port, .. } => Some(*port),
            _ => None,
        },
    };

    // Check if system DNS is already pointing at our resolver
    let dns_ip = state.dns_socket.split(':').next().unwrap_or("127.0.0.1").to_string();
    let system_dns_active = if state.dns_status == "Running" {
        check_system_dns(&dns_ip).await
    } else {
        false
    };

    let dns = DnsApiStatus {
        status: state.dns_status.clone(),
        socket: state.dns_socket.clone(),
        forward: state.dns_forward.clone(),
        system_dns_active,
    };

    let proxy = ProxyApiStatus {
        status: if state.proxy_running.load(Ordering::Relaxed) { "Running".to_string() } else { "Stopped".to_string() },
        port: state.proxy_port,
        requests_served: state.proxy_requests.load(Ordering::Relaxed),
    };

    Json(NodeStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs,
        relay_port: state.relay_port,
        dht: dht_info,
        watchlist,
        upnp,
        dns,
        proxy,
    })
}

/// Health check endpoint for Docker/Umbrel.
async fn health_check() -> &'static str {
    "ok"
}

async fn serve_dashboard() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}

async fn serve_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/javascript")],
        include_str!("dashboard.js"),
    )
}

async fn serve_css() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/css")],
        include_str!("dashboard.css"),
    )
}

async fn serve_qr_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/javascript")],
        include_str!("qrcode.min.js"),
    )
}

/// Resolve a pkarr public key and return its DNS records.
async fn api_resolve(
    State(state): State<Arc<DashboardState>>,
    Path(public_key_str): Path<String>,
) -> Result<Json<ResolveResponse>, StatusCode> {
    // Simple rate limit: minimum 2 seconds between resolve requests
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let last = state.resolve_last_request.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last) < 2000 {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    state.resolve_last_request.store(now_ms, Ordering::Relaxed);

    let client = state.client.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let public_key = pkarr::PublicKey::try_from(public_key_str.as_str())
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let signed_packet = client
        .resolve(&public_key)
        .await
        .ok_or(StatusCode::NOT_FOUND)?;

    let elapsed_secs = signed_packet.elapsed();
    let compressed_size = signed_packet.encoded_packet().len();
    let timestamp_us = signed_packet.timestamp().as_u64();

    // Extract DNS records using the public all_resource_records() iterator
    let origin = public_key.to_z32();
    let mut records = Vec::new();

    for rr in signed_packet.all_resource_records() {
        let full_name = rr.name.to_string();
        // Strip the origin (public key) suffix from the name
        let name = if full_name == origin {
            "@".to_string()
        } else if let Some(prefix) = full_name.strip_suffix(&format!(".{}", origin)) {
            prefix.to_string()
        } else {
            full_name.clone()
        };

        let (record_type, value) = format_rdata(&rr.rdata);

        records.push(DnsRecord {
            name,
            record_type,
            value,
            ttl: rr.ttl,
        });
    }

    Ok(Json(ResolveResponse {
        public_key: public_key_str,
        records,
        last_updated: timestamp_us / 1_000_000,
        compressed_size,
        elapsed_secs,
    }))
}

/// Format an RData value into (type_string, value_string).
fn format_rdata(rdata: &pkarr::dns::rdata::RData) -> (String, String) {
    use pkarr::dns::rdata::RData;
    use std::net::{Ipv4Addr, Ipv6Addr};

    match rdata {
        RData::A(a) => (
            "A".into(),
            Ipv4Addr::from(a.address).to_string(),
        ),
        RData::AAAA(aaaa) => (
            "AAAA".into(),
            Ipv6Addr::from(aaaa.address).to_string(),
        ),
        RData::CNAME(cname) => (
            "CNAME".into(),
            cname.0.to_string(),
        ),
        RData::TXT(txt) => {
            let s: String = txt.clone().try_into().unwrap_or_default();
            ("TXT".into(), s)
        }
        RData::NS(ns) => (
            "NS".into(),
            ns.0.to_string(),
        ),
        RData::HTTPS(https) => (
            "HTTPS".into(),
            format!("priority={} target={}", https.priority, https.target),
        ),
        RData::SVCB(svcb) => (
            "SVCB".into(),
            format!("priority={} target={}", svcb.priority, svcb.target),
        ),
        other => (
            format!("{:?}", other).split('(').next().unwrap_or("UNKNOWN").to_string(),
            format!("{:?}", other),
        ),
    }
}

// === Watchlist API ===

#[derive(Deserialize)]
struct WatchlistAddRequest {
    key: String,
}

#[derive(Serialize)]
struct WatchlistResponse {
    keys: Vec<String>,
    count: usize,
}

/// List all watchlist keys.
async fn api_watchlist_list(
    State(state): State<Arc<DashboardState>>,
) -> Json<WatchlistResponse> {
    let keys = state.shared_keys.read().unwrap().clone();
    let count = keys.len();
    Json(WatchlistResponse { keys, count })
}

/// Add a public key to the watchlist.
async fn api_watchlist_add(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<WatchlistAddRequest>,
) -> Result<Json<WatchlistResponse>, (StatusCode, String)> {
    let raw = body.key.trim();

    // Strip common URI prefixes (pubky://, pubky:, pk:, bare "pubky" prefix)
    let key_str = if let Some(k) = raw.strip_prefix("pubky://") {
        k.split('/').next().unwrap_or(k)
    } else if let Some(k) = raw.strip_prefix("pubky:") {
        k
    } else if let Some(k) = raw.strip_prefix("pk:") {
        k
    } else if raw.starts_with("pubky") && raw.len() > 52 {
        &raw[5..]
    } else {
        raw
    };

    // Validate it's a valid pkarr public key
    let public_key: PublicKey = key_str.parse()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid public key: {}", e)))?;

    let normalized = public_key.to_string();
    let mut keys = state.shared_keys.write().unwrap();

    // Don't add duplicates
    if !keys.contains(&normalized) {
        keys.push(normalized);
        info!("Watchlist: added key, now watching {} key(s)", keys.len());
    }

    let count = keys.len();
    let keys_clone = keys.clone();
    drop(keys); // release lock before disk I/O
    save_watchlist_keys(&state.data_dir, &keys_clone);
    Ok(Json(WatchlistResponse { keys: keys_clone, count }))
}

/// Remove a public key from the watchlist.
async fn api_watchlist_remove(
    State(state): State<Arc<DashboardState>>,
    Path(key): Path<String>,
) -> Json<WatchlistResponse> {
    let mut keys = state.shared_keys.write().unwrap();
    keys.retain(|k| k != &key);
    info!("Watchlist: removed key, now watching {} key(s)", keys.len());
    let count = keys.len();
    let keys_clone = keys.clone();
    drop(keys); // release lock before disk I/O
    save_watchlist_keys(&state.data_dir, &keys_clone);
    Json(WatchlistResponse { keys: keys_clone, count })
}

/// Toggle PKDNS enabled/disabled in config.toml.
async fn api_dns_toggle(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<DnsToggleRequest>,
) -> Result<Json<DnsToggleResponse>, (StatusCode, String)> {
    let config_path = state.data_dir.join("config.toml");

    // Read existing config or start with empty table
    let mut doc: toml::Value = if config_path.exists() {
        let contents = std::fs::read_to_string(&config_path)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to read config: {}", e)))?;
        toml::from_str(&contents).unwrap_or(toml::Value::Table(Default::default()))
    } else {
        toml::Value::Table(Default::default())
    };

    // Ensure [dns] table exists and set enabled
    let table = doc.as_table_mut().unwrap();
    let dns_table = table.entry("dns")
        .or_insert_with(|| toml::Value::Table(Default::default()));
    if let Some(t) = dns_table.as_table_mut() {
        t.insert("enabled".to_string(), toml::Value::Boolean(body.enabled));
    }

    let output = toml::to_string_pretty(&doc)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to serialize config: {}", e)))?;
    std::fs::write(&config_path, &output)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to write config: {}", e)))?;

    info!("PKDNS toggled to enabled={} in {:?}", body.enabled, config_path);

    Ok(Json(DnsToggleResponse {
        enabled: body.enabled,
        restart_required: true,
    }))
}

/// Set macOS system DNS to point to the local PKDNS resolver.
async fn api_dns_set_system(
    State(state): State<Arc<DashboardState>>,
) -> Result<Json<DnsSystemResponse>, (StatusCode, String)> {
    let ip = state.dns_socket.split(':').next().unwrap_or("127.0.0.1");
    run_networksetup_dns(ip).await
}

/// Reset macOS system DNS to DHCP default.
async fn api_dns_reset_system() -> Result<Json<DnsSystemResponse>, (StatusCode, String)> {
    run_networksetup_dns("empty").await
}

/// Run networksetup to set DNS on the primary network service.
async fn run_networksetup_dns(dns_value: &str) -> Result<Json<DnsSystemResponse>, (StatusCode, String)> {
    // Find the primary network service (Wi-Fi, Ethernet, etc.)
    let list_output = tokio::process::Command::new("networksetup")
        .args(["-listallnetworkservices"])
        .output()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list network services: {}", e)))?;

    let services = String::from_utf8_lossy(&list_output.stdout);
    let service = services.lines()
        .filter(|l| !l.starts_with('*') && !l.starts_with("An asterisk"))
        .find(|l| l.contains("Wi-Fi") || l.contains("Ethernet"))
        .unwrap_or("Wi-Fi")
        .to_string();

    // Use osascript for admin privileges (shows password dialog)
    let script = format!(
        "do shell script \"networksetup -setdnsservers '{}' {}\" with administrator privileges",
        service, dns_value
    );

    let output = tokio::process::Command::new("osascript")
        .args(["-e", &script])
        .output()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to set DNS: {}", e)))?;

    if output.status.success() {
        info!("System DNS set to '{}' on service '{}'", dns_value, service);
        Ok(Json(DnsSystemResponse {
            success: true,
            service: service.clone(),
            message: if dns_value == "empty" {
                format!("DNS reset to DHCP default on {}", service)
            } else {
                format!("DNS set to {} on {}", dns_value, service)
            },
        }))
    } else {
        let err = String::from_utf8_lossy(&output.stderr);
        Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to set DNS: {}", err)))
    }
}

/// Shutdown the node process.
async fn api_shutdown() -> &'static str {
    info!("Shutdown requested via dashboard");
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        std::process::exit(0);
    });
    "Shutting down..."
}

/// Restart the node process (exits with code 42 for Tauri to respawn).
async fn api_restart() -> &'static str {
    info!("Restart requested via dashboard");
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        std::process::exit(42);
    });
    "Restarting..."
}

// === Data structures ===

#[derive(Serialize)]
struct NodeStatus {
    version: String,
    uptime_secs: u64,
    relay_port: u16,
    dht: Option<DhtStatus>,
    watchlist: WatchlistStatus,
    upnp: UpnpApiStatus,
    dns: DnsApiStatus,
    proxy: ProxyApiStatus,
}

#[derive(Serialize)]
struct DhtStatus {
    local_addr: String,
    id: String,
    firewalled: bool,
    server_mode: bool,
    dht_size_estimate: usize,
}

#[derive(Serialize)]
struct WatchlistStatus {
    enabled: bool,
    key_count: usize,
    republish_interval_secs: u64,
}

#[derive(Serialize)]
struct UpnpApiStatus {
    status: String,
    external_ip: Option<String>,
    port: Option<u16>,
}

#[derive(Serialize)]
struct DnsApiStatus {
    status: String,
    socket: String,
    forward: String,
    system_dns_active: bool,
}

/// Check if macOS system DNS is set to the given IP.
async fn check_system_dns(dns_ip: &str) -> bool {
    let output = tokio::process::Command::new("networksetup")
        .args(["-listallnetworkservices"])
        .output()
        .await;
    let services = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return false,
    };
    for service_name in services.lines()
        .filter(|l| !l.starts_with('*') && !l.starts_with("An asterisk"))
        .filter(|l| l.contains("Wi-Fi") || l.contains("Ethernet"))
    {
        let dns_output = tokio::process::Command::new("networksetup")
            .args(["-getdnsservers", service_name])
            .output()
            .await;
        if let Ok(o) = dns_output {
            let text = String::from_utf8_lossy(&o.stdout);
            for line in text.lines() {
                if line.trim() == dns_ip {
                    return true;
                }
            }
        }
    }
    false
}

#[derive(Deserialize)]
struct DnsToggleRequest {
    enabled: bool,
}

#[derive(Serialize)]
struct DnsToggleResponse {
    enabled: bool,
    restart_required: bool,
}

#[derive(Serialize)]
struct DnsSystemResponse {
    success: bool,
    service: String,
    message: String,
}

#[derive(Serialize)]
struct ResolveResponse {
    public_key: String,
    records: Vec<DnsRecord>,
    last_updated: u64,
    compressed_size: usize,
    elapsed_secs: u32,
}

#[derive(Serialize)]
struct DnsRecord {
    name: String,
    record_type: String,
    value: String,
    ttl: u32,
}

#[derive(Serialize)]
struct ProxyApiStatus {
    status: String,
    port: u16,
    requests_served: u64,
}

// === Vanity Key Generator ===

#[derive(Default)]
struct VanityState {
    running: bool,
    target: String,
    suffix: bool,
    keys_checked: u64,
    started_at: Option<std::time::Instant>,
    result_pubkey: Option<String>,
    result_seed: Option<String>,
    cancel: Option<Arc<AtomicBool>>,
}

#[derive(Deserialize)]
struct VanityStartRequest {
    prefix: String,
    #[serde(default)]
    suffix: bool,
}

#[derive(Serialize)]
struct VanityStatusResponse {
    running: bool,
    target: String,
    suffix: bool,
    keys_checked: u64,
    elapsed_secs: f64,
    estimated_secs: f64,
    rate: f64,
    result: Option<VanityResult>,
}

#[derive(Serialize)]
struct VanityResult {
    pubkey: String,
    seed: String,
}

/// Start vanity key grinding.
async fn api_vanity_start(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<VanityStartRequest>,
) -> Result<Json<VanityStatusResponse>, (StatusCode, String)> {
    let target = body.prefix.to_lowercase();

    // Validate z-base32 characters
    const Z32_CHARS: &str = "ybndrfg8ejkmcpqxot1uwisza345h769";
    for c in target.chars() {
        if !Z32_CHARS.contains(c) {
            return Err((StatusCode::BAD_REQUEST, format!("Invalid z-base32 character: '{}'. Valid: {}", c, Z32_CHARS)));
        }
    }
    if target.is_empty() || target.len() > 10 {
        return Err((StatusCode::BAD_REQUEST, "Prefix must be 1-10 characters".to_string()));
    }

    let mut vanity = state.vanity.lock().await;
    // Cancel any existing run
    if let Some(cancel) = vanity.cancel.take() {
        cancel.store(true, Ordering::Relaxed);
    }

    let cancel = Arc::new(AtomicBool::new(false));
    vanity.running = true;
    vanity.target = target.clone();
    vanity.suffix = body.suffix;
    vanity.keys_checked = 0;
    vanity.started_at = Some(std::time::Instant::now());
    vanity.result_pubkey = None;
    vanity.result_seed = None;
    vanity.cancel = Some(cancel.clone());

    let suffix = body.suffix;
    let vanity_mutex = state.clone();
    let num_threads = num_cpus::get().max(1);

    // Spawn grinding threads
    for _ in 0..num_threads {
        let target = target.clone();
        let cancel = cancel.clone();
        let state = vanity_mutex.clone();
        tokio::task::spawn_blocking(move || {
            let mut local_count: u64 = 0;
            while !cancel.load(Ordering::Relaxed) {
                let kp = Keypair::random();
                let z32 = kp.public_key().to_z32();
                local_count += 1;

                let matched = if suffix {
                    z32.ends_with(&target)
                } else {
                    z32.starts_with(&target)
                };

                if matched {
                    // Found a match!
                    let seed_bytes = kp.secret_key();
                    let seed_z32 = z32_encode(&seed_bytes[..32]);
                    if let Ok(mut v) = state.vanity.try_lock() {
                        v.result_pubkey = Some(z32);
                        v.result_seed = Some(seed_z32);
                        v.keys_checked += local_count;
                        v.running = false;
                    }
                    cancel.store(true, Ordering::Relaxed);
                    return;
                }

                // Update count periodically
                if local_count % 10_000 == 0 {
                    if let Ok(mut v) = state.vanity.try_lock() {
                        v.keys_checked += local_count;
                        local_count = 0;
                    }
                }
            }
            // Final count update
            if let Ok(mut v) = state.vanity.try_lock() {
                v.keys_checked += local_count;
            }
        });
    }

    let elapsed = 0.0f64;
    let target_len = target.len();
    let estimated = 32.0f64.powi(target_len as i32);

    Ok(Json(VanityStatusResponse {
        running: true,
        target,
        suffix: body.suffix,
        keys_checked: 0,
        elapsed_secs: elapsed,
        estimated_secs: estimated, // Will be refined when rate is known
        rate: 0.0,
        result: None,
    }))
}

/// Get vanity grinder status.
async fn api_vanity_status(
    State(state): State<Arc<DashboardState>>,
) -> Json<VanityStatusResponse> {
    let vanity = state.vanity.lock().await;
    let elapsed = vanity.started_at
        .map(|s| s.elapsed().as_secs_f64())
        .unwrap_or(0.0);
    let rate = if elapsed > 0.0 { vanity.keys_checked as f64 / elapsed } else { 0.0 };
    let target_len = vanity.target.len();
    let total_expected = 32.0f64.powi(target_len as i32);
    let estimated = if rate > 0.0 { total_expected / rate } else { total_expected };

    let result = if let (Some(pk), Some(seed)) = (&vanity.result_pubkey, &vanity.result_seed) {
        Some(VanityResult {
            pubkey: pk.clone(),
            seed: seed.clone(),
        })
    } else {
        None
    };

    Json(VanityStatusResponse {
        running: vanity.running,
        target: vanity.target.clone(),
        suffix: vanity.suffix,
        keys_checked: vanity.keys_checked,
        elapsed_secs: elapsed,
        estimated_secs: estimated,
        rate,
        result,
    })
}

/// Stop vanity grinder.
async fn api_vanity_stop(
    State(state): State<Arc<DashboardState>>,
) -> Json<VanityStatusResponse> {
    {
        let mut vanity = state.vanity.lock().await;
        if let Some(cancel) = vanity.cancel.take() {
            cancel.store(true, Ordering::Relaxed);
        }
        vanity.running = false;
    }
    api_vanity_status(State(state)).await
}

/// z-base32 encode bytes.
pub fn z32_encode(data: &[u8]) -> String {
    const Z32_ALPHABET: &[u8] = b"ybndrfg8ejkmcpqxot1uwisza345h769";
    let mut result = String::new();
    let mut bits: u64 = 0;
    let mut num_bits: u32 = 0;
    for &byte in data {
        bits = (bits << 8) | byte as u64;
        num_bits += 8;
        while num_bits >= 5 {
            num_bits -= 5;
            let index = ((bits >> num_bits) & 0x1F) as usize;
            result.push(Z32_ALPHABET[index] as char);
        }
    }
    if num_bits > 0 {
        let index = ((bits << (5 - num_bits)) & 0x1F) as usize;
        result.push(Z32_ALPHABET[index] as char);
    }
    result
}

// === Proxy /etc/hosts Management ===

/// Publish signed DNS records to the DHT.
async fn api_publish(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let secret_hex = body.get("secret_key").and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "Missing secret_key".to_string()))?;
    let records_arr = body.get("records").and_then(|v| v.as_array())
        .ok_or((StatusCode::BAD_REQUEST, "Missing records array".to_string()))?;
    let add_to_watchlist = body.get("add_to_watchlist").and_then(|v| v.as_bool()).unwrap_or(true);

    // Parse secret key
    let secret_bytes = hex::decode(secret_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid hex key: {}", e)))?;
    if secret_bytes.len() != 32 {
        return Err((StatusCode::BAD_REQUEST, format!("Secret key must be 32 bytes (64 hex chars), got {}", secret_bytes.len())));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&secret_bytes);
    let keypair = pkarr::Keypair::from_secret_key(&key_bytes);
    let public_key_str = keypair.public_key().to_string();

    // Parse records
    let mut record_configs = Vec::new();
    for rec in records_arr {
        let record_type = rec.get("type").and_then(|v| v.as_str()).unwrap_or("").to_uppercase();
        let name = rec.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let value = rec.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let ttl = rec.get("ttl").and_then(|v| v.as_u64()).map(|t| t as u32);

        if record_type.is_empty() || name.is_empty() || value.is_empty() {
            return Err((StatusCode::BAD_REQUEST, "Each record needs type, name, and value".to_string()));
        }

        // For HTTPS records, build an HTTPS SVCB-style record
        if record_type == "HTTPS" {
            // HTTPS records use the publisher's HTTPS builder
            record_configs.push(crate::config::RecordConfig {
                record_type: "HTTPS".to_string(),
                name,
                value,
                ttl,
            });
        } else {
            record_configs.push(crate::config::RecordConfig {
                record_type,
                name,
                value,
                ttl,
            });
        }
    }

    if record_configs.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "At least one record is required".to_string()));
    }

    // Build and sign the packet
    let signed_packet = crate::publisher::build_signed_packet(&keypair, &record_configs)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to build packet: {}", e)))?;

    // Publish to DHT
    let client = pkarr::Client::builder().build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create client: {}", e)))?;
    client.publish(&signed_packet, None).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Publish failed: {}", e)))?;

    // Optionally add to watchlist
    if add_to_watchlist {
        let mut keys = state.shared_keys.write().unwrap();
        if !keys.contains(&public_key_str) {
            keys.push(public_key_str.clone());
        }
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "public_key": public_key_str,
        "records_published": record_configs.len(),
        "added_to_watchlist": add_to_watchlist,
        "message": format!("Published {} record(s) for {}", record_configs.len(), &public_key_str[..12])
    })))
}

const HOSTS_MARKER_BEGIN: &str = "# BEGIN PUBKY-NODE PROXY";
const HOSTS_MARKER_END: &str = "# END PUBKY-NODE PROXY";

/// Configure /etc/hosts with entries for all watchlist keys pointing to 127.0.0.1.
async fn api_proxy_setup_hosts(
    State(state): State<Arc<DashboardState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let keys = state.shared_keys.read().unwrap().clone();
    if keys.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "No keys in watchlist. Add keys to the watchlist first.".to_string()));
    }

    // Build hosts entries
    let mut entries = Vec::new();
    entries.push(HOSTS_MARKER_BEGIN.to_string());
    for key in &keys {
        for tld in &["pkarr", "key", "pubky"] {
            entries.push(format!("127.0.0.1 {}.{}", key, tld));
        }
    }
    entries.push(HOSTS_MARKER_END.to_string());
    let block = entries.join("\n");

    // Read existing hosts, remove old block, append new
    let hosts = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
    let cleaned = remove_hosts_block(&hosts);
    let new_hosts = format!("{}\n\n{}\n", cleaned.trim_end(), block);

    // Single admin prompt: write hosts + flush DNS + enable pfctl port forwarding
    let pf_rule = format!("rdr pass on lo0 inet proto tcp from any to 127.0.0.1 port 80 -> 127.0.0.1 port {}", state.proxy_port);
    let shell_cmds = format!(
        "echo '{}' | tee /etc/hosts > /dev/null && dscacheutil -flushcache && echo '{}' | pfctl -ef - 2>/dev/null; true",
        new_hosts.replace('\\', "\\\\").replace('\'', "'\\''"),
        pf_rule
    );
    let script = format!(
        "do shell script \"{}\" with administrator privileges",
        shell_cmds.replace('"', "\\\"")
    );

    let output = tokio::process::Command::new("osascript")
        .args(["-e", &script])
        .output()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to run osascript: {}", e)))?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to configure proxy: {}", err)));
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "entries": keys.len() * 3,
        "message": format!("Added {} host entries for {} keys (port 80 → {} forwarding enabled)", keys.len() * 3, keys.len(), state.proxy_port)
    })))
}

/// Remove pubky-node proxy entries from /etc/hosts.
async fn api_proxy_reset_hosts() -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let hosts = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
    let cleaned = remove_hosts_block(&hosts);

    // Single admin prompt: restore hosts + flush DNS + disable pfctl
    let shell_cmds = format!(
        "echo '{}' | tee /etc/hosts > /dev/null && dscacheutil -flushcache && pfctl -d 2>/dev/null; true",
        cleaned.trim_end().replace('\\', "\\\\").replace('\'', "'\\''")
    );
    let script = format!(
        "do shell script \"{}\" with administrator privileges",
        shell_cmds.replace('"', "\\\"")
    );

    let output = tokio::process::Command::new("osascript")
        .args(["-e", &script])
        .output()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to run osascript: {}", e)))?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to reset proxy: {}", err)));
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Removed proxy entries from /etc/hosts and disabled port forwarding"
    })))
}

fn remove_hosts_block(hosts: &str) -> String {
    let mut result = String::new();
    let mut in_block = false;
    for line in hosts.lines() {
        if line.trim() == HOSTS_MARKER_BEGIN {
            in_block = true;
            continue;
        }
        if line.trim() == HOSTS_MARKER_END {
            in_block = false;
            continue;
        }
        if !in_block {
            result.push_str(line);
            result.push('\n');
        }
    }
    result
}

/// Check if /etc/hosts has proxy entries.
async fn api_proxy_hosts_status() -> Json<serde_json::Value> {
    let configured = std::fs::read_to_string("/etc/hosts")
        .map(|h| h.contains(HOSTS_MARKER_BEGIN))
        .unwrap_or(false);
    Json(serde_json::json!({ "configured": configured }))
}

// === HTTP Proxy for .pkarr domains ===

async fn start_http_proxy(state: Arc<DashboardState>) {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], state.proxy_port));
    info!("HTTP Proxy listening on http://127.0.0.1:{}/", state.proxy_port);

    let proxy_app = Router::new()
        .route("/pubky-img", get(proxy_image_handler))
        .fallback(get(proxy_handler))
        .with_state(state.clone());

    state.proxy_running.store(true, Ordering::Relaxed);

    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => {
            if let Err(e) = axum::serve(listener, proxy_app).await {
                tracing::error!("HTTP proxy error: {}", e);
                state.proxy_running.store(false, Ordering::Relaxed);
            }
        }
        Err(e) => {
            tracing::error!("Failed to bind HTTP proxy on {}: {}", addr, e);
            state.proxy_running.store(false, Ordering::Relaxed);
        }
    }
}

/// Proxy image requests to the homeserver with the pubky-host header.
async fn proxy_image_handler(
    State(state): State<Arc<DashboardState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let pubkey_str = match params.get("key") {
        Some(k) => k.clone(),
        None => return (StatusCode::BAD_REQUEST, "Missing key param").into_response(),
    };
    let path = match params.get("path") {
        Some(p) => p.clone(),
        None => return (StatusCode::BAD_REQUEST, "Missing path param").into_response(),
    };
    let client_opt = match &state.client {
        Some(c) => c,
        None => {
            return (StatusCode::SERVICE_UNAVAILABLE, "DHT not available").into_response();
        }
    };

    // Resolve user's PKARR to find homeserver
    let pubkey = match PublicKey::try_from(pubkey_str.as_str()) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid key").into_response(),
    };

    let mut homeserver_host = "homeserver.pubky.app".to_string();
    if let Some(packet) = client_opt.resolve(&pubkey).await {
        for rr in packet.resource_records("_pubky") {
            match &rr.rdata {
                pkarr::dns::rdata::RData::HTTPS(https) => {
                    let target = https.0.target.to_string();
                    if !target.is_empty() && target != "." {
                        // Resolve the homeserver key's PKARR to get its hostname
                        if let Ok(hs_pk) = PublicKey::try_from(target.as_str()) {
                            if let Some(hs_packet) = client_opt.resolve(&hs_pk).await {
                                for hs_rr in hs_packet.all_resource_records() {
                                    if let pkarr::dns::rdata::RData::HTTPS(hs_https) = &hs_rr.rdata {
                                        let hs_target = hs_https.0.target.to_string();
                                        if !hs_target.is_empty() && hs_target != "." {
                                            homeserver_host = hs_target;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
                pkarr::dns::rdata::RData::SVCB(svcb) => {
                    let target = svcb.target.to_string();
                    if !target.is_empty() {
                        if let Ok(hs_pk) = PublicKey::try_from(target.as_str()) {
                            if let Some(hs_packet) = client_opt.resolve(&hs_pk).await {
                                for hs_rr in hs_packet.all_resource_records() {
                                    if let pkarr::dns::rdata::RData::HTTPS(hs_https) = &hs_rr.rdata {
                                        let hs_target = hs_https.0.target.to_string();
                                        if !hs_target.is_empty() && hs_target != "." {
                                            homeserver_host = hs_target;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
                _ => {}
            }
        }
    }

    let url = format!("https://{}/{}", homeserver_host, path);
    let http_client = reqwest::Client::new();
    match http_client.get(&url).header("pubky-host", &pubkey_str).send().await {
        Ok(resp) if resp.status().is_success() => {
            let content_type = resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();
            match resp.bytes().await {
                Ok(bytes) => {
                    // Check if this is file metadata JSON (pubky files return metadata, not the actual blob)
                    if content_type.contains("json") || (bytes.len() < 1024 && bytes.starts_with(b"{")) {
                        if let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                            if let Some(src) = meta.get("src").and_then(|v| v.as_str()) {
                                let blob_content_type = meta.get("content_type").and_then(|v| v.as_str()).unwrap_or("image/jpeg");
                                // Follow the src to get the actual blob
                                let blob_path = src.strip_prefix(&format!("pubky://{}/", pubkey_str))
                                    .unwrap_or(src.strip_prefix("pubky://").unwrap_or(src));
                                let blob_url = format!("https://{}/{}", homeserver_host, blob_path);
                                match http_client.get(&blob_url).header("pubky-host", &pubkey_str).send().await {
                                    Ok(blob_resp) if blob_resp.status().is_success() => {
                                        match blob_resp.bytes().await {
                                            Ok(blob_bytes) => {
                                                let mut headers = axum::http::HeaderMap::new();
                                                headers.insert("content-type", blob_content_type.parse().unwrap_or_else(|_| "image/jpeg".parse().unwrap()));
                                                headers.insert("cache-control", "public, max-age=86400".parse().unwrap());
                                                return (headers, blob_bytes).into_response();
                                            }
                                            Err(_) => return (StatusCode::BAD_GATEWAY, "Failed to read blob").into_response(),
                                        }
                                    }
                                    _ => return (StatusCode::NOT_FOUND, "Blob not found").into_response(),
                                }
                            }
                        }
                    }
                    // Not metadata, serve directly
                    let mut headers = axum::http::HeaderMap::new();
                    headers.insert("content-type", content_type.parse().unwrap_or_else(|_| "application/octet-stream".parse().unwrap()));
                    headers.insert("cache-control", "public, max-age=3600".parse().unwrap());
                    (headers, bytes).into_response()
                }
                Err(_) => (StatusCode::BAD_GATEWAY, "Failed to read image").into_response(),
            }
        }
        _ => (StatusCode::NOT_FOUND, "Image not found").into_response(),
    }
}

async fn proxy_handler(
    State(state): State<Arc<DashboardState>>,
    req: axum::extract::Request,
) -> impl IntoResponse {
    state.proxy_requests.fetch_add(1, Ordering::Relaxed);

    // Extract the host from the request
    let host = req.headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    // Strip port and TLD
    let hostname = host.split(':').next().unwrap_or(host);
    let pubkey_str = hostname
        .strip_suffix(".pkarr").or_else(|| hostname.strip_suffix(".key"))
        .or_else(|| hostname.strip_suffix(".pubky"))
        .unwrap_or(hostname);

    // Try to parse as a public key
    let pubkey = match PublicKey::try_from(pubkey_str) {
        Ok(pk) => pk,
        Err(_) => {
            return Html(format!(
                "<html><body style='background:#1a1a2e;color:#eee;font-family:Inter,sans-serif;padding:40px;'>\
                <h1>❌ Invalid Key</h1><p><code>{}</code> is not a valid public key.</p></body></html>",
                hostname
            )).into_response();
        }
    };

    // Resolve the key via PKARR
    let client = match &state.client {
        Some(c) => c,
        None => {
            return Html("<html><body style='background:#1a1a2e;color:#eee;font-family:Inter,sans-serif;padding:40px;'>\
                <h1>⚠️ DHT Not Available</h1><p>The DHT client is not running.</p></body></html>".to_string()
            ).into_response();
        }
    };

    let packet = match client.resolve(&pubkey).await {
        Some(p) => p,
        None => {
            return Html(format!(
                "<html><body style='background:#1a1a2e;color:#eee;font-family:Inter,sans-serif;padding:40px;'>\
                <h1>🔍 Key Not Found</h1><p>No PKARR records found for <code>{}</code></p></body></html>",
                pubkey_str
            )).into_response();
        }
    };

    // Check for _pubky SVCB/HTTPS record → homeserver
    let mut homeserver_key: Option<String> = None;
    let mut records_html = String::new();
    for rr in packet.resource_records("_pubky") {
        match &rr.rdata {
            pkarr::dns::rdata::RData::HTTPS(https) => {
                let target = https.0.target.to_string();
                homeserver_key = Some(target.clone());
                records_html.push_str(&format!("<li><strong>_pubky HTTPS</strong> → <code>{}</code></li>", target));
            }
            pkarr::dns::rdata::RData::SVCB(svcb) => {
                let target = svcb.target.to_string();
                homeserver_key = Some(target.clone());
                records_html.push_str(&format!("<li><strong>_pubky SVCB</strong> → <code>{}</code></li>", target));
            }
            _ => {}
        }
    }

    // Collect all records for display
    for rr in packet.all_resource_records() {
        let (rtype, rval) = crate::dashboard::format_rdata(&rr.rdata);
        records_html.push_str(&format!("<li><strong>{}</strong> {} → <code>{}</code></li>", rr.name, rtype, rval));
    }

    // Try to fetch profile from homeserver
    let mut profile_html = String::new();
    if let Some(hs_key_str) = &homeserver_key {
        // Resolve homeserver's PKARR records to find its ICANN hostname
        let mut homeserver_host = String::new();
        if let Ok(hs_pk) = PublicKey::try_from(hs_key_str.as_str()) {
            if let Some(hs_packet) = client.resolve(&hs_pk).await {
                for rr in hs_packet.all_resource_records() {
                    if let pkarr::dns::rdata::RData::HTTPS(https) = &rr.rdata {
                        let target = https.0.target.to_string();
                        if !target.is_empty() && target != "." {
                            homeserver_host = target;
                            break;
                        }
                    }
                }
            }
        }

        if homeserver_host.is_empty() {
            homeserver_host = "homeserver.pubky.app".to_string();
        }

        // Fetch profile using pubky-host header
        let profile_url = format!("https://{}/pub/pubky.app/profile.json", homeserver_host);
        let http_client = reqwest::Client::new();
        if let Ok(resp) = http_client
            .get(&profile_url)
            .header("pubky-host", pubkey_str)
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(text) = resp.text().await {
                    if let Ok(profile) = serde_json::from_str::<serde_json::Value>(&text) {
                        let name = profile.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
                        let bio = profile.get("bio").and_then(|v| v.as_str()).unwrap_or("");
                        let status = profile.get("status").and_then(|v| v.as_str()).unwrap_or("");
                        let image = profile.get("image").and_then(|v| v.as_str()).unwrap_or("");
                        let link = profile.get("links").and_then(|v| v.as_array());

                        // Rewrite pubky:// image URLs to local proxy
                        let img_url = if image.starts_with("pubky://") {
                            let path = image.strip_prefix(&format!("pubky://{}/", pubkey_str))
                                .unwrap_or(image.strip_prefix("pubky://").unwrap_or(image));
                            format!("/pubky-img?key={}&path={}", pubkey_str, path)
                        } else if !image.is_empty() {
                            image.to_string()
                        } else {
                            String::new()
                        };

                        profile_html = format!(
                            r#"<div class="profile-card">
                            <div class="avatar-wrapper">
                            {img_tag}
                            </div>
                            <h1 class="profile-name">{name}</h1>
                            {status_tag}
                            <p class="profile-bio">{bio}</p>
                            <div class="profile-links">{links}</div>
                            </div>"#,
                            img_tag = if img_url.is_empty() {
                                r#"<div class="avatar-placeholder">👤</div>"#.to_string()
                            } else {
                                format!(
                                    r#"<img src="{url}" class="avatar" alt="{name}" onerror="this.parentElement.innerHTML='<div class=\'avatar-placeholder\'>👤</div>'">"#,
                                    url = img_url, name = name
                                )
                            },
                            name = name,
                            status_tag = if status.is_empty() {
                                String::new()
                            } else {
                                format!(r#"<div class="profile-status">{}</div>"#, status)
                            },
                            bio = bio,
                            links = link.map(|l| l.iter().filter_map(|v| {
                                let title = v.get("title").and_then(|t| t.as_str())?;
                                let url = v.get("url").and_then(|u| u.as_str())?;
                                let icon = match title.to_lowercase().as_str() {
                                    t if t.contains("twitter") || t.contains("x (") || t == "x" => "𝕏",
                                    t if t.contains("github") => "⌨",
                                    t if t.contains("medium") => "✍",
                                    t if t.contains("website") => "🌐",
                                    t if t.contains("youtube") => "▶",
                                    t if t.contains("discord") => "💬",
                                    t if t.contains("telegram") => "✈",
                                    t if t.contains("linkedin") => "💼",
                                    _ => "🔗",
                                };
                                Some(format!(r#"<a href="{}" class="link-btn" target="_blank" rel="noopener"><span class="link-icon">{}</span><span>{}</span></a>"#, url, icon, title))
                            }).collect::<Vec<_>>().join("")).unwrap_or_default(),
                        );

                        // Store homeserver info separately
                        profile_html.push_str(&format!(
                            r#"<div class="homeserver-info">Homeserver: <code>{}</code></div>"#,
                            hs_key_str
                        ));
                    }
                }
            }
        }
    }

    let page = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — Pubky</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter+Tight:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
:root{{
  --bg: #111116;
  --card: #1c1c22;
  --card-hover: #25252d;
  --border: #2a2a32;
  --fg: #f0f0f4;
  --muted: #89898f;
  --brand: #a3e635;
  --brand-dim: rgba(163,230,53,0.12);
  --accent: #6366f1;
  --accent-dim: rgba(99,102,241,0.12);
  --radius: 12px;
}}
body{{
  background:var(--bg);
  color:var(--fg);
  font-family:'Inter Tight',Inter,system-ui,sans-serif;
  min-height:100vh;
  padding:0;
  -webkit-font-smoothing:antialiased;
}}
.page{{
  max-width:480px;
  margin:0 auto;
  padding:48px 20px 32px;
  min-height:100vh;
  display:flex;
  flex-direction:column;
}}
.profile-card{{
  text-align:center;
  margin-bottom:24px;
}}
.avatar-wrapper{{
  margin:0 auto 16px;
  width:104px;height:104px;
  border-radius:50%;
  padding:3px;
  background:linear-gradient(135deg,var(--brand),var(--accent));
}}
.avatar{{
  width:98px;height:98px;
  border-radius:50%;
  object-fit:cover;
  display:block;
  border:3px solid var(--bg);
}}
.avatar-placeholder{{
  width:98px;height:98px;
  border-radius:50%;
  background:var(--card);
  display:flex;align-items:center;justify-content:center;
  font-size:36px;
  border:3px solid var(--bg);
}}
.profile-name{{
  font-size:28px;
  font-weight:700;
  color:var(--fg);
  letter-spacing:-0.02em;
  margin-bottom:4px;
}}
.profile-status{{
  font-size:14px;
  color:var(--brand);
  margin:6px 0 8px;
  font-weight:500;
}}
.profile-bio{{
  color:var(--muted);
  font-size:14px;
  line-height:1.5;
  max-width:380px;
  margin:0 auto 20px;
}}
.profile-links{{
  display:flex;
  flex-direction:column;
  gap:10px;
  margin-top:8px;
}}
.link-btn{{
  display:flex;
  align-items:center;
  gap:12px;
  padding:14px 18px;
  background:var(--card);
  border:1px solid var(--border);
  border-radius:var(--radius);
  color:var(--fg);
  text-decoration:none;
  font-size:15px;
  font-weight:500;
  transition:all 0.2s ease;
  cursor:pointer;
}}
.link-btn:hover{{
  background:var(--card-hover);
  border-color:var(--brand);
  transform:translateY(-1px);
  box-shadow:0 4px 12px rgba(163,230,53,0.08);
}}
.link-icon{{
  font-size:18px;
  width:24px;
  text-align:center;
  flex-shrink:0;
}}
.key-section{{
  margin-top:auto;
  padding-top:24px;
}}
.key-box{{
  display:flex;
  align-items:center;
  gap:8px;
  padding:10px 14px;
  background:var(--card);
  border:1px solid var(--border);
  border-radius:var(--radius);
  cursor:pointer;
  transition:border-color 0.2s;
}}
.key-box:hover{{border-color:var(--brand);}}
.key-box:active{{background:var(--card-hover);}}
.key-label{{
  font-size:11px;
  text-transform:uppercase;
  letter-spacing:0.5px;
  color:var(--muted);
  font-weight:600;
}}
.key-value{{
  font-family:'JetBrains Mono',monospace;
  font-size:11px;
  color:var(--fg);
  word-break:break-all;
  flex:1;
  opacity:0.7;
}}
.copy-btn{{
  background:none;border:none;
  color:var(--muted);
  cursor:pointer;
  padding:4px;
  font-size:16px;
  transition:color 0.2s;
  flex-shrink:0;
}}
.copy-btn:hover{{color:var(--brand);}}
.records-toggle{{
  display:flex;
  align-items:center;
  gap:6px;
  padding:10px 0;
  color:var(--muted);
  font-size:12px;
  cursor:pointer;
  border:none;
  background:none;
  width:100%;
  font-family:inherit;
  text-transform:uppercase;
  letter-spacing:0.5px;
  font-weight:600;
  margin-top:12px;
}}
.records-toggle:hover{{color:var(--fg);}}
.records-toggle .chevron{{
  transition:transform 0.2s;
  font-size:10px;
}}
.records-toggle.open .chevron{{transform:rotate(90deg);}}
.records-list{{
  display:none;
  margin-top:8px;
  padding:12px;
  background:var(--card);
  border:1px solid var(--border);
  border-radius:var(--radius);
}}
.records-list.show{{display:block;}}
.records-list li{{
  padding:6px 0;
  border-bottom:1px solid rgba(255,255,255,0.04);
  font-size:12px;
  color:var(--muted);
  font-family:'JetBrains Mono',monospace;
  word-break:break-all;
}}
.records-list li:last-child{{border:none;}}
.homeserver-info{{
  text-align:center;
  color:var(--muted);
  font-size:11px;
  margin-top:16px;
  opacity:0.6;
}}
.homeserver-info code{{
  font-family:'JetBrains Mono',monospace;
  font-size:10px;
  background:var(--card);
  padding:2px 6px;
  border-radius:4px;
}}
.footer{{
  text-align:center;
  padding:20px 0 8px;
  color:var(--muted);
  font-size:11px;
  opacity:0.5;
}}
.footer a{{color:var(--brand);text-decoration:none;}}
.footer a:hover{{opacity:0.8;}}
.pubky-badge{{
  display:inline-flex;
  align-items:center;
  gap:4px;
  margin-top:4px;
}}
@media(max-width:480px){{
  .page{{padding:32px 16px 24px;}}
  .profile-name{{font-size:24px;}}
  .link-btn{{padding:12px 16px;font-size:14px;}}
  .avatar-wrapper{{width:88px;height:88px;}}
  .avatar,.avatar-placeholder{{width:82px;height:82px;}}
}}
</style>
</head>
<body>
<div class="page">
{profile}
<div class="key-section">
<div class="key-box" onclick="copyKey()" id="key-box" title="Click to copy">
<div style="flex:1;min-width:0;">
<div class="key-label">Public Key</div>
<div class="key-value" id="pubkey-text">{key}</div>
</div>
<button class="copy-btn" id="copy-icon" title="Copy">📋</button>
</div>
<button class="records-toggle" onclick="toggleRecords()" id="records-btn">
<span class="chevron">▶</span> PKARR Records ({record_count})
</button>
<div class="records-list" id="records-list">
<ul>{records}</ul>
</div>
</div>
<div class="footer">
<div class="pubky-badge">
<span>Powered by</span>
<a href="http://127.0.0.1:9090">Pubky Node</a>
</div>
</div>
</div>
<script>
function copyKey(){{
  var t=document.getElementById('pubkey-text').textContent;
  navigator.clipboard.writeText(t).then(function(){{
    var b=document.getElementById('copy-icon');
    b.textContent='✅';
    setTimeout(function(){{b.textContent='📋';}},1500);
  }});
}}
function toggleRecords(){{
  var l=document.getElementById('records-list');
  var b=document.getElementById('records-btn');
  l.classList.toggle('show');
  b.classList.toggle('open');
}}
</script>
</body>
</html>"#,
        title = pubkey_str,
        key = pubkey_str,
        profile = profile_html,
        records = records_html,
        record_count = records_html.matches("<li>").count(),
    );

    Html(page).into_response()
}

// ─── Test helpers & integration tests ───────────────────────────

/// Build a fully-wired router + state from a temp data directory.
/// Identical to start_dashboard but doesn't bind a port — used for testing.
#[cfg(test)]
fn build_test_router(data_dir: &std::path::Path) -> Router {
    use crate::config::WatchlistConfig;
    use crate::upnp::UpnpStatus;

    let auth_hash: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(None));
    let shared_keys: SharedWatchlistKeys = Arc::new(RwLock::new(Vec::new()));
    let vault = KeyVault::new(data_dir);
    let homeserver = HomeserverManager::new(data_dir);
    let tunnel = TunnelManager::new(homeserver.get_config().drive_icann_port);
    let relay_tunnel = TunnelManager::new(8080);
    let identity = IdentityManager::new(data_dir);
    let (log_tx, _) = broadcast::channel::<String>(100);

    let state = Arc::new(DashboardState {
        client: None,
        watchlist_config: WatchlistConfig::default(),
        shared_keys,
        data_dir: data_dir.to_path_buf(),
        start_time: std::time::Instant::now(),
        relay_port: 8080,
        upnp_status: UpnpStatus::Disabled,
        dns_status: "Disabled".to_string(),
        dns_socket: "127.0.0.1:5300".to_string(),
        dns_forward: "1.1.1.1:53".to_string(),
        resolve_last_request: AtomicU64::new(0),
        vanity: Mutex::new(VanityState::default()),
        proxy_running: AtomicBool::new(false),
        proxy_port: 9091,
        proxy_requests: AtomicU64::new(0),
        auth_hash: auth_hash.clone(),
        vault,
        homeserver,
        tunnel,
        relay_tunnel,
        identity,
        log_tx,
    });

    *state.homeserver.log_tx.write().unwrap() = Some(state.log_tx.clone());
    let shared_auth = auth_hash;

    Router::new()
        .route("/health", get(health_check))
        .route("/api/auth/check", get(api_auth_check))
        .route("/api/auth/setup", post(api_auth_setup))
        .route("/api/auth/login", post(api_auth_login))
        .route("/api/auth/change-password", post(api_auth_change_password))
        .route("/api/settings", get(api_settings))
        .route("/api/vault/status", get(api_vault_status))
        .route("/api/vault/create", post(api_vault_create))
        .route("/api/vault/unlock", post(api_vault_unlock))
        .route("/api/vault/lock", post(api_vault_lock))
        .route("/api/vault/keys", get(api_vault_keys))
        .route("/api/vault/add", post(api_vault_add))
        .route("/api/vault/export", post(api_vault_export))
        .route("/api/vault/export-all", get(api_vault_export_all))
        .route("/api/vault/import", post(api_vault_import))
        .route("/api/vault/rename", post(api_vault_rename))
        .route("/api/vault/delete/{pubkey}", delete(api_vault_delete))
        .route("/api/homeserver/status", get(api_hs_status))
        .route("/api/homeserver/setup-check", get(api_hs_setup_check))
        .route("/api/homeserver/config", get(api_hs_config))
        .route("/api/homeserver/logs", get(api_hs_logs))
        .route("/api/tunnel/status", get(api_tunnel_status))
        .route("/api/tunnel/check", get(api_tunnel_check))
        .route("/api/relay-tunnel/status", get(api_relay_tunnel_status))
        .route("/api/status", get(api_status))
        .route("/api/watchlist", post(api_watchlist_add).get(api_watchlist_list))
        .route("/api/watchlist/{key}", delete(api_watchlist_remove))
        .route("/api/identity/list", get(api_identity_list))
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn(auth_check))
        .layer(Extension(shared_auth))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode, Method, header},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt; // for `.oneshot()`

    // ─── Helpers ──────────────────────────────────────────────────

    async fn response_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    fn get(path: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(path)
            .body(Body::empty())
            .unwrap()
    }

    fn post_json(path: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn delete_req(path: &str) -> Request<Body> {
        Request::builder()
            .method(Method::DELETE)
            .uri(path)
            .body(Body::empty())
            .unwrap()
    }

    // Produce a valid 52-char z-base-32 pkarr public key string for testing.
    fn valid_pkarr_key() -> String {
        // Generate a real random keypair and return its public key as z32 string
        pkarr::Keypair::random().public_key().to_string()
    }

    // ─── Health ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_health_check_returns_ok() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/health")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"ok");
    }

    // ─── Auth ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_auth_check_no_password_set() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/auth/check")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert_eq!(j["has_password"], false);
    }

    #[tokio::test]
    async fn test_auth_setup_too_short_password() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(post_json("/api/auth/setup", serde_json::json!({"password": "abc"}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_auth_setup_success_then_login() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());

        // Setup
        let resp = app.clone().oneshot(post_json("/api/auth/setup", serde_json::json!({"password": "hunter2"}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert_eq!(j["success"], true);

        // auth/check should now report has_password=true
        let resp2 = app.clone().oneshot(get("/api/auth/check")).await.unwrap();
        let j2 = response_json(resp2).await;
        assert_eq!(j2["has_password"], true);

        // Valid login
        let resp3 = app.clone().oneshot(post_json("/api/auth/login", serde_json::json!({"password": "hunter2"}))).await.unwrap();
        assert_eq!(resp3.status(), StatusCode::OK);

        // Wrong password login
        let resp4 = app.oneshot(post_json("/api/auth/login", serde_json::json!({"password": "wrong"}))).await.unwrap();
        assert_eq!(resp4.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_setup_twice_rejected() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        app.clone().oneshot(post_json("/api/auth/setup", serde_json::json!({"password": "first1"}))).await.unwrap();
        let resp = app.oneshot(post_json("/api/auth/setup", serde_json::json!({"password": "second1"}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    // ─── Watchlist ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_watchlist_empty_initially() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/watchlist")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert_eq!(j["count"], 0);
        assert!(j["keys"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_watchlist_add_valid_key() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let key = valid_pkarr_key();
        let resp = app.oneshot(post_json("/api/watchlist", serde_json::json!({"key": key}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert_eq!(j["count"], 1);
    }

    #[tokio::test]
    async fn test_watchlist_add_invalid_key_rejected() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(post_json("/api/watchlist", serde_json::json!({"key": "not-a-valid-key"}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_watchlist_add_then_list_then_remove() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let key = valid_pkarr_key();

        // Add
        app.clone().oneshot(post_json("/api/watchlist", serde_json::json!({"key": key.clone()}))).await.unwrap();

        // List — should have 1
        let list_resp = app.clone().oneshot(get("/api/watchlist")).await.unwrap();
        let j = response_json(list_resp).await;
        assert_eq!(j["count"], 1);

        // Remove
        let rm_resp = app.clone().oneshot(delete_req(&format!("/api/watchlist/{}", key))).await.unwrap();
        assert_eq!(rm_resp.status(), StatusCode::OK);
        let j2 = response_json(rm_resp).await;
        assert_eq!(j2["count"], 0);
    }

    #[tokio::test]
    async fn test_watchlist_add_duplicate_ignored() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let key = valid_pkarr_key();

        app.clone().oneshot(post_json("/api/watchlist", serde_json::json!({"key": key.clone()}))).await.unwrap();
        let resp2 = app.oneshot(post_json("/api/watchlist", serde_json::json!({"key": key}))).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let j = response_json(resp2).await;
        // Duplicate not added — still 1
        assert_eq!(j["count"], 1);
    }

    #[tokio::test]
    async fn test_watchlist_accepts_pubky_uri_prefix() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let key = valid_pkarr_key();
        let uri = format!("pubky://{}", key);
        let resp = app.oneshot(post_json("/api/watchlist", serde_json::json!({"key": uri}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert_eq!(j["count"], 1);
    }

    // ─── Vault ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_vault_status_no_vault() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/vault/status")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert_eq!(j["exists"], false);
        assert_eq!(j["unlocked"], false);
    }

    #[tokio::test]
    async fn test_vault_create_success() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(post_json("/api/vault/create", serde_json::json!({"password": "vault_pw"}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert_eq!(j["success"], true);
    }

    #[tokio::test]
    async fn test_vault_create_short_password_rejected() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(post_json("/api/vault/create", serde_json::json!({"password": "pw"}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_vault_create_then_status_shows_unlocked() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        app.clone().oneshot(post_json("/api/vault/create", serde_json::json!({"password": "testpass"}))).await.unwrap();
        let resp = app.oneshot(get("/api/vault/status")).await.unwrap();
        let j = response_json(resp).await;
        assert_eq!(j["exists"], true);
        assert_eq!(j["unlocked"], true);
    }

    #[tokio::test]
    async fn test_vault_lock_then_status_shows_locked() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        app.clone().oneshot(post_json("/api/vault/create", serde_json::json!({"password": "testpass"}))).await.unwrap();
        app.clone().oneshot(post_json("/api/vault/lock", serde_json::json!({}))).await.unwrap();
        let resp = app.oneshot(get("/api/vault/status")).await.unwrap();
        let j = response_json(resp).await;
        assert_eq!(j["exists"], true);
        assert_eq!(j["unlocked"], false);
    }

    #[tokio::test]
    async fn test_vault_unlock_wrong_password() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        app.clone().oneshot(post_json("/api/vault/create", serde_json::json!({"password": "correct_pw"}))).await.unwrap();
        app.clone().oneshot(post_json("/api/vault/lock", serde_json::json!({}))).await.unwrap();
        let resp = app.oneshot(post_json("/api/vault/unlock", serde_json::json!({"password": "wrong_pw"}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_vault_keys_locked_returns_423() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        // No vault — locked by default
        let resp = app.oneshot(get("/api/vault/keys")).await.unwrap();
        // Vault locked returns 423 Locked
        assert_eq!(resp.status(), StatusCode::LOCKED);
    }

    #[tokio::test]
    async fn test_vault_add_list_delete_rename_flow() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());

        // Need a real 64-hex-char secret
        let kp = pkarr::Keypair::random();
        let secret_hex = hex::encode(&kp.secret_key()[..32]);
        let pubkey = kp.public_key().to_string();

        // Create vault
        app.clone().oneshot(post_json("/api/vault/create", serde_json::json!({"password": "pw1234"}))).await.unwrap();

        // Add key
        let add_resp = app.clone().oneshot(post_json("/api/vault/add", serde_json::json!({
            "name": "Test Key",
            "secret_hex": secret_hex,
            "key_type": "pkarr",
            "pubkey": pubkey,
        }))).await.unwrap();
        assert_eq!(add_resp.status(), StatusCode::OK);
        let j = response_json(add_resp).await;
        assert_eq!(j["success"], true);
        assert_eq!(j["key"]["pubkey"], pubkey);

        // List keys — should have 1
        let list_resp = app.clone().oneshot(get("/api/vault/keys")).await.unwrap();
        let lj = response_json(list_resp).await;
        assert_eq!(lj["keys"].as_array().unwrap().len(), 1);
        assert!(lj["keys"][0].get("secret_hex").is_none(), "secret must not appear in list");

        // Rename
        let rename_resp = app.clone().oneshot(post_json("/api/vault/rename", serde_json::json!({
            "pubkey": pubkey,
            "name": "Renamed Key",
        }))).await.unwrap();
        assert_eq!(rename_resp.status(), StatusCode::OK);

        // Verify rename
        let list2 = app.clone().oneshot(get("/api/vault/keys")).await.unwrap();
        let lj2 = response_json(list2).await;
        assert_eq!(lj2["keys"][0]["name"], "Renamed Key");

        // Delete
        let del_resp = app.clone().oneshot(delete_req(&format!("/api/vault/delete/{}", pubkey))).await.unwrap();
        assert_eq!(del_resp.status(), StatusCode::OK);

        // List again — empty
        let list3 = app.oneshot(get("/api/vault/keys")).await.unwrap();
        let lj3 = response_json(list3).await;
        assert!(lj3["keys"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_vault_add_short_secret_rejected() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        app.clone().oneshot(post_json("/api/vault/create", serde_json::json!({"password": "pw1234"}))).await.unwrap();
        let resp = app.oneshot(post_json("/api/vault/add", serde_json::json!({
            "name": "Bad",
            "secret_hex": "tooshort",
            "key_type": "manual",
            "pubkey": "anypubkey",
        }))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_vault_export_all_format() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        app.clone().oneshot(post_json("/api/vault/create", serde_json::json!({"password": "pw1234"}))).await.unwrap();
        let resp = app.oneshot(get("/api/vault/export-all")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert_eq!(j["format"], "pubky-vault-backup-v1");
        assert!(j["keys"].is_array());
    }

    // ─── Homeserver ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_homeserver_status_returns_valid_shape() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/homeserver/status")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        // Must have a "state" field
        assert!(j.get("state").is_some(), "homeserver status must have 'state' field");
        // Must have ports
        assert!(j.get("ports").is_some(), "homeserver status must have 'ports' field");
    }

    #[tokio::test]
    async fn test_homeserver_setup_check_returns_valid_shape() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/homeserver/setup-check")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // Should return JSON — exact shape depends on what's installed but must be valid
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v.is_object(), "setup-check must return a JSON object");
    }

    #[tokio::test]
    async fn test_homeserver_config_returns_shape() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/homeserver/config")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert!(j.get("signup_mode").is_some());
        assert!(j.get("drive_icann_port").is_some());
    }

    #[tokio::test]
    async fn test_homeserver_logs_returns_shape() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/homeserver/logs")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert!(j.get("lines").is_some());
        assert!(j["lines"].is_array());
    }

    // ─── Tunnel ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_tunnel_status_returns_shape() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/tunnel/status")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert!(j.get("running").is_some() || j.get("state").is_some() || j.get("status").is_some(),
            "tunnel status must have a running/state/status field, got: {}", j);
    }

    #[tokio::test]
    async fn test_tunnel_check_returns_shape() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/tunnel/check")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert!(j.get("available").is_some(), "tunnel/check must have 'available' field");
    }

    // ─── Node Status ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_api_status_returns_valid_shape() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/status")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert!(j.get("version").is_some(), "status must include version");
        assert!(j.get("uptime_secs").is_some(), "status must include uptime_secs");
        assert!(j.get("watchlist").is_some(), "status must include watchlist");
        assert!(j.get("relay_port").is_some(), "status must include relay_port");
    }

    // ─── Settings ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_settings_returns_data_dir() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/settings")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert!(j.get("data_dir").is_some());
        assert!(j.get("platform").is_some());
    }

    // ─── Identity ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_identity_list_empty_initially() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/identity/list")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert!(j.get("identities").is_some());
        assert!(j["identities"].as_array().unwrap().is_empty());
    }
}

