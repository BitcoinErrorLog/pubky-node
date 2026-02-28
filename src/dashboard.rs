//! Web dashboard and REST API server.
//!
//! Provides a real-time monitoring UI, key explorer, user guide,
//! and JSON API endpoints for node status and DHT key resolution.
//! Includes security headers, rate limiting, and a health check endpoint.

use std::path::PathBuf;
use std::sync::{Arc, RwLock, atomic::{AtomicU64, Ordering}};

use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Response},
    routing::{get, post, delete},
    Router,
};
use pkarr::{Client, PublicKey};
use serde::{Serialize, Deserialize};
use tokio::task::JoinHandle;
use tracing::info;

use crate::config::WatchlistConfig;
use crate::upnp::UpnpStatus;

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
    });

    let app = Router::new()
        .route("/", get(serve_dashboard))
        .route("/health", get(health_check))
        .route("/api/status", get(api_status))
        .route("/api/resolve/{public_key}", get(api_resolve))
        .route("/api/watchlist", post(api_watchlist_add).get(api_watchlist_list))
        .route("/api/watchlist/{key}", delete(api_watchlist_remove))
        .route("/api/dns/toggle", post(api_dns_toggle))
        .route("/dashboard.js", get(serve_js))
        .route("/dashboard.css", get(serve_css))
        .layer(middleware::from_fn(security_headers))
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

    let dns = DnsApiStatus {
        status: state.dns_status.clone(),
        socket: state.dns_socket.clone(),
        forward: state.dns_forward.clone(),
    };

    Json(NodeStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs,
        relay_port: state.relay_port,
        dht: dht_info,
        watchlist,
        upnp,
        dns,
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
