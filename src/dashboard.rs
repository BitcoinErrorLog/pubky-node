//! Web dashboard and REST API server.
//!
//! Provides a real-time monitoring UI, key explorer, user guide,
//! and JSON API endpoints for node status and DHT key resolution.
//! Includes security headers, rate limiting, and a health check endpoint.

use std::path::PathBuf;
use std::sync::{Arc, RwLock, atomic::{AtomicU64, AtomicBool, Ordering}};

use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Response},
    routing::{get, post, delete},
    Router,
};
use pkarr::{Client, Keypair, PublicKey};
use serde::{Serialize, Deserialize};
use tokio::task::JoinHandle;
use tokio::sync::Mutex;
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
    /// Vanity key generator state.
    vanity: Mutex<VanityState>,
    /// HTTP proxy running flag.
    proxy_running: AtomicBool,
    proxy_port: u16,
    proxy_requests: AtomicU64,
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
        vanity: Mutex::new(VanityState::default()),
        proxy_running: AtomicBool::new(false),
        proxy_port: 9091,
        proxy_requests: AtomicU64::new(0),
    });

    // Start HTTP proxy for .pkarr domains
    let proxy_state = state.clone();
    tokio::spawn(async move {
        start_http_proxy(proxy_state).await;
    });

    let app = Router::new()
        .route("/", get(serve_dashboard))
        .route("/health", get(health_check))
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

    // Write via osascript (sudo)
    let script = format!(
        "do shell script \"echo '{}' | sudo tee /etc/hosts > /dev/null\" with administrator privileges",
        new_hosts.replace('\\', "\\\\").replace('\'', "'\\''").replace('"', "\\\"")
    );

    let output = tokio::process::Command::new("osascript")
        .args(["-e", &script])
        .output()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to run osascript: {}", e)))?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update /etc/hosts: {}", err)));
    }

    // Flush DNS cache
    let _ = tokio::process::Command::new("dscacheutil")
        .args(["-flushcache"])
        .output()
        .await;

    Ok(Json(serde_json::json!({
        "success": true,
        "entries": keys.len() * 3,
        "message": format!("Added {} host entries for {} keys", keys.len() * 3, keys.len())
    })))
}

/// Remove pubky-node proxy entries from /etc/hosts.
async fn api_proxy_reset_hosts() -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let hosts = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
    let cleaned = remove_hosts_block(&hosts);

    let script = format!(
        "do shell script \"echo '{}' | sudo tee /etc/hosts > /dev/null\" with administrator privileges",
        cleaned.trim_end().replace('\\', "\\\\").replace('\'', "'\\''").replace('"', "\\\"")
    );

    let output = tokio::process::Command::new("osascript")
        .args(["-e", &script])
        .output()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to run osascript: {}", e)))?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to reset /etc/hosts: {}", err)));
    }

    let _ = tokio::process::Command::new("dscacheutil")
        .args(["-flushcache"])
        .output()
        .await;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Removed proxy entries from /etc/hosts"
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
    if let Some(hs_key) = &homeserver_key {
        // Try fetching from the public relay API
        let profile_url = format!("https://homeserver.pubky.app/{}/pub/pubky.app/profile.json", pubkey_str);
        if let Ok(resp) = reqwest::get(&profile_url).await {
            if let Ok(text) = resp.text().await {
                if let Ok(profile) = serde_json::from_str::<serde_json::Value>(&text) {
                    let name = profile.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
                    let bio = profile.get("bio").and_then(|v| v.as_str()).unwrap_or("");
                    let image = profile.get("image").and_then(|v| v.as_str()).unwrap_or("");
                    let link = profile.get("links").and_then(|v| v.as_array());

                    profile_html = format!(
                        r#"<div style="background:linear-gradient(135deg,#2d1b69,#1a1a2e);border-radius:16px;padding:32px;margin-bottom:24px;border:1px solid rgba(99,102,241,0.3);">
                        {img_tag}
                        <h2 style="margin:0 0 8px;color:#a5b4fc;">{name}</h2>
                        <p style="color:#94a3b8;margin:0 0 16px;">{bio}</p>
                        <div style="display:flex;gap:8px;flex-wrap:wrap;">{links}</div>
                        <p style="color:#64748b;font-size:12px;margin-top:16px;">Homeserver: <code>{hs}</code></p>
                        </div>"#,
                        img_tag = if image.is_empty() { String::new() } else {
                            format!(r#"<img src="{}" style="width:80px;height:80px;border-radius:50%;border:2px solid #6366f1;margin-bottom:16px;" alt="avatar">"#, image)
                        },
                        name = name,
                        bio = bio,
                        links = link.map(|l| l.iter().filter_map(|v| {
                            let title = v.get("title").and_then(|t| t.as_str())?;
                            let url = v.get("url").and_then(|u| u.as_str())?;
                            Some(format!(r#"<a href="{}" style="background:#6366f1;color:white;padding:6px 14px;border-radius:8px;text-decoration:none;font-size:13px;" target="_blank">{}</a>"#, url, title))
                        }).collect::<Vec<_>>().join("")).unwrap_or_default(),
                        hs = hs_key,
                    );
                }
            }
        }
    }

    let page = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{key} — Pubky Profile</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:#0f0f23;color:#e2e8f0;font-family:Inter,sans-serif;padding:40px 20px;}}
.container{{max-width:640px;margin:0 auto;}}
h1{{font-size:18px;color:#818cf8;margin-bottom:24px;word-break:break-all;}}
code{{background:rgba(99,102,241,0.15);padding:2px 6px;border-radius:4px;font-family:'JetBrains Mono',monospace;font-size:13px;}}
ul{{list-style:none;margin-top:16px;}}
li{{padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.06);font-size:14px;}}
.footer{{margin-top:32px;text-align:center;color:#475569;font-size:12px;}}
.footer a{{color:#6366f1;text-decoration:none;}}
</style>
</head>
<body>
<div class="container">
{profile}
<h1>🔑 <code>{key}</code></h1>
<div style="margin-top:16px;">
<h3 style="color:#94a3b8;font-size:14px;margin-bottom:8px;">PKARR Records</h3>
<ul>{records}</ul>
</div>
<div class="footer">
<p>Served by <a href="http://127.0.0.1:9090">Pubky Node</a> HTTP Proxy</p>
</div>
</div>
</body>
</html>"#,
        key = pubkey_str,
        profile = profile_html,
        records = records_html,
    );

    Html(page).into_response()
}
