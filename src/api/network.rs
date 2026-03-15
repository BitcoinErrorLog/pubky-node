//! Network, status, DNS, proxy, and resolve API handlers.
//!
//! Contains the main node status endpoint, DHT resolve, DNS management,
//! proxy hosts management, HTTP proxy, and the profile page renderer.

use super::state::DashboardState;
use crate::upnp::UpnpStatus;
use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Json},
    routing::get,
    Router,
};
use pkarr::{Keypair, PublicKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tracing::info;

// ─── Data structures ────────────────────────────────────────────

#[derive(Serialize)]
pub struct NodeStatus {
    pub version: String,
    pub uptime_secs: u64,
    pub relay_port: u16,
    pub dht: Option<DhtStatus>,
    pub watchlist: WatchlistStatus,
    pub upnp: UpnpApiStatus,
    pub dns: DnsApiStatus,
    pub proxy: ProxyApiStatus,
}

#[derive(Serialize)]
pub struct DhtStatus {
    pub local_addr: String,
    pub id: String,
    pub firewalled: bool,
    pub server_mode: bool,
    pub dht_size_estimate: usize,
}

#[derive(Serialize)]
pub struct WatchlistStatus {
    pub enabled: bool,
    pub key_count: usize,
    pub republish_interval_secs: u64,
}

#[derive(Serialize)]
pub struct UpnpApiStatus {
    pub status: String,
    pub external_ip: Option<String>,
    pub port: Option<u16>,
}

#[derive(Serialize)]
pub struct DnsApiStatus {
    pub status: String,
    pub socket: String,
    pub forward: String,
    pub system_dns_active: bool,
}

#[derive(Serialize)]
pub struct ProxyApiStatus {
    pub status: String,
    pub port: u16,
    pub requests_served: u64,
}

#[derive(Serialize)]
pub struct ResolveResponse {
    pub public_key: String,
    pub records: Vec<DnsRecord>,
    pub last_updated: u64,
    pub compressed_size: usize,
    pub elapsed_secs: u32,
}

#[derive(Serialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
}

#[derive(Deserialize)]
pub struct DnsToggleRequest {
    pub enabled: bool,
}

#[derive(Serialize)]
pub struct DnsToggleResponse {
    pub enabled: bool,
    pub restart_required: bool,
}

#[derive(Serialize)]
pub struct DnsSystemResponse {
    pub success: bool,
    pub service: String,
    pub message: String,
}

// ─── Status Handler ─────────────────────────────────────────────

/// JSON API endpoint: returns node status.
pub async fn api_status(
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

    let key_count = state.shared_keys.read()
        .map(|guard| guard.len())
        .unwrap_or(0);
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
pub async fn health_check() -> &'static str {
    "ok"
}

/// Shutdown the node process.
pub async fn api_shutdown() -> &'static str {
    info!("Shutdown requested via dashboard");
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        std::process::exit(0);
    });
    "Shutting down..."
}

/// Restart the node process (exits with code 42 for Tauri to respawn).
pub async fn api_restart() -> &'static str {
    info!("Restart requested via dashboard");
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        std::process::exit(42);
    });
    "Restarting..."
}

// ─── Resolve Handler ────────────────────────────────────────────

/// Resolve a pkarr public key and return its DNS records.
pub async fn api_resolve(
    State(state): State<Arc<DashboardState>>,
    Path(public_key_str): Path<String>,
) -> Result<Json<ResolveResponse>, StatusCode> {
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

    let origin = public_key.to_z32();
    let mut records = Vec::new();

    for rr in signed_packet.all_resource_records() {
        let full_name = rr.name.to_string();
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
pub fn format_rdata(rdata: &pkarr::dns::rdata::RData) -> (String, String) {
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

// ─── DNS Management ─────────────────────────────────────────────

/// Toggle PKDNS enabled/disabled in config.toml.
pub async fn api_dns_toggle(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<DnsToggleRequest>,
) -> Result<Json<DnsToggleResponse>, (StatusCode, String)> {
    let config_path = state.data_dir.join("config.toml");

    let mut doc: toml::Value = if config_path.exists() {
        let contents = std::fs::read_to_string(&config_path)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to read config: {}", e)))?;
        toml::from_str(&contents).unwrap_or(toml::Value::Table(Default::default()))
    } else {
        toml::Value::Table(Default::default())
    };

    let table = doc.as_table_mut()
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Config is not a table".to_string()))?;
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
pub async fn api_dns_set_system(
    State(state): State<Arc<DashboardState>>,
) -> Result<Json<DnsSystemResponse>, (StatusCode, String)> {
    let ip = state.dns_socket.split(':').next().unwrap_or("127.0.0.1");
    run_networksetup_dns(ip).await
}

/// Reset macOS system DNS to DHCP default.
pub async fn api_dns_reset_system() -> Result<Json<DnsSystemResponse>, (StatusCode, String)> {
    run_networksetup_dns("empty").await
}

async fn run_networksetup_dns(dns_value: &str) -> Result<Json<DnsSystemResponse>, (StatusCode, String)> {
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

// ─── Proxy Hosts Management ────────────────────────────────────

const HOSTS_MARKER_BEGIN: &str = "# BEGIN PUBKY-NODE PROXY";
const HOSTS_MARKER_END: &str = "# END PUBKY-NODE PROXY";

/// Configure /etc/hosts with entries for all watchlist keys.
pub async fn api_proxy_setup_hosts(
    State(state): State<Arc<DashboardState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let keys = state.shared_keys.read()
        .map(|guard| guard.clone())
        .unwrap_or_default();
    if keys.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "No keys in watchlist. Add keys to the watchlist first.".to_string()));
    }

    let mut entries = Vec::new();
    entries.push(HOSTS_MARKER_BEGIN.to_string());
    for key in &keys {
        for tld in &["pkarr", "key", "pubky"] {
            entries.push(format!("127.0.0.1 {}.{}", key, tld));
        }
    }
    entries.push(HOSTS_MARKER_END.to_string());
    let block = entries.join("\n");

    let hosts = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
    let cleaned = remove_hosts_block(&hosts);
    let new_hosts = format!("{}\n\n{}\n", cleaned.trim_end(), block);

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
pub async fn api_proxy_reset_hosts() -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let hosts = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
    let cleaned = remove_hosts_block(&hosts);

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
pub async fn api_proxy_hosts_status() -> Json<serde_json::Value> {
    let configured = std::fs::read_to_string("/etc/hosts")
        .map(|h| h.contains(HOSTS_MARKER_BEGIN))
        .unwrap_or(false);
    Json(serde_json::json!({ "configured": configured }))
}

// ─── HTTP Proxy for .pkarr domains ─────────────────────────────

pub async fn start_http_proxy(state: Arc<DashboardState>) {
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
                    if content_type.contains("json") || (bytes.len() < 1024 && bytes.starts_with(b"{")) {
                        if let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                            if let Some(src) = meta.get("src").and_then(|v| v.as_str()) {
                                let blob_content_type = meta.get("content_type").and_then(|v| v.as_str()).unwrap_or("image/jpeg");
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

/// Main proxy handler for .pkarr domain navigation.
pub async fn proxy_handler(
    State(state): State<Arc<DashboardState>>,
    req: axum::extract::Request,
) -> impl IntoResponse {
    state.proxy_requests.fetch_add(1, Ordering::Relaxed);

    let host = req.headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let hostname = host.split(':').next().unwrap_or(host);
    let pubkey_str = hostname
        .strip_suffix(".pkarr").or_else(|| hostname.strip_suffix(".key"))
        .or_else(|| hostname.strip_suffix(".pubky"))
        .unwrap_or(hostname);

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

    for rr in packet.all_resource_records() {
        let (rtype, rval) = format_rdata(&rr.rdata);
        records_html.push_str(&format!("<li><strong>{}</strong> {} → <code>{}</code></li>", rr.name, rtype, rval));
    }

    // Try to fetch profile from homeserver
    let mut profile_html = String::new();
    if let Some(hs_key_str) = &homeserver_key {
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

                        profile_html.push_str(&format!(
                            r#"<div class="homeserver-info">Homeserver: <code>{}</code></div>"#,
                            hs_key_str
                        ));
                    }
                }
            }
        }
    }

    // Render the full profile page — includes embedded CSS
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
.profile-card{{text-align:center;margin-bottom:24px;}}
.avatar-wrapper{{margin:0 auto 16px;width:104px;height:104px;border-radius:50%;padding:3px;background:linear-gradient(135deg,var(--brand),var(--accent));}}
.avatar{{width:98px;height:98px;border-radius:50%;object-fit:cover;display:block;border:3px solid var(--bg);}}
.avatar-placeholder{{width:98px;height:98px;border-radius:50%;background:var(--card);display:flex;align-items:center;justify-content:center;font-size:36px;border:3px solid var(--bg);}}
.profile-name{{font-size:28px;font-weight:700;color:var(--fg);letter-spacing:-0.02em;margin-bottom:4px;}}
.profile-status{{font-size:14px;color:var(--brand);margin:6px 0 8px;font-weight:500;}}
.profile-bio{{color:var(--muted);font-size:14px;line-height:1.5;max-width:380px;margin:0 auto 20px;}}
.profile-links{{display:flex;flex-direction:column;gap:10px;margin-top:8px;}}
.link-btn{{display:flex;align-items:center;gap:12px;padding:14px 18px;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);color:var(--fg);text-decoration:none;font-size:15px;font-weight:500;transition:all 0.2s ease;cursor:pointer;}}
.link-btn:hover{{background:var(--card-hover);border-color:var(--brand);transform:translateY(-1px);box-shadow:0 4px 12px rgba(163,230,53,0.08);}}
.link-icon{{font-size:18px;width:24px;text-align:center;flex-shrink:0;}}
.key-section{{margin-top:auto;padding-top:24px;}}
.key-box{{display:flex;align-items:center;gap:8px;padding:10px 14px;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);cursor:pointer;transition:border-color 0.2s;}}
.key-box:hover{{border-color:var(--brand);}}
.key-box:active{{background:var(--card-hover);}}
.key-label{{font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:var(--muted);font-weight:600;}}
.key-value{{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--fg);word-break:break-all;flex:1;opacity:0.7;}}
.copy-btn{{background:none;border:none;color:var(--muted);cursor:pointer;padding:4px;font-size:16px;transition:color 0.2s;flex-shrink:0;}}
.copy-btn:hover{{color:var(--brand);}}
.records-toggle{{display:flex;align-items:center;gap:6px;padding:10px 0;color:var(--muted);font-size:12px;cursor:pointer;border:none;background:none;width:100%;font-family:inherit;text-transform:uppercase;letter-spacing:0.5px;font-weight:600;margin-top:12px;}}
.records-toggle:hover{{color:var(--fg);}}
.records-toggle .chevron{{transition:transform 0.2s;font-size:10px;}}
.records-toggle.open .chevron{{transform:rotate(90deg);}}
.records-list{{display:none;margin-top:8px;padding:12px;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);}}
.records-list.show{{display:block;}}
.records-list li{{padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.04);font-size:12px;color:var(--muted);font-family:'JetBrains Mono',monospace;word-break:break-all;}}
.records-list li:last-child{{border:none;}}
.homeserver-info{{text-align:center;color:var(--muted);font-size:11px;margin-top:16px;opacity:0.6;}}
.homeserver-info code{{font-family:'JetBrains Mono',monospace;font-size:10px;background:var(--card);padding:2px 6px;border-radius:4px;}}
.footer{{text-align:center;padding:20px 0 8px;color:var(--muted);font-size:11px;opacity:0.5;}}
.footer a{{color:var(--brand);text-decoration:none;}}
.footer a:hover{{opacity:0.8;}}
.pubky-badge{{display:inline-flex;align-items:center;gap:4px;margin-top:4px;}}
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

// ─── Publish ────────────────────────────────────────────────────

/// Publish signed DNS records to the DHT.
pub async fn api_publish(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let secret_hex = body.get("secret_key").and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "Missing secret_key".to_string()))?;
    let records_arr = body.get("records").and_then(|v| v.as_array())
        .ok_or((StatusCode::BAD_REQUEST, "Missing records array".to_string()))?;
    let add_to_watchlist = body.get("add_to_watchlist").and_then(|v| v.as_bool()).unwrap_or(true);

    let secret_bytes = hex::decode(secret_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid hex key: {}", e)))?;
    if secret_bytes.len() != 32 {
        return Err((StatusCode::BAD_REQUEST, format!("Secret key must be 32 bytes (64 hex chars), got {}", secret_bytes.len())));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&secret_bytes);
    let keypair = Keypair::from_secret_key(&key_bytes);
    let public_key_str = keypair.public_key().to_string();

    let mut record_configs = Vec::new();
    for rec in records_arr {
        let record_type = rec.get("type").and_then(|v| v.as_str()).unwrap_or("").to_uppercase();
        let name = rec.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let value = rec.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let ttl = rec.get("ttl").and_then(|v| v.as_u64()).map(|t| t as u32);

        if record_type.is_empty() || name.is_empty() || value.is_empty() {
            return Err((StatusCode::BAD_REQUEST, "Each record needs type, name, and value".to_string()));
        }

        record_configs.push(crate::config::RecordConfig {
            record_type,
            name,
            value,
            ttl,
        });
    }

    if record_configs.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "At least one record is required".to_string()));
    }

    let signed_packet = crate::publisher::build_signed_packet(&keypair, &record_configs)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to build packet: {}", e)))?;

    let client = pkarr::Client::builder().build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create client: {}", e)))?;
    client.publish(&signed_packet, None).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Publish failed: {}", e)))?;

    if add_to_watchlist {
        if let Ok(mut keys) = state.shared_keys.write() {
            if !keys.contains(&public_key_str) {
                keys.push(public_key_str.clone());
            }
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
