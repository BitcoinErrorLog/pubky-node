//! Cloudflare Tunnel API handlers.
//!
//! Manages homeserver tunnel and relay tunnel start/stop/status.

use super::state::DashboardState;
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use std::sync::Arc;

/// GET /api/tunnel/status
pub async fn api_tunnel_status(
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
pub async fn api_tunnel_start(
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
                        let domain = url.trim_start_matches("https://").trim_start_matches("http://").to_string();
                        tracing::info!("Tunnel active: {} — updating homeserver config", domain);

                        let update = serde_json::json!({ "icann_domain": domain });
                        if let Err(e) = state_clone.homeserver.update_config(update) {
                            tracing::warn!("Failed to update icann_domain with tunnel URL: {}", e);
                        }

                        // Re-publish PKARR with new domain
                        if let Some(pk) = state_clone.homeserver.server_pubkey() {
                            let secret = state_clone.vault.export_key(&pk)
                                .ok()
                                .or_else(|| state_clone.homeserver.read_server_secret());
                            if let Some(sec) = secret {
                                let _ = super::homeserver::publish_homeserver_pkarr(&sec, &domain, &state_clone).await;
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
pub async fn api_tunnel_stop(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    state.tunnel.stop();
    Json(serde_json::json!({ "success": true }))
}

/// GET /api/tunnel/check — is cloudflared binary available?
pub async fn api_tunnel_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "available": crate::tunnel::TunnelManager::binary_available(),
        "download_url": "https://github.com/cloudflare/cloudflared/releases/latest"
    }))
}

// ─── Relay Tunnel ─────────────────────────────────────────────

/// GET /api/relay-tunnel/status
pub async fn api_relay_tunnel_status(
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
pub async fn api_relay_tunnel_start(
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
pub async fn api_relay_tunnel_stop(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    state.relay_tunnel.stop();
    Json(serde_json::json!({ "success": true }))
}

/// GET /api/logs/stream — Server-Sent Events stream of homeserver stdout.
pub async fn api_logs_stream(
    State(state): State<Arc<DashboardState>>,
) -> impl axum::response::IntoResponse {
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
