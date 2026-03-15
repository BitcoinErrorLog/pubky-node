//! Reachability self-test API handler.
//!
//! Checks whether the node's relay, tunnel, and DHT are healthy/reachable.

use super::state::DashboardState;
use crate::tunnel::TunnelState;
use axum::{
    extract::State,
    response::Json,
};
use std::sync::Arc;

/// GET /api/reachability-check — check relay, tunnel, and DHT health.
pub async fn api_reachability_check(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    // 1. Check if DHT client is available
    let dht_healthy = state.client.is_some();

    // 2. Check relay reachability by probing our own relay port
    let relay_port = state.relay_port;
    let relay_reachable = check_tcp_port("127.0.0.1", relay_port).await;

    // 3. Check if either tunnel is active
    let hs_tunnel_running = matches!(state.tunnel.state(), TunnelState::Running);
    let relay_tunnel_running = matches!(state.relay_tunnel.state(), TunnelState::Running);
    let tunnel_active = hs_tunnel_running || relay_tunnel_running;

    // 4. Get public URLs if available
    let hs_tunnel_url = state.tunnel.public_url();
    let relay_tunnel_url = state.relay_tunnel.public_url();

    // Build suggestion
    let suggestion = if dht_healthy && relay_reachable {
        if tunnel_active {
            "All systems operational. Your node is fully reachable."
        } else {
            "Relay is local-only. Consider starting a Cloudflare Tunnel for public reachability."
        }
    } else if !dht_healthy {
        "DHT client is not running. The node may have started without network support."
    } else {
        "Relay port is not responding locally. Check if the relay started correctly."
    };

    Json(serde_json::json!({
        "relay_reachable": relay_reachable,
        "tunnel_active": tunnel_active,
        "dht_healthy": dht_healthy,
        "relay_port": relay_port,
        "hs_tunnel_url": hs_tunnel_url,
        "relay_tunnel_url": relay_tunnel_url,
        "suggestion": suggestion,
    }))
}

/// Try connecting to a local TCP port to see if the relay is up.
async fn check_tcp_port(host: &str, port: u16) -> bool {
    tokio::net::TcpStream::connect(format!("{}:{}", host, port))
        .await
        .is_ok()
}
