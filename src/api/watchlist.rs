//! Watchlist API handlers.
//!
//! Manages the watchlist of public keys for DHT republishing.

use super::state::DashboardState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use pkarr::PublicKey;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;

#[derive(Deserialize)]
pub struct WatchlistAddRequest {
    pub key: String,
}

#[derive(Serialize)]
pub struct WatchlistResponse {
    pub keys: Vec<String>,
    pub count: usize,
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

pub fn save_watchlist_keys(data_dir: &std::path::Path, keys: &[String]) {
    let path = data_dir.join("watchlist_keys.json");
    if let Ok(json) = serde_json::to_string_pretty(keys) {
        if let Err(e) = std::fs::write(&path, json) {
            tracing::warn!("Failed to save watchlist keys to {}: {}", path.display(), e);
        }
    }
}

/// List all watchlist keys.
pub async fn api_watchlist_list(
    State(state): State<Arc<DashboardState>>,
) -> Json<WatchlistResponse> {
    let keys = state.shared_keys.read()
        .map(|guard| guard.clone())
        .unwrap_or_default();
    let count = keys.len();
    Json(WatchlistResponse { keys, count })
}

/// Add a public key to the watchlist.
pub async fn api_watchlist_add(
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
    let mut keys = state.shared_keys.write()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Lock error".to_string()))?;

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
pub async fn api_watchlist_remove(
    State(state): State<Arc<DashboardState>>,
    Path(key): Path<String>,
) -> Json<WatchlistResponse> {
    let (keys_clone, count) = {
        let mut keys = state.shared_keys.write()
            .expect("watchlist lock");
        keys.retain(|k| k != &key);
        info!("Watchlist: removed key, now watching {} key(s)", keys.len());
        let count = keys.len();
        let keys_clone = keys.clone();
        (keys_clone, count)
    };
    save_watchlist_keys(&state.data_dir, &keys_clone);
    Json(WatchlistResponse { keys: keys_clone, count })
}
