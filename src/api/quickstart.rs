//! Quickstart API — one-click identity creation.
//!
//! Chains: generate vault key → signup on homeserver → publish PKARR → add to watchlist.

use super::state::DashboardState;
use super::homeserver::publish_homeserver_pkarr;
use super::watchlist::save_watchlist_keys;
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use std::sync::Arc;

/// POST /api/quickstart — one-click identity creation.
///
/// 1. Generate a new keypair in the vault
/// 2. Get a signup token from the homeserver
/// 3. Sign up on the local homeserver
/// 4. Publish PKARR record for the homeserver's server key
/// 5. Add user key to watchlist for auto-republish
///
/// Requires: vault unlocked, homeserver running.
pub async fn api_quickstart(
    State(state): State<Arc<DashboardState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    // 1. Check vault is unlocked
    if !state.vault.is_unlocked() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Vault is locked. Unlock it first.",
            "step": "vault"
        })));
    }

    // 2. Check homeserver is running
    let hs_state = state.homeserver.state();
    if hs_state != crate::homeserver::HomeserverState::Running {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Homeserver is not running. Start it first.",
            "step": "homeserver"
        })));
    }

    // 3. Generate a new keypair and add to vault
    let kp = pkarr::Keypair::random();
    let secret_hex = hex::encode(&kp.secret_key()[..32]);
    let pubkey = kp.public_key().to_string();

    if let Err(e) = state.vault.add_key("My Identity", &secret_hex, "pkarr", &pubkey) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Key generation failed: {}", e),
            "step": "keygen"
        })));
    }

    // 4. Get the homeserver public key
    let hs_pubkey = match state.homeserver.server_pubkey() {
        Some(pk) => pk,
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "error": "Homeserver public key not available. Wait for it to fully start.",
            "step": "homeserver_key"
        }))),
    };

    // 5. Get a signup token from the homeserver admin API
    let cfg = state.homeserver.get_config();
    let token_url = format!("http://127.0.0.1:{}/signup_token", cfg.admin_port);
    let signup_token = match super::homeserver::admin_fetch_get(&token_url, &cfg.admin_password).await {
        Ok(data) => data.get("token").and_then(|t| t.as_str()).map(|s| s.to_string()),
        Err(e) => {
            tracing::warn!("Quickstart: failed to get signup token: {}", e);
            None // Try without a token (if signup_mode is "open")
        }
    };

    // 6. Sign up on the homeserver
    let signup_token_ref = signup_token.as_deref();
    match state.identity.signup(&secret_hex, &hs_pubkey, signup_token_ref, cfg.drive_icann_port).await {
        Ok(info) => {
            tracing::info!("Quickstart: signed up {} on homeserver", info.pubkey);
        }
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Signup failed: {}", e),
            "step": "signup",
            "pubkey": pubkey
        }))),
    }

    // 7. Publish PKARR record for the homeserver's server key
    let hs_secret = state.vault.export_key(&hs_pubkey)
        .ok()
        .or_else(|| state.homeserver.read_server_secret());

    let mut pkarr_published = false;
    if let Some(hs_sec) = hs_secret {
        match publish_homeserver_pkarr(&hs_sec, &cfg.icann_domain, &state).await {
            Ok(()) => {
                pkarr_published = true;
                tracing::info!("Quickstart: PKARR published for homeserver");
            }
            Err(e) => {
                tracing::warn!("Quickstart: PKARR publish failed: {}", e);
            }
        }
    }

    // 8. Add user key to watchlist for auto-republish
    {
        let mut keys = state.shared_keys.write().expect("watchlist lock");
        if !keys.contains(&pubkey) {
            keys.push(pubkey.clone());
            tracing::info!("Quickstart: added {} to watchlist", pubkey);
        }
        let keys_clone = keys.clone();
        drop(keys);
        save_watchlist_keys(&state.data_dir, &keys_clone);
    }

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "pubkey": pubkey,
        "homeserver": hs_pubkey,
        "pkarr_published": pkarr_published,
        "message": format!("Identity created! Your pubky URI is: pubky://{}", pubkey)
    })))
}
