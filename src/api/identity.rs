//! Identity API handlers.
//!
//! Signup, signin, and identity listing for homeserver identities.

use super::state::DashboardState;
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use std::sync::Arc;

/// POST /api/identity/signup
pub async fn api_identity_signup(
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
pub async fn api_identity_signin(
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
pub async fn api_identity_list(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    let ids = state.identity.list();
    Json(serde_json::json!({ "identities": ids }))
}
