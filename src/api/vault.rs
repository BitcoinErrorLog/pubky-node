//! Key Vault API handlers.
//!
//! CRUD operations for the encrypted key vault.

use super::state::DashboardState;
use crate::keyvault::VaultKey;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use std::sync::Arc;

/// Ensure the homeserver's current key is in the vault.
/// Called after vault unlock/create — the moment vault access becomes available.
/// Reads the homeserver secret file, derives the pubkey, and imports if missing.
pub fn ensure_server_key_in_vault(state: &Arc<DashboardState>) {
    // Read the homeserver's secret from its file
    let secret_hex = match state.homeserver.read_server_secret() {
        Some(s) => s,
        None => return, // No homeserver key yet — nothing to import
    };

    // Derive the public key
    let secret_bytes = match hex::decode(secret_hex.trim()) {
        Ok(b) if b.len() == 32 => b,
        _ => return,
    };
    let mut key = [0u8; 32];
    key.copy_from_slice(&secret_bytes);
    let kp = pkarr::Keypair::from_secret_key(&key);
    let pubkey = kp.public_key().to_z32();

    // Import into vault if not already there
    if !state.vault.has_key(&pubkey) {
        match state.vault.add_key("Server Key", secret_hex.trim(), "homeserver", &pubkey) {
            Ok(_) => tracing::info!("Homeserver key auto-imported into vault: {}", pubkey),
            Err(e) => tracing::warn!("Could not auto-import homeserver key: {}", e),
        }
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

/// GET /api/vault/status — check if vault exists and is unlocked.
pub async fn api_vault_status(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "exists": state.vault.exists(),
        "unlocked": state.vault.is_unlocked(),
    }))
}

/// POST /api/vault/create — create a new vault with password.
pub async fn api_vault_create(
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
        Ok(()) => {
            ensure_server_key_in_vault(&state);
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "message": "Vault created and unlocked."
            })))
        }
        Err(e) => (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": e
        }))),
    }
}

/// POST /api/vault/unlock — unlock vault with password.
pub async fn api_vault_unlock(
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
        Ok(()) => {
            ensure_server_key_in_vault(&state);
            (StatusCode::OK, Json(serde_json::json!({
                "success": true
            })))
        }
        Err(e) => (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": e
        }))),
    }
}

/// POST /api/vault/lock — lock the vault (clear in-memory keys).
pub async fn api_vault_lock(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    state.vault.lock();
    Json(serde_json::json!({ "success": true }))
}

/// GET /api/vault/keys — list keys (public info, no secrets).
pub async fn api_vault_keys(
    State(state): State<Arc<DashboardState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.vault.list_keys() {
        Ok(keys) => (StatusCode::OK, Json(serde_json::json!({ "keys": keys }))),
        Err(e) => (StatusCode::LOCKED, Json(serde_json::json!({ "error": e }))),
    }
}

/// POST /api/vault/add — add a key to the vault.
pub async fn api_vault_add(
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
pub async fn api_vault_export(
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
pub async fn api_vault_delete(
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
pub async fn api_vault_rename(
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
pub async fn api_vault_export_all(
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
pub async fn api_vault_import(
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

/// POST /api/vault/generate — generate a random Ed25519 keypair and add to vault.
pub async fn api_vault_generate(
    State(state): State<Arc<DashboardState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Generate a random pkarr keypair
    let kp = pkarr::Keypair::random();
    let secret_hex = hex::encode(&kp.secret_key()[..32]);
    let pubkey = kp.public_key().to_string();

    match state.vault.add_key("Generated Key", &secret_hex, "pkarr", &pubkey) {
        Ok(info) => (StatusCode::OK, Json(serde_json::json!({
            "success": true,
            "key": info
        }))),
        Err(e) => (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": e
        }))),
    }
}
