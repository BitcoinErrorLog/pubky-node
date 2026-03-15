//! Authentication API handlers.
//!
//! Handles password setup, login, and change for the dashboard.

use super::state::DashboardState;
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use std::sync::Arc;
use tracing::info;

// ─── Auth helpers ───────────────────────────────────────────────

/// Auth configuration stored on disk at `~/.pubky-node/auth.json`
#[derive(serde::Serialize, serde::Deserialize)]
struct AuthConfig {
    password_hash: String,
}

pub fn auth_config_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("auth.json")
}

pub fn load_auth_config(data_dir: &std::path::Path) -> Option<AuthConfig> {
    let path = auth_config_path(data_dir);
    let data = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&data).ok()
}

/// Load just the auth hash string from disk, if set.
pub fn load_auth_hash(data_dir: &std::path::Path) -> Option<String> {
    load_auth_config(data_dir).map(|c| c.password_hash)
}

fn save_auth_config(data_dir: &std::path::Path, config: &AuthConfig) -> Result<(), String> {
    let path = auth_config_path(data_dir);
    let data = serde_json::to_string_pretty(config).map_err(|e| e.to_string())?;
    std::fs::write(&path, data).map_err(|e| e.to_string())
}

pub fn hash_password(password: &str) -> Result<String, String> {
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::{Argon2, PasswordVerifier, PasswordHash};
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

/// Extract Basic Auth credentials from request header.
pub fn extract_basic_auth(req: &axum::extract::Request) -> Option<(String, String)> {
    use axum::http::header;
    let header_val = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = header_val.strip_prefix("Basic ")?;
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    let (user, pass) = decoded_str.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

// ─── Handlers ───────────────────────────────────────────────────

/// GET /api/auth/check — returns whether a password is configured.
pub async fn api_auth_check(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    let has_password = state.auth_hash.read()
        .map(|guard| guard.is_some())
        .unwrap_or(false);
    Json(serde_json::json!({
        "has_password": has_password
    }))
}

/// POST /api/auth/setup — set the dashboard password (first-run only).
pub async fn api_auth_setup(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Reject if password already set
    let already_set = state.auth_hash.read()
        .map(|guard| guard.is_some())
        .unwrap_or(false);
    if already_set {
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

    if let Ok(mut guard) = state.auth_hash.write() {
        *guard = Some(hash);
    }
    info!("Dashboard password set successfully");

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "message": "Password set. The dashboard now requires authentication."
    })))
}

/// POST /api/auth/login — validate password.
pub async fn api_auth_login(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let password = match body.get("password").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Password required."
        }))),
    };

    let hash = state.auth_hash.read().ok().and_then(|guard| guard.clone());
    match hash {
        Some(h) if verify_password(password, &h) => {
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
pub async fn api_auth_change_password(
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
    let current_hash = state.auth_hash.read().ok().and_then(|guard| guard.clone());
    match current_hash {
        Some(h) if verify_password(current_pw, &h) => {},
        _ => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Current password is incorrect."
        }))),
    }

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

    if let Ok(mut guard) = state.auth_hash.write() {
        *guard = Some(new_hash);
    }
    info!("Dashboard password changed successfully");

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "message": "Password changed successfully."
    })))
}

/// GET /api/settings — return data directory paths and platform info.
pub async fn api_settings(
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
