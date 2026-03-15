//! Backup API handlers.
//!
//! CRUD operations for the backup manager: start/stop backups,
//! view status, list backups, verify integrity, export bundles.

use super::state::DashboardState;
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use std::sync::Arc;

/// GET /api/backup/status — current backup status summary.
pub async fn api_backup_status(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    Json(state.backup.global_status())
}

/// GET /api/backup/list — list all backed-up identities with their status.
pub async fn api_backup_list(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    let backups = state.backup.list();
    Json(serde_json::json!({ "backups": backups }))
}

/// POST /api/backup/start — add a pubky to the backup list.
pub async fn api_backup_start(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let pubky = match body.get("pubky").and_then(|v| v.as_str()) {
        Some(p) if !p.is_empty() => p,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "pubky is required."
        }))),
    };

    match state.backup.add_pubky(pubky) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({
            "success": true,
            "message": format!("Backup started for {}", pubky)
        }))),
        Err(e) => (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": e
        }))),
    }
}

/// POST /api/backup/stop — remove a pubky from the backup list.
pub async fn api_backup_stop(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let pubky = match body.get("pubky").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "pubky is required."
        }))),
    };

    match state.backup.remove_pubky(pubky) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({
            "success": true,
            "message": format!("Backup stopped for {}", pubky)
        }))),
        Err(e) => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": e
        }))),
    }
}

/// POST /api/backup/force-sync — trigger immediate sync for a pubky.
pub async fn api_backup_force_sync(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let pubky = match body.get("pubky").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "pubky is required."
        }))),
    };

    match state.backup.force_sync(pubky) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({
            "success": true,
            "message": "Sync triggered — running in background"
        }))),
        Err(e) => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": e
        }))),
    }
}

/// POST /api/backup/sync-all — trigger immediate sync for ALL pubkeys.
pub async fn api_backup_sync_all(
    State(state): State<Arc<DashboardState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.backup.force_sync_all() {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({
            "success": true,
            "message": "Sync-all triggered — running in background"
        }))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": e
        }))),
    }
}

/// POST /api/backup/verify — verify integrity of backup data.
pub async fn api_backup_verify(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let pubky = match body.get("pubky").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "pubky is required."
        }))),
    };

    match state.backup.verify(pubky) {
        Ok(result) => (StatusCode::OK, Json(result)),
        Err(e) => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": e
        }))),
    }
}

/// POST /api/backup/export — create a recovery bundle.
pub async fn api_backup_export(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let pubky = match body.get("pubky").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "pubky is required."
        }))),
    };

    let include_keys = body.get("include_keys").and_then(|v| v.as_bool()).unwrap_or(false);

    match state.backup.export_bundle(pubky, include_keys, &state.vault) {
        Ok(bundle) => (StatusCode::OK, Json(bundle)),
        Err(e) => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": e
        }))),
    }
}

/// POST /api/backup/migrate — re-publish PKARR record pointing to new homeserver.
pub async fn api_backup_migrate(
    State(_state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let _pubky = match body.get("pubky").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "pubky is required."
        }))),
    };

    let _new_homeserver = match body.get("new_homeserver").and_then(|v| v.as_str()) {
        Some(h) => h,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "new_homeserver URL is required."
        }))),
    };

    // TODO: Re-publish PKARR record pointing to new homeserver
    // This requires fetching the key from vault, building a new DNS packet
    // with the new homeserver URL, and publishing to DHT.
    (StatusCode::NOT_IMPLEMENTED, Json(serde_json::json!({
        "error": "Migration requires manual PKARR record update. Use the Keys tab to re-publish DNS records pointing to the new homeserver."
    })))
}

/// POST /api/backup/open-dir — open the backup directory in the system file manager.
pub async fn api_backup_open_dir(
    State(state): State<Arc<DashboardState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let dir = state.backup.backup_dir();
    if !dir.exists() {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "Backup directory does not exist yet."
        })));
    }
    let dir_str = dir.to_string_lossy().to_string();
    tokio::spawn(async move {
        let _ = tokio::process::Command::new("open")
            .arg(&dir_str)
            .output()
            .await;
    });
    (StatusCode::OK, Json(serde_json::json!({ "opened": true })))
}

/// POST /api/backup/snapshot — create a snapshot of a pubky's backup data.
pub async fn api_backup_snapshot_create(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let pubky = match body.get("pubky").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "pubky is required."
        }))),
    };
    match state.backup.create_snapshot(pubky) {
        Ok(info) => (StatusCode::OK, Json(info)),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))),
    }
}

/// GET /api/backup/snapshots — list all snapshots.
pub async fn api_backup_snapshot_list(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    let snapshots = state.backup.list_snapshots(None);
    Json(serde_json::json!({ "snapshots": snapshots }))
}

/// POST /api/backup/snapshot/restore — restore a snapshot.
pub async fn api_backup_snapshot_restore(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let pubky = match body.get("pubky").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "pubky is required." }))),
    };
    let timestamp = match body.get("timestamp").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "timestamp is required." }))),
    };
    match state.backup.restore_snapshot(pubky, timestamp) {
        Ok(info) => (StatusCode::OK, Json(info)),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))),
    }
}

/// DELETE /api/backup/snapshot — delete a snapshot.
pub async fn api_backup_snapshot_delete(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let pubky = match body.get("pubky").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "pubky is required." }))),
    };
    let timestamp = match body.get("timestamp").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "timestamp is required." }))),
    };
    match state.backup.delete_snapshot(pubky, timestamp) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "deleted": true }))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))),
    }
}
