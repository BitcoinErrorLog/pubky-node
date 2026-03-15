// API endpoints for homeserver migration.

use std::sync::Arc;
use axum::{extract::State, http::StatusCode, Json};
use crate::api::state::DashboardState;
use crate::migration::{self, PreflightRequest};

/// POST /api/migration/preflight — validate migration inputs.
pub async fn api_migration_preflight(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<PreflightRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let result = migration::run_preflight(
        &state.backup,
        &state.vault,
        &body.pubky,
        &body.target_homeserver,
        &body.source,
    );

    (StatusCode::OK, Json(serde_json::json!({
        "ok": result.ok,
        "checks": result.checks,
        "file_count": result.file_count,
        "total_bytes": result.total_bytes,
    })))
}

/// POST /api/migration/execute — start the migration pipeline.
pub async fn api_migration_execute(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let pubky = match body.get("pubky").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "pubky required" }))),
    };
    let target = match body.get("target_homeserver").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "target_homeserver required" }))),
    };
    let source = body.get("source").and_then(|v| v.as_str()).unwrap_or("latest").to_string();
    let signup_token = body.get("signup_token").and_then(|v| v.as_str()).map(|s| s.to_string());
    let dry_run = body.get("dry_run").and_then(|v| v.as_bool()).unwrap_or(false);

    // Check if a migration is already running
    {
        let ms = state.migration_state.read().unwrap();
        if ms.phase != "idle" && ms.phase != "done" && ms.phase != "error" {
            return (StatusCode::CONFLICT, Json(serde_json::json!({
                "error": format!("Migration already in progress (phase: {})", ms.phase)
            })));
        }
    }

    // Clone what we need for the background task
    let dashboard = state.clone();

    tokio::spawn(migration::execute_migration(
        dashboard,
        pubky,
        target,
        source,
        signup_token,
        dry_run,
    ));

    (StatusCode::OK, Json(serde_json::json!({ "started": true })))
}

/// GET /api/migration/status — current migration progress.
pub async fn api_migration_status(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    let ms = state.migration_state.read().unwrap();
    Json(serde_json::json!({
        "phase": ms.phase,
        "total_files": ms.total_files,
        "uploaded_files": ms.uploaded_files,
        "total_bytes": ms.total_bytes,
        "uploaded_bytes": ms.uploaded_bytes,
        "error": ms.error,
        "dry_run": ms.dry_run,
        "target_homeserver": ms.target_homeserver,
        "target_pubkey": ms.target_pubkey,
        "source_pubky": ms.source_pubky,
    }))
}
