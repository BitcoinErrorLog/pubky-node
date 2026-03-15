//! Layout API — GET/PUT/POST endpoints for dashboard layout customization.

use std::sync::Arc;
use axum::extract::State;
use axum::Json;
use crate::api::state::DashboardState;
use crate::layout;

/// GET /api/layout — returns current layout
pub async fn api_layout_get(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    let layout = layout::load_layout(&state.data_dir);
    Json(serde_json::to_value(&layout).unwrap_or_default())
}

/// PUT /api/layout — save updated layout
pub async fn api_layout_put(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let layout: layout::Layout = match serde_json::from_value(body) {
        Ok(l) => l,
        Err(e) => return Json(serde_json::json!({ "status": "error", "error": e.to_string() })),
    };
    match layout::save_layout(&state.data_dir, &layout) {
        Ok(()) => Json(serde_json::json!({ "status": "ok" })),
        Err(e) => Json(serde_json::json!({ "status": "error", "error": e.to_string() })),
    }
}

/// POST /api/layout/reset — reset to default layout
pub async fn api_layout_reset(
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    let layout = layout::reset_layout(&state.data_dir);
    Json(serde_json::to_value(&layout).unwrap_or_default())
}
