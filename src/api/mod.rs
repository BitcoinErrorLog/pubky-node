//! API module — unified router and handler modules for the dashboard REST API.
//!
//! This module provides `build_router()` as the single source of truth for all
//! API routes. Both the production dashboard and test harness use this function,
//! eliminating route duplication.

pub mod state;
pub mod auth;
pub mod vault;
pub mod watchlist;
pub mod homeserver;
pub mod quickstart;
pub mod tunnel;
pub mod identity;
pub mod network;
pub mod keys;
pub mod reachability;
pub mod backup;
pub mod migration;
pub mod profile;
pub mod layout;
use state::DashboardState;
use std::sync::{Arc, RwLock};
use axum::{
    extract::Extension,
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post, delete},
    Router,
};

// Re-exports for external use
pub use state::SharedWatchlistKeys;
pub use watchlist::{load_watchlist_keys, save_watchlist_keys};

/// Build the complete API router with all routes.
///
/// This is the **single source of truth** for route definitions.
/// Used by both `start_dashboard()` (production) and `build_test_router()` (tests).
pub fn build_router(
    state: Arc<DashboardState>,
    shared_auth: Arc<RwLock<Option<String>>>,
) -> Router {
    Router::new()
        // Static assets and health
        .route("/", get(serve_dashboard))
        .route("/health", get(network::health_check))
        .route("/dashboard.js", get(serve_js))
        .route("/dashboard.css", get(serve_css))
        .route("/qrcode.min.js", get(serve_qr_js))
        // Auth
        .route("/api/auth/check", get(auth::api_auth_check))
        .route("/api/auth/setup", post(auth::api_auth_setup))
        .route("/api/auth/login", post(auth::api_auth_login))
        .route("/api/auth/change-password", post(auth::api_auth_change_password))
        .route("/api/settings", get(auth::api_settings))
        // Vault
        .route("/api/vault/create", post(vault::api_vault_create))
        .route("/api/vault/unlock", post(vault::api_vault_unlock))
        .route("/api/vault/lock", post(vault::api_vault_lock))
        .route("/api/vault/keys", get(vault::api_vault_keys))
        .route("/api/vault/add", post(vault::api_vault_add))
        .route("/api/vault/export", post(vault::api_vault_export))
        .route("/api/vault/export-all", get(vault::api_vault_export_all))
        .route("/api/vault/import", post(vault::api_vault_import))
        .route("/api/vault/rename", post(vault::api_vault_rename))
        .route("/api/vault/delete/{pubkey}", delete(vault::api_vault_delete))
        .route("/api/vault/status", get(vault::api_vault_status))
        .route("/api/vault/generate", post(vault::api_vault_generate))
        // Homeserver
        .route("/api/homeserver/status", get(homeserver::api_hs_status))
        .route("/api/homeserver/start", post(homeserver::api_hs_start))
        .route("/api/homeserver/stop", post(homeserver::api_hs_stop))
        .route("/api/homeserver/info", get(homeserver::api_hs_info))
        .route("/api/homeserver/signup-token", get(homeserver::api_hs_signup_token))
        .route("/api/homeserver/setup-check", get(homeserver::api_hs_setup_check))
        .route("/api/homeserver/config", get(homeserver::api_hs_config).post(homeserver::api_hs_config_save))
        .route("/api/homeserver/generate-config", post(homeserver::api_hs_generate_config))
        .route("/api/homeserver/logs", get(homeserver::api_hs_logs))
        .route("/api/homeserver/fix", post(homeserver::api_hs_fix))
        .route("/api/homeserver/proxy-url", get(homeserver::api_hs_proxy_url))
        .route("/api/homeserver/publish-pkarr", post(homeserver::api_hs_publish_pkarr))
        .route("/api/homeserver/set-key", post(homeserver::api_hs_set_key))
        .route("/api/quickstart", post(quickstart::api_quickstart))
        .route("/api/homeserver/users", get(homeserver::api_hs_users))
        .route("/api/homeserver/users/{pubkey}/quota", post(homeserver::api_hs_set_user_quota))
        .route("/hs", get(homeserver::api_hs_icann_proxy))
        .route("/hs/", get(homeserver::api_hs_icann_proxy))
        .route("/hs/{*path}", get(homeserver::api_hs_icann_proxy).post(homeserver::api_hs_icann_proxy).put(homeserver::api_hs_icann_proxy).delete(homeserver::api_hs_icann_proxy))
        // Identity
        .route("/api/identity/signup", post(identity::api_identity_signup))
        .route("/api/identity/signin", post(identity::api_identity_signin))
        .route("/api/identity/list", get(identity::api_identity_list))
        // Profile
        .route("/api/profile/{pubkey}", get(profile::api_profile_get).put(profile::api_profile_put))
        .route("/api/profile/{pubkey}/nexus", get(profile::api_profile_nexus))
        .route("/api/profile/{pubkey}/nexus-submit", post(profile::api_profile_nexus_submit))
        .route("/api/profile/{pubkey}/verify", get(profile::api_profile_verify))
        // Tunnel
        .route("/api/tunnel/status", get(tunnel::api_tunnel_status))
        .route("/api/tunnel/start", post(tunnel::api_tunnel_start))
        .route("/api/tunnel/stop", post(tunnel::api_tunnel_stop))
        .route("/api/tunnel/check", get(tunnel::api_tunnel_check))
        .route("/api/relay-tunnel/status", get(tunnel::api_relay_tunnel_status))
        .route("/api/relay-tunnel/start", post(tunnel::api_relay_tunnel_start))
        .route("/api/relay-tunnel/stop", post(tunnel::api_relay_tunnel_stop))
        .route("/api/dns-tunnel/status", get(tunnel::api_dns_tunnel_status))
        .route("/api/dns-tunnel/start", post(tunnel::api_dns_tunnel_start))
        .route("/api/dns-tunnel/stop", post(tunnel::api_dns_tunnel_stop))
        .route("/api/logs/stream", get(tunnel::api_logs_stream))
        // Network / Status / DNS
        .route("/api/status", get(network::api_status))
        .route("/api/resolve/{public_key}", get(network::api_resolve))
        .route("/api/dns/toggle", post(network::api_dns_toggle))
        .route("/api/dns/set-system", post(network::api_dns_set_system))
        .route("/api/dns/reset-system", post(network::api_dns_reset_system))
        .route("/api/node/shutdown", post(network::api_shutdown))
        .route("/api/node/restart", post(network::api_restart))
        .route("/api/proxy/setup-hosts", post(network::api_proxy_setup_hosts))
        .route("/api/proxy/reset-hosts", post(network::api_proxy_reset_hosts))
        .route("/api/proxy/hosts-status", get(network::api_proxy_hosts_status))
        .route("/api/publish", post(network::api_publish))
        // Reachability
        .route("/api/reachability-check", get(reachability::api_reachability_check))
        // Backup
        .route("/api/backup/status", get(backup::api_backup_status))
        .route("/api/backup/list", get(backup::api_backup_list))
        .route("/api/backup/start", post(backup::api_backup_start))
        .route("/api/backup/stop", post(backup::api_backup_stop))
        .route("/api/backup/force-sync", post(backup::api_backup_force_sync))
        .route("/api/backup/sync-all", post(backup::api_backup_sync_all))
        .route("/api/backup/verify", post(backup::api_backup_verify))
        .route("/api/backup/export", post(backup::api_backup_export))
        .route("/api/backup/migrate", post(backup::api_backup_migrate))
        .route("/api/backup/open-dir", post(backup::api_backup_open_dir))
        .route("/api/backup/snapshot", post(backup::api_backup_snapshot_create))
        .route("/api/backup/snapshots", get(backup::api_backup_snapshot_list))
        .route("/api/backup/snapshot/restore", post(backup::api_backup_snapshot_restore))
        .route("/api/backup/snapshot/delete", post(backup::api_backup_snapshot_delete))
        // Migration
        .route("/api/migration/preflight", post(migration::api_migration_preflight))
        .route("/api/migration/execute", post(migration::api_migration_execute))
        .route("/api/migration/status", get(migration::api_migration_status))
        // Watchlist
        .route("/api/watchlist", post(watchlist::api_watchlist_add).get(watchlist::api_watchlist_list))
        .route("/api/watchlist/{key}", delete(watchlist::api_watchlist_remove))
        // Keys / Vanity
        .route("/api/keys/vanity/start", post(keys::api_vanity_start))
        .route("/api/keys/vanity/status", get(keys::api_vanity_status))
        .route("/api/keys/vanity/stop", post(keys::api_vanity_stop))
        // Layout
        .route("/api/layout", get(layout::api_layout_get).put(layout::api_layout_put))
        .route("/api/layout/reset", post(layout::api_layout_reset))
        // Middleware
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn(auth_check))
        .layer(Extension(shared_auth))
        .with_state(state)
}

// ─── Static asset serving ───────────────────────────────────────

async fn serve_dashboard() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
        ],
        include_str!("../dashboard.html"),
    )
}

async fn serve_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/javascript"),
            (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
        ],
        include_str!("../dashboard.js"),
    )
}

async fn serve_css() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/css"),
            (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
        ],
        include_str!("../dashboard.css"),
    )
}

async fn serve_qr_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/javascript")],
        include_str!("../qrcode.min.js"),
    )
}

// ─── Middleware ──────────────────────────────────────────────────

/// Middleware that adds security headers to all responses.
async fn security_headers(
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        "X-Frame-Options",
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static(
            "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self'; connect-src 'self' http://localhost:6881"
        ),
    );
    headers.insert(
        "Referrer-Policy",
        HeaderValue::from_static("no-referrer"),
    );
    response
}

/// Middleware: check auth on protected routes.
async fn auth_check(
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if path == "/"
        || path == "/health"
        || path.starts_with("/api/auth/")
        || path == "/dashboard.js"
        || path == "/dashboard.css"
        || path == "/qrcode.min.js"
        || path.starts_with("/hs")
    {
        return next.run(request).await;
    }

    let hash_opt = request.extensions()
        .get::<Arc<RwLock<Option<String>>>>()
        .and_then(|h| h.read().ok())
        .and_then(|guard| guard.clone());

    let hash = match hash_opt {
        Some(h) => h,
        None => {
            return next.run(request).await;
        }
    };

    if let Some(pw) = request.headers().get("X-Auth-Password").and_then(|v| v.to_str().ok()) {
        if auth::verify_password(pw, &hash) {
            return next.run(request).await;
        }
    }

    if let Some((_user, pass)) = auth::extract_basic_auth(&request) {
        if auth::verify_password(&pass, &hash) {
            return next.run(request).await;
        }
    }

    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from("{\"error\":\"Unauthorized\"}"))
        .unwrap()
}
