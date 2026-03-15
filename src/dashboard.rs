//! Web dashboard and REST API server.
//!
//! This file is now a thin wrapper that delegates to the `api` module.
//! All handler functions, state, and route definitions live in `src/api/`.

use crate::api;
use crate::api::state::DashboardState;

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use pkarr::Client;
use tokio::task::JoinHandle;
use tokio::sync::broadcast;
use tracing::info;

use crate::config::WatchlistConfig;
use crate::upnp::UpnpStatus;

pub use api::state::SharedWatchlistKeys;
pub use api::watchlist::{load_watchlist_keys, save_watchlist_keys};
pub use api::keys::z32_encode;

/// Starts the web dashboard HTTP server.
/// Returns the join handle for the server task.
pub fn start_dashboard(
    port: u16,
    bind_addr: [u8; 4],
    relay_port: u16,
    client: Option<Client>,
    watchlist_config: WatchlistConfig,
    shared_keys: SharedWatchlistKeys,
    data_dir: PathBuf,
    upnp_status: UpnpStatus,
    dns_status: String,
    dns_socket: String,
    dns_forward: String,
) -> JoinHandle<()> {
    // Load existing auth config if present
    let loaded_hash = api::auth::load_auth_hash(&data_dir);

    if loaded_hash.is_some() {
        info!("Dashboard auth: password configured");
    } else {
        info!("Dashboard auth: no password set — setup required on first visit");
    }

    let auth_hash: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(loaded_hash));
    let (log_tx, _) = broadcast::channel::<String>(1000);

    let state = DashboardState::new(
        client,
        watchlist_config,
        shared_keys,
        data_dir,
        relay_port,
        upnp_status,
        dns_status,
        dns_socket,
        dns_forward,
        auth_hash.clone(),
        log_tx,
    );

    // Start HTTP proxy for .pkarr domains
    let proxy_state = state.clone();
    tokio::spawn(async move {
        api::network::start_http_proxy(proxy_state).await;
    });

    let shared_auth = auth_hash;
    let app = api::build_router(state, shared_auth);

    let addr = std::net::SocketAddr::from((bind_addr, port));
    info!("Dashboard listening on http://{}/", addr);

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .expect("failed to bind dashboard port");
        axum::serve(listener, app)
            .await
            .expect("dashboard server error");
    })
}

// ─── Test helpers & integration tests ───────────────────────────

/// Build a fully-wired router + state from a temp data directory.
/// Uses `api::build_router()` — same unified router as production.
#[cfg(test)]
fn build_test_router(data_dir: &std::path::Path) -> axum::Router {
    use crate::api::state::DashboardState;
    use crate::config::WatchlistConfig;
    use crate::upnp::UpnpStatus;

    let auth_hash: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(None));
    let shared_keys: SharedWatchlistKeys = Arc::new(RwLock::new(Vec::new()));
    let (log_tx, _) = broadcast::channel::<String>(100);

    let state = DashboardState::new(
        None,
        WatchlistConfig::default(),
        shared_keys,
        data_dir.to_path_buf(),
        8080,
        UpnpStatus::Disabled,
        "Disabled".to_string(),
        "127.0.0.1:5300".to_string(),
        "1.1.1.1:53".to_string(),
        auth_hash.clone(),
        log_tx,
    );

    api::build_router(state, auth_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode, Method, header},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt; // for `.oneshot()`

    // ─── Helpers ──────────────────────────────────────────────────

    async fn response_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    fn get(path: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(path)
            .body(Body::empty())
            .unwrap()
    }

    fn post_json(path: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn delete_req(path: &str) -> Request<Body> {
        Request::builder()
            .method(Method::DELETE)
            .uri(path)
            .body(Body::empty())
            .unwrap()
    }

    // Produce a valid 52-char z-base-32 pkarr public key string for testing.
    fn valid_pkarr_key() -> String {
        pkarr::Keypair::random().public_key().to_string()
    }

    // ─── Health ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_health_check_returns_ok() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/health")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"ok");
    }

    // ─── Auth ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_auth_check_no_password_set() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/auth/check")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert_eq!(j["has_password"], false);
    }

    #[tokio::test]
    async fn test_auth_setup_too_short_password() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(post_json("/api/auth/setup", serde_json::json!({"password": "abc"}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_auth_setup_success_then_login() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());

        // Setup
        let resp = app.clone().oneshot(post_json("/api/auth/setup", serde_json::json!({"password": "hunter2"}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert_eq!(j["success"], true);

        // auth/check should now report has_password=true
        let resp2 = app.clone().oneshot(get("/api/auth/check")).await.unwrap();
        let j2 = response_json(resp2).await;
        assert_eq!(j2["has_password"], true);

        // Valid login
        let resp3 = app.clone().oneshot(post_json("/api/auth/login", serde_json::json!({"password": "hunter2"}))).await.unwrap();
        assert_eq!(resp3.status(), StatusCode::OK);

        // Wrong password login
        let resp4 = app.oneshot(post_json("/api/auth/login", serde_json::json!({"password": "wrong"}))).await.unwrap();
        assert_eq!(resp4.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_setup_twice_rejected() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        app.clone().oneshot(post_json("/api/auth/setup", serde_json::json!({"password": "first1"}))).await.unwrap();
        let resp = app.oneshot(post_json("/api/auth/setup", serde_json::json!({"password": "second1"}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    // ─── Watchlist ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_watchlist_empty_initially() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/watchlist")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert_eq!(j["count"], 0);
        assert!(j["keys"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_watchlist_add_valid_key() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let key = valid_pkarr_key();
        let resp = app.oneshot(post_json("/api/watchlist", serde_json::json!({"key": key}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert_eq!(j["count"], 1);
    }

    #[tokio::test]
    async fn test_watchlist_add_invalid_key_rejected() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(post_json("/api/watchlist", serde_json::json!({"key": "not-a-valid-key"}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_watchlist_add_then_list_then_remove() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let key = valid_pkarr_key();

        // Add
        app.clone().oneshot(post_json("/api/watchlist", serde_json::json!({"key": key.clone()}))).await.unwrap();

        // List — should have 1
        let list_resp = app.clone().oneshot(get("/api/watchlist")).await.unwrap();
        let j = response_json(list_resp).await;
        assert_eq!(j["count"], 1);

        // Remove
        let rm_resp = app.clone().oneshot(delete_req(&format!("/api/watchlist/{}", key))).await.unwrap();
        assert_eq!(rm_resp.status(), StatusCode::OK);
        let j2 = response_json(rm_resp).await;
        assert_eq!(j2["count"], 0);
    }

    #[tokio::test]
    async fn test_watchlist_add_duplicate_ignored() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let key = valid_pkarr_key();

        app.clone().oneshot(post_json("/api/watchlist", serde_json::json!({"key": key.clone()}))).await.unwrap();
        let resp2 = app.oneshot(post_json("/api/watchlist", serde_json::json!({"key": key}))).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let j = response_json(resp2).await;
        // Duplicate not added — still 1
        assert_eq!(j["count"], 1);
    }

    #[tokio::test]
    async fn test_watchlist_accepts_pubky_uri_prefix() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let key = valid_pkarr_key();
        let uri = format!("pubky://{}", key);
        let resp = app.oneshot(post_json("/api/watchlist", serde_json::json!({"key": uri}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert_eq!(j["count"], 1);
    }

    // ─── Vault ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_vault_status_no_vault() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/vault/status")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert_eq!(j["exists"], false);
        assert_eq!(j["unlocked"], false);
    }

    #[tokio::test]
    async fn test_vault_create_success() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(post_json("/api/vault/create", serde_json::json!({"password": "vault_pw"}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert_eq!(j["success"], true);
    }

    #[tokio::test]
    async fn test_vault_create_short_password_rejected() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(post_json("/api/vault/create", serde_json::json!({"password": "pw"}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_vault_create_then_status_shows_unlocked() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        app.clone().oneshot(post_json("/api/vault/create", serde_json::json!({"password": "testpass"}))).await.unwrap();
        let resp = app.oneshot(get("/api/vault/status")).await.unwrap();
        let j = response_json(resp).await;
        assert_eq!(j["exists"], true);
        assert_eq!(j["unlocked"], true);
    }

    #[tokio::test]
    async fn test_vault_lock_then_status_shows_locked() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        app.clone().oneshot(post_json("/api/vault/create", serde_json::json!({"password": "testpass"}))).await.unwrap();
        app.clone().oneshot(post_json("/api/vault/lock", serde_json::json!({}))).await.unwrap();
        let resp = app.oneshot(get("/api/vault/status")).await.unwrap();
        let j = response_json(resp).await;
        assert_eq!(j["exists"], true);
        assert_eq!(j["unlocked"], false);
    }

    #[tokio::test]
    async fn test_vault_unlock_wrong_password() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        app.clone().oneshot(post_json("/api/vault/create", serde_json::json!({"password": "correct_pw"}))).await.unwrap();
        app.clone().oneshot(post_json("/api/vault/lock", serde_json::json!({}))).await.unwrap();
        let resp = app.oneshot(post_json("/api/vault/unlock", serde_json::json!({"password": "wrong_pw"}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_vault_keys_locked_returns_423() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/vault/keys")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::LOCKED);
    }

    #[tokio::test]
    async fn test_vault_add_list_delete_rename_flow() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());

        let kp = pkarr::Keypair::random();
        let secret_hex = hex::encode(&kp.secret_key()[..32]);
        let pubkey = kp.public_key().to_string();

        // Create vault
        app.clone().oneshot(post_json("/api/vault/create", serde_json::json!({"password": "pw1234"}))).await.unwrap();

        // Add key
        let add_resp = app.clone().oneshot(post_json("/api/vault/add", serde_json::json!({
            "name": "Test Key",
            "secret_hex": secret_hex,
            "key_type": "pkarr",
            "pubkey": pubkey,
        }))).await.unwrap();
        assert_eq!(add_resp.status(), StatusCode::OK);
        let j = response_json(add_resp).await;
        assert_eq!(j["success"], true);
        assert_eq!(j["key"]["pubkey"], pubkey);

        // List keys — should have 1
        let list_resp = app.clone().oneshot(get("/api/vault/keys")).await.unwrap();
        let lj = response_json(list_resp).await;
        assert_eq!(lj["keys"].as_array().unwrap().len(), 1);
        assert!(lj["keys"][0].get("secret_hex").is_none(), "secret must not appear in list");

        // Rename
        let rename_resp = app.clone().oneshot(post_json("/api/vault/rename", serde_json::json!({
            "pubkey": pubkey,
            "name": "Renamed Key",
        }))).await.unwrap();
        assert_eq!(rename_resp.status(), StatusCode::OK);

        // Verify rename
        let list2 = app.clone().oneshot(get("/api/vault/keys")).await.unwrap();
        let lj2 = response_json(list2).await;
        assert_eq!(lj2["keys"][0]["name"], "Renamed Key");

        // Delete
        let del_resp = app.clone().oneshot(delete_req(&format!("/api/vault/delete/{}", pubkey))).await.unwrap();
        assert_eq!(del_resp.status(), StatusCode::OK);

        // List again — empty
        let list3 = app.oneshot(get("/api/vault/keys")).await.unwrap();
        let lj3 = response_json(list3).await;
        assert!(lj3["keys"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_vault_add_short_secret_rejected() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        app.clone().oneshot(post_json("/api/vault/create", serde_json::json!({"password": "pw1234"}))).await.unwrap();
        let resp = app.oneshot(post_json("/api/vault/add", serde_json::json!({
            "name": "Bad",
            "secret_hex": "tooshort",
            "key_type": "manual",
            "pubkey": "anypubkey",
        }))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_vault_export_all_format() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        app.clone().oneshot(post_json("/api/vault/create", serde_json::json!({"password": "pw1234"}))).await.unwrap();
        let resp = app.oneshot(get("/api/vault/export-all")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert_eq!(j["format"], "pubky-vault-backup-v1");
        assert!(j["keys"].is_array());
    }

    // ─── Homeserver ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_homeserver_status_returns_valid_shape() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/homeserver/status")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert!(j.get("state").is_some(), "homeserver status must have 'state' field");
        assert!(j.get("ports").is_some(), "homeserver status must have 'ports' field");
    }

    #[tokio::test]
    async fn test_homeserver_setup_check_returns_valid_shape() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/homeserver/setup-check")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v.is_object(), "setup-check must return a JSON object");
    }

    #[tokio::test]
    async fn test_homeserver_config_returns_shape() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/homeserver/config")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert!(j.get("signup_mode").is_some());
        assert!(j.get("drive_icann_port").is_some());
    }

    #[tokio::test]
    async fn test_homeserver_logs_returns_shape() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/homeserver/logs")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert!(j.get("lines").is_some());
        assert!(j["lines"].is_array());
    }

    // ─── Tunnel ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_tunnel_status_returns_shape() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/tunnel/status")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert!(j.get("running").is_some() || j.get("state").is_some() || j.get("status").is_some(),
            "tunnel status must have a running/state/status field, got: {}", j);
    }

    #[tokio::test]
    async fn test_tunnel_check_returns_shape() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/tunnel/check")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert!(j.get("available").is_some(), "tunnel/check must have 'available' field");
    }

    // ─── Node Status ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_api_status_returns_valid_shape() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/status")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert!(j.get("version").is_some(), "status must include version");
        assert!(j.get("uptime_secs").is_some(), "status must include uptime_secs");
        assert!(j.get("watchlist").is_some(), "status must include watchlist");
        assert!(j.get("relay_port").is_some(), "status must include relay_port");
    }

    // ─── Settings ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_settings_returns_data_dir() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/settings")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert!(j.get("data_dir").is_some());
        assert!(j.get("platform").is_some());
    }

    // ─── Identity ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_identity_list_empty_initially() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/identity/list")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert!(j.get("identities").is_some());
        assert!(j["identities"].as_array().unwrap().is_empty());
    }
    // ─── Reachability ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_reachability_check_returns_shape() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/reachability-check")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert!(j.get("relay_reachable").is_some(), "must have relay_reachable field");
        assert!(j.get("tunnel_active").is_some(), "must have tunnel_active field");
        assert!(j.get("dht_healthy").is_some(), "must have dht_healthy field");
        assert!(j.get("suggestion").is_some(), "must have suggestion field");
    }

    #[tokio::test]
    async fn test_reachability_check_without_client() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/reachability-check")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        // Without a real DHT client, dht_healthy should be false
        assert_eq!(j["dht_healthy"].as_bool(), Some(false));
        // Tunnel should be inactive in test
        assert_eq!(j["tunnel_active"].as_bool(), Some(false));
    }
    // ─── Backup ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_backup_status_returns_shape() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/backup/status")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert!(j.get("backup_count").is_some(), "must have backup_count");
        assert!(j.get("active_syncs").is_some(), "must have active_syncs");
        assert!(j.get("total_size").is_some(), "must have total_size");
    }

    #[tokio::test]
    async fn test_backup_list_empty_initially() {
        let td = tempfile::tempdir().unwrap();
        let app = build_test_router(td.path());
        let resp = app.oneshot(get("/api/backup/list")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_json(resp).await;
        assert!(j["backups"].as_array().unwrap().is_empty());
    }
}
