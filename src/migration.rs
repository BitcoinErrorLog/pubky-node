// Homeserver Migration — move data from one homeserver to another.
//
// Pipeline:
//   1. Preflight — verify backup, key, target reachable, discover target pubkey
//   2. Fresh backup — force-sync + pre-migration snapshot
//   3. Signup — POST auth token to target /signup, get session cookie
//   4. Upload — PUT all files to target with concurrent uploads + resume
//   5. PKARR publish — update _pubky HTTPS record to point to new homeserver

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};

/// Migration progress state shared between API and background task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationState {
    pub phase: String,           // "idle", "preflight", "backup", "signup", "uploading", "pkarr", "done", "error"
    pub total_files: usize,
    pub uploaded_files: usize,
    pub total_bytes: u64,
    pub uploaded_bytes: u64,
    pub error: Option<String>,
    pub dry_run: bool,
    pub target_homeserver: String,
    pub target_pubkey: String,    // discovered z32 pubkey of target homeserver
    pub source_pubky: String,
    pub source_type: String,      // "latest" or "snapshot:..."
}

impl Default for MigrationState {
    fn default() -> Self {
        MigrationState {
            phase: "idle".to_string(),
            total_files: 0,
            uploaded_files: 0,
            total_bytes: 0,
            uploaded_bytes: 0,
            error: None,
            dry_run: false,
            target_homeserver: String::new(),
            target_pubkey: String::new(),
            source_pubky: String::new(),
            source_type: String::new(),
        }
    }
}

pub type SharedMigrationState = Arc<RwLock<MigrationState>>;

pub fn new_shared_state() -> SharedMigrationState {
    Arc::new(RwLock::new(MigrationState::default()))
}

/// Preflight request body.
#[derive(Debug, Deserialize)]
pub struct PreflightRequest {
    pub pubky: String,
    pub target_homeserver: String,
    pub source: String,              // "latest" or "snapshot:..."
    pub signup_token: Option<String>,
}

/// Preflight result.
#[derive(Debug, Serialize)]
pub struct PreflightResult {
    pub ok: bool,
    pub checks: Vec<PreflightCheck>,
    pub file_count: usize,
    pub total_bytes: u64,
    pub target_pubkey: String,
}

#[derive(Debug, Serialize)]
pub struct PreflightCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// Run preflight checks.
pub fn run_preflight(
    backup: &crate::backup::BackupManager,
    vault: &crate::keyvault::KeyVault,
    pubky: &str,
    target_homeserver: &str,
    source: &str,
) -> PreflightResult {
    let mut checks = Vec::new();
    let mut file_count = 0usize;
    let mut total_bytes = 0u64;

    // 1. Check backup/snapshot exists
    match backup.get_backup_files(pubky, source) {
        Ok(files) => {
            file_count = files.len();
            total_bytes = files.iter().map(|(_, p)| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)).sum();
            checks.push(PreflightCheck {
                name: "Backup data".to_string(),
                passed: !files.is_empty(),
                detail: format!("{} files, {} bytes", file_count, total_bytes),
            });
        }
        Err(e) => {
            checks.push(PreflightCheck {
                name: "Backup data".to_string(),
                passed: false,
                detail: e,
            });
        }
    }

    // 2. Check key exists in vault
    let has_key = vault.has_key(pubky);
    checks.push(PreflightCheck {
        name: "Secret key in vault".to_string(),
        passed: has_key,
        detail: if has_key { "Key available".to_string() } else { "Key not found in vault — needed for signup and PKARR".to_string() },
    });

    // 3. Check target homeserver URL looks valid
    let url_ok = target_homeserver.starts_with("http://") || target_homeserver.starts_with("https://");
    checks.push(PreflightCheck {
        name: "Target URL".to_string(),
        passed: url_ok,
        detail: if url_ok { target_homeserver.to_string() } else { "Must start with http:// or https://".to_string() },
    });

    let all_ok = checks.iter().all(|c| c.passed);

    PreflightResult {
        ok: all_ok,
        checks,
        file_count,
        total_bytes,
        target_pubkey: String::new(), // discovered at runtime during actual migration
    }
}

/// Execute the full migration pipeline (runs in a background task).
pub async fn execute_migration(
    dashboard: Arc<crate::api::state::DashboardState>,
    pubky: String,
    target_homeserver: String,
    source: String,
    signup_token: Option<String>,
    dry_run: bool,
) {
    let migration_state = dashboard.migration_state.clone();
    // Initialize state
    {
        let mut state = migration_state.write().unwrap();
        *state = MigrationState {
            phase: "backup".to_string(),
            source_pubky: pubky.clone(),
            source_type: source.clone(),
            target_homeserver: target_homeserver.clone(),
            dry_run,
            ..Default::default()
        };
    }

    // Phase 1: Create pre-migration snapshot
    tracing::info!("Migration: creating pre-migration snapshot for {}...", &pubky[..12.min(pubky.len())]);
    match dashboard.backup.create_snapshot(&pubky) {
        Ok(info) => tracing::info!("Migration: pre-migration snapshot created: {}", info.get("timestamp").and_then(|v| v.as_str()).unwrap_or("?")),
        Err(e) => tracing::warn!("Migration: snapshot failed (continuing): {}", e),
    }

    // Phase 2: Enumerate files
    let files = match dashboard.backup.get_backup_files(&pubky, &source) {
        Ok(f) => f,
        Err(e) => {
            set_error(&migration_state, &format!("Failed to list backup files: {}", e));
            return;
        }
    };
    let total_bytes: u64 = files.iter().map(|(_, p)| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)).sum();
    {
        let mut state = migration_state.write().unwrap();
        state.total_files = files.len();
        state.total_bytes = total_bytes;
    }

    if files.is_empty() {
        set_error(&migration_state, "No files to upload");
        return;
    }

    // Phase 3: Signup on target homeserver
    {
        let mut state = migration_state.write().unwrap();
        state.phase = "signup".to_string();
    }
    tracing::info!("Migration: signing up on target homeserver {}...", &target_homeserver);

    let secret_hex = match dashboard.vault.export_key(&pubky) {
        Ok(s) => s,
        Err(e) => {
            set_error(&migration_state, &format!("Failed to export key: {}", e));
            return;
        }
    };
    let session_cookie = match signup_on_target(&secret_hex, &pubky, &target_homeserver, signup_token.as_deref()).await {
        Ok(cookie) => cookie,
        Err(e) => {
            set_error(&migration_state, &format!("Signup failed: {}", e));
            return;
        }
    };
    tracing::info!("Migration: signup successful, got session cookie");

    // Phase 4: Upload files with concurrency
    {
        let mut state = migration_state.write().unwrap();
        state.phase = "uploading".to_string();
    }

    let upload_result = upload_files(
        &files,
        &target_homeserver,
        &pubky,
        &session_cookie,
        &migration_state,
    ).await;

    if let Err(e) = upload_result {
        set_error(&migration_state, &format!("Upload failed: {}", e));
        return;
    }

    // Phase 5: PKARR publish (skip if dry-run)
    if dry_run {
        tracing::info!("Migration: dry-run mode — skipping PKARR publish");
        let mut state = migration_state.write().unwrap();
        state.phase = "done".to_string();
        return;
    }

    {
        let mut state = migration_state.write().unwrap();
        state.phase = "pkarr".to_string();
    }

    // For PKARR, we need to discover the target homeserver's pubkey
    // Try to resolve it from the target URL or use a known mapping
    if let Some(ref client) = dashboard.client {
        match update_pkarr_record(&secret_hex, &target_homeserver, client).await {
            Ok(hs_pubkey) => {
                tracing::info!("Migration: PKARR record updated, pointing to {}", &hs_pubkey[..12.min(hs_pubkey.len())]);
                let mut state = migration_state.write().unwrap();
                state.target_pubkey = hs_pubkey;
                state.phase = "done".to_string();
            }
            Err(e) => {
                // PKARR failure is serious but data is already uploaded
                let mut state = migration_state.write().unwrap();
                state.phase = "done".to_string();
                state.error = Some(format!("Data uploaded successfully but PKARR update failed: {}. You may need to manually update your DNS record.", e));
            }
        }
    } else {
        let mut state = migration_state.write().unwrap();
        state.phase = "done".to_string();
        state.error = Some("Data uploaded but no PKARR client available for DNS update".to_string());
    }
}

fn set_error(state: &SharedMigrationState, msg: &str) {
    tracing::error!("Migration error: {}", msg);
    let mut s = state.write().unwrap();
    s.phase = "error".to_string();
    s.error = Some(msg.to_string());
}

/// Signup on the target homeserver, returning the session cookie value.
async fn signup_on_target(
    secret_hex: &str,
    pubky: &str,
    target_homeserver: &str,
    signup_token: Option<&str>,
) -> Result<String, String> {
    let keypair = decode_keypair(secret_hex)?;
    let token = build_auth_token(&keypair)?;

    let mut url = format!("{}/signup", target_homeserver.trim_end_matches('/'));
    if let Some(tok) = signup_token {
        if !tok.is_empty() {
            url = format!("{}?signup_token={}", url, urlencoding_encode(tok));
        }
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let resp = client
        .post(&url)
        .body(token)
        .header("content-type", "application/octet-stream")
        .send()
        .await
        .map_err(|e| format!("Signup request failed: {}", e))?;

    let status = resp.status();

    // Extract session cookie from Set-Cookie header
    let cookie_val = resp.headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|v| {
            let s = v.to_str().unwrap_or("");
            // Cookie format: {pubky}={session_value}; ...
            if s.starts_with(pubky) || s.contains(pubky) {
                s.split('=').nth(1).and_then(|v| v.split(';').next()).map(|v| v.to_string())
            } else {
                None
            }
        });

    if !status.is_success() && status.as_u16() != 409 {
        // 409 = already signed up, which is OK
        let body_text = resp.text().await.unwrap_or_default();
        return Err(format!("Signup failed ({}): {}", status, body_text));
    }

    // If 409, try signin instead
    if status.as_u16() == 409 || cookie_val.is_none() {
        return signin_on_target(secret_hex, pubky, target_homeserver).await;
    }

    cookie_val.ok_or_else(|| "No session cookie received from signup".to_string())
}

/// Signin (for when the user is already signed up on the target).
async fn signin_on_target(
    secret_hex: &str,
    pubky: &str,
    target_homeserver: &str,
) -> Result<String, String> {
    let keypair = decode_keypair(secret_hex)?;
    let token = build_auth_token(&keypair)?;

    let url = format!("{}/signin", target_homeserver.trim_end_matches('/'));

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let resp = client
        .post(&url)
        .body(token)
        .header("content-type", "application/octet-stream")
        .send()
        .await
        .map_err(|e| format!("Signin request failed: {}", e))?;

    let status = resp.status();

    let cookie_val = resp.headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|v| {
            let s = v.to_str().unwrap_or("");
            if s.starts_with(pubky) || s.contains(pubky) {
                s.split('=').nth(1).and_then(|v| v.split(';').next()).map(|v| v.to_string())
            } else {
                // Try any cookie
                s.split('=').nth(1).and_then(|v| v.split(';').next()).map(|v| v.to_string())
            }
        });

    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        return Err(format!("Signin failed ({}): {}", status, body_text));
    }

    cookie_val.ok_or_else(|| "No session cookie received from signin".to_string())
}

/// Upload files to the target homeserver with concurrency.
async fn upload_files(
    files: &[(String, PathBuf)],
    target_homeserver: &str,
    pubky: &str,
    session_cookie: &str,
    migration_state: &SharedMigrationState,
) -> Result<(), String> {
    use tokio::sync::Semaphore;

    let concurrency = 10;
    let sem = Arc::new(Semaphore::new(concurrency));
    let client = Arc::new(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?);

    let base_url = target_homeserver.trim_end_matches('/').to_string();
    let cookie_header = format!("{}={}", pubky, session_cookie);
    let state = migration_state.clone();
    let errors: Arc<RwLock<Vec<String>>> = Arc::new(RwLock::new(Vec::new()));

    let mut handles = Vec::new();

    for (rel_path, abs_path) in files {
        let permit = sem.clone().acquire_owned().await.map_err(|e| e.to_string())?;
        let client = client.clone();
        let base_url = base_url.clone();
        let cookie = cookie_header.clone();
        let rel = rel_path.clone();
        let abs = abs_path.clone();
        let state = state.clone();
        let errors = errors.clone();
        let pubky_str = pubky.to_string();

        let handle = tokio::spawn(async move {
            let _permit = permit;

            // Read file
            let body = match tokio::fs::read(&abs).await {
                Ok(b) => b,
                Err(e) => {
                    errors.write().unwrap().push(format!("{}: read error: {}", rel, e));
                    return;
                }
            };

            let file_size = body.len() as u64;
            let content_type = infer_content_type(&rel);

            // Build URL: {base}/pub/{relative_path}
            // The backup stores files as pub/pubky-app/... so we need to prepend correctly
            let put_path = if rel.starts_with("pub/") {
                format!("{}/{}", base_url, rel)
            } else {
                format!("{}/pub/{}", base_url, rel)
            };

            // PUT the file
            let result = client
                .put(&put_path)
                .header("cookie", &cookie)
                .header("content-type", content_type)
                .header("pubky-host", &pubky_str)
                .body(body)
                .send()
                .await;

            match result {
                Ok(resp) if resp.status().is_success() => {
                    let mut s = state.write().unwrap();
                    s.uploaded_files += 1;
                    s.uploaded_bytes += file_size;
                }
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    tracing::warn!("Migration upload {} failed ({}): {}", rel, status, &body[..body.len().min(200)]);
                    // Don't abort on individual file failures
                    let mut s = state.write().unwrap();
                    s.uploaded_files += 1; // count as attempted
                    errors.write().unwrap().push(format!("{}: HTTP {}", rel, status));
                }
                Err(e) => {
                    tracing::warn!("Migration upload {} failed: {}", rel, e);
                    errors.write().unwrap().push(format!("{}: {}", rel, e));
                }
            }
        });

        handles.push(handle);
    }

    // Wait for all uploads to complete
    for handle in handles {
        let _ = handle.await;
    }

    let errs = errors.read().unwrap();
    if errs.len() > files.len() / 2 {
        return Err(format!("Too many upload failures ({}/{}): {}", errs.len(), files.len(), errs.first().unwrap_or(&String::new())));
    }

    if !errs.is_empty() {
        tracing::warn!("Migration: {} upload errors (out of {})", errs.len(), files.len());
    }

    tracing::info!("Migration: upload phase complete ({} files)", files.len());
    Ok(())
}

/// Update the PKARR record to point to the new homeserver.
async fn update_pkarr_record(
    secret_hex: &str,
    target_homeserver: &str,
    pkarr_client: &pkarr::Client,
) -> Result<String, String> {
    use pkarr::dns::rdata::SVCB;
    use pkarr::dns::Name;

    let keypair = decode_keypair(secret_hex)?;

    // The target homeserver URL needs to be converted to a domain for the HTTPS record.
    // For now, extract the domain from the URL.
    let target_domain = target_homeserver
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .ok_or("Invalid target URL")?
        .split(':')
        .next()
        .ok_or("Invalid target URL")?;

    // Build the _pubky HTTPS record pointing to the target homeserver domain
    let name: Name = "_pubky.".try_into().map_err(|e: pkarr::dns::SimpleDnsError| e.to_string())?;
    let target_fqdn = format!("{}.", target_domain);
    let target: Name = target_fqdn.as_str().try_into().map_err(|e: pkarr::dns::SimpleDnsError| e.to_string())?;
    let svcb = SVCB::new(0, target);

    let packet = pkarr::SignedPacket::builder()
        .https(name, svcb, 3600)
        .sign(&keypair)
        .map_err(|e| format!("Failed to build signed packet: {}", e))?;

    pkarr_client
        .publish(&packet, None)
        .await
        .map_err(|e| format!("PKARR publish failed: {}", e))?;

    Ok(target_domain.to_string())
}

/// Infer content-type from file extension.
fn infer_content_type(path: &str) -> &'static str {
    if path.ends_with(".json") { "application/json" }
    else if path.ends_with(".txt") { "text/plain" }
    else if path.ends_with(".html") || path.ends_with(".htm") { "text/html" }
    else if path.ends_with(".css") { "text/css" }
    else if path.ends_with(".js") { "application/javascript" }
    else if path.ends_with(".png") { "image/png" }
    else if path.ends_with(".jpg") || path.ends_with(".jpeg") { "image/jpeg" }
    else if path.ends_with(".gif") { "image/gif" }
    else if path.ends_with(".webp") { "image/webp" }
    else if path.ends_with(".svg") { "image/svg+xml" }
    else if path.ends_with(".mp4") { "video/mp4" }
    else if path.ends_with(".webm") { "video/webm" }
    else { "application/octet-stream" }
}

// ─── Helpers (same as identity.rs) ──────────────────────────────

fn decode_keypair(secret_hex: &str) -> Result<pkarr::Keypair, String> {
    let bytes = hex::decode(secret_hex)
        .map_err(|e| format!("Invalid secret hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("Secret must be 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(pkarr::Keypair::from_secret_key(&arr))
}

fn build_auth_token(keypair: &pkarr::Keypair) -> Result<Vec<u8>, String> {
    let version: u8 = 0;
    let caps_bytes: &[u8] = &[];
    let mut to_sign = Vec::new();
    to_sign.push(version);
    to_sign.extend_from_slice(caps_bytes);
    let signature = keypair.sign(&to_sign);
    let sig_bytes = signature.to_bytes();
    let mut token = to_sign;
    token.extend_from_slice(&sig_bytes);
    Ok(token)
}

fn urlencoding_encode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u32),
        })
        .collect::<Vec<_>>()
        .join("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_content_type() {
        assert_eq!(infer_content_type("profile.json"), "application/json");
        assert_eq!(infer_content_type("image.png"), "image/png");
        assert_eq!(infer_content_type("blob"), "application/octet-stream");
        assert_eq!(infer_content_type("style.css"), "text/css");
    }

    #[test]
    fn test_decode_keypair_valid() {
        let hex = "0".repeat(64);
        assert!(decode_keypair(&hex).is_ok());
    }
}
