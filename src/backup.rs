//! Backup Manager — continuous sync of pubky user data to local storage.
//!
//! Implements cursor-based event polling from homeservers, downloading
//! user resources and storing them locally. Based on the same concepts
//! as pubky-backup-core but using plain HTTP (via reqwest) instead of
//! the `pubky` crate, avoiding version conflicts with local `pkarr` deps.
//!
//! Storage layout (compatible with pubky-backup):
//! ```text
//! {data_dir}/backups/
//! ├── {pubky}/
//! │   ├── cursor          # Sync progress cursor
//! │   └── pub/            # Backed-up resources
//! │       ├── pubky.app/
//! │       │   ├── profile.json
//! │       │   └── ...
//! └── backup_state.json   # Global state: which pubkeys are being backed up
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use pkarr::PublicKey;

const SYNC_INTERVAL_SECS: u64 = 60;
const EVENTS_LIMIT: u32 = 1000;

/// Status of a single pubky backup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubkyBackupStatus {
    pub pubky: String,
    pub is_syncing: bool,
    pub last_sync: Option<String>,
    pub data_size: u64,
    pub sync_count: u64,
    pub last_error: Option<String>,
    pub file_count: u64,
}

/// Persisted state: which pubkeys are configured for backup.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BackupState {
    pub pubkeys: Vec<String>,
    pub enabled: bool,
}

/// Central backup manager.
pub struct BackupManager {
    backup_dir: PathBuf,
    state: Arc<RwLock<BackupState>>,
    statuses: Arc<RwLock<HashMap<String, PubkyBackupStatus>>>,
    control_tx: RwLock<Option<broadcast::Sender<BackupControlMessage>>>,
    pkarr_client: Option<pkarr::Client>,
}

#[derive(Debug, Clone)]
pub enum BackupControlMessage {
    ForceSync(String),
    ForceSyncAll,
    #[allow(dead_code)]
    Shutdown,
}

impl BackupManager {
    pub fn new(data_dir: &Path) -> Self {
        let backup_dir = data_dir.join("backups");
        let _ = std::fs::create_dir_all(&backup_dir);

        let state_file = backup_dir.join("backup_state.json");
        let state = if state_file.exists() {
            std::fs::read_to_string(&state_file)
                .ok()
                .and_then(|s| serde_json::from_str::<BackupState>(&s).ok())
                .unwrap_or_default()
        } else {
            BackupState::default()
        };

        let mut statuses = HashMap::new();
        for pk in &state.pubkeys {
            let pk_dir = backup_dir.join(pk);
            statuses.insert(pk.clone(), PubkyBackupStatus {
                pubky: pk.clone(),
                is_syncing: false,
                last_sync: None,
                data_size: calculate_dir_size(&pk_dir),
                sync_count: 0,
                last_error: None,
                file_count: count_files(&pk_dir),
            });
        }

        BackupManager {
            backup_dir,
            state: Arc::new(RwLock::new(state)),
            statuses: Arc::new(RwLock::new(statuses)),
            control_tx: RwLock::new(None),
            pkarr_client: None,
        }
    }

    /// Set the pkarr client for DHT resolution.
    pub fn set_pkarr_client(&mut self, client: pkarr::Client) {
        self.pkarr_client = Some(client);
    }

    /// Start the background auto-sync loop.
    pub fn start_auto_sync(&self) {
        let (tx, mut rx) = broadcast::channel::<BackupControlMessage>(32);
        *self.control_tx.write().unwrap() = Some(tx);

        let state_arc = Arc::clone(&self.state);
        let statuses_arc = Arc::clone(&self.statuses);
        let backup_dir = self.backup_dir.clone();
        let pkarr_client = self.pkarr_client.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(SYNC_INTERVAL_SECS));
            interval.tick().await; // skip first immediate tick

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        sync_all_keys(&state_arc, &statuses_arc, &backup_dir, &pkarr_client).await;
                    }
                    msg = rx.recv() => {
                        match msg {
                            Ok(BackupControlMessage::ForceSync(pubky)) => {
                                sync_one_key(&pubky, &statuses_arc, &backup_dir, &pkarr_client).await;
                            }
                            Ok(BackupControlMessage::ForceSyncAll) => {
                                sync_all_keys(&state_arc, &statuses_arc, &backup_dir, &pkarr_client).await;
                            }
                            Ok(BackupControlMessage::Shutdown) => {
                                tracing::info!("Backup auto-sync shutting down");
                                break;
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                tracing::warn!("Backup control channel lagged by {} messages", n);
                            }
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            }
        });
    }

    fn save_state(&self) {
        let state_file = self.backup_dir.join("backup_state.json");
        if let Ok(state) = self.state.read() {
            let _ = std::fs::write(&state_file, serde_json::to_string_pretty(&*state).unwrap_or_default());
        }
    }

    pub fn add_pubky(&self, pubky: &str) -> Result<(), String> {
        if pubky.len() < 32 || pubky.len() > 64 {
            return Err("Invalid pubky format.".into());
        }
        {
            let mut state = self.state.write().map_err(|e| e.to_string())?;
            if state.pubkeys.contains(&pubky.to_string()) {
                return Err("Pubky already in backup list.".into());
            }
            state.pubkeys.push(pubky.to_string());
        }
        let _ = std::fs::create_dir_all(self.backup_dir.join(pubky));
        {
            let mut statuses = self.statuses.write().map_err(|e| e.to_string())?;
            statuses.insert(pubky.to_string(), PubkyBackupStatus {
                pubky: pubky.to_string(),
                is_syncing: false,
                last_sync: None,
                data_size: 0,
                sync_count: 0,
                last_error: None,
                file_count: 0,
            });
        }
        self.save_state();
        Ok(())
    }

    pub fn remove_pubky(&self, pubky: &str) -> Result<(), String> {
        {
            let mut state = self.state.write().map_err(|e| e.to_string())?;
            let before = state.pubkeys.len();
            state.pubkeys.retain(|p| p != pubky);
            if state.pubkeys.len() == before {
                return Err("Pubky not found in backup list.".into());
            }
        }
        {
            let mut statuses = self.statuses.write().map_err(|e| e.to_string())?;
            statuses.remove(pubky);
        }
        self.save_state();
        Ok(())
    }

    pub fn list(&self) -> Vec<PubkyBackupStatus> {
        self.statuses.read().map(|s| s.values().cloned().collect()).unwrap_or_default()
    }

    #[allow(dead_code)]
    pub fn status(&self, pubky: &str) -> Option<PubkyBackupStatus> {
        self.statuses.read().ok()?.get(pubky).cloned()
    }

    pub fn global_status(&self) -> serde_json::Value {
        let backups = self.list();
        let active_syncs = backups.iter().filter(|b| b.is_syncing).count();
        let total_size: u64 = backups.iter().map(|b| b.data_size).sum();
        serde_json::json!({
            "backup_count": backups.len(),
            "active_syncs": active_syncs,
            "total_size": total_size,
            "enabled": self.state.read().map(|s| s.enabled).unwrap_or(false),
            "backup_dir": self.backup_dir.display().to_string(),
            "sync_interval_secs": SYNC_INTERVAL_SECS,
        })
    }

    pub fn force_sync(&self, pubky: &str) -> Result<(), String> {
        {
            let statuses = self.statuses.read().map_err(|e| e.to_string())?;
            if !statuses.contains_key(pubky) {
                return Err("Pubky not in backup list.".into());
            }
        }
        if let Some(tx) = self.control_tx.read().unwrap().as_ref() {
            let _ = tx.send(BackupControlMessage::ForceSync(pubky.to_string()));
        }
        Ok(())
    }

    pub fn force_sync_all(&self) -> Result<(), String> {
        if let Some(tx) = self.control_tx.read().unwrap().as_ref() {
            let _ = tx.send(BackupControlMessage::ForceSyncAll);
        }
        Ok(())
    }

    pub fn verify(&self, pubky: &str) -> Result<serde_json::Value, String> {
        let pk_dir = self.backup_dir.join(pubky);
        if !pk_dir.exists() {
            return Err("No backup data found for this pubky.".into());
        }
        Ok(serde_json::json!({
            "pubky": pubky,
            "valid": true,
            "file_count": count_files(&pk_dir),
            "total_size": calculate_dir_size(&pk_dir),
            "has_cursor": pk_dir.join("cursor").exists(),
            "cursor": read_cursor(&pk_dir),
            "backup_path": pk_dir.display().to_string(),
        }))
    }

    pub fn export_bundle(&self, pubky: &str, include_keys: bool, vault: &crate::keyvault::KeyVault) -> Result<serde_json::Value, String> {
        let pk_dir = self.backup_dir.join(pubky);
        if !pk_dir.exists() {
            return Err("No backup data for this pubky.".into());
        }
        let mut bundle = serde_json::json!({
            "format": "pubky-recovery-bundle-v1",
            "pubky": pubky,
            "exported_at": format_utc_now(),
            "file_count": count_files(&pk_dir),
            "total_size": calculate_dir_size(&pk_dir),
            "backup_dir": pk_dir.display().to_string(),
        });
        if include_keys {
            if let Ok(secret_hex) = vault.export_key(pubky) {
                bundle["secret_key"] = serde_json::json!(secret_hex);
            }
        }
        Ok(bundle)
    }

    pub fn backup_dir(&self) -> &Path {
        &self.backup_dir
    }

    // ─── Snapshot Management ────────────────────────────────────

    fn snapshots_dir(&self) -> PathBuf {
        self.backup_dir.join("snapshots")
    }

    /// Create a timestamped snapshot of a pubky's backup data.
    pub fn create_snapshot(&self, pubky: &str) -> Result<serde_json::Value, String> {
        let pk_dir = self.backup_dir.join(pubky);
        if !pk_dir.exists() {
            return Err("No backup data exists for this pubky".to_string());
        }

        let file_count = count_files(&pk_dir);
        if file_count == 0 {
            return Err("Backup directory is empty — sync first".to_string());
        }

        let timestamp = chrono_timestamp();
        let snap_dir = self.snapshots_dir().join(pubky).join(&timestamp);
        let _ = std::fs::create_dir_all(&snap_dir);

        // Copy all files from pk_dir to snap_dir (skip cursor file and snapshots)
        copy_dir_recursive(&pk_dir, &snap_dir, &["cursor"])
            .map_err(|e| format!("Snapshot copy failed: {}", e))?;

        let size = calculate_dir_size(&snap_dir);
        let files = count_files(&snap_dir);

        tracing::info!("Snapshot created: {} ({} files, {} bytes)", timestamp, files, size);

        Ok(serde_json::json!({
            "pubky": pubky,
            "timestamp": timestamp,
            "file_count": files,
            "size": size,
            "path": snap_dir.display().to_string(),
        }))
    }

    /// List all snapshots for a pubky (or all pubkeys if pubky is None).
    pub fn list_snapshots(&self, pubky: Option<&str>) -> Vec<serde_json::Value> {
        let base = self.snapshots_dir();
        if !base.exists() { return vec![]; }

        let mut snapshots = Vec::new();

        let dirs: Vec<PathBuf> = if let Some(pk) = pubky {
            vec![base.join(pk)]
        } else {
            std::fs::read_dir(&base)
                .ok()
                .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.is_dir()).collect())
                .unwrap_or_default()
        };

        for pk_snap_dir in dirs {
            let pk_name = pk_snap_dir.file_name().unwrap_or_default().to_string_lossy().to_string();
            if let Ok(rd) = std::fs::read_dir(&pk_snap_dir) {
                for entry in rd.filter_map(|e| e.ok()) {
                    let ts_dir = entry.path();
                    if !ts_dir.is_dir() { continue; }
                    let full_name = ts_dir.file_name().unwrap_or_default().to_string_lossy().to_string();
                    // Extract tier and timestamp from "tier_timestamp" format
                    let (tier, display_ts) = if let Some(rest) = full_name.strip_prefix("daily_") {
                        ("daily", rest.to_string())
                    } else if let Some(rest) = full_name.strip_prefix("monthly_") {
                        ("monthly", rest.to_string())
                    } else if let Some(rest) = full_name.strip_prefix("quarterly_") {
                        ("quarterly", rest.to_string())
                    } else if let Some(rest) = full_name.strip_prefix("yearly_") {
                        ("yearly", rest.to_string())
                    } else {
                        ("manual", full_name.clone())
                    };
                    snapshots.push(serde_json::json!({
                        "pubky": pk_name,
                        "timestamp": full_name,
                        "display_ts": display_ts,
                        "tier": tier,
                        "file_count": count_files(&ts_dir),
                        "size": calculate_dir_size(&ts_dir),
                    }));
                }
            }
        }

        snapshots.sort_by(|a, b| {
            let ta = a["timestamp"].as_str().unwrap_or("");
            let tb = b["timestamp"].as_str().unwrap_or("");
            tb.cmp(ta) // newest first
        });

        snapshots
    }

    /// Restore a snapshot: replaces current backup data with snapshot data.
    pub fn restore_snapshot(&self, pubky: &str, timestamp: &str) -> Result<serde_json::Value, String> {
        let snap_dir = self.snapshots_dir().join(pubky).join(timestamp);
        if !snap_dir.exists() {
            return Err(format!("Snapshot '{}' not found for pubky", timestamp));
        }

        let pk_dir = self.backup_dir.join(pubky);

        // Save current cursor before wiping
        let old_cursor = read_cursor(&pk_dir);

        // Remove current backup data (but keep cursor and snapshots)
        if pk_dir.exists() {
            for entry in std::fs::read_dir(&pk_dir).map_err(|e| e.to_string())? {
                let entry = entry.map_err(|e| e.to_string())?;
                let name = entry.file_name().to_string_lossy().to_string();
                if name == "cursor" { continue; } // keep cursor
                let path = entry.path();
                if path.is_dir() {
                    let _ = std::fs::remove_dir_all(&path);
                } else {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }

        // Copy snapshot data into pk_dir
        copy_dir_recursive(&snap_dir, &pk_dir, &[])
            .map_err(|e| format!("Restore copy failed: {}", e))?;

        // Restore the cursor (don't reset it — the snapshot data is older but
        // we still want to track from the same position in the event stream)
        if !old_cursor.is_empty() {
            write_cursor(&pk_dir, &old_cursor);
        }

        let files = count_files(&pk_dir);
        let size = calculate_dir_size(&pk_dir);

        tracing::info!("Snapshot '{}' restored for {} ({} files)", timestamp, &pubky[..12.min(pubky.len())], files);

        Ok(serde_json::json!({
            "pubky": pubky,
            "restored_from": timestamp,
            "file_count": files,
            "size": size,
        }))
    }

    /// Delete a snapshot.
    pub fn delete_snapshot(&self, pubky: &str, timestamp: &str) -> Result<(), String> {
        let snap_dir = self.snapshots_dir().join(pubky).join(timestamp);
        if !snap_dir.exists() {
            return Err("Snapshot not found".to_string());
        }
        std::fs::remove_dir_all(&snap_dir).map_err(|e| format!("Failed to delete snapshot: {}", e))?;
        // Clean up empty parent dir
        let parent = self.snapshots_dir().join(pubky);
        if parent.exists() {
            if let Ok(rd) = std::fs::read_dir(&parent) {
                if rd.count() == 0 {
                    let _ = std::fs::remove_dir(&parent);
                }
            }
        }
        Ok(())
    }

    /// Get all files from a backup source (current backup or snapshot).
    /// Returns Vec of (relative_path_for_put, absolute_path_on_disk).
    /// `source` is either "latest" or "snapshot:tier_timestamp" (e.g. "snapshot:daily_2026-03-15_070136").
    pub fn get_backup_files(&self, pubky: &str, source: &str) -> Result<Vec<(String, std::path::PathBuf)>, String> {
        let base_dir = if source == "latest" {
            self.backup_dir.join(pubky)
        } else if let Some(snap_name) = source.strip_prefix("snapshot:") {
            self.snapshots_dir().join(pubky).join(snap_name)
        } else {
            return Err(format!("Invalid source '{}'. Use 'latest' or 'snapshot:<name>'", source));
        };

        if !base_dir.exists() {
            return Err(format!("Source directory does not exist: {}", base_dir.display()));
        }

        let mut files = Vec::new();
        collect_files_recursive(&base_dir, &base_dir, &mut files);
        Ok(files)
    }
}

// ─── Free-standing sync functions (used by background task) ─────

async fn sync_all_keys(
    state: &Arc<RwLock<BackupState>>,
    statuses: &Arc<RwLock<HashMap<String, PubkyBackupStatus>>>,
    backup_dir: &Path,
    pkarr_client: &Option<pkarr::Client>,
) {
    let pubkeys: Vec<String> = state.read().map(|s| s.pubkeys.clone()).unwrap_or_default();
    if pubkeys.is_empty() { return; }
    tracing::info!("Backup: starting sync cycle for {} key(s)", pubkeys.len());
    for pk in &pubkeys {
        sync_one_key(pk, statuses, backup_dir, pkarr_client).await;
    }
    tracing::info!("Backup: sync cycle complete");

    // Run snapshot rotation after sync
    for pk in &pubkeys {
        run_snapshot_rotation(pk, backup_dir);
    }
}

// ─── Snapshot Rotation (Grandfather-Father-Son) ─────────────────

const DAILY_KEEP: usize = 7;
const MONTHLY_KEEP: usize = 3;
const QUARTERLY_KEEP: usize = 4;
// Yearly: keep all (no limit)

/// Runs the automated snapshot rotation for a pubky:
/// 1. Create today's daily snapshot if none exists
/// 2. Prune dailies > DAILY_KEEP, promoting the oldest to monthly
/// 3. Prune monthlies > MONTHLY_KEEP, promoting the oldest to quarterly
/// 4. Prune quarterlies > QUARTERLY_KEEP, promoting the oldest to yearly
fn run_snapshot_rotation(pubky: &str, backup_dir: &Path) {
    let pk_dir = backup_dir.join(pubky);
    if !pk_dir.exists() { return; }
    let file_count = count_files(&pk_dir);
    if file_count == 0 { return; }

    let snap_base = backup_dir.join("snapshots").join(pubky);
    let _ = std::fs::create_dir_all(&snap_base);

    let today = today_date_str(); // "2026-03-15"

    // 1. Create daily snapshot if none today
    let dailies = list_tier_snapshots(&snap_base, "daily");
    let has_today = dailies.iter().any(|name| name.contains(&today));
    if !has_today {
        let ts = chrono_timestamp();
        let snap_name = format!("daily_{}", ts);
        let snap_dir = snap_base.join(&snap_name);
        if let Err(e) = copy_dir_recursive(&pk_dir, &snap_dir, &["cursor"]) {
            tracing::warn!("Snapshot rotation: failed to create daily: {}", e);
            return;
        }
        tracing::info!("Snapshot rotation [{}...]: created {}", &pubky[..12.min(pubky.len())], snap_name);
    }

    // 2. Prune dailies, promote oldest to monthly
    rotate_tier(&snap_base, "daily", DAILY_KEEP, Some("monthly"));

    // 3. Prune monthlies, promote oldest to quarterly
    rotate_tier(&snap_base, "monthly", MONTHLY_KEEP, Some("quarterly"));

    // 4. Prune quarterlies, promote oldest to yearly
    rotate_tier(&snap_base, "quarterly", QUARTERLY_KEEP, Some("yearly"));
}

/// Get sorted snapshot directory names for a given tier prefix.
fn list_tier_snapshots(snap_base: &Path, tier: &str) -> Vec<String> {
    let prefix = format!("{}_", tier);
    let mut names: Vec<String> = std::fs::read_dir(snap_base)
        .ok()
        .map(|rd| rd.filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with(&prefix))
            .collect())
        .unwrap_or_default();
    names.sort(); // chronological order (oldest first)
    names
}

/// Keep only `keep` snapshots of the given tier.
/// If there are more, promote the oldest to `promote_to` tier (rename), then delete the rest.
fn rotate_tier(snap_base: &Path, tier: &str, keep: usize, promote_to: Option<&str>) {
    let mut snapshots = list_tier_snapshots(snap_base, tier);
    if snapshots.len() <= keep { return; }

    // Promote the oldest one to the next tier (rename directory)
    if let Some(next_tier) = promote_to {
        let oldest = &snapshots[0];
        let ts_part = oldest.strip_prefix(&format!("{}_", tier)).unwrap_or(oldest);
        let new_name = format!("{}_{}", next_tier, ts_part);
        let old_path = snap_base.join(oldest);
        let new_path = snap_base.join(&new_name);
        if let Err(e) = std::fs::rename(&old_path, &new_path) {
            tracing::warn!("Snapshot rotation: promote {} → {} failed: {}", oldest, new_name, e);
        } else {
            tracing::info!("Snapshot rotation: promoted {} → {}", oldest, new_name);
        }
        snapshots.remove(0); // remove the promoted one from the list
    }

    // Delete extras (keep only `keep` newest)
    while snapshots.len() > keep {
        let to_delete = snapshots.remove(0);
        let path = snap_base.join(&to_delete);
        if let Err(e) = std::fs::remove_dir_all(&path) {
            tracing::warn!("Snapshot rotation: delete {} failed: {}", to_delete, e);
        } else {
            tracing::info!("Snapshot rotation: deleted {}", to_delete);
        }
    }
}

fn today_date_str() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let days = secs / 86400;
    let (y, m, d) = unix_days_to_date(days as i64);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

async fn sync_one_key(
    pubky: &str,
    statuses: &Arc<RwLock<HashMap<String, PubkyBackupStatus>>>,
    backup_dir: &Path,
    pkarr_client: &Option<pkarr::Client>,
) {
    if let Ok(mut s) = statuses.write() {
        if let Some(st) = s.get_mut(pubky) {
            st.is_syncing = true;
            st.last_error = None;
        }
    }

    let pk_dir = backup_dir.join(pubky);
    let result = perform_sync(pubky, &pk_dir, pkarr_client).await;

    if let Ok(mut s) = statuses.write() {
        if let Some(st) = s.get_mut(pubky) {
            st.is_syncing = false;
            st.last_sync = Some(format_utc_now());
            st.sync_count += 1;
            st.data_size = calculate_dir_size(&pk_dir);
            st.file_count = count_files(&pk_dir);
            match result {
                Ok(n) => {
                    tracing::info!("Backup [{}...]: synced {} events", &pubky[..12.min(pubky.len())], n);
                    st.last_error = None;
                }
                Err(ref e) => {
                    tracing::warn!("Backup [{}...]: sync error: {}", &pubky[..12.min(pubky.len())], e);
                    st.last_error = Some(e.clone());
                }
            }
        }
    }
}

/// Fetch events from homeserver and download/delete resources.
async fn perform_sync(pubky: &str, pk_dir: &Path, pkarr_client: &Option<pkarr::Client>) -> Result<usize, String> {
    let _ = std::fs::create_dir_all(pk_dir);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let (homeserver_base, _pubky_host) = resolve_homeserver_via_pkarr(pubky, pkarr_client).await?;

    let mut total_events = 0usize;
    let pubky_prefix = format!("pubky://{}/", pubky);

    for iteration in 0..50 {
        let cursor = read_cursor(pk_dir);
        let events_url = if cursor.is_empty() {
            format!("{}/events/?limit={}", homeserver_base, EVENTS_LIMIT)
        } else {
            format!("{}/events/?limit={}&cursor={}", homeserver_base, EVENTS_LIMIT, cursor)
        };

        tracing::debug!("Backup [{}...]: fetching events (iter={}, cursor='{}')",
            &pubky[..12.min(pubky.len())], iteration, &cursor);

        let resp = client.get(&events_url)
            .header("pubky-host", pubky)
            .send().await
            .map_err(|e| format!("Events fetch failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("Events endpoint returned {}", resp.status()));
        }

        let body = resp.text().await
            .map_err(|e| format!("Failed to read events body: {}", e))?;

        let (events, new_cursor) = parse_events_response(&body);

        if events.is_empty() {
            tracing::debug!("Backup [{}...]: no events, caught up", &pubky[..12.min(pubky.len())]);
            break;
        }

        // Filter and process only events belonging to our target pubky
        let mut my_events = 0usize;
        for event in &events {
            match event {
                SyncEvent::Put { url, path } => {
                    if !url.starts_with(&pubky_prefix) {
                        continue; // Skip events for other pubkeys
                    }
                    my_events += 1;
                    let resource_url = format!("{}{}", homeserver_base, path);
                    match client.get(&resource_url).header("pubky-host", pubky).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            if let Ok(data) = resp.bytes().await {
                                let file_path = pk_dir.join(path.trim_start_matches('/'));
                                if let Some(parent) = file_path.parent() {
                                    let _ = std::fs::create_dir_all(parent);
                                }
                                let _ = std::fs::write(&file_path, &data);
                            }
                        }
                        Ok(resp) => {
                            tracing::debug!("Backup: resource {} returned {}", path, resp.status());
                        }
                        Err(e) => {
                            tracing::debug!("Backup: failed to fetch {}: {}", path, e);
                        }
                    }
                }
                SyncEvent::Del { url, path } => {
                    if !url.starts_with(&pubky_prefix) {
                        continue;
                    }
                    my_events += 1;
                    let file_path = pk_dir.join(path.trim_start_matches('/'));
                    let _ = std::fs::remove_file(&file_path);
                }
            }
        }

        total_events += my_events;
        tracing::info!("Backup [{}...]: processed {}/{} events (ours/total)",
            &pubky[..12.min(pubky.len())], my_events, events.len());

        // Save cursor even if none were ours — we consumed them
        if !new_cursor.is_empty() {
            write_cursor(pk_dir, &new_cursor);
        }
        if events.len() < EVENTS_LIMIT as usize { break; }
    }

    Ok(total_events)
}

// ─── Sync Event Types ───────────────────────────────────────────

#[derive(Debug)]
enum SyncEvent {
    Put { url: String, path: String },
    Del { url: String, path: String },
}

fn parse_events_response(body: &str) -> (Vec<SyncEvent>, String) {
    let mut events = Vec::new();
    let mut cursor = String::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        if let Some(c) = line.strip_prefix("cursor: ") {
            cursor = c.trim().to_string();
            continue;
        }
        if let Some(url) = line.strip_prefix("PUT ") {
            let url = url.trim().to_string();
            if let Some(path) = extract_path_from_pubky_url(&url) {
                events.push(SyncEvent::Put { url, path });
            }
        } else if let Some(url) = line.strip_prefix("DEL ") {
            let url = url.trim().to_string();
            if let Some(path) = extract_path_from_pubky_url(&url) {
                events.push(SyncEvent::Del { url, path });
            }
        }
    }
    (events, cursor)
}

fn extract_path_from_pubky_url(url: &str) -> Option<String> {
    let stripped = url.strip_prefix("pubky://")?;
    let slash_idx = stripped.find('/')?;
    Some(stripped[slash_idx..].to_string())
}

// ─── Homeserver Resolution ──────────────────────────────────────

/// Resolve homeserver via pkarr DHT resolution.
/// Returns (base_url, pubky_host_header).
///
/// Pattern (same as network.rs proxy):
/// 1. Resolve pubky → _pubky HTTPS/SVCB record → homeserver KEY
/// 2. Resolve homeserver KEY → HTTPS record → actual domain
/// 3. Return https://{domain} as base URL
async fn resolve_homeserver_via_pkarr(
    pubky: &str,
    pkarr_client: &Option<pkarr::Client>,
) -> Result<(String, String), String> {
    let client = pkarr_client.as_ref()
        .ok_or_else(|| "Pkarr client not available".to_string())?;

    let public_key = PublicKey::try_from(pubky)
        .map_err(|e| format!("Invalid pubky '{}': {}", pubky, e))?;

    // Step 1: Resolve the pubky to find _pubky HTTPS/SVCB record
    let packet = client.resolve(&public_key).await
        .ok_or_else(|| format!("No pkarr record found for {}", &pubky[..12.min(pubky.len())]))?;

    let mut homeserver_key_str: Option<String> = None;
    for rr in packet.resource_records("_pubky") {
        match &rr.rdata {
            pkarr::dns::rdata::RData::HTTPS(https) => {
                let target = https.0.target.to_string();
                if !target.is_empty() && target != "." {
                    homeserver_key_str = Some(target);
                    break;
                }
            }
            pkarr::dns::rdata::RData::SVCB(svcb) => {
                let target = svcb.target.to_string();
                if !target.is_empty() && target != "." {
                    homeserver_key_str = Some(target);
                    break;
                }
            }
            _ => {}
        }
    }

    let hs_key_str = homeserver_key_str
        .ok_or_else(|| format!("No _pubky HTTPS/SVCB record found for {}", &pubky[..12.min(pubky.len())]))?;

    // Step 2: Resolve the homeserver key to find its HTTPS domain
    let mut homeserver_host = String::new();
    if let Ok(hs_pk) = PublicKey::try_from(hs_key_str.as_str()) {
        if let Some(hs_packet) = client.resolve(&hs_pk).await {
            for rr in hs_packet.all_resource_records() {
                if let pkarr::dns::rdata::RData::HTTPS(https) = &rr.rdata {
                    let target = https.0.target.to_string();
                    if !target.is_empty() && target != "." {
                        homeserver_host = target.trim_end_matches('.').to_string();
                        break;
                    }
                }
            }
        }
    }

    if homeserver_host.is_empty() {
        // Fallback to default
        homeserver_host = "homeserver.pubky.app".to_string();
    }

    let base_url = format!("https://{}", homeserver_host);
    tracing::info!("Backup: resolved homeserver for {} → {}", &pubky[..12.min(pubky.len())], base_url);
    Ok((base_url, pubky.to_string()))
}

// ─── Cursor Management ──────────────────────────────────────────

fn read_cursor(pk_dir: &Path) -> String {
    std::fs::read_to_string(pk_dir.join("cursor")).unwrap_or_default().trim().to_string()
}

fn write_cursor(pk_dir: &Path, cursor: &str) {
    let _ = std::fs::write(pk_dir.join("cursor"), cursor);
}

// ─── Filesystem Helpers ─────────────────────────────────────────

fn calculate_dir_size(path: &Path) -> u64 {
    if !path.exists() { return 0; }
    let mut size = 0u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_dir() { size += calculate_dir_size(&entry.path()); }
                else { size += meta.len(); }
            }
        }
    }
    size
}

fn count_files(path: &Path) -> u64 {
    if !path.exists() { return 0; }
    let mut count = 0u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_dir() { count += count_files(&entry.path()); }
                else { count += 1; }
            }
        }
    }
    count
}

fn format_utc_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let days = secs / 86400;
    let tod = secs % 86400;
    let (y, m, d) = unix_days_to_date(days as i64);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, tod / 3600, (tod % 3600) / 60, tod % 60)
}

/// Generate a filesystem-safe timestamp for snapshot directory names.
fn chrono_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let days = secs / 86400;
    let tod = secs % 86400;
    let (y, m, d) = unix_days_to_date(days as i64);
    format!("{:04}-{:02}-{:02}_{:02}{:02}{:02}", y, m, d, tod / 3600, (tod % 3600) / 60, tod % 60)
}

/// Recursively copy directory contents, optionally skipping named entries.
fn copy_dir_recursive(src: &Path, dst: &Path, skip: &[&str]) -> std::io::Result<()> {
    let _ = std::fs::create_dir_all(dst);
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if skip.iter().any(|s| *s == name_str.as_ref()) { continue; }
        if name_str == "snapshots" { continue; } // never copy snapshots into snapshots
        let src_path = entry.path();
        let dst_path = dst.join(&name);
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path, skip)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

/// Recursively collect all files as (relative_path, absolute_path) pairs.
/// Skips cursor files and the snapshots directory.
fn collect_files_recursive(base: &Path, current: &Path, out: &mut Vec<(String, std::path::PathBuf)>) {
    let rd = match std::fs::read_dir(current) {
        Ok(r) => r,
        Err(_) => return,
    };
    for entry in rd.filter_map(|e| e.ok()) {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "cursor" || name == "snapshots" { continue; }
        if path.is_dir() {
            collect_files_recursive(base, &path, out);
        } else {
            if let Ok(rel) = path.strip_prefix(base) {
                let rel_str = rel.to_string_lossy().to_string();
                out.push((rel_str, path.clone()));
            }
        }
    }
}

fn unix_days_to_date(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backup_manager_new() {
        let td = tempfile::tempdir().unwrap();
        let mgr = BackupManager::new(td.path());
        assert!(mgr.backup_dir().exists());
        assert!(mgr.list().is_empty());
    }

    #[test]
    fn test_backup_add_and_list() {
        let td = tempfile::tempdir().unwrap();
        let mgr = BackupManager::new(td.path());
        mgr.add_pubky("g1b6wp8bhhxtsksy3td7rj6mgg7s5k8c68663sajkfscshwj8g5y").unwrap();
        assert_eq!(mgr.list().len(), 1);
    }

    #[test]
    fn test_parse_events_response() {
        let body = "PUT pubky://abc123/pub/profile.json\nDEL pubky://abc123/pub/posts/old\ncursor: xyz789\n";
        let (events, cursor) = parse_events_response(body);
        assert_eq!(events.len(), 2);
        assert_eq!(cursor, "xyz789");
    }

    #[test]
    fn test_extract_path_from_pubky_url() {
        assert_eq!(extract_path_from_pubky_url("pubky://abc123/pub/foo"), Some("/pub/foo".into()));
        assert_eq!(extract_path_from_pubky_url("https://example.com"), None);
    }

    #[test]
    fn test_cursor_read_write() {
        let td = tempfile::tempdir().unwrap();
        let dir = td.path().join("testkey");
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(read_cursor(&dir), "");
        write_cursor(&dir, "c123");
        assert_eq!(read_cursor(&dir), "c123");
    }
}
