// Homeserver Manager — lifecycle management for pubky-homeserver
//
// Responsibilities:
//   1. Auto-detect binary (bundled sidecar, PATH, data dir)
//   2. Manage embedded PostgreSQL (start, stop, create DB)
//   3. Generate config.toml with smart defaults
//   4. Start/stop homeserver as child process
//   5. Health check polling on admin port
//   6. Proxy admin API endpoints

use crate::embedded_pg::EmbeddedPg;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::sync::broadcast;

/// Homeserver operational state.
#[derive(Debug, Clone, PartialEq)]
pub enum HomeserverState {
    Stopped,
    Starting,
    Running,
    Error(String),
}

impl HomeserverState {
    pub fn as_str(&self) -> &str {
        match self {
            HomeserverState::Stopped => "stopped",
            HomeserverState::Starting => "starting",
            HomeserverState::Running => "running",
            HomeserverState::Error(_) => "error",
        }
    }
}

/// Homeserver configuration.
#[derive(Debug, Clone)]
pub struct HomeserverConfig {
    pub database_url: String,
    pub drive_icann_port: u16,
    pub drive_pubky_port: u16,
    pub admin_port: u16,
    pub metrics_port: u16,
    pub admin_password: String,
    pub signup_mode: String,
    pub storage_quota_mb: u64,
    pub public_ip: String,
    pub icann_domain: String,
}

impl Default for HomeserverConfig {
    fn default() -> Self {
        HomeserverConfig {
            database_url: "postgres://127.0.0.1:5433/pubky_homeserver".into(),
            drive_icann_port: 6286,
            drive_pubky_port: 6287,
            admin_port: 6288,
            metrics_port: 6289,
            admin_password: generate_random_password(),
            signup_mode: "token_required".into(),
            storage_quota_mb: 0,
            public_ip: "127.0.0.1".into(),
            icann_domain: "localhost".into(),
        }
    }
}

/// Setup check results.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SetupCheck {
    pub postgres_ok: bool,
    pub postgres_msg: String,
    pub binary_ok: bool,
    pub binary_path: String,
    pub config_ok: bool,
    pub config_path: String,
    pub db_ok: bool,
    pub db_msg: String,
}

/// Homeserver process manager.
pub struct HomeserverManager {
    state: RwLock<HomeserverState>,
    process: RwLock<Option<Child>>,
    started_at: RwLock<Option<Instant>>,
    data_dir: PathBuf,
    config_path: PathBuf,
    binary_path: RwLock<Option<PathBuf>>,
    config: RwLock<HomeserverConfig>,
    pub server_pubkey: RwLock<Option<String>>,
    stdout_lines: Arc<RwLock<Vec<String>>>,
    /// Optional broadcast sender — if set, all stdout/stderr lines are forwarded to SSE stream.
    pub log_tx: RwLock<Option<broadcast::Sender<String>>>,
    /// Embedded PostgreSQL instance (managed lifecycle).
    embedded_pg: tokio::sync::RwLock<Option<EmbeddedPg>>,
}

impl HomeserverManager {
    /// Create a new HomeserverManager.
    pub fn new(data_dir: &Path) -> Self {
        let config_path = data_dir.join("config.toml");
        let config = if config_path.exists() {
            parse_config_file(&config_path).unwrap_or_default()
        } else {
            HomeserverConfig::default()
        };

        HomeserverManager {
            state: RwLock::new(HomeserverState::Stopped),
            process: RwLock::new(None),
            started_at: RwLock::new(None),
            data_dir: data_dir.to_path_buf(),
            config_path,
            binary_path: RwLock::new(None),
            config: RwLock::new(config),
            server_pubkey: RwLock::new(None),
            stdout_lines: Arc::new(RwLock::new(Vec::new())),
            log_tx: RwLock::new(None),
            embedded_pg: tokio::sync::RwLock::new(None),
        }
    }

    /// Get the current state.
    pub fn state(&self) -> HomeserverState {
        self.state.read().unwrap().clone()
    }

    /// Get the uptime in seconds (if running).
    pub fn uptime_secs(&self) -> u64 {
        self.started_at.read().unwrap()
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(0)
    }

    /// Get the server's public key (if known).
    pub fn server_pubkey(&self) -> Option<String> {
        self.server_pubkey.read().unwrap().clone()
    }

    /// Get log lines.
    pub fn get_logs(&self, last_n: usize) -> Vec<String> {
        let lines = self.stdout_lines.read().unwrap();
        let skip = if lines.len() > last_n { lines.len() - last_n } else { 0 };
        lines[skip..].to_vec()
    }

    /// Get the current config.
    pub fn get_config(&self) -> HomeserverConfig {
        self.config.read().unwrap().clone()
    }

    // ─── Setup Checks ─────────────────────────────────────────

    /// Run all prerequisites checks.
    pub fn check_setup(&self) -> SetupCheck {
        let binary = self.find_binary();
        let binary_ok = binary.is_some();
        let binary_path = binary.as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "Not found".into());

        if binary_ok {
            *self.binary_path.write().unwrap() = binary;
        }

        // Check embedded PostgreSQL state
        let pg_running = self.embedded_pg.blocking_read().is_some();
        let (postgres_ok, postgres_msg) = if pg_running {
            (true, "Embedded PostgreSQL running".into())
        } else {
            (true, "Embedded PostgreSQL (auto-starts with homeserver)".into())
        };

        let config_ok = self.config_path.exists();
        let db_msg = if pg_running {
            "Database ready".into()
        } else {
            "Auto-created when homeserver starts".into()
        };

        SetupCheck {
            postgres_ok,
            postgres_msg,
            binary_ok,
            binary_path,
            config_ok,
            config_path: self.config_path.display().to_string(),
            db_ok: true, // Always true — embedded PG handles DB creation
            db_msg,
        }
    }

    /// Find the homeserver binary.
    /// Search order: bundled sidecar → data_dir/bin → PATH → common install dirs
    fn find_binary(&self) -> Option<PathBuf> {
        // 1. Check bundled sidecar directory (same dir as current exe — Tauri convention)
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                // Same directory as current exe (Tauri sidecar convention)
                let sibling = dir.join("pubky-homeserver");
                if sibling.exists() {
                    return Some(sibling);
                }
                // macOS: .app/Contents/MacOS/../Resources/
                let resources = dir.join("../Resources/pubky-homeserver");
                if resources.exists() {
                    return Some(resources);
                }
            }
        }

        // 2. Check data dir bin/
        let local_bin = self.data_dir.join("bin").join("pubky-homeserver");
        if local_bin.exists() {
            return Some(local_bin);
        }

        // 3. Check PATH
        if let Ok(output) = Command::new("which").arg("pubky-homeserver").output() {
            if output.status.success() {
                let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path_str.is_empty() {
                    return Some(PathBuf::from(path_str));
                }
            }
        }

        // 4. Common install locations
        if let Some(home) = dirs_next::home_dir() {
            for rel in [".local/bin/pubky-homeserver", ".cargo/bin/pubky-homeserver"] {
                let p = home.join(rel);
                if p.exists() {
                    return Some(p);
                }
            }
        }

        None
    }

    // ─── Auto-Fix All Prerequisites ───────────────────────────

    /// Automatically fix all prerequisites:
    /// 1. Start embedded PostgreSQL (extracts on first run)
    /// 2. Generate config if missing
    /// Returns a step-by-step log of what was done.
    pub async fn auto_fix(&self) -> Vec<String> {
        let mut log = Vec::new();

        // Step 1: Start embedded PostgreSQL
        let pg_running = self.embedded_pg.read().await.is_some();
        if !pg_running {
            log.push("Starting embedded PostgreSQL...".into());
            match EmbeddedPg::start(&self.data_dir).await {
                Ok(pg) => {
                    let url = pg.connection_url();
                    log.push(format!("✅ PostgreSQL started ({})", url));
                    // Update config to use embedded PG URL
                    self.config.write().unwrap().database_url = url;
                    *self.embedded_pg.write().await = Some(pg);
                }
                Err(e) => {
                    log.push(format!("❌ PostgreSQL failed: {}", e));
                    return log;
                }
            }
        } else {
            log.push("✅ Embedded PostgreSQL already running.".into());
        }

        // Step 2: Find binary
        match self.find_binary() {
            Some(path) => {
                log.push("✅ Homeserver binary found.".into());
                *self.binary_path.write().unwrap() = Some(path);
            }
            None => {
                log.push("❌ pubky-homeserver binary not found.".into());
            }
        }

        // Step 3: Generate config if needed
        if !self.config_path.exists() {
            match self.generate_config() {
                Ok(()) => log.push("✅ Config generated.".into()),
                Err(e) => log.push(format!("❌ Config generation failed: {}", e)),
            }
        } else {
            log.push("✅ Config already exists.".into());
        }

        log
    }

    /// Generate config.toml with current settings.
    pub fn generate_config(&self) -> Result<(), String> {
        let cfg = self.config.read().unwrap();
        let toml = format!(
r#"[general]
database_url = "{}"
signup_mode = "{}"
user_storage_quota_mb = {}

[drive]
pubky_listen_socket = "127.0.0.1:{}"
icann_listen_socket = "127.0.0.1:{}"

[storage]
type = "file_system"

[admin]
enabled = true
listen_socket = "127.0.0.1:{}"
admin_password = "{}"

[metrics]
enabled = true
listen_socket = "127.0.0.1:{}"

[pkdns]
public_ip = "{}"
icann_domain = "{}"
user_keys_republisher_interval = 14400

[logging]
level = "info"
"#,
            cfg.database_url, cfg.signup_mode, cfg.storage_quota_mb,
            cfg.drive_pubky_port, cfg.drive_icann_port,
            cfg.admin_port, cfg.admin_password,
            cfg.metrics_port,
            cfg.public_ip, cfg.icann_domain,
        );

        if let Some(parent) = self.config_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&self.config_path, toml).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Update config fields.
    pub fn update_config(&self, updates: serde_json::Value) -> Result<(), String> {
        let mut cfg = self.config.write().unwrap();
        if let Some(v) = updates.get("database_url").and_then(|v| v.as_str()) {
            cfg.database_url = v.to_string();
        }
        if let Some(v) = updates.get("signup_mode").and_then(|v| v.as_str()) {
            cfg.signup_mode = v.to_string();
        }
        if let Some(v) = updates.get("admin_password").and_then(|v| v.as_str()) {
            cfg.admin_password = v.to_string();
        }
        if let Some(v) = updates.get("public_ip").and_then(|v| v.as_str()) {
            cfg.public_ip = v.to_string();
        }
        if let Some(v) = updates.get("icann_domain").and_then(|v| v.as_str()) {
            cfg.icann_domain = v.to_string();
        }
        if let Some(v) = updates.get("storage_quota_mb").and_then(|v| v.as_u64()) {
            cfg.storage_quota_mb = v;
        }
        drop(cfg);
        self.generate_config()
    }

    // ─── Process Lifecycle ────────────────────────────────────

    /// Start the homeserver process.
    /// Automatically starts embedded PostgreSQL if not already running.
    pub async fn start(&self) -> Result<String, String> {
        let state = self.state();
        if state == HomeserverState::Running || state == HomeserverState::Starting {
            return Err("Homeserver is already running.".into());
        }

        // Ensure embedded PostgreSQL is running
        let pg_running = self.embedded_pg.read().await.is_some();
        if !pg_running {
            tracing::info!("Auto-starting embedded PostgreSQL before homeserver...");
            match EmbeddedPg::start(&self.data_dir).await {
                Ok(pg) => {
                    let url = pg.connection_url();
                    tracing::info!("Embedded PostgreSQL started: {}", url);
                    self.config.write().unwrap().database_url = url;
                    // Regenerate config to use embedded PG URL
                    let _ = self.generate_config();
                    *self.embedded_pg.write().await = Some(pg);
                }
                Err(e) => {
                    return Err(format!("Failed to start embedded PostgreSQL: {}", e));
                }
            }
        }

        let binary = self.binary_path.read().unwrap().clone()
            .or_else(|| self.find_binary())
            .ok_or("Homeserver binary not found.")?;

        // Ensure config exists
        if !self.config_path.exists() {
            self.generate_config()?;
        }

        *self.state.write().unwrap() = HomeserverState::Starting;
        self.stdout_lines.write().unwrap().clear();

        let mut cmd = Command::new(&binary);
        cmd.arg("--data-dir")
           .arg(&self.data_dir)
           .stdout(Stdio::piped())
           .stderr(Stdio::piped());

        match cmd.spawn() {
            Ok(mut child) => {
                let pid = child.id();

                // Drain stdout+stderr into ring buffer (and optional SSE broadcast)
                let log_buf = Arc::clone(&self.stdout_lines);
                let log_sender = self.log_tx.read().unwrap().clone();

                // stdout
                if let Some(stdout) = child.stdout.take() {
                    let buf = Arc::clone(&log_buf);
                    let sender = log_sender.clone();
                    std::thread::spawn(move || {
                        use std::io::BufRead;
                        for line in std::io::BufReader::new(stdout).lines().flatten() {
                            if let Some(ref tx) = sender { let _ = tx.send(line.clone()); }
                            let mut b = buf.write().unwrap();
                            b.push(line);
                            if b.len() > 1000 { b.remove(0); }
                        }
                    });
                }
                // stderr (homeserver logs mainly come here)
                if let Some(stderr) = child.stderr.take() {
                    let buf = Arc::clone(&log_buf);
                    let sender = log_sender;
                    std::thread::spawn(move || {
                        use std::io::BufRead;
                        for line in std::io::BufReader::new(stderr).lines().flatten() {
                            if let Some(ref tx) = sender { let _ = tx.send(line.clone()); }
                            let mut b = buf.write().unwrap();
                            b.push(line);
                            if b.len() > 1000 { b.remove(0); }
                        }
                    });
                }

                *self.process.write().unwrap() = Some(child);
                *self.started_at.write().unwrap() = Some(Instant::now());
                *self.state.write().unwrap() = HomeserverState::Running;

                // Store binary path for future use
                *self.binary_path.write().unwrap() = Some(binary.clone());

                Ok(format!("Homeserver started (PID: {})", pid))
            }
            Err(e) => {
                *self.state.write().unwrap() = HomeserverState::Error(e.to_string());
                Err(format!("Failed to start: {}", e))
            }
        }
    }

    /// Stop the homeserver process.
    pub fn stop(&self) -> Result<(), String> {
        let mut proc_guard = self.process.write().unwrap();
        if let Some(ref mut child) = *proc_guard {
            // Try graceful shutdown first
            let _ = child.kill();
            let _ = child.wait();
            *proc_guard = None;
            *self.state.write().unwrap() = HomeserverState::Stopped;
            *self.started_at.write().unwrap() = None;
            *self.server_pubkey.write().unwrap() = None;
            Ok(())
        } else {
            *self.state.write().unwrap() = HomeserverState::Stopped;
            Err("No process to stop.".into())
        }
    }

    /// Check if the process is still alive.
    /// Also detects externally-running homeserver via admin port probe.
    pub fn check_process(&self) -> bool {
        // First check our own child process
        let mut proc_guard = self.process.write().unwrap();
        if let Some(ref mut child) = *proc_guard {
            match child.try_wait() {
                Ok(Some(status)) => {
                    *proc_guard = None;
                    let msg = format!("Process exited with {}", status);
                    *self.state.write().unwrap() = HomeserverState::Error(msg);
                    *self.started_at.write().unwrap() = None;
                    return false;
                }
                Ok(None) => return true,
                Err(e) => {
                    *self.state.write().unwrap() = HomeserverState::Error(e.to_string());
                    return false;
                }
            }
        }
        drop(proc_guard);

        // No child process — check if admin port is responding (externally managed server)
        let cfg = self.config.read().unwrap();
        let admin_port = cfg.admin_port;
        drop(cfg);

        if std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", admin_port).parse().unwrap(),
            std::time::Duration::from_millis(200),
        ).is_ok() {
            // Admin port is alive — homeserver is running externally
            *self.state.write().unwrap() = HomeserverState::Running;
            if self.started_at.read().unwrap().is_none() {
                *self.started_at.write().unwrap() = Some(Instant::now());
            }
            return true;
        }

        // Nothing running
        if *self.state.read().unwrap() == HomeserverState::Running {
            *self.state.write().unwrap() = HomeserverState::Stopped;
        }
        false
    }

    /// Get the PID if running.
    pub fn pid(&self) -> Option<u32> {
        self.process.read().unwrap().as_ref().map(|c| c.id())
    }

    // ─── Admin API Proxy ──────────────────────────────────────

    /// Get the admin base URL.
    #[allow(dead_code)]
    fn admin_url(&self) -> String {
        let cfg = self.config.read().unwrap();
        format!("http://127.0.0.1:{}", cfg.admin_port)
    }

    /// Proxy a GET request to the admin API.
    #[allow(dead_code)]
    pub async fn admin_get(&self, path: &str) -> Result<serde_json::Value, String> {
        let cfg = self.config.read().unwrap();
        let url = format!("http://127.0.0.1:{}{}", cfg.admin_port, path);
        let password = cfg.admin_password.clone();
        drop(cfg);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| e.to_string())?;

        let resp = client.get(&url)
            .header("X-Admin-Password", &password)
            .send()
            .await
            .map_err(|e| format!("Admin API error: {}", e))?;

        let body = resp.text().await.map_err(|e| e.to_string())?;
        serde_json::from_str(&body).map_err(|_| body)
    }

    /// Proxy a POST request to the admin API.
    pub async fn admin_post(&self, path: &str) -> Result<serde_json::Value, String> {
        let cfg = self.config.read().unwrap();
        let url = format!("http://127.0.0.1:{}{}", cfg.admin_port, path);
        let password = cfg.admin_password.clone();
        drop(cfg);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| e.to_string())?;

        let resp = client.post(&url)
            .header("X-Admin-Password", &password)
            .send()
            .await
            .map_err(|e| format!("Admin API error: {}", e))?;

        let body = resp.text().await.map_err(|e| e.to_string())?;
        serde_json::from_str(&body).map_err(|_| body)
    }

    /// Get server info from admin API.
    #[allow(dead_code)]
    pub async fn get_info(&self) -> Result<serde_json::Value, String> {
        self.admin_get("/info").await
    }

    /// Generate a signup token.
    #[allow(dead_code)]
    pub async fn generate_signup_token(&self) -> Result<String, String> {
        let resp = self.admin_get("/generate_signup_token").await?;
        resp.get("token")
            .or(resp.get("signup_token"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| format!("Unexpected response: {}", resp))
    }

    /// Disable a user.
    #[allow(dead_code)]
    pub async fn disable_user(&self, pubkey: &str) -> Result<serde_json::Value, String> {
        self.admin_post(&format!("/users/{}/disable", pubkey)).await
    }

    /// Enable a user.
    #[allow(dead_code)]
    pub async fn enable_user(&self, pubkey: &str) -> Result<serde_json::Value, String> {
        self.admin_post(&format!("/users/{}/enable", pubkey)).await
    }
}

// ─── Helpers ────────────────────────────────────────────────────


/// Parse a simple config.toml to extract key settings.
fn parse_config_file(path: &Path) -> Result<HomeserverConfig, String> {
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut cfg = HomeserverConfig::default();

    for line in content.lines() {
        let line = line.trim();
        if let Some((key, val)) = line.split_once('=') {
            let key = key.trim();
            let val = val.trim().trim_matches('"');
            match key {
                "database_url" => cfg.database_url = val.to_string(),
                "signup_mode" => cfg.signup_mode = val.to_string(),
                "user_storage_quota_mb" => cfg.storage_quota_mb = val.parse().unwrap_or(0),
                "admin_password" => cfg.admin_password = val.to_string(),
                "public_ip" => cfg.public_ip = val.to_string(),
                "icann_domain" => cfg.icann_domain = val.to_string(),
                "listen_socket" | "pubky_listen_socket" | "icann_listen_socket" => {
                    // Parse port from "127.0.0.1:PORT"
                    if let Some(port_str) = val.rsplit(':').next() {
                        if let Ok(port) = port_str.parse::<u16>() {
                            if key == "pubky_listen_socket" {
                                cfg.drive_pubky_port = port;
                            } else if key == "icann_listen_socket" {
                                cfg.drive_icann_port = port;
                            } else if line.contains("[admin]") || cfg.admin_port == 6288 {
                                // This is tricky with simple parsing; use section context
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    Ok(cfg)
}

/// Generate a random 24-character hex password.
fn generate_random_password() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
