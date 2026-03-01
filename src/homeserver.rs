// Homeserver Manager — lifecycle management for pubky-homeserver
//
// Responsibilities:
//   1. Auto-detect binary (PATH, data dir, sibling pubky-core build)
//   2. Auto-detect PostgreSQL (pg_isready)
//   3. Generate config.toml with smart defaults
//   4. Start/stop homeserver as child process
//   5. Health check polling on admin port
//   6. Proxy admin API endpoints

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

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
            database_url: "postgres://localhost:5432/pubky_homeserver".into(),
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
    server_pubkey: RwLock<Option<String>>,
    stdout_lines: RwLock<Vec<String>>,
}

impl HomeserverManager {
    /// Create a new HomeserverManager.
    pub fn new(data_dir: &Path) -> Self {
        // Ensure Homebrew Postgres is in PATH for all subprocess calls
        let pg_bin = "/opt/homebrew/opt/postgresql@17/bin";
        let current_path = std::env::var("PATH").unwrap_or_default();
        if !current_path.contains(pg_bin) && std::path::Path::new(pg_bin).exists() {
            std::env::set_var("PATH", format!("{}:{}", pg_bin, current_path));
        }

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
            stdout_lines: RwLock::new(Vec::new()),
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

        let (postgres_ok, postgres_msg) = check_postgres();
        let config_ok = self.config_path.exists();
        let (db_ok, db_msg) = check_database(&self.config.read().unwrap().database_url);

        SetupCheck {
            postgres_ok,
            postgres_msg,
            binary_ok,
            binary_path,
            config_ok,
            config_path: self.config_path.display().to_string(),
            db_ok,
            db_msg,
        }
    }

    /// Find the homeserver binary.
    fn find_binary(&self) -> Option<PathBuf> {
        // 1. Check PATH
        if let Ok(output) = Command::new("which").arg("pubky-homeserver").output() {
            if output.status.success() {
                let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path_str.is_empty() {
                    return Some(PathBuf::from(path_str));
                }
            }
        }

        // 2. Check data dir bin/
        let local_bin = self.data_dir.join("bin").join("pubky-homeserver");
        if local_bin.exists() {
            return Some(local_bin);
        }

        // 3. Check well-known workspace paths for pre-built binary
        let search_paths = [
            // Common dev workspace locations
            "/Volumes/vibedrive/vibes-dev/pubky-core/target/release/pubky-homeserver",
            // Home directory builds
            "~/src/pubky-core/target/release/pubky-homeserver",
            "~/dev/pubky-core/target/release/pubky-homeserver",
            "~/projects/pubky-core/target/release/pubky-homeserver",
        ];

        for path_str in search_paths {
            let expanded = if path_str.starts_with('~') {
                if let Some(home) = dirs_next::home_dir() {
                    home.join(&path_str[2..])
                } else {
                    PathBuf::from(path_str)
                }
            } else {
                PathBuf::from(path_str)
            };
            if expanded.exists() {
                return Some(expanded);
            }
        }

        // 4. Check sibling dirs relative to current exe
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                for rel in &[
                    "../../pubky-core/target/release/pubky-homeserver",
                    "../pubky-core/target/release/pubky-homeserver",
                ] {
                    let p = dir.join(rel);
                    if p.exists() {
                        return Some(p);
                    }
                }
            }
        }

        None
    }

    // ─── Auto-Fix All Prerequisites ───────────────────────────

    /// Automatically fix all prerequisites:
    /// 1. Install PostgreSQL via Homebrew if missing
    /// 2. Start PostgreSQL service
    /// 3. Create database if missing
    /// 4. Generate config if missing
    /// Returns a step-by-step log of what was done.
    pub fn auto_fix(&self) -> Vec<String> {
        let mut log = Vec::new();
        let pg_bin = "/opt/homebrew/opt/postgresql@17/bin";

        // Extend PATH for this process to include Homebrew Postgres
        let current_path = std::env::var("PATH").unwrap_or_default();
        if !current_path.contains(pg_bin) {
            std::env::set_var("PATH", format!("{}:{}", pg_bin, current_path));
        }

        // Step 1: Check/install PostgreSQL
        let (pg_ok, _) = check_postgres();
        if !pg_ok {
            log.push("Installing PostgreSQL via Homebrew...".into());
            match Command::new("brew").args(&["install", "postgresql@17"]).output() {
                Ok(out) => {
                    if out.status.success() {
                        log.push("✅ PostgreSQL 17 installed.".into());
                    } else {
                        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
                        log.push(format!("❌ brew install failed: {}", err));
                        return log;
                    }
                }
                Err(e) => {
                    log.push(format!("❌ Homebrew not found: {}", e));
                    return log;
                }
            }

            // Start the service
            log.push("Starting PostgreSQL service...".into());
            let _ = Command::new("brew").args(&["services", "start", "postgresql@17"]).output();
            // Wait a moment for Postgres to start
            std::thread::sleep(std::time::Duration::from_secs(2));

            // Re-check
            let (pg_ok2, _) = check_postgres();
            if pg_ok2 {
                log.push("✅ PostgreSQL started.".into());
            } else {
                log.push("⚠️ PostgreSQL installed but may need manual start.".into());
            }
        } else {
            log.push("✅ PostgreSQL already running.".into());
        }

        // Step 2: Create database
        let db_url = self.config.read().unwrap().database_url.clone();
        let (db_ok, _) = check_database(&db_url);
        if !db_ok {
            let db_name = db_url.rsplit('/').next().unwrap_or("pubky_homeserver");
            log.push(format!("Creating database '{}'...", db_name));
            match Command::new("createdb").arg(db_name).output() {
                Ok(out) => {
                    if out.status.success() {
                        log.push(format!("✅ Database '{}' created.", db_name));
                    } else {
                        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
                        if err.contains("already exists") {
                            log.push(format!("✅ Database '{}' already exists.", db_name));
                        } else {
                            log.push(format!("❌ createdb failed: {}", err));
                        }
                    }
                }
                Err(e) => log.push(format!("❌ createdb not found: {}", e)),
            }
        } else {
            log.push("✅ Database already exists.".into());
        }

        // Step 3: Find binary (re-check with updated PATH)
        match self.find_binary() {
            Some(path) => {
                log.push(format!("✅ Binary found: {}", path.display()));
                *self.binary_path.write().unwrap() = Some(path);
            }
            None => {
                log.push("❌ pubky-homeserver binary not found.".into());
                log.push("   Install with: cargo install pubky-homeserver".into());
                log.push("   Or build from: https://github.com/pubky/pubky-core".into());
            }
        }

        // Step 4: Generate config if needed
        if !self.config_path.exists() {
            match self.generate_config() {
                Ok(()) => log.push(format!("✅ Config generated: {}", self.config_path.display())),
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
    pub fn start(&self) -> Result<String, String> {
        let state = self.state();
        if state == HomeserverState::Running || state == HomeserverState::Starting {
            return Err("Homeserver is already running.".into());
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
            Ok(child) => {
                let pid = child.id();
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
    fn admin_url(&self) -> String {
        let cfg = self.config.read().unwrap();
        format!("http://127.0.0.1:{}", cfg.admin_port)
    }

    /// Proxy a GET request to the admin API.
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
    pub async fn get_info(&self) -> Result<serde_json::Value, String> {
        self.admin_get("/info").await
    }

    /// Generate a signup token.
    pub async fn generate_signup_token(&self) -> Result<String, String> {
        let resp = self.admin_get("/generate_signup_token").await?;
        resp.get("token")
            .or(resp.get("signup_token"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| format!("Unexpected response: {}", resp))
    }

    /// Disable a user.
    pub async fn disable_user(&self, pubkey: &str) -> Result<serde_json::Value, String> {
        self.admin_post(&format!("/users/{}/disable", pubkey)).await
    }

    /// Enable a user.
    pub async fn enable_user(&self, pubkey: &str) -> Result<serde_json::Value, String> {
        self.admin_post(&format!("/users/{}/enable", pubkey)).await
    }
}

// ─── Helpers ────────────────────────────────────────────────────

/// Check if PostgreSQL is running.
fn check_postgres() -> (bool, String) {
    // Try Homebrew path first, then PATH
    let pg_isready = if std::path::Path::new("/opt/homebrew/opt/postgresql@17/bin/pg_isready").exists() {
        "/opt/homebrew/opt/postgresql@17/bin/pg_isready"
    } else {
        "pg_isready"
    };
    match Command::new(pg_isready).arg("-h").arg("localhost").arg("-p").arg("5432").output() {
        Ok(output) => {
            if output.status.success() {
                (true, "PostgreSQL is running (localhost:5432)".into())
            } else {
                let msg = String::from_utf8_lossy(&output.stderr).trim().to_string();
                (false, format!("PostgreSQL not ready: {}", msg))
            }
        }
        Err(_) => (false, "pg_isready not found. Click Fix All to install.".into()),
    }
}

/// Check if the database exists.
fn check_database(database_url: &str) -> (bool, String) {
    let db_name = database_url.rsplit('/').next().unwrap_or("pubky_homeserver");
    let psql = if std::path::Path::new("/opt/homebrew/opt/postgresql@17/bin/psql").exists() {
        "/opt/homebrew/opt/postgresql@17/bin/psql"
    } else {
        "psql"
    };

    match Command::new(psql)
        .args(&["-lqt"])
        .output()
    {
        Ok(output) => {
            let list = String::from_utf8_lossy(&output.stdout);
            if list.lines().any(|line| {
                line.split('|').next()
                    .map(|s| s.trim() == db_name)
                    .unwrap_or(false)
            }) {
                (true, format!("Database '{}' exists", db_name))
            } else {
                (false, format!("Database '{}' not found", db_name))
            }
        }
        Err(_) => (false, "psql not found. Click Fix All to install.".into()),
    }
}


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
