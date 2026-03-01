// Tunnel Manager — lifecycle management for cloudflared quick-tunnel
//
// Spawns `cloudflared tunnel --url http://127.0.0.1:{icann_port}` and
// parses stdout for the public trycloudflare.com URL.

use std::process::{Child, Command, Stdio};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, PartialEq)]
pub enum TunnelState {
    Stopped,
    Starting,
    Running,
    Error(String),
}

impl TunnelState {
    pub fn as_str(&self) -> &str {
        match self {
            TunnelState::Stopped => "stopped",
            TunnelState::Starting => "starting",
            TunnelState::Running => "running",
            TunnelState::Error(_) => "error",
        }
    }
}

/// Shared inner state — placed in Arc so threads can safely mutate it.
struct TunnelInner {
    process: std::sync::Mutex<Option<Child>>,
    state: RwLock<TunnelState>,
    public_url: RwLock<Option<String>>,
}

pub struct TunnelManager {
    inner: Arc<TunnelInner>,
    target_port: u16,
}

impl TunnelManager {
    pub fn new(target_port: u16) -> Self {
        TunnelManager {
            inner: Arc::new(TunnelInner {
                process: std::sync::Mutex::new(None),
                state: RwLock::new(TunnelState::Stopped),
                public_url: RwLock::new(None),
            }),
            target_port,
        }
    }

    pub fn state(&self) -> TunnelState {
        self.inner.state.read().unwrap().clone()
    }

    pub fn public_url(&self) -> Option<String> {
        self.inner.public_url.read().unwrap().clone()
    }

    /// Check if cloudflared binary is available.
    pub fn binary_available() -> bool {
        Self::find_binary().is_some()
    }

    /// Find cloudflared binary path.
    /// Search order: bundled sidecar → data_dir/bin → PATH
    fn find_binary() -> Option<std::path::PathBuf> {
        // 1. Check bundled sidecar directory (same dir as current exe — Tauri convention)
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let sibling = dir.join("cloudflared");
                if sibling.exists() {
                    return Some(sibling);
                }
                // macOS: .app/Contents/MacOS/../Resources/
                let resources = dir.join("../Resources/cloudflared");
                if resources.exists() {
                    return Some(resources);
                }
            }
        }

        // 2. Check data dir
        let home = dirs_next::home_dir().unwrap_or_default();
        let local = home.join(".pubky-node/bin/cloudflared");
        if local.exists() {
            return Some(local);
        }

        // 3. Check PATH
        if let Ok(out) = Command::new("which").arg("cloudflared").output() {
            if out.status.success() {
                let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !path.is_empty() {
                    return Some(std::path::PathBuf::from(path));
                }
            }
        }

        None
    }

    /// Start a cloudflared quick-tunnel to the homeserver ICANN port.
    pub fn start(&self) -> Result<(), String> {
        if matches!(self.state(), TunnelState::Running | TunnelState::Starting) {
            return Err("Tunnel already running.".into());
        }

        let binary = Self::find_binary()
            .ok_or_else(|| "cloudflared not found. Install from https://github.com/cloudflare/cloudflared/releases".to_string())?;

        let target_url = format!("http://127.0.0.1:{}", self.target_port);

        let mut child = Command::new(&binary)
            .args(&["tunnel", "--url", &target_url])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to start cloudflared: {}", e))?;

        *self.inner.state.write().unwrap() = TunnelState::Starting;
        *self.inner.public_url.write().unwrap() = None;

        // Spawn thread to read stderr (cloudflared logs the URL to stderr)
        let stderr = child.stderr.take();
        let inner = Arc::clone(&self.inner);

        std::thread::spawn(move || {
            if let Some(stderr) = stderr {
                use std::io::BufRead;
                for line in std::io::BufReader::new(stderr).lines().flatten() {
                    tracing::debug!("cloudflared: {}", &line);

                    if let Some(url) = extract_tunnel_url(&line) {
                        tracing::info!("Cloudflare Tunnel URL: {}", url);
                        *inner.public_url.write().unwrap() = Some(url);
                        *inner.state.write().unwrap() = TunnelState::Running;
                    }
                }
                // Process exited
                let mut s = inner.state.write().unwrap();
                if !matches!(*s, TunnelState::Stopped) {
                    *s = TunnelState::Error("cloudflared process exited".into());
                }
            }
        });

        *self.inner.process.lock().unwrap() = Some(child);
        Ok(())
    }

    /// Stop the tunnel process.
    pub fn stop(&self) {
        let mut proc = self.inner.process.lock().unwrap();
        if let Some(ref mut child) = *proc {
            let _ = child.kill();
            let _ = child.wait();
        }
        *proc = None;
        *self.inner.state.write().unwrap() = TunnelState::Stopped;
        *self.inner.public_url.write().unwrap() = None;
    }

    /// Check if process is still alive.
    pub fn check_process(&self) {
        let mut proc = self.inner.process.lock().unwrap();
        if let Some(ref mut child) = *proc {
            if let Ok(Some(_)) = child.try_wait() {
                *proc = None;
                let mut s = self.inner.state.write().unwrap();
                if matches!(*s, TunnelState::Running) {
                    *s = TunnelState::Error("Process exited unexpectedly".into());
                }
            }
        }
    }
}

/// Extract a trycloudflare.com URL from a cloudflared log line.
fn extract_tunnel_url(line: &str) -> Option<String> {
    if let Some(start) = line.find("https://") {
        let rest = &line[start..];
        let end = rest.find(|c: char| c.is_whitespace() || c == '|' || c == '"').unwrap_or(rest.len());
        let url = rest[..end].trim_end_matches('/').to_string();
        if url.contains("trycloudflare.com") && url.len() > 10 {
            return Some(url);
        }
    }
    None
}
