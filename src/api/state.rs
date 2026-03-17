//! Shared dashboard state used by all API handlers.

use crate::homeserver::HomeserverManager;
use crate::identity::IdentityManager;
use crate::keyvault::KeyVault;
use crate::tunnel::TunnelManager;
use crate::config::WatchlistConfig;
use crate::upnp::UpnpStatus;

use std::path::PathBuf;
use std::sync::{Arc, RwLock, atomic::{AtomicU64, AtomicBool}};
use tokio::sync::{Mutex, broadcast};

/// Shared mutable list of watchlist public keys.
pub type SharedWatchlistKeys = Arc<RwLock<Vec<String>>>;

/// State shared with all dashboard route handlers.
pub struct DashboardState {
    pub client: Option<pkarr::Client>,
    pub watchlist_config: WatchlistConfig,
    pub shared_keys: SharedWatchlistKeys,
    pub data_dir: PathBuf,
    pub start_time: std::time::Instant,
    pub relay_port: u16,
    pub upnp_status: UpnpStatus,
    pub dns_status: String,
    pub dns_socket: String,
    pub dns_forward: String,
    /// Simple rate limiter: epoch millis of last resolve request.
    pub resolve_last_request: AtomicU64,
    /// Vanity key generator state.
    pub vanity: Mutex<VanityState>,
    /// HTTP proxy running flag.
    pub proxy_running: AtomicBool,
    pub proxy_port: u16,
    pub proxy_requests: AtomicU64,
    /// Dashboard password hash (argon2). None = no password set yet.
    pub auth_hash: Arc<RwLock<Option<String>>>,
    /// Encrypted key vault.
    pub vault: KeyVault,
    /// Homeserver process manager.
    pub homeserver: HomeserverManager,
    /// Cloudflare tunnel manager (homeserver).
    pub tunnel: TunnelManager,
    /// Cloudflare tunnel manager (relay HTTP API).
    pub relay_tunnel: TunnelManager,
    /// Cloudflare tunnel manager (PKDNS DoH HTTP API).
    pub dns_tunnel: TunnelManager,
    /// Port for DNS-over-HTTPS HTTP server.
    pub doh_port: u16,
    /// Identity manager (signup/signin tracking).
    pub identity: IdentityManager,
    /// Backup manager for pubky data backup.
    pub backup: crate::backup::BackupManager,
    /// Migration state (shared with background task).
    pub migration_state: crate::migration::SharedMigrationState,
    /// Broadcast channel for log streaming (homeserver stdout lines).
    pub log_tx: broadcast::Sender<String>,
}

/// Vanity key generator internal state.
#[derive(Default)]
pub struct VanityState {
    pub running: bool,
    pub target: String,
    pub suffix: bool,
    pub keys_checked: u64,
    pub started_at: Option<std::time::Instant>,
    pub result_pubkey: Option<String>,
    pub result_seed: Option<String>,
    pub cancel: Option<Arc<AtomicBool>>,
}

impl DashboardState {
    /// Construct a new DashboardState with all subsystem managers.
    pub fn new(
        client: Option<pkarr::Client>,
        watchlist_config: WatchlistConfig,
        shared_keys: SharedWatchlistKeys,
        data_dir: PathBuf,
        relay_port: u16,
        upnp_status: UpnpStatus,
        dns_status: String,
        dns_socket: String,
        dns_forward: String,
        auth_hash: Arc<RwLock<Option<String>>>,
        log_tx: broadcast::Sender<String>,
    ) -> Arc<Self> {
        let vault = KeyVault::new(&data_dir);
        let homeserver = HomeserverManager::new(&data_dir);
        let tunnel = TunnelManager::new(homeserver.get_config().drive_icann_port);
        let relay_tunnel = TunnelManager::new(relay_port);
        let doh_port = 8553u16;
        let dns_tunnel = TunnelManager::new(doh_port);
        let identity = IdentityManager::new(&data_dir);
        let mut backup = crate::backup::BackupManager::new(&data_dir);
        if let Some(ref c) = client {
            backup.set_pkarr_client(c.clone());
        }

        let state = Arc::new(Self {
            client,
            watchlist_config,
            shared_keys,
            data_dir,
            start_time: std::time::Instant::now(),
            relay_port,
            upnp_status,
            dns_status,
            dns_socket,
            dns_forward,
            resolve_last_request: AtomicU64::new(0),
            vanity: Mutex::new(VanityState::default()),
            proxy_running: AtomicBool::new(false),
            proxy_port: 9091,
            proxy_requests: AtomicU64::new(0),
            auth_hash,
            vault,
            homeserver,
            tunnel,
            relay_tunnel,
            dns_tunnel,
            doh_port,
            identity,
            backup,
            migration_state: crate::migration::new_shared_state(),
            log_tx,
        });

        // Wire log broadcast into homeserver so stdout/stderr reach SSE clients
        *state.homeserver.log_tx.write().unwrap() = Some(state.log_tx.clone());

        // Start backup auto-sync background loop
        state.backup.start_auto_sync();

        // Auto-start homeserver if binary is available
        {
            let check = state.homeserver.check_setup();
            if check.binary_ok {
                // Check if homeserver is already running from a previous session
                if state.homeserver.check_process() {
                    tracing::info!("Homeserver already running (detected via admin port) — skipping auto-start");
                } else {
                    tracing::info!("Homeserver binary found — auto-starting...");
                    let state_clone = state.clone();
                    tokio::spawn(async move {
                        // Retry up to 3 times (homeserver can crash on transient DHT errors)
                        for attempt in 1..=3 {
                            match state_clone.homeserver.start().await {
                                Ok(_logs) => {
                                    tracing::info!("Homeserver auto-started successfully");
                                    return;
                                }
                                Err(e) => {
                                    if e.contains("already running") {
                                        tracing::info!("Homeserver already running — auto-start skipped");
                                        return;
                                    }
                                    tracing::warn!(
                                        "Homeserver auto-start attempt {}/3 failed: {}",
                                        attempt, e
                                    );
                                    if attempt < 3 {
                                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                    }
                                }
                            }
                        }
                        tracing::error!("Homeserver auto-start failed after 3 attempts");
                    });
                }
            } else {
                tracing::info!("Homeserver binary not found — skipping auto-start. Install pubky-homeserver or run build-sidecars.sh");
            }
        }

        state
    }
}
