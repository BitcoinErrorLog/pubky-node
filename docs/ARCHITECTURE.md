# Pubky Node — Architecture

## Subsystem Lifecycle

`run_daemon()` in `main.rs` boots everything in this order:

```
1. Load config (TOML + env overrides + CLI flags)
2. Initialize data directory
3. Start Pkarr relay (HTTP + DHT node)
4. Start UPnP port mapping (async, best-effort)
5. Start PKDNS resolver subprocess
6. Start DNS publisher (periodic task)
7. Start watchlist republisher (periodic task)
8. Start HTTP proxy (port 9091)
9. Start dashboard server (port 9090 — mounts all API routes)
10. Auto-start homeserver (if binary available)
    → Start embedded PostgreSQL
    → Start homeserver subprocess
    → Auto-start Cloudflare tunnel
    → Auto-publish PKARR record with tunnel URL
11. Wait for SIGINT/SIGTERM → graceful shutdown
```

Shutdown happens in reverse order. Each subsystem receives a `watch::Receiver<bool>` and polls it.

## Module Dependency Graph

```
main.rs
├── config.rs         (used by all — provides Config struct)
├── relay.rs          (pkarr-relay, pkarr::Client)
├── dns.rs            (subprocess: pkdns binary)
├── publisher.rs      (uses pkarr::Client from relay)
├── watchlist.rs      (uses pkarr::Client from relay)
├── upnp.rs           (standalone, igd-next crate)
├── homeserver.rs     (subprocess: pubky-homeserver binary)
├── embedded_pg.rs    (bundled PostgreSQL extraction + management)
├── tunnel.rs         (subprocess: cloudflared binary)
├── keyvault.rs       (standalone crypto: argon2 + chacha20poly1305)
├── identity.rs       (uses keyvault keys, calls homeserver admin API)
├── backup.rs         (periodic remote homeserver sync)
├── dashboard.rs      (axum server, embedded HTML/CSS/JS)
└── api/              (split API handlers)
    ├── mod.rs         (route registration)
    ├── state.rs       (DashboardState struct + auto-start logic)
    ├── auth.rs        (password authentication, sessions)
    ├── homeserver.rs  (start/stop, config, PKARR publish, set-key)
    ├── vault.rs       (key vault CRUD, generate, import, export)
    ├── tunnel.rs      (Cloudflare tunnel start/stop/status)
    ├── watchlist.rs   (add/remove/list)
    ├── identity.rs    (signup/list)
    ├── quickstart.rs  (one-click: keygen → signup → PKARR → watchlist)
    ├── network.rs     (network status, HTTP proxy)
    └── profile.rs     (pubky.app profile read/write via homeserver)
```

## DashboardState (the shared context)

All subsystems communicate through `DashboardState`, which holds `Arc<RwLock<T>>` references:

```rust
struct DashboardState {
    client: Option<pkarr::Client>,           // DHT client (from relay)
    relay_port: u16,
    watchlist_keys: SharedWatchlistKeys,      // Arc<RwLock<Vec<String>>>
    data_dir: PathBuf,
    upnp_status: UpnpStatus,
    dns_enabled: Arc<RwLock<bool>>,
    vault: KeyVaultManager,                   // Encrypted key storage
    homeserver: HomeserverManager,            // Process lifecycle
    tunnel: TunnelManager,                    // Cloudflare HS tunnel
    relay_tunnel: TunnelManager,              // Cloudflare relay tunnel
    dns_tunnel: TunnelManager,               // Cloudflare DNS tunnel
    identities: Arc<RwLock<Vec<Identity>>>,
    backup: BackupManager,                    // Remote homeserver sync
    log_sender: broadcast::Sender<String>,
    // ... auth config, shutdown channels
}
```

## API Route Map

All routes are registered in `api/mod.rs`:

| Prefix | Auth | Description |
|--------|------|-------------|
| `/api/auth/*` | No | Login, setup, change password |
| `/api/status` | Yes | Node status (DHT, relay, UPnP, DNS, proxy) |
| `/api/resolve/:key` | Yes | Key Explorer — resolve DHT records |
| `/api/publish` | Yes | Sign and publish DNS records |
| `/api/vault/*` | Yes | Key vault CRUD operations |
| `/api/identity/*` | Yes | Signup/signin on homeserver |
| `/api/watchlist` | Yes | Watchlist CRUD |
| `/api/keys/vanity/*` | Yes | Vanity key generator |
| `/api/homeserver/*` | Yes | Homeserver process control + admin |
| `/api/profile/*` | Yes | Profile read/write on homeserver |
| `/api/tunnel/*` | Yes | Homeserver Cloudflare tunnel |
| `/api/relay-tunnel/*` | Yes | Relay Cloudflare tunnel |
| `/api/dns-tunnel/*` | Yes | DNS DoH Cloudflare tunnel |
| `/api/dns/*` | Yes | DNS toggle, system DNS setup |
| `/api/proxy/*` | Yes | /etc/hosts management |
| `/api/backup/*` | Yes | Backup sync status + snapshots |
| `/api/quickstart` | Yes | One-click identity creation |
| `/api/logs/stream` | Yes | SSE log stream (homeserver stdout) |
| `/api/settings` | Yes | Data directory, platform info |
| `/api/shutdown` | Yes | Graceful node shutdown |
| `/api/restart` | Yes | Node restart |
| `/health` | No | Health check ("ok") |
| `/` | No* | Serves embedded HTML (*password prompt) |

## UI Architecture

The dashboard is a single-page app with **no build step**:

- `dashboard.html` — sidebar layout with 10 pages (~2100 lines)
- `dashboard.css` — dark theme, responsive grid, cards (~2000+ lines)
- `dashboard.js` — all client-side logic, polling, API calls (~4800+ lines)

**Sidebar pages**: Dashboard | Keychain | Profile | Server Dashboard | Network Status | Network Explorer | PKARR Publisher | Recovery | Guide | Settings

All 3 files are embedded into the Rust binary via `include_str!()` — changes require rebuild.

## Tauri Desktop App

The Tauri wrapper (`src-tauri/`) is thin:
- Opens a webview pointing at `http://localhost:9090/`
- Manages sidecars: `pubky-node`, `pkdns`, `cloudflared`, `pubky-homeserver`
- System tray with close-to-tray behavior
- Sidecars are pre-built via `scripts/build-sidecars.sh`

## Deployment Targets

| Target | Entry Point |
|--------|-------------|
| macOS desktop | `cargo tauri build` → `.dmg` |
| Docker / Umbrel | `Dockerfile` → multi-stage build |
| CLI binary | `cargo build --release` |

## Auto-Start Chain

On application launch, `state.rs` orchestrates automatic startup:

1. Check if homeserver binary exists
2. Check if homeserver is already running (port probe)
3. Start embedded PostgreSQL → start homeserver (retry up to 3x)
4. Check if `cloudflared` binary exists
5. Start Cloudflare tunnel
6. Wait 5s for tunnel URL
7. Publish PKARR record with current tunnel URL
