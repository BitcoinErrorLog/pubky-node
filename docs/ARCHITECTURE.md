# Pubky Node — Architecture

## Subsystem Lifecycle

`run_daemon()` in `main.rs` boots everything in this order:

```
1. Load config (TOML + env overrides + CLI flags)
2. Initialize data directory
3. Start embedded PostgreSQL (if homeserver enabled)
4. Start Pkarr relay (HTTP + DHT node)
5. Start UPnP port mapping (async, best-effort)
6. Start PKDNS resolver subprocess
7. Start DNS publisher (periodic task)
8. Start watchlist republisher (periodic task)
9. Start HTTP proxy (port 9091)
10. Start dashboard server (port 9090 — mounts all API routes)
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
├── embedded_pg.rs    (postgresql_embedded crate)
├── tunnel.rs         (subprocess: cloudflared binary)
├── keyvault.rs       (standalone crypto: argon2 + chacha20poly1305)
├── identity.rs       (uses keyvault keys, calls homeserver admin API)
└── dashboard.rs      (axum server, depends on ALL of the above via DashboardState)
```

## DashboardState (the shared context)

```rust
struct DashboardState {
    client: Option<pkarr::Client>,      // DHT client (from relay)
    relay_port: u16,
    watchlist_keys: SharedWatchlistKeys, // Arc<RwLock<Vec<String>>>
    data_dir: PathBuf,
    upnp_status: UpnpStatus,            // Arc<RwLock<UpnpInfo>>
    dns_status: String,
    dns_enabled: Arc<RwLock<bool>>,
    dns_socket: String,
    dns_forward: String,
    vault: Arc<RwLock<Option<KeyVault>>>,
    vault_path: PathBuf,
    homeserver: Arc<RwLock<HomeserverState>>,
    tunnel: Arc<RwLock<TunnelState>>,
    relay_tunnel: Arc<RwLock<TunnelState>>,
    identities: Arc<RwLock<Vec<Identity>>>,
    log_sender: broadcast::Sender<String>,
    // ... auth config, shutdown channels, etc.
}
```

## API Route Map

All routes are defined in `start_dashboard()` in `dashboard.rs`:

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
| `/api/tunnel/*` | Yes | Homeserver Cloudflare tunnel |
| `/api/relay-tunnel/*` | Yes | Relay Cloudflare tunnel |
| `/api/dns/*` | Yes | DNS toggle, system DNS setup |
| `/api/proxy/*` | Yes | /etc/hosts management |
| `/api/logs/stream` | Yes | SSE log stream (homeserver stdout) |
| `/api/settings` | Yes | Data directory, platform info |
| `/api/shutdown` | Yes | Graceful node shutdown |
| `/api/restart` | Yes | Node restart |
| `/health` | No | Health check ("ok") |
| `/` | No* | Serves embedded HTML (*password prompt in JS) |

## UI Architecture

The dashboard is a single-page app with **no build step**:

- `dashboard.html` — all HTML structure (~1600 lines), 6 tabs worth of UI
- `dashboard.css` — all styles (~2000+ lines), dark theme, responsive grid
- `dashboard.js` — all client-side logic, polling, API calls, SSE

Tabs: **Networks** | **Keys** | **Homeserver** | **Explorer** | (icons) **Guide** | **Settings**

All 3 files are embedded into the Rust binary via `include_str!()` and served as inline responses.

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

## Testing

```bash
cargo test                    # 93 tests, 0 failures (as of last check)
cargo clippy                  # lint check
```

Tests are mostly in `dashboard.rs` (`#[cfg(test)]` module at the bottom) and cover:
- Config parsing and validation
- API endpoint responses
- Key vault encryption/decryption
- Watchlist persistence
