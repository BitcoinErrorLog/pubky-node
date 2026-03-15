# Pubky Node — Agent Bootstrap Context

> Read this file first in any new AI session. It gives you everything you need to orient yourself.

## What This Project Is

**Pubky Node** is a unified sovereign network participant for the Pubky ecosystem. It bundles multiple subsystems into a single Rust binary with a web dashboard:

- **Mainline DHT node** — connects to ~12M+ peer BitTorrent DHT network (BEP44)
- **Pkarr relay** — HTTP API for publishing/resolving signed DNS packets
- **DNS publisher** — signs and publishes DNS records to DHT
- **PKDNS resolver** — local DNS server for sovereign `.pkarr` / `.key` domains
- **Homeserver** — a full Pubky homeserver with embedded PostgreSQL
- **Web dashboard** — real-time monitoring UI and management tools
- **Desktop app** — Tauri wrapper for macOS/Windows/Linux with system tray

## Repository Layout

```
pubky-node/
├── src/                    # Main Rust source (the binary crate)
│   ├── main.rs             # Entrypoint: CLI parsing + run_daemon() orchestration
│   ├── config.rs           # TOML config + env var overrides + validation
│   ├── dashboard.rs        # Route setup + embedded asset serving
│   ├── dashboard.html      # Embedded HTML for the dashboard UI (~2100 lines)
│   ├── dashboard.css       # Embedded CSS for the dashboard (~2000+ lines)
│   ├── dashboard.js        # Embedded JS for the dashboard (~3700+ lines)
│   ├── relay.rs            # Pkarr relay startup wrapper
│   ├── dns.rs              # PKDNS subprocess management
│   ├── publisher.rs        # DNS record signing + DHT publishing with retry
│   ├── watchlist.rs        # Identity republisher (keeps DHT records alive)
│   ├── homeserver.rs       # Homeserver process lifecycle management
│   ├── embedded_pg.rs      # Embedded PostgreSQL extraction and management
│   ├── tunnel.rs           # Cloudflare quick-tunnel management (cloudflared subprocess)
│   ├── keyvault.rs         # Encrypted key storage (argon2id + ChaCha20-Poly1305)
│   ├── identity.rs         # EdDSA AuthToken signup/signin on homeserver
│   ├── upnp.rs             # UPnP auto-port-forwarding
│   ├── api/                # API endpoint handlers (split from dashboard.rs)
│   │   ├── mod.rs           # Route registration + shared imports
│   │   ├── state.rs         # DashboardState struct + initialization
│   │   ├── auth.rs          # Authentication middleware
│   │   ├── homeserver.rs    # Homeserver lifecycle, config, PKARR publish, set-key
│   │   ├── vault.rs         # Key vault CRUD (add, export, generate, import)
│   │   ├── tunnel.rs        # Cloudflare tunnel start/stop/status + relay tunnel
│   │   ├── watchlist.rs     # Watchlist add/remove/list
│   │   ├── identity.rs      # Identity signup/list
│   │   ├── quickstart.rs    # One-click identity creation (keygen→signup→PKARR→watchlist)
│   │   └── network.rs       # Network status, HTTP proxy
│   └── cli/                # CLI subcommand handlers
│       ├── mod.rs           # Subcommand enum definition
│       ├── resolve.rs       # `pubky-node resolve <KEY>`
│       ├── publish.rs       # `pubky-node publish ...`
│       ├── keygen.rs        # `pubky-node keygen`
│       ├── vanity.rs        # `pubky-node vanity <PREFIX>`
│       ├── status.rs        # `pubky-node status`
│       ├── dns_setup.rs     # `pubky-node dns-setup`
│       ├── proxy_hosts.rs   # `pubky-node proxy-hosts`
│       ├── watchlist.rs     # `pubky-node watchlist {list,add,remove}`
│       ├── homeserver.rs    # `pubky-node homeserver {status,start,stop,...}`
│       ├── tunnel.rs        # `pubky-node tunnel {status,start,stop,check}`
│       └── node.rs          # `pubky-node node {restart,shutdown}`
│
├── src-tauri/              # Tauri desktop app wrapper
│   ├── Cargo.toml           # Tauri crate deps
│   ├── tauri.conf.json      # Tauri config (window, sidecars, etc.)
│   ├── src/lib.rs           # Tauri setup (system tray, close-to-tray)
│   ├── src/main.rs          # Tauri main entrypoint
│   ├── binaries/            # Compiled sidecars (pubky-node, pkdns, cloudflared, homeserver)
│   └── icons/               # App icons for all platforms
│
├── src-ui/                 # Thin Tauri webview entry point
│   └── index.html           # Just loads http://localhost:9090/ in the Tauri window
│
├── scripts/
│   └── build-sidecars.sh    # Builds pubky-node + pkdns binaries for Tauri sidecar
│
├── docs/
│   └── screenshots/         # Dashboard tab screenshots (used by README)
│
├── umbrel/                 # Umbrel app store deployment
│   ├── README.md
│   └── pubky-node/          # Docker compose, manifest, exports
│
├── Cargo.toml              # Main crate dependencies
├── Dockerfile              # Multi-stage build for Docker/Umbrel
├── config.sample.toml      # Example configuration file
└── README.md               # Project README (comprehensive)
```

## Key Architecture Patterns

### Supervision Model
`main.rs::run_daemon()` is the supervisor. It starts subsystems in order and manages graceful shutdown via `tokio::signal` + shutdown channels. Each subsystem gets a `shutdown_rx` channel.

### API Module Structure
API handlers are split into `src/api/` modules (homeserver, vault, tunnel, watchlist, identity, quickstart, network). Routes are registered in `api/mod.rs`. State is in `api/state.rs` with the `DashboardState` struct holding `Arc<RwLock<...>>` references to all subsystem state. The dashboard UI (HTML/CSS/JS) is embedded via `include_str!()` in `dashboard.rs`.

### Homeserver Key Management
The homeserver stores its secret keypair at `{data_dir}/secret` as a hex string. On startup it calls `read_or_create_keypair()` — reads from `secret` file or generates a random one.
- **set_server_key()**: Writes a vault key's secret to the `secret` file BEFORE starting the homeserver, so the HS uses a key we control.
- **read_server_secret()**: Reads the secret back from the file for PKARR publishing.
- **publish_homeserver_pkarr()**: Publishes an HTTPS record to DHT. Falls back to tunnel URL when domain is "localhost", and to `read_server_secret()` when vault doesn't have the key.

### Embedded Assets
The HTML, CSS, and JS files in `src/` are embedded into the binary at compile time via `include_str!()` in `dashboard.rs`. Changes to these files require a rebuild to take effect in the running app.

### Subprocess Management
Several components run as subprocesses managed by the main binary:
- **pkdns** — DNS resolver (spawned via `Command::new`)
- **cloudflared** — Cloudflare tunnels (2 instances: homeserver + relay)
- **pubky-homeserver** — the homeserver binary
- **embedded PostgreSQL** — extracted from bundled tarball on first run

### Local Dependencies
`pkarr` and `pkarr-relay` are local path dependencies (sibling directories):
```toml
pkarr-relay = { path = "../pkarr/relay" }
pkarr = { path = "../pkarr/pkarr", ... }
```
The sibling repos must exist at:
- `/Volumes/vibedrive/vibes-dev/pkarr/`
- `/Volumes/vibedrive/vibes-dev/pkdns/`

## Common Commands

```bash
# Development — just the CLI binary (fastest iteration)
cargo build --release
cargo run --release
cargo run --release -- --no-dns    # skip pkdns if binary not available

# Run tests
cargo test

# Full desktop app build (see /deploy-changes workflow)
bash scripts/build-sidecars.sh --release   # compile sidecars
cargo tauri build                           # build .dmg

# Docker
docker build -t pubky-node -f Dockerfile .
```

## Dashboard Access
- URL: `http://localhost:9090/`
- Password-protected (set on first run)
- Dev credentials stored in `.dev-secrets` (gitignored)
- Auth: `X-Auth-Password` header or HTTP Basic Auth

## Key API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/quickstart` | POST | One-click: keygen → signup → PKARR → watchlist |
| `/api/homeserver/set-key` | POST | Assign a vault key as the homeserver's identity |
| `/api/homeserver/start` | POST | Start homeserver + auto-publish PKARR |
| `/api/homeserver/publish-pkarr` | POST | Publish homeserver's PKARR record to DHT |
| `/api/tunnel/start` | POST | Start tunnel + auto-update PKARR with tunnel URL |
| `/api/vault/generate` | POST | Generate random Ed25519 keypair in vault |
| `/api/vault/unlock` | POST | Unlock vault with password |
| `/api/vault/keys` | GET | List vault keys (public info only) |

## Data Directory
Default: `~/Library/Application Support/pubky-node/` on macOS (override with `--data-dir`)

Key files:
- `config.toml` — user config
- `auth.json` — dashboard password hash
- `keyvault.enc` — encrypted key vault
- `watchlist.json` — persisted watchlist keys
- `identities.json` — registered identities
- `secret` — homeserver's Ed25519 secret key (hex, 64 chars)
- `pkarr-cache/` — LMDB cache
- `pg/` — embedded PostgreSQL data
- `config.toml` — homeserver-generated config (ports, signup mode, etc.)

## Conventions

1. **100% vibes** — this codebase was prompted using AI tools; no human has reviewed the code line-by-line
2. **Single-file dashboard** — all API routes live in `dashboard.rs`, HTML in `dashboard.html`
3. **No frontend framework** — the dashboard is vanilla HTML/CSS/JS with no build step
4. **State sharing** — subsystems communicate via `Arc<RwLock<T>>` fields in `DashboardState`
5. **Graceful shutdown** — all long-running tasks listen on `tokio::sync::watch` channels
6. **Config precedence** — CLI flags > environment variables > config.toml > defaults

## Known Gotchas

- **macOS app replacement**: Must `rm -rf "/Applications/Pubky Node.app"` before copying new build — `cp -R` silently skips existing app bundles
- **Embedded HTML**: Changes to `dashboard.html/css/js` require a full `cargo build` to be included (they're `include_str!()`)
- **Port 53**: PKDNS needs port 53 which requires elevated privileges or conflicts with existing DNS
- **Sibling repos**: Build fails if `../pkarr/` and `../pkdns/` directories don't exist
- **PostgreSQL extraction**: First-run extracts embedded PG (~100MB) to `~/.pubky-node/pg/` — takes 30-60 seconds
- **Dev vs Release**: The DEV badge, missing binaries, etc. are NOT about cargo debug/release profiles. The `cargo run --release` approach works fine for dev — the Tauri DMG is for distribution. Use `/deploy-changes` workflow only when shipping.
- **Port 9090 conflict**: If running `cargo run --release` AND the Tauri app simultaneously, they fight over port 9090. Kill one before starting the other.
- **Vault must be unlocked** for identity operations: The wizard key selector, quickstart, and PKARR publishing all require the vault to be unlocked.
- **Homeserver key flow**: The homeserver generates its OWN key on first run (writes to `{data_dir}/secret`). To control which key it uses, call `set_server_key()` BEFORE first start — otherwise you'll need to delete the `secret` file and restart.
- **PKARR publish fallback chain**: vault.export_key() → read_server_secret() → fail. This is used everywhere PKARR is published (manual, auto-start, tunnel-start).
