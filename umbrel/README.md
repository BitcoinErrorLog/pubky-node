# Pubky Node — Umbrel App Store

One-click deployment of Pubky Node on [Umbrel](https://umbrel.com).

## What You Get

| Feature | Description |
|---------|-------------|
| **DHT Node** | Full Mainline DHT participant — the largest P2P network on Earth |
| **Pkarr Relay** | HTTP API for publishing and resolving decentralized DNS records |
| **Web Dashboard** | Real-time monitoring with Key Explorer and User Guide |
| **Identity Watchlist** | Keeps friends' records alive by periodically republishing them |
| **UPnP Auto-Config** | Automatically opens ports on your router for full DHT participation |
| **DNS Publisher** | Sign and publish DNS records with Ed25519 keys |

## Quick Start

### 1. Add the Community App Store

On your Umbrel device:
1. Go to **App Store** → **Community App Stores**
2. Paste this repository URL
3. Click **Add**

### 2. Install Pubky Node

Find "Pubky Node" in the Networking category and click **Install**. That's it — zero configuration required.

### 3. Open the Dashboard

Click the app icon to access the dashboard. You'll see:
- **Status tab** — DHT connectivity, relay info, UPnP status, watchlist
- **Explorer tab** — Look up any public key's DNS records on the DHT
- **Guide tab** — Comprehensive documentation

## Network & Port Forwarding

### Automatic (UPnP)
Pubky Node automatically attempts to configure your router via UPnP on startup. If your router supports it (most do), UDP port 6881 is mapped automatically and your node runs in **Server mode** — actively helping store data for the network.

### If UPnP Fails
The node falls back to **Client mode**, which is fully functional:
- ✅ Resolve any public key
- ✅ Publish your own records
- ✅ Run the relay and dashboard
- ❌ Won't store data for other nodes

To manually enable Server mode, forward **UDP port 6881** on your router.

### Checking Your Status
Open the dashboard and look at the **Network / UPnP** card:
- **Active** — Port mapped successfully, full participation
- **No Gateway** — UPnP not available, running in client mode
- **Failed** — UPnP found but couldn't map the port

## Configuration

### Environment Variables

Set these in `docker-compose.yml` under `environment:` to customize without a config file:

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `pubky_node=info,pkarr=info` | Log level |
| `PUBKY_RELAY_PORT` | `6881` | Pkarr relay HTTP port |
| `PUBKY_DHT_PORT` | `6881` | Mainline DHT UDP port |
| `PUBKY_WATCHLIST_KEYS` | *(empty)* | Comma-separated public keys to watch |
| `PUBKY_DNS_ENABLED` | `false` | Enable pkdns resolver (needs port 53) |

### Config File

For advanced users, create `/data/config.toml` inside the container (mapped to `${APP_DATA_DIR}/data/config.toml` on the host). See the [main README](https://github.com/pubky/pubky-node#configuration) for all options.

### Example: Adding Watchlist Keys

Edit `docker-compose.yml`:

```yaml
environment:
  - PUBKY_WATCHLIST_KEYS=pk:yg4gxe7z1r7mr6orids9fh95y7gxhdsxjqi6nngsxxtakqaxr5no,pk:another_key_here
```

Then restart the app in Umbrel.

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 9090 | TCP | Dashboard (proxied through Umbrel) |
| 6881 | TCP | Pkarr relay HTTP API |
| 6881 | UDP | Mainline DHT (needs forwarding for server mode) |

## Data Persistence

All data is stored in `${APP_DATA_DIR}/data/`:

| Path | Contents |
|------|----------|
| `config.toml` | User configuration (created on demand) |
| `pkarr-cache/` | LMDB cache for signed packets |
| `pkdns/` | DNS resolver cache (if enabled) |

## Building from Source

The Docker image bundles both `pubky-node` and `pkdns`. To build:

```bash
# From the parent directory containing pubky-node, pkarr, and pkdns repos
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/pubky/pubky-node:v0.1.0 \
  -f pubky-node/Dockerfile \
  --push .
```

## Repository Structure

```
umbrel/
├── umbrel-app-store.yml      # Store metadata (id: pubky)
├── pubky-node/
│   ├── umbrel-app.yml        # App manifest
│   ├── docker-compose.yml    # Container services
│   └── exports.sh            # Env vars for other Umbrel apps
└── README.md                 # This file
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Dashboard not loading | Check Umbrel logs: `docker logs pubky-node_server_1` |
| DHT shows 0 nodes | Wait 30 seconds for bootstrap, check internet connectivity |
| UPnP shows "No Gateway" | Router may not support UPnP, or it's disabled in router settings |
| DNS resolver not starting | `pkdns` needs port 53 which conflicts with some systems. Set `PUBKY_DNS_ENABLED=false` |

## Links

- [Pubky Node GitHub](https://github.com/pubky/pubky-node)
- [Pkarr Protocol](https://github.com/pubky/pkarr)
- [Umbrel Documentation](https://umbrel.com/umbrelos)
