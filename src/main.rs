mod config;
mod dashboard;
mod dns;
mod publisher;
mod relay;
mod upnp;
mod watchlist;

use std::path::PathBuf;

use clap::Parser;
use tracing::info;

use config::{default_data_dir, load_config};

#[derive(Parser, Debug)]
#[command(
    name = "pubky-node",
    version,
    about = "A unified sovereign network participant for the Pubky ecosystem"
)]
struct Cli {
    /// Path to the data directory containing config.toml
    #[arg(short, long, default_value_os_t = default_data_dir())]
    data_dir: PathBuf,

    /// Override the relay HTTP port
    #[arg(long)]
    relay_port: Option<u16>,

    /// Override the DHT UDP port
    #[arg(long)]
    dht_port: Option<u16>,

    /// Dashboard HTTP port
    #[arg(long, default_value_t = 9090)]
    dashboard_port: u16,

    /// Dashboard bind address (127.0.0.1 = local only, 0.0.0.0 = all interfaces)
    #[arg(long, default_value = "127.0.0.1")]
    dashboard_bind: String,

    /// Disable the DNS resolver
    #[arg(long)]
    no_dns: bool,

    /// Disable UPnP auto-port-forwarding
    #[arg(long)]
    no_upnp: bool,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.verbose {
        "pubky_node=debug,pkarr=debug,mainline=debug,info"
    } else {
        "pubky_node=info,warn"
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| filter.into()),
        )
        .init();

    // Ensure data directory exists
    std::fs::create_dir_all(&cli.data_dir)?;

    // Load configuration
    let config_path = cli.data_dir.join("config.toml");
    let mut config = load_config(&config_path)?;

    // Apply CLI overrides
    if let Some(port) = cli.relay_port {
        config.relay.http_port = port;
    }
    if let Some(port) = cli.dht_port {
        config.dht.port = port;
    }
    if cli.no_dns {
        config.dns.enabled = false;
    }

    // Default cache path to data_dir if not set
    if config.cache.path.is_none() {
        config.cache.path = Some(cli.data_dir.clone());
    }

    info!("╔════════════════════════════════════════╗");
    info!("║        Pubky Node v{}         ║", env!("CARGO_PKG_VERSION"));
    info!("╚════════════════════════════════════════╝");
    info!("Data directory: {:?}", cli.data_dir);

    // === Start subsystems ===

    // 0. UPnP auto-port-forwarding (best-effort, before DHT boots)
    let upnp_status = if cli.no_upnp {
        info!("UPnP: disabled by --no-upnp flag");
        upnp::UpnpStatus::Disabled
    } else {
        upnp::try_map_port(config.dht.port).await
    };

    // Spawn UPnP renewal if mapping succeeded
    let upnp_renewal = if upnp_status.is_mapped() {
        Some(upnp::spawn_renewal(config.dht.port))
    } else {
        None
    };

    // 1. Pkarr Relay (boots DHT node + HTTP relay)
    let relay = relay::start_relay(&config).await?;

    // 2. DNS resolver (subprocess)
    let mut dns_process = dns::DnsProcess::start(&config).await?;

    // 3. Dashboard (separate HTTP server)
    let bind_addr: [u8; 4] = match cli.dashboard_bind.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => ip.octets(),
        Err(_) => {
            tracing::warn!("Invalid --dashboard-bind '{}', defaulting to 127.0.0.1", cli.dashboard_bind);
            [127, 0, 0, 1]
        }
    };
    let dashboard_client = match pkarr::Client::builder().build() {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!("Failed to build dashboard pkarr client: {}. Explorer will be unavailable.", e);
            None
        }
    };
    let dashboard_handle = dashboard::start_dashboard(
        cli.dashboard_port,
        bind_addr,
        config.relay.http_port,
        dashboard_client,
        config.watchlist.clone(),
        upnp_status,
    );

    // 4. Publisher (sign and publish DNS records from secret keys)
    let publisher_handle = if config.publisher.enabled && !config.publisher.keys.is_empty() {
        let client = pkarr::Client::builder().build()?;
        Some(publisher::start_publisher(&config.publisher, client))
    } else {
        None
    };

    // 5. Identity watchlist & republisher
    let watchlist_handle = if config.watchlist.enabled {
        let client = pkarr::Client::builder()
            .build()?;

        watchlist::start_watchlist(&config.watchlist, client)
    } else {
        None
    };

    // === Wait for shutdown ===
    info!("All subsystems running. Press Ctrl+C to stop.");

    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for ctrl-c");

    info!("Shutting down...");

    // Shutdown subsystems
    dashboard_handle.abort();
    if let Some(handle) = publisher_handle {
        handle.abort();
    }
    if let Some(handle) = watchlist_handle {
        handle.abort();
    }
    if let Some(handle) = upnp_renewal {
        handle.abort();
    }
    if let Some(ref mut dns) = dns_process {
        dns.shutdown().await;
    }
    relay.shutdown();

    info!("Pubky Node stopped.");
    Ok(())
}
