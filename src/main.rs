mod cli;
mod config;
mod dashboard;
mod dns;
mod publisher;
mod relay;
mod upnp;
mod watchlist;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing::info;

use config::{default_data_dir, load_config};

#[derive(Parser, Debug)]
#[command(
    name = "pubky-node",
    version,
    about = "A unified sovereign network participant for the Pubky ecosystem"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    // --- Global flags (also used as defaults for `run`) ---
    /// Path to the data directory containing config.toml
    #[arg(short, long, default_value_os_t = default_data_dir(), global = true)]
    data_dir: PathBuf,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the full Pubky Node daemon (default when no subcommand given)
    Run(RunArgs),

    /// Resolve a public key's DNS records from the DHT
    Resolve(cli::resolve::ResolveArgs),

    /// Publish DNS records to the DHT
    Publish(cli::publish::PublishArgs),

    /// Generate a new Ed25519 keypair for DNS publishing
    Keygen(cli::keygen::KeygenArgs),

    /// Query a running node's status
    Status(cli::status::StatusArgs),

    /// Configure OS DNS for .pkarr/.key domain resolution
    #[command(name = "dns-setup")]
    DnsSetup(cli::dns_setup::DnsSetupArgs),
}

#[derive(Parser, Debug)]
struct RunArgs {
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

    match cli.command {
        None | Some(Commands::Run(_)) => {
            // Extract RunArgs (use defaults if bare invocation)
            let run_args = match cli.command {
                Some(Commands::Run(args)) => args,
                _ => RunArgs {
                    relay_port: None,
                    dht_port: None,
                    dashboard_port: 9090,
                    dashboard_bind: "127.0.0.1".to_string(),
                    no_dns: false,
                    no_upnp: false,
                },
            };
            run_daemon(cli.data_dir, run_args).await
        }
        Some(Commands::Resolve(args)) => cli::resolve::execute(args).await,
        Some(Commands::Publish(args)) => cli::publish::execute(args).await,
        Some(Commands::Keygen(args)) => cli::keygen::execute(args),
        Some(Commands::Status(args)) => cli::status::execute(args).await,
        Some(Commands::DnsSetup(args)) => cli::dns_setup::execute(args),
    }
}

async fn run_daemon(data_dir: PathBuf, run_args: RunArgs) -> anyhow::Result<()> {
    // Ensure data directory exists
    std::fs::create_dir_all(&data_dir)?;

    // Load configuration
    let config_path = data_dir.join("config.toml");
    let mut config = load_config(&config_path)?;

    // Apply CLI overrides
    if let Some(port) = run_args.relay_port {
        config.relay.http_port = port;
    }
    if let Some(port) = run_args.dht_port {
        config.dht.port = port;
    }
    if run_args.no_dns {
        config.dns.enabled = false;
    }

    // Default cache path to data_dir if not set
    if config.cache.path.is_none() {
        config.cache.path = Some(data_dir.clone());
    }

    info!("╔════════════════════════════════════════╗");
    info!("║        Pubky Node v{}         ║", env!("CARGO_PKG_VERSION"));
    info!("╚════════════════════════════════════════╝");
    info!("Data directory: {:?}", data_dir);

    // === Start subsystems ===

    // 0. UPnP auto-port-forwarding (best-effort, before DHT boots)
    let upnp_status = if run_args.no_upnp {
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
    let bind_addr: [u8; 4] = match run_args.dashboard_bind.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => ip.octets(),
        Err(_) => {
            tracing::warn!("Invalid --dashboard-bind '{}', defaulting to 127.0.0.1", run_args.dashboard_bind);
            [127, 0, 0, 1]
        }
    };
    let dashboard_client = match pkarr::Client::builder().no_default_network().build() {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!("Failed to build dashboard pkarr client: {}. Explorer will be unavailable.", e);
            None
        }
    };

    // Shared mutable watchlist keys (accessible from dashboard API + watchlist loop)
    let shared_keys: dashboard::SharedWatchlistKeys =
        std::sync::Arc::new(std::sync::RwLock::new(config.watchlist.keys.clone()));

    let dashboard_handle = dashboard::start_dashboard(
        run_args.dashboard_port,
        bind_addr,
        config.relay.http_port,
        dashboard_client,
        config.watchlist.clone(),
        shared_keys.clone(),
        upnp_status,
    );

    // 4. Publisher (sign and publish DNS records from secret keys)
    let publisher_handle = if config.publisher.enabled && !config.publisher.keys.is_empty() {
        let client = pkarr::Client::builder().build()?;
        Some(publisher::start_publisher(&config.publisher, client))
    } else {
        None
    };

    // 5. Identity watchlist & republisher (always runs, reads shared keys each cycle)
    let watchlist_client = pkarr::Client::builder().build()?;
    let watchlist_handle = watchlist::start_watchlist(
        shared_keys,
        config.watchlist.republish_interval_secs,
        watchlist_client,
    );

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
    watchlist_handle.abort();
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
