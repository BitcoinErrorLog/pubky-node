//! UPnP auto-port-forwarding for the Mainline DHT.
//!
//! Attempts to automatically configure the router to forward UDP traffic
//! to the DHT port. Falls back gracefully to client mode if UPnP is
//! unavailable or the router doesn't support it.

use std::net::SocketAddrV4;
use std::time::Duration;

use tracing::{info, warn, debug};

/// Result of a UPnP port mapping attempt.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum UpnpStatus {
    /// Port successfully mapped. Contains external IP and port.
    Mapped { external_ip: String, port: u16 },
    /// UPnP gateway found but mapping failed.
    Failed(String),
    /// No UPnP gateway found on the network.
    NotFound,
    /// UPnP was disabled by config/CLI.
    Disabled,
}

impl UpnpStatus {
    pub fn is_mapped(&self) -> bool {
        matches!(self, UpnpStatus::Mapped { .. })
    }

    pub fn label(&self) -> &str {
        match self {
            UpnpStatus::Mapped { .. } => "Active",
            UpnpStatus::Failed(_) => "Failed",
            UpnpStatus::NotFound => "No Gateway",
            UpnpStatus::Disabled => "Disabled",
        }
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            UpnpStatus::Failed(msg) => Some(msg.as_str()),
            _ => None,
        }
    }
}

/// Attempt to map a UDP port via UPnP.
///
/// This is best-effort: if it fails, the DHT still works in client mode.
pub async fn try_map_port(dht_port: u16) -> UpnpStatus {
    info!("UPnP: searching for gateway device...");

    let search_result = tokio::time::timeout(
        Duration::from_secs(5),
        igd_next::aio::tokio::search_gateway(igd_next::SearchOptions {
            timeout: Some(Duration::from_secs(3)),
            ..Default::default()
        }),
    )
    .await;

    let gateway = match search_result {
        Ok(Ok(gw)) => {
            info!("UPnP: found gateway at {}", gw.addr);
            gw
        }
        Ok(Err(e)) => {
            debug!("UPnP: gateway search failed: {}", e);
            warn!("UPnP: no gateway found. DHT will run in client mode.");
            return UpnpStatus::NotFound;
        }
        Err(_) => {
            debug!("UPnP: gateway search timed out");
            warn!("UPnP: search timed out. DHT will run in client mode.");
            return UpnpStatus::NotFound;
        }
    };

    // Determine our local address for the mapping
    let local_ip = match gateway.addr.ip() {
        std::net::IpAddr::V4(_) => {
            // Use 0.0.0.0 — the gateway will resolve to our actual LAN IP
            std::net::Ipv4Addr::UNSPECIFIED
        }
        _ => {
            warn!("UPnP: IPv6 gateway not supported for port mapping");
            return UpnpStatus::Failed("IPv6 gateway".to_string());
        }
    };

    let local_addr = SocketAddrV4::new(local_ip, dht_port);

    // Request the port mapping (lease duration 7200s = 2 hours, will be renewed)
    let lease_duration = 7200;
    match gateway
        .add_port(
            igd_next::PortMappingProtocol::UDP,
            dht_port,
            std::net::SocketAddr::V4(local_addr),
            lease_duration,
            "Pubky Node DHT",
        )
        .await
    {
        Ok(()) => {
            // Get the external IP to report
            let external_ip = match gateway.get_external_ip().await {
                Ok(ip) => ip.to_string(),
                Err(_) => "unknown".to_string(),
            };

            info!(
                "UPnP: mapped UDP port {} → {} (external IP: {}, lease: {}s)",
                dht_port, local_addr, external_ip, lease_duration
            );

            UpnpStatus::Mapped {
                external_ip,
                port: dht_port,
            }
        }
        Err(e) => {
            let msg = format!("{}", e);
            warn!("UPnP: port mapping failed: {}. DHT will run in client mode.", msg);
            UpnpStatus::Failed(msg)
        }
    }
}

/// Spawn a background task that renews the UPnP port mapping periodically.
pub fn spawn_renewal(dht_port: u16) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Renew every 60 minutes (lease is 2 hours, so plenty of margin)
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        interval.tick().await; // skip immediate tick

        loop {
            interval.tick().await;
            debug!("UPnP: renewing port mapping for UDP {}", dht_port);
            let status = try_map_port(dht_port).await;
            match status {
                UpnpStatus::Mapped { .. } => {
                    debug!("UPnP: renewal successful");
                }
                other => {
                    warn!("UPnP: renewal failed: {:?}", other);
                }
            }
        }
    })
}
