//! Pkarr relay initialization.
//!
//! Configures and starts the Pkarr relay, which combines an HTTP API
//! for publishing/resolving signed DNS packets with an internal
//! Mainline DHT node for peer-to-peer record storage.

use anyhow::Context;
use pkarr_relay::Relay;
use tracing::info;

use crate::config::Config;

/// Starts the Pkarr relay (HTTP API + internal DHT node).
/// Returns the running Relay handle.
pub async fn start_relay(config: &Config) -> anyhow::Result<Relay> {
    let mut builder = Relay::builder();

    builder.http_port(config.relay.http_port);

    // Configure cache storage
    if let Some(ref cache_path) = config.cache.path {
        builder.storage(cache_path.clone());
    }
    builder.cache_size(config.cache.size);

    // Configure the internal DHT node port via the pkarr client builder
    let dht_port = config.dht.port;
    builder.pkarr(move |pkarr_builder| {
        pkarr_builder.dht(move |dht_builder| {
            dht_builder.port(dht_port)
        })
    });

    info!("Starting Pkarr relay on HTTP port {}...", config.relay.http_port);
    info!("Starting DHT node on UDP port {}...", config.dht.port);

    // Safety: LMDB cache usage. We accept this as documented in pkarr-relay.
    let relay = unsafe { builder.run() }
        .await
        .context("Failed to start Pkarr relay")?;

    info!("Relay listening on {}", relay.local_url());

    Ok(relay)
}
