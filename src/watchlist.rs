use std::time::Duration;

use pkarr::{Client, PublicKey};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::config::WatchlistConfig;

/// Starts the identity watchlist republisher loop.
///
/// Periodically resolves and republishes the configured public keys
/// to keep their Pkarr records alive on the DHT.
pub fn start_watchlist(
    config: &WatchlistConfig,
    client: Client,
) -> Option<JoinHandle<()>> {
    if !config.enabled {
        info!("Identity watchlist is disabled");
        return None;
    }

    if config.keys.is_empty() {
        info!("Watchlist is enabled but no keys configured");
        return None;
    }

    let keys: Vec<String> = config.keys.clone();
    let interval_secs = config.republish_interval_secs;
    let interval = Duration::from_secs(interval_secs);

    info!(
        "Watchlist active: monitoring {} key(s), republishing every {}s",
        keys.len(),
        interval_secs,
    );

    let handle = tokio::spawn(async move {
        // Run first cycle immediately on startup
        republish_cycle(&client, &keys, interval_secs).await;

        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // consume the immediate tick

        loop {
            ticker.tick().await;
            republish_cycle(&client, &keys, interval_secs).await;
        }
    });

    Some(handle)
}

async fn republish_cycle(client: &Client, keys: &[String], interval_secs: u64) {
    info!("Watchlist: starting republish cycle for {} key(s)", keys.len());

    for key_str in keys {
        match key_str.parse::<PublicKey>() {
            Ok(public_key) => {
                republish_one(client, &public_key, key_str, interval_secs).await;
            }
            Err(e) => {
                warn!("Watchlist: invalid public key '{}': {}", key_str, e);
            }
        }
    }

    info!("Watchlist: republish cycle complete");
}

async fn republish_one(client: &Client, public_key: &PublicKey, label: &str, interval_secs: u64) {
    let short = &label[..label.len().min(12)];

    match client.resolve(public_key).await {
        Some(signed_packet) => {
            let age_secs = signed_packet.elapsed();

            // M5: Skip republish if record is still fresh (less than half interval)
            let freshness_threshold = interval_secs as u32 / 2;
            if age_secs < freshness_threshold {
                info!(
                    "Watchlist [{}...]: record is still fresh (age: {}s < {}s threshold), skipping",
                    short, age_secs, freshness_threshold,
                );
                return;
            }

            info!(
                "Watchlist [{}...]: record needs refresh (age: {}s), republishing...",
                short, age_secs,
            );

            match client.publish(&signed_packet, None).await {
                Ok(()) => {
                    info!("Watchlist [{}...]: republished successfully", short);
                }
                Err(e) => {
                    error!("Watchlist [{}...]: republish failed: {}", short, e);
                }
            }
        }
        None => {
            warn!(
                "Watchlist [{}...]: no record found on DHT, cannot republish",
                short,
            );
        }
    }
}
