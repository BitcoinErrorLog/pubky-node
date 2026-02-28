use std::time::Duration;

use pkarr::{Client, PublicKey};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::dashboard::SharedWatchlistKeys;

/// Starts the identity watchlist republisher loop.
///
/// Periodically reads the shared key list and republishes each key's
/// Pkarr records to keep them alive on the DHT.
pub fn start_watchlist(
    shared_keys: SharedWatchlistKeys,
    interval_secs: u64,
    client: Client,
) -> JoinHandle<()> {
    let interval = Duration::from_secs(interval_secs);

    info!(
        "Watchlist republisher started (interval: {}s)",
        interval_secs,
    );

    tokio::spawn(async move {
        // Small delay before first cycle to let DHT bootstrap
        tokio::time::sleep(Duration::from_secs(5)).await;

        let mut ticker = tokio::time::interval(interval);

        loop {
            ticker.tick().await;

            let keys = shared_keys.read().unwrap().clone();
            if keys.is_empty() {
                continue;
            }

            info!("Watchlist: starting republish cycle for {} key(s)", keys.len());
            republish_cycle(&client, &keys, interval_secs).await;
            info!("Watchlist: republish cycle complete");
        }
    })
}

async fn republish_cycle(client: &Client, keys: &[String], interval_secs: u64) {
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
}

async fn republish_one(client: &Client, public_key: &PublicKey, label: &str, interval_secs: u64) {
    let short = &label[..label.len().min(12)];

    match client.resolve(public_key).await {
        Some(signed_packet) => {
            let age_secs = signed_packet.elapsed();

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
