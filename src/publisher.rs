//! DNS record publishing to the Mainline DHT.
//!
//! Adapted from pkdns-publisher. Supports:
//! - **Publisher mode**: sign and publish DNS records from a secret key
//! - **Republisher mode**: already handled by `watchlist.rs`

use std::time::Duration;

use pkarr::{Client, Keypair, SignedPacket};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::config::PublisherConfig;

/// Start the publisher loop as a background task.
pub fn start_publisher(config: &PublisherConfig, client: Client) -> JoinHandle<()> {
    let interval = Duration::from_secs(config.interval_secs);
    let max_retries = config.max_retries;
    let retry_delay = Duration::from_secs(config.retry_delay_secs);

    // Load all keypairs once at startup (M3: avoid repeated disk reads)
    let loaded_keys: Vec<(usize, Keypair, Vec<RecordConfig>)> = config
        .keys
        .iter()
        .enumerate()
        .filter_map(|(i, key_config)| {
            match key_config.load_keypair() {
                Ok(kp) => Some((i, kp, key_config.records.clone())),
                Err(e) => {
                    error!("Publisher key[{}]: failed to load keypair: {}", i, e);
                    None
                }
            }
        })
        .collect();

    if loaded_keys.is_empty() {
        info!("Publisher: no valid keypairs loaded, publisher will not run");
    }

    tokio::spawn(async move {
        info!("Publisher: managing {} keypair(s)", loaded_keys.len());

        loop {
            for (i, keypair, records) in &loaded_keys {
                publish_key(&client, *i, keypair, records, max_retries, retry_delay).await;
            }

            info!("Publisher: sleeping {}s until next cycle", interval.as_secs());
            tokio::time::sleep(interval).await;
        }
    })
}

async fn publish_key(
    client: &Client,
    index: usize,
    keypair: &Keypair,
    records: &[RecordConfig],
    max_retries: u32,
    retry_delay: Duration,
) {
    let public_key = keypair.public_key();
    let label = public_key.to_string();
    let short = &label[..label.len().min(12)];

    // Build the signed packet from configured records
    let packet = match build_signed_packet(keypair, records) {
        Ok(p) => p,
        Err(e) => {
            error!("Publisher key[{}] [{}...]: failed to build packet: {}", index, short, e);
            return;
        }
    };

    info!(
        "Publisher key[{}] [{}...]: publishing {} record(s)...",
        index,
        short,
        records.len()
    );

    // Publish with retry
    publish_with_retry(client, &packet, short, max_retries, retry_delay).await;
}

async fn publish_with_retry(
    client: &Client,
    packet: &SignedPacket,
    label: &str,
    max_retries: u32,
    base_delay: Duration,
) {
    for attempt in 0..=max_retries {
        match client.publish(packet, None).await {
            Ok(()) => {
                info!("Publisher [{}...]: published successfully", label);
                return;
            }
            Err(e) => {
                if attempt < max_retries {
                    let delay = base_delay * 2u32.pow(attempt);
                    warn!(
                        "Publisher [{}...]: attempt {}/{} failed: {}. Retrying in {:?}...",
                        label, attempt + 1, max_retries, e, delay
                    );
                    tokio::time::sleep(delay).await;
                } else {
                    error!(
                        "Publisher [{}...]: all {} attempts failed: {}",
                        label,
                        max_retries + 1,
                        e
                    );
                }
            }
        }
    }
}

/// Build a SignedPacket from a keypair and a list of DNS record configs.
fn build_signed_packet(
    keypair: &Keypair,
    records: &[RecordConfig],
) -> anyhow::Result<SignedPacket> {
    use pkarr::dns::rdata::TXT;
    use pkarr::dns::Name;

    let mut builder = SignedPacket::builder();

    for record in records {
        // Use "." for apex, otherwise append "."
        let name_str = if record.name == "@" {
            ".".to_string()
        } else {
            format!("{}.", record.name)
        };
        let ttl = record.ttl.unwrap_or(3600);

        match record.record_type.to_uppercase().as_str() {
            "A" => {
                let addr: std::net::Ipv4Addr = record.value.parse()?;
                let name: Name = name_str.as_str().try_into()?;
                builder = builder.a(name, addr, ttl);
            }
            "AAAA" => {
                let addr: std::net::Ipv6Addr = record.value.parse()?;
                let name: Name = name_str.as_str().try_into()?;
                builder = builder.aaaa(name, addr, ttl);
            }
            "CNAME" => {
                let name: Name = name_str.as_str().try_into()?;
                let target: Name = record.value.as_str().try_into()?;
                builder = builder.cname(name, target, ttl);
            }
            "TXT" => {
                let name: Name = name_str.as_str().try_into()?;
                let txt: TXT = record.value.as_str().try_into()?;
                builder = builder.txt(name, txt, ttl);
            }
            other => {
                anyhow::bail!("Unsupported record type: {}", other);
            }
        }
    }

    let packet = builder.sign(keypair)?;
    Ok(packet)
}

// Re-export config types used by this module
pub use crate::config::RecordConfig;
