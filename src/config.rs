//! Configuration loading and validation for Pubky Node.
//!
//! Supports TOML file configuration with environment variable overrides
//! for containerized deployments (Docker/Umbrel). All fields have sensible
//! defaults so the node runs out of the box with zero configuration.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use std::fmt;

/// Top-level configuration for Pubky Node.
#[derive(Debug, Default, Deserialize, Clone)]
#[serde(default)]
pub struct Config {
    pub relay: RelayConfig,
    pub dht: DhtConfig,
    pub cache: CacheConfig,
    pub dns: DnsConfig,
    pub watchlist: WatchlistConfig,
    pub publisher: PublisherConfig,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct RelayConfig {
    /// Port for the Pkarr relay HTTP server.
    pub http_port: u16,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct DhtConfig {
    /// Port for the Mainline DHT UDP socket.
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct CacheConfig {
    /// Path for persistent LMDB cache storage.
    pub path: Option<PathBuf>,
    /// Maximum number of SignedPackets to cache.
    pub size: usize,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct DnsConfig {
    /// Enable the local Pkdns resolver.
    pub enabled: bool,
    /// Path to the pkdns binary. If not set, searches PATH.
    pub binary: Option<PathBuf>,
    /// DNS listening socket.
    pub socket: String,
    /// ICANN fallback DNS server.
    pub forward: String,
    /// Path to pkdns data directory.
    pub pkdns_dir: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct WatchlistConfig {
    /// Enable the identity watchlist and republisher.
    pub enabled: bool,
    /// Public keys to monitor and republish (zbase32 encoded).
    pub keys: Vec<String>,
    /// Seconds between republish cycles.
    pub republish_interval_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct PublisherConfig {
    /// Enable the publisher.
    pub enabled: bool,
    /// Keypairs to sign and publish.
    pub keys: Vec<KeyConfig>,
    /// Seconds between publish cycles.
    pub interval_secs: u64,
    /// Maximum retry attempts.
    pub max_retries: u32,
    /// Base delay between retries (exponential backoff).
    pub retry_delay_secs: u64,
}

#[derive(Deserialize, Clone)]
pub struct KeyConfig {
    /// Hex-encoded 32-byte Ed25519 secret key.
    pub secret_key: Option<String>,
    /// Path to file containing the hex secret key.
    pub secret_key_file: Option<PathBuf>,
    /// DNS records to publish.
    #[serde(default)]
    pub records: Vec<RecordConfig>,
}

impl fmt::Debug for KeyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyConfig")
            .field("secret_key", &self.secret_key.as_ref().map(|_| "[REDACTED]"))
            .field("secret_key_file", &self.secret_key_file)
            .field("records", &self.records)
            .finish()
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct RecordConfig {
    /// Record type: A, AAAA, CNAME, TXT
    #[serde(rename = "type")]
    pub record_type: String,
    /// Record name. "@" for apex.
    pub name: String,
    /// Record value.
    pub value: String,
    /// TTL in seconds.
    pub ttl: Option<u32>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self { http_port: 6881 }
    }
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self { port: 6881 }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            path: None,
            size: 1_000_000,
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            binary: None,
            socket: "127.0.0.1:53".to_string(),
            forward: "8.8.8.8:53".to_string(),
            pkdns_dir: None,
        }
    }
}

impl Default for WatchlistConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            keys: Vec::new(),
            republish_interval_secs: 3600,
        }
    }
}

impl Default for PublisherConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            keys: Vec::new(),
            interval_secs: 3600,
            max_retries: 3,
            retry_delay_secs: 5,
        }
    }
}

impl KeyConfig {
    /// Load the keypair from either inline secret_key or secret_key_file.
    pub fn load_keypair(&self) -> anyhow::Result<pkarr::Keypair> {
        use zeroize::Zeroizing;

        let hex_str = Zeroizing::new(match (&self.secret_key, &self.secret_key_file) {
            (Some(key), None) => key.trim().to_string(),
            (None, Some(path)) => {
                std::fs::read_to_string(path)
                    .map_err(|e| anyhow::anyhow!("Failed to read key file {:?}: {}", path, e))?
                    .trim()
                    .to_string()
            }
            (Some(_), Some(_)) => {
                anyhow::bail!("Specify either secret_key or secret_key_file, not both");
            }
            (None, None) => {
                anyhow::bail!("No secret_key or secret_key_file specified");
            }
        });

        let bytes = Zeroizing::new(
            hex::decode(hex_str.as_str())
                .map_err(|e| anyhow::anyhow!("Invalid hex key: {}", e))?
        );
        if bytes.len() != 32 {
            anyhow::bail!("Secret key must be 32 bytes, got {}", bytes.len());
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&bytes);
        Ok(pkarr::Keypair::from_secret_key(&seed))
        // hex_str, bytes, and seed are all zeroized when dropped here
    }
}

/// Determine the default data directory: ~/.pubky-node
pub fn default_data_dir() -> PathBuf {
    dirs_next::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("pubky-node")
}

/// Load config from a TOML file, falling back to defaults for missing fields.
pub fn load_config(path: &Path) -> anyhow::Result<Config> {
    if path.exists() {
        // Check file permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(path) {
                let mode = meta.permissions().mode();
                if mode & 0o077 != 0 {
                    tracing::warn!(
                        "Config file {:?} is readable by group/others (mode {:o}). \
                         If it contains secret keys, set permissions to 0600: chmod 600 {:?}",
                        path, mode & 0o777, path
                    );
                }
            }
        }

        let contents = std::fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&contents)?;

        // Validate DNS config inputs
        validate_dns_config(&config.dns)?;

        // Apply environment variable overrides (for Docker/Umbrel)
        apply_env_overrides(&mut config);

        Ok(config)
    } else {
        tracing::info!("No config file found at {:?}, using defaults", path);
        let mut config = Config::default();
        apply_env_overrides(&mut config);
        Ok(config)
    }
}

/// Apply environment variable overrides to config.
/// Supports: PUBKY_RELAY_PORT, PUBKY_DHT_PORT, PUBKY_WATCHLIST_KEYS, PUBKY_DNS_ENABLED
fn apply_env_overrides(config: &mut Config) {
    if let Ok(val) = std::env::var("PUBKY_RELAY_PORT") {
        if let Ok(port) = val.parse::<u16>() {
            config.relay.http_port = port;
        }
    }
    if let Ok(val) = std::env::var("PUBKY_DHT_PORT") {
        if let Ok(port) = val.parse::<u16>() {
            config.dht.port = port;
        }
    }
    if let Ok(val) = std::env::var("PUBKY_WATCHLIST_KEYS") {
        let keys: Vec<String> = val.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !keys.is_empty() {
            config.watchlist.keys = keys;
            config.watchlist.enabled = true;
        }
    }
    if let Ok(val) = std::env::var("PUBKY_DNS_ENABLED") {
        config.dns.enabled = val == "1" || val.eq_ignore_ascii_case("true");
    }
}

/// Validate DNS configuration to prevent injection.
fn validate_dns_config(dns: &DnsConfig) -> anyhow::Result<()> {
    if dns.enabled {
        // Validate forward address looks like a socket addr
        if !dns.forward.is_empty() {
            dns.forward.parse::<std::net::SocketAddr>()
                .map_err(|_| anyhow::anyhow!(
                    "dns.forward must be a valid socket address (e.g. 8.8.8.8:53), got: {}",
                    dns.forward
                ))?;
        }
        // Validate socket address
        if !dns.socket.is_empty() {
            dns.socket.parse::<std::net::SocketAddr>()
                .map_err(|_| anyhow::anyhow!(
                    "dns.socket must be a valid socket address (e.g. 127.0.0.1:53), got: {}",
                    dns.socket
                ))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.relay.http_port, 6881);
        assert_eq!(config.dht.port, 6881);
        assert_eq!(config.cache.size, 1_000_000);
        assert!(config.dns.enabled);
        assert_eq!(config.dns.forward, "8.8.8.8:53");
        assert!(!config.watchlist.enabled);
        assert!(config.watchlist.keys.is_empty());
        assert!(!config.publisher.enabled);
    }

    #[test]
    fn test_load_missing_file_returns_defaults() {
        let path = Path::new("/nonexistent/config.toml");
        let config = load_config(path).unwrap();
        assert_eq!(config.relay.http_port, 6881);
    }

    #[test]
    fn test_load_partial_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "[relay]\nhttp_port = 9999").unwrap();

        let config = load_config(&path).unwrap();
        assert_eq!(config.relay.http_port, 9999);
        // Other fields should be defaults
        assert_eq!(config.dht.port, 6881);
    }

    #[test]
    fn test_env_override_relay_port() {
        std::env::set_var("PUBKY_RELAY_PORT", "7777");
        let mut config = Config::default();
        apply_env_overrides(&mut config);
        assert_eq!(config.relay.http_port, 7777);
        std::env::remove_var("PUBKY_RELAY_PORT");
    }

    #[test]
    fn test_env_override_dht_port() {
        std::env::set_var("PUBKY_DHT_PORT", "8888");
        let mut config = Config::default();
        apply_env_overrides(&mut config);
        assert_eq!(config.dht.port, 8888);
        std::env::remove_var("PUBKY_DHT_PORT");
    }

    #[test]
    fn test_env_override_watchlist_keys() {
        std::env::set_var("PUBKY_WATCHLIST_KEYS", "key1, key2, key3");
        let mut config = Config::default();
        apply_env_overrides(&mut config);
        assert!(config.watchlist.enabled);
        assert_eq!(config.watchlist.keys, vec!["key1", "key2", "key3"]);
        std::env::remove_var("PUBKY_WATCHLIST_KEYS");
    }

    #[test]
    fn test_env_override_dns_enabled() {
        std::env::set_var("PUBKY_DNS_ENABLED", "false");
        let mut config = Config::default();
        apply_env_overrides(&mut config);
        assert!(!config.dns.enabled);
        std::env::remove_var("PUBKY_DNS_ENABLED");

        std::env::set_var("PUBKY_DNS_ENABLED", "true");
        apply_env_overrides(&mut config);
        assert!(config.dns.enabled);
        std::env::remove_var("PUBKY_DNS_ENABLED");
    }

    #[test]
    fn test_env_override_invalid_port_ignored() {
        // Set a known port first, then try an invalid override
        let mut config = Config::default();
        config.relay.http_port = 1234;
        std::env::set_var("PUBKY_RELAY_PORT", "not_a_number");
        apply_env_overrides(&mut config);
        assert_eq!(config.relay.http_port, 1234); // unchanged from our set value
        std::env::remove_var("PUBKY_RELAY_PORT");
    }

    #[test]
    fn test_validate_dns_config_valid() {
        let dns = DnsConfig {
            enabled: true,
            forward: "8.8.8.8:53".to_string(),
            socket: "127.0.0.1:53".to_string(),
            ..DnsConfig::default()
        };
        assert!(validate_dns_config(&dns).is_ok());
    }

    #[test]
    fn test_validate_dns_config_invalid_forward() {
        let dns = DnsConfig {
            enabled: true,
            forward: "not_a_socket; rm -rf /".to_string(),
            ..DnsConfig::default()
        };
        assert!(validate_dns_config(&dns).is_err());
    }

    #[test]
    fn test_validate_dns_config_disabled_skips_validation() {
        let dns = DnsConfig {
            enabled: false,
            forward: "garbage".to_string(),
            ..DnsConfig::default()
        };
        assert!(validate_dns_config(&dns).is_ok());
    }

    #[test]
    fn test_key_config_debug_redacts_secret() {
        let kc = KeyConfig {
            secret_key: Some("super_secret_key_material".to_string()),
            secret_key_file: None,
            records: vec![],
        };
        let debug_output = format!("{:?}", kc);
        assert!(!debug_output.contains("super_secret"));
        assert!(debug_output.contains("[REDACTED]"));
    }
}
