//! `pubky-node publish` — publish DNS records to the DHT from the command line.

use clap::Args;
use pkarr::Keypair;

use crate::config::RecordConfig;
use crate::publisher::build_signed_packet;

#[derive(Args, Debug)]
pub struct PublishArgs {
    /// Ed25519 secret key as 64-char hex string
    #[arg(long, group = "key_source")]
    pub secret_key: Option<String>,

    /// Path to file containing the secret key
    #[arg(long, group = "key_source")]
    pub secret_key_file: Option<String>,

    /// DNS records in format "TYPE NAME VALUE [TTL]" (can repeat)
    #[arg(long = "record", num_args = 1)]
    pub records: Vec<String>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Parse a record string like "A @ 1.2.3.4 3600" into a RecordConfig.
pub fn parse_record_string(s: &str) -> anyhow::Result<RecordConfig> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 3 {
        anyhow::bail!(
            "Invalid record format: '{}'. Expected: TYPE NAME VALUE [TTL]",
            s
        );
    }

    Ok(RecordConfig {
        record_type: parts[0].to_uppercase(),
        name: parts[1].to_string(),
        value: parts[2].to_string(),
        ttl: parts.get(3).and_then(|t| t.parse().ok()),
    })
}

pub async fn execute(args: PublishArgs) -> anyhow::Result<()> {
    // Load secret key
    let secret_hex = if let Some(ref key) = args.secret_key {
        key.clone()
    } else if let Some(ref path) = args.secret_key_file {
        std::fs::read_to_string(path)?
            .trim()
            .to_string()
    } else {
        anyhow::bail!("Must provide --secret-key or --secret-key-file");
    };

    if args.records.is_empty() {
        anyhow::bail!("Must provide at least one --record");
    }

    // Parse secret key
    let secret_bytes = hex::decode(&secret_hex)
        .map_err(|e| anyhow::anyhow!("Invalid hex secret key: {}", e))?;
    if secret_bytes.len() != 32 {
        anyhow::bail!("Secret key must be 32 bytes (64 hex chars), got {}", secret_bytes.len());
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&secret_bytes);
    let keypair = Keypair::from_secret_key(&key_bytes);

    // Parse records
    let records: Vec<RecordConfig> = args.records.iter()
        .map(|r| parse_record_string(r))
        .collect::<anyhow::Result<Vec<_>>>()?;

    eprintln!("Publishing {} record(s) for {}...", records.len(), keypair.public_key());

    // Build and publish
    let signed_packet = build_signed_packet(&keypair, &records)?;

    let client = pkarr::Client::builder().build()?;
    client.publish(&signed_packet, None).await
        .map_err(|e| anyhow::anyhow!("Publish failed: {}", e))?;

    if args.json {
        println!("{}", serde_json::json!({
            "status": "published",
            "public_key": keypair.public_key().to_string(),
            "records": records.len(),
        }));
    } else {
        println!("✓ Published {} record(s)", records.len());
        println!("  Public key: {}", keypair.public_key());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_record_a_with_ttl() {
        let rec = parse_record_string("A @ 1.2.3.4 3600").unwrap();
        assert_eq!(rec.record_type, "A");
        assert_eq!(rec.name, "@");
        assert_eq!(rec.value, "1.2.3.4");
        assert_eq!(rec.ttl, Some(3600));
    }

    #[test]
    fn test_parse_record_txt_no_ttl() {
        let rec = parse_record_string("TXT _pubky v=1").unwrap();
        assert_eq!(rec.record_type, "TXT");
        assert_eq!(rec.name, "_pubky");
        assert_eq!(rec.value, "v=1");
        assert_eq!(rec.ttl, None);
    }

    #[test]
    fn test_parse_record_cname() {
        let rec = parse_record_string("cname @ example.com 300").unwrap();
        assert_eq!(rec.record_type, "CNAME");
        assert_eq!(rec.name, "@");
        assert_eq!(rec.value, "example.com");
        assert_eq!(rec.ttl, Some(300));
    }

    #[test]
    fn test_parse_record_too_few_parts() {
        assert!(parse_record_string("A @").is_err());
    }

    #[test]
    fn test_parse_record_invalid_ttl_ignored() {
        let rec = parse_record_string("A @ 1.2.3.4 notanumber").unwrap();
        assert_eq!(rec.ttl, None);
    }
}
