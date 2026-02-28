//! `pubky-node resolve <KEY>` — look up a public key's DNS records from the DHT.

use clap::Args;
use pkarr::{PublicKey, Client};
use pkarr::dns::rdata::RData;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Args, Debug)]
pub struct ResolveArgs {
    /// The z-base-32 encoded public key to resolve
    pub key: String,

    /// Output as JSON instead of human-readable format
    #[arg(long)]
    pub json: bool,
}

pub async fn execute(args: ResolveArgs) -> anyhow::Result<()> {
    let public_key: PublicKey = args.key.parse()
        .map_err(|e| anyhow::anyhow!("Invalid public key '{}': {}", args.key, e))?;

    let client = Client::builder().build()?;

    eprintln!("Resolving {}...", args.key);

    match client.resolve(&public_key).await {
        Some(signed_packet) => {
            let origin = public_key.to_z32();
            let elapsed = signed_packet.elapsed();

            if args.json {
                let mut json_records = Vec::new();
                for rr in signed_packet.all_resource_records() {
                    let (rtype, value) = format_rdata(&rr.rdata);
                    let name = strip_origin(&rr.name.to_string(), &origin);
                    json_records.push(serde_json::json!({
                        "name": name,
                        "type": rtype,
                        "value": value,
                        "ttl": rr.ttl,
                    }));
                }

                let output = serde_json::json!({
                    "public_key": args.key,
                    "age_secs": elapsed,
                    "records": json_records,
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                let records: Vec<_> = signed_packet.all_resource_records().collect();
                println!("Key:  {}", args.key);
                println!("Age:  {}s", elapsed);
                println!("Records ({}):", records.len());
                println!("{:<6} {:<16} {:<40} TTL", "TYPE", "NAME", "VALUE");
                println!("{}", "-".repeat(70));
                for rr in &records {
                    let (rtype, value) = format_rdata(&rr.rdata);
                    let name = strip_origin(&rr.name.to_string(), &origin);
                    println!("{:<6} {:<16} {:<40} {}", rtype, name, value, rr.ttl);
                }
            }
        }
        None => {
            if args.json {
                println!("{}", serde_json::json!({
                    "public_key": args.key,
                    "error": "not_found",
                }));
            } else {
                eprintln!("No records found for {}", args.key);
            }
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Strip the origin (public key z32) suffix from a record name.
fn strip_origin(full_name: &str, origin: &str) -> String {
    if full_name == origin {
        "@".to_string()
    } else if let Some(prefix) = full_name.strip_suffix(&format!(".{}", origin)) {
        prefix.to_string()
    } else {
        full_name.to_string()
    }
}

/// Format an RData value into (type_string, value_string).
fn format_rdata(rdata: &RData) -> (String, String) {
    match rdata {
        RData::A(a) => (
            "A".into(),
            Ipv4Addr::from(a.address).to_string(),
        ),
        RData::AAAA(aaaa) => (
            "AAAA".into(),
            Ipv6Addr::from(aaaa.address).to_string(),
        ),
        RData::CNAME(cname) => (
            "CNAME".into(),
            cname.0.to_string(),
        ),
        RData::TXT(txt) => {
            let s: String = txt.clone().try_into().unwrap_or_default();
            ("TXT".into(), s)
        }
        RData::NS(ns) => (
            "NS".into(),
            ns.0.to_string(),
        ),
        other => (
            format!("{:?}", other).split('(').next().unwrap_or("UNKNOWN").to_string(),
            format!("{:?}", other),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_key_format() {
        let result = "not_a_valid_key".parse::<PublicKey>();
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_key_format() {
        let key_str = "yg4gxe7z1r7mr6orids9fh95y7gxhdsxjqi6nngsxxtakqaxr5no";
        let result = key_str.parse::<PublicKey>();
        assert!(result.is_ok());
    }

    #[test]
    fn test_strip_origin_at() {
        let origin = "yg4gxe7z1r7mr6orids9fh95y7gxhdsxjqi6nngsxxtakqaxr5no";
        assert_eq!(strip_origin(origin, origin), "@");
    }

    #[test]
    fn test_strip_origin_subdomain() {
        let origin = "yg4gxe7z1r7mr6orids9fh95y7gxhdsxjqi6nngsxxtakqaxr5no";
        let full = format!("_pubky.{}", origin);
        assert_eq!(strip_origin(&full, origin), "_pubky");
    }

    #[test]
    fn test_strip_origin_unrelated() {
        assert_eq!(strip_origin("example.com", "origin"), "example.com");
    }
}
