//! `pubky-node keygen` — generate a new Ed25519 keypair for DNS publishing.

use clap::Args;
use pkarr::Keypair;

#[derive(Args, Debug)]
pub struct KeygenArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn execute(args: KeygenArgs) -> anyhow::Result<()> {
    let keypair = Keypair::random();
    let public_key = keypair.public_key().to_string();
    let secret_key = hex::encode(keypair.secret_key());

    if args.json {
        println!("{}", serde_json::json!({
            "public_key": public_key,
            "secret_key": secret_key,
        }));
    } else {
        println!("Public Key:  {}", public_key);
        println!("Secret Key:  {}", secret_key);
        eprintln!();
        eprintln!("⚠  SAVE YOUR SECRET KEY — it cannot be recovered.");
        eprintln!("   Use it with: pubky-node publish --secret-key {}", secret_key);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_produces_valid_keypair() {
        let keypair = Keypair::random();
        let public_str = keypair.public_key().to_string();
        let secret_hex = hex::encode(keypair.secret_key());

        // Public key should be 52 chars z-base-32
        assert_eq!(public_str.len(), 52);

        // Secret key should be 64 hex chars (32 bytes)
        assert_eq!(secret_hex.len(), 64);

        // Secret key should decode back
        let decoded = hex::decode(&secret_hex).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_keygen_unique() {
        let kp1 = Keypair::random();
        let kp2 = Keypair::random();
        assert_ne!(kp1.public_key().to_string(), kp2.public_key().to_string());
    }
}
