//! `pubky-node vanity` — generate a vanity PKARR keypair.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use clap::Args;
use pkarr::Keypair;

use crate::dashboard::z32_encode;

#[derive(Args, Debug)]
pub struct VanityArgs {
    /// The prefix (or suffix) to search for in z-base-32
    pub target: String,

    /// Match the end of the key instead of the beginning
    #[arg(long)]
    pub suffix: bool,

    /// Number of threads (default: all CPU cores)
    #[arg(long, short)]
    pub threads: Option<usize>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn execute(args: VanityArgs) -> anyhow::Result<()> {
    let target = args.target.to_lowercase();
    let z32_chars = "ybndrfg8ejkmcpqxot1uwisza345h769";

    // Validate z-base-32
    for ch in target.chars() {
        if !z32_chars.contains(ch) {
            anyhow::bail!(
                "Invalid z-base-32 character '{ch}'. Valid: {z32_chars}"
            );
        }
    }

    let threads = args.threads.unwrap_or_else(num_cpus::get);
    let found = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    if !args.json {
        let mode = if args.suffix { "suffix" } else { "prefix" };
        eprintln!(
            "Searching for z-base-32 {} '{target}' using {threads} threads...",
            mode
        );
    }

    // Spawn worker threads
    let result: Arc<std::sync::Mutex<Option<(String, String)>>> =
        Arc::new(std::sync::Mutex::new(None));

    let mut handles = Vec::new();
    for _ in 0..threads {
        let found = found.clone();
        let counter = counter.clone();
        let result = result.clone();
        let target = target.clone();
        let suffix = args.suffix;

        handles.push(std::thread::spawn(move || {
            while !found.load(Ordering::Relaxed) {
                let keypair = Keypair::random();
                let pubkey = z32_encode(&keypair.public_key().to_bytes());
                counter.fetch_add(1, Ordering::Relaxed);

                let matches = if suffix {
                    pubkey.ends_with(&target)
                } else {
                    pubkey.starts_with(&target)
                };

                if matches {
                    found.store(true, Ordering::Relaxed);
                    let seed = z32_encode(&keypair.secret_key()[..32]);
                    *result.lock().unwrap() = Some((pubkey, seed));
                    return;
                }
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let elapsed = start.elapsed().as_secs_f64();
    let total = counter.load(Ordering::Relaxed);

    if let Some((pubkey, seed)) = result.lock().unwrap().take() {
        if args.json {
            println!("{}", serde_json::json!({
                "public_key": pubkey,
                "seed": seed,
                "keys_checked": total,
                "elapsed_secs": elapsed,
            }));
        } else {
            println!();
            println!("Public Key:  {}", pubkey);
            println!("Secret Seed: {}", seed);
            println!();
            eprintln!("Found in {:.2}s ({} keys checked)", elapsed, total);
            eprintln!("⚠  SAVE YOUR SEED — it cannot be recovered.");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    /// z-base-32 alphabet reference: ybndrfg8ejkmcpqxot1uwisza345h769
    const Z32: &str = "ybndrfg8ejkmcpqxot1uwisza345h769";

    fn is_valid_z32_char(c: char) -> bool {
        Z32.contains(c)
    }

    #[test]
    fn test_z32_alphabet_rejects_uppercase() {
        assert!(!is_valid_z32_char('A'));
        assert!(!is_valid_z32_char('Z'));
        assert!(!is_valid_z32_char('B'));
    }

    #[test]
    fn test_z32_alphabet_rejects_ambiguous_chars() {
        // Verify specific chars absent from z-base-32 (ybndrfg8ejkmcpqxot1uwisza345h769)
        // '0' is absent (replaced by 'o')
        assert!(!is_valid_z32_char('0'));
        // '2' is absent
        assert!(!is_valid_z32_char('2'));
        // 'l' (lowercase L) is absent (replaced by '1')
        assert!(!is_valid_z32_char('l'));
        // 'v' is absent
        assert!(!is_valid_z32_char('v'));
        // Confirm chars that ARE in the alphabet
        assert!(is_valid_z32_char('o')); // 'o' IS in z-base-32
        assert!(is_valid_z32_char('6')); // '6' IS in z-base-32
        assert!(is_valid_z32_char('1')); // '1' IS in z-base-32 (replaces 'l')
    }

    #[test]
    fn test_z32_alphabet_accepts_valid_chars() {
        for c in Z32.chars() {
            assert!(is_valid_z32_char(c), "Expected '{}' to be valid z32", c);
        }
    }

    #[test]
    fn test_z32_alphabet_rejects_special_chars() {
        assert!(!is_valid_z32_char('-'));
        assert!(!is_valid_z32_char('_'));
        assert!(!is_valid_z32_char(' '));
        assert!(!is_valid_z32_char('!'));
    }

    #[test]
    fn test_z32_length() {
        // z-base-32 alphabet must have exactly 32 characters
        assert_eq!(Z32.len(), 32);
    }

    #[test]
    fn test_z32_no_duplicates() {
        let chars: std::collections::HashSet<char> = Z32.chars().collect();
        assert_eq!(chars.len(), 32, "z32 alphabet must not have duplicate characters");
    }
}

