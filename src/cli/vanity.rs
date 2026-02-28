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
