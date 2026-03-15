//! Vanity key generator API handlers.

use super::state::DashboardState;
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use pkarr::Keypair;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Deserialize)]
pub struct VanityStartRequest {
    pub prefix: String,
    #[serde(default)]
    pub suffix: bool,
}

#[derive(Serialize)]
pub struct VanityStatusResponse {
    pub running: bool,
    pub target: String,
    pub suffix: bool,
    pub keys_checked: u64,
    pub elapsed_secs: f64,
    pub estimated_secs: f64,
    pub rate: f64,
    pub result: Option<VanityResult>,
}

#[derive(Serialize)]
pub struct VanityResult {
    pub pubkey: String,
    pub seed: String,
}

/// z-base32 encode bytes.
pub fn z32_encode(data: &[u8]) -> String {
    const Z32_ALPHABET: &[u8] = b"ybndrfg8ejkmcpqxot1uwisza345h769";
    let mut result = String::new();
    let mut bits: u64 = 0;
    let mut num_bits: u32 = 0;
    for &byte in data {
        bits = (bits << 8) | byte as u64;
        num_bits += 8;
        while num_bits >= 5 {
            num_bits -= 5;
            let index = ((bits >> num_bits) & 0x1F) as usize;
            result.push(Z32_ALPHABET[index] as char);
        }
    }
    if num_bits > 0 {
        let index = ((bits << (5 - num_bits)) & 0x1F) as usize;
        result.push(Z32_ALPHABET[index] as char);
    }
    result
}

/// Start vanity key grinding.
pub async fn api_vanity_start(
    State(state): State<Arc<DashboardState>>,
    Json(body): Json<VanityStartRequest>,
) -> Result<Json<VanityStatusResponse>, (StatusCode, String)> {
    let target = body.prefix.to_lowercase();

    const Z32_CHARS: &str = "ybndrfg8ejkmcpqxot1uwisza345h769";
    for c in target.chars() {
        if !Z32_CHARS.contains(c) {
            return Err((StatusCode::BAD_REQUEST, format!("Invalid z-base32 character: '{}'. Valid: {}", c, Z32_CHARS)));
        }
    }
    if target.is_empty() || target.len() > 10 {
        return Err((StatusCode::BAD_REQUEST, "Prefix must be 1-10 characters".to_string()));
    }

    let mut vanity = state.vanity.lock().await;
    if let Some(cancel) = vanity.cancel.take() {
        cancel.store(true, Ordering::Relaxed);
    }

    let cancel = Arc::new(AtomicBool::new(false));
    vanity.running = true;
    vanity.target = target.clone();
    vanity.suffix = body.suffix;
    vanity.keys_checked = 0;
    vanity.started_at = Some(std::time::Instant::now());
    vanity.result_pubkey = None;
    vanity.result_seed = None;
    vanity.cancel = Some(cancel.clone());

    let suffix = body.suffix;
    let vanity_mutex = state.clone();
    let num_threads = num_cpus::get().max(1);

    for _ in 0..num_threads {
        let target = target.clone();
        let cancel = cancel.clone();
        let state = vanity_mutex.clone();
        tokio::task::spawn_blocking(move || {
            let mut local_count: u64 = 0;
            while !cancel.load(Ordering::Relaxed) {
                let kp = Keypair::random();
                let z32 = kp.public_key().to_z32();
                local_count += 1;

                let matched = if suffix {
                    z32.ends_with(&target)
                } else {
                    z32.starts_with(&target)
                };

                if matched {
                    let seed_bytes = kp.secret_key();
                    let seed_z32 = z32_encode(&seed_bytes[..32]);
                    if let Ok(mut v) = state.vanity.try_lock() {
                        v.result_pubkey = Some(z32);
                        v.result_seed = Some(seed_z32);
                        v.keys_checked += local_count;
                        v.running = false;
                    }
                    cancel.store(true, Ordering::Relaxed);
                    return;
                }

                if local_count % 10_000 == 0 {
                    if let Ok(mut v) = state.vanity.try_lock() {
                        v.keys_checked += local_count;
                        local_count = 0;
                    }
                }
            }
            if let Ok(mut v) = state.vanity.try_lock() {
                v.keys_checked += local_count;
            }
        });
    }

    let target_len = target.len();
    let estimated = 32.0f64.powi(target_len as i32);

    Ok(Json(VanityStatusResponse {
        running: true,
        target,
        suffix: body.suffix,
        keys_checked: 0,
        elapsed_secs: 0.0,
        estimated_secs: estimated,
        rate: 0.0,
        result: None,
    }))
}

/// Get vanity grinder status.
pub async fn api_vanity_status(
    State(state): State<Arc<DashboardState>>,
) -> Json<VanityStatusResponse> {
    let vanity = state.vanity.lock().await;
    let elapsed = vanity.started_at
        .map(|s| s.elapsed().as_secs_f64())
        .unwrap_or(0.0);
    let rate = if elapsed > 0.0 { vanity.keys_checked as f64 / elapsed } else { 0.0 };
    let target_len = vanity.target.len();
    let total_expected = 32.0f64.powi(target_len as i32);
    let estimated = if rate > 0.0 { total_expected / rate } else { total_expected };

    let result = if let (Some(pk), Some(seed)) = (&vanity.result_pubkey, &vanity.result_seed) {
        Some(VanityResult {
            pubkey: pk.clone(),
            seed: seed.clone(),
        })
    } else {
        None
    };

    Json(VanityStatusResponse {
        running: vanity.running,
        target: vanity.target.clone(),
        suffix: vanity.suffix,
        keys_checked: vanity.keys_checked,
        elapsed_secs: elapsed,
        estimated_secs: estimated,
        rate,
        result,
    })
}

/// Stop vanity grinder.
pub async fn api_vanity_stop(
    State(state): State<Arc<DashboardState>>,
) -> Json<VanityStatusResponse> {
    {
        let mut vanity = state.vanity.lock().await;
        if let Some(cancel) = vanity.cancel.take() {
            cancel.store(true, Ordering::Relaxed);
        }
        vanity.running = false;
    }
    api_vanity_status(State(state)).await
}
