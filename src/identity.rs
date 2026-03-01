// Identity Manager — sign up / sign in user identities on the local homeserver.
//
// Uses raw HTTP signup: POST https://{homeserver}/signup with an EdDSA-signed
// auth token, matching the Pubky SDK's AuthToken protocol.
//
// This avoids adding the full pubky-sdk dependency (which pulls in many extras).
// We only need: pkarr::Keypair + a few bytes of auth token construction.

use std::sync::RwLock;
use serde::{Deserialize, Serialize};

/// Info returned after a successful signup or signin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityInfo {
    pub pubkey: String,
    pub homeserver: String,
    pub signed_up_at: u64,
    pub status: String, // "active" | "error"
    pub error: Option<String>,
}

/// In-memory registry of known identities.
pub struct IdentityManager {
    identities: RwLock<Vec<IdentityInfo>>,
    data_dir: std::path::PathBuf,
}

impl IdentityManager {
    pub fn new(data_dir: &std::path::Path) -> Self {
        let mut manager = IdentityManager {
            identities: RwLock::new(Vec::new()),
            data_dir: data_dir.to_path_buf(),
        };
        manager.load_from_disk();
        manager
    }

    pub fn list(&self) -> Vec<IdentityInfo> {
        self.identities.read().unwrap().clone()
    }

    /// Sign up a keypair on the homeserver.
    /// 
    /// Protocol:
    ///   POST https://{homeserver_pubkey}/signup?signup_token={token}
    ///   Body: raw EdDSA-signed Pubky AuthToken bytes
    ///
    /// Since we're talking to our *local* homeserver (port 6286, no TLS),
    /// the URL becomes http://127.0.0.1:{icann_port}/signup
    pub async fn signup(
        &self,
        secret_hex: &str,
        homeserver_pubkey: &str,
        signup_token: Option<&str>,
        icann_port: u16,
    ) -> Result<IdentityInfo, String> {
        use pkarr::Keypair;

        let keypair = decode_keypair(secret_hex)?;
        let pubkey = keypair.public_key().to_z32();

        // Build auth token (Ed25519 signed)
        let token = build_auth_token(&keypair)?;

        // POST to local homeserver ICANN endpoint
        let mut url = format!("http://127.0.0.1:{}/signup", icann_port);
        if let Some(tok) = signup_token {
            url = format!("{}?signup_token={}", url, urlencoding_encode(tok));
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| format!("HTTP client error: {}", e))?;

        let resp = client
            .post(&url)
            .body(token)
            .header("content-type", "application/octet-stream")
            .send()
            .await
            .map_err(|e| format!("Signup request failed: {}", e))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Signup failed ({}): {}", status, body));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let info = IdentityInfo {
            pubkey: pubkey.clone(),
            homeserver: homeserver_pubkey.to_string(),
            signed_up_at: now,
            status: "active".to_string(),
            error: None,
        };

        {
            let mut ids = self.identities.write().unwrap();
            // Replace if already exists
            if let Some(existing) = ids.iter_mut().find(|i| i.pubkey == pubkey) {
                *existing = info.clone();
            } else {
                ids.push(info.clone());
            }
        }
        self.save_to_disk();

        Ok(info)
    }

    /// Refresh/verify a session (sign in) using the existing keypair.
    pub async fn signin(
        &self,
        secret_hex: &str,
        icann_port: u16,
    ) -> Result<IdentityInfo, String> {
        use pkarr::Keypair;

        let keypair = decode_keypair(secret_hex)?;
        let pubkey = keypair.public_key().to_z32();

        let token = build_auth_token(&keypair)?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| format!("HTTP client error: {}", e))?;

        let url = format!("http://127.0.0.1:{}/signin", icann_port);
        let resp = client
            .post(&url)
            .body(token)
            .header("content-type", "application/octet-stream")
            .send()
            .await
            .map_err(|e| format!("Signin request failed: {}", e))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Signin failed ({}): {}", status, body));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let info = IdentityInfo {
            pubkey: pubkey.clone(),
            homeserver: String::new(),
            signed_up_at: now,
            status: "active".to_string(),
            error: None,
        };

        {
            let mut ids = self.identities.write().unwrap();
            if let Some(existing) = ids.iter_mut().find(|i| i.pubkey == pubkey) {
                existing.signed_up_at = now;
                existing.status = "active".to_string();
                existing.error = None;
            } else {
                ids.push(info.clone());
            }
        }
        self.save_to_disk();

        Ok(info)
    }

    fn load_from_disk(&mut self) {
        let path = self.data_dir.join("identities.json");
        if let Ok(data) = std::fs::read_to_string(&path) {
            if let Ok(ids) = serde_json::from_str::<Vec<IdentityInfo>>(&data) {
                *self.identities.write().unwrap() = ids;
            }
        }
    }

    fn save_to_disk(&self) {
        let path = self.data_dir.join("identities.json");
        let ids = self.identities.read().unwrap();
        if let Ok(json) = serde_json::to_string_pretty(&*ids) {
            let _ = std::fs::write(&path, json);
        }
    }
}

/// Decode a 32-byte hex secret key into a Keypair.
fn decode_keypair(secret_hex: &str) -> Result<pkarr::Keypair, String> {
    let bytes = hex::decode(secret_hex)
        .map_err(|e| format!("Invalid secret hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("Secret must be 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(pkarr::Keypair::from_secret_key(&arr))
}

/// Build a minimal Pubky AuthToken (root capability, signed with keypair).
/// 
/// Token format (Pubky protocol):
///   [capabilities_bytes][signature_bytes]
/// 
/// For root capability the capabilities bytes are `\x00` (empty/root marker).
/// The signature covers: concat(capabilities_bytes).
/// 
/// This is a minimal implementation matching the SDK's root AuthToken.
fn build_auth_token(keypair: &pkarr::Keypair) -> Result<Vec<u8>, String> {
    let version: u8 = 0;
    let caps_bytes: &[u8] = &[];

    let mut to_sign = Vec::new();
    to_sign.push(version);
    to_sign.extend_from_slice(caps_bytes);

    let signature = keypair.sign(&to_sign);
    let sig_bytes = signature.to_bytes();

    let mut token = to_sign;
    token.extend_from_slice(&sig_bytes);
    Ok(token)
}

/// Simple percent-encoding for signup token in URL query.
fn urlencoding_encode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u32),
        })
        .collect::<Vec<_>>()
        .join("")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── decode_keypair ──────────────────────────────────────────

    #[test]
    fn test_decode_keypair_valid() {
        // 32 zero bytes = valid (all-zero key)
        let hex = "0".repeat(64);
        let result = decode_keypair(&hex);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decode_keypair_invalid_hex() {
        let result = decode_keypair("not_hex!!");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Invalid secret hex"));
    }

    #[test]
    fn test_decode_keypair_wrong_length() {
        // 16 bytes (32 hex chars) — too short
        let result = decode_keypair(&"ab".repeat(16));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("32 bytes"));
    }

    // ─── build_auth_token ────────────────────────────────────────

    #[test]
    fn test_build_auth_token_length() {
        // version(1) + caps(0) + Ed25519 signature(64) = 65 bytes
        let kp = pkarr::Keypair::random();
        let token = build_auth_token(&kp).unwrap();
        assert_eq!(token.len(), 65, "token must be 65 bytes: 1 version + 64 sig");
    }

    #[test]
    fn test_build_auth_token_starts_with_version() {
        let kp = pkarr::Keypair::random();
        let token = build_auth_token(&kp).unwrap();
        assert_eq!(token[0], 0, "first byte must be version 0");
    }

    #[test]
    fn test_build_auth_token_signature_is_nonzero() {
        // A real Ed25519 signature over a non-empty message will never be all zeros
        let kp = pkarr::Keypair::random();
        let token = build_auth_token(&kp).unwrap();
        let sig_bytes = &token[1..65];
        assert!(
            sig_bytes.iter().any(|&b| b != 0),
            "signature bytes should not all be zero"
        );
    }

    #[test]
    fn test_build_auth_token_different_keys_differ() {
        let kp1 = pkarr::Keypair::random();
        let kp2 = pkarr::Keypair::random();
        let t1 = build_auth_token(&kp1).unwrap();
        let t2 = build_auth_token(&kp2).unwrap();
        // Signatures for different keys must differ
        assert_ne!(t1, t2);
    }

    // ─── urlencoding_encode ──────────────────────────────────────

    #[test]
    fn test_urlencoding_safe_chars_unchanged() {
        let input = "ABCZabcz0129-_.~";
        assert_eq!(urlencoding_encode(input), input);
    }

    #[test]
    fn test_urlencoding_space_encoded() {
        assert_eq!(urlencoding_encode(" "), "%20");
    }

    #[test]
    fn test_urlencoding_special_chars() {
        assert_eq!(urlencoding_encode("a+b"), "a%2Bb");
        assert_eq!(urlencoding_encode("a/b"), "a%2Fb");
        assert_eq!(urlencoding_encode("a=b"), "a%3Db");
    }

    #[test]
    fn test_urlencoding_empty_string() {
        assert_eq!(urlencoding_encode(""), "");
    }
}

