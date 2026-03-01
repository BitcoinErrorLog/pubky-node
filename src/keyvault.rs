// Key Vault — encrypted key storage using argon2 key derivation + ChaCha20-Poly1305 AEAD
//
// Storage format (keyvault.enc):
//   [32 bytes salt] [12 bytes nonce] [encrypted JSON payload]
//
// The vault password is used with argon2id to derive a 32-byte encryption key.
// The JSON payload contains an array of VaultKey entries.

use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use uuid::Uuid;

/// A key stored in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultKey {
    pub id: String,
    pub name: String,
    pub key_type: String, // "vanity" | "pkarr" | "homeserver" | "manual"
    pub pubkey: String,
    pub secret_hex: String,
    pub created_at: String,
}

/// Public-facing key info (no secret).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultKeyInfo {
    pub id: String,
    pub name: String,
    pub key_type: String,
    pub pubkey: String,
    pub created_at: String,
}

impl From<&VaultKey> for VaultKeyInfo {
    fn from(k: &VaultKey) -> Self {
        VaultKeyInfo {
            id: k.id.clone(),
            name: k.name.clone(),
            key_type: k.key_type.clone(),
            pubkey: k.pubkey.clone(),
            created_at: k.created_at.clone(),
        }
    }
}

/// The in-memory vault payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultPayload {
    keys: Vec<VaultKey>,
}

/// Key Vault manager.
pub struct KeyVault {
    vault_path: PathBuf,
    /// Decrypted keys — Some = unlocked, None = locked
    unlocked_keys: RwLock<Option<Vec<VaultKey>>>,
    /// The derived encryption key (held while unlocked)
    derived_key: RwLock<Option<[u8; 32]>>,
}

impl KeyVault {
    /// Create a new KeyVault instance. Does NOT unlock.
    pub fn new(data_dir: &Path) -> Self {
        KeyVault {
            vault_path: data_dir.join("keyvault.enc"),
            unlocked_keys: RwLock::new(None),
            derived_key: RwLock::new(None),
        }
    }

    /// Check if a vault file exists on disk.
    pub fn exists(&self) -> bool {
        self.vault_path.exists()
    }

    /// Check if the vault is currently unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.unlocked_keys.read().unwrap().is_some()
    }

    /// Create a new vault with the given password. Fails if vault already exists.
    pub fn create(&self, password: &str) -> Result<(), String> {
        if self.exists() {
            return Err("Vault already exists.".into());
        }

        let payload = VaultPayload { keys: vec![] };
        let json = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;

        let (salt, nonce, ciphertext) = encrypt_data(password, &json)?;

        // Write: salt(32) + nonce(12) + ciphertext
        let mut file_data = Vec::with_capacity(32 + 12 + ciphertext.len());
        file_data.extend_from_slice(&salt);
        file_data.extend_from_slice(&nonce);
        file_data.extend_from_slice(&ciphertext);

        // Ensure parent dir exists
        if let Some(parent) = self.vault_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&self.vault_path, &file_data).map_err(|e| e.to_string())?;

        // Auto-unlock after creation
        let dk = derive_key(password, &salt)?;
        *self.unlocked_keys.write().unwrap() = Some(payload.keys);
        *self.derived_key.write().unwrap() = Some(dk);

        Ok(())
    }

    /// Unlock the vault with the given password. Decrypts and holds keys in memory.
    pub fn unlock(&self, password: &str) -> Result<(), String> {
        if !self.exists() {
            return Err("Vault does not exist. Create it first.".into());
        }

        let file_data = std::fs::read(&self.vault_path).map_err(|e| e.to_string())?;
        if file_data.len() < 44 {
            return Err("Invalid vault file.".into());
        }

        let salt: [u8; 32] = file_data[..32].try_into().unwrap();
        let nonce: [u8; 12] = file_data[32..44].try_into().unwrap();
        let ciphertext = &file_data[44..];

        let dk = derive_key(password, &salt)?;

        let cipher = ChaCha20Poly1305::new_from_slice(&dk)
            .map_err(|e| format!("Cipher init error: {}", e))?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .map_err(|_| "Invalid password or corrupted vault.")?;

        let payload: VaultPayload =
            serde_json::from_slice(&plaintext).map_err(|e| format!("Vault data error: {}", e))?;

        *self.unlocked_keys.write().unwrap() = Some(payload.keys);
        *self.derived_key.write().unwrap() = Some(dk);

        Ok(())
    }

    /// Lock the vault — clear all in-memory keys and derived key.
    pub fn lock(&self) {
        *self.unlocked_keys.write().unwrap() = None;
        *self.derived_key.write().unwrap() = None;
    }

    /// List keys (public info only, no secrets). Requires unlocked vault.
    pub fn list_keys(&self) -> Result<Vec<VaultKeyInfo>, String> {
        let guard = self.unlocked_keys.read().unwrap();
        match guard.as_ref() {
            Some(keys) => Ok(keys.iter().map(VaultKeyInfo::from).collect()),
            None => Err("Vault is locked.".into()),
        }
    }

    /// Add a key to the vault. Requires unlocked vault. Saves to disk.
    pub fn add_key(
        &self,
        name: &str,
        secret_hex: &str,
        key_type: &str,
        pubkey: &str,
    ) -> Result<VaultKeyInfo, String> {
        let key = VaultKey {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            key_type: key_type.to_string(),
            pubkey: pubkey.to_string(),
            secret_hex: secret_hex.to_string(),
            created_at: chrono_now(),
        };

        let info = VaultKeyInfo::from(&key);

        {
            let mut guard = self.unlocked_keys.write().unwrap();
            match guard.as_mut() {
                Some(keys) => {
                    // Don't add duplicate pubkeys
                    if keys.iter().any(|k| k.pubkey == pubkey) {
                        return Err("Key with this pubkey already exists in vault.".into());
                    }
                    keys.push(key);
                }
                None => return Err("Vault is locked.".into()),
            }
        }

        self.save_to_disk()?;
        Ok(info)
    }

    /// Export a key's secret hex. Requires unlocked vault.
    pub fn export_key(&self, pubkey: &str) -> Result<String, String> {
        let guard = self.unlocked_keys.read().unwrap();
        match guard.as_ref() {
            Some(keys) => {
                keys.iter()
                    .find(|k| k.pubkey == pubkey)
                    .map(|k| k.secret_hex.clone())
                    .ok_or_else(|| "Key not found.".into())
            }
            None => Err("Vault is locked.".into()),
        }
    }

    /// Delete a key from the vault. Requires unlocked vault. Saves to disk.
    pub fn delete_key(&self, pubkey: &str) -> Result<(), String> {
        {
            let mut guard = self.unlocked_keys.write().unwrap();
            match guard.as_mut() {
                Some(keys) => {
                    let before = keys.len();
                    keys.retain(|k| k.pubkey != pubkey);
                    if keys.len() == before {
                        return Err("Key not found.".into());
                    }
                }
                None => return Err("Vault is locked.".into()),
            }
        }

        self.save_to_disk()
    }

    /// Rename a key by pubkey. Requires unlocked vault. Saves to disk.
    pub fn rename_key(&self, pubkey: &str, new_name: &str) -> Result<(), String> {
        {
            let mut guard = self.unlocked_keys.write().unwrap();
            match guard.as_mut() {
                Some(keys) => {
                    let key = keys.iter_mut().find(|k| k.pubkey == pubkey);
                    match key {
                        Some(k) => k.name = new_name.to_string(),
                        None => return Err("Key not found.".into()),
                    }
                }
                None => return Err("Vault is locked.".into()),
            }
        }
        self.save_to_disk()
    }

    /// Export all keys (including secrets) for full vault backup.
    pub fn export_all_keys(&self) -> Result<Vec<VaultKey>, String> {
        let guard = self.unlocked_keys.read().unwrap();
        match guard.as_ref() {
            Some(keys) => Ok(keys.clone()),
            None => Err("Vault is locked.".into()),
        }
    }

    /// Import keys into the vault. Skips keys whose pubkey already exists.
    /// Returns the number of keys imported.
    pub fn import_keys(&self, new_keys: Vec<VaultKey>) -> Result<usize, String> {
        let mut imported = 0;
        {
            let mut guard = self.unlocked_keys.write().unwrap();
            match guard.as_mut() {
                Some(keys) => {
                    for mut nk in new_keys {
                        if !keys.iter().any(|k| k.pubkey == nk.pubkey) {
                            // Assign a fresh ID to avoid collisions
                            nk.id = Uuid::new_v4().to_string();
                            keys.push(nk);
                            imported += 1;
                        }
                    }
                }
                None => return Err("Vault is locked.".into()),
            }
        }
        if imported > 0 {
            self.save_to_disk()?;
        }
        Ok(imported)
    }

    /// Re-encrypt and save current keys to disk.
    fn save_to_disk(&self) -> Result<(), String> {
        let dk_guard = self.derived_key.read().unwrap();
        let dk = dk_guard.as_ref().ok_or("Vault is locked (no derived key).")?;

        let keys_guard = self.unlocked_keys.read().unwrap();
        let keys = keys_guard.as_ref().ok_or("Vault is locked.")?;

        let payload = VaultPayload { keys: keys.clone() };
        let json = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;

        // Generate new nonce for each save (salt stays the same)
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let cipher = ChaCha20Poly1305::new_from_slice(dk)
            .map_err(|e| format!("Cipher init error: {}", e))?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), json.as_slice())
            .map_err(|e| format!("Encryption error: {}", e))?;

        // Read existing salt from file
        let existing = std::fs::read(&self.vault_path).map_err(|e| e.to_string())?;
        let salt = &existing[..32];

        // Write: salt(32) + new_nonce(12) + new_ciphertext
        let mut file_data = Vec::with_capacity(32 + 12 + ciphertext.len());
        file_data.extend_from_slice(salt);
        file_data.extend_from_slice(&nonce_bytes);
        file_data.extend_from_slice(&ciphertext);

        std::fs::write(&self.vault_path, &file_data).map_err(|e| e.to_string())
    }
}

// ─── Crypto helpers ─────────────────────────────────────────────

/// Derive a 32-byte key from password + salt using argon2id.
fn derive_key(password: &str, salt: &[u8; 32]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Key derivation error: {}", e))?;
    Ok(key)
}

/// Encrypt data with a password. Returns (salt, nonce, ciphertext).
fn encrypt_data(password: &str, plaintext: &[u8]) -> Result<([u8; 32], [u8; 12], Vec<u8>), String> {
    let mut salt = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let dk = derive_key(password, &salt)?;

    let cipher = ChaCha20Poly1305::new_from_slice(&dk)
        .map_err(|e| format!("Cipher init error: {}", e))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| format!("Encryption error: {}", e))?;

    Ok((salt, nonce_bytes, ciphertext))
}

/// Get current UTC timestamp as ISO 8601 string (no chrono dependency).
fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Simple UTC timestamp: YYYY-MM-DDTHH:MM:SSZ
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Calculate date from days since epoch (simplified)
    let (year, month, day) = days_to_date(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_date(days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
