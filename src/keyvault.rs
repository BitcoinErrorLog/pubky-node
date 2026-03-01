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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn make_vault(dir: &PathBuf) -> KeyVault {
        KeyVault::new(dir)
    }

    // ─── Lifecycle ───────────────────────────────────────────────

    #[test]
    fn test_create_vault_new() {
        let td = temp_dir();
        let v = make_vault(&td.path().to_path_buf());
        assert!(!v.exists());
        v.create("password123").unwrap();
        assert!(v.exists());
        assert!(v.is_unlocked());
    }

    #[test]
    fn test_create_vault_twice_fails() {
        let td = temp_dir();
        let v = make_vault(&td.path().to_path_buf());
        v.create("pw").unwrap();
        let err = v.create("pw").unwrap_err();
        assert!(err.contains("already exists"));
    }

    #[test]
    fn test_unlock_correct_password() {
        let td = temp_dir();
        let v = make_vault(&td.path().to_path_buf());
        v.create("secret").unwrap();
        v.lock();
        assert!(!v.is_unlocked());
        v.unlock("secret").unwrap();
        assert!(v.is_unlocked());
    }

    #[test]
    fn test_unlock_wrong_password_fails() {
        let td = temp_dir();
        let v = make_vault(&td.path().to_path_buf());
        v.create("correct").unwrap();
        v.lock();
        let err = v.unlock("wrong").unwrap_err();
        assert!(err.contains("Invalid password") || err.contains("corrupted"));
    }

    #[test]
    fn test_unlock_nonexistent_vault_fails() {
        let td = temp_dir();
        let v = make_vault(&td.path().to_path_buf());
        let err = v.unlock("pw").unwrap_err();
        assert!(err.contains("does not exist"));
    }

    #[test]
    fn test_list_locked_returns_error() {
        let td = temp_dir();
        let v = make_vault(&td.path().to_path_buf());
        let err = v.list_keys().unwrap_err();
        assert!(err.contains("locked"));
    }

    // ─── CRUD ────────────────────────────────────────────────────

    #[test]
    fn test_add_and_list_key() {
        let td = temp_dir();
        let v = make_vault(&td.path().to_path_buf());
        v.create("pw").unwrap();

        let info = v.add_key("My Key", "deadbeef", "pkarr", "pubkey_abc").unwrap();
        assert_eq!(info.name, "My Key");
        assert_eq!(info.pubkey, "pubkey_abc");
        assert_eq!(info.key_type, "pkarr");

        let keys = v.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].pubkey, "pubkey_abc");
    }

    #[test]
    fn test_add_duplicate_pubkey_fails() {
        let td = temp_dir();
        let v = make_vault(&td.path().to_path_buf());
        v.create("pw").unwrap();
        v.add_key("Key 1", "hex1", "pkarr", "pubkey_dup").unwrap();
        let err = v.add_key("Key 2", "hex2", "pkarr", "pubkey_dup").unwrap_err();
        assert!(err.contains("already exists"));
    }

    #[test]
    fn test_export_key() {
        let td = temp_dir();
        let v = make_vault(&td.path().to_path_buf());
        v.create("pw").unwrap();
        v.add_key("K", "secrethex", "pkarr", "mypubkey").unwrap();
        let secret = v.export_key("mypubkey").unwrap();
        assert_eq!(secret, "secrethex");
    }

    #[test]
    fn test_export_nonexistent_key_fails() {
        let td = temp_dir();
        let v = make_vault(&td.path().to_path_buf());
        v.create("pw").unwrap();
        let err = v.export_key("nope").unwrap_err();
        assert!(err.contains("not found") || err.contains("Key not found"));
    }

    #[test]
    fn test_delete_key() {
        let td = temp_dir();
        let v = make_vault(&td.path().to_path_buf());
        v.create("pw").unwrap();
        v.add_key("K", "h", "pkarr", "pk1").unwrap();
        v.delete_key("pk1").unwrap();
        let keys = v.list_keys().unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn test_delete_nonexistent_fails() {
        let td = temp_dir();
        let v = make_vault(&td.path().to_path_buf());
        v.create("pw").unwrap();
        let err = v.delete_key("ghost").unwrap_err();
        assert!(err.contains("not found") || err.contains("Key not found"));
    }

    #[test]
    fn test_rename_key() {
        let td = temp_dir();
        let v = make_vault(&td.path().to_path_buf());
        v.create("pw").unwrap();
        v.add_key("OldName", "h", "pkarr", "pk1").unwrap();
        v.rename_key("pk1", "NewName").unwrap();
        let keys = v.list_keys().unwrap();
        assert_eq!(keys[0].name, "NewName");
    }

    // ─── Persist roundtrip ───────────────────────────────────────

    #[test]
    fn test_persist_and_reload() {
        let td = temp_dir();
        let path = td.path().to_path_buf();

        {
            let v = make_vault(&path);
            v.create("mypass").unwrap();
            v.add_key("TestKey", "secretdata", "manual", "pubkey_rt").unwrap();
        }

        // Reload from disk with a new vault instance
        let v2 = make_vault(&path);
        assert!(v2.exists());
        v2.unlock("mypass").unwrap();
        let keys = v2.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].pubkey, "pubkey_rt");
        assert_eq!(keys[0].name, "TestKey");
    }

    // ─── Import / Export All ────────────────────────────────────

    #[test]
    fn test_import_skips_duplicates() {
        let td = temp_dir();
        let v = make_vault(&td.path().to_path_buf());
        v.create("pw").unwrap();
        v.add_key("K1", "h1", "pkarr", "pk1").unwrap();

        let full = v.export_all_keys().unwrap();
        assert_eq!(full.len(), 1);
        assert_eq!(full[0].secret_hex, "h1");

        // Import same keys again — should be skipped
        let imported = v.import_keys(full).unwrap();
        assert_eq!(imported, 0);
        assert_eq!(v.list_keys().unwrap().len(), 1);
    }

    #[test]
    fn test_import_new_keys() {
        let td = temp_dir();
        let v = make_vault(&td.path().to_path_buf());
        v.create("pw").unwrap();

        let new_keys = vec![VaultKey {
            id: "id1".to_string(),
            name: "Imported".to_string(),
            key_type: "pkarr".to_string(),
            pubkey: "pk_imported".to_string(),
            secret_hex: "hexdata".to_string(),
            created_at: "2025-01-01T00:00:00Z".to_string(),
        }];

        let imported = v.import_keys(new_keys).unwrap();
        assert_eq!(imported, 1);
        let keys = v.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].pubkey, "pk_imported");
    }

    // ─── Date helper ─────────────────────────────────────────────

    #[test]
    fn test_days_to_date_unix_epoch() {
        // Day 0 = 1970-01-01
        let (y, m, d) = days_to_date(0);
        assert_eq!(y, 1970);
        assert_eq!(m, 1);
        assert_eq!(d, 1);
    }

    #[test]
    fn test_days_to_date_known_date() {
        // 2025-03-01 = days since epoch
        // 2025-01-01 = 365*55 + 14 leap days = 20089 days from 1970
        // 2025-03-01 = 20089 + 31 + 28 = 20148
        let (y, m, d) = days_to_date(20148);
        assert_eq!(y, 2025);
        assert_eq!(m, 3);
        assert_eq!(d, 1);
    }

    #[test]
    fn test_chrono_now_format() {
        let ts = chrono_now();
        // Should match YYYY-MM-DDTHH:MM:SSZ
        assert_eq!(ts.len(), 20);
        assert!(ts.contains('T'));
        assert!(ts.ends_with('Z'));
        assert!(ts.starts_with("20")); // 21st century
    }
}

