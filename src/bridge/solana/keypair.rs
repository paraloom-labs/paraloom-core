//! Keypair management for bridge authority
//!
//! Loads and manages the bridge authority keypair for signing transactions

use crate::bridge::{BridgeError, Result};
use solana_sdk::signature::{Keypair, Signer};
use std::fs;
use std::io::Write;
use std::path::Path;

/// Load keypair from file
pub fn load_keypair_from_file(path: &str) -> Result<Keypair> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(BridgeError::ConfigError(
            "Keypair file path cannot be empty".to_string(),
        ));
    }
    let path = Path::new(trimmed);

    if !path.exists() {
        return Err(BridgeError::ConfigError(format!(
            "Keypair file not found: {}",
            path.display()
        )));
    }

    let file_contents = fs::read_to_string(path)
        .map_err(|e| BridgeError::ConfigError(format!("Failed to read keypair file: {}", e)))?;

    // Parse JSON format keypair
    let bytes: Vec<u8> = serde_json::from_str(&file_contents)
        .map_err(|e| BridgeError::ConfigError(format!("Failed to parse keypair JSON: {}", e)))?;

    if bytes.len() != 64 {
        return Err(BridgeError::ConfigError(format!(
            "Invalid keypair byte length: expected 64, got {}",
            bytes.len()
        )));
    }

    let keypair = Keypair::try_from(bytes.as_slice()).map_err(|e| {
        BridgeError::ConfigError(format!("Failed to create keypair from bytes: {}", e))
    })?;

    // Verify the embedded 32-byte public-key suffix matches the public key
    // derived from the 32-byte secret seed (RUSTSEC-2022-0093).
    let secret_seed: [u8; 32] = bytes[..32].try_into().expect("checked 64-byte slice");
    let derived = Keypair::new_from_array(secret_seed);
    if keypair.pubkey() != derived.pubkey() {
        return Err(BridgeError::ConfigError(
            "Keypair public-key half does not match secret seed".to_string(),
        ));
    }

    Ok(keypair)
}

/// Load just the public key (base58) from a keypair file, so a validator can
/// advertise the wallet it co-signs settlement with (#260) without exposing the
/// secret elsewhere.
pub fn pubkey_from_file(path: &str) -> Result<String> {
    Ok(load_keypair_from_file(path)?.pubkey().to_string())
}

/// Generate a new keypair (for testing)
#[cfg(test)]
pub fn generate_keypair() -> Keypair {
    Keypair::new()
}

/// Save keypair to file in JSON format
#[allow(dead_code)]
pub fn save_keypair_to_file(keypair: &Keypair, path: &str) -> Result<()> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(BridgeError::ConfigError(
            "Keypair file path cannot be empty".to_string(),
        ));
    }
    let path_obj = Path::new(trimmed);
    if let Some(parent) = path_obj.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| {
                BridgeError::ConfigError(format!(
                    "Failed to create keypair parent directory: {}",
                    e
                ))
            })?;
        }
    }

    let bytes = keypair.to_bytes();
    let json = serde_json::to_string(&bytes.to_vec())
        .map_err(|e| BridgeError::ConfigError(format!("Failed to serialize keypair: {}", e)))?;

    // Create and restrict the secret-key file to owner-only (0600) before
    // writing secret material so it is never exposed under a permissive umask.
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path_obj)
            .map_err(|e| BridgeError::ConfigError(format!("Failed to open keypair file: {}", e)))?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| {
                BridgeError::ConfigError(format!(
                    "Failed to restrict keypair file permissions: {}",
                    e
                ))
            })?;
        file.write_all(json.as_bytes()).map_err(|e| {
            BridgeError::ConfigError(format!("Failed to write keypair file: {}", e))
        })?;
        file.sync_all().map_err(|e| {
            BridgeError::ConfigError(format!("Failed to sync keypair file: {}", e))
        })?;
    }

    #[cfg(not(unix))]
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path_obj)
            .map_err(|e| BridgeError::ConfigError(format!("Failed to open keypair file: {}", e)))?;
        file.write_all(json.as_bytes()).map_err(|e| {
            BridgeError::ConfigError(format!("Failed to write keypair file: {}", e))
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_keypair_save_and_load() {
        let keypair = generate_keypair();
        let pubkey = keypair.pubkey();

        // Create temp file
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_str().unwrap();

        // Save keypair
        save_keypair_to_file(&keypair, path).unwrap();

        // The saved secret-key file must be owner-only (0600), never
        // world/group-readable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "keypair file must be 0600, got {:o}",
                mode & 0o777
            );
        }

        // Load keypair
        let loaded = load_keypair_from_file(path).unwrap();

        // Verify they match
        assert_eq!(pubkey, loaded.pubkey());
    }

    #[test]
    fn test_load_nonexistent_file() {
        let result = load_keypair_from_file("/nonexistent/path/keypair.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_rejects_mismatched_public_key_half() {
        let kp1 = generate_keypair();
        let kp2 = generate_keypair();
        let mut bytes = kp1.to_bytes();
        bytes[32..64].copy_from_slice(kp2.pubkey().as_ref());

        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_str().unwrap();
        let json = serde_json::to_string(&bytes.to_vec()).unwrap();
        fs::write(path, json).unwrap();

        let err = load_keypair_from_file(path).unwrap_err();
        assert!(
            err.to_string().contains("does not match secret seed"),
            "unexpected error: {err}"
        );
        assert!(pubkey_from_file(path).is_err());
    }

    #[test]
    fn test_load_rejects_wrong_byte_length() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_str().unwrap();
        fs::write(path, "[1, 2, 3, 4]").unwrap();

        let err = load_keypair_from_file(path).unwrap_err();
        assert!(
            err.to_string().contains("Invalid keypair byte length"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_save_creates_missing_parent_directories() {
        let keypair = generate_keypair();
        let dir = tempfile::tempdir().unwrap();
        let nested_path = dir.path().join("nested").join("dir").join("keypair.json");
        let path_str = nested_path.to_str().unwrap();

        save_keypair_to_file(&keypair, path_str).unwrap();
        let loaded = load_keypair_from_file(path_str).unwrap();
        assert_eq!(keypair.pubkey(), loaded.pubkey());
    }
}
