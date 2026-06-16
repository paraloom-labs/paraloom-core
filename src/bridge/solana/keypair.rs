//! Keypair management for bridge authority
//!
//! Loads and manages the bridge authority keypair for signing transactions

use crate::bridge::{BridgeError, Result};
use solana_sdk::signature::Keypair;
use std::fs;
use std::path::Path;

/// Load keypair from file
pub fn load_keypair_from_file(path: &str) -> Result<Keypair> {
    let path = Path::new(path);

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

    Keypair::try_from(bytes.as_slice()).map_err(|e| {
        BridgeError::ConfigError(format!("Failed to create keypair from bytes: {}", e))
    })
}

/// Load just the public key (base58) from a keypair file, so a validator can
/// advertise the wallet it co-signs settlement with (#260) without exposing the
/// secret elsewhere.
pub fn pubkey_from_file(path: &str) -> Result<String> {
    use solana_sdk::signature::Signer;
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
    let bytes = keypair.to_bytes();
    let json = serde_json::to_string(&bytes.to_vec())
        .map_err(|e| BridgeError::ConfigError(format!("Failed to serialize keypair: {}", e)))?;

    fs::write(path, json)
        .map_err(|e| BridgeError::ConfigError(format!("Failed to write keypair file: {}", e)))?;

    // The file holds the secret key — restrict it to the owner (0600) so it is
    // never left world-readable at the process umask.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| {
            BridgeError::ConfigError(format!(
                "Failed to restrict keypair file permissions: {}",
                e
            ))
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signature::Signer;
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
}
