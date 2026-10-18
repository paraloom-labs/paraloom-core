//! Keypair management for bridge authority
//!
//! Loads and manages the bridge authority keypair for signing transactions

use crate::bridge::{BridgeError, Result};
use solana_sdk::signature::{Keypair, Signer};
use std::fs;
use std::path::Path;
use std::sync::atomic::{compiler_fence, Ordering};

fn zeroize_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid aligned mutable reference to a `u8` in `buf`.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

fn zeroize_string(s: &mut String) {
    // SAFETY: zeroing UTF-8 bytes produces valid all-NUL UTF-8 before clearing.
    unsafe { zeroize_bytes(s.as_bytes_mut()) };
    s.clear();
}

/// Load keypair from file and verify that its 32-byte public key half matches
/// the 32-byte secret key half.
pub fn load_keypair_from_file(path: &str) -> Result<Keypair> {
    let path = Path::new(path);

    if !path.exists() {
        return Err(BridgeError::ConfigError(format!(
            "Keypair file not found: {}",
            path.display()
        )));
    }

    let mut file_contents = fs::read_to_string(path)
        .map_err(|e| BridgeError::ConfigError(format!("Failed to read keypair file: {}", e)))?;

    // Parse JSON format keypair and zeroize the raw string buffer immediately.
    let parse_res: std::result::Result<Vec<u8>, serde_json::Error> =
        serde_json::from_str(&file_contents);
    zeroize_string(&mut file_contents);
    let mut bytes =
        parse_res.map_err(|e| BridgeError::ConfigError(format!("Failed to parse keypair JSON: {}", e)))?;

    let expected_pub: Option<[u8; 32]> = bytes.get(32..64).and_then(|s| s.try_into().ok());
    let kp_res = Keypair::try_from(bytes.as_slice()).map_err(|e| {
        BridgeError::ConfigError(format!("Failed to create keypair from bytes: {}", e))
    });
    zeroize_bytes(&mut bytes);
    let kp = kp_res?;

    // Verify both that the derived public key matches the stored 32-byte public
    // half in `bytes[32..64]` and that a self-signature verifies cleanly.
    const SELF_CHECK_MSG: &[u8] = b"paraloom:keypair-self-check:v1";
    let sig = kp.sign_message(SELF_CHECK_MSG);
    if expected_pub != Some(kp.pubkey().to_bytes())
        || !sig.verify(kp.pubkey().as_ref(), SELF_CHECK_MSG)
    {
        return Err(BridgeError::ConfigError(
            "Keypair public key half does not match secret key".to_string(),
        ));
    }

    Ok(kp)
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

/// Save keypair to file in JSON format, restricting permissions before writing
/// secret key material on Unix and zeroizing temporary secret buffers.
#[allow(dead_code)]
pub fn save_keypair_to_file(keypair: &Keypair, path: &str) -> Result<()> {
    let mut bytes = keypair.to_bytes();
    let mut bytes_vec = bytes.to_vec();
    zeroize_bytes(&mut bytes);
    let json_res = serde_json::to_string(&bytes_vec);
    zeroize_bytes(&mut bytes_vec);
    let mut json = json_res
        .map_err(|e| BridgeError::ConfigError(format!("Failed to serialize keypair: {}", e)))?;

    let write_res = (|| -> Result<()> {
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)
                .map_err(|e| {
                    BridgeError::ConfigError(format!("Failed to open keypair file: {}", e))
                })?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| {
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
            fs::write(path, json.as_bytes()).map_err(|e| {
                BridgeError::ConfigError(format!("Failed to write keypair file: {}", e))
            })?;
        }
        Ok(())
    })();

    zeroize_string(&mut json);
    write_res
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
    fn test_load_rejects_mismatched_public_key_half() {
        let kp1 = generate_keypair();
        let kp2 = generate_keypair();
        let mut raw = kp1.to_bytes();
        // Replace the 32-byte public key half with kp2's public key.
        raw[32..64].copy_from_slice(kp2.pubkey().as_ref());

        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_str().unwrap();
        fs::write(path, serde_json::to_string(&raw.to_vec()).unwrap()).unwrap();

        let err = load_keypair_from_file(path).expect_err("mismatched pubkey half must fail");
        assert!(matches!(err, BridgeError::ConfigError(_)));
    }

    #[test]
    fn test_load_nonexistent_file() {
        let result = load_keypair_from_file("/nonexistent/path/keypair.json");
        assert!(result.is_err());
    }
}
