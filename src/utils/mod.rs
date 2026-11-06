//! Utility functions

/// Wall-clock seconds since the UNIX epoch.
///
/// `SystemTime::now().duration_since(UNIX_EPOCH)` only fails when the
/// system clock is set before 1970-01-01 — possible in theory on a
/// catastrophically misconfigured machine, never in practice on a
/// well-managed validator. The previous code used `.unwrap()` for
/// this, which would crash the process mid-consensus on such a clock.
/// `unwrap_or_default()` returns `Duration::ZERO`, equivalent to a
/// 1970 timestamp; the misconfiguration becomes visible through
/// "1970-01-01" timestamps in logs and metrics rather than a panic.
pub fn now_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Convert bytes to a hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Convert a hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, &'static str> {
    if !hex.is_ascii() {
        return Err("Invalid hex character");
    }
    if !hex.len().is_multiple_of(2) {
        return Err("Hex string must have an even number of characters");
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| "Invalid hex character")?;
        bytes.push(byte);
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip_and_validation() {
        let original = vec![0x00, 0x12, 0xab, 0xff];
        let encoded = bytes_to_hex(&original);
        assert_eq!(encoded, "0012abff");
        assert_eq!(hex_to_bytes(&encoded).unwrap(), original);
        assert_eq!(
            hex_to_bytes("abc"),
            Err("Hex string must have an even number of characters")
        );
        assert_eq!(hex_to_bytes("0g"), Err("Invalid hex character"));
    }

    #[test]
    fn hex_to_bytes_rejects_multibyte_utf8_without_panicking() {
        // "a€" is 1 + 3 = 4 UTF-8 bytes (even length), where byte index 2 falls
        // inside the 3-byte '€' codepoint. Must return Err, never panic.
        assert_eq!(hex_to_bytes("a€"), Err("Invalid hex character"));
        assert_eq!(hex_to_bytes("é"), Err("Invalid hex character"));
        assert_eq!(hex_to_bytes("🦀"), Err("Invalid hex character"));
    }
}
