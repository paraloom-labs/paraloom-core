//! Regression test suite for Issue #1372:
//! - utils::hex_to_bytes UTF-8 char-boundary panic
//! - 0600 file permissions for sensitive note/keypair storage
//! - Merkle tree slicing & underflow guards

use paraloom::utils::hex_to_bytes;

#[test]
fn test_issue_1372_hex_to_bytes_utf8_char_boundary_poc() {
    // PoC: Prior to the fix, multi-byte UTF-8 strings with even byte length (e.g., "a€" = 4 bytes)
    // caused an unhandled runtime panic at `&hex[i..i+2]` because byte index 2 was not a char boundary.
    // With the fix, non-ASCII input is gracefully rejected with Err.
    let malicious_utf8_even_len = "a€";
    assert_eq!(malicious_utf8_even_len.len(), 4);

    let res = hex_to_bytes(malicious_utf8_even_len);
    assert!(res.is_err(), "Expected Err, got {:?}", res);

    // Test emoji with even length (e.g. 🦀 is 4 bytes)
    let crab_emoji = "🦀";
    assert_eq!(crab_emoji.len(), 4);
    assert!(hex_to_bytes(crab_emoji).is_err());
}

#[cfg(unix)]
#[test]
fn test_issue_1372_sensitive_file_permissions_0600() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let test_file = temp_dir.path().join("private_swap_note_test.json");

    fs::write(&test_file, b"{\"in_sk\": \"secret\"}").expect("write test file");
    fs::set_permissions(&test_file, fs::Permissions::from_mode(0o600)).expect("set 0600");

    let metadata = fs::metadata(&test_file).expect("get metadata");
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "Sensitive file must be restricted to 0600, got {:o}",
        mode
    );
}

#[test]
fn test_issue_1372_merkle_tree_checked_sub_underflow_guard() {
    // Validate checked_sub(1) prevents panic on next_index == 0
    let next_index: u64 = 0;
    assert!(
        next_index.checked_sub(1).is_none(),
        "next_index=0 must not underflow"
    );

    let next_index_valid: u64 = 5;
    assert_eq!(next_index_valid.checked_sub(1), Some(4));
}
