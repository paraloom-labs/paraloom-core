//! Regression tests for #1690:
//! `wallet new-address` leaves a pre-existing keys dir / key file at loose permissions.

#[test]
#[cfg(unix)]
fn test_wallet_new_address_tightens_preexisting_loose_permissions() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let keys_dir = temp_dir.path().join(".paraloom/keys");
    std::fs::create_dir_all(&keys_dir).expect("create keys dir");
    std::fs::set_permissions(&keys_dir, std::fs::Permissions::from_mode(0o755))
        .expect("chmod 755 keys dir");

    let key_file = keys_dir.join("test.key");
    std::fs::write(&key_file, b"dummy old key content").expect("write dummy key");
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o644))
        .expect("chmod 644 key file");

    let exe = env!("CARGO_BIN_EXE_paraloom");
    let output = Command::new(exe)
        .args(["wallet", "new-address", "--label", "test"])
        .current_dir(temp_dir.path())
        .output()
        .expect("execute paraloom wallet new-address");

    assert!(
        output.status.success(),
        "CLI command failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let dir_perms = std::fs::metadata(&keys_dir)
        .expect("get keys dir metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        dir_perms, 0o700,
        "keys dir should be tightened to 0700, got {:o}",
        dir_perms
    );

    let file_perms = std::fs::metadata(&key_file)
        .expect("get key file metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        file_perms, 0o600,
        "key file should be tightened to 0600, got {:o}",
        file_perms
    );
}

#[test]
#[cfg(unix)]
fn test_wallet_new_address_fresh_creation_permissions() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let exe = env!("CARGO_BIN_EXE_paraloom");
    let output = Command::new(exe)
        .args(["wallet", "new-address", "--label", "fresh"])
        .current_dir(temp_dir.path())
        .output()
        .expect("execute paraloom wallet new-address");

    assert!(
        output.status.success(),
        "CLI command failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let keys_dir = temp_dir.path().join(".paraloom/keys");
    let key_file = keys_dir.join("fresh.key");

    let dir_perms = std::fs::metadata(&keys_dir)
        .expect("get keys dir metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        dir_perms, 0o700,
        "keys dir should be created as 0700, got {:o}",
        dir_perms
    );

    let file_perms = std::fs::metadata(&key_file)
        .expect("get key file metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        file_perms, 0o600,
        "key file should be created as 0600, got {:o}",
        file_perms
    );
}
