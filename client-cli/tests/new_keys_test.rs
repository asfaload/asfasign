use features_lib::{AsfaloadSecretKeyTrait, AsfaloadSecretKeys};
use tempfile::TempDir;

const TEST_PASSWORD: &str = "test_password_123";

// Verifies that a key created via --password-command can be loaded with the
// password the command printed -- i.e. it is equivalent to passing the same
// string via --password.
#[test]
fn test_new_keys_password_command_produces_loadable_key() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("mykey");

    // `printf %s` outputs the password with no trailing newline.
    let cmd_str = format!("sh -c 'printf %s {TEST_PASSWORD}'");

    let mut cmd = assert_cmd::cargo_bin_cmd!("client-cli");
    cmd.arg("new-keys")
        .arg("-n")
        .arg("mykey")
        .arg("-o")
        .arg(temp_dir.path())
        .arg("-c")
        .arg(&cmd_str)
        .arg("--accept-weak-password");
    cmd.assert().success();

    AsfaloadSecretKeys::from_file(&key_path, TEST_PASSWORD)
        .expect("key generated with --password-command should load with the printed password");
}

// `echo` appends a trailing newline; the implementation must strip it so the
// effective password matches what the user (or another command using --password)
// would type.
#[test]
fn test_new_keys_password_command_trims_trailing_newline() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("mykey");

    let cmd_str = format!("sh -c 'echo {TEST_PASSWORD}'");

    let mut cmd = assert_cmd::cargo_bin_cmd!("client-cli");
    cmd.arg("new-keys")
        .arg("-n")
        .arg("mykey")
        .arg("-o")
        .arg(temp_dir.path())
        .arg("-c")
        .arg(&cmd_str)
        .arg("--accept-weak-password");
    cmd.assert().success();

    AsfaloadSecretKeys::from_file(&key_path, TEST_PASSWORD)
        .expect("trailing newline from echo should be trimmed before the password is used");
}
