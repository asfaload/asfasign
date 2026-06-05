// Binary-level tests for the ping command. Server-backed behavior is covered
// by tests/client-server-integration-tests; here we only verify CLI wiring.

// An unreachable backend must produce a non-zero exit code.
#[test]
fn test_ping_unreachable_backend_fails() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    // Port 9 (discard protocol) is essentially guaranteed to refuse connections.
    cmd.arg("ping").arg("-u").arg("http://127.0.0.1:9");
    cmd.assert().failure();
}
