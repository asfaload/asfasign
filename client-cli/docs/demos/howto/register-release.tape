Output out/register-release.gif

Set Shell "bash"
Set Width 1200
Set Height 700
Set TypingSpeed 60ms
Set PlaybackSpeed 1.0

Type "# 1. The release publishes a checksums file alongside its artifacts."
Enter
Type 'echo "$ASFALOAD_DEMO_CSUM_URL"'
Enter
Sleep 2s

Type "# 2. Register the release against the backend"
Enter
Type 'asfaload-cli register-assets --secret-key ~/.asfaload/key_0 --password-file ~/.asfaload/.demo-password -u "$ASFALOAD_DEMO_BACKEND_URL" --csum-file "$ASFALOAD_DEMO_CSUM_URL"'
Enter
Sleep 5s
