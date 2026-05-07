Output out/activate-signers-file.gif

Set Shell "bash"
Set Width 1200
Set Height 700
Set TypingSpeed 60ms
Set PlaybackSpeed 1.0

Type "# 1. Check what needs your signature"
Enter
Type 'asfaload-cli list-pending --secret-key ~/.asfaload/key_0 --password-file ~/.asfaload/.demo-password -u "$ASFALOAD_DEMO_BACKEND_URL"'
Enter
Sleep 3s

Type "# 2. Each signer signs the pending file (every signer must sign)"
Enter
Type 'asfaload-cli sign-pending --secret-key ~/.asfaload/key_0 --password-file ~/.asfaload/.demo-password -u "$ASFALOAD_DEMO_BACKEND_URL" "$ASFALOAD_DEMO_PENDING_SIGNERS_PATH"'
Enter
Sleep 3s

Type 'asfaload-cli sign-pending --secret-key ~/.asfaload/key_1 --password-file ~/.asfaload/.demo-password -u "$ASFALOAD_DEMO_BACKEND_URL" "$ASFALOAD_DEMO_PENDING_SIGNERS_PATH"'
Enter
Sleep 3s

Type 'asfaload-cli sign-pending --secret-key ~/.asfaload/key_2 --password-file ~/.asfaload/.demo-password -u "$ASFALOAD_DEMO_BACKEND_URL" "$ASFALOAD_DEMO_PENDING_SIGNERS_PATH"'
Enter
Sleep 4s
