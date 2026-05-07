Output out/generate-keys.gif

Set Shell "bash"
Set Width 1200
Set Height 700
Set TypingSpeed 60ms
Set PlaybackSpeed 1.0

Type "# 1. Choose a directory for keys"
Enter
Type "mkdir -p ~/.asfaload"
Enter
Sleep 1s

Type "# 2. Generate the key pair (non-interactive: password from --password-file)"
Enter
Type "asfaload-cli new-keys --name mykey --output-dir ~/.asfaload --password-file ~/.asfaload/.demo-password"
Enter
Sleep 4s

Type "# 3. Verify the output"
Enter
Type "ls ~/.asfaload/mykey*"
Enter
Sleep 3s
