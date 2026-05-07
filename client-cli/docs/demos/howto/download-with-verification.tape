Output out/download-with-verification.gif

Set Shell "bash"
Set Width 1200
Set Height 700
Set TypingSpeed 60ms
Set PlaybackSpeed 1.0

Type "# 1. Download the artifact; signatures are verified before saving."
Enter
Type "cd ~"
Enter
Type 'asfaload-cli download --type fileserver -u "$ASFALOAD_DEMO_BACKEND_URL" "$ASFALOAD_DEMO_ARTIFACT_URL"'
Enter
Sleep 6s

Type "# 2. The verified file is now on disk"
Enter
Type "ls -lh artifact.bin"
Enter
Sleep 3s
