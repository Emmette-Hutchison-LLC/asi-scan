# VHS tape for the asi-scan usage demo.
# Regenerate with:  vhs docs/demo.tape   (run from the repo root)
Output docs/demo.gif

Set Shell bash
Set FontSize 14
Set Width 1440
Set Height 560
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Sleep 500ms
Type "# asi-scan: runtime OWASP Agentic Top 10 (ASI01-ASI10) scanner for MCP"
Sleep 700ms
Enter
Sleep 400ms
Type "uv run asi-scan scan --target self-test --format md 2>/dev/null"
Sleep 700ms
Enter
Sleep 4s
