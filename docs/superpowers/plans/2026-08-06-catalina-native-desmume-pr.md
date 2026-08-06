# Pull Request Summary

Builds a manually triggered Catalina-native DeSmuME debugger artifact without changing RE-MCP runtime behavior.

The workflow:

- Fetches DeSmuME `release_0_9_13`.
- Applies a narrow environment-driven ARM9 GDB startup patch.
- Builds Cocoa dev+ for Intel `x86_64` with macOS 10.15 as the deployment target.
- Validates architecture, minimum OS, launcher behavior, and patch presence.
- Packages the app, direct launcher, compatibility report, and checksums.
- Uploads complete native build diagnostics even on failure.

Merge remains blocked on a successful workflow run and target Catalina smoke test.
