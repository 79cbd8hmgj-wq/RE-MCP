# Catalina-Native Verification Gate

Do not merge this branch until the manually triggered workflow produces an artifact and the artifact passes on-device Catalina validation.

Required checks:

1. Workflow completes successfully on `macos-15-intel`.
2. Packaged binary reports `x86_64` only.
3. Mach-O minimum macOS version is no later than 10.15.
4. App launches on the target Catalina Mac.
5. Known-good NDS ROM boots.
6. Requested ARM9 GDB port listens on localhost.
7. RE-MCP can probe the port after launcher integration.
8. Raw ARM9 register read succeeds.
9. Bounded ARM9 memory read succeeds.
