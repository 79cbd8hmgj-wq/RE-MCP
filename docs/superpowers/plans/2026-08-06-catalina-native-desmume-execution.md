# Catalina-Native DeSmuME Execution Status

Implemented on `feature/catalina-native-desmume`:

- Manual-only Catalina-native build workflow.
- Pinned DeSmuME 0.9.13 source checkout.
- Narrow Cocoa ARM9 GDB autostart patch.
- Intel `x86_64` and macOS 10.15 compatibility checks.
- Direct inner-binary launcher with ROM and port validation.
- Bundle documentation, compatibility report, internal checksums, outer ZIP checksum, and failure diagnostics.
- Static repository policy tests.
- Operator documentation and target-Mac acceptance checklist.

Outstanding external verification:

- Run the manual GitHub Actions workflow.
- Inspect any native Xcode build failures.
- Download the artifact.
- Smoke-test it on the target macOS Catalina machine.
- Add RE-MCP `macos-cocoa` launcher integration only after the artifact passes.
