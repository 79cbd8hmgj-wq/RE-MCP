# Catalina-Native DeSmuME Debug Bundle Design

## Goal

Create a manually triggered GitHub Actions workflow that builds and packages a DeSmuME debugger bundle specifically for Intel Macs running macOS Catalina 10.15. The first milestone is a reproducible, downloadable emulator artifact. RE-MCP integration changes remain out of scope until that artifact is verified on the target Mac.

## Scope

This design covers:

- A fresh branch based on `main`.
- A `workflow_dispatch`-only GitHub Actions workflow.
- A pinned DeSmuME source revision.
- An Intel `x86_64` Cocoa application build.
- A macOS 10.15 deployment target.
- ARM9 GDB-stub support and automatic port configuration.
- A launcher that executes the app binary directly so RE-MCP can own the process later.
- Compatibility inspection, diagnostics, checksums, and artifact packaging.

This design does not yet modify RE-MCP's tool schema, process manager, GDB client, or runtime-evidence behavior.

## Architecture

The workflow runs on an Intel macOS GitHub-hosted runner and performs five isolated stages:

1. Fetch a pinned DeSmuME source revision.
2. Apply a small repository-owned Catalina/GDB patch.
3. Build the Cocoa frontend as `x86_64` with `MACOSX_DEPLOYMENT_TARGET=10.15` and signing disabled.
4. Assemble a portable bundle with the application, launcher, documentation, compatibility report, and SHA-256 checksum.
5. Upload the bundle and diagnostic logs as a GitHub Actions artifact.

The produced launcher invokes `DeSmuME Debug.app/Contents/MacOS/<CFBundleExecutable>` directly rather than using `open`. It accepts an absolute ROM path and ARM9 GDB port, exports `RE_MCP_ARM9_GDB_PORT`, and replaces itself with the emulator process using `exec`.

## Workflow Contract

The workflow file will be:

```text
.github/workflows/build-desmume-catalina-native.yml
```

Trigger:

```yaml
on:
  workflow_dispatch:
```

No push or pull-request trigger will be included.

The build will use:

- Architecture: `x86_64`
- Minimum target: macOS `10.15`
- Code signing: disabled
- DeSmuME source: pinned tag or commit, not an unpinned default branch
- Build type: Cocoa debug-capable/dev+ application

## Source Patch Boundary

The patch script will be repository-owned and narrowly scoped. It may:

- Read `RE_MCP_ARM9_GDB_PORT` at application startup.
- Validate that the value is an integer from 1024 through 65535.
- Start the ARM9 GDB stub automatically when the variable is present.
- Leave normal application startup unchanged when the variable is absent.

It must not add arbitrary command execution, remote network binding, memory writes, breakpoint automation, or unrelated emulator modifications.

## Bundle Layout

The downloadable ZIP will contain:

```text
desmume-catalina-native-debug/
├── DeSmuME Debug.app/
├── run-desmume-debug.command
├── README.txt
├── compatibility-report.txt
└── SHA256SUMS.txt
```

The launcher contract will be:

```bash
./run-desmume-debug.command /absolute/path/to/game.nds 20000
```

The launcher will:

- Require exactly two arguments.
- Require an existing readable ROM file.
- Require a GDB port from 1024 through 65535.
- Resolve its own bundle directory.
- Read `CFBundleExecutable` from `Info.plist`.
- Verify that the inner executable exists and is executable.
- Export `RE_MCP_ARM9_GDB_PORT`.
- Use `exec` to launch the inner executable with the ROM path.

## Compatibility Verification

The workflow will fail unless all of the following pass:

- The packaged executable exists.
- `lipo -archs` reports only `x86_64`.
- The Mach-O minimum macOS version is no later than 10.15.
- The app contains the expected Cocoa executable and `Info.plist`.
- The launcher contains the environment-variable handoff.
- The patched source contains the GDB autostart hook.
- The ZIP and checksum are generated successfully.

The workflow will capture:

- Xcode project/scheme discovery output.
- Full build log.
- Condensed error summary when the build fails.
- `file` output.
- `lipo` architecture output.
- `otool -L` dependency output.
- Mach-O load commands.
- Parsed minimum-macOS result.

Diagnostics will be uploaded even when the build fails.

## Error Handling

- Source-fetch failure stops before patching.
- Patch failure stops before building.
- Xcode failures retain complete logs and a condensed error report.
- Missing app bundles, executables, or metadata fail packaging.
- Incorrect architecture or deployment target fails compatibility validation.
- Artifact upload uses `if: always()` so diagnostics remain available after failures.

## Testing Strategy

Repository-level tests will verify static policy where practical:

- The workflow is manual-only.
- The workflow pins the source revision.
- The build specifies `ARCHS=x86_64`.
- The build specifies `MACOSX_DEPLOYMENT_TARGET=10.15`.
- The launcher validates argument count, ROM readability, and port range.
- The launcher directly executes the inner app binary.
- The patch is limited to environment-driven ARM9 GDB startup.

The GitHub Actions run validates the native build. Final acceptance requires a manual smoke test on the user's Catalina Mac:

1. Download and extract the artifact.
2. Remove quarantine if macOS applies it.
3. Launch a known-good NDS ROM through the packaged launcher.
4. Confirm the Cocoa application opens.
5. Confirm localhost port 20000 is listening.
6. Confirm RE-MCP can probe the port.
7. Confirm a raw ARM9 register packet can be read.
8. Confirm a bounded memory read succeeds.

## Acceptance Criteria

The design is complete when a manually started workflow produces a downloadable ZIP whose DeSmuME Cocoa executable is Intel `x86_64`, declares a minimum macOS version no later than 10.15, launches a ROM through the included script, and automatically exposes the ARM9 GDB stub on the requested localhost port.

RE-MCP integration proceeds only after the native artifact passes the Catalina smoke test.
