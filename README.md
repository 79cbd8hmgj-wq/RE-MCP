# RE-MCP

A safety-first local Model Context Protocol server for ROM reverse-engineering workflows.

RE-MCP uses **stdio** and exposes narrow, tested tools rather than an unrestricted shell.

## Current capabilities

### General

- Project Git status
- Allowlisted npm verification
- SHA-256 file verification
- Capability and policy reporting

### Bakugan DS

- Compile, Ruff, mypy, pytest, or full quality suite
- Regenerate Milestone 6E contracts
- Run the Milestone 6E installer in dry-run mode
- Generate the Milestone 6E roster analysis

### DeSmuME and ARM9 GDB

- Start, inspect, and stop one server-owned DeSmuME process
- Probe and wait for the owned ARM9 GDB port
- Read the raw ARM9 register packet
- Read up to 4096 bytes of ARM9 memory
- Atomically capture raw registers plus labeled memory regions

RE-MCP does not currently expose breakpoints, execution control, register writes, memory writes, or arbitrary GDB commands.

## Requirements

- Node.js 20 or newer
- An MCP host that can launch local stdio servers
- A dedicated workspace containing the intended repositories and private ROM-development inputs
- For emulator tools, a verified DeSmuME debug bundle

## Downloadable RE-MCP bundle

The `Package` GitHub Actions workflow publishes a `re-mcp-downloadable-bundle` artifact containing:

- Compiled JavaScript
- Production dependencies
- Configuration template
- Installation self-check
- SHA-256 checksum

After downloading and extracting the archive:

```bash
cd re-mcp-0.6.0
node scripts/check-install.mjs .
```

Copy `mcp-config.example.json`, replace both absolute paths, and add the resulting configuration to your MCP host.

## Build the Catalina-native DeSmuME debugger bundle

The manual **Build Catalina-Native DeSmuME Debug Bundle** workflow builds the DeSmuME 0.9.13 Cocoa dev+ application for Intel `x86_64` Macs with a macOS 10.15 deployment target. It applies a narrow patch that starts the existing ARM9 GDB stub when `RE_MCP_ARM9_GDB_PORT` is supplied.

To run it:

1. Open the repository's **Actions** tab.
2. Select **Build Catalina-Native DeSmuME Debug Bundle**.
3. Select branch `feature/catalina-native-desmume`.
4. Choose **Run workflow**.
5. Download `desmume-catalina-native-debug-bundle` after the job finishes.
6. Verify `desmume-catalina-native-debug.zip` against the accompanying `.zip.sha256` file before extraction.

After extraction on the Catalina Mac:

```bash
xattr -dr com.apple.quarantine desmume-catalina-native-debug
chmod +x desmume-catalina-native-debug/run-desmume-debug.command
./desmume-catalina-native-debug/run-desmume-debug.command \
  /absolute/path/to/Bakugan.nds 20000
```

Only remove quarantine after verifying the checksum and confirming that the artifact came from the expected workflow run.

### Catalina acceptance checklist

Before integrating this launcher mode into RE-MCP, verify on the target macOS Catalina 10.15 system that:

- The Cocoa application opens.
- The ROM boots successfully.
- `lsof -nP -iTCP:20000 -sTCP:LISTEN` shows a localhost listener.
- RE-MCP's `desmume_probe_gdb` succeeds after the launcher integration is added.
- A raw ARM9 register packet can be read.
- One bounded ARM9 memory read succeeds.

The current branch produces and validates the native artifact only. RE-MCP launcher-schema integration is the next milestone after this smoke test passes.

## Build RE-MCP from source

```bash
npm install
npm run check
npm run build
```

Run directly:

```bash
RE_MCP_WORKSPACE_ROOT=/absolute/path/to/rom-modding \
node dist/index.js
```

The server refuses to start without an explicit workspace root.

## DeSmuME launcher contract

The currently verified Linux launcher contract is:

```bash
run-desmume-debug.sh --arm9gdb=20000 /path/to/game.nds
```

The candidate Catalina-native bundle uses:

```bash
run-desmume-debug.command /path/to/game.nds 20000
```

RE-MCP owns at most one emulator child process per server instance. It rejects duplicate starts, captures bounded logs, and terminates the owned emulator during MCP shutdown.

## Security model

- No arbitrary shell tool
- No shell interpolation
- Fixed executable and argument construction
- Workspace path containment
- Process timeouts and bounded output
- Minimal child-process environment
- Milestone 6E installation restricted to dry-run mode
- One server-owned DeSmuME process
- GDB restricted to the owned localhost port
- Read-only `g` and bounded `m` packets
- Runtime evidence restricted to project `analysis/generated`
- No attachment to unrelated emulator processes

Do not use your general home directory as `RE_MCP_WORKSPACE_ROOT`. Create a dedicated directory containing only the repositories and private inputs intended for RE-MCP.
