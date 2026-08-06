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
- Linux CLI and macOS Catalina Cocoa launcher modes
- Probe and wait for the owned ARM9 GDB port
- Read the raw ARM9 register packet
- Read up to 4096 bytes of ARM9 memory
- Atomically capture raw registers plus labeled memory regions

RE-MCP does not currently expose breakpoints, execution control, register writes, memory writes, or arbitrary GDB commands.

## Requirements

- Node.js 20 or newer
- An MCP host that can launch local stdio servers
- A dedicated workspace containing the intended repositories and private ROM-development inputs
- For emulator tools, either the Linux bundle or the Catalina debug bundle

## Downloadable RE-MCP bundle

The `Package` GitHub Actions workflow publishes a `re-mcp-downloadable-bundle` artifact containing compiled JavaScript, production dependencies, a configuration template, an installation self-check, and a SHA-256 checksum.

After downloading and extracting the archive:

```bash
cd re-mcp-0.7.0
node scripts/check-install.mjs .
```

Copy `mcp-config.example.json`, replace both absolute paths, and add the resulting configuration to your MCP host.

## Build the Catalina DeSmuME debug bundle

The hosted workflow builds DeSmuME 0.9.13's documented macOS **dev+** configuration as Intel `x86_64`, with a macOS 10.15 deployment target and an RE-MCP-specific ARM9 GDB autostart hook.

A local builder is also included:

```bash
chmod +x scripts/build-desmume-catalina.sh
./scripts/build-desmume-catalina.sh
```

Output:

```text
.build/desmume-catalina/output/desmume-catalina-debug.zip
.build/desmume-catalina/output/desmume-catalina-debug.zip.sha256
```

Place the extracted bundle under the dedicated RE-MCP workspace. Start it with `desmume_start` using:

```json
{
  "launcher": "private/desmume-catalina/run-desmume-debug.command",
  "rom": "private/Bakugan.nds",
  "mode": "macos-cocoa",
  "arm9GdbPort": 20000
}
```

The launcher passes the selected port through `RE_MCP_ARM9_GDB_PORT`; the patched dev+ application starts its ARM9 GDB stub automatically.

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

## Launcher contracts

Linux:

```bash
run-desmume-debug.sh --arm9gdb=20000 /path/to/game.nds
```

Catalina:

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
