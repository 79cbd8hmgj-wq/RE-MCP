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
- Derive the main ARM9 executable range from the NDS ROM header before launch
- Maintain an allowlist of the main ARM9 range plus up to 64 explicit or overlay executable ranges
- Add, remove, and list controlled ARM9 software breakpoints
- Continue execution, wait for a stop, interrupt/pause, and single-step up to 100 instructions
- Decode DeSmuME ARM9 registers into `r0`-`r12`, `sp`, `lr`, `pc`, and `cpsr`
- Capture structured stop context with bounded PC, stack, and optional memory windows
- Match breakpoint hits, track hit counts, and retain ARM/Thumb execution history
- Atomically capture raw registers plus labeled memory regions
- Reset debugger state automatically when the owned emulator exits or its process generation changes

RE-MCP does **not** expose register writes, general memory writes, watchpoints, or an arbitrary GDB-command tool.

## Dynamic-debugging tools

The controlled debugger surface consists of nine MCP tools:

- `desmume_breakpoint_add`
- `desmume_breakpoint_remove`
- `desmume_breakpoint_list`
- `desmume_continue`
- `desmume_step_instruction`
- `desmume_pause`
- `desmume_wait_for_stop`
- `desmume_capture_stop_context`
- `desmume_executable_ranges_replace`

The existing `desmume_read_register_packet`, `desmume_read_memory`, `desmume_probe_gdb`, and `desmume_wait_for_gdb` tools share the same owned debugger session rather than opening a competing GDB connection.

### Dynamic-debugging limits

- GDB host is fixed to `127.0.0.1` and the ARM9 port recorded for the current owned DeSmuME process.
- At most 32 active breakpoints are allowed.
- Breakpoints must resolve inside the main ARM9 executable range or an explicitly allowlisted executable range.
- ARM breakpoints must be 4-byte aligned; Thumb breakpoints must be 2-byte aligned.
- `auto` execution mode fails when ARM versus Thumb remains ambiguous.
- Continue and stop-wait requests are bounded to at most 30000 ms.
- Single-step requests allow 1 through 100 instructions, with a bounded wait for every step.
- Stop context captures 64 bytes around PC and up to 64 bytes from SP, clamped at address-space boundaries.
- A stop-context request may add at most eight labeled regions, each from 1 through 4096 bytes.
- Additional executable ranges are capped at 64.
- Stop-context output is bounded by the configured `maxOutputBytes` value.
- Emulator exit, explicit stop, or a new process generation invalidates the old debugger session and session-scoped state.

### Example debugger workflow

1. Call `desmume_start` with a verified launcher, the intended `.nds` ROM, and an ARM9 GDB port. RE-MCP parses the ROM header before launch and initializes the debugger with the derived main ARM9 range.
2. Use `desmume_wait_for_gdb` or `desmume_probe_gdb` to confirm the owned stub is reachable.
3. Add a validated breakpoint with `desmume_breakpoint_add`. Specify `arm` or `thumb` when mode is not already unambiguous.
4. Call `desmume_continue`, optionally supplying `expectedBreakpointId`. Context capture is enabled by default.
5. Inspect the returned stop reason, decoded `pc`/`cpsr`, matched breakpoint, hit count, and bounded memory windows.
6. Use `desmume_step_instruction` for a bounded instruction sequence while stopped.
7. If execution is running after a timeout, use `desmume_wait_for_stop` or `desmume_pause` rather than issuing a stopped-state command.
8. Remove the breakpoint with `desmume_breakpoint_remove` when finished.
9. Call `desmume_stop` or restart the emulator. Session-scoped breakpoints, executable ranges, stop state, and the old GDB connection are invalidated.

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

### Catalina dynamic-debugging acceptance

Automated CI verifies packet framing, breakpoint lifecycle, execution state, timeout behavior, register decoding, context capture, lifecycle reset, and MCP validation. Final acceptance still requires the verified native DeSmuME bundle on the target Intel macOS Catalina system.

Follow [`docs/dynamic-debugging-catalina-acceptance.md`](docs/dynamic-debugging-catalina-acceptance.md) to verify breakpoint installation, continue/stop, PC and CPSR capture, single stepping, pause, breakpoint removal, and debugger-state reset after emulator restart.

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

The Catalina-native bundle uses:

```bash
run-desmume-debug.command /path/to/game.nds 20000
```

RE-MCP owns at most one emulator child process per server instance. It rejects duplicate starts, captures bounded logs, resets session-scoped debugger state when that process exits, and terminates the owned emulator during MCP shutdown.

## Security model

- No arbitrary shell tool
- No shell interpolation
- Fixed executable and argument construction
- Workspace path containment
- Process timeouts and bounded output
- Minimal child-process environment
- Milestone 6E installation restricted to dry-run mode
- One server-owned DeSmuME process
- GDB restricted to the owned localhost ARM9 port
- Breakpoints restricted to validated executable ranges
- Maximum 32 active breakpoints and 100 instructions per single-step request
- Bounded continue, wait, pause, register, memory, and stop-context operations
- Controlled GDB packets only: software breakpoint insert/remove, continue, single-step, interrupt, register read, bounded memory read, and stop-status query
- No arbitrary GDB packet tool
- No register writes, general memory writes, or watchpoints
- Runtime evidence restricted to project `analysis/generated`
- Debugger session, breakpoint registry, executable ranges, and stop state reset with emulator lifecycle
- No attachment to unrelated emulator processes

Do not use your general home directory as `RE_MCP_WORKSPACE_ROOT`. Create a dedicated directory containing only the repositories and private inputs intended for RE-MCP.
