# RE-MCP

A safety-first Model Context Protocol server for ROM reverse-engineering workflows.

The server targets local **stdio** use and wraps allowlisted repository, verification, ROM-analysis, and emulator operations without exposing an unrestricted shell.

## Current tools

### General

- `server_capabilities`
- `get_project_status`
- `run_project_verification`
- `verify_file_sha256`

### Bakugan

- `bakugan_run_quality_suite`
- `bakugan_regenerate_m6e_contracts`
- `bakugan_install_m6e_dry_run`
- `bakugan_analyze_m6e_roster`

### DeSmuME

- `desmume_status`
- `desmume_start`
- `desmume_stop`

The DeSmuME launcher follows the verified Bakugan debug-bundle contract:

```bash
run-desmume-debug.sh --arm9gdb=20000 /path/to/game.nds
```

RE-MCP owns at most one emulator child process per server instance. It reports that process's PID and bounded logs, rejects duplicate starts, and stops only that owned child. The emulator is terminated during MCP shutdown.

Save-state loading, screenshots, GDB commands, register access, and memory operations remain unavailable until separate contracts are implemented and tested.

## Requirements

- Node.js 20 or newer
- Projects and private ROM-development inputs stored below one dedicated workspace directory
- An MCP host capable of launching local stdio servers
- For emulator tools, the extracted Linux DeSmuME debug bundle

## Install and build

```bash
npm install
npm run check
npm run build
```

## Run

```bash
RE_MCP_WORKSPACE_ROOT=/absolute/path/to/rom-modding \
node dist/index.js
```

The server refuses to start without an explicit workspace root.

## Example MCP host configuration

```json
{
  "mcpServers": {
    "re-mcp": {
      "command": "node",
      "args": ["/absolute/path/to/RE-MCP/dist/index.js"],
      "env": {
        "RE_MCP_WORKSPACE_ROOT": "/absolute/path/to/rom-modding"
      }
    }
  }
}
```

## Security model

- No arbitrary shell tool
- No shell interpolation
- Fixed executable and argument construction
- Workspace path containment
- Narrow project-name validation
- Process timeouts and bounded output
- Minimal child-process environment
- Read-only Git operation
- Milestone 6E installation restricted to dry-run mode
- One server-owned DeSmuME process
- No attachment to unrelated or pre-existing emulator processes

Do not point the server at your general home directory. Use a dedicated workspace containing only repositories and private ROM-development inputs intended for this server.
