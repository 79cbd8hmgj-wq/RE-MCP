# RE-MCP

A safety-first Model Context Protocol server for ROM reverse-engineering workflows.

The first release targets local **stdio** use and wraps allowlisted repository and verification operations without exposing an unrestricted shell.

## Current tools

- `server_capabilities` — reports the active safety boundary.
- `get_project_status` — runs read-only `git status` inside one allowed project.
- `run_project_verification` — runs one allowlisted npm script: `test`, `typecheck`, `build`, or `check`.

ROM rebuilding, emulator control, and debugger tools will be added only after their path, process-ownership, timeout, and evidence contracts are tested.

## Requirements

- Node.js 20 or newer
- Projects stored as direct children of one dedicated workspace directory
- An MCP host capable of launching local stdio servers

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
- Read-only Git operation in the initial release
- Verification scripts limited to explicit npm script names

Do not point the server at your general home directory. Use a dedicated workspace containing only repositories and private ROM-development inputs intended for this server.
