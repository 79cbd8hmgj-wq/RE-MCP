# Controller Independence 1.0 — PR A: GitHub Copilot Integration Design

Date: 2026-08-10
Status: approved by the user's standing authorization to implement recommended controller-independence PRs

## Goal

Make GitHub Copilot Agent in VS Code a first-class controller for RE-MCP without coupling RE-MCP's deterministic reverse-engineering or mutation engine to GitHub, Copilot, or any specific model provider.

The controller may reason, select tools, and iterate. RE-MCP remains the authority for ROM facts, guarded mutation, rebuild, verification, and evidence.

## Context

RE-MCP already exposes a stdio MCP server from `dist/index.js` and requires `RE_MCP_WORKSPACE_ROOT`. Optional Ghidra configuration is supplied through environment variables. The repository currently ships a generic `mcp-config.example.json` using the older/common `mcpServers` shape for external MCP clients.

Current VS Code supports workspace MCP configuration in `.vscode/mcp.json` with a top-level `servers` object. GitHub Copilot in VS Code can use MCP tools from Agent mode. Repository-wide Copilot instructions are supported through `.github/copilot-instructions.md`.

## Approaches considered

### A. Workspace-native VS Code/Copilot configuration — selected

Commit a `.vscode/mcp.json` that launches the built RE-MCP server with workspace-safe variable substitution, add repository Copilot instructions, and validate both through source/package acceptance.

Advantages:
- shortest path from VS Code Copilot Agent to RE-MCP;
- configuration is versioned with the project;
- no new runtime dependency or controller service;
- preserves the existing stdio MCP transport;
- easy to inspect and disable.

Trade-off:
- requires a built `dist/index.js` and a valid workspace root on the user's machine.

### B. User-profile-only MCP configuration

Document a user-level VS Code MCP entry and avoid committing `.vscode/mcp.json`.

Advantages:
- no repository-local editor configuration.

Rejected because:
- setup becomes manual and machine-specific;
- package acceptance cannot prove the recommended configuration exists;
- controller setup is harder to reproduce.

### C. Copilot-specific wrapper process

Add a wrapper executable between Copilot and RE-MCP.

Advantages:
- could inject controller-specific policy or telemetry.

Rejected because:
- unnecessary coupling;
- creates another process and failure surface;
- risks duplicating policy that belongs in RE-MCP's deterministic tool boundaries or repository instructions.

## Selected architecture

```text
GitHub Copilot Agent (VS Code)
          |
          | MCP stdio
          v
   node dist/index.js
          |
          v
        RE-MCP
          |
          +-- read-only reverse-engineering tools
          +-- controlled debugger/runtime tools
          +-- guarded mutation/rebuild/verification tools
```

Copilot is disposable. RE-MCP owns truth and deterministic execution.

## Files and responsibilities

### `.vscode/mcp.json`

Provide a workspace-scoped `re-mcp` stdio server entry using `node` and `${workspaceFolder}/dist/index.js`.

The configuration must not contain ROM paths, API keys, Ghidra paths, or user-home absolute paths. It should obtain the RE-MCP workspace root through an input variable so the user explicitly chooses the dedicated ROM-modding workspace when the server starts. Optional Ghidra settings remain outside the committed workspace configuration because they are machine-specific.

### `.github/copilot-instructions.md`

Define controller rules that reinforce, but do not replace, server-side enforcement:

- measure ROM facts with RE-MCP rather than inventing them;
- never claim a hypothesis is confirmed without evidence;
- preserve source ROM immutability;
- prefer canonical NDS selectors/components over raw offsets;
- distinguish stored compressed overlay bytes from decoded runtime images;
- validate before building mutations;
- require verification before calling a patch complete;
- treat physical DeSmuME acceptance as a separate real-machine gate;
- stop only for a genuine blocker, not ordinary tool errors that can be diagnosed safely.

Instructions must not grant capabilities that RE-MCP does not expose.

### `scripts/check-copilot-mcp-install.mjs`

Add deterministic acceptance for the shipped controller integration. The script will:

1. require `.vscode/mcp.json` and `.github/copilot-instructions.md`;
2. parse MCP JSON;
3. require exactly one `re-mcp` workspace server entry;
4. require stdio execution through `node` and the workspace-relative built server path;
5. reject hard-coded secrets, absolute home paths, arbitrary ROM paths, and caller-selected output paths in the config;
6. require a workspace-root input reference rather than a checked-in private path;
7. verify the Copilot instructions contain the core evidence/safety contract;
8. verify `dist/index.js` exists in packaged acceptance.

This is configuration/package acceptance only. It does not claim that GitHub Copilot itself is available in CI or that a native VS Code UI session executed the tools.

### `.github/workflows/package.yml`

Include the controller configuration/instructions in the downloadable bundle and run the Copilot integration smoke check after the existing package checks.

### `README.md`

Document:

- build RE-MCP first;
- open the repository in VS Code with GitHub Copilot enabled;
- trust/start the `re-mcp` MCP server;
- provide a dedicated `RE_MCP_WORKSPACE_ROOT` through the configured input;
- enable RE-MCP tools in Agent mode;
- explain that Copilot is the preferred controller but not part of RE-MCP's trust boundary;
- retain the existing generic client configuration for non-VS-Code MCP clients.

## Error handling and safety

- Missing build: VS Code server launch fails visibly because `dist/index.js` is absent; documentation tells the user to run `npm install && npm run build`.
- Missing workspace root: VS Code prompts through an input variable; RE-MCP still independently fails closed if `RE_MCP_WORKSPACE_ROOT` is missing or invalid.
- Missing Ghidra: optional Ghidra tools retain their existing fail-closed behavior; Copilot integration does not invent a path.
- Tool failures: controller instructions require reading deterministic tool errors/evidence and correcting the next action rather than bypassing guards.
- No secrets are committed.
- No generic write API, raw ROM writer, or controller-specific mutation path is added.

## Acceptance criteria

PR A is complete when:

1. repository and downloadable package contain a valid current VS Code MCP workspace configuration for `re-mcp`;
2. repository-wide Copilot instructions encode the evidence and mutation safety contract;
3. a deterministic test/smoke check rejects unsafe or stale controller configuration;
4. package CI runs that check against the assembled bundle;
5. README contains a reproducible Copilot Agent setup path;
6. existing typecheck/tests/package acceptance remain green;
7. no production RE-MCP ROM logic is changed;
8. CI documentation explicitly avoids claiming physical VS Code/Copilot or DeSmuME acceptance.

## Out of scope

- Continue, LiteLLM, Groq, OpenRouter, or Ollama fallback routing (later PR);
- controller checkpoint/state protocol (later PR);
- model benchmarking (later PR);
- changes to ROM analysis/mutation semantics;
- embedding GitHub authentication or Copilot APIs inside RE-MCP;
- physical GUI automation of VS Code/Copilot in CI.
