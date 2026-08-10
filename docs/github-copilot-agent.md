# GitHub Copilot Agent controller

GitHub Copilot Agent in VS Code can use RE-MCP directly through the workspace MCP configuration at `.vscode/mcp.json`. Copilot is a controller convenience layer and is not part of RE-MCP's trust boundary; RE-MCP remains responsible for deterministic ROM facts, guarded mutation, rebuild, verification, and evidence.

## Setup

1. Install dependencies and build the server:

   ```bash
   npm install
   npm run build
   ```

2. Open the RE-MCP repository in VS Code with GitHub Copilot enabled.
3. Start and trust the workspace `re-mcp` MCP server defined by `.vscode/mcp.json`.
4. When VS Code prompts for `reMcpWorkspaceRoot`, enter the absolute path to a dedicated RE-MCP ROM-modding workspace. Do not use a general home directory.
5. In GitHub Copilot Agent chat, choose **Configure Tools** and enable the RE-MCP tools needed for the task.
6. Keep `.github/copilot-instructions.md` enabled as repository instructions. Those rules require the controller to measure ROM facts through RE-MCP, preserve source immutability, distinguish compressed stored bytes from decoded runtime images, validate before builds, and require fresh verification before declaring a patch complete.

If Ghidra tools are needed, configure the existing optional Ghidra environment settings outside the committed workspace MCP configuration; those paths are machine-specific. The committed `.vscode/mcp.json` intentionally contains no Ghidra path, ROM path, API key, user-home path, or output path.

`mcp-config.example.json` remains the generic template for non-VS-Code MCP clients.

## Controller boundary

RE-MCP owns truth and deterministic execution. Copilot may reason, select tools, and iterate, but it must not bypass RE-MCP guards, fabricate tool output, invent runtime state, or create an alternate ROM writer. The source ROM remains immutable; modifications go only through RE-MCP's guarded mutation/build/verification surface.

Physical DeSmuME/emulator execution remains a separate real-machine acceptance gate. A semantically verified rebuilt ROM or a successful Copilot tool session is not evidence that native emulator execution occurred.

## Acceptance scope

Source and package CI validate the workspace MCP configuration, repository instructions, compiled `dist/index.js`, this guide, and the assembled downloadable bundle. That acceptance does not prove a native VS Code/Copilot session executed RE-MCP. It also does not replace the separate Physical DeSmuME acceptance workflow.
