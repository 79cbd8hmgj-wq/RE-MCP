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

## Provider-neutral controller checkpoints

RE-MCP keeps controller handoff state for each exact source ROM at the RE-MCP-owned path:

```text
analysis/generated/nds/<sha-prefix>/controller/checkpoint.json
```

The controller never selects another checkpoint output path. The checkpoint is marked `controller-state-only`: it records what a previous controller reported, but it does not turn that prose into authoritative ROM evidence.

When continuing existing ROM work:

1. Call `controller_checkpoint_read` for the ROM before assuming prior investigation state.
2. If no checkpoint exists, the tool returns `expectedRevision: 0` and no file is created.
3. If a checkpoint exists, recover its objective, reported confirmed facts, hypotheses, completed actions, and next actions.
4. Revalidate consequential facts with the relevant deterministic RE-MCP analysis/runtime/verification tools before using them for mutation, rebuild, or another consequential decision.

Before a planned controller handoff:

1. Read the current checkpoint if necessary and keep its latest `expectedRevision`.
2. Write bounded handoff state with `controller_checkpoint_write` and that exact `expectedRevision`.
3. If RE-MCP reports a revision conflict, call `controller_checkpoint_read`, reconcile the newer state, and retry. Do not overwrite or bypass the conflict.
4. The new controller reads the same exact-ROM checkpoint and continues from the recorded objective/state while independently revalidating consequential facts.

This makes a Copilot → Continue handoff, or a later Continue → Copilot handoff, independent of either provider's private conversation history. Do not put chain-of-thought, raw model transcripts, API keys, provider credentials, secrets, or arbitrary metadata into checkpoints.

Evidence references inside checkpoint entries may point only to existing files in the exact source-SHA RE-MCP analysis/output namespaces and are hash-bound when written. That proves which artifact the previous controller referenced; it does not prove that the controller's interpretation of the artifact was correct.

## Controller boundary

RE-MCP owns truth and deterministic execution. Copilot may reason, select tools, and iterate, but it must not bypass RE-MCP guards, fabricate tool output, invent runtime state, or create an alternate ROM writer. The source ROM remains immutable; modifications go only through RE-MCP's guarded mutation/build/verification surface.

Physical DeSmuME/emulator execution remains a separate real-machine acceptance gate. A semantically verified rebuilt ROM or a successful Copilot tool session is not evidence that native emulator execution occurred.

## Acceptance scope

Source and package CI validate the workspace MCP configuration, repository instructions, compiled `dist/index.js`, this guide, and the assembled downloadable bundle. Checkpoint package acceptance also verifies compiled write/read, optimistic revision conflict, controlled path placement, and tamper rejection. That acceptance does not prove a native VS Code/Copilot session executed RE-MCP or that an actual provider-to-provider handoff occurred. It also does not replace the separate Physical DeSmuME acceptance workflow.
