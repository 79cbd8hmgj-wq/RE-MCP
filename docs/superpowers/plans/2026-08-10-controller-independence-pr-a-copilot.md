# Controller Independence 1.0 — PR A Copilot Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a reproducible GitHub Copilot Agent → RE-MCP workspace integration for VS Code while preserving RE-MCP's provider-independent deterministic trust boundary.

**Architecture:** Add only controller-facing configuration, instructions, package acceptance, and documentation. VS Code launches the existing stdio server directly from `dist/index.js`; no Copilot SDK, wrapper process, or ROM-engine behavior is introduced. CI validates configuration shape and safety properties but explicitly does not claim a real Copilot/VS Code GUI session ran.

**Tech Stack:** VS Code MCP workspace configuration, GitHub Copilot repository instructions, Node.js 20 ESM package smoke scripts, Node test runner + TypeScript/tsx, GitHub Actions.

## Global Constraints

- Do not change production ROM analysis, debugger, mutation, rebuild, or verification semantics.
- Keep the source ROM immutable and preserve RE-MCP's existing controlled mutation path.
- Do not add a generic raw ROM writer, arbitrary offset writer, caller-selected output path, or controller-specific mutation path.
- Do not commit API keys, GitHub credentials, ROM paths, user-home absolute paths, or machine-specific Ghidra paths.
- Workspace MCP configuration must launch the existing stdio server with `node` and `${workspaceFolder}/dist/index.js`.
- `RE_MCP_WORKSPACE_ROOT` must come from an explicit VS Code input variable rather than a checked-in private path.
- CI/package acceptance must not claim physical VS Code/Copilot execution or physical DeSmuME acceptance.

---

### Task 1: Workspace MCP and Copilot instruction contract

**Files:**
- Create: `tests/copilot-controller-integration.test.ts`
- Create: `.vscode/mcp.json`
- Create: `.github/copilot-instructions.md`

**Interfaces:**
- Consumes: existing `node dist/index.js` stdio entry point and `RE_MCP_WORKSPACE_ROOT` environment contract.
- Produces: workspace MCP server named `re-mcp`; repository-wide Copilot evidence/safety instructions.

- [ ] **Step 1: Write the failing contract tests**

Create `tests/copilot-controller-integration.test.ts` with tests that load repository text/JSON and assert:

```ts
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const root = process.cwd();

async function readText(relative: string): Promise<string> {
  return readFile(path.join(root, relative), "utf8");
}

test("VS Code Copilot workspace config launches only the RE-MCP stdio server", async () => {
  const config = JSON.parse(await readText(".vscode/mcp.json")) as {
    servers?: Record<string, { type?: string; command?: string; args?: string[]; env?: Record<string, string> }>;
    inputs?: Array<{ id?: string; type?: string; description?: string; password?: boolean }>;
  };
  assert.deepEqual(Object.keys(config.servers ?? {}), ["re-mcp"]);
  assert.equal(config.servers?.["re-mcp"]?.type, "stdio");
  assert.equal(config.servers?.["re-mcp"]?.command, "node");
  assert.deepEqual(config.servers?.["re-mcp"]?.args, ["${workspaceFolder}/dist/index.js"]);
  assert.equal(config.servers?.["re-mcp"]?.env?.RE_MCP_WORKSPACE_ROOT, "${input:reMcpWorkspaceRoot}");
  assert.equal(config.inputs?.[0]?.id, "reMcpWorkspaceRoot");
  assert.equal(config.inputs?.[0]?.type, "promptString");
  assert.equal(config.inputs?.[0]?.password, false);
});

test("Copilot instructions preserve the deterministic RE-MCP trust boundary", async () => {
  const instructions = await readText(".github/copilot-instructions.md");
  for (const required of [
    "RE-MCP owns truth and deterministic execution",
    "Never modify the source ROM",
    "canonical NDS",
    "compressed overlay",
    "nds_mutation_validate",
    "nds_mutation_verify",
    "Physical DeSmuME",
    "genuine blocker",
  ]) {
    assert.match(instructions, new RegExp(required.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&"), "i"));
  }
});
```

Add a third test that serializes `.vscode/mcp.json` and rejects strings matching `sk-`, `ghp_`, `/Users/`, `/home/`, `.nds`, `RE_MCP_GHIDRA_HOME`, or output-path configuration.

- [ ] **Step 2: Run the tests and verify RED**

Run:

```bash
npm test -- --test-name-pattern='Copilot|workspace config'
```

Expected: FAIL because `.vscode/mcp.json` and `.github/copilot-instructions.md` do not exist.

- [ ] **Step 3: Add the minimal safe VS Code MCP configuration**

Create `.vscode/mcp.json` exactly in the current VS Code workspace format:

```json
{
  "servers": {
    "re-mcp": {
      "type": "stdio",
      "command": "node",
      "args": ["${workspaceFolder}/dist/index.js"],
      "env": {
        "RE_MCP_WORKSPACE_ROOT": "${input:reMcpWorkspaceRoot}"
      }
    }
  },
  "inputs": [
    {
      "id": "reMcpWorkspaceRoot",
      "type": "promptString",
      "description": "Absolute path to the dedicated RE-MCP ROM-modding workspace",
      "password": false
    }
  ]
}
```

- [ ] **Step 4: Add repository-wide Copilot instructions**

Create `.github/copilot-instructions.md` with direct rules covering:

```md
# RE-MCP Copilot Controller Instructions

RE-MCP owns truth and deterministic execution. GitHub Copilot is a disposable reasoning/controller layer.

- Use RE-MCP tools to measure ROM facts instead of guessing them.
- Never modify the source ROM. Use only RE-MCP's guarded mutation/build surface for modifications.
- Prefer canonical NDS components/selectors and proven runtime mappings over arbitrary raw offsets.
- Treat compressed overlay stored bytes and decoded runtime images as distinct identities.
- Do not call a hypothesis confirmed until deterministic RE-MCP evidence supports it.
- Run `nds_mutation_validate` before mutation builds and require `nds_mutation_verify`/fresh verification evidence before declaring a patch complete.
- Treat Physical DeSmuME/emulator execution as a separate real-machine acceptance gate.
- Diagnose ordinary tool errors and continue safely; stop only for a genuine blocker.
- Never bypass guards, fabricate tool output, invent runtime state, or create an alternate ROM writer.
```

- [ ] **Step 5: Run focused and full tests**

Run:

```bash
npm test -- --test-name-pattern='Copilot|workspace config'
npm run check
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add tests/copilot-controller-integration.test.ts .vscode/mcp.json .github/copilot-instructions.md
git commit -m "feat: add Copilot RE-MCP workspace integration"
```

---

### Task 2: Package acceptance for the controller integration

**Files:**
- Modify: `tests/copilot-controller-integration.test.ts`
- Create: `scripts/check-copilot-mcp-install.mjs`
- Modify: `.github/workflows/package.yml`

**Interfaces:**
- Consumes: `.vscode/mcp.json`, `.github/copilot-instructions.md`, assembled `dist/index.js`.
- Produces: deterministic package smoke command that validates the assembled downloadable bundle's Copilot controller surface.

- [ ] **Step 1: Extend the source contract test to demand package wiring**

Add a test that reads `.github/workflows/package.yml` and requires all of:

```ts
assert.match(workflow, /cp -R \.vscode/);
assert.match(workflow, /cp -R \.github\/copilot-instructions\.md/);
assert.match(workflow, /check-copilot-mcp-install\.mjs/);
```

Also require `scripts/check-copilot-mcp-install.mjs` to exist.

- [ ] **Step 2: Run focused test and verify RED**

Run:

```bash
npm test -- --test-name-pattern='package.*Copilot|Copilot.*package'
```

Expected: FAIL because the smoke script and package workflow wiring do not yet exist.

- [ ] **Step 3: Implement `scripts/check-copilot-mcp-install.mjs`**

The script must:

```js
import { access, readFile } from "node:fs/promises";
import path from "node:path";

const root = path.resolve(process.argv[2] ?? process.cwd());
const mcpPath = path.join(root, ".vscode", "mcp.json");
const instructionsPath = path.join(root, ".github", "copilot-instructions.md");
await access(path.join(root, "dist", "index.js"));
await access(mcpPath);
await access(instructionsPath);

const configText = await readFile(mcpPath, "utf8");
const config = JSON.parse(configText);
const server = config.servers?.["re-mcp"];
if (Object.keys(config.servers ?? {}).join(",") !== "re-mcp") throw new Error("Expected exactly one packaged re-mcp MCP server");
if (server?.type !== "stdio" || server?.command !== "node") throw new Error("Packaged re-mcp server must use node stdio");
if (JSON.stringify(server.args) !== JSON.stringify(["${workspaceFolder}/dist/index.js"])) throw new Error("Packaged re-mcp server path is not workspace-relative");
if (server.env?.RE_MCP_WORKSPACE_ROOT !== "${input:reMcpWorkspaceRoot}") throw new Error("Packaged workspace root must use the VS Code input");
const input = config.inputs?.find((entry) => entry.id === "reMcpWorkspaceRoot");
if (input?.type !== "promptString" || input.password !== false) throw new Error("Packaged workspace-root input contract is invalid");
for (const forbidden of [/sk-[A-Za-z0-9]/i, /ghp_[A-Za-z0-9]/i, /\/Users\//, /\/home\//, /\.nds\b/i, /RE_MCP_GHIDRA_HOME/, /outputPath/i]) {
  if (forbidden.test(configText)) throw new Error(`Unsafe packaged MCP configuration matched ${forbidden}`);
}
const instructions = await readFile(instructionsPath, "utf8");
for (const required of ["RE-MCP owns truth and deterministic execution", "Never modify the source ROM", "nds_mutation_validate", "nds_mutation_verify", "Physical DeSmuME", "genuine blocker"]) {
  if (!instructions.toLowerCase().includes(required.toLowerCase())) throw new Error(`Missing Copilot controller instruction: ${required}`);
}
console.log("GitHub Copilot RE-MCP package smoke passed");
```

- [ ] **Step 4: Wire the assembled bundle**

Update `.github/workflows/package.yml` so assembly copies `.vscode/` and `.github/copilot-instructions.md` into the temporary bundle and invokes:

```bash
node scripts/check-copilot-mcp-install.mjs .
```

after the existing install/Ghidra/mutation package checks.

- [ ] **Step 5: Run source verification**

Run:

```bash
npm run check
npm run build
node scripts/check-copilot-mcp-install.mjs .
```

Expected: PASS and print `GitHub Copilot RE-MCP package smoke passed`.

- [ ] **Step 6: Commit**

```bash
git add tests/copilot-controller-integration.test.ts scripts/check-copilot-mcp-install.mjs .github/workflows/package.yml
git commit -m "test: add Copilot package acceptance"
```

---

### Task 3: Reproducible Copilot Agent setup documentation

**Files:**
- Modify: `tests/copilot-controller-integration.test.ts`
- Modify: `README.md`

**Interfaces:**
- Consumes: shipped `.vscode/mcp.json` and Copilot instructions.
- Produces: human setup flow that does not overclaim CI/native acceptance.

- [ ] **Step 1: Add RED documentation assertions**

Extend `tests/copilot-controller-integration.test.ts` to require README text containing:

```ts
for (const phrase of [
  "GitHub Copilot Agent",
  ".vscode/mcp.json",
  "npm run build",
  "reMcpWorkspaceRoot",
  "Configure Tools",
  "trust",
  "not part of RE-MCP's trust boundary",
  "does not prove a native VS Code/Copilot session",
]) {
  assert.match(readme, new RegExp(phrase.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&"), "i"));
}
```

- [ ] **Step 2: Run focused test and verify RED**

Run:

```bash
npm test -- --test-name-pattern='Copilot.*README|README.*Copilot'
```

Expected: FAIL because the dedicated setup section is absent.

- [ ] **Step 3: Add README section**

Add a concise `GitHub Copilot Agent controller` section near MCP setup/package usage explaining:

1. `npm install && npm run build`;
2. open the RE-MCP repository in VS Code with GitHub Copilot enabled;
3. start/trust the workspace `re-mcp` MCP server defined in `.vscode/mcp.json`;
4. enter the absolute dedicated ROM-modding workspace when prompted for `reMcpWorkspaceRoot`;
5. in Agent chat choose **Configure Tools** and enable the RE-MCP tools needed for the task;
6. verify `.github/copilot-instructions.md` appears in Copilot references when repository instructions are used;
7. explain optional Ghidra remains machine-specific and can be configured outside the committed workspace config;
8. state that Copilot is a controller convenience layer and is not part of RE-MCP's trust boundary;
9. state package CI validates configuration and shipped files but does not prove a native VS Code/Copilot session or physical DeSmuME execution.

Keep `mcp-config.example.json` documented for non-VS-Code MCP clients.

- [ ] **Step 4: Run complete verification**

Run:

```bash
npm run check
npm run build
node scripts/check-copilot-mcp-install.mjs .
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/copilot-controller-integration.test.ts README.md
git commit -m "docs: add Copilot Agent controller setup"
```

---

### Task 4: Exact-head PR acceptance

**Files:**
- Review all PR A changed files.

**Interfaces:**
- Consumes: completed Tasks 1-3.
- Produces: reviewable PR with exact-head automated evidence.

- [ ] **Step 1: Review the full diff for scope and safety**

Confirm no production `src/` files changed and no configuration contains secrets, ROM paths, machine-specific paths, arbitrary output paths, or alternate write behavior.

- [ ] **Step 2: Run final local/source checks**

```bash
npm run check
npm run build
node scripts/check-copilot-mcp-install.mjs .
```

Expected: PASS.

- [ ] **Step 3: Open PR A**

Title:

```text
Controller Independence PR A: add GitHub Copilot integration
```

PR body must include scope, safety boundary, exact head SHA, test count/results, package status, and explicit statement that native VS Code/Copilot and physical DeSmuME acceptance remain separate.

- [ ] **Step 4: Wait for exact-head GitHub Actions**

Require CI and Package success on the current head. Any later commit invalidates prior exact-head evidence.

- [ ] **Step 5: Review threads and final diff**

Resolve real blockers, rerun exact-head checks after fixes, and leave the PR open for merge unless the user has separately authorized merging completed PRs.
