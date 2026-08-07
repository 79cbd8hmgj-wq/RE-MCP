# NDS Ghidra Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add controlled Ghidra 12.x bootstrap/status tools that create one analyst-safe local project per full NDS ROM SHA-256, import canonical ARM9/ARM7 and uncompressed overlays, seed RE-MCP-proven entry/direct-call evidence before normal auto-analysis, and never expose arbitrary Ghidra or shell execution.

**Architecture:** Build a deterministic bridge from the canonical NDS map plus bounded ARM9/ARM7 proven-function discovery, then invoke only a validated `support/analyzeHeadless` with RE-MCP-owned Java scripts. Replaceable bridge inputs stay under `analysis/generated/nds/<sha-prefix>/ghidra-bridge/`; persistent Ghidra project/state stays under `analysis/ghidra/nds/<full-sha256>/`. Java emits a result into the generated bridge; Node validates it before updating persistent run-state sidecars.

**Tech Stack:** Node.js 20+, TypeScript 5.7, MCP SDK, Zod, existing Capstone.js ARM backend, existing `runProcess()` wrapper, Ghidra 12.x headless Java scripting, GitHub Actions.

## Global Constraints

- Ghidra compatibility target: official 12.x; reference acceptance release is **12.1.2**.
- Official acceptance asset: `ghidra_12.1.2_PUBLIC_20260605.zip` from tag `Ghidra_12.1.2_build`.
- Official published SHA-256: `b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d`.
- ARM9 language: exactly `ARM:LE:32:v5t`.
- ARM7 language: exactly `ARM:LE:32:v4t`.
- Persistent project identity uses the **full** ROM SHA-256.
- Compressed overlays are never imported as executable runtime bytes.
- RE-MCP proves entries only; it never fabricates function-body/end ranges.
- Normal Ghidra auto-analysis runs after RE-MCP evidence import, but remains non-authoritative to RE-MCP.
- Reruns preserve analyst labels, comments, bookmarks, types, namespaces, function names/signatures, and Ghidra-only discoveries.
- `RE_MCP_GHIDRA_HOME` is optional at startup.
- `RE_MCP_GHIDRA_TIMEOUT_MS` default: `900000`; maximum: `3600000` per headless invocation.
- Ghidra stdout/stderr uses `RE_MCP_MAX_OUTPUT_BYTES`; overflow terminates the process.
- Source ROM SHA is checked before bridge generation, immediately before Ghidra execution, and after bootstrap.
- Normal CI must not download/require Ghidra; real-Ghidra acceptance is `workflow_dispatch` only.
- No DeSmuME/GDB production behavior changes.

---

## File map

### Create
- `src/services/nds/ghidra-model.ts` — manifest/status types, stable names, deterministic paths, sorting.
- `src/services/nds/ghidra-bridge.ts` — transactional bridge generation/validation and fixed bounded discovery.
- `src/services/nds/ghidra-installation.ts` — `GHIDRA_HOME`, version, executable, language validation.
- `src/services/nds/ghidra-runner.ts` — RE-MCP script-path resolver, exact import/process argv builders, bounded execution.
- `src/services/nds/ghidra-project.ts` — bootstrap/reconciliation orchestration and non-mutating status.
- `src/tools/nds-ghidra.ts` — `nds_ghidra_bootstrap`, `nds_ghidra_status`.
- `resources/ghidra/ReMcpPrepareProgram.java`
- `resources/ghidra/ReMcpImportEvidence.java`
- `resources/ghidra/ReMcpRecordAnalysis.java`
- `tests/nds-ghidra-model.test.ts`
- `tests/nds-ghidra-bridge.test.ts`
- `tests/nds-ghidra-installation.test.ts`
- `tests/nds-ghidra-runner.test.ts`
- `tests/nds-ghidra-project.test.ts`
- `tests/nds-ghidra-tools.test.ts`
- `tests/nds-ghidra-resources.test.ts`
- `scripts/ghidra-acceptance.mjs`
- `.github/workflows/ghidra-integration.yml`

### Modify
- `src/config.ts`
- `src/services/process-runner.ts`
- `src/services/nds/errors.ts`
- `src/index.ts`
- `scripts/check-install.mjs`
- `.github/workflows/package.yml`
- `mcp-config.example.json`
- `README.md`

---

### Task 1: Add bounded Ghidra configuration and kill-on-output-limit process support

**Files:**
- Modify: `src/config.ts`
- Modify: `src/services/process-runner.ts`
- Test: `tests/config.test.ts`
- Test: `tests/process-runner.test.ts`

**Interfaces:**

```ts
export interface ServerConfig {
  readonly workspaceRoot: string;
  readonly commandTimeoutMs: number;
  readonly maxOutputBytes: number;
  readonly ghidraHome: string | null;
  readonly ghidraTimeoutMs: number;
}

export interface RunRequest {
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
  readonly terminateOnOutputLimit?: boolean;
}

export interface RunResult {
  readonly exitCode: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
  readonly outputTruncated: boolean;
  readonly outputLimitExceeded: boolean;
}
```

- [ ] **Step 1: Write failing config tests**

```ts
const base = loadConfig({ RE_MCP_WORKSPACE_ROOT: "/tmp/work" });
assert.equal(base.ghidraHome, null);
assert.equal(base.ghidraTimeoutMs, 900_000);

const max = loadConfig({
  RE_MCP_WORKSPACE_ROOT: "/tmp/work",
  RE_MCP_GHIDRA_HOME: "/opt/ghidra_12.1.2_PUBLIC",
  RE_MCP_GHIDRA_TIMEOUT_MS: "3600000",
});
assert.equal(max.ghidraTimeoutMs, 3_600_000);

assert.throws(() => loadConfig({
  RE_MCP_WORKSPACE_ROOT: "/tmp/work",
  RE_MCP_GHIDRA_TIMEOUT_MS: "3600001",
}), /RE_MCP_GHIDRA_TIMEOUT_MS must be between 1 and 3600000/);
```

- [ ] **Step 2: Run focused config tests; verify FAIL**

```bash
npm test -- --test-name-pattern="Ghidra config"
```

- [ ] **Step 3: Implement config parsing**

Add `DEFAULT_GHIDRA_TIMEOUT_MS = 900_000`, `MAX_GHIDRA_TIMEOUT_MS = 3_600_000`, a bounded-positive-int helper, optional resolved `ghidraHome`, and bounded `ghidraTimeoutMs`.

- [ ] **Step 4: Write failing process-runner overflow test**

```ts
const result = await runProcess({
  executable: process.execPath,
  args: ["-e", "process.stdout.write('x'.repeat(1024)); setInterval(() => {}, 1000)"],
  cwd: process.cwd(),
  timeoutMs: 5_000,
  maxOutputBytes: 64,
  terminateOnOutputLimit: true,
});
assert.equal(result.outputLimitExceeded, true);
assert.equal(result.stdout.length, 64);
assert.equal(result.timedOut, false);
```

- [ ] **Step 5: Run focused process test; verify FAIL**

```bash
npm test -- --test-name-pattern="output limit"
```

- [ ] **Step 6: Implement opt-in termination**

On first overflow, set `outputLimitExceeded = true`; if `terminateOnOutputLimit === true`, send `SIGTERM` once and schedule the existing 2-second `SIGKILL` fallback. Existing callers retain prior truncate-only behavior by default.

- [ ] **Step 7: Verify**

```bash
npm test -- --test-name-pattern="Ghidra config|output limit"
npm run typecheck
```

- [ ] **Step 8: Commit**

```bash
git add src/config.ts src/services/process-runner.ts tests/config.test.ts tests/process-runner.test.ts
git commit -m "feat: add bounded Ghidra process configuration"
```

---

### Task 2: Define deterministic bridge/project model

**Files:**
- Create: `src/services/nds/ghidra-model.ts`
- Create: `tests/nds-ghidra-model.test.ts`

**Produces:**

```ts
export const GHIDRA_BRIDGE_FORMAT = "re-mcp-nds-ghidra" as const;
export const GHIDRA_BRIDGE_FORMAT_VERSION = 1 as const;
export const GHIDRA_ARM9_LANGUAGE = "ARM:LE:32:v5t" as const;
export const GHIDRA_ARM7_LANGUAGE = "ARM:LE:32:v4t" as const;

export function ghidraGeneratedBridgeRoot(map: NdsRomMap, workspaceRoot: string): string;
export function ghidraPersistentRoot(map: NdsRomMap, workspaceRoot: string): string;
export function ghidraProjectRoot(map: NdsRomMap, workspaceRoot: string): string;
export function ghidraStateRoot(map: NdsRomMap, workspaceRoot: string): string;
export function ghidraProjectName(map: NdsRomMap): string;
export function ghidraProgramName(processor: NdsProcessor): "RE-MCP_ARM9" | "RE-MCP_ARM7";
export function ghidraOverlaySpaceName(processor: NdsProcessor, overlayId: number): string;
export function buildGhidraBridgeManifest(input: {
  readonly map: NdsRomMap;
  readonly arm9: DiscoverNdsFunctionsResult;
  readonly arm7: DiscoverNdsFunctionsResult;
  readonly artifacts: readonly GhidraBridgeArtifact[];
}): GhidraBridgeManifest;
```

- [ ] **Step 1: Write failing path/name tests**

Assert persistent root contains the full SHA; two fake SHAs with the same first 16 chars produce different persistent roots; program/overlay names are exact and stable.

- [ ] **Step 2: Run; verify FAIL**

```bash
npm test -- --test-name-pattern="Ghidra bridge model"
```

- [ ] **Step 3: Implement constants, types, paths, comparators**

Use `resolveInside()` for all roots. Canonical sort: ARM9 before ARM7, overlays ascending ID, functions/proofs/calls via existing canonical comparators.

- [ ] **Step 4: Write failing manifest tests**

Require each overlay record to use exactly one status:

```ts
"importable" | "not-imported-compressed"
```

and preserve BSS/file-backed distinctions plus discovery `complete|partial-coverage|truncated` metadata.

- [ ] **Step 5: Implement pure manifest transformation**

Do not perform I/O or infer function ends.

- [ ] **Step 6: Verify and commit**

```bash
npm test -- --test-name-pattern="Ghidra bridge model"
npm run typecheck
git add src/services/nds/ghidra-model.ts tests/nds-ghidra-model.test.ts
git commit -m "feat: define deterministic Ghidra bridge model"
```

---

### Task 3: Generate and validate bridge bundle transactionally

**Files:**
- Create: `src/services/nds/ghidra-bridge.ts`
- Create: `tests/nds-ghidra-bridge.test.ts`
- Modify: `src/services/nds/errors.ts`

**Produces:**

```ts
export interface GeneratedGhidraBridge {
  readonly bridgeRoot: string;
  readonly manifestPath: string;
  readonly manifestSha256: string;
  readonly manifest: GhidraBridgeManifest;
}

export async function generateNdsGhidraBridge(
  map: NdsRomMap,
  workspaceRoot: string,
): Promise<GeneratedGhidraBridge>;

export async function validateGeneratedGhidraBridge(
  bridge: GeneratedGhidraBridge,
): Promise<void>;
```

Fixed discovery policy:

```ts
const GHIDRA_DISCOVERY_LIMITS: FunctionDiscoveryLimits = {
  maxComponents: 32,
  maxFunctions: 128,
  maxCallSites: 512,
  maxTotalBlocks: 512,
  maxTotalInstructions: 4096,
  maxTotalBytes: 32768,
  maxTotalEdges: 2048,
  perFunctionCfg: {
    maxBlocks: 64,
    maxInstructions: 512,
    maxBytes: 2048,
    maxEdges: 128,
  },
};
```

ARM9/ARM7 request:

```ts
{ scope: { kind: "all-executable-components" }, seeds: [] }
```

- [ ] **Step 1: Write failing generator test**

Using existing synthetic NDS fixture style, require static bundle refresh, ARM9/ARM7 discovery, `manifest.json`, `evidence/functions.json`, `evidence/calls.json`, `results/` directory, copied Java scripts, deterministic hashes, and compressed-overlay omission metadata.

- [ ] **Step 2: Run; verify FAIL**

```bash
npm test -- --test-name-pattern="Ghidra bridge generation"
```

- [ ] **Step 3: Add error categories**

```ts
export type NdsGhidraErrorCategory =
  | "ghidra-not-configured"
  | "invalid-ghidra-installation"
  | "unsupported-ghidra-version"
  | "ghidra-language-unavailable"
  | "ghidra-project-locked"
  | "bridge-generation-failed"
  | "ghidra-import-failed"
  | "ghidra-analysis-failed"
  | "ghidra-analysis-timeout"
  | "ghidra-output-limit"
  | "project-state-mismatch";
```

Add to `AnyNdsErrorCategory`.

- [ ] **Step 4: Implement generation**

Call `extractNdsAnalysisBundle()`, then one Capstone backend for bounded ARM9 and ARM7 discovery; close it in `finally`. Build the bridge in a temporary sibling and atomically promote only `ghidra-bridge/`. Reuse static-bundle binaries by relative reference rather than duplicating executable bytes.

- [ ] **Step 5: Write failing integrity tests**

ROM mutation during discovery → `invalid-rom`, no promoted bridge. Tampered evidence file after generation → `validateGeneratedGhidraBridge()` throws `bridge-generation-failed`.

- [ ] **Step 6: Implement SHA checks and artifact validation**

`manifestSha256` is the hash of exact `manifest.json` bytes; do not embed that hash recursively inside the manifest itself.

- [ ] **Step 7: Verify and commit**

```bash
npm test -- --test-name-pattern="Ghidra bridge|function discovery|analysis bundle"
npm run typecheck
git add src/services/nds/ghidra-bridge.ts src/services/nds/errors.ts tests/nds-ghidra-bridge.test.ts
git commit -m "feat: generate validated NDS Ghidra bridge bundles"
```

---

### Task 4: Validate Ghidra installation and build exact headless invocations

**Files:**
- Create: `src/services/nds/ghidra-installation.ts`
- Create: `src/services/nds/ghidra-runner.ts`
- Create: `tests/nds-ghidra-installation.test.ts`
- Create: `tests/nds-ghidra-runner.test.ts`

**Produces:**

```ts
export interface ValidatedGhidraInstallation {
  readonly home: string;
  readonly analyzeHeadless: string;
  readonly version: string;
}

export function resolveReMcpGhidraScriptPath(): string;

export async function validateGhidraInstallation(
  config: ServerConfig,
): Promise<ValidatedGhidraInstallation>;

export interface GhidraInvocation {
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly stage: "arm9-import" | "arm9-process" | "arm7-import" | "arm7-process";
}

export function buildGhidraImportInvocation(...): GhidraInvocation;
export function buildGhidraProcessInvocation(...): GhidraInvocation;
export async function runGhidraInvocation(
  invocation: GhidraInvocation,
  config: ServerConfig,
): Promise<RunResult>;
```

- [ ] **Step 1: Write failing installation tests with fake tree**

Fixture:

```text
<tmp>/ghidra_12.1.2_PUBLIC/
├── support/analyzeHeadless
├── Ghidra/application.properties
└── Ghidra/Processors/ARM/data/languages/ARM.ldefs
```

`application.properties`: `application.version=12.1.2`. Require both exact language IDs. Cover missing config/executable, version 11.x, missing language.

- [ ] **Step 2: Run; verify FAIL**

```bash
npm test -- --test-name-pattern="Ghidra installation"
```

- [ ] **Step 3: Implement installation validation**

Derive all Ghidra paths beneath `ghidraHome` with `resolveInside()`. Accept `/^12\./`. Require exact v5t/v4t language IDs.

- [ ] **Step 4: Implement RE-MCP script-path resolver with failing test first**

Use module-relative path, not cwd or `GHIDRA_HOME`:

```ts
export function resolveReMcpGhidraScriptPath(): string {
  return fileURLToPath(new URL("../../../resources/ghidra/", import.meta.url));
}
```

This resolves correctly from both `src/services/nds/*.ts` under tsx and packaged `dist/services/nds/*.js` because `resources/` is at package root.

- [ ] **Step 5: Write failing argv tests**

Initial ARM9 semantic sequence must contain:

```text
<project-root> RE-MCP-<full-sha>
-import <generated-root>/arm9.bin
-loader BinaryLoader
-processor ARM:LE:32:v5t
-loader-baseAddr 0x<ram-base>
-scriptPath <RE-MCP resources/ghidra>
-preScript ReMcpPrepareProgram.java <manifest> arm9
-preScript ReMcpImportEvidence.java <manifest> arm9
-postScript ReMcpRecordAnalysis.java <manifest> arm9 <generated-results-file>
```

ARM7 uses v4t. Existing programs use `-process RE-MCP_ARM9`/`RE-MCP_ARM7` and never `-overwrite`.

- [ ] **Step 6: Implement argv builders**

No caller-provided executable, script path, loader, language, project name/path, raw args, or environment.

- [ ] **Step 7: Write failing runner error tests**

Fake executable fixtures cover timeout → `ghidra-analysis-timeout`, output overflow → `ghidra-output-limit`, import nonzero → `ghidra-import-failed`, process nonzero → `ghidra-analysis-failed`, known project-lock stderr → `ghidra-project-locked`.

- [ ] **Step 8: Implement bounded execution**

```ts
await runProcess({
  executable: invocation.executable,
  args: invocation.args,
  cwd: invocation.cwd,
  timeoutMs: config.ghidraTimeoutMs,
  maxOutputBytes: config.maxOutputBytes,
  terminateOnOutputLimit: true,
});
```

- [ ] **Step 9: Verify and commit**

```bash
npm test -- --test-name-pattern="Ghidra installation|Ghidra invocation|Ghidra runner"
npm run typecheck
git add src/services/nds/ghidra-installation.ts src/services/nds/ghidra-runner.ts tests/nds-ghidra-installation.test.ts tests/nds-ghidra-runner.test.ts
git commit -m "feat: add controlled Ghidra headless runner"
```

---

### Task 5: Implement analyst-safe Ghidra scripts

**Files:**
- Create: `resources/ghidra/ReMcpPrepareProgram.java`
- Create: `resources/ghidra/ReMcpImportEvidence.java`
- Create: `resources/ghidra/ReMcpRecordAnalysis.java`
- Create: `tests/nds-ghidra-resources.test.ts`

**Owned Program Information keys:**

```text
re-mcp.bridge-format
re-mcp.rom-sha256
re-mcp.manifest-sha256
re-mcp.processor
re-mcp.last-import
re-mcp.last-analysis-status
re-mcp.ghidra-version
```

**Owned address property maps:**

```text
re-mcp.function-id
re-mcp.function-proof
re-mcp.function-mode
re-mcp.overlay-id
re-mcp.call-evidence
```

- [ ] **Step 1: Write failing resource-contract tests**

Load Java sources as text and require all owned keys; forbid destructive analyst operations such as `clearListing`, `removeFunction`, `removeSymbol`, and removal of non-RE-MCP memory. Require overlay creation and manifest/processor argument validation.

- [ ] **Step 2: Run; verify FAIL**

```bash
npm test -- --test-name-pattern="Ghidra resource contract"
```

- [ ] **Step 3: Implement `ReMcpPrepareProgram.java`**

It must parse manifest + processor, validate program language/ROM SHA/processor metadata, confirm main-base identity, create/reconcile uncompressed overlay blocks with `overlay=true`, create only canonical uninitialized BSS where safe, tag overlay starts, skip compressed overlays, and establish ARM/Thumb context only at exact RE-MCP-proven entries.

Deterministic overlay names:

```text
RE_MCP_ARM9_OVL_<id>
RE_MCP_ARM7_OVL_<id>
```

No function body is created by guessed range.

- [ ] **Step 4: Implement `ReMcpImportEvidence.java`**

Create/reuse RE-MCP property maps, resolve main addresses in default space and overlay entries in named overlay spaces, attach function ID/proof/mode, and add exact direct-call references only when manifest caller+target identities are exact. Do not delete/rename analyst objects.

- [ ] **Step 5: Implement `ReMcpRecordAnalysis.java`**

Accept only `<manifest> <processor> <result-json-path>`. Validate that result path matches the manifest-declared generated `results/<processor>.json` location. Write deterministic result JSON containing ROM SHA, manifest SHA, processor, program name, analysis status `complete`, Ghidra version, overlay/evidence counts.

Persistent `analysis/ghidra/.../state/` files are **not** written by Java; Node writes them only after validating this generated result.

- [ ] **Step 6: Strengthen resource tests**

Require result-path validation, exact overlay-name templates, exact owned property names, and no forbidden destructive APIs.

- [ ] **Step 7: Verify and commit**

```bash
npm test -- --test-name-pattern="Ghidra resource contract"
git add resources/ghidra tests/nds-ghidra-resources.test.ts
git commit -m "feat: add RE-MCP Ghidra reconciliation scripts"
```

---

### Task 6: Orchestrate project bootstrap, reconciliation, and status

**Files:**
- Create: `src/services/nds/ghidra-project.ts`
- Create: `tests/nds-ghidra-project.test.ts`

**Produces:**

```ts
export interface NdsGhidraBootstrapResult {
  readonly sourceRomSha256: string;
  readonly projectPath: string;
  readonly ghidraVersion: string;
  readonly manifestSha256: string;
  readonly runKind: "initial" | "reconciled" | "already-current";
  readonly processors: readonly GhidraProcessorBootstrapResult[];
  readonly evidenceCoverage: readonly GhidraEvidenceCoverage[];
}

export interface NdsGhidraStatusResult {
  readonly sourceRomSha256: string;
  readonly projectPath: string;
  readonly projectExists: boolean;
  readonly bridgeExists: boolean;
  readonly manifestSha256: string | null;
  readonly ghidraVersion: string | null;
  readonly processors: readonly GhidraProcessorStatus[];
  readonly lastFailure: GhidraFailureSidecar | null;
}

export async function bootstrapNdsGhidraProject(
  romPath: string,
  config: ServerConfig,
): Promise<NdsGhidraBootstrapResult>;

export async function readNdsGhidraStatus(
  romPath: string,
  config: ServerConfig,
): Promise<NdsGhidraStatusResult>;
```

- [ ] **Step 1: Write failing initial-bootstrap test with injected deps**

Internal deps:

```ts
interface GhidraProjectDeps {
  readonly validateInstallation: typeof validateGhidraInstallation;
  readonly generateBridge: typeof generateNdsGhidraBridge;
  readonly runInvocation: typeof runGhidraInvocation;
}
```

Assert ARM9 import then ARM7 import, each generated result is validated, persistent state is written only after validation, and final run is `initial`.

- [ ] **Step 2: Run; verify FAIL**

```bash
npm test -- --test-name-pattern="Ghidra project bootstrap"
```

- [ ] **Step 3: Implement first-run state machine**

Before Ghidra, Node writes `state/latest-run.json` with stage `starting`. After each processor, validate generated result against full ROM SHA, manifest SHA, processor, program name, and expected counts. Only then update persistent success state.

- [ ] **Step 4: Write failing rerun/mismatch tests**

Cover:
1. matching prior identity → `-process`, not `-import`/`-overwrite`;
2. newer manifest, same ROM → reconcile through `-process`;
3. project exists without matching RE-MCP state → `project-state-mismatch`;
4. stored state points to another full SHA → `project-state-mismatch`;
5. ARM9 succeeds, ARM7 fails → preserve project, record `latest-failure.json`;
6. analyst marker fixture survives rerun.

- [ ] **Step 5: Implement rerun rules**

Never infer owned program existence solely from directory existence. Require matching RE-MCP state. Never delete project on failed reconciliation.

- [ ] **Step 6: Write failing non-mutating status tests**

Assert status parses ROM identity and deterministic bridge/state files but never calls installation validation, bridge generation, `runProcess`, or Ghidra.

- [ ] **Step 7: Implement status**

Missing project is a normal status result, not an error.

- [ ] **Step 8: Add ROM-race tests**

Mutation after bridge generation/before execution and mutation after Ghidra/before final return both → `invalid-rom`, no success claim.

- [ ] **Step 9: Verify and commit**

```bash
npm test -- --test-name-pattern="Ghidra project|Ghidra status"
npm run typecheck
git add src/services/nds/ghidra-project.ts tests/nds-ghidra-project.test.ts
git commit -m "feat: orchestrate analyst-safe Ghidra projects"
```

---

### Task 7: Register exactly two bounded MCP tools

**Files:**
- Create: `src/tools/nds-ghidra.ts`
- Create: `tests/nds-ghidra-tools.test.ts`
- Modify: `src/index.ts`

**Public schemas:**

```ts
{ rom: z.string().min(1) }
```

for both `nds_ghidra_bootstrap` and `nds_ghidra_status`.

- [ ] **Step 1: Write failing tool-registration/schema tests**

Require exactly the two names and no schema fields for executable, projectPath, processor, language, loader, args, env, scriptPath, or outputPath.

- [ ] **Step 2: Run; verify FAIL**

```bash
npm test -- --test-name-pattern="Ghidra MCP tools"
```

- [ ] **Step 3: Implement `registerNdsGhidraTools()`**

Resolve ROM inside workspace, call project service, bound serialized output under `maxOutputBytes`, and map all Ghidra categories to corrective actions.

Example:

```ts
case "ghidra-not-configured":
  return "Set RE_MCP_GHIDRA_HOME to a supported local Ghidra 12.x installation and restart RE-MCP.";
case "ghidra-project-locked":
  return "Close the SHA-scoped project in other Ghidra processes, then retry without deleting the project.";
case "project-state-mismatch":
  return "Inspect the SHA-scoped RE-MCP state; RE-MCP will not overwrite unrecognized analyst project state.";
```

- [ ] **Step 4: Register in `src/index.ts`**

Add import + `registerNdsGhidraTools(server, config)`, both tool names in capabilities, and policy text describing optional SHA-scoped analyst-preserving Ghidra bootstrap with non-authoritative Ghidra inference.

- [ ] **Step 5: Add output-bound/error tests**

- [ ] **Step 6: Verify and commit**

```bash
npm test -- --test-name-pattern="Ghidra MCP tools|server capabilities"
npm run typecheck
npm run build
git add src/tools/nds-ghidra.ts src/index.ts tests/nds-ghidra-tools.test.ts
git commit -m "feat: expose controlled NDS Ghidra tools"
```

---

### Task 8: Package resources and update user-facing documentation

**Files:**
- Modify: `scripts/check-install.mjs`
- Modify: `.github/workflows/package.yml`
- Modify: `mcp-config.example.json`
- Modify: `README.md`

- [ ] **Step 1: Add failing package-resource checks**

Require:

```text
resources/ghidra/ReMcpPrepareProgram.java
resources/ghidra/ReMcpImportEvidence.java
resources/ghidra/ReMcpRecordAnalysis.java
```

and compiled Ghidra tool registration.

- [ ] **Step 2: Run package check; verify failure before packaging update**

```bash
npm run build
node scripts/check-install.mjs .
```

- [ ] **Step 3: Update package workflow**

Add:

```bash
cp -R resources "$root/"
```

before production install/self-check.

- [ ] **Step 4: Update example config**

```json
{
  "RE_MCP_WORKSPACE_ROOT": "/ABSOLUTE/PATH/TO/rom-modding",
  "RE_MCP_GHIDRA_HOME": "/ABSOLUTE/PATH/TO/ghidra_12.1.2_PUBLIC",
  "RE_MCP_GHIDRA_TIMEOUT_MS": "900000"
}
```

README must say Ghidra settings are optional unless these two tools are used.

- [ ] **Step 5: Document trust/lifecycle semantics**

Document full-SHA project layout, v5t/v4t, true uncompressed overlay spaces, compressed omission, proven-entry-not-body semantics, non-authoritative auto-analysis, analyst-work preservation, no generic Ghidra tool, non-mutating status, and separation from Catalina debugger acceptance.

- [ ] **Step 6: Verify and commit**

```bash
npm run check
npm run build
node scripts/check-install.mjs .
git add scripts/check-install.mjs .github/workflows/package.yml mcp-config.example.json README.md
git commit -m "docs: package and document Ghidra integration"
```

---

### Task 9: Add manual real-Ghidra 12.1.2 acceptance

**Files:**
- Create: `scripts/ghidra-acceptance.mjs`
- Create: `.github/workflows/ghidra-integration.yml`

**Pinned release:**

```text
Tag: Ghidra_12.1.2_build
Asset: ghidra_12.1.2_PUBLIC_20260605.zip
URL: https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip
SHA-256: b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d
Java: JDK 21
```

- [ ] **Step 1: Implement deterministic acceptance script with fixture assertions**

CLI:

```text
node scripts/ghidra-acceptance.mjs <workspace-root> <rom-relative-path>
```

Generate/use a synthetic NDS containing ARM9 main direct call, ARM7 main, two uncompressed overlays sharing a runtime base, one compressed overlay record, and an exact Thumb target. No private ROM.

Verify project/state paths, processor language metadata, distinct overlay spaces, compressed omission, ARM/Thumb entry evidence, no bridge body/end claim, successful auto-analysis, second-run non-destructive reconciliation, and preservation of a deterministic analyst marker inserted between runs.

- [ ] **Step 2: Create `workflow_dispatch`-only workflow**

```yaml
name: Ghidra Integration Acceptance
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  ghidra:
    runs-on: ubuntu-24.04
    timeout-minutes: 30
```

Use `actions/setup-java@v4` with Java 21. Download exactly the pinned URL, verify exact SHA with `sha256sum -c`, then unzip.

- [ ] **Step 3: Execute source verification + real acceptance**

```bash
npm install
npm run check
npm run build
RE_MCP_WORKSPACE_ROOT="$RUNNER_TEMP/work" \
RE_MCP_GHIDRA_HOME="$RUNNER_TEMP/ghidra_12.1.2_PUBLIC" \
RE_MCP_GHIDRA_TIMEOUT_MS=900000 \
node scripts/ghidra-acceptance.mjs "$RUNNER_TEMP/work" fixture.nds
```

- [ ] **Step 4: Commit**

```bash
git add scripts/ghidra-acceptance.mjs .github/workflows/ghidra-integration.yml
git commit -m "ci: add manual Ghidra 12.1.2 acceptance"
```

---

### Task 10: Final verification and PR readiness

**Files:**
- Modify only files required by verified failures.

- [ ] **Step 1: Run full normal verification**

```bash
npm run check
npm run build
```

- [ ] **Step 2: Mirror packaged-bundle assembly locally**

```bash
version="$(node -p "require('./package.json').version")"
root="/tmp/re-mcp-${version}"
rm -rf "$root"
mkdir -p "$root/dist"
cp package.json README.md mcp-config.example.json "$root/"
cp -R scripts resources "$root/"
cp -R dist/src/. "$root/dist/"
(
  cd "$root"
  npm install --omit=dev --ignore-scripts
  node scripts/check-install.mjs .
)
```

- [ ] **Step 3: Run targeted safety regressions**

```bash
npm test -- --test-name-pattern="Ghidra|process runner|NDS function|analysis bundle|DeSmuME"
```

- [ ] **Step 4: Diff-scope review**

Confirm no generic shell/Ghidra tool, arbitrary command args/path surface, compressed-overlay decode, Ghidra-to-RE-MCP promotion, function-body proof, ROM mutation, or debugger extension.

- [ ] **Step 5: Commit verified fixes only if needed**

```bash
git add <files actually changed by fixes>
git commit -m "fix: close Ghidra integration verification gaps"
```

Do not create an empty commit.

- [ ] **Step 6: Open PR against `main`**

Title:

```text
Add controlled NDS Ghidra integration
```

PR body must report SHA-scoped lifecycle, v5t/v4t programs, true overlays, compressed omissions, proven-entry-only semantics, analyst preservation, bounded `analyzeHeadless`, normal CI/package results, manual 12.1.2 acceptance status, and unchanged Catalina/DeSmuME gate.

**Do not merge without explicit user approval.**
