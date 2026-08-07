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
- Persistent project identity uses the full ROM SHA-256.
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
- `src/services/nds/ghidra-installation.ts` — Ghidra-home/version/executable/language validation.
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

### Task 1: Add bounded Ghidra configuration and output-limit termination

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

```ts
const DEFAULT_GHIDRA_TIMEOUT_MS = 900_000;
const MAX_GHIDRA_TIMEOUT_MS = 3_600_000;

function boundedPositiveInteger(
  value: string | undefined,
  fallback: number,
  maximum: number,
  name: string,
): number {
  const parsed = positiveInteger(value, fallback, name);
  if (parsed > maximum) {
    throw new Error(`${name} must be between 1 and ${maximum}`);
  }
  return parsed;
}
```

Return:

```ts
ghidraHome: environment.RE_MCP_GHIDRA_HOME?.trim()
  ? path.resolve(environment.RE_MCP_GHIDRA_HOME)
  : null,
ghidraTimeoutMs: boundedPositiveInteger(
  environment.RE_MCP_GHIDRA_TIMEOUT_MS,
  DEFAULT_GHIDRA_TIMEOUT_MS,
  MAX_GHIDRA_TIMEOUT_MS,
  "RE_MCP_GHIDRA_TIMEOUT_MS",
),
```

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

- [ ] **Step 6: Implement opt-in output termination**

Use a single termination helper so timeout and output overflow cannot schedule repeated kills:

```ts
let terminationStarted = false;
const terminate = () => {
  if (terminationStarted) return;
  terminationStarted = true;
  child.kill("SIGTERM");
  setTimeout(() => child.kill("SIGKILL"), 2_000).unref();
};
```

Inside the append path:

```ts
if (chunk.length > remaining || current.length >= request.maxOutputBytes) {
  outputTruncated = true;
  outputLimitExceeded = true;
  if (request.terminateOnOutputLimit === true) terminate();
}
```

Timeout sets `timedOut = true` then calls `terminate()`.

- [ ] **Step 7: Verify and commit**

```bash
npm test -- --test-name-pattern="Ghidra config|output limit"
npm run typecheck
git add src/config.ts src/services/process-runner.ts tests/config.test.ts tests/process-runner.test.ts
git commit -m "feat: add bounded Ghidra process configuration"
```

---

### Task 2: Define deterministic bridge/project identities

**Files:**
- Create: `src/services/nds/ghidra-model.ts`
- Create: `tests/nds-ghidra-model.test.ts`

**Interfaces:**

```ts
export const GHIDRA_BRIDGE_FORMAT = "re-mcp-nds-ghidra" as const;
export const GHIDRA_BRIDGE_FORMAT_VERSION = 1 as const;
export const GHIDRA_ARM9_LANGUAGE = "ARM:LE:32:v5t" as const;
export const GHIDRA_ARM7_LANGUAGE = "ARM:LE:32:v4t" as const;

export interface GhidraBridgeArtifact {
  readonly path: string;
  readonly sha256: string;
  readonly size: number;
}

export interface GhidraBridgeManifest {
  readonly format: typeof GHIDRA_BRIDGE_FORMAT;
  readonly formatVersion: typeof GHIDRA_BRIDGE_FORMAT_VERSION;
  readonly sourceRomSha256: string;
  readonly sha256Prefix: string;
  readonly processors: readonly GhidraProcessorManifest[];
  readonly discovery: readonly GhidraDiscoveryManifest[];
  readonly artifacts: readonly GhidraBridgeArtifact[];
  readonly generatedResultPaths: Readonly<Record<NdsProcessor, string>>;
}

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

```ts
assert.equal(ghidraProjectName(map), `RE-MCP-${map.sha256}`);
assert.equal(ghidraProgramName("arm9"), "RE-MCP_ARM9");
assert.equal(ghidraProgramName("arm7"), "RE-MCP_ARM7");
assert.equal(ghidraOverlaySpaceName("arm9", 7), "RE_MCP_ARM9_OVL_7");
assert.match(ghidraPersistentRoot(map, root), new RegExp(`${map.sha256.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`));
```

Create two maps with identical first 16 SHA hex characters and distinct full SHA values; assert persistent roots differ.

- [ ] **Step 2: Run; verify FAIL**

```bash
npm test -- --test-name-pattern="Ghidra bridge model"
```

- [ ] **Step 3: Implement path/name helpers**

```ts
export function ghidraGeneratedBridgeRoot(map: NdsRomMap, workspaceRoot: string): string {
  return resolveInside(workspaceRoot, path.join("analysis", "generated", "nds", map.sha256Prefix, "ghidra-bridge"));
}

export function ghidraPersistentRoot(map: NdsRomMap, workspaceRoot: string): string {
  return resolveInside(workspaceRoot, path.join("analysis", "ghidra", "nds", map.sha256));
}

export function ghidraProjectRoot(map: NdsRomMap, workspaceRoot: string): string {
  return resolveInside(ghidraPersistentRoot(map, workspaceRoot), "project");
}

export function ghidraStateRoot(map: NdsRomMap, workspaceRoot: string): string {
  return resolveInside(ghidraPersistentRoot(map, workspaceRoot), "state");
}
```

- [ ] **Step 4: Write failing manifest tests**

Require overlay import status to be exactly:

```ts
type GhidraOverlayImportStatus = "importable" | "not-imported-compressed";
```

Assert BSS/file-backed distinctions, deterministic processor/overlay/function/call ordering, and discovery `complete|partial-coverage|truncated` metadata are retained.

- [ ] **Step 5: Implement pure manifest transformation**

Core mapping must select language without guessing:

```ts
const language = processor === "arm9" ? GHIDRA_ARM9_LANGUAGE : GHIDRA_ARM7_LANGUAGE;
const overlays = sourceOverlays
  .slice()
  .sort((a, b) => a.overlayId - b.overlayId)
  .map((overlay) => ({
    processor,
    overlayId: overlay.overlayId,
    runtimeAddress: overlay.ramAddress,
    ramSize: overlay.ramSize,
    bssSize: overlay.bssSize,
    fileId: overlay.fileId,
    compressed: overlay.compressed,
    importStatus: overlay.compressed ? "not-imported-compressed" : "importable",
  }));
```

Do not add a function end/body field.

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

**Interfaces:**

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

Fixed discovery limits:

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

- [ ] **Step 1: Write failing bridge-generation test**

Require `manifest.json`, `evidence/functions.json`, `evidence/calls.json`, `results/`, copied Java scripts, deterministic hashes, ARM9/ARM7 discovery, and compressed-overlay omission metadata.

- [ ] **Step 2: Run; verify FAIL**

```bash
npm test -- --test-name-pattern="Ghidra bridge generation"
```

- [ ] **Step 3: Add canonical Ghidra error categories**

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

Add `NdsGhidraErrorCategory` to `AnyNdsErrorCategory`.

- [ ] **Step 4: Implement bounded discovery and bridge generation**

```ts
await extractNdsAnalysisBundle(map, workspaceRoot);
const backend = await createCapstoneArmBackend();
try {
  const arm9 = await discoverNdsFunctions(map, {
    processor: "arm9",
    scope: { kind: "all-executable-components" },
    seeds: [],
  }, GHIDRA_DISCOVERY_LIMITS, backend);
  const arm7 = await discoverNdsFunctions(map, {
    processor: "arm7",
    scope: { kind: "all-executable-components" },
    seeds: [],
  }, GHIDRA_DISCOVERY_LIMITS, backend);
  await buildAndPromoteBridge({ map, workspaceRoot, arm9, arm7 });
} finally {
  backend.close();
}
```

`buildAndPromoteBridge` must create a temporary sibling, write/fsync/hash evidence/scripts/manifest, then rename to final `ghidra-bridge`. Refer to existing static-bundle binaries/overlays by deterministic relative paths; do not duplicate them.

- [ ] **Step 5: Write failing integrity tests**

ROM mutation during discovery must throw `invalid-rom` and leave no promoted bridge. Tamper with `functions.json`, then require `validateGeneratedGhidraBridge()` to throw `bridge-generation-failed`.

- [ ] **Step 6: Implement artifact validation**

```ts
for (const artifact of bridge.manifest.artifacts) {
  const absolute = resolveInside(bridge.bridgeRoot, artifact.path);
  const actual = await hashFileSha256(absolute);
  if (actual !== artifact.sha256) {
    throw new NdsError("bridge-generation-failed", `Ghidra bridge artifact hash mismatch: ${artifact.path}`);
  }
}
```

Hash exact `manifest.json` bytes after writing; do not place `manifestSha256` inside the manifest itself.

- [ ] **Step 7: Verify and commit**

```bash
npm test -- --test-name-pattern="Ghidra bridge|function discovery|analysis bundle"
npm run typecheck
git add src/services/nds/ghidra-bridge.ts src/services/nds/errors.ts tests/nds-ghidra-bridge.test.ts
git commit -m "feat: generate validated NDS Ghidra bridge bundles"
```

---

### Task 4: Validate Ghidra installation and construct exact headless invocations

**Files:**
- Create: `src/services/nds/ghidra-installation.ts`
- Create: `src/services/nds/ghidra-runner.ts`
- Create: `tests/nds-ghidra-installation.test.ts`
- Create: `tests/nds-ghidra-runner.test.ts`

**Interfaces:**

```ts
export interface ValidatedGhidraInstallation {
  readonly home: string;
  readonly analyzeHeadless: string;
  readonly version: string;
}

export interface GhidraInvocationInput {
  readonly installation: ValidatedGhidraInstallation;
  readonly map: NdsRomMap;
  readonly bridge: GeneratedGhidraBridge;
  readonly processor: NdsProcessor;
}

export interface GhidraInvocation {
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly stage: "arm9-import" | "arm9-process" | "arm7-import" | "arm7-process";
}

export function resolveReMcpGhidraScriptPath(): string;
export async function validateGhidraInstallation(config: ServerConfig): Promise<ValidatedGhidraInstallation>;
export function buildGhidraImportInvocation(input: GhidraInvocationInput): GhidraInvocation;
export function buildGhidraProcessInvocation(input: GhidraInvocationInput): GhidraInvocation;
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

Use `application.version=12.1.2`; require exact v5t/v4t IDs. Cover missing config/executable, 11.x, missing language.

- [ ] **Step 2: Run; verify FAIL**

```bash
npm test -- --test-name-pattern="Ghidra installation"
```

- [ ] **Step 3: Implement installation validation**

```ts
if (config.ghidraHome === null) {
  throw new NdsError("ghidra-not-configured", "RE_MCP_GHIDRA_HOME is not configured");
}
const executable = resolveInside(config.ghidraHome, path.join("support", "analyzeHeadless"));
const properties = resolveInside(config.ghidraHome, path.join("Ghidra", "application.properties"));
const ldefs = resolveInside(config.ghidraHome, path.join("Ghidra", "Processors", "ARM", "data", "languages", "ARM.ldefs"));
```

Parse `application.version`; reject unless `/^12\./`. Require exact `id="ARM:LE:32:v5t"` and `id="ARM:LE:32:v4t"` in `ARM.ldefs`.

- [ ] **Step 4: Write failing RE-MCP script-path test, then implement resolver**

```ts
export function resolveReMcpGhidraScriptPath(): string {
  return fileURLToPath(new URL("../../../resources/ghidra/", import.meta.url));
}
```

Assert it resolves under repository/package root, not under Ghidra home or cwd.

- [ ] **Step 5: Write failing argv tests**

Initial ARM9 expected semantic sequence:

```text
<project-root> RE-MCP-<full-sha>
-import <generated-root>/arm9.bin
-loader BinaryLoader
-processor ARM:LE:32:v5t
-loader-baseAddr 0x<arm9-ram-base>
-scriptPath <RE-MCP-resources-ghidra>
-preScript ReMcpPrepareProgram.java <manifest> arm9
-preScript ReMcpImportEvidence.java <manifest> arm9
-postScript ReMcpRecordAnalysis.java <manifest> arm9 <generated-arm9-result>
```

ARM7 must use v4t. Existing programs use `-process RE-MCP_ARM9`/`RE-MCP_ARM7` and never `-overwrite`.

- [ ] **Step 6: Implement argv builders**

```ts
function languageFor(processor: NdsProcessor): string {
  return processor === "arm9" ? GHIDRA_ARM9_LANGUAGE : GHIDRA_ARM7_LANGUAGE;
}
function addressHex(value: number): string {
  return `0x${value.toString(16)}`;
}
```

Build arguments only from canonical map/bridge/install values. No caller-supplied command surface.

- [ ] **Step 7: Write failing runner-error tests**

Fake executable cases: timeout → `ghidra-analysis-timeout`; overflow → `ghidra-output-limit`; import nonzero → `ghidra-import-failed`; process nonzero → `ghidra-analysis-failed`; project-lock stderr fixture → `ghidra-project-locked`.

- [ ] **Step 8: Implement bounded execution**

```ts
const result = await runProcess({
  executable: invocation.executable,
  args: invocation.args,
  cwd: invocation.cwd,
  timeoutMs: config.ghidraTimeoutMs,
  maxOutputBytes: config.maxOutputBytes,
  terminateOnOutputLimit: true,
});
if (result.timedOut) throw new NdsError("ghidra-analysis-timeout", `${invocation.stage} timed out`);
if (result.outputLimitExceeded) throw new NdsError("ghidra-output-limit", `${invocation.stage} exceeded RE_MCP_MAX_OUTPUT_BYTES`);
```

Then classify lock/nonzero stage failures.

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

**Owned keys:**

```text
Program Information:
re-mcp.bridge-format
re-mcp.rom-sha256
re-mcp.manifest-sha256
re-mcp.processor
re-mcp.last-import
re-mcp.last-analysis-status
re-mcp.ghidra-version

Address property maps:
re-mcp.function-id
re-mcp.function-proof
re-mcp.function-mode
re-mcp.overlay-id
re-mcp.call-evidence
```

- [ ] **Step 1: Write failing Java resource-contract tests**

```ts
for (const name of ["ReMcpPrepareProgram.java", "ReMcpImportEvidence.java", "ReMcpRecordAnalysis.java"]) {
  const source = await readFile(path.join(resourceRoot, name), "utf8");
  assert.doesNotMatch(source, /clearListing|removeFunction|removeSymbol/);
}
```

Also require every owned key, overlay creation with `overlay=true`, and argument-count checks.

- [ ] **Step 2: Run; verify FAIL**

```bash
npm test -- --test-name-pattern="Ghidra resource contract"
```

- [ ] **Step 3: Implement `ReMcpPrepareProgram.java`**

Core structure:

```java
String[] args = getScriptArgs();
if (args.length != 2) throw new IllegalArgumentException("expected manifest path and processor");
Path manifestPath = Paths.get(args[0]).toAbsolutePath().normalize();
String processor = args[1];
if (!processor.equals("arm9") && !processor.equals("arm7")) throw new IllegalArgumentException("invalid processor");
```

Parse manifest, validate language/ROM SHA/processor metadata, confirm main-base identity, create/reconcile each uncompressed overlay as an initialized overlay memory block, create only canonical uninitialized BSS where non-conflicting, tag overlay starts, skip compressed overlays, and set ARM/Thumb context only at exact proven entries. Never create a guessed function body.

- [ ] **Step 4: Implement `ReMcpImportEvidence.java`**

Use RE-MCP property maps on exact entry addresses/spaces. Core ownership pattern:

```java
PropertyMapManager maps = currentProgram.getUsrPropertyManager();
StringPropertyMap functionIds = maps.getStringPropertyMap("re-mcp.function-id");
if (functionIds == null) functionIds = maps.createStringPropertyMap("re-mcp.function-id");
```

Apply proof/mode/call metadata to exact main/default or named overlay addresses. Add direct-call references only when manifest caller/target identities are exact. Do not delete/rename analyst objects.

- [ ] **Step 5: Implement `ReMcpRecordAnalysis.java`**

```java
String[] args = getScriptArgs();
if (args.length != 3) throw new IllegalArgumentException("expected manifest, processor, result path");
```

Validate result path equals manifest-declared `results/<processor>.json` path. Write deterministic JSON with ROM SHA, manifest SHA, processor, program name, `analysisStatus: "complete"`, Ghidra version, overlay count, proven-entry count, direct-call count. Do not write persistent project state from Java.

- [ ] **Step 6: Strengthen resource tests and commit**

```bash
npm test -- --test-name-pattern="Ghidra resource contract"
git add resources/ghidra tests/nds-ghidra-resources.test.ts
git commit -m "feat: add RE-MCP Ghidra reconciliation scripts"
```

---

### Task 6: Orchestrate analyst-safe project bootstrap and non-mutating status

**Files:**
- Create: `src/services/nds/ghidra-project.ts`
- Create: `tests/nds-ghidra-project.test.ts`

**Interfaces:**

```ts
export interface GhidraProcessorBootstrapResult {
  readonly processor: NdsProcessor;
  readonly programName: string;
  readonly status: "imported" | "reconciled" | "already-current";
  readonly importedOverlays: number;
  readonly compressedOverlayIds: readonly number[];
  readonly provenEntries: number;
  readonly directCalls: number;
  readonly analysisStatus: "complete";
}

export interface NdsGhidraBootstrapResult {
  readonly sourceRomSha256: string;
  readonly projectPath: string;
  readonly ghidraVersion: string;
  readonly manifestSha256: string;
  readonly runKind: "initial" | "reconciled" | "already-current";
  readonly processors: readonly GhidraProcessorBootstrapResult[];
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

- [ ] **Step 1: Write failing first-run orchestration test with injected deps**

```ts
interface GhidraProjectDeps {
  readonly validateInstallation: typeof validateGhidraInstallation;
  readonly generateBridge: typeof generateNdsGhidraBridge;
  readonly runInvocation: typeof runGhidraInvocation;
}
```

Assert ARM9 import then ARM7 import; each generated result is validated before Node writes persistent success state.

- [ ] **Step 2: Run; verify FAIL**

```bash
npm test -- --test-name-pattern="Ghidra project bootstrap"
```

- [ ] **Step 3: Implement first-run state machine**

```ts
await writeStateAtomic(stateRoot, "latest-run.json", {
  format: "re-mcp-nds-ghidra-run-state",
  formatVersion: 1,
  sourceRomSha256: map.sha256,
  manifestSha256: bridge.manifestSha256,
  stage: "starting",
});
```

After each run, parse `results/<processor>.json`; require exact ROM SHA, manifest SHA, processor, program name, and `analysisStatus === "complete"` before writing `latest-success.json`.

- [ ] **Step 4: Write failing rerun/mismatch tests**

Cover matching prior identity → process/no overwrite; newer manifest same ROM → process/reconciled; project without matching RE-MCP state → `project-state-mismatch`; different SHA state → mismatch; ARM7 failure after ARM9 success → preserve project and write `latest-failure.json`.

- [ ] **Step 5: Implement rerun decision**

```ts
const existing = await readExistingState(stateRoot);
if (await projectExists(projectRoot) && existing === null) {
  throw new NdsError("project-state-mismatch", "Existing Ghidra project has no matching RE-MCP state");
}
const initial = !(await projectExists(projectRoot));
const invocation = initial
  ? buildGhidraImportInvocation(input)
  : buildGhidraProcessInvocation(input);
```

Never use `-overwrite` for reconciliation and never delete the project on failure.

- [ ] **Step 6: Write failing non-mutating status tests**

Inject spies that throw if installation validation, bridge generation, or process execution occurs; `readNdsGhidraStatus()` must still succeed from ROM identity + deterministic files.

- [ ] **Step 7: Implement status**

```ts
const map = await readNdsRomMap(romPath);
return {
  sourceRomSha256: map.sha256,
  projectPath: path.relative(config.workspaceRoot, ghidraProjectRoot(map, config.workspaceRoot)),
  projectExists: await exists(ghidraProjectRoot(map, config.workspaceRoot)),
  bridgeExists: await exists(ghidraGeneratedBridgeRoot(map, config.workspaceRoot)),
  ...await readStatusSidecars(map, config.workspaceRoot),
};
```

Missing project is a normal result.

- [ ] **Step 8: Add ROM-race tests**

Mutate source after bridge generation/before Ghidra and after Ghidra/before return; both must throw `invalid-rom` and never write final success.

- [ ] **Step 9: Verify and commit**

```bash
npm test -- --test-name-pattern="Ghidra project|Ghidra status"
npm run typecheck
git add src/services/nds/ghidra-project.ts tests/nds-ghidra-project.test.ts
git commit -m "feat: orchestrate analyst-safe Ghidra projects"
```

---

### Task 7: Expose exactly two bounded MCP tools

**Files:**
- Create: `src/tools/nds-ghidra.ts`
- Create: `tests/nds-ghidra-tools.test.ts`
- Modify: `src/index.ts`

**Public schema for both tools:**

```ts
{ rom: z.string().min(1) }
```

- [ ] **Step 1: Write failing tool registration/schema tests**

Assert only `rom` is accepted; no executable, projectPath, processor, language, loader, args, env, scriptPath, outputPath.

- [ ] **Step 2: Run; verify FAIL**

```bash
npm test -- --test-name-pattern="Ghidra MCP tools"
```

- [ ] **Step 3: Implement `registerNdsGhidraTools()`**

```ts
export function registerNdsGhidraTools(server: McpServer, config: ServerConfig): void {
  server.tool("nds_ghidra_bootstrap", "Create or safely reconcile the SHA-scoped Ghidra project for one canonical NDS ROM.", { rom: z.string().min(1) }, async ({ rom }) => {
    try {
      return boundedTextResult(config, "nds_ghidra_bootstrap", await bootstrapNdsGhidraProject(resolveInside(config.workspaceRoot, rom), config));
    } catch (error) {
      return ghidraErrorResult(config, "nds_ghidra_bootstrap", error);
    }
  });
  server.tool("nds_ghidra_status", "Read SHA-scoped Ghidra bridge/project state without invoking Ghidra or mutating files.", { rom: z.string().min(1) }, async ({ rom }) => {
    try {
      return boundedTextResult(config, "nds_ghidra_status", await readNdsGhidraStatus(resolveInside(config.workspaceRoot, rom), config));
    } catch (error) {
      return ghidraErrorResult(config, "nds_ghidra_status", error);
    }
  });
}
```

Use the existing NDS bounded-result style rather than introducing an unbounded serializer.

- [ ] **Step 4: Implement corrective actions and register in `src/index.ts`**

```ts
case "ghidra-not-configured":
  return "Set RE_MCP_GHIDRA_HOME to a supported local Ghidra 12.x installation and restart RE-MCP.";
case "ghidra-project-locked":
  return "Close the SHA-scoped project in other Ghidra processes, then retry without deleting the project.";
case "project-state-mismatch":
  return "Inspect the SHA-scoped RE-MCP state; RE-MCP will not overwrite unrecognized analyst project state.";
```

Add import/registration, both capability names, and policy text describing optional SHA-scoped analyst-preserving Ghidra bootstrap with non-authoritative Ghidra inference.

- [ ] **Step 5: Write output-bound/error tests**

Use a test config with `maxOutputBytes: 128` and stub bootstrap result containing a diagnostic string larger than 128 bytes; require `category: "output-bound-exceeded"`. Stub a `NdsError("ghidra-not-configured", ...)`; require error result to preserve category and corrective action.

```ts
assert.equal(parsed.category, "output-bound-exceeded");
assert.equal(errorParsed.category, "ghidra-not-configured");
assert.match(errorParsed.correctiveAction, /RE_MCP_GHIDRA_HOME/);
```

- [ ] **Step 6: Verify and commit**

```bash
npm test -- --test-name-pattern="Ghidra MCP tools|server capabilities"
npm run typecheck
npm run build
git add src/tools/nds-ghidra.ts src/index.ts tests/nds-ghidra-tools.test.ts
git commit -m "feat: expose controlled NDS Ghidra tools"
```

---

### Task 8: Package resources and document the integration

**Files:**
- Modify: `scripts/check-install.mjs`
- Modify: `.github/workflows/package.yml`
- Modify: `mcp-config.example.json`
- Modify: `README.md`

- [ ] **Step 1: Add failing package-resource checks**

```js
for (const relative of [
  "resources/ghidra/ReMcpPrepareProgram.java",
  "resources/ghidra/ReMcpImportEvidence.java",
  "resources/ghidra/ReMcpRecordAnalysis.java",
]) {
  await access(path.join(root, relative));
}
```

Also require compiled Ghidra tool registration in the assembled package.

- [ ] **Step 2: Run check before workflow packaging change; verify expected failure in assembled-package simulation**

```bash
npm run build
node scripts/check-install.mjs .
```

When run at repository root the resource check may already pass; the failing assertion must be demonstrated against the current package-workflow assembly that does not yet copy `resources/`.

- [ ] **Step 3: Update package workflow**

```bash
cp -R resources "$root/"
```

Place before production install/self-check.

- [ ] **Step 4: Update example configuration**

```json
{
  "RE_MCP_WORKSPACE_ROOT": "/ABSOLUTE/PATH/TO/rom-modding",
  "RE_MCP_GHIDRA_HOME": "/ABSOLUTE/PATH/TO/ghidra_12.1.2_PUBLIC",
  "RE_MCP_GHIDRA_TIMEOUT_MS": "900000"
}
```

State that Ghidra settings are optional unless the Ghidra tools are used.

- [ ] **Step 5: Update README**

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

- [ ] **Step 1: Implement deterministic acceptance script**

CLI:

```text
node scripts/ghidra-acceptance.mjs <workspace-root> <rom-relative-path>
```

Generate a synthetic NDS with ARM9 main direct call, ARM7 main, two uncompressed overlays sharing a runtime base, one compressed overlay metadata record, and one exact Thumb target. No private ROM.

Core assertions:

```js
assert.equal(status.sourceRomSha256, expectedSha);
assert.equal(status.processors.find((p) => p.processor === "arm9").language, "ARM:LE:32:v5t");
assert.equal(status.processors.find((p) => p.processor === "arm7").language, "ARM:LE:32:v4t");
assert.deepEqual(overlappingOverlayNames.sort(), ["RE_MCP_ARM9_OVL_1", "RE_MCP_ARM9_OVL_2"]);
assert.ok(status.compressedOverlayIds.includes(3));
```

Insert a deterministic analyst marker between first and second bootstrap and assert it remains afterward. Assert bridge evidence has no function-end/body field.

- [ ] **Step 2: Create manual-only workflow**

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
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: '21'
```

Download the pinned URL, verify exact SHA with `sha256sum -c`, then unzip.

- [ ] **Step 3: Execute source verification and real acceptance**

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

- [ ] **Step 2: Mirror package assembly locally**

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

- [ ] **Step 4: Inspect final diff for forbidden scope expansion**

Reject the change if it contains a generic shell/Ghidra tool, arbitrary command args/path surface, compressed-overlay decode, Ghidra-to-RE-MCP evidence promotion, function-body/end proof, ROM mutation, or debugger extension.

- [ ] **Step 5: Commit verification fixes only when needed**

```bash
git status --short
git add -p
git diff --cached --check
git commit -m "fix: close Ghidra integration verification gaps"
```

If `git status --short` is clean, skip the commit.

- [ ] **Step 6: Open PR against `main`**

Title:

```text
Add controlled NDS Ghidra integration
```

PR body reports SHA-scoped lifecycle, v5t/v4t programs, true overlays, compressed omissions, proven-entry-only semantics, analyst preservation, bounded `analyzeHeadless`, normal CI/package results, manual 12.1.2 acceptance status, and unchanged Catalina/DeSmuME gate.

**Do not merge without explicit user approval.**
