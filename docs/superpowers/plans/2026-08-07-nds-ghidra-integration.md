# NDS Ghidra Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a controlled Ghidra 12.x bootstrap/status integration that creates one analyst-safe local project per full NDS ROM SHA-256, imports canonical ARM9/ARM7 and uncompressed overlays, seeds RE-MCP-proven entry/call evidence before normal Ghidra auto-analysis, and never exposes arbitrary Ghidra or shell execution.

**Architecture:** RE-MCP generates a deterministic bridge manifest/evidence bundle from the canonical NDS map plus bounded proven-function discovery, then drives only a server-configured `support/analyzeHeadless` through a narrow runner. Persistent Ghidra state lives under `analysis/ghidra/nds/<full-sha256>/`, while replaceable bridge artifacts remain under `analysis/generated/nds/<sha-prefix>/ghidra-bridge/`. Java scripts reconcile RE-MCP-owned metadata/overlay spaces without treating Ghidra-derived bodies or symbols as proof.

**Tech Stack:** Node.js 20+, TypeScript 5.7, MCP SDK, Zod, existing Capstone.js ARM backend, Node `child_process.spawn` through `runProcess`, Ghidra 12.x headless Java scripting, GitHub Actions.

## Global Constraints

- Initial compatibility target is official Ghidra 12.x; current reference acceptance version is Ghidra 12.1.
- ARM9 language is exactly `ARM:LE:32:v5t`; ARM7 language is exactly `ARM:LE:32:v4t`.
- Persistent project identity uses the full source ROM SHA-256, not only the existing 16-hex SHA prefix.
- Generated bridge inputs live under `analysis/generated/nds/<sha-prefix>/ghidra-bridge/`; persistent Ghidra state lives under `analysis/ghidra/nds/<full-sha256>/`.
- Compressed overlays are never imported as executable bytes in this milestone.
- RE-MCP proves function entries only; it never invents Ghidra function-body/end boundaries.
- Normal Ghidra auto-analysis runs after RE-MCP evidence import, but Ghidra-derived results do not become RE-MCP evidence.
- Reruns preserve analyst labels, comments, bookmarks, types, namespaces, names, signatures, and Ghidra-only discoveries.
- No caller-controlled executable, project path/name, processor language, loader, script path, shell string, raw Ghidra arguments, environment variables, or output path.
- `RE_MCP_GHIDRA_HOME` is optional at server startup; Ghidra tools fail with `ghidra-not-configured` when absent.
- `RE_MCP_GHIDRA_TIMEOUT_MS` defaults to 900,000 ms and is capped at 3,600,000 ms per headless subprocess invocation.
- Ghidra stdout/stderr is bounded by `RE_MCP_MAX_OUTPUT_BYTES`; output overflow terminates the Ghidra subprocess.
- Source ROM SHA-256 is checked before bridge generation, immediately before Ghidra execution, and after the top-level bootstrap.
- Normal CI must not download or require Ghidra. Real-Ghidra acceptance is isolated to a manual workflow.
- No native DeSmuME/GDB production behavior changes in this milestone.

---

## File structure

### Create

- `src/services/nds/ghidra-model.ts` — bridge manifest/evidence/status types, deterministic naming, and validation constants.
- `src/services/nds/ghidra-bridge.ts` — build/validate/promote the deterministic bridge bundle and run bounded ARM9/ARM7 function discovery.
- `src/services/nds/ghidra-installation.ts` — validate `RE_MCP_GHIDRA_HOME`, supported version, executable, and required languages.
- `src/services/nds/ghidra-runner.ts` — construct and execute the allowlisted `analyzeHeadless` invocations.
- `src/services/nds/ghidra-project.ts` — orchestrate bootstrap/reconciliation state and read non-mutating status sidecars.
- `src/tools/nds-ghidra.ts` — register `nds_ghidra_bootstrap` and `nds_ghidra_status`.
- `resources/ghidra/ReMcpPrepareProgram.java` — validate program ownership, create/reconcile uncompressed overlay spaces/BSS context, and establish proven ARM/Thumb entry context.
- `resources/ghidra/ReMcpImportEvidence.java` — import entry/property/direct-call evidence without creating guessed function bodies.
- `resources/ghidra/ReMcpRecordAnalysis.java` — record successful analysis metadata and structured state summary.
- `tests/nds-ghidra-model.test.ts`
- `tests/nds-ghidra-bridge.test.ts`
- `tests/nds-ghidra-installation.test.ts`
- `tests/nds-ghidra-runner.test.ts`
- `tests/nds-ghidra-project.test.ts`
- `tests/nds-ghidra-tools.test.ts`
- `tests/nds-ghidra-resources.test.ts`
- `.github/workflows/ghidra-integration.yml` — manual real-Ghidra acceptance workflow only.

### Modify

- `src/config.ts` — optional Ghidra home and bounded Ghidra timeout.
- `src/services/process-runner.ts` — opt-in termination when output reaches the configured cap.
- `src/services/nds/errors.ts` — Ghidra-specific NDS error categories.
- `src/index.ts` — register the two Ghidra tools and update capabilities.
- `scripts/check-install.mjs` — verify packaged Ghidra resources and compiled registration.
- `.github/workflows/package.yml` — copy `resources/` into the downloadable bundle.
- `mcp-config.example.json` — document optional Ghidra configuration.
- `README.md` — document bootstrap/status behavior, safety boundary, paths, Ghidra requirements, and manual acceptance.

---

### Task 1: Add Ghidra configuration and output-limit termination support

**Files:**
- Modify: `src/config.ts`
- Modify: `src/services/process-runner.ts`
- Test: `tests/config.test.ts`
- Test: `tests/process-runner.test.ts`

**Interfaces:**
- Consumes: existing `loadConfig()` and `runProcess()` call sites.
- Produces:
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

- [ ] **Step 1: Write failing config tests for absent/default/bounded Ghidra settings**

Add assertions equivalent to:

```ts
const config = loadConfig({ RE_MCP_WORKSPACE_ROOT: "/tmp/work" });
assert.equal(config.ghidraHome, null);
assert.equal(config.ghidraTimeoutMs, 900_000);

assert.equal(loadConfig({
  RE_MCP_WORKSPACE_ROOT: "/tmp/work",
  RE_MCP_GHIDRA_HOME: "/opt/ghidra_12.1_PUBLIC",
  RE_MCP_GHIDRA_TIMEOUT_MS: "3600000",
}).ghidraTimeoutMs, 3_600_000);

assert.throws(() => loadConfig({
  RE_MCP_WORKSPACE_ROOT: "/tmp/work",
  RE_MCP_GHIDRA_TIMEOUT_MS: "3600001",
}), /RE_MCP_GHIDRA_TIMEOUT_MS must be between 1 and 3600000/);
```

- [ ] **Step 2: Run the config tests and confirm failure**

Run:

```bash
npm test -- --test-name-pattern="Ghidra config"
```

Expected: FAIL because `ServerConfig` does not yet expose Ghidra settings.

- [ ] **Step 3: Implement bounded Ghidra configuration**

Add a bounded helper and parse the optional home without making it required:

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

Set:

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

- [ ] **Step 4: Write a failing process-runner test for kill-on-output-limit**

Use `process.execPath` with `-e` to emit more than 64 bytes and keep the process alive. Assert:

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

- [ ] **Step 5: Run the process-runner test and confirm failure**

Run:

```bash
npm test -- --test-name-pattern="terminate.*output limit"
```

Expected: FAIL because current `runProcess()` truncates but does not terminate.

- [ ] **Step 6: Implement opt-in output-limit termination without changing existing callers**

Track `outputLimitExceeded`; on the first overflow with `terminateOnOutputLimit === true`, send `SIGTERM` and schedule the existing `SIGKILL` fallback. Preserve current truncation behavior when the option is absent/false.

- [ ] **Step 7: Run focused and full tests**

Run:

```bash
npm test -- --test-name-pattern="Ghidra config|output limit"
npm run typecheck
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/config.ts src/services/process-runner.ts tests/config.test.ts tests/process-runner.test.ts
git commit -m "feat: add bounded Ghidra process configuration"
```

---

### Task 2: Define deterministic Ghidra bridge and project identities

**Files:**
- Create: `src/services/nds/ghidra-model.ts`
- Create: `tests/nds-ghidra-model.test.ts`

**Interfaces:**
- Consumes: `NdsRomMap`, `DiscoverNdsFunctionsResult`, `ProvenFunctionIdentity`, `FunctionProof`, and `ProvenFunctionCallEdge`.
- Produces:

```ts
export const GHIDRA_BRIDGE_FORMAT = "re-mcp-nds-ghidra" as const;
export const GHIDRA_BRIDGE_FORMAT_VERSION = 1 as const;
export const GHIDRA_ARM9_LANGUAGE = "ARM:LE:32:v5t" as const;
export const GHIDRA_ARM7_LANGUAGE = "ARM:LE:32:v4t" as const;

export interface GhidraBridgeManifest {
  readonly format: typeof GHIDRA_BRIDGE_FORMAT;
  readonly formatVersion: typeof GHIDRA_BRIDGE_FORMAT_VERSION;
  readonly sourceRomSha256: string;
  readonly sha256Prefix: string;
  readonly processors: readonly GhidraProcessorManifest[];
  readonly functionDiscovery: readonly GhidraFunctionDiscoveryManifest[];
  readonly artifacts: readonly GhidraBridgeArtifact[];
}

export function ghidraGeneratedBridgeRoot(map: NdsRomMap, workspaceRoot: string): string;
export function ghidraPersistentRoot(map: NdsRomMap, workspaceRoot: string): string;
export function ghidraProjectName(map: NdsRomMap): string;
export function ghidraProgramName(processor: NdsProcessor): "RE-MCP_ARM9" | "RE-MCP_ARM7";
export function ghidraOverlaySpaceName(processor: NdsProcessor, overlayId: number): string;
export function stableJson(value: unknown): string;
```

`ghidraPersistentRoot()` must resolve exactly beneath `analysis/ghidra/nds/<full-sha256>/`. `ghidraGeneratedBridgeRoot()` must resolve beneath `analysis/generated/nds/<sha-prefix>/ghidra-bridge/`.

- [ ] **Step 1: Write failing tests for full-SHA paths and deterministic names**

Include:

```ts
assert.match(ghidraPersistentRoot(map, root), new RegExp(`${map.sha256}/?$`));
assert.equal(ghidraProjectName(map), `RE-MCP-${map.sha256}`);
assert.equal(ghidraProgramName("arm9"), "RE-MCP_ARM9");
assert.equal(ghidraOverlaySpaceName("arm9", 7), "RE_MCP_ARM9_OVL_7");
```

Also construct two maps with the same first 16 SHA characters and verify persistent roots differ.

- [ ] **Step 2: Run the model tests and confirm failure**

```bash
npm test -- --test-name-pattern="Ghidra bridge model"
```

Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement the model constants, types, comparators, and path helpers**

Use `resolveInside()` for both roots. Sort processors ARM9 then ARM7, overlays by numeric ID, functions using the existing canonical function comparator, proofs using `compareFunctionProof`, and call edges using `compareFunctionCallEdge`.

`stableJson()` must serialize already-canonicalized structures with two-space indentation plus a trailing newline:

```ts
export function stableJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}
```

- [ ] **Step 4: Add failing tests for manifest validation and compressed-overlay representation**

Assert that every overlay record contains one of:

```ts
{ importStatus: "importable", artifact: "../overlays/..." }
{ importStatus: "not-imported-compressed", artifact: "../overlays/..." }
```

and that compressed records have no executable runtime artifact mapping claim.

- [ ] **Step 5: Implement pure `buildGhidraBridgeManifest(...)` transformation**

Use an explicit signature:

```ts
export function buildGhidraBridgeManifest(input: {
  readonly map: NdsRomMap;
  readonly arm9: DiscoverNdsFunctionsResult;
  readonly arm7: DiscoverNdsFunctionsResult;
  readonly artifacts: readonly GhidraBridgeArtifact[];
}): GhidraBridgeManifest;
```

This function performs no I/O and never infers function ends.

- [ ] **Step 6: Run model tests and typecheck**

```bash
npm test -- --test-name-pattern="Ghidra bridge model"
npm run typecheck
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/services/nds/ghidra-model.ts tests/nds-ghidra-model.test.ts
git commit -m "feat: define deterministic Ghidra bridge model"
```

---

### Task 3: Generate and validate the transactional bridge bundle

**Files:**
- Create: `src/services/nds/ghidra-bridge.ts`
- Create: `tests/nds-ghidra-bridge.test.ts`
- Modify: `src/services/nds/errors.ts`

**Interfaces:**
- Consumes: canonical `NdsRomMap`, existing `extractNdsAnalysisBundle()`, `discoverNdsFunctions()`, `createCapstoneArmBackend()`, and Task 2 model helpers.
- Produces:

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

Use fixed discovery limits equal to the current public defaults:

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

Both processors use `{ scope: { kind: "all-executable-components" }, seeds: [] }` so caller input cannot change proof policy.

- [ ] **Step 1: Write a failing bridge-generation test using the existing synthetic NDS fixture pattern**

Assert the generator:

- refreshes the static analysis bundle;
- runs ARM9 and ARM7 discovery;
- creates `ghidra-bridge/manifest.json`;
- creates `evidence/functions.json` and `evidence/calls.json`;
- copies the three packaged Ghidra scripts;
- records hashes for every bridge-owned file;
- reports compressed overlays as omitted from executable import.

- [ ] **Step 2: Run and confirm failure**

```bash
npm test -- --test-name-pattern="generate.*Ghidra bridge"
```

Expected: FAIL because generation does not exist.

- [ ] **Step 3: Add Ghidra error categories**

Extend the canonical NDS error union with:

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

Include it in `AnyNdsErrorCategory` without casts in new Ghidra services.

- [ ] **Step 4: Implement transactional bridge generation**

Algorithm:

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
  // Build manifest/evidence under a temporary ghidra-bridge sibling,
  // fsync/hash files, then atomically promote only ghidra-bridge.
} finally {
  backend.close();
}
```

Reuse existing static bundle `arm9.bin`, `arm7.bin`, and overlay artifacts by relative path; do not duplicate executable bytes into the bridge subdirectory.

- [ ] **Step 5: Write failing integrity tests for source mutation and artifact tampering**

Test two cases:

1. mutate the ROM during discovery and expect `invalid-rom` with no promoted bridge;
2. tamper with `functions.json` after generation and expect `validateGeneratedGhidraBridge()` to fail `bridge-generation-failed`.

- [ ] **Step 6: Implement pre/post SHA checks and artifact-hash validation**

Use the existing `hashFileSha256()` helper. A generated manifest's `manifestSha256` is the hash of the exact `manifest.json` bytes and is not embedded recursively inside that same file.

- [ ] **Step 7: Run bridge tests and full NDS static regression tests**

```bash
npm test -- --test-name-pattern="Ghidra bridge|function discovery|analysis bundle"
npm run typecheck
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/services/nds/ghidra-bridge.ts src/services/nds/errors.ts tests/nds-ghidra-bridge.test.ts
git commit -m "feat: generate validated NDS Ghidra bridge bundles"
```

---

### Task 4: Validate Ghidra 12.x installations and construct headless commands

**Files:**
- Create: `src/services/nds/ghidra-installation.ts`
- Create: `src/services/nds/ghidra-runner.ts`
- Create: `tests/nds-ghidra-installation.test.ts`
- Create: `tests/nds-ghidra-runner.test.ts`

**Interfaces:**
- Consumes: Task 1 config/process runner and Task 2 manifest/path helpers.
- Produces:

```ts
export interface ValidatedGhidraInstallation {
  readonly home: string;
  readonly analyzeHeadless: string;
  readonly version: string;
  readonly scriptPath: string;
}

export async function validateGhidraInstallation(
  config: ServerConfig,
): Promise<ValidatedGhidraInstallation>;

export interface GhidraInvocation {
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly stage: "arm9-import" | "arm9-process" | "arm7-import" | "arm7-process";
}

export function buildGhidraImportInvocation(input: {
  readonly installation: ValidatedGhidraInstallation;
  readonly map: NdsRomMap;
  readonly bridge: GeneratedGhidraBridge;
  readonly processor: NdsProcessor;
}): GhidraInvocation;

export function buildGhidraProcessInvocation(input: {
  readonly installation: ValidatedGhidraInstallation;
  readonly map: NdsRomMap;
  readonly bridge: GeneratedGhidraBridge;
  readonly processor: NdsProcessor;
}): GhidraInvocation;

export async function runGhidraInvocation(
  invocation: GhidraInvocation,
  config: ServerConfig,
): Promise<RunResult>;
```

- [ ] **Step 1: Write failing installation tests against a temporary fake Ghidra tree**

Construct:

```text
<tmp>/ghidra_12.1_PUBLIC/
├── support/analyzeHeadless
├── Ghidra/application.properties
└── Ghidra/Processors/ARM/data/languages/ARM.ldefs
```

`application.properties` contains `application.version=12.1`; `ARM.ldefs` contains both required language IDs. Assert valid resolution and these failures:

- missing config → `ghidra-not-configured`;
- missing executable → `invalid-ghidra-installation`;
- version 11.4 → `unsupported-ghidra-version`;
- missing v4t/v5t language → `ghidra-language-unavailable`.

- [ ] **Step 2: Run installation tests and confirm failure**

```bash
npm test -- --test-name-pattern="Ghidra installation"
```

Expected: FAIL because validator does not exist.

- [ ] **Step 3: Implement installation validation**

Resolve `support/analyzeHeadless` and `Ghidra/.../ARM.ldefs` beneath the configured root with `resolveInside()`. Parse `application.version` and accept only `/^12\./`. Require exact `id="ARM:LE:32:v5t"` and `id="ARM:LE:32:v4t"` text in the language definitions.

- [ ] **Step 4: Write failing command-construction tests**

For an initial ARM9 import, assert the exact semantic argument sequence contains:

```text
<project-root>
RE-MCP-<full-sha>
-import <generated-root>/arm9.bin
-loader BinaryLoader
-processor ARM:LE:32:v5t
-loader-baseAddr 0x<arm9-ram-base>
-scriptPath <packaged-resource-script-path>
-preScript ReMcpPrepareProgram.java <manifest> arm9
-preScript ReMcpImportEvidence.java <manifest> arm9
-postScript ReMcpRecordAnalysis.java <manifest> arm9
```

For ARM7, require `ARM:LE:32:v4t`. For an existing program, require `-process RE-MCP_ARM9`/`RE-MCP_ARM7` and no `-import`, `-loader`, or caller-controlled args.

- [ ] **Step 5: Implement import/process invocation builders**

Use explicit hex base formatting:

```ts
function addressHex(value: number): string {
  return `0x${value.toString(16)}`;
}
```

Never use `-overwrite` on an existing analyst project.

- [ ] **Step 6: Write failing runner tests for timeout/output/nonzero exit mapping**

Use a fake `analyzeHeadless` script and assert:

- `runProcess` receives `terminateOnOutputLimit: true`;
- timeout produces `ghidra-analysis-timeout`;
- output overflow produces `ghidra-output-limit`;
- import-stage nonzero exit produces `ghidra-import-failed`;
- process-stage nonzero exit produces `ghidra-analysis-failed`;
- stderr matching a project-lock fixture produces `ghidra-project-locked`.

- [ ] **Step 7: Implement `runGhidraInvocation()` stage-aware error mapping**

Pass exactly:

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

Throw typed `NdsError` categories for timed out, output limit, lock, and nonzero exit cases.

- [ ] **Step 8: Run tests and typecheck**

```bash
npm test -- --test-name-pattern="Ghidra installation|Ghidra invocation|Ghidra runner"
npm run typecheck
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add src/services/nds/ghidra-installation.ts src/services/nds/ghidra-runner.ts tests/nds-ghidra-installation.test.ts tests/nds-ghidra-runner.test.ts
git commit -m "feat: add controlled Ghidra headless runner"
```

---

### Task 5: Add RE-MCP-owned Ghidra reconciliation scripts

**Files:**
- Create: `resources/ghidra/ReMcpPrepareProgram.java`
- Create: `resources/ghidra/ReMcpImportEvidence.java`
- Create: `resources/ghidra/ReMcpRecordAnalysis.java`
- Create: `tests/nds-ghidra-resources.test.ts`

**Interfaces:**
- Consumes: bridge `manifest.json`, `evidence/functions.json`, `evidence/calls.json`, processor arg `arm9|arm7`.
- Produces Ghidra-owned state only under these keys/maps:

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

The scripts must never delete or rename analyst symbols/comments/types/bookmarks/functions.

- [ ] **Step 1: Write failing resource contract tests**

Load all three Java sources as text and assert:

- exact metadata/property-map names are present;
- no `removeSymbol`, `removeFunction`, `clearListing`, or `removeMemoryBlock` call is present;
- overlay creation explicitly requests overlay behavior;
- scripts require manifest path and processor arguments;
- no network/file path other than manifest-derived workspace bridge artifacts is accepted.

- [ ] **Step 2: Run and confirm failure**

```bash
npm test -- --test-name-pattern="Ghidra resource contract"
```

Expected: FAIL because resources do not exist.

- [ ] **Step 3: Implement `ReMcpPrepareProgram.java`**

The script must:

1. parse manifest and processor arg;
2. verify current program language matches required v5t/v4t;
3. verify/create Program Information ownership keys;
4. reject ROM SHA or processor mismatch with a nonzero script failure;
5. ensure main executable base corresponds to imported binary base;
6. create each uncompressed overlay as an initialized overlay memory block at canonical runtime address using the overlay backing artifact;
7. create canonical uninitialized BSS blocks only when nonzero and non-conflicting;
8. tag overlay starting addresses with `re-mcp.overlay-id`;
9. skip compressed overlays entirely as executable blocks;
10. establish ARM/Thumb context at RE-MCP-proven entry addresses without defining a guessed function body.

Use deterministic overlay block names `RE_MCP_ARM9_OVL_<id>` / `RE_MCP_ARM7_OVL_<id>`.

- [ ] **Step 4: Implement `ReMcpImportEvidence.java`**

For each proven entry of the selected processor:

```java
StringPropertyMap ids = currentProgram.getUsrPropertyManager()
    .createStringPropertyMap("re-mcp.function-id");
StringPropertyMap proofs = currentProgram.getUsrPropertyManager()
    .createStringPropertyMap("re-mcp.function-proof");
StringPropertyMap modes = currentProgram.getUsrPropertyManager()
    .createStringPropertyMap("re-mcp.function-mode");
```

Resolve main addresses in the default space and overlay entries in their named overlay spaces. Add entry metadata and exact direct-call references only when the manifest names one exact caller and target space/address. Do not call a function creation API with a fabricated body range.

- [ ] **Step 5: Implement `ReMcpRecordAnalysis.java`**

Write successful analysis metadata and a deterministic sidecar `latest-success.json` beneath the full-SHA persistent root containing:

```json
{
  "format": "re-mcp-nds-ghidra-run-state",
  "formatVersion": 1,
  "sourceRomSha256": "<full sha>",
  "manifestSha256": "<manifest sha>",
  "processor": "arm9",
  "programName": "RE-MCP_ARM9",
  "analysisStatus": "complete",
  "ghidraVersion": "<version>"
}
```

The sidecar path is supplied only through the manifest-derived project root, not arbitrary script input.

- [ ] **Step 6: Strengthen tests with exact forbidden mutation patterns and deterministic names**

Add assertions for every owned key and both overlay name templates.

- [ ] **Step 7: Run resource tests**

```bash
npm test -- --test-name-pattern="Ghidra resource contract"
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add resources/ghidra tests/nds-ghidra-resources.test.ts
git commit -m "feat: add RE-MCP Ghidra reconciliation scripts"
```

---

### Task 6: Orchestrate analyst-safe project bootstrap and non-mutating status

**Files:**
- Create: `src/services/nds/ghidra-project.ts`
- Create: `tests/nds-ghidra-project.test.ts`

**Interfaces:**
- Consumes: Tasks 2–5 services.
- Produces:

```ts
export interface NdsGhidraBootstrapResult {
  readonly sourceRomSha256: string;
  readonly projectPath: string;
  readonly ghidraVersion: string;
  readonly manifestSha256: string;
  readonly runKind: "initial" | "reconciled" | "already-current";
  readonly processors: readonly {
    readonly processor: NdsProcessor;
    readonly programName: string;
    readonly status: "imported" | "reconciled" | "already-current";
    readonly importedOverlays: number;
    readonly compressedOverlayIds: readonly number[];
    readonly provenEntries: number;
    readonly directCalls: number;
    readonly analysisStatus: "complete";
  }[];
  readonly evidenceCoverage: readonly {
    readonly processor: NdsProcessor;
    readonly status: "complete" | "partial-coverage" | "truncated";
    readonly truncationReasons: readonly string[];
  }[];
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

- [ ] **Step 1: Write failing initial-bootstrap orchestration test with injected fake runner**

Factor internal dependencies through an optional test-only dependency object so tests can record calls without a real Ghidra process:

```ts
interface GhidraProjectDeps {
  readonly validateInstallation: typeof validateGhidraInstallation;
  readonly generateBridge: typeof generateNdsGhidraBridge;
  readonly runInvocation: typeof runGhidraInvocation;
}
```

Assert first run executes ARM9 import then ARM7 import and returns `runKind: "initial"`.

- [ ] **Step 2: Run and confirm failure**

```bash
npm test -- --test-name-pattern="Ghidra project bootstrap"
```

Expected: FAIL because orchestration does not exist.

- [ ] **Step 3: Implement first-run bootstrap and run-state sidecars**

Before invocation, persist a non-success `latest-run.json` sidecar with stage `starting`. After each successful processor, read the Ghidra-produced `latest-success.json` and verify full ROM SHA, manifest SHA, processor, and program name. Only then advance to the next processor.

After both succeed, write a deterministic summary sidecar with `analysisStatus: "complete"`.

- [ ] **Step 4: Write failing rerun tests for current/reconciled/mismatch cases**

Cover:

1. identical successful sidecars → use `-process`, no `-import`, return `already-current` for bridge-owned state after successful processing;
2. same ROM SHA but newer manifest → use `-process`, return `reconciled`;
3. project directory exists without matching RE-MCP run-state identity → `project-state-mismatch`;
4. run-state references another full ROM SHA → `project-state-mismatch`;
5. ARM9 success followed by ARM7 failure → preserve project and record structured last failure, never delete project.

- [ ] **Step 5: Implement rerun decision rules**

Never infer a usable existing RE-MCP program solely from directory existence. Require matching RE-MCP sidecar identity; otherwise fail closed.

Do not use `-overwrite` for reconciliations.

- [ ] **Step 6: Write failing status tests**

Assert `readNdsGhidraStatus()`:

- parses the ROM to obtain the full SHA;
- does not call installation validation or `runProcess`;
- reports absent project cleanly;
- reports manifest/run-state metadata when present;
- reports `lastFailure` from sidecar without mutating files.

- [ ] **Step 7: Implement non-mutating status**

Status may hash/read deterministic manifest/sidecar files but must not launch Ghidra or regenerate the bridge.

- [ ] **Step 8: Add source-SHA race tests**

Mutate the ROM after bridge generation but before invocation and after the final processor run; both must return `invalid-rom` and not claim success.

- [ ] **Step 9: Run focused tests and typecheck**

```bash
npm test -- --test-name-pattern="Ghidra project|Ghidra status"
npm run typecheck
```

Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add src/services/nds/ghidra-project.ts tests/nds-ghidra-project.test.ts
git commit -m "feat: orchestrate analyst-safe Ghidra projects"
```

---

### Task 7: Expose the two bounded MCP tools and capability/error metadata

**Files:**
- Create: `src/tools/nds-ghidra.ts`
- Create: `tests/nds-ghidra-tools.test.ts`
- Modify: `src/index.ts`

**Interfaces:**
- Consumes: `bootstrapNdsGhidraProject()`, `readNdsGhidraStatus()`, `ServerConfig`.
- Produces exactly two public tools:

```text
nds_ghidra_bootstrap
nds_ghidra_status
```

Both schemas accept only:

```ts
{ rom: z.string().min(1) }
```

- [ ] **Step 1: Write failing tool registration/schema tests**

Verify both tools register and reject extra caller-controlled Ghidra inputs such as `executable`, `projectPath`, `processor`, `args`, and `scriptPath` because they are absent from the schema.

- [ ] **Step 2: Run and confirm failure**

```bash
npm test -- --test-name-pattern="Ghidra MCP tools"
```

Expected: FAIL because tools are not registered.

- [ ] **Step 3: Implement `registerNdsGhidraTools(server, config)`**

Use `resolveInside(config.workspaceRoot, rom)` before service calls. Follow existing bounded JSON response patterns and map Ghidra categories to corrective actions such as:

```ts
case "ghidra-not-configured":
  return "Set RE_MCP_GHIDRA_HOME to a supported local Ghidra 12.x installation and restart RE-MCP.";
case "ghidra-project-locked":
  return "Close the SHA-scoped Ghidra project in GUI/headless processes, then retry without deleting the project.";
case "project-state-mismatch":
  return "Inspect the SHA-scoped project/run-state metadata; RE-MCP will not overwrite unrecognized analyst state.";
```

- [ ] **Step 4: Register tools in `src/index.ts` and update capability output**

Add:

```ts
import { registerNdsGhidraTools } from "./tools/nds-ghidra.js";
...
registerNdsGhidraTools(server, config);
```

Add both names to `server_capabilities.tools` and extend `ndsStaticAnalysisPolicy` to state that controlled Ghidra bootstrap is optional, SHA-scoped, analyst-preserving, and non-authoritative for RE-MCP evidence.

- [ ] **Step 5: Write output-bound/error tests**

Assert success responses above `RE_MCP_MAX_OUTPUT_BYTES` produce the existing output-bound error shape and failures preserve structured Ghidra categories/corrective actions.

- [ ] **Step 6: Run tool tests, typecheck, and build**

```bash
npm test -- --test-name-pattern="Ghidra MCP tools|server capabilities"
npm run typecheck
npm run build
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/tools/nds-ghidra.ts src/index.ts tests/nds-ghidra-tools.test.ts
git commit -m "feat: expose controlled NDS Ghidra tools"
```

---

### Task 8: Package resources and document the installation/workflow

**Files:**
- Modify: `scripts/check-install.mjs`
- Modify: `.github/workflows/package.yml`
- Modify: `mcp-config.example.json`
- Modify: `README.md`

**Interfaces:**
- Consumes: compiled tool registration and `resources/ghidra/*.java`.
- Produces a self-contained downloadable RE-MCP bundle that includes Ghidra bridge scripts but does not include Ghidra itself.

- [ ] **Step 1: Write a failing package self-check expectation**

Extend `scripts/check-install.mjs` to require these exact files beneath the package root:

```text
resources/ghidra/ReMcpPrepareProgram.java
resources/ghidra/ReMcpImportEvidence.java
resources/ghidra/ReMcpRecordAnalysis.java
```

Also inspect compiled `dist/index.js`/registered module content sufficiently to assert `nds_ghidra_bootstrap` and `nds_ghidra_status` are shipped.

- [ ] **Step 2: Run package check locally and confirm failure before workflow copy change**

```bash
npm run build
node scripts/check-install.mjs .
```

Expected: FAIL on the new resource requirement until package/resource handling is updated.

- [ ] **Step 3: Update package workflow to include resources**

Add:

```bash
cp -R resources "$root/"
```

before the production install/self-check.

- [ ] **Step 4: Update example MCP configuration**

Use:

```json
{
  "RE_MCP_WORKSPACE_ROOT": "/ABSOLUTE/PATH/TO/rom-modding",
  "RE_MCP_GHIDRA_HOME": "/ABSOLUTE/PATH/TO/ghidra_12.1_PUBLIC",
  "RE_MCP_GHIDRA_TIMEOUT_MS": "900000"
}
```

Explain in README that the two Ghidra settings are optional unless Ghidra tools are used.

- [ ] **Step 5: Document exact bridge/project layout and trust model**

README must state:

- one full-SHA project per ROM;
- ARM9 v5t / ARM7 v4t;
- true overlay spaces for uncompressed overlays;
- compressed overlays omitted;
- RE-MCP imports proven entries, not proven body boundaries;
- Ghidra auto-analysis remains non-authoritative;
- reruns preserve analyst work;
- no generic Ghidra command/script tool;
- status does not invoke Ghidra;
- real-Ghidra acceptance is separate from Catalina debugger acceptance.

- [ ] **Step 6: Run package check and full verification**

```bash
npm run check
npm run build
node scripts/check-install.mjs .
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add scripts/check-install.mjs .github/workflows/package.yml mcp-config.example.json README.md
git commit -m "docs: package and document Ghidra integration"
```

---

### Task 9: Add manual real-Ghidra 12.1 acceptance

**Files:**
- Create: `.github/workflows/ghidra-integration.yml`
- Modify: `tests/nds-ghidra-resources.test.ts` or create `scripts/ghidra-acceptance.mjs` if the workflow needs a single deterministic verifier.
- Create: `scripts/ghidra-acceptance.mjs`

**Interfaces:**
- Consumes: built RE-MCP code, official Ghidra 12.1 distribution, synthetic NDS fixture generated locally in the workflow.
- Produces: a manually-triggered pass/fail acceptance artifact/log; it is not part of normal `pull_request` CI.

- [ ] **Step 1: Add a deterministic acceptance verifier script with failing fixture-first tests**

`ghidra-acceptance.mjs` accepts only:

```text
node scripts/ghidra-acceptance.mjs <workspace-root> <rom-relative-path>
```

It launches the built RE-MCP service layer or directly calls the compiled bootstrap service with configured environment and verifies:

- project exists under `analysis/ghidra/nds/<full-sha>/`;
- ARM9/ARM7 success sidecars exist;
- expected language IDs are recorded;
- two synthetic overlapping overlays are represented by distinct named spaces;
- one compressed overlay is reported omitted;
- a known ARM entry and Thumb direct-call target carry RE-MCP evidence;
- no bridge metadata claims a function end/body;
- second bootstrap leaves bridge-owned identity unchanged;
- an analyst-marker fixture added between runs remains present.

- [ ] **Step 2: Create a `workflow_dispatch`-only Ghidra workflow**

Use:

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

Pin Ghidra 12.1 download URL and SHA-256 in workflow environment variables. Verify the archive SHA before extraction. Do not attach this workflow to `push` or `pull_request`.

- [ ] **Step 3: Generate the synthetic NDS fixture inside the workflow**

Use an existing test fixture helper exposed through a small Node script or add a deterministic fixture builder to `scripts/ghidra-acceptance.mjs`. The fixture must contain:

- ARM9 main entry with at least one direct call;
- ARM7 main entry;
- two uncompressed overlays sharing the same runtime base but different IDs;
- one compressed overlay metadata record;
- at least one proven Thumb target with exact mode evidence.

No private ROM is used or uploaded.

- [ ] **Step 4: Run build and real headless acceptance in the workflow**

Commands:

```bash
npm install
npm run check
npm run build
RE_MCP_WORKSPACE_ROOT="$RUNNER_TEMP/work" \
RE_MCP_GHIDRA_HOME="$RUNNER_TEMP/ghidra_12.1_PUBLIC" \
RE_MCP_GHIDRA_TIMEOUT_MS=900000 \
node scripts/ghidra-acceptance.mjs "$RUNNER_TEMP/work" fixture.nds
```

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ghidra-integration.yml scripts/ghidra-acceptance.mjs tests/nds-ghidra-resources.test.ts
git commit -m "ci: add manual Ghidra 12.1 acceptance"
```

---

### Task 10: Final regression, package verification, and PR readiness

**Files:**
- Modify only files required by failures found in this task.

**Interfaces:**
- Consumes: all previous tasks.
- Produces: a review-ready branch with green normal CI/package checks and no debugger-gate regression.

- [ ] **Step 1: Run the complete repository verification suite**

```bash
npm run check
npm run build
```

Expected: PASS.

- [ ] **Step 2: Run package assembly semantics locally**

Mirror the package workflow:

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

Expected: `check-install.mjs` reports success without requiring Ghidra.

- [ ] **Step 3: Run targeted safety regressions**

```bash
npm test -- --test-name-pattern="Ghidra|process runner|NDS function|analysis bundle|DeSmuME"
```

Expected: PASS. No DeSmuME/GDB production behavior should have changed.

- [ ] **Step 4: Inspect the final diff for forbidden scope expansion**

Confirm there is no:

- generic command/script tool;
- arbitrary Ghidra args/path schema;
- compressed-overlay decoding;
- Ghidra-to-RE-MCP evidence promotion;
- function-end/body proof claim;
- native debugger extension.

- [ ] **Step 5: Commit any verification-only fixes**

If no fixes were needed, do not create an empty commit. If fixes were required:

```bash
git add <only files changed by verified fixes>
git commit -m "fix: close Ghidra integration verification gaps"
```

- [ ] **Step 6: Open a pull request against `main`**

Use title:

```text
Add controlled NDS Ghidra integration
```

PR body must summarize:

- SHA-scoped project lifecycle;
- ARM9/ARM7 languages and true overlay spaces;
- compressed-overlay omission;
- proven-entry-only evidence semantics;
- analyst-work preservation;
- bounded `analyzeHeadless` safety;
- normal CI/package results;
- manual Ghidra 12.1 acceptance status;
- explicit statement that Catalina/DeSmuME acceptance remains separate and unchanged.

Do not merge without explicit user approval.
