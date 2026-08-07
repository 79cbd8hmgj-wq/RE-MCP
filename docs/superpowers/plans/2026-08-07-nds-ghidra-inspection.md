# NDS Controlled Ghidra Inspection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add five bounded, strictly read-only MCP tools for inspecting an already-current RE-MCP-owned Ghidra project: function metadata, decompiler output, symbols, references, and direct callers/callees.

**Architecture:** Reuse the existing full-ROM-SHA Ghidra project and validated `analyzeHeadless`, but require a trusted completed bootstrap state before every inspection. Node resolves canonical NDS selectors, writes one server-owned request artifact, runs exactly one RE-MCP inspection script with `-process`, `-readOnly`, and `-noanalysis`, validates one versioned result artifact, deletes transport files, and returns explicitly separated canonical / RE-MCP-evidence / Ghidra-derived output.

**Tech Stack:** Node.js 20+, TypeScript 5.7, MCP SDK, Zod, existing canonical NDS parser/resolver, existing Ghidra 12.x integration, Ghidra 12.1.2 headless Java scripting/decompiler APIs, GitHub Actions.

## Global Constraints

- Inspection never bootstraps or reconciles Ghidra implicitly.
- Inspection requires a complete trusted `latest-success.json`, matching complete `latest-run.json`, no `latest-failure.json`, a matching bridge manifest hash, and both ARM9/ARM7 processors.
- Configured Ghidra version must exactly match the trusted project state's recorded version.
- Every inspection invocation must contain `-process`, `-readOnly`, `-noanalysis`, fixed `-scriptPath`, and fixed `ReMcpInspectProgram.java`.
- Inspection invocations must never contain `-import`, `ReMcpPrepareProgram.java`, `ReMcpImportEvidence.java`, or `ReMcpRecordAnalysis.java`.
- Caller input never controls Ghidra executable, project path/name, program name, address-space name, script, CLI args, environment map, request path, or result path.
- Public address selectors are canonical NDS `{ rom, processor, runtimeAddress, overlayId? }` selectors.
- Overlapping overlay ownership remains ambiguous unless `overlayId` selects one canonical candidate.
- Compressed overlays are not present as executable Ghidra overlays and return `ghidra-address-not-inspectable`.
- Function/decompiler inspection requires main or uncompressed-overlay executable code; BSS is not decompilable.
- Ghidra-derived bodies, symbols, references, calls, signatures, and decompiler text never become canonical RE-MCP facts.
- One processor program is processed per tool invocation.
- Function body ranges are capped at 256.
- Symbol/reference/call pages default to 100 and cap at 1000; pagination offset caps at 100000.
- Symbol query length is 1..128 Unicode characters; no regex/expression language.
- Decompiler output defaults to 20000 characters and caps at 100000 characters; per-function decompile timeout is fixed at 30 seconds.
- Existing `RE_MCP_GHIDRA_TIMEOUT_MS` and `RE_MCP_MAX_OUTPUT_BYTES` remain hard outer bounds.
- Temporary request/result transport files live only under `analysis/generated/nds/<sha-prefix>/ghidra-inspection/` and are deleted after validation/best-effort failure cleanup.
- Persistent `analysis/ghidra/...` project/state and source ROM remain read-only during inspection.
- Normal CI/package checks must not require or download Ghidra.
- Physical Catalina/DeSmuME debugger behavior remains unchanged.

---

## File structure

### Create

- `src/services/nds/ghidra-inspection-model.ts` — operation enums, bounded request/result envelopes, canonical selector/result authority types, deterministic transport paths.
- `src/services/nds/ghidra-inspection.ts` — readiness gate, canonical selector resolution, request/result transport, runner orchestration, result validation and cleanup.
- `tests/nds-ghidra-inspection-model.test.ts` — pure model/path/limit tests.
- `tests/nds-ghidra-inspection.test.ts` — readiness, selector, transport, result validation, cleanup and orchestration tests.
- `tests/nds-ghidra-inspection-tools.test.ts` — five MCP schemas, routing, error mapping, output bounds.
- `resources/ghidra/ReMcpInspectProgram.java` — fixed read-only Ghidra inspection script for all five operations.

### Modify

- `src/services/nds/ghidra-project.ts` — export a trusted inspection-readiness snapshot without mutating project/status behavior.
- `src/services/nds/ghidra-runner.ts` — add inspection invocation stage/builder and inspection-specific runner error mapping.
- `src/services/nds/errors.ts` — add inspection error categories.
- `src/tools/nds-ghidra.ts` — register five new bounded inspection tools and dependency hooks.
- `src/index.ts` — advertise seven total Ghidra tools and read-only inspection trust boundary.
- `tests/nds-ghidra-project.test.ts` — trusted readiness characterization/regression tests.
- `tests/nds-ghidra-runner.test.ts` — exact read-only/no-analysis argv and error mapping.
- `tests/nds-ghidra-resources.test.ts` — inspection Java source contract.
- `tests/nds-ghidra-tools.test.ts` — retain two existing bootstrap/status contracts while allowing seven total registered tools.
- `scripts/check-install.mjs` — require packaged inspection Java resource.
- `scripts/ghidra-acceptance.mjs` — exercise all five read-only operations and project-byte preservation.
- `.github/workflows/package.yml` — packaged inspection resource/tool smoke without Ghidra.
- `README.md` — capability list, authority and read-only semantics.
- `docs/nds-ghidra-integration.md` — inspection workflow/requirements/errors.

---

### Task 1: Add trusted inspection readiness and inspection error categories

**Files:**
- Modify: `src/services/nds/errors.ts`
- Modify: `src/services/nds/ghidra-project.ts`
- Test: `tests/nds-ghidra-project.test.ts`

**Interfaces:**

```ts
export type NdsGhidraInspectionErrorCategory =
  | "ghidra-project-not-current"
  | "ghidra-version-mismatch"
  | "ghidra-address-not-inspectable"
  | "ghidra-inspection-failed"
  | "ghidra-inspection-timeout"
  | "ghidra-inspection-result-invalid";

export interface TrustedGhidraInspectionState {
  readonly map: NdsRomMap;
  readonly projectRoot: string;
  readonly projectName: string;
  readonly bridgeRoot: string;
  readonly bridgeManifestPath: string;
  readonly manifestSha256: string;
  readonly ghidraVersion: string;
  readonly completedProcessors: readonly ["arm9", "arm7"];
}

export async function readTrustedGhidraInspectionState(
  romPath: string,
  config: ServerConfig,
): Promise<TrustedGhidraInspectionState>;
```

- [ ] **Step 1: Write failing error-union and trusted-state tests**

Add tests that require every new category to construct through `NdsError`, then create a valid temporary SHA-scoped state with:

```ts
latestSuccess = {
  format: "re-mcp-nds-ghidra-run-state",
  formatVersion: 1,
  sourceRomSha256: map.sha256,
  manifestSha256: manifestSha,
  ghidraVersion: "12.1.2",
  stage: "complete",
  existingProcessors: ["arm9", "arm7"],
  completedProcessors: ["arm9", "arm7"],
  processors: [arm9Result, arm7Result],
};
```

Write the same object to `latest-run.json` and `latest-success.json`, create both project markers and the bridge manifest, and assert:

```ts
const state = await readTrustedGhidraInspectionState(romPath, config);
assert.equal(state.map.sha256, map.sha256);
assert.equal(state.manifestSha256, manifestSha);
assert.equal(state.ghidraVersion, "12.1.2");
assert.deepEqual(state.completedProcessors, ["arm9", "arm7"]);
```

- [ ] **Step 2: Run focused tests and verify RED**

Run:

```bash
npm test -- --test-name-pattern="trusted Ghidra inspection|inspection error category"
```

Expected: FAIL because the inspection categories/export do not exist.

- [ ] **Step 3: Extend the Ghidra service error union**

Implement:

```ts
export type NdsGhidraInspectionErrorCategory =
  | "ghidra-project-not-current"
  | "ghidra-version-mismatch"
  | "ghidra-address-not-inspectable"
  | "ghidra-inspection-failed"
  | "ghidra-inspection-timeout"
  | "ghidra-inspection-result-invalid";

export type NdsServiceErrorCategory =
  | AnyNdsErrorCategory
  | NdsGhidraErrorCategory
  | NdsGhidraInspectionErrorCategory;
```

- [ ] **Step 4: Implement the strict trusted-state reader**

Refactor only reusable read-only helpers from `ghidra-project.ts`; do not change bootstrap semantics. `readTrustedGhidraInspectionState()` must:

```ts
const map = await readNdsRomMap(romPath);
const project = await inspectProject(map, config.workspaceRoot);
if (!project.exists || project.partial) {
  throw new NdsError("ghidra-project-not-current", "...");
}

const latestRun = await readStateFile(stateRoot, "latest-run.json");
const latestSuccess = await readStateFile(stateRoot, "latest-success.json");
const failure = await readJsonIfExists(path.join(stateRoot, "latest-failure.json"));
if (failure !== null) throw new NdsError("ghidra-project-not-current", "...");
if (latestRun === null || latestSuccess === null) throw new NdsError("ghidra-project-not-current", "...");
if (latestRun.stage !== "complete" || latestSuccess.stage !== "complete") {
  throw new NdsError("ghidra-project-not-current", "...");
}
if (!hasAllProcessors(latestRun.completedProcessors) || !hasAllProcessors(latestSuccess.completedProcessors)) {
  throw new NdsError("ghidra-project-not-current", "...");
}
if (latestRun.manifestSha256 !== latestSuccess.manifestSha256) {
  throw new NdsError("ghidra-project-not-current", "...");
}
```

Hash the existing bridge `manifest.json` without regenerating it and require equality to `latestSuccess.manifestSha256`.

Return the canonical map and deterministic project/bridge paths. Do not call `validateGhidraInstallation()` here; version validation belongs to Task 6 orchestration so the pure state reader remains usable in tests/status code.

- [ ] **Step 5: Add failure-state characterization tests**

Require `ghidra-project-not-current` for each independent case:

```ts
await rm(latestSuccessPath);
await writeFile(latestFailurePath, JSON.stringify(failureState));
await rm(bridgeManifestPath);
await writeFile(latestRunPath, JSON.stringify({ ...latestSuccess, stage: "arm9-complete" }));
await writeFile(latestRunPath, JSON.stringify({ ...latestSuccess, completedProcessors: ["arm9"] }));
```

Also mutate the bridge manifest bytes after recording its SHA and require refusal.

- [ ] **Step 6: Run focused tests and type-check**

```bash
npm test -- --test-name-pattern="trusted Ghidra inspection|inspection error category"
npm run typecheck
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/services/nds/errors.ts src/services/nds/ghidra-project.ts tests/nds-ghidra-project.test.ts
git commit -m "feat: add trusted Ghidra inspection readiness"
```

---

### Task 2: Define bounded inspection model, transport paths, and canonical selectors

**Files:**
- Create: `src/services/nds/ghidra-inspection-model.ts`
- Create: `tests/nds-ghidra-inspection-model.test.ts`

**Interfaces:**

```ts
export const GHIDRA_INSPECTION_FORMAT = "re-mcp-nds-ghidra-inspection" as const;
export const GHIDRA_INSPECTION_FORMAT_VERSION = 1 as const;

export type GhidraInspectionOperation =
  | "inspect-function"
  | "decompile-function"
  | "search-symbols"
  | "list-references"
  | "list-calls";

export interface GhidraCanonicalAddressIdentity {
  readonly processor: NdsProcessor;
  readonly runtimeAddress: number;
  readonly component: "main" | "overlay";
  readonly overlayId: number | null;
  readonly addressSpace: string;
  readonly fileBacked: boolean;
  readonly bss: boolean;
  readonly compressed: boolean;
}

export interface GhidraInspectionRequest {
  readonly format: typeof GHIDRA_INSPECTION_FORMAT;
  readonly formatVersion: typeof GHIDRA_INSPECTION_FORMAT_VERSION;
  readonly requestId: string;
  readonly sourceRomSha256: string;
  readonly processor: NdsProcessor;
  readonly programName: "RE-MCP_ARM9" | "RE-MCP_ARM7";
  readonly operation: GhidraInspectionOperation;
  readonly selector: GhidraCanonicalAddressIdentity | null;
  readonly parameters: Readonly<Record<string, string | number | boolean>>;
}

export interface GhidraInspectionResultEnvelope {
  readonly format: typeof GHIDRA_INSPECTION_FORMAT;
  readonly formatVersion: typeof GHIDRA_INSPECTION_FORMAT_VERSION;
  readonly requestId: string;
  readonly sourceRomSha256: string;
  readonly processor: NdsProcessor;
  readonly programName: string;
  readonly operation: GhidraInspectionOperation;
  readonly payload: unknown;
}

export function ghidraInspectionRoot(map: NdsRomMap, workspaceRoot: string): string;
export function ghidraInspectionRequestPath(map: NdsRomMap, workspaceRoot: string, requestId: string): string;
export function ghidraInspectionResultPath(map: NdsRomMap, workspaceRoot: string, requestId: string): string;
export function validateInspectionRequestId(value: string): string;
export function clampInspectionPage(limit: number | undefined, offset: number | undefined): { limit: number; offset: number };
export function clampDecompilerCharacters(value: number | undefined): number;
```

- [ ] **Step 1: Write failing pure model tests**

Require:

```ts
assert.equal(validateInspectionRequestId("a1b2c3d4e5f6a7b8"), "a1b2c3d4e5f6a7b8");
assert.throws(() => validateInspectionRequestId("../escape"));
assert.deepEqual(clampInspectionPage(undefined, undefined), { limit: 100, offset: 0 });
assert.deepEqual(clampInspectionPage(1000, 100000), { limit: 1000, offset: 100000 });
assert.throws(() => clampInspectionPage(1001, 0));
assert.throws(() => clampInspectionPage(100, 100001));
assert.equal(clampDecompilerCharacters(undefined), 20000);
assert.equal(clampDecompilerCharacters(100000), 100000);
assert.throws(() => clampDecompilerCharacters(100001));
```

Path tests must assert both request and result remain beneath:

```text
/workspace/analysis/generated/nds/<sha-prefix>/ghidra-inspection/
```

- [ ] **Step 2: Run focused model tests and verify RED**

```bash
npm test -- --test-name-pattern="Ghidra inspection model"
```

Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement constants, request/result types, bounds, and paths**

Use only Node `path` plus existing `resolveInside()`; do not accept caller paths.

Use a strict request ID regex:

```ts
const REQUEST_ID = /^[a-f0-9]{16}$/u;
```

Bounds:

```ts
const DEFAULT_PAGE_LIMIT = 100;
const MAX_PAGE_LIMIT = 1000;
const MAX_PAGE_OFFSET = 100000;
const DEFAULT_DECOMPILE_CHARACTERS = 20000;
const MAX_DECOMPILE_CHARACTERS = 100000;
```

- [ ] **Step 4: Add deterministic operation/parameter validation tests**

Require exact match modes/directions and symbol-query length:

```ts
assert.equal(validateSymbolQuery("Main"), "Main");
assert.throws(() => validateSymbolQuery(""));
assert.throws(() => validateSymbolQuery("x".repeat(129)));
assert.equal(validateSymbolMatch(undefined), "prefix");
assert.throws(() => validateSymbolMatch("regex" as never));
assert.equal(validateReferenceDirection(undefined), "both");
assert.equal(validateCallDirection(undefined), "both");
```

- [ ] **Step 5: Implement validation helpers**

Produce:

```ts
export type GhidraSymbolMatch = "exact" | "prefix" | "contains";
export type GhidraReferenceDirection = "from" | "to" | "both";
export type GhidraCallDirection = "callers" | "callees" | "both";

export function validateSymbolQuery(value: string): string;
export function validateSymbolMatch(value: string | undefined): GhidraSymbolMatch;
export function validateReferenceDirection(value: string | undefined): GhidraReferenceDirection;
export function validateCallDirection(value: string | undefined): GhidraCallDirection;
```

- [ ] **Step 6: Verify and commit**

```bash
npm test -- --test-name-pattern="Ghidra inspection model"
npm run typecheck
git add src/services/nds/ghidra-inspection-model.ts tests/nds-ghidra-inspection-model.test.ts
git commit -m "feat: define bounded Ghidra inspection model"
```

---

### Task 3: Add fixed read-only Ghidra inspection invocation and runner mapping

**Files:**
- Modify: `src/services/nds/ghidra-runner.ts`
- Modify: `tests/nds-ghidra-runner.test.ts`

**Interfaces:**

Extend stage:

```ts
export type GhidraInvocationStage =
  | "arm9-import"
  | "arm9-process"
  | "arm7-import"
  | "arm7-process"
  | "arm9-inspect"
  | "arm7-inspect";
```

Add:

```ts
export interface GhidraInspectionInvocationInput {
  readonly installation: ValidatedGhidraInstallation;
  readonly map: NdsRomMap;
  readonly processor: NdsProcessor;
  readonly workspaceRoot: string;
  readonly requestPath: string;
  readonly resultPath: string;
}

export function buildGhidraInspectionInvocation(
  input: GhidraInspectionInvocationInput,
): GhidraInvocation;
```

- [ ] **Step 1: Write failing argv contract test**

Construct ARM9 input and require:

```ts
assert.equal(invocation.stage, "arm9-inspect");
assert.equal(hasSequence(invocation.args, ["-process", "RE-MCP_ARM9"]), true);
assert.equal(invocation.args.includes("-readOnly"), true);
assert.equal(invocation.args.includes("-noanalysis"), true);
assert.equal(hasSequence(invocation.args, ["-scriptPath", resolveReMcpGhidraScriptPath()]), true);
assert.equal(hasSequence(invocation.args, [
  "-postScript",
  "ReMcpInspectProgram.java",
  requestPath,
  resultPath,
]), true);
for (const forbidden of ["-import", "ReMcpPrepareProgram.java", "ReMcpImportEvidence.java", "ReMcpRecordAnalysis.java"]) {
  assert.equal(invocation.args.includes(forbidden), false, forbidden);
}
```

Also require ARM7 uses `RE-MCP_ARM7` and `arm7-inspect`.

- [ ] **Step 2: Run focused runner tests and verify RED**

```bash
npm test -- --test-name-pattern="inspection invocation|inspection timeout|inspection exit"
```

Expected: FAIL because the builder/stages do not exist.

- [ ] **Step 3: Implement inspection invocation builder**

Build exactly:

```ts
args: [
  ...projectPrefixForMap(input.map, input.workspaceRoot),
  "-process",
  ghidraProgramName(input.processor),
  "-readOnly",
  "-noanalysis",
  "-scriptPath",
  resolveReMcpGhidraScriptPath(),
  "-postScript",
  "ReMcpInspectProgram.java",
  input.requestPath,
  input.resultPath,
]
```

Use `resolveInside()` to prove request/result are under the canonical generated inspection root before constructing argv.

- [ ] **Step 4: Add failing inspection-specific runner mapping tests**

Require:

```ts
await assert.rejects(
  runGhidraInvocation(directInvocation("setInterval(() => {}, 1000)", "arm9-inspect"), config({ ghidraTimeoutMs: 100 })),
  (error) => errorCategory(error) === "ghidra-inspection-timeout",
);
await assert.rejects(
  runGhidraInvocation(directInvocation("process.exit(9)", "arm9-inspect"), config()),
  (error) => errorCategory(error) === "ghidra-inspection-failed",
);
```

Hidden `REPORT SCRIPT ERROR` at inspection stage must also map to `ghidra-inspection-failed`.

- [ ] **Step 5: Implement inspection-stage error mapping**

Add:

```ts
function isInspectionStage(stage: GhidraInvocationStage): boolean {
  return stage.endsWith("-inspect");
}
```

Timeout mapping:

```ts
const timeoutCategory = isInspectionStage(invocation.stage)
  ? "ghidra-inspection-timeout"
  : "ghidra-analysis-timeout";
```

Nonzero/script error mapping:

```ts
if (isInspectionStage(invocation.stage)) {
  throw new NdsError("ghidra-inspection-failed", message);
}
```

Keep `ghidra-project-locked` and `ghidra-output-limit` shared.

- [ ] **Step 6: Verify and commit**

```bash
npm test -- --test-name-pattern="inspection invocation|inspection timeout|inspection exit|script error"
npm run typecheck
git add src/services/nds/ghidra-runner.ts tests/nds-ghidra-runner.test.ts
git commit -m "feat: add read-only Ghidra inspection invocation"
```

---

### Task 4: Implement read-only Java function inspection and decompilation

**Files:**
- Create: `resources/ghidra/ReMcpInspectProgram.java`
- Modify: `tests/nds-ghidra-resources.test.ts`

**Interfaces / request operations:**

`inspect-function` parameters:

```json
{}
```

`decompile-function` parameters:

```json
{"maxCharacters":20000}
```

Common selector in request:

```json
{
  "processor":"arm9",
  "runtimeAddress":33554432,
  "component":"main",
  "overlayId":null,
  "addressSpace":"ram",
  "fileBacked":true,
  "bss":false,
  "compressed":false
}
```

- [ ] **Step 1: Add failing Java source-contract tests**

Require source to contain:

```ts
assert.match(source, /args\.length\s*!=\s*2/);
assert.match(source, /re-mcp-nds-ghidra-inspection/);
assert.match(source, /Program\.PROGRAM_INFO/);
assert.match(source, /re-mcp\.rom-sha256/);
assert.match(source, /re-mcp\.processor/);
assert.match(source, /FunctionManager/);
assert.match(source, /DecompInterface/);
assert.match(source, /decompileFunction/);
assert.match(source, /30/);
```

Reject mutators:

```ts
for (const forbidden of [
  /createFunction\s*\(/,
  /removeFunction\s*\(/,
  /setBody\s*\(/,
  /addMemoryReference\s*\(/,
  /createInitializedBlock\s*\(/,
  /createUninitializedBlock\s*\(/,
  /setValue\s*\(/,
  /Runtime\.getRuntime/,
  /ProcessBuilder/,
  /java\.net\./,
]) assert.doesNotMatch(source, forbidden);
```

- [ ] **Step 2: Run resource test and verify RED**

```bash
npm test -- --test-name-pattern="Ghidra inspection resource"
```

Expected: FAIL because `ReMcpInspectProgram.java` does not exist.

- [ ] **Step 3: Implement fixed request parsing and ownership validation**

The script must:

```java
String[] args = getScriptArgs();
if (args.length != 2) {
    throw new IllegalArgumentException("expected inspection request path and result path");
}
JsonObject request = readRequest(Paths.get(args[0]).toRealPath());
Path resultPath = Paths.get(args[1]).toAbsolutePath().normalize();
validateRequestEnvelope(request);
validateProgramOwnership(request);
```

Validate:

```java
format == "re-mcp-nds-ghidra-inspection"
formatVersion == 1
request.programName == currentProgram.getName()
request.sourceRomSha256 == Program Information "re-mcp.rom-sha256"
request.processor == Program Information "re-mcp.processor"
```

No script path/project path comes from request JSON.

- [ ] **Step 4: Implement address resolution inside the already-selected program**

Use the exact request `addressSpace` and unsigned 32-bit `runtimeAddress` only after Node has canonicalized them:

```java
AddressSpace space = currentProgram.getAddressFactory().getAddressSpace(addressSpaceName);
if (space == null) throw new IllegalStateException("requested canonical address space is not present");
Address address = space.getAddress(runtimeAddress);
```

Require overlay flag consistency:

```java
if (component.equals("overlay") && !space.isOverlaySpace()) throw ...;
if (component.equals("main") && space.isOverlaySpace()) throw ...;
```

- [ ] **Step 5: Implement `inspect-function` payload**

Use:

```java
Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
```

If null, return:

```json
{"found":false}
```

If present, emit:

```json
{
  "found": true,
  "entry": {"space":"ram","offset":33554432},
  "name":"FUN_02000000",
  "namespace":"Global",
  "signature":"undefined FUN_02000000(void)",
  "callingConvention":"unknown",
  "thunk":false,
  "external":false,
  "varArgs":false,
  "bodyRanges":[{"space":"ram","start":33554432,"endExclusive":33554448}],
  "bodyRangesTruncated":false,
  "entrySymbol": {"name":"FUN_02000000","source":"DEFAULT","primary":true,"dynamic":false},
  "reMcpEvidence": {
    "functionId": null,
    "functionProof": null,
    "functionMode": null,
    "overlayId": null
  }
}
```

Read RE-MCP property maps with `StringPropertyMap.getString(address)`; do not mutate them.

Iterate `function.getBody().getAddressRanges()` and stop after 256 ranges while setting `bodyRangesTruncated`.

- [ ] **Step 6: Implement `decompile-function` payload**

Require `function != null`, then:

```java
DecompInterface decompiler = new DecompInterface();
try {
    decompiler.openProgram(currentProgram);
    DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
    String c = result.decompileCompleted()
        ? result.getDecompiledFunction().getC()
        : "";
    int maxCharacters = requireBoundedInt(parameters, "maxCharacters", 1, 100000);
    boolean truncated = c.length() > maxCharacters;
    if (truncated) c = c.substring(0, maxCharacters);
    // emit completion/error fields and C text
} finally {
    decompiler.dispose();
}
```

Do not call analyzers or program mutation APIs.

- [ ] **Step 7: Implement atomic result write**

Write a sibling temporary file and move it into place:

```java
Path temporary = resultPath.resolveSibling("." + resultPath.getFileName() + ".tmp");
Files.writeString(temporary, gson.toJson(envelope) + "\n", StandardCharsets.UTF_8);
try {
    Files.move(temporary, resultPath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
} catch (AtomicMoveNotSupportedException ignored) {
    Files.move(temporary, resultPath, StandardCopyOption.REPLACE_EXISTING);
}
```

- [ ] **Step 8: Verify source contract and commit**

```bash
npm test -- --test-name-pattern="Ghidra inspection resource"
git add resources/ghidra/ReMcpInspectProgram.java tests/nds-ghidra-resources.test.ts
git commit -m "feat: add read-only Ghidra function inspection"
```

---

### Task 5: Extend Java inspection to symbols, references, and direct calls

**Files:**
- Modify: `resources/ghidra/ReMcpInspectProgram.java`
- Modify: `tests/nds-ghidra-resources.test.ts`

**Interfaces / request parameters:**

`search-symbols`:

```json
{"query":"FUN_","match":"prefix","limit":100,"offset":0}
```

`list-references`:

```json
{"direction":"both","limit":100,"offset":0}
```

`list-calls`:

```json
{"direction":"both","limit":100,"offset":0}
```

- [ ] **Step 1: Add failing source-contract tests for the three operations**

Require:

```ts
assert.match(source, /SymbolTable/);
assert.match(source, /ReferenceManager/);
assert.match(source, /getReferencesFrom/);
assert.match(source, /getReferencesTo/);
assert.match(source, /isCall\s*\(/);
assert.match(source, /search-symbols/);
assert.match(source, /list-references/);
assert.match(source, /list-calls/);
```

Continue rejecting all mutation APIs from Task 4.

- [ ] **Step 2: Run resource test and verify RED**

```bash
npm test -- --test-name-pattern="Ghidra inspection resource"
```

Expected: FAIL on missing operations.

- [ ] **Step 3: Implement deterministic symbol search**

Iterate `currentProgram.getSymbolTable().getAllSymbols(true)` and match only:

```java
exact: name.equals(query)
prefix: name.startsWith(query)
contains: name.contains(query)
```

Collect bounded records, sort by:

```text
address-space name, unsigned offset, namespace, name, symbol type
```

Apply `offset` and `limit` after deterministic sorting. Emit `totalMatches`, `returned`, `offset`, `limit`, `truncated`.

- [ ] **Step 4: Implement deterministic reference listing**

For `from`, `to`, or both, collect exact Ghidra reference fields:

```json
{
  "from":{"space":"ram","offset":33554432},
  "to":{"space":"ram","offset":33554464},
  "type":"UNCONDITIONAL_CALL",
  "source":"ANALYSIS",
  "operandIndex":0,
  "primary":true
}
```

Deduplicate exact identical records, sort by from-space/from-offset/to-space/to-offset/type/source/operand, then page.

- [ ] **Step 5: Implement depth-1 callers/callees**

Resolve the containing `Function` first. For callees, enumerate references from addresses inside the function body and keep only `reference.getReferenceType().isCall()`. Resolve target functions with `getFunctionAt()` then `getFunctionContaining()`.

For callers, enumerate `getReferencesTo(function.getEntryPoint())` and keep call references; resolve source function with `getFunctionContaining(reference.getFromAddress())`.

Emit one edge per call site and deduplicate exact duplicates. Do not recursively traverse discovered functions.

- [ ] **Step 6: Add RE-MCP call-evidence matching**

Read `re-mcp.call-evidence` at each call site. Emit:

```json
"reMcpDirectCallEvidence": <string-or-null>
```

Do not interpret Ghidra call type as canonical RE-MCP proof.

- [ ] **Step 7: Verify and commit**

```bash
npm test -- --test-name-pattern="Ghidra inspection resource"
git add resources/ghidra/ReMcpInspectProgram.java tests/nds-ghidra-resources.test.ts
git commit -m "feat: add Ghidra symbol reference and call inspection"
```

---

### Task 6: Add Node inspection orchestration, selector resolution, transport validation, and cleanup

**Files:**
- Create: `src/services/nds/ghidra-inspection.ts`
- Create: `tests/nds-ghidra-inspection.test.ts`
- Modify: `src/services/nds/ghidra-project.ts`

**Interfaces:**

```ts
export interface GhidraInspectionDependencies {
  readonly readTrustedState: typeof readTrustedGhidraInspectionState;
  readonly validateInstallation: typeof validateGhidraInstallation;
  readonly runInvocation: typeof runGhidraInvocation;
  readonly randomBytes: typeof import("node:crypto").randomBytes;
}

export interface GhidraAddressSelector {
  readonly processor: NdsProcessor;
  readonly runtimeAddress: number;
  readonly overlayId?: number;
}

export async function inspectNdsGhidraFunction(
  romPath: string,
  selector: GhidraAddressSelector,
  config: ServerConfig,
): Promise<unknown>;

export async function decompileNdsGhidraFunction(
  romPath: string,
  selector: GhidraAddressSelector & { readonly maxCharacters?: number },
  config: ServerConfig,
): Promise<unknown>;

export async function searchNdsGhidraSymbols(
  romPath: string,
  input: { readonly processor: NdsProcessor; readonly query: string; readonly match?: GhidraSymbolMatch; readonly limit?: number; readonly offset?: number },
  config: ServerConfig,
): Promise<unknown>;

export async function listNdsGhidraReferences(
  romPath: string,
  selector: GhidraAddressSelector & { readonly direction?: GhidraReferenceDirection; readonly limit?: number; readonly offset?: number },
  config: ServerConfig,
): Promise<unknown>;

export async function listNdsGhidraCalls(
  romPath: string,
  selector: GhidraAddressSelector & { readonly direction?: GhidraCallDirection; readonly limit?: number; readonly offset?: number },
  config: ServerConfig,
): Promise<unknown>;
```

- [ ] **Step 1: Write failing readiness/version orchestration tests**

Mock trusted state at Ghidra `12.1.2`; mock installation `12.1.3` and require:

```ts
await assert.rejects(
  inspectNdsGhidraFunction(romPath, selector, config, deps),
  (error) => errorCategory(error) === "ghidra-version-mismatch",
);
```

Also assert `runInvocation` is never called when readiness or version validation fails.

- [ ] **Step 2: Run focused tests and verify RED**

```bash
npm test -- --test-name-pattern="Ghidra inspection orchestration|Ghidra inspection selector|Ghidra inspection cleanup"
```

Expected: FAIL because the service does not exist.

- [ ] **Step 3: Implement canonical address selector resolution**

Use the existing canonical runtime resolver rather than duplicating range logic. Convert one exact resolution to:

```ts
{
  processor,
  runtimeAddress,
  component: "main" | "overlay",
  overlayId,
  addressSpace: component === "main" ? "ram" : ghidraOverlaySpaceName(processor, overlayId),
  fileBacked,
  bss,
  compressed,
}
```

Rules:

```ts
if (multipleCandidates && input.overlayId === undefined) throw new NdsError("ghidra-address-not-inspectable", "ambiguous ...");
if (selectedOverlay.compressed) throw new NdsError("ghidra-address-not-inspectable", "compressed overlay ...");
if (operation === "decompile-function" && (identity.bss || !identity.fileBacked)) throw new NdsError("ghidra-address-not-inspectable", "...");
```

Do not accept raw address-space strings.

- [ ] **Step 4: Add selector tests for main, overlapping overlays, compressed overlay, and BSS**

Use synthetic `NdsRomMap` fixtures to require:

- main -> `ram`;
- overlap without `overlayId` -> `ghidra-address-not-inspectable`;
- overlap + explicit valid `overlayId` -> deterministic `RE_MCP_ARM9_OVL_<id>`;
- compressed overlay -> refusal;
- BSS -> allowed for `list-references`, refused for `decompile-function`.

- [ ] **Step 5: Implement transport lifecycle**

Create request ID:

```ts
const requestId = dependencies.randomBytes(8).toString("hex");
```

Write request atomically under the generated inspection root, then build/run the fixed inspection invocation. After process success:

```ts
const parsed = JSON.parse(await readFile(resultPath, "utf8"));
const validated = validateInspectionResult(parsed, request);
```

Always cleanup in `finally`:

```ts
await Promise.all([
  rm(requestPath, { force: true }),
  rm(resultPath, { force: true }),
]).catch(() => undefined);
```

- [ ] **Step 6: Implement strict result-envelope validation**

Require exact equality for:

```ts
format
formatVersion
requestId
sourceRomSha256
processor
programName
operation
```

Malformed JSON, missing file, mismatched identity, or unsupported payload shape must throw `ghidra-inspection-result-invalid`.

Validate operation-specific payloads enough to prevent arbitrary Java output from becoming trusted structured data:

- function: boolean `found`, bounded body ranges, strings/nulls only;
- decompile: boolean completion/truncated, C string <= requested max;
- symbols/references/calls: arrays <= requested `limit`, non-negative counts and bounded address fields.

- [ ] **Step 7: Implement authority-separated public result wrappers**

For address operations return:

```ts
{
  canonical: {
    sourceRomSha256: state.map.sha256,
    processor,
    runtimeAddress,
    component,
    overlayId,
    fileBacked,
    bss,
    compressed,
  },
  reMcpEvidence: validated.payload.reMcpEvidence ?? null,
  ghidraDerived: <validated Ghidra payload without reMcpEvidence>,
}
```

For symbol search, each hit may carry `reMcpEvidence` separately, while the search result envelope remains `ghidraDerived`.

- [ ] **Step 8: Add cleanup/result-mismatch tests**

Require cleanup after:

- success;
- Ghidra nonzero failure;
- missing result file;
- malformed JSON;
- wrong request ID;
- wrong ROM SHA;
- wrong processor/program/operation.

Also mutate the source ROM between trusted-state read and return; require a final SHA check and `invalid-rom` rather than returning stale inspection data.

- [ ] **Step 9: Verify and commit**

```bash
npm test -- --test-name-pattern="Ghidra inspection orchestration|Ghidra inspection selector|Ghidra inspection cleanup|inspection result"
npm run typecheck
git add src/services/nds/ghidra-inspection.ts src/services/nds/ghidra-project.ts tests/nds-ghidra-inspection.test.ts
git commit -m "feat: orchestrate bounded Ghidra inspection"
```

---

### Task 7: Expose the five MCP inspection tools

**Files:**
- Modify: `src/tools/nds-ghidra.ts`
- Create: `tests/nds-ghidra-inspection-tools.test.ts`
- Modify: `tests/nds-ghidra-tools.test.ts`
- Modify: `src/index.ts`

**Interfaces:**

Extend `NdsGhidraToolDependencies`:

```ts
readonly inspectFunction: typeof inspectNdsGhidraFunction;
readonly decompileFunction: typeof decompileNdsGhidraFunction;
readonly searchSymbols: typeof searchNdsGhidraSymbols;
readonly listReferences: typeof listNdsGhidraReferences;
readonly listCalls: typeof listNdsGhidraCalls;
```

- [ ] **Step 1: Write failing registration test**

Require exactly seven Ghidra tools:

```ts
assert.deepEqual([...server.tools.keys()].sort(), [
  "nds_ghidra_bootstrap",
  "nds_ghidra_decompile_function",
  "nds_ghidra_inspect_function",
  "nds_ghidra_list_calls",
  "nds_ghidra_list_references",
  "nds_ghidra_search_symbols",
  "nds_ghidra_status",
]);
```

- [ ] **Step 2: Write failing schema tests**

Common address schema:

```ts
rom: z.string().min(1),
processor: z.enum(["arm9", "arm7"]),
runtimeAddress: z.number().int().min(0).max(0xffffffff),
overlayId: z.number().int().min(0).max(0xffffffff).optional(),
```

Additional exact bounds:

```ts
maxCharacters: z.number().int().min(1).max(100000).optional()
query: z.string().min(1).max(128)
match: z.enum(["exact", "prefix", "contains"]).optional()
limit: z.number().int().min(1).max(1000).optional()
offset: z.number().int().min(0).max(100000).optional()
direction: z.enum([...]).optional()
```

Explicitly assert all inspection schemas do **not** contain:

```text
executable, projectPath, programName, addressSpace, scriptPath, args, env, outputPath, ensureCurrent, bootstrap
```

- [ ] **Step 3: Run focused MCP tests and verify RED**

```bash
npm test -- --test-name-pattern="Ghidra inspection MCP|registers exactly"
```

Expected: FAIL because only bootstrap/status are registered.

- [ ] **Step 4: Register the five tools using existing workspace containment/output helpers**

Each handler must:

```ts
const romPath = resolveInside(config.workspaceRoot, rom);
const result = await dependencies.<operation>(romPath, <bounded input>, config);
return boundedTextResult(config, operation, result);
```

Use existing `ghidraErrorResult()`.

- [ ] **Step 5: Add corrective actions for every inspection category**

Examples:

```ts
case "ghidra-project-not-current":
  return "Run nds_ghidra_bootstrap for this unchanged ROM, then retry inspection after it reports a complete current project.";
case "ghidra-version-mismatch":
  return "Use the same validated Ghidra version recorded by the current SHA-scoped project, or explicitly bootstrap/reconcile the project before inspection.";
case "ghidra-address-not-inspectable":
  return "Choose one canonical main/uncompressed-overlay address; specify overlayId when static overlay ownership overlaps. Compressed overlay inspection requires a future decompression milestone.";
case "ghidra-inspection-timeout":
  return "Retry after reducing external load or adjust the bounded Ghidra subprocess timeout; inspection never enables auto-analysis.";
case "ghidra-inspection-result-invalid":
  return "Inspect the RE-MCP/Ghidra installation and generated inspection diagnostics; do not trust or reuse the invalid result artifact.";
```

- [ ] **Step 6: Update capability reporting**

In `src/index.ts`, list the five inspection tools and state:

```text
Ghidra inspection is strictly read-only, requires an already-current SHA-scoped project, runs with auto-analysis disabled, and returns Ghidra-derived information as non-authoritative.
```

- [ ] **Step 7: Verify and commit**

```bash
npm test -- --test-name-pattern="Ghidra inspection MCP|registers exactly|index registers"
npm run typecheck
git add src/tools/nds-ghidra.ts src/index.ts tests/nds-ghidra-inspection-tools.test.ts tests/nds-ghidra-tools.test.ts
git commit -m "feat: expose controlled Ghidra inspection tools"
```

---

### Task 8: Package, document, and run full regression checks

**Files:**
- Modify: `scripts/check-install.mjs`
- Modify: `.github/workflows/package.yml`
- Modify: `README.md`
- Modify: `docs/nds-ghidra-integration.md`
- Test: existing package/check-install tests and full suite

- [ ] **Step 1: Write failing package resource smoke assertion**

Require installed bundle to contain:

```text
resources/ghidra/ReMcpInspectProgram.java
```

and compiled registration source/output to include all five new tool names.

- [ ] **Step 2: Run package/source verification and verify RED**

```bash
npm run check
npm run build
```

Expected: package/check-install assertion fails until the new resource is included by the existing packaging rules/check list.

- [ ] **Step 3: Update installation/package checks**

Extend `scripts/check-install.mjs` resource list with:

```js
"resources/ghidra/ReMcpInspectProgram.java"
```

Extend package smoke to require:

```text
nds_ghidra_inspect_function
nds_ghidra_decompile_function
nds_ghidra_search_symbols
nds_ghidra_list_references
nds_ghidra_list_calls
```

No Ghidra download is allowed in normal `package.yml`.

- [ ] **Step 4: Document the inspection surface**

README and `docs/nds-ghidra-integration.md` must document:

- seven total Ghidra tools;
- strict current-project requirement;
- no automatic bootstrap;
- exact `-readOnly` + `-noanalysis` behavior;
- canonical address selectors and overlay ambiguity;
- compressed-overlay refusal;
- authority separation (`canonical`, `reMcpEvidence`, `ghidraDerived`);
- decompiler/symbol/reference/call bounds;
- all new structured error categories;
- no Ghidra-derived promotion and no debugger behavior changes.

- [ ] **Step 5: Run full verification**

```bash
npm run check
npm run build
```

Expected: PASS with zero test failures/type errors/build errors.

- [ ] **Step 6: Review final diff for forbidden scope**

Require no changes to:

```text
src/services/desmume-gdb.ts
src/services/debug-controller.ts
src/services/owned-process.ts
```

and no new runtime dependency unless an already-existing package mechanism requires metadata-only packaging changes.

Run:

```bash
git diff --name-only main...HEAD
git diff -- package.json package-lock.json src/services/desmume-gdb.ts src/services/debug-controller.ts src/services/owned-process.ts
```

Expected: debugger diff empty; dependency diff empty.

- [ ] **Step 7: Commit**

```bash
git add scripts/check-install.mjs .github/workflows/package.yml README.md docs/nds-ghidra-integration.md
git commit -m "docs: document controlled Ghidra inspection"
```

---

### Task 9: Extend real Ghidra 12.1.2 acceptance for byte-preserving inspection

**Files:**
- Modify: `scripts/ghidra-acceptance.mjs`
- Optional temporary acceptance workflow only during PR verification; delete it before merge.

- [ ] **Step 1: Add project-content hashing helper**

After the normal bootstrap/analyst-marker setup, recursively hash regular persistent project files under the SHA-scoped project root while excluding transient lock names only:

```js
const TRANSIENT_PROJECT_FILES = new Set(["project.lock", ".lock"]);
```

Produce a sorted `{ relativePath, sha256, size }[]` snapshot. Do not compare mtimes.

- [ ] **Step 2: Add real inspection acceptance calls**

Using the fixture's known ARM9 entry/direct-call addresses, invoke the production inspection services/tools and require:

```js
functionResult.ghidraDerived.found === true
decompileResult.ghidraDerived.completed === true
typeof decompileResult.ghidraDerived.c === "string"
symbolResult.ghidraDerived.results.length > 0
referenceResult.ghidraDerived.results.some((ref) => ref.type.includes("CALL"))
callResult.ghidraDerived.edges.length > 0
```

Also inspect each of the two overlapping ARM9 overlays by explicit `overlayId` and require distinct deterministic address-space names despite identical numeric runtime bases.

- [ ] **Step 3: Verify analyst marker persistence and byte equality**

After all five operations:

```js
assert.deepEqual(await snapshotProject(projectRoot), projectBeforeInspection);
```

Then use the existing marker-verification path to require the analyst marker still exists.

If Ghidra creates transient files that survive process exit, identify and exclude only exact documented lock/temp names; do not broadly ignore `.rep` content changes.

- [ ] **Step 4: Reject hidden Ghidra errors**

Keep/extend application-log checks so acceptance fails on:

```text
REPORT SCRIPT ERROR
Exception
```

unless a line is an explicitly known benign fixture diagnostic already accepted by the existing script.

- [ ] **Step 5: Run real acceptance against official Ghidra 12.1.2 + JDK 21**

Use the existing pinned archive and SHA:

```text
ghidra_12.1.2_PUBLIC_20260605.zip
b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d
```

Expected: bootstrap + all five inspection operations + byte-preservation checks pass.

- [ ] **Step 6: Remove any temporary PR-trigger workflow**

If a temporary workflow was added to obtain real acceptance, delete it before the merge-ready head. Keep only the existing manual/workflow-dispatch acceptance mechanism.

- [ ] **Step 7: Run final normal CI/package verification on cleaned head**

```bash
npm run check
npm run build
```

Then require GitHub CI and Package workflows to succeed on the exact cleaned head.

- [ ] **Step 8: Commit final acceptance changes**

```bash
git add scripts/ghidra-acceptance.mjs
git commit -m "test: verify read-only Ghidra inspection"
```

---

## Final verification checklist

Before opening or marking the implementation PR merge-ready:

- [ ] `npm run check` passes on the final cleaned head.
- [ ] `npm run build` passes on the final cleaned head.
- [ ] Package smoke succeeds with `ReMcpInspectProgram.java` included.
- [ ] All seven Ghidra tools are registered; only five are inspection tools.
- [ ] Every inspection invocation contains `-readOnly` and `-noanalysis`.
- [ ] No inspection invocation contains `-import` or bootstrap mutation scripts.
- [ ] Strict trusted-state tests cover project/state/bridge/failure/version mismatches.
- [ ] Canonical selector tests cover main, overlapping overlays, explicit overlay identity, compressed overlays, and BSS.
- [ ] Java source contract rejects all listed mutator/process/network APIs.
- [ ] Results preserve `canonical`, `reMcpEvidence`, and `ghidraDerived` authority boundaries.
- [ ] Request/result transport files are cleaned on every exit path.
- [ ] Source ROM SHA is checked after inspection before returning.
- [ ] Real Ghidra 12.1.2 acceptance passes all five operations.
- [ ] Persistent Ghidra project non-transient file hashes are unchanged before vs after inspection.
- [ ] Analyst marker survives inspection.
- [ ] No debugger/GDB/process-lifecycle production file changed.
- [ ] No new runtime dependency was added.
- [ ] Temporary PR-trigger acceptance workflow, if used, is removed before merge.
