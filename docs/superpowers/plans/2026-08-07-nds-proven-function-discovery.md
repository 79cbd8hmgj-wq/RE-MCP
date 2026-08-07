# NDS Proven Function Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add bounded, read-only Nintendo DS proven-function discovery and focused function analysis using only program-entry and resolved direct-call evidence.

**Architecture:** Build a small function-analysis layer on top of the existing canonical NDS code-source resolver, CFG analyzer, and proven-reference/xref machinery. Keep canonical identity/evidence, scope/seed validation, graph discovery, and focused proof composition in separate services; expose only `nds_discover_functions` and `nds_analyze_function` through the existing `src/tools/nds.ts` MCP surface.

**Tech Stack:** TypeScript 5.7+, Node.js >=20, Node test runner, Zod, `@alexaltea/capstone-js` 5.0.9, existing RE-MCP NDS parser/resolver/disassembly/CFG/reference services.

## Global Constraints

- Proven function entry sources are only `program-entry` and deterministic resolved `direct-call` targets.
- Direct branches, conditional branches, indirect calls, returns, alignment, prologue-like bytes, and explicit seeds do not prove functions.
- Explicit seeds are coverage-only unless independently proven.
- No function-end or exclusive byte-range ownership claims.
- No tail-call inference, indirect-target recovery, register propagation, jump-table recovery, symbol inference, persistent function index, overlay decompression, debugger integration, ROM mutation, or caller-controlled output paths.
- Preserve processor/component/overlay/mode identity and canonical ambiguity semantics.
- Compressed overlays remain `compressed-overlay-not-decodable` coverage gaps.
- All ROM reads remain SHA-validated and read-only.
- `nds_discover_functions` limits: components 32/128, functions 128/1024, direct call sites 512/8192, blocks 512/4096, instructions 4096/32768, decoded bytes 32 KiB/256 KiB, traversal edges 2048/16384.
- Per-function CFG limits: blocks 64/256, instructions 512/4096, bytes 2 KiB/16 KiB, edges 128/1024.
- `nds_analyze_function` proof limits: components 32/128, blocks 128/512, instructions 2048/16384, bytes 8 KiB/64 KiB, edges 512/4096, proof sites 256/2048.
- Focused target CFG uses the same existing CFG defaults/maxima: 64/256 blocks, 512/4096 instructions, 2 KiB/16 KiB bytes, 128/1024 edges.
- Both tools must obey `RE_MCP_MAX_OUTPUT_BYTES`.
- The physical Intel macOS Catalina/DeSmuME debugger acceptance gate remains separate and unchanged.

---

## File Structure

**Create**

- `src/services/nds/function-model.ts` — canonical proven-function identity, proof, call-edge, coverage, ordering, and helper keys.
- `src/services/nds/function-source.ts` — function scope parsing/canonicalization, component ordering, explicit coverage-seed validation, and program-entry canonicalization.
- `src/services/nds/function-discovery.ts` — globally bounded proven-function/call-graph walk and coverage accounting.
- `src/services/nds/function-analysis.ts` — focused proof search and target CFG composition with `proven` / `not-proven-function-entry` / `proof-inconclusive` semantics.
- `tests/nds-function-model.test.ts`
- `tests/nds-function-source.test.ts`
- `tests/nds-function-discovery.test.ts`
- `tests/nds-function-analysis.test.ts`

**Modify**

- `src/services/nds/errors.ts` — add function-analysis error categories to `AnyNdsErrorCategory`.
- `src/tools/nds.ts` — add schemas, normalization, tool registrations, limit defaults/maxima, and corrective actions for both public tools.
- `tests/nds-tools.test.ts` — verify schemas, tool registration, errors, output bounds, and packaged tool result shape.
- `scripts/check-install.mjs` — packaged smoke scenario for deterministic proven-function behavior.
- `README.md` — document the new static-analysis workflow, proof semantics, coverage limits, and deferred scope.

---

### Task 1: Canonical Function Identity and Evidence Model

**Files:**
- Create: `src/services/nds/function-model.ts`
- Create: `tests/nds-function-model.test.ts`

**Interfaces:**
- Consumes: `ArmMode` from `src/services/disassembly/backend.ts`, `NdsProcessor` from `src/services/nds/overlays.ts`, and canonical code-source fields already exposed by `NdsCodeSource`.
- Produces:

```ts
export interface ProvenFunctionIdentity {
  readonly processor: NdsProcessor;
  readonly component: "main" | "overlay";
  readonly overlayId: number | null;
  readonly runtimeAddress: number;
  readonly romOffset: number;
  readonly mode: ArmMode;
}

export type FunctionProof =
  | {
      readonly kind: "program-entry";
      readonly processor: NdsProcessor;
      readonly headerEntryAddress: number;
    }
  | {
      readonly kind: "direct-call";
      readonly caller: {
        readonly functionId: string | null;
        readonly component: "main" | "overlay";
        readonly overlayId: number | null;
        readonly instructionAddress: number;
        readonly instructionRomOffset: number;
        readonly mode: ArmMode;
      };
      readonly target: ProvenFunctionIdentity;
    };

export interface ProvenFunctionCallEdge {
  readonly callerFunctionId: string;
  readonly instructionAddress: number;
  readonly instructionRomOffset: number;
  readonly calleeFunctionId: string;
}

export type FunctionComponentCoverageStatus =
  | "scanned"
  | "no-proven-seed"
  | "compressed-overlay-not-decodable"
  | "out-of-limit";

export function provenFunctionId(identity: ProvenFunctionIdentity): string;
export function compareProvenFunctionIdentity(left: ProvenFunctionIdentity, right: ProvenFunctionIdentity): number;
export function compareFunctionProof(left: FunctionProof, right: FunctionProof): number;
export function compareFunctionCallEdge(left: ProvenFunctionCallEdge, right: ProvenFunctionCallEdge): number;
```

- [ ] **Step 1: Write failing ordering and identity tests**

Add tests that assert:

```ts
assert.equal(
  provenFunctionId({
    processor: "arm9",
    component: "overlay",
    overlayId: 7,
    runtimeAddress: 0x02200000,
    romOffset: 0x1200,
    mode: "thumb",
  }),
  "arm9:overlay:7:02200000:thumb",
);
```

Also assert deterministic ordering: ARM9 before ARM7, main before overlay, lower overlay ID before higher, lower address before higher, ARM before Thumb; `program-entry` proof before `direct-call`; call edges by caller ID then call-site address then callee ID.

- [ ] **Step 2: Run the focused test and verify failure**

Run:

```bash
npm test -- --test-name-pattern="proven function identity|function proof ordering|function call edge ordering"
```

Expected: FAIL because `function-model.ts` and exported helpers do not exist.

- [ ] **Step 3: Implement the canonical model and comparators**

Use zero-padded eight-digit lower-case hex runtime addresses in IDs:

```ts
function hex32(value: number): string {
  return (value >>> 0).toString(16).padStart(8, "0");
}
```

Use fixed processor/component/mode order maps and simple numeric/string comparison helpers. Do not infer or validate code ownership in this file; this file is model/ordering only.

- [ ] **Step 4: Run the focused test**

Run:

```bash
npm test -- --test-name-pattern="proven function identity|function proof ordering|function call edge ordering"
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/services/nds/function-model.ts tests/nds-function-model.test.ts
git commit -m "feat: add canonical NDS function model"
```

---

### Task 2: Function Scope and Coverage-Seed Canonicalization

**Files:**
- Create: `src/services/nds/function-source.ts`
- Create: `tests/nds-function-source.test.ts`
- Modify: `src/services/nds/errors.ts`

**Interfaces:**
- Consumes: `NdsRomMap`, `NdsProcessor`, `NdsCodeSource`, `resolveNdsCodeSource`, overlay metadata, and `ProvenFunctionIdentity`.
- Produces:

```ts
export type FunctionSearchScope =
  | { readonly kind: "main" }
  | { readonly kind: "overlay"; readonly overlayIds: readonly number[] }
  | { readonly kind: "main-and-overlays"; readonly overlayIds: readonly number[] }
  | { readonly kind: "all-executable-components" };

export interface FunctionSearchSeed {
  readonly runtimeAddress: number;
  readonly mode: ArmMode;
  readonly overlayId?: number;
}

export interface FunctionComponentIdentity {
  readonly processor: NdsProcessor;
  readonly component: "main" | "overlay";
  readonly overlayId: number | null;
  readonly compressed: boolean;
}

export interface PreparedFunctionSearch {
  readonly components: readonly FunctionComponentIdentity[];
  readonly explicitSeeds: readonly NdsCodeSource[];
  readonly programEntry: {
    readonly identity: ProvenFunctionIdentity;
    readonly source: NdsCodeSource;
    readonly proof: Extract<FunctionProof, { readonly kind: "program-entry" }>;
  } | null;
}

export function prepareFunctionSearch(
  map: NdsRomMap,
  processor: NdsProcessor,
  scope: FunctionSearchScope,
  seeds: readonly FunctionSearchSeed[],
): PreparedFunctionSearch;

export function canonicalizeFunctionTarget(
  map: NdsRomMap,
  processor: NdsProcessor,
  runtimeAddress: number,
  mode: ArmMode,
  allowedComponents: ReadonlySet<string>,
): ProvenFunctionIdentity | null;
```

Add error categories:

```ts
export type NdsFunctionErrorCategory =
  | "invalid-function-scope"
  | "invalid-function-seed"
  | "function-entry-not-uniquely-resolved"
  | "function-discovery-limit-exceeded";
```

and include them in `AnyNdsErrorCategory`.

- [ ] **Step 1: Write failing scope/seed tests**

Cover:

- `main`, selected overlays, `main-and-overlays`, and `all-executable-components` canonical ordering;
- duplicate overlay IDs rejected with `invalid-function-scope`;
- unknown overlay ID rejected;
- explicit ARM/Thumb seed aligned correctly and resolving uniquely;
- BSS-only, compressed, out-of-scope, wrong-overlay, misaligned, and ambiguous seeds rejected with `invalid-function-seed`;
- duplicate canonical seeds deduplicated;
- selected main yields one ARM-mode program-entry proof;
- overlay-only scope yields `programEntry: null`;
- canonical direct-call target returns `null` for compressed/BSS/unmapped/ambiguous/out-of-scope targets.

Use existing `createNdsFixture`, `writeFatEntry`, and `writeOverlayRecord` helpers rather than creating a new fixture format.

- [ ] **Step 2: Run focused tests and verify failure**

Run:

```bash
npm test -- --test-name-pattern="function search scope|function seed|program entry|canonical function target"
```

Expected: FAIL because source preparation functions/error categories do not exist.

- [ ] **Step 3: Implement scope preparation and target canonicalization**

Reuse the same validation philosophy as `xref-source.ts`:

- enumerate canonical selected components for one processor;
- mark compressed overlays but never decode them;
- resolve seeds through `resolveNdsCodeSource` with explicit mode and optional overlay disambiguation;
- require exact initialized file-backed source and alignment;
- deduplicate by processor/component/overlay/address/mode key;
- canonicalize main header entry in ARM mode only when main is selected.

Do not treat explicit seeds as function identities/proofs.

- [ ] **Step 4: Run focused tests**

```bash
npm test -- --test-name-pattern="function search scope|function seed|program entry|canonical function target"
```

Expected: PASS.

- [ ] **Step 5: Run typecheck**

```bash
npm run typecheck
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/services/nds/function-source.ts src/services/nds/errors.ts tests/nds-function-source.test.ts
git commit -m "feat: add NDS function search sources"
```

---

### Task 3: Proven Function Discovery Graph

**Files:**
- Create: `src/services/nds/function-discovery.ts`
- Create: `tests/nds-function-discovery.test.ts`

**Interfaces:**
- Consumes: `prepareFunctionSearch`, `canonicalizeFunctionTarget`, `analyzeNdsControlFlow`, `StaticControlFlowGraph`, `ProvenFunctionIdentity`, `FunctionProof`, and `ProvenFunctionCallEdge`.
- Produces:

```ts
export interface FunctionDiscoveryLimits {
  readonly maxComponents: number;
  readonly maxFunctions: number;
  readonly maxCallSites: number;
  readonly maxTotalBlocks: number;
  readonly maxTotalInstructions: number;
  readonly maxTotalBytes: number;
  readonly maxTotalEdges: number;
  readonly perFunctionCfg: ControlFlowLimits;
}

export type FunctionDiscoveryTruncationReason =
  | "component-limit"
  | "function-limit"
  | "call-site-limit"
  | "block-limit"
  | "instruction-limit"
  | "byte-limit"
  | "edge-limit";

export interface DiscoveredFunction {
  readonly id: string;
  readonly entry: ProvenFunctionIdentity;
  readonly evidence: readonly FunctionProof[];
  readonly directCallerCount: number;
  readonly directCallSiteCount: number;
  readonly cfg: {
    readonly status: "complete" | "truncated";
    readonly truncationReasons: readonly string[];
    readonly blocks: number;
    readonly instructions: number;
    readonly decodedBytes: number;
    readonly traversalEdges: number;
    readonly returnSites: number;
    readonly unresolvedEdges: number;
  };
}

export interface DiscoverNdsFunctionsRequest {
  readonly processor: NdsProcessor;
  readonly scope: FunctionSearchScope;
  readonly seeds: readonly FunctionSearchSeed[];
}

export interface DiscoverNdsFunctionsResult {
  readonly status: "complete" | "partial-coverage" | "truncated";
  readonly processor: NdsProcessor;
  readonly functions: readonly DiscoveredFunction[];
  readonly calls: readonly ProvenFunctionCallEdge[];
  readonly coverage: readonly {
    readonly component: "main" | "overlay";
    readonly overlayId: number | null;
    readonly status: FunctionComponentCoverageStatus;
  }[];
  readonly truncationReasons: readonly FunctionDiscoveryTruncationReason[];
  readonly totals: {
    readonly functions: number;
    readonly callSites: number;
    readonly blocks: number;
    readonly instructions: number;
    readonly decodedBytes: number;
    readonly traversalEdges: number;
  };
}

export async function discoverNdsFunctions(
  map: NdsRomMap,
  request: DiscoverNdsFunctionsRequest,
  limits: FunctionDiscoveryLimits,
  backend: ArmDisassemblyBackend,
): Promise<DiscoverNdsFunctionsResult>;
```

- [ ] **Step 1: Write failing positive discovery tests**

Use a `FakeBackend` matching `tests/nds-xrefs.test.ts`. Cover:

```text
program entry -> BL function A -> BL function B
```

Assert:

- all three entries are proven once;
- program entry has `program-entry` evidence;
- A/B have `direct-call` evidence;
- call edges preserve each call-site address;
- direct caller/call-site counts are correct;
- direct branch-reachable blocks can contain calls that prove callees;
- ARM and Thumb identities remain distinct and correct;
- program-entry and direct-call evidence can coexist for the same entry.

- [ ] **Step 2: Write failing non-proof and recursion tests**

Cover:

- direct branch target does not become a function;
- indirect call does not become a function;
- return does not create a function/end;
- unproven explicit seed remains absent from `functions` but can expose a direct call proving another target;
- self recursion produces one function and one recursive call edge;
- mutual recursion produces two functions without repeated CFG analysis;
- duplicate explicit seeds and duplicate traversal paths do not duplicate work/evidence sites.

- [ ] **Step 3: Run focused discovery tests and verify failure**

```bash
npm test -- --test-name-pattern="discover NDS functions|function recursion|coverage-only seed"
```

Expected: FAIL because `discoverNdsFunctions` does not exist.

- [ ] **Step 4: Implement discovery traversal**

Implement two queues internally:

```ts
type ScheduledWork =
  | { kind: "function"; identity: ProvenFunctionIdentity }
  | { kind: "coverage"; source: NdsCodeSource };
```

Requirements:

- canonical function identity is the function visited key;
- canonical source block identity is the coverage visited key;
- program entry is inserted as a proven function before traversal;
- coverage-only seed traversal may discover direct calls but never creates a function for the seed;
- for function work, call `analyzeNdsControlFlow` and inspect its `calls` array; only resolved direct calls with non-null `targetAddress`, `targetMode`, and `resolution.status === "resolved"` may be canonicalized into function proof;
- preserve per-function CFG truncation independently from global truncation;
- count return sites from `unresolvedEdges.kind === "return"`;
- count unresolved exits from the complete `unresolvedEdges` array;
- preserve exact direct call-site evidence and deduplicate by source instruction + canonical target;
- only emit `ProvenFunctionCallEdge` when caller is a proven function;
- calls discovered from coverage-only seeds produce proof with `caller.functionId: null` but no call-graph edge;
- never traverse out-of-scope callees.

- [ ] **Step 5: Add failing overlay/coverage tests**

Cover selected main + one uncompressed overlay + one compressed overlay:

- valid explicit overlay coverage seed => overlay `scanned`;
- unseeded selected overlay => `no-proven-seed`;
- compressed selected overlay => `compressed-overlay-not-decodable`;
- unique direct call into selected overlay => proven overlay function;
- ambiguous overlay call target => no function identity created;
- result status becomes `partial-coverage` when no global truncation exists but selected coverage is incomplete.

- [ ] **Step 6: Implement coverage accounting**

Reuse the xref coverage vocabulary and deterministic component order. `truncated` takes precedence over `partial-coverage`; otherwise any non-`scanned` selected component yields `partial-coverage`.

- [ ] **Step 7: Add failing aggregate limit tests**

Create one small graph fixture per cap and assert each reason independently:

```text
component-limit
function-limit
call-site-limit
block-limit
instruction-limit
byte-limit
edge-limit
```

Also create one fixture that exhausts at least two budgets in the same operation and assert all applicable reasons are returned in fixed order.

- [ ] **Step 8: Implement aggregate budget enforcement**

Before scheduling/retaining work that would exceed a budget, add the relevant reason and stop that expansion safely. Global totals must count canonical decoded/analyzed work once and not increase on duplicate scheduling.

- [ ] **Step 9: Run discovery tests and typecheck**

```bash
npm test -- --test-name-pattern="discover NDS functions|function recursion|coverage-only seed|function discovery limit|function coverage"
npm run typecheck
```

Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add src/services/nds/function-discovery.ts tests/nds-function-discovery.test.ts
git commit -m "feat: add bounded NDS function discovery"
```

---

### Task 4: Focused Function Proof and Analysis

**Files:**
- Create: `src/services/nds/function-analysis.ts`
- Create: `tests/nds-function-analysis.test.ts`

**Interfaces:**
- Consumes: `findNdsXrefs`, `analyzeNdsControlFlow`, `prepareFunctionSearch`, canonical target resolution, function model helpers, and existing reference-scan limits.
- Produces:

```ts
export interface AnalyzeNdsFunctionRequest {
  readonly processor: NdsProcessor;
  readonly runtimeAddress: number;
  readonly mode: ArmMode;
  readonly overlayId?: number;
  readonly proofScope: FunctionSearchScope;
  readonly seeds: readonly FunctionSearchSeed[];
}

export interface AnalyzeFunctionLimits {
  readonly proof: ReferenceScanLimits;
  readonly cfg: ControlFlowLimits;
}

export type AnalyzeFunctionProofStatus =
  | "proven"
  | "not-proven-function-entry"
  | "proof-inconclusive";

export interface AnalyzeNdsFunctionResult {
  readonly proofStatus: AnalyzeFunctionProofStatus;
  readonly entry: ProvenFunctionIdentity;
  readonly evidence: readonly FunctionProof[];
  readonly proofSearch: {
    readonly status: "complete" | "partial-coverage" | "truncated";
    readonly coverage: readonly FunctionComponentCoverage[];
    readonly truncationReasons: readonly string[];
  };
  readonly cfg: StaticControlFlowGraph | null;
  readonly callers: readonly FunctionProof[];
  readonly outgoingCalls: readonly StaticCallEdge[];
  readonly returnSites: readonly number[];
  readonly unresolvedExits: readonly StaticUnresolvedEdge[];
}

export async function analyzeNdsFunction(
  map: NdsRomMap,
  request: AnalyzeNdsFunctionRequest,
  limits: AnalyzeFunctionLimits,
  backend: ArmDisassemblyBackend,
): Promise<AnalyzeNdsFunctionResult>;
```

- [ ] **Step 1: Write failing program-entry and direct-call proof tests**

Assert:

- exact main ARM header entry returns `proofStatus: "proven"` with `program-entry` proof and a non-null CFG;
- a direct-call target returns `proven` with direct caller evidence;
- target mode and canonical component identity must match the call target;
- if proof is found before unrelated coverage truncates, result remains `proven` and still reports incomplete coverage metadata.

- [ ] **Step 2: Write failing negative/inconclusive tests**

Assert:

- a complete proof search with no qualifying call returns `not-proven-function-entry`, `cfg: null`;
- byte/block/instruction/edge/result truncation without proof returns `proof-inconclusive`;
- compressed or no-seed selected coverage without proof returns `proof-inconclusive`;
- direct branch-only reference does not prove the target;
- ambiguous requested entry yields `function-entry-not-uniquely-resolved` rather than a semantic proof status.

- [ ] **Step 3: Run focused tests and verify failure**

```bash
npm test -- --test-name-pattern="analyze NDS function|proof-inconclusive|not-proven-function-entry"
```

Expected: FAIL because `analyzeNdsFunction` does not exist.

- [ ] **Step 4: Implement proof composition**

Procedure:

1. Canonicalize requested target using processor/address/mode/optional overlay and require unique uncompressed file-backed code.
2. If exact main header ARM entry, synthesize `program-entry` proof without reverse search.
3. Otherwise call `findNdsXrefs` against the exact runtime target and selected scope/seeds.
4. Retain only `reference.kind === "direct-call"` whose resolved canonical target identity equals the requested identity including mode/component/overlay.
5. If any proof exists, set `proofStatus = "proven"` even when proof search is partial/truncated.
6. If no proof and xref search is `complete` with all selected coverage `scanned`, set `not-proven-function-entry`.
7. Otherwise set `proof-inconclusive`.
8. Run `analyzeNdsControlFlow` only when `proven`; return CFG/calls/return/unresolved metadata.

Do not reinterpret direct branches as proof.

- [ ] **Step 5: Run focused tests and typecheck**

```bash
npm test -- --test-name-pattern="analyze NDS function|proof-inconclusive|not-proven-function-entry"
npm run typecheck
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/services/nds/function-analysis.ts tests/nds-function-analysis.test.ts
git commit -m "feat: add focused NDS function analysis"
```

---

### Task 5: MCP Tool Schemas, Errors, and Output Bounds

**Files:**
- Modify: `src/tools/nds.ts`
- Modify: `tests/nds-tools.test.ts`

**Interfaces:**
- Consumes: `discoverNdsFunctions`, `analyzeNdsFunction`, new function scope/seed types, and existing `boundedTextResult`/`ndsErrorResult` conventions.
- Produces public tools:

```text
nds_discover_functions
nds_analyze_function
```

- [ ] **Step 1: Write failing tool-registration/schema tests**

Add tests that assert both tools register and enforce:

- `rom` non-empty string;
- processor `arm9|arm7`;
- function scope discriminated union identical to spec;
- explicit seeds max 128 and mode `arm|thumb`;
- discovery defaults/maxima exactly match the approved table;
- proof defaults/maxima exactly match the approved table;
- CFG defaults/maxima exactly match existing CFG values;
- invalid zero/negative/over-max values are rejected before service execution.

- [ ] **Step 2: Add failing error/result-shape tests**

Assert corrective actions for:

```text
invalid-function-scope
invalid-function-seed
function-entry-not-uniquely-resolved
function-discovery-limit-exceeded
```

Also assert serialized successful results go through `boundedTextResult`, and a deliberately tiny `maxOutputBytes` returns the existing `output-bound-exceeded` category.

- [ ] **Step 3: Run tool tests and verify failure**

```bash
npm test -- --test-name-pattern="NDS function tool|function discovery schema|function analysis schema|function error corrective action"
```

Expected: FAIL because tools/schemas/corrective actions are not registered.

- [ ] **Step 4: Add Zod schemas and normalizers**

Add constants in `src/tools/nds.ts`:

```ts
const functionComponentLimitSchema = z.number().int().min(1).max(128).default(32);
const functionLimitSchema = z.number().int().min(1).max(1024).default(128);
const functionCallSiteLimitSchema = z.number().int().min(1).max(8192).default(512);
const functionBlockLimitSchema = z.number().int().min(1).max(4096).default(512);
const functionInstructionLimitSchema = z.number().int().min(1).max(32768).default(4096);
const functionByteLimitSchema = z.number().int().min(2).max(262144).default(32768);
const functionEdgeLimitSchema = z.number().int().min(1).max(16384).default(2048);
```

Reuse existing CFG schemas for per-function/target CFG. Reuse xref-scale schemas for focused proof search where maxima/defaults match; introduce distinct names only where semantic clarity improves the tool contract.

- [ ] **Step 5: Register `nds_discover_functions`**

Handler sequence:

```ts
const map = await readNdsRomMap(resolveRom(config, rom));
const backend = await createCapstoneArmBackend();
try {
  const result = await discoverNdsFunctions(map, request, limits, backend);
  return boundedTextResult(config, operation, result);
} finally {
  backend.close();
}
```

Follow the repository's existing backend lifecycle exactly; if the current tool code uses a helper instead of direct `try/finally`, use that existing helper.

- [ ] **Step 6: Register `nds_analyze_function`**

Build `AnalyzeFunctionLimits` from proof and CFG schema fields, call the service, and return through `boundedTextResult`.

- [ ] **Step 7: Extend corrective actions**

Add precise messages:

```text
invalid-function-scope -> select main/existing overlays/all executable components without duplicate overlay IDs
invalid-function-seed -> use an aligned ARM/Thumb seed resolving uniquely to selected uncompressed file-backed code
function-entry-not-uniquely-resolved -> provide processor/mode/overlay details that select one exact initialized executable source
function-discovery-limit-exceeded -> use positive bounded function-discovery/proof limits within documented maxima
```

- [ ] **Step 8: Run tool tests and full typecheck**

```bash
npm test -- --test-name-pattern="NDS function tool|function discovery schema|function analysis schema|function error corrective action"
npm run typecheck
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add src/tools/nds.ts tests/nds-tools.test.ts
git commit -m "feat: expose NDS function analysis tools"
```

---

### Task 6: Packaged Smoke Acceptance and Documentation

**Files:**
- Modify: `scripts/check-install.mjs`
- Modify: `README.md`

**Interfaces:**
- Consumes: assembled production package and new MCP tool registrations.
- Produces: one package-install smoke scenario that proves deterministic program-entry/direct-call function discovery plus user-facing documentation.

- [ ] **Step 1: Add a failing package-smoke assertion**

Extend the existing NDS package fixture so packaged execution exercises at least one deterministic call chain:

```text
ARM9 entry -> direct call -> second proven function
```

Assert the packaged server/tool path reports exactly the expected proven function entries and does not promote a branch-only target.

- [ ] **Step 2: Run package smoke and verify failure**

Use the repository's current package-smoke command/path from `scripts/check-install.mjs`. If no dedicated npm script exists, run:

```bash
npm run build
node scripts/check-install.mjs
```

Expected before implementation wiring is complete: FAIL on missing new function assertion/tool.

- [ ] **Step 3: Complete packaged smoke fixture/tool invocation**

Keep smoke bounded and deterministic. It must use the packaged Capstone.js/WASM backend, not a fake backend.

- [ ] **Step 4: Update README static-analysis workflow**

Document this order:

```text
nds_inspect_rom
-> nds_list_files / nds_list_overlays / address resolution
-> nds_search_pattern
-> nds_disassemble_range
-> nds_list_references
-> nds_analyze_control_flow
-> nds_find_xrefs
-> nds_discover_functions / nds_analyze_function
-> controlled extraction / analysis bundle
```

Explicitly state:

- entries are proven only by program-entry/direct-call evidence;
- ends are not inferred;
- explicit seeds are coverage hints, not proof;
- branches do not create functions;
- indirect calls stay unresolved;
- compressed overlays are coverage gaps;
- static function discovery is independent of pending Catalina debugger acceptance;
- heuristic function discovery, symbols, Ghidra bridge, decompression, runtime overlay state, and mutation remain deferred.

- [ ] **Step 5: Run package smoke**

```bash
npm run build
node scripts/check-install.mjs
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add scripts/check-install.mjs README.md
git commit -m "docs: document NDS proven function discovery"
```

---

### Task 7: Full Verification and Pull Request

**Files:**
- Review all files changed by Tasks 1-6.

**Interfaces:**
- Consumes: complete milestone branch.
- Produces: verified PR ready for review/merge; no merge performed automatically unless separately authorized.

- [ ] **Step 1: Run the full repository test suite**

```bash
npm test
```

Expected: PASS with no skipped/failed tests caused by the milestone.

- [ ] **Step 2: Run typecheck**

```bash
npm run typecheck
```

Expected: PASS.

- [ ] **Step 3: Run build**

```bash
npm run build
```

Expected: PASS.

- [ ] **Step 4: Run packaged install smoke**

```bash
node scripts/check-install.mjs
```

Expected: PASS.

- [ ] **Step 5: Review the final diff against the spec**

Confirm all of the following before opening the PR:

```text
[ ] only program entry/direct calls prove functions
[ ] explicit seeds remain coverage-only
[ ] no function-end fields/claims were introduced
[ ] branch-only and indirect-call targets are not functions
[ ] recursion terminates deterministically
[ ] ambiguity/compression/BSS remain conservative
[ ] all aggregate limits have tests
[ ] proof-inconclusive and complete-negative semantics are distinct
[ ] output bounds and SHA checks remain intact
[ ] no debugger behavior changed
[ ] README deferred-scope list remains accurate
```

- [ ] **Step 6: Commit any final test/doc-only corrections**

If verification required corrections, commit only those verified changes with a narrow message such as:

```bash
git commit -am "test: tighten NDS function discovery acceptance"
```

Do not create an empty commit when no corrections are needed.

- [ ] **Step 7: Open the PR**

PR title:

```text
Add proven NDS function discovery
```

PR body must summarize:

- two new read-only MCP tools;
- strict proof sources and explicit non-proof cases;
- aggregate/per-function/proof bounds;
- coverage/inconclusive semantics;
- package smoke and test coverage;
- explicit statement that physical Catalina debugger acceptance remains separate.

- [ ] **Step 8: Check CI once after the final meaningful branch commit**

Inspect the PR head's workflow runs once. If a job fails, inspect the failed job logs, fix the concrete issue, rerun verification, and push one corrective commit. Avoid tight polling loops.
