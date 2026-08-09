# Controlled NDS Runtime Correlation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correlate one current stopped server-owned DeSmuME ARM9 state with the exact launched NDS ROM, canonical static ownership, bounded ARM/Thumb analysis, existing proven function evidence, and optional already-ready read-only Ghidra context.

**Architecture:** PR A binds every owned emulator generation to a full launch-time ROM SHA-256 and adds one pure correlation service plus one live MCP orchestration tool. PR B layers opt-in Ghidra enrichment on top of the already-established canonical candidate identity; it never bootstraps, reconciles, mutates, or uses Ghidra to decide canonical ownership.

**Tech Stack:** Node.js 20+, TypeScript 5.7, existing MCP SDK/Zod, existing Capstone.js ARM decoder, existing NDS parser/resolver/disassembly/reference/function services, existing controlled Ghidra 12.1.2/JDK 21 inspection infrastructure, Node test runner with `tsx`.

## Global Constraints

- The milestone is read-only.
- Do not add watchpoints, register writes, memory writes, arbitrary GDB packets, conditional breakpoint scripting, repeated-step tracing, ROM mutation, or Ghidra mutation.
- `nds_correlate_stop_context` accepts no caller-selected ROM path, processor, PC, register set, overlay ID, arbitrary memory region, Ghidra project path, program path, or script path.
- Processor is fixed to `arm9` because the existing owned DeSmuME debugger surface is ARM9-only.
- The launch-time ROM identity is the full lowercase SHA-256 of the exact file used for that owned process generation.
- Compute SHA-256 before `OwnedProcessManager.start()` and again after process creation; a mismatch fails start, stops that process generation, and resets debugger state.
- Keep `readArm9ExecutableRange()` as the narrow launch compatibility path; malformed FAT/FNT/overlay data must not become a new `desmume_start` blocker.
- The correlation operation reparses the ROM with `readNdsRomMap()` and requires `map.sha256 === launchSha256`.
- Reverify full source ROM identity immediately before returning a successful correlation result.
- Never guess overlapping overlay loaded state. Preserve every canonical `RuntimeCandidate` returned by `resolveRuntimeAddress()`.
- The observed PC and ARM/Thumb mode come only from decoded live registers/CPSR. Do not rewind, normalize, or otherwise adjust PC for breakpoint semantics.
- For compressed overlays, keep `representation: "derived-overlay"`, `romOffset: null`, and the existing bounded runtime-image provenance.
- BSS/runtime-only candidates receive no fabricated instruction stream.
- Static decoding uses the exact observed mode. Never decode both ARM and Thumb and choose the more plausible stream.
- Function reporting is exact-entry proof only. Do not invent containing-function ownership for a mid-function PC.
- Ghidra information stays under `ghidraDerived`; it never promotes canonical ownership or RE-MCP function proof.
- `includeGhidra: false` performs no Ghidra readiness check or subprocess work.
- Ghidra enrichment may use only an already-current full-ROM-SHA-scoped project and must run read-only/no-analysis through the existing inspection service.
- No automatic Ghidra bootstrap, reconciliation, migration, or auto-analysis.
- The new MCP response exposes the ROM only as a workspace-relative path, never an absolute filesystem path.
- Nearby instructions: default 8, range 1..32.
- Returned static references: default 16, range 0..64.
- Correlation timeout: default 3000 ms, range 100..30000 ms.
- Final serialized response must fit `config.maxOutputBytes`.
- Existing debugger tool result shapes remain unchanged.
- Existing physical Intel Catalina/DeSmuME debugger acceptance remains a separate outstanding gate.
- No new production runtime dependency.

---

# Delivery topology

Use two independently reviewed PRs:

1. **PR A — Runtime identity + canonical static correlation:** Tasks 1–4. Branch from current `main` after this design/plan documentation is accepted.
2. **PR B — Controlled Ghidra enrichment + hardening:** Tasks 5–8. Branch from current `main` only after PR A merges.

---

## File structure

### PR A

- Modify `src/services/nds/io.ts` — export one streaming full-file SHA-256 helper reused by launch and correlation identity checks.
- Modify `src/tools/desmume.ts` — bind `romSha256` to owned process metadata without changing GDB packet behavior.
- Create `src/services/nds/runtime-correlation.ts` — pure canonical/static correlation model and service.
- Create `src/tools/nds-runtime.ts` — live stopped-state orchestration and MCP contract.
- Modify `src/index.ts` — register the new runtime-correlation tool with the same owned process/debug controller instances used by DeSmuME tools.
- Modify capability/install reporting files only where current project patterns require explicit tool enumeration.
- Create `tests/nds-runtime-identity.test.ts`.
- Create `tests/nds-runtime-correlation.test.ts`.
- Create `tests/nds-runtime-tools.test.ts`.
- Extend existing DeSmuME start/race/lifecycle tests for regression contracts.

### PR B

- Create `src/services/nds/runtime-correlation-ghidra.ts` — candidate-scoped, already-ready read-only Ghidra enrichment adapter.
- Modify `src/services/nds/runtime-correlation.ts` — accept the optional enrichment dependency and attach `ghidraDerived` without changing canonical semantics.
- Modify `src/tools/nds-runtime.ts` — expose `includeGhidra` and `decompileGhidraFunction` options.
- Create `tests/nds-runtime-correlation-ghidra.test.ts`.
- Extend `tests/nds-runtime-tools.test.ts`.
- Create `scripts/ghidra-runtime-correlation-acceptance.mjs`.
- Add a temporary branch-scoped Ghidra acceptance workflow following the existing pinned Ghidra 12.1.2/JDK 21 acceptance pattern; remove/retire it before merge if repository convention requires temporary workflows not to remain.
- Update `README.md` and Ghidra/runtime-correlation documentation.

---

# PR A — Runtime identity + canonical static correlation

### Task 1: Bind owned DeSmuME generations to a full ROM SHA-256

**Files:**
- Modify: `src/services/nds/io.ts`
- Modify: `src/tools/desmume.ts`
- Test: `tests/nds-runtime-identity.test.ts`
- Test: `tests/desmume-start-race.test.ts`
- Test: `tests/desmume-debug-lifecycle.test.ts`

**Interfaces:**
- Produces: `sha256NdsFile(filePath: string): Promise<string>`
- Produces owned process metadata field: `romSha256: string`
- Preserves existing `readArm9ExecutableRange(romPath)` launch behavior.

- [ ] **Step 1: Write RED tests for the streaming SHA helper**

Add a deterministic temp-file test:

```ts
const rom = path.join(tempDir, "fixture.nds");
await writeFile(rom, Buffer.from("runtime-correlation-rom"));
assert.equal(
  await sha256NdsFile(rom),
  "9d8be25a2d9f1cd1b28f7f2f3dc38c511b4ba7f89a65ee3fdbdcb94c365d4f20",
);
```

If that literal digest differs when independently calculated in the test authoring environment, replace the literal with the independently verified SHA-256 before committing; do not calculate the expected value with `sha256NdsFile()` itself.

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/nds-runtime-identity.test.ts
```

Expected: FAIL because `sha256NdsFile` is not exported.

- [ ] **Step 3: Implement the streaming helper**

In `src/services/nds/io.ts`, use a read stream rather than `readFile()` so ROM size does not become a memory spike:

```ts
export async function sha256NdsFile(filePath: string): Promise<string> {
  return await new Promise<string>((resolve, reject) => {
    const hash = createHash("sha256");
    const stream = createReadStream(filePath);
    stream.on("error", reject);
    hash.on("error", reject);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}
```

Reuse/import existing `node:crypto`/`node:fs` facilities rather than adding a package.

- [ ] **Step 4: Verify helper GREEN**

```bash
node --test --import tsx tests/nds-runtime-identity.test.ts
```

Expected: PASS.

- [ ] **Step 5: Write RED `desmume_start` identity tests**

Extend fake-manager/start tests to assert:

```ts
assert.match(started.metadata.romSha256, /^[0-9a-f]{64}$/);
assert.equal(started.metadata.rom, expectedAbsoluteRomPath);
```

Add a test where the file is mutated between pre-start hash and post-start verification by a test double/hook around process start. Required behavior:

```ts
assert.equal(manager.status().running, false);
assert.equal(debuggerController.status().state, "unavailable");
assert.match(resultText, /ROM changed during DeSmuME start/i);
```

Also retain a regression fixture whose ARM9 header is valid while unrelated FAT/FNT/overlay bytes are malformed; `desmume_start` must still reach the process manager because this task must not replace `readArm9ExecutableRange()` with `readNdsRomMap()`.

- [ ] **Step 6: Implement pre/post launch hashing**

In `desmume_start`, structure the critical path as:

```ts
const arm9Range = await readArm9ExecutableRange(romPath);
const romSha256 = await sha256NdsFile(romPath);
const status = await manager.start({
  executable: launcherPath,
  args: buildDesmumeArguments(port, romPath),
  cwd: path.dirname(launcherPath),
  maxOutputBytes: config.maxOutputBytes,
  metadata: {
    emulator: "desmume",
    arm9GdbPort: port,
    rom: romPath,
    romSha256,
  },
});
const verifiedSha256 = await sha256NdsFile(romPath);
if (verifiedSha256 !== romSha256) {
  await manager.stop();
  await debuggerController.reset("ROM identity changed during DeSmuME start");
  throw new Error("ROM changed during DeSmuME start; restart with an unchanged ROM");
}
```

Keep the existing owned-process-generation race check after identity verification. If current manager stop/reset APIs differ, use their existing explicit owned-process shutdown/reset methods; do not send process signals directly from the tool.

- [ ] **Step 7: Run identity + existing debugger regressions**

```bash
node --test --import tsx \
  tests/nds-runtime-identity.test.ts \
  tests/desmume-start-race.test.ts \
  tests/desmume-debug-lifecycle.test.ts \
  tests/desmume-debug-tools.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/services/nds/io.ts src/tools/desmume.ts \
  tests/nds-runtime-identity.test.ts tests/desmume-start-race.test.ts \
  tests/desmume-debug-lifecycle.test.ts tests/desmume-debug-tools.test.ts
git commit -m "feat: bind DeSmuME sessions to ROM identity"
```

---

### Task 2: Add the pure canonical runtime-correlation model

**Files:**
- Create: `src/services/nds/runtime-correlation.ts`
- Test: `tests/nds-runtime-correlation.test.ts`
- Reuse: `src/services/nds/rom-map.ts`
- Reuse: `src/services/nds/resolver.ts`
- Reuse: `src/services/stop-context.ts`

**Interfaces:**
- Consumes: `readNdsRomMap(romPath): Promise<NdsRomMap>`
- Consumes: `resolveRuntimeAddress(map, address, "arm9"): RuntimeResolution`
- Consumes: `StopContext`
- Produces:

```ts
export interface NdsRuntimeCorrelationOptions {
  readonly nearbyInstructions: number;
  readonly referenceLimit: number;
  readonly maxOutputBytes: number;
}

export interface NdsRuntimeCorrelationInput {
  readonly romPath: string;
  readonly romDisplayPath: string;
  readonly expectedRomSha256: string;
  readonly stopContext: StopContext;
  readonly options: NdsRuntimeCorrelationOptions;
}

export interface NdsRuntimeCandidateCorrelation {
  readonly canonical: RuntimeCandidate;
  readonly static: NdsRuntimeStaticCorrelation;
  readonly ghidraDerived: { readonly status: "not-requested" };
}

export interface NdsRuntimeCorrelationResult {
  readonly runtimeObserved: {
    readonly capturedAt: string;
    readonly pc: number;
    readonly sp: number;
    readonly lr: number;
    readonly cpsr: number;
    readonly mode: "arm" | "thumb";
    readonly stop: StopContext["stop"];
    readonly breakpoint: StopContext["breakpoint"] | null;
  };
  readonly rom: {
    readonly path: string;
    readonly sha256: string;
    readonly launchSha256: string;
    readonly identityMatched: true;
  };
  readonly canonical: {
    readonly processor: "arm9";
    readonly status: "resolved" | "ambiguous" | "unmapped";
    readonly candidateCount: number;
  };
  readonly candidates: readonly NdsRuntimeCandidateCorrelation[];
}

export async function correlateNdsStopContext(
  input: NdsRuntimeCorrelationInput,
  backend: ArmDisassemblyBackend,
): Promise<NdsRuntimeCorrelationResult>;
```

- [ ] **Step 1: Write RED identity and ownership tests**

Create synthetic NDS fixtures using the existing fixture builders. Cover:

```ts
assert.equal(result.rom.identityMatched, true);
assert.equal(result.runtimeObserved.pc, stopContext.registers.pc);
assert.equal(result.runtimeObserved.mode, stopContext.registers.mode);
assert.equal(result.canonical.processor, "arm9");
```

Add mismatch behavior:

```ts
await assert.rejects(
  correlateNdsStopContext({ ...input, expectedRomSha256: "0".repeat(64) }, backend),
  /launch-time ROM SHA-256/i,
);
```

Add an unmapped PC case that remains a successful correlation with `candidateCount === 0`.

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/nds-runtime-correlation.test.ts
```

Expected: FAIL because the runtime-correlation module does not exist.

- [ ] **Step 3: Implement validation and canonical candidate normalization**

The service must:

```ts
const map = await readNdsRomMap(input.romPath);
if (map.sha256 !== input.expectedRomSha256) {
  throw new NdsError(
    "runtime-correlation-rom-identity-mismatch",
    "Current ROM SHA-256 does not match the launch-time ROM SHA-256",
  );
}
const resolution = resolveRuntimeAddress(map, input.stopContext.registers.pc, "arm9");
const candidates = resolution.status === "unmapped"
  ? []
  : resolution.status === "ambiguous-runtime-address"
    ? [...resolution.candidates]
    : [resolution.candidate];
```

Do not collapse `compressed-no-direct-rom-mapping` into an error; its candidate is statically analyzable through the derived runtime-image path. Do not collapse `runtime-only-bss` into an error; retain its runtime-only candidate.

- [ ] **Step 4: Preserve overlap ambiguity exactly**

Add a fixture with two ARM9 overlays covering the same PC and assert stable candidate ordering by canonical overlay ID while the top-level status remains ambiguous:

```ts
assert.equal(result.canonical.status, "ambiguous");
assert.deepEqual(
  result.candidates.map((candidate) => candidate.canonical.overlayId),
  [12, 19],
);
```

The implementation may sort only for deterministic response ordering; sorting must not choose a loaded overlay.

- [ ] **Step 5: Add final ROM identity revalidation and output bound**

Immediately before return:

```ts
const finalSha256 = await sha256NdsFile(input.romPath);
if (finalSha256 !== input.expectedRomSha256) {
  throw new NdsError(
    "runtime-correlation-rom-identity-mismatch",
    "Source ROM changed during runtime correlation",
  );
}
if (Buffer.byteLength(JSON.stringify(result), "utf8") > input.options.maxOutputBytes) {
  throw new NdsError(
    "runtime-correlation-output-limit",
    "Runtime correlation result exceeds configured output limit",
  );
}
```

- [ ] **Step 6: Run ownership/identity GREEN**

```bash
node --test --import tsx tests/nds-runtime-correlation.test.ts
npm run typecheck
```

Expected: PASS for identity, resolved main, ambiguous overlay, BSS, and unmapped cases.

- [ ] **Step 7: Commit**

```bash
git add src/services/nds/runtime-correlation.ts tests/nds-runtime-correlation.test.ts
git commit -m "feat: correlate runtime stops with canonical NDS ownership"
```

---

### Task 3: Enrich every canonical candidate with bounded static evidence

**Files:**
- Modify: `src/services/nds/runtime-correlation.ts`
- Test: `tests/nds-runtime-correlation.test.ts`
- Reuse: `src/services/nds/disassembly.ts`
- Reuse: `src/services/nds/reference-list.ts`
- Reuse: `src/services/nds/function-analysis.ts`
- Reuse: `tests/helpers/nds-compressed-code-fixture.ts`

**Interfaces:**
- Consumes: `disassembleNdsRange(map, location, options, backend)`
- Consumes: `listNdsReferences(map, location, options, backend)`
- Consumes: `analyzeNdsFunction(map, request, limits, backend)`
- Produces:

```ts
export type NdsRuntimeStaticCorrelation =
  | {
      readonly status: "available";
      readonly instructions: readonly StaticInstruction[];
      readonly references: readonly StaticReference[];
      readonly functionEntry: {
        readonly proofStatus: AnalyzeFunctionProofStatus;
        readonly runtimeMode: "arm" | "thumb";
        readonly staticMode: "arm" | "thumb";
        readonly modeConsistent: boolean;
        readonly evidence: readonly FunctionProof[];
      };
    }
  | {
      readonly status: "runtime-only" | "not-decodable";
      readonly reason: string;
    };
```

- [ ] **Step 1: Write RED main-code instruction/reference tests**

For a fixture with known Thumb instructions at the observed PC:

```ts
assert.equal(candidate.static.status, "available");
assert.equal(candidate.static.instructions[0]?.address, observedPc);
assert.equal(candidate.static.instructions[0]?.mode, "thumb");
assert.ok(candidate.static.instructions.length <= 8);
assert.ok(candidate.static.references.length <= 16);
```

Add a direct call/reference fixture and assert the existing reference kind is preserved; do not introduce a new correlation-only reference classifier.

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/nds-runtime-correlation.test.ts
```

Expected: FAIL because candidate static evidence is not populated.

- [ ] **Step 3: Implement candidate-specific location construction**

For every canonical candidate, construct the existing `NdsDisassemblyLocation` using runtime-observed mode:

```ts
const location = {
  processor: "arm9" as const,
  runtimeAddress: candidate.runtimeAddress,
  mode: input.stopContext.registers.mode,
  ...(candidate.overlayId === null ? {} : { overlayId: candidate.overlayId }),
};
```

Do not pass an overlay ID for ARM9 main. For BSS/runtime-only representation, return `status: "runtime-only"` before invoking disassembly.

- [ ] **Step 4: Reuse bounded disassembly and reference services**

Use the exact same instruction window for both calls:

```ts
const maxBytes = Math.min(128, input.options.nearbyInstructions * 4);
const instructions = await disassembleNdsRange(
  map,
  location,
  { maxInstructions: input.options.nearbyInstructions, maxBytes },
  backend,
);
const references = await listNdsReferences(
  map,
  location,
  { maxInstructions: input.options.nearbyInstructions, maxBytes },
  backend,
);
```

Retain at most `referenceLimit` references in response order. If `referenceLimit === 0`, skip `listNdsReferences()` entirely and return `[]`.

If disassembly returns a non-resolved code-source status, convert it to bounded `not-decodable` static status using the existing status string; do not invent instructions.

- [ ] **Step 5: Write and implement exact function-entry proof tests**

Use existing `analyzeNdsFunction()` with conservative bounded proof/CFG limits and a proof scope that can establish the existing program-entry/direct-call rules. The response must distinguish:

```ts
proofStatus === "proven"
proofStatus === "not-proven-function-entry"
proofStatus === "proof-inconclusive"
```

Do not rename a non-proven PC into a containing function. Record mode consistency only from the returned exact `entry.mode`:

```ts
modeConsistent: analysis.entry.mode === input.stopContext.registers.mode
```

A mode mismatch is data in the result, not an automatic retry in the opposite mode.

- [ ] **Step 6: Add compressed-overlay and BSS tests**

Using the existing compressed-code fixture, assert:

```ts
assert.equal(candidate.canonical.representation, "derived-overlay");
assert.equal(candidate.static.status, "available");
assert.equal(candidate.static.instructions[0]?.romOffset, null);
```

For overlay BSS:

```ts
assert.equal(candidate.canonical.representation, "runtime-only");
assert.equal(candidate.static.status, "runtime-only");
```

- [ ] **Step 7: Run static-correlation GREEN**

```bash
node --test --import tsx \
  tests/nds-runtime-correlation.test.ts \
  tests/nds-compressed-static-analysis.test.ts \
  tests/nds-function-analysis.test.ts \
  tests/nds-reference-list.test.ts \
  tests/nds-disassembly.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/services/nds/runtime-correlation.ts tests/nds-runtime-correlation.test.ts
git commit -m "feat: attach bounded static evidence to runtime stops"
```

---

### Task 4: Expose `nds_correlate_stop_context` without changing debugger contracts

**Files:**
- Create: `src/tools/nds-runtime.ts`
- Modify: `src/index.ts`
- Modify: explicit capability/install reporting files used by the current repository, if required by current tests
- Test: `tests/nds-runtime-tools.test.ts`
- Test: `tests/desmume-debug-tools.test.ts`
- Test: `tests/desmume-debug-lifecycle.test.ts`

**Interfaces:**
- Consumes the same `OwnedProcessManager` and `DebugController` instance registered for DeSmuME tools.
- Produces:

```ts
export function registerNdsRuntimeTools(
  server: McpServer,
  config: ServerConfig,
  manager: OwnedProcessManager,
  debuggerController: DebugController,
  backend: ArmDisassemblyBackend,
): void;
```

Public tool input:

```ts
{
  timeoutMs: z.number().int().min(100).max(30_000).default(3_000),
  nearbyInstructions: z.number().int().min(1).max(32).default(8),
  referenceLimit: z.number().int().min(0).max(64).default(16),
}
```

- [ ] **Step 1: Write RED registration/schema tests**

Assert the tool exists and rejects:

- timeout below 100 or above 30000;
- nearby instructions 0 or 33;
- reference limit below 0 or above 64;
- any unsupported caller-controlled ROM/PC/processor/overlay field if the MCP test harness validates unknown keys strictly.

- [ ] **Step 2: Write RED stopped-state orchestration tests**

With the fake RSP server/controller:

```ts
assert.equal(debuggerController.status().state, "stopped");
const result = await callTool("nds_correlate_stop_context", {});
assert.equal(result.runtimeObserved.pc, expectedRegisterPc);
assert.equal(result.runtimeObserved.mode, expectedRegisterMode);
```

Also prove correlation never resumes execution by asserting the fake RSP server receives only stopped-state register/memory requests used by `captureCurrentStopContext`; no `c`, `s`, or raw interrupt is observed.

- [ ] **Step 3: Implement owned-session validation**

The tool must derive identity from `manager.status()`:

```ts
const status = manager.status();
if (!status.running) {
  throw new NdsError(
    "runtime-correlation-no-owned-process",
    "No owned DeSmuME process is running",
  );
}
const romPath = status.metadata.rom;
const launchSha256 = status.metadata.romSha256;
if (typeof romPath !== "string" || typeof launchSha256 !== "string" || !/^[0-9a-f]{64}$/.test(launchSha256)) {
  throw new NdsError(
    "runtime-correlation-rom-identity-missing",
    "Owned DeSmuME session does not contain a valid launch-time ROM identity",
  );
}
```

Require `debuggerController.status().state === "stopped"` before capture. Do not call pause automatically.

- [ ] **Step 4: Capture current context without PC correction**

Use only:

```ts
const context = await debuggerController.captureCurrentStopContext({
  timeoutMs,
  maxOutputBytes: config.maxOutputBytes,
});
```

Pass `context.registers.pc` and `context.registers.mode` through untouched. No `pc - 2`, `pc - 4`, breakpoint-kind adjustment, or symbol/range-based correction is allowed.

- [ ] **Step 5: Produce a workspace-relative ROM display path**

Compute display path with `path.relative(config.workspaceRoot, romPath)`. Reject a result that escapes the workspace (`..`, absolute path) even though `desmume_start` already resolves inside it. Pass only that relative display path into `correlateNdsStopContext()`.

- [ ] **Step 6: Register from `src/index.ts` with shared instances**

Do not construct a second process manager or debug controller. Follow the existing index initialization order so DeSmuME and runtime-correlation tools share the same live state.

- [ ] **Step 7: Run PR A focused/full verification**

```bash
node --test --import tsx \
  tests/nds-runtime-identity.test.ts \
  tests/nds-runtime-correlation.test.ts \
  tests/nds-runtime-tools.test.ts \
  tests/desmume-debug-tools.test.ts \
  tests/desmume-debug-lifecycle.test.ts \
  tests/desmume-start-race.test.ts
npm run check
npm run build
```

Expected: PASS.

- [ ] **Step 8: Review PR A trust boundaries**

Run:

```bash
git diff --check main...HEAD
git diff -- src/services/gdb-session.ts src/services/gdb-rsp.ts src/services/debug-controller.ts
```

Expected: no whitespace errors; no production changes to GDB packet/session/controller semantics. `src/tools/desmume.ts` may change only for ROM identity metadata/start-time validation.

- [ ] **Step 9: Commit and open PR A**

```bash
git add src/tools/nds-runtime.ts src/index.ts src/tools/desmume.ts \
  src/services/nds/io.ts src/services/nds/runtime-correlation.ts \
  tests/nds-runtime-identity.test.ts tests/nds-runtime-correlation.test.ts \
  tests/nds-runtime-tools.test.ts tests/desmume-debug-tools.test.ts \
  tests/desmume-debug-lifecycle.test.ts tests/desmume-start-race.test.ts
git commit -m "feat: correlate stopped ARM9 state with NDS static analysis"
```

Open a PR titled:

```text
Correlate stopped ARM9 state with NDS static analysis
```

The PR body must explicitly state: no GDB packet behavior change, no Ghidra dependency in PR A, no loaded-overlay guessing, no writes, and physical Catalina acceptance remains pending.

---

# PR B — Controlled Ghidra enrichment + hardening

Start from current `main` only after PR A merges.

### Task 5: Add an already-ready, candidate-scoped Ghidra enrichment adapter

**Files:**
- Create: `src/services/nds/runtime-correlation-ghidra.ts`
- Test: `tests/nds-runtime-correlation-ghidra.test.ts`
- Reuse: `src/services/nds/ghidra-inspection-readiness.ts`
- Reuse: `src/services/nds/ghidra-inspection-service.ts`
- Reuse: `src/services/nds/ghidra-project.ts`

**Interfaces:**
- Produces:

```ts
export type RuntimeGhidraEnrichment =
  | { readonly status: "not-requested" }
  | { readonly status: "not-ready"; readonly reason: string }
  | {
      readonly status: "available";
      readonly function: unknown | null;
      readonly decompilation: unknown | null;
    }
  | { readonly status: "failed"; readonly category: string; readonly message: string };

export interface RuntimeGhidraEnrichmentRequest {
  readonly map: NdsRomMap;
  readonly candidate: RuntimeCandidate;
  readonly decompileFunction: boolean;
  readonly maxOutputBytes: number;
}

export type RuntimeGhidraEnricher = (
  request: RuntimeGhidraEnrichmentRequest,
) => Promise<RuntimeGhidraEnrichment>;
```

Use concrete existing Ghidra inspection result types instead of `unknown` when implementing; the plan uses `unknown` here only as a boundary shorthand because the adapter must return the existing inspection payloads unchanged rather than invent a parallel Ghidra model.

- [ ] **Step 1: Write RED no-work/not-ready tests**

Test adapter dependencies with spies:

```ts
const enrichment = await enrichRuntimeCandidateWithGhidra(request, deps);
assert.equal(enrichment.status, "not-ready");
assert.equal(bootstrapCalls, 0);
assert.equal(reconcileCalls, 0);
```

The production adapter must have no bootstrap/reconcile dependency at all. If a test requires stubbing such functions, that is a design error.

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/nds-runtime-correlation-ghidra.test.ts
```

Expected: FAIL because the adapter does not exist.

- [ ] **Step 3: Implement readiness-only entry**

Use the existing strict inspection readiness function for the full ROM SHA. If readiness reports absent/stale/not-current, return `not-ready` without launching a subprocess.

- [ ] **Step 4: Map canonical candidate identity to existing inspection requests**

Build the address request from canonical data only:

```ts
const address = {
  processor: "arm9" as const,
  runtimeAddress: request.candidate.runtimeAddress,
  ...(request.candidate.overlayId === null
    ? {}
    : { overlayId: request.candidate.overlayId }),
};
```

Never use Ghidra to choose among candidates. The caller invokes the adapter separately for each canonical candidate.

- [ ] **Step 5: Run function inspection read-only**

Call the existing inspection-service function corresponding to `nds_ghidra_get_function` for the exact canonical address. Preserve its existing bounded/read-only behavior. A no-function result is valid and becomes `function: null` rather than a canonical failure.

If `decompileFunction === true`, call the existing decompiler inspection only when the exact address is inspectable as a function under that service's rules. Do not run decompilation merely to guess a containing function.

- [ ] **Step 6: Convert Ghidra-layer failures without contaminating canonical status**

Catch only Ghidra readiness/inspection errors and return:

```ts
{
  status: "failed",
  category: error instanceof NdsError ? error.category : "ghidra-inspection-failed",
  message: error instanceof Error ? error.message : String(error),
}
```

Do not catch ROM-identity mismatch from the correlation layer here.

- [ ] **Step 7: Verify GREEN**

```bash
node --test --import tsx \
  tests/nds-runtime-correlation-ghidra.test.ts \
  tests/nds-ghidra-inspection.test.ts \
  tests/nds-ghidra-inspection-readiness.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/services/nds/runtime-correlation-ghidra.ts \
  tests/nds-runtime-correlation-ghidra.test.ts
git commit -m "feat: enrich runtime correlation from ready Ghidra projects"
```

---

### Task 6: Wire opt-in Ghidra enrichment into the correlation service and MCP tool

**Files:**
- Modify: `src/services/nds/runtime-correlation.ts`
- Modify: `src/tools/nds-runtime.ts`
- Test: `tests/nds-runtime-correlation.test.ts`
- Test: `tests/nds-runtime-tools.test.ts`

**Interfaces:**
- Extend `NdsRuntimeCorrelationOptions`:

```ts
readonly includeGhidra: boolean;
readonly decompileGhidraFunction: boolean;
```

- Extend `correlateNdsStopContext()` with an optional dependency:

```ts
export async function correlateNdsStopContext(
  input: NdsRuntimeCorrelationInput,
  backend: ArmDisassemblyBackend,
  ghidraEnricher?: RuntimeGhidraEnricher,
): Promise<NdsRuntimeCorrelationResult>;
```

- [ ] **Step 1: Write RED `includeGhidra: false` no-call tests**

```ts
let calls = 0;
await correlateNdsStopContext(inputWithGhidraFalse, backend, async () => {
  calls += 1;
  throw new Error("must not run");
});
assert.equal(calls, 0);
assert.ok(result.candidates.every((c) => c.ghidraDerived.status === "not-requested"));
```

- [ ] **Step 2: Write RED per-candidate ambiguity tests**

For two overlapping overlays, assert the enricher receives overlay IDs `[12, 19]` in deterministic candidate order and neither enrichment changes `canonical.status === "ambiguous"`.

- [ ] **Step 3: Implement enrichment dispatch**

For every candidate:

```ts
const ghidraDerived = !input.options.includeGhidra
  ? { status: "not-requested" as const }
  : ghidraEnricher === undefined
    ? { status: "failed" as const, category: "ghidra-enricher-unavailable", message: "Ghidra enrichment dependency is unavailable" }
    : await ghidraEnricher({
        map,
        candidate,
        decompileFunction: input.options.decompileGhidraFunction,
        maxOutputBytes: input.options.maxOutputBytes,
      });
```

Ghidra runs after canonical/static candidate establishment and before the final ROM SHA/output-size checks.

- [ ] **Step 4: Extend MCP schema**

Add:

```ts
includeGhidra: z.boolean().default(false),
decompileGhidraFunction: z.boolean().default(false),
```

Reject `decompileGhidraFunction: true` when `includeGhidra: false` with a structured tool error rather than silently enabling Ghidra.

- [ ] **Step 5: Construct the production enricher only for requested calls**

The tool may close over config/service dependencies, but must not perform readiness or subprocess work before `includeGhidra` is known true.

- [ ] **Step 6: Verify GREEN**

```bash
node --test --import tsx \
  tests/nds-runtime-correlation.test.ts \
  tests/nds-runtime-correlation-ghidra.test.ts \
  tests/nds-runtime-tools.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/services/nds/runtime-correlation.ts src/tools/nds-runtime.ts \
  tests/nds-runtime-correlation.test.ts tests/nds-runtime-tools.test.ts
git commit -m "feat: add opt-in Ghidra runtime correlation"
```

---

### Task 7: Add mandatory real Ghidra runtime-correlation acceptance

**Files:**
- Create: `scripts/ghidra-runtime-correlation-acceptance.mjs`
- Create/Modify: branch-scoped temporary workflow under `.github/workflows/`
- Test: existing source-contract tests for workflows/scripts, or create `tests/nds-runtime-ghidra-acceptance-source.test.ts` if no suitable contract file exists

**Interfaces:**
- Consumes pinned Ghidra 12.1.2 archive/checksum and Temurin JDK 21 used by current real-Ghidra acceptance.
- Produces a process exit code 0 only when main-code and overlay correlation enrichment both satisfy trust-boundary assertions.

- [ ] **Step 1: Write RED source-contract tests**

Assert the acceptance script contains checks for:

```text
includeGhidra: true
canonical ownership before Ghidra
main-code candidate
explicit overlay candidate
compressed overlay when fixture supports it
not-requested/no-bootstrap separation
read-only inspection
no hidden Ghidra script exceptions
```

Also require the workflow to pin the exact same Ghidra 12.1.2 artifact SHA-256 already used by repository acceptance.

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/nds-runtime-ghidra-acceptance-source.test.ts
```

Expected: FAIL because the acceptance script/workflow does not exist.

- [ ] **Step 3: Implement the acceptance fixture flow**

The script should reuse the existing synthetic NDS/Ghidra acceptance fixture generation rather than introduce a private ROM requirement. Required logical sequence:

```text
create synthetic fixture
build canonical map/bundle
explicitly bootstrap current Ghidra project using existing acceptance helper
construct deterministic stopped contexts for one ARM9-main address and one overlay address
run pure/runtime correlation with includeGhidra=true
assert canonical candidate identity first
assert ghidraDerived.status=available
assert decompilation only when exact function inspection supports it
assert compressed-overlay romOffset remains null when tested
```

This acceptance does not test DeSmuME/GDB; it tests the real Ghidra half of correlation.

- [ ] **Step 4: Add hidden-error and read-only persistence assertions**

Reuse the current Ghidra application-log rejection pattern:

```bash
if grep -nE 'REPORT SCRIPT ERROR|Exception' "$HOME/.config/ghidra/ghidra_12.1.2_PUBLIC/application.log"; then
  exit 1
fi
```

Snapshot the persistent project before read-only correlation inspection and verify no project bytes/analyst marker change afterward, following the existing hardened inspection acceptance pattern.

- [ ] **Step 5: Verify script syntax and source contracts locally**

```bash
node --check scripts/ghidra-runtime-correlation-acceptance.mjs
node --test --import tsx tests/nds-runtime-ghidra-acceptance-source.test.ts
npm run check
npm run build
```

Expected: PASS.

- [ ] **Step 6: Commit and push for real Actions execution**

```bash
git add scripts/ghidra-runtime-correlation-acceptance.mjs \
  .github/workflows tests/nds-runtime-ghidra-acceptance-source.test.ts
git commit -m "test: add real Ghidra runtime correlation acceptance"
```

- [ ] **Step 7: Require real Ghidra acceptance GREEN before PR B can be ready**

Record the successful workflow run ID and verify all of these steps are green:

```text
install/check/build
pinned Ghidra download verification
runtime-correlation bootstrap fixture
main candidate correlation
explicit overlay candidate correlation
compressed-overlay correlation when supported
read-only persistence check
hidden Ghidra error rejection
```

If the workflow fails, diagnose and fix the production/test code; do not weaken canonical authority rules or remove acceptance assertions to obtain green.

---

### Task 8: Documentation, capability surface, and final cross-layer regression

**Files:**
- Modify: `README.md`
- Modify: capability/install reporting files required by current repository conventions
- Modify: `docs/dynamic-debugging-catalina-acceptance.md`
- Create or Modify: runtime-correlation user documentation under `docs/`
- Test: install/capability/package tests that enumerate tools/resources

**Interfaces:**
- Documents final MCP tool:

```text
nds_correlate_stop_context
```

with `timeoutMs`, `nearbyInstructions`, `referenceLimit`, `includeGhidra`, and `decompileGhidraFunction`.

- [ ] **Step 1: Update README capability text**

Document that runtime correlation:

- consumes the current stopped ARM9 session;
- proves full launch/current ROM identity;
- preserves overlapping overlay ambiguity;
- uses observed CPSR mode exactly;
- can decode compressed-overlay runtime images without fabricating ROM offsets;
- reports exact-entry function proof only;
- optionally attaches already-ready read-only Ghidra information.

Explicitly document that it does **not** detect the loaded overlay or modify the ROM/emulator/Ghidra project.

- [ ] **Step 2: Extend Catalina acceptance guide with one post-debugger correlation check**

Add only after the existing native breakpoint/stop-context checks:

```text
real breakpoint stop
-> nds_correlate_stop_context
-> launch/current SHA match
-> observed PC/CPSR mode unchanged
-> canonical candidate(s)
-> bounded static evidence
```

Make clear this new line does not retroactively make CI/fake-RSP proof equivalent to native DeSmuME acceptance.

- [ ] **Step 3: Update capability/install assertions**

Where the repository explicitly enumerates tools, add exactly `nds_correlate_stop_context` and keep every existing tool unchanged.

- [ ] **Step 4: Run full final verification**

```bash
npm run check
npm run build
```

Also run the focused suites:

```bash
node --test --import tsx \
  tests/nds-runtime-identity.test.ts \
  tests/nds-runtime-correlation.test.ts \
  tests/nds-runtime-correlation-ghidra.test.ts \
  tests/nds-runtime-tools.test.ts \
  tests/nds-runtime-ghidra-acceptance-source.test.ts \
  tests/desmume-debug-tools.test.ts \
  tests/desmume-debug-lifecycle.test.ts \
  tests/nds-ghidra-inspection.test.ts \
  tests/nds-compressed-static-analysis.test.ts
```

Expected: PASS.

- [ ] **Step 5: Review final diff against trust boundaries**

```bash
git diff --check main...HEAD
git diff main...HEAD -- src/services/gdb-session.ts src/services/gdb-rsp.ts src/services/debug-controller.ts
```

Expected: no GDB transport/controller production changes.

Review all `runtime-correlation*` code for these forbidden strings/behaviors:

```text
loadedOverlay
bestMatch
register write
memory write
watchpoint
bootstrap on inspection
reconcile on inspection
PC rewind
```

Any appearance must be documentation/tests explicitly rejecting the behavior, not production implementation.

- [ ] **Step 6: Verify exact PR B head checks**

Before marking ready, verify the live head SHA has:

- CI success;
- Package success;
- mandatory real Ghidra runtime-correlation acceptance success.

If the head moves, reverify checks on the new exact head.

- [ ] **Step 7: Commit final docs and open/ready PR B**

```bash
git add README.md docs src tests scripts .github/workflows
git commit -m "docs: document controlled NDS runtime correlation"
```

Open/update PR title:

```text
Add controlled Ghidra enrichment to runtime correlation
```

PR body must state:

- canonical runtime/static correlation was established in PR A;
- Ghidra enrichment is opt-in and secondary;
- no automatic bootstrap/reconciliation;
- no loaded-overlay inference;
- real Ghidra 12.1.2/JDK 21 acceptance passed on the exact head;
- physical Catalina/DeSmuME acceptance remains separate.

Do not merge either PR without explicit user authorization.
