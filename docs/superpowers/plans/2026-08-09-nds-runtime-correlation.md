# Controlled NDS Runtime Correlation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correlate one current stopped server-owned DeSmuME ARM9 state with the exact launched NDS ROM, canonical static ownership, bounded ARM/Thumb analysis, existing proven function evidence, and optional already-ready read-only Ghidra context.

**Architecture:** PR A binds each owned emulator process generation to a full ROM SHA-256, adds a pure canonical/static correlation service, and exposes one stopped-state MCP tool. PR B adds opt-in candidate-scoped Ghidra enrichment only after canonical ownership is established; Ghidra never bootstraps automatically, mutates state, or selects a loaded overlay.

**Tech Stack:** Node.js 20+, TypeScript 5.7, existing MCP SDK/Zod, existing Capstone.js ARM backend, existing NDS parser/resolver/disassembly/reference/function services, existing Ghidra 12.1.2/JDK 21 inspection infrastructure, Node test runner with `tsx`.

## Global Constraints

- Read-only milestone: no watchpoints, register writes, memory writes, arbitrary GDB packets, conditional breakpoint scripting, repeated-step tracing, ROM mutation, or Ghidra mutation.
- `nds_correlate_stop_context` accepts no caller-selected ROM path, processor, PC, register set, overlay ID, arbitrary memory region, Ghidra project/program/script path, or loaded-overlay hint.
- Processor is fixed to `arm9` because the existing owned DeSmuME debugger is ARM9-only.
- Launch identity is the full lowercase SHA-256 of the exact ROM used by that owned process generation.
- Hash the ROM before `OwnedProcessManager.start()` and again after process creation. A mismatch stops that owned generation, resets debugger state, and fails start.
- Keep `readArm9ExecutableRange()` as the narrow launch compatibility path. Do not make `desmume_start` depend on valid FAT/FNT/overlay structures.
- Correlation reparses with `readNdsRomMap()` and requires `map.sha256 === launchSha256`.
- Rehash immediately before returning a successful correlation result.
- Preserve every `RuntimeCandidate` from `resolveRuntimeAddress()`. Never guess among overlapping overlays.
- PC and execution mode come directly from decoded live registers/CPSR. Do not rewind or correct PC for breakpoint semantics.
- Static decoding uses the exact observed ARM/Thumb mode; never decode both modes and choose one.
- Compressed overlays retain `representation: "derived-overlay"` and `romOffset: null`.
- BSS/runtime-only candidates get no fabricated instruction stream.
- Function reporting is exact-entry proof only. Do not infer containing-function ownership for arbitrary mid-function PCs.
- Ghidra stays under `ghidraDerived`; it never changes canonical ownership or RE-MCP function proof.
- `includeGhidra: false` performs no Ghidra readiness check or subprocess work.
- Ghidra enrichment may use only an already-current full-ROM-SHA-scoped project through existing read-only/no-analysis inspection.
- No automatic Ghidra bootstrap, reconciliation, migration, or auto-analysis.
- MCP output exposes only a workspace-relative ROM path.
- `timeoutMs`: default 3000, range 100..30000.
- `nearbyInstructions`: default 8, range 1..32.
- `referenceLimit`: default 16, range 0..64.
- Final serialized response must fit `config.maxOutputBytes`.
- Existing debugger tool result shapes remain unchanged.
- Physical Intel Catalina/DeSmuME acceptance remains a separate outstanding gate.
- No new production runtime dependency.

---

## Delivery topology

1. **PR A — Runtime identity + canonical static correlation:** Tasks 1–4. Branch from current `main` after this design/plan documentation is accepted.
2. **PR B — Controlled Ghidra enrichment + hardening:** Tasks 5–8. Branch from current `main` only after PR A merges.

---

# PR A — Runtime identity + canonical static correlation

### Task 1: Bind each owned DeSmuME generation to the full ROM SHA-256

**Files:**
- Modify: `src/tools/desmume.ts`
- Reuse unchanged: `src/services/nds/io.ts`
- Test: `tests/nds-runtime-identity.test.ts`
- Test: `tests/desmume-start-race.test.ts`
- Test: `tests/desmume-debug-lifecycle.test.ts`

**Interfaces:**
- Consumes existing `hashFileSha256(filePath: string): Promise<string>` from `src/services/nds/io.ts`.
- Produces owned-process metadata field `romSha256: string` alongside existing `rom` and `arm9GdbPort`.
- Preserves existing `readArm9ExecutableRange(romPath)` launch semantics.

- [ ] **Step 1: Write RED start-metadata tests**

Add a valid synthetic ROM and assert the process-start request contains:

```ts
assert.equal(startRequest.metadata.rom, expectedAbsoluteRomPath);
assert.equal(
  startRequest.metadata.romSha256,
  "a47e00f66bf37a7e8e6fc487572ef9c4679b0be5bef584d73eee9955bcd5be73",
);
```

Use the bytes `Buffer.from("runtime-correlation-rom")` only in the dedicated hash fixture that independently proves the literal above. The actual `desmume_start` fixture must remain a valid ARM9-header ROM.

- [ ] **Step 2: Write RED mutation-during-start test**

Arrange a test process manager whose `start()` hook mutates the ROM after the pre-launch hash. Assert:

```ts
assert.equal(manager.status().running, false);
assert.equal(debuggerController.status().state, "unavailable");
assert.match(resultText, /ROM changed during DeSmuME start/i);
```

- [ ] **Step 3: Write RED narrow-launch regression**

Create a fixture with a valid ARM9 header but deliberately invalid unrelated FAT/FNT/overlay bytes. Assert `desmume_start` still reaches `OwnedProcessManager.start()`. This prevents accidental replacement of `readArm9ExecutableRange()` with `readNdsRomMap()`.

- [ ] **Step 4: Run RED**

```bash
node --test --import tsx \
  tests/nds-runtime-identity.test.ts \
  tests/desmume-start-race.test.ts
```

Expected: FAIL because `romSha256` is not launch metadata and no post-start identity check exists.

- [ ] **Step 5: Implement pre/post launch identity checks**

Import existing `hashFileSha256` and structure the launch path as:

```ts
const arm9Range = await readArm9ExecutableRange(romPath);
const romSha256 = await hashFileSha256(romPath);

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

const verifiedSha256 = await hashFileSha256(romPath);
if (verifiedSha256 !== romSha256) {
  await manager.stop();
  await debuggerController.reset("ROM identity changed during DeSmuME start");
  throw new Error("ROM changed during DeSmuME start; restart with an unchanged ROM");
}
```

Keep the existing process-generation race check after this identity check.

- [ ] **Step 6: Run focused debugger regressions**

```bash
node --test --import tsx \
  tests/nds-runtime-identity.test.ts \
  tests/desmume-start-race.test.ts \
  tests/desmume-debug-lifecycle.test.ts \
  tests/desmume-debug-tools.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/tools/desmume.ts tests/nds-runtime-identity.test.ts \
  tests/desmume-start-race.test.ts tests/desmume-debug-lifecycle.test.ts \
  tests/desmume-debug-tools.test.ts
git commit -m "feat: bind DeSmuME sessions to ROM identity"
```

---

### Task 2: Add runtime-correlation error categories and canonical ownership model

**Files:**
- Modify: `src/services/nds/errors.ts`
- Create: `src/services/nds/runtime-correlation.ts`
- Test: `tests/nds-runtime-correlation.test.ts`

**Interfaces:**
- Consumes `readNdsRomMap(romPath): Promise<NdsRomMap>`.
- Consumes `resolveRuntimeAddress(map, address, "arm9"): RuntimeResolution`.
- Consumes `hashFileSha256(filePath): Promise<string>`.
- Consumes `StopContext`.
- Produces:

```ts
export type NdsRuntimeCorrelationErrorCategory =
  | "runtime-correlation-no-owned-process"
  | "runtime-correlation-rom-identity-missing"
  | "runtime-correlation-rom-identity-mismatch"
  | "runtime-correlation-debugger-not-stopped"
  | "runtime-correlation-context-failed"
  | "runtime-correlation-output-limit";
```

Add `NdsRuntimeCorrelationErrorCategory` to `AnyNdsErrorCategory` so correlation errors remain part of the non-Ghidra NDS service surface.

Define:

```ts
export interface NdsRuntimeCorrelationOptions {
  readonly nearbyInstructions: number;
  readonly referenceLimit: number;
  readonly maxOutputBytes: number;
  readonly includeGhidra: false;
  readonly decompileGhidraFunction: false;
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

- [ ] **Step 1: Write RED error-union/type tests**

Add a compile/runtime test that constructs:

```ts
const error = new NdsError<NdsRuntimeCorrelationErrorCategory>(
  "runtime-correlation-rom-identity-mismatch",
  "mismatch",
);
assert.equal(error.category, "runtime-correlation-rom-identity-mismatch");
```

- [ ] **Step 2: Write RED identity/resolution tests**

Cover ARM9 main, ambiguous overlays, BSS, compressed overlay, and unmapped PC. Assert PC/mode are copied verbatim from `stopContext.registers`.

For ambiguity:

```ts
assert.equal(result.canonical.status, "ambiguous");
assert.deepEqual(
  result.candidates.map((entry) => entry.canonical.overlayId),
  [12, 19],
);
```

Sorting by overlay ID is permitted only for deterministic output; the result must remain ambiguous.

- [ ] **Step 3: Run RED**

```bash
node --test --import tsx tests/nds-runtime-correlation.test.ts
```

Expected: FAIL because correlation categories/module do not exist.

- [ ] **Step 4: Implement categories and initial identity check**

In `errors.ts`, add the new union and include it in `AnyNdsErrorCategory`.

In `runtime-correlation.ts`:

```ts
const map = await readNdsRomMap(input.romPath);
if (map.sha256 !== input.expectedRomSha256) {
  throw new NdsError<NdsRuntimeCorrelationErrorCategory>(
    "runtime-correlation-rom-identity-mismatch",
    "Current ROM SHA-256 does not match the launch-time ROM SHA-256",
  );
}
```

- [ ] **Step 5: Normalize canonical candidates without changing resolver semantics**

```ts
const resolution = resolveRuntimeAddress(
  map,
  input.stopContext.registers.pc,
  "arm9",
);

const candidates = resolution.status === "unmapped"
  ? []
  : resolution.status === "ambiguous-runtime-address"
    ? [...resolution.candidates].sort(
        (left, right) => (left.overlayId ?? -1) - (right.overlayId ?? -1),
      )
    : [resolution.candidate];
```

Retain candidates from `compressed-no-direct-rom-mapping` and `runtime-only-bss`; neither is a top-level correlation failure.

- [ ] **Step 6: Build runtime/canonical result without static enrichment yet**

Every candidate initially gets:

```ts
{
  canonical: candidate,
  static: candidate.representation === "runtime-only"
    ? { status: "runtime-only", reason: "canonical runtime candidate has no exact initialized code bytes" }
    : { status: "not-decodable", reason: "static enrichment not performed yet" },
  ghidraDerived: { status: "not-requested" },
}
```

- [ ] **Step 7: Add final SHA/output-bound checks**

Immediately before return:

```ts
const finalSha256 = await hashFileSha256(input.romPath);
if (finalSha256 !== input.expectedRomSha256) {
  throw new NdsError<NdsRuntimeCorrelationErrorCategory>(
    "runtime-correlation-rom-identity-mismatch",
    "Source ROM changed during runtime correlation",
  );
}
if (Buffer.byteLength(JSON.stringify(result), "utf8") > input.options.maxOutputBytes) {
  throw new NdsError<NdsRuntimeCorrelationErrorCategory>(
    "runtime-correlation-output-limit",
    "Runtime correlation result exceeds configured output limit",
  );
}
```

- [ ] **Step 8: Run GREEN and commit**

```bash
node --test --import tsx tests/nds-runtime-correlation.test.ts
npm run typecheck
git add src/services/nds/errors.ts src/services/nds/runtime-correlation.ts \
  tests/nds-runtime-correlation.test.ts
git commit -m "feat: model canonical runtime stop correlation"
```

---

### Task 3: Attach bounded static instructions, references, and exact function-entry proof

**Files:**
- Modify: `src/services/nds/runtime-correlation.ts`
- Test: `tests/nds-runtime-correlation.test.ts`
- Reuse: `src/services/nds/disassembly.ts`
- Reuse: `src/services/nds/reference-list.ts`
- Reuse: `src/services/nds/function-analysis.ts`
- Reuse: `tests/helpers/nds-compressed-code-fixture.ts`

**Interfaces:**
- Uses `disassembleNdsRange(map, location, options, backend)`.
- Uses `listNdsReferences(map, location, options, backend)`.
- Uses `analyzeNdsFunction(map, request, limits, backend)`.
- Replaces candidate static type with:

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

- [ ] **Step 1: Write RED exact-mode disassembly tests**

For a known Thumb fixture:

```ts
assert.equal(candidate.static.status, "available");
assert.equal(candidate.static.instructions[0]?.address, observedPc);
assert.equal(candidate.static.instructions[0]?.mode, "thumb");
assert.ok(candidate.static.instructions.length <= 8);
```

Add an ARM case and a deliberate mode-mismatch fixture. The service must not retry the opposite mode.

- [ ] **Step 2: Write RED reference-limit tests**

Assert `referenceLimit: 0` returns `[]` and does not invoke reference analysis when dependencies are instrumented. Assert `referenceLimit: 2` truncates only the response list, not canonical ownership.

- [ ] **Step 3: Write RED exact function-entry tests**

Cover `proven`, `not-proven-function-entry`, and `proof-inconclusive`. Assert a mid-function PC is never labeled as a containing function.

- [ ] **Step 4: Run RED**

```bash
node --test --import tsx tests/nds-runtime-correlation.test.ts
```

Expected: FAIL because static evidence is still placeholder status.

- [ ] **Step 5: Construct one candidate-specific disassembly location**

```ts
const location = {
  processor: "arm9" as const,
  runtimeAddress: candidate.runtimeAddress,
  mode: input.stopContext.registers.mode,
  ...(candidate.overlayId === null ? {} : { overlayId: candidate.overlayId }),
};
```

Do not include `overlayId` for ARM9 main. Return `runtime-only` immediately when `candidate.representation === "runtime-only"`.

- [ ] **Step 6: Reuse existing bounded disassembly/reference services**

```ts
const maxBytes = Math.min(128, input.options.nearbyInstructions * 4);
const disassembly = await disassembleNdsRange(
  map,
  location,
  { maxInstructions: input.options.nearbyInstructions, maxBytes },
  backend,
);
```

If `"instructions" in disassembly` is false, return `not-decodable` with `reason: disassembly.status`.

When `referenceLimit > 0`:

```ts
const referenceResult = await listNdsReferences(
  map,
  location,
  { maxInstructions: input.options.nearbyInstructions, maxBytes },
  backend,
);
const references = "references" in referenceResult
  ? referenceResult.references.slice(0, input.options.referenceLimit)
  : [];
```

- [ ] **Step 7: Reuse exact function-entry proof**

Call `analyzeNdsFunction()` with the same processor/address/mode/overlay identity and conservative fixed limits copied from the existing public `nds_analyze_function` defaults. Do not create looser correlation-specific proof limits.

Record:

```ts
functionEntry: {
  proofStatus: analysis.proofStatus,
  runtimeMode: input.stopContext.registers.mode,
  staticMode: analysis.entry.mode,
  modeConsistent: analysis.entry.mode === input.stopContext.registers.mode,
  evidence: analysis.evidence,
}
```

A mismatch is reported; it never triggers another decode.

- [ ] **Step 8: Add compressed-overlay/BSS assertions**

Compressed initialized code:

```ts
assert.equal(candidate.canonical.representation, "derived-overlay");
assert.equal(candidate.static.status, "available");
assert.equal(candidate.static.instructions[0]?.romOffset, null);
```

BSS:

```ts
assert.equal(candidate.canonical.representation, "runtime-only");
assert.equal(candidate.static.status, "runtime-only");
```

- [ ] **Step 9: Run GREEN and commit**

```bash
node --test --import tsx \
  tests/nds-runtime-correlation.test.ts \
  tests/nds-compressed-static-analysis.test.ts \
  tests/nds-function-analysis.test.ts \
  tests/nds-reference-list.test.ts \
  tests/nds-disassembly.test.ts
npm run typecheck
git add src/services/nds/runtime-correlation.ts tests/nds-runtime-correlation.test.ts
git commit -m "feat: attach static evidence to runtime stops"
```

---

### Task 4: Expose `nds_correlate_stop_context` through shared live debugger state

**Files:**
- Create: `src/tools/nds-runtime.ts`
- Modify: `src/index.ts`
- Modify: capability/install enumeration files required by current tests
- Test: `tests/nds-runtime-tools.test.ts`
- Test: `tests/desmume-debug-tools.test.ts`
- Test: `tests/desmume-debug-lifecycle.test.ts`

**Interfaces:**

```ts
export function registerNdsRuntimeTools(
  server: McpServer,
  config: ServerConfig,
  manager: OwnedProcessManager,
  debuggerController: DebugController,
  backend: ArmDisassemblyBackend,
): void;
```

Public PR-A tool schema:

```ts
{
  timeoutMs: z.number().int().min(100).max(30_000).default(3_000),
  nearbyInstructions: z.number().int().min(1).max(32).default(8),
  referenceLimit: z.number().int().min(0).max(64).default(16),
}
```

- [ ] **Step 1: Write RED schema/registration tests**

Assert registration of exactly `nds_correlate_stop_context` and rejection of out-of-range timeout/instruction/reference values. The schema must expose no ROM/PC/processor/overlay field.

- [ ] **Step 2: Write RED no-process, missing-identity, and running-state tests**

Expected categories:

```text
runtime-correlation-no-owned-process
runtime-correlation-rom-identity-missing
runtime-correlation-debugger-not-stopped
```

The tool must not auto-pause a running debugger.

- [ ] **Step 3: Write RED stopped-state/no-resume test**

Use the fake RSP server. Correlation may issue stopped-state `?`, `g`, and bounded `m...` reads through `captureCurrentStopContext`, but must send no `c`, `s`, or `0x03` interrupt.

- [ ] **Step 4: Implement owned-session identity validation**

```ts
const status = manager.status();
if (!status.running) {
  throw new NdsError<NdsRuntimeCorrelationErrorCategory>(
    "runtime-correlation-no-owned-process",
    "No owned DeSmuME process is running",
  );
}
const romPath = status.metadata.rom;
const launchSha256 = status.metadata.romSha256;
if (
  typeof romPath !== "string"
  || typeof launchSha256 !== "string"
  || !/^[0-9a-f]{64}$/.test(launchSha256)
) {
  throw new NdsError<NdsRuntimeCorrelationErrorCategory>(
    "runtime-correlation-rom-identity-missing",
    "Owned DeSmuME session does not contain a valid launch-time ROM identity",
  );
}
```

- [ ] **Step 5: Require stopped state and capture without PC adjustment**

```ts
if (debuggerController.status().state !== "stopped") {
  throw new NdsError<NdsRuntimeCorrelationErrorCategory>(
    "runtime-correlation-debugger-not-stopped",
    "Runtime correlation requires the owned debugger to be stopped",
  );
}
const context = await debuggerController.captureCurrentStopContext({
  timeoutMs,
  maxOutputBytes: config.maxOutputBytes,
});
```

Pass `context.registers.pc` and `context.registers.mode` through unchanged.

- [ ] **Step 6: Compute safe display path and call correlation**

```ts
const displayPath = path.relative(config.workspaceRoot, romPath);
if (path.isAbsolute(displayPath) || displayPath === ".." || displayPath.startsWith(`..${path.sep}`)) {
  throw new NdsError<NdsRuntimeCorrelationErrorCategory>(
    "runtime-correlation-context-failed",
    "Owned ROM path is outside the configured workspace",
  );
}
```

Call `correlateNdsStopContext()` with `includeGhidra: false` and `decompileGhidraFunction: false`.

- [ ] **Step 7: Register from `src/index.ts` with the existing shared manager/controller/backend**

Do not instantiate a second `OwnedProcessManager`, `DebugController`, or ARM backend.

- [ ] **Step 8: Verify PR A**

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
git diff --check main...HEAD
```

Also verify no production diff in:

```bash
git diff main...HEAD -- src/services/gdb-session.ts src/services/gdb-rsp.ts src/services/debug-controller.ts
```

Expected: empty.

- [ ] **Step 9: Commit and open PR A**

```bash
git add src/services/nds/errors.ts src/services/nds/runtime-correlation.ts \
  src/tools/desmume.ts src/tools/nds-runtime.ts src/index.ts tests
git commit -m "feat: correlate stopped ARM9 state with NDS static analysis"
```

Open PR title:

```text
Correlate stopped ARM9 state with NDS static analysis
```

PR body must state: no GDB packet behavior changes; no Ghidra dependency in PR A; no loaded-overlay guessing; no write capabilities; physical Catalina acceptance remains pending.

---

# PR B — Controlled Ghidra enrichment + hardening

### Task 5: Add candidate-scoped already-ready Ghidra enrichment

**Files:**
- Create: `src/services/nds/runtime-correlation-ghidra.ts`
- Test: `tests/nds-runtime-correlation-ghidra.test.ts`
- Reuse: `src/services/nds/ghidra-inspection-readiness.ts`
- Reuse: `src/services/nds/ghidra-inspection-service.ts`

**Interfaces:**
- Reuse concrete `GhidraInspectionAuthorityResult`.
- Reuse `inspectNdsGhidraFunction()` and `decompileNdsGhidraFunction()`.
- Produces:

```ts
export type RuntimeGhidraEnrichment =
  | { readonly status: "not-requested" }
  | { readonly status: "not-ready"; readonly reason: string }
  | {
      readonly status: "available";
      readonly function: GhidraInspectionAuthorityResult;
      readonly decompilation: GhidraInspectionAuthorityResult | null;
    }
  | {
      readonly status: "failed";
      readonly category: string;
      readonly message: string;
    };

export interface RuntimeGhidraEnrichmentRequest {
  readonly romPath: string;
  readonly map: NdsRomMap;
  readonly candidate: RuntimeCandidate;
  readonly decompileFunction: boolean;
  readonly maxOutputBytes: number;
}

export type RuntimeGhidraEnricher = (
  request: RuntimeGhidraEnrichmentRequest,
) => Promise<RuntimeGhidraEnrichment>;
```

- [ ] **Step 1: Write RED absent/stale-project tests**

Use the existing readiness dependency and assert absent/stale project maps to `status: "not-ready"`. The adapter must have no bootstrap/reconcile function in its dependency interface.

- [ ] **Step 2: Write RED main/overlay selector tests**

Main:

```ts
assert.deepEqual(selector, {
  processor: "arm9",
  runtimeAddress: candidate.runtimeAddress,
});
```

Overlay:

```ts
assert.deepEqual(selector, {
  processor: "arm9",
  runtimeAddress: candidate.runtimeAddress,
  overlayId: candidate.overlayId,
});
```

- [ ] **Step 3: Run RED**

```bash
node --test --import tsx tests/nds-runtime-correlation-ghidra.test.ts
```

Expected: FAIL because the adapter does not exist.

- [ ] **Step 4: Implement readiness-only entry**

Use `readTrustedGhidraInspectionState()` before any inspection. Catch only its current-project absence/staleness category and return `not-ready`; other malformed/trust failures become `failed`.

- [ ] **Step 5: Run exact function inspection**

```ts
const selector = {
  processor: "arm9" as const,
  runtimeAddress: request.candidate.runtimeAddress,
  ...(request.candidate.overlayId === null
    ? {}
    : { overlayId: request.candidate.overlayId }),
};
const functionResult = await inspectNdsGhidraFunction(
  request.romPath,
  selector,
  config,
);
```

When `decompileFunction` is true, call `decompileNdsGhidraFunction()` with the same selector and existing configured/max-character bound. Do not search for a containing function when exact inspection says `found: false`.

- [ ] **Step 6: Preserve authority separation on errors**

Return Ghidra errors as:

```ts
{
  status: "failed",
  category: error instanceof NdsError ? error.category : "ghidra-inspection-failed",
  message: error instanceof Error ? error.message : String(error),
}
```

Do not catch or rewrite a top-level ROM identity mismatch from the correlation service.

- [ ] **Step 7: Run GREEN and commit**

```bash
node --test --import tsx \
  tests/nds-runtime-correlation-ghidra.test.ts \
  tests/nds-ghidra-inspection.test.ts \
  tests/nds-ghidra-inspection-readiness.test.ts
npm run typecheck
git add src/services/nds/runtime-correlation-ghidra.ts \
  tests/nds-runtime-correlation-ghidra.test.ts
git commit -m "feat: enrich runtime correlation from ready Ghidra projects"
```

---

### Task 6: Wire opt-in Ghidra enrichment into the correlation service/tool

**Files:**
- Modify: `src/services/nds/runtime-correlation.ts`
- Modify: `src/tools/nds-runtime.ts`
- Test: `tests/nds-runtime-correlation.test.ts`
- Test: `tests/nds-runtime-tools.test.ts`

**Interfaces:**

Extend options:

```ts
readonly includeGhidra: boolean;
readonly decompileGhidraFunction: boolean;
```

Extend service:

```ts
export async function correlateNdsStopContext(
  input: NdsRuntimeCorrelationInput,
  backend: ArmDisassemblyBackend,
  ghidraEnricher?: RuntimeGhidraEnricher,
): Promise<NdsRuntimeCorrelationResult>;
```

- [ ] **Step 1: Write RED no-Ghidra-work test**

With `includeGhidra: false`, inject an enricher that throws if called. Assert call count remains zero and every candidate has `ghidraDerived.status === "not-requested"`.

- [ ] **Step 2: Write RED ambiguous-overlay enrichment test**

For candidates 12 and 19, assert the enricher receives both explicit overlay IDs while top-level canonical status stays `ambiguous`.

- [ ] **Step 3: Implement per-candidate dispatch after static correlation**

```ts
const ghidraDerived = !input.options.includeGhidra
  ? { status: "not-requested" as const }
  : ghidraEnricher === undefined
    ? {
        status: "failed" as const,
        category: "ghidra-inspection-failed",
        message: "Ghidra enrichment dependency is unavailable",
      }
    : await ghidraEnricher({
        romPath: input.romPath,
        map,
        candidate,
        decompileFunction: input.options.decompileGhidraFunction,
        maxOutputBytes: input.options.maxOutputBytes,
      });
```

Do this only after canonical/static ownership has been established.

- [ ] **Step 4: Extend MCP schema**

```ts
includeGhidra: z.boolean().default(false),
decompileGhidraFunction: z.boolean().default(false),
```

Reject `decompileGhidraFunction: true` with `includeGhidra: false`; never silently enable Ghidra.

- [ ] **Step 5: Construct production enricher lazily**

The tool may close over `config`, but readiness/installation/subprocess work starts only inside the enricher after `includeGhidra === true`.

- [ ] **Step 6: Run GREEN and commit**

```bash
node --test --import tsx \
  tests/nds-runtime-correlation.test.ts \
  tests/nds-runtime-correlation-ghidra.test.ts \
  tests/nds-runtime-tools.test.ts
npm run typecheck
git add src/services/nds/runtime-correlation.ts src/tools/nds-runtime.ts \
  tests/nds-runtime-correlation.test.ts tests/nds-runtime-tools.test.ts
git commit -m "feat: add opt-in Ghidra runtime correlation"
```

---

### Task 7: Add mandatory real-Ghidra correlation acceptance

**Files:**
- Create: `scripts/ghidra-runtime-correlation-acceptance.mjs`
- Create: branch-scoped temporary workflow under `.github/workflows/`
- Create: `tests/nds-runtime-ghidra-acceptance-source.test.ts`

**Interfaces:**
- Uses the same pinned Ghidra 12.1.2 archive URL/SHA-256 and Temurin JDK 21 as current real-Ghidra acceptance.
- Exit 0 requires successful main and overlay correlation enrichment while preserving read-only project bytes.

- [ ] **Step 1: Write RED source-contract tests**

Require the new script/workflow to contain assertions for:

```text
main-code candidate
explicit overlay candidate
compressed-overlay candidate when fixture supports it
includeGhidra=true
canonical candidate asserted before ghidraDerived
read-only inspection
persistent project unchanged
hidden Ghidra exceptions rejected
```

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/nds-runtime-ghidra-acceptance-source.test.ts
```

Expected: FAIL because script/workflow do not exist.

- [ ] **Step 3: Implement real-tool acceptance script**

Reuse existing synthetic NDS/Ghidra acceptance fixture generation. Sequence:

```text
create fixture
explicitly bootstrap trusted project using existing acceptance path
snapshot persistent project
construct deterministic StopContext for ARM9 main
correlate with includeGhidra=true
assert canonical main identity then ghidraDerived available
construct deterministic StopContext for explicit overlay
correlate with includeGhidra=true
assert canonical overlay identity then ghidraDerived available
exercise compressed overlay when fixture provides one and assert romOffset remains null
verify project snapshot unchanged
```

This script intentionally does not launch DeSmuME or claim native debugger acceptance.

- [ ] **Step 4: Add hidden-error rejection**

Use the established application-log check:

```bash
log="$HOME/.config/ghidra/ghidra_12.1.2_PUBLIC/application.log"
if grep -nE 'REPORT SCRIPT ERROR|Exception' "$log"; then
  exit 1
fi
```

- [ ] **Step 5: Add branch-scoped workflow**

Use `ubuntu-24.04`, Node 20, Temurin 21, pinned Ghidra 12.1.2 checksum, `npm install`, `npm run check`, `npm run build`, script syntax check, acceptance run, and hidden-error check.

- [ ] **Step 6: Run local source verification**

```bash
node --check scripts/ghidra-runtime-correlation-acceptance.mjs
node --test --import tsx tests/nds-runtime-ghidra-acceptance-source.test.ts
npm run check
npm run build
```

- [ ] **Step 7: Commit and require Actions GREEN**

```bash
git add scripts/ghidra-runtime-correlation-acceptance.mjs \
  .github/workflows tests/nds-runtime-ghidra-acceptance-source.test.ts
git commit -m "test: add real Ghidra runtime correlation acceptance"
```

Do not mark PR B ready until this real Ghidra workflow passes on the exact current head. If head moves, rerun/reverify the new head.

---

### Task 8: Documentation, capability surface, and final trust-boundary verification

**Files:**
- Modify: `README.md`
- Modify: `docs/dynamic-debugging-catalina-acceptance.md`
- Create: `docs/nds-runtime-correlation.md`
- Modify: explicit capability/install enumeration files required by current tests
- Test: current install/capability/package tests

- [ ] **Step 1: Document the final tool contract**

Document:

```text
nds_correlate_stop_context
  timeoutMs
  nearbyInstructions
  referenceLimit
  includeGhidra
  decompileGhidraFunction
```

State explicitly: current stopped ARM9 only; exact launch/current SHA identity; no PC correction; overlap ambiguity preserved; compressed runtime provenance preserved; exact function-entry proof only; Ghidra optional/read-only/already-current only.

- [ ] **Step 2: Extend Catalina acceptance with one final correlation check**

After the existing real breakpoint/stop-context checks, add:

```text
real breakpoint stop
-> nds_correlate_stop_context
-> launch/current SHA match
-> observed PC/CPSR mode unchanged
-> valid canonical candidate(s)
-> bounded static evidence
```

Keep wording explicit that CI/fake-RSP coverage is not native DeSmuME proof.

- [ ] **Step 3: Update tool enumeration/capability tests**

Add exactly `nds_correlate_stop_context`; do not remove or rename existing tools.

- [ ] **Step 4: Run final focused/full verification**

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
npm run check
npm run build
git diff --check main...HEAD
```

- [ ] **Step 5: Verify no GDB transport/controller change**

```bash
git diff main...HEAD -- \
  src/services/gdb-session.ts \
  src/services/gdb-rsp.ts \
  src/services/debug-controller.ts
```

Expected: empty.

- [ ] **Step 6: Trust-boundary source review**

Search production runtime-correlation code for forbidden behavior. Any match must be only a rejection/error/documentation string, not an implementation path:

```bash
grep -RniE 'loadedOverlay|bestMatch|watchpoint|register write|memory write|bootstrap|reconcile|pc[[:space:]_-]*(rewind|adjust|correct)' \
  src/services/nds/runtime-correlation*.ts src/tools/nds-runtime.ts || true
```

Manually verify no call to Ghidra bootstrap/reconciliation exists in `runtime-correlation-ghidra.ts`.

- [ ] **Step 7: Verify exact-head checks and open/ready PR B**

Before marking ready, verify live head SHA has:

- CI success;
- Package success;
- mandatory real Ghidra runtime-correlation acceptance success.

Open/update PR title:

```text
Add controlled Ghidra enrichment to runtime correlation
```

PR body must state: canonical correlation comes from PR A; Ghidra enrichment is secondary; no auto-bootstrap/reconcile; no loaded-overlay inference; real Ghidra acceptance passed on exact head; physical Catalina/DeSmuME acceptance remains separate.

Do not merge either PR without explicit user authorization.
