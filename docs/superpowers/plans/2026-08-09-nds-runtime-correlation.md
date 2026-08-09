# Controlled NDS Runtime Correlation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correlate one current stopped server-owned DeSmuME ARM9 state with the exact launched NDS ROM, canonical static ownership, bounded ARM/Thumb analysis, existing proven function evidence, and optional already-ready read-only Ghidra context.

**Architecture:** PR A binds each owned emulator generation to a full ROM SHA-256, adds a pure canonical/static correlation service, and exposes one stopped-state MCP tool. PR B adds opt-in Ghidra enrichment after canonical candidate identity is established; Ghidra never bootstraps automatically, mutates state, or chooses a loaded overlay.

**Tech Stack:** Node.js 20+, TypeScript 5.7, MCP SDK/Zod, existing Capstone.js backend, existing NDS parser/resolver/disassembly/reference/function services, existing Ghidra 12.1.2/JDK 21 inspection infrastructure, Node test runner with `tsx`.

## Global Constraints

- Read-only only: no watchpoints, register writes, memory writes, arbitrary GDB packets, conditional breakpoint scripting, repeated-step tracing, ROM mutation, or Ghidra mutation.
- Public tool accepts no caller-selected ROM path, processor, PC, register set, overlay ID, memory region, Ghidra project/program/script path, or loaded-overlay hint.
- Processor is fixed to `arm9`.
- Launch identity is the full lowercase SHA-256 of the exact ROM used by that owned process generation.
- Hash before `OwnedProcessManager.start()` and after process creation. A mismatch stops that owned generation, resets debugger state, and fails start.
- Keep `readArm9ExecutableRange()` as the narrow launch compatibility path; invalid FAT/FNT/overlay data must not become a new `desmume_start` blocker.
- Correlation reparses with `readNdsRomMap()` and requires `map.sha256 === launchSha256`, then rehashes immediately before return.
- Preserve every `RuntimeCandidate` returned by `resolveRuntimeAddress()`; never guess overlapping loaded-overlay state.
- PC/mode come directly from decoded live registers/CPSR. No breakpoint-PC rewind/correction.
- Decode only the observed ARM/Thumb mode.
- Compressed overlays retain `representation: "derived-overlay"` and `romOffset: null`.
- BSS/runtime-only candidates get no fabricated code bytes.
- Function reporting is exact-entry proof only; no containing-function inference for arbitrary mid-function PCs.
- Ghidra remains under `ghidraDerived`; it cannot change canonical ownership or RE-MCP proof.
- `includeGhidra: false` performs no Ghidra work.
- Ghidra may use only an already-current full-ROM-SHA project via existing read-only/no-analysis inspection.
- No automatic Ghidra bootstrap, reconcile, migration, or auto-analysis.
- New MCP output exposes only a workspace-relative ROM path.
- `timeoutMs`: default 3000, range 100..30000.
- `nearbyInstructions`: default 8, range 1..32.
- `referenceLimit`: default 16, range 0..64.
- Final serialized response must fit `config.maxOutputBytes`.
- Existing debugger tool response shapes remain unchanged.
- Physical Intel Catalina/DeSmuME acceptance remains a separate gate.
- No new production runtime dependency.

---

## Delivery topology

1. **PR A — Runtime identity + canonical static correlation:** Tasks 1–4, branched from current `main`.
2. **PR B — Controlled Ghidra enrichment + hardening:** Tasks 5–8, branched from `main` only after PR A merges.

---

# PR A — Runtime identity + canonical static correlation

### Task 1: Bind owned DeSmuME generations to full ROM SHA-256

**Files:**
- Modify: `src/tools/desmume.ts`
- Reuse unchanged: `src/services/nds/io.ts`
- Test: `tests/nds-runtime-identity.test.ts`
- Test: `tests/desmume-start-race.test.ts`
- Test: `tests/desmume-debug-lifecycle.test.ts`

**Interfaces:**
- Consumes existing `hashFileSha256(filePath: string): Promise<string>`.
- Adds owned-process metadata `romSha256: string` beside `rom` and `arm9GdbPort`.

- [ ] **Step 1: Write RED metadata/mutation tests**

Assert a valid start request includes a 64-hex `romSha256`. Add a manager test double that mutates the ROM during `start()` and assert the process is stopped, debugger state resets to `unavailable`, and the result reports `ROM changed during DeSmuME start`.

- [ ] **Step 2: Write RED narrow-launch regression**

Create a fixture with a valid ARM9 header but malformed unrelated FAT/FNT/overlay data. Assert `desmume_start` still reaches `OwnedProcessManager.start()`.

- [ ] **Step 3: Run RED**

```bash
node --test --import tsx tests/nds-runtime-identity.test.ts tests/desmume-start-race.test.ts
```

Expected: FAIL because launch metadata has no ROM SHA and no post-start verification.

- [ ] **Step 4: Implement pre/post hashing**

```ts
const arm9Range = await readArm9ExecutableRange(romPath);
const romSha256 = await hashFileSha256(romPath);
const status = await manager.start({
  executable: launcherPath,
  args: buildDesmumeArguments(port, romPath),
  cwd: path.dirname(launcherPath),
  maxOutputBytes: config.maxOutputBytes,
  metadata: { emulator: "desmume", arm9GdbPort: port, rom: romPath, romSha256 },
});
const verifiedSha256 = await hashFileSha256(romPath);
if (verifiedSha256 !== romSha256) {
  await manager.stop();
  await debuggerController.reset("ROM identity changed during DeSmuME start");
  throw new Error("ROM changed during DeSmuME start; restart with an unchanged ROM");
}
```

Keep the existing owned-process-generation race check after identity verification.

- [ ] **Step 5: Run GREEN**

```bash
node --test --import tsx \
  tests/nds-runtime-identity.test.ts \
  tests/desmume-start-race.test.ts \
  tests/desmume-debug-lifecycle.test.ts \
  tests/desmume-debug-tools.test.ts
npm run typecheck
```

- [ ] **Step 6: Commit**

```bash
git add src/tools/desmume.ts tests/nds-runtime-identity.test.ts \
  tests/desmume-start-race.test.ts tests/desmume-debug-lifecycle.test.ts \
  tests/desmume-debug-tools.test.ts
git commit -m "feat: bind DeSmuME sessions to ROM identity"
```

---

### Task 2: Add correlation error categories and canonical ownership service

**Files:**
- Modify: `src/services/nds/errors.ts`
- Create: `src/services/nds/runtime-correlation.ts`
- Test: `tests/nds-runtime-correlation.test.ts`

**Interfaces:**

Add:

```ts
export type NdsRuntimeCorrelationErrorCategory =
  | "runtime-correlation-no-owned-process"
  | "runtime-correlation-rom-identity-missing"
  | "runtime-correlation-rom-identity-mismatch"
  | "runtime-correlation-debugger-not-stopped"
  | "runtime-correlation-context-failed"
  | "runtime-correlation-output-limit";
```

Include this union in `AnyNdsErrorCategory`.

Define:

```ts
export interface NdsRuntimeCorrelationOptions {
  readonly nearbyInstructions: number;
  readonly referenceLimit: number;
  readonly maxOutputBytes: number;
  readonly includeGhidra: boolean;
  readonly decompileGhidraFunction: boolean;
}

export interface NdsRuntimeCorrelationInput {
  readonly romPath: string;
  readonly romDisplayPath: string;
  readonly expectedRomSha256: string;
  readonly stopContext: StopContext;
  readonly options: NdsRuntimeCorrelationOptions;
}

export async function correlateNdsStopContext(
  input: NdsRuntimeCorrelationInput,
  backend: ArmDisassemblyBackend,
): Promise<NdsRuntimeCorrelationResult>;
```

Result must separate `runtimeObserved`, `rom`, top-level `canonical`, candidate `canonical`, candidate `static`, and candidate `ghidraDerived`.

- [ ] **Step 1: Write RED identity/resolution tests**

Cover ARM9 main, ambiguous overlays, compressed initialized overlay, BSS, and unmapped PC. Assert `runtimeObserved.pc` and `mode` equal the `StopContext.registers` values exactly.

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/nds-runtime-correlation.test.ts
```

- [ ] **Step 3: Implement identity and canonical resolution**

```ts
const map = await readNdsRomMap(input.romPath);
if (map.sha256 !== input.expectedRomSha256) {
  throw new NdsError<NdsRuntimeCorrelationErrorCategory>(
    "runtime-correlation-rom-identity-mismatch",
    "Current ROM SHA-256 does not match the launch-time ROM SHA-256",
  );
}
const resolution = resolveRuntimeAddress(map, input.stopContext.registers.pc, "arm9");
const candidates = resolution.status === "unmapped"
  ? []
  : resolution.status === "ambiguous-runtime-address"
    ? [...resolution.candidates].sort((a, b) => (a.overlayId ?? -1) - (b.overlayId ?? -1))
    : [resolution.candidate];
```

Sorting is only deterministic presentation; top-level status remains `ambiguous` when resolver status is ambiguous.

- [ ] **Step 4: Add final identity/output checks**

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

- [ ] **Step 5: Run GREEN and commit**

```bash
node --test --import tsx tests/nds-runtime-correlation.test.ts
npm run typecheck
git add src/services/nds/errors.ts src/services/nds/runtime-correlation.ts \
  tests/nds-runtime-correlation.test.ts
git commit -m "feat: model canonical runtime stop correlation"
```

---

### Task 3: Attach bounded static instructions, references, and exact function proof

**Files:**
- Modify: `src/services/nds/runtime-correlation.ts`
- Test: `tests/nds-runtime-correlation.test.ts`
- Reuse: `src/services/nds/disassembly.ts`
- Reuse: `src/services/nds/reference-list.ts`
- Reuse: `src/services/nds/function-analysis.ts`
- Reuse: `tests/helpers/nds-compressed-code-fixture.ts`

**Interfaces:**

Candidate static output:

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
  | { readonly status: "runtime-only" | "not-decodable"; readonly reason: string };
```

- [ ] **Step 1: Write RED static-evidence tests**

Cover observed Thumb and ARM, `referenceLimit: 0`, direct-call reference retention, exact program/direct-call function proof, non-proven mid-function PC, compressed-overlay `romOffset: null`, and BSS `runtime-only`.

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/nds-runtime-correlation.test.ts
```

- [ ] **Step 3: Build candidate-specific location using observed mode only**

```ts
const location = {
  processor: "arm9" as const,
  runtimeAddress: candidate.runtimeAddress,
  mode: input.stopContext.registers.mode,
  ...(candidate.overlayId === null ? {} : { overlayId: candidate.overlayId }),
};
```

If `candidate.representation === "runtime-only"`, return `status: "runtime-only"` without invoking decoder services.

- [ ] **Step 4: Reuse bounded disassembly/reference services**

```ts
const maxBytes = Math.min(128, input.options.nearbyInstructions * 4);
const disassembly = await disassembleNdsRange(
  map,
  location,
  { maxInstructions: input.options.nearbyInstructions, maxBytes },
  backend,
);
```

If no `instructions` field exists, return `not-decodable` with `reason: disassembly.status`.

When `referenceLimit > 0`, call `listNdsReferences()` with the same location/window and slice returned references to `referenceLimit`; when limit is 0, do not call it.

- [ ] **Step 5: Reuse exact function-entry proof with fixed existing-style bounds**

Call `analyzeNdsFunction()` using the same processor/address/mode/overlay identity. Use:

```ts
proof: {
  maxComponents: 32,
  maxBlocks: 128,
  maxInstructions: 2048,
  maxBytes: 8192,
  maxEdges: 512,
  maxXrefs: 256,
},
cfg: {
  maxBlocks: 64,
  maxInstructions: 512,
  maxBytes: 2048,
  maxEdges: 128,
},
```

Use a proof scope/seeds equivalent to current public defaults for the candidate's canonical component. Do not broaden proof rules.

Record `modeConsistent: analysis.entry.mode === input.stopContext.registers.mode`; never retry the other mode.

- [ ] **Step 6: Run GREEN and commit**

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

### Task 4: Expose `nds_correlate_stop_context` using shared manager/controller state

**Files:**
- Create: `src/tools/nds-runtime.ts`
- Modify: `src/index.ts`
- Modify: explicit capability/install enumeration files required by current tests
- Test: `tests/nds-runtime-tools.test.ts`
- Test: existing DeSmuME lifecycle/tool tests

**Interfaces:**

```ts
export function registerNdsRuntimeTools(
  server: McpServer,
  config: ServerConfig,
  manager: OwnedProcessManager,
  debuggerController: DebugController,
): void;
```

Tool schema for PR A:

```ts
{
  timeoutMs: z.number().int().min(100).max(30_000).default(3_000),
  nearbyInstructions: z.number().int().min(1).max(32).default(8),
  referenceLimit: z.number().int().min(0).max(64).default(16),
}
```

- [ ] **Step 1: Write RED schema/state tests**

Cover registration, bounds, no-owned-process, missing launch identity, running debugger rejection, stopped success, and no caller ROM/PC/processor/overlay fields.

- [ ] **Step 2: Write RED no-resume fake-RSP test**

Correlation may use stopped-state `?`, `g`, and bounded `m...` reads through `captureCurrentStopContext`; fake server must observe no `c`, `s`, or interrupt byte.

- [ ] **Step 3: Implement live state validation/capture**

Validate `manager.status()` and 64-hex `metadata.romSha256`; require `debuggerController.status().state === "stopped"`; then:

```ts
const context = await debuggerController.captureCurrentStopContext({
  timeoutMs,
  maxOutputBytes: config.maxOutputBytes,
});
```

Do not alter `context.registers.pc` or `mode`.

- [ ] **Step 4: Compute workspace-relative display path**

```ts
const displayPath = path.relative(config.workspaceRoot, romPath);
if (path.isAbsolute(displayPath) || displayPath === ".." || displayPath.startsWith(`..${path.sep}`)) {
  throw new NdsError<NdsRuntimeCorrelationErrorCategory>(
    "runtime-correlation-context-failed",
    "Owned ROM path is outside the configured workspace",
  );
}
```

- [ ] **Step 5: Create/close Capstone backend per invocation**

Match existing NDS tool lifecycle:

```ts
const backend = await createCapstoneArmBackend();
try {
  return await correlateNdsStopContext(input, backend);
} finally {
  backend.close();
}
```

- [ ] **Step 6: Share the existing DebugController in `src/index.ts`**

Change:

```ts
registerDesmumeTools(server, config, desmumeManager);
```

to:

```ts
const desmumeDebugger = registerDesmumeTools(server, config, desmumeManager);
registerNdsRuntimeTools(server, config, desmumeManager, desmumeDebugger);
```

Do not create a second manager/controller.

- [ ] **Step 7: Verify PR A and open PR**

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
git diff main...HEAD -- src/services/gdb-session.ts src/services/gdb-rsp.ts src/services/debug-controller.ts
```

Expected final diff command: empty.

Commit:

```bash
git add src tests
git commit -m "feat: correlate stopped ARM9 state with NDS static analysis"
```

Open PR: **`Correlate stopped ARM9 state with NDS static analysis`**. State explicitly: no GDB packet change, no Ghidra dependency in PR A, no loaded-overlay guessing, no writes, physical Catalina acceptance still pending.

---

# PR B — Controlled Ghidra enrichment + hardening

### Task 5: Add candidate-scoped already-current Ghidra enrichment

**Files:**
- Create: `src/services/nds/runtime-correlation-ghidra.ts`
- Test: `tests/nds-runtime-correlation-ghidra.test.ts`
- Reuse: `src/services/nds/ghidra-inspection-service.ts`

**Interfaces:**

```ts
export type RuntimeGhidraEnrichment =
  | { readonly status: "not-requested" }
  | { readonly status: "not-ready"; readonly reason: string }
  | {
      readonly status: "available";
      readonly function: GhidraInspectionAuthorityResult;
      readonly decompilation: GhidraInspectionAuthorityResult | null;
    }
  | { readonly status: "failed"; readonly category: string; readonly message: string };

export interface RuntimeGhidraEnrichmentRequest {
  readonly romPath: string;
  readonly candidate: RuntimeCandidate;
  readonly decompileFunction: boolean;
}

export type RuntimeGhidraEnricher = (
  request: RuntimeGhidraEnrichmentRequest,
) => Promise<RuntimeGhidraEnrichment>;
```

- [ ] **Step 1: Write RED main/overlay/not-ready tests**

Assert main selector omits `overlayId`; overlay selector includes the exact canonical ID. Assert `ghidra-project-not-current` becomes `status: "not-ready"`. Adapter dependency surface must contain no bootstrap/reconcile function.

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/nds-runtime-correlation-ghidra.test.ts
```

- [ ] **Step 3: Implement exact selector and inspect function**

```ts
const selector = {
  processor: "arm9" as const,
  runtimeAddress: request.candidate.runtimeAddress,
  ...(request.candidate.overlayId === null ? {} : { overlayId: request.candidate.overlayId }),
};
const functionResult = await inspectNdsGhidraFunction(request.romPath, selector, config);
```

The inspection service itself enforces current-project readiness, exact canonical selector identity, read-only/no-analysis invocation, and ROM identity.

- [ ] **Step 4: Decompile only exact found function when requested**

If `request.decompileFunction` and `functionResult.ghidraDerived.found === true`, call `decompileNdsGhidraFunction()` with the same selector. Do not search for a containing function when `found` is false.

- [ ] **Step 5: Preserve Ghidra failure category**

Map `ghidra-project-not-current` to `not-ready`. Other Ghidra inspection errors become `failed` with original category/message. Do not rewrite canonical data.

- [ ] **Step 6: Run GREEN and commit**

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

### Task 6: Wire opt-in Ghidra enrichment into service/tool

**Files:**
- Modify: `src/services/nds/runtime-correlation.ts`
- Modify: `src/tools/nds-runtime.ts`
- Test: `tests/nds-runtime-correlation.test.ts`
- Test: `tests/nds-runtime-tools.test.ts`

**Interfaces:**

```ts
export async function correlateNdsStopContext(
  input: NdsRuntimeCorrelationInput,
  backend: ArmDisassemblyBackend,
  ghidraEnricher?: RuntimeGhidraEnricher,
): Promise<NdsRuntimeCorrelationResult>;
```

Tool adds:

```ts
includeGhidra: z.boolean().default(false),
decompileGhidraFunction: z.boolean().default(false),
```

- [ ] **Step 1: Write RED no-work and ambiguity tests**

With `includeGhidra: false`, an injected enricher must never be called. With overlapping overlays and Ghidra enabled, enricher receives every canonical candidate separately while top-level status remains ambiguous.

- [ ] **Step 2: Implement dispatch after canonical/static evidence**

```ts
const ghidraDerived = !input.options.includeGhidra
  ? { status: "not-requested" as const }
  : ghidraEnricher === undefined
    ? { status: "failed" as const, category: "ghidra-inspection-failed", message: "Ghidra enrichment dependency is unavailable" }
    : await ghidraEnricher({
        romPath: input.romPath,
        candidate,
        decompileFunction: input.options.decompileGhidraFunction,
      });
```

- [ ] **Step 3: Enforce option relationship**

Reject `decompileGhidraFunction: true` when `includeGhidra: false`; never silently enable Ghidra.

- [ ] **Step 4: Run GREEN and commit**

```bash
node --test --import tsx \
  tests/nds-runtime-correlation.test.ts \
  tests/nds-runtime-correlation-ghidra.test.ts \
  tests/nds-runtime-tools.test.ts
npm run typecheck
git add src/services/nds/runtime-correlation.ts src/tools/nds-runtime.ts tests
git commit -m "feat: add opt-in Ghidra runtime correlation"
```

---

### Task 7: Add mandatory real-Ghidra correlation acceptance

**Files:**
- Create: `scripts/ghidra-runtime-correlation-acceptance.mjs`
- Create: branch-scoped temporary workflow under `.github/workflows/`
- Create: `tests/nds-runtime-ghidra-acceptance-source.test.ts`

- [ ] **Step 1: Write RED source-contract test**

Require pinned Ghidra 12.1.2 checksum/JDK 21 and assertions for main candidate, explicit overlay candidate, compressed overlay when fixture supports it, canonical-before-Ghidra authority, read-only project preservation, and hidden Ghidra exception rejection.

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/nds-runtime-ghidra-acceptance-source.test.ts
```

- [ ] **Step 3: Implement real-tool acceptance flow**

Reuse existing synthetic Ghidra acceptance fixture. Explicitly bootstrap through the existing acceptance helper, snapshot persistent project, construct deterministic `StopContext` objects (no DeSmuME), run correlation with `includeGhidra: true`, assert canonical identity first and `ghidraDerived.status === "available"` second, test compressed-overlay `romOffset: null`, then verify project snapshot unchanged.

- [ ] **Step 4: Add workflow and hidden-error check**

Use `ubuntu-24.04`, Node 20, Temurin 21, existing pinned Ghidra 12.1.2 URL/SHA, `npm install`, `npm run check`, `npm run build`, `node --check`, acceptance execution, and:

```bash
log="$HOME/.config/ghidra/ghidra_12.1.2_PUBLIC/application.log"
if grep -nE 'REPORT SCRIPT ERROR|Exception' "$log"; then exit 1; fi
```

- [ ] **Step 5: Verify locally, commit, then require Actions GREEN**

```bash
node --check scripts/ghidra-runtime-correlation-acceptance.mjs
node --test --import tsx tests/nds-runtime-ghidra-acceptance-source.test.ts
npm run check
npm run build
git add scripts .github/workflows tests/nds-runtime-ghidra-acceptance-source.test.ts
git commit -m "test: add real Ghidra runtime correlation acceptance"
```

Do not mark PR B ready until real Ghidra acceptance passes on the exact current head.

---

### Task 8: Documentation, capability surface, and final trust-boundary verification

**Files:**
- Modify: `README.md`
- Modify: `src/index.ts` capability text/tool list
- Modify: `docs/dynamic-debugging-catalina-acceptance.md`
- Create: `docs/nds-runtime-correlation.md`
- Modify: install/package capability tests as required

- [ ] **Step 1: Document final tool**

Document `timeoutMs`, `nearbyInstructions`, `referenceLimit`, `includeGhidra`, `decompileGhidraFunction`; stopped ARM9 only; exact launch/current SHA; no PC correction; overlapping ambiguity; compressed provenance; exact-entry proof; Ghidra optional/read-only/current-only.

- [ ] **Step 2: Extend Catalina native checklist**

After existing real breakpoint/stop-context checks add:

```text
real breakpoint stop
-> nds_correlate_stop_context
-> launch/current SHA match
-> observed PC/CPSR mode unchanged
-> canonical candidate(s)
-> bounded static evidence
```

State that CI/fake-RSP does not equal native DeSmuME proof.

- [ ] **Step 3: Update capability enumeration**

Add exactly `nds_correlate_stop_context`; preserve every existing tool name.

- [ ] **Step 4: Run final verification**

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
git diff main...HEAD -- src/services/gdb-session.ts src/services/gdb-rsp.ts src/services/debug-controller.ts
```

Expected final diff command: empty.

- [ ] **Step 5: Trust-boundary search**

```bash
grep -RniE 'loadedOverlay|bestMatch|watchpoint|register write|memory write|pc[[:space:]_-]*(rewind|adjust|correct)' \
  src/services/nds/runtime-correlation*.ts src/tools/nds-runtime.ts || true
```

Any match must be rejection text, not implementation. Manually confirm `runtime-correlation-ghidra.ts` imports/calls no bootstrap/reconcile function.

- [ ] **Step 6: Verify exact-head CI/Package/real-Ghidra checks and open PR B**

Open/update PR title **`Add controlled Ghidra enrichment to runtime correlation`**. State: canonical correlation comes from PR A; Ghidra is secondary; no auto-bootstrap/reconcile; no loaded-overlay inference; real Ghidra acceptance passed on exact head; physical Catalina acceptance remains separate.

Do not merge either PR without explicit user authorization.
