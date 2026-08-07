# Dynamic Debugging Breakpoints Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add controlled ARM9 software breakpoints, bounded execution control, and structured stop-context capture for the single DeSmuME process owned by RE-MCP.

**Architecture:** Implement Patch 1 in three reviewable PRs. PR 1 adds the stateful GDB session, ROM-derived executable ranges, ARM/Thumb mode resolution, and breakpoint registry. PR 2 adds real breakpoint packets and execution control. PR 3 exposes MCP tools, register decoding, context capture, lifecycle cleanup, documentation, and native acceptance steps.

**Tech Stack:** Node.js 20+, TypeScript 5.7, Node `net`, Node test runner, `tsx`, Zod, MCP SDK, GDB Remote Serial Protocol, Nintendo DS ROM header parsing.

## Global Constraints

- Only connect to `127.0.0.1` and the ARM9 GDB port owned by the current DeSmuME process.
- Do not expose arbitrary GDB RSP packets.
- Do not add register writes, general memory writes, or watchpoints.
- Maximum active breakpoints: 32.
- Maximum single-step count per request: 100.
- Maximum wait or continue timeout: 30000 ms.
- ARM addresses must be 4-byte aligned; Thumb addresses must be 2-byte aligned.
- `auto` mode must fail when execution mode remains ambiguous.
- Breakpoints are valid only inside the derived ARM9 range or an explicitly allowlisted executable range.
- Debugger state must reset when the owned DeSmuME process changes or exits.
- Existing read-only register and memory tools must continue to work.
- Every task follows TDD: failing test, minimal implementation, passing test, commit.

---

# PR 1 — Debugger Foundation

## File Structure

- Create `src/services/gdb-session.ts`: persistent localhost-only RSP session and debugger state machine.
- Create `src/services/gdb-stop.ts`: stop-reply types and parsers.
- Create `src/services/nds-arm9.ts`: NDS ARM9 header parser and executable-range derivation.
- Create `src/services/executable-ranges.ts`: executable allowlist and ARM/Thumb mode resolution.
- Create `src/services/breakpoint-registry.ts`: session-scoped breakpoint bookkeeping.
- Modify `src/services/gdb-rsp.ts`: export shared packet/checksum helpers without changing current behavior.
- Modify `src/services/owned-process.ts`: expose stable process identity needed to invalidate debugger sessions.
- Test in `tests/gdb-session.test.ts`, `tests/gdb-stop.test.ts`, `tests/nds-arm9.test.ts`, `tests/executable-ranges.test.ts`, and `tests/breakpoint-registry.test.ts`.

### Task 1: Extract reusable RSP framing

**Files:**
- Modify: `src/services/gdb-rsp.ts`
- Test: `tests/gdb-rsp.test.ts`

**Interfaces:**
- Produces: `rspChecksum(payload: string): string`
- Produces: `encodeRspPacket(payload: string): string`
- Produces: `parseRspPacket(buffer: string): { payload: string; raw: string; consumed: number } | null`

- [ ] **Step 1: Write failing packet-parser tests**

Add tests covering a valid packet, an incomplete packet, checksum mismatch, and a leading `+` acknowledgement before `$...#xx`.

```ts
assert.deepEqual(parseRspPacket("+$OK#9a"), {
  payload: "OK",
  raw: "$OK#9a",
  consumed: 7,
});
```

- [ ] **Step 2: Run the focused test**

Run: `node --test --import tsx tests/gdb-rsp.test.ts`

Expected: FAIL because `parseRspPacket` and `rspChecksum` are not exported.

- [ ] **Step 3: Implement the minimal framing helpers**

Preserve `sendRspCommand()` behavior. Reject checksum mismatches with `Error("GDB RSP reply checksum mismatch")`.

- [ ] **Step 4: Run focused and full tests**

Run:

```bash
node --test --import tsx tests/gdb-rsp.test.ts
npm test
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/services/gdb-rsp.ts tests/gdb-rsp.test.ts
git commit -m "refactor: extract reusable GDB RSP framing"
```

### Task 2: Add stop-reply parsing

**Files:**
- Create: `src/services/gdb-stop.ts`
- Test: `tests/gdb-stop.test.ts`

**Interfaces:**
- Produces: `type GdbStopReply`
- Produces: `parseGdbStopReply(payload: string): GdbStopReply`

```ts
export type GdbStopReply =
  | { kind: "signal"; signal: number; fields: Readonly<Record<string, string>>; raw: string }
  | { kind: "exited"; status: number; raw: string }
  | { kind: "terminated"; signal: number; raw: string };
```

- [ ] **Step 1: Write failing tests for `S`, `T`, `W`, and `X` replies**

Include malformed hex, unsupported payloads, and `T05thread:1;` field parsing.

- [ ] **Step 2: Verify failure**

Run: `node --test --import tsx tests/gdb-stop.test.ts`

Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement strict parser**

Reject unsupported payloads with `Error("Unsupported GDB stop reply: <payload>")`.

- [ ] **Step 4: Run tests**

Run: `node --test --import tsx tests/gdb-stop.test.ts`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/services/gdb-stop.ts tests/gdb-stop.test.ts
git commit -m "feat: parse GDB stop replies"
```

### Task 3: Add a persistent GDB session state machine

**Files:**
- Create: `src/services/gdb-session.ts`
- Test: `tests/gdb-session.test.ts`

**Interfaces:**
- Produces: `type DebuggerState = "unavailable" | "stopped" | "running" | "waiting"`
- Produces: `class GdbSession`

```ts
new GdbSession({
  host: "127.0.0.1",
  port,
  maxReplyBytes,
  connectTimeoutMs,
});
```

Required methods in PR 1:

```ts
connect(): Promise<void>
close(): Promise<void>
state(): DebuggerState
sendStoppedCommand(payload: string, timeoutMs: number): Promise<string>
reset(reason: string): void
```

`sendStoppedCommand` is an internal explicit command transport, not an MCP-exposed arbitrary packet API.

- [ ] **Step 1: Create a deterministic fake RSP server in the test file**

The fake server must validate client packets, send `+`, and return configured packet replies.

- [ ] **Step 2: Write failing lifecycle tests**

Cover connect, serialized command use, checksum failure, reply-size limit, timeout, close, and reset.

- [ ] **Step 3: Run the focused test**

Run: `node --test --import tsx tests/gdb-session.test.ts`

Expected: FAIL because `GdbSession` is absent.

- [ ] **Step 4: Implement minimal persistent socket/session behavior**

Do not implement continue, step, or pause yet. Session starts in `stopped` only after a successful command exchange or explicit initialization method.

- [ ] **Step 5: Run tests and typecheck**

```bash
node --test --import tsx tests/gdb-session.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/services/gdb-session.ts tests/gdb-session.test.ts
git commit -m "feat: add persistent GDB session foundation"
```

### Task 4: Parse the ARM9 executable range from an NDS ROM

**Files:**
- Create: `src/services/nds-arm9.ts`
- Test: `tests/nds-arm9.test.ts`

**Interfaces:**
- Produces: `readArm9ExecutableRange(romPath: string): Promise<Arm9ExecutableRange>`

```ts
interface Arm9ExecutableRange {
  readonly start: number;
  readonly end: number;
  readonly size: number;
  readonly source: "arm9-header";
  readonly label: "ARM9 main";
}
```

- [ ] **Step 1: Write fixture-building tests**

Create temporary ROM headers with little-endian values at `0x28` and `0x2C`. Test valid parsing, short file, zero size, overflow beyond `0xffffffff`, and unreasonable range outside DS main RAM.

- [ ] **Step 2: Verify failure**

Run: `node --test --import tsx tests/nds-arm9.test.ts`

Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement bounded 0x30-byte header read**

Validate the range is inside `0x02000000` through `0x02400000` and that `end > start`.

- [ ] **Step 4: Run tests**

Run: `node --test --import tsx tests/nds-arm9.test.ts`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/services/nds-arm9.ts tests/nds-arm9.test.ts
git commit -m "feat: derive ARM9 executable range from NDS header"
```

### Task 5: Add executable-range validation and mode resolution

**Files:**
- Create: `src/services/executable-ranges.ts`
- Test: `tests/executable-ranges.test.ts`

**Interfaces:**
- Produces: `ExecutableRangeRegistry`
- Produces: `normalizeBreakpointAddress(address: number, mode: BreakpointMode): number`
- Produces: `resolveExecutionMode(input: ResolveModeInput): "arm" | "thumb"`

```ts
type BreakpointMode = "arm" | "thumb" | "auto";
type RangeSource = "arm9-header" | "overlay" | "explicit";
```

- [ ] **Step 1: Write failing tests**

Cover range count limits, overlap rules, address containment, ARM/Thumb alignment, bit-0 Thumb normalization, symbol mode, range default, execution history, Thumb-bit inference, unambiguous 2-byte alignment, and ambiguous 4-byte alignment rejection.

- [ ] **Step 2: Verify failure**

Run: `node --test --import tsx tests/executable-ranges.test.ts`

- [ ] **Step 3: Implement the registry and resolver**

Cap additional ranges at 64. Preserve the derived ARM9 range and reject its removal.

- [ ] **Step 4: Run tests and typecheck**

```bash
node --test --import tsx tests/executable-ranges.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/services/executable-ranges.ts tests/executable-ranges.test.ts
git commit -m "feat: validate executable ranges and ARM Thumb modes"
```

### Task 6: Add the breakpoint registry

**Files:**
- Create: `src/services/breakpoint-registry.ts`
- Test: `tests/breakpoint-registry.test.ts`

**Interfaces:**
- Produces: `BreakpointRegistry`
- Produces: `BreakpointRecord`

Required methods:

```ts
add(input: AddBreakpointInput): BreakpointRecord
remove(id: string): BreakpointRecord
markInstalled(id: string): void
markRemoved(id: string): void
recordHit(address: number, mode: "arm" | "thumb"): BreakpointRecord | null
list(): readonly BreakpointRecord[]
clear(): void
```

- [ ] **Step 1: Write failing tests**

Cover generated IDs, 32-item cap, duplicate address/mode rejection, install state, hit counts, unknown removal, deterministic listing order, and clear.

- [ ] **Step 2: Verify failure**

Run: `node --test --import tsx tests/breakpoint-registry.test.ts`

- [ ] **Step 3: Implement the in-memory registry**

Use server-generated IDs such as `bp-1`, `bp-2`; no persistence.

- [ ] **Step 4: Run all PR 1 tests**

```bash
node --test --import tsx \
  tests/gdb-rsp.test.ts \
  tests/gdb-stop.test.ts \
  tests/gdb-session.test.ts \
  tests/nds-arm9.test.ts \
  tests/executable-ranges.test.ts \
  tests/breakpoint-registry.test.ts
npm run check
npm run build
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/services/breakpoint-registry.ts tests/breakpoint-registry.test.ts
git commit -m "feat: add bounded breakpoint registry"
```

### Task 7: Open PR 1

- [ ] **Step 1: Review the branch diff against `main`**

Run: `git diff --check main...HEAD`

Expected: no whitespace errors.

- [ ] **Step 2: Open PR**

Title: `Add dynamic debugger foundation`

The PR body must list the stateful GDB session, ARM9 parser, executable-range policy, mode resolver, registry limits, tests, and explicitly state that no execution-control MCP tools are exposed yet.

---

# PR 2 — Breakpoints and Execution Control

Start from current `main` after PR 1 merges.

## File Structure

- Modify `src/services/gdb-session.ts`: add breakpoint, continue, step, wait, and interrupt methods.
- Create `src/services/debug-controller.ts`: coordinate session, registry, executable ranges, and execution state.
- Test in `tests/gdb-session-execution.test.ts` and `tests/debug-controller.test.ts`.

### Task 8: Implement software breakpoint packet lifecycle

**Interfaces:**

```ts
insertSoftwareBreakpoint(address: number, kind: 2 | 4, timeoutMs: number): Promise<void>
removeSoftwareBreakpoint(address: number, kind: 2 | 4, timeoutMs: number): Promise<void>
```

- [ ] Write failing fake-server tests for `Z0,<addr>,<kind>` and `z0,<addr>,<kind>`.
- [ ] Verify tests fail.
- [ ] Implement strict `OK` acknowledgement handling; reject `E..` and unsupported replies.
- [ ] Run focused tests and commit `feat: add GDB software breakpoint packets`.

### Task 9: Implement continue, wait, and pause

**Interfaces:**

```ts
continueExecution(timeoutMs: number): Promise<ExecutionResult>
waitForStop(timeoutMs: number): Promise<ExecutionResult>
interruptAndWait(timeoutMs: number): Promise<ExecutionResult>
```

- [ ] Write failing tests for `c`, asynchronous stop replies, timeout while remaining running, `0x03` interrupt, exit replies, and connection loss.
- [ ] Verify failure.
- [ ] Implement state transitions exactly as defined in the spec.
- [ ] Run focused tests and commit `feat: add bounded GDB execution control`.

### Task 10: Implement bounded single stepping

**Interfaces:**

```ts
stepInstructions(count: number, perStepTimeoutMs: number): Promise<StepSequenceResult>
```

- [ ] Write failing tests for one step, 100 steps, rejecting 0 and 101, stopping early on breakpoint/signal/exit/timeout.
- [ ] Implement one `s` packet per instruction.
- [ ] Run focused tests and commit `feat: add bounded ARM9 single stepping`.

### Task 11: Add the debug controller

**Files:**
- Create: `src/services/debug-controller.ts`
- Test: `tests/debug-controller.test.ts`

**Interfaces:**

```ts
class DebugController {
  initialize(sessionIdentity: string, arm9Range: Arm9ExecutableRange): void;
  replaceAdditionalRanges(ranges: readonly ExecutableRangeInput[]): void;
  addBreakpoint(input: AddBreakpointRequest): Promise<BreakpointRecord>;
  removeBreakpoint(id: string): Promise<BreakpointRecord>;
  continueExecution(input: ContinueRequest): Promise<ExecutionResult>;
  step(input: StepRequest): Promise<StepSequenceResult>;
  pause(timeoutMs: number): Promise<ExecutionResult>;
  waitForStop(timeoutMs: number): Promise<ExecutionResult>;
  reset(reason: string): Promise<void>;
}
```

- [ ] Write failing orchestration tests.
- [ ] Implement rollback when GDB installation fails so registry and stub never diverge.
- [ ] Verify session identity changes clear breakpoints and close the old connection.
- [ ] Run `npm run check && npm run build`.
- [ ] Commit `feat: coordinate breakpoints and debugger execution`.

### Task 12: Open PR 2

Title: `Add controlled ARM9 breakpoints and execution control`

The PR body must document supported packets (`Z0`, `z0`, `c`, `s`, interrupt), timeouts, failure recovery, and fake-RSP integration coverage.

---

# PR 3 — Stop Context and MCP Integration

Start from current `main` after PR 2 merges.

## File Structure

- Create `src/services/arm9-registers.ts`: decode supported DeSmuME register packets.
- Create `src/services/stop-context.ts`: capture stop reason, registers, and bounded memory windows.
- Modify `src/services/debug-controller.ts`: hit matching, execution history, and context capture.
- Modify `src/tools/desmume.ts`: expose validated MCP tools and start-time ARM9 metadata.
- Modify `src/services/owned-process.ts`: notify/reset debugger lifecycle if needed.
- Modify `README.md`: document dynamic-debugging capabilities and safety limits.
- Test in `tests/arm9-registers.test.ts`, `tests/stop-context.test.ts`, `tests/desmume-debug-tools.test.ts`, and existing DeSmuME tests.

### Task 13: Decode ARM9 registers

**Interfaces:**

```ts
decodeArm9RegisterPacket(payload: string): Arm9RegisterContext
```

The result includes `r0`–`r12`, `sp`, `lr`, `pc`, `cpsr`, `raw`, `byteOrder: "little"`, and `mode` from CPSR bit 5.

- [ ] Write failing fixtures for the exact supported DeSmuME packet width and malformed packets.
- [ ] Implement strict little-endian decoding.
- [ ] Run tests and commit `feat: decode DeSmuME ARM9 registers`.

### Task 14: Capture structured stop context

**Interfaces:**

```ts
captureStopContext(input: CaptureStopContextInput): Promise<StopContext>
```

Defaults:

- 64 bytes around PC;
- 64 bytes from SP;
- up to eight additional regions;
- each region at most 4096 bytes;
- total response bounded by `config.maxOutputBytes`.

- [ ] Write failing tests for PC underflow/overflow clamping, SP reads, additional-region limits, GDB memory errors, and output limits.
- [ ] Implement context capture using existing read-only `m` behavior.
- [ ] Run tests and commit `feat: capture structured debugger stop context`.

### Task 15: Wire context and hit tracking into the controller

- [ ] Write failing tests that match stop PC to a breakpoint, increment hit count, record execution history, and preserve unexpected stops.
- [ ] Implement context capture for continue, wait, pause, and final step result when requested.
- [ ] Run tests and commit `feat: attach context to debugger stops`.

### Task 16: Expose MCP tools

**Files:**
- Modify: `src/tools/desmume.ts`
- Test: `tests/desmume-debug-tools.test.ts`

Add:

```text
desmume_breakpoint_add
desmume_breakpoint_remove
desmume_breakpoint_list
desmume_continue
desmume_step_instruction
desmume_pause
desmume_wait_for_stop
desmume_capture_stop_context
desmume_executable_ranges_replace
```

`desmume_start` must parse the ROM header before launch and initialize the controller with the owned process identity and derived ARM9 range.

- [ ] Write failing MCP registration and validation tests.
- [ ] Implement Zod schemas with exact timeout, count, address, range, and memory-region bounds.
- [ ] Ensure all tool errors include operation, debugger state, emulator-running status, connection usability, and corrective action when known.
- [ ] Run existing and new DeSmuME tests.
- [ ] Commit `feat: expose controlled DeSmuME debugger tools`.

### Task 17: Lifecycle cleanup and regression verification

- [ ] Write tests proving `desmume_stop`, process exit, and a new `desmume_start` clear the old GDB session, executable ranges, breakpoint registry, and stop context.
- [ ] Implement the smallest lifecycle hook necessary in `OwnedProcessManager` or the DeSmuME tool module.
- [ ] Run:

```bash
npm run check
npm run build
```

Expected: PASS, including existing read-register and read-memory tests.

- [ ] Commit `fix: reset debugger state with emulator lifecycle`.

### Task 18: Documentation and native acceptance checklist

- [ ] Update `README.md` with the nine dynamic-debugging tools, safety limits, and example workflow.
- [ ] Add `docs/dynamic-debugging-catalina-acceptance.md` with exact steps to launch a known ROM, derive the ARM9 range, add a breakpoint, continue, capture PC/CPSR, step once, pause, remove the breakpoint, restart, and confirm state reset.
- [ ] Run `npm run check && npm run build`.
- [ ] Commit `docs: add dynamic debugging acceptance guide`.

### Task 19: Open PR 3

Title: `Expose ARM9 debugger tools and stop context`

The PR body must list every MCP tool, validation limits, lifecycle-reset guarantees, automated verification, and the remaining requirement for physical Catalina/DeSmuME acceptance testing.

---

## Final Verification

After all three PRs merge:

```bash
npm ci
npm run check
npm run build
```

Then run the Catalina acceptance guide with the verified native DeSmuME bundle. Patch 1 is complete only after the target Mac confirms breakpoint installation, stop capture, single stepping, pause, removal, and state reset after emulator restart.
