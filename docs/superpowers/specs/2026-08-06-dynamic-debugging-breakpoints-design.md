# Controlled ARM9 Breakpoints and Execution Control Design

## Goal

Add the first Dynamic Debugging patch to RE-MCP: controlled ARM9 software breakpoints, bounded execution control, and automatic stop-context capture for the single DeSmuME process owned by the server.

This patch extends the existing read-only GDB RSP integration without exposing arbitrary GDB packets, unrestricted memory writes, register writes, watchpoints, or disassembly.

## Scope

Patch 1 adds these MCP tools:

- `desmume_breakpoint_add`
- `desmume_breakpoint_remove`
- `desmume_breakpoint_list`
- `desmume_continue`
- `desmume_step_instruction`
- `desmume_pause`
- `desmume_wait_for_stop`
- `desmume_capture_stop_context`

The patch also adds session-scoped executable-range metadata, breakpoint state, execution-mode resolution, stop-reply parsing, and structured register decoding.

Out of scope:

- hardware watchpoints;
- arbitrary GDB RSP commands;
- register writes;
- general memory-write tools;
- integrated ARM/Thumb disassembly;
- Ghidra integration;
- overlay discovery from emulator internals;
- persistent symbol databases.

## Current Architecture

RE-MCP currently:

- owns at most one DeSmuME process;
- stores the owned ARM9 GDB port in process metadata;
- sends one bounded GDB RSP request per TCP connection;
- reads the raw register packet with `g`;
- performs bounded memory reads with `m`;
- rejects attachment to unrelated emulator processes.

Patch 1 preserves those boundaries but introduces a session controller that owns debugger state for the current DeSmuME process.

## Components

### 1. GDB RSP session service

Create a stateful GDB RSP client for execution-control operations. The current one-request helper remains available for simple read operations, but continue, step, pause, breakpoint lifecycle, and stop waiting use a single debugger session so asynchronous stop replies can be handled correctly.

The session service will:

- connect only to `127.0.0.1` and the GDB port owned by the current DeSmuME process;
- encode and verify GDB RSP packets;
- acknowledge valid replies;
- support bounded response sizes;
- expose explicit methods rather than arbitrary command strings;
- serialize execution-control operations;
- close automatically when the owned process exits or is stopped;
- invalidate all breakpoint and stop state when the process identity changes.

### 2. Executable-range policy

Breakpoint validation uses three sources:

1. The main ARM9 executable range derived from the loaded NDS ROM header at `desmume_start`.
2. Overlay executable ranges supplied through an explicit, session-scoped allowlist.
3. Additional explicit executable ranges supplied through the same allowlist for confirmed executable regions.

Each range stores:

- stable range ID;
- label;
- start address, inclusive;
- end address, exclusive;
- source: `arm9-header`, `overlay`, or `explicit`;
- optional overlay ID;
- optional default execution mode;
- optional symbol-mode mappings.

Ranges must be inside valid ARM9 address space, non-empty, non-overlapping unless they describe the same bytes, and bounded in count.

The initial patch will derive the main ARM9 range by reading these little-endian NDS header fields from the ROM before launch:

- ARM9 RAM address at header offset `0x28`;
- ARM9 size at header offset `0x2C`.

The effective range is `[ramAddress, ramAddress + size)`, with overflow and file-size validation.

### 3. Breakpoint registry

Breakpoints are stored only in memory for the active emulator session.

Each breakpoint contains:

- server-generated ID;
- normalized address;
- requested mode: `arm`, `thumb`, or `auto`;
- resolved mode: `arm` or `thumb`;
- GDB breakpoint kind;
- matching executable-range ID;
- enabled state;
- hit count;
- optional symbol;
- optional overlay ID;
- creation timestamp.

The registry caps active breakpoints at 32. Duplicate breakpoints at the same normalized address and resolved mode are rejected.

Software breakpoints use GDB RSP `Z0,address,kind` and `z0,address,kind` packets. Patch 1 does not expose raw memory writes even if the stub internally implements software breakpoints by patching code.

### 4. ARM/Thumb mode resolution

Breakpoint requests accept:

```text
arm
thumb
auto
```

Explicit modes are validated directly:

- ARM addresses must be 4-byte aligned;
- Thumb addresses must be 2-byte aligned;
- a Thumb-style address with bit 0 set is normalized by clearing bit 0 before validation.

`auto` resolves in this order:

1. exact symbol-mode metadata in the matching executable range;
2. range default mode;
3. recorded execution history for the normalized address;
4. bit 0 set means Thumb;
5. unambiguous alignment: address aligned to 2 but not 4 means Thumb.

If both ARM and Thumb remain possible, the request fails and requires an explicit mode. RE-MCP will never guess ARM merely because the address is 4-byte aligned.

Breakpoint kinds are:

- ARM: 4 bytes;
- Thumb: 2 bytes.

### 5. Execution state machine

The debugger session tracks:

```text
unavailable
stopped
running
waiting
```

Rules:

- Breakpoints may only be added or removed while stopped.
- Continue and step require a stopped session.
- Only one execution-control request may be active.
- `desmume_continue` and `desmume_step_instruction` use bounded timeouts.
- A timeout does not imply that the emulator stopped; the state remains running until a stop reply, explicit pause, process exit, or connection failure establishes otherwise.
- `desmume_pause` sends the GDB interrupt byte and waits a bounded interval for a stop reply.
- `desmume_wait_for_stop` only waits; it does not resume execution.
- Process exit invalidates the session and all breakpoint state.

### 6. Stop handling

The service recognizes standard GDB stop replies:

- `Sxx`;
- `Txx...`;
- `Wxx`;
- `Xxx`.

Each stop event records:

- reason category;
- signal number;
- raw stop payload;
- whether the emulator process is still running;
- matched breakpoint ID when determinable;
- timestamp;
- decoded register context;
- configured nearby-memory captures.

When the stop PC matches an active breakpoint, that breakpoint's hit count increments.

### 7. Register decoding

Patch 1 decodes DeSmuME's raw ARM9 `g` packet into a stable register model after validating the exact expected packet width for the supported stub.

The model contains:

- `r0` through `r12`;
- `sp` / `r13`;
- `lr` / `r14`;
- `pc` / `r15`;
- `cpsr`;
- raw register packet;
- byte order;
- resolved current mode.

Mode is inferred from CPSR's Thumb bit when CPSR is available. The observed PC/mode pair is saved as session execution history for future `auto` resolution.

If the register packet format differs from the supported contract, context capture fails clearly rather than silently mislabeling registers.

### 8. Stop-context capture

`desmume_capture_stop_context` captures the current stopped state without resuming execution.

Default context:

- stop reason;
- breakpoint metadata;
- decoded registers;
- 64 bytes around PC, bounded to valid unsigned 32-bit space;
- 64 bytes from SP;
- timestamp.

The tool may accept up to eight additional read-only memory regions. Each region is capped at 4096 bytes, and the total capture is capped by the configured output limit.

`desmume_continue`, `desmume_step_instruction`, and `desmume_wait_for_stop` accept `captureContext`, defaulting to true. On a stop, they return the same structured context.

Patch 3 will add instruction decoding. Patch 1 returns nearby bytes only.

## Tool Contracts

### `desmume_breakpoint_add`

Inputs:

- `address`: unsigned 32-bit integer;
- `mode`: `arm | thumb | auto`;
- optional `symbol`;
- optional `rangeId` to disambiguate overlapping metadata.

Returns the stored breakpoint record and GDB acknowledgement.

### `desmume_breakpoint_remove`

Input:

- breakpoint ID.

Removes the matching GDB breakpoint and registry entry. Removing an unknown ID fails.

### `desmume_breakpoint_list`

Returns the active registry, maximum count, debugger state, and executable ranges.

### `desmume_continue`

Inputs:

- `timeoutMs`: 100 through 30000, default 10000;
- optional expected breakpoint ID;
- `captureContext`: default true;
- optional additional memory regions.

Resumes with `c` and waits until stop, timeout, exit, or connection failure.

An unexpected breakpoint is returned as a valid stop with an `expectedBreakpointMatched` flag set to false; it is not discarded.

### `desmume_step_instruction`

Inputs:

- `count`: 1 through 100;
- per-step timeout: 100 through 5000, default 1000;
- `captureContext`: default true after the final completed step.

Uses one `s` request per instruction. It stops early and returns context if a signal, breakpoint, exit, timeout, or failure occurs.

### `desmume_pause`

Inputs:

- timeout: 100 through 5000, default 1000;
- `captureContext`: default true.

Sends the GDB interrupt byte only while running and waits for the resulting stop.

### `desmume_wait_for_stop`

Inputs:

- timeout: 100 through 30000;
- `captureContext`: default true.

Waits for a stop event from an already-running session.

### `desmume_capture_stop_context`

Inputs:

- optional additional memory regions.

Requires a stopped session and returns the current context.

## Executable-range configuration

Patch 1 adds an MCP tool or start-time input for replacing the session-scoped executable-range allowlist after ROM validation. The implementation plan will choose the least disruptive API after reviewing existing tool-registration patterns.

Allowlisted overlay and explicit ranges require:

- label;
- start and end addresses;
- source type;
- optional overlay ID;
- optional default mode;
- optional exact symbol-mode entries.

The derived main ARM9 range cannot be removed while the emulator session is active.

## Error Handling

All errors are structured and must identify:

- operation;
- debugger state;
- whether the emulator remains running;
- whether the GDB connection remains usable;
- corrective action when known.

Specific failures include:

- no owned DeSmuME process;
- GDB port unavailable;
- malformed ROM header;
- address outside all executable ranges;
- unresolved `auto` mode;
- invalid ARM or Thumb alignment;
- breakpoint limit reached;
- duplicate breakpoint;
- unsupported GDB reply;
- RSP checksum mismatch;
- execution timeout;
- process exit;
- malformed register packet;
- memory-capture limit exceeded.

## Safety and Security

Patch 1 preserves these restrictions:

- localhost-only GDB connection;
- only the server-owned emulator and port;
- no arbitrary GDB command tool;
- no register writes;
- no general memory-write tool;
- no watchpoints;
- maximum 32 breakpoints;
- maximum 100 single steps per request;
- all waits bounded to 30 seconds;
- all memory captures bounded by region and total-output limits;
- executable-range validation before installing breakpoints;
- debugger state cleared when the owned process changes.

## Testing Strategy

### Unit tests

- RSP packet encoding and checksum verification;
- stop-reply parsing;
- interrupt handling;
- breakpoint packet construction;
- ARM/Thumb address normalization and alignment;
- auto-mode resolution order and ambiguity rejection;
- NDS ARM9 header parsing and overflow checks;
- executable-range validation;
- breakpoint registry limits and duplicate rejection;
- ARM9 register packet decoding;
- execution-state transitions;
- timeout behavior;
- stop-context memory-window calculations.

### Integration tests

Use a deterministic fake GDB RSP server to verify:

- breakpoint add/remove lifecycle;
- continue to breakpoint;
- single-step sequences;
- asynchronous stop replies;
- pause interrupt;
- expected-breakpoint mismatch;
- connection loss and process exit;
- context capture after stop;
- session reset after emulator restart.

### Repository verification

- TypeScript typecheck;
- all existing tests;
- new dynamic-debugging tests;
- package build;
- no regression to current read-only register and memory tools.

### Native acceptance

After the Catalina DeSmuME bundle passes its own smoke test:

1. start a known-good ROM through RE-MCP;
2. verify the derived ARM9 range;
3. add a breakpoint at a known ARM9 instruction;
4. continue and observe a stop;
5. verify decoded PC, CPSR, and register values;
6. single-step one instruction;
7. pause a running session;
8. remove the breakpoint;
9. restart DeSmuME and confirm all old breakpoint state is gone.

## Acceptance Criteria

Patch 1 is complete when RE-MCP can safely add and remove validated ARM9 software breakpoints, continue, pause, single-step, wait for stops, and return structured stop context for only its owned DeSmuME process, while rejecting ambiguous execution modes, invalid executable addresses, unbounded operations, and unsupported GDB behavior.
