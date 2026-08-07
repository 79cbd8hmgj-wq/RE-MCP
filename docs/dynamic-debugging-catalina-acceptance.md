# Catalina Dynamic Debugging Acceptance Guide

This checklist is the native acceptance gate for Dynamic Debugging Patch 1. Run it on the target Intel Mac running macOS Catalina 10.15 with the verified Catalina-native DeSmuME debug bundle and a known-good private NDS ROM inside the configured RE-MCP workspace.

Automated CI covers protocol parsing, safety bounds, state transitions, fake-RSP integration, MCP schemas, and lifecycle cleanup. This guide verifies the remaining dependency: real DeSmuME 0.9.13 ARM9 GDB behavior on the target machine.

## Preconditions

- Verify the RE-MCP bundle and DeSmuME bundle checksums before use.
- Use a dedicated `RE_MCP_WORKSPACE_ROOT`; do not use the general home directory.
- Confirm the intended ROM is a readable `.nds` file in that workspace.
- Confirm the Catalina DeSmuME launcher is executable and inside the workspace.
- Ensure the selected ARM9 GDB port is unprivileged and not already occupied. Port `20000` is the standard acceptance value.
- Start with no other DeSmuME process using that GDB port.

Record the RE-MCP commit SHA, DeSmuME bundle checksum, ROM SHA-256, macOS version, and test date with the acceptance result.

## 1. Start the owned emulator and derive the ARM9 range

Call `desmume_start` with:

- the verified Catalina launcher path relative to the workspace;
- the known ROM path relative to the workspace;
- `arm9GdbPort: 20000`.

Pass criteria:

- DeSmuME starts and the ROM boots.
- The response reports one owned running process.
- The response contains `debugger.arm9ExecutableRange` with a non-empty range derived from the ROM header.
- The range lies inside DS ARM9 main RAM.
- The debugger session identity contains the current owned process generation.
- No breakpoint from any previous emulator session is present.

Stop immediately if the reported ROM/range does not match the intended test input.

## 2. Confirm the owned GDB stub is reachable

Call `desmume_wait_for_gdb` with a bounded timeout such as `10000` ms, then call `desmume_probe_gdb`.

Pass criteria:

- Both operations target `127.0.0.1` and port `20000`.
- The stub is reported reachable.
- RE-MCP does not attach to any unrelated emulator process.

Optional host-side confirmation:

```bash
lsof -nP -iTCP:20000 -sTCP:LISTEN
```

The listener must belong to the intended DeSmuME process.

## 3. Confirm the existing read-only path still works

While the debugger is stopped, call:

1. `desmume_read_register_packet`;
2. `desmume_read_memory` for a small known-valid ARM9 memory region.

Pass criteria:

- The register packet is returned without opening a competing GDB session.
- The bounded memory read succeeds.
- No register or memory write operation is exposed.

## 4. Choose and install one known executable breakpoint

Use a runtime address known to execute during the selected test flow. The address must be inside the derived ARM9 range or a deliberately added executable range.

If the test address belongs to an overlay, first call `desmume_executable_ranges_replace` with the exact known overlay range and execution mode.

Call `desmume_breakpoint_add` with the chosen address and an explicit `arm` or `thumb` mode unless mode is already unambiguous.

Pass criteria:

- A server-generated ID such as `bp-1` is returned.
- The record is enabled.
- ARM uses breakpoint kind 4 and Thumb uses kind 2.
- `desmume_breakpoint_list` reports the same breakpoint.
- An out-of-range or misaligned address is rejected rather than sent to GDB.

Record the breakpoint ID, address, mode, and range ID.

## 5. Continue to the breakpoint and capture stop context

Call `desmume_continue` with:

- a bounded timeout;
- `expectedBreakpointId` set to the installed breakpoint ID;
- context capture enabled.

Trigger the known in-game action if user input is required to reach the breakpoint.

Pass criteria when the breakpoint is reached:

- The result is a stop, not a fabricated timeout success.
- The stop is matched to the expected breakpoint.
- The breakpoint hit count increments.
- The returned context contains decoded `pc` and `cpsr`.
- The reported execution mode agrees with CPSR bit 5 and the installed breakpoint mode.
- A bounded PC memory window and stack window are returned.
- `stoppedAt` / context timestamps are present.

Record `pc`, `cpsr`, stop signal/reason, matched breakpoint ID, and hit count.

If continue times out, pass only if the result remains explicitly `running`; use `desmume_wait_for_stop` or `desmume_pause` next rather than issuing a stopped-state command.

## 6. Capture the current stopped context explicitly

While stopped, call `desmume_capture_stop_context`.

Optionally include one small labeled additional region relevant to the test.

Pass criteria:

- Registers decode successfully.
- The current `pc` is plausible and consistent with the previous stop.
- The PC window is at most 64 bytes.
- The stack window is at most 64 bytes.
- Additional regions remain within the configured limits.
- The total response remains within RE-MCP's output bound.

## 7. Single-step once

Call `desmume_step_instruction` with `count: 1` and context capture enabled.

Pass criteria:

- Exactly one `s` operation is issued by the controlled execution path.
- The result reports `requested: 1` and `completed: 1` unless a genuine signal/exit/timeout interrupts the step.
- The final stop contains decoded context.
- `pc` advances or otherwise changes consistently with the executed instruction and ARM/Thumb semantics.

Do not require a specific byte delta for every instruction; branches and mode changes are valid execution outcomes.

## 8. Verify bounded multi-step behavior

Call `desmume_step_instruction` with a small count such as `3`.

Pass criteria:

- No more than the requested number of instructions execute.
- A breakpoint, unexpected signal, exit, or timeout stops the sequence early and is reported explicitly.
- A request above 100 instructions is rejected by validation.

## 9. Verify pause / interrupt

Continue execution with a short timeout that intentionally allows the emulator to remain running, or otherwise reach a known running state.

Call `desmume_pause`.

Pass criteria:

- RE-MCP sends the controlled raw GDB interrupt path.
- The emulator returns to stopped state within the bounded pause timeout.
- The stop reason is returned.
- Context capture succeeds when enabled.
- DeSmuME remains alive and usable after the pause.

## 10. Remove the breakpoint

Call `desmume_breakpoint_remove` with the recorded breakpoint ID, then call `desmume_breakpoint_list`.

Pass criteria:

- The GDB removal succeeds.
- The removed ID is no longer active in the registry.
- A failed removal does not falsely delete the local registry record.

## 11. Verify lifecycle reset on explicit stop

Call `desmume_stop`.

Pass criteria:

- Only the server-owned DeSmuME process is stopped.
- The debugger becomes uninitialized/unavailable.
- Breakpoint registry state is empty.
- Additional executable ranges are cleared.
- Stored stop context/history is no longer available as current-session state.
- Subsequent debugger operations instruct the caller to start a new owned emulator session.

## 12. Verify lifecycle reset after restart

Start the same ROM again with `desmume_start` and wait for GDB readiness.

Pass criteria:

- The new debugger session identity differs from the prior process generation.
- Breakpoint IDs begin from fresh session-scoped state.
- No prior breakpoint is installed or listed.
- No prior additional executable range survives unless explicitly supplied again.
- No prior stop context is treated as current.
- Register and memory reads work on the new session.

## 13. Verify spontaneous-exit cleanup

With a new owned session active, close DeSmuME normally or cause the emulator process to exit without calling `desmume_stop`.

Pass criteria:

- RE-MCP observes the owned process generation exiting.
- The old GDB connection is invalidated.
- Breakpoints, executable ranges, and stop state are cleared.
- Starting another owned DeSmuME process produces a clean debugger session.

## 14. Safety-negative checks

Confirm the MCP surface does **not** provide:

- an arbitrary GDB packet tool;
- register writes;
- general memory writes;
- watchpoints;
- attachment to an unrelated process or non-local GDB host.

Also confirm:

- a 33rd active breakpoint is rejected;
- a 101-instruction step request is rejected;
- more than eight additional context regions are rejected;
- a context region over 4096 bytes is rejected;
- more than 64 additional executable ranges are rejected;
- ambiguous `auto` ARM/Thumb resolution fails rather than guessing.

## Acceptance record

Mark Dynamic Debugging Patch 1 native acceptance **PASS** only if all required sections above pass on the target Catalina machine.

Record:

```text
RE-MCP commit:
RE-MCP bundle SHA-256:
DeSmuME bundle SHA-256:
ROM SHA-256:
macOS version:
Mac model:
ARM9 GDB port:
Breakpoint address/mode:
Observed PC:
Observed CPSR:
Observed stop reason:
Lifecycle reset verified: yes/no
Safety-negative checks verified: yes/no
Result: PASS/FAIL
Notes:
```

A CI-green PR is not sufficient to mark this native checklist complete; the final PASS must come from the physical Catalina/DeSmuME run.
