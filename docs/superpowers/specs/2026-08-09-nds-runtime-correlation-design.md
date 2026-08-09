# Controlled NDS Runtime Correlation Design

## Goal

Connect RE-MCP's existing controlled ARM9 debugger evidence to its canonical Nintendo DS static-analysis and Ghidra layers without weakening any existing trust boundary.

The milestone adds one high-value workflow: while the server-owned DeSmuME session is stopped, RE-MCP can capture the observed ARM9 state and explain that stop in canonical NDS terms — ROM identity, runtime ownership candidates, exact ARM/Thumb code interpretation, proven static evidence, and optional already-ready Ghidra context.

The primary public tool is:

```text
nds_correlate_stop_context
```

This milestone is read-only. It does not add watchpoints, memory/register writes, arbitrary GDB packets, conditional breakpoint scripting, runtime tracing, ROM mutation, Ghidra mutation, or automatic loaded-overlay claims.

## Current Architecture

RE-MCP already has the required capabilities as separate layers:

- a server-owned DeSmuME process with one ARM9 GDB port;
- controlled software breakpoints, continue, pause, bounded stepping, stop waiting, register decoding, and bounded memory capture;
- a canonical full-SHA NDS model with ARM9/ARM7 main executables, FAT/FNT/NitroFS, overlays, BSS, compressed-overlay metadata, and runtime/ROM resolution;
- exact ARM/Thumb disassembly and control-flow analysis over canonical physical or derived runtime code sources;
- deterministic reference/xref and proven function-entry discovery;
- bounded pattern search;
- full-ROM-SHA-scoped controlled Ghidra projects with read-only function, decompiler, symbol, reference, and call inspection;
- decoded compressed-overlay runtime images shared by static analysis and Ghidra.

Today these layers do not produce one structured answer for a live stop. The debugger reports runtime facts, while the caller must manually translate the PC into the static/Ghidra model.

## Design Principles

### 1. Runtime observation does not silently rewrite static authority

The observed PC and CPSR-derived ARM/Thumb mode are runtime facts from the active GDB session. Canonical ROM structure remains derived from the exact source ROM. Ghidra remains a secondary analysis source.

The correlation result keeps these authority classes visibly separate:

```text
runtimeObserved
canonical
reMcpEvidence
ghidraDerived
```

A Ghidra inference never becomes a canonical RE-MCP fact merely because it appears in the same response.

### 2. Full ROM identity binds the runtime session to static analysis

`desmume_start` continues using the existing narrow ARM9-header compatibility path for executable-range derivation. It must not begin requiring a fully valid FAT/FNT/overlay model just to launch the emulator.

In addition, start computes the full SHA-256 of the ROM immediately before process launch and stores it in the owned process metadata for that exact process generation. After the process is created, start re-hashes the same ROM before returning success. The pre-launch and post-start hashes must match.

If they differ, start fails, stops the newly owned process, and resets the debugger instead of recording an uncertain runtime/static identity.

The debugger session therefore records both:

```text
workspace-contained ROM path
launch-time full ROM SHA-256
```

`nds_correlate_stop_context` reparses/re-hashes the current ROM through the canonical NDS model and requires its full SHA-256 to match the launch-time SHA before static evidence is correlated with the live process.

If the ROM file changes after DeSmuME starts, correlation fails instead of mixing live evidence from one image with static evidence from another.

This metadata addition does not change GDB packet behavior, execution-state behavior, breakpoint behavior, or the existing ARM9 executable-range policy.

### 3. Overlay ambiguity is preserved

A runtime address can statically belong to multiple mutually exclusive overlays. The first correlation milestone does not infer which overlay is loaded from ID order, Ghidra output, breakpoint range metadata, nearby bytes, or any other heuristic.

If the observed PC has multiple canonical candidates, the response returns all candidates.

Each candidate may receive its own static interpretation by explicitly selecting that canonical overlay internally for analysis, but the top-level ownership remains ambiguous.

Example:

```text
observed PC 0x02201000
  -> ARM9 overlay 12 candidate
  -> ARM9 overlay 19 candidate
```

The result may decode both candidate interpretations, but does not choose one as loaded.

Runtime loaded-overlay detection is a later milestone.

### 4. Candidate-specific analysis is exact, not heuristic

The observed CPSR mode is used as the initial ARM/Thumb mode for static decoding.

For each canonical executable candidate at PC, correlation reuses the existing canonical code-source and disassembly layer. This includes decoded compressed-overlay runtime images.

It does not:

- decode both ARM and Thumb and choose the more plausible result;
- derive a function from prologue appearance;
- assign a direct ROM offset to decoded compressed-overlay bytes;
- treat BSS as initialized executable bytes;
- guess an overlay when several overlap.

If existing RE-MCP proof establishes an exact function entry at the same PC with a mode that conflicts with the observed CPSR mode, the correlation result reports that evidence conflict. Runtime mode does not silently overwrite static proof, and static proof does not overwrite the observed runtime mode.

### 5. The observed PC is never adjusted heuristically

Correlation uses the PC exactly as returned by the existing ARM9 register decoder.

It does not subtract 2 or 4 bytes, rewind to a software-breakpoint address, or apply any DeSmuME-specific trap-PC correction heuristic.

The physical Catalina acceptance gate exists in part to validate DeSmuME's real stop-PC semantics. If native acceptance reveals a stub-specific PC rule, that rule must be designed and fixed in the debugger layer rather than hidden inside correlation.

### 6. The existing debugger API remains intact

The existing tools continue to return their current result shapes:

- `desmume_continue`
- `desmume_step_instruction`
- `desmume_pause`
- `desmume_wait_for_stop`
- `desmume_capture_stop_context`

Correlation is a separate tool. This avoids making the still-pending physical Catalina debugger acceptance gate dependent on a large response-shape migration.

## Architecture

### A. Launch-time ROM identity

Extend the owned DeSmuME metadata written by `desmume_start` with:

```ts
romSha256: string
```

The complete ROM is hashed immediately before launch and again after the owned process is created but before `desmume_start` returns success. Both hashes must be identical.

The existing narrow ARM9 range parsing remains independent from the full canonical NDS parser.

A successful owned process generation therefore has a stable tuple:

```text
process generation
workspace-contained ROM path
launch-time ROM SHA-256
ARM9 GDB port
```

The correlation layer refuses sessions that predate this metadata or otherwise lack a valid lowercase 64-hex-character SHA-256.

### B. Runtime correlation service

Add a focused service:

```text
src/services/nds/runtime-correlation.ts
```

with a core operation conceptually shaped as:

```ts
correlateNdsStopContext(input): Promise<NdsRuntimeCorrelationResult>
```

The service accepts already-captured runtime evidence and explicit dependencies for canonical/static/Ghidra analysis. It contains no socket, process-manager, or MCP registration logic, which keeps it deterministic and testable.

Inputs include:

```text
romPath
expectedRomSha256
StopContext
nearby instruction limit
reference limit
optional Ghidra enrichment policy
max output bytes
```

The service performs:

1. canonical ROM parse and full-SHA verification;
2. processor-fixed ARM9 runtime resolution for the observed PC;
3. candidate normalization;
4. candidate-specific static instruction decoding using the observed runtime mode;
5. bounded deterministic reference classification around PC where exact code exists;
6. exact function-entry proof query at PC, without inventing a containing function;
7. mode-consistency comparison when exact static function-entry mode proof exists;
8. optional read-only Ghidra enrichment;
9. final source-ROM SHA revalidation before return;
10. serialized output-bound enforcement.

### C. Live MCP orchestration

Add a small cross-layer registration module:

```text
src/tools/nds-runtime.ts
```

rather than expanding either `src/tools/nds.ts` or `src/tools/desmume.ts` into a mixed-responsibility module.

`nds_correlate_stop_context` receives the existing `OwnedProcessManager` and `DebugController` instances from server composition.

The tool derives the active ROM from the single server-owned DeSmuME session; the caller does not provide a separate ROM path.

The tool:

1. requires one running owned DeSmuME process;
2. requires launch-time ROM SHA metadata;
3. requires a stopped debugger state;
4. captures the current stop context through the existing controller;
5. passes that context and exact owned ROM identity to the correlation service;
6. converts the internal absolute ROM path to a validated workspace-relative path for MCP output;
7. returns one bounded structured result.

It never resumes execution.

## Public Tool Contract

### `nds_correlate_stop_context`

Purpose: explain the current stopped ARM9 state using the exact ROM and existing RE-MCP analysis layers.

Inputs:

```ts
{
  timeoutMs?: number;                // 100..30000, default 3000
  nearbyInstructions?: number;       // 1..32, default 8
  referenceLimit?: number;           // 0..64, default 16; 0 disables reference work
  includeGhidra?: boolean;           // default false
  decompileGhidraFunction?: boolean; // default false; requires includeGhidra
}
```

The first milestone intentionally does not accept:

- a caller-selected ROM;
- a caller-selected processor;
- a caller-supplied PC or register set;
- an overlay ID used to force a loaded-state claim;
- arbitrary GDB memory regions;
- arbitrary Ghidra project/program/script arguments.

Callers that want offline/static analysis already have the canonical NDS tools. This tool is specifically the correlation of the current server-owned runtime stop.

## Result Shape

Conceptual result:

```json
{
  "runtimeObserved": {
    "capturedAt": "...",
    "pc": 33558528,
    "sp": 37740544,
    "lr": 33559040,
    "cpsr": 32,
    "mode": "thumb",
    "stop": { "kind": "signal", "signal": 5 },
    "breakpoint": null
  },
  "rom": {
    "workspacePath": "game.nds",
    "sha256": "...",
    "launchSha256": "...",
    "identityMatched": true
  },
  "canonical": {
    "processor": "arm9",
    "status": "resolved",
    "candidateCount": 1
  },
  "candidates": [
    {
      "canonical": {
        "kind": "arm9-main",
        "runtimeAddress": 33558528
      },
      "reMcpEvidence": {
        "status": "available",
        "instructions": [],
        "references": [],
        "functionEntryProof": {},
        "modeConsistency": "not-proven"
      },
      "ghidraDerived": {
        "status": "not-requested"
      }
    }
  ]
}
```

For overlapping overlays:

```json
{
  "canonical": {
    "processor": "arm9",
    "status": "ambiguous",
    "candidateCount": 2
  },
  "candidates": [
    {
      "canonical": { "kind": "overlay", "overlayId": 12 },
      "reMcpEvidence": {},
      "ghidraDerived": { "status": "not-requested" }
    },
    {
      "canonical": { "kind": "overlay", "overlayId": 19 },
      "reMcpEvidence": {},
      "ghidraDerived": { "status": "not-requested" }
    }
  ]
}
```

No field named `loadedOverlay`, `bestMatch`, or equivalent is produced in this milestone.

The MCP result exposes only a workspace-relative ROM path. Internal absolute filesystem paths are not added to the new public response.

## Canonical Candidate Semantics

### ARM9 main

A PC in the ARM9 main initialized range has one canonical main candidate. Static decoding uses the exact main code source.

### Overlay initialized code

Every matching overlay candidate is retained. For compressed overlays, the existing bounded BLZ runtime-image layer supplies exact decoded initialized bytes. Such instructions keep:

```text
romOffset = null
representation = derived-overlay
```

where appropriate.

### Overlay BSS/runtime-only region

BSS can be a canonical runtime ownership candidate, but no static instruction stream is fabricated. Candidate evidence status is explicitly runtime-only/non-decodable.

### Unmapped address

The tool still returns the runtime observation, ROM identity, and an explicit canonical `unmapped` status. It does not fail merely because the PC is not statically mappable, provided the runtime capture itself is valid.

## RE-MCP Evidence at PC

### Nearby instructions

For each decodable candidate, decode from the exact observed PC in the observed ARM/Thumb mode.

The default is 8 instructions; maximum 32. Existing code-byte bounds remain authoritative.

### References

Classify only the existing deterministic single-instruction/static-window reference classes. The correlation layer does not broaden the reference model.

A `referenceLimit` of 0 skips reference analysis entirely.

### Function evidence

The canonical layer may report whether the exact PC is a proven function entry under existing rules.

It must not label an arbitrary mid-function PC as belonging to a canonical containing function because RE-MCP does not currently claim function-body ownership ranges.

If the exact PC is not a proven function entry, the result reports the existing negative/inconclusive proof semantics.

### Runtime/static mode consistency

When exact function-entry proof exists at the observed PC, correlation compares its proven ARM/Thumb mode with the CPSR-derived runtime mode and reports one of:

```text
match
conflict
not-proven
```

A conflict is evidence to investigate. It is not auto-corrected.

A later milestone may add bounded containing-function correlation with a separately designed evidence model.

## Optional Ghidra Enrichment

Ghidra enrichment is opt-in and secondary.

When `includeGhidra` is false:

```text
ghidraDerived.status = not-requested
```

When true, the correlation layer may use only an already-current full-ROM-SHA-scoped controlled Ghidra project.

It must not:

- bootstrap Ghidra automatically;
- reconcile or migrate a project;
- run auto-analysis;
- write labels/types/comments;
- accept caller-selected project/program/script paths.

For each canonical candidate, Ghidra enrichment uses the same canonical address and explicit overlay identity when needed. If no ready project exists, correlation remains successful and returns an explicit `not-ready` Ghidra status.

Ghidra-derived information may include, where the existing inspection layer supports it:

- function metadata at the candidate address;
- symbol/name information;
- bounded decompiler text when `decompileGhidraFunction` is requested and a function is inspectable;
- references/calls relevant to the exact candidate.

Ghidra failure must never cause the canonical layer to guess ownership. Validation failures inside a requested Ghidra operation are reported as Ghidra enrichment failure while preserving successfully established runtime/canonical information, unless source-ROM identity itself becomes invalid.

## ROM Mutation and Time-of-Check Rules

Correlation is invalid if the static source ROM changes underneath the operation.

Required checks:

1. launch-time SHA exists;
2. canonical parse SHA equals launch-time SHA;
3. existing static readers continue their own before/after SHA checks;
4. correlation verifies full source identity immediately before returning.

A source-ROM mismatch is a top-level failure because the core purpose of the tool is to correlate the running process to that exact static image.

The running emulator is not claimed to reflect later on-disk edits.

## Error Model

Add narrow correlation categories:

```text
runtime-correlation-no-owned-process
runtime-correlation-rom-identity-missing
runtime-correlation-rom-identity-mismatch
runtime-correlation-debugger-not-stopped
runtime-correlation-context-failed
runtime-correlation-output-limit
```

Existing NDS parse/resolver/code-source/decompression/Ghidra categories remain authoritative for their own layers.

Errors identify:

```text
operation
category
debugger state
emulator running state
corrective action
```

Examples:

- running debugger -> pause/wait for stop before correlation;
- missing launch SHA -> restart the owned emulator with the current RE-MCP version;
- ROM identity mismatch -> stop the emulator and restart it with the intended unmodified ROM;
- Ghidra not ready -> bootstrap explicitly with `nds_ghidra_bootstrap` if Ghidra enrichment is desired.

## Safety and Bounds

The milestone preserves all existing restrictions and adds no new write capability.

Required limits:

- nearby instructions: 1..32;
- references retained: 0..64;
- one current stopped context per invocation;
- no recursive Ghidra call traversal beyond existing inspection limits;
- optional decompiler output remains under existing Ghidra decompiler bounds;
- final serialized response must fit `config.maxOutputBytes`;
- all waits remain bounded to 30 seconds;
- full-ROM SHA must match before return.

No new runtime dependency is required.

## Testing Strategy

### Pure correlation service tests

Use synthetic NDS fixtures and constructed stop contexts to cover:

- ARM9-main stop;
- ARM and Thumb observed modes;
- exact nearby instruction decoding;
- deterministic reference classification;
- exact PC function-entry proof;
- function-entry mode match and conflict reporting;
- a PC that is not a proven function entry;
- overlapping overlay candidates preserved without selection;
- candidate-specific decoding for overlapping overlays;
- compressed-overlay candidate decoded from exact derived runtime bytes;
- compressed-overlay instructions retaining no fabricated ROM offset;
- overlay BSS returning runtime-only evidence status;
- unmapped PC returning a valid unmapped correlation;
- output-limit enforcement;
- ROM mutation before final return causing failure.

### Launch identity tests

Characterize and preserve the current `desmume_start` narrow ARM9-header behavior.

Add tests proving:

- full ROM SHA is recorded in owned process metadata;
- pre-launch and post-start ROM hashes must match;
- a hash change during startup stops the new owned process and fails start;
- unrelated malformed FAT/FNT/overlay structures do not become a new launch blocker merely because correlation metadata was added;
- a new process generation gets a fresh ROM identity;
- old process-generation identity cannot be reused.

### Fake-RSP MCP integration tests

Using the existing deterministic fake GDB server patterns, verify:

- correlation requires stopped state;
- current PC/mode comes from decoded live registers, not caller input;
- no PC rewind/correction is performed;
- correlation captures without resuming execution;
- exact owned ROM path/SHA is used;
- MCP output contains only a workspace-relative ROM path;
- current stop/breakpoint metadata is retained;
- existing debugger tools keep their response contracts.

### Ghidra tests

Unit/contract tests verify:

- no automatic bootstrap/reconciliation call path;
- `includeGhidra: false` performs no Ghidra work;
- absent/stale project produces bounded `not-ready` enrichment;
- ambiguous overlays are enriched per explicit candidate rather than guessed;
- Ghidra-derived information remains authority-separated.

PR B must run real Ghidra 12.1.2/JDK 21 acceptance using the existing pinned acceptance infrastructure. The native test must cover at least one main-code candidate and one overlay candidate, including compressed-overlay inspection where the fixture supports it.

### Repository regression

Every implementation PR must pass:

```text
npm run check
npm run build
Package workflow
```

Production changes to debugger/GDB packet behavior are out of scope.

## Physical Catalina Acceptance Boundary

The original Dynamic Debugging Patch 1 physical Intel Catalina/DeSmuME acceptance remains a separate outstanding gate.

This milestone does not claim that fake-RSP verification proves native DeSmuME behavior.

Because the new tool consumes the existing stopped-state/register/memory interfaces rather than extending their packet semantics, implementation can proceed with CI/fake-RSP coverage. Once the physical debugger gate is available, the native checklist should be extended with one final correlation check:

```text
real breakpoint stop
  -> nds_correlate_stop_context
  -> exact launch ROM SHA
  -> observed PC/CPSR mode
  -> valid canonical candidate(s)
  -> bounded static instruction interpretation
```

Native failure in the underlying debugger is fixed at that layer rather than worked around by the correlation service.

## Delivery Topology

Use two independently reviewable implementation PRs after the design and implementation plan are approved.

### PR A — Runtime identity + canonical static correlation

Includes:

- launch-time full ROM SHA binding;
- pure runtime-correlation service;
- dedicated `src/tools/nds-runtime.ts` orchestration;
- current-stop MCP tool registration;
- canonical ownership candidate output;
- nearby static instruction decoding;
- deterministic references;
- exact function-entry proof and mode-consistency reporting;
- compressed-overlay support through the existing runtime-image layer;
- fake-RSP/static fixture coverage;
- no Ghidra enrichment yet.

### PR B — Controlled Ghidra enrichment + hardening

Includes:

- opt-in already-ready Ghidra enrichment;
- no automatic bootstrap/reconciliation;
- per-candidate overlay-safe inspection;
- decompiler option under existing limits;
- package/docs/capability updates;
- mandatory real-Ghidra acceptance for the enrichment path;
- final cross-layer regression and trust-boundary review.

PR B starts from current `main` only after PR A merges.

## Explicitly Deferred

Not part of this milestone:

- watchpoints;
- value-change tracing;
- conditional breakpoints;
- call/return stepping;
- repeated-step runtime tracing;
- runtime loaded-overlay detection;
- automatic overlay disambiguation from memory bytes;
- canonical containing-function inference for arbitrary mid-function PCs;
- register-value propagation/data-flow inference;
- structure/type recovery;
- Ghidra symbol/type mutation;
- ROM writes/recompression/rebuilding;
- patch generation;
- save-state automation;
- generic emulator abstraction.

## Acceptance Criteria

The milestone is complete when, for one stopped server-owned DeSmuME ARM9 session, RE-MCP can return a bounded correlation result that:

1. proves it is using the same full ROM identity that was launched;
2. reports the observed PC and CPSR-derived execution mode without breakpoint-PC heuristics;
3. maps the PC into canonical NDS main/overlay/BSS/unmapped candidates without guessing overlapping overlays;
4. decodes exact candidate-specific static instructions when initialized code exists, including compressed-overlay runtime images;
5. reports existing deterministic references and exact function-entry proof semantics without broadening them;
6. explicitly reports runtime/static function-entry mode consistency when such proof exists;
7. optionally adds authority-separated information from an already-current Ghidra project without mutating or bootstrapping it;
8. revalidates source-ROM identity before returning;
9. exposes only a workspace-relative ROM path in the new MCP result;
10. preserves every existing debugger and Ghidra safety restriction;
11. passes CI/package verification and mandatory real-Ghidra acceptance for PR B;
12. leaves physical Catalina/DeSmuME debugger acceptance explicitly separate until run on the target machine.
