# NDS Proven Function Discovery Design

Date: 2026-08-07
Status: Approved design
Repository: `79cbd8hmgj-wq/RE-MCP`
Milestone scope: bounded, evidence-based ARM/Thumb function-entry discovery and function-centric analysis

## Summary

Add a native-independent Nintendo DS static function-discovery layer on top of the existing canonical NDS structure model, ARM/Thumb disassembly, control-flow analysis, proven-reference discovery, and xref search.

The milestone introduces two MCP tools:

1. `nds_discover_functions` — discover a bounded call graph of statically proven function entries from trusted executable seeds;
2. `nds_analyze_function` — prove and analyze one requested function entry without promoting an unproven address to function status.

The central epistemic rule is strict: RE-MCP may call an address a **proven function entry** only when static evidence establishes it as an executable entry point. This milestone intentionally does not guess prologues, epilogues, function ends, jump-table targets, or indirect-call targets.

A function entry can be proven by:

- the selected processor's NDS executable entry address, recorded as `program-entry` evidence; or
- a deterministic resolved direct-call target, recorded as `direct-call` evidence.

This milestone is fully static and does not depend on pending physical Intel macOS Catalina/DeSmuME dynamic-debugging acceptance. The debugger feature set remains frozen until that separate native acceptance gate is completed.

## Approved scope choices

1. **Proven entries only.** No prologue or plausibility heuristics.
2. **Program entry plus direct-call targets are the only proof sources.**
3. **Direct branches remain intrafunction CFG traversal and never prove a new function entry.**
4. **Indirect calls never prove a function entry.**
5. **Explicit overlay seeds provide search coverage only.** They do not themselves prove a function.
6. **No function-end claims.** The tool exposes reachable bounded CFG structure instead.
7. **Call-graph discovery is globally bounded.** Aggregate limits prevent per-function CFG budgets from multiplying into an unbounded scan.
8. **Ambiguity is preserved.** Overlay selection never converts an ambiguous target into a proven owner.
9. **Compressed overlays remain explicit coverage gaps.** No decompression is added here.
10. **Two public tools only.** Existing CFG and xref tools remain the lower-level primitives.

## Goals

- introduce one RE-MCP-owned canonical proven-function identity and evidence model;
- discover statically proven ARM9/ARM7 function entries from program entry and resolved direct calls;
- build a bounded function-to-function call graph without guessing indirect targets;
- preserve all caller evidence for each discovered function;
- reuse existing CFG semantics for intrafunction traversal;
- distinguish complete negative proof from inconclusive proof caused by coverage gaps or truncation;
- preserve processor, overlay, mode, ROM identity, BSS, compression, path, output, and read-only safety rules;
- terminate safely under recursion and mutual recursion;
- prove production behavior in unit/integration/package smoke tests.

## Non-goals

This milestone does not add:

- heuristic function discovery;
- function-prologue pattern matching;
- function-end or byte-range ownership claims;
- tail-call classification beyond existing branch semantics;
- indirect-call target recovery;
- register-value propagation;
- jump-table or switch recovery;
- pointer inference;
- symbol recovery;
- persistent function databases or indexes;
- Ghidra/radare2 integration;
- compressed-overlay decompression;
- runtime loaded-overlay detection;
- generic binary analysis;
- runtime debugger/watchpoint integration;
- ROM mutation/rebuild/patch generation;
- caller-controlled output paths.

## Existing primitives reused

The design must compose with, rather than duplicate, the current static stack:

- canonical `NdsRomMap` and runtime/ROM resolution;
- `resolveNdsCodeSource` and exact ARM/Thumb source ownership;
- `analyzeNdsControlFlow` for bounded CFG construction;
- `StaticCallEdge` emitted by CFG analysis;
- `classifyNdsInstructionReferences` and `direct-call` reference semantics;
- `findNdsXrefs` for bounded proof searches where appropriate;
- SHA-validated NDS ROM readers;
- current MCP result/error/output-bound conventions.

The existing CFG behavior remains unchanged: direct calls are recorded but callees are not traversed as intrafunction blocks.

## Canonical function identity

A proven function is identified by:

```text
processor
+ component
+ overlayId
+ runtimeAddress
+ ARM/Thumb mode
```

Conceptually:

```ts
interface ProvenFunctionIdentity {
  processor: "arm9" | "arm7";
  component: "main" | "overlay";
  overlayId: number | null;
  runtimeAddress: number;
  romOffset: number;
  mode: "arm" | "thumb";
}
```

The ROM offset must come from one exact file-backed resolved code source. BSS-only, unmapped, compressed-without-direct-mapping, or ambiguous code locations cannot become a canonical proven function entry.

A stable string ID may use:

```text
arm9:main:02012340:thumb
arm9:overlay:7:02040000:arm
```

The exact serialization is implementation-defined, but it must be deterministic and collision-free for the canonical identity fields.

## Function proof model

### Proof kinds

```ts
type FunctionProofKind =
  | "program-entry"
  | "direct-call";
```

### Program-entry evidence

When the selected processor's main executable component is in scope, its NDS header entry address is a proven function entry if it resolves uniquely to file-backed executable code in ARM mode.

Evidence conceptually includes:

```ts
{
  kind: "program-entry";
  processor: "arm9" | "arm7";
  headerEntryAddress: number;
}
```

Program-entry proof applies only to the processor main executable component.

### Direct-call evidence

A direct-call proof is valid only when an already-decoded instruction has canonical control-flow semantics:

```text
flow.kind == call
flow.directTarget != null
flow.targetMode != null
```

and the call target resolves uniquely to one selected, uncompressed, file-backed code source for the same processor.

Evidence conceptually includes:

```ts
{
  kind: "direct-call";
  caller: {
    functionId: string | null;
    component: "main" | "overlay";
    overlayId: number | null;
    instructionAddress: number;
    instructionRomOffset: number;
    mode: "arm" | "thumb";
  };
  target: ProvenFunctionIdentity;
}
```

The caller function ID is present when the call was discovered while analyzing a proven function. A proof-search implementation may retain equivalent source evidence before caller-function attribution is known.

### What is not proof

None of the following may establish function status:

- an explicit analyst seed by itself;
- a direct branch target;
- a conditional branch target;
- a decoded return instruction;
- a plausible function prologue;
- alignment alone;
- a literal or pointer-like constant;
- an indirect call;
- an ambiguous overlay candidate;
- a selected overlay ID without a qualifying call target;
- sequential decoding that merely appears function-shaped.

## Function boundary policy

This milestone does not claim function end addresses or exclusive byte ownership.

For a proven entry, RE-MCP exposes the existing bounded reachable CFG and summary facts such as:

- block count;
- instruction count;
- decoded byte count;
- traversal edge count;
- direct outgoing calls;
- return sites;
- unresolved exits;
- CFG truncation state.

A return instruction proves only a return site in the current reachable graph. Multiple returns, shared epilogues, tail branches, jump tables, interleaved data, and unreachable code make a single inferred end unsafe.

## Search scope

Function discovery uses the same static executable-scope philosophy as reverse-xref search.

Conceptually:

```ts
type FunctionSearchScope =
  | { kind: "main" }
  | { kind: "overlay"; overlayIds: number[] }
  | { kind: "main-and-overlays"; overlayIds: number[] }
  | { kind: "all-executable-components" };
```

The caller selects exactly one processor: `arm9` or `arm7`.

`all-executable-components` means all static executable components for the selected processor. It does not claim those overlays are simultaneously loaded at runtime.

## Search seeds

Initial traversal seeds are:

1. the selected processor main header entry point when main is in scope;
2. caller-supplied explicit mode-tagged seeds that validate uniquely inside selected scope.

Conceptual explicit seed:

```ts
{
  runtimeAddress: number;
  mode: "arm" | "thumb";
  overlayId?: number;
}
```

An explicit seed means only: "decode reachable code from here to gain static coverage." It does **not** make the seed a proven function.

Reject a seed when it is:

- outside selected scope;
- for the other processor;
- mismatched to the supplied overlay;
- outside exact initialized file-backed code;
- BSS-only;
- compressed;
- misaligned for its mode;
- ambiguous after allowed overlay disambiguation.

Duplicate canonical seeds are accepted but deduplicated before traversal.

## `nds_discover_functions`

Add public MCP tool:

```text
nds_discover_functions
```

Purpose: discover a bounded call graph of proven functions inside one selected processor/scope.

Conceptual input:

```ts
{
  rom: string;
  processor: "arm9" | "arm7";
  scope: FunctionSearchScope;
  seeds?: Array<{
    runtimeAddress: number;
    mode: "arm" | "thumb";
    overlayId?: number;
  }>;

  maxFunctions?: number;
  maxCallSites?: number;
  maxTotalBlocks?: number;
  maxTotalInstructions?: number;
  maxTotalBytes?: number;
  maxTotalEdges?: number;
  maxComponents?: number;

  maxCfgBlocksPerFunction?: number;
  maxCfgInstructionsPerFunction?: number;
  maxCfgBytesPerFunction?: number;
  maxCfgEdgesPerFunction?: number;
}
```

### Discovery limits

All discovery limits are global unless explicitly labeled per-function.

| Limit | Default | Maximum |
| --- | ---: | ---: |
| Components considered | 32 | 128 |
| Proven functions retained/analyzed | 128 | 1,024 |
| Direct call sites retained | 512 | 8,192 |
| Total basic blocks decoded | 512 | 4,096 |
| Total instructions decoded | 4,096 | 32,768 |
| Total decoded source bytes | 32 KiB | 256 KiB |
| Total traversal edges | 2,048 | 16,384 |

Per-function CFG limits reuse the existing public CFG defaults/maxima:

| Per-function CFG limit | Default | Maximum |
| --- | ---: | ---: |
| Blocks | 64 | 256 |
| Instructions | 512 | 4,096 |
| Decoded bytes | 2 KiB | 16 KiB |
| Traversal edges | 128 | 1,024 |

Aggregate budgets always dominate. Reaching a per-function cap marks that function CFG truncated; reaching an aggregate cap marks the overall discovery truncated.

### Discovery algorithm

The service performs a deterministic graph walk over **proven entries** while using explicit seeds only for coverage.

1. Validate scope, component limits, seeds, and all budgets.
2. If main is selected, canonicalize the processor header entry and record `program-entry` proof.
3. Schedule valid explicit coverage seeds.
4. Analyze reachable code from program entry / coverage seeds using existing CFG semantics.
5. For each resolved direct call encountered:
   - canonicalize the target identity;
   - reject it as a callee candidate if outside processor/scope, compressed, BSS-only, ambiguous, or unmapped;
   - record direct-call proof when canonicalization succeeds;
   - add a function-to-function call edge when the caller is a proven function;
   - queue each newly proven function entry once for its own CFG analysis.
6. Continue until the queue is empty or a global budget is exhausted.
7. Produce deterministic function, evidence, call-edge, coverage, and truncation ordering.

### Distinguishing proven-function traversal from coverage traversal

A program entry or direct-call target is a proven function and may own one function-centric CFG result.

An explicit unproven seed may be decoded solely to discover qualifying direct calls. Any direct-call targets discovered from such coverage are valid proven functions, but the seed address itself remains absent from the function list unless independently proven.

Coverage traversal therefore needs internal attribution that distinguishes:

```text
proven-function analysis
vs
coverage-only seed traversal
```

This distinction must survive recursion, duplicate seeds, and overlapping reachable blocks.

### Recursion

Canonical function identity is the visited key. Each proven function identity is queued for function analysis at most once.

Self recursion and mutual recursion therefore add call edges/evidence without repeatedly re-analyzing the same proven entry.

### Call graph edge

Conceptually:

```ts
interface ProvenFunctionCallEdge {
  callerFunctionId: string;
  instructionAddress: number;
  instructionRomOffset: number;
  calleeFunctionId: string;
}
```

Distinct call sites remain distinct edges. Duplicate observations of the exact same call site/target identity are deduplicated deterministically.

### Function result summary

Conceptually:

```ts
interface DiscoveredFunction {
  id: string;
  entry: ProvenFunctionIdentity;
  evidence: readonly FunctionProof[];
  directCallerCount: number;
  directCallSiteCount: number;
  cfg: {
    status: "complete" | "truncated";
    truncationReasons: readonly string[];
    blocks: number;
    instructions: number;
    decodedBytes: number;
    traversalEdges: number;
    returnSites: number;
    unresolvedEdges: number;
  };
}
```

`directCallerCount` counts unique non-null proven caller function IDs. `directCallSiteCount` counts distinct retained direct-call evidence sites, including evidence found from coverage-only seeds whose `caller.functionId` is null.

The implementation may expose additional existing canonical metadata, but must not add heuristic function boundaries or inferred symbols.

### Discovery result

Conceptually:

```ts
{
  status: "complete" | "partial-coverage" | "truncated";
  processor: "arm9" | "arm7";
  functions: DiscoveredFunction[];
  calls: ProvenFunctionCallEdge[];
  coverage: FunctionComponentCoverage[];
  truncationReasons: FunctionDiscoveryTruncationReason[];
  totals: {
    functions: number;
    callSites: number;
    blocks: number;
    instructions: number;
    decodedBytes: number;
    traversalEdges: number;
  };
}
```

## `nds_analyze_function`

Add public MCP tool:

```text
nds_analyze_function
```

Purpose: answer "is this address statically proven to be a function entry within the selected proof scope, and if so what does its bounded CFG show?"

Conceptual input:

```ts
{
  rom: string;
  processor: "arm9" | "arm7";
  runtimeAddress: number;
  mode: "arm" | "thumb";
  overlayId?: number;
  proofScope: FunctionSearchScope;
  seeds?: FunctionSearchSeed[];

  maxProofComponents?: number;
  maxProofBlocks?: number;
  maxProofInstructions?: number;
  maxProofBytes?: number;
  maxProofEdges?: number;
  maxProofCallSites?: number;

  maxCfgBlocks?: number;
  maxCfgInstructions?: number;
  maxCfgBytes?: number;
  maxCfgEdges?: number;
}
```

### Focused proof-search limits

The proof search intentionally reuses the current reverse-xref scale:

| Proof-search limit | Default | Maximum |
| --- | ---: | ---: |
| Components considered | 32 | 128 |
| Blocks decoded | 128 | 512 |
| Instructions decoded | 2,048 | 16,384 |
| Decoded bytes | 8 KiB | 64 KiB |
| Traversal edges | 512 | 4,096 |
| Direct-call proof sites retained | 256 | 2,048 |

The final proven target CFG reuses the existing CFG defaults/maxima:

| Target CFG limit | Default | Maximum |
| --- | ---: | ---: |
| Blocks | 64 | 256 |
| Instructions | 512 | 4,096 |
| Decoded bytes | 2 KiB | 16 KiB |
| Traversal edges | 128 | 1,024 |

### Requested-entry resolution

The requested processor/address/mode/optional overlay must first resolve uniquely to exact uncompressed file-backed executable code. If it does not, return a narrow canonical error/result rather than selecting among candidates.

### Proof procedure

The focused tool checks proof in this order:

1. if the target is exactly the selected processor main header entry in ARM mode, return `program-entry` proof;
2. otherwise run a bounded proof search over the selected scope/seeds for deterministic direct calls to the exact canonical entry identity.

Proof matching includes target mode and canonical component ownership. A numeric runtime address alone is insufficient when ownership is ambiguous.

### Semantic outcomes

The tool must distinguish three non-error proof outcomes:

```ts
type AnalyzeFunctionProofStatus =
  | "proven"
  | "not-proven-function-entry"
  | "proof-inconclusive";
```

#### `proven`

At least one valid proof exists. Return:

- canonical function identity;
- all retained bounded proof evidence;
- direct callers/call sites;
- outgoing direct calls;
- return sites;
- unresolved exits;
- full existing CFG result or equivalent function-centric CFG projection;
- proof-search coverage metadata.

#### `not-proven-function-entry`

Return this only when the selected proof search completed without truncation or coverage gaps relevant to the selected scope and found no program-entry or direct-call proof.

This is a complete negative result for the approved proof model only. It does not claim the address can never be a function under richer future analyses.

#### `proof-inconclusive`

Return this when proof could not be established and the selected proof search was incomplete because of one or more of:

- component limit;
- block limit;
- instruction limit;
- byte limit;
- edge limit;
- call-site/result limit;
- compressed selected components;
- selected overlays with no proven/explicit seed coverage;
- other explicit canonical coverage gaps.

A truncated or partial search may still return `proven` if qualifying evidence was found before truncation. Incompleteness affects negative proof, not already-established positive proof.

## Component coverage

Use coverage metadata equivalent to the proven-reference scan model, adapted for function discovery:

```ts
type FunctionComponentCoverageStatus =
  | "scanned"
  | "no-proven-seed"
  | "compressed-overlay-not-decodable"
  | "out-of-limit";
```

A selected component with a valid explicit coverage seed may become `scanned` without that seed being called a function.

A selected compressed overlay is never decoded and reports `compressed-overlay-not-decodable`.

Coverage metadata must prevent an empty function/xref result from being presented as exhaustive when selected code was not actually searched.

## Global discovery truncation

Conceptual discovery truncation reasons:

```ts
type FunctionDiscoveryTruncationReason =
  | "component-limit"
  | "function-limit"
  | "call-site-limit"
  | "block-limit"
  | "instruction-limit"
  | "byte-limit"
  | "edge-limit";
```

Per-function CFG truncation reasons remain the existing CFG vocabulary and are preserved inside each function summary.

If more than one global budget is exhausted, preserve all applicable reasons in deterministic order.

## Deterministic ordering

Function ordering must be stable by:

1. processor;
2. main before overlay;
3. overlay ID;
4. runtime address;
5. ARM before Thumb.

Proof evidence ordering must be stable with `program-entry` before `direct-call`, then caller component/overlay/address/mode.

Call edges sort by caller function identity, call-site address, and callee identity.

Coverage follows canonical component ordering.

## Ambiguity and overlays

Overlay address overlap is never solved by guessing.

A direct call may prove that an instruction targets numeric runtime address `X` while ownership resolution remains ambiguous across overlay candidates. In that case:

- the call remains a valid control-flow fact at the instruction level;
- no proven function identity is created from that target;
- no callee function is queued;
- the unresolved/ambiguous condition is retained in analysis metadata where the underlying CFG/reference model supports it.

Passing a selected overlay ID in scope does not retroactively make an otherwise ambiguous direct-call target unique unless the existing canonical resolver explicitly supports that disambiguation for the actual source/target relationship.

## Direct branches, tail branches, and calls

- conditional/unconditional direct branches remain normal CFG edges;
- branch targets do not create functions;
- no branch is promoted to a tail call in this milestone;
- resolved direct calls create function proof and call-graph edges;
- indirect calls remain unresolved call sites and do not create functions;
- return instructions create return-site metadata only.

## Error model

Add narrow function-analysis error categories as needed:

```text
invalid-function-scope
invalid-function-seed
function-entry-not-uniquely-resolved
function-discovery-limit-exceeded
```

Prefer semantic result statuses (`not-proven-function-entry`, `proof-inconclusive`) over errors when the request itself is valid but evidence is absent or incomplete.

MCP corrective actions must remain specific and bounded, consistent with the current NDS tool style.

## ROM identity and read safety

All function proof/discovery reads must use the existing SHA-validated NDS reader conventions.

The source ROM hash must be verified before and after bounded reads as already required by the static layer. If the file changes during analysis, fail rather than returning mixed-revision evidence.

This milestone is read-only:

- no ROM writes;
- no extracted artifacts required;
- no caller-chosen output paths;
- no debugger process control;
- no runtime memory access.

## MCP output bounds

Both new tools must pass through the existing `RE_MCP_MAX_OUTPUT_BYTES` protection.

Tool-level result limits are deliberately bounded for interactive use. If a valid result still exceeds the configured serialized-output cap, return the standard `output-bound-exceeded` error and require narrower limits.

## Testing requirements

### Core proof tests

- ARM9 program-entry proof;
- ARM7 program-entry proof;
- ARM direct-call target proof;
- Thumb direct-call target proof;
- immediate mode-switching direct call where existing canonical decoding proves target mode;
- multiple direct callers collapse to one canonical function;
- all qualifying caller evidence is preserved subject to explicit result limits;
- program-entry plus direct-call evidence can coexist for the same entry.

### Non-proof tests

- direct branch target does not create a function;
- conditional branch target does not create a function;
- indirect call does not create a function;
- return site does not imply a new function or end address;
- explicit seed does not create a function by itself;
- plausible aligned code without qualifying proof remains unproven.

### Graph traversal tests

- nested call chains;
- self recursion;
- mutual recursion;
- duplicate call sites observed through duplicate coverage paths are deduplicated;
- duplicate explicit seeds do not duplicate work;
- calls discovered inside branch-reachable basic blocks prove callees;
- caller fallthrough remains intrafunction CFG behavior;
- out-of-scope call targets are not traversed as discovered functions.

### Overlay and coverage tests

- valid explicit overlay coverage seed;
- explicit overlay seed remains coverage-only unless independently proven;
- overlay call target resolving uniquely creates a proven function;
- ambiguous overlay call target remains unproven;
- compressed overlay reports coverage gap;
- selected overlay with no seed reports `no-proven-seed`;
- main plus overlay mixed scope ordering is deterministic.

### Focused proof-status tests

- `proven` by program entry;
- `proven` by direct call;
- `not-proven-function-entry` only after complete proof coverage;
- `proof-inconclusive` for truncated proof search;
- `proof-inconclusive` for compressed/no-seed coverage gaps;
- positive proof remains `proven` even if unrelated selected coverage is incomplete, while coverage metadata still reports that incompleteness.

### Limit tests

Require explicit tests for each aggregate discovery cap:

- component limit;
- function limit;
- call-site limit;
- total block limit;
- total instruction limit;
- total byte limit;
- total edge limit;
- simultaneous exhaustion preserving multiple truncation reasons.

Also test per-function CFG truncation separately from global discovery truncation and all focused proof-search bounds.

### Integrity and MCP tests

- ROM mutation during discovery/proof fails safely;
- schema bounds reject invalid zero/negative/excessive limits;
- invalid scope and seed errors use correct categories/corrective actions;
- ambiguous requested function entry does not get guessed;
- `RE_MCP_MAX_OUTPUT_BYTES` remains enforced;
- both tool registrations appear in the assembled server;
- package-install smoke invokes at least one deterministic proven-function scenario using the packaged Capstone.js/WASM backend.

## Documentation changes required during implementation

Update README static-analysis workflow to place function discovery after reference/xref analysis and before future symbol/Ghidra layers.

Document clearly that:

- function **entries** are proven under a narrow evidence model;
- function **ends** are not inferred;
- explicit seeds are coverage hints, not proof;
- direct branches do not create functions;
- indirect calls remain unresolved;
- compressed overlays are not analyzed as code;
- this static milestone is independent of pending Catalina dynamic-debugger acceptance.

## Implementation boundaries

Likely implementation units:

```text
src/services/nds/function-model.ts
  canonical identity, proof, ordering

src/services/nds/function-source.ts
  scope and seed validation/canonicalization

src/services/nds/function-discovery.ts
  bounded proven-entry/call-graph traversal

src/services/nds/function-analysis.ts
  focused proof + CFG composition

src/tools/nds.ts
  schemas, tool registration, output/error mapping
```

Exact filenames may change to fit existing project structure, but responsibilities should remain isolated. Do not duplicate low-level instruction semantics already owned by disassembly/reference/CFG services.

## Acceptance criteria

The milestone is complete when:

1. `nds_discover_functions` returns only program-entry/direct-call-proven functions;
2. `nds_analyze_function` distinguishes `proven`, complete-negative `not-proven-function-entry`, and incomplete `proof-inconclusive`;
3. no direct branch, indirect call, explicit seed, or prologue heuristic can create function proof;
4. recursion terminates through canonical visited identities;
5. selected component coverage and truncation are explicit;
6. ambiguous/compressed/BSS/unmapped targets are never guessed into functions;
7. aggregate, per-function CFG, and proof-search bounds are enforced and tested;
8. output and SHA integrity protections remain intact;
9. package smoke proves the production packaged backend path;
10. no dynamic-debugger behavior changes and no physical-Catalina acceptance claim is introduced.

## Deferred follow-on work

After this milestone, high-value native-independent follow-ons include:

- table/record inference built on proven functions/references/patterns;
- symbol/evidence database;
- static binary/snapshot diffing;
- constrained Ghidra bridge;
- deterministic code/data candidate analysis;
- compressed-overlay decompression.

Watchpoints, runtime value tracing, and other debugger-dependent extensions remain deferred until physical Intel macOS Catalina/DeSmuME acceptance succeeds.
