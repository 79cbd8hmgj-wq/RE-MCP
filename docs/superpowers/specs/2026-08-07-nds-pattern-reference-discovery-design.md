# NDS Pattern + Reference Discovery Design

Date: 2026-08-07
Status: Approved design
Repository: `79cbd8hmgj-wq/RE-MCP`
Milestone scope: instruction-aware proven-reference discovery only

## Summary

Add a native-independent Nintendo DS static reference-discovery layer on top of the canonical `NdsRomMap` and ARM/Thumb disassembly foundation.

This milestone adds two bounded query directions:

1. source-to-reference analysis: report statically proven references emitted by instructions in one bounded code window;
2. target-to-xref analysis: search a caller-selected, bounded executable scope for statically proven instructions that reference one target.

The core epistemic rule is strict: every emitted reference must be explainable from one decoded ARM/Thumb instruction, architectural PC semantics where applicable, and the canonical NDS address model. Ordinary immediates that merely resemble addresses are not references. Literal-pool contents are not reinterpreted as pointers. Register-state inference, multi-instruction data flow, function discovery, raw pattern search, and persistent indexing are deferred.

This milestone is fully static and does not depend on pending physical Intel Catalina/DeSmuME dynamic-debugging acceptance.

## Approved scope choices

1. **Proven references only.** No pointer-like immediate heuristics.
2. **Direct control flow plus deterministic PC-relative addressing.** Include direct branch/call targets, PC-relative literal slots, and deterministic PC-relative address construction.
3. **On-demand queries only.** No persistent xref index.
4. **Both directions.** Source-to-reference and target-to-xref.
5. **Caller-selectable reverse-search scope.** Main, explicit overlays, selected main+overlays, or all executable components for one processor.
6. **Direct calls expand reverse-xref scan coverage.** This is local to the xref scanner and does not change `nds_analyze_control_flow`.
7. **Literal loads reference the literal-pool slot only.** The loaded value is not interpreted.
8. **Reverse targets accept runtime address or ROM offset.** A ROM offset must canonicalize to one runtime target suitable for instruction-reference matching.

## Goals

- introduce one RE-MCP-owned deterministic reference model/classifier;
- detect proven direct branch and direct call targets using existing canonical control-flow semantics;
- detect architecturally deterministic ARM/Thumb PC-relative literal-slot references;
- detect deterministic PC-relative address construction such as supported `ADR` and equivalent immediate `ADD`/`SUB` from `PC`;
- expose bounded source-to-reference and target-to-xref MCP tools;
- expand xref code coverage through proven direct branch/call targets without claiming function boundaries;
- preserve processor, component, overlay, mode, ambiguity, BSS, compressed-overlay, ROM-identity, and read-only safety rules;
- expose partial-coverage and truncation metadata so incomplete searches are never presented as complete negative evidence;
- prove the feature from the assembled production package using the existing pinned Capstone.js/WASM backend.

## Non-goals

This milestone does not add:

- wildcard or raw byte-pattern search;
- integer-constant or string search;
- generic binary analysis;
- pointer-like immediate heuristics;
- literal-pool value pointer inference;
- pointer-array or table scanning;
- switch/jump-table recovery;
- register-value propagation;
- inter-instruction data-flow analysis;
- stack-value inference;
- relocation-like inference;
- code/data plausibility heuristics;
- function discovery or function-boundary claims;
- symbol recovery/databases;
- persistent whole-ROM xref indexes;
- compressed-overlay decompression;
- runtime loaded-overlay inference;
- debugger integration;
- ROM mutation/rebuild/patch generation;
- caller-controlled output paths.

## Architecture

Use one shared deterministic classifier with two query engines:

```text
Canonical NDS code source
        |
        v
Canonical StaticInstruction
        |
        v
Deterministic Reference Classifier
        |
        +------------------------+
        |                        |
        v                        v
source -> references       target -> xrefs
bounded linear window      bounded proven-code scan
```

The classifier is the sole owner of reference semantics. The source and reverse-xref engines may not invent independent instruction-reference rules.

The Capstone adapter remains the only layer that understands raw Capstone ARM operand/detail structures. It translates them into RE-MCP-owned normalized metadata. No raw Capstone object becomes part of the NDS/reference public model.

The existing CFG analyzer remains behaviorally independent: `nds_analyze_control_flow` continues to annotate direct calls without traversing callees. The xref scanner may traverse proven direct call targets solely for statically proven coverage.

## Canonical reference model

Use a canonical model conceptually equivalent to:

```ts
import type { RuntimeResolution } from "./resolver.js";

type StaticReferenceKind =
  | "direct-branch"
  | "direct-call"
  | "literal-pool"
  | "pc-relative-address";

type StaticReferenceMechanism =
  | "direct-control-flow"
  | "pc-relative-literal-address"
  | "pc-relative-address-construction";

interface StaticReference {
  kind: StaticReferenceKind;

  source: {
    processor: "arm9" | "arm7";
    component: "main" | "overlay";
    overlayId: number | null;
    instructionAddress: number;
    instructionRomOffset: number;
    mode: "arm" | "thumb";
  };

  target: {
    runtimeAddress: number;
    romOffset: number | null;
    resolution: RuntimeResolution;
  };

  evidence: {
    instructionMnemonic: string;
    mechanism: StaticReferenceMechanism;
  };
}
```

The implementation may wrap or narrow `RuntimeResolution`, but it must preserve its existing exact status vocabulary:

- `resolved`;
- `unmapped`;
- `ambiguous-runtime-address`;
- `runtime-only-bss`;
- `compressed-no-direct-rom-mapping`.

For a `resolved` runtime candidate, `target.romOffset` is its deterministic ROM offset. Otherwise it is `null` unless an already-established canonical resolver relationship proves an exact direct ROM offset.

A reference can be proven even when target ownership is ambiguous. For example, an instruction may provably reference runtime address `X` while `RuntimeResolution` is `ambiguous-runtime-address`. The reference remains valid; no candidate owner is selected.

Reference identity is at least:

```text
source processor
+ source component
+ source overlayId
+ source instruction runtime address
+ source mode
+ reference kind
+ target runtime address
```

Distinct source instructions that reference the same target remain distinct xrefs.

Reverse-xref ordering is deterministic by processor, component, overlay/main identity, source runtime address, mode, reference kind, then target address as a final tie-breaker.

## Decoder metadata extension

PC-relative literal/address classification requires narrowly extending normalized operand metadata. Support a memory operand conceptually equivalent to:

```ts
interface DecodedArmMemoryOperand {
  baseRegister: string | null;
  indexRegister: string | null;
  displacement: number;
}

type DecodedArmOperand =
  | { kind: "immediate"; value: number }
  | { kind: "register"; name: string }
  | { kind: "memory"; value: DecodedArmMemoryOperand }
  | { kind: "other" };
```

Normalized instruction identity/flags may be extended only as required to distinguish supported architectural forms.

Parsing mnemonic/operand display strings is not a general reference-discovery mechanism. Narrow adapter fallbacks are allowed only where Capstone 5.0.9 demonstrably omits structured metadata and the fallback identifies an exact supported form without parsing numeric targets from display text.

## Deterministic reference classification

### Direct branches

Immediate direct branches with an existing deterministic canonical control-flow target emit:

```text
kind: direct-branch
mechanism: direct-control-flow
```

This includes conditional and unconditional direct branches. Reuse the target already produced by canonical disassembly semantics; do not independently parse or recalculate it from operand text.

Register-indirect branches such as `BX rN` emit no proven target reference.

### Direct calls

Immediate direct calls with a deterministic canonical target emit:

```text
kind: direct-call
mechanism: direct-control-flow
```

Supported immediate mode-switching calls such as immediate `BLX` preserve the deterministic target mode for traversal.

Register-indirect calls such as `BLX rN` emit no proven target reference.

### PC-relative literal-pool references

Supported PC-relative literal-load forms reference the **literal-pool slot address**, not the value stored there.

```text
LDR r0, [PC, #offset]
            |
            v
     literal-pool slot
```

The slot contents are never emitted as a secondary pointer/reference in this milestone.

For supported ARM-state forms:

```text
architectural PC = instructionAddress + 8
```

For supported Thumb literal forms:

```text
architectural PC = Align(instructionAddress + 4, 4)
```

Apply the encoded displacement according to the exact instruction form. The classifier must use architectural semantics, not decoder display formatting.

### PC-relative address construction

Supported forms that deterministically construct an address from architectural `PC` plus/minus an encoded immediate emit:

```text
kind: pc-relative-address
mechanism: pc-relative-address-construction
```

Supported examples may include exact encodings equivalent to:

```text
ADR r0, label
ADD r0, PC, #imm
SUB r0, PC, #imm
```

Forms requiring any unknown register contribution are excluded, including examples such as:

```text
ADD r0, PC, r3
LDR r0, [PC, r2]
```

No earlier/later instruction state is inferred.

## Proven-reference invariant

Every emitted reference must be explainable from:

1. one decoded instruction;
2. its normalized structured semantics;
3. ARM/Thumb architectural PC rules where applicable; and
4. canonical NDS target resolution.

These are never sufficient evidence by themselves:

- an immediate falls inside ARM9/ARM7 RAM;
- an immediate equals a ROM offset;
- a literal-pool value resembles a pointer;
- adjacent bytes resemble a pointer table;
- an earlier instruction might have placed an address in a register.

## `nds_list_references`

Add a public MCP tool:

```text
nds_list_references
```

Purpose: answer “what proven references does this bounded code window emit?”

Conceptual input:

```ts
{
  rom: string;
  processor: "arm9" | "arm7";
  runtimeAddress?: number;
  romOffset?: number;
  overlayId?: number;
  mode: "arm" | "thumb" | "auto";
  maxInstructions?: number;
  maxBytes?: number;
}
```

Exactly one of `runtimeAddress` or `romOffset` is required. Source resolution, `overlayId`, alignment, compressed-overlay/BSS rejection, and conservative `auto` mode exactly follow `nds_disassemble_range` policy.

Limits reuse the linear-disassembly contract:

| Limit | Default | Maximum |
| --- | ---: | ---: |
| Instructions | 32 | 256 |
| Source bytes | 128 | 1,024 |

The tool decodes sequentially only and does not follow branches/calls. Every successfully decoded instruction is passed through the shared classifier.

Conceptual result:

```ts
{
  status: "complete" | "decode-stopped" | "component-boundary";
  source: {
    processor: "arm9" | "arm7";
    component: "main" | "overlay";
    overlayId: number | null;
    startRuntimeAddress: number;
    startRomOffset: number;
    mode: "arm" | "thumb";
  };
  instructionsExamined: number;
  decodedBytes: number;
  references: StaticReference[];
}
```

An empty `references` array claims only that no supported deterministic reference occurred in the decoded bounded window.

## `nds_find_xrefs`

Add a public MCP tool:

```text
nds_find_xrefs
```

Purpose: answer “which proven instructions inside this bounded selected scope reference this target?”

### Target selector

Accept exactly one:

```ts
{ targetRuntimeAddress: number }
```

or:

```ts
{ targetRomOffset: number }
```

A runtime target remains the authoritative numeric target for matching even when `resolveRuntimeAddress` reports ambiguous ownership. Preserve that ambiguity in metadata.

A ROM-offset target is resolved using the existing `RomOffsetResolution.matches`. Consider only matches with a non-null `runtimeAddress` for the selected processor. The target is accepted only when those applicable matches identify exactly one unique runtime address.

If more than one unique applicable runtime address exists, return:

```text
ambiguous-reference-target
```

If none exists, return:

```text
reference-target-not-runtime-addressable
```

Ordinary NitroFS/structural bytes with no runtime mapping therefore cannot be reverse-xref targets in this milestone.

### Processor and component scope

The caller selects one processor (`arm9` or `arm7`) and one scope:

```ts
type ReferenceSearchScope =
  | { kind: "main" }
  | { kind: "overlay"; overlayIds: number[] }
  | { kind: "main-and-overlays"; overlayIds: number[] }
  | { kind: "all-executable-components" };
```

`all-executable-components` means main plus overlay components for the selected processor. It is a static search scope and does not claim simultaneous loaded-overlay state.

Scope eligibility is not mode evidence. An overlay is never decoded merely because it was selected.

## Proven mode-tagged seeds

Reverse-xref search never linear-sweeps arbitrary executable bytes in both modes.

Initial seeds are:

1. the selected processor main header entry point, in ARM mode, when main is in scope;
2. caller-supplied explicit mode-tagged seeds that validate uniquely inside selected scope;
3. deterministic direct branch targets discovered by the scan;
4. deterministic direct call targets discovered by the scan.

An overlay has no assumed entry mode from overlay metadata alone.

Conceptual explicit seed:

```ts
{
  runtimeAddress: number;
  mode: "arm" | "thumb";
  overlayId?: number;
}
```

Reject a seed when it is outside scope, for the other processor, mismatched to the supplied overlay, outside the exact file-backed initialized extent, BSS-only, compressed, misaligned for its mode, or still ambiguous after allowed disambiguation.

## Reverse-xref scan traversal

Queued block identity is:

```text
processor + component + overlayId + runtimeAddress + mode
```

Schedule/decode each identity at most once.

Traversal rules:

- **ordinary instruction:** classify references and continue sequentially;
- **conditional direct branch:** record reference, queue proven in-scope taken target and valid same-component fallthrough, then terminate block;
- **unconditional direct branch:** record reference, queue proven in-scope target, terminate block;
- **direct call:** record reference, queue proven in-scope callee target, continue caller fallthrough in the current block;
- **indirect call:** emit no target reference, do not follow callee, continue valid caller fallthrough;
- **indirect branch/return:** terminate block without guessing a target;
- **local decode stop:** terminate that block, but continue already queued deterministic blocks if bounds permit;
- **backend failure:** use `disassembly-backend-failure`, not a local decode-stop condition.

Following a direct call target is solely a reverse-xref coverage rule. It does not create function-boundary or function-discovery semantics.

A proven reference to a target outside selected component scope remains a valid reference/xref match, but that target is not traversed.

Traversal never crosses the selected processor boundary.

## Coverage accounting

Each requested component receives one status:

```ts
type ComponentCoverageStatus =
  | "scanned"
  | "no-proven-seed"
  | "compressed-overlay-not-decodable"
  | "out-of-limit";
```

- main is seeded from its header entry when selected;
- an overlay becomes `scanned` only after a valid explicit or proven branch/call seed reaches it;
- a selected overlay with no such seed is `no-proven-seed`;
- a selected compressed overlay is never decoded as runtime instructions and reports `compressed-overlay-not-decodable`;
- components prevented from otherwise eligible exploration by a global cap report `out-of-limit` as appropriate.

Coverage metadata must prevent “zero xrefs” from being misrepresented as complete absence when requested components were not searched.

## Reverse-search limits

All limits apply globally to one `nds_find_xrefs` operation.

| Limit | Default | Maximum |
| --- | ---: | ---: |
| Components considered | 32 | 128 |
| Proven-code blocks | 128 | 512 |
| Instructions decoded | 2,048 | 16,384 |
| Decoded source bytes | 8 KiB | 64 KiB |
| Traversal edges | 512 | 4,096 |
| Xrefs returned | 256 | 2,048 |

Truncation reasons:

```text
component-limit
block-limit
instruction-limit
byte-limit
edge-limit
result-limit
```

Normal cap exhaustion returns a deterministic partial result; already proven xrefs are retained. `result-limit` returns the deterministic prefix under the documented ordering.

## Reverse-xref result semantics

Conceptual result:

```ts
{
  status: "complete" | "partial-coverage" | "truncated";
  target: {
    requestedBy: "runtime-address" | "rom-offset";
    runtimeAddress: number;
    romOffset: number | null;
    resolution: RuntimeResolution;
  };
  scan: {
    processor: "arm9" | "arm7";
    componentsRequested: number;
    componentsScanned: number;
    blocksDecoded: number;
    instructionsDecoded: number;
    decodedBytes: number;
    traversalEdges: number;
  };
  coverage: Array<{
    component: "main" | "overlay";
    overlayId: number | null;
    status: ComponentCoverageStatus;
  }>;
  truncationReasons: Array<
    | "component-limit"
    | "block-limit"
    | "instruction-limit"
    | "byte-limit"
    | "edge-limit"
    | "result-limit"
  >;
  xrefs: StaticReference[];
}
```

Status rules:

- `complete`: every requested eligible component was safely explored within bounds;
- `partial-coverage`: one or more requested components lacked a proven seed or were compressed, while otherwise eligible work completed within bounds;
- `truncated`: at least one global cap prevented otherwise eligible exploration.

`truncated` takes precedence when truncation and independent coverage gaps both occur; the `coverage` array still records the gaps.

Meaning of zero xrefs:

- zero + `complete`: no supported proven reference was found in the fully explored selected scope;
- zero + `partial-coverage`: none was found in explored code, but some requested components were not safely searchable;
- zero + `truncated`: none was found before one or more caps cut exploration short.

Only the first is a complete negative statement for the selected scope.

## Errors and structured conditions

Add/reference categories equivalent to:

```text
ambiguous-reference-target
reference-target-not-runtime-addressable
invalid-reference-scope
invalid-reference-seed
reference-scan-limit-exceeded
```

Reuse existing more-specific NDS/disassembly categories where applicable, including:

```text
ambiguous-runtime-address
compressed-overlay-not-decodable
runtime-only-bss
unmapped
disassembly-backend-failure
```

Normal configured cap exhaustion is `status: "truncated"`, not an operational error. `reference-scan-limit-exceeded` is reserved for impossible/internal limit-state or invariant failures.

Malformed public inputs continue through normal MCP/Zod validation.

## ROM identity and read-only guarantees

Both top-level operations preserve the established NDS static-analysis identity invariant:

1. validate/hash the ROM before analysis;
2. operate against the canonical map associated with that identity;
3. validate/hash again after analysis;
4. reject the result if the ROM changed during the operation.

The post-operation identity check must still run when decoder/classifier/search work throws, matching established NDS static-analysis behavior.

Neither tool writes to the ROM or caller-selected filesystem destinations.

## Existing CFG compatibility

This milestone must not change public `nds_analyze_control_flow` behavior:

- direct calls remain annotated but not traversed;
- indirect-target rules remain unchanged;
- CFG limits/result semantics remain unchanged.

Lower-level helpers may be shared only if traversal policies remain explicitly separate.

## MCP surface acceptance

Add exactly two NDS static MCP tools:

```text
nds_list_references
nds_find_xrefs
```

The existing nine-tool NDS static surface therefore becomes exactly eleven tools.

Public schemas must not add generic surfaces equivalent to:

```text
binary
bytes
baseAddress
caller-controlled output path
raw offset/length extraction
```

`server_capabilities` must state that:

- reference discovery is NDS-mapped and read-only;
- only deterministic single-instruction references are emitted;
- reverse-xref search is bounded and may have partial coverage;
- direct calls may expand xref scan coverage without changing CFG call traversal;
- loaded-overlay state is not inferred;
- generic binary/pattern search and heuristic pointer discovery are not provided.

## TDD acceptance matrix

Implementation must cover at least:

| Case | Required result |
| --- | --- |
| ARM immediate `B` | `direct-branch` |
| Thumb conditional direct branch | `direct-branch` |
| ARM `BL` | `direct-call` |
| immediate mode-switching `BLX` | direct call with correct target mode |
| `BX rN` | no proven target reference |
| `BLX rN` | no proven target reference |
| ARM PC-relative literal `LDR` | literal-pool slot only |
| Thumb PC-relative literal `LDR` | aligned architectural-PC slot calculation |
| literal slot contains pointer-looking value | no secondary reference |
| deterministic ARM `ADR` | `pc-relative-address` |
| deterministic Thumb PC-relative construction | `pc-relative-address` |
| PC-relative form needs unknown register | no reference |
| target ownership ambiguous | reference retained with `ambiguous-runtime-address` resolution |
| target is BSS | reference retained with `runtime-only-bss` resolution |
| target is compressed overlay | reference retained with `compressed-no-direct-rom-mapping` resolution |
| direct call during xref scan | in-scope proven callee queued |
| indirect call during xref scan | caller continues; callee not guessed |
| direct target outside selected scope | reference retained; target not traversed |
| valid explicitly seeded overlay | scanned |
| selected overlay without seed | `no-proven-seed` |
| selected compressed overlay | explicit partial coverage |
| duplicate paths reach same block | decoded once |
| scan cycle | deterministic termination |
| block/instruction/byte/edge cap | deterministic `truncated` result |
| result cap | deterministic prefix + `result-limit` |
| ROM-offset target has one unique applicable runtime address | accepted |
| ROM-offset target has multiple applicable runtime addresses | `ambiguous-reference-target` |
| ROM target has no applicable runtime address | `reference-target-not-runtime-addressable` |
| runtime target ownership ambiguous | numeric runtime target still matched |
| invalid overlay seed | `invalid-reference-seed` or more-specific established condition |
| ROM changes during operation | integrity failure, no stale result |
| backend initialization/runtime failure | `disassembly-backend-failure` |

Classifier tests must be independent from traversal tests so traversal success is not the only proof of instruction semantics.

## Package acceptance

The feature continues using exact `@alexaltea/capstone-js` 5.0.9 JavaScript/WASM. Source-tree success alone is insufficient.

The assembled production package smoke path must import built reference services and prove at least:

1. one direct ARM control-flow instruction classifies as a proven reference;
2. one Thumb PC-relative instruction classifies to the architecturally correct target.

The smoke test must run from the assembled package using bundled Capstone JS/WASM, with no source-tree decoder fallback, native addon, radare2 subprocess, or runtime network download.

## Documentation acceptance

README documentation must describe:

- both new tools;
- all four supported proven reference kinds;
- source-to-reference versus target-to-xref semantics;
- reverse-search component scope and overlay seed requirements;
- direct-call traversal for xref coverage only;
- literal-slot-only semantics;
- scan limits;
- `complete`, `partial-coverage`, and `truncated` meanings;
- ambiguous/BSS/compressed/unmapped target handling;
- deferred heuristic/pattern-search capabilities;
- continued separation from physical Catalina/DeSmuME acceptance.

## Security/safety properties

This milestone remains static and read-only. It does not:

- accept arbitrary debugger/RSP endpoints;
- write registers/memory;
- mutate ROMs;
- infer executable memory outside canonical NDS components;
- execute target ROM code;
- invoke arbitrary external binaries;
- accept caller-selected extraction/output paths;
- accept raw caller-provided executable bytes.

All decoding remains limited to validated file-backed NDS code regions.

## Implementation-order guidance

The implementation plan should proceed bottom-up with TDD, approximately:

1. normalized operand/address metadata for supported PC-relative forms;
2. deterministic reference classifier and fixtures;
3. canonical target-resolution integration;
4. bounded source-to-reference service;
5. bounded reverse-xref worklist, direct-call traversal, and coverage accounting;
6. MCP schemas/registration/capabilities;
7. packaged smoke acceptance;
8. README and final regression audit.

Each implementation task begins with failing tests for its externally observable or canonical-service behavior before production changes.

## Definition of done

The milestone is complete only when:

1. `nds_list_references` emits only supported deterministic single-instruction references from validated NDS code sources.
2. `nds_find_xrefs` scans only caller-selected same-processor executable scope from proven mode-tagged seeds.
3. One shared classifier owns direct branch/call and PC-relative reference semantics.
4. Direct calls expand xref scan coverage without changing existing CFG behavior.
5. ARM/Thumb PC-relative literal-slot calculations are architecture-correct.
6. Deterministic PC-relative address construction works without register-state inference.
7. Literal contents and ordinary pointer-looking immediates are never promoted to references.
8. Existing `RuntimeResolution` statuses are preserved for ambiguous/BSS/compressed/unmapped targets and never guessed away.
9. Coverage/truncation metadata prevents incomplete searches from being presented as complete negative evidence.
10. All configured bounds are enforced deterministically.
11. ROM identity is checked before and after top-level analysis.
12. The NDS static MCP surface is exactly eleven tools after adding the two approved tools.
13. Source type-check/tests/build pass.
14. Assembled package smoke verification passes using bundled Capstone.js/WASM.
15. README and `server_capabilities` accurately document the feature and exclusions.
16. No physical Catalina/DeSmuME acceptance claim is made by this static milestone.
