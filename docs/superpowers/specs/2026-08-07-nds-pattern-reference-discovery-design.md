# NDS Pattern + Reference Discovery Design

Date: 2026-08-07
Status: Approved design
Repository: `79cbd8hmgj-wq/RE-MCP`
Milestone scope: instruction-aware proven-reference discovery only

## Summary

Add a native-independent Nintendo DS static reference-discovery layer to RE-MCP on top of the canonical `NdsRomMap` and ARM/Thumb disassembly foundation.

This milestone provides two bounded query directions:

1. source-to-reference analysis: determine which statically proven references are emitted by instructions in a bounded code window;
2. target-to-xref analysis: search a caller-selected, bounded set of executable NDS components for statically proven instructions that reference one target.

The milestone intentionally uses a strict epistemic rule: every emitted reference must be explainable from one decoded ARM/Thumb instruction plus architectural PC semantics and the canonical NDS address model. Ordinary immediates that merely resemble addresses are not references. Literal-pool contents are not reinterpreted as pointers. Register-state inference, data-flow inference, function discovery, raw byte-pattern scanning, and persistent indexing are deferred.

This work remains fully static and does not depend on physical Intel Catalina/DeSmuME dynamic-debugging acceptance.

## Goals

1. Introduce one canonical RE-MCP-owned deterministic reference model and classifier.
2. Detect proven direct branch and direct call targets using the existing canonical control-flow semantics.
3. Detect architecturally deterministic PC-relative literal-pool slot references.
4. Detect deterministic PC-relative address construction such as supported `ADR` or equivalent immediate `ADD`/`SUB` from `PC`.
5. Provide a bounded source-to-reference MCP query.
6. Provide a bounded target-to-xref MCP query over an explicitly selected processor/component scope.
7. Expand reverse-xref code coverage through proven direct branch and direct call targets without changing existing CFG traversal semantics or claiming function boundaries.
8. Preserve NDS ambiguity, BSS, compressed-overlay, mode, component, processor, ROM-identity, and read-only safety rules.
9. Preserve useful partial-coverage and truncation metadata so absence of an xref is never overstated.
10. Prove the feature from the assembled production package using the existing pinned Capstone.js/WASM backend.

## Non-goals

This milestone does not add:

- raw byte-pattern or wildcard-signature search;
- integer-constant search;
- string search;
- generic binary search or disassembly;
- pointer-like immediate heuristics;
- literal-pool value pointer inference;
- pointer-array scanning;
- switch/jump-table recovery;
- register-value propagation;
- inter-instruction data-flow analysis;
- stack-value inference;
- table-content interpretation;
- relocation-like inference;
- code/data plausibility heuristics;
- function discovery or function-boundary claims;
- symbol recovery or symbol databases;
- persistent whole-ROM xref indexes;
- compressed-overlay decompression;
- runtime loaded-overlay inference;
- debugger integration;
- ROM mutation, rebuild, or patch generation;
- arbitrary caller-controlled output paths.

## Approved scope choices

The design decisions approved for this milestone are:

1. **Proven references only.** No pointer-like immediate heuristics.
2. **Direct control flow plus deterministic PC-relative addressing.** Include direct branch/call targets, PC-relative literal slots, and deterministic PC-relative address construction.
3. **On-demand queries only.** No persistent xref index.
4. **Both query directions.** Source-to-reference and target-to-xref.
5. **Caller-selectable reverse-search scope.** Main, explicit overlays, selected main+overlays, or all executable components for one processor.
6. **Direct call targets expand xref scan coverage.** This rule is local to xref scanning and does not change `nds_analyze_control_flow`.
7. **Literal loads reference the literal-pool slot only.** The loaded value is not interpreted.
8. **Reverse targets accept runtime address or ROM offset.** ROM offsets must canonicalize to one runtime target suitable for instruction-reference matching.

## Architecture

Use a shared deterministic reference classifier with two separate bounded query engines:

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

The classifier is the sole owner of reference semantics. Neither public query engine may invent its own instruction-reference rules.

The Capstone adapter remains responsible for translating Capstone ARM operand/detail information into RE-MCP-owned decoder metadata. The reference layer must not expose or depend on raw Capstone objects outside the adapter boundary.

The existing CFG analyzer remains behaviorally independent. `nds_analyze_control_flow` continues to annotate direct calls without traversing callees. The new xref scan may traverse proven direct call targets solely to improve statically proven code coverage.

## Canonical reference model

The implementation should introduce a model conceptually equivalent to:

```ts
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
    resolutionStatus: string;
    resolution: unknown;
  };

  evidence: {
    instructionMnemonic: string;
    mechanism: StaticReferenceMechanism;
  };
}
```

The exact TypeScript shape may reuse existing canonical resolver types instead of the placeholder `string`/`unknown` fields above. The required invariant is that the model preserves:

- exact source processor/component/overlay identity;
- exact source instruction runtime address and ROM offset;
- source ARM/Thumb mode;
- one proven target runtime address;
- deterministic ROM relationship when one exists;
- explicit target-resolution status when ownership/backing is ambiguous, BSS-only, compressed, or unmapped;
- the architectural mechanism that proves the reference.

A reference can be proven even when static ownership of its target is not unique. For example, an instruction can provably reference runtime address `X` while `NdsRomMap` reports multiple possible overlay owners for `X`. The reference is retained; the target mapping remains explicitly ambiguous.

## Decoder metadata extension

The current canonical decoder already supports deterministic direct control-flow targets. PC-relative literal/address classification requires narrowly extending normalized operand metadata.

The backend representation should support a memory operand conceptually equivalent to:

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

Additional normalized instruction identity/metadata may be added where required to distinguish supported literal/address forms. Parsing mnemonic/operand display strings is not an acceptable general reference-discovery mechanism.

Narrow adapter fallbacks may be used only where the existing Capstone 5.0.9 runtime demonstrably omits required structured metadata and the fallback can identify one exact supported architectural form without parsing numeric targets from display text.

## Reference classification rules

### 1. Direct branches

Immediate direct branches that already have deterministic canonical control-flow targets emit:

```text
kind: direct-branch
mechanism: direct-control-flow
```

This includes unconditional and conditional direct branches.

The reference classifier reuses the canonical target produced by the existing disassembly semantics. It does not independently parse or recalculate branch targets from operand text.

Register-indirect branches such as `BX rN` do not emit a proven target reference.

### 2. Direct calls

Immediate direct calls that already have deterministic canonical control-flow targets emit:

```text
kind: direct-call
mechanism: direct-control-flow
```

Immediate mode-switching call forms such as supported immediate `BLX` preserve the statically determined target mode in traversal metadata.

Register-indirect calls such as `BLX rN` do not emit a proven target reference.

### 3. PC-relative literal-pool references

Supported PC-relative literal-load forms emit a reference to the address of the literal-pool slot itself.

Conceptually:

```text
LDR r0, [PC, #offset]
            |
            v
     literal-pool slot
```

The value stored in the slot is never interpreted as a second reference in this milestone, even when it numerically resembles a mapped RAM or ROM address.

#### ARM architectural PC

For supported ARM-state literal forms:

```text
architectural PC = instructionAddress + 8
```

The encoded displacement is then applied according to the exact instruction semantics.

#### Thumb architectural PC

For supported Thumb literal forms:

```text
architectural PC = Align(instructionAddress + 4, 4)
```

The encoded displacement is then applied according to the exact instruction semantics.

The classifier must implement the architectural rule for the supported instruction form rather than trusting a decoder display string or an incidental PC presentation from Capstone.

### 4. PC-relative address construction

Supported forms that deterministically construct an address from architectural `PC` plus/minus an encoded immediate emit:

```text
kind: pc-relative-address
mechanism: pc-relative-address-construction
```

Examples include supported encodings equivalent to:

```text
ADR r0, label
ADD r0, PC, #imm
SUB r0, PC, #imm
```

A form requiring an unknown register contribution is excluded. Examples:

```text
ADD r0, PC, r3
LDR r0, [PC, r2]
```

No inter-instruction register state is inferred.

## Proven-reference invariant

Every emitted reference must be explainable from:

1. one decoded instruction;
2. that instruction's normalized structured semantics;
3. ARM/Thumb architectural PC rules where applicable; and
4. canonical NDS target resolution.

The following are never sufficient evidence by themselves:

- an immediate value happens to fall inside ARM9/ARM7 RAM;
- an immediate value happens to equal a ROM offset;
- a literal-pool value resembles a pointer;
- bytes adjacent to code resemble a pointer table;
- a register might contain an address based on earlier instructions.

## Canonical target resolution

Every proven runtime target is passed through one shared NDS target-resolution path.

The reference itself is retained when the architectural target is deterministic but static NDS ownership/backing is not. Target metadata must preserve the most specific canonical condition available, including cases equivalent to:

- uniquely resolved file-backed target;
- ambiguous runtime ownership/component mapping;
- runtime-only BSS target;
- compressed target with no direct ROM-byte mapping;
- unmapped runtime target.

No ambiguous target owner is silently chosen.

## Reference identity, deduplication, and ordering

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

Results are deterministic. Reverse-xref results are sorted by:

1. processor;
2. component;
3. overlay ID, with main treated deterministically;
4. source runtime address;
5. mode;
6. reference kind;
7. target runtime address when required as a final tie-breaker.

## Public MCP surface

Add exactly two public MCP tools:

1. `nds_list_references`
2. `nds_find_xrefs`

No other public pattern/reference tool is added in this milestone.

Both tools are NDS-aware and read-only. They accept an NDS ROM source and canonical NDS selectors, not arbitrary binary byte buffers, generic base addresses, or caller-selected output paths.

`server_capabilities` and README documentation must be updated consistently when these tools land.

## `nds_list_references`

Purpose:

> What proven references are emitted by instructions in this bounded code window?

### Input

Conceptually:

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

Exactly one of `runtimeAddress` or `romOffset` is required.

Source resolution, `overlayId`, alignment, compressed-overlay rejection, BSS rejection, and conservative `auto` mode follow the existing `nds_disassemble_range` policy.

### Limits

Reuse the existing bounded linear-disassembly limits:

| Limit | Default | Maximum |
| --- | ---: | ---: |
| Instructions | 32 | 256 |
| Source bytes | 128 | 1,024 |

Both limits apply simultaneously.

### Semantics

The tool decodes sequentially only. It does not follow branches or calls.

Every successfully decoded instruction is passed through the shared deterministic reference classifier.

The result is conceptually equivalent to:

```ts
{
  status:
    | "complete"
    | "decode-stopped"
    | "component-boundary";

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

A valid empty `references` array means only that no supported deterministic reference was found in the decoded bounded window.

## `nds_find_xrefs`

Purpose:

> Which proven instructions inside this explicitly selected bounded search scope reference this target?

### Target selector

Accept exactly one of:

```ts
{ targetRuntimeAddress: number }
```

or:

```ts
{ targetRomOffset: number }
```

### Runtime-address target

A caller-supplied runtime address is the authoritative numeric target used for xref matching.

Static ownership of that runtime address may still be ambiguous. That ambiguity is preserved in target-resolution metadata and does not prevent matching an instruction whose proven effective target equals the requested runtime address.

### ROM-offset target

A ROM-offset target must canonicalize to exactly one runtime address suitable for instruction-reference matching.

If the ROM offset has multiple possible runtime-address relationships, return:

```text
ambiguous-reference-target
```

If it has no runtime-address relationship suitable for this instruction-reference milestone, return:

```text
reference-target-not-runtime-addressable
```

For example, ordinary NitroFS or structural ROM bytes that are not mapped to a runtime address are not valid xref targets here.

### Search processor and scope

The caller selects exactly one processor:

```text
arm9 | arm7
```

and one explicit static scope:

```ts
type ReferenceSearchScope =
  | { kind: "main" }
  | { kind: "overlay"; overlayIds: number[] }
  | { kind: "main-and-overlays"; overlayIds: number[] }
  | { kind: "all-executable-components" };
```

`all-executable-components` means canonical main plus overlay components for the selected processor. It does not claim those overlays are loaded simultaneously at runtime.

The scope selects which components are eligible to be scanned. It does not by itself provide ARM/Thumb mode evidence for an overlay.

## Proven-code seeds

Reverse-xref search never linear-sweeps arbitrary executable bytes in both modes.

Each selected component is explored only from trusted mode-tagged seeds.

Initial proven seeds are:

1. the selected ARM9/ARM7 main header entry point when main is in scope;
2. caller-supplied explicit mode-tagged seeds that validate against a selected component;
3. deterministic direct branch targets discovered by the scan;
4. deterministic direct call targets discovered by the scan.

The main header entry point is an ARM seed under the existing conservative mode policy.

An overlay has no assumed ARM/Thumb entry mode merely because it appears in the overlay table or scope.

## Caller-supplied seeds

Conceptually:

```ts
{
  runtimeAddress: number;
  mode: "arm" | "thumb";
  overlayId?: number;
}
```

An explicit seed must resolve uniquely to a selected executable component for the selected processor.

Reject an explicit seed when any of the following is true:

- it resolves outside the caller-selected scope;
- it resolves to the other processor;
- an `overlayId` is supplied but does not match the exact selected overlay;
- it falls outside the exact file-backed initialized extent;
- it lands in BSS;
- it lands in a compressed overlay;
- alignment is invalid for the supplied mode;
- source resolution remains ambiguous.

The caller cannot seed arbitrary NitroFS/structural data as code.

## Reverse-xref scan engine

The reverse-xref engine is a dedicated bounded proven-code traversal that reuses the canonical decoder and reference classifier but has its own traversal policy.

### Block identity

Queued block identity is at least:

```text
processor
+ component
+ overlayId
+ runtimeAddress
+ mode
```

A block is scheduled/decoded at most once under the same identity. Cycles terminate deterministically.

### Ordinary instruction

Classify references, then continue sequentially.

### Conditional direct branch

1. classify and record the direct-branch reference;
2. queue the proven taken target when it is inside the selected scope and safely decodable;
3. queue valid same-component fallthrough;
4. terminate the current block.

### Unconditional direct branch

1. classify and record the direct-branch reference;
2. queue the proven target when it is inside the selected scope and safely decodable;
3. terminate the block.

### Direct call

1. classify and record the direct-call reference;
2. queue the proven call target when it is inside the selected scope and safely decodable;
3. continue caller fallthrough in the current block when valid.

Following a call target here is a code-coverage rule only. It does not declare a function, function boundary, ownership hierarchy, or call graph beyond the proven instruction edge.

### Indirect call

No proven target reference is emitted. The unknown callee is not followed. Valid caller fallthrough continues.

### Indirect branch or return

Terminate the current block. No target is guessed.

### Decode stop

A local undecodable instruction terminates the affected block. Already queued deterministic blocks may continue if global limits permit.

A backend runtime/initialization failure is operational and follows the existing `disassembly-backend-failure` path rather than being treated as local undecodable bytes.

## Scope enforcement on discovered targets

Reference correctness and scan coverage are separate.

If an instruction provably references a target outside the selected component scope:

- the reference remains valid and can match the requested xref target;
- that target is not queued for further decoding.

Example: if scope contains main and overlays 3 and 7, a proven call from main into overlay 12 remains a `direct-call` reference, but overlay 12 is not scanned.

The selected processor remains a hard boundary. Reverse-xref traversal never crosses from ARM9 into ARM7 or vice versa.

## Component coverage semantics

Each requested component receives a deterministic coverage state conceptually drawn from:

```ts
type ComponentCoverageStatus =
  | "scanned"
  | "no-proven-seed"
  | "compressed-overlay-not-decodable"
  | "out-of-limit";
```

A selected overlay becomes `scanned` only when it receives a valid explicit seed or a proven branch/call seed.

An included overlay that never receives a proven seed is `no-proven-seed`.

A selected compressed overlay is not decoded as runtime instructions and reports `compressed-overlay-not-decodable`.

Coverage metadata must make clear that `no-proven-seed` and compressed components were not searched. A zero-xref result must not imply absence inside unscanned components.

## Reverse-search limits

All limits apply globally across one `nds_find_xrefs` operation.

| Limit | Default | Maximum |
| --- | ---: | ---: |
| Components considered | 32 | 128 |
| Proven-code blocks | 128 | 512 |
| Instructions decoded | 2,048 | 16,384 |
| Decoded source bytes | 8 KiB | 64 KiB |
| Traversal edges | 512 | 4,096 |
| Xrefs returned | 256 | 2,048 |

Limits must be enforced deterministically.

Truncation reasons are drawn from:

```text
component-limit
block-limit
instruction-limit
byte-limit
edge-limit
result-limit
```

When `result-limit` is reached, retain a deterministic prefix according to the documented result ordering.

Normal limit exhaustion returns a valid partial result. It does not throw away already proven xrefs.

## Reverse-xref result semantics

The result is conceptually equivalent to:

```ts
{
  status:
    | "complete"
    | "partial-coverage"
    | "truncated";

  target: {
    requestedBy: "runtime-address" | "rom-offset";
    runtimeAddress: number;
    romOffset: number | null;
    resolution: unknown;
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

### Status precedence

- `complete`: every requested eligible component was safely explored within bounds.
- `partial-coverage`: one or more requested components could not be safely explored because no proven seed existed or the component was compressed, and no traversal/result cap prevented completion of otherwise eligible work.
- `truncated`: one or more global limits prevented completing otherwise eligible exploration.

`truncated` takes precedence over `partial-coverage` when both conditions occur. The coverage array still records unscanned components, so the caller can distinguish truncation from independent no-seed/compressed coverage gaps.

### Meaning of zero xrefs

- zero xrefs + `complete`: no supported proven reference to the target was found in the fully explored selected scope;
- zero xrefs + `partial-coverage`: no supported proven reference was found in the explored portion, but some requested components were not safely searchable;
- zero xrefs + `truncated`: no supported proven reference was found before one or more scan limits cut exploration short.

Only the first condition supports a complete negative statement for the selected scope.

## Error and condition categories

Reference-specific categories should include equivalents of:

```text
ambiguous-reference-target
reference-target-not-runtime-addressable
invalid-reference-scope
invalid-reference-seed
reference-scan-limit-exceeded
```

Existing NDS/disassembly categories remain reused where they are more specific, including equivalents of:

```text
ambiguous-runtime-address
compressed-overlay-not-decodable
runtime-only-bss
unmapped
disassembly-backend-failure
```

Normal configured limit exhaustion is represented by a `truncated` result, not an operational error. `reference-scan-limit-exceeded` is reserved for impossible/internal limit-state or invariant failures rather than ordinary bounded traversal completion.

Malformed schemas are rejected through the normal MCP/Zod validation path.

## ROM identity and integrity

Both top-level operations preserve the existing static-analysis ROM identity invariant:

1. validate/hash the ROM before the operation;
2. resolve/decode/classify/search using the canonical NDS map associated with that identity;
3. validate/hash the ROM again after the operation;
4. reject the result if the ROM changed during analysis.

The post-operation check must still occur when decoder/classifier/search work throws, consistent with the established NDS static-analysis integrity behavior.

Neither tool writes to the ROM or to caller-selected filesystem destinations.

## Existing CFG compatibility

This milestone must not change the public behavior of `nds_analyze_control_flow`.

Specifically:

- existing CFG direct calls remain annotated but not traversed;
- existing CFG indirect-target rules remain unchanged;
- existing CFG limits remain unchanged;
- existing CFG result semantics remain unchanged.

The reverse-xref scanner may share lower-level worklist helpers only if doing so does not couple the two traversal policies or alter the established CFG contract.

## TDD acceptance matrix

Implementation must cover at least the following behaviors with deterministic tests.

| Case | Required result |
| --- | --- |
| ARM immediate `B` | one `direct-branch` reference |
| Thumb immediate conditional branch | one `direct-branch` reference |
| ARM `BL` | one `direct-call` reference |
| immediate mode-switching `BLX` | `direct-call` with correctly propagated target mode |
| `BX rN` | no proven target reference |
| `BLX rN` | no proven target reference |
| ARM PC-relative literal `LDR` | literal-pool slot address only |
| Thumb PC-relative literal `LDR` | slot computed with aligned architectural Thumb PC |
| literal slot contains mapped RAM-looking value | no secondary pointer/reference emitted |
| deterministic ARM `ADR` | `pc-relative-address` reference |
| deterministic Thumb PC-relative address construction | `pc-relative-address` reference |
| PC-relative form with unknown register contribution | no reference |
| proven target has ambiguous overlay ownership | reference retained with ambiguous target resolution |
| proven target lands in BSS | reference retained with runtime-only target metadata |
| direct call during reverse scan | callee queued when in selected scope |
| indirect call during reverse scan | caller fallthrough continues; unknown callee not guessed |
| direct branch target outside selected scope | reference retained; target not traversed |
| valid explicitly seeded overlay | overlay scanned |
| selected overlay without proven seed | `no-proven-seed` coverage |
| selected compressed overlay | explicit compressed partial coverage |
| duplicate paths reach same block identity | block decoded once |
| traversal cycle | deterministic termination |
| block/instruction/byte/edge cap | valid deterministic `truncated` result |
| result cap | deterministic xref prefix + `result-limit` |
| ROM-offset target has unique runtime mapping | accepted and canonicalized |
| ROM-offset target has multiple runtime mappings | `ambiguous-reference-target` |
| ROM target has no runtime relationship | `reference-target-not-runtime-addressable` |
| source runtime target ownership is ambiguous | runtime target still used for numeric xref matching |
| invalid overlay seed | `invalid-reference-seed` or more specific existing condition |
| ROM changes during operation | integrity failure; no stale result returned |
| decoder backend initialization/runtime failure | `disassembly-backend-failure` |

Tests should separate classifier semantics from traversal policy so a traversal test is not the only evidence that an instruction classifies correctly.

## MCP acceptance

Tool registration tests must prove that the NDS static tool surface grows from nine to exactly eleven tools by adding:

```text
nds_list_references
nds_find_xrefs
```

Public schemas must not expose fields equivalent to:

```text
binary
bytes
baseAddress
output
arbitrary output path
raw offset/length extraction
```

The public tool descriptions must describe the proven-reference and bounded/partial-coverage semantics accurately.

`server_capabilities` must state that:

- instruction-aware reference discovery is NDS-mapped and read-only;
- only deterministic single-instruction references are emitted;
- reverse-xref search is bounded and may have partial coverage;
- direct calls may expand xref scan coverage without changing CFG call traversal;
- loaded-overlay state is not inferred;
- generic binary search/disassembly and heuristic pointer discovery are not provided.

## Package acceptance

Because the feature relies on the existing exact `@alexaltea/capstone-js` 5.0.9 JavaScript/WASM backend, successful source-tree tests alone are insufficient.

The assembled production package acceptance must continue proving that Capstone JS/WASM is present and initializes without network access.

Add a packaged smoke path that imports the built reference service and proves at least:

1. one direct ARM control-flow instruction classifies as a proven reference;
2. one Thumb PC-relative instruction classifies to the architecturally correct target.

The smoke test must run against the assembled package rather than importing source-tree TypeScript or copying decoder assets from the source checkout after assembly.

No native addon, radare2 subprocess, or runtime network decoder download is introduced.

## Documentation acceptance

README documentation must describe:

- the two new MCP tools;
- the four supported proven reference kinds;
- the difference between source-to-reference and target-to-xref queries;
- reverse-search scope and explicit overlay seed requirements;
- direct-call traversal for xref coverage only;
- literal-slot-only semantics;
- bounded scan limits;
- `complete`, `partial-coverage`, and `truncated` meanings;
- conservative treatment of ambiguous/BSS/compressed/unmapped targets;
- deferred heuristic/pattern-search capabilities;
- continued separation from pending physical Catalina/DeSmuME acceptance.

## Security and safety properties

This milestone remains static and read-only.

It must not:

- accept arbitrary debugger/RSP endpoints;
- add register or memory writes;
- add ROM writes;
- infer arbitrary executable memory outside canonical NDS components;
- execute target ROM code;
- invoke arbitrary external binaries;
- accept caller-selected extraction/output paths;
- treat raw user-provided bytes as an executable source.

All decoding remains limited to validated file-backed NDS code regions.

## Implementation-order guidance

The implementation plan should decompose the milestone so correctness is established from the bottom up, approximately:

1. normalized operand/address metadata required for PC-relative forms;
2. deterministic reference classifier and unit fixtures;
3. canonical target-resolution integration;
4. bounded source-to-reference service;
5. bounded reverse-xref worklist with direct-call traversal and coverage accounting;
6. MCP schemas/registration/capabilities;
7. package smoke acceptance;
8. README/final regression audit.

Every implementation task must begin with failing tests for its externally observable or canonical service behavior before production changes are written.

## Definition of done

The milestone is complete only when all of the following are true:

1. `nds_list_references` returns only supported deterministic single-instruction references from validated NDS code sources.
2. `nds_find_xrefs` searches only caller-selected same-processor executable scope from proven mode-tagged seeds.
3. Direct branches and calls classify through one shared reference model.
4. Direct call targets expand reverse-xref scan coverage without changing existing CFG behavior.
5. ARM and Thumb PC-relative literal-slot calculations are architecture-correct.
6. Deterministic PC-relative address construction is supported without register-state inference.
7. Literal-pool contents and ordinary pointer-looking immediates are not promoted to references.
8. Ambiguous/BSS/compressed/unmapped target mappings remain explicit and are never guessed.
9. Reverse-search coverage and truncation metadata prevent incomplete searches from being presented as complete negative evidence.
10. All configured bounds are enforced deterministically.
11. ROM identity is checked before and after top-level analysis.
12. Public MCP surface is exactly eleven NDS static tools after adding the two approved tools.
13. Source CI/type-check/tests/build pass.
14. Assembled production-package smoke verification passes using bundled Capstone.js/WASM.
15. README and `server_capabilities` accurately document the feature and its exclusions.
16. No physical Catalina/DeSmuME acceptance claim is made by this static milestone.
