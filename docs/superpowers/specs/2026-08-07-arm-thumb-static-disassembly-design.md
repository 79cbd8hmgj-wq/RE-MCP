# ARM/Thumb Static Disassembly Design

Date: 2026-08-07
Status: Approved design
Repository: `79cbd8hmgj-wq/RE-MCP`

## Summary

Add a native-independent Nintendo DS static disassembly layer to RE-MCP using `@alexaltea/capstone-js` as a JavaScript+WebAssembly Capstone backend. The milestone provides bounded ARM/Thumb linear disassembly and bounded direct-control-flow analysis over code bytes that can be mapped deterministically from the canonical `NdsRomMap`.

The new layer remains NDS-aware. It does not accept arbitrary binaries, arbitrary base addresses, raw caller-provided byte buffers, or caller-controlled output paths. It does not perform heuristic function discovery, recursively traverse calls, infer loaded overlays, mutate ROMs, or depend on DeSmuME acceptance.

## Goals

1. Decode ARM and Thumb instructions from validated Nintendo DS code regions.
2. Normalize decoder output into RE-MCP-owned instruction types rather than exposing Capstone-specific structures.
3. Classify direct control flow conservatively and resolve deterministic targets through the existing NDS address model.
4. Provide two public MCP capabilities:
   - bounded linear disassembly;
   - bounded basic-block/CFG traversal.
5. Preserve the existing NDS foundation's ambiguity, BSS, compressed-overlay, and ROM-identity safety rules.
6. Keep the implementation self-contained for RE-MCP packaging, including the WebAssembly runtime assets needed by Capstone.js.

## Non-goals

This milestone does not add:

- heuristic function discovery or function-boundary claims;
- recursive traversal into call targets;
- symbol recovery;
- generic binary disassembly;
- arbitrary binary paths, base addresses, or raw byte buffers;
- broad code/data heuristics;
- compressed-overlay decompression;
- Ghidra or radare2 integration;
- runtime loaded-overlay detection;
- debugger-dependent analysis;
- register or memory writes;
- watchpoints;
- ROM mutation;
- ROM rebuild or patch generation.

Physical Catalina/DeSmuME Dynamic Debugging acceptance remains a separate unresolved gate and is not required for this static milestone.

## Dependency choice

Use `@alexaltea/capstone-js`, currently version `5.0.9`, as the disassembly backend.

Reasons:

- JavaScript + WebAssembly avoids a native N-API addon requirement.
- Capstone supports ARM disassembly.
- The package can be bundled with RE-MCP rather than requiring an external executable.
- It keeps this milestone narrower than a radare2 subprocess integration.

The implementation plan must pin the chosen package version and prove actual Node 20/package-bundle compatibility in tests. The design does not claim native Catalina compatibility merely from package metadata.

Reference material at design time:

- Capstone.js project: <https://alexaltea.github.io/capstone.js/>
- npm package: `@alexaltea/capstone-js`

## Architecture

Use a canonical decoder service plus a separate control-flow engine:

```text
NdsRomMap
   |
   v
NDS code-source resolver
   |
   v
Capstone WASM adapter
   |
   v
Canonical RE-MCP instruction model
   |-- bounded linear decoder
   `-- bounded basic-block/CFG analyzer
```

The Capstone adapter is intentionally narrow. NDS address resolution, component identity, ARM/Thumb mode rules, traversal limits, branch semantics, ambiguity handling, and MCP schemas stay outside the third-party decoder adapter.

Suggested service separation:

```text
src/services/disassembly/
  capstone.ts
  arm-decoder.ts
  instruction.ts
  control-flow.ts
```

Exact file names may be adjusted during implementation to match repository conventions, but the architectural boundaries are requirements.

## Backend interface

The decoder backend exposes a narrow RE-MCP-owned interface conceptually equivalent to:

```ts
interface ArmDisassemblyBackend {
  decodeOne(
    bytes: Uint8Array,
    address: number,
    mode: "arm" | "thumb"
  ): DecodedArmInstruction | null;
}
```

The NDS services and CFG engine must not import Capstone types directly.

This boundary allows control-flow tests to use deterministic fake decoders and permits a future backend replacement without changing the MCP contract.

## Canonical instruction model

Each successfully normalized instruction records at least:

```ts
type ArmMode = "arm" | "thumb";

interface StaticInstruction {
  address: number;
  romOffset: number;
  size: 2 | 4;
  bytesHex: string;
  mode: ArmMode;

  mnemonic: string;
  operands: string;

  flow: {
    kind:
      | "fallthrough"
      | "conditional-branch"
      | "unconditional-branch"
      | "call"
      | "return"
      | "indirect-branch"
      | "indirect-call";
    directTarget: number | null;
    targetMode: ArmMode | null;
    fallthrough: number | null;
  };

  source: {
    processor: "arm9" | "arm7";
    component: "main" | "overlay";
    overlayId: number | null;
  };
}
```

The exact TypeScript shape may add metadata needed for diagnostics, but it must not remove the semantics above or expose raw Capstone objects as the public model.

`address` is the normalized runtime address. `romOffset` is present only when the instruction's exact source bytes have a deterministic ROM mapping; this milestone only decodes regions where that condition holds.

## ARM/Thumb mode policy

Public disassembly requests accept:

- `arm`;
- `thumb`;
- conservative `auto`.

`auto` succeeds only when RE-MCP has deterministic mode evidence.

Approved deterministic evidence for this milestone:

1. NDS ARM9 or ARM7 header entry points are ARM seeds.
2. A direct control-flow edge already decoded by the same analysis may propagate a statically determined target mode.
3. An explicitly mode-tagged trusted internal seed may qualify in the future, but this milestone introduces no additional seed source.

The following are not sufficient evidence:

- merely being inside an executable range;
- merely belonging to an overlay;
- decoding both modes and choosing the stream that looks more plausible;
- caller-supplied arbitrary odd/even address conventions without a trusted semantic source.

If `auto` cannot prove a mode, return `mode-ambiguous` and do not decode.

### Mode propagation

For CFG traversal:

- ARM `B` / `BL` preserve ARM mode at their direct target.
- Thumb `B` / `BL` preserve Thumb mode at their direct target.
- immediate mode-switching control-flow instructions such as `BLX` use instruction semantics to determine target mode when statically available.
- register-indirect `BX` / `BLX` do not receive an invented target mode or address; that edge terminates as unresolved.

Normalized addresses and mode are tracked separately. RE-MCP does not use address bit 0 as a general-purpose mode guess for arbitrary requests.

## NDS code-source resolution

Disassembly reads directly from a validated `.nds` ROM using the canonical NDS static model. It never requires extraction as a prerequisite and never accepts a generic binary source.

Supported entry forms are conceptually:

```ts
{
  processor: "arm9" | "arm7";
  runtimeAddress: number;
  mode: "arm" | "thumb" | "auto";
  overlayId?: number;
}
```

or:

```ts
{
  processor: "arm9" | "arm7";
  romOffset: number;
  mode: "arm" | "thumb" | "auto";
  overlayId?: number;
}
```

`overlayId` is a disambiguator only. Supplying it does not claim that the overlay is loaded at runtime.

A valid decode source must resolve uniquely to one of:

- ARM9 main;
- ARM7 main;
- an uncompressed ARM9 overlay;
- an uncompressed ARM7 overlay.

The processor is part of source identity. Static traversal must never jump from ARM9 analysis into ARM7 analysis or vice versa.

## Ambiguity rules

If a requested runtime address or direct branch target belongs to multiple possible code mappings, RE-MCP must not choose one.

Return or record:

```text
ambiguous-code-source
```

A caller may resolve an ambiguous starting location by providing an exact overlay ID when that produces one deterministic source.

Control-flow traversal encountering an ambiguous target records the unresolved edge and does not continue through it.

## BSS and file-backed boundaries

BSS has no ROM source bytes and is never disassembled.

A request that lands in runtime-only BSS returns:

```text
runtime-only-bss
```

For an uncompressed overlay, only the exact file-backed initialized bytes may be decoded. If the overlay runtime extent is larger than its physical backing file, the unbacked runtime suffix is not decoded.

An instruction may not straddle a validated component boundary. Decoding stops before crossing into an adjacent ROM region even if bytes are physically contiguous in the file.

## Compressed overlays

Compressed overlays are explicitly outside the decodable source set for this milestone.

A compressed-overlay request returns:

```text
compressed-overlay-not-decodable
```

The result should include useful overlay/file/backing metadata, but RE-MCP must not disassemble the stored compressed bytes as if they were runtime instructions and must not invent a direct runtime-to-compressed-byte mapping.

Overlay decompression is a separate future milestone.

## ROM identity

The ROM SHA-256 associated with the canonical map remains authoritative.

Before disassembly, RE-MCP verifies that the source ROM still matches the identity used to construct the NDS map. A stale map must not be applied to modified source bytes.

The implementation may reuse an existing trusted identity-validation helper if one already satisfies this invariant.

## Alignment

ARM decoding requires a 4-byte-aligned runtime start address.

Thumb decoding requires a 2-byte-aligned runtime start address.

Invalid alignment is rejected rather than rounded or silently adjusted.

## Linear disassembly

Expose one bounded linear-disassembly operation.

Proposed public MCP name:

```text
nds_disassemble_range
```

The tool decodes sequential instructions from one uniquely validated starting location using the selected/proven mode.

### Limits

| Limit | Default | Maximum |
| --- | ---: | ---: |
| Instructions | 32 | 256 |
| Source bytes | 128 | 1,024 |

Both limits apply simultaneously.

The decoder stops at the first of:

- instruction limit;
- source-byte limit;
- end of the validated file-backed component;
- decode failure;
- an instruction that would cross the component boundary.

On a decode failure, RE-MCP stops at that location. It does not skip bytes and resume, because doing so could silently desynchronize the instruction stream.

Linear disassembly classifies control flow but does not alter the sequential traversal behavior based on branches.

## Direct control-flow analysis

Expose one bounded CFG operation.

Proposed public MCP name:

```text
nds_analyze_control_flow
```

The analyzer starts from one validated entry point and discovers reachable basic blocks by following deterministic non-call direct control-flow edges.

### Basic-block termination

Continue sequential decoding until a block terminator:

- unconditional direct branch;
- conditional direct branch;
- return;
- indirect branch;
- decode failure;
- component boundary;
- configured traversal limit.

Conditional branches generate both the deterministic taken target and fall-through path when valid.

Unconditional direct branches generate their deterministic target when valid.

### Call policy

Direct calls are fully annotated but are not traversed.

A direct call should record, when deterministically available:

- target runtime address;
- target processor;
- target component;
- overlay identity;
- exact ROM offset;
- target mode;
- resolution status.

The called target does not become a discovered CFG block solely because of the call.

Indirect calls likewise terminate as unresolved call events without traversal.

This prevents the milestone from turning into recursive function discovery.

### Indirect control flow

Register-indirect branches and calls do not receive guessed targets.

Record them as unresolved terminal control-flow events:

- `indirect-branch`;
- `indirect-call`;
- `return` where semantics prove a return.

## Cross-component direct branches

A deterministic direct branch may traverse into another uncompressed executable component for the same processor when the canonical resolver can map the target uniquely and the target mode is proven.

Traversal stops on that edge when the target is:

- ambiguous;
- unmapped;
- BSS-only;
- inside a compressed overlay;
- for the other processor;
- otherwise not deterministically file-backed.

Static resolution does not imply an overlay is loaded at runtime.

## CFG identity and deduplication

A discovered basic block is identified by at least:

```text
processor + component + overlayId + runtimeAddress + mode
```

Mode is part of identity. ARM and Thumb interpretations must never be silently merged.

The implementation must prevent infinite worklists caused by cycles and must not decode an already discovered block repeatedly under the same identity.

## CFG limits

| Limit | Default | Maximum |
| --- | ---: | ---: |
| Basic blocks | 64 | 256 |
| Total instructions | 512 | 4,096 |
| Total decoded source bytes | 2 KiB | 16 KiB |
| Traversal edges | 128 | 1,024 |

All limits apply simultaneously.

If any traversal cap prevents complete exploration, return a valid partial result with:

```text
status: "truncated"
```

and explicit truncation reasons drawn from:

```text
block-limit
instruction-limit
byte-limit
edge-limit
```

A partial graph must never be presented as complete.

## CFG result semantics

The public/canonical result is conceptually equivalent to:

```ts
interface StaticControlFlowGraph {
  entry: {
    address: number;
    mode: "arm" | "thumb";
    processor: "arm9" | "arm7";
    overlayId: number | null;
  };

  status: "complete" | "truncated";
  truncationReasons: string[];

  blocks: StaticBasicBlock[];
  edges: StaticControlFlowEdge[];
  calls: StaticCallEdge[];
  unresolvedEdges: StaticUnresolvedEdge[];

  totals: {
    blocks: number;
    instructions: number;
    bytes: number;
    edges: number;
  };
}
```

CFG edges distinguish at least:

- `fallthrough`;
- `branch`;
- `conditional-taken`;
- `conditional-fallthrough`.

Calls are represented separately from traversed CFG edges.

## MCP surface

Add exactly two public MCP tools in this milestone:

1. `nds_disassemble_range`
2. `nds_analyze_control_flow`

Both tools:

- require an NDS ROM source;
- resolve through the canonical NDS map;
- enforce processor and mode schemas;
- enforce bounded caps;
- may accept `overlayId` only as a source disambiguator;
- must not expose arbitrary binary input;
- must not expose arbitrary raw byte ranges outside the validated NDS code mapping;
- must not expose caller-controlled output paths;
- must not mutate the ROM.

`server_capabilities` and README documentation must be updated consistently when the tools land.

## Structured conditions and errors

Expected static-analysis conditions should remain structured results where they describe a valid analysis outcome or an inability to proceed safely:

- `ambiguous-code-source`;
- `compressed-overlay-not-decodable`;
- `runtime-only-bss`;
- `unmapped-address`;
- `mode-ambiguous`;
- `decode-stopped`;
- `component-boundary`;
- `truncated`.

The implementation should preserve useful resolver/source metadata alongside these statuses.

Operational failures continue using RE-MCP's structured MCP error envelope.

A decoder runtime/initialization failure must be distinguishable from malformed ROM data, using a category equivalent to:

```text
disassembly-backend-failure
```

An NDS parser/resolver error retains the most specific existing NDS category available.

## Decoder-stop semantics

A decode failure is local and explicit.

For linear decoding, return the successfully decoded prefix plus a `decode-stopped` reason/position rather than skipping bytes.

For CFG decoding, terminate the affected block, record the stop reason, and continue processing other already queued deterministic blocks if limits permit.

A decoder failure caused by the backend itself is not equivalent to an undecodable byte sequence and must use the operational backend-failure path.

## Packaging requirements

Successful source-tree CI is not sufficient because the backend relies on WebAssembly assets.

The package workflow must prove that the assembled self-contained artifact includes everything needed to initialize Capstone.js without network access.

The package acceptance smoke test must, from the packaged artifact rather than the source checkout:

1. initialize the Capstone.js WASM runtime;
2. decode at least one known ARM fixture;
3. decode at least one known Thumb fixture;
4. exit cleanly without requiring an external Capstone/radare2 installation or runtime download.

If the upstream package requires special `.wasm` asset copying or loader configuration, that becomes an explicit part of the bundle assembly and package tests.

## Testing strategy

Development follows TDD.

### Backend adapter tests

Cover:

- known ARM instruction decoding;
- known Thumb instruction decoding;
- exact address normalization;
- instruction size normalization;
- exact bytes normalization;
- mnemonic/operand normalization;
- decoder close/cleanup behavior as required by the package;
- malformed/truncated decode input;
- WebAssembly/backend initialization failure mapping.

### NDS code-source tests

Cover:

- ARM9 main mapping;
- ARM7 main mapping;
- uncompressed ARM9 overlay mapping;
- uncompressed ARM7 overlay mapping;
- compressed-overlay rejection;
- BSS rejection;
- ambiguous overlay mapping;
- explicit overlay-ID disambiguation;
- component-end boundary;
- ROM identity mismatch;
- ARM alignment rejection;
- Thumb alignment rejection;
- explicit ARM mode;
- explicit Thumb mode;
- deterministic header-entry `auto` mode;
- deterministic CFG-propagated `auto` mode;
- unresolved `auto` mode returning `mode-ambiguous`.

### Instruction/control-flow classification tests

Cover representative direct and indirect control-flow semantics needed by the canonical model, including:

- ordinary fall-through;
- conditional direct branch;
- unconditional direct branch;
- direct call;
- return;
- indirect branch;
- indirect call;
- ARM-preserving direct target;
- Thumb-preserving direct target;
- deterministic immediate ARM/Thumb mode switch where supported by the instruction semantics.

The implementation must test the exact Capstone metadata used for these classifications rather than relying only on mnemonic string matching unless the plan explicitly proves no stronger metadata is available.

### CFG tests

Cover:

- conditional branch plus fall-through;
- unconditional branch;
- direct call recorded but not traversed;
- indirect branch termination;
- indirect call termination;
- return termination;
- deterministic ARM-to-Thumb or Thumb-to-ARM transition where applicable;
- duplicate block prevention;
- cycles;
- deterministic cross-component direct branch;
- ambiguous target termination;
- compressed-overlay target termination;
- same-processor enforcement;
- each traversal limit independently;
- simultaneous limits;
- truncated results never reported as complete;
- decode failure terminating only the affected block.

### MCP tests

Cover:

- exactly two new public tool registrations;
- schemas and numeric caps;
- processor validation;
- mode validation;
- optional overlay disambiguator behavior;
- structured static-analysis statuses;
- structured operational backend errors;
- no generic binary input;
- no arbitrary caller base address;
- no caller-controlled output path;
- no raw arbitrary byte extraction surface;
- capability metadata and README consistency.

### Package workflow tests

Cover:

- self-contained bundle includes required JS/WASM assets;
- isolated packaged runtime initializes the decoder;
- isolated packaged runtime decodes known ARM and Thumb fixtures;
- no runtime network dependency.

## Documentation

README documentation for the milestone must explain:

- the two static disassembly tools;
- ARM/Thumb explicit and conservative `auto` mode semantics;
- ambiguity behavior;
- BSS limitations;
- compressed-overlay rejection;
- linear-disassembly limits;
- CFG traversal behavior;
- calls recorded but not traversed;
- indirect-target limitations;
- truncation semantics;
- static overlay resolution does not imply runtime loaded state;
- the distinction between this static milestone and pending native Catalina/DeSmuME acceptance.

## Security and safety invariants

The milestone preserves the existing read-only static-analysis boundary:

- localhost/debugger transport policy is unaffected;
- no new debugger write capability is added;
- ROM reads are limited to deterministically mapped NDS code components;
- no arbitrary filesystem binary decode surface is added;
- no caller-controlled output location is added;
- no ROM mutation is introduced;
- ambiguous mappings are never guessed;
- compressed runtime code is never faked from compressed storage bytes;
- analysis limits prevent unbounded recursive traversal.

## Success criteria

The milestone is complete when all of the following are true:

1. A packaged RE-MCP build can initialize the pinned Capstone.js WASM backend without network access.
2. `nds_disassemble_range` can safely decode bounded ARM and Thumb windows from deterministic main or uncompressed-overlay code mappings.
3. `auto` mode decodes only when mode is proven by an approved deterministic source.
4. `nds_analyze_control_flow` builds bounded basic blocks from deterministic direct branch/fall-through edges.
5. Calls are annotated but not recursively traversed.
6. Indirect control-flow targets are never guessed.
7. Cross-component traversal happens only for uniquely resolvable, same-processor, uncompressed, file-backed targets.
8. Ambiguous mappings, BSS, compressed overlays, alignment failures, and stale ROM identity are handled explicitly.
9. CFG cap exhaustion is reported as `truncated`, never `complete`.
10. Public APIs expose only the two approved NDS-aware tools and do not create a generic binary-disassembly surface.
11. Unit, integration, type-check, build, and package smoke tests pass in CI.
12. README/capability documentation matches implemented behavior.

## Follow-on milestones

Likely later work, each requiring its own design gate, includes:

- compressed-overlay decompression;
- reference/xref indexing;
- seed-based function discovery;
- function-boundary heuristics;
- pattern/table inference;
- richer static symbolization;
- optional Ghidra/radare2 interoperability;
- native debugger/static correlation after physical Catalina acceptance.
