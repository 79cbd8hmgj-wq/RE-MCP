# NDS Static Analysis Foundation — Design Specification

Date: 2026-08-07
Status: Approved design, pending implementation plan
Branch: `design/nds-static-analysis-foundation`

## 1. Purpose

Build a native-independent Nintendo DS static-analysis foundation for RE-MCP without extending the unverified live DeSmuME debugger behavior before the physical Catalina acceptance run.

The milestone establishes one canonical, validated NDS ROM model that future disassembly, Ghidra, pattern-search, table-inference, and runtime-correlation tooling can reuse.

The original `.nds` file remains immutable. The only writes allowed by this milestone are deterministic derived artifacts under a controlled `analysis/generated/nds/...` tree.

## 2. Goals

The milestone must provide:

- strict Nintendo DS header parsing;
- ARM9 and ARM7 executable metadata;
- FAT parsing;
- FNT/NitroFS hierarchy reconstruction;
- ARM9 and ARM7 overlay-table parsing;
- file-backed overlay metadata joined through FAT;
- canonical executable-range discovery;
- runtime-address to ROM-offset resolution;
- ROM-offset to structural/runtime classification;
- controlled extraction of ARM9, ARM7, overlays, and selected NitroFS files;
- deterministic full static-analysis bundle generation;
- ROM SHA-256 identity attached to all parsed/extracted results;
- compatibility preservation for the existing `readArm9ExecutableRange()` debugger-facing behavior;
- seven bounded MCP tools for user-facing access;
- fixture-driven automated tests independent of DeSmuME.

## 3. Non-goals

This milestone does not add or change:

- disassembly or instruction decoding;
- function discovery or branch analysis;
- Capstone, radare2, or Ghidra integration;
- pattern scanning or table inference;
- compression or decompression;
- graphics decoding;
- runtime overlay-loaded-state detection;
- watchpoints;
- conditional or advanced breakpoints;
- stepping/continue/pause behavior;
- ROM mutation;
- NitroFS replacement/rebuild;
- patch generation;
- arbitrary byte-range dumping;
- arbitrary output paths.

Dynamic Debugging Patch 1 remains functionally frozen pending the physical Catalina/DeSmuME acceptance test.

## 4. Chosen architecture

Use one canonical `NdsRomMap` service as the authoritative parsed representation of a ROM.

Recommended internal layout:

```text
src/services/nds/
├── header.ts
├── fat.ts
├── fnt.ts
├── overlays.ts
├── rom-map.ts
├── resolver.ts
└── extraction.ts
```

The exact file split may change during implementation if a cleaner separation emerges, but the architectural boundary must remain: parsing, resolution, and extraction are internal services; MCP registration lives separately in `src/tools/nds.ts`.

### 4.1 Canonical model

Conceptually, the model contains:

```text
NdsRomMap
├── identity
├── header
├── arm9
├── arm7
├── filesystem
│   ├── directories
│   └── files
├── overlays
│   ├── arm9[]
│   └── arm7[]
└── executableRanges[]
```

It also exposes narrow resolver operations for runtime addresses and ROM offsets.

All consumers use this model rather than independently re-parsing NDS offsets or duplicating address arithmetic.

## 5. ROM identity and input safety

Every parse begins by validating the requested ROM path through RE-MCP's existing workspace-containment rules.

The parser must verify:

- the path resolves inside `RE_MCP_WORKSPACE_ROOT`;
- the file exists and is readable;
- the file is large enough for the required NDS header fields;
- every referenced offset/size region fits inside the actual file;
- every arithmetic operation used for ranges is safe and does not overflow;
- the ROM SHA-256 is calculated and attached to the canonical model.

The full SHA-256 is the canonical ROM identity. A 16-hex-character prefix may be used only for deterministic generated-directory naming; manifests always store the full hash.

## 6. Header parsing

The header parser must expose at least:

- game title;
- game code;
- maker code;
- unit code;
- device capacity;
- ROM version;
- ARM9 ROM offset;
- ARM9 entry address;
- ARM9 RAM/load address;
- ARM9 size;
- ARM7 ROM offset;
- ARM7 entry address;
- ARM7 RAM/load address;
- ARM7 size;
- FNT offset and size;
- FAT offset and size;
- ARM9 overlay-table offset and size;
- ARM7 overlay-table offset and size;
- banner offset.

For each offset/size region:

```text
offset >= 0
size >= 0
offset + size <= actual ROM size
```

Overflow, truncated regions, or impossible ranges fail explicitly.

ARM9 behavior already expected by `readArm9ExecutableRange()` remains compatible.

## 7. FAT parsing

FAT is authoritative for physical file byte ranges.

Each FAT record provides:

```text
fileId
startOffset
endOffset
size
```

Validation rules:

- FAT byte length must be divisible by 8;
- `startOffset <= endOffset`;
- both endpoints must be valid relative to ROM length;
- size arithmetic must be safe;
- zero-length files may exist but must never cause invalid reads.

FNT names or overlay metadata must not override FAT's physical file range.

## 8. FNT / NitroFS reconstruction

FNT is authoritative for directory/name hierarchy.

The parser reconstructs:

- directory IDs;
- parent relations;
- directory subtable offsets;
- first file IDs;
- file names;
- subdirectory relations;
- full NitroFS paths.

Validation rules:

- referenced directories must exist;
- malformed subtable offsets fail;
- directory cycles fail;
- named file IDs must resolve to FAT entries;
- malformed traversal must never escape the FNT region;
- FAT entries that have no FNT name remain addressable by `fileId`.

Filename handling must preserve original byte-derived identity sufficiently to avoid corrupting traversal. Display normalization must not alter file-ID mapping.

## 9. Overlay parsing

ARM9 and ARM7 overlay tables remain processor-specific.

Each overlay record preserves at least:

```text
processor
overlayId
ramAddress
ramSize
bssSize
staticInitStart
staticInitEnd
fileId
flags / packed metadata
```

The parser joins `fileId` through FAT to add:

```text
romOffset
romSize
```

The implementation must preserve the distinction between:

- file-backed bytes;
- runtime allocation size;
- BSS/runtime-only bytes.

It must never assume `romSize == ramSize`.

Overlay-table byte length must be valid for the DS overlay-record size. Invalid file IDs or table truncation fail explicitly.

## 10. Canonical executable ranges

The canonical map exposes validated executable ranges for:

- ARM9 main;
- ARM7 main;
- ARM9 overlays;
- ARM7 overlays.

The range model is static. It does not claim an overlay is currently loaded.

Overlapping overlay runtime ranges are permitted because different overlays may occupy the same RAM region at different times.

## 11. Runtime-address resolution

### 11.1 Main executable

For ARM9 main:

```text
ramAddress <= address < ramAddress + size
relativeOffset = address - ramAddress
romOffset = romOffsetBase + relativeOffset
```

ARM7 follows the same rule.

### 11.2 Overlay addresses

An overlay is a static candidate when:

```text
ramAddress <= address < ramAddress + ramSize
```

Then:

```text
relativeOffset = address - ramAddress
```

If `relativeOffset` falls inside the file-backed range, return the corresponding ROM offset.

If it falls in runtime-only/BSS space, return an explicit runtime-only result with `romOffset: null`.

### 11.3 Ambiguous overlays

If more than one static overlay candidate contains the address, the resolver returns all candidates and marks the result ambiguous.

It must not choose a candidate by overlay ID, table order, size, or any other heuristic.

Static analysis cannot determine which mutually exclusive overlay is loaded. Runtime loaded-state correlation is deferred until after native debugger acceptance.

## 12. ROM-offset resolution

`nds_resolve_rom_offset` returns a classification set rather than forcing a single category.

A ROM byte may simultaneously belong to:

- a NitroFS/FAT file;
- an ARM9 or ARM7 overlay backing file;
- ARM9 main;
- ARM7 main;
- a structural region such as header/FNT/FAT/overlay table;
- another unmapped ROM region.

Where deterministic runtime mapping exists, the match includes that runtime address.

If the same byte has multiple valid classifications, all are returned.

## 13. Extraction model

Extraction may read only byte ranges already validated by `NdsRomMap`.

The public extraction tool does not accept arbitrary `offset`, `length`, or output path values.

Allowed selectors are recognized components:

- `arm9`;
- `arm7`;
- `arm9-overlay` plus overlay ID;
- `arm7-overlay` plus overlay ID;
- `nitrofs-file` plus file ID or resolved NitroFS path.

The original ROM is never modified.

### 13.1 Generated layout

Deterministic output root:

```text
analysis/generated/nds/<first-16-sha256-hex>/
```

Full analysis bundle layout:

```text
analysis/generated/nds/<sha-prefix>/
├── manifest.json
├── address-map.json
├── filesystem.json
├── overlays.json
├── arm9.bin
├── arm7.bin
└── overlays/
    ├── arm9/
    └── arm7/
```

The full bundle does not automatically extract every NitroFS file. Individual NitroFS files remain opt-in through `nds_extract_component`.

### 13.2 Artifact metadata

Each extracted artifact records at least:

- source ROM path or workspace-relative identity;
- source ROM SHA-256;
- component kind;
- processor where applicable;
- overlay/file ID where applicable;
- ROM offset;
- source byte length;
- RAM/load address where applicable;
- extracted file path;
- extracted artifact SHA-256.

### 13.3 Atomic writes

Individual generated files use temporary siblings followed by close/sync and rename into their final path.

Full analysis bundles are assembled in a temporary generated directory and promoted to the final deterministic directory only after all required files succeed.

A failed operation must not leave a partial directory that appears to be a completed bundle.

## 14. MCP tool surface

The milestone exposes exactly seven primary public tools.

### 14.1 `nds_inspect_rom`

Input:

```json
{ "rom": "relative/path/game.nds" }
```

Returns bounded canonical summary including:

- ROM identity and size;
- game metadata;
- ARM9/ARM7 metadata;
- FNT/FAT regions;
- overlay-table metadata;
- banner offset;
- NitroFS file count;
- ARM9/ARM7 overlay counts;
- validated executable ranges.

### 14.2 `nds_list_files`

Supports bounded listing/filtering such as:

- ROM path;
- prefix;
- limit;
- offset/cursor.

Each result contains file ID, optional path, ROM start/end offsets, and size.

### 14.3 `nds_list_overlays`

Supports processor selection: `arm9`, `arm7`, or `all`.

Returns bounded overlay metadata including RAM range, BSS, file ID, FAT-backed ROM range, and packed/compression-related flags without claiming loaded state.

### 14.4 `nds_resolve_runtime_address`

Input includes ROM path, address, and processor.

Returns:

- main-executable resolution;
- one overlay resolution;
- runtime-only/BSS resolution;
- explicit ambiguity with all candidates;
- or unmapped result.

### 14.5 `nds_resolve_rom_offset`

Returns all structural/file/runtime classifications matching one ROM offset.

### 14.6 `nds_extract_component`

Extracts exactly one recognized component to the server-selected deterministic generated path.

It never accepts an arbitrary output path.

### 14.7 `nds_extract_analysis_bundle`

Produces the deterministic static-analysis package containing executable binaries and structural/address metadata, but not a blanket extraction of every NitroFS asset.

## 15. Tool registration and capabilities

Public NDS tools live in `src/tools/nds.ts` and register through:

```text
registerNdsTools(server, config)
```

`src/index.ts` adds these tools to `server_capabilities`.

They have no `OwnedProcessManager`, GDB, or DeSmuME dependency.

## 16. Output bounding and pagination

All MCP responses respect `config.maxOutputBytes`.

Potentially large list operations provide bounded pagination/filtering rather than dumping an entire ROM structure.

At minimum, applicable list tools support a caller-supplied bounded `limit` and offset/cursor model. Prefix and processor filters are used where appropriate.

If a serialized response would exceed the configured output bound, return a structured `output-bound-exceeded` failure with a corrective action instructing the caller to narrow the request.

## 17. Error model

Static-analysis errors use stable categories suitable for MCP callers.

Required categories include:

```text
invalid-rom
malformed-header
range-out-of-bounds
malformed-fat
malformed-fnt
malformed-overlay-table
unknown-file-id
unknown-overlay-id
ambiguous-runtime-address
runtime-only-bss
output-bound-exceeded
generated-path-failure
```

Where ambiguity or runtime-only/BSS is a normal resolution outcome rather than an exceptional parser failure, the MCP tool may return a successful structured result carrying that status rather than `isError: true`. The implementation plan must make this distinction explicit and test it.

Error responses include:

```text
error
operation
category
correctiveAction
```

No raw parser stack trace is exposed through MCP output.

## 18. Dependency policy

No new runtime dependencies are introduced for this milestone.

Implementation should rely on built-in Node.js facilities such as:

- `Buffer`;
- `node:fs/promises`;
- `node:crypto`;
- `node:path`.

Capstone, radare2, Ghidra, Kaitai, and other external analysis dependencies are deferred to later milestones where their functionality is directly needed.

## 19. Compatibility migration for `nds-arm9.ts`

The existing public `readArm9ExecutableRange(romPath)` function remains available.

Its implementation should become a narrow compatibility adapter over the canonical NDS parser/model while preserving its existing result shape and validation behavior expected by debugger code and tests.

This milestone must not require changes to the externally observable behavior of:

- `desmume_start`;
- breakpoint validation;
- continue;
- single-step;
- pause;
- stop-context capture.

Any refactor touching shared parsing code must keep the existing debugger test suite green.

## 20. Testing strategy

Testing is fixture-driven and independent of DeSmuME.

Recommended test groups:

```text
tests/nds-header.test.ts
tests/nds-fat.test.ts
tests/nds-fnt.test.ts
tests/nds-overlays.test.ts
tests/nds-rom-map.test.ts
tests/nds-resolver.test.ts
tests/nds-extraction.test.ts
tests/nds-tools.test.ts
```

Synthetic NDS fixtures should be generated in tests so offsets and malformed cases are deterministic.

Required coverage includes:

### Header and core ranges

- valid ARM9/ARM7 metadata;
- short/truncated ROM;
- zero or invalid executable size where prohibited;
- overflow;
- region past EOF;
- compatibility behavior for `readArm9ExecutableRange()`.

### FAT

- valid records;
- FAT length not divisible by 8;
- `start > end`;
- record past EOF;
- zero-length file.

### FNT

- root files;
- nested directories;
- unnamed FAT entries;
- invalid directory reference;
- cycle;
- malformed subtable offset;
- file ID outside FAT;
- unusual filename bytes without traversal corruption.

### Overlays

- ARM9 overlays;
- ARM7 overlays;
- valid FAT join;
- invalid file ID;
- malformed/truncated table;
- overlapping runtime ranges;
- file-backed size differing from runtime size/BSS;
- packed/compression metadata preserved without unsafe assumptions.

### Resolver

- ARM9 main runtime to ROM;
- ARM7 main runtime to ROM;
- single overlay resolution;
- overlay BSS/runtime-only resolution;
- overlapping overlay ambiguity;
- unmapped runtime address;
- ROM offset with one classification;
- ROM offset with multiple classifications;
- structural-region classification.

### Extraction

- ARM9 extraction;
- ARM7 extraction;
- overlay extraction;
- NitroFS file extraction by ID;
- NitroFS file extraction by valid resolved path;
- unknown IDs rejected;
- arbitrary output path impossible at MCP schema level;
- deterministic generated location;
- source/artifact SHA-256 recorded;
- atomic output behavior;
- bundle failure does not leave a completed-looking partial bundle;
- original ROM remains byte-for-byte unchanged after extraction.

### MCP surface

- exactly the seven planned NDS tools registered;
- schema bounds for addresses, limits, processor selectors, overlay IDs, and file selectors;
- workspace containment enforced;
- structured errors;
- output-bound handling;
- pagination/filter behavior;
- `server_capabilities` includes the seven tools.

## 21. Security guarantees

This milestone preserves RE-MCP's safety-first boundary:

- no arbitrary shell;
- no arbitrary read path outside workspace;
- no arbitrary output path;
- no raw offset/length extraction primitive;
- no writes to the source ROM;
- no ROM replacement or rebuild;
- no debugger/GDB expansion;
- no attachment to external processes;
- all generated files remain under controlled `analysis/generated/nds/...` paths;
- all read ranges originate from validated canonical ROM structures;
- responses remain bounded by server configuration.

## 22. Implementation sequencing constraint

Implementation should proceed test-first in small units:

1. canonical header/identity model;
2. FAT;
3. FNT;
4. overlays;
5. `NdsRomMap` composition;
6. runtime and ROM-offset resolvers;
7. controlled extraction;
8. `readArm9ExecutableRange()` compatibility migration;
9. MCP tools and capability registration;
10. documentation and final regression verification.

The detailed implementation plan may split this into multiple PRs if that reduces risk. The design does not require all work to land in one oversized PR.

## 23. Acceptance criteria

The milestone is complete when:

- all seven NDS tools are implemented and documented;
- all required parser/resolver/extraction tests pass;
- type-check, full tests, and build pass;
- existing debugger tests remain green;
- no new runtime dependency is required;
- the source ROM is provably unchanged by extraction tests;
- generated output is deterministic, bounded, and workspace-contained;
- ambiguous overlay addresses are never guessed;
- runtime-only BSS addresses never receive fabricated ROM offsets;
- `readArm9ExecutableRange()` preserves debugger-facing compatibility;
- Dynamic Debugging Patch 1 behavior has not been extended before native Catalina acceptance.

## 24. Follow-on milestones

This foundation is intentionally designed to support the following order:

```text
NDS Static Analysis Foundation
          ↓
ARM/Thumb Static Disassembly
          ↓
Pattern + Reference Discovery
          ↓
Ghidra Integration
          ↓
Static ↔ Runtime Correlation
```

After the physical Catalina debugger acceptance passes, future runtime tools may consume this same canonical NDS mapping to correlate breakpoint PCs and loaded overlays with static ROM structures.
