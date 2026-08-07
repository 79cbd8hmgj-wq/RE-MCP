# NDS Static Analysis Foundation — Design Specification

Date: 2026-08-07
Status: Approved design, pending implementation plan
Branch: `design/nds-static-analysis-foundation`

## 1. Purpose

Build a native-independent Nintendo DS static-analysis foundation for RE-MCP without extending the unverified live DeSmuME debugger behavior before the physical Catalina acceptance run.

The milestone establishes one canonical, validated NDS ROM model that future disassembly, Ghidra, pattern-search, table-inference, and runtime-correlation tooling can reuse.

The source `.nds` file remains immutable. The only writes allowed are deterministic derived artifacts under a controlled `analysis/generated/nds/...` tree.

## 2. Goals

The milestone must provide:

- strict Nintendo DS header parsing;
- ARM9 and ARM7 executable metadata;
- FAT parsing;
- FNT/NitroFS hierarchy reconstruction;
- ARM9 and ARM7 overlay-table parsing;
- overlay file metadata joined through FAT;
- canonical executable-range discovery;
- runtime-address resolution;
- ROM-offset structural/runtime classification;
- controlled extraction of ARM9, ARM7, overlays, and selected NitroFS files;
- deterministic full static-analysis bundle generation;
- ROM SHA-256 identity attached to parsed and extracted results;
- compatibility preservation for existing `readArm9ExecutableRange()` behavior;
- seven bounded MCP tools;
- fixture-driven tests independent of DeSmuME.

## 3. Non-goals

This milestone does not add or change:

- disassembly or instruction decoding;
- function discovery or branch analysis;
- Capstone, radare2, Ghidra, or Kaitai integration;
- pattern scanning or table inference;
- compression/decompression support;
- graphics decoding;
- runtime overlay-loaded-state detection;
- watchpoints;
- conditional/advanced breakpoints;
- stepping, continue, pause, or stop-context behavior;
- ROM mutation;
- NitroFS replacement or rebuild;
- patch generation;
- arbitrary byte-range dumping;
- arbitrary output paths.

Dynamic Debugging Patch 1 remains functionally frozen pending the physical Catalina/DeSmuME acceptance run.

## 4. Architecture

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

Exact file boundaries may change during implementation, but the architectural boundary is fixed: parsing, resolution, and extraction are internal services; MCP registration lives in `src/tools/nds.ts`.

Conceptually:

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

All consumers use this model rather than independently parsing offsets or duplicating address arithmetic.

## 5. ROM identity and input safety

Every parse must:

- resolve the requested ROM inside `RE_MCP_WORKSPACE_ROOT` using existing containment helpers;
- require a readable regular file;
- require enough bytes for all NDS header fields consumed by this milestone;
- validate every referenced region against actual ROM length;
- reject unsafe integer/range arithmetic;
- calculate a full SHA-256 identity.

The full SHA-256 is canonical. A first-16-hex-character prefix may be used only for generated-directory naming; manifests store the full hash.

## 6. Header parsing

Expose at least:

- game title;
- game code;
- maker code;
- unit code;
- device capacity;
- ROM version;
- ARM9 ROM offset, entry address, RAM/load address, and size;
- ARM7 ROM offset, entry address, RAM/load address, and size;
- FNT offset/size;
- FAT offset/size;
- ARM9 overlay-table offset/size;
- ARM7 overlay-table offset/size;
- banner offset.

For every offset/size region:

```text
offset >= 0
size >= 0
offset + size <= actual ROM size
```

Overflow, truncation, or impossible ranges fail explicitly.

## 7. FAT parsing

FAT is authoritative for physical file ranges.

Each record exposes:

```text
fileId
startOffset
endOffset
size
```

Validation:

- FAT length divisible by 8;
- `startOffset <= endOffset`;
- both offsets within ROM bounds;
- safe size arithmetic;
- zero-length files may exist but never cause invalid reads.

FNT or overlay metadata never override FAT's physical range.

## 8. FNT / NitroFS reconstruction

FNT is authoritative for names and hierarchy.

Reconstruct:

- directory IDs;
- parent relations;
- subtable offsets;
- first file IDs;
- file names;
- subdirectory relations;
- full NitroFS paths.

Validation:

- directory references must resolve;
- malformed subtable offsets fail;
- directory cycles fail;
- named file IDs must resolve through FAT;
- traversal may not leave the FNT region;
- unnamed FAT entries remain addressable by `fileId`.

Display normalization must never alter file-ID mapping or traversal semantics.

## 9. Overlay parsing

ARM9 and ARM7 overlay tables remain processor-specific. Each table record is 32 bytes / eight little-endian `u32` values.

Preserve:

```text
processor
overlayId
ramAddress
ramSize
bssSize
staticInitStart
staticInitEnd
fileId
compressedSize
flags
compressed
```

The final packed field at record offset `0x1C` is interpreted as:

```text
compressedSize = packed & 0x00FFFFFF
flags          = packed >>> 24
compressed     = (flags & 1) != 0
```

The parser joins `fileId` through FAT to add physical `romOffset` and `romSize`.

Important distinctions:

- `ramSize` describes the initialized overlay image size in RAM;
- `bssSize` is additional zero-initialized runtime memory following the initialized image;
- `compressedSize` and FAT-backed `romSize` describe stored representation metadata;
- a compressed overlay does not have a byte-for-byte mapping between decompressed runtime bytes and compressed ROM bytes.

The parser must never assume `romSize == ramSize`, and must never fabricate a direct runtime-to-ROM byte mapping for compressed overlays.

Overlay-table length must be divisible by 32. Invalid file IDs, truncated records, unsafe ranges, or inconsistent packed metadata fail explicitly where correctness cannot be established.

## 10. Canonical executable/runtime ranges

Expose static candidate ranges for:

- ARM9 main;
- ARM7 main;
- ARM9 overlays;
- ARM7 overlays.

For an overlay, distinguish:

```text
initialized range: [ramAddress, ramAddress + ramSize)
BSS range:         [ramAddress + ramSize, ramAddress + ramSize + bssSize)
```

All additions must be overflow-checked.

The map does not claim an overlay is currently loaded. Overlapping overlay ranges are valid static candidates.

## 11. Runtime-address resolution

### 11.1 Main executable

For ARM9 main:

```text
ramAddress <= address < ramAddress + size
relativeOffset = address - ramAddress
romOffset = romOffsetBase + relativeOffset
```

ARM7 follows the same rule.

### 11.2 Uncompressed overlay initialized bytes

If exactly one uncompressed overlay candidate contains the address within its initialized range:

```text
relativeOffset = address - ramAddress
```

A direct ROM mapping is returned only when that relative offset is also inside the validated FAT-backed file range.

### 11.3 Compressed overlay initialized bytes

If a compressed overlay candidate contains the address, identify the overlay and relative runtime offset, but return no exact ROM byte offset:

```text
romOffset: null
romMapping: "compressed"
```

The result may include the overlay backing file's `romOffset`, `romSize`, and `fileId` as container metadata, but must clearly distinguish those from an exact runtime-byte mapping.

Exact decompressed-runtime ↔ compressed-ROM byte correlation is deferred to the future compression/decompression milestone.

### 11.4 Overlay BSS

If the address falls in:

```text
ramAddress + ramSize <= address < ramAddress + ramSize + bssSize
```

return an explicit runtime-only/BSS candidate with `romOffset: null`.

### 11.5 Ambiguous overlays

If multiple static overlay candidates contain the address, return all candidates and mark the result ambiguous.

Never choose by overlay ID, table order, size, compression state, or heuristic.

Static analysis cannot determine loaded state.

## 12. ROM-offset resolution

`nds_resolve_rom_offset` returns a classification set rather than forcing one category.

A ROM byte may belong to multiple structures simultaneously, including:

- FAT/NitroFS file;
- ARM9/ARM7 overlay backing file;
- ARM9 main;
- ARM7 main;
- header/FNT/FAT/overlay-table structural regions;
- an otherwise unmapped region.

For uncompressed main/overlay bytes with deterministic mapping, include runtime address.

For bytes belonging to a compressed overlay file, report the overlay/file classification but do not invent a runtime address for that compressed byte position.

## 13. Extraction model

Extraction reads only ranges validated by `NdsRomMap`.

Public extraction does not accept arbitrary `offset`, `length`, or output path values.

Allowed selectors:

- `arm9`;
- `arm7`;
- `arm9-overlay` plus overlay ID;
- `arm7-overlay` plus overlay ID;
- `nitrofs-file` plus file ID or resolved NitroFS path.

Overlay extraction in this milestone extracts the exact stored FAT-backed bytes. If the overlay is compressed, the extracted artifact remains compressed; decompression is explicitly deferred.

The source ROM is never modified.

### 13.1 Generated layout

```text
analysis/generated/nds/<first-16-sha256-hex>/
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

The analysis bundle does not dump every NitroFS file. Individual assets remain opt-in.

### 13.2 Artifact metadata

Record at least:

- source ROM workspace-relative identity;
- source ROM SHA-256;
- component kind;
- processor where applicable;
- overlay/file ID where applicable;
- physical ROM offset;
- source byte length;
- RAM/load address where applicable;
- compression state and compressed-size metadata where applicable;
- output path;
- artifact SHA-256.

### 13.3 Atomic writes

Individual files use temporary siblings, close/sync, then rename.

Full bundles are assembled in a temporary generated directory and promoted only after all required artifacts succeed.

Failure must not leave a partial directory that appears complete.

## 14. MCP tool surface

Expose exactly seven primary tools.

### `nds_inspect_rom`

Returns bounded ROM identity, game metadata, ARM9/ARM7 metadata, filesystem/table regions, overlay counts, and validated ranges.

### `nds_list_files`

Supports ROM, prefix, bounded `limit`, and pagination offset/cursor. Results include file ID, optional path, ROM range, and size.

### `nds_list_overlays`

Supports processor `arm9`, `arm7`, or `all`. Returns bounded overlay metadata including initialized range, BSS range, file ID, physical backing range, `compressedSize`, flags, and compression state without claiming loaded state.

### `nds_resolve_runtime_address`

Input: ROM, 32-bit address, processor.

Returns main resolution, one overlay candidate, compressed/no-direct-ROM mapping, BSS/runtime-only result, explicit ambiguity, or unmapped result.

### `nds_resolve_rom_offset`

Returns all structural/file/runtime classifications for one validated ROM offset.

### `nds_extract_component`

Extracts exactly one recognized component to a server-selected deterministic generated path. No arbitrary output path.

### `nds_extract_analysis_bundle`

Produces executable binaries, stored overlay binaries, and structural/address metadata without blanket NitroFS extraction.

## 15. Tool registration

Public NDS tools live in `src/tools/nds.ts` and register through:

```text
registerNdsTools(server, config)
```

`src/index.ts` adds all seven names to `server_capabilities`.

These tools have no `OwnedProcessManager`, GDB, or DeSmuME dependency.

## 16. Output bounds and pagination

All MCP responses respect `config.maxOutputBytes`.

Potentially large operations use bounded pagination/filtering. Applicable list tools support a bounded caller `limit` plus offset/cursor; prefix and processor filters apply where relevant.

If serialization would exceed the configured bound, return `output-bound-exceeded` with a corrective action to narrow the request.

## 17. Error/result model

Parser/operation error categories include:

```text
invalid-rom
malformed-header
range-out-of-bounds
malformed-fat
malformed-fnt
malformed-overlay-table
unknown-file-id
unknown-overlay-id
output-bound-exceeded
generated-path-failure
```

Resolution statuses such as these are normal structured outcomes rather than parser failures:

```text
unmapped
ambiguous-runtime-address
runtime-only-bss
compressed-no-direct-rom-mapping
```

True error responses include:

```text
error
operation
category
correctiveAction
```

No raw parser stack traces are exposed through MCP output.

## 18. Dependency policy

No new runtime dependencies.

Use built-in Node.js facilities such as `Buffer`, `node:fs/promises`, `node:crypto`, and `node:path`.

External analysis/decompression dependencies remain deferred.

## 19. Compatibility migration for `nds-arm9.ts`

Keep public:

```text
readArm9ExecutableRange(romPath)
```

Its implementation becomes a narrow adapter over the canonical parser/model while preserving existing result shape and debugger-facing validation behavior.

This milestone must not alter externally observable behavior of:

- `desmume_start`;
- breakpoint validation;
- continue;
- single-step;
- pause;
- stop-context capture.

Existing debugger tests must remain green.

## 20. Testing strategy

Testing is fixture-driven and independent of DeSmuME.

Recommended groups:

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

Synthetic fixtures control all offsets and malformed cases.

Required coverage:

### Header/core

- valid ARM9/ARM7 metadata;
- truncated ROM/header;
- invalid sizes;
- overflow;
- region past EOF;
- `readArm9ExecutableRange()` compatibility.

### FAT

- valid records;
- non-multiple-of-8 size;
- `start > end`;
- range past EOF;
- zero-length file.

### FNT

- root and nested files;
- unnamed FAT entries;
- invalid directory reference;
- cycle;
- malformed subtable offset;
- file ID outside FAT;
- unusual filename bytes without traversal corruption.

### Overlays

- ARM9 and ARM7 records;
- exact 32-byte record validation;
- packed `compressedSize`/flags decode;
- compression flag decode;
- valid FAT join;
- invalid file ID;
- truncated table;
- overlapping runtime ranges;
- initialized range plus BSS range;
- compressed overlay whose physical size differs from runtime size;
- flags preserved without unsupported interpretation.

### Resolver

- ARM9/ARM7 main mapping;
- uncompressed overlay direct mapping;
- compressed overlay returns no exact ROM byte mapping;
- overlay BSS/runtime-only result;
- overlapping-overlay ambiguity;
- unmapped runtime address;
- ROM offset with one classification;
- ROM offset with multiple classifications;
- compressed overlay ROM bytes do not receive fabricated runtime addresses;
- structural-region classification.

### Extraction

- ARM9/ARM7 extraction;
- uncompressed overlay extraction;
- compressed overlay extraction remains stored/compressed bytes;
- NitroFS extraction by ID and path;
- unknown IDs rejected;
- arbitrary output path impossible through schema;
- deterministic generated location;
- source/artifact hashes recorded;
- atomic file/bundle behavior;
- failed bundle does not appear complete;
- source ROM byte-for-byte unchanged.

### MCP surface

- exactly seven NDS tools registered;
- schema bounds;
- workspace containment;
- structured errors/statuses;
- output bound handling;
- pagination/filter behavior;
- `server_capabilities` updated.

## 21. Security guarantees

Preserve:

- no arbitrary shell;
- no read outside workspace;
- no arbitrary output path;
- no raw offset/length extraction primitive;
- no source-ROM writes;
- no ROM replacement/rebuild;
- no debugger/GDB expansion;
- no process attachment;
- generated files only below controlled `analysis/generated/nds/...`;
- all read ranges originate from validated ROM structures;
- bounded MCP output.

## 22. Implementation sequence

Test-first sequence:

1. header/identity model;
2. FAT;
3. FNT;
4. overlays, including packed compression metadata;
5. `NdsRomMap` composition;
6. runtime and ROM-offset resolvers;
7. controlled extraction;
8. `readArm9ExecutableRange()` compatibility migration;
9. MCP tools/capability registration;
10. documentation and full regression verification.

The implementation plan may split this across multiple PRs. One oversized PR is not required.

## 23. Acceptance criteria

Complete when:

- all seven tools are implemented/documented;
- parser/resolver/extraction tests pass;
- type-check, full tests, and build pass;
- existing debugger tests remain green;
- no new runtime dependency is introduced;
- source ROM remains unchanged in extraction tests;
- output is deterministic, bounded, and workspace-contained;
- overlapping overlays are never guessed;
- BSS addresses never receive ROM offsets;
- compressed overlay runtime bytes never receive fabricated direct ROM offsets;
- compressed overlay file bytes never receive fabricated runtime addresses;
- `readArm9ExecutableRange()` remains compatible;
- Dynamic Debugging Patch 1 behavior is not extended before native Catalina acceptance.

## 24. Follow-on milestones

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

After physical Catalina debugger acceptance, runtime tooling may consume this canonical map to correlate breakpoint PCs and loaded overlays with static ROM structures.
