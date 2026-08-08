# Controlled NDS Compressed Overlay Support Design

Date: 2026-08-08  
Status: approved design, pending written-spec review  
Base: `main` after PR #26 Controlled Ghidra Inspection

## Goal

Add safe Nintendo DS compressed-overlay support so RE-MCP can analyze code that is currently unavailable to native static analysis and Ghidra because the overlay exists in ROM only in compressed form.

The source ROM remains immutable. Compressed storage bytes and decompressed runtime bytes are separate representations with separate provenance. A decompressed runtime byte must never be assigned a fabricated physical ROM offset.

## Recommended architecture

Use a dependency-free TypeScript Nintendo DS BLZ/code-compression decoder beneath a canonical derived-overlay runtime-image service.

The derived runtime image then becomes an exact byte source for the existing NDS analysis stack:

```text
canonical compressed overlay file
        |
        v
bounded NDS BLZ decoder
        |
        v
provenance-tracked derived runtime image
        |
        +-- disassembly / CFG
        +-- references / xrefs
        +-- proven function discovery
        +-- generated analysis bundle
        +-- controlled Ghidra bootstrap/import
```

This is preferred over an external Python/ndspy runtime dependency or extraction-only decompression because it keeps RE-MCP self-contained and lets all existing analysis layers consume the same exact decoded bytes.

## Compression boundary

Only an overlay already marked compressed by the validated NDS overlay/FAT model may enter the decoder path.

The public surface does not accept:

- arbitrary files;
- arbitrary ROM offsets;
- caller-supplied compressed buffers;
- caller-supplied expected decompressed sizes;
- generic decompression algorithms or format selectors.

The stored input range comes from canonical FAT/overlay metadata. The expected initialized runtime size comes from canonical overlay `ramSize`.

## Bounded BLZ decoder

Create a small internal decoder that validates the Nintendo DS backward-LZ/code-compression footer, encoded-region geometry, token stream, and every back-reference before returning bytes.

The decoder rejects:

- truncated or impossible footer/header geometry;
- encoded regions outside the canonical overlay file;
- truncated control/token data;
- back-references before available decoded history;
- arithmetic overflow;
- writes past the expected output size;
- output shorter or longer than canonical `ramSize`;
- inputs/outputs beyond hard limits.

Initial internal limits:

- maximum stored compressed overlay: 16 MiB;
- maximum decoded overlay runtime image: 16 MiB;
- maximum aggregate derived-overlay bytes in one top-level analysis operation: 64 MiB.

BSS is not part of the decoded initialized runtime image.

## Derived runtime-image model

The runtime-image service owns decompression and provenance.

A decoded overlay record contains at least:

- processor;
- overlay ID;
- source ROM SHA-256;
- source file ID;
- stored ROM offset and stored size;
- stored SHA-256;
- canonical runtime address and runtime size;
- BSS size;
- representation `derived-blz`;
- decoded bytes;
- decoded/runtime SHA-256.

The service:

1. requires a canonical compressed overlay;
2. validates source-ROM identity before reading;
3. reads only the overlay's FAT-backed stored range;
4. hashes the stored bytes;
5. decodes against canonical `ramSize`;
6. hashes the runtime image;
7. validates source-ROM identity again before returning.

No persistent decoded cache is required initially. One top-level analysis operation may reuse an operation-scoped decoded-image cache so the same overlay is not decoded or charged against the aggregate budget repeatedly.

## Address semantics

Compressed-overlay support must not make decompressed bytes appear physically ROM-backed.

For an initialized byte in a decoded overlay:

- runtime address is canonical;
- processor/overlay ownership is canonical;
- `runtimeImageOffset = runtimeAddress - overlay.ramAddress` is exact;
- direct `romOffset` remains `null`;
- the stored compressed backing range is reported separately as provenance.

BSS remains runtime-only and has neither stored initialized bytes nor decoded initialized bytes.

`nds_resolve_rom_offset` continues to describe physical compressed storage. It must not assign a decompressed runtime address to an arbitrary byte inside the compressed file.

## Static-analysis integration

Generalize the existing exact code-byte source abstraction from file-backed-only to:

```text
rom-file-backed
or
derived-overlay
```

Both variants retain the same canonical processor/component/runtime identity and proof rules. Only the byte provider differs.

The following existing tools/services may then consume decoded compressed-overlay code:

- `nds_disassemble_range`
- `nds_analyze_control_flow`
- `nds_list_references`
- `nds_find_xrefs`
- `nds_discover_functions`
- `nds_analyze_function`

Decompression does not change ambiguity rules. Overlapping overlays remain ambiguous unless an existing canonical selector chooses one overlay. An explicit overlay ID performs static selection only; it does not claim that overlay is loaded at runtime.

Function proof is unchanged. A decoded overlay function entry is proven only by existing deterministic proof sources such as exact direct-call evidence. Decompression, alignment, a recognizable prologue, Ghidra output, or caller overlay selection is not function-entry proof.

## Pattern-search behavior

`nds_search_pattern` retains physical-ROM semantics. It searches the stored ROM representation.

A pattern match inside compressed storage is a compressed-storage match, not a decoded-runtime match. This milestone does not silently add decompressed-runtime pattern searching.

## Generated artifacts

When a derived runtime image needs persistence for an analysis bundle or Ghidra bridge, write it only under the deterministic generated-analysis tree, for example:

```text
analysis/generated/nds/<sha-prefix>/derived/overlays/arm9/overlay-0007.runtime.bin
```

Generated metadata records both stored and decoded provenance, including hashes and sizes.

Writes use the existing atomic generated-artifact discipline. Source-ROM identity is checked before final promotion. Existing exact compressed component extraction remains unchanged.

No caller-selected output path is introduced.

## Controlled Ghidra integration

Ghidra must consume the same Node-produced derived runtime image. Java-side Ghidra scripts do not implement decompression.

For a compressed overlay that decodes successfully:

- generate a deterministic decoded runtime artifact;
- preserve stored compressed provenance in the bridge manifest;
- import the decoded artifact into the existing deterministic true overlay address space;
- keep BSS as a separate uninitialized overlay block;
- record both stored and runtime hashes.

Uncompressed overlays keep the existing direct-import behavior.

Existing SHA-scoped projects may add a formerly absent RE-MCP-owned compressed-overlay space only if ROM identity and generated provenance match and no conflicting owned/analyst state exists. Conflicts fail closed with project-state mismatch; RE-MCP does not replace the analyst project.

Controlled Ghidra Inspection remains read-only with auto-analysis disabled and simply consumes the reconciled project after explicit bootstrap.

## Error model

Add narrow categories where necessary:

```text
malformed-blz
blz-output-size-mismatch
blz-output-limit
compressed-overlay-runtime-unavailable
```

Existing invalid-ROM, ambiguity, generated-path, output-bound, Ghidra-lock/state, and project-mismatch errors remain authoritative for their existing domains.

No failure path falls back to interpreting compressed storage bytes as ARM/Thumb instructions.

## Testing

### Decoder tests

Use committed independent golden vectors for:

- literal-only data;
- backward references;
- mixed control groups;
- valid footer/header variants;
- truncated footer/token data;
- impossible encoded-region geometry;
- invalid back-references;
- output underflow/overflow;
- expected-size mismatch;
- hard input/output limit rejection.

Production correctness must not depend on importing ndspy or another decoder.

### Runtime-image tests

Cover:

- ARM9 and ARM7 compressed overlays;
- exact stored/runtime hashes;
- source mutation before/during/after decode;
- unknown/wrong overlay IDs;
- uncompressed-overlay rejection by the compressed-only service;
- BSS exclusion;
- operation-scoped decode reuse and aggregate limit.

### Static-analysis regressions

Synthetic compressed-overlay fixtures must prove:

- ARM and Thumb disassembly from decoded bytes;
- CFG traversal;
- reference extraction;
- reverse xrefs;
- deterministic direct-call function-entry proof;
- overlapping compressed overlays remain ambiguous;
- explicit overlay selection works without loaded-state claims;
- runtime resolution keeps `romOffset: null` for decoded bytes;
- ROM-offset resolution continues to describe compressed storage only.

### Ghidra acceptance

Extend the manual Ghidra 12.1.2 / JDK 21 acceptance fixture with at least one compressed ARM9 overlay containing known decoded code.

Verify:

- decoded bytes are imported into the deterministic true overlay space;
- compressed storage bytes are not used as executable block contents;
- BSS remains uninitialized;
- provenance hashes match;
- overlapping overlay identities remain distinct;
- read-only Ghidra inspection can inspect the decoded overlay;
- rerun preserves analyst state;
- hidden Ghidra script errors/exceptions are absent.

Normal CI/package remains Ghidra-free.

## Delivery sequence

Implement in three independently verified slices:

1. native bounded BLZ decoder + canonical runtime-image provenance;
2. static-analysis consumption + generated bundle/package support;
3. controlled Ghidra bridge/import + real-Ghidra acceptance.

Each slice must pass its own CI/package gates before the next layer is added.

## Explicit non-goals

This milestone does not add:

- BLZ recompression;
- overlay replacement;
- ROM rebuilding;
- patch generation;
- arbitrary/generic decompression tools;
- arbitrary binary input;
- caller-selected decoder limits or output paths;
- compressed ARM9-main support;
- LZ10/LZ11/RLE/Huffman asset decompression;
- decoded-runtime pattern search;
- runtime loaded-overlay detection;
- Ghidra-to-RE-MCP evidence promotion;
- debugger/watchpoint/runtime-tracing behavior.

## Acceptance criteria

Complete when:

1. canonical compressed ARM9/ARM7 overlays decode through a bounded dependency-free NDS BLZ decoder;
2. decoded length exactly matches canonical initialized runtime size;
3. compressed storage and decoded runtime bytes retain separate hashes/provenance;
4. runtime resolution never fabricates a direct ROM offset for decoded bytes;
5. native disassembly, CFG, references/xrefs, and proven-function tools consume decoded overlay code without changing proof or ambiguity rules;
6. physical-ROM pattern-search semantics remain unchanged;
7. generated decoded artifacts stay under the deterministic analysis tree and source ROM remains unchanged;
8. Ghidra bootstrap safely imports validated decoded overlay spaces without overwriting analyst state;
9. read-only Ghidra inspection consumes those spaces after bootstrap;
10. malformed streams, expansion limits, source mutation, ambiguity, and ownership conflicts fail closed;
11. normal CI, full tests, build, and package smoke pass without Ghidra;
12. real Ghidra 12.1.2/JDK 21 acceptance passes;
13. no DeSmuME/GDB production behavior changes.
