# NDS Rebuild Core 2 Design

**Date:** 2026-08-09  
**Status:** Proposed design after approved milestone direction; awaiting written-spec review  
**Milestone:** Agentic ROM Modification Pipeline — NDS Rebuild Core 2  
**Scope:** Generic, native-independent Nintendo DS variable-size rebuild and compressed-overlay mutation foundation

## 1. Goal

Extend the merged Controlled NDS Mutation Core so RE-MCP can safely produce structurally valid Nintendo DS ROMs when approved changes no longer fit inside the source ROM's existing fixed physical layout.

The milestone must add three capabilities that the current same-size mutation surface deliberately excludes:

1. variable-size replacement of existing non-overlay NitroFS files;
2. append-only creation of new NitroFS extension files while preserving every existing file ID and path;
3. decoded compressed-overlay replacement with deterministic BLZ recompression and exact decode-back verification.

The source ROM remains immutable. The public mutation surface remains manifest-driven. No caller receives a generic offset writer, arbitrary layout controls, or arbitrary output path.

This milestone is a container/rebuild foundation, not a semantic patch compiler. It sits underneath the existing RE stack and underneath later executable-injection/orchestration work:

```text
patch requirement
    ↓
missing implementation fact?
    ├─ yes → static analysis / Ghidra / runtime evidence
    └─ no
         ↓
proven patch artifacts + exact guards
         ↓
manifest v1/v2 compilation
         ↓
NDS Rebuild Core 2
         ↓
reparse + structural proof + payload proof
         ↓
verified complete .nds
```

A requested behavior still never authorizes RE-MCP to invent implementation locations, runtime geometry, hook sites, save semantics, or data formats.

## 2. Why this milestone is required

The merged Milestone 1 mutation core can safely perform same-size guarded byte edits and exact-size whole-component replacements. That is not enough for the currently planned Bakugan patch families.

The planned systems require, in different combinations:

- new or expanded authored data blocks;
- larger text/data assets;
- new persistent data carriers;
- runtime modules whose stored compressed representation may change size;
- editing decoded compressed overlay code and then returning it to a valid stored representation;
- deterministic rebuilt ROMs whose FAT/FNT relationships no longer match the source byte-for-byte.

The existing RE stack already provides canonical NDS parsing, FAT/FNT reconstruction, overlay metadata, compressed-overlay decoding, ARM/Thumb analysis, Ghidra inspection, and runtime correlation. Core 2 should reuse that knowledge rather than create a separate ROM builder with weaker semantics.

## 3. Design alternatives considered

### 3.1 Full canonical repack of the whole ROM

A conventional builder could deserialize every known structure and rewrite all components into a new compact layout.

**Rejected for this milestone.** The current canonical parser intentionally models the structures required for analysis, not every potentially meaningful commercial-ROM byte. Repacking all source regions would create unnecessary risk around unknown/reserved regions, banners, padding, vendor-specific layout choices, or metadata not yet owned by RE-MCP.

### 3.2 In-place gap allocator

A builder could search source padding/gaps and place enlarged payloads into apparently unused regions.

**Rejected for this milestone.** A byte range that looks unused is not proven free merely because the current parser does not reference it. Treating gaps as allocatable without explicit evidence would violate RE-MCP's fail-closed model.

### 3.3 Append-only rebuild tail — selected

Core 2 preserves the complete source ROM byte-for-byte as the initial output prefix. Variable-size replacement payloads, new files, and rebuilt metadata tables are appended after the source image. Only the exact header fields necessary to redirect canonical metadata are changed in the copied output prefix.

Benefits:

- unknown source regions remain physically untouched;
- existing file IDs remain stable;
- unchanged FAT payloads remain at their source offsets;
- old metadata tables may remain as inert source bytes while the header points to rebuilt copies;
- no source-gap ownership claim is required;
- diff attribution is straightforward;
- the layout algorithm is deterministic and versionable.

The cost is potentially larger output ROMs. That trade-off is accepted for Core 2 because safety and determinism are more important than compactness. A future compaction/repack milestone may optimize size only after RE-MCP owns enough of the format to prove it safely.

## 4. Non-negotiable safety invariants

Every successful Core 2 build must satisfy all of the following:

1. The source ROM is never opened for writing.
2. The full source SHA-256 is pinned by the manifest and checked before planning, before materialization, and after verification.
3. Every existing target is selected through canonical NDS ownership, never a caller-supplied physical ROM offset.
4. Every replacement artifact is workspace-contained, hash-pinned, and revalidated before use.
5. Existing file IDs never change.
6. Existing NitroFS paths never change.
7. Existing directory IDs never change.
8. New file IDs are append-only after the source FAT count.
9. New directory IDs are append-only after the source FNT directory count.
10. Core 2 does not infer or alter ARM9/ARM7 runtime load addresses, overlay runtime addresses, initialized runtime sizes, BSS sizes, or static-initializer ranges.
11. Decoded compressed-overlay replacement must preserve the canonical initialized runtime byte count exactly.
12. No source padding/gap is treated as free space.
13. No build is published unless the rebuilt ROM reparses through the canonical model and every structural/payload invariant passes.
14. Every byte changed inside the original source-length prefix is attributable to either an explicitly approved fixed-layout mutation or an exact planned header rewrite.
15. Every byte after the source-length prefix is attributable to a planned rebuild segment or deterministic padding.
16. Existing deterministic build directories are never silently repaired or overwritten.

## 5. Backward-compatible public surface

Core 2 does not add a second public mutation API.

The public MCP tools remain:

```text
nds_mutation_validate
nds_mutation_build
nds_mutation_verify
```

Their MCP input remains only:

```text
rom
manifest
```

The manifest format becomes versioned:

- `formatVersion: 1` retains the exact merged Milestone 1 semantics and build identity;
- `formatVersion: 2` enables the Core 2 rebuild operations and rebuild contract described here.

A v1 manifest must continue to produce the exact same normalized meaning, build ID, output layout, and verification behavior as before this milestone.

No automatic conversion of v1 manifests to v2 is required.

## 6. Manifest v2

The top-level identity remains:

```json
{
  "format": "re-mcp-nds-mutation",
  "formatVersion": 2,
  "source": {
    "sha256": "64-lowercase-hex"
  },
  "output": {
    "filename": "modded.nds"
  },
  "operations": []
}
```

The strict parsing rules from v1 remain:

- unknown keys rejected;
- unsafe output filenames rejected;
- zero operations rejected;
- uppercase/noncanonical hashes rejected;
- arbitrary offsets rejected;
- inline binary payloads rejected;
- paths remain workspace-relative and containment-checked.

V2 retains both v1 operation types:

```text
replace-bytes
replace-component
```

and adds exactly three Core 2 operation types:

```text
replace-nitrofs-file
add-nitrofs-file
replace-decoded-overlay
```

No delete, rename, arbitrary-table-write, raw-FAT-edit, raw-FNT-edit, or arbitrary-header-write operation is exposed.

## 7. Operation: variable-size NitroFS replacement

Conceptual form:

```json
{
  "type": "replace-nitrofs-file",
  "target": {
    "fileId": 142
  },
  "expectedOriginalSha256": "...",
  "replacement": {
    "artifact": "analysis/generated/patches/file-142.bin",
    "sha256": "..."
  }
}
```

The target may use exactly one of:

- exact existing `fileId`; or
- exact existing canonical NitroFS `path`.

Rules:

- the selected FAT file must already exist;
- an overlay-backed FAT file is rejected; overlay ownership cannot be bypassed through the generic NitroFS operation;
- exact original stored-file SHA-256 is mandatory;
- replacement artifact SHA-256 is mandatory;
- replacement may be smaller, equal, or larger than the source file;
- replacement must be non-empty unless a future explicit zero-length policy is approved;
- no-op replacement hash is rejected;
- file ID and path remain unchanged;
- the replacement payload is relocated into the append-only rebuild tail;
- only that file's final FAT range changes logically;
- every other existing FAT entry remains logically unchanged unless separately targeted by an approved operation.

An exact-size replacement may still use legacy `replace-component`; `replace-nitrofs-file` exists specifically to authorize relocation/size change under v2 semantics.

## 8. Operation: add NitroFS extension file

Conceptual form:

```json
{
  "type": "add-nitrofs-file",
  "path": "re_mcp/attributes/i2dt.bin",
  "replacement": {
    "artifact": "analysis/generated/patches/i2dt.bin",
    "sha256": "..."
  }
}
```

### 8.1 Preserve existing file-ID semantics

FNT file IDs are implicit from directory records and entry order. Adding an ordinary file inside an existing directory can renumber later file IDs and silently break overlay or game-code consumers.

Core 2 therefore permits new files only beneath a **new top-level extension subtree** whose first path segment does not exist in the source FNT.

Examples:

```text
source has no re_mcp/

valid:
    re_mcp/attributes/i2dt.bin
    re_mcp/abilities/a2dt.bin
    re_mcp/economy/e2dt.bin

invalid:
    data/new-file.bin        # data/ already exists
    root-existing.bin        # root insertion would alter an existing file-ID run
```

This rule allows new persistent patch data without renumbering any source file.

### 8.2 Path contract

New path segments must:

- use printable ASCII only;
- contain 1 through 127 bytes;
- contain no `/`, `\\`, NUL, `.` or `..` segment;
- be unique case-sensitively;
- stay within a bounded canonical path length;
- not collide with any source file or directory;
- not collide with another v2 addition.

The first segment of every new path must name a source-absent top-level directory. Multiple manifests operations may populate the same new extension subtree.

### 8.3 New directory and file ID assignment

To make IDs independent of caller operation ordering:

- existing directory IDs are preserved exactly;
- newly created directories are assigned IDs after the source directory count in canonical lexicographic preorder of complete directory paths;
- existing file IDs are preserved exactly;
- new file IDs begin at the source FAT count;
- new files are assigned by new directory ID order, then lexicographic filename order within each directory.

The resolved plan records every assigned directory ID and file ID before any output write occurs.

No operation may request a specific numeric new file ID or directory ID.

## 9. Operation: decoded compressed-overlay replacement

Conceptual form:

```json
{
  "type": "replace-decoded-overlay",
  "target": {
    "processor": "arm9",
    "overlayId": 7
  },
  "expectedStoredSha256": "...",
  "expectedRuntimeSha256": "...",
  "replacement": {
    "artifact": "analysis/generated/patches/overlay7-runtime.bin",
    "sha256": "..."
  }
}
```

Rules:

- the selected canonical overlay must currently be compressed;
- exact source stored-component SHA-256 is required;
- exact source decoded runtime SHA-256 is required;
- replacement artifact SHA-256 is required;
- replacement artifact byte length must equal the overlay's canonical `ramSize` exactly;
- BSS is not present in the replacement artifact and is not rewritten;
- `ramAddress`, `ramSize`, `bssSize`, static initializer range, processor, overlay ID, and file ID remain unchanged;
- the replacement decoded bytes must differ from the source runtime image;
- RE-MCP owns compression; callers do not supply compressed bytes, BLZ parameters, or packed overlay metadata;
- the deterministic encoder produces a new stored BLZ payload;
- the overlay FAT backing is relocated into the append-only tail;
- the overlay-table packed compressed-size field is updated to the exact encoded size;
- existing overlay flags remain unchanged;
- the encoded size must fit the canonical 24-bit packed size field;
- decoding the newly encoded payload through the existing decoder must reproduce the requested runtime bytes exactly before the plan is considered valid.

Core 2 deliberately does **not** resize the overlay's initialized runtime image. Runtime-module growth and runtime-memory allocation belong to the later Executable Injection + Hook Core.

## 10. Deterministic BLZ encoder contract

Core 2 adds a repository-owned deterministic BLZ encoder paired with the existing strict decoder.

The encoder must:

1. accept only bounded initialized overlay runtime bytes;
2. emit one canonical output for identical input bytes and encoder contract version;
3. use no external executable or environment-dependent compressor;
4. reject inputs or encoded outputs exceeding configured hard limits;
5. reject encoded size above the overlay table's 24-bit representation;
6. decode its own output through `decodeNdsBlz`;
7. require exact byte equality with the requested runtime image;
8. report encoded SHA-256, encoded byte count, runtime SHA-256, and encoder contract version.

The build identity includes the encoder contract version so a future algorithm change cannot silently produce different bytes under an old deterministic build ID.

Compression ratio is not a correctness requirement. Core 2 prioritizes deterministic valid round-trip encoding over optimal size.

## 11. Append-only layout planner

V2 rebuild layout is computed completely before output materialization.

### 11.1 Source prefix

The output begins as an exact full-byte copy of the source ROM.

No source gap, old payload, old metadata table, padding region, or unknown region is reclaimed.

### 11.2 Rebuild tail start

The tail starts at the first 0x200-byte boundary at or after the exact source file size.

Bytes between source EOF and the first tail segment are deterministic `0xFF` padding.

### 11.3 Segment order

The planner allocates appended segments in this deterministic order:

1. relocated replacement payloads for existing FAT file IDs, ascending by final file ID;
2. payloads for newly added FAT file IDs, ascending by assigned file ID;
3. rebuilt FNT, only when new files/directories require it;
4. rebuilt FAT, whenever any FAT range changes or file count grows;
5. rebuilt ARM9 overlay table, only when a compressed-overlay packed field changes;
6. rebuilt ARM7 overlay table, only when a compressed-overlay packed field changes.

Payload starts are 0x200-aligned. Metadata-table starts are 4-byte-aligned. Alignment padding is always `0xFF`.

All ranges are checked with safe-integer and 32-bit ROM-offset arithmetic before materialization.

### 11.4 Why unchanged files stay in place

If an existing FAT file is not targeted, its original start/end offsets remain in the rebuilt FAT exactly. Core 2 does not duplicate every file or compact the cartridge image.

If an existing file is variable-size replaced or represents a recompressed overlay, only that file gets a new appended FAT range.

## 12. FNT writer contract

The current parser is authoritative for source FNT meaning. Core 2 adds a deterministic serializer only for the constrained extension model.

When no new file is added, the original FNT remains authoritative and is not rebuilt.

When new extension files exist, the serializer must preserve semantically:

- every existing directory ID;
- every existing parent relationship;
- every existing directory path;
- every existing `firstFileId` relationship necessary to preserve source file IDs;
- every existing file ID → path mapping;
- every unnamed source FAT entry as unnamed;
- all source path segment bytes.

New directories and files are appended under the ID policy in Section 8.

The rebuilt FNT must reparse to the exact source filesystem plus only the explicitly added extension paths.

Core 2 does not support:

- renaming source files;
- deleting source files;
- deleting source directories;
- moving source files between directories;
- inserting new files into an existing source directory's implicit file-ID run.

## 13. FAT writer contract

A rebuilt FAT is required whenever:

- an existing file is relocated because of variable-size replacement;
- a compressed overlay is recompressed and relocated;
- a new file is added.

Rules:

- source file count and every existing file ID are preserved;
- unchanged existing entries retain exact source start/end offsets;
- targeted relocated files receive their exact planned appended range;
- new entries are appended after all source entries in assigned file-ID order;
- every entry has `start <= end` and lies inside the final logical ROM size;
- no two live FAT ranges may overlap;
- each replacement/new payload hashes to its pinned or deterministic derived SHA-256;
- overlay-backed file IDs continue to reference the correct overlay payload.

## 14. Overlay-table writer contract

Core 2 rebuilds an overlay table only when `replace-decoded-overlay` changes a packed compressed-size field for that processor.

For every source record the rebuilt table preserves exactly:

- overlay ID;
- RAM address;
- initialized RAM size;
- BSS size;
- static initializer start/end;
- file ID;
- flags high byte.

Only the lower packed 24-bit compressed-size value of explicitly targeted compressed overlays may change.

The rebuilt table must contain the same record count and record ordering as the source table.

No overlay may be added, deleted, renumbered, moved in RAM, or resized in runtime memory in this milestone.

## 15. Rebuild-aware NDS header model

The current analysis parser intentionally reads only the header fields required by the static model. Core 2 must extend the internal header representation enough to safely redirect rebuilt metadata and describe final image capacity while preserving all unknown/unowned bytes.

The rebuild path must read and preserve the full header block needed for checksum validation. It may mutate only fields explicitly owned by the resolved rebuild plan:

- `deviceCapacity`, when final padded capacity requires a larger representable cartridge size;
- FNT offset/size, only when the FNT is rebuilt;
- FAT offset/size, only when the FAT is rebuilt;
- ARM9 overlay-table offset/size, only when that table is rebuilt;
- ARM7 overlay-table offset/size, only when that table is rebuilt;
- used/logical ROM size field required by the NDS header contract;
- header checksum field(s) whose covered bytes were changed.

ARM9/ARM7 ROM offsets, RAM addresses, entry addresses, and initialized sizes remain unchanged in Core 2.

Banner location and all other unowned header bytes remain unchanged.

Checksum/size encoders must be repository-owned and fixture-tested. The implementation may not simply copy a stale header checksum after changing covered header bytes.

## 16. Final ROM size and capacity

Core 2 never assumes that bytes beyond source EOF are implicitly present.

After planning all meaningful tail segments:

1. `logicalUsedSize` is the end of the final meaningful rebuild segment;
2. the header's used-ROM-size field is updated to the planned logical value;
3. the smallest representable NDS device-capacity size that can contain `logicalUsedSize` is selected;
4. the output is padded with `0xFF` to that deterministic capacity boundary;
5. unsupported capacity or 32-bit overflow fails closed.

Core 2 may therefore enlarge a ROM substantially even for a modest variable-size change. This is intentional in the first safe append-only implementation.

The planner has a repository-defined maximum rebuilt ROM size. It is not caller-controlled through the manifest.

## 17. Mixed v1/v2 operations and logical conflicts

A v2 manifest may combine fixed-layout operations with Core 2 operations.

Conflict detection expands beyond physical source-range overlap because some v2 targets relocate in the output.

Rejected combinations include:

- two operations replacing the same logical component;
- `replace-bytes` within a file also selected by `replace-nitrofs-file`;
- `replace-bytes` or `replace-component` against a compressed overlay also selected by `replace-decoded-overlay`;
- generic NitroFS replacement of an overlay backing file;
- two new files with the same canonical path;
- a new path colliding with a source path;
- a new subtree whose top-level segment exists in the source;
- different selectors resolving to the same source logical file;
- any fixed-layout mutation touching header/FAT/FNT/overlay-table bytes that the rebuild planner owns.

Adjacent or independent changes remain valid.

There is still no ordered layering. Higher-level orchestration must resolve patch precedence before producing one low-level manifest.

## 18. Resolved rebuild plan

V2 preflight compiles the manifest into a complete deterministic layout plan before any final output is visible.

Plan-level data includes:

- source path identity, SHA-256, size, and source capacity;
- normalized manifest SHA-256;
- manifest format version;
- rebuild contract version;
- BLZ encoder contract version;
- output filename;
- deterministic build ID;
- logical used size;
- final padded size/capacity;
- header rewrite byte ranges and expected source bytes;
- appended segment map;
- rebuilt FNT/FAT/overlay-table hashes and sizes where applicable;
- assigned new directory IDs;
- assigned new file IDs;
- every operation and its source/final canonical ownership;
- expected final payload SHA-256 for every relocated/new FAT file;
- expected decoded runtime SHA-256 for every recompressed overlay.

Every appended segment records:

```text
kind
alignment
start
end
size
sha256 or deterministic padding rule
source operation(s)
```

No output offset is caller-selected.

## 19. Deterministic build identity v2

V1 build identity remains unchanged.

V2 build identity is SHA-256 of canonical JSON containing exactly the reproducibility inputs needed to distinguish rebuild behavior:

```json
{
  "format": "re-mcp-nds-build-identity",
  "formatVersion": 2,
  "sourceSha256": "...",
  "manifestSha256": "...",
  "replacementArtifactSha256": ["..."],
  "rebuildContractVersion": 1,
  "blzEncoderContractVersion": 1
}
```

Replacement artifact hashes are listed in normalized manifest operation order. Derived encoded BLZ hashes are not independent identity inputs because they are deterministic products of pinned runtime artifacts plus the encoder contract version; they are recorded in the resolved plan and verification evidence.

The full 64-hex build ID remains the deterministic build-directory name.

## 20. Validate behavior

`nds_mutation_validate` remains read-only with respect to final build publication.

For a v2 manifest it must perform enough work to prove the plan is materializable, including:

- source identity checks;
- strict manifest parsing;
- canonical target resolution;
- artifact hashing;
- original component/runtime guards;
- new path/ID planning;
- FNT/FAT/overlay-table serialization in memory;
- deterministic append-layout planning;
- header rewrite planning;
- BLZ encoding and decode-back verification for every decoded-overlay operation;
- all hard-limit/capacity checks;
- all logical and structural conflict checks.

Validation may perform bounded CPU/memory work. It must not create/publish the deterministic output build directory.

## 21. Single writer/materialization boundary

The Milestone 1 hardening principle remains: there must be one auditable module responsible for ROM output writes.

`src/services/nds/mutation/apply.ts` remains that boundary and is extended rather than creating an independent generic ROM writer.

It receives a fully guarded resolved v1/v2 plan and does not:

- parse manifests;
- resolve selectors;
- choose file IDs;
- choose offsets;
- infer header values;
- decide conflict precedence;
- weaken guards.

For v2 it:

1. creates the staged output from the exact source bytes;
2. applies approved fixed-prefix operations;
3. appends deterministic alignment/payload/metadata segments from the resolved plan;
4. applies exact planned header rewrites to the staged copy;
5. pads to the exact final capacity;
6. fsyncs/closes the staged output.

No module other than the designated materialization boundary may open a staged/final ROM for write access.

## 22. Post-build verification

A v2 build succeeds only if all verification layers pass.

### 22.1 Source identity

Source SHA-256 is revalidated before verification and after the complete output verification sequence.

### 22.2 Canonical output parse

The final staged output must parse through the canonical NDS model, including the rebuilt FNT/FAT/overlay relationships.

### 22.3 Prefix preservation

Across the original source-length prefix, every byte difference must belong to exactly one of:

- an approved v1 fixed-layout operation range; or
- an exact header rewrite byte range from the resolved rebuild plan.

No other source-prefix byte may change.

### 22.4 Append-tail proof

Every output byte after source EOF must belong to exactly one planned segment or deterministic `0xFF` padding range.

No unplanned tail bytes are permitted.

### 22.5 Existing filesystem identity

For every source file ID:

- the same file ID exists in the output;
- the same canonical source path or unnamed status exists;
- unchanged files retain exact source SHA-256 and FAT range;
- variable-replaced files match the replacement SHA-256 at the planned new range;
- overlay-backed IDs remain owned by the same processor/overlay.

### 22.6 Added filesystem identity

Every new file:

- has exactly the assigned appended file ID;
- has exactly the planned canonical path;
- hashes to its pinned artifact hash;
- exists only under an approved new extension subtree.

No additional file or directory may appear.

### 22.7 Overlay semantic identity

For each source overlay, output verification requires identical:

- processor;
- overlay ID;
- RAM address;
- initialized RAM size;
- BSS size;
- static initializer range;
- file ID;
- flags.

For targeted decoded compressed overlays only:

- compressed stored size may change;
- FAT range may change;
- packed compressed size must equal the exact new encoded payload size;
- decoding the output stored bytes through the existing decoder must equal the pinned requested runtime SHA-256 and exact requested bytes.

Untargeted overlays must retain exact stored SHA-256 and runtime SHA-256.

### 22.8 Header proof

The verifier compares full source/output header bytes and permits differences only in the exact fields planned under Section 15 plus checksum bytes that necessarily cover those changes.

Header checksum validation must pass on the output.

### 22.9 Final size/capacity proof

Output file size, logical used size, capacity field, and deterministic end padding must match the resolved plan exactly.

### 22.10 Unexpected diff accounting

V2 evidence reports separately:

```text
sourcePrefixChangedBytes
approvedFixedMutationBytes
approvedHeaderRewriteBytes
appendedMeaningfulBytes
appendedPaddingBytes
unexpectedChangedBytes = 0
```

Growth is not treated as an unexplained byte diff simply because the source had no corresponding bytes; every grown byte is attributed to a planned segment.

## 23. Existing-build verification and publication

The existing atomic output directory contract remains:

```text
output/nds/<source-sha-prefix>/<build-id>/
```

with:

```text
<output-name>.nds
mutation-manifest.json
resolved-plan.json
verification.json
changed-components.json
output.sha256
```

V2 evidence additionally records:

```text
rebuild-layout.json
```

`rebuild-layout.json` contains only deterministic canonical metadata: header rewrites, appended segments, assigned new file/directory IDs, layout/encoder contract versions, sizes, and hashes. It contains no absolute workspace paths or timestamps.

If a deterministic output directory already exists, `nds_mutation_build` may reuse it only after full fresh v2 verification. Any mismatch returns `publish-collision`; RE-MCP never repairs or overwrites the existing directory.

## 24. Error model additions

Core 2 retains all v1 errors and adds precise v2 categories, including:

```text
unsupported-rebuild-target
filesystem-extension-invalid
filesystem-path-collision
filesystem-id-capacity-exceeded
fnt-rebuild-failed
fat-rebuild-failed
overlay-table-rebuild-failed
decoded-overlay-guard-failed
blz-encode-failed
blz-roundtrip-mismatch
blz-packed-size-overflow
header-rebuild-failed
header-checksum-invalid
rom-capacity-exceeded
rebuild-layout-overflow
rebuild-prefix-diff
rebuild-tail-mismatch
filesystem-semantic-mismatch
overlay-semantic-mismatch
```

MCP-facing errors must include corrective guidance without exposing absolute workspace paths.

No error may suggest bypassing exact source/component guards.

## 25. Internal architecture

The existing mutation package remains the owning subsystem.

Expected additions/refactors:

```text
src/services/nds/
├── header.ts                     # extend rebuild-critical header model
├── fat.ts                        # parser retained
├── fnt.ts                        # parser retained
├── overlays.ts                   # parser retained
├── blz.ts                        # decoder retained; encoder API added or paired
├── blz-encode.ts                 # deterministic encoder if kept separate
└── mutation/
    ├── manifest.ts               # v1 + v2 strict parsing
    ├── selectors.ts              # canonical targets
    ├── guards.ts                 # source/artifact/runtime guards
    ├── planner.ts                # v1 + v2 resolved-plan dispatcher
    ├── conflicts.ts              # physical + logical conflict rules
    ├── filesystem-plan.ts        # new path, ID and FNT/FAT semantic plan
    ├── layout.ts                 # append-only segment allocator
    ├── header-plan.ts            # exact header rewrites/checksum plan
    ├── overlay-plan.ts           # compressed-size/table plan
    ├── apply.ts                  # sole staged ROM write boundary
    ├── verify.ts                 # v1 + v2 verifier dispatcher
    ├── report.ts                 # deterministic evidence
    ├── staging.ts                # atomic staging/publication
    └── build.ts                  # orchestration
```

File names may be adjusted during implementation planning if repository conventions make a narrower decomposition clearer, but responsibilities must remain isolated and testable.

## 26. Hard limits

Core 2 must enforce repository-owned limits before allocating/writing large outputs.

At minimum the design requires bounds for:

- maximum final ROM size;
- maximum output growth;
- maximum replacement artifact size;
- maximum count of new files;
- maximum total new-file bytes;
- maximum FNT directories (`<= 0x1000` by current parser contract);
- maximum FNT/FAT serialized bytes;
- maximum BLZ input/output bytes;
- maximum aggregate decoded-overlay bytes during validation;
- maximum file ID representable by the FNT model;
- maximum packed compressed size (`0x00ffffff`);
- maximum safe 32-bit ROM offset.

The implementation plan must choose explicit constants and test every boundary. None are manifest-controlled.

## 27. Testing strategy

Core 2 remains native-independent and must be exhaustively testable in CI with synthetic NDS fixtures.

### 27.1 Header tests

Cover:

- full rebuild-critical header parsing;
- exact preservation of unowned header bytes;
- FNT/FAT/overlay-table pointer rewrites;
- used-ROM-size update;
- capacity growth;
- checksum recomputation;
- checksum corruption rejection;
- arithmetic overflow.

### 27.2 FNT/FAT tests

Cover:

- variable-size existing file relocation;
- unchanged file ranges preserved;
- existing IDs/paths preserved;
- multiple new extension subtrees;
- deterministic new directory IDs;
- deterministic new file IDs;
- path collisions;
- existing-top-level-directory rejection;
- file/directory capacity boundaries;
- unnamed FAT entries preserved;
- semantic reparse equality.

### 27.3 BLZ tests

Cover:

- deterministic known fixtures;
- literal-heavy data;
- highly compressible data;
- incompressible data;
- exact encode→decode identity;
- encoded-size limit;
- 24-bit packed-size boundary;
- corruption rejection;
- wrong expected source runtime hash;
- replacement runtime-size mismatch.

### 27.4 Layout tests

Cover:

- source already 0x200 aligned;
- source unaligned;
- payload alignment;
- table alignment;
- deterministic segment ordering;
- final capacity padding;
- 32-bit overflow;
- maximum-growth rejection.

### 27.5 Build tests

Cover:

- v1 unchanged behavior;
- one variable NitroFS replacement;
- one new extension file;
- nested new extension directories;
- one decoded compressed-overlay replacement;
- mixed fixed-layout + variable operations;
- source ROM byte-identical after success/failure;
- failure before publication leaves no final build;
- deterministic rerun reuse after fresh verification;
- tampered deterministic output fails closed;
- output reparses and all new semantic relationships match plan;
- unrelated source payloads remain byte-identical.

### 27.6 Hardening tests

Require:

- no second generic ROM writer;
- no generic arbitrary-offset public tool;
- no caller-selected new file IDs/directories IDs;
- no caller-selected output offsets/alignment;
- no source-gap allocator;
- no implicit file-ID renumbering;
- no overlay runtime-size mutation;
- no external BLZ compressor invocation.

## 28. Package smoke

The downloadable bundle must execute a real assembled-package Core 2 smoke test before artifact upload.

The synthetic fixture should exercise, in one deterministic build where practical:

1. a variable-size non-overlay NitroFS file replacement;
2. at least one new extension-subtree file;
3. a compressed overlay whose decoded runtime image is replaced and deterministically recompressed;
4. final FNT/FAT/overlay-table/header reparse;
5. source-ROM immutability;
6. exact zero unexpected changes under the v2 verifier;
7. fresh verification/reuse of the published deterministic build.

The smoke must use the packaged compiled modules, not source TypeScript imports.

## 29. Compatibility with existing analysis/Ghidra systems

Core 2 must not change the evidence semantics of static analysis.

For a rebuilt ROM:

- it receives a new full ROM SHA-256 identity;
- canonical parsing derives the output's actual FAT/FNT/overlay geometry;
- Ghidra projects remain isolated by full output ROM SHA-256;
- source-ROM Ghidra state is never reused as if it belonged to the rebuilt ROM;
- decoded compressed-overlay runtime provenance remains separate from stored bytes;
- runtime/static correlation must bind to the exact rebuilt ROM SHA when eventually used for acceptance.

No Core 2 build is allowed to claim that a source-ROM static proof automatically proves the behavior of the rebuilt output. Higher-level patch acceptance remains responsible for runtime validation where required.

## 30. Explicit exclusions

NDS Rebuild Core 2 does **not** include:

- variable ARM9/ARM7 initialized-size changes;
- overlay runtime `ramSize` growth/shrink;
- BSS growth/shrink;
- new overlays;
- overlay runtime-address relocation;
- automatic code-cave discovery;
- ARM/Thumb hook generation;
- branch veneers/trampolines;
- relocation/fixup processing for injected code;
- generic executable memory allocation;
- write watchpoints;
- runtime memory writes/instrumentation;
- save-format inference or migration semantics;
- text-format inference;
- graphics format decoding/encoding;
- deletion or renaming of existing NitroFS files;
- file-ID renumbering;
- general whole-ROM compaction;
- natural-language patch-plan parsing;
- multi-patch dependency/conflict orchestration;
- automatic gameplay acceptance testing.

Those exclusions are intentional boundaries, not forgotten requirements.

## 31. Relationship to later milestones

Core 2 should make the next milestones possible in this order:

```text
NDS Rebuild Core 2
    ↓
Executable Injection + Hook Core
    - controlled runtime growth
    - code/data allocation
    - ARM/Thumb hooks/trampolines
    - overlay/main executable geometry changes where proven
    ↓
Dynamic Write-Origin Tracing
    - watchpoints/value-change tracing
    - reversible instrumentation fallback
    ↓
Save/Text/Asset Foundation
    - transactional save migration
    - text/resource expansion
    - project asset pipelines
    ↓
Agentic Patch Orchestration
    - plan intake
    - gap analysis
    - dependency/conflict graph
    - RE fallback loop
    - unified build/test/release
```

A later milestone may optimize the append-only layout or allow proven source-space reuse. Core 2 must not pre-emptively add those risks.

## 32. Milestone acceptance contract

NDS Rebuild Core 2 is complete only when all of the following are proven on the exact final implementation head:

### Backward compatibility

- all v1 mutation tests still pass;
- existing v1 deterministic build IDs/output behavior remain unchanged;
- the three public MCP tool schemas remain constrained to ROM + manifest paths.

### Variable-size filesystem rebuild

- an existing non-overlay NitroFS file can be replaced with a different-size pinned artifact;
- existing file ID/path remain unchanged;
- every unrelated source file retains exact bytes and logical identity;
- output reparses correctly.

### Safe filesystem extension

- new files can be created only under new source-absent top-level extension subtrees;
- every source file/directory ID remains unchanged;
- new IDs are deterministic and append-only;
- FNT/FAT reparse exactly to source semantics plus approved additions.

### Compressed overlays

- caller supplies decoded runtime bytes, not stored BLZ bytes;
- source stored and runtime hashes are guarded;
- deterministic BLZ encoding succeeds;
- decode-back equals the requested runtime bytes exactly;
- runtime geometry remains unchanged;
- overlay/FAT metadata reflects the new stored payload exactly.

### Layout/header

- output preserves the complete source ROM as its initial physical basis except exact approved fixed mutations/header rewrites;
- no source gap is allocated;
- tail layout is deterministic;
- header size/pointer/capacity/checksum changes are exact and verified;
- final output size/capacity is deterministic and bounded.

### Verification/publication

- source ROM remains byte-identical;
- output parses through the canonical NDS model;
- every source-prefix change and appended byte is attributed;
- `unexpectedChangedBytes` is zero;
- tampered existing builds fail closed;
- fresh deterministic reuse works;
- package smoke exercises the Core 2 rebuild path from the assembled downloadable artifact;
- CI typecheck, complete test suite, build, and package workflows pass.

Only after this acceptance contract is on `main` should RE-MCP proceed to generic executable growth/hook injection.
