# Controlled NDS Mutation Core Design

**Date:** 2026-08-09  
**Status:** Approved design; implementation not started  
**Milestone:** Agentic ROM Modification Pipeline — Milestone 1  
**Scope:** Generic Nintendo DS mutation foundation

## 1. Goal

Add RE-MCP's first generic write-capable Nintendo DS subsystem.

Given one validated source ROM and one strict mutation manifest, RE-MCP must apply only conflict-free same-size guarded mutations to a staged copy, fully verify the resulting ROM, and atomically publish a complete `.nds` plus deterministic evidence. The source ROM remains immutable.

This subsystem sits below, rather than replaces, the existing reverse-engineering stack:

```text
patch requirements
    ↓
identify missing implementation facts
    ↓
static analysis / xrefs / functions / Ghidra / decompilation / runtime correlation
    ↓
prove implementation details
    ↓
compile deterministic mutation manifest
    ↓
Controlled NDS Mutation Core
    ↓
verified complete ROM
```

If a higher-level patch plan lacks enough information for a safe mutation, the agent must return to reverse engineering instead of inventing an operation.

## 2. Product boundary

Milestone 1 is generic NDS-first, not Bakugan-specific.

It accepts a complete machine mutation manifest whose targets, guards, replacement artifacts, and output identity are already known. It does not parse natural-language patch plans, synthesize ARM hooks, solve dependencies between patch packs, or infer semantic game edits.

## 3. All-or-nothing safety contract

Every successful build follows this order:

```text
immutable source ROM
        ↓
canonical NDS parse
        ↓
exact source SHA-256 validation
        ↓
strict manifest parse
        ↓
canonical selector resolution
        ↓
all original-byte/component guards
        ↓
all replacement artifact guards
        ↓
all overlap/conflict checks
        ↓
staged full-ROM copy
        ↓
apply all operations
        ↓
canonical output reparse
        ↓
structural immutability verification
        ↓
per-operation verification
        ↓
complete source→output diff attribution
        ↓
source SHA-256 revalidation
        ↓
atomic build-directory publication
```

A failure anywhere before publication exposes no final ROM. The source ROM is never opened with write access.

## 4. Manifest-only mutation input

Milestone 1 accepts mutations only from strict JSON stored inside the configured workspace.

Conceptual top-level form:

```json
{
  "format": "re-mcp-nds-mutation",
  "formatVersion": 1,
  "source": {
    "sha256": "64-lowercase-hex-characters"
  },
  "output": {
    "filename": "modded-game.nds"
  },
  "operations": [
    {}
  ]
}
```

Requirements:

- `format` is exactly `re-mcp-nds-mutation`;
- `formatVersion` is exactly `1`;
- source SHA-256 is exactly 64 lowercase hexadecimal characters; uppercase hashes are rejected rather than normalized;
- `operations` contains at least one operation;
- unknown top-level, operation, selector, and replacement fields are rejected;
- unsafe output filenames are rejected;
- malformed byte strings are rejected;
- unsupported mutation types are rejected;
- normalized JSON representation is deterministic.

There is no inline arbitrary mutation-list API and no generic byte-write MCP endpoint.

## 5. Canonical selectors

Mutations target canonical NDS ownership, never a bare absolute ROM offset.

Allowed component classes:

- ARM9 main executable;
- ARM7 main executable;
- ARM9 overlay by exact overlay ID;
- ARM7 overlay by exact overlay ID;
- NitroFS file by exact file ID;
- NitroFS file by exact canonical path.

### 5.1 Byte-edit selectors

A byte edit may use:

- component-relative offset; or
- runtime address when the canonical map resolves it uniquely to the explicitly selected executable component.

Ambiguous runtime ownership fails closed. An explicit overlay ID may disambiguate one static overlay source, but does not claim that overlay is loaded at runtime.

### 5.2 Overlay-backed NitroFS alias rule

A FAT/NitroFS file that backs an ARM9 or ARM7 overlay is not mutable through the generic NitroFS selector. The caller must use the canonical overlay selector.

This prevents a NitroFS alias from bypassing overlay-specific provenance and compressed-overlay validation rules.

### 5.3 Whole-component selectors

Whole-component replacement selects one exact canonical component. Physical ROM ranges are derived by RE-MCP from `NdsRomMap`; the manifest does not supply start/end ROM offsets.

## 6. Supported operations

Milestone 1 supports exactly two operation types.

### 6.1 Guarded byte replacement

Conceptual form:

```json
{
  "type": "replace-bytes",
  "target": {
    "component": "arm9",
    "relativeOffset": 1234
  },
  "expected": "E3A00000",
  "replacement": "E3A00001"
}
```

Rules:

- expected and replacement lengths are equal and non-zero;
- replacement bytes must differ from expected bytes; no-op edits are rejected;
- the complete range is inside one allowed component;
- exact original bytes must match during preflight;
- structural metadata may not be touched;
- compressed derived-runtime bytes may not be targeted;
- physical range may not overlap any other operation.

### 6.2 Whole-component same-size replacement

Conceptual form:

```json
{
  "type": "replace-component",
  "target": {
    "component": "arm9-overlay",
    "overlayId": 7
  },
  "expectedOriginalSha256": "...",
  "replacement": {
    "artifact": "analysis/generated/patches/overlay7.bin",
    "sha256": "..."
  }
}
```

Rules:

- exact original component SHA-256 is mandatory;
- replacement artifact is inside the configured workspace;
- replacement artifact SHA-256 is mandatory and must match;
- replacement stored size equals original stored size exactly;
- replacement SHA-256 must differ from the original component SHA-256; no-op component replacements are rejected;
- replacement artifact may not be the source ROM, mutation manifest, staged ROM, or final output ROM;
- whole-component ownership is exclusive and cannot coexist with another operation touching that component.

## 7. Strict guard policy

Every build requires exact full source ROM SHA-256 identity.

Operation guards are mandatory:

- byte replacement → exact expected original bytes;
- whole-component replacement → exact original component SHA-256;
- replacement artifact → exact replacement SHA-256.

There is no force, wildcard, ignore-stale, or apply-regardless mode.

All guards pass before the staged ROM is modified.

## 8. Replacement artifact policy

Whole-component payloads come only from controlled workspace files.

RE-MCP must:

1. resolve the artifact under the configured workspace root;
2. reject traversal/out-of-root paths;
3. require a regular file;
4. ensure it is not the source ROM, manifest, staged ROM, or final output ROM;
5. hash it;
6. compare its hash to the manifest;
7. compare its size to the selected stored component;
8. preserve workspace-relative artifact identity and hash in the resolved plan/report.

Binary payloads are not embedded in JSON.

## 9. Structural metadata is immutable

Milestone 1 changes content within the existing layout; it does not change the layout.

Immutable regions/geometry:

- NDS header;
- FAT;
- FNT;
- ARM9 overlay table;
- ARM7 overlay table;
- component physical boundaries;
- file counts;
- overlay counts.

Consequently, Milestone 1 does not support variable-size replacement, FAT relocation, FNT restructuring, new/deleted NitroFS files, overlay-table changes, or ROM layout changes.

Output ROM size must equal source ROM size exactly.

## 10. Allowed mutable content

Within the existing layout, Milestone 1 may mutate:

- ARM9 initialized executable bytes;
- ARM7 initialized executable bytes;
- uncompressed ARM9 overlay stored bytes;
- uncompressed ARM7 overlay stored bytes;
- non-overlay NitroFS file contents;
- exact-size stored compressed-overlay components under Section 11.

## 11. Compressed overlay contract

Stored BLZ bytes and decoded derived runtime bytes remain separate representations.

### 11.1 Allowed

A compressed overlay may be replaced only as a whole exact-size stored component.

Required evidence:

- exact processor and overlay ID;
- exact original stored-component SHA-256;
- controlled replacement artifact;
- exact replacement SHA-256;
- exact same stored size.

After replacement, the staged output must pass the existing BLZ/runtime-image validation and yield a derived runtime image consistent with canonical overlay runtime geometry.

### 11.2 Forbidden

Milestone 1 does not permit:

- byte edits addressed against decoded derived overlay bytes;
- fabricated direct ROM offsets for decoded bytes;
- automatic BLZ recompression;
- decode → edit → recompress workflows.

Those belong to Milestone 2.

## 12. Conflict policy

Any physical overlap is rejected before staging.

Rejected examples:

- byte edit vs byte edit with any common byte;
- identical overlapping edits;
- containment overlaps;
- byte edit inside a component selected for whole replacement;
- two whole replacements of the same component;
- different selectors resolving to the same physical range.

Adjacent non-overlapping ranges are valid.

There is no ordered layering in Milestone 1. Future orchestration resolves dependencies/conflicts before producing the low-level manifest.

## 13. Resolved mutation plan

Preflight compiles the manifest into a deterministic resolved plan.

Each resolved operation records:

- operation index;
- normalized operation type;
- canonical component identity;
- processor/overlay ID when applicable;
- NitroFS file identity when applicable;
- component-relative range;
- exact physical ROM range;
- original guard evidence;
- replacement bytes or workspace-relative artifact identity/hash;
- replacement size;
- compressed status and required post-build validation.

Plan-level data includes:

- source SHA-256 and size;
- normalized manifest SHA-256;
- output filename;
- deterministic build ID;
- immutable structural ranges.

## 14. Deterministic identities

### 14.1 Canonical JSON

Deterministic manifest/plan hashing uses repository-owned canonical JSON serialization with:

- UTF-8;
- object keys sorted lexicographically at every level;
- arrays preserved in semantic order;
- no insignificant whitespace;
- integers serialized as JSON integers;
- workspace-relative forward-slash paths;
- no timestamps, process IDs, absolute workspace paths, temporary paths, or environment-specific values.

### 14.2 Manifest SHA-256

`manifestSha256` is SHA-256 of the canonical normalized manifest bytes.

### 14.3 Build ID

`buildId` is the full lowercase 64-hex SHA-256 of canonical JSON containing exactly:

```json
{
  "format": "re-mcp-nds-build-identity",
  "formatVersion": 1,
  "sourceSha256": "...",
  "manifestSha256": "...",
  "replacementArtifactSha256": ["...", "..."]
}
```

Replacement hashes are listed in manifest operation order. Byte-only manifests use an empty array.

The full 64-hex build ID is used as the build-directory name.

## 15. Output containment

The manifest provides only a safe output filename.

A safe filename:

- is a simple basename;
- contains no slash/backslash;
- is neither `.` nor `..`;
- ends in `.nds` case-sensitively;
- does not contain NUL/control characters.

Final layout:

```text
output/nds/
└── <source-sha-prefix>/
    └── <full-build-id>/
        ├── <safe-output-name>.nds
        ├── mutation-manifest.json
        ├── resolved-plan.json
        ├── verification.json
        ├── changed-components.json
        └── output.sha256
```

Deterministic evidence files use workspace-relative paths so identical inputs in different absolute workspace locations can still produce byte-identical deterministic metadata.

## 16. Staging, publication, and idempotence

Build steps:

1. create a temporary sibling build directory;
2. copy the complete immutable source ROM to a staged ROM;
3. open only the staged ROM for mutation;
4. apply every resolved operation;
5. flush and close staged output;
6. perform full verification;
7. write deterministic metadata;
8. flush required files;
9. atomically rename the temporary directory to the final build directory.

Failure cleanup is best-effort and no final build directory is published.

### 16.1 Existing deterministic build

If the final build directory already exists, `nds_mutation_build` is idempotent only when `nds_mutation_verify` proves that existing directory is the exact valid build for the same source SHA-256, manifest SHA-256, build ID, output filename, replacement hashes, and verification contract. In that case the existing verified build is returned without rewriting it.

If any existing-build evidence differs or verification fails, publication returns `publish-collision` and does not overwrite or repair the directory.

## 17. Single mutation writer boundary

Only `apply.ts` may write ROM bytes.

It receives a fully resolved, fully guarded, conflict-free plan. It does not interpret selectors or weaken validation. Every write is bounded to one resolved range, and the source ROM path is never accepted as its destination.

## 18. Post-build verification

A build succeeds only if all checks pass.

### 18.1 Source integrity

Source SHA-256 is calculated before preflight and after staged verification. Both equal the manifest source hash.

### 18.2 Canonical output parse

The staged output reparses successfully through canonical `NdsRomMap`.

### 18.3 ROM size

Output size equals source size exactly.

### 18.4 Structural immutability

Source/output bytes covering the NDS header, FAT, FNT, ARM9 overlay table, and ARM7 overlay table are byte-identical.

The reparsed output retains identical structural counts and component physical boundaries.

### 18.5 Per-operation proof

- byte replacements contain exactly requested replacement bytes at exactly resolved ranges;
- whole replacements hash exactly to their pinned replacement hashes;
- compressed replacement overlays successfully produce valid derived runtime images under the existing BLZ/runtime geometry rules.

### 18.6 Complete diff attribution

RE-MCP computes the complete byte-level source→output diff.

Every changed byte must belong to exactly one approved operation range. Every approved operation is non-no-op by construction.

The build must prove:

```text
unexpectedChangedBytes = 0
```

Anything else invalidates the build.

## 19. Deterministic evidence

Successful deterministic evidence includes:

- workspace-relative source ROM identity;
- source SHA-256 and size;
- workspace-relative output ROM identity;
- output SHA-256 and size;
- manifest SHA-256;
- build ID;
- operation count;
- changed component count;
- changed byte count;
- source unchanged result;
- structural metadata unchanged result;
- canonical output parse result;
- unexpected changed byte count;
- compressed-overlay validation results;
- final verification status.

Each operation report includes canonical target, resolved physical range, guard evidence, replacement evidence, and post-build verification.

Human-facing tool responses may add runtime context, but reproducibility-critical files must remain deterministic.

## 20. Error model

Use structured `NdsError` categories.

Required categories:

- `mutation-manifest-invalid`;
- `source-rom-mismatch`;
- `unsupported-mutation-target`;
- `structural-metadata-mutation`;
- `ambiguous-runtime-target`;
- `original-byte-guard-failed`;
- `original-component-guard-failed`;
- `replacement-artifact-missing`;
- `replacement-artifact-hash-mismatch`;
- `replacement-size-mismatch`;
- `mutation-no-op`;
- `mutation-overlap`;
- `compressed-overlay-invalid`;
- `staging-failed`;
- `post-build-parse-failed`;
- `structural-map-changed`;
- `unexpected-rom-diff`;
- `output-verification-failed`;
- `publish-collision`;
- `publish-failed`.

MCP errors include deterministic corrective guidance where available.

## 21. Internal architecture

```text
src/services/nds/mutation/
├── manifest.ts
├── selectors.ts
├── guards.ts
├── planner.ts
├── conflicts.ts
├── staging.ts
├── apply.ts
├── verify.ts
├── report.ts
└── build.ts
```

Responsibilities:

- `manifest.ts`: strict parsing, canonical normalization, safe filename validation, canonical JSON/hash inputs;
- `selectors.ts`: canonical component/range resolution, runtime ambiguity handling, overlay-backed NitroFS alias rejection, structural exclusion;
- `guards.ts`: source bytes/component hashes and replacement artifact path/hash/size validation;
- `planner.ts`: compile manifest + `NdsRomMap` into deterministic resolved plan/build identity;
- `conflicts.ts`: physical interval overlap and whole-component exclusivity checks;
- `staging.ts`: controlled temporary directory, source copy, cleanup;
- `apply.ts`: only ROM-byte writer;
- `verify.ts`: source re-hash, canonical reparse, structure comparison, operation proof, compressed-overlay proof, complete diff attribution;
- `report.ts`: deterministic machine-readable evidence;
- `build.ts`: preflight → stage → apply → verify → publish orchestration and idempotent-existing-build handling.

## 22. MCP surface

Milestone 1 exposes exactly three high-level tools.

### 22.1 `nds_mutation_validate`

Read-only preflight.

Inputs:

- source ROM path under configured workspace;
- manifest path under configured workspace.

Returns source/manifest identity, normalized resolved plan, guard/conflict results, build ID, and buildable status. It creates no output ROM.

### 22.2 `nds_mutation_build`

Controlled write operation.

It repeats full preflight, stages the complete ROM, applies all operations, runs full verification, and publishes only after success. It never trusts a previous validation result.

If an exact valid deterministic build already exists, it returns that verified build idempotently. It never overwrites a divergent existing directory.

### 22.3 `nds_mutation_verify`

Read-only verification of an existing RE-MCP build under the controlled output root.

It reloads source/manifest lineage and repeats structural, operation, hash, compressed-overlay, and complete-diff checks. It is not a generic arbitrary two-ROM diff tool.

## 23. Capability reporting

`server_capabilities` changes only when the production subsystem exists.

It must state that mutation:

- requires a strict manifest;
- supports only same-size canonical content edits/replacements;
- keeps source ROMs immutable;
- forbids structural metadata mutation;
- permits compressed overlays only as prebuilt exact-size stored replacements;
- does not support decoded compressed-overlay edits or recompression;
- exposes no arbitrary ROM-offset or generic filesystem writer.

## 24. TDD verification matrix

Synthetic NDS fixtures must cover the system without copyrighted ROMs.

### Manifest

- valid manifest;
- empty operations rejected;
- unknown fields rejected;
- uppercase/malformed hashes rejected;
- unsafe filename rejected;
- unsupported version/type rejected;
- deterministic canonical JSON/hash.

### Selectors

- ARM9/ARM7 relative edits;
- uncompressed ARM9/ARM7 overlay edits;
- non-overlay NitroFS file ID/path edits;
- unique runtime-address edit;
- ambiguous runtime address rejected;
- overlay-backed NitroFS alias rejected;
- range crossing component boundary rejected;
- structural metadata cannot be selected.

### Guards/artifacts

- expected bytes pass/fail;
- component SHA passes/fails;
- replacement artifact missing;
- artifact hash mismatch;
- artifact size mismatch;
- artifact aliasing source/manifest/output rejected;
- source ROM hash mismatch;
- source changes during build.

### No-op/conflicts

- byte no-op rejected;
- whole-component no-op rejected;
- disjoint operations pass;
- one-byte/identical/containment overlaps rejected;
- adjacent ranges pass;
- whole-component + byte edit rejected;
- selector aliases resolving to the same physical bytes rejected.

### Mutation

- ARM9/ARM7 output correct;
- uncompressed overlay output correct;
- NitroFS output correct;
- whole-component output correct;
- multiple disjoint operations apply atomically;
- source stays byte-identical.

### Compressed overlays

- valid exact-size stored replacement accepted;
- invalid BLZ rejected;
- wrong size rejected;
- derived runtime geometry mismatch rejected;
- decoded-runtime byte-edit path unavailable;
- NitroFS alias cannot bypass overlay rules.

### Verification

- valid output reparses;
- size mismatch rejected;
- header/FAT/FNT/overlay-table changes detected;
- unexpected byte corruption detected;
- missing requested mutation detected;
- replacement component hash mismatch detected;
- valid build proves zero unexpected changed bytes.

### Publication/reproducibility

- staging/apply/verification failures publish nothing;
- identical clean builds produce byte-identical ROMs and deterministic evidence;
- build ID stable across absolute workspace paths;
- changing source/manifest/replacement identity changes build ID;
- exact existing valid build is returned idempotently;
- divergent existing build directory causes `publish-collision` and is not overwritten;
- source hash remains identical before/after every mutation test.

## 25. Explicit exclusions

Milestone 1 does not implement:

- variable-size replacement;
- ROM repacking/relocation;
- FAT/FNT mutation;
- new/deleted NitroFS files;
- overlay-table/header mutation;
- BLZ compression/recompression;
- decoded compressed-overlay mutation;
- automatic assembly compilation;
- ARM hook synthesis;
- natural-language patch-plan parsing;
- semantic patch compilation;
- multi-patch dependency solving;
- ordered operation layering;
- BPS/xdelta generation;
- automatic emulator/gameplay acceptance;
- register/runtime-memory writes;
- arbitrary ROM-offset writes;
- arbitrary caller-selected output paths.

## 26. Follow-on milestones

```text
M1 — Controlled NDS Mutation Core
     same-size guarded mutation → verified complete ROM

M2 — NDS Rebuild + BLZ Recompression
     decoded overlay edits, recompression, variable-size replacement,
     FAT-aware relocation/rebuild

M3 — Patch Compilation + Orchestration
     proven RE findings + patch requirements → one conflict-free build plan

M4 — Automated Build Verification + Emulator Acceptance
     boot/smoke/runtime checks against produced ROMs

M5 — Full Agentic Patch-Plan Execution
     patch plans + ROM + assets → investigate gaps → implement →
     rebuild → verify → playable modded ROM
```

## 27. Acceptance contract

Milestone 1 is complete only when:

```text
Input
    source .nds and strict manifest are workspace-contained
    replacement artifacts are workspace-contained and pinned

Preflight
    exact source SHA-256 matches
    every selector resolves canonically and uniquely
    every original guard matches
    every replacement hash/size matches
    overlay aliases cannot bypass overlay rules
    structural metadata is untargetable
    no operation is a no-op
    no operations overlap

Build
    source ROM is never writable
    complete staged copy is produced
    all writes remain inside resolved ranges
    output size equals source size

Verification
    source SHA remains unchanged
    output reparses canonically
    header/FAT/FNT/overlay tables are byte-identical
    structural geometry is unchanged
    each requested mutation is present exactly
    compressed replacements validate as stored BLZ/runtime images
    full ROM diff attributes every changed byte to exactly one operation
    unexpected changed bytes = 0

Publication
    no final build appears before verification
    final directory is atomically published
    existing exact valid build is reusable idempotently
    divergent existing build is never overwritten
    ROM, hashes, resolved plan, and verification evidence are present
    identical inputs produce deterministic ROM output and deterministic evidence
```

Later milestones may broaden rebuild capability, but must preserve the source-identity, provenance, transaction, conflict, containment, and verification guarantees established here.
