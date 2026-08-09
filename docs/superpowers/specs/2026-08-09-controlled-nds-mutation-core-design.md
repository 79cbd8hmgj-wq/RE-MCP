# Controlled NDS Mutation Core Design

**Date:** 2026-08-09  
**Status:** Approved design, implementation not started  
**Milestone:** Agentic ROM Modification Pipeline — Milestone 1  
**Scope:** Generic Nintendo DS mutation foundation

## 1. Goal

Add the first generic write-capable Nintendo DS subsystem to RE-MCP.

The milestone must take one validated source ROM plus one repository/workspace mutation manifest, apply only conflict-free same-size guarded mutations to a staged copy, fully verify the resulting ROM, and atomically publish a complete playable `.nds` output plus machine-readable evidence.

The source ROM must remain immutable.

This milestone does not replace the existing reverse-engineering stack. The long-term agentic workflow remains:

```text
patch requirements
    ↓
identify missing implementation facts
    ↓
RE-MCP static analysis / Ghidra / decompilation / runtime correlation
    ↓
prove implementation details
    ↓
compile a deterministic mutation manifest
    ↓
Controlled NDS Mutation Core
    ↓
verified playable ROM
```

If a higher-level patch plan lacks enough information to identify a safe mutation, the agent must return to reverse engineering instead of inventing an operation.

## 2. Product boundary

This milestone is generic NDS-first rather than Bakugan-specific.

It introduces a low-level mutation engine that can be used by future game-specific or agentic orchestration layers. It intentionally does not parse natural-language patch plans, synthesize assembly hooks, resolve dependencies between independent patch packs, or perform semantic game-specific edits.

The mutation engine accepts only a complete, deterministic machine manifest whose targets, guards, replacement artifacts, and output identity are already known.

## 3. Core safety contract

Every successful build follows this sequence:

```text
immutable source ROM
        ↓
parse canonical NDS map
        ↓
validate exact source SHA-256
        ↓
load strict mutation manifest
        ↓
resolve every canonical selector
        ↓
validate every original-byte/component guard
        ↓
validate every replacement artifact and hash
        ↓
reject all overlaps/conflicts
        ↓
create staged full-ROM copy
        ↓
apply every operation
        ↓
reparse staged output
        ↓
verify structural immutability
        ↓
verify every requested mutation
        ↓
prove every changed byte is authorized
        ↓
revalidate source ROM SHA-256
        ↓
atomically publish complete build directory
```

The transaction is all-or-nothing.

A failure at any step must not publish a final ROM.

The source ROM is never opened with write access.

## 4. Manifest-only mutation input

Milestone 1 accepts mutations only from a strict JSON manifest stored inside an allowed repository/workspace path.

There is no inline arbitrary mutation list and no generic byte-write MCP tool.

Conceptual top-level form:

```json
{
  "format": "re-mcp-nds-mutation",
  "formatVersion": 1,
  "source": {
    "sha256": "64 lowercase hex characters"
  },
  "output": {
    "filename": "modded-game.nds"
  },
  "operations": []
}
```

### 4.1 Manifest strictness

The parser must reject:

- unknown top-level fields;
- unknown operation fields;
- unknown selector fields;
- unsupported format versions;
- malformed SHA-256 values;
- unsafe output filenames;
- empty or malformed byte strings;
- impossible component selectors;
- mutation types outside this specification.

Normalization must be deterministic so logically identical manifests resolve to the same normalized representation.

## 5. Canonical mutation selectors

Mutation operations must target NDS components through canonical ownership rather than a bare ROM offset.

Allowed target classes:

- ARM9 main executable;
- ARM7 main executable;
- ARM9 overlay by exact overlay ID;
- ARM7 overlay by exact overlay ID;
- NitroFS file by exact file ID;
- NitroFS file by exact canonical path.

### 5.1 Byte-edit addressing

A bounded byte edit may use one of these component-local selectors:

- `relativeOffset` inside the selected component;
- a runtime address when the canonical NDS map resolves that address uniquely to the selected executable component.

Runtime addresses that match multiple static overlay candidates are rejected as ambiguous unless the operation also specifies the exact overlay identity and the canonical resolver can prove the selected source.

No operation may directly target an arbitrary absolute ROM offset.

### 5.2 Whole-component addressing

Whole-component replacement targets one exact canonical component.

The component's physical stored range is derived from the canonical NDS map rather than supplied by the manifest.

## 6. Operation types

Milestone 1 supports two mutation forms.

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

Requirements:

- `expected` and `replacement` must have identical non-zero byte lengths;
- the selected range must be fully contained in one allowed component;
- the exact original bytes must match before any staging write occurs;
- the operation may not touch structural metadata;
- the resolved physical byte range may not overlap any other operation.

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

Requirements:

- the original component SHA-256 must match exactly;
- the replacement artifact must be inside an allowed workspace path;
- the artifact SHA-256 must match the manifest before staging;
- replacement size must equal the original stored component size;
- the whole component becomes exclusively owned by that operation and cannot contain any other mutation operation.

## 7. Strict guard policy

Every build always requires the exact full source ROM SHA-256.

Operation-specific guards are mandatory:

- bounded byte edits require exact expected original bytes;
- whole-component replacements require the exact original component SHA-256;
- replacement artifacts require their exact replacement SHA-256.

There is no wildcard guard, force mode, ignore-stale mode, or apply-regardless path.

All guards are checked during preflight before a staged ROM is modified.

## 8. Replacement artifact policy

Whole-component payloads come only from controlled workspace artifacts.

The engine must:

1. resolve the artifact path inside the configured workspace;
2. reject traversal or paths outside that root;
3. require the file to exist and be a regular file;
4. calculate its SHA-256;
5. compare the hash with the manifest;
6. compare its size with the selected stored component;
7. retain the artifact path and hash in the resolved plan and verification report.

Large replacement binaries are not embedded in the mutation manifest.

## 9. Structural metadata is immutable

Milestone 1 must not modify the NDS structural layout.

The following source regions are immutable:

- core NDS header;
- FAT;
- FNT;
- ARM9 overlay table;
- ARM7 overlay table;
- component start/end boundaries;
- file counts;
- overlay counts.

Therefore this milestone does not support:

- variable-size component replacement;
- FAT relocation;
- FNT restructuring;
- new NitroFS files;
- file deletion;
- overlay-table changes;
- ROM layout changes.

The output ROM must retain the same size as the source ROM.

## 10. Allowed mutable content

Within the immutable layout, Milestone 1 may modify:

- ARM9 initialized executable bytes;
- ARM7 initialized executable bytes;
- uncompressed ARM9 overlay stored bytes;
- uncompressed ARM7 overlay stored bytes;
- NitroFS file contents;
- exact-size stored compressed-overlay components, subject to the compressed-overlay rules below.

## 11. Compressed overlay contract

RE-MCP already distinguishes a compressed overlay's stored FAT-backed representation from its decoded derived runtime representation. Milestone 1 preserves that distinction.

### 11.1 Allowed

A whole compressed overlay may be replaced only as an exact same-size stored component.

The operation must include:

- exact processor and overlay ID;
- exact original stored-component SHA-256;
- controlled replacement artifact;
- exact replacement artifact SHA-256;
- exact same stored size.

After replacement, RE-MCP must use the existing BLZ/runtime-image machinery to validate that the replacement remains a valid compressed overlay representation and yields a valid derived runtime image consistent with the overlay's canonical runtime geometry.

### 11.2 Forbidden

Milestone 1 must not allow:

- byte edits addressed against the decoded derived runtime representation;
- treating decoded runtime bytes as though they had direct source ROM offsets;
- automatic BLZ recompression;
- decoded-edit → recompress → replace workflows.

Decoded-overlay editing and recompression belong to Milestone 2.

## 12. Conflict policy

All physical overlap between mutation operations is rejected during preflight.

Examples that must fail:

- two byte edits touching any common byte;
- two identical byte edits targeting the same range;
- a byte edit inside a component also selected for whole-component replacement;
- two whole-component replacements targeting the same component;
- two distinct selectors that resolve to the same physical byte range.

Milestone 1 has no ordered layering semantics.

Future multi-patch orchestration must resolve dependencies and conflicts before producing the final low-level mutation manifest.

## 13. Resolved mutation plan

The engine compiles the strict manifest into a deterministic resolved plan before staging.

Each resolved operation records:

- operation index;
- normalized operation type;
- canonical component identity;
- processor when applicable;
- overlay ID when applicable;
- NitroFS file ID/path when applicable;
- component-relative range;
- exact physical ROM range;
- expected original bytes or original component SHA-256;
- replacement bytes or replacement artifact path/hash;
- replacement size;
- compressed status and validation requirements.

The plan also records:

- full source ROM SHA-256;
- source ROM size;
- normalized manifest SHA-256;
- output filename;
- deterministic build ID;
- structural ranges that must remain immutable.

## 14. Deterministic build identity

The build ID must be derived deterministically from:

- normalized manifest contents;
- full source ROM SHA-256;
- all pinned replacement artifact SHA-256 values.

The exact derivation algorithm must be specified in implementation and covered by deterministic tests. It must not include timestamps, process IDs, temporary paths, or other nondeterministic state.

## 15. Output containment

The manifest may provide only a safe filename, not an arbitrary destination path.

Final builds are published underneath an RE-MCP-controlled tree conceptually equivalent to:

```text
output/nds/
└── <source-sha-prefix>/
    └── <build-id>/
        ├── <safe-output-name>.nds
        ├── mutation-manifest.json
        ├── resolved-plan.json
        ├── verification.json
        ├── changed-components.json
        └── output.sha256
```

The output filename must be a simple filename with `.nds` extension and no path separators or traversal components.

## 16. Staging and atomic publication

The engine must reuse RE-MCP's existing containment and atomic-output philosophy.

The final build directory must not exist until verification passes.

Build sequence:

1. create a temporary sibling build directory;
2. copy the complete source ROM into that temporary directory;
3. open only the staged copy for mutation;
4. apply all resolved operations;
5. flush and close the staged ROM;
6. verify the staged ROM completely;
7. write deterministic build metadata to the temporary directory;
8. flush required files;
9. atomically rename the temporary directory to its final build directory.

On failure, temporary output is removed best-effort and no final build directory is published.

If the deterministic final build directory already exists, the engine must not silently overwrite it. It must verify whether the existing build is the exact same valid build or return a structured collision/error result according to the implementation plan.

## 17. Mutation application boundary

Only one internal module should be responsible for writing bytes to the staged ROM.

The application layer receives a fully resolved, fully guarded, conflict-free plan. It must not perform selector interpretation or relax validation.

Writes must be bounded to the exact resolved ranges.

The source ROM path must never be accepted by the writer as a writable destination.

## 18. Post-build verification contract

A build is successful only after all checks below pass.

### 18.1 Source integrity

Calculate the source ROM SHA-256 before preflight and again after staged output verification.

Both must equal the manifest source SHA-256.

Any source change during the operation invalidates the build.

### 18.2 Canonical output parse

Reparse the staged output through the canonical NDS parser.

The output must remain a valid canonical NDS ROM.

### 18.3 ROM size

The output ROM size must equal the source ROM size exactly.

### 18.4 Structural immutability

Compare source and output bytes covering:

- NDS header;
- FAT;
- FNT;
- ARM9 overlay table;
- ARM7 overlay table.

Every structural byte must be identical.

The reparsed output map must preserve the same structural component boundaries and counts as the source map.

### 18.5 Operation verification

For each byte operation, the staged output must contain exactly the requested replacement bytes at exactly the resolved range.

For each whole-component replacement, the staged component SHA-256 must equal the replacement artifact SHA-256.

For each replaced compressed overlay, BLZ/runtime-image validation must pass on the staged output representation.

### 18.6 Whole-ROM diff proof

Compute the complete byte-level source → output difference.

Every changed byte must be attributable to exactly one approved resolved operation.

No approved operation may leave a requested byte unchanged unless its requested replacement byte already equals the expected source byte; the implementation plan should reject such no-op byte operations to keep the diff contract simple.

The final verification must prove:

```text
unexpected changed bytes = 0
```

An unexpected changed byte invalidates the entire build.

### 18.7 Untouched content

Because the whole-ROM diff is authoritative, every byte outside approved operation ranges is implicitly proven identical. Reports should additionally summarize untouched components for analyst readability without replacing the byte-level proof.

## 19. Verification evidence

A successful machine-readable report must include at least:

- source ROM path;
- source ROM SHA-256;
- source ROM size;
- output ROM path;
- output ROM SHA-256;
- output ROM size;
- normalized manifest SHA-256;
- deterministic build ID;
- operation count;
- changed component count;
- changed byte count;
- source unchanged result;
- structural metadata unchanged result;
- canonical output parse result;
- unexpected changed byte count;
- compressed-overlay validation results;
- final verification status.

Each operation report must include its canonical target, resolved physical range, guard evidence, replacement evidence, and post-build verification result.

## 20. Error model

Mutation failures should use structured `NdsError` categories consistent with the existing NDS service style.

Required categories include:

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
- `mutation-overlap`;
- `compressed-overlay-invalid`;
- `staging-failed`;
- `post-build-parse-failed`;
- `structural-map-changed`;
- `unexpected-rom-diff`;
- `output-verification-failed`;
- `publish-failed`.

MCP-facing errors should include corrective guidance where a deterministic corrective action exists.

## 21. Internal architecture

Recommended service layout:

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

### 21.1 `manifest.ts`

Responsibilities:

- strict schema parsing;
- normalization;
- safe output filename validation;
- manifest hashing input preparation.

No filesystem mutation.

### 21.2 `selectors.ts`

Responsibilities:

- canonical selector resolution;
- component/range ownership proof;
- runtime-address uniqueness handling;
- structural-range exclusion.

No writes.

### 21.3 `guards.ts`

Responsibilities:

- exact source byte checks;
- component SHA-256 checks;
- replacement artifact existence/hash/size checks;
- compressed replacement preflight validation when practical.

No writes.

### 21.4 `planner.ts`

Responsibilities:

- compile manifest + canonical ROM map into the resolved plan;
- require all preflight checks before returning a buildable plan;
- compute normalized operation metadata and build identity inputs.

No writes.

### 21.5 `conflicts.ts`

Responsibilities:

- physical interval overlap detection;
- whole-component exclusivity checks;
- alias collision detection.

No writes.

### 21.6 `staging.ts`

Responsibilities:

- create controlled temporary build directory;
- copy immutable source ROM to staged ROM path;
- ensure staged and source paths are distinct;
- cleanup failed staging directories.

It does not interpret mutation semantics.

### 21.7 `apply.ts`

Responsibilities:

- apply only fully resolved operations to the staged copy;
- enforce exact write bounds;
- flush/close output safely.

This is the only service module permitted to mutate ROM bytes.

### 21.8 `verify.ts`

Responsibilities:

- source re-hash;
- canonical output reparse;
- size verification;
- structural byte/map comparison;
- per-operation verification;
- compressed-overlay validation;
- complete source/output diff attribution.

No mutation.

### 21.9 `report.ts`

Responsibilities:

- deterministic JSON evidence objects;
- changed-component summary;
- output SHA record;
- no timestamps or nondeterministic fields in reproducibility-critical files unless explicitly separated from deterministic content.

### 21.10 `build.ts`

Responsibilities:

- all-or-nothing orchestration;
- preflight → stage → apply → verify → publish;
- failure cleanup;
- final result construction.

It does not bypass lower-level contracts.

## 22. MCP surface

Milestone 1 exposes only three high-level tools.

### 22.1 `nds_mutation_validate`

Read-only preflight.

Inputs:

- source ROM path under configured workspace;
- mutation manifest path under configured workspace.

Returns:

- manifest identity;
- source ROM identity;
- normalized resolved plan;
- guard results;
- conflict result;
- build ID;
- whether the plan is buildable.

It creates no output ROM.

### 22.2 `nds_mutation_build`

Controlled write operation.

Inputs:

- source ROM path under configured workspace;
- mutation manifest path under configured workspace.

Behavior:

- repeats full preflight rather than trusting an earlier validation call;
- stages a complete copy;
- applies every operation;
- runs full verification;
- atomically publishes the build only after success.

Returns the final build paths and verification summary.

### 22.3 `nds_mutation_verify`

Read-only revalidation of an RE-MCP-produced build.

It accepts controlled identifiers/paths for an existing build under the RE-MCP output root, reloads its source/manifest lineage, and repeats the relevant structural, operation, hash, and diff checks.

It must not become a generic arbitrary two-ROM diff tool.

## 23. Capability reporting

`server_capabilities` must be updated only when the production mutation subsystem is implemented.

The policy description must make clear that:

- mutation requires a strict manifest;
- only same-size canonical component edits/replacements are supported;
- source ROMs remain immutable;
- structural metadata mutation is prohibited;
- compressed overlays may be replaced only as prebuilt exact-size stored components;
- decoded compressed-overlay editing and recompression are not yet supported;
- no arbitrary ROM-offset write or generic filesystem writer exists.

## 24. Testing strategy

Implementation must be TDD-driven and fixture-heavy.

Synthetic NDS fixtures should cover exact component geometry without requiring copyrighted ROMs.

Minimum test matrix:

### 24.1 Manifest

- valid minimal manifest;
- unknown fields rejected;
- malformed/uppercase/non-64-character source hashes rejected according to normalization policy;
- unsafe filenames rejected;
- unsupported versions rejected;
- unsupported operation types rejected.

### 24.2 Selectors

- ARM9 relative edit;
- ARM7 relative edit;
- uncompressed ARM9 overlay edit;
- uncompressed ARM7 overlay edit;
- NitroFS file-ID edit;
- NitroFS path edit;
- unique runtime-address edit;
- ambiguous runtime address rejected;
- range crossing component end rejected;
- structural metadata cannot be selected.

### 24.3 Guards

- exact expected bytes pass;
- stale expected bytes fail;
- exact component SHA passes;
- stale component SHA fails;
- replacement artifact missing;
- replacement artifact hash mismatch;
- replacement size mismatch;
- source ROM hash mismatch;
- source changes between preflight and completion.

### 24.4 Conflicts

- disjoint operations pass;
- one-byte overlap rejected;
- identical overlap rejected;
- containment overlap rejected;
- adjacent ranges pass;
- whole-component + byte edit rejected;
- selector aliases resolving to one physical range rejected.

### 24.5 Mutation

- ARM9 output bytes correct;
- ARM7 output bytes correct;
- overlay output bytes correct;
- NitroFS output bytes correct;
- whole-component replacement correct;
- multiple disjoint operations applied atomically;
- source file byte-identical before/after.

### 24.6 Compressed overlays

- valid exact-size stored replacement accepted;
- invalid BLZ replacement rejected;
- wrong stored size rejected;
- decoded runtime geometry mismatch rejected;
- decoded-runtime byte-edit selector unavailable.

### 24.7 Verification

- canonical output reparse succeeds for valid builds;
- output size mismatch rejected;
- header mutation detected;
- FAT mutation detected;
- FNT mutation detected;
- overlay-table mutation detected;
- unexpected non-target byte mutation detected;
- requested operation not present detected;
- replacement component hash mismatch detected;
- unexpected changed byte count is exactly zero for valid build.

### 24.8 Publication and reproducibility

- failed staging publishes no final build;
- failed apply publishes no final build;
- failed verification publishes no final build;
- two clean identical builds produce byte-identical ROMs;
- deterministic resolved plans and reports are byte-identical for identical inputs;
- build ID is stable for identical inputs;
- changing replacement hash or manifest changes build ID;
- source hash before/after every test remains identical.

## 25. Non-goals and explicit exclusions

Milestone 1 does not implement:

- variable-size replacement;
- ROM repacking or relocation;
- FAT editing;
- FNT editing;
- new/deleted NitroFS files;
- overlay-table editing;
- NDS header editing;
- BLZ compression/recompression;
- decoded compressed-overlay mutation;
- automatic assembly compilation;
- ARM hook synthesis;
- natural-language patch-plan parsing;
- semantic patch compilation;
- multi-patch dependency solving;
- ordered operation layering;
- BPS/xdelta generation;
- automatic emulator launch or gameplay acceptance;
- register or runtime memory writes;
- arbitrary ROM-offset writes;
- arbitrary caller-selected output paths.

## 26. Follow-on milestones

This milestone is the first layer of the broader Agentic ROM Modification Pipeline.

Planned progression:

```text
M1 — Controlled NDS Mutation Core
     same-size guarded mutation → verified complete ROM

M2 — NDS Rebuild + BLZ Recompression
     decoded overlay edits, recompression, variable-size replacement,
     FAT-aware relocation/rebuild

M3 — Patch Compilation + Orchestration
     proven RE findings and multiple patch requirements →
     one conflict-free deterministic mutation/rebuild plan

M4 — Automated Build Verification + Emulator Acceptance
     boot/smoke/runtime checks against produced ROMs

M5 — Full Agentic Patch-Plan Execution
     patch plans + ROM + assets → investigate gaps → implement →
     rebuild → verify → playable modded ROM
```

## 27. Acceptance contract

Milestone 1 is complete only when all of the following are true:

```text
Input:
    one source .nds under configured workspace
    one strict mutation manifest under configured workspace
    optional pinned replacement artifacts under configured workspace

Preflight:
    full source SHA-256 matches
    every selector resolves canonically and uniquely
    every expected-byte/component guard matches
    every replacement artifact hash and size matches
    structural metadata is not targeted
    no operations overlap

Build:
    source ROM is never opened for writing
    complete staged copy is produced
    all operations apply only to resolved ranges
    output ROM size equals source size

Verification:
    source SHA remains unchanged
    output reparses through canonical NDS model
    header/FAT/FNT/overlay tables remain byte-identical
    structural geometry remains unchanged
    each requested mutation is present exactly
    replaced compressed overlays validate as stored BLZ/runtime images
    complete ROM diff attributes every changed byte to one approved operation
    unexpected changed bytes equal zero

Publication:
    no final build appears before verification succeeds
    final directory is atomically published
    output .nds, hashes, resolved plan, and verification evidence are present
    identical inputs yield deterministic ROM output and deterministic evidence
```

This contract intentionally establishes a narrow, fail-closed mutation foundation. Later milestones may broaden what can be rebuilt, but they must preserve the source-identity, transaction, provenance, conflict, containment, and verification guarantees established here.
