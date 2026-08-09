# Controlled NDS Mutation Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add RE-MCP's first generic write-capable Nintendo DS subsystem: strict same-size canonical mutations applied only to a staged ROM copy, followed by complete structural/diff verification and atomic publication of a complete `.nds` build.

**Architecture:** Compile a strict workspace mutation manifest into a fully resolved, guarded, conflict-free plan before any write occurs. A separate staging/application layer may mutate only the staged copy, while an independent verifier reparses the output, proves structural immutability and complete byte-diff attribution, and permits atomic publication only after every check passes. Existing NDS parsing, resolver, BLZ/runtime-image, SHA, workspace-containment, and atomic-output patterns remain authoritative.

**Tech Stack:** Node.js >=20, TypeScript 5.7, Node `node:test`, Zod 3.23, existing RE-MCP NDS parser/resolver/BLZ services, MCP SDK, Node `fs/promises`/`crypto`/`path`.

## Global Constraints

- Source ROMs are immutable and are never opened with write access.
- Every manifest requires the exact full lowercase SHA-256 of the source ROM.
- Mutation input is a strict JSON manifest under `RE_MCP_WORKSPACE_ROOT`; no inline arbitrary mutation list is accepted.
- Targets use canonical NDS ownership only: ARM9, ARM7, exact ARM9/ARM7 overlay ID, NitroFS file ID, or exact NitroFS path.
- No bare absolute-ROM-offset mutation primitive exists.
- `replace-bytes` requires exact expected original bytes and same-length replacement bytes.
- `replace-component` requires exact original component SHA-256 plus a workspace-contained replacement artifact pinned by exact SHA-256 and exact stored size.
- All physical mutation overlap is rejected; Milestone 1 has no ordered layering semantics.
- Core NDS header, FAT, FNT, ARM9 overlay table, ARM7 overlay table, component boundaries, file counts, and overlay counts remain immutable.
- Output ROM size must equal source ROM size exactly.
- Compressed overlays may only be replaced as prebuilt exact-size stored components. Decoded-runtime edits and BLZ recompression are excluded.
- A NitroFS selector that aliases overlay backing bytes must obey the overlay's compression rules; aliases cannot bypass compressed-overlay safety.
- The complete source→output byte diff must attribute every changed byte to exactly one approved operation; unexpected changed bytes must equal zero.
- Final output is confined to `output/nds/<source-sha-prefix>/<build-id>/` beneath the configured workspace.
- The manifest supplies only a simple lowercase-`.nds` output filename, never a destination directory.
- Build metadata used for reproducibility contains workspace-relative paths only and no timestamps, process IDs, or machine-specific absolute paths.
- Identical inputs produce the same normalized manifest, full 64-hex build ID, ROM bytes, and deterministic evidence files.
- If the deterministic final build already exists, it is reused only after full revalidation proves it is exactly the same valid build; divergent/corrupt content is never overwritten.
- Preserve the existing distinction between stored compressed overlay bytes and derived runtime images with `romOffset: null`.
- Do not alter debugger/GDB behavior or claim physical Catalina/DeSmuME acceptance from CI.
- Do not add new runtime dependencies.
- TDD is mandatory: each task begins with a focused failing test and ends with focused verification plus a commit.
- Never merge a PR without explicit user authorization. At each PR gate, stop after exact-head CI/package verification and request merge approval.

---

## File Structure

### New mutation service package

```text
src/services/nds/mutation/
├── manifest.ts     # strict manifest model, canonical normalization, manifest hash
├── selectors.ts    # canonical component/range resolution + structural exclusion
├── guards.ts       # source/original/replacement guards + compressed artifact preflight
├── conflicts.ts    # physical interval collision detection
├── planner.ts      # all read-only preflight + deterministic build identity
├── staging.ts      # temporary build tree and immutable source copy
├── apply.ts        # the only module permitted to write staged ROM bytes
├── verify.ts       # reparse, structural proof, per-op proof, whole-ROM diff attribution
├── report.ts       # deterministic evidence serialization
└── build.ts        # all-or-nothing orchestration, publication, idempotent reuse/reverify
```

### New MCP tool module

```text
src/tools/nds-mutation.ts
```

It owns only:

```text
nds_mutation_validate
nds_mutation_build
nds_mutation_verify
```

### Tests

```text
tests/helpers/nds-mutation-fixture.ts
tests/nds-mutation-manifest.test.ts
tests/nds-mutation-selectors.test.ts
tests/nds-mutation-guards.test.ts
tests/nds-mutation-planner.test.ts
tests/nds-mutation-apply.test.ts
tests/nds-mutation-verify.test.ts
tests/nds-mutation-build.test.ts
tests/nds-mutation-tools.test.ts
tests/nds-mutation-hardening.test.ts
```

### Existing files changed by the milestone

```text
src/services/nds/errors.ts
src/index.ts
scripts/check-install.mjs
README.md
```

## PR decomposition

- **PR A — Mutation planning foundation:** Tasks 1–4. Strict manifest, selectors, guards, conflict detection, deterministic resolved plan. No ROM writer and no public MCP registration.
- **PR B — Transactional build engine:** Tasks 5–8. Staging/application, independent verification, deterministic reporting/publication, revalidation/idempotent reuse. Still no public tool registration.
- **PR C — MCP/release integration:** Tasks 9–10. Register the three public tools, capability policy, package smoke checks, docs, final regression.

PR A should branch from the approved design branch `design/controlled-nds-mutation-core` so the spec and this plan travel with the first implementation PR. PR B must branch from updated `main` only after PR A is explicitly approved and merged. PR C must branch from updated `main` only after PR B is explicitly approved and merged.

---

### Task 1: Define Strict Manifest Parsing and Deterministic Normalization

**Files:**
- Create: `src/services/nds/mutation/manifest.ts`
- Modify: `src/services/nds/errors.ts`
- Create: `tests/helpers/nds-mutation-fixture.ts`
- Create: `tests/nds-mutation-manifest.test.ts`

**Interfaces:**
- Consumes: `resolveInside(workspaceRoot, requestedPath)` from `src/security/paths.ts`.
- Produces:
  - `NdsMutationComponentSelector`
  - `NdsMutationByteTarget`
  - `NdsReplaceBytesOperation`
  - `NdsReplaceComponentOperation`
  - `NdsMutationManifestV1`
  - `LoadedNdsMutationManifest`
  - `loadNdsMutationManifest(workspaceRoot: string, requestedPath: string): Promise<LoadedNdsMutationManifest>`
  - `serializeCanonicalMutationManifest(manifest: NdsMutationManifestV1): string`
  - `NdsMutationErrorCategory` added to the service error union.

- [ ] **Step 1: Write the failing manifest tests**

Create `tests/nds-mutation-manifest.test.ts` with focused cases for valid parsing, strict unknown-field rejection, lowercase SHA policy, byte normalization, no-op rejection, output filename containment, deterministic operation ordering, and workspace manifest containment.

```ts
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import {
  loadNdsMutationManifest,
  serializeCanonicalMutationManifest,
} from "../src/services/nds/mutation/manifest.js";
import { createMutationFixture } from "./helpers/nds-mutation-fixture.js";

test("loads and canonically normalizes one strict mutation manifest", async () => {
  const fixture = await createMutationFixture();
  const manifestPath = path.join(fixture.directory, "plans", "mutation.json");
  await mkdir(path.dirname(manifestPath), { recursive: true });
  await writeFile(manifestPath, JSON.stringify({
    format: "re-mcp-nds-mutation",
    formatVersion: 1,
    source: { sha256: fixture.sourceSha256 },
    output: { filename: "test-mod.nds" },
    operations: [
      {
        type: "replace-bytes",
        target: { component: "arm9", relativeOffset: 4 },
        expected: "AABB",
        replacement: "CCDD",
      },
    ],
  }));

  const loaded = await loadNdsMutationManifest(fixture.directory, "plans/mutation.json");
  assert.equal(loaded.manifest.operations[0]?.type, "replace-bytes");
  assert.match(loaded.sha256, /^[0-9a-f]{64}$/u);
  assert.equal(loaded.canonicalJson, serializeCanonicalMutationManifest(loaded.manifest));
  assert.match(loaded.canonicalJson, /"expected":"aabb"/u);
});

test("rejects uppercase source hashes and no-op byte operations", async () => {
  const fixture = await createMutationFixture();
  await assert.rejects(
    fixture.writeManifest({ sourceSha256: fixture.sourceSha256.toUpperCase() }),
    (error: unknown) => error instanceof NdsError && error.category === "mutation-manifest-invalid",
  );
  await assert.rejects(
    fixture.writeManifest({ expected: "aabb", replacement: "AABB" }),
    (error: unknown) => error instanceof NdsError && error.category === "mutation-manifest-invalid",
  );
});
```

Create `tests/helpers/nds-mutation-fixture.ts` as a thin reusable wrapper around `createNdsFixture()`. It should build a small valid ROM containing ARM9, ARM7, one ordinary NitroFS file, one uncompressed overlay-backed FAT file, and one valid compressed overlay-backed FAT file using the existing compressed-code fixture. The helper should expose `directory`, `romPath`, `sourceSha256`, canonical component offsets, and helpers to write manifests/artifacts without hiding expected test values.

- [ ] **Step 2: Run the focused tests and confirm RED**

Run:

```bash
node --test --import tsx tests/nds-mutation-manifest.test.ts
```

Expected: FAIL because `src/services/nds/mutation/manifest.ts` and `createMutationFixture()` do not exist.

- [ ] **Step 3: Add mutation error categories**

Extend `src/services/nds/errors.ts` with:

```ts
export type NdsMutationErrorCategory =
  | "mutation-manifest-invalid"
  | "source-rom-mismatch"
  | "unsupported-mutation-target"
  | "structural-metadata-mutation"
  | "ambiguous-runtime-target"
  | "original-byte-guard-failed"
  | "original-component-guard-failed"
  | "replacement-artifact-missing"
  | "replacement-artifact-hash-mismatch"
  | "replacement-size-mismatch"
  | "mutation-overlap"
  | "compressed-overlay-invalid"
  | "staging-failed"
  | "post-build-parse-failed"
  | "structural-map-changed"
  | "unexpected-rom-diff"
  | "output-verification-failed"
  | "publish-failed";
```

Add `NdsMutationErrorCategory` to `NdsServiceErrorCategory`, but do not add it to the established read-only `AnyNdsErrorCategory` alias.

- [ ] **Step 4: Implement the strict manifest model**

In `manifest.ts`, define discriminated selectors and operations so impossible selector combinations do not survive parsing:

```ts
export type NdsMutationComponentSelector =
  | { readonly component: "arm9" }
  | { readonly component: "arm7" }
  | { readonly component: "arm9-overlay"; readonly overlayId: number }
  | { readonly component: "arm7-overlay"; readonly overlayId: number }
  | { readonly component: "nitrofs-file"; readonly fileId: number }
  | { readonly component: "nitrofs-path"; readonly filePath: string };

export type NdsMutationByteTarget = NdsMutationComponentSelector & (
  | { readonly relativeOffset: number }
  | { readonly runtimeAddress: number }
);

export interface NdsReplaceBytesOperation {
  readonly type: "replace-bytes";
  readonly target: NdsMutationByteTarget;
  readonly expected: string;
  readonly replacement: string;
}

export interface NdsReplaceComponentOperation {
  readonly type: "replace-component";
  readonly target: NdsMutationComponentSelector;
  readonly expectedOriginalSha256: string;
  readonly replacement: Readonly<{
    artifact: string;
    sha256: string;
  }>;
}
```

Use strict Zod objects/unions. Require source and component SHA strings to match `/^[0-9a-f]{64}$/`. Accept byte hex case-insensitively only at parse time, require even non-zero length, normalize byte hex to lowercase, require expected/replacement lengths to match, and reject an operation whose normalized expected/replacement strings are identical.

Artifact references must be portable workspace-relative POSIX paths: reject NUL, backslash, absolute paths, empty/`.`/`..` path segments, and leading/trailing slash. Output filenames must match:

```ts
/^[A-Za-z0-9][A-Za-z0-9._-]{0,122}\.nds$/
```

and must contain no path separator.

- [ ] **Step 5: Implement canonical serialization and manifest hashing**

Normalize operations by canonical operation JSON, then sort that canonical string lexicographically. Serialize objects with lexicographically sorted object keys and arrays in their normalized order. The canonical manifest string has no whitespace and no trailing newline.

```ts
export interface LoadedNdsMutationManifest {
  readonly manifestPath: string; // internal absolute path only
  readonly workspaceRelativePath: string; // forward-slash normalized
  readonly manifest: NdsMutationManifestV1;
  readonly canonicalJson: string;
  readonly sha256: string;
}
```

`loadNdsMutationManifest()` must resolve the manifest through `resolveInside`, require a regular file, parse UTF-8 JSON, normalize it, and compute:

```ts
createHash("sha256").update(canonicalJson, "utf8").digest("hex")
```

The deterministic report layer must later use `workspaceRelativePath`, never `manifestPath`.

- [ ] **Step 6: Complete the shared mutation fixture helper and run GREEN**

Run:

```bash
node --test --import tsx tests/nds-mutation-manifest.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/services/nds/errors.ts \
        src/services/nds/mutation/manifest.ts \
        tests/helpers/nds-mutation-fixture.ts \
        tests/nds-mutation-manifest.test.ts
git commit -m "feat: define strict NDS mutation manifests"
```

---

### Task 2: Resolve Canonical Mutation Targets and Immutable Structural Ranges

**Files:**
- Create: `src/services/nds/mutation/selectors.ts`
- Create: `tests/nds-mutation-selectors.test.ts`

**Interfaces:**
- Consumes: `NdsRomMap`, `resolveRuntimeAddress()`, and manifest selector types from Task 1.
- Produces:
  - `NdsMutationOverlayOwner`
  - `NdsResolvedMutationComponent`
  - `NdsResolvedMutationRange`
  - `resolveNdsMutationComponent(map, selector)`
  - `resolveNdsMutationByteTarget(map, target, byteLength)`
  - `ndsImmutableStructuralRanges(map)`
  - `assertMutationRangeOutsideStructure(map, start, end)`

- [ ] **Step 1: Write failing selector tests**

Cover ARM9/ARM7 relative targets, overlay targets, NitroFS ID/path targets, unique runtime targets, exact-overlay disambiguation, main-runtime ambiguity rejection, boundary crossing, compressed-overlay byte-edit rejection, and NitroFS aliases of compressed overlay backing.

```ts
test("resolves an exact uncompressed overlay relative byte range", async () => {
  const { map } = await createMutationFixture();
  const target = resolveNdsMutationByteTarget(
    map,
    { component: "arm9-overlay", overlayId: 2, relativeOffset: 4 },
    2,
  );
  assert.equal(target.romStart, target.component.romStart + 4);
  assert.equal(target.romEnd, target.romStart + 2);
  assert.equal(target.component.overlayId, 2);
});

test("rejects byte edits through a NitroFS alias of a compressed overlay", async () => {
  const { map, compressedFileId } = await createMutationFixture();
  assert.throws(
    () => resolveNdsMutationByteTarget(
      map,
      { component: "nitrofs-file", fileId: compressedFileId, relativeOffset: 0 },
      2,
    ),
    (error: unknown) => error instanceof NdsError && error.category === "unsupported-mutation-target",
  );
});
```

- [ ] **Step 2: Run the focused tests and confirm RED**

```bash
node --test --import tsx tests/nds-mutation-selectors.test.ts
```

Expected: FAIL because `selectors.ts` does not exist.

- [ ] **Step 3: Implement canonical component resolution**

Use the canonical map rather than accepting physical offsets from the manifest.

```ts
export interface NdsMutationOverlayOwner {
  readonly processor: "arm9" | "arm7";
  readonly overlayId: number;
  readonly compressed: boolean;
}

export interface NdsResolvedMutationComponent {
  readonly component: NdsMutationComponentSelector["component"];
  readonly processor: "arm9" | "arm7" | null;
  readonly overlayId: number | null;
  readonly fileId: number | null;
  readonly filePath: string | null;
  readonly romStart: number;
  readonly romEnd: number;
  readonly size: number;
  readonly compressed: boolean;
  readonly overlayOwners: readonly NdsMutationOverlayOwner[];
}
```

For NitroFS targets, derive `overlayOwners` by matching the selected FAT `fileId` against both overlay tables. Sort owners by processor then overlay ID for deterministic output.

- [ ] **Step 4: Implement byte-range and runtime-address resolution**

```ts
export interface NdsResolvedMutationRange {
  readonly component: NdsResolvedMutationComponent;
  readonly relativeOffset: number;
  readonly romStart: number;
  readonly romEnd: number;
  readonly size: number;
}
```

Rules:

- `relativeOffset` must be a non-negative safe integer and `relativeOffset + byteLength <= component.size`.
- ARM9/ARM7 runtime addressing is accepted only when `resolveRuntimeAddress()` returns one exact `resolved` candidate matching that main component; if overlays overlap it, reject with `ambiguous-runtime-target`.
- Exact overlay selectors may filter an `ambiguous-runtime-address` result only to their exact processor/overlay ID; exactly one matching `rom-file-backed` uncompressed candidate is required.
- Runtime-only/BSS and `derived-overlay` candidates are not writable byte sources.
- Any byte edit whose selected component is a compressed overlay, or whose NitroFS file is backing any compressed overlay, is rejected with `unsupported-mutation-target`.

- [ ] **Step 5: Implement immutable structural range computation**

Use the exact ranges:

```ts
header: [0, Math.min(0x200, map.fileSize))
fnt: map.header.fnt
fat: map.header.fat
arm9-overlay-table: map.header.arm9OverlayTable
arm7-overlay-table: map.header.arm7OverlayTable
```

Drop zero-length ranges, sort by start/end, merge overlapping/adjacent ranges for byte comparison, and make `assertMutationRangeOutsideStructure()` reject any intersection with `structural-metadata-mutation`.

Apply this check to the complete physical range of both byte targets and whole components. This fails closed on malformed/custom layouts where an otherwise canonical file overlaps metadata.

- [ ] **Step 6: Run selector tests and typecheck**

```bash
node --test --import tsx tests/nds-mutation-selectors.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/services/nds/mutation/selectors.ts \
        tests/nds-mutation-selectors.test.ts
git commit -m "feat: resolve canonical NDS mutation targets"
```

---

### Task 3: Enforce Original and Replacement Guards

**Files:**
- Create: `src/services/nds/mutation/guards.ts`
- Create: `tests/nds-mutation-guards.test.ts`

**Interfaces:**
- Consumes: loaded manifest operations and resolved targets from Tasks 1–2; existing `readExact()`, `hashFileSha256()`, `decodeNdsBlz()`.
- Produces:
  - `GuardedNdsByteOperation`
  - `GuardedNdsComponentOperation`
  - `GuardedNdsMutationOperation`
  - `guardNdsMutationOperation(map, workspaceRoot, index, operation): Promise<GuardedNdsMutationOperation>`
  - `assertNdsMutationSourceIdentity(map, expectedSha256): Promise<void>`

- [ ] **Step 1: Write failing guard tests**

Include exact byte success/failure, component SHA success/failure, missing artifact, artifact path escape, artifact hash mismatch, wrong size, no-op whole-component replacement, valid compressed stored replacement, malformed BLZ replacement, and compressed NitroFS alias validation.

```ts
test("fails before mutation when expected original bytes are stale", async () => {
  const fixture = await createMutationFixture();
  await assert.rejects(
    guardNdsMutationOperation(
      fixture.map,
      fixture.directory,
      0,
      {
        type: "replace-bytes",
        target: { component: "arm9", relativeOffset: 0 },
        expected: "ffff",
        replacement: "1234",
      },
    ),
    (error: unknown) => error instanceof NdsError && error.category === "original-byte-guard-failed",
  );
});
```

- [ ] **Step 2: Run the tests and confirm RED**

```bash
node --test --import tsx tests/nds-mutation-guards.test.ts
```

- [ ] **Step 3: Implement source and byte guards**

`assertNdsMutationSourceIdentity()` must hash `map.romPath` and require both:

```ts
map.sha256 === expectedSha256
actualSha256 === expectedSha256
```

A byte operation must resolve through Task 2, open the source ROM read-only, read exactly the expected range, and compare to `Buffer.from(operation.expected, "hex")` with exact byte equality.

- [ ] **Step 4: Implement component and replacement artifact guards**

For whole-component replacement:

1. resolve the exact canonical component;
2. reject structural overlap;
3. hash the exact stored source component range and compare to `expectedOriginalSha256`;
4. resolve the artifact via `resolveInside(workspaceRoot, operation.replacement.artifact)`;
5. require a regular file;
6. require exact artifact SHA-256;
7. require exact artifact size equal to component stored size;
8. reject a replacement whose actual SHA equals the source component SHA as a no-op.

Return only a workspace-relative forward-slash artifact path in deterministic evidence, while retaining an internal absolute artifact path for later application.

- [ ] **Step 5: Validate compressed replacement artifacts without changing the source**

For every compressed overlay owner of the physical component, read the replacement artifact and validate its stored prefix using the owner metadata:

```ts
const compressedPayload = replacementBytes.subarray(0, overlay.compressedSize);
const decoded = decodeNdsBlz(compressedPayload, overlay.ramSize);
assert.equal(decoded.bytes.length, overlay.ramSize);
```

Convert BLZ/geometry failures to `NdsError("compressed-overlay-invalid", ...)` at this mutation boundary. If one FAT file backs multiple compressed overlays, the artifact must validate for every such owner.

- [ ] **Step 6: Run guard tests and typecheck**

```bash
node --test --import tsx tests/nds-mutation-guards.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/services/nds/mutation/guards.ts \
        tests/nds-mutation-guards.test.ts
git commit -m "feat: guard NDS mutation inputs"
```

---

### Task 4: Compile the Conflict-Free Deterministic Mutation Plan

**Files:**
- Create: `src/services/nds/mutation/conflicts.ts`
- Create: `src/services/nds/mutation/planner.ts`
- Create: `tests/nds-mutation-planner.test.ts`

**Interfaces:**
- Consumes: `LoadedNdsMutationManifest`, guarded operations, immutable structural ranges.
- Produces:
  - `assertNoNdsMutationConflicts(operations)`
  - `NdsResolvedMutationPlan`
  - `compileNdsMutationPlan(map, workspaceRoot, loadedManifest): Promise<NdsResolvedMutationPlan>`
  - `serializeResolvedNdsMutationPlan(plan): unknown` for deterministic/redacted MCP/report output.

- [ ] **Step 1: Write failing planner/conflict tests**

Cover disjoint operations, one-byte overlap, containment, identical overlap, adjacent ranges, whole-component + byte overlap, selector aliases resolving to the same physical range, source SHA mismatch, source mutation during preflight, deterministic operation ordering, and build-ID stability.

```ts
test("rejects physical aliases even when selectors differ", async () => {
  const fixture = await createMutationFixture();
  const loaded = await fixture.loadManifest({
    operations: [
      fixture.replaceUncompressedOverlayById(),
      fixture.replaceSameBackingByNitroFsFileId(),
    ],
  });
  await assert.rejects(
    compileNdsMutationPlan(fixture.map, fixture.directory, loaded),
    (error: unknown) => error instanceof NdsError && error.category === "mutation-overlap",
  );
});
```

- [ ] **Step 2: Run tests and confirm RED**

```bash
node --test --import tsx tests/nds-mutation-planner.test.ts
```

- [ ] **Step 3: Implement physical interval conflict detection**

Sort operations by `romStart`, then `romEnd`, then normalized operation index. Reject whenever:

```ts
next.romStart < previous.romEnd
```

Adjacent ranges (`next.romStart === previous.romEnd`) are allowed. Do not special-case identical replacements: all overlap fails.

- [ ] **Step 4: Implement the read-only planner**

`compileNdsMutationPlan()` must:

1. call `assertNdsMutationSourceIdentity()` before operation work;
2. compare `loadedManifest.manifest.source.sha256` to `map.sha256` and fail with `source-rom-mismatch`;
3. guard every normalized operation;
4. reject every physical conflict;
5. compute immutable structural ranges;
6. hash the source ROM again after preflight and require the same SHA;
7. sort the application view by physical start without changing each normalized operation index.

Define:

```ts
export interface NdsResolvedMutationPlan {
  readonly sourceRomPath: string; // internal only
  readonly sourceWorkspacePath: string;
  readonly sourceSha256: string;
  readonly sourceSha256Prefix: string;
  readonly sourceSize: number;
  readonly manifestWorkspacePath: string;
  readonly manifestSha256: string;
  readonly outputFilename: string;
  readonly buildId: string;
  readonly operations: readonly GuardedNdsMutationOperation[];
  readonly immutableStructuralRanges: readonly NdsMutationPhysicalRange[];
}
```

- [ ] **Step 5: Lock the exact build-ID algorithm**

Use the actual verified artifact SHA values from guarded component operations in normalized operation order. Let:

```ts
artifactShas = planOperations
  .filter((op) => op.type === "replace-component")
  .map((op) => op.replacement.sha256);
```

Compute the full 64-hex build ID as:

```ts
sha256(
  Buffer.from([
    "re-mcp-nds-mutation-build-v1",
    sourceSha256,
    manifestSha256,
    ...artifactShas,
  ].join("\0"), "utf8"),
)
```

where `sha256()` is lowercase hex. No timestamps, paths outside normalized workspace-relative manifest data, process IDs, or random values participate.

- [ ] **Step 6: Implement deterministic/redacted plan serialization**

`serializeResolvedNdsMutationPlan()` must omit internal absolute paths and Buffer objects. It should expose workspace-relative source/manifest/artifact paths, canonical identities, physical ranges, guards/hashes, structural ranges, source identity, manifest hash, build ID, and output filename in stable property order.

- [ ] **Step 7: Run PR-A verification**

```bash
node --test --import tsx \
  tests/nds-mutation-manifest.test.ts \
  tests/nds-mutation-selectors.test.ts \
  tests/nds-mutation-guards.test.ts \
  tests/nds-mutation-planner.test.ts
npm run typecheck
npm test
npm run build
git diff --check
```

Expected: all pass. Confirm no file outside the new planning package/tests plus `errors.ts` and the approved docs changed.

- [ ] **Step 8: Commit**

```bash
git add src/services/nds/mutation/conflicts.ts \
        src/services/nds/mutation/planner.ts \
        tests/nds-mutation-planner.test.ts
git commit -m "feat: compile guarded NDS mutation plans"
```

## PR A merge gate

Create PR A from the implementation branch based on `design/controlled-nds-mutation-core` to `main`. The PR must contain the approved spec/plan plus Tasks 1–4 only. Verify the exact PR head with CI and Package; review changed filenames and unresolved threads; then **stop and request explicit merge authorization**. Do not begin PR B from a stacked branch.

---

### Task 5: Stage an Immutable ROM Copy and Apply Only Resolved Writes

**Files:**
- Create: `src/services/nds/mutation/staging.ts`
- Create: `src/services/nds/mutation/apply.ts`
- Create: `tests/nds-mutation-apply.test.ts`

**Interfaces:**
- Consumes: `NdsResolvedMutationPlan` from Task 4.
- Produces:
  - `NdsMutationStage`
  - `createNdsMutationStage(plan, workspaceRoot): Promise<NdsMutationStage>`
  - `cleanupNdsMutationStage(stage): Promise<void>`
  - `applyNdsMutationPlan(plan, stage): Promise<void>`

- [ ] **Step 1: Write failing staging/application tests**

Cover staged copy identity, source immutability, byte edits, whole-component replacement, multiple disjoint writes, exact output size, failure cleanup, and enforcement that the writer receives only resolved operations.

```ts
test("applies disjoint operations only to the staged ROM", async () => {
  const fixture = await createMutationFixture();
  const sourceBefore = await hashFileSha256(fixture.romPath);
  const plan = await fixture.compilePlanWithArm9AndNitroFsEdits();
  const stage = await createNdsMutationStage(plan, fixture.directory);
  await applyNdsMutationPlan(plan, stage);

  assert.equal(await hashFileSha256(fixture.romPath), sourceBefore);
  assert.notEqual(await hashFileSha256(stage.stagedRomPath), sourceBefore);
});
```

- [ ] **Step 2: Run and confirm RED**

```bash
node --test --import tsx tests/nds-mutation-apply.test.ts
```

- [ ] **Step 3: Implement controlled staging paths**

Final path geometry is fixed:

```text
output/nds/<source-sha-prefix>/<build-id>/
```

The temporary root must be a sibling whose basename begins with `.<build-id>.tmp-`. Only `staging.ts` constructs these paths. The output ROM path inside staging is exactly `plan.outputFilename`.

`createNdsMutationStage()` must:

- resolve the final/staging roots inside `workspaceRoot`;
- require staged and source ROM paths to differ;
- create the temporary directory with exclusive semantics;
- copy the source ROM without opening the source for write;
- fsync/close the staged ROM;
- verify its SHA equals `plan.sourceSha256` before returning.

Convert staging failures to `staging-failed` and best-effort remove the temporary directory.

- [ ] **Step 4: Implement the only staged-ROM writer**

`apply.ts` is the only module permitted to open the staged ROM with `r+`.

For `replace-bytes`, decode `replacement` and perform a complete positional write at the resolved `romStart`.

For `replace-component`, open the already-guarded artifact read-only and copy it into the exact staged component range in bounded chunks. Never derive a new position from manifest data inside `apply.ts`.

After all writes:

```ts
await stagedHandle.sync();
await stagedHandle.close();
```

Then require `stat(stagedRomPath).size === plan.sourceSize`.

- [ ] **Step 5: Add failure injection and source-write regression coverage**

Expose a narrow injected filesystem/writer seam only if tests need it. A forced write failure after one successful staged operation must leave the source hash unchanged; higher-level build cleanup is tested later. Add a source-contract assertion that `apply.ts` never calls `open(plan.sourceRomPath, "r+")` or accepts a caller-selected destination.

- [ ] **Step 6: Run focused tests and typecheck**

```bash
node --test --import tsx tests/nds-mutation-apply.test.ts
npm run typecheck
```

- [ ] **Step 7: Commit**

```bash
git add src/services/nds/mutation/staging.ts \
        src/services/nds/mutation/apply.ts \
        tests/nds-mutation-apply.test.ts
git commit -m "feat: stage and apply NDS mutations"
```

---

### Task 6: Independently Verify Structure, Operations, Compressed Overlays, and the Complete ROM Diff

**Files:**
- Create: `src/services/nds/mutation/verify.ts`
- Create: `tests/nds-mutation-verify.test.ts`

**Interfaces:**
- Consumes: source `NdsRomMap`, `NdsResolvedMutationPlan`, staged/output ROM path, existing `readNdsRomMap()` and `createNdsOverlayRuntimeContext()`.
- Produces:
  - `NdsMutationVerificationResult`
  - `verifyNdsMutationOutput(sourceMap, plan, outputRomPath): Promise<NdsMutationVerificationResult>`

- [ ] **Step 1: Write failing verification tests**

Minimum cases:

- valid byte-edit output passes;
- output size mismatch fails;
- output parse failure maps to `post-build-parse-failed`;
- header/FAT/FNT/overlay-table corruption fails;
- component geometry change fails even if parser accepts it;
- requested byte output missing fails;
- replacement component hash mismatch fails;
- unexpected byte outside all operations fails;
- valid compressed replacement decodes through the staged/output canonical map;
- invalid compressed replacement fails;
- source changed after planning fails;
- valid output reports `unexpectedChangedBytes === 0`.

```ts
test("rejects one unexpected changed byte outside every approved operation", async () => {
  const fixture = await createMutationFixture();
  const { plan, stagedRomPath } = await fixture.buildUnverifiedStage();
  await fixture.flipByte(stagedRomPath, fixture.unrelatedRomOffset);

  await assert.rejects(
    verifyNdsMutationOutput(fixture.map, plan, stagedRomPath),
    (error: unknown) => error instanceof NdsError && error.category === "unexpected-rom-diff",
  );
});
```

- [ ] **Step 2: Run and confirm RED**

```bash
node --test --import tsx tests/nds-mutation-verify.test.ts
```

- [ ] **Step 3: Implement canonical output and structural verification**

`verifyNdsMutationOutput()` must:

1. hash the source and require `plan.sourceSha256` before output work;
2. require exact output size;
3. call `readNdsRomMap(outputRomPath)` and translate parser failures to `post-build-parse-failed`;
4. compare every immutable structural byte range source→output;
5. compare structural geometry excluding expected path/hash differences.

Geometry comparison must include:

```text
header fields and executable ranges
FAT entries
filesystem file IDs/paths/start/end/size
overlay metadata for ARM9 and ARM7
executableRanges
file count
overlay counts
```

Any difference is `structural-map-changed`.

- [ ] **Step 4: Implement per-operation verification**

For byte operations, read the output range and require exact replacement bytes.

For component replacements, hash the exact output stored component range and require the verified replacement SHA.

For every compressed overlay owner of a replaced physical component, construct a fresh runtime context from the **output** map and call:

```ts
await createNdsOverlayRuntimeContext(outputMap).getCompressedOverlay(processor, overlayId);
```

Require stored size/offset and derived runtime geometry to match canonical overlay metadata. Translate mutation-boundary failures to `compressed-overlay-invalid`.

- [ ] **Step 5: Implement streaming complete-ROM diff attribution**

Read source and output in fixed-size chunks instead of loading whole ROMs. Maintain operations sorted by physical range. For every byte where source differs from output:

1. increment `changedByteCount`;
2. find the one containing approved operation interval;
3. if no interval contains it, increment unexpected count and retain at most the first 16 unexpected offsets for the error;
4. because overlap was already rejected, more than one owner is an internal invariant failure.

If unexpected count is non-zero, throw `unexpected-rom-diff`.

The result must include `unexpectedChangedBytes: 0` on success.

- [ ] **Step 6: Revalidate source identity last**

After all output checks, hash the source one more time. A source change at any point invalidates the build with `source-rom-mismatch`, even if output verification otherwise passed.

- [ ] **Step 7: Run verification tests and typecheck**

```bash
node --test --import tsx tests/nds-mutation-verify.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/services/nds/mutation/verify.ts \
        tests/nds-mutation-verify.test.ts
git commit -m "feat: verify complete NDS mutation outputs"
```

---

### Task 7: Emit Deterministic Evidence and Atomically Publish a Verified Build

**Files:**
- Create: `src/services/nds/mutation/report.ts`
- Create: `src/services/nds/mutation/build.ts`
- Create: `tests/nds-mutation-build.test.ts`

**Interfaces:**
- Consumes: planner, staging, application, verifier.
- Produces:
  - `NdsMutationBuildResult`
  - `buildNdsMutation(map, workspaceRoot, loadedManifest): Promise<NdsMutationBuildResult>`
  - deterministic metadata writers/readers used by Task 8.

- [ ] **Step 1: Write failing transaction/publication tests**

Cover successful publication, no final directory before verification, cleanup on staging/apply/verification failure, deterministic metadata, source immutability, and two clean builds in separate workspaces yielding identical output ROM/evidence bytes.

```ts
test("publishes only after full verification succeeds", async () => {
  const fixture = await createMutationFixture();
  const loaded = await fixture.loadValidManifest();
  const result = await buildNdsMutation(fixture.map, fixture.directory, loaded);

  assert.equal(result.verification.status, "passed");
  assert.equal(result.reused, false);
  assert.equal(await hashFileSha256(fixture.romPath), fixture.sourceSha256);
  await readFile(result.outputRomPath);
  await readFile(path.join(result.outputRoot, "verification.json"));
});
```

- [ ] **Step 2: Run and confirm RED**

```bash
node --test --import tsx tests/nds-mutation-build.test.ts
```

- [ ] **Step 3: Implement deterministic report serialization**

The temporary build directory must contain exactly:

```text
<outputFilename>
mutation-manifest.json
resolved-plan.json
verification.json
changed-components.json
output.sha256
```

Use deterministic property order and `JSON.stringify(value, null, 2) + "\n"`. Never serialize internal absolute paths.

`mutation-manifest.json` is the normalized manifest representation, not the user's original whitespace/key order.

`output.sha256` is exactly:

```text
<64-lowercase-hash>  <outputFilename>\n
```

`changed-components.json` deduplicates canonical physical components and sorts them by `romStart`, then component identity.

- [ ] **Step 4: Implement all-or-nothing orchestration**

`buildNdsMutation()` must always recompile full preflight rather than trusting a prior validate result. On a new build:

```text
compile plan
→ create stage
→ apply
→ verify
→ write deterministic evidence
→ fsync required files
→ atomic rename temporary root to final root
```

On any exception before promotion, best-effort remove the temporary root and rethrow the structured error. Translate final rename/promotion failures to `publish-failed`.

The final directory is never created piecemeal.

- [ ] **Step 5: Implement result sanitization**

```ts
export interface NdsMutationBuildResult {
  readonly buildId: string;
  readonly reused: boolean;
  readonly outputRoot: string;       // internal absolute; tools sanitize
  readonly outputRomPath: string;    // internal absolute; tools sanitize
  readonly outputSha256: string;
  readonly verification: NdsMutationVerificationResult;
}
```

Report files store only workspace-relative versions of output/source/manifest/artifact paths.

- [ ] **Step 6: Run build tests and typecheck**

```bash
node --test --import tsx tests/nds-mutation-build.test.ts
npm run typecheck
```

- [ ] **Step 7: Commit**

```bash
git add src/services/nds/mutation/report.ts \
        src/services/nds/mutation/build.ts \
        tests/nds-mutation-build.test.ts
git commit -m "feat: publish verified NDS mutation builds"
```

---

### Task 8: Revalidate Existing Builds and Support Safe Idempotent Reuse

**Files:**
- Modify: `src/services/nds/mutation/build.ts`
- Modify: `src/services/nds/mutation/report.ts`
- Modify: `tests/nds-mutation-build.test.ts`

**Interfaces:**
- Produces:
  - `verifyPublishedNdsMutationBuild(map, workspaceRoot, loadedManifest): Promise<NdsMutationBuildResult>`
  - idempotent exact-build reuse from `buildNdsMutation()`.

- [ ] **Step 1: Add failing existing-build tests**

```ts
test("reuses an existing deterministic build only after full revalidation", async () => {
  const fixture = await createMutationFixture();
  const loaded = await fixture.loadValidManifest();
  const first = await buildNdsMutation(fixture.map, fixture.directory, loaded);
  const second = await buildNdsMutation(fixture.map, fixture.directory, loaded);
  assert.equal(second.buildId, first.buildId);
  assert.equal(second.reused, true);
  assert.equal(second.outputSha256, first.outputSha256);
});

test("never overwrites a corrupt existing build with the same build id", async () => {
  const fixture = await createMutationFixture();
  const loaded = await fixture.loadValidManifest();
  const first = await buildNdsMutation(fixture.map, fixture.directory, loaded);
  await fixture.flipByte(first.outputRomPath, fixture.unrelatedRomOffset);
  await assert.rejects(
    buildNdsMutation(fixture.map, fixture.directory, loaded),
    (error: unknown) => error instanceof NdsError && error.category === "publish-failed",
  );
});
```

Also test tampered `resolved-plan.json`, `verification.json`, `changed-components.json`, and `output.sha256` individually.

- [ ] **Step 2: Run and confirm RED**

```bash
node --test --import tsx tests/nds-mutation-build.test.ts
```

- [ ] **Step 3: Implement published-build revalidation**

`verifyPublishedNdsMutationBuild()` must:

1. compile full current preflight from source + manifest + artifacts;
2. derive the deterministic final directory from source prefix/build ID;
3. require exactly the expected output/evidence filenames;
4. run `verifyNdsMutationOutput()` against the published `.nds`;
5. regenerate the expected deterministic evidence in memory;
6. byte-compare every evidence file with its expected serialization;
7. return `reused: true` only if all checks pass.

Do not trust a previously written `verification.json` as proof.

- [ ] **Step 4: Add exact-reuse behavior to build orchestration**

Before creating a stage, test whether the deterministic final root already exists. If absent, build normally. If present:

- exact revalidation success → return the reused build;
- any content/lineage/evidence mismatch → throw `publish-failed` and leave the existing directory untouched.

Never delete or overwrite a divergent deterministic build automatically.

- [ ] **Step 5: Run full PR-B verification**

```bash
node --test --import tsx \
  tests/nds-mutation-apply.test.ts \
  tests/nds-mutation-verify.test.ts \
  tests/nds-mutation-build.test.ts
npm run typecheck
npm test
npm run build
git diff --check
```

Expected: PASS, including source-before/source-after invariants in every write-capable test.

- [ ] **Step 6: Commit**

```bash
git add src/services/nds/mutation/build.ts \
        src/services/nds/mutation/report.ts \
        tests/nds-mutation-build.test.ts
git commit -m "feat: revalidate deterministic NDS builds"
```

## PR B merge gate

Branch PR B from `main` only after PR A is merged. PR B contains Tasks 5–8. Verify the exact PR head with CI and Package, review the complete diff and unresolved threads, and **stop for explicit merge authorization**. Do not begin PR C from the PR-B branch.

---

### Task 9: Expose the Three Controlled Mutation MCP Tools

**Files:**
- Create: `src/tools/nds-mutation.ts`
- Create: `tests/nds-mutation-tools.test.ts`
- Modify: `src/index.ts`

**Interfaces:**
- Produces public MCP tools:
  - `nds_mutation_validate`
  - `nds_mutation_build`
  - `nds_mutation_verify`
  - `registerNdsMutationTools(server: McpServer, config: ServerConfig): void`

- [ ] **Step 1: Write failing MCP registration/schema tests**

Reuse the existing `FakeMcpServer` pattern from `tests/nds-tools.test.ts`.

```ts
const EXPECTED_MUTATION_TOOLS = [
  "nds_mutation_validate",
  "nds_mutation_build",
  "nds_mutation_verify",
] as const;

test("registers exactly the three controlled NDS mutation tools", () => {
  const server = registerMutationTools("/workspace");
  assert.deepEqual([...server.tools.keys()].sort(), [...EXPECTED_MUTATION_TOOLS].sort());
});

test("mutation tools accept only ROM and manifest workspace paths", () => {
  const server = registerMutationTools("/workspace");
  assert.deepEqual(server.parse("nds_mutation_build", {
    rom: "roms/game.nds",
    manifest: "plans/mod.json",
  }), {
    rom: "roms/game.nds",
    manifest: "plans/mod.json",
  });
  assert.throws(() => server.parse("nds_mutation_build", {
    rom: "roms/game.nds",
    manifest: "plans/mod.json",
    output: "/tmp/game.nds",
  }));
});
```

- [ ] **Step 2: Run and confirm RED**

```bash
node --test --import tsx tests/nds-mutation-tools.test.ts
```

- [ ] **Step 3: Implement bounded structured tool responses**

Each schema contains only:

```ts
{
  rom: z.string().min(1),
  manifest: z.string().min(1),
}
```

Each handler resolves both paths through `resolveInside(config.workspaceRoot, ...)` and never accepts raw byte ranges, operation arrays, output paths, build IDs, or destination directories.

Handlers:

```text
nds_mutation_validate
  readNdsRomMap
  → loadNdsMutationManifest
  → compileNdsMutationPlan
  → serializeResolvedNdsMutationPlan

nds_mutation_build
  readNdsRomMap
  → loadNdsMutationManifest
  → buildNdsMutation

nds_mutation_verify
  readNdsRomMap
  → loadNdsMutationManifest
  → verifyPublishedNdsMutationBuild
```

All returned paths must be converted to workspace-relative forward-slash form before serialization.

- [ ] **Step 4: Add mutation-specific actionable error mapping**

Map every `NdsMutationErrorCategory` to concrete corrective guidance. Examples:

```ts
case "original-byte-guard-failed":
  return "Re-run reverse engineering against this exact ROM revision and regenerate the manifest expected bytes; RE-MCP will not apply a stale byte patch.";
case "mutation-overlap":
  return "Resolve patch conflicts before compiling the final low-level manifest; Milestone 1 does not layer overlapping operations.";
case "compressed-overlay-invalid":
  return "Provide an exact-size prebuilt stored BLZ overlay that decodes successfully for every canonical overlay owner; decoded-runtime editing/recompression is not supported yet.";
```

Underlying canonical parser/BLZ errors remain structured rather than being collapsed to generic mutation failures.

- [ ] **Step 5: Add end-to-end tool tests**

Invoke all three tools against a synthetic fixture:

1. `validate` returns a buildable resolved plan and creates no `output/nds` tree;
2. `build` publishes the new ROM and reports `unexpectedChangedBytes: 0`;
3. `verify` revalidates the published build;
4. a stale source hash produces a structured `source-rom-mismatch`/identity error;
5. tool output never contains the host temp directory prefix or another absolute path.

- [ ] **Step 6: Register the tool module and update capability policy**

Modify `src/index.ts`:

```ts
import { registerNdsMutationTools } from "./tools/nds-mutation.js";
...
registerNdsMutationTools(server, config);
```

Update `server_capabilities` only now, when the full production subsystem exists:

- mutation policy: strict manifest-only, same-size canonical mutations to immutable source copies;
- compressed overlays: stored exact-size replacement only;
- structural metadata/variable-size/recompression/arbitrary offset writes still prohibited;
- add the three new tool names to the tool list.

- [ ] **Step 7: Run focused and full checks**

```bash
node --test --import tsx tests/nds-mutation-tools.test.ts
npm run typecheck
npm test
npm run build
git diff --check
```

- [ ] **Step 8: Commit**

```bash
git add src/tools/nds-mutation.ts \
        tests/nds-mutation-tools.test.ts \
        src/index.ts
git commit -m "feat: expose controlled NDS mutation tools"
```

---

### Task 10: Harden Packaging, Document the Contract, and Run Final Regression

**Files:**
- Create: `tests/nds-mutation-hardening.test.ts`
- Modify: `scripts/check-install.mjs`
- Modify: `README.md`

**Interfaces:**
- Consumes: complete Milestone 1 service/tool surface.
- Produces: package-level source contract, packaged mutation smoke test, user-facing mutation documentation, final acceptance evidence.

- [ ] **Step 1: Write failing hardening/package contract tests**

`tests/nds-mutation-hardening.test.ts` should inspect source/tool text where useful and execute behavior where possible. It must assert:

- no MCP schema named `nds_mutation_*` accepts `romOffset`, `outputPath`, `operations`, or raw replacement bytes;
- `apply.ts` is the only mutation-package module containing an `r+` ROM open;
- source ROM is never passed as the staged destination;
- `server_capabilities` lists exactly the three mutation tools and describes same-size/manifest/source-immutable limits;
- decoded compressed overlay mutation/recompression is not advertised.

Run:

```bash
node --test --import tsx tests/nds-mutation-hardening.test.ts
```

Expected: initially FAIL until packaging/docs/index source contract is complete.

- [ ] **Step 2: Extend packaged-file requirements**

Add at least these paths to `scripts/check-install.mjs` required files:

```text
dist/services/nds/mutation/manifest.js
dist/services/nds/mutation/selectors.js
dist/services/nds/mutation/guards.js
dist/services/nds/mutation/conflicts.js
dist/services/nds/mutation/planner.js
dist/services/nds/mutation/staging.js
dist/services/nds/mutation/apply.js
dist/services/nds/mutation/verify.js
dist/services/nds/mutation/report.js
dist/services/nds/mutation/build.js
dist/tools/nds-mutation.js
```

Also require built `dist/index.js` to contain:

```js
registerNdsMutationTools(server, config)
```

- [ ] **Step 3: Add a packaged mutation smoke test**

In `scripts/check-install.mjs`, create a small temporary valid NDS fixture using only Node APIs, then import the built mutation modules. Build a strict manifest with one guarded ARM9 same-size byte edit and run the packaged path:

```text
readNdsRomMap
→ loadNdsMutationManifest
→ buildNdsMutation
→ verifyPublishedNdsMutationBuild
```

Assert:

- source hash remains unchanged;
- output hash differs;
- output size equals source size;
- verification status is `passed`;
- unexpected changed bytes are zero;
- second build returns `reused: true`;
- cleanup removes the temp workspace after smoke completion.

The packaged smoke must not require Ghidra or DeSmuME.

- [ ] **Step 4: Document Milestone 1 in README**

Add a `Controlled NDS Mutation` section explaining:

```text
patch requirement may be incomplete
→ use static/Ghidra/runtime RE to prove missing facts
→ compile strict mutation manifest
→ nds_mutation_validate
→ nds_mutation_build
→ nds_mutation_verify
→ complete verified .nds
```

Document the two operation forms with compact JSON examples. Explicitly state:

- no source in-place mutation;
- no arbitrary ROM offsets;
- no structural metadata edits;
- same-size only;
- exact guards mandatory;
- no overlaps;
- replacement artifacts remain workspace-contained and hash-pinned;
- compressed overlays are stored-component replacement only;
- decoded edits/recompression/variable-size rebuild are Milestone 2;
- successful builds live under `output/nds/<source-prefix>/<build-id>/` with deterministic evidence.

Do not imply that a successful structural build proves gameplay behavior or that the pending physical Catalina debugger gate has passed.

- [ ] **Step 5: Run the complete Milestone 1 acceptance matrix**

```bash
node --test --import tsx \
  tests/nds-mutation-manifest.test.ts \
  tests/nds-mutation-selectors.test.ts \
  tests/nds-mutation-guards.test.ts \
  tests/nds-mutation-planner.test.ts \
  tests/nds-mutation-apply.test.ts \
  tests/nds-mutation-verify.test.ts \
  tests/nds-mutation-build.test.ts \
  tests/nds-mutation-tools.test.ts \
  tests/nds-mutation-hardening.test.ts
npm run typecheck
npm test
npm run build
node scripts/check-install.mjs .
git diff --check
```

Expected: zero failures.

- [ ] **Step 6: Perform the final source/diff audit**

Before opening PR C, verify:

```text
No source-ROM write primitive exists.
No arbitrary ROM-offset write primitive exists.
No caller-selected output directory exists.
No structural metadata mutation path exists.
No variable-size replacement exists.
No decoded compressed-overlay mutation/recompression exists.
No overlap layering exists.
All final publication routes pass through full verification.
All public output paths are workspace-relative.
No debugger/GDB behavior changed.
```

- [ ] **Step 7: Commit**

```bash
git add tests/nds-mutation-hardening.test.ts \
        scripts/check-install.mjs \
        README.md
git commit -m "docs: complete controlled NDS mutation acceptance"
```

## PR C merge gate

Branch PR C from `main` only after PR B is explicitly approved and merged. Open the final Milestone 1 PR, then on its exact head verify CI, Package, changed filenames, review threads, and package smoke evidence. **Stop and request explicit merge authorization.**

After PR C is merged, Milestone 1 is complete and the next design cycle is **Milestone 2 — NDS Rebuild + BLZ Recompression**; do not start Milestone 2 implementation without its own approved design/spec.

---

## Final Acceptance Contract

Milestone 1 is complete only when this exact flow succeeds:

```text
source .nds + strict manifest + optional pinned artifacts
        ↓
exact source SHA validation
        ↓
canonical target resolution
        ↓
all byte/component/artifact guards
        ↓
compressed stored-artifact validation where required
        ↓
zero mutation overlaps
        ↓
full source copy to controlled staging
        ↓
only staged copy opened for write
        ↓
all same-size operations applied
        ↓
output canonical NDS reparse
        ↓
header/FAT/FNT/overlay-table bytes unchanged
        ↓
structural geometry unchanged
        ↓
every operation verified exactly
        ↓
compressed replacements decode from output map
        ↓
complete source/output diff attribution
        ↓
unexpected changed bytes == 0
        ↓
source SHA still unchanged
        ↓
deterministic evidence written
        ↓
atomic build-directory publication
        ↓
complete verified .nds
```

A pre-existing deterministic build may be reused only after the same source/manifest/artifact preflight, fresh ROM verification, and byte-for-byte evidence regeneration check all pass. Any divergent existing build remains untouched and causes a fail-closed error.
