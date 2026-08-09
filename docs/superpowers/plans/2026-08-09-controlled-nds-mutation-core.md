# Controlled NDS Mutation Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add RE-MCP's first generic write-capable Nintendo DS subsystem: strict same-size canonical mutations applied only to a staged ROM copy, followed by complete structural/diff verification and atomic publication of a complete `.nds` build.

**Architecture:** A read-only compiler turns one strict workspace manifest into a canonical, guarded, conflict-free physical mutation plan before any write occurs. A separate application layer may write only to a staged source copy; an independent verifier reparses the result, proves structural immutability, verifies every operation, attributes the complete source→output diff, and permits atomic publication only after all checks pass. Existing NDS parsing, address resolution, BLZ/runtime-image, SHA-256, workspace-containment, and atomic-output behavior remain authoritative.

**Tech Stack:** Node.js >=20, TypeScript 5.7, Node `node:test`, Zod 3.23, MCP SDK, existing RE-MCP NDS services, Node `fs/promises`/`crypto`/`path`.

## Global Constraints

- Source ROMs are immutable and are never opened with write access.
- Every manifest requires the exact full lowercase SHA-256 of the source ROM.
- Mutation input is a strict JSON manifest under `RE_MCP_WORKSPACE_ROOT`; no inline arbitrary mutation list is accepted.
- Canonical targets only: ARM9, ARM7, exact ARM9/ARM7 overlay ID, NitroFS file ID, or exact NitroFS path.
- No bare absolute-ROM-offset mutation primitive exists.
- `replace-bytes` requires exact expected original bytes and same-length replacement bytes.
- `replace-component` requires exact original component SHA-256 and a workspace-contained replacement artifact pinned by exact SHA-256 and exact stored size.
- All physical overlap is rejected; Milestone 1 has no ordered layering semantics.
- The first `0x200` header bytes, FAT, FNT, ARM9 overlay table, ARM7 overlay table, component boundaries, file counts, and overlay counts are immutable.
- Output ROM size equals source ROM size exactly.
- Compressed overlays may only be replaced as prebuilt exact-size stored components. Decoded-runtime mutation and BLZ recompression are excluded.
- NitroFS aliases of overlay backing bytes obey the overlay's compression rules; aliases cannot bypass compressed-overlay safety.
- Every changed output byte must belong to exactly one approved physical operation range; unexpected changed bytes must equal zero.
- Final output is confined to `output/nds/<source-sha-prefix>/<build-id>/` beneath the configured workspace.
- The manifest supplies only a simple `.nds` filename, never an output directory.
- Deterministic evidence contains workspace-relative paths only and no timestamps, process IDs, random IDs, or machine-specific absolute paths.
- Identical inputs produce the same normalized manifest, full 64-hex build ID, ROM bytes, and deterministic evidence.
- A pre-existing deterministic build is reused only after fresh full revalidation; divergent/corrupt content is never overwritten or deleted automatically.
- Preserve stored-compressed versus derived-runtime provenance; decoded overlay bytes retain `romOffset: null`.
- Do not add runtime dependencies.
- Do not alter debugger/GDB behavior or claim physical Catalina/DeSmuME acceptance from CI.
- TDD is mandatory: focused RED test → minimal implementation → focused GREEN → typecheck → commit.
- Never merge a PR without explicit user authorization. At each PR gate, verify the exact head/checks/review state and stop for merge approval.

---

## File Map

### New services

```text
src/services/nds/mutation/
├── manifest.ts     # schema, normalization, canonical JSON, manifest hash
├── selectors.ts    # canonical ownership/range resolution + immutable regions
├── guards.ts       # source/original/replacement guards + compressed artifact preflight
├── conflicts.ts    # physical interval collision detection
├── planner.ts      # full read-only preflight + deterministic build ID
├── staging.ts      # controlled temporary/final output paths + source copy
├── apply.ts        # only staged-ROM writer
├── verify.ts       # canonical reparse, structure/op/diff/compressed verification
├── report.ts       # deterministic evidence serialization
└── build.ts        # all-or-nothing build, publication, reverify/reuse
```

### New public tool module

```text
src/tools/nds-mutation.ts
```

Public surface at milestone completion:

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

### Existing files changed

```text
src/services/nds/errors.ts
src/index.ts
scripts/check-install.mjs
README.md
```

## Shared Test Fixture Contract

Task 1 creates `tests/helpers/nds-mutation-fixture.ts`; later tasks may use only this explicitly defined fixture API, not undeclared convenience helpers.

```ts
export interface NdsMutationFixture {
  readonly directory: string;
  readonly romPath: string;
  readonly sourceBytes: Buffer;
  readonly sourceSha256: string;
  readonly map: NdsRomMap;

  readonly arm9RomOffset: number;                 // 0x0200
  readonly arm7RomOffset: number;                 // 0x0600
  readonly ordinaryFileId: number;                // 0
  readonly ordinaryFileRomOffset: number;         // 0x1200
  readonly ordinaryFileSize: number;              // 0x20
  readonly uncompressedOverlayId: number;         // 2
  readonly uncompressedOverlayFileId: number;     // 1
  readonly uncompressedOverlayRomOffset: number;  // 0x1300
  readonly uncompressedOverlaySize: number;       // 0x40
  readonly compressedOverlayId: number;           // 7
  readonly compressedOverlayFileId: number;       // 2
  readonly compressedOverlayRomOffset: number;    // 0x1400
  readonly compressedOverlaySize: number;         // 0x80
  readonly unrelatedRomOffset: number;            // 0x1800

  writeManifestDocument(document: unknown, relativePath?: string): Promise<string>;
  writeArtifact(relativePath: string, bytes: Buffer): Promise<string>;
  flipByte(filePath: string, offset: number): Promise<void>;
}

export async function createMutationFixture(): Promise<NdsMutationFixture>;
```

The fixture is a `0x5000`-byte valid synthetic NDS built with existing `tests/helpers/nds-fixture.ts`. FAT entries are:

```text
file 0: 0x1200..0x1220 ordinary NitroFS asset
file 1: 0x1300..0x1340 ARM9 overlay 2, uncompressed, RAM 0x02200000, size 0x40
file 2: 0x1400..0x1480 ARM9 overlay 7, compressed, RAM 0x02210000
```

FNT names are `asset.bin`, `overlay2.bin`, `overlay7.bin`. Overlay 7 uses `COMPRESSED_ARM_CODE_STORED`/`COMPRESSED_ARM_CODE_DECODED` from `tests/helpers/nds-compressed-code-fixture.ts`, padded to `0x80` stored bytes exactly as existing compressed-overlay tests do. `sourceBytes` is a copy of the bytes written to disk. `writeManifestDocument()` returns a workspace-relative forward-slash path; it only writes JSON and does not invoke production parsing. `writeArtifact()` likewise returns the workspace-relative path. `flipByte()` opens only the named test file and XORs one byte with `0xff`.

## PR Decomposition

- **PR A — Mutation planning foundation:** Tasks 1–4. No ROM write path and no public MCP registration.
- **PR B — Transactional build engine:** Tasks 5–8. Internal staged writer/verifier/publication/revalidation; still no public MCP registration.
- **PR C — MCP/release integration:** Tasks 9–10. Register all three public tools, capabilities, packaging smoke, docs, final regression.

PR A branches from `design/controlled-nds-mutation-core` so the approved spec and this plan ship with the first implementation PR. PR B branches from updated `main` only after PR A is explicitly merged. PR C branches from updated `main` only after PR B is explicitly merged.

---

### Task 1: Strict Manifest Model, Normalization, and Error Taxonomy

**Files:**
- Create: `src/services/nds/mutation/manifest.ts`
- Modify: `src/services/nds/errors.ts`
- Create: `tests/helpers/nds-mutation-fixture.ts`
- Create: `tests/nds-mutation-manifest.test.ts`

**Interfaces:**
- Produces `NdsMutationComponentSelector`, `NdsMutationByteTarget`, `NdsReplaceBytesOperation`, `NdsReplaceComponentOperation`, `NdsMutationManifestV1`, `LoadedNdsMutationManifest`.
- Produces `loadNdsMutationManifest(workspaceRoot: string, requestedPath: string): Promise<LoadedNdsMutationManifest>`.
- Produces `serializeCanonicalMutationManifest(manifest: NdsMutationManifestV1): string`.
- Adds `NdsMutationErrorCategory` to `NdsServiceErrorCategory` but not to read-only `AnyNdsErrorCategory`.

- [ ] **Step 1: Write the failing manifest tests and fixture**

Create the shared fixture exactly as specified above. Then add tests including:

```ts
test("normalizes byte hex and produces stable canonical JSON", async () => {
  const fixture = await createMutationFixture();
  const manifest = {
    format: "re-mcp-nds-mutation",
    formatVersion: 1,
    source: { sha256: fixture.sourceSha256 },
    output: { filename: "test-mod.nds" },
    operations: [{
      type: "replace-bytes",
      target: { component: "arm9", relativeOffset: 4 },
      expected: "AABB",
      replacement: "CCDD",
    }],
  };
  const relative = await fixture.writeManifestDocument(manifest);
  const loaded = await loadNdsMutationManifest(fixture.directory, relative);
  assert.match(loaded.canonicalJson, /"expected":"aabb"/u);
  assert.match(loaded.sha256, /^[0-9a-f]{64}$/u);
  assert.equal(loaded.canonicalJson, serializeCanonicalMutationManifest(loaded.manifest));
});

test("rejects uppercase source SHA and a byte-operation no-op", async () => {
  const fixture = await createMutationFixture();
  const badSha = await fixture.writeManifestDocument({
    format: "re-mcp-nds-mutation",
    formatVersion: 1,
    source: { sha256: fixture.sourceSha256.toUpperCase() },
    output: { filename: "test.nds" },
    operations: [{
      type: "replace-bytes",
      target: { component: "arm9", relativeOffset: 0 },
      expected: "AABB",
      replacement: "aabb",
    }],
  }, "plans/bad.json");
  await assert.rejects(
    loadNdsMutationManifest(fixture.directory, badSha),
    (error: unknown) => error instanceof NdsError
      && error.category === "mutation-manifest-invalid",
  );
});
```

Also test unknown fields at every object level, unsupported format/version, zero operations, odd/empty/nonhex byte strings, mismatched byte lengths, invalid selectors, absolute/traversal/backslash artifact paths, unsafe output filename, non-regular manifest path, manifest path escape, and operation-order canonicalization.

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/nds-mutation-manifest.test.ts
```

Expected: module/helper missing.

- [ ] **Step 3: Add the mutation error union**

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

- [ ] **Step 4: Implement strict Zod parsing**

Define:

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
  readonly replacement: Readonly<{ artifact: string; sha256: string }>;
}
```

All Zod objects are `.strict()`. Source/component/artifact hashes match `/^[0-9a-f]{64}$/`. Byte hex accepts `[0-9A-Fa-f]` only at input, must be even/non-zero/equal-length, then normalizes lowercase. Reject an entire `replace-bytes` operation when normalized expected equals replacement.

Artifact references are portable workspace-relative POSIX strings: no NUL, `\\`, leading `/`, trailing `/`, empty segment, `.` segment, or `..` segment. Output name matches `/^[A-Za-z0-9][A-Za-z0-9._-]{0,122}\.nds$/` and contains no separator.

- [ ] **Step 5: Implement canonical serialization and loading**

Canonicalize objects by lexicographically sorted keys. Canonicalize each normalized operation independently, sort operations lexicographically by that canonical operation string, then serialize the normalized manifest without whitespace/newline.

```ts
export interface LoadedNdsMutationManifest {
  readonly manifestPath: string;             // internal absolute only
  readonly workspaceRelativePath: string;    // deterministic/report safe
  readonly manifest: NdsMutationManifestV1;
  readonly canonicalJson: string;
  readonly sha256: string;
}
```

`loadNdsMutationManifest()` resolves via `resolveInside`, requires a regular file, parses UTF-8 JSON, converts path/JSON/Zod failures to `mutation-manifest-invalid`, normalizes, and hashes canonical UTF-8 bytes with SHA-256.

- [ ] **Step 6: Run GREEN and typecheck**

```bash
node --test --import tsx tests/nds-mutation-manifest.test.ts
npm run typecheck
```

- [ ] **Step 7: Commit**

```bash
git add src/services/nds/errors.ts \
        src/services/nds/mutation/manifest.ts \
        tests/helpers/nds-mutation-fixture.ts \
        tests/nds-mutation-manifest.test.ts
git commit -m "feat: define strict NDS mutation manifests"
```

---

### Task 2: Canonical Target Resolution and Structural Exclusion

**Files:**
- Create: `src/services/nds/mutation/selectors.ts`
- Create: `tests/nds-mutation-selectors.test.ts`

**Interfaces:**
- Consumes `NdsRomMap`, `resolveRuntimeAddress()`, Task-1 selectors.
- Produces `NdsMutationPhysicalRange`, `NdsMutationOverlayOwner`, `NdsResolvedMutationComponent`, `NdsResolvedMutationRange`.
- Produces `resolveNdsMutationComponent(map, selector)`, `resolveNdsMutationByteTarget(map, target, byteLength)`, `ndsImmutableStructuralRanges(map)`, `assertMutationRangeOutsideStructure(map, start, end)`.

- [ ] **Step 1: Write RED selector tests**

```ts
test("resolves an uncompressed overlay relative byte range", async () => {
  const fixture = await createMutationFixture();
  const resolved = resolveNdsMutationByteTarget(
    fixture.map,
    { component: "arm9-overlay", overlayId: fixture.uncompressedOverlayId, relativeOffset: 4 },
    2,
  );
  assert.equal(resolved.romStart, fixture.uncompressedOverlayRomOffset + 4);
  assert.equal(resolved.romEnd, resolved.romStart + 2);
});

test("rejects byte edits through a compressed-overlay NitroFS alias", async () => {
  const fixture = await createMutationFixture();
  assert.throws(
    () => resolveNdsMutationByteTarget(
      fixture.map,
      { component: "nitrofs-file", fileId: fixture.compressedOverlayFileId, relativeOffset: 0 },
      2,
    ),
    (error: unknown) => error instanceof NdsError
      && error.category === "unsupported-mutation-target",
  );
});
```

Also cover ARM9/ARM7 relative targets, NitroFS ID/path equivalence, unknown IDs/paths, unique runtime target, main runtime address overlapping an overlay, exact overlay-ID disambiguation, BSS/runtime-only address, derived compressed runtime address, range crossing component end, and structural overlap.

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/nds-mutation-selectors.test.ts
```

- [ ] **Step 3: Implement physical/component types**

```ts
export interface NdsMutationPhysicalRange {
  readonly start: number;
  readonly end: number;
  readonly label: string;
}

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

export interface NdsResolvedMutationRange {
  readonly component: NdsResolvedMutationComponent;
  readonly relativeOffset: number;
  readonly romStart: number;
  readonly romEnd: number;
  readonly size: number;
}
```

For NitroFS selection, derive overlay owners by file ID across both overlay tables. Sort owners by processor then ID. `compressed` is true for an exact compressed-overlay selector **or** a NitroFS component with any compressed overlay owner.

- [ ] **Step 4: Implement runtime/relative range rules**

- Relative offset is a non-negative safe integer; `relativeOffset + byteLength <= component.size`.
- Main runtime selectors require `resolveRuntimeAddress()` to return one exact `resolved` candidate for that main component. Any main/overlay ambiguity fails `ambiguous-runtime-target`.
- Exact overlay selectors may filter an `ambiguous-runtime-address` result to the requested processor/overlay ID; exactly one `rom-file-backed`, uncompressed candidate is required.
- BSS/runtime-only/derived-overlay runtime candidates cannot become byte-write ranges.
- Byte edits to a compressed overlay or NitroFS backing any compressed overlay fail `unsupported-mutation-target`.

- [ ] **Step 5: Implement immutable structural intervals**

Generate, sort, and merge these non-empty intervals:

```text
[0, min(0x200, fileSize))
FNT
FAT
ARM9 overlay table
ARM7 overlay table
```

`assertMutationRangeOutsideStructure()` rejects any intersection with `structural-metadata-mutation`. Apply it to byte ranges and entire whole-component ranges.

- [ ] **Step 6: Run GREEN and typecheck**

```bash
node --test --import tsx tests/nds-mutation-selectors.test.ts
npm run typecheck
```

- [ ] **Step 7: Commit**

```bash
git add src/services/nds/mutation/selectors.ts tests/nds-mutation-selectors.test.ts
git commit -m "feat: resolve canonical NDS mutation targets"
```

---

### Task 3: Source, Original-Byte, Component, Artifact, and Compressed Guards

**Files:**
- Create: `src/services/nds/mutation/guards.ts`
- Create: `tests/nds-mutation-guards.test.ts`

**Interfaces:**
- Produces `GuardedNdsByteOperation`, `GuardedNdsComponentOperation`, `GuardedNdsMutationOperation`.
- Produces `assertNdsMutationSourceIdentity(map, expectedSha256): Promise<void>`.
- Produces `guardNdsMutationOperation(map, workspaceRoot, index, operation): Promise<GuardedNdsMutationOperation>`.

- [ ] **Step 1: Write RED guard tests**

Use the explicit fixture API. Include exact byte pass/stale failure, source SHA mismatch, component SHA pass/stale failure, artifact missing, artifact hash mismatch, wrong artifact size, no-op whole-component replacement, valid compressed stored replacement, malformed compressed replacement, and compressed NitroFS alias validation.

```ts
test("fails a stale original-byte guard", async () => {
  const fixture = await createMutationFixture();
  await assert.rejects(
    guardNdsMutationOperation(fixture.map, fixture.directory, 0, {
      type: "replace-bytes",
      target: { component: "arm9", relativeOffset: 0 },
      expected: "ffff",
      replacement: "1234",
    }),
    (error: unknown) => error instanceof NdsError
      && error.category === "original-byte-guard-failed",
  );
});
```

Artifact traversal/absolute-path syntax is already rejected by Task 1 and should be tested there rather than bypassing the parsed manifest type here.

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/nds-mutation-guards.test.ts
```

- [ ] **Step 3: Implement source and byte guards**

`assertNdsMutationSourceIdentity()` requires both `map.sha256 === expectedSha256` and a fresh `hashFileSha256(map.romPath) === expectedSha256`; mismatch is `source-rom-mismatch`.

A byte operation resolves through Task 2, opens source read-only, calls existing `readExact()`, and byte-compares against `Buffer.from(expected, "hex")`. Mismatch is `original-byte-guard-failed`.

- [ ] **Step 4: Implement component/artifact guards**

For `replace-component`:

1. resolve the component and structural exclusion;
2. hash exactly `[component.romStart, component.romEnd)` and compare to `expectedOriginalSha256`;
3. resolve `replacement.artifact` with `resolveInside(workspaceRoot, ...)`;
4. require a regular file;
5. require actual replacement SHA equals the manifest SHA;
6. require exact artifact size equals stored component size;
7. reject replacement SHA equal to actual original component SHA as `mutation-manifest-invalid` no-op.

Return both internal absolute artifact path and deterministic workspace-relative artifact path in the guarded operation; only the latter may be serialized later.

- [ ] **Step 5: Validate compressed stored artifacts pre-write**

For every compressed overlay owner, find the canonical overlay record, read the replacement bytes, select `replacementBytes.subarray(0, overlay.compressedSize)`, and call:

```ts
const decoded = decodeNdsBlz(compressedPayload, overlay.ramSize);
if (decoded.bytes.length !== overlay.ramSize) {
  throw new NdsError("compressed-overlay-invalid", "Decoded overlay size mismatch");
}
```

Convert BLZ/geometry failures at this boundary to `compressed-overlay-invalid`. A shared FAT file must validate against every compressed owner.

- [ ] **Step 6: Run GREEN and typecheck**

```bash
node --test --import tsx tests/nds-mutation-guards.test.ts
npm run typecheck
```

- [ ] **Step 7: Commit**

```bash
git add src/services/nds/mutation/guards.ts tests/nds-mutation-guards.test.ts
git commit -m "feat: guard NDS mutation inputs"
```

---

### Task 4: Conflict Detection and Deterministic Read-Only Planning

**Files:**
- Create: `src/services/nds/mutation/conflicts.ts`
- Create: `src/services/nds/mutation/planner.ts`
- Create: `tests/nds-mutation-planner.test.ts`

**Interfaces:**
- Produces `assertNoNdsMutationConflicts(operations): void`.
- Produces `NdsResolvedMutationPlan`.
- Produces `compileNdsMutationPlan(map, workspaceRoot, loadedManifest): Promise<NdsResolvedMutationPlan>`.
- Produces `serializeResolvedNdsMutationPlan(plan): unknown`.

- [ ] **Step 1: Write RED conflict/planner tests**

Test disjoint, adjacent, one-byte overlap, containment, identical overlap, whole-component + byte overlap, overlay-vs-NitroFS physical alias collision, source SHA mismatch, source change during preflight, operation-order normalization, plan serialization with no absolute path, and build-ID stability.

For the alias collision test, create one replacement artifact and two `replace-component` operations: one targets `arm9-overlay` ID 2 and one targets NitroFS file ID 1. Both resolve to `0x1300..0x1340` and must fail `mutation-overlap`.

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/nds-mutation-planner.test.ts
```

- [ ] **Step 3: Implement interval collision detection**

Sort guarded operations by physical start, physical end, normalized operation index. Reject whenever:

```ts
next.romStart < previous.romEnd
```

Adjacent intervals pass. No identical-overlap exception exists.

- [ ] **Step 4: Implement planner sequencing**

`compileNdsMutationPlan()`:

```text
assert source identity
→ require manifest source SHA == map SHA
→ guard every normalized operation
→ reject all physical overlap
→ compute immutable structural ranges
→ fresh source SHA check again
→ build deterministic plan
```

```ts
export interface NdsResolvedMutationPlan {
  readonly sourceRomPath: string;             // internal only
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

Keep normalized operation indices stable; separately sort the returned application view by physical range so application order cannot affect output.

- [ ] **Step 5: Lock the exact build-ID algorithm**

Take actual verified replacement SHA values from component operations in normalized operation-index order:

```ts
const artifactShas = operations
  .filter((op): op is GuardedNdsComponentOperation => op.type === "replace-component")
  .sort((a, b) => a.index - b.index)
  .map((op) => op.replacement.sha256);
```

Build ID is the full lowercase SHA-256 of UTF-8 bytes:

```ts
[
  "re-mcp-nds-mutation-build-v1",
  sourceSha256,
  manifestSha256,
  ...artifactShas,
].join("\0")
```

- [ ] **Step 6: Implement redacted deterministic plan serialization**

`serializeResolvedNdsMutationPlan()` includes workspace-relative source/manifest/artifact paths, canonical component identities, physical ranges, guards, hashes, structural ranges, source identity, manifest hash, build ID, and output name. It must not expose `sourceRomPath` or internal absolute artifact paths.

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

- [ ] **Step 8: Commit**

```bash
git add src/services/nds/mutation/conflicts.ts \
        src/services/nds/mutation/planner.ts \
        tests/nds-mutation-planner.test.ts
git commit -m "feat: compile guarded NDS mutation plans"
```

## PR A Merge Gate

Open PR A to `main` containing the approved spec/plan and Tasks 1–4 only. Verify exact head, CI, Package, changed filenames, and unresolved review threads. **Stop for explicit merge authorization.** PR B must not branch from the unmerged PR-A head.

---

### Task 5: Controlled Staging and the Sole Staged-ROM Writer

**Files:**
- Create: `src/services/nds/mutation/staging.ts`
- Create: `src/services/nds/mutation/apply.ts`
- Create: `tests/nds-mutation-apply.test.ts`

**Interfaces:**
- Produces `NdsMutationStage`, `createNdsMutationStage(plan, workspaceRoot): Promise<NdsMutationStage>`, `cleanupNdsMutationStage(stage): Promise<void>`.
- Produces `NdsMutationApplyIo`, `applyNdsMutationPlan(plan, stage, io?): Promise<void>`.

- [ ] **Step 1: Write RED staging/application tests**

Build a one-operation plan explicitly in the test:

```ts
const expected = fixture.sourceBytes.subarray(
  fixture.arm9RomOffset,
  fixture.arm9RomOffset + 2,
).toString("hex");
const replacement = expected === "1234" ? "5678" : "1234";
const manifestPath = await fixture.writeManifestDocument({
  format: "re-mcp-nds-mutation",
  formatVersion: 1,
  source: { sha256: fixture.sourceSha256 },
  output: { filename: "apply-test.nds" },
  operations: [{
    type: "replace-bytes",
    target: { component: "arm9", relativeOffset: 0 },
    expected,
    replacement,
  }],
});
const loaded = await loadNdsMutationManifest(fixture.directory, manifestPath);
const plan = await compileNdsMutationPlan(fixture.map, fixture.directory, loaded);
```

Then assert source hash unchanged, staged initial hash equals source, staged hash changes after apply, output size unchanged, and expected staged bytes present. Add a second disjoint operation and a whole-component artifact case.

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/nds-mutation-apply.test.ts
```

- [ ] **Step 3: Implement staging**

Final root:

```text
output/nds/<source-sha-prefix>/<build-id>/
```

Temporary root is a sibling named `.<build-id>.tmp-<process-local-unique-suffix>`; the suffix is not serialized or used in build identity. `createNdsMutationStage()` resolves all paths inside workspace, requires staged/source paths differ, creates the temporary directory, copies source read-only to `plan.outputFilename`, fsyncs/closes the staged file, and verifies staged SHA equals `plan.sourceSha256`. Failures are `staging-failed` and remove temp best-effort.

- [ ] **Step 4: Implement the exact failure-injection seam and writer**

```ts
export interface NdsMutationApplyIo {
  open(path: string, flags: "r" | "r+"): Promise<FileHandle>;
}
```

`applyNdsMutationPlan(plan, stage, io = defaultApplyIo)` is the only mutation-package function that opens the staged ROM with `"r+"`.

- `replace-bytes`: positional full write of decoded replacement bytes at resolved `romStart`.
- `replace-component`: open guarded artifact with `"r"`, copy exactly component size in bounded chunks to resolved staged range.
- Do not reinterpret selectors or derive positions from raw manifest data.
- Sync/close staged handle after all operations; require staged size equals `plan.sourceSize`.

The test `NdsMutationApplyIo` throws on the second staged write after recording the first. Assert the source SHA is still unchanged. This seam is test-only injection support, not MCP surface.

- [ ] **Step 5: Add source-contract assertions**

Read `src/services/nds/mutation/*.ts` in the test and assert only `apply.ts` contains an `"r+"` open and that no mutation service exports a generic `(romOffset, bytes)` write API.

- [ ] **Step 6: Run GREEN and typecheck**

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

### Task 6: Independent Output Verification and Whole-ROM Diff Proof

**Files:**
- Create: `src/services/nds/mutation/verify.ts`
- Create: `tests/nds-mutation-verify.test.ts`

**Interfaces:**
- Produces `NdsMutationOperationVerification`, `NdsCompressedOverlayVerification`, `NdsMutationVerificationResult`.
- Produces `verifyNdsMutationOutput(sourceMap, plan, outputRomPath): Promise<NdsMutationVerificationResult>`.

- [ ] **Step 1: Write RED verification tests**

Create a plan/stage/apply sequence explicitly using Task-5 code; do not use an undeclared fixture shortcut. Test valid output, size mismatch, output parse failure, header/FAT/FNT/overlay-table mutation, parser-valid geometry change, missing requested replacement, wrong component replacement hash, one unexpected unrelated byte, valid compressed replacement, invalid compressed output, and source mutation after planning.

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/nds-mutation-verify.test.ts
```

- [ ] **Step 3: Define the exact verification result**

```ts
export interface NdsMutationOperationVerification {
  readonly index: number;
  readonly status: "passed";
  readonly romStart: number;
  readonly romEnd: number;
}

export interface NdsCompressedOverlayVerification {
  readonly processor: "arm9" | "arm7";
  readonly overlayId: number;
  readonly status: "passed";
  readonly runtimeSha256: string;
}

export interface NdsMutationVerificationResult {
  readonly status: "passed";
  readonly sourceSha256: string;
  readonly outputSha256: string;
  readonly sourceSize: number;
  readonly outputSize: number;
  readonly sourceUnchanged: true;
  readonly structuralMetadataUnchanged: true;
  readonly structuralMapUnchanged: true;
  readonly changedByteCount: number;
  readonly unexpectedChangedBytes: 0;
  readonly operations: readonly NdsMutationOperationVerification[];
  readonly compressedOverlays: readonly NdsCompressedOverlayVerification[];
}
```

- [ ] **Step 4: Implement canonical parse/structure/per-operation checks**

Sequence:

1. fresh source SHA must equal plan SHA;
2. output file size must equal source size (`output-verification-failed` otherwise);
3. `readNdsRomMap(outputRomPath)`; parse errors become `post-build-parse-failed`;
4. compare every immutable structural byte interval source→output;
5. compare source/output structural geometry excluding paths and ROM SHA;
6. verify exact replacement bytes for every byte operation;
7. verify exact replacement SHA for every component operation.

Geometry equality includes header fields/executable metadata, FAT entries, filesystem IDs/paths/ranges/sizes, ARM9/ARM7 overlay metadata, executable ranges, file count, and overlay counts. Structural byte/geometry mismatch is `structural-map-changed`; requested output mismatch is `output-verification-failed`.

- [ ] **Step 5: Revalidate compressed replacements from the output map**

For each unique compressed overlay owner of a replaced physical component:

```ts
const runtime = await createNdsOverlayRuntimeContext(outputMap)
  .getCompressedOverlay(owner.processor, owner.overlayId);
```

Require output stored range/size and runtime size/BSS geometry match the unchanged canonical overlay record. Convert mutation-boundary decode/geometry failure to `compressed-overlay-invalid`. Deduplicate owners and sort processor/overlay ID.

- [ ] **Step 6: Implement streaming complete-ROM diff attribution**

Read source/output with read-only file handles in fixed-size chunks. Operations are already non-overlapping physical intervals. For each differing byte, increment `changedByteCount`; if no approved interval contains its absolute offset, increment unexpected count and retain only the first 16 unexpected offsets for the thrown error. Any unexpected count throws `unexpected-rom-diff`.

After all output checks, hash source again. Any source change at any point is `source-rom-mismatch`. Successful return fixes `unexpectedChangedBytes` to literal `0`.

- [ ] **Step 7: Run GREEN and typecheck**

```bash
node --test --import tsx tests/nds-mutation-verify.test.ts
npm run typecheck
```

- [ ] **Step 8: Commit**

```bash
git add src/services/nds/mutation/verify.ts tests/nds-mutation-verify.test.ts
git commit -m "feat: verify complete NDS mutation outputs"
```

---

### Task 7: Deterministic Evidence and Atomic Publication

**Files:**
- Create: `src/services/nds/mutation/report.ts`
- Create: `src/services/nds/mutation/build.ts`
- Create: `tests/nds-mutation-build.test.ts`

**Interfaces:**
- Produces `NdsMutationBuildResult`.
- Produces `buildNdsMutation(map, workspaceRoot, loadedManifest): Promise<NdsMutationBuildResult>`.
- `report.ts` produces pure deterministic byte/string serializers for every evidence file so Task 8 can regenerate them in memory.

- [ ] **Step 1: Write RED transaction/publication tests**

For each test, construct a one-byte ARM9 manifest using `fixture.sourceBytes` as shown in Task 5. Test successful publication, no final directory before verification, cleanup after forced apply/verify failure, source immutability, exact evidence filenames, no absolute paths in evidence, and two fixtures with identical bytes and identical relative layout producing byte-identical ROM/evidence files.

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/nds-mutation-build.test.ts
```

- [ ] **Step 3: Implement pure deterministic evidence serializers**

The final directory contains exactly:

```text
<outputFilename>
mutation-manifest.json
resolved-plan.json
verification.json
changed-components.json
output.sha256
```

`mutation-manifest.json` is pretty-printed normalized manifest data, not original user whitespace/order. Other JSON is `JSON.stringify(value, null, 2) + "\n"` with explicitly constructed stable property order. No internal absolute path is included. `output.sha256` is exactly `<hash>  <outputFilename>\n`.

`changed-components.json` deduplicates physical components and sorts by ROM start then canonical identity.

- [ ] **Step 4: Implement all-or-nothing build orchestration**

`buildNdsMutation()` always compiles full preflight itself. New build path:

```text
compile plan
→ stage source copy
→ apply resolved writes
→ verify complete output
→ write/sync deterministic evidence
→ atomic rename temporary build root to final root
```

Any exception before promotion removes temp best-effort and publishes nothing. Promotion/rename errors become `publish-failed`.

- [ ] **Step 5: Define the build result**

```ts
export interface NdsMutationBuildResult {
  readonly buildId: string;
  readonly reused: boolean;
  readonly outputRoot: string;      // internal absolute; tool sanitizes
  readonly outputRomPath: string;   // internal absolute; tool sanitizes
  readonly outputSha256: string;
  readonly verification: NdsMutationVerificationResult;
}
```

No `reused` flag is serialized into deterministic evidence.

- [ ] **Step 6: Run GREEN and typecheck**

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

### Task 8: Existing-Build Revalidation and Idempotent Reuse

**Files:**
- Modify: `src/services/nds/mutation/build.ts`
- Modify: `src/services/nds/mutation/report.ts`
- Modify: `tests/nds-mutation-build.test.ts`

**Interfaces:**
- Produces `verifyPublishedNdsMutationBuild(map, workspaceRoot, loadedManifest): Promise<NdsMutationBuildResult>`.
- Updates `buildNdsMutation()` to reuse only a freshly revalidated exact deterministic build.

- [ ] **Step 1: Add RED reuse/tamper tests**

Construct the valid manifest explicitly as in Task 5, then:

```ts
const first = await buildNdsMutation(fixture.map, fixture.directory, loaded);
const second = await buildNdsMutation(fixture.map, fixture.directory, loaded);
assert.equal(second.buildId, first.buildId);
assert.equal(second.reused, true);
assert.equal(second.outputSha256, first.outputSha256);
```

Separate tests tamper the output ROM, `mutation-manifest.json`, `resolved-plan.json`, `verification.json`, `changed-components.json`, and `output.sha256`. Each subsequent build/verify must fail `publish-failed` and leave the existing final directory untouched.

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/nds-mutation-build.test.ts
```

- [ ] **Step 3: Implement published-build revalidation**

`verifyPublishedNdsMutationBuild()`:

```text
fresh full preflight from source+manifest+artifacts
→ derive deterministic final root
→ require exactly expected six entries
→ fresh verifyNdsMutationOutput() on published ROM
→ regenerate all expected evidence bytes in memory
→ byte-compare every evidence file
→ return reused:true only on exact success
```

Do not use stored `verification.json` as proof; it is only compared after fresh verification.

- [ ] **Step 4: Integrate reuse into build**

Before staging, if final root is absent, build normally. If final root exists, call published-build revalidation. Exact success returns reused build. Any mismatch becomes `publish-failed`; do not delete, repair, or overwrite that directory.

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

- [ ] **Step 6: Commit**

```bash
git add src/services/nds/mutation/build.ts \
        src/services/nds/mutation/report.ts \
        tests/nds-mutation-build.test.ts
git commit -m "feat: revalidate deterministic NDS builds"
```

## PR B Merge Gate

Branch PR B from `main` only after PR A is explicitly merged. PR B contains Tasks 5–8. Verify exact head, CI, Package, changed filenames, and unresolved review threads. **Stop for explicit merge authorization.** PR C must not branch from the unmerged PR-B head.

---

### Task 9: Public Mutation MCP Surface and Capability Policy

**Files:**
- Create: `src/tools/nds-mutation.ts`
- Create: `tests/nds-mutation-tools.test.ts`
- Modify: `src/index.ts`

**Interfaces:**
- Produces `registerNdsMutationTools(server: McpServer, config: ServerConfig): void`.
- Public tools are exactly `nds_mutation_validate`, `nds_mutation_build`, `nds_mutation_verify`.

- [ ] **Step 1: Write RED registration/schema tests using the existing FakeMcpServer pattern**

```ts
const EXPECTED = [
  "nds_mutation_validate",
  "nds_mutation_build",
  "nds_mutation_verify",
] as const;

assert.deepEqual([...server.tools.keys()].sort(), [...EXPECTED].sort());
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
```

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/nds-mutation-tools.test.ts
```

- [ ] **Step 3: Implement the exact schemas and handlers**

Every tool schema is only:

```ts
{
  rom: z.string().min(1),
  manifest: z.string().min(1),
}
```

Both paths resolve with `resolveInside(config.workspaceRoot, ...)`.

```text
validate: readNdsRomMap → loadNdsMutationManifest → compileNdsMutationPlan → serializeResolvedNdsMutationPlan
build:    readNdsRomMap → loadNdsMutationManifest → buildNdsMutation
verify:   readNdsRomMap → loadNdsMutationManifest → verifyPublishedNdsMutationBuild
```

Tool output converts all internal absolute output paths to workspace-relative forward-slash paths and obeys `config.maxOutputBytes` using the same bounded JSON pattern as existing NDS tools.

- [ ] **Step 4: Implement actionable error mapping**

Add a `switch` covering every `NdsMutationErrorCategory`. At minimum:

```ts
case "original-byte-guard-failed":
  return "Re-run reverse engineering against this exact ROM revision and regenerate the expected bytes; RE-MCP will not apply a stale byte patch.";
case "mutation-overlap":
  return "Resolve patch conflicts before producing the final low-level manifest; Milestone 1 does not layer overlapping operations.";
case "compressed-overlay-invalid":
  return "Provide an exact-size stored BLZ overlay that validates for every canonical overlay owner; decoded-runtime editing and recompression are not supported yet.";
```

Preserve underlying canonical parser/BLZ categories when they escape before the mutation boundary rather than collapsing them to a generic error.

- [ ] **Step 5: Add end-to-end tool tests**

Using the explicit fixture API and a one-byte ARM9 manifest:

1. `validate` returns build ID/plan and creates no `output/nds` tree;
2. `build` publishes the ROM and returns `verification.unexpectedChangedBytes === 0`;
3. `verify` freshly revalidates it;
4. stale source identity returns a structured error;
5. no response contains `fixture.directory` as an absolute path.

- [ ] **Step 6: Register tools and update capabilities**

In `src/index.ts`:

```ts
import { registerNdsMutationTools } from "./tools/nds-mutation.js";
...
registerNdsMutationTools(server, config);
```

Only now update `server_capabilities`:

- mutation policy states strict manifest-only same-size canonical mutation to source copies;
- source remains immutable;
- compressed overlays are exact-size stored replacement only;
- structural mutation, variable-size rebuild, recompression, arbitrary ROM offsets, arbitrary output paths remain prohibited;
- tool list includes exactly the three new mutation tools.

- [ ] **Step 7: Run GREEN/full checks**

```bash
node --test --import tsx tests/nds-mutation-tools.test.ts
npm run typecheck
npm test
npm run build
git diff --check
```

- [ ] **Step 8: Commit**

```bash
git add src/tools/nds-mutation.ts tests/nds-mutation-tools.test.ts src/index.ts
git commit -m "feat: expose controlled NDS mutation tools"
```

---

### Task 10: Package Smoke, Hardening Contract, Documentation, and Final Regression

**Files:**
- Create: `tests/nds-mutation-hardening.test.ts`
- Modify: `scripts/check-install.mjs`
- Modify: `README.md`

**Interfaces:**
- Produces packaged mutation smoke coverage and final Milestone-1 documentation/acceptance evidence.

- [ ] **Step 1: Write RED hardening tests**

Assert from source and behavior:

```text
No nds_mutation_* schema accepts romOffset, outputPath, operations, or inline replacement bytes.
Only apply.ts contains the staged-ROM "r+" open.
No mutation package exports a raw (romOffset, bytes) writer.
server_capabilities lists exactly the three mutation tools and the same-size/manifest/source-immutable limits.
No decoded compressed-overlay mutation/recompression is advertised.
```

```bash
node --test --import tsx tests/nds-mutation-hardening.test.ts
```

Expected: RED until package/docs source contract is complete.

- [ ] **Step 2: Extend package requirements exactly**

Add these built files to the `required` array in `scripts/check-install.mjs`:

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

Require built `dist/index.js` to contain `registerNdsMutationTools(server, config)`.

- [ ] **Step 3: Add an actual packaged mutation smoke**

Inside `scripts/check-install.mjs`, create a temporary valid NDS with existing-style raw Node Buffer header fields, write one manifest containing a guarded 2-byte ARM9 replacement at component-relative offset `0`, then import built modules and run:

```text
readNdsRomMap
→ loadNdsMutationManifest
→ buildNdsMutation
→ verifyPublishedNdsMutationBuild
```

Assert source SHA unchanged, output SHA changed, output size unchanged, verification status `passed`, unexpected changed bytes `0`, and the second build result `reused === true`. Remove the temp workspace in `finally`. This smoke must not invoke Ghidra or DeSmuME.

- [ ] **Step 4: Document the completed Milestone 1 workflow**

Add `Controlled NDS Mutation` to README:

```text
patch requirement may lack implementation facts
→ static/xref/function/Ghidra/decompilation/runtime correlation resolves those facts
→ agent compiles strict machine manifest
→ nds_mutation_validate
→ nds_mutation_build
→ nds_mutation_verify
→ complete structurally verified .nds
```

Include compact JSON examples for both operation types and explicitly document source immutability, exact guards, canonical selectors, no overlap, same-size-only layout, controlled output tree, deterministic evidence, stored compressed-overlay replacement only, and Milestone-2 deferral of decoded edits/recompression/variable-size rebuild.

State that successful structural build verification is not gameplay acceptance and does not close the physical Catalina debugger gate.

- [ ] **Step 5: Run the complete milestone matrix**

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

- [ ] **Step 6: Perform final source/diff audit**

Verify the PR contains no source-ROM writer, arbitrary ROM-offset writer, caller-selected output directory, structural metadata mutation, variable-size replacement, decoded compressed-overlay mutation, BLZ recompression, overlap layering, or debugger/GDB behavior change. Verify every publication route invokes full verification and public paths are workspace-relative.

- [ ] **Step 7: Commit**

```bash
git add tests/nds-mutation-hardening.test.ts scripts/check-install.mjs README.md
git commit -m "docs: complete controlled NDS mutation acceptance"
```

## PR C Merge Gate

Branch PR C from `main` only after PR B is explicitly merged. Verify the exact PR-C head, CI, Package, changed filenames, unresolved review threads, and packaged mutation smoke. **Stop for explicit merge authorization.**

After PR C is merged, Milestone 1 is complete. The next design cycle is **Milestone 2 — NDS Rebuild + BLZ Recompression**; do not begin Milestone-2 implementation without a separate approved design/spec.

---

## Final Acceptance Contract

```text
source .nds + strict manifest + optional pinned artifacts
        ↓
exact source SHA validation
        ↓
canonical target resolution
        ↓
all original-byte/component/artifact guards
        ↓
compressed stored-artifact validation where required
        ↓
zero physical overlaps
        ↓
full source copy to controlled staging
        ↓
only staged copy opened for write
        ↓
all same-size operations applied
        ↓
canonical output reparse
        ↓
header/FAT/FNT/overlay-table bytes unchanged
        ↓
structural geometry unchanged
        ↓
every requested operation verified exactly
        ↓
compressed replacements decode from output map
        ↓
complete source/output diff attribution
        ↓
unexpected changed bytes == 0
        ↓
source SHA unchanged after verification
        ↓
deterministic evidence generated
        ↓
atomic build-directory publication
        ↓
complete verified .nds
```

A pre-existing deterministic build may be reused only after the same source/manifest/artifact preflight, fresh ROM verification, and byte-for-byte evidence regeneration check all pass. Any divergent existing build remains untouched and fails closed.
