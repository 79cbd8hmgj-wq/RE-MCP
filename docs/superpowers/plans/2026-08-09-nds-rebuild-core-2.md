# NDS Rebuild Core 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the merged controlled NDS mutation engine with deterministic append-only variable-size NitroFS rebuilding, constrained NitroFS extension files, decoded compressed-overlay replacement, deterministic BLZ recompression, and full rebuild-aware verification without weakening the immutable-source or single-writer safety model.

**Architecture:** Preserve manifest v1 and its build identity exactly. Manifest v2 compiles semantic operations into a complete append-only layout plan: changed/new FAT payloads first, then rebuilt FNT/FAT/overlay tables, exact header rewrites, and deterministic `0xFF` capacity padding. `apply.ts` remains the sole staged-ROM writer; validation/planning performs all selector, guard, BLZ, ID, layout, checksum, and conflict decisions before materialization.

**Tech Stack:** TypeScript 5.7, Node.js 20+, Node `Buffer`/`crypto`/`fs/promises`, Zod 3.23, existing canonical NDS parser/FAT/FNT/overlay/BLZ services, Node test runner + `tsx`, deterministic JSON, GitHub CI/package workflows.

## Global Constraints

- Source ROM is immutable and is never opened for writing.
- Full source SHA-256 is mandatory and must be revalidated before planning/materialization and after verification.
- Public MCP surface remains exactly `nds_mutation_validate`, `nds_mutation_build`, and `nds_mutation_verify`, with only `rom` and `manifest` input paths.
- `formatVersion: 1` semantics, canonical JSON meaning, build identity, output structure, and verification behavior remain byte-for-byte compatible with merged Milestone 1.
- `formatVersion: 2` adds exactly `replace-nitrofs-file`, `add-nitrofs-file`, and `replace-decoded-overlay`; v2 also accepts the two v1 operation types.
- No caller-selected physical ROM offsets, new file IDs, directory IDs, output offsets, alignments, capacity values, BLZ parameters, raw FAT/FNT writes, or arbitrary header writes.
- Existing file IDs, existing NitroFS paths, and existing directory IDs never change.
- New NitroFS files are permitted only below source-absent top-level extension subtrees.
- Existing ARM9/ARM7 ROM offsets, runtime addresses, entry points, initialized sizes, overlay runtime addresses, overlay `ramSize`, overlay `bssSize`, static initializer ranges, overlay IDs, overlay file IDs, and overlay flags remain unchanged.
- A decoded compressed-overlay replacement must be exactly the canonical initialized `ramSize`; BSS is not part of the replacement artifact.
- Core 2 never allocates source gaps or reclaims source payload/table bytes.
- Rebuild tail begins at `alignUp(sourceSize, 0x200)` and uses deterministic `0xFF` padding.
- Relocated/new payload starts are `0x200` aligned. Rebuilt metadata table starts are 4-byte aligned.
- V2 final ROM size is a deterministic NDS device-capacity boundary and must not exceed **512 MiB**.
- V2 total growth beyond source size must not exceed **128 MiB**.
- One replacement artifact must not exceed **64 MiB**.
- At most **256** new files may be added in one manifest and their total payload bytes must not exceed **64 MiB**.
- Rebuilt FNT and rebuilt FAT must each be at most **4 MiB**.
- Existing BLZ limits remain **16 MiB stored / 16 MiB decoded**, with **64 MiB aggregate decoded-overlay validation**.
- Overlay packed compressed size must fit `0x00ff_ffff`.
- FNT directory count remains `<= 0x1000`; new file IDs must remain representable by the FNT `u16 firstFileId` model (`final FAT count <= 0x10000`).
- All planned ROM offsets/end offsets must fit unsigned 32-bit addressable file geometry and JavaScript safe integers.
- `apply.ts` remains the only mutation module that may open a staged ROM with `"r+"`.
- No external BLZ compressor executable or environment-dependent compression library is permitted.
- Failure before publication exposes no final build directory; an existing deterministic build is reused only after fresh complete verification.
- Every source-prefix changed byte and every output-tail byte must be attributed. Final `unexpectedChangedBytes` must be `0`.
- Core 2 remains native-independent: no DeSmuME/GDB/Ghidra acceptance is required for this milestone.

## PR / Merge Boundaries

Implement in four dependent PRs. Each PR branches from `main` **after the preceding PR is reviewed and merged**.

1. **PR A — V2 format and structural serializers:** Tasks 1–4.
2. **PR B — BLZ, overlay, layout, and v2 planning:** Tasks 5–8.
3. **PR C — Single-writer materialization and semantic verifier:** Tasks 9–10.
4. **PR D — Deterministic evidence, package smoke, public hardening, docs:** Tasks 11–12.

Do not stack later implementation PRs on an unmerged predecessor. Each PR must pass CI and Package before its merge gate.

---

## File Responsibility Map

### Create

```text
src/services/nds/header-rebuild.ts
    Full 0x160-byte rebuild-critical header snapshot, NDS header CRC16,
    device-capacity selection, exact owned-field rewrite serialization.

src/services/nds/fnt-serialize.ts
    Deterministic serializer for source filesystem semantics plus constrained
    append-only extension subtrees.

src/services/nds/fat-serialize.ts
    Deterministic FAT serializer from final file-ID/range records.

src/services/nds/overlays-serialize.ts
    Deterministic source-order overlay-table serializer with only approved
    compressed-size field substitutions.

src/services/nds/blz-encode.ts
    Repository-owned deterministic backwards-LZ BLZ encoder and round-trip
    result contract paired to decodeNdsBlz().

src/services/nds/mutation/filesystem-plan.ts
    V2 existing-file target guards, new path tree validation, deterministic
    directory/file ID assignment, final filesystem semantic plan.

src/services/nds/mutation/overlay-plan.ts
    Decoded-overlay source/runtime guards, replacement artifact validation,
    deterministic BLZ encoding, final overlay stored-payload plan.

src/services/nds/mutation/layout.ts
    Append-only segment allocator, alignment, hard limits, logical used size,
    device-capacity padding geometry.

src/services/nds/mutation/header-plan.ts
    Exact source-header guard bytes and final owned-field/checksum rewrite plan.

src/services/nds/mutation/verify-v2.ts
    Rebuild-specific prefix/tail, filesystem, overlay, header, capacity,
    operation, and source-identity verification.

src/services/nds/mutation/report-v2.ts
    V2 changed-component and rebuild-layout deterministic evidence serialization.

tests/nds-mutation-manifest-v2.test.ts
tests/nds-header-rebuild.test.ts
tests/nds-fnt-serialize.test.ts
tests/nds-fat-serialize.test.ts
tests/nds-blz-encode.test.ts
tests/nds-overlay-rebuild.test.ts
tests/nds-rebuild-layout.test.ts
tests/nds-mutation-planner-v2.test.ts
tests/nds-mutation-apply-v2.test.ts
tests/nds-mutation-verify-v2.test.ts
tests/nds-mutation-build-v2.test.ts
tests/nds-rebuild-hardening.test.ts
```

### Modify

```text
src/services/nds/mutation/manifest.ts
src/services/nds/mutation/guards.ts
src/services/nds/mutation/conflicts.ts
src/services/nds/mutation/planner.ts
src/services/nds/mutation/staging.ts
src/services/nds/mutation/apply.ts
src/services/nds/mutation/verify.ts
src/services/nds/mutation/report.ts
src/services/nds/mutation/build.ts
src/services/nds/errors.ts
tests/helpers/nds-mutation-fixture.ts
tests/nds-mutation-build.test.ts
scripts/check-nds-mutation-install.mjs
.github/workflows/package.yml
README.md
```

The existing parser files (`header.ts`, `fat.ts`, `fnt.ts`, `overlays.ts`) remain parser-focused. New serializers/rebuild helpers are separate modules rather than turning parsers into mixed read/write modules.

---

### Task 1: Add Manifest V2 Types and Strict Parsing Without Changing V1

**Files:**
- Modify: `src/services/nds/mutation/manifest.ts`
- Modify: `tests/helpers/nds-mutation-fixture.ts`
- Create: `tests/nds-mutation-manifest-v2.test.ts`
- Test: `tests/nds-mutation-manifest.test.ts`

**Interfaces:**
- Produces:
  - `NdsMutationManifestV1` unchanged.
  - `NdsMutationManifestV2`.
  - `NdsMutationManifest = NdsMutationManifestV1 | NdsMutationManifestV2`.
  - `NdsReplaceNitroFsFileOperation`.
  - `NdsAddNitroFsFileOperation`.
  - `NdsReplaceDecodedOverlayOperation`.
  - `LoadedNdsMutationManifest.manifest: NdsMutationManifest`.
- Existing `serializeCanonicalJson()` remains unchanged and is the canonical serializer for both versions.

- [ ] **Step 1: Extend the test fixture writer with an explicit manifest version.**

Add to `MutationManifestOverrides`:

```ts
readonly formatVersion?: 1 | 2;
```

and write:

```ts
formatVersion: overrides.formatVersion ?? 1,
```

Do not change the default; every existing test must still create v1 unless it opts into v2.

- [ ] **Step 2: Write RED v2 schema tests.**

Create table-driven tests that load these valid operations under `formatVersion: 2`:

```ts
{
  type: "replace-nitrofs-file",
  target: { fileId: 0 },
  expectedOriginalSha256: "a".repeat(64),
  replacement: { artifact: "patches/file.bin", sha256: "b".repeat(64) },
}

{
  type: "add-nitrofs-file",
  path: "re_mcp/attributes/i2dt.bin",
  replacement: { artifact: "patches/i2dt.bin", sha256: "c".repeat(64) },
}

{
  type: "replace-decoded-overlay",
  target: { processor: "arm9", overlayId: 7 },
  expectedStoredSha256: "d".repeat(64),
  expectedRuntimeSha256: "e".repeat(64),
  replacement: { artifact: "patches/overlay7-runtime.bin", sha256: "f".repeat(64) },
}
```

Assert normalized output preserves lowercase hashes, exact operation order, and exact path text.

- [ ] **Step 3: Add RED rejection cases with exact categories.**

Every case must reject as `mutation-manifest-invalid`:

```text
v1 containing any v2-only operation
unknown formatVersion 0, 3, or string "2"
unknown operation field
replace-nitrofs-file with both fileId and filePath
replace-nitrofs-file with neither fileId nor filePath
add-nitrofs-file with a numeric fileId or directoryId field
add-nitrofs-file path beginning '/', containing '\\', empty segment, '.' or '..'
replace-decoded-overlay with processor other than arm9/arm7
uppercase expected/runtime/artifact hashes
inline replacement bytes instead of artifact path
caller-selected romOffset/outputOffset/alignment/compressedSize fields
```

- [ ] **Step 4: Add a v1 canonical-regression vector before implementation.**

For one existing v1 fixture, assert its canonical JSON string and SHA-256 are exactly equal before and after the v2 parser work. Store the literal expected string/hash in the test; do not regenerate the expected hash with the implementation under test.

- [ ] **Step 5: Run the RED tests.**

```bash
node --test --import tsx tests/nds-mutation-manifest-v2.test.ts
```

Expected: v2 manifests fail because `formatVersion` currently accepts only `1`.

- [ ] **Step 6: Implement discriminated v1/v2 strict schemas.**

Use separate Zod top-level schemas:

```ts
const manifestV1Schema = z.object({
  format: z.literal("re-mcp-nds-mutation"),
  formatVersion: z.literal(1),
  source: sourceSchema,
  output: outputSchema,
  operations: z.array(v1OperationSchema).min(1).max(4096),
}).strict();

const manifestV2Schema = z.object({
  format: z.literal("re-mcp-nds-mutation"),
  formatVersion: z.literal(2),
  source: sourceSchema,
  output: outputSchema,
  operations: z.array(v2OperationSchema).min(1).max(4096),
}).strict();

const manifestSchema = z.discriminatedUnion("formatVersion", [
  manifestV1Schema,
  manifestV2Schema,
]);
```

Keep the existing v1 operation normalization code path unchanged. Add dedicated normalizers for the three v2 operation types.

- [ ] **Step 7: Enforce lexical new-path validation at parse time.**

`add-nitrofs-file.path` must be a portable POSIX relative path whose segments are printable ASCII bytes `0x20..0x7e`, 1–127 bytes each, not `.`/`..`, with a total canonical path length `<= 4096`. Source collisions and top-level-subtree ownership are planner checks, not parser checks.

- [ ] **Step 8: Run focused and full mutation tests.**

```bash
node --test --import tsx tests/nds-mutation-manifest.test.ts tests/nds-mutation-manifest-v2.test.ts
npm run typecheck
```

Expected: PASS, including the frozen v1 canonical hash.

- [ ] **Step 9: Commit.**

```bash
git add src/services/nds/mutation/manifest.ts \
        tests/helpers/nds-mutation-fixture.ts \
        tests/nds-mutation-manifest-v2.test.ts \
        tests/nds-mutation-manifest.test.ts
git commit -m "feat: add NDS mutation manifest v2"
```

---

### Task 2: Add Rebuild-Critical Header, CRC16, Used-Size, and Capacity Helpers

**Files:**
- Create: `src/services/nds/header-rebuild.ts`
- Create: `tests/nds-header-rebuild.test.ts`
- Modify: `src/services/nds/errors.ts`
- Test: `tests/nds-header.test.ts`

**Interfaces:**
- Produces:

```ts
export const NDS_REBUILD_HEADER_BYTES = 0x160;
export const MAX_NDS_REBUILT_ROM_BYTES = 512 * 1024 * 1024;

export interface NdsRebuildHeaderSnapshot {
  readonly bytes: Buffer;
  readonly deviceCapacity: number;
  readonly romUsedSize: number;
  readonly headerSize: number;
  readonly headerCrc16: number;
}

export function crc16NdsHeader(bytes: Uint8Array): number;
export function ndsCapacityBytes(deviceCapacity: number): number;
export function selectNdsDeviceCapacity(logicalUsedSize: number): {
  readonly deviceCapacity: number;
  readonly capacityBytes: number;
};
export async function readNdsRebuildHeader(romPath: string): Promise<NdsRebuildHeaderSnapshot>;
export function serializeNdsRebuildHeader(
  source: NdsRebuildHeaderSnapshot,
  rewrites: NdsOwnedHeaderRewriteInput,
): Buffer;
```

Owned offsets are fixed constants:

```text
0x14      u8   device capacity
0x40..47       FNT offset/size
0x48..4F       FAT offset/size
0x50..57       ARM9 overlay table offset/size
0x58..5F       ARM7 overlay table offset/size
0x80..83  u32  logical/used ROM size
0x84..87  u32  header size (read/preserve only)
0x15E..15F u16 header CRC16
```

Header CRC is calculated over bytes `0x000..0x15D` using reflected polynomial `0xA001`, initial value `0xFFFF`, with the resulting 16-bit value written little-endian at `0x15E`.

Device-capacity byte `n` represents `128 KiB << n`. Core 2 permits codes only where the resulting capacity is `<= 512 MiB`; `selectNdsDeviceCapacity()` chooses the smallest representable capacity containing `logicalUsedSize`.

- [ ] **Step 1: Write CRC RED tests with a standalone reference helper inside the test.**

The test reference implementation must be local to the test and structurally independent from production. Assert a fixed 0x15E-byte deterministic vector produces one literal expected CRC recorded in the test after calculating it once with the reference helper.

Also flip one covered byte and assert CRC changes.

- [ ] **Step 2: Write capacity RED tests.**

Assert:

```ts
assert.equal(ndsCapacityBytes(0), 128 * 1024);
assert.equal(ndsCapacityBytes(1), 256 * 1024);
assert.deepEqual(selectNdsDeviceCapacity(128 * 1024), {
  deviceCapacity: 0,
  capacityBytes: 128 * 1024,
});
assert.deepEqual(selectNdsDeviceCapacity((128 * 1024) + 1), {
  deviceCapacity: 1,
  capacityBytes: 256 * 1024,
});
```

Reject zero/negative unsafe logical size, >512 MiB, and overflow.

- [ ] **Step 3: Write full-header preservation RED tests.**

Construct a 0x160-byte synthetic header with nonzero sentinels in unowned ranges. Request only FAT pointer/size and used-ROM-size changes. Assert every output byte outside the exact owned fields plus CRC is unchanged.

- [ ] **Step 4: Run RED.**

```bash
node --test --import tsx tests/nds-header-rebuild.test.ts
```

Expected: module not found.

- [ ] **Step 5: Implement checked header helpers.**

Use `Buffer.readUInt32LE` / `writeUInt32LE`, safe-integer checks, and copy-on-write:

```ts
const output = Buffer.from(source.bytes);
```

Never mutate `source.bytes` in place.

- [ ] **Step 6: Add precise errors.**

Add `header-rebuild-failed`, `header-checksum-invalid`, and `rom-capacity-exceeded` to the NDS error category union and MCP corrective-action mapping.

`readNdsRebuildHeader()` must validate the stored header CRC before returning. Tests must create valid synthetic CRCs explicitly.

- [ ] **Step 7: Run focused and existing header suites.**

```bash
node --test --import tsx tests/nds-header.test.ts tests/nds-header-rebuild.test.ts
npm run typecheck
```

- [ ] **Step 8: Commit.**

```bash
git add src/services/nds/header-rebuild.ts src/services/nds/errors.ts \
        tests/nds-header-rebuild.test.ts tests/nds-header.test.ts
git commit -m "feat: add rebuild-aware NDS header contract"
```

---

### Task 3: Plan and Serialize Constrained NitroFS Extension Subtrees

**Files:**
- Create: `src/services/nds/fnt-serialize.ts`
- Create: `src/services/nds/mutation/filesystem-plan.ts`
- Create: `tests/nds-fnt-serialize.test.ts`
- Modify: `tests/helpers/nds-mutation-fixture.ts`
- Test: `tests/nds-fnt.test.ts`

**Interfaces:**
- Produces:

```ts
export interface NdsAddedDirectoryPlan {
  readonly path: string;
  readonly directoryId: number;
  readonly parentDirectoryId: number;
  readonly firstFileId: number;
}

export interface NdsAddedFilePlan {
  readonly path: string;
  readonly fileId: number;
  readonly directoryId: number;
  readonly filename: string;
  readonly replacementWorkspacePath: string;
  readonly replacementAbsolutePath: string;
  readonly replacementSha256: string;
  readonly replacementSize: number;
}

export interface NdsFilesystemExtensionPlan {
  readonly addedDirectories: readonly NdsAddedDirectoryPlan[];
  readonly addedFiles: readonly NdsAddedFilePlan[];
  readonly finalDirectoryCount: number;
  readonly finalFileCount: number;
}

export async function planNdsFilesystemExtensions(...): Promise<NdsFilesystemExtensionPlan>;
export function serializeExtendedNdsFnt(
  source: NdsFilesystem,
  extension: NdsFilesystemExtensionPlan,
): Buffer;
```

- [ ] **Step 1: Extend the mutation fixture with a nested source FNT.**

Add at least one existing top-level directory such as `data/` containing one file, while preserving the current root files and overlay-backed file IDs. Expose its directory ID/path in the fixture result.

- [ ] **Step 2: Write RED extension-planning tests.**

Supply operations in deliberately shuffled order:

```text
re_mcp/economy/e2dt.bin
re_mcp/abilities/a2dt.bin
zzz_patch/state.bin
re_mcp/attributes/i2dt.bin
```

Assert assigned directory IDs are source count + lexicographic preorder and file IDs begin at source FAT count, ordered by directory ID then filename—not operation order.

- [ ] **Step 3: Add exact rejection tests.**

Reject:

```text
data/new.bin                  source top-level exists
asset.bin                     root insertion
re_mcp/../evil.bin            invalid segment
re_mcp/a.bin twice            path collision
same new path with different artifacts
257 new files                 count limit
new payload aggregate >64MiB aggregate limit (use fake stat injection, not huge real files)
final directory count >0x1000
final FAT count >0x10000
artifact symlink/non-regular/out-of-workspace
artifact hash mismatch
```

- [ ] **Step 4: Write FNT semantic round-trip RED tests.**

Serialize source + extension, write the bytes into a synthetic ROM fixture pointed to by a temporary FNT header region, parse it with existing `parseNdsFnt()`, and assert:

```ts
for (const sourceFile of source.files) {
  const finalFile = parsed.files[sourceFile.fileId];
  assert.equal(finalFile?.path, sourceFile.path);
}
for (const added of extension.addedFiles) {
  assert.equal(parsed.files[added.fileId]?.path, added.path);
}
```

Also assert every source directory retains exact directory ID/path/parent/firstFileId semantics.

- [ ] **Step 5: Run RED.**

```bash
node --test --import tsx tests/nds-fnt-serialize.test.ts
```

- [ ] **Step 6: Implement deterministic extension-tree planning.**

Build a path trie only from new extension operations. Determine new directory paths independent of operation order, sort complete directory paths lexicographically in preorder, then assign IDs sequentially after source directory count.

New `firstFileId` values are assigned from the final deterministic new-file ordering. Existing directory records use source `firstFileId` unchanged.

- [ ] **Step 7: Implement deterministic FNT serialization.**

Reconstruct source semantic subtables using source directory IDs/paths and existing file IDs. Encode source names through `latin1` to preserve the parser's byte-faithful source path segments. Encode new names as validated ASCII.

Directory entries do not consume file IDs. New top-level directory references may be appended to the root subtable without renumbering root files.

- [ ] **Step 8: Enforce 4 MiB serialized FNT limit and reparse proof.**

`serializeExtendedNdsFnt()` must reject output > `4 * 1024 * 1024`. Planner tests must prove the serialized FNT reparses to exact source semantics plus approved additions.

- [ ] **Step 9: Run focused tests and typecheck.**

```bash
node --test --import tsx tests/nds-fnt.test.ts tests/nds-fnt-serialize.test.ts
npm run typecheck
```

- [ ] **Step 10: Commit.**

```bash
git add src/services/nds/fnt-serialize.ts \
        src/services/nds/mutation/filesystem-plan.ts \
        tests/helpers/nds-mutation-fixture.ts \
        tests/nds-fnt-serialize.test.ts
git commit -m "feat: plan append-only NitroFS extensions"
```

---

### Task 4: Add FAT Serialization and Variable-Size Existing-File Guards

**Files:**
- Create: `src/services/nds/fat-serialize.ts`
- Create: `tests/nds-fat-serialize.test.ts`
- Modify: `src/services/nds/mutation/filesystem-plan.ts`
- Modify: `src/services/nds/mutation/guards.ts`
- Modify: `src/services/nds/mutation/conflicts.ts`
- Test: `tests/nds-mutation-guards.test.ts`
- Test: `tests/nds-mutation-conflicts.test.ts`

**Interfaces:**
- Produces:

```ts
export interface NdsFinalFatEntry {
  readonly fileId: number;
  readonly startOffset: number;
  readonly endOffset: number;
}

export function serializeNdsFat(entries: readonly NdsFinalFatEntry[]): Buffer;

export interface NdsRelocatedFilePlan {
  readonly operationIndex: number;
  readonly fileId: number;
  readonly filePath: string | null;
  readonly sourceStart: number;
  readonly sourceEnd: number;
  readonly sourceSha256: string;
  readonly replacementWorkspacePath: string;
  readonly replacementAbsolutePath: string;
  readonly replacementSha256: string;
  readonly replacementSize: number;
}
```

Final FAT offsets are filled after Task 7 layout allocation; this task owns semantic entries and serialization, not placement.

- [ ] **Step 1: Write FAT serializer RED tests.**

Assert exact 8-byte little-endian records, file-ID sequence `0..N-1`, `start <= end`, no overlapping nonzero live ranges, u32 bounds, final bytes <=4 MiB.

- [ ] **Step 2: Write variable replacement guard RED tests.**

For the fixture ordinary file, create smaller/equal/larger artifacts and assert `replace-nitrofs-file` accepts all three only when:

- target resolves to that exact non-overlay file;
- original stored SHA matches;
- artifact hash matches;
- artifact is non-empty and <=64 MiB;
- artifact hash differs from source file hash.

- [ ] **Step 3: Add overlay alias and logical-conflict RED cases.**

Reject `replace-nitrofs-file` for the file ID/path backing either overlay. Reject combinations:

```text
replace-nitrofs-file(file 0) + replace-bytes inside file 0
replace-nitrofs-file(file 0 by ID) + replace-nitrofs-file(same file by path)
add-nitrofs-file whose canonical path duplicates another addition
```

Use `mutation-overlap` for fixed physical overlap and `unsupported-rebuild-target` / `filesystem-path-collision` for semantic v2 conflicts as defined by the design.

- [ ] **Step 4: Run RED.**

```bash
node --test --import tsx tests/nds-fat-serialize.test.ts tests/nds-mutation-guards.test.ts tests/nds-mutation-conflicts.test.ts
```

- [ ] **Step 5: Implement replacement artifact/source guards.**

Factor shared artifact validation so v1 `replace-component`, v2 file replacement, new-file addition, and later decoded-overlay operations all use one containment/regular-file/non-symlink/hash/size-bound path without changing v1 rules.

- [ ] **Step 6: Implement `serializeNdsFat()`.**

The serializer must never choose ranges; it serializes an already-complete final entry array and rejects invalid geometry before returning bytes.

- [ ] **Step 7: Run PR-A regression gate.**

```bash
npm run typecheck
npm test
npm run build
```

Expected: all existing v1 tests remain green; new v2 structural tests pass.

- [ ] **Step 8: Commit.**

```bash
git add src/services/nds/fat-serialize.ts \
        src/services/nds/mutation/filesystem-plan.ts \
        src/services/nds/mutation/guards.ts \
        src/services/nds/mutation/conflicts.ts \
        tests/nds-fat-serialize.test.ts \
        tests/nds-mutation-guards.test.ts \
        tests/nds-mutation-conflicts.test.ts
git commit -m "feat: guard variable-size NitroFS replacements"
```

**PR A merge gate:** Review Tasks 1–4, prove frozen v1 manifest vector unchanged, CI + Package green, then merge before PR B begins.

---

### Task 5: Implement a Deterministic Repository-Owned BLZ Encoder

**Files:**
- Create: `src/services/nds/blz-encode.ts`
- Create: `tests/nds-blz-encode.test.ts`
- Test: `tests/nds-blz.test.ts`
- Test: `tests/nds-overlay-runtime.test.ts`

**Interfaces:**
- Produces:

```ts
export const NDS_BLZ_ENCODER_CONTRACT_VERSION = 1;

export interface NdsBlzEncodeResult {
  readonly bytes: Buffer;
  readonly storedSize: number;
  readonly runtimeSize: number;
  readonly storedSha256: string;
  readonly runtimeSha256: string;
  readonly contractVersion: 1;
}

export function encodeNdsBlz(
  runtime: Buffer,
  limits?: NdsBlzLimits,
): NdsBlzEncodeResult;
```

The deterministic token policy is:

1. Process the candidate compressed suffix from high address toward low address, matching decoder direction.
2. Search displacement `3..4098` within already-known higher-address decoded bytes.
3. Choose the **longest** match up to 18 bytes.
4. On equal length choose the **smallest displacement**.
5. Emit a back-reference only for length >=3; otherwise emit a literal.
6. Form flag groups in decode order, bit `0x80` through `0x01`.
7. Evaluate valid group-boundary cut points and choose the compressed suffix producing the **smallest final stored size**; tie-break with the **smallest passthrough prefix**.
8. Header size is the minimum `8..11` bytes needed to make stored length 4-byte aligned; header padding is `0xFF` and footer is the existing decoder format.
9. If no candidate yields `storedSize < runtimeSize` and a non-empty encoded region, fail `blz-encode-failed` rather than inventing an invalid compressed overlay.

- [ ] **Step 1: Write deterministic RED vectors.**

Use the existing `COMPRESSED_ARM_CODE_DECODED` fixture plus:

```text
64 bytes of repeating 0x00
512 bytes repeating 16-byte pattern
literal-heavy deterministic pseudo-random bytes
exact 16 MiB boundary via injected limit override (do not allocate repeatedly)
```

For successful cases assert:

```ts
const first = encodeNdsBlz(input);
const second = encodeNdsBlz(Buffer.from(input));
assert.deepEqual(first.bytes, second.bytes);
assert.deepEqual(decodeNdsBlz(first.bytes, input.length).bytes, input);
assert.equal(first.runtimeSha256, sha256(input));
assert.equal(first.storedSha256, sha256(first.bytes));
assert.equal(first.contractVersion, 1);
```

For the literal-heavy vector, assert either deterministic valid compression or the exact `blz-encode-failed` category; never allow malformed output.

- [ ] **Step 2: Write tie-break regression tests.**

Construct data with two equal-length possible matches at different displacements and assert the stored output equals one literal fixture generated from the specified smallest-displacement rule.

- [ ] **Step 3: Write bound/failure RED tests.**

Reject empty input, >16 MiB runtime input, encoded output >16 MiB, no valid compressed suffix, and packed size >`0x00ff_ffff` using limit injection where possible.

- [ ] **Step 4: Run RED.**

```bash
node --test --import tsx tests/nds-blz-encode.test.ts
```

- [ ] **Step 5: Implement the encoder without external tools.**

Keep token search in small pure helpers so match selection, group formation, suffix selection, and final footer construction can each be unit-tested. Avoid environment, timestamps, randomization, or compression-level options.

- [ ] **Step 6: Make decode-back a mandatory production postcondition.**

Before returning, call:

```ts
const decoded = decodeNdsBlz(stored, runtime.length, limits);
if (!decoded.bytes.equals(runtime)) {
  throw new NdsError("blz-roundtrip-mismatch", ...);
}
```

- [ ] **Step 7: Run BLZ + overlay-runtime regressions.**

```bash
node --test --import tsx tests/nds-blz.test.ts tests/nds-blz-encode.test.ts tests/nds-overlay-runtime.test.ts
npm run typecheck
```

- [ ] **Step 8: Commit.**

```bash
git add src/services/nds/blz-encode.ts tests/nds-blz-encode.test.ts
git commit -m "feat: add deterministic NDS BLZ encoder"
```

---

### Task 6: Guard Decoded Overlay Replacements and Serialize Overlay Tables

**Files:**
- Create: `src/services/nds/overlays-serialize.ts`
- Create: `src/services/nds/mutation/overlay-plan.ts`
- Create: `tests/nds-overlay-rebuild.test.ts`
- Modify: `src/services/nds/mutation/guards.ts`
- Modify: `src/services/nds/mutation/conflicts.ts`
- Modify: `tests/helpers/nds-mutation-fixture.ts`

**Interfaces:**
- Produces:

```ts
export interface NdsDecodedOverlayReplacementPlan {
  readonly operationIndex: number;
  readonly processor: NdsProcessor;
  readonly overlayId: number;
  readonly fileId: number;
  readonly sourceStoredStart: number;
  readonly sourceStoredEnd: number;
  readonly sourceStoredSha256: string;
  readonly sourceRuntimeSha256: string;
  readonly replacementRuntimeWorkspacePath: string;
  readonly replacementRuntimeAbsolutePath: string;
  readonly replacementRuntimeSha256: string;
  readonly runtimeSize: number;
  readonly encodedBytes: Buffer;
  readonly encodedSha256: string;
  readonly encodedSize: number;
}

export async function planDecodedOverlayReplacement(...): Promise<NdsDecodedOverlayReplacementPlan>;
export function serializeNdsOverlayTable(
  source: readonly NdsOverlay[],
  compressedSizeOverrides: ReadonlyMap<number, number>,
): Buffer;
```

- [ ] **Step 1: Add RED source/runtime guard tests.**

For the compressed overlay fixture, derive the actual source stored and runtime hashes. Assert planning succeeds only when both expected hashes match exactly and the replacement runtime artifact:

- is regular/non-symlink/workspace-contained;
- hashes exactly to manifest replacement SHA;
- length equals `overlay.ramSize` exactly;
- differs from source runtime bytes;
- produces a valid deterministic BLZ result.

- [ ] **Step 2: Add exact rejection tests.**

Reject:

```text
uncompressed overlay target
unknown overlay ID
wrong processor
stored SHA mismatch
runtime SHA mismatch
replacement runtime SHA mismatch
replacement runtime size +/- 1 byte
replacement runtime identical to source runtime
encoded size > 0x00ffffff
replace-component same overlay + replace-decoded-overlay
replace-bytes same compressed overlay + replace-decoded-overlay
replace-nitrofs-file on overlay backing file
```

- [ ] **Step 3: Write overlay serializer RED tests.**

Serialize source records with one compressed-size override. Compare every 32-byte record field and assert the only changed bits are lower 24 bits of packed field for the targeted overlay. Flags high byte must be byte-identical.

Reparse the serialized table through a temporary canonical ROM and assert processor/ID/RAM/BSS/static-init/file/flags semantics unchanged, with only `compressedSize` updated.

- [ ] **Step 4: Run RED.**

```bash
node --test --import tsx tests/nds-overlay-rebuild.test.ts
```

- [ ] **Step 5: Implement source runtime loading through the existing overlay runtime context.**

Do not create a second BLZ decoder path. Use `createNdsOverlayRuntimeContext(map).getCompressedOverlay(processor, overlayId)` and compare both stored/runtime hashes to manifest guards.

- [ ] **Step 6: Encode and immediately decode-back replacement runtime bytes.**

Store encoded bytes in the resolved overlay plan so `apply.ts` later performs no compression decisions.

- [ ] **Step 7: Run focused regressions and typecheck.**

```bash
node --test --import tsx tests/nds-overlay-rebuild.test.ts tests/nds-overlay-runtime.test.ts tests/nds-mutation-conflicts.test.ts
npm run typecheck
```

- [ ] **Step 8: Commit.**

```bash
git add src/services/nds/overlays-serialize.ts \
        src/services/nds/mutation/overlay-plan.ts \
        src/services/nds/mutation/guards.ts \
        src/services/nds/mutation/conflicts.ts \
        tests/helpers/nds-mutation-fixture.ts \
        tests/nds-overlay-rebuild.test.ts
git commit -m "feat: plan decoded overlay recompression"
```

---

### Task 7: Implement Deterministic Append-Only Layout Allocation

**Files:**
- Create: `src/services/nds/mutation/layout.ts`
- Create: `tests/nds-rebuild-layout.test.ts`

**Interfaces:**
- Produces:

```ts
export const NDS_REBUILD_CONTRACT_VERSION = 1;
export const MAX_NDS_REBUILD_GROWTH_BYTES = 128 * 1024 * 1024;

export type NdsRebuildSegmentKind =
  | "relocated-file"
  | "new-file"
  | "fnt"
  | "fat"
  | "arm9-overlay-table"
  | "arm7-overlay-table";

export interface NdsRebuildSegment {
  readonly kind: NdsRebuildSegmentKind;
  readonly ownerId: string;
  readonly alignment: 0x200 | 4;
  readonly start: number;
  readonly end: number;
  readonly size: number;
  readonly sha256: string;
  readonly bytes: Buffer;
}

export interface NdsRebuildLayout {
  readonly sourceSize: number;
  readonly tailStart: number;
  readonly logicalUsedSize: number;
  readonly finalSize: number;
  readonly deviceCapacity: number;
  readonly segments: readonly NdsRebuildSegment[];
}

export function planNdsRebuildLayout(input: NdsRebuildLayoutInput): NdsRebuildLayout;
```

- [ ] **Step 1: Write RED alignment/order tests.**

Test both source size exactly 0x200-aligned and source size ending at `...01`. Provide shuffled input payloads and assert final segment order is exactly:

```text
existing relocated file IDs ascending
new file IDs ascending
FNT
FAT
ARM9 overlay table
ARM7 overlay table
```

Payload segment starts `% 0x200 === 0`; metadata starts `% 4 === 0`; all gaps are represented by the materializer as `0xFF` and are not implicit meaningful segments.

- [ ] **Step 2: Write RED final-capacity tests.**

For a small source fixture, assert `logicalUsedSize` is final meaningful segment end and `finalSize` equals `selectNdsDeviceCapacity(logicalUsedSize).capacityBytes`.

- [ ] **Step 3: Write exact bound RED tests.**

Reject:

```text
source/final geometry > u32
finalSize >512MiB
growth >128MiB
one artifact >64MiB
new-file aggregate >64MiB
FNT/FAT >4MiB
BLZ encoded/decoded limits violated
unsafe integer arithmetic
```

Use synthetic segment descriptors and fake byte-source sizes; do not allocate hundreds of MiB in tests.

- [ ] **Step 4: Run RED.**

```bash
node --test --import tsx tests/nds-rebuild-layout.test.ts
```

- [ ] **Step 5: Implement `alignUp()` with overflow checks and deterministic allocation.**

`alignUp(value, alignment)` must reject non-safe integers, non-positive alignments, and results >`0xffffffff` before any output is opened.

- [ ] **Step 6: Run focused tests.**

```bash
node --test --import tsx tests/nds-rebuild-layout.test.ts tests/nds-header-rebuild.test.ts
npm run typecheck
```

- [ ] **Step 7: Commit.**

```bash
git add src/services/nds/mutation/layout.ts tests/nds-rebuild-layout.test.ts
git commit -m "feat: add append-only NDS rebuild layout"
```

---

### Task 8: Compile the Complete V2 Resolved Plan and Exact Header Rewrites

**Files:**
- Create: `src/services/nds/mutation/header-plan.ts`
- Create: `tests/nds-mutation-planner-v2.test.ts`
- Modify: `src/services/nds/mutation/planner.ts`
- Modify: `src/services/nds/mutation/filesystem-plan.ts`
- Modify: `src/services/nds/mutation/overlay-plan.ts`
- Modify: `src/services/nds/mutation/conflicts.ts`
- Modify: `src/services/nds/mutation/staging.ts`
- Modify: `src/services/nds/errors.ts`
- Test: `tests/nds-mutation-planner.test.ts`

**Interfaces:**
- Refactors current resolved plan into a discriminated union while preserving v1 serialization:

```ts
export interface NdsResolvedMutationPlanV1 {
  readonly formatVersion: 1;
  // existing v1 fields and semantics
}

export interface NdsResolvedMutationPlanV2 {
  readonly formatVersion: 2;
  readonly rebuildContractVersion: 1;
  readonly blzEncoderContractVersion: 1;
  readonly sourceRomPath: string;
  readonly sourceWorkspacePath: string;
  readonly sourceSha256: string;
  readonly sourceSha256Prefix: string;
  readonly sourceSize: number;
  readonly manifestWorkspacePath: string;
  readonly manifestSha256: string;
  readonly outputFilename: string;
  readonly buildId: string;
  readonly fixedOperations: readonly GuardedNdsMutationOperation[];
  readonly relocatedFiles: readonly NdsRelocatedFilePlan[];
  readonly addedFiles: readonly NdsAddedFilePlan[];
  readonly decodedOverlays: readonly NdsDecodedOverlayReplacementPlan[];
  readonly layout: NdsRebuildLayout;
  readonly headerPlan: NdsHeaderRewritePlan;
  readonly finalFat: readonly NdsFinalFatEntry[];
}

export type NdsResolvedMutationPlan = NdsResolvedMutationPlanV1 | NdsResolvedMutationPlanV2;
```

`compileNdsMutationPlan()` remains the single public planner entry point and dispatches by manifest version.

- [ ] **Step 1: Freeze v1 resolved-plan/build-ID regression before refactor.**

Use one existing fixture and assert literal expected:

```text
manifestSha256
buildId
serializeResolvedNdsMutationPlan(plan)
```

These expected values must be checked in before modifying planner types.

- [ ] **Step 2: Write a RED mixed v2 plan test.**

Create one manifest containing:

```text
replace-bytes in ARM9
replace-nitrofs-file for ordinary file
add-nitrofs-file re_mcp/attributes/i2dt.bin
replace-decoded-overlay arm9 overlay 7
```

Assert validation/planning produces:

- deterministic relocated/new file IDs and ranges;
- new FNT/FAT bytes and hashes;
- rebuilt ARM9 overlay-table bytes/hash;
- no ARM7 overlay-table segment;
- exact header rewrites;
- logical used/final capacity sizes;
- source ROM still unchanged;
- identical plan/build ID in a second absolute workspace with byte-identical inputs.

- [ ] **Step 3: Implement `NdsHeaderRewritePlan`.**

```ts
export interface NdsHeaderByteRewrite {
  readonly offset: number;
  readonly expected: string;
  readonly replacement: string;
  readonly label: string;
}

export interface NdsHeaderRewritePlan {
  readonly sourceHeaderSha256: string;
  readonly outputHeaderSha256: string;
  readonly rewrites: readonly NdsHeaderByteRewrite[];
  readonly outputHeaderBytes: Buffer;
}
```

The planner computes the final header entirely in memory from source snapshot + final FNT/FAT/overlay-table ranges + logical used size + device capacity. Convert source/output differences into minimal contiguous rewrite ranges. Reject any changed header byte outside approved owned fields plus CRC.

- [ ] **Step 4: Build final FAT/table bytes after layout ranges are known.**

Because FAT bytes contain payload ranges and the FAT itself is a tail segment, use a two-phase deterministic layout:

1. allocate all payload segments;
2. serialize final FAT with their ranges;
3. allocate metadata in fixed order using known serialized sizes;
4. serialize header using final metadata ranges.

FNT content/size is known before metadata placement. Overlay-table content/size is known before metadata placement.

- [ ] **Step 5: Implement v2 build identity exactly.**

Canonical input:

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

Artifact hashes are in normalized manifest operation order and include all artifact-backed operations (legacy component replacement plus each v2 artifact operation). Derived BLZ stored hash is evidence, not an identity input.

- [ ] **Step 6: Generalize stage artifact alias checks.**

`staging.ts` must reject any artifact-backed v1/v2 operation whose resolved file aliases the staged ROM. Do this via one helper that enumerates resolved artifact paths from either plan version.

- [ ] **Step 7: Add planner error categories.**

Add and map:

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
rebuild-layout-overflow
```

No corrective action may suggest bypassing guards.

- [ ] **Step 8: Run PR-B regression gate.**

```bash
node --test --import tsx \
  tests/nds-mutation-planner.test.ts \
  tests/nds-mutation-planner-v2.test.ts \
  tests/nds-rebuild-layout.test.ts \
  tests/nds-overlay-rebuild.test.ts \
  tests/nds-blz-encode.test.ts
npm run typecheck
npm test
npm run build
```

- [ ] **Step 9: Commit.**

```bash
git add src/services/nds/mutation/header-plan.ts \
        src/services/nds/mutation/planner.ts \
        src/services/nds/mutation/filesystem-plan.ts \
        src/services/nds/mutation/overlay-plan.ts \
        src/services/nds/mutation/conflicts.ts \
        src/services/nds/mutation/staging.ts \
        src/services/nds/errors.ts \
        tests/nds-mutation-planner-v2.test.ts \
        tests/nds-mutation-planner.test.ts
git commit -m "feat: compile deterministic NDS rebuild plans"
```

**PR B merge gate:** Review Tasks 5–8, require deterministic BLZ round-trip, exact v1 planner/build-ID regression, CI + Package green, then merge before PR C begins.

---

### Task 9: Extend `apply.ts` as the Sole V2 Materialization Writer

**Files:**
- Modify: `src/services/nds/mutation/apply.ts`
- Create: `tests/nds-mutation-apply-v2.test.ts`
- Test: `tests/nds-mutation-apply.test.ts`
- Test: `tests/nds-mutation-hardening.test.ts`

**Interfaces:**
- `applyNdsMutationPlan(plan, stage, io?)` remains the only materialization API.
- V1 path executes the existing exact fixed-size logic unchanged.
- V2 path performs no planning/compression/hash decisions; it consumes only resolved bytes/ranges from the plan.

- [ ] **Step 1: Write RED materialization tests using a resolved mixed v2 plan.**

After `applyNdsMutationPlan()` and before semantic verification, assert raw bytes:

```text
source prefix identical except approved replace-bytes/header rewrite ranges
relocated ordinary replacement at planned FAT payload segment
new file at planned payload segment
encoded compressed overlay at planned payload segment
rebuilt FNT/FAT/ARM9 overlay table at exact planned segments
all alignment gaps contain only 0xFF
all bytes from logicalUsedSize to finalSize contain only 0xFF
staged file size == plan.layout.finalSize
source ROM SHA unchanged
```

- [ ] **Step 2: Add injected-write-failure RED tests.**

Extend `NdsMutationApplyIo` test adapter so writes can fail after a controlled byte count. Assert failure raises `staging-failed`/original error and never opens source ROM with `r+`.

- [ ] **Step 3: Run RED.**

```bash
node --test --import tsx tests/nds-mutation-apply-v2.test.ts
```

- [ ] **Step 4: Implement deterministic positional write helpers.**

Add helpers only inside `apply.ts`:

```ts
writeAt(handle, bytes, position)
fillRange(handle, 0xff, start, end)
resizeFile(handle, finalSize)
```

For v2:

1. staged file is already exact source copy;
2. apply approved fixed operations in source-prefix order;
3. write planned tail segments in segment order, filling every gap with `0xFF`;
4. write exact header rewrite replacement bytes at planned source-prefix offsets;
5. resize/pad to exact final size;
6. `sync()` and close.

- [ ] **Step 5: Preserve the single-writer hardening invariant.**

Update hardening scan to require that among `src/services/nds/mutation/**/*.ts`, only `apply.ts` contains staged-ROM `"r+"` open capability. New serializers/planners must not open any ROM for write.

- [ ] **Step 6: Run focused + legacy apply suites.**

```bash
node --test --import tsx \
  tests/nds-mutation-apply.test.ts \
  tests/nds-mutation-apply-v2.test.ts \
  tests/nds-mutation-hardening.test.ts
npm run typecheck
```

- [ ] **Step 7: Commit.**

```bash
git add src/services/nds/mutation/apply.ts \
        tests/nds-mutation-apply-v2.test.ts \
        tests/nds-mutation-hardening.test.ts
git commit -m "feat: materialize append-only NDS rebuilds"
```

---

### Task 10: Add Complete V2 Semantic Verification

**Files:**
- Create: `src/services/nds/mutation/verify-v2.ts`
- Create: `tests/nds-mutation-verify-v2.test.ts`
- Modify: `src/services/nds/mutation/verify.ts`
- Modify: `src/services/nds/errors.ts`
- Test: `tests/nds-mutation-verify.test.ts`

**Interfaces:**
- `verifyNdsMutationOutput()` dispatches by `plan.formatVersion`.
- Existing `NdsMutationVerificationResult` becomes a discriminated result union or common interface with v1 fields preserved exactly.
- Produces v2 counts:

```ts
export interface NdsMutationVerificationResultV2 {
  readonly formatVersion: 2;
  readonly status: "passed";
  readonly sourceSha256: string;
  readonly outputSha256: string;
  readonly sourceSize: number;
  readonly outputSize: number;
  readonly sourceUnchanged: true;
  readonly sourcePrefixChangedBytes: number;
  readonly approvedFixedMutationBytes: number;
  readonly approvedHeaderRewriteBytes: number;
  readonly appendedMeaningfulBytes: number;
  readonly appendedPaddingBytes: number;
  readonly unexpectedChangedBytes: 0;
  readonly operations: readonly NdsMutationOperationVerification[];
  readonly compressedOverlays: readonly NdsCompressedOverlayVerification[];
}
```

- [ ] **Step 1: Write one full-success RED verification test.**

Materialize the mixed v2 plan from Task 8, then call verifier and assert:

```text
canonical output parse succeeds
output SHA equals canonical parsed SHA
source SHA unchanged
all source file IDs preserved
all source paths/unnamed status preserved
unchanged source FAT entries retain source ranges + hashes
relocated file retains ID/path and matches replacement hash
new file has exact assigned ID/path/hash
compressed overlay keeps runtime geometry/flags/file ID and decodes exactly to replacement runtime bytes
header differs only in planned fields/CRC
final capacity/used size exactly match plan
all prefix/tail attribution counts sum correctly
unexpectedChangedBytes == 0
```

- [ ] **Step 2: Add tamper matrix RED tests.**

Starting from a valid staged v2 output, separately tamper:

```text
unapproved source-prefix byte
header pointer byte
header CRC
relocated payload byte
new-file payload byte
FNT path byte
FAT range byte
overlay packed compressed-size byte
encoded overlay byte
alignment padding byte
final capacity padding byte
truncate final file
append one extra byte
```

Each must fail with a precise v2 category, never pass because the ROM remains parseable.

- [ ] **Step 3: Add unchanged-source semantic tests.**

For every source file not targeted, hash source and final payload and assert exact equality. For every untargeted overlay, assert both stored SHA and decoded runtime SHA (for compressed overlays) remain equal.

- [ ] **Step 4: Run RED.**

```bash
node --test --import tsx tests/nds-mutation-verify-v2.test.ts
```

- [ ] **Step 5: Implement prefix attribution.**

Read source/output only over the source-length prefix in bounded chunks. A difference is valid only when it falls in exactly one approved fixed mutation range or one header rewrite range. Count duplicates as a planner bug and reject.

- [ ] **Step 6: Implement tail attribution.**

Walk from `sourceSize` to `finalSize` against the resolved segment map. Segment bytes must hash exactly; every non-segment byte must equal `0xFF`. Split meaningful/padding counts explicitly.

- [ ] **Step 7: Implement filesystem/overlay/header semantic proof.**

Use a freshly parsed output `NdsRomMap`, not plan assumptions. Compare source/output by IDs and canonical paths, then validate each targeted/new file against plan hashes/ranges. Use existing overlay runtime context for decoded output overlay verification.

Re-read full output rebuild header and validate header CRC and exact plan-owned rewrites.

- [ ] **Step 8: Add v2 verification errors.**

Map:

```text
rebuild-prefix-diff
rebuild-tail-mismatch
filesystem-semantic-mismatch
overlay-semantic-mismatch
header-checksum-invalid
output-verification-failed
```

- [ ] **Step 9: Run PR-C regression gate.**

```bash
node --test --import tsx \
  tests/nds-mutation-apply-v2.test.ts \
  tests/nds-mutation-verify.test.ts \
  tests/nds-mutation-verify-v2.test.ts
npm run typecheck
npm test
npm run build
```

- [ ] **Step 10: Commit.**

```bash
git add src/services/nds/mutation/verify-v2.ts \
        src/services/nds/mutation/verify.ts \
        src/services/nds/errors.ts \
        tests/nds-mutation-verify-v2.test.ts
git commit -m "feat: verify rebuilt NDS semantics"
```

**PR C merge gate:** Review Tasks 9–10 with special attention to the single-writer scan and tamper matrix. Require CI + Package green, then merge before PR D begins.

---

### Task 11: Add V2 Evidence, Fresh Reuse, and Assembled-Package Core 2 Smoke

**Files:**
- Create: `src/services/nds/mutation/report-v2.ts`
- Create: `tests/nds-mutation-build-v2.test.ts`
- Modify: `src/services/nds/mutation/report.ts`
- Modify: `src/services/nds/mutation/build.ts`
- Modify: `tests/nds-mutation-build.test.ts`
- Modify: `scripts/check-nds-mutation-install.mjs`
- Modify: `.github/workflows/package.yml`

**Interfaces:**
- V1 evidence set remains exactly unchanged.
- V2 adds exactly one deterministic file:

```text
rebuild-layout.json
```

- `NDS_MUTATION_EVIDENCE_FILENAMES` becomes version-aware via:

```ts
export function ndsMutationEvidenceFilenames(
  plan: NdsResolvedMutationPlan,
): readonly string[];
```

- [ ] **Step 1: Freeze v1 build/evidence regression.**

Run the existing v1 build fixture and assert its exact entry set remains:

```text
changed-components.json
mutation-manifest.json
output.sha256
<output>.nds
resolved-plan.json
verification.json
```

No `rebuild-layout.json` for v1.

- [ ] **Step 2: Write RED v2 evidence tests.**

Build the mixed v2 fixture and assert final entry set contains the v1 evidence plus `rebuild-layout.json`. Parse it and require:

```text
rebuildContractVersion == 1
blzEncoderContractVersion == 1
sourceSize/tailStart/logicalUsedSize/finalSize/deviceCapacity
exact header rewrites
exact ordered segment list with kind/start/end/size/hash/alignment/ownerId
assigned new directory IDs
assigned new file IDs
no absolute workspace path
no timestamp/PID/temp path
```

- [ ] **Step 3: Add deterministic cross-workspace v2 build test.**

Create two fixtures with byte-identical source/manifests/artifacts in different absolute temp directories. Assert identical:

```text
buildId
output ROM bytes
all evidence bytes
```

- [ ] **Step 4: Add fresh reuse/tamper tests for every v2 published entry.**

First rebuild returns `reused === false`; second exact build returns `reused === true` only after full v2 verification. Tamper each output/evidence entry separately and require `publish-collision` without repair.

- [ ] **Step 5: Update build publication entry validation to be plan-version aware.**

`requireExactPublishedEntries()` must compare against `ndsMutationEvidenceFilenames(plan)` plus the output ROM. Unexpected/missing files remain fail-closed.

- [ ] **Step 6: Extend package smoke with a real v2 synthetic ROM.**

The assembled `dist/` smoke must import compiled modules and exercise in one v2 build:

```text
variable-size ordinary NitroFS replacement
new re_mcp/smoke/state.bin extension file
decoded compressed overlay replacement
FNT/FAT/ARM9 overlay table rebuild
header/capacity/CRC rewrite
fresh v2 verifier
second-run verified reuse
source ROM byte-identical
```

Do not import `.ts` source files from the package smoke.

- [ ] **Step 7: Require exact package output.**

Package smoke must fail unless it prints:

```text
NDS mutation package smoke passed
NDS rebuild Core 2 package smoke passed
```

and Package workflow must run this script before artifact upload.

- [ ] **Step 8: Run focused build/package source test.**

```bash
node --test --import tsx tests/nds-mutation-build.test.ts tests/nds-mutation-build-v2.test.ts
npm run build
node scripts/check-nds-mutation-install.mjs .
```

- [ ] **Step 9: Commit.**

```bash
git add src/services/nds/mutation/report-v2.ts \
        src/services/nds/mutation/report.ts \
        src/services/nds/mutation/build.ts \
        tests/nds-mutation-build.test.ts \
        tests/nds-mutation-build-v2.test.ts \
        scripts/check-nds-mutation-install.mjs \
        .github/workflows/package.yml
git commit -m "feat: publish deterministic NDS rebuild evidence"
```

---

### Task 12: Harden Public Boundaries, Document Core 2, and Run Final Acceptance

**Files:**
- Create: `tests/nds-rebuild-hardening.test.ts`
- Modify: `tests/nds-mutation-tools.test.ts`
- Modify: `tests/nds-mutation-capability.test.ts`
- Modify: `README.md`
- Test: all mutation/rebuild/package tests

**Interfaces:**
- No new public MCP tool names.
- Existing three schemas still accept exactly:

```text
rom: string
manifest: string
```

- Capability text describes manifest v2 rebuilds but does not claim executable-runtime growth, watchpoints, save migration, or agentic patch orchestration.

- [ ] **Step 1: Write public-schema hardening tests before README/index changes.**

Assert registered mutation tools are still exactly:

```ts
assert.deepEqual([...toolNames].sort(), [
  "nds_mutation_build",
  "nds_mutation_validate",
  "nds_mutation_verify",
]);
```

For each tool schema reject keys such as:

```text
romOffset
offset
outputPath
alignment
fileId
directoryId
compressedSize
blzOptions
```

because those belong inside a validated workspace manifest or are never caller-controlled.

- [ ] **Step 2: Add repository hardening scans.**

`tests/nds-rebuild-hardening.test.ts` must scan source text and prove:

- only `apply.ts` contains mutation staged-ROM `"r+"` open capability;
- no `child_process`/`spawn`/`exec` use appears in `blz-encode.ts`;
- no source-gap allocator symbol/term is introduced in rebuild modules;
- v2 manifest exposes no numeric new file/directory ID field;
- v2 manifest exposes no output offset/alignment/capacity field;
- decoded overlay operation exposes runtime artifact, not stored compressed artifact/parameters;
- package smoke contains all three Core 2 operation classes and checks source immutability/reuse.

- [ ] **Step 3: Update README Core 2 documentation.**

Add a `Controlled NDS Rebuild — Core 2` section documenting:

```text
manifest v1 remains fixed-layout Milestone 1
manifest v2 adds variable existing NitroFS replacement
manifest v2 adds source-absent extension subtrees
manifest v2 adds decoded compressed-overlay replacement/recompression
append-only tail strategy
new IDs assigned deterministically by RE-MCP
source gaps never allocated
source ROM immutable
new output may grow to a capacity boundary
rebuild-layout.json evidence
```

Explicitly state exclusions:

```text
ARM9/ARM7 initialized-size growth
overlay ramSize/BSS growth
new overlays/runtime relocation
code allocation/hooks/trampolines
watchpoints/runtime memory writes
save migration semantics
text/graphics semantic inference
file deletion/renaming
whole-ROM compaction
natural-language patch compilation
multi-patch orchestration
automatic gameplay acceptance
```

- [ ] **Step 4: Update capability/policy wording only if tests prove current wording is stale.**

Do not add new tool registrations. Capability text should say controlled append-only layout/FAT/FNT/overlay metadata rebuild is available only through manifest v2 and exact guards.

- [ ] **Step 5: Run complete local verification.**

```bash
npm run typecheck
npm test
npm run build
node scripts/check-nds-mutation-install.mjs .
git diff --check
```

All commands must pass on the exact final PR-D head.

- [ ] **Step 6: Run exact final regression assertions.**

Confirm from test output/logs:

```text
all pre-Core-2 v1 mutation tests pass
v1 frozen canonical manifest hash passes
v1 frozen resolved-plan/build ID passes
v1 evidence file set unchanged
v2 variable file rebuild passes
v2 extension file rebuild passes
v2 decoded overlay BLZ round-trip passes
v2 mixed build passes
v2 tamper matrix fails closed
v2 deterministic cross-workspace build passes
single-writer scan passes
no external BLZ process scan passes
package Core 2 smoke passes
```

- [ ] **Step 7: Push PR D and require GitHub gates.**

On the exact PR head require:

```text
CI: typecheck + full tests + build = success
Package: assembled self-contained bundle smoke + artifact upload = success
Runtime Correlation Ghidra Acceptance: skipped if path filters do not include Core 2, otherwise success
zero unresolved review threads
```

- [ ] **Step 8: Commit final docs/hardening.**

```bash
git add tests/nds-rebuild-hardening.test.ts \
        tests/nds-mutation-tools.test.ts \
        tests/nds-mutation-capability.test.ts \
        README.md
git commit -m "docs: complete NDS Rebuild Core 2"
```

**PR D merge gate:** Perform final diff review, exact-head workflow verification, zero-thread check, then stop for explicit user merge approval.

---

## Final Acceptance Matrix

Core 2 is complete only when the final merged implementation proves all rows below.

| Contract | Required proof |
|---|---|
| V1 compatibility | Frozen manifest hash, resolved plan/build ID, evidence set, complete old tests |
| V2 parsing | Strict versioned schema; no arbitrary offset/ID/layout controls |
| Source safety | Source SHA unchanged after validate/build/verify success and every injected failure |
| Existing variable file | Same file ID/path, new deterministic FAT range, pinned payload hash |
| New extension file | Only new source-absent top-level subtree; deterministic IDs; exact path/hash |
| FNT | Source semantic identity plus approved additions only; <=4 MiB |
| FAT | Source IDs preserved; unchanged ranges preserved; relocated/new ranges exact; <=4 MiB |
| BLZ | Repository-owned deterministic encoder; exact encode→decode identity; limits enforced |
| Overlay | Runtime geometry/flags/file ID preserved; only compressed size/FAT backing may change |
| Layout | No source-gap allocation; deterministic append order/alignment/padding |
| Header | Only owned fields + CRC change; output CRC valid; used size/capacity exact |
| Output bounds | <=512 MiB final, <=128 MiB growth, safe u32/safe-integer arithmetic |
| Materialization | `apply.ts` sole staged-ROM writer |
| Verification | Prefix and tail fully attributed; semantic reparse passes; unexpectedChangedBytes=0 |
| Publication | Atomic; deterministic; fresh reuse only; tamper collision fails closed |
| Public surface | Exactly three tools, only ROM + manifest inputs |
| Package | Assembled compiled bundle performs real Core 2 build/verify/reuse smoke |
| Scope | No executable growth/hooks/watchpoints/save semantics/orchestration introduced |

## Next Milestone Handoff

After Core 2 is merged, do **not** go live on the Bakugan patch suite yet. The next approved design cycle should be **Executable Injection + Hook Core**, because the Attribute, Ability, and Economy plans require new runtime modules/hooks and the Career plan later requires controlled runtime experimentation. Core 2 supplies the safe container/recompression foundation that milestone will build upon.
