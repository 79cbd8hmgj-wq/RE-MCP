# NDS Rebuild Core 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deterministic append-only variable-size NDS rebuilding, constrained NitroFS extension files, decoded compressed-overlay replacement, deterministic BLZ recompression, and rebuild-aware verification while preserving the immutable source ROM, the current public MCP surface, and exact manifest-v1 behavior.

**Architecture:** Manifest v2 compiles all semantic changes into a complete in-memory rebuild plan before any staged ROM write. Existing bytes remain the physical prefix; changed/new FAT payloads and rebuilt metadata are appended in deterministic order; only exact owned header fields are rewritten. `apply.ts` remains the sole staged-ROM writer, and verification reparses the finished ROM and proves every prefix/tail byte and logical structure.

**Tech Stack:** TypeScript 5.7, Node.js 20+, Zod 3.23, Node `Buffer`/`crypto`/`fs/promises`, existing NDS parser/FAT/FNT/overlay/BLZ services, Node test runner + `tsx`, GitHub CI and Package workflows.

## Global Constraints

- Source ROM is immutable and is never opened for writing.
- Full source SHA-256 is mandatory and is revalidated before planning, before materialization, and after verification.
- Public MCP tools remain exactly `nds_mutation_validate`, `nds_mutation_build`, and `nds_mutation_verify`; each accepts only `rom` and `manifest`.
- `formatVersion: 1` canonical semantics, build ID, output structure, evidence set, and verification behavior remain unchanged.
- `formatVersion: 2` accepts the two v1 operations plus exactly `replace-nitrofs-file`, `add-nitrofs-file`, and `replace-decoded-overlay`.
- No caller-selected physical ROM offset, output offset, alignment, capacity byte, new file ID, new directory ID, raw FAT/FNT field, BLZ parameter, or arbitrary header write.
- Existing file IDs, existing NitroFS paths, existing directory IDs, overlay IDs, overlay file IDs, overlay flags, ARM9/ARM7 runtime geometry, and overlay runtime geometry remain unchanged.
- New files are allowed only under top-level NitroFS directories absent from the source.
- No source padding/gap is allocated or reclaimed.
- Rebuild tail starts at `alignUp(sourceSize, 0x200)`; all unowned growth bytes are deterministic `0xFF` padding.
- Relocated/new payloads are `0x200` aligned; rebuilt metadata tables are 4-byte aligned.
- Final ROM size is a representable NDS capacity boundary, maximum **512 MiB**.
- Maximum growth beyond source size: **128 MiB**.
- Maximum one artifact: **64 MiB**.
- Maximum new files: **256**; aggregate new-file payload bytes: **64 MiB**.
- Maximum serialized FNT: **4 MiB**; maximum serialized FAT: **4 MiB**.
- BLZ limits remain **16 MiB stored / 16 MiB decoded**; aggregate decoded-overlay validation remains **64 MiB**.
- Packed overlay compressed size must fit `0x00ff_ffff`.
- Final directory count `<= 0x1000`; final FAT count `<= 0x10000` so FNT `firstFileId` remains representable.
- All ROM offsets/end offsets must fit unsigned 32-bit file geometry and JavaScript safe integers.
- `apply.ts` remains the only mutation module that may open the staged ROM with `"r+"`.
- No external compressor executable/process is permitted.
- No build publishes unless canonical reparse, semantic verification, source revalidation, and complete diff attribution all pass with `unexpectedChangedBytes === 0`.
- Core 2 is native-independent; no DeSmuME/GDB/Ghidra acceptance is part of this milestone.

## PR / Merge Boundaries

1. **PR A — V2 format + structural serializers:** Tasks 1–4.
2. **PR B — BLZ + overlay + append-only planning:** Tasks 5–8.
3. **PR C — single-writer materialization + semantic verification:** Tasks 9–10.
4. **PR D — evidence + package smoke + hardening + docs:** Tasks 11–12.

Each PR branches from `main` only after its predecessor is reviewed and merged. Each PR must pass CI and Package before its merge gate.

---

## File Responsibility Map

### Create

```text
src/services/nds/header-rebuild.ts
src/services/nds/fnt-serialize.ts
src/services/nds/fat-serialize.ts
src/services/nds/overlays-serialize.ts
src/services/nds/blz-encode.ts
src/services/nds/mutation/filesystem-plan.ts
src/services/nds/mutation/overlay-plan.ts
src/services/nds/mutation/layout.ts
src/services/nds/mutation/header-plan.ts
src/services/nds/mutation/verify-v2.ts
src/services/nds/mutation/report-v2.ts

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
tests/nds-mutation-tools.test.ts
tests/nds-mutation-capability.test.ts
scripts/check-nds-mutation-install.mjs
.github/workflows/package.yml
README.md
```

Parser modules remain read-focused; serialization/rebuild responsibilities live in separate files.

---

### Task 1: Add Strict Manifest V2 While Freezing V1

**Files:**
- Modify: `src/services/nds/mutation/manifest.ts`
- Modify: `tests/helpers/nds-mutation-fixture.ts`
- Create: `tests/nds-mutation-manifest-v2.test.ts`
- Test: `tests/nds-mutation-manifest.test.ts`

**Interfaces:**

```ts
export type NdsExistingNitroTarget =
  | { readonly fileId: number }
  | { readonly filePath: string };

export interface NdsReplaceNitroFsFileOperation {
  readonly type: "replace-nitrofs-file";
  readonly target: NdsExistingNitroTarget;
  readonly expectedOriginalSha256: string;
  readonly replacement: { readonly artifact: string; readonly sha256: string };
}

export interface NdsAddNitroFsFileOperation {
  readonly type: "add-nitrofs-file";
  readonly path: string;
  readonly replacement: { readonly artifact: string; readonly sha256: string };
}

export interface NdsReplaceDecodedOverlayOperation {
  readonly type: "replace-decoded-overlay";
  readonly target: { readonly processor: "arm9" | "arm7"; readonly overlayId: number };
  readonly expectedStoredSha256: string;
  readonly expectedRuntimeSha256: string;
  readonly replacement: { readonly artifact: string; readonly sha256: string };
}

export type NdsMutationOperationV2 =
  | NdsReplaceBytesOperation
  | NdsReplaceComponentOperation
  | NdsReplaceNitroFsFileOperation
  | NdsAddNitroFsFileOperation
  | NdsReplaceDecodedOverlayOperation;

export interface NdsMutationManifestV2 {
  readonly format: "re-mcp-nds-mutation";
  readonly formatVersion: 2;
  readonly source: { readonly sha256: string };
  readonly output: { readonly filename: string };
  readonly operations: readonly NdsMutationOperationV2[];
}

export type NdsMutationManifest = NdsMutationManifestV1 | NdsMutationManifestV2;
```

- [ ] **Step 1: Extend fixture manifest writer without changing its default.**

```ts
readonly formatVersion?: 1 | 2;
// writer:
formatVersion: overrides.formatVersion ?? 1,
```

- [ ] **Step 2: Add a literal v1 canonical regression before parser refactor.**

For one fixed v1 manifest, store literal expected canonical JSON and SHA-256 in the test. Assert both remain exactly equal after v2 support. Do not calculate the expected SHA with production code.

- [ ] **Step 3: Write valid v2 RED cases.**

Load one manifest for each new operation with exact lowercase hashes and assert normalized fields and operation order.

- [ ] **Step 4: Write exact invalid v2 RED cases.**

Require `mutation-manifest-invalid` for:

```text
v1 + any v2-only operation
formatVersion 0, 3, or "2"
unknown operation/root/replacement keys
replace-nitrofs-file with both/neither fileId/filePath
add-nitrofs-file containing fileId/directoryId/outputOffset/alignment
replace-decoded-overlay containing compressed bytes/parameters/compressedSize
uppercase hashes
inline binary payloads
absolute/backslash/traversal paths
```

- [ ] **Step 5: Run RED.**

```bash
node --test --import tsx tests/nds-mutation-manifest-v2.test.ts
```

Expected: v2 rejected because only version 1 exists.

- [ ] **Step 6: Implement separate strict v1/v2 Zod schemas.**

Keep current v1 normalization function unchanged. Use a discriminated union on `formatVersion`. V2 reuses the v1 operation schemas plus the three new strict operation schemas.

- [ ] **Step 7: Validate new paths lexically.**

`add-nitrofs-file.path` is POSIX relative, total length `1..4096`, each segment printable ASCII `0x20..0x7e`, 1–127 bytes, not `.`/`..`, no slash/backslash/NUL inside a segment. Source collisions remain planner checks.

- [ ] **Step 8: Run focused regression.**

```bash
node --test --import tsx tests/nds-mutation-manifest.test.ts tests/nds-mutation-manifest-v2.test.ts
npm run typecheck
```

- [ ] **Step 9: Commit.**

```bash
git add src/services/nds/mutation/manifest.ts tests/helpers/nds-mutation-fixture.ts \
  tests/nds-mutation-manifest.test.ts tests/nds-mutation-manifest-v2.test.ts
git commit -m "feat: add NDS mutation manifest v2"
```

---

### Task 2: Add Rebuild-Critical Header/CRC/Capacity Contract

**Files:**
- Create: `src/services/nds/header-rebuild.ts`
- Create: `tests/nds-header-rebuild.test.ts`
- Modify: `src/services/nds/errors.ts`
- Test: `tests/nds-header.test.ts`

**Interfaces:**

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

export interface NdsOwnedHeaderRewriteInput {
  readonly deviceCapacity: number;
  readonly romUsedSize: number;
  readonly fnt?: { readonly offset: number; readonly size: number };
  readonly fat?: { readonly offset: number; readonly size: number };
  readonly arm9OverlayTable?: { readonly offset: number; readonly size: number };
  readonly arm7OverlayTable?: { readonly offset: number; readonly size: number };
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

Owned offsets:

```text
0x14         device capacity u8
0x40..0x47  FNT offset/size
0x48..0x4F  FAT offset/size
0x50..0x57  ARM9 overlay table offset/size
0x58..0x5F  ARM7 overlay table offset/size
0x80..0x83  used/logical ROM size u32
0x84..0x87  header size u32, read/preserve only
0x15E..0x15F header CRC16
```

CRC: reflected polynomial `0xA001`, initial `0xFFFF`, over bytes `0x000..0x15D`; write little-endian at `0x15E`.
Capacity: `128 KiB << deviceCapacity`; select smallest representable capacity containing logical used size, capped at 512 MiB.

- [ ] **Step 1: Write RED CRC tests with an independent test-local reference loop.**

Create deterministic 0x15E bytes, calculate one literal expected CRC with the test helper, then assert production must equal that literal. Flip one byte and assert mismatch.

- [ ] **Step 2: Write RED capacity boundaries.**

```ts
assert.equal(ndsCapacityBytes(0), 128 * 1024);
assert.equal(ndsCapacityBytes(1), 256 * 1024);
assert.equal(selectNdsDeviceCapacity(128 * 1024).deviceCapacity, 0);
assert.equal(selectNdsDeviceCapacity((128 * 1024) + 1).deviceCapacity, 1);
```

Reject invalid/unsafe values and >512 MiB.

- [ ] **Step 3: Write RED preservation test.**

Fill the 0x160 header with sentinels; change only FAT range + used size. Assert all bytes outside approved fields and CRC remain byte-identical.

- [ ] **Step 4: Run RED.**

```bash
node --test --import tsx tests/nds-header-rebuild.test.ts
```

- [ ] **Step 5: Implement copy-on-write full-header helpers and stored-CRC validation.**

`readNdsRebuildHeader()` requires a regular file with >=0x160 bytes and validates stored CRC. `serializeNdsRebuildHeader()` rewrites only provided owned fields, recomputes CRC, and never mutates source bytes.

- [ ] **Step 6: Add errors.**

```text
header-rebuild-failed
header-checksum-invalid
rom-capacity-exceeded
```

Add deterministic corrective actions to MCP error mapping.

- [ ] **Step 7: Verify.**

```bash
node --test --import tsx tests/nds-header.test.ts tests/nds-header-rebuild.test.ts
npm run typecheck
```

- [ ] **Step 8: Commit.**

```bash
git add src/services/nds/header-rebuild.ts src/services/nds/errors.ts tests/nds-header-rebuild.test.ts
git commit -m "feat: add rebuild-aware NDS header contract"
```

---

### Task 3: Plan New NitroFS Extension Trees and Serialize FNT

**Files:**
- Create: `src/services/nds/fnt-serialize.ts`
- Create: `src/services/nds/mutation/filesystem-plan.ts`
- Create: `tests/nds-fnt-serialize.test.ts`
- Modify: `tests/helpers/nds-mutation-fixture.ts`

**Interfaces:**

```ts
export interface NdsAddedDirectoryPlan {
  readonly path: string;
  readonly directoryId: number;
  readonly parentDirectoryId: number;
  readonly firstFileId: number;
}

export interface NdsAddedFilePlan {
  readonly operationIndex: number;
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

export async function planNdsFilesystemExtensions(
  map: NdsRomMap,
  workspaceRoot: string,
  operations: readonly Readonly<{ index: number; operation: NdsAddNitroFsFileOperation }>[],
): Promise<NdsFilesystemExtensionPlan>;

export function serializeExtendedNdsFnt(
  source: NdsFilesystem,
  extension: NdsFilesystemExtensionPlan,
): Buffer;
```

- [ ] **Step 1: Extend fixture with an existing nested top-level directory.**

Add `data/existing.bin` while preserving current root files and overlay file IDs.

- [ ] **Step 2: Write RED deterministic ID assignment.**

Feed operations shuffled:

```text
re_mcp/economy/e2dt.bin
re_mcp/abilities/a2dt.bin
zzz_patch/state.bin
re_mcp/attributes/i2dt.bin
```

Assert directory IDs are assigned after source directory count in lexicographic preorder; new file IDs begin at source FAT count and are ordered by directory ID then filename, independent of operation order.

- [ ] **Step 3: Write RED invalid extension cases.**

Reject existing top-level (`data/new.bin`), root insertion (`new.bin`), duplicate new path, source path collision, invalid segment, 257 files, >64 MiB aggregate new payload via injected file metadata, >0x1000 directories, >0x10000 final files, nonregular/symlink/out-of-workspace artifact, hash mismatch.

- [ ] **Step 4: Write RED semantic FNT round-trip.**

Serialize, put serialized bytes in a synthetic ROM, parse with existing `parseNdsFnt()`, and assert every source directory/file ID/path/parent/firstFileId remains semantically identical and every new file has exactly its assigned path/ID.

- [ ] **Step 5: Run RED.**

```bash
node --test --import tsx tests/nds-fnt-serialize.test.ts
```

- [ ] **Step 6: Implement deterministic trie/ID planning.**

Only new subtrees enter the trie. Existing IDs stay fixed. New directory IDs use lexicographic preorder of complete paths. New file IDs use directory-ID order then lexicographic filename.

- [ ] **Step 7: Implement serializer.**

Source segments are encoded `latin1`; new segments are validated ASCII. Existing `firstFileId` values are retained exactly. New top-level directory refs may be appended to root because directory entries do not consume file IDs.

- [ ] **Step 8: Enforce 4 MiB serialized FNT limit and reparse proof.**

- [ ] **Step 9: Verify and commit.**

```bash
node --test --import tsx tests/nds-fnt.test.ts tests/nds-fnt-serialize.test.ts
npm run typecheck
git add src/services/nds/fnt-serialize.ts src/services/nds/mutation/filesystem-plan.ts \
  tests/helpers/nds-mutation-fixture.ts tests/nds-fnt-serialize.test.ts
git commit -m "feat: plan append-only NitroFS extensions"
```

---

### Task 4: Guard Variable Existing Files and Serialize FAT

**Files:**
- Create: `src/services/nds/fat-serialize.ts`
- Create: `tests/nds-fat-serialize.test.ts`
- Modify: `src/services/nds/mutation/filesystem-plan.ts`
- Modify: `src/services/nds/mutation/guards.ts`
- Modify: `src/services/nds/mutation/conflicts.ts`
- Test: `tests/nds-mutation-guards.test.ts`
- Test: `tests/nds-mutation-conflicts.test.ts`

**Interfaces:**

```ts
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

export async function planNdsRelocatedFiles(
  map: NdsRomMap,
  workspaceRoot: string,
  operations: readonly Readonly<{ index: number; operation: NdsReplaceNitroFsFileOperation }>[],
): Promise<readonly NdsRelocatedFilePlan[]>;

export interface NdsFinalFatEntry {
  readonly fileId: number;
  readonly startOffset: number;
  readonly endOffset: number;
}

export function serializeNdsFat(entries: readonly NdsFinalFatEntry[]): Buffer;
```

- [ ] **Step 1: Write RED FAT serialization.**

Assert exact 8-byte LE records, contiguous file IDs `0..N-1`, `start <= end`, no overlapping live ranges, u32 geometry, <=4 MiB serialized output.

- [ ] **Step 2: Write RED variable replacement guards.**

For ordinary non-overlay file, smaller/equal/larger artifacts succeed only with exact source SHA, exact artifact SHA, nonempty regular contained artifact <=64 MiB, and non-no-op hash.

- [ ] **Step 3: Write RED alias/conflict cases.**

Reject overlay-backed file target, same logical file targeted by ID and path twice, `replace-nitrofs-file` + `replace-bytes` in same file, and duplicate new file paths.

- [ ] **Step 4: Run RED.**

```bash
node --test --import tsx tests/nds-fat-serialize.test.ts tests/nds-mutation-guards.test.ts tests/nds-mutation-conflicts.test.ts
```

- [ ] **Step 5: Factor one shared artifact guard helper.**

V1 component replacement and all v2 artifact operations use the same containment/non-symlink/regular/hash/size primitive; v1 same-size semantics remain unchanged.

- [ ] **Step 6: Implement FAT serializer with no placement decisions.**

- [ ] **Step 7: PR-A verification.**

```bash
npm run typecheck
npm test
npm run build
```

- [ ] **Step 8: Commit.**

```bash
git add src/services/nds/fat-serialize.ts src/services/nds/mutation/filesystem-plan.ts \
  src/services/nds/mutation/guards.ts src/services/nds/mutation/conflicts.ts \
  tests/nds-fat-serialize.test.ts tests/nds-mutation-guards.test.ts tests/nds-mutation-conflicts.test.ts
git commit -m "feat: guard variable-size NitroFS replacements"
```

**PR A merge gate:** v1 frozen canonical vector passes; all new structural tests pass; CI + Package success; review then explicit merge gate.

---

### Task 5: Implement Deterministic Repository-Owned BLZ Encoding

**Files:**
- Create: `src/services/nds/blz-encode.ts`
- Create: `tests/nds-blz-encode.test.ts`
- Test: `tests/nds-blz.test.ts`
- Test: `tests/nds-overlay-runtime.test.ts`

**Interfaces:**

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

Deterministic token rule:

1. Process high address toward low address.
2. Search displacement 3..4098 in already-decoded higher-address history.
3. Longest match wins, max 18 bytes.
4. Equal length: smallest displacement wins.
5. Use back-reference only at length >=3; otherwise literal.
6. Flags consume bits `0x80` to `0x01` in decode order.
7. Evaluate group-boundary passthrough cuts; choose smallest final stored size, tie smallest passthrough prefix.
8. Use minimum header size 8..11 needed for 4-byte-aligned stored size; header padding is `0xFF`.
9. If no nonempty encoded suffix produces a valid stored size smaller than runtime size, throw `blz-encode-failed`.

- [ ] **Step 1: Write RED deterministic vectors.**

Use current decoded compressed-code fixture, repeated zeros, repeated 16-byte pattern, and deterministic literal-heavy input. Successful vectors must satisfy `encode(input)` byte-identical across calls and `decodeNdsBlz(encoded, input.length).bytes.equals(input)`.

Literal-heavy input may deterministically fail `blz-encode-failed`; it may never emit malformed BLZ.

- [ ] **Step 2: Write tie-break fixture.**

Construct equal-length matches at two displacements and assert one literal expected encoded byte sequence using smallest displacement.

- [ ] **Step 3: Write limit RED cases.**

Reject empty input, >16 MiB runtime, >16 MiB encoded, no valid compressed suffix, and packed size >`0x00ff_ffff` through limit injection where possible.

- [ ] **Step 4: Run RED.**

```bash
node --test --import tsx tests/nds-blz-encode.test.ts
```

- [ ] **Step 5: Implement encoder as pure match/group/footer helpers.**

No randomization, timestamps, environment choice, external process, or compression-level input.

- [ ] **Step 6: Enforce production decode-back postcondition.**

```ts
const decoded = decodeNdsBlz(stored, runtime.length, limits);
if (!decoded.bytes.equals(runtime)) {
  throw new NdsError("blz-roundtrip-mismatch", "Encoded overlay did not decode to the requested runtime bytes");
}
```

- [ ] **Step 7: Verify and commit.**

```bash
node --test --import tsx tests/nds-blz.test.ts tests/nds-blz-encode.test.ts tests/nds-overlay-runtime.test.ts
npm run typecheck
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

**Interfaces:**

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

export async function planDecodedOverlayReplacement(
  map: NdsRomMap,
  workspaceRoot: string,
  index: number,
  operation: NdsReplaceDecodedOverlayOperation,
  runtimeContext: NdsOverlayRuntimeContext,
): Promise<NdsDecodedOverlayReplacementPlan>;

export function serializeNdsOverlayTable(
  source: readonly NdsOverlay[],
  compressedSizeOverrides: ReadonlyMap<number, number>,
): Buffer;
```

- [ ] **Step 1: Write RED happy path.**

Require exact source stored/runtime hashes; replacement runtime hash; artifact length exactly `ramSize`; replacement differs from source; deterministic BLZ result.

- [ ] **Step 2: Write RED failures.**

Reject uncompressed/unknown/wrong-processor overlay, source stored/runtime mismatch, artifact hash mismatch, runtime size +/-1, no-op runtime, packed-size overflow, same overlay targeted by `replace-component`/`replace-bytes`, and generic NitroFS replacement of overlay backing.

- [ ] **Step 3: Write overlay-table RED proof.**

With one override, compare every 32-byte source/output record and prove only targeted lower packed 24 bits change; flags high byte and all runtime geometry remain exact. Reparse through a temporary ROM.

- [ ] **Step 4: Run RED.**

```bash
node --test --import tsx tests/nds-overlay-rebuild.test.ts
```

- [ ] **Step 5: Implement through existing runtime decoder context.**

Use `runtimeContext.getCompressedOverlay()`; do not introduce a second decoder path. Encode replacement during planning and store bytes/hash/size in the resolved plan.

- [ ] **Step 6: Verify and commit.**

```bash
node --test --import tsx tests/nds-overlay-rebuild.test.ts tests/nds-overlay-runtime.test.ts tests/nds-mutation-conflicts.test.ts
npm run typecheck
git add src/services/nds/overlays-serialize.ts src/services/nds/mutation/overlay-plan.ts \
  src/services/nds/mutation/guards.ts src/services/nds/mutation/conflicts.ts tests/nds-overlay-rebuild.test.ts
git commit -m "feat: plan decoded overlay recompression"
```

---

### Task 7: Implement Two-Phase Append-Only Layout Allocation

**Files:**
- Create: `src/services/nds/mutation/layout.ts`
- Create: `tests/nds-rebuild-layout.test.ts`

**Interfaces:**

```ts
export const NDS_REBUILD_CONTRACT_VERSION = 1;
export const MAX_NDS_REBUILD_GROWTH_BYTES = 128 * 1024 * 1024;

export interface NdsPayloadLayoutInput {
  readonly kind: "relocated-file" | "new-file";
  readonly ownerId: string;
  readonly fileId: number;
  readonly bytes: Buffer;
  readonly sha256: string;
}

export interface NdsRebuildSegment {
  readonly kind: "relocated-file" | "new-file" | "fnt" | "fat" | "arm9-overlay-table" | "arm7-overlay-table";
  readonly ownerId: string;
  readonly alignment: 0x200 | 4;
  readonly start: number;
  readonly end: number;
  readonly size: number;
  readonly sha256: string;
  readonly bytes: Buffer;
}

export interface NdsPayloadLayout {
  readonly sourceSize: number;
  readonly tailStart: number;
  readonly segments: readonly NdsRebuildSegment[];
  readonly nextOffset: number;
}

export interface NdsMetadataLayoutInput {
  readonly fnt?: Buffer;
  readonly fat: Buffer;
  readonly arm9OverlayTable?: Buffer;
  readonly arm7OverlayTable?: Buffer;
}

export interface NdsRebuildLayout {
  readonly sourceSize: number;
  readonly tailStart: number;
  readonly logicalUsedSize: number;
  readonly finalSize: number;
  readonly deviceCapacity: number;
  readonly segments: readonly NdsRebuildSegment[];
}

export function planNdsPayloadLayout(
  sourceSize: number,
  payloads: readonly NdsPayloadLayoutInput[],
): NdsPayloadLayout;

export function finalizeNdsRebuildLayout(
  payloadLayout: NdsPayloadLayout,
  metadata: NdsMetadataLayoutInput,
): NdsRebuildLayout;
```

- [ ] **Step 1: Write RED order/alignment.**

Shuffled payload inputs must output existing relocated file IDs ascending, then new file IDs ascending. Payload starts `%0x200===0`. Metadata order: optional FNT, FAT, optional ARM9 table, optional ARM7 table; starts `%4===0`.

- [ ] **Step 2: Write RED capacity.**

`logicalUsedSize` equals final meaningful segment end; final size equals selected device capacity.

- [ ] **Step 3: Write RED hard limits without huge allocations.**

Reject unsafe/u32 overflow, >512 MiB final, >128 MiB growth, >64 MiB one artifact, >64 MiB aggregate new payload, >4 MiB FNT/FAT.

- [ ] **Step 4: Run RED.**

```bash
node --test --import tsx tests/nds-rebuild-layout.test.ts
```

- [ ] **Step 5: Implement checked `alignUp` and two-phase allocation.**

No output file is opened here. Padding is geometry only; materializer writes `0xFF`.

- [ ] **Step 6: Verify and commit.**

```bash
node --test --import tsx tests/nds-rebuild-layout.test.ts tests/nds-header-rebuild.test.ts
npm run typecheck
git add src/services/nds/mutation/layout.ts tests/nds-rebuild-layout.test.ts
git commit -m "feat: add append-only NDS rebuild layout"
```

---

### Task 8: Compile Complete V2 Plan and Exact Header Rewrites

**Files:**
- Create: `src/services/nds/mutation/header-plan.ts`
- Create: `tests/nds-mutation-planner-v2.test.ts`
- Modify: `src/services/nds/mutation/planner.ts`
- Modify: `src/services/nds/mutation/filesystem-plan.ts`
- Modify: `src/services/nds/mutation/overlay-plan.ts`
- Modify: `src/services/nds/mutation/staging.ts`
- Modify: `src/services/nds/errors.ts`
- Test: `tests/nds-mutation-planner.test.ts`

**Interfaces:**

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

export type NdsResolvedMutationOperationV2 =
  | { readonly kind: "fixed"; readonly index: number; readonly operation: GuardedNdsMutationOperation }
  | { readonly kind: "relocated-file"; readonly index: number; readonly file: NdsRelocatedFilePlan }
  | { readonly kind: "new-file"; readonly index: number; readonly file: NdsAddedFilePlan }
  | { readonly kind: "decoded-overlay"; readonly index: number; readonly overlay: NdsDecodedOverlayReplacementPlan };

export interface NdsResolvedMutationPlanV1 {
  readonly sourceRomPath: string;
  readonly sourceWorkspacePath: string;
  readonly sourceSha256: string;
  readonly sourceSha256Prefix: string;
  readonly sourceSize: number;
  readonly manifestWorkspacePath: string;
  readonly manifestSha256: string;
  readonly outputFilename: string;
  readonly buildId: string;
  readonly operations: readonly GuardedNdsMutationOperation[];
  readonly applicationOperations: readonly GuardedNdsMutationOperation[];
  readonly immutableStructuralRanges: readonly NdsMutationPhysicalRange[];
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
  readonly operations: readonly NdsResolvedMutationOperationV2[];
  readonly filesystemExtension: NdsFilesystemExtensionPlan;
  readonly finalFat: readonly NdsFinalFatEntry[];
  readonly layout: NdsRebuildLayout;
  readonly headerPlan: NdsHeaderRewritePlan;
}

export type NdsResolvedMutationPlan = NdsResolvedMutationPlanV1 | NdsResolvedMutationPlanV2;
```

- [ ] **Step 1: Freeze literal v1 resolved-plan/build-ID regression before refactor.**

Assert existing fixture's literal `manifestSha256`, `buildId`, and serialized plan.

- [ ] **Step 2: Write mixed v2 RED plan.**

Use:

```text
replace-bytes ARM9
replace-nitrofs-file ordinary file
add-nitrofs-file re_mcp/attributes/i2dt.bin
replace-decoded-overlay arm9 overlay 7
```

Assert deterministic file IDs/ranges, FNT/FAT/table hashes, ARM9 overlay table rebuilt only, exact header rewrites, logical/final sizes, source unchanged, and byte-identical plan/build ID in another absolute workspace.

- [ ] **Step 3: Implement two-phase planning.**

Order:

```text
validate source + manifest
resolve/guard fixed operations
plan variable existing files
plan extension tree/files
plan/encode decoded overlays using one shared runtime context
logical conflict checks
plan payload ranges
build final FAT using payload ranges
serialize optional FNT and overlay tables
finalize metadata layout
serialize exact output header
compile minimal contiguous header rewrites
source revalidation
```

- [ ] **Step 4: Exact header rewrite allowlist.**

Reject if source/output header differs outside device capacity, FNT/FAT/table pointer+size fields actually rebuilt, used size, and CRC.

- [ ] **Step 5: Implement v2 build identity exactly.**

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

Artifact hashes follow normalized manifest operation order. Derived BLZ stored hash is evidence, not identity input.

- [ ] **Step 6: Generalize staging artifact-alias checks.**

Enumerate artifact paths from all v1/v2 resolved operations; reject staged/final/source/manifest aliases without weakening v1 behavior.

- [ ] **Step 7: Add exact planner errors.**

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

- [ ] **Step 8: PR-B verification.**

```bash
node --test --import tsx tests/nds-mutation-planner.test.ts tests/nds-mutation-planner-v2.test.ts \
  tests/nds-rebuild-layout.test.ts tests/nds-overlay-rebuild.test.ts tests/nds-blz-encode.test.ts
npm run typecheck
npm test
npm run build
```

- [ ] **Step 9: Commit.**

```bash
git add src/services/nds/mutation/header-plan.ts src/services/nds/mutation/planner.ts \
  src/services/nds/mutation/filesystem-plan.ts src/services/nds/mutation/overlay-plan.ts \
  src/services/nds/mutation/staging.ts src/services/nds/errors.ts tests/nds-mutation-planner-v2.test.ts \
  tests/nds-mutation-planner.test.ts
git commit -m "feat: compile deterministic NDS rebuild plans"
```

**PR B merge gate:** deterministic BLZ, exact v1 planner/build-ID regression, CI + Package success, review then explicit merge gate.

---

### Task 9: Extend `apply.ts` as Sole V2 Materializer

**Files:**
- Modify: `src/services/nds/mutation/apply.ts`
- Create: `tests/nds-mutation-apply-v2.test.ts`
- Test: `tests/nds-mutation-apply.test.ts`
- Test: `tests/nds-mutation-hardening.test.ts`

**Interfaces:**

`applyNdsMutationPlan(plan, stage, io?)` remains the only writer API. V1 path remains current behavior. V2 performs no selection, hashing, compression, ID assignment, offset choice, or conflict decision.

- [ ] **Step 1: Write RED raw materialization assertions.**

After applying mixed v2 plan:

```text
source prefix differs only at fixed mutation/header rewrite ranges
relocated file/new file/encoded overlay occupy exact planned payload segments
FNT/FAT/ARM9 table occupy exact metadata segments
all gaps/padding are 0xFF
staged size == plan.layout.finalSize
source SHA unchanged
```

- [ ] **Step 2: Write injected write-failure RED cases.**

Test IO adapter fails after controlled writes. Assert source never opened `r+`, stage cleanup remains possible, no final publication.

- [ ] **Step 3: Run RED.**

```bash
node --test --import tsx tests/nds-mutation-apply-v2.test.ts
```

- [ ] **Step 4: Implement writer-local helpers.**

```ts
async function writeAt(handle: FileHandle, bytes: Uint8Array, position: number): Promise<void>;
async function fillRange(handle: FileHandle, value: number, start: number, end: number): Promise<void>;
```

V2 order: fixed prefix operations → planned tail with 0xFF gaps → header rewrites → extend/fill to final size → sync/close.

- [ ] **Step 5: Keep sole-writer hardening.**

Source scan requires only `apply.ts` in mutation services to expose staged-ROM `"r+"` open.

- [ ] **Step 6: Verify and commit.**

```bash
node --test --import tsx tests/nds-mutation-apply.test.ts tests/nds-mutation-apply-v2.test.ts tests/nds-mutation-hardening.test.ts
npm run typecheck
git add src/services/nds/mutation/apply.ts tests/nds-mutation-apply-v2.test.ts tests/nds-mutation-hardening.test.ts
git commit -m "feat: materialize append-only NDS rebuilds"
```

---

### Task 10: Add Complete V2 Semantic Verification

**Files:**
- Create: `src/services/nds/mutation/verify-v2.ts`
- Create: `tests/nds-mutation-verify-v2.test.ts`
- Modify: `src/services/nds/mutation/verify.ts`
- Modify: `src/services/nds/errors.ts`

**Interfaces:**

```ts
export interface NdsOutputRange {
  readonly start: number;
  readonly end: number;
}

export interface NdsMutationOperationVerificationV2 {
  readonly index: number;
  readonly kind: NdsResolvedMutationOperationV2["kind"];
  readonly status: "passed";
  readonly sourceRange: NdsOutputRange | null;
  readonly outputRange: NdsOutputRange;
  readonly outputSha256: string | null;
}

export interface NdsMutationVerificationResultV1 {
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
  readonly operations: readonly NdsMutationOperationVerificationV2[];
  readonly compressedOverlays: readonly NdsCompressedOverlayVerification[];
}

export type NdsMutationVerificationResult =
  | NdsMutationVerificationResultV1
  | NdsMutationVerificationResultV2;
```

- [ ] **Step 1: Write full-success RED verification.**

Require fresh canonical output parse; output SHA consistency; source unchanged; all source IDs/paths preserved; unchanged FAT ranges/hashes preserved; relocated/new file exact IDs/ranges/hashes; compressed overlay exact runtime geometry/flags/file ID and decode equality; exact header plan/CRC; exact capacity; attribution counts; zero unexpected bytes.

- [ ] **Step 2: Write tamper matrix RED.**

Individually tamper: unapproved source-prefix byte, header pointer, header CRC, relocated payload, new payload, FNT path, FAT range, overlay packed size, encoded overlay byte, alignment padding, capacity padding, truncation, extra final byte. Every case fails closed with rebuild-specific error.

- [ ] **Step 3: Prove unchanged component identity.**

Every untargeted source FAT file retains exact range/hash. Untargeted compressed overlays retain both stored and decoded runtime SHA.

- [ ] **Step 4: Run RED.**

```bash
node --test --import tsx tests/nds-mutation-verify-v2.test.ts
```

- [ ] **Step 5: Implement bounded prefix attribution.**

Every changed source-prefix byte must belong to exactly one fixed-operation range or one header rewrite range.

- [ ] **Step 6: Implement tail attribution.**

Every segment hashes exactly; every nonsegment byte from source EOF to final EOF is `0xFF`; meaningful/padding counts are separate.

- [ ] **Step 7: Implement semantic reparse proof.**

Use freshly parsed output model and rebuild header; compare filesystem/overlay/header semantics to source + resolved plan, not to planner assumptions alone.

- [ ] **Step 8: Add errors.**

```text
rebuild-prefix-diff
rebuild-tail-mismatch
filesystem-semantic-mismatch
overlay-semantic-mismatch
header-checksum-invalid
```

- [ ] **Step 9: PR-C verification.**

```bash
node --test --import tsx tests/nds-mutation-apply-v2.test.ts tests/nds-mutation-verify-v2.test.ts
npm run typecheck
npm test
npm run build
```

- [ ] **Step 10: Commit.**

```bash
git add src/services/nds/mutation/verify-v2.ts src/services/nds/mutation/verify.ts \
  src/services/nds/errors.ts tests/nds-mutation-verify-v2.test.ts
git commit -m "feat: verify rebuilt NDS semantics"
```

**PR C merge gate:** single-writer scan + tamper matrix + CI/Package success, review then explicit merge gate.

---

### Task 11: Add V2 Evidence, Fresh Reuse, and Package Smoke

**Files:**
- Create: `src/services/nds/mutation/report-v2.ts`
- Create: `tests/nds-mutation-build-v2.test.ts`
- Modify: `src/services/nds/mutation/report.ts`
- Modify: `src/services/nds/mutation/build.ts`
- Modify: `tests/nds-mutation-build.test.ts`
- Modify: `scripts/check-nds-mutation-install.mjs`
- Modify: `.github/workflows/package.yml`

**Interfaces:**

V1 evidence remains exactly current. V2 adds exactly `rebuild-layout.json`.

```ts
export function ndsMutationEvidenceFilenames(
  plan: NdsResolvedMutationPlan,
): readonly string[];
```

V2 `rebuild-layout.json` records only deterministic metadata: contract versions, source/tail/logical/final sizes, capacity, exact header rewrites, ordered segments, assigned new IDs, hashes, and no absolute paths/timestamps/PIDs/temp names.

- [ ] **Step 1: Freeze v1 evidence entry set.**

No `rebuild-layout.json` for v1.

- [ ] **Step 2: Write v2 RED evidence/build tests.**

Require one mixed v2 build produces valid `rebuild-layout.json`, exact rebuilt ROM/evidence, and source unchanged.

- [ ] **Step 3: Cross-workspace determinism.**

Byte-identical inputs under different absolute roots produce identical build ID, ROM bytes, and every evidence file.

- [ ] **Step 4: Fresh reuse/tamper.**

Second exact run is reused only after complete fresh v2 verification. Tamper each ROM/evidence entry separately: `publish-collision`, no repair.

- [ ] **Step 5: Make exact published entry list version-aware.**

`requireExactPublishedEntries()` uses `ndsMutationEvidenceFilenames(plan)` + output ROM.

- [ ] **Step 6: Extend assembled package smoke.**

Using only built `dist/` modules, the synthetic v2 ROM must initialize a valid 0x160-byte rebuild header and matching header CRC before planning. It must exercise:

```text
variable ordinary NitroFS replacement
new re_mcp/smoke/state.bin
one decoded compressed overlay replacement/recompression
FNT/FAT/ARM9 overlay table/header rebuild
fresh verify
second-run reuse
source byte-identical
```

- [ ] **Step 7: Require smoke markers.**

```text
NDS mutation package smoke passed
NDS rebuild Core 2 package smoke passed
```

Package workflow must run the script before artifact upload.

- [ ] **Step 8: Verify and commit.**

```bash
node --test --import tsx tests/nds-mutation-build.test.ts tests/nds-mutation-build-v2.test.ts
npm run build
node scripts/check-nds-mutation-install.mjs .
git add src/services/nds/mutation/report-v2.ts src/services/nds/mutation/report.ts \
  src/services/nds/mutation/build.ts tests/nds-mutation-build.test.ts tests/nds-mutation-build-v2.test.ts \
  scripts/check-nds-mutation-install.mjs .github/workflows/package.yml
git commit -m "feat: publish deterministic NDS rebuild evidence"
```

---

### Task 12: Harden Public Boundaries, Document Core 2, and Run Final Acceptance

**Files:**
- Create: `tests/nds-rebuild-hardening.test.ts`
- Modify: `tests/nds-mutation-tools.test.ts`
- Modify: `tests/nds-mutation-capability.test.ts`
- Modify: `README.md`

**Interfaces:**

No new public tool. Existing schemas remain `rom` + `manifest` only.

- [ ] **Step 1: Write public-schema regression.**

```ts
assert.deepEqual([...toolNames].sort(), [
  "nds_mutation_build",
  "nds_mutation_validate",
  "nds_mutation_verify",
]);
```

Reject MCP input keys `romOffset`, `offset`, `outputPath`, `alignment`, `fileId`, `directoryId`, `compressedSize`, `blzOptions`.

- [ ] **Step 2: Add source hardening scans.**

Require:

```text
only apply.ts has staged mutation "r+" capability
blz-encode.ts contains no child_process/spawn/exec
no source-gap allocator path exists
manifest v2 exposes no caller new numeric IDs or output offsets/alignment/capacity
replace-decoded-overlay accepts decoded artifact only, no stored BLZ params
package smoke contains all three Core 2 operations and source/reuse assertions
```

- [ ] **Step 3: Add analysis/Ghidra compatibility regression statement/test.**

Build output must have a new full ROM SHA, reparsed canonical geometry, and no code path may reuse source-ROM Ghidra state by path alone. Existing full-SHA project keying tests must remain green; no Ghidra production changes are expected.

- [ ] **Step 4: Update README.**

Document v1 vs v2, append-only layout, variable NitroFS replacement, new source-absent extension subtrees, decoded overlay recompression, deterministic IDs, source immutability, capacity growth, and `rebuild-layout.json`.

Explicit exclusions:

```text
ARM9/ARM7 initialized-size growth
overlay ramSize/BSS growth/new overlays/runtime relocation
code allocation/hooks/trampolines
watchpoints/runtime memory writes
save-format migration semantics
text/graphics semantic inference
file deletion/renaming
whole-ROM compaction
natural-language patch compilation
multi-patch orchestration
automatic gameplay acceptance
```

- [ ] **Step 5: Update capability wording without new tool registration.**

State manifest-v2 append-only FAT/FNT/overlay metadata rebuild is guarded/controlled; do not claim excluded later milestones.

- [ ] **Step 6: Run full local acceptance.**

```bash
npm run typecheck
npm test
npm run build
node scripts/check-nds-mutation-install.mjs .
git diff --check
```

- [ ] **Step 7: Confirm exact regression matrix from logs.**

```text
all pre-Core-2 v1 tests pass
frozen v1 canonical manifest hash passes
frozen v1 resolved plan/build ID passes
v1 evidence set unchanged
v2 variable file rebuild passes
v2 extension file rebuild passes
v2 decoded overlay round-trip passes
v2 mixed build passes
v2 tamper matrix fails closed
cross-workspace deterministic output passes
single-writer scan passes
no external BLZ process scan passes
assembled Core 2 package smoke passes
```

- [ ] **Step 8: Commit.**

```bash
git add tests/nds-rebuild-hardening.test.ts tests/nds-mutation-tools.test.ts \
  tests/nds-mutation-capability.test.ts README.md
git commit -m "docs: complete NDS Rebuild Core 2"
```

- [ ] **Step 9: PR-D exact-head gate.**

Require CI success, Package success, Ghidra acceptance skipped by path filter or successful if triggered, zero unresolved review threads, then stop for explicit user merge approval.

---

## Final Acceptance Matrix

| Contract | Required proof |
|---|---|
| V1 compatibility | Frozen manifest hash, resolved plan/build ID, evidence set, complete old tests |
| V2 schema | Strict operations; no arbitrary offset/ID/layout controls |
| Source safety | Source SHA unchanged after validate/build/verify and injected failures |
| Variable existing file | Same file ID/path; deterministic new FAT range; exact replacement hash |
| Extension files | New source-absent subtree only; deterministic appended IDs; exact path/hash |
| FNT | Source semantics plus approved additions only; <=4 MiB |
| FAT | Source IDs preserved; unchanged ranges preserved; relocated/new ranges exact; <=4 MiB |
| BLZ | Repository-owned deterministic encoder; exact decode-back; limits enforced |
| Overlay | Runtime geometry/flags/file ID preserved; only stored size/FAT backing changes |
| Layout | No source-gap allocation; deterministic order/alignment/padding |
| Header | Only owned fields + CRC change; used size/capacity exact |
| Bounds | <=512 MiB final; <=128 MiB growth; u32/safe-integer checks |
| Writer | `apply.ts` sole staged-ROM writer |
| Verification | Full prefix/tail attribution + semantic reparse + `unexpectedChangedBytes=0` |
| Publication | Atomic; deterministic; fresh reuse only; tamper fails closed |
| Public surface | Exactly three tools; only ROM + manifest inputs |
| Package | Compiled assembled bundle runs real Core 2 build/verify/reuse smoke |
| Scope | No executable growth/hooks/watchpoints/save semantics/orchestration |

## Next Milestone Handoff

After Core 2 is merged, do **not** go live on the Bakugan patch suite. Begin the design cycle for **Executable Injection + Hook Core**, because the Attribute, Ability, and Economy plans require runtime module/hook insertion and the Career plan later requires controlled runtime experiments. Core 2 provides the safe container/recompression foundation for that work.
