# Controlled NDS Compressed Overlay Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decode canonical Nintendo DS BLZ/code-compressed overlays into provenance-tracked runtime images, let the existing static-analysis stack consume those exact runtime bytes, and safely import the same derived images into controlled Ghidra projects.

**Architecture:** Keep the existing validated ROM/FAT/overlay map as authority. Add a bounded internal BLZ decoder and operation-scoped overlay-runtime context, then generalize code sources from direct-ROM-only bytes to either `rom-file-backed` or `derived-overlay`. All static-analysis and Ghidra consumers use the same decoded runtime representation; decompressed bytes never receive a fabricated direct ROM offset.

**Tech Stack:** TypeScript/Node.js 20, existing RE-MCP NDS parser/resolver services, Capstone.js/WASM, Java Ghidra scripts, Ghidra 12.1.2 with JDK 21 for manual acceptance. No new production runtime dependency.

## Global Constraints

- Source ROM is immutable and must match the canonical full SHA-256 before and after derived-byte operations.
- Maximum stored compressed overlay: **16 MiB**.
- Maximum decoded overlay runtime image: **16 MiB**.
- Maximum aggregate decoded-overlay bytes in one top-level operation: **64 MiB**.
- Expected decoded initialized size comes only from canonical overlay `ramSize`.
- BSS is excluded from decoded initialized bytes and remains runtime-only/uninitialized.
- A decompressed runtime byte has canonical runtime identity and exact `runtimeImageOffset`, but `romOffset` is `null`.
- `nds_resolve_rom_offset` remains physical-storage semantics.
- `nds_search_pattern` remains physical-ROM search; no silent decoded-runtime search is added.
- Overlapping overlay ranges remain ambiguous unless the existing explicit canonical overlay selector selects one overlay.
- Explicit overlay selection is static identity only and does not claim the overlay is loaded at runtime.
- Function proof remains limited to existing deterministic proof: processor program entry and exact resolved direct calls.
- Decompression, alignment, prologue appearance, Ghidra output, and explicit overlay selection are not function proof.
- Ghidra Java scripts consume Node-generated derived artifacts; Java does not implement BLZ.
- No BLZ recompression, ROM rebuilding, patch generation, generic decompression MCP tool, caller-selected output path, compressed ARM9-main support, LZ10/LZ11/RLE/Huffman asset decompression, runtime loaded-overlay detection, or Ghidra-to-RE-MCP evidence promotion.
- No DeSmuME/GDB/debug-controller/owned-process production behavior changes.

---

## Delivery topology

Use three independently verified PRs:

1. **PR A — Native decoder + canonical runtime images:** Tasks 1–3. Continue draft PR #27 and include the approved design/plan.
2. **PR B — Static-analysis consumption + generated artifacts:** Tasks 4–7, branch from `main` only after PR A merges.
3. **PR C — Controlled Ghidra import + real acceptance:** Tasks 8–10, branch from `main` only after PR B merges.

---

### Task 1: Bounded Nintendo DS BLZ decoder

**Files:**
- Create: `src/services/nds/blz.ts`
- Modify: `src/services/nds/errors.ts`
- Create: `tests/nds-blz.test.ts`
- Add fixtures: `tests/fixtures/nds-blz/literal-only.bin`
- Add fixtures: `tests/fixtures/nds-blz/literal-only.dec.bin`
- Add fixtures: `tests/fixtures/nds-blz/backreference.bin`
- Add fixtures: `tests/fixtures/nds-blz/backreference.dec.bin`
- Add fixtures: `tests/fixtures/nds-blz/mixed-groups.bin`
- Add fixtures: `tests/fixtures/nds-blz/mixed-groups.dec.bin`
- Add fixtures: `tests/fixtures/nds-blz/uncompressed-prefix.bin`
- Add fixtures: `tests/fixtures/nds-blz/uncompressed-prefix.dec.bin`

**Interfaces:**

```ts
export interface NdsBlzLimits {
  readonly maxStoredBytes: number;
  readonly maxDecodedBytes: number;
}

export interface NdsBlzDecodeResult {
  readonly bytes: Buffer;
  readonly storedSize: number;
  readonly decodedSize: number;
  readonly headerSize: number;
  readonly encodedRegionSize: number;
}

export const DEFAULT_NDS_BLZ_LIMITS: NdsBlzLimits;

export function decodeNdsBlz(
  stored: Buffer,
  expectedDecodedSize: number,
  limits?: NdsBlzLimits,
): NdsBlzDecodeResult;
```

Add:

```ts
export type NdsBlzErrorCategory =
  | "malformed-blz"
  | "blz-output-size-mismatch"
  | "blz-output-limit";
```

and include it in `NdsServiceErrorCategory`/the NDS service error union used by callers.

- [ ] **Step 1: Commit independent golden vectors before decoder implementation**

Cross-check each compressed fixture with an established Nintendo DS code-compression implementation outside production code. Use overlay compression semantics, not ARM9-main compression. Commit only the compressed bytes and expected decoded bytes; CI must not import the external implementation.

- [ ] **Step 2: Write RED fixture tests**

`tests/nds-blz.test.ts` reads each pair and checks exact output:

```ts
const result = decodeNdsBlz(stored, expected.length);
assert.deepEqual(result.bytes, expected);
assert.equal(result.storedSize, stored.length);
assert.equal(result.decodedSize, expected.length);
assert.ok(result.headerSize >= 8);
assert.ok(result.encodedRegionSize > 0);
```

Add direct malformed vectors in the test for a 7-byte footer truncation, impossible header geometry, truncated control/token data, invalid back-reference history, decoded-size mismatch, stored-size limit, and decoded-size limit. Use small custom limits for limit tests to avoid unnecessary large allocations.

- [ ] **Step 3: Run the RED test**

```bash
npm test -- tests/nds-blz.test.ts
```

Expected: FAIL because `src/services/nds/blz.ts` is absent.

- [ ] **Step 4: Implement `decodeNdsBlz()`**

The implementation must:

1. reject unsafe/non-positive expected sizes;
2. reject stored/output sizes above configured limits before allocating output;
3. parse the NDS code-compression footer from the end of the input;
4. validate header length, compressed region length, and uncompressed-prefix geometry before indexing;
5. copy the uncompressed prefix exactly;
6. decode control groups backwards from the encoded region;
7. copy clear-bit tokens as backwards literals;
8. decode set-bit two-byte tokens as backwards `(length, displacement)` copies;
9. reject a back-reference unless every source byte comes from already-decoded history;
10. reject any read/write index that leaves the validated encoded/output ranges;
11. require final decoded length to equal `expectedDecodedSize` exactly.

Allocate returned bytes only after all size limits are validated. Because callers use this function only for canonically marked compressed overlays, an invalid stream throws instead of returning the stored input unchanged.

- [ ] **Step 5: Verify GREEN**

```bash
npm test -- tests/nds-blz.test.ts
npm run check
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/services/nds/blz.ts src/services/nds/errors.ts tests/nds-blz.test.ts tests/fixtures/nds-blz
git commit -m "feat: add bounded NDS BLZ decoder"
```

---

### Task 2: Canonical compressed-overlay runtime images and aggregate budgets

**Files:**
- Create: `src/services/nds/overlay-runtime.ts`
- Create: `tests/nds-overlay-runtime.test.ts`
- Modify: `src/services/nds/errors.ts`

**Interfaces:**

```ts
export interface NdsOverlayRuntimeImage {
  readonly processor: NdsProcessor;
  readonly overlayId: number;
  readonly fileId: number;
  readonly sourceRomSha256: string;
  readonly storedRomOffset: number;
  readonly storedSize: number;
  readonly storedSha256: string;
  readonly runtimeAddress: number;
  readonly runtimeSize: number;
  readonly bssSize: number;
  readonly representation: "derived-blz";
  readonly runtimeSha256: string;
  readonly bytes: Buffer;
}

export interface NdsOverlayRuntimeLimits {
  readonly maxStoredBytes: number;
  readonly maxDecodedBytes: number;
  readonly maxAggregateDecodedBytes: number;
}

export interface NdsOverlayRuntimeContext {
  getCompressedOverlay(
    processor: NdsProcessor,
    overlayId: number,
  ): Promise<NdsOverlayRuntimeImage>;
  readonly decodedBytesCharged: number;
}

export function createNdsOverlayRuntimeContext(
  map: NdsRomMap,
  limits?: Partial<NdsOverlayRuntimeLimits>,
): NdsOverlayRuntimeContext;
```

Add category `"compressed-overlay-runtime-unavailable"` for canonical selection/runtime-image failures that are not BLZ stream errors.

- [ ] **Step 1: Write RED runtime-image tests**

Build synthetic ARM9 and ARM7 compressed overlays whose FAT entries contain Task 1 fixture bytes. Assert runtime/stored sizes, both SHA-256 hashes, runtime base, BSS exclusion, `representation === "derived-blz"`, and exact decoded bytes.

Add tests proving:
- unknown overlay ID fails;
- uncompressed overlay ID fails the compressed-only service;
- stored/decoded limit failures are rejected before a cache entry is created;
- repeated lookup of the same processor/overlay returns the same cached image and charges decoded bytes once;
- different overlays charge aggregate decoded size independently and fail before exceeding the configured aggregate cap;
- source mutation before read and during decode is rejected;
- a cached image is not returned after the source ROM no longer matches `map.sha256`.

- [ ] **Step 2: Run RED**

```bash
npm test -- tests/nds-overlay-runtime.test.ts
```

Expected: FAIL because `overlay-runtime.ts` is absent.

- [ ] **Step 3: Implement canonical lookup and decode context**

Use exact canonical lookup:

```ts
const overlays = processor === "arm9" ? map.overlays.arm9 : map.overlays.arm7;
const overlay = overlays.find((candidate) => candidate.overlayId === overlayId);
if (overlay === undefined || !overlay.compressed) {
  throw new NdsError(
    "compressed-overlay-runtime-unavailable",
    `${processor.toUpperCase()} overlay ${overlayId} is not a canonical compressed overlay`,
  );
}
```

Before reading stored bytes, require `hashFileSha256(map.romPath) === map.sha256`. Read exactly `[overlay.romOffset, overlay.romOffset + overlay.romSize)`, compute `storedSha256`, decode with `overlay.ramSize`, compute `runtimeSha256`, and re-hash the ROM before cache/return. Cache key: `${processor}:${overlayId}`. Charge aggregate decoded bytes only after a unique decode succeeds.

- [ ] **Step 4: Verify GREEN**

```bash
npm test -- tests/nds-overlay-runtime.test.ts tests/nds-blz.test.ts
npm run check
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/services/nds/overlay-runtime.ts src/services/nds/errors.ts tests/nds-overlay-runtime.test.ts
git commit -m "feat: add canonical compressed overlay runtime images"
```

---

### Task 3: Resolver provenance for derived runtime bytes

**Files:**
- Modify: `src/services/nds/resolver.ts`
- Modify: `tests/nds-resolver.test.ts`

**Interfaces:** Extend `RuntimeCandidate`:

```ts
readonly runtimeImageOffset: number | null;
readonly representation: "rom-file-backed" | "derived-overlay" | "runtime-only";
```

Mapping rules:
- main/uncompressed initialized: `rom-file-backed`, exact `romOffset`, `runtimeImageOffset = relativeOffset`;
- compressed initialized overlay: `derived-overlay`, `romOffset = null`, `runtimeImageOffset = relativeOffset`;
- BSS: `runtime-only`, `romOffset = null`, `runtimeImageOffset = null`.

Existing `backingRomOffset`, `backingRomSize`, `fileId`, and compression metadata remain physical provenance.

- [ ] **Step 1: Write RED resolver tests**

For a compressed initialized address require `status === "compressed-no-direct-rom-mapping"`, `representation === "derived-overlay"`, `romOffset === null`, exact `runtimeImageOffset`, and exact backing storage range. For BSS require runtime-only/null offsets. For `resolveRomOffset()` inside compressed FAT storage require the overlay storage match to keep `runtimeAddress === null`.

- [ ] **Step 2: Run RED**

```bash
npm test -- tests/nds-resolver.test.ts
```

Expected: FAIL because the new provenance fields are absent.

- [ ] **Step 3: Populate every resolver candidate deterministically**

Do not change resolver statuses in this task. PR B's byte-source layer converts a compressed runtime candidate into usable derived code; physical ROM-offset resolution stays unchanged.

- [ ] **Step 4: Verify PR A**

```bash
npm test -- tests/nds-resolver.test.ts
npm run check
npm test
npm run build
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/services/nds/resolver.ts tests/nds-resolver.test.ts
git commit -m "feat: expose compressed overlay runtime provenance"
```

### PR A gate

- [ ] Update PR #27 body/title from design-only wording to the implemented PR A scope.
- [ ] Require exact-head CI success: install, type-check, full tests, build.
- [ ] Require exact-head Package success.
- [ ] Compare against `main` and confirm no DeSmuME/GDB/controller/process-lifecycle production file changed.
- [ ] Mark ready only when the exact head is green; merge only through the protected explicit approval gate.

---

### Task 4: Generalize `NdsCodeSource` and exact byte reading

**PR B branch:** `feature/nds-compressed-overlay-static-analysis`, created from updated `main` after PR A merges.

**Files:**
- Modify: `src/services/nds/disassembly-source.ts`
- Modify: `tests/nds-disassembly-source.test.ts`

**Interfaces:**

```ts
export type NdsCodeRepresentation = "rom-file-backed" | "derived-overlay";

export interface NdsCodeSource {
  readonly processor: NdsProcessor;
  readonly component: "main" | "overlay";
  readonly overlayId: number | null;
  readonly runtimeAddress: number;
  readonly romOffset: number | null;
  readonly runtimeImageOffset: number;
  readonly runtimeStart: number;
  readonly runtimeEnd: number;
  readonly romStart: number | null;
  readonly romEnd: number | null;
  readonly representation: NdsCodeRepresentation;
  readonly mode: ArmMode;
}

export async function withValidatedNdsCodeReader<T>(
  map: NdsRomMap,
  callback: (
    read: (source: NdsCodeSource, maxBytes: number) => Promise<Buffer>,
  ) => Promise<T>,
): Promise<T>;
```

`withValidatedNdsCodeReader()` owns one `NdsOverlayRuntimeContext` for the full callback, so one top-level static operation gets decode reuse plus the 64 MiB aggregate cap.

- [ ] **Step 1: Characterize current main/uncompressed behavior**

Before type changes, add green tests pinning main and uncompressed overlay source runtime range, exact ROM offset, ARM/Thumb alignment, `codeSourceAt()`, and control-flow retargeting.

- [ ] **Step 2: Add RED compressed-runtime source tests**

For runtime address + explicit compressed `overlayId`, require `status === "resolved"`, `representation === "derived-overlay"`, `romOffset === null`, and exact `runtimeImageOffset`. Without overlay ID, overlapping runtime candidates remain `ambiguous-code-source`. A ROM-offset selector into compressed storage must not resolve as decoded runtime code.

- [ ] **Step 3: Run RED**

```bash
npm test -- tests/nds-disassembly-source.test.ts
```

Expected: compressed source assertions FAIL.

- [ ] **Step 4: Refactor source classification and `codeSourceAt()`**

Compressed initialized runtime candidates become derived sources. `codeSourceAt()` advances `runtimeImageOffset` by runtime delta; it advances `romOffset` only for `rom-file-backed` sources. Component boundaries use `runtimeEnd`, not a nullable ROM end.

- [ ] **Step 5: Implement `withValidatedNdsCodeReader()`**

For ROM-backed sources read the existing exact ROM range. For derived sources obtain `runtimeContext.getCompressedOverlay(source.processor, source.overlayId)` and return the bounded slice beginning at `source.runtimeImageOffset`. Require non-null overlay ID for `derived-overlay` and throw an internal NDS range error if that invariant is broken.

Keep ROM SHA verification before the callback and after the callback.

- [ ] **Step 6: Verify GREEN**

```bash
npm test -- tests/nds-disassembly-source.test.ts tests/nds-overlay-runtime.test.ts
npm run check
```

Expected: PASS after internal reader imports are renamed.

- [ ] **Step 7: Commit**

```bash
git add src/services/nds/disassembly-source.ts tests/nds-disassembly-source.test.ts
git commit -m "feat: read NDS code from canonical runtime images"
```

---

### Task 5: Disassembly, CFG, references, and xrefs over decoded overlays

**Files:**
- Modify: `src/services/nds/disassembly.ts`
- Modify: `src/services/nds/control-flow.ts`
- Modify: `src/services/nds/references.ts`
- Modify: `src/services/nds/reference-list.ts`
- Modify: `src/services/nds/xref-source.ts`
- Modify: `src/services/nds/xrefs.ts`
- Modify: `tests/nds-disassembly.test.ts`
- Modify: `tests/nds-control-flow.test.ts`
- Modify: `tests/nds-reference-list.test.ts`
- Modify: `tests/nds-xrefs.test.ts`
- Modify: `tests/nds-reference-target-mode.test.ts`

**Type changes:**

```ts
export interface StaticInstruction {
  readonly address: number;
  readonly romOffset: number | null;
  // existing remaining fields unchanged
}
```

and:

```ts
StaticReference["source"]["instructionRomOffset"]: number | null
```

Target `romOffset` is already nullable and remains so.

- [ ] **Step 1: Add a synthetic compressed-code fixture shared by focused static tests**

Decoded bytes contain valid ARM/Thumb instructions, an exact direct branch/call, and a deterministic PC-relative/literal reference. The ROM contains BLZ stored bytes, so a test can prove returned instructions match decoded bytes rather than compressed storage.

- [ ] **Step 2: Write RED end-to-end assertions**

Require:
- linear disassembly returns expected decoded mnemonics/bytes;
- `StaticInstruction.romOffset === null` and canonical overlay source identity is retained;
- component-boundary logic uses runtime initialized end;
- CFG follows an in-overlay deterministic edge;
- `StaticReference.source.instructionRomOffset === null` for decoded code;
- reference target resolution remains canonical;
- reverse xref discovery finds the same decoded direct reference;
- overlapping compressed overlays remain ambiguous without explicit overlay selection.

- [ ] **Step 3: Run RED**

```bash
npm test -- tests/nds-disassembly.test.ts tests/nds-control-flow.test.ts tests/nds-reference-list.test.ts tests/nds-xrefs.test.ts tests/nds-reference-target-mode.test.ts
```

Expected: compressed cases/type assertions FAIL.

- [ ] **Step 4: Route exact reads through `withValidatedNdsCodeReader()`**

Replace `withValidatedNdsRomReader` imports. Remove arithmetic that assumes `source.romOffset`/`romEnd` are numbers. Use runtime range for read/component boundaries and canonical processor/component/overlay/runtime/mode for identity.

- [ ] **Step 5: Update reference source provenance**

Copy `instruction.romOffset` as nullable. Sorting/dedup remains based on processor/component/overlay/instruction runtime address/mode/reference kind/target runtime address, so nullable physical provenance must not become identity.

- [ ] **Step 6: Verify GREEN**

```bash
npm test -- tests/nds-disassembly.test.ts tests/nds-control-flow.test.ts tests/nds-reference-list.test.ts tests/nds-xrefs.test.ts tests/nds-reference-target-mode.test.ts
npm run check
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/services/nds/disassembly.ts src/services/nds/control-flow.ts src/services/nds/references.ts src/services/nds/reference-list.ts src/services/nds/xref-source.ts src/services/nds/xrefs.ts tests/nds-disassembly.test.ts tests/nds-control-flow.test.ts tests/nds-reference-list.test.ts tests/nds-xrefs.test.ts tests/nds-reference-target-mode.test.ts
git commit -m "feat: analyze compressed NDS overlay code"
```

---

### Task 6: Proven function discovery and focused analysis with nullable ROM provenance

**Files:**
- Modify: `src/services/nds/function-model.ts`
- Modify: `src/services/nds/function-source.ts`
- Modify: `src/services/nds/function-discovery.ts`
- Modify: `src/services/nds/function-analysis.ts`
- Modify: `tests/nds-function-model.test.ts`
- Modify: `tests/nds-function-source.test.ts`
- Modify: `tests/nds-function-discovery.test.ts`
- Modify: `tests/nds-function-analysis.test.ts`
- Modify: `tests/nds-function-integrity.test.ts`

**Type changes:**

```ts
export interface ProvenFunctionIdentity {
  readonly processor: NdsProcessor;
  readonly component: "main" | "overlay";
  readonly overlayId: number | null;
  readonly runtimeAddress: number;
  readonly romOffset: number | null;
  readonly mode: ArmMode;
}
```

Change both direct-call physical provenance fields to nullable:

```ts
FunctionProof direct-call caller.instructionRomOffset: number | null
ProvenFunctionCallEdge.instructionRomOffset: number | null
```

Function IDs and comparison remain based on processor/component/overlay/runtime/mode, not ROM offset.

- [ ] **Step 1: Write RED model/proof tests**

Assert derived overlay function identities allow `romOffset: null`, IDs remain stable, and direct-call proof/call edges preserve `instructionRomOffset: null`.

Add a compressed overlay with an explicit coverage seed containing one direct call to a second entry. Require the second entry to be proven only by exact `direct-call` evidence. Require the explicit seed itself and a prologue-looking byte sequence to remain unproven.

- [ ] **Step 2: Run RED**

```bash
npm test -- tests/nds-function-model.test.ts tests/nds-function-source.test.ts tests/nds-function-discovery.test.ts tests/nds-function-analysis.test.ts tests/nds-function-integrity.test.ts
```

Expected: nullable-provenance/compressed cases FAIL.

- [ ] **Step 3: Update function model and proof propagation**

`identityFromSource()` copies nullable `source.romOffset`. Direct-call evidence copies nullable instruction ROM provenance. Coverage no longer reports `compressed-overlay-not-decodable` for a successfully decoded overlay. If decoding fails because BLZ is malformed or a decode budget is exceeded, coverage remains incomplete and surfaces a deterministic truncation/error reason; stored compressed bytes are never interpreted as instructions.

- [ ] **Step 4: Preserve proof boundary**

`canonicalizeFunctionTarget()` still calls canonical code-source resolution and requires the selected component set. Do not add heuristic seeds, prologue recognition, Ghidra facts, or branch-only proof.

- [ ] **Step 5: Verify GREEN**

```bash
npm test -- tests/nds-function-model.test.ts tests/nds-function-source.test.ts tests/nds-function-discovery.test.ts tests/nds-function-analysis.test.ts tests/nds-function-integrity.test.ts
npm run check
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/services/nds/function-model.ts src/services/nds/function-source.ts src/services/nds/function-discovery.ts src/services/nds/function-analysis.ts tests/nds-function-model.test.ts tests/nds-function-source.test.ts tests/nds-function-discovery.test.ts tests/nds-function-analysis.test.ts tests/nds-function-integrity.test.ts
git commit -m "feat: prove functions in decoded NDS overlays"
```

---

### Task 7: Deterministic derived artifacts in analysis bundles and package smoke

**Files:**
- Create: `src/services/nds/derived-artifacts.ts`
- Modify: `src/services/nds/extraction.ts`
- Modify: `tests/nds-extraction.test.ts`
- Modify: `scripts/check-install.mjs`

**Interfaces:**

```ts
export interface NdsDerivedOverlayArtifact {
  readonly output: string;
  readonly representation: "derived-blz";
  readonly processor: NdsProcessor;
  readonly overlayId: number;
  readonly fileId: number;
  readonly storedRomOffset: number;
  readonly storedSize: number;
  readonly storedSha256: string;
  readonly runtimeAddress: number;
  readonly runtimeSize: number;
  readonly runtimeSha256: string;
  readonly bssSize: number;
}

export async function writeNdsDerivedOverlayArtifact(
  root: string,
  image: NdsOverlayRuntimeImage,
): Promise<NdsDerivedOverlayArtifact>;
```

Path:

```text
analysis/generated/nds/<sha-prefix>/derived/overlays/<processor>/overlay-<id>.runtime.bin
```

- [ ] **Step 1: Write RED bundle tests**

Require a compressed overlay bundle to contain both exact stored extraction under `overlays/<processor>/overlay_<id>.bin` and decoded runtime artifact under `derived/overlays/<processor>/overlay-<id>.runtime.bin`. Assert exact stored/runtime hashes, `runtimeSize === ramSize`, and BSS exclusion.

Add a mutation/promotion failure test proving the previous final bundle remains intact and the temporary tree is removed.

- [ ] **Step 2: Run RED**

```bash
npm test -- tests/nds-extraction.test.ts
```

Expected: FAIL because derived artifacts are absent.

- [ ] **Step 3: Implement atomic derived writer**

`writeNdsDerivedOverlayArtifact()` writes `image.bytes` to a temporary file inside the supplied generated root, syncs it, verifies the resulting SHA-256 equals `image.runtimeSha256`, and renames atomically to the deterministic path. It never accepts a caller/MCP path; `root` is only the internally selected analysis-bundle temporary root.

- [ ] **Step 4: Integrate with the existing bundle transaction**

Create one `NdsOverlayRuntimeContext` for `extractNdsAnalysisBundle()`. Keep every stored overlay extraction unchanged. For each compressed overlay also get its runtime image and write a derived artifact inside the same temporary bundle. Add a `derivedOverlays` array to `manifest.json`; bump the static-analysis bundle `formatVersion` from 1 to 2. Perform the existing final source SHA check before temp→final promotion.

`extractNdsComponent()` remains stored-byte extraction only.

- [ ] **Step 5: Extend packaged smoke**

`check-install.mjs` creates a valid synthetic ROM with one small compressed overlay using committed fixture bytes, runs compiled production bundle generation, and requires the generated runtime artifact bytes/hash to match the committed expected decoded bytes. The package check does not invoke Python, ndspy, Ghidra, or a network resource.

- [ ] **Step 6: Verify PR B**

```bash
npm test -- tests/nds-extraction.test.ts
npm run check
npm test
npm run build
node scripts/check-install.mjs .
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/services/nds/derived-artifacts.ts src/services/nds/extraction.ts tests/nds-extraction.test.ts scripts/check-install.mjs
git commit -m "feat: persist decoded overlay analysis artifacts"
```

### PR B gate

- [ ] Require exact-head CI and Package success.
- [ ] Run existing `nds_search_pattern` tests and explicitly confirm compressed-overlay matches still describe stored FAT bytes only.
- [ ] Compare against `main`; confirm no DeSmuME/GDB/controller/process-lifecycle production files changed.
- [ ] Merge only through the protected explicit approval gate.

---

### Task 8: Ghidra bridge manifest for derived overlay artifacts

**PR C branch:** `feature/nds-compressed-overlay-ghidra`, created from updated `main` after PR B merges.

**Files:**
- Modify: `src/services/nds/ghidra-model.ts`
- Modify: `src/services/nds/ghidra-bridge.ts`
- Modify: `tests/nds-ghidra-model.test.ts`
- Modify: `tests/nds-ghidra-bridge.test.ts`

**Interfaces:** Bump `GHIDRA_BRIDGE_FORMAT_VERSION` from 1 to 2.

```ts
export type GhidraOverlayImportStatus =
  | "importable"
  | "importable-derived";

export interface GhidraOverlayManifest {
  readonly processor: NdsProcessor;
  readonly overlayId: number;
  readonly spaceName: string;
  readonly artifactPath: string;
  readonly fileId: number;
  readonly runtimeAddress: number;
  readonly ramSize: number;
  readonly bssSize: number;
  readonly representation: "rom-file-backed" | "derived-blz";
  readonly initializedSize: number;
  readonly storedRomOffset: number;
  readonly storedSize: number;
  readonly storedSha256: string;
  readonly runtimeSha256: string;
  readonly compressed: boolean;
  readonly compressedSize: number | null;
  readonly importStatus: GhidraOverlayImportStatus;
}
```

For uncompressed overlays, `artifactPath` remains the stored overlay artifact, `representation = "rom-file-backed"`, `initializedSize = Math.min(ramSize, romSize)`, and `importStatus = "importable"`.

For compressed overlays, `artifactPath` is the deterministic derived runtime artifact, `representation = "derived-blz"`, `initializedSize = ramSize`, and `importStatus = "importable-derived"`.

- [ ] **Step 1: Write RED bridge/model tests**

Require compressed overlay records to contain distinct stored/runtime hashes and derived artifact path. Require no `not-imported-compressed` status in bridge format v2. Require all artifact paths to remain under the generated analysis root.

- [ ] **Step 2: Run RED**

```bash
npm test -- tests/nds-ghidra-model.test.ts tests/nds-ghidra-bridge.test.ts
```

Expected: old status/format assertions FAIL.

- [ ] **Step 3: Build v2 manifests from bundle provenance**

Do not decompress a second time in Ghidra bridge generation. Read the validated v2 analysis-bundle manifest, associate each compressed canonical overlay with its derived artifact record by processor/overlay ID, and require source SHA, runtime size, and runtime address to match the canonical map before producing the bridge manifest.

- [ ] **Step 4: Validate derived bridge artifacts**

`validateGeneratedGhidraBridge()` verifies derived artifact regular-file status, exact size, and SHA-256 using the same artifact inventory validation as other bridge inputs.

- [ ] **Step 5: Verify GREEN**

```bash
npm test -- tests/nds-ghidra-model.test.ts tests/nds-ghidra-bridge.test.ts tests/nds-ghidra-tools.test.ts
npm run check
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/services/nds/ghidra-model.ts src/services/nds/ghidra-bridge.ts tests/nds-ghidra-model.test.ts tests/nds-ghidra-bridge.test.ts
git commit -m "feat: bridge decoded overlays into Ghidra"
```

---

### Task 9: Safe persistent-Ghidra reconciliation for derived overlays

**Files:**
- Modify: `resources/ghidra/ReMcpPrepareProgram.java`
- Modify: `tests/nds-ghidra-resources.test.ts`
- Create: `tests/nds-ghidra-compressed-overlay-resource.test.ts`
- Modify: `tests/nds-ghidra-project.test.ts`

**Manifest contract consumed by Java:** `importStatus`, `representation`, `initializedSize`, `runtimeSha256`, canonical runtime geometry, and artifact path.

- [ ] **Step 1: Write RED source-contract tests**

Require Java source to accept only `importable` and `importable-derived`, consume `initializedSize`, reject unknown representations/statuses, resolve artifact paths under generated analysis, create true overlay blocks, and keep BSS uninitialized in the same overlay address space.

- [ ] **Step 2: Write RED ownership/conflict tests**

Require per-overlay program-info metadata keys:

```text
re-mcp.overlay.<overlayId>.representation
re-mcp.overlay.<overlayId>.runtime-sha256
```

For a newly created derived overlay, bootstrap sets matching metadata after block validation. For an existing block, bootstrap validates block name, overlay space, runtime start, initialized size, representation, and runtime hash metadata. Any conflict fails closed; Java never deletes/recreates an existing conflicting analyst/project block.

For a v1 project with an existing canonical uncompressed RE-MCP block but no per-overlay hash metadata, permit one migration only after canonical geometry is validated, then record the v2 metadata. A formerly absent compressed overlay can be added as a new RE-MCP-owned overlay block because the project already has matching full ROM SHA ownership.

- [ ] **Step 3: Run RED**

```bash
npm test -- tests/nds-ghidra-resources.test.ts tests/nds-ghidra-compressed-overlay-resource.test.ts tests/nds-ghidra-project.test.ts
```

Expected: FAIL until Java understands bridge v2/derived status.

- [ ] **Step 4: Update `ReMcpPrepareProgram.java`**

Use manifest `initializedSize` for both representations. For `derived-blz`, open only the derived artifact; never open compressed stored bytes as executable contents. Create BSS using `createUninitializedBlock` at `runtimeAddress + ramSize` in the initialized block's true overlay address space. Keep labels/comments/bookmarks/types/namespaces/function names/signatures untouched.

- [ ] **Step 5: Verify GREEN**

```bash
npm test -- tests/nds-ghidra-resources.test.ts tests/nds-ghidra-compressed-overlay-resource.test.ts tests/nds-ghidra-project.test.ts tests/nds-ghidra-runner.test.ts
npm run check
npm run build
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add resources/ghidra/ReMcpPrepareProgram.java tests/nds-ghidra-resources.test.ts tests/nds-ghidra-compressed-overlay-resource.test.ts tests/nds-ghidra-project.test.ts
git commit -m "feat: reconcile decoded overlays in Ghidra"
```

---

### Task 10: Real Ghidra acceptance, docs, and final regression

**Files:**
- Modify: `scripts/ghidra-acceptance.mjs`
- Modify: `scripts/ghidra-inspection-hardening-acceptance.mjs`
- Modify: `tests/nds-ghidra-acceptance.test.ts`
- Modify: `docs/nds-ghidra-integration.md`
- Modify: `README.md`

**Acceptance fixture:** one compressed ARM9 overlay containing known decoded code, alongside the existing overlapping overlay identities and analyst marker checks.

- [ ] **Step 1: Write RED acceptance-contract assertions**

`tests/nds-ghidra-acceptance.test.ts` requires the harness source to verify:
- compressed stored bytes differ from decoded runtime bytes;
- runtime artifact SHA equals manifest `runtimeSha256`;
- Ghidra overlay memory bytes equal decoded runtime bytes;
- BSS is uninitialized;
- hardened read-only inspection can inspect a proven function/reference/call inside the derived overlay;
- overlapping numeric runtime addresses remain separate overlay spaces;
- rerun preserves `REMCP_ACCEPTANCE_ANALYST_MARKER` and existing project content;
- hidden `REPORT SCRIPT ERROR`/exceptions fail acceptance.

- [ ] **Step 2: Run RED**

```bash
npm test -- tests/nds-ghidra-acceptance.test.ts
```

Expected: FAIL because compressed-overlay acceptance assertions are absent.

- [ ] **Step 3: Extend both acceptance harnesses**

Embed/read committed valid compressed overlay fixture bytes; do not run an external compressor in Actions. `ghidra-acceptance.mjs` verifies bootstrap/import/provenance/project preservation. `ghidra-inspection-hardening-acceptance.mjs` performs the existing read-only/no-analysis checks against a decoded overlay identity and snapshots persistent project bytes before/after inspection.

- [ ] **Step 4: Update documentation**

Document storage-vs-runtime distinction, derived artifact location/provenance, `romOffset: null` for decoded runtime bytes, unchanged physical `nds_search_pattern`, explicit bootstrap requirement, and unchanged Ghidra non-authority boundary.

- [ ] **Step 5: Run all Ghidra-independent verification**

```bash
npm run check
npm test
npm run build
node scripts/check-install.mjs .
node --check scripts/ghidra-acceptance.mjs
node --check scripts/ghidra-inspection-hardening-acceptance.mjs
```

Expected: PASS.

- [ ] **Step 6: Dispatch the permanent manual Ghidra workflow on the exact PR head**

Use `.github/workflows/ghidra-integration.yml`. Require Ghidra 12.1.2 archive SHA verification, JDK 21, bootstrap acceptance, derived-overlay checks, hardened read-only inspection, analyst/project preservation, and hidden-error rejection. Do not claim real acceptance until the workflow job reports success.

- [ ] **Step 7: Final clean-head verification**

After any acceptance-only cleanup, compare final head against the real-Ghidra-verified functional head. Production behavior must be identical. Require exact-final-head CI and Package success and no unresolved review threads. Confirm the diff contains no DeSmuME/GDB/controller/owned-process production files.

- [ ] **Step 8: Commit docs/acceptance changes**

```bash
git add scripts/ghidra-acceptance.mjs scripts/ghidra-inspection-hardening-acceptance.mjs tests/nds-ghidra-acceptance.test.ts docs/nds-ghidra-integration.md README.md
git commit -m "test: accept decoded overlays with real Ghidra"
```

### PR C gate

- [ ] Exact-head CI: success.
- [ ] Exact-head Package: success.
- [ ] Real Ghidra 12.1.2/JDK 21 acceptance: success on production-equivalent code.
- [ ] PR mergeable, ready, no unresolved review threads.
- [ ] No debugger-dependent production behavior changed.
- [ ] Merge only through the protected explicit approval gate.

---

## End-state verification checklist

1. Canonically marked ARM9/ARM7 compressed overlays decode through the bounded internal BLZ implementation.
2. Decoded initialized length equals canonical `ramSize`; BSS remains separate.
3. Stored compressed and decoded runtime representations retain separate SHA-256 provenance.
4. Runtime resolution exposes exact `runtimeImageOffset` and `romOffset: null` for decoded bytes.
5. ROM-offset resolution continues to describe compressed physical storage only.
6. Static instructions/references/function proofs permit nullable physical ROM provenance without changing canonical runtime identity.
7. Disassembly, CFG, references, xrefs, function discovery, and focused function analysis consume decoded overlay bytes.
8. Overlap ambiguity and function proof rules remain unchanged.
9. `nds_search_pattern` remains physical-ROM only.
10. Analysis bundles contain both exact stored compressed overlays and deterministic derived runtime artifacts.
11. Ghidra bootstrap imports validated derived runtime bytes into true overlay spaces and keeps BSS uninitialized.
12. Read-only Ghidra inspection consumes those spaces without mutating the persistent project.
13. Malformed BLZ, size/aggregate limits, source mutation, artifact tampering, and ownership conflicts fail closed.
14. Normal CI/package require neither Ghidra nor an external decompression dependency.
15. Real Ghidra 12.1.2/JDK 21 acceptance verifies the final Ghidra path.
16. Physical Intel Catalina/DeSmuME debugger acceptance remains a separate frozen gate.