# Controlled NDS Compressed Overlay Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decode canonical Nintendo DS BLZ/code-compressed overlays into provenance-tracked runtime images, let the existing static-analysis stack consume those exact runtime bytes, and safely import the same derived images into controlled Ghidra projects.

**Architecture:** Preserve the existing canonical ROM/FAT/overlay model as authority. Add a bounded internal BLZ decoder and an operation-scoped compressed-overlay runtime-image service, then generalize `NdsCodeSource` from direct-ROM-only bytes to either `rom-file-backed` or `derived-overlay` bytes. Static analysis and Ghidra consume that shared runtime representation; no layer fabricates a direct ROM offset for decompressed bytes.

**Tech Stack:** TypeScript/Node.js 20, existing RE-MCP NDS parser/resolver/static-analysis services, Capstone.js/WASM, Java Ghidra scripts, Ghidra 12.1.2 with JDK 21 for manual acceptance. No new production runtime dependency.

## Global Constraints

- Source ROM is read-only and must match the canonical full SHA-256 before and after derived-byte operations.
- Maximum stored compressed overlay: **16 MiB**.
- Maximum decoded overlay runtime image: **16 MiB**.
- Maximum aggregate decoded-overlay bytes in one top-level operation: **64 MiB**.
- Expected decoded initialized size comes only from canonical overlay `ramSize`.
- BSS is excluded from the decoded initialized image and remains runtime-only/uninitialized.
- A decompressed runtime byte has canonical runtime identity and `runtimeImageOffset`, but **never** a fabricated direct `romOffset`.
- `nds_resolve_rom_offset` remains physical-storage semantics.
- `nds_search_pattern` remains physical-ROM search and does not silently search decoded runtime images.
- Overlapping overlay runtime ranges remain ambiguous unless the existing explicit canonical overlay selector resolves one overlay.
- Overlay selection is static identity only; it does not claim that an overlay is loaded at runtime.
- Function proof remains limited to existing deterministic proof such as program entry and exact resolved direct calls. Decompression, alignment, prologues, Ghidra output, and explicit selection are not proof.
- Ghidra Java scripts consume Node-generated runtime artifacts; they do not implement BLZ.
- No BLZ recompression, ROM rebuilding, patch generation, generic decompression MCP tool, caller-selected output path, compressed ARM9-main support, asset decompression, runtime overlay detection, or Ghidra-to-RE-MCP evidence promotion.
- No DeSmuME/GDB/debug-controller production behavior changes.

---

## Delivery topology

Implement and merge this milestone as three independently verified PRs:

1. **PR A — Native decoder + canonical runtime images**: Tasks 1–3.
2. **PR B — Static-analysis consumption + generated artifacts**: Tasks 4–7, branched from `main` after PR A merges.
3. **PR C — Controlled Ghidra import + real acceptance**: Tasks 8–10, branched from `main` after PR B merges.

The approved design and this plan travel with PR A so later PRs can reference documents already on `main`.

---

### Task 1: Add a bounded Nintendo DS BLZ decoder

**Files:**
- Create: `src/services/nds/blz.ts`
- Modify: `src/services/nds/errors.ts`
- Create: `tests/nds-blz.test.ts`
- Add binary fixtures: `tests/fixtures/nds-blz/*.bin`

**Interfaces:**
- Consumes: a canonical overlay's stored bytes plus its canonical expected initialized runtime size.
- Produces:

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

- Add service error categories to the canonical NDS service error union:

```ts
export type NdsBlzErrorCategory =
  | "malformed-blz"
  | "blz-output-size-mismatch"
  | "blz-output-limit";
```

- [ ] **Step 1: Commit independent golden vectors before production decoder code**

Add committed binary fixtures covering:

```text
literal-only.bin          -> literal-only.dec.bin
backreference.bin         -> backreference.dec.bin
mixed-groups.bin          -> mixed-groups.dec.bin
uncompressed-prefix.bin   -> uncompressed-prefix.dec.bin
```

Generate/cross-check the compressed fixture bytes outside production code with an established NDS code-compression implementation, then commit only the binary vectors and expected decoded binaries. For overlays, use the overlay variant of the format, not ARM9-main compression. The test suite must not import the external implementation.

- [ ] **Step 2: Write RED decoder tests**

`tests/nds-blz.test.ts` must read the committed fixture pairs and assert exact bytes plus metadata:

```ts
const decoded = decodeNdsBlz(compressed, expected.length);
assert.deepEqual(decoded.bytes, expected);
assert.equal(decoded.storedSize, compressed.length);
assert.equal(decoded.decodedSize, expected.length);
assert.ok(decoded.headerSize >= 8);
assert.ok(decoded.encodedRegionSize > 0);
```

Add explicit malformed cases created directly in the test:

```ts
assert.throws(() => decodeNdsBlz(Buffer.alloc(7), 32), category("malformed-blz"));
assert.throws(() => decodeNdsBlz(badHeaderGeometry, 64), category("malformed-blz"));
assert.throws(() => decodeNdsBlz(truncatedToken, 64), category("malformed-blz"));
assert.throws(() => decodeNdsBlz(invalidBackReference, 64), category("malformed-blz"));
assert.throws(() => decodeNdsBlz(validCompressed, expected.length + 1), category("blz-output-size-mismatch"));
assert.throws(() => decodeNdsBlz(Buffer.alloc(16 * 1024 * 1024 + 1), 1), category("blz-output-limit"));
assert.throws(() => decodeNdsBlz(validCompressed, 16 * 1024 * 1024 + 1), category("blz-output-limit"));
```

Also test custom limits with small values so CI does not allocate huge buffers for every bound case.

- [ ] **Step 3: Run the focused RED test**

Run:

```bash
npm test -- --test-name-pattern="BLZ" tests/nds-blz.test.ts
```

Expected: FAIL because `src/services/nds/blz.ts` does not exist or `decodeNdsBlz` is not defined.

- [ ] **Step 4: Implement the decoder with backward-only bounded writes**

Implement `decodeNdsBlz()` so it:

1. rejects unsafe/non-positive expected sizes and limit violations before allocation;
2. parses the NDS code-compression footer from the end of the stored input;
3. validates header length and encoded-region geometry before indexing;
4. copies the uncompressed prefix exactly;
5. decodes control groups from the end of the encoded region toward the beginning of the output;
6. treats a clear control bit as one backwards literal byte;
7. treats a set control bit as one two-byte backward-reference token, deriving length and displacement from that token;
8. checks every source index is already-decoded history before copying;
9. prevents writes below the start of the encoded output region or beyond `expectedDecodedSize`;
10. requires the final decoded size to equal `expectedDecodedSize` exactly.

Use `Buffer.allocUnsafe(expectedDecodedSize)` only after the output limit checks; fill every returned byte deterministically before return. Do not return the original stored input for an invalid or apparently-uncompressed stream because this function is called only for canonically marked compressed overlays.

- [ ] **Step 5: Run decoder tests and type-check**

Run:

```bash
npm test -- tests/nds-blz.test.ts
npm run check
```

Expected: PASS.

- [ ] **Step 6: Commit Task 1**

```bash
git add src/services/nds/blz.ts src/services/nds/errors.ts tests/nds-blz.test.ts tests/fixtures/nds-blz
git commit -m "feat: add bounded NDS BLZ decoder"
```

---

### Task 2: Add canonical compressed-overlay runtime images and operation budgets

**Files:**
- Create: `src/services/nds/overlay-runtime.ts`
- Create: `tests/nds-overlay-runtime.test.ts`
- Reuse fixture helpers from existing NDS synthetic-ROM tests; do not add a second ROM parser.

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

- Add category:

```ts
"compressed-overlay-runtime-unavailable"
```

for canonical overlay/runtime-image failures that are not malformed BLZ itself.

- [ ] **Step 1: Write RED runtime-image tests**

Cover ARM9 and ARM7 compressed overlays with synthetic ROMs whose FAT entries contain committed valid BLZ fixture bytes. Assert:

```ts
const context = createNdsOverlayRuntimeContext(map);
const image = await context.getCompressedOverlay("arm9", 7);
assert.equal(image.overlayId, 7);
assert.equal(image.representation, "derived-blz");
assert.equal(image.runtimeAddress, overlay.ramAddress);
assert.equal(image.runtimeSize, overlay.ramSize);
assert.equal(image.bytes.length, overlay.ramSize);
assert.equal(image.storedRomOffset, overlay.romOffset);
assert.equal(image.storedSize, overlay.romSize);
assert.equal(image.bssSize, overlay.bssSize);
assert.equal(image.storedSha256, sha256(storedBytes));
assert.equal(image.runtimeSha256, sha256(decodedBytes));
```

Also assert:
- unknown overlay ID fails;
- an uncompressed overlay is rejected by `getCompressedOverlay`;
- stored-size and decoded-size limits fail closed;
- two calls for the same processor/overlay return the same cached image object and charge aggregate decoded bytes only once;
- decoding two different overlays charges the sum and rejects the second if it would exceed 64 MiB/custom test limit;
- source mutation before read, between stored-byte read and final return, and after a cached decode is detected before a top-level consumer can treat the cache as trusted;
- BSS bytes are absent from `image.bytes`.

- [ ] **Step 2: Run RED runtime-image tests**

```bash
npm test -- tests/nds-overlay-runtime.test.ts
```

Expected: FAIL because `overlay-runtime.ts` does not exist.

- [ ] **Step 3: Implement canonical overlay lookup, exact stored-range read, hashes, cache, and budget**

Implementation rules:

```ts
const overlay = overlaysFor(map, processor).find(x => x.overlayId === overlayId);
if (!overlay?.compressed) throw new NdsError("compressed-overlay-runtime-unavailable", ...);
```

Before reading, hash `map.romPath` and require `map.sha256`. Open read-only, read exactly `overlay.romSize` bytes at `overlay.romOffset`, close, decode with `overlay.ramSize`, hash both representations, then hash the source ROM again before caching/returning. The cache key is `${processor}:${overlayId}`.

The context must charge `image.bytes.length` only on first successful decode of a unique key; a failed decode never consumes budget and never enters cache.

- [ ] **Step 4: Run focused tests and full type-check**

```bash
npm test -- tests/nds-overlay-runtime.test.ts tests/nds-blz.test.ts
npm run check
```

Expected: PASS.

- [ ] **Step 5: Commit Task 2**

```bash
git add src/services/nds/overlay-runtime.ts src/services/nds/errors.ts tests/nds-overlay-runtime.test.ts
git commit -m "feat: add canonical compressed overlay runtime images"
```

---

### Task 3: Extend resolver provenance without inventing ROM mappings

**Files:**
- Modify: `src/services/nds/resolver.ts`
- Modify: `tests/nds-resolver.test.ts`

**Interfaces:**

Extend `RuntimeCandidate` with:

```ts
readonly runtimeImageOffset: number | null;
readonly representation: "rom-file-backed" | "derived-overlay" | "runtime-only";
```

Rules:
- main/uncompressed initialized code: `representation: "rom-file-backed"`, exact `romOffset`, `runtimeImageOffset: relativeOffset`;
- compressed initialized overlay: `representation: "derived-overlay"`, `romOffset: null`, `runtimeImageOffset: relativeOffset`, existing `backingRomOffset/backingRomSize` retained;
- BSS: `representation: "runtime-only"`, `romOffset: null`, `runtimeImageOffset: null`.

Keep `resolveRomOffset()` physical. Bytes inside a compressed overlay FAT range continue to produce an overlay storage match with `runtimeAddress: null`.

- [ ] **Step 1: Write RED resolver assertions**

Add tests for one compressed overlay runtime byte:

```ts
assert.equal(result.status, "compressed-no-direct-rom-mapping");
assert.equal(result.candidate.romOffset, null);
assert.equal(result.candidate.runtimeImageOffset, address - overlay.ramAddress);
assert.equal(result.candidate.representation, "derived-overlay");
assert.equal(result.candidate.backingRomOffset, overlay.romOffset);
assert.equal(result.candidate.backingRomSize, overlay.romSize);
```

For `resolveRomOffset(map, overlay.romOffset + 3)`, assert the compressed overlay match still has `runtimeAddress === null`.

For BSS, assert `runtimeImageOffset === null` and `representation === "runtime-only"`.

- [ ] **Step 2: Run RED resolver test**

```bash
npm test -- tests/nds-resolver.test.ts
```

Expected: FAIL because the new fields are absent.

- [ ] **Step 3: Populate provenance fields in all resolver candidates**

Do not change the existing resolver status model. This task adds provenance only; the static byte-source layer in PR B decides whether a `compressed-no-direct-rom-mapping` candidate is usable as derived code.

- [ ] **Step 4: Run resolver + full checks**

```bash
npm test -- tests/nds-resolver.test.ts
npm run check
npm run build
```

Expected: PASS.

- [ ] **Step 5: Commit Task 3**

```bash
git add src/services/nds/resolver.ts tests/nds-resolver.test.ts
git commit -m "feat: expose compressed overlay runtime provenance"
```

### PR A verification and integration gate

- [ ] Run:

```bash
npm run check
npm test
npm run build
```

Expected: all pass with no Ghidra requirement.

- [ ] Ensure package workflow passes on the exact head.
- [ ] Confirm changed production files are limited to NDS decoder/runtime/resolver/error surfaces and no debugger files changed.
- [ ] Mark PR #27 ready only after exact-head CI/package are green, then merge after the protected merge approval gate.

---

### Task 4: Generalize exact code sources to ROM-backed or derived-overlay bytes

**PR B branch:** create from updated `main` after PR A merges, e.g. `feature/nds-compressed-overlay-static-analysis`.

**Files:**
- Modify: `src/services/nds/disassembly-source.ts`
- Modify: `tests/nds-disassembly-source.test.ts`

**Interfaces:**

Replace the direct-ROM-only `NdsCodeSource` assumption with:

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
```

Add a shared reader entry point:

```ts
export async function withValidatedNdsCodeReader<T>(
  map: NdsRomMap,
  callback: (
    read: (source: NdsCodeSource, maxBytes: number) => Promise<Buffer>,
  ) => Promise<T>,
): Promise<T>;
```

It owns one `NdsOverlayRuntimeContext` for the top-level callback, preserving the 64 MiB aggregate decoded-image budget and decode reuse.

- [ ] **Step 1: Characterize current uncompressed source behavior before changing types**

Add tests that pin main and uncompressed overlay `romOffset`, runtime geometry, ARM/Thumb alignment, control-flow retargeting, and before/after ROM SHA checks. Run them green before modifying production.

- [ ] **Step 2: Add RED compressed-runtime source tests**

For a compressed overlay selected by runtime address + explicit `overlayId`, require:

```ts
assert.equal(resolution.status, "resolved");
assert.equal(resolution.source.representation, "derived-overlay");
assert.equal(resolution.source.romOffset, null);
assert.equal(resolution.source.runtimeImageOffset, address - overlay.ramAddress);
```

An overlapping address without overlay ID must remain `ambiguous-code-source`. A ROM-offset selector into compressed storage must not resolve as runtime code.

- [ ] **Step 3: Run RED source tests**

```bash
npm test -- tests/nds-disassembly-source.test.ts
```

Expected: FAIL on compressed-overlay expectations.

- [ ] **Step 4: Refactor source classification and `codeSourceAt()`**

For compressed initialized runtime candidates, create `derived-overlay` sources with `romStart/romEnd/romOffset === null` and exact runtime offsets. For ROM-backed sources preserve existing behavior.

`codeSourceAt()` must advance:

```ts
runtimeImageOffset: source.runtimeImageOffset + (runtimeAddress - source.runtimeAddress)
```

and advance `romOffset` only when `representation === "rom-file-backed"`.

- [ ] **Step 5: Implement `withValidatedNdsCodeReader()`**

For ROM-backed sources, read the existing exact ROM range. For derived overlay sources:

```ts
const image = await runtimeContext.getCompressedOverlay(source.processor, source.overlayId!);
const start = source.runtimeImageOffset;
const length = Math.min(maxBytes, image.bytes.length - start);
return image.bytes.subarray(start, start + length);
```

Keep source-ROM SHA validation before opening/decoding and after the callback. Do not expose the runtime context to MCP callers.

- [ ] **Step 6: Run source tests and compile all call sites**

```bash
npm test -- tests/nds-disassembly-source.test.ts tests/nds-overlay-runtime.test.ts
npm run check
```

Expected: PASS after updating internal call sites to the new reader name/signature.

- [ ] **Step 7: Commit Task 4**

```bash
git add src/services/nds/disassembly-source.ts tests/nds-disassembly-source.test.ts
git commit -m "feat: read NDS code from canonical runtime images"
```

---

### Task 5: Enable compressed overlays in disassembly, CFG, references, and xrefs

**Files:**
- Modify as required by type flow: `src/services/nds/disassembly.ts`
- Modify: `src/services/nds/control-flow.ts`
- Modify: `src/services/nds/reference-list.ts`
- Modify: `src/services/nds/xref-source.ts`
- Modify: `src/services/nds/xrefs.ts`
- Tests: `tests/nds-disassembly.test.ts`, `tests/nds-control-flow.test.ts`, `tests/nds-reference-list.test.ts`, `tests/nds-xrefs.test.ts`

**Interfaces:** Existing public service/tool result shapes remain authoritative except code-source provenance may now report `representation: "derived-overlay"`, `romOffset: null`, and exact `runtimeImageOffset`.

- [ ] **Step 1: Write one synthetic compressed ARM overlay fixture with known ARM/Thumb code**

Decoded bytes must contain at least:
- deterministic instructions that Capstone can decode;
- one direct branch/call with known target mode;
- one PC-relative/literal reference usable by reference tests.

Use the same canonical overlay metadata and BLZ stored bytes across the four focused test files.

- [ ] **Step 2: Write RED end-to-end static tests**

Require:
- `disassembleNdsRange` returns decoded instructions from the runtime image, not compressed storage bytes;
- CFG traversal follows an in-overlay direct edge;
- `listNdsReferences` reports deterministic decoded-code references;
- `findNdsXrefs` finds the same direct reference in reverse;
- all returned compressed-overlay identities keep `romOffset: null`;
- overlapping compressed overlays still require explicit overlay selection.

- [ ] **Step 3: Run the focused RED suite**

```bash
npm test -- tests/nds-disassembly.test.ts tests/nds-control-flow.test.ts tests/nds-reference-list.test.ts tests/nds-xrefs.test.ts
```

Expected: at least compressed-overlay cases FAIL before the reader integration is threaded through every service.

- [ ] **Step 4: Route all exact code reads through `withValidatedNdsCodeReader()`**

Remove assumptions such as arithmetic on non-null `source.romOffset`. Control-flow identity must use runtime/component/overlay/mode, not ROM offset, for derived sources.

- [ ] **Step 5: Preserve bounds and truncation behavior**

The existing max blocks/instructions/bytes/edges and `RE_MCP_MAX_OUTPUT_BYTES` behavior remain unchanged. Decoded-image memory is additionally bounded by the operation-scoped 64 MiB cap.

- [ ] **Step 6: Run focused + regression tests**

```bash
npm test -- tests/nds-disassembly.test.ts tests/nds-control-flow.test.ts tests/nds-reference-list.test.ts tests/nds-xrefs.test.ts tests/nds-reference-target-mode.test.ts
npm run check
```

Expected: PASS.

- [ ] **Step 7: Commit Task 5**

```bash
git add src/services/nds/disassembly.ts src/services/nds/control-flow.ts src/services/nds/reference-list.ts src/services/nds/xref-source.ts src/services/nds/xrefs.ts tests/nds-disassembly.test.ts tests/nds-control-flow.test.ts tests/nds-reference-list.test.ts tests/nds-xrefs.test.ts
git commit -m "feat: analyze compressed NDS overlay code"
```

---

### Task 6: Extend proven function discovery and focused function analysis

**Files:**
- Modify: `src/services/nds/function-source.ts`
- Modify: `src/services/nds/function-discovery.ts`
- Modify: `src/services/nds/function-analysis.ts`
- Modify: `src/services/nds/function-model.ts` only if its non-null ROM-offset typing requires it
- Tests: `tests/nds-function-source.test.ts`, `tests/nds-function-discovery.test.ts`, `tests/nds-function-analysis.test.ts`, `tests/nds-function-integrity.test.ts`

**Interfaces:** `ProvenFunctionIdentity.romOffset` must become `number | null` if it is currently non-null. Identity uniqueness continues to use processor + component + overlay ID + runtime address + mode; `romOffset` is provenance, not the key for derived overlay functions.

- [ ] **Step 1: Write RED proof-boundary tests**

Create a compressed overlay with a direct call from an explicit search seed to a second decoded function. Assert the target becomes proven only through `direct-call` evidence. Also assert:
- an explicit seed alone is not proof;
- a prologue-looking decoded sequence is not proof;
- overlapping overlay target resolution remains ambiguous without canonical overlay context;
- focused analysis distinguishes complete negative proof from truncation exactly as before.

- [ ] **Step 2: Run RED function tests**

```bash
npm test -- tests/nds-function-source.test.ts tests/nds-function-discovery.test.ts tests/nds-function-analysis.test.ts tests/nds-function-integrity.test.ts
```

Expected: compressed-overlay cases FAIL until nullable ROM provenance is supported throughout function identity/evidence.

- [ ] **Step 3: Update function identities and canonicalization**

`identityFromSource()` must copy `source.romOffset` without requiring non-null. `canonicalizeFunctionTarget()` still resolves through canonical code-source ownership and selected component scope.

Coverage should no longer classify a successfully decodable compressed overlay as an unavoidable compressed gap. A malformed/limit-failing compressed overlay must produce an explicit incomplete/truncated coverage reason rather than being interpreted as code from stored bytes.

- [ ] **Step 4: Run proof tests and full type-check**

```bash
npm test -- tests/nds-function-source.test.ts tests/nds-function-discovery.test.ts tests/nds-function-analysis.test.ts tests/nds-function-integrity.test.ts
npm run check
```

Expected: PASS.

- [ ] **Step 5: Commit Task 6**

```bash
git add src/services/nds/function-source.ts src/services/nds/function-discovery.ts src/services/nds/function-analysis.ts src/services/nds/function-model.ts tests/nds-function-source.test.ts tests/nds-function-discovery.test.ts tests/nds-function-analysis.test.ts tests/nds-function-integrity.test.ts
git commit -m "feat: prove functions in decoded NDS overlays"
```

---

### Task 7: Persist derived runtime artifacts in analysis bundles and package smoke

**Files:**
- Modify: `src/services/nds/extraction.ts`
- Create: `src/services/nds/derived-artifacts.ts` if keeping atomic derived writes out of the already-large extraction service is cleaner
- Modify: `tests/nds-extraction.test.ts`
- Modify: `scripts/check-install.mjs`
- Modify package workflow smoke only if the existing script cannot exercise the new artifact

**Interfaces:** For each compressed overlay, persist a deterministic generated artifact at:

```text
analysis/generated/nds/<sha-prefix>/derived/overlays/<processor>/overlay-<id>.runtime.bin
```

Bundle manifest entries for derived images must include:

```ts
{
  representation: "derived-blz",
  processor,
  overlayId,
  fileId,
  storedRomOffset,
  storedSize,
  storedSha256,
  runtimeAddress,
  runtimeSize,
  runtimeSha256,
  bssSize,
  output
}
```

- [ ] **Step 1: Write RED transactional bundle tests**

Require the bundle to contain both:
- the original exact compressed stored overlay extraction under `overlays/...`; and
- the decoded runtime artifact under `derived/overlays/...`.

Assert hashes/sizes against the runtime-image service, `runtimeSize === ramSize`, and no BSS bytes in the derived file. Add a source-mutation test that leaves the previous final bundle intact and removes the temporary bundle.

- [ ] **Step 2: Run RED extraction tests**

```bash
npm test -- tests/nds-extraction.test.ts
```

Expected: FAIL because derived runtime artifacts are absent.

- [ ] **Step 3: Generate derived images inside the existing transaction**

Instantiate one `NdsOverlayRuntimeContext` for bundle generation. For each compressed overlay, obtain its image, atomically write `image.bytes` inside the temporary bundle, record exact provenance, then perform the existing source-SHA recheck before temp→final promotion.

Do not change `extractNdsComponent()` behavior: explicit overlay extraction remains exact stored FAT-backed bytes.

- [ ] **Step 4: Extend package smoke**

The packaged smoke ROM must include a valid small compressed overlay and require the compiled production service to generate a decoded runtime artifact whose bytes/hash match the known expected runtime bytes. No Python/ndspy invocation is allowed in package CI.

- [ ] **Step 5: Run bundle/package-facing checks locally**

```bash
npm test -- tests/nds-extraction.test.ts tests/package-capstone-install.test.ts
npm run check
npm run build
node scripts/check-install.mjs .
```

Expected: PASS.

- [ ] **Step 6: Commit Task 7**

```bash
git add src/services/nds/extraction.ts src/services/nds/derived-artifacts.ts tests/nds-extraction.test.ts scripts/check-install.mjs .github/workflows/package.yml
git commit -m "feat: persist decoded overlay analysis artifacts"
```

If `derived-artifacts.ts` or the workflow file is not needed after the implementation is kept focused, omit that path from the commit rather than creating an empty abstraction.

### PR B verification and integration gate

- [ ] Run full tests, type-check, and build.
- [ ] Require exact-head CI and Package success.
- [ ] Confirm `nds_search_pattern` tests still prove physical-ROM behavior for compressed storage.
- [ ] Confirm no debugger/runtime-control files changed.
- [ ] Merge only after the protected merge approval gate.

---

### Task 8: Extend Ghidra bridge manifests to derived overlay artifacts

**PR C branch:** create from updated `main` after PR B merges, e.g. `feature/nds-compressed-overlay-ghidra`.

**Files:**
- Modify: `src/services/nds/ghidra-model.ts`
- Modify: `src/services/nds/ghidra-bridge.ts`
- Modify: `tests/nds-ghidra-model.test.ts`
- Modify: `tests/nds-ghidra-bridge.test.ts`

**Interfaces:** Bump `GHIDRA_BRIDGE_FORMAT_VERSION` because overlay artifact semantics gain runtime/stored provenance. Preserve `importable` for existing uncompressed overlays and add:

```ts
export type GhidraOverlayImportStatus =
  | "importable"
  | "importable-derived";
```

Extend `GhidraOverlayManifest` with:

```ts
readonly representation: "rom-file-backed" | "derived-blz";
readonly initializedSize: number;
readonly storedRomOffset: number;
readonly storedSize: number;
readonly storedSha256: string;
readonly runtimeSha256: string;
```

For compressed overlays:
- `artifactPath` points to the generated derived runtime file;
- `representation === "derived-blz"`;
- `initializedSize === ramSize`;
- `importStatus === "importable-derived"`;
- stored and runtime hashes come from bundle/runtime provenance.

For uncompressed overlays:
- keep the existing file-backed artifact and behavior;
- `initializedSize === Math.min(ramSize, romSize)`;
- `representation === "rom-file-backed"`.

- [ ] **Step 1: Write RED manifest tests**

Assert a compressed overlay is no longer `not-imported-compressed`, points only to a generated runtime artifact, contains both stored/runtime hashes, and retains canonical ROM storage metadata separately.

- [ ] **Step 2: Run RED bridge/model tests**

```bash
npm test -- tests/nds-ghidra-model.test.ts tests/nds-ghidra-bridge.test.ts
```

Expected: FAIL on old bridge format/status.

- [ ] **Step 3: Build bridge records from the generated bundle/runtime provenance**

Do not decompress again inside Ghidra bridge generation. `extractNdsAnalysisBundle()` already produces and validates the derived artifact; bridge generation copies/references that exact artifact and records its hash in the bridge artifact inventory.

- [ ] **Step 4: Validate all manifest artifact hashes before Ghidra runs**

`validateGeneratedGhidraBridge()` must verify the derived runtime artifact size/hash exactly like every other bridge artifact and reject any mismatch before `analyzeHeadless` starts.

- [ ] **Step 5: Run focused + package tests**

```bash
npm test -- tests/nds-ghidra-model.test.ts tests/nds-ghidra-bridge.test.ts tests/nds-ghidra-tools.test.ts
npm run check
```

Expected: PASS.

- [ ] **Step 6: Commit Task 8**

```bash
git add src/services/nds/ghidra-model.ts src/services/nds/ghidra-bridge.ts tests/nds-ghidra-model.test.ts tests/nds-ghidra-bridge.test.ts
git commit -m "feat: bridge decoded overlays into Ghidra"
```

---

### Task 9: Reconcile derived overlays into persistent Ghidra projects without overwriting analyst state

**Files:**
- Modify: `resources/ghidra/ReMcpPrepareProgram.java`
- Modify: `tests/nds-ghidra-resources.test.ts`
- Modify/add focused source-contract test if existing resource test is too broad
- Modify: `tests/nds-ghidra-project.test.ts` or acceptance harness assertions for project-state behavior

**Interfaces:** Java accepts only `importable` and `importable-derived`. It reads `initializedSize`, `representation`, and `runtimeSha256` from the trusted bridge manifest.

- [ ] **Step 1: Write RED Java source-contract tests**

Require the resource to:
- accept `importable-derived`;
- use manifest `initializedSize` rather than `Math.min(ramSize, fileBackedSize)`;
- resolve only generated-analysis-contained artifacts;
- create true Ghidra overlay blocks at canonical runtime addresses;
- keep BSS in the same overlay address space and uninitialized;
- reject unknown import status/representation;
- retain the existing no-destructive-repair guarantees.

- [ ] **Step 2: Add ownership/hash metadata contract**

Use per-overlay program metadata keys derived from processor/overlay ID, for example:

```text
re-mcp.overlay.<id>.representation
re-mcp.overlay.<id>.runtime-sha256
```

On a newly created derived block, set those values after successful creation/validation. On an existing RE-MCP overlay block:
- validate name, overlay-space identity, runtime start, and exact initialized size;
- require existing representation/hash metadata to match, or when migrating a v1 file-backed owned block, validate its canonical geometry before writing only the new metadata;
- never delete/recreate a conflicting block;
- fail `project-state-mismatch` through the existing headless failure path on conflict.

- [ ] **Step 3: Run RED resource/project tests**

```bash
npm test -- tests/nds-ghidra-resources.test.ts tests/nds-ghidra-project.test.ts
```

Expected: FAIL until Java and the expected bridge version/status are updated.

- [ ] **Step 4: Update `ReMcpPrepareProgram.java`**

For both importable representations, open only the manifest artifact and create the initialized overlay block with exactly `initializedSize`. Never read compressed stored bytes for `derived-blz`. BSS creation remains `createUninitializedBlock` at `runtimeAddress + ramSize` in the true overlay space.

Keep analyst labels/comments/bookmarks/types/namespaces/functions untouched. Existing block conflicts terminate bootstrap rather than being repaired.

- [ ] **Step 5: Run Ghidra-independent tests**

```bash
npm test -- tests/nds-ghidra-resources.test.ts tests/nds-ghidra-project.test.ts tests/nds-ghidra-runner.test.ts
npm run check
npm run build
```

Expected: PASS.

- [ ] **Step 6: Commit Task 9**

```bash
git add resources/ghidra/ReMcpPrepareProgram.java tests/nds-ghidra-resources.test.ts tests/nds-ghidra-project.test.ts
git commit -m "feat: reconcile decoded overlays in Ghidra"
```

---

### Task 10: Real-Ghidra acceptance, docs, and final regression

**Files:**
- Modify: `scripts/ghidra-acceptance.mjs`
- Modify: `scripts/ghidra-inspection-hardening-acceptance.mjs`
- Modify: `.github/workflows/ghidra-integration.yml` only if the harness invocation itself changes
- Modify: `tests/nds-ghidra-acceptance.test.ts`
- Modify: `docs/nds-ghidra-integration.md`
- Modify: `README.md` only where public capability text needs compressed-overlay status updated

**Acceptance fixture:** Add one compressed ARM9 overlay with known decoded ARM/Thumb code. Keep the existing two overlapping uncompressed overlay identities and analyst marker checks so this is additive coverage, not replacement coverage.

- [ ] **Step 1: Write RED acceptance-contract assertions**

Source tests must require the harness to verify:
- compressed overlay stored bytes differ from decoded runtime bytes;
- runtime artifact hash equals the bridge manifest `runtimeSha256`;
- Ghidra memory bytes in the compressed overlay space equal decoded runtime bytes;
- BSS block is uninitialized;
- hardened read-only inspection can inspect a function/reference/call inside the derived overlay when RE-MCP proof exists;
- the same numeric runtime address in another overlay remains a distinct Ghidra overlay space;
- rerunning bootstrap preserves `REMCP_ACCEPTANCE_ANALYST_MARKER` and existing project content;
- hidden `REPORT SCRIPT ERROR` / exceptions are rejected.

- [ ] **Step 2: Run RED acceptance-contract tests**

```bash
npm test -- tests/nds-ghidra-acceptance.test.ts
```

Expected: FAIL until the real acceptance harness includes compressed-overlay assertions.

- [ ] **Step 3: Extend synthetic acceptance ROM and harness**

Use committed/embedded valid overlay BLZ fixture bytes; do not invoke an external compressor during Actions. The harness must derive the canonical map through compiled RE-MCP services, bootstrap Ghidra, inspect the true derived overlay space, snapshot persistent project bytes before read-only inspection, and compare them after inspection.

- [ ] **Step 4: Update docs**

Document:
- compressed overlays are decoded by RE-MCP before static/Ghidra analysis;
- stored compressed extraction is still available and distinct from derived runtime artifacts;
- decoded runtime addresses have no fabricated direct ROM offset;
- explicit Ghidra bootstrap is still required before read-only inspection;
- Ghidra remains non-authoritative for RE-MCP proof;
- `nds_search_pattern` remains physical-ROM only.

- [ ] **Step 5: Run all local/GitHub-independent verification**

```bash
npm run check
npm test
npm run build
node scripts/check-install.mjs .
node --check scripts/ghidra-acceptance.mjs
node --check scripts/ghidra-inspection-hardening-acceptance.mjs
```

Expected: PASS.

- [ ] **Step 6: Run the manual real-Ghidra gate**

Dispatch `.github/workflows/ghidra-integration.yml` on the exact PR head. Require:
- Ghidra 12.1.2 archive SHA verification;
- JDK 21;
- bootstrap acceptance success;
- compressed derived-overlay checks success;
- hardened read-only inspection success;
- analyst-state/project-byte preservation success;
- no hidden Ghidra script errors/exceptions.

Do not claim this gate passed until the exact workflow job reports success.

- [ ] **Step 7: Final scope review and clean-head gates**

After removing any temporary trigger workflow used only for PR automation, compare the final head against the real-Ghidra-verified functional head. Only acceptance/docs cleanup may differ. Then require exact-final-head CI and Package success.

Confirm no production changes under DeSmuME GDB transport, debugger controller, stop-context, or owned-process lifecycle.

- [ ] **Step 8: Commit Task 10 cleanup/docs**

```bash
git add scripts/ghidra-acceptance.mjs scripts/ghidra-inspection-hardening-acceptance.mjs .github/workflows/ghidra-integration.yml tests/nds-ghidra-acceptance.test.ts docs/nds-ghidra-integration.md README.md
git commit -m "test: accept decoded overlays with real Ghidra"
```

Only add files that actually changed.

### PR C final integration gate

- [ ] Current PR head is mergeable and not draft.
- [ ] Exact-head CI passes type-check, full tests, and build.
- [ ] Exact-head Package passes source verification and self-contained bundle smoke.
- [ ] Real Ghidra 12.1.2/JDK 21 acceptance passed on production-equivalent code.
- [ ] No unresolved review threads remain.
- [ ] No debugger-dependent production behavior changed.
- [ ] Merge only after the protected explicit approval gate.

---

## End-state verification checklist

When all three PRs are merged, verify these user-visible truths from `main`:

1. Canonically marked ARM9/ARM7 compressed overlays decode through the internal bounded BLZ implementation.
2. Decoded initialized length equals overlay `ramSize`; BSS is separate.
3. Stored compressed and decoded runtime representations have separate SHA-256 provenance.
4. Runtime resolution exposes exact `runtimeImageOffset` but `romOffset: null` for decoded bytes.
5. ROM-offset resolution still treats the compressed file as physical storage only.
6. Disassembly, CFG, references, xrefs, proven-function discovery, and focused function analysis consume decoded overlay bytes.
7. Overlap ambiguity and function proof rules are unchanged.
8. `nds_search_pattern` still searches only physical ROM bytes.
9. Analysis bundles contain both exact stored compressed overlay files and deterministic derived runtime artifacts.
10. Ghidra bootstrap imports validated derived bytes into true overlay spaces and keeps BSS uninitialized.
11. Read-only Ghidra inspection consumes those spaces without mutating the persistent project.
12. Malformed BLZ, size/aggregate limits, source mutation, ownership conflicts, and generated-artifact tampering fail closed.
13. Normal CI/package require no Ghidra or external decompression dependency.
14. Real Ghidra 12.1.2/JDK 21 acceptance proves the final Ghidra path.
15. Native Catalina/DeSmuME debugger acceptance remains a separate frozen gate.