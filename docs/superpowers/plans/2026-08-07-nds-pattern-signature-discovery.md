# NDS Pattern and Signature Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one bounded, deterministic, read-only `nds_search_pattern` tool that searches validated Nintendo DS ROMs for exact/wildcard byte signatures, typed integers, ASCII strings, and UTF-16LE strings while preserving canonical NDS ownership and strict scan limits.

**Architecture:** Compile every public pattern into one exact byte+mask representation, resolve caller scope into canonical NDS component intervals plus a normalized physical read union, then run one chunked matcher that preserves overlapping hits and component-boundary semantics. A separate ownership mapper annotates each full-span hit with deterministic NDS relationships, while the top-level search service provides pagination, context, SHA integrity checks, and the MCP adapter/output policy.

**Tech Stack:** TypeScript ES2022/NodeNext, Node.js >=20, Node `node:test`, Zod, existing RE-MCP `NdsRomMap`/FAT/FNT/overlay/resolver infrastructure, Node `fs/promises`, existing SHA-256 helpers, GitHub Actions package verification.

## Global Constraints

- Node.js runtime floor remains `>=20`; do not change package dependency versions.
- Add exactly one public NDS tool: `nds_search_pattern`; the NDS static tool surface becomes exactly twelve tools.
- Support exactly four public pattern kinds: `byte-signature`, `integer`, `ascii`, `utf16le`.
- Byte signatures accept only whitespace-separated exact bytes (`00`..`FF`) and whole-byte wildcards (`??`); reject nibble wildcards, regex, alternation, repetition, empty signatures, and all-wildcard signatures.
- Integer searches require explicit width `8 | 16 | 32`, endianness `little | big`, signedness, and optional alignment `1 | 2 | 4`; alignment defaults to `1` and is evaluated against absolute ROM offset.
- ASCII is exact/case-sensitive and rejects non-ASCII input. UTF-16LE is exact/case-sensitive. Neither string search appends a terminator or performs normalization.
- Every encoded pattern is `1..4096` bytes.
- Scope is either `whole-rom` or canonical `components`; there is no caller-defined arbitrary byte range.
- Component scope may select ARM9 main, ARM7 main, explicit ARM9/ARM7 overlay IDs, NitroFS file IDs, and exact NitroFS paths.
- Selector caps: at most 128 overlay selectors total and at most 256 NitroFS selectors total; after deduplication, at most 256 selected canonical component intervals.
- Duplicate selectors and overlapping physical selections are canonicalized. Each physical ROM byte is scanned at most once per request.
- A component-scoped match is valid only if its full `[start,end)` span lies inside at least one selected canonical component. Merely adjacent components never authorize a cross-boundary match.
- `whole-rom` is one search domain and may match across structural/component boundaries.
- Compressed overlays are searched only as exact stored FAT-backed bytes. Do not decompress and do not fabricate runtime mappings.
- Preserve overlapping matches (`AA AA` in `AA AA AA` yields starts at both bytes 0 and 1).
- Result order is ascending absolute ROM offset.
- Public/default bounds: `limit 100/1000 max`, `offset 0/99999 max`, `contextBytes 0/64 max per side`, `maxScanBytes 64 MiB/512 MiB max`.
- Internal discovered-match ceiling is exactly `100000`.
- Truncation reasons are exactly `scan-byte-limit` and `match-count-limit`.
- `offset` is a match index, not a scan-resume cursor. Raising `offset` alone never extends coverage beyond `maxScanBytes` truncation.
- `discoveredMatches` counts only matches actually established before completion/truncation.
- `nextOffset` is non-null only when the current scan has already discovered later matches beyond the returned page.
- Context is informational, does not count toward `scannedBytes`, and remains inside a deterministic selected containing component for component scope; whole-ROM context is clipped only to ROM bounds.
- Attach a runtime address only when the full hit span has a deterministic direct file-backed runtime mapping. Uncompressed overlay mapping is bounded to `min(ramSize, romSize)`; compressed overlays never receive runtime mapping.
- Do not invent banner ownership from `bannerOffset`; the current canonical model has no validated banner extent.
- Pattern search verifies ROM SHA-256 before scanning and again before returning. If the scan fails, the final SHA check still runs before the original scan error is rethrown.
- Add pattern-specific errors exactly: `invalid-pattern`, `invalid-pattern-scope`, `pattern-search-limit-exceeded`; reuse existing NDS structural/file/output errors where already applicable.
- No generic binary input, caller-supplied bytes, caller-supplied base/runtime address, arbitrary start/end range, arbitrary output path, ROM mutation/rebuild, runtime memory search, decompression, heuristic pointer/reference inference, persistent index, or multi-pattern batch.
- Do not change Capstone, disassembly, CFG, proven-reference, reverse-xref, extraction, or DeSmuME debugger/controller/runtime semantics.
- Physical Intel Catalina/DeSmuME acceptance remains separate and must not be claimed by this milestone.

---

## File Map

### Create

- `src/services/nds/patterns.ts` — public pattern union, canonical compiled pattern, exact encoders/validators.
- `src/services/nds/pattern-scope.ts` — canonical component selection, selector validation/deduplication, normalized physical read union, full-span component containment, deterministic context component selection.
- `src/services/nds/pattern-ownership.ts` — full-span canonical ownership and deterministic direct runtime mappings.
- `src/services/nds/pattern-match.ts` — low-level chunked exact/masked matcher, alignment, overlap, scan/match limits, page accounting.
- `src/services/nds/pattern-search.ts` — top-level filesystem/SHA orchestration, compiler/scope/matcher composition, context reads, final result model.
- `tests/nds-patterns.test.ts`
- `tests/nds-pattern-scope.test.ts`
- `tests/nds-pattern-ownership.test.ts`
- `tests/nds-pattern-match.test.ts`
- `tests/nds-pattern-search.test.ts`

### Modify

- `src/services/nds/errors.ts`
- `src/services/nds/header.ts`
- `src/tools/nds.ts`
- `src/index.ts`
- `tests/nds-tools.test.ts`
- `scripts/check-install.mjs`
- `tests/package-capstone-install.test.ts`
- `README.md`

### Reuse unchanged unless a failing regression test proves a narrow compatibility defect

- `src/services/nds/rom-map.ts`
- `src/services/nds/fat.ts`
- `src/services/nds/fnt.ts`
- `src/services/nds/overlays.ts`
- `src/services/nds/resolver.ts`
- `src/services/nds/disassembly-source.ts`
- `src/services/nds/disassembly.ts`
- `src/services/nds/control-flow.ts`
- `src/services/nds/references.ts`
- `src/services/nds/xrefs.ts`
- `tests/helpers/nds-fixture.ts`
- `package.json`
- `.github/workflows/package.yml`

---

### Task 1: Canonical pattern compiler and error taxonomy

**Files:**
- Create: `src/services/nds/patterns.ts`
- Modify: `src/services/nds/errors.ts`
- Test: `tests/nds-patterns.test.ts`

**Interfaces:**

```ts
export type NdsSearchPattern =
  | { readonly kind: "byte-signature"; readonly signature: string }
  | {
      readonly kind: "integer";
      readonly value: number;
      readonly width: 8 | 16 | 32;
      readonly endian: "little" | "big";
      readonly signed: boolean;
      readonly alignment?: 1 | 2 | 4;
    }
  | { readonly kind: "ascii"; readonly text: string }
  | { readonly kind: "utf16le"; readonly text: string };

export interface CompiledNdsPattern {
  readonly bytes: Uint8Array;
  readonly mask: Uint8Array;
  readonly alignment: 1 | 2 | 4;
  readonly sourceKind: NdsSearchPattern["kind"];
}

export const NDS_PATTERN_MAX_BYTES = 4096;
export function compileNdsPattern(pattern: NdsSearchPattern): CompiledNdsPattern;
```

`src/services/nds/errors.ts` adds:

```ts
export type NdsPatternSearchErrorCategory =
  | "invalid-pattern"
  | "invalid-pattern-scope"
  | "pattern-search-limit-exceeded";
```

and includes it in `AnyNdsErrorCategory`.

- [ ] **Step 1: Write failing compiler tests**

Create `tests/nds-patterns.test.ts`:

```ts
import assert from "node:assert/strict";
import test from "node:test";
import { NdsError } from "../src/services/nds/errors.js";
import { compileNdsPattern } from "../src/services/nds/patterns.js";

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

test("compiles exact and wildcard byte signatures", () => {
  const compiled = compileNdsPattern({
    kind: "byte-signature",
    signature: "12 34 ?? 78",
  });
  assert.equal(hex(compiled.bytes), "12340078");
  assert.equal(hex(compiled.mask), "ffff00ff");
  assert.equal(compiled.alignment, 1);
});

test("rejects malformed and non-identifying byte signatures", () => {
  for (const signature of ["", "12 GG", "A? 12", "??", "?? ??"] as const) {
    assert.throws(
      () => compileNdsPattern({ kind: "byte-signature", signature }),
      (error) => error instanceof NdsError && error.category === "invalid-pattern",
    );
  }
});

test("encodes integer width, endian, signedness, and alignment exactly", () => {
  assert.equal(hex(compileNdsPattern({
    kind: "integer", value: 0x1234, width: 16, endian: "little", signed: false,
  }).bytes), "3412");
  assert.equal(hex(compileNdsPattern({
    kind: "integer", value: 0x1234, width: 16, endian: "big", signed: false,
  }).bytes), "1234");
  assert.equal(hex(compileNdsPattern({
    kind: "integer", value: -1, width: 32, endian: "little", signed: true,
    alignment: 4,
  }).bytes), "ffffffff");
  assert.equal(compileNdsPattern({
    kind: "integer", value: 1, width: 32, endian: "little", signed: false,
  }).alignment, 1);
});

test("rejects integer values outside requested range", () => {
  for (const pattern of [
    { kind: "integer", value: 256, width: 8, endian: "little", signed: false },
    { kind: "integer", value: -129, width: 8, endian: "little", signed: true },
  ] as const) {
    assert.throws(
      () => compileNdsPattern(pattern),
      (error) => error instanceof NdsError && error.category === "invalid-pattern",
    );
  }
});

test("encodes ASCII and UTF-16LE exactly without terminators", () => {
  assert.equal(hex(compileNdsPattern({ kind: "ascii", text: "Ab" }).bytes), "4162");
  assert.equal(hex(compileNdsPattern({ kind: "utf16le", text: "AΩ" }).bytes), "4100a903");
  assert.throws(
    () => compileNdsPattern({ kind: "ascii", text: "Ω" }),
    (error) => error instanceof NdsError && error.category === "invalid-pattern",
  );
  assert.throws(
    () => compileNdsPattern({ kind: "utf16le", text: "" }),
    (error) => error instanceof NdsError && error.category === "invalid-pattern",
  );
});

test("enforces 4096 encoded-byte maximum", () => {
  assert.equal(compileNdsPattern({ kind: "ascii", text: "A".repeat(4096) }).bytes.length, 4096);
  assert.throws(
    () => compileNdsPattern({ kind: "ascii", text: "A".repeat(4097) }),
    (error) => error instanceof NdsError && error.category === "invalid-pattern",
  );
});
```

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/nds-patterns.test.ts
```

Expected: FAIL because the new service/error category does not exist.

- [ ] **Step 3: Implement the error union and byte-signature compiler**

Use only:

```ts
const EXACT_BYTE = /^[0-9a-fA-F]{2}$/u;
const WILDCARD = "??";
```

Concrete tokens append parsed byte + `0xff` mask. `??` appends `0x00` byte + `0x00` mask. Reject no tokens, malformed tokens, and masks containing no exact byte.

- [ ] **Step 4: Implement integer encoding**

Require `Number.isSafeInteger(value)`. Validate range with `BigInt`:

```ts
function integerBounds(width: 8 | 16 | 32, signed: boolean): readonly [bigint, bigint] {
  const bits = BigInt(width);
  return signed
    ? [-(1n << (bits - 1n)), (1n << (bits - 1n)) - 1n]
    : [0n, (1n << bits) - 1n];
}
```

For signed negatives use two's complement:

```ts
const modulus = 1n << BigInt(width);
const encoded = value < 0n ? modulus + value : value;
```

Emit exact requested endian bytes; never search an alternate representation.

- [ ] **Step 5: Implement strings and shared encoded-length validation**

Reject any ASCII UTF-16 code unit above `0x7f`, then encode via `Buffer.from(text, "ascii")`. Encode UTF-16LE via `Buffer.from(text, "utf16le")`. Reject every encoded result outside `1..4096` bytes. Return fresh `Uint8Array` objects.

- [ ] **Step 6: Run GREEN**

```bash
node --test --import tsx tests/nds-patterns.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/services/nds/errors.ts src/services/nds/patterns.ts tests/nds-patterns.test.ts
git commit -m "feat: compile bounded NDS search patterns"
```

---

### Task 2: Canonical component scope resolver and physical-union normalization

**Files:**
- Create: `src/services/nds/pattern-scope.ts`
- Test: `tests/nds-pattern-scope.test.ts`

**Interfaces:**

```ts
export type NdsPatternSearchScope =
  | { readonly kind: "whole-rom" }
  | {
      readonly kind: "components";
      readonly arm9Main?: boolean;
      readonly arm7Main?: boolean;
      readonly arm9OverlayIds?: readonly number[];
      readonly arm7OverlayIds?: readonly number[];
      readonly nitroFsFileIds?: readonly number[];
      readonly nitroFsPaths?: readonly string[];
    };

export type NdsPatternComponentKind =
  | "arm9-main"
  | "arm7-main"
  | "arm9-overlay"
  | "arm7-overlay"
  | "nitrofs-file";

export interface NdsPatternComponent {
  readonly key: string;
  readonly kind: NdsPatternComponentKind;
  readonly start: number;
  readonly end: number;
  readonly processor: "arm9" | "arm7" | null;
  readonly overlayId: number | null;
  readonly fileId: number | null;
  readonly path: string | null;
  readonly compressed: boolean;
}

export interface NdsPatternPhysicalRange {
  readonly start: number;
  readonly end: number;
}

export interface ResolvedNdsPatternScope {
  readonly kind: "whole-rom" | "components";
  readonly components: readonly NdsPatternComponent[];
  readonly physicalRanges: readonly NdsPatternPhysicalRange[];
}

export function resolveNdsPatternScope(map: NdsRomMap, scope: NdsPatternSearchScope): ResolvedNdsPatternScope;
export function patternSpanIsEligible(scope: ResolvedNdsPatternScope, start: number, end: number): boolean;
export function selectPatternContextComponent(scope: ResolvedNdsPatternScope, start: number, end: number): NdsPatternComponent | null;
```

- [ ] **Step 1: Write failing scope tests with an explicit fixture helper**

At the top of `tests/nds-pattern-scope.test.ts`, define:

```ts
async function createScopeFixture() {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    fntSize: 0x40,
    fatSize: 16,
    arm9OverlaySize: 32,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1200, 0x1220);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1300, 0x1380);
  writeFntMainRecord(fixture.buffer, 0x800, 0, 8, 0, 1);
  writeFntSubtable(fixture.buffer, 0x800, 8, [encodeFntFileEntry("asset.bin")]);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 7,
    ramAddress: 0x02200000,
    ramSize: 0x80,
    bssSize: 0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 1,
    compressedSize: 0,
    flags: 0,
  });
  await fixture.write();
  return fixture;
}
```

Then test selector deduplication and physical overlap:

```ts
const fixture = await createScopeFixture();
const map = await readNdsRomMap(fixture.romPath);
const resolved = resolveNdsPatternScope(map, {
  kind: "components",
  arm9Main: true,
  arm9OverlayIds: [7, 7],
  nitroFsFileIds: [0],
  nitroFsPaths: ["asset.bin"],
});
assert.equal(resolved.components.filter((c) => c.kind === "arm9-main").length, 1);
assert.equal(resolved.components.filter((c) => c.kind === "arm9-overlay").length, 1);
assert.equal(resolved.components.filter((c) => c.kind === "nitrofs-file").length, 1);

const overlap = resolveNdsPatternScope(map, {
  kind: "components",
  arm9OverlayIds: [7],
  nitroFsFileIds: [1],
});
assert.equal(overlap.components.length, 2);
assert.deepEqual(overlap.physicalRanges, [{ start: 0x1300, end: 0x1380 }]);
```

Add direct containment tests using a manual scope so no helper is implicit:

```ts
const adjacent: ResolvedNdsPatternScope = {
  kind: "components",
  components: [
    { key: "file:0", kind: "nitrofs-file", start: 0, end: 2, processor: null, overlayId: null, fileId: 0, path: "a.bin", compressed: false },
    { key: "file:1", kind: "nitrofs-file", start: 2, end: 4, processor: null, overlayId: null, fileId: 1, path: "b.bin", compressed: false },
  ],
  physicalRanges: [{ start: 0, end: 4 }],
};
assert.equal(patternSpanIsEligible(adjacent, 1, 3), false);

const overlapping: ResolvedNdsPatternScope = {
  kind: "components",
  components: [
    { key: "file:0", kind: "nitrofs-file", start: 0, end: 4, processor: null, overlayId: null, fileId: 0, path: "a.bin", compressed: false },
    { key: "file:1", kind: "nitrofs-file", start: 2, end: 6, processor: null, overlayId: null, fileId: 1, path: "b.bin", compressed: false },
  ],
  physicalRanges: [{ start: 0, end: 6 }],
};
assert.equal(patternSpanIsEligible(overlapping, 1, 3), true);
```

Also test empty component scope, unknown overlay/file/path, combined selector caps, 256-component cap, whole-ROM range, and deterministic context component selection.

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/nds-pattern-scope.test.ts
```

Expected: FAIL because `pattern-scope.ts` does not exist.

- [ ] **Step 3: Implement canonical component construction and validation**

Use main ROM ranges from `map.header.arm9/arm7`, overlay stored ranges `[overlay.romOffset, overlay.romOffset + overlay.romSize)`, and files from `map.filesystem.files`. Exact paths compare with `===`.

Combined pre-dedup caps:

```ts
arm9OverlayIds.length + arm7OverlayIds.length <= 128
nitroFsFileIds.length + nitroFsPaths.length <= 256
```

After deduplication by stable component `key`, require `components.length <= 256`. Empty `components` throws `invalid-pattern-scope`. Cap violations throw `pattern-search-limit-exceeded`. Missing IDs reuse `unknown-overlay-id` / `unknown-file-id`.

- [ ] **Step 4: Normalize only the physical read union**

Sort selected `[start,end)` ranges and merge when `next.start <= current.end`. This merge is only an I/O optimization. `patternSpanIsEligible()` must separately require the complete hit span to fit within at least one original selected component. `whole-rom` returns `{ start: 0, end: map.fileSize }`.

- [ ] **Step 5: Implement deterministic context component selection**

Among components fully containing the hit, sort by descending span, then kind order `arm9-main`, `arm7-main`, `arm9-overlay`, `arm7-overlay`, `nitrofs-file`, then overlay/file ID ascending, then key lexical. Return the first; return `null` for whole-ROM.

- [ ] **Step 6: Run GREEN**

```bash
node --test --import tsx tests/nds-pattern-scope.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/services/nds/pattern-scope.ts tests/nds-pattern-scope.test.ts
git commit -m "feat: resolve bounded NDS pattern scopes"
```

---

### Task 3: Deterministic hit ownership and runtime mapping

**Files:**
- Create: `src/services/nds/pattern-ownership.ts`
- Modify: `src/services/nds/header.ts`
- Test: `tests/nds-pattern-ownership.test.ts`

**Interfaces:**

```ts
export const NDS_PARSED_HEADER_BYTES = 0x6c;

export type NdsPatternOwner =
  | { readonly kind: "arm9-main" | "arm7-main"; readonly processor: "arm9" | "arm7"; readonly runtimeAddress: number }
  | {
      readonly kind: "arm9-overlay" | "arm7-overlay";
      readonly processor: "arm9" | "arm7";
      readonly overlayId: number;
      readonly fileId: number;
      readonly compressed: boolean;
      readonly runtimeAddress: number | null;
    }
  | { readonly kind: "nitrofs-file"; readonly fileId: number; readonly path: string | null }
  | { readonly kind: "header" | "fnt" | "fat" | "arm9-overlay-table" | "arm7-overlay-table" }
  | { readonly kind: "unmapped" };

export function ownersForNdsPatternHit(map: NdsRomMap, start: number, end: number): readonly NdsPatternOwner[];
```

All ownership uses full-hit-span containment.

- [ ] **Step 1: Write failing ownership tests with an explicit fixture helper**

Define:

```ts
async function createOwnershipFixture() {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    fntSize: 0x40,
    fatSize: 24,
    arm9OverlaySize: 64,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1200, 0x1220);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1300, 0x1340);
  writeFatEntry(fixture.buffer, 0x900, 2, 0x1400, 0x1440);
  writeFntMainRecord(fixture.buffer, 0x800, 0, 8, 0, 1);
  writeFntSubtable(fixture.buffer, 0x800, 8, [encodeFntFileEntry("asset.bin")]);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 7,
    ramAddress: 0x02200000,
    ramSize: 0x20,
    bssSize: 0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 1,
    compressedSize: 0,
    flags: 0,
  });
  writeOverlayRecord(fixture.buffer, 0xa00, 1, {
    overlayId: 8,
    ramAddress: 0x02300000,
    ramSize: 0x80,
    bssSize: 0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 2,
    compressedSize: 0x30,
    flags: 1,
  });
  await fixture.write();
  return fixture;
}
```

Tests must assert:

```ts
const fixture = await createOwnershipFixture();
const map = await readNdsRomMap(fixture.romPath);
assert.deepEqual(ownersForNdsPatternHit(map, 0x204, 0x208), [{
  kind: "arm9-main", processor: "arm9", runtimeAddress: 0x02000004,
}]);

const mapped = ownersForNdsPatternHit(map, 0x1304, 0x1308)
  .find((owner) => owner.kind === "arm9-overlay");
assert.equal(mapped?.runtimeAddress, 0x02200004);

const beyondPrefix = ownersForNdsPatternHit(map, 0x1324, 0x1328)
  .find((owner) => owner.kind === "arm9-overlay");
assert.equal(beyondPrefix?.runtimeAddress, null);

const compressed = ownersForNdsPatternHit(map, 0x1404, 0x1408)
  .find((owner) => owner.kind === "arm9-overlay");
assert.equal(compressed?.runtimeAddress, null);
```

Also assert overlay-backed bytes include both overlay and `nitrofs-file` ownership for file ID 1, structural regions receive header/FNT/FAT/overlay-table owners when the full hit fits, a hit at `bannerOffset` gets no banner owner, and truly ownerless bytes get exactly `{ kind: "unmapped" }`.

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/nds-pattern-ownership.test.ts
```

Expected: FAIL because ownership mapping and exported header extent do not exist.

- [ ] **Step 3: Export the existing parsed-header extent without behavior change**

In `header.ts`:

```ts
export const NDS_PARSED_HEADER_BYTES = 0x6c;
```

Use this constant where the private `FULL_HEADER_BYTES` value was used.

- [ ] **Step 4: Implement full-span ownership and runtime mapping**

Use:

```ts
function contains(hitStart: number, hitEnd: number, ownerStart: number, ownerEnd: number): boolean {
  return hitEnd > hitStart && hitStart >= ownerStart && hitEnd <= ownerEnd;
}
```

Main runtime mapping is `ramAddress + (hitStart - romOffset)` only for a fully contained hit.

Uncompressed overlay mapping uses:

```ts
const mappedBytes = Math.min(overlay.ramSize, overlay.romSize);
const mappedEnd = overlay.romOffset + mappedBytes;
```

and attaches a runtime address only when `!overlay.compressed && hitEnd <= mappedEnd`. Otherwise the overlay owner remains valid with `runtimeAddress: null`.

Owner order is deterministic: ARM9 main, ARM7 main, ARM9 overlays by ID, ARM7 overlays by ID, NitroFS files by file ID, header, FNT, FAT, ARM9 overlay table, ARM7 overlay table. Add `unmapped` only when no owner exists.

- [ ] **Step 5: Run GREEN plus header regression**

```bash
node --test --import tsx tests/nds-pattern-ownership.test.ts tests/nds-header.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/services/nds/header.ts src/services/nds/pattern-ownership.ts tests/nds-pattern-ownership.test.ts
git commit -m "feat: map NDS pattern hit ownership"
```

---

### Task 4: Bounded streaming matcher, overlap, alignment, pagination, and truncation

**Files:**
- Create: `src/services/nds/pattern-match.ts`
- Test: `tests/nds-pattern-match.test.ts`

**Interfaces:**

```ts
export type NdsPatternTruncationReason = "scan-byte-limit" | "match-count-limit";

export interface NdsPatternMatchOptions {
  readonly offset: number;
  readonly limit: number;
  readonly maxScanBytes: number;
}

export interface NdsPatternScanResult {
  readonly status: "complete" | "truncated";
  readonly truncationReasons: readonly NdsPatternTruncationReason[];
  readonly offset: number;
  readonly limit: number;
  readonly nextOffset: number | null;
  readonly scannedBytes: number;
  readonly discoveredMatches: number;
  readonly matchOffsets: readonly number[];
}

export type NdsPatternReadAt = (romOffset: number, length: number) => Promise<Buffer>;

export const NDS_PATTERN_DEFAULT_SCAN_BYTES = 64 * 1024 * 1024;
export const NDS_PATTERN_MAX_SCAN_BYTES = 512 * 1024 * 1024;
export const NDS_PATTERN_DEFAULT_LIMIT = 100;
export const NDS_PATTERN_MAX_LIMIT = 1000;
export const NDS_PATTERN_MAX_OFFSET = 99999;
export const NDS_PATTERN_MATCH_CEILING = 100000;
export const NDS_PATTERN_SCAN_CHUNK_BYTES = 64 * 1024;

export async function scanNdsPatternMatches(
  scope: ResolvedNdsPatternScope,
  pattern: CompiledNdsPattern,
  readAt: NdsPatternReadAt,
  options: NdsPatternMatchOptions,
  internalChunkBytes?: number,
): Promise<NdsPatternScanResult>;
```

`internalChunkBytes` is a service/test seam only and is never exposed by MCP.

- [ ] **Step 1: Write failing pure matcher tests with all local helpers defined**

At the top of `tests/nds-pattern-match.test.ts` define:

```ts
function memoryReader(buffer: Buffer) {
  return async (offset: number, length: number) =>
    Buffer.from(buffer.subarray(offset, offset + length));
}

function wholeRomScope(size: number): ResolvedNdsPatternScope {
  return {
    kind: "whole-rom",
    components: [],
    physicalRanges: [{ start: 0, end: size }],
  };
}
```

Then test overlap and chunk carry:

```ts
test("returns overlapping matches and counts each physical byte once", async () => {
  const bytes = Buffer.from([0xaa, 0xaa, 0xaa]);
  const result = await scanNdsPatternMatches(
    wholeRomScope(bytes.length),
    compileNdsPattern({ kind: "byte-signature", signature: "AA AA" }),
    memoryReader(bytes),
    { offset: 0, limit: 10, maxScanBytes: 3 },
    2,
  );
  assert.deepEqual(result.matchOffsets, [0, 1]);
  assert.equal(result.scannedBytes, 3);
  assert.equal(result.status, "complete");
});
```

Add a wildcard match that crosses a two-byte internal chunk boundary and assert it appears once.

For adjacent-component rejection use this exact scope:

```ts
const adjacentScope: ResolvedNdsPatternScope = {
  kind: "components",
  components: [
    { key: "file:0", kind: "nitrofs-file", start: 0, end: 2, processor: null, overlayId: null, fileId: 0, path: "a", compressed: false },
    { key: "file:1", kind: "nitrofs-file", start: 2, end: 4, processor: null, overlayId: null, fileId: 1, path: "b", compressed: false },
  ],
  physicalRanges: [{ start: 0, end: 4 }],
};
```

Search pattern `BB CC` in bytes `[0x00,0xbb,0xcc,0x00]` and assert no match at 1. Search the same bytes with `wholeRomScope(4)` and assert match `[1]`.

Also add an overlapping-component scope where one selected component spans the entire candidate and prove the match remains valid.

- [ ] **Step 2: Add pagination/alignment/truncation RED tests**

Use single-byte `AA` over five bytes and assert for `offset:2, limit:2`:

```ts
assert.deepEqual(result.matchOffsets, [2, 3]);
assert.equal(result.discoveredMatches, 5);
assert.equal(result.nextOffset, 4);
```

Test 2-byte and 4-byte alignment against non-zero absolute ROM starts.

For scan truncation, make the physical range larger than `maxScanBytes` and assert `status === "truncated"`, reasons equal `[
"scan-byte-limit"]`, and a candidate whose final byte was not read is absent.

For the 100000 ceiling, use a 100001-byte in-memory buffer of `0xaa`, single-byte pattern `AA`, a sufficiently large scan budget, and assert:

```ts
assert.equal(result.discoveredMatches, 100000);
assert.equal(result.status, "truncated");
assert.deepEqual(result.truncationReasons, ["match-count-limit"]);
```

- [ ] **Step 3: Run RED**

```bash
node --test --import tsx tests/nds-pattern-match.test.ts
```

Expected: FAIL because `pattern-match.ts` does not exist.

- [ ] **Step 4: Implement exact option validation and chunked scanning**

Require safe integers with:

```text
1 <= limit <= 1000
0 <= offset <= 99999
1 <= maxScanBytes <= 512 MiB
1 <= internalChunkBytes
```

Invalid values throw `pattern-search-limit-exceeded`.

Iterate `scope.physicalRanges` in ascending order. Read at most `min(chunkBytes, rangeRemaining, scanBudgetRemaining)` new bytes. Carry at most `pattern.bytes.length - 1` previous contiguous bytes into the next matching window. Do not carry across a physical gap. Increment `scannedBytes` only by newly read bytes.

- [ ] **Step 5: Implement exact candidate matching**

For every candidate start with a full pattern available:

1. require absolute ROM alignment;
2. require `patternSpanIsEligible(scope, start, end)`;
3. compare every byte using `(actual & mask) === (expected & mask)`;
4. avoid rechecking starts already completed in the prior carry window;
5. on match increment `discoveredMatches` and retain only match indices in the requested page.

Advance candidate start by one byte so overlap is preserved.

- [ ] **Step 6: Implement truncation and page metadata**

Stop with `scan-byte-limit` when the physical scan budget ends before all ranges are fully read. Stop immediately at 100000 established matches with `match-count-limit`.

Set:

```ts
const returnedEndIndex = options.offset + matchOffsets.length;
const nextOffset = returnedEndIndex < discoveredMatches ? returnedEndIndex : null;
```

Do not infer undiscovered matches beyond a truncation boundary.

- [ ] **Step 7: Run GREEN**

```bash
node --test --import tsx tests/nds-pattern-match.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/services/nds/pattern-match.ts tests/nds-pattern-match.test.ts
git commit -m "feat: scan bounded NDS byte patterns"
```

---

### Task 5: Top-level pattern search, context, result records, and SHA integrity

**Files:**
- Create: `src/services/nds/pattern-search.ts`
- Test: `tests/nds-pattern-search.test.ts`

**Interfaces:**

```ts
export interface NdsPatternHitContext {
  readonly beforeHex: string;
  readonly afterHex: string;
  readonly clippedAtStart: boolean;
  readonly clippedAtEnd: boolean;
}

export interface NdsPatternHit {
  readonly romOffset: number;
  readonly endOffset: number;
  readonly length: number;
  readonly bytesHex: string;
  readonly owners: readonly NdsPatternOwner[];
  readonly context?: NdsPatternHitContext;
}

export interface NdsPatternSearchOptions {
  readonly offset?: number;
  readonly limit?: number;
  readonly maxScanBytes?: number;
  readonly contextBytes?: number;
}

export interface NdsPatternSearchResult {
  readonly status: "complete" | "truncated";
  readonly truncationReasons: readonly NdsPatternTruncationReason[];
  readonly offset: number;
  readonly limit: number;
  readonly nextOffset: number | null;
  readonly scannedBytes: number;
  readonly discoveredMatches: number;
  readonly matches: readonly NdsPatternHit[];
}

export const NDS_PATTERN_MAX_CONTEXT_BYTES = 64;

export interface NdsPatternSearchDependencies {
  readonly hashFileSha256: (filePath: string) => Promise<string>;
}

export async function searchNdsPattern(
  map: NdsRomMap,
  pattern: NdsSearchPattern,
  scope: NdsPatternSearchScope,
  options?: NdsPatternSearchOptions,
  dependencies?: Partial<NdsPatternSearchDependencies>,
): Promise<NdsPatternSearchResult>;
```

- [ ] **Step 1: Write failing real-file search tests**

Start with:

```ts
test("searches ARM9 main and returns canonical hit records", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x20 });
  fixture.buffer.set([0xaa, 0xaa, 0xaa], 0x200);
  await fixture.write();
  const map = await readNdsRomMap(fixture.romPath);
  const result = await searchNdsPattern(
    map,
    { kind: "byte-signature", signature: "AA AA" },
    { kind: "components", arm9Main: true },
    { limit: 10 },
  );
  assert.equal(result.status, "complete");
  assert.deepEqual(result.matches.map((hit) => hit.romOffset), [0x200, 0x201]);
  assert.equal(result.matches[0]?.owners[0]?.kind, "arm9-main");
});
```

Add separate real-file cases for integer, ASCII, UTF-16LE, compressed overlay stored bytes, exact NitroFS path, and combined component scope. Build those fixtures directly with the existing `createNdsFixture`, `writeFatEntry`, `writeFntMainRecord`, `writeFntSubtable`, `encodeFntFileEntry`, and `writeOverlayRecord` helpers; do not introduce a second shared fixture module.

- [ ] **Step 2: Add boundary and context RED tests**

Construct two adjacent FAT/NitroFS files with ranges `[0x1200,0x1220)` and `[0x1220,0x1240)`, place `AA` at `0x121f` and `BB` at `0x1220`, and assert component scope over both files does not return `AA BB`. Assert whole-ROM scope does return it.

For component context, place a hit one byte from a selected file start, request `contextBytes: 4`, and assert before-context clips at that file start with `clippedAtStart: true`. For whole-ROM, prove context is clipped only at offset 0/file size.

- [ ] **Step 3: Add source-integrity RED tests**

Define the pattern explicitly:

```ts
const pattern = { kind: "byte-signature", signature: "AA" } as const;
```

Pre-scan mismatch:

```ts
const map = await readNdsRomMap(fixture.romPath);
fixture.buffer[0x200] ^= 0xff;
await fixture.write();
await assert.rejects(
  searchNdsPattern(map, pattern, { kind: "whole-rom" }),
  (error) => error instanceof NdsError && error.category === "invalid-rom",
);
```

Post-scan check through the deterministic hash dependency:

```ts
let hashCalls = 0;
await assert.rejects(
  searchNdsPattern(map, pattern, { kind: "whole-rom" }, {}, {
    hashFileSha256: async () => (++hashCalls === 1 ? map.sha256 : "0".repeat(64)),
  }),
  (error) => error instanceof NdsError && error.category === "invalid-rom",
);
assert.equal(hashCalls, 2);
```

- [ ] **Step 4: Run RED**

```bash
node --test --import tsx tests/nds-pattern-search.test.ts
```

Expected: FAIL because `pattern-search.ts` does not exist.

- [ ] **Step 5: Implement defaults, compiler/scope composition, and the integrity envelope**

Defaults:

```ts
const offset = options.offset ?? 0;
const limit = options.limit ?? 100;
const maxScanBytes = options.maxScanBytes ?? 64 * 1024 * 1024;
const contextBytes = options.contextBytes ?? 0;
```

Validate `contextBytes` as a safe integer in `0..64` or throw `pattern-search-limit-exceeded`.

Use the same outcome structure as `withValidatedNdsRomReader`: hash before, open file, run scan/context reads while capturing success/error, close file in `finally`, hash after, then either throw changed-ROM `invalid-rom`, rethrow the original scan error, or return success.

The injected dependency may replace only `hashFileSha256`; filesystem reading always uses production `open`/`readExact`.

- [ ] **Step 6: Implement result records and context reads**

Compile once, resolve scope once, call `scanNdsPatternMatches`, then for every returned offset read the exact matched bytes and create:

```ts
{
  romOffset,
  endOffset: romOffset + compiled.bytes.length,
  length: compiled.bytes.length,
  bytesHex: matchedBytes.toString("hex"),
  owners: ownersForNdsPatternHit(map, romOffset, endOffset),
}
```

When `contextBytes > 0`, component scope uses `selectPatternContextComponent()` and clamps context to that component. Whole-ROM clamps to `[0,map.fileSize)`. `clippedAtStart` / `clippedAtEnd` compare requested vs clamped bounds. Context reads do not modify `scannedBytes`.

- [ ] **Step 7: Run GREEN and related regressions**

```bash
node --test --import tsx tests/nds-patterns.test.ts tests/nds-pattern-scope.test.ts tests/nds-pattern-ownership.test.ts tests/nds-pattern-match.test.ts tests/nds-pattern-search.test.ts tests/nds-resolver.test.ts tests/nds-extraction.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/services/nds/pattern-search.ts tests/nds-pattern-search.test.ts
git commit -m "feat: add canonical NDS pattern search service"
```

---

### Task 6: Register `nds_search_pattern` and update server capabilities

**Files:**
- Modify: `src/tools/nds.ts`
- Modify: `src/index.ts`
- Modify: `tests/nds-tools.test.ts`

**Interfaces:** public MCP tool `nds_search_pattern`.

- [ ] **Step 1: Write failing registration/schema tests**

Add `"nds_search_pattern"` to `EXPECTED_TOOLS` and require exactly twelve registrations.

Assert defaults:

```ts
assert.deepEqual(server.parse("nds_search_pattern", {
  rom: "game.nds",
  pattern: { kind: "byte-signature", signature: "AA ?? BB" },
  scope: { kind: "whole-rom" },
}), {
  rom: "game.nds",
  pattern: { kind: "byte-signature", signature: "AA ?? BB" },
  scope: { kind: "whole-rom" },
  offset: 0,
  limit: 100,
  maxScanBytes: 64 * 1024 * 1024,
  contextBytes: 0,
});
```

Assert schema rejection for `limit:1001`, `offset:100000`, `maxScanBytes:512*1024*1024+1`, `contextBytes:65`, and integer alignment `3`.

Assert no top-level schema fields named:

```ts
for (const forbidden of [
  "binary", "bytes", "baseAddress", "runtimeAddress",
  "start", "end", "length", "output", "path",
]) {
  assert.equal(Object.hasOwn(server.schema("nds_search_pattern"), forbidden), false);
}
```

- [ ] **Step 2: Write failing handler/error/output-bound tests**

Build an ARM9 fixture with `AA AA AA`, invoke the tool, and assert offsets `[0x200,0x201]`. Add malformed-pattern and empty-component-scope calls and require error categories `invalid-pattern` and `invalid-pattern-scope` with corrective actions. Register with a very small `maxOutputBytes`, request many hits/context, and require existing `output-bound-exceeded` handling.

- [ ] **Step 3: Run RED**

```bash
node --test --import tsx tests/nds-tools.test.ts
```

Expected: FAIL because the twelfth tool does not exist.

- [ ] **Step 4: Add exact Zod schemas**

Use:

```ts
const patternSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("byte-signature"), signature: z.string().min(1) }),
  z.object({
    kind: z.literal("integer"),
    value: z.number().int(),
    width: z.union([z.literal(8), z.literal(16), z.literal(32)]),
    endian: z.enum(["little", "big"]),
    signed: z.boolean(),
    alignment: z.union([z.literal(1), z.literal(2), z.literal(4)]).optional(),
  }),
  z.object({ kind: z.literal("ascii"), text: z.string().min(1) }),
  z.object({ kind: z.literal("utf16le"), text: z.string().min(1) }),
]);

const patternScopeSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("whole-rom") }),
  z.object({
    kind: z.literal("components"),
    arm9Main: z.boolean().optional(),
    arm7Main: z.boolean().optional(),
    arm9OverlayIds: z.array(uint32Schema).max(128).optional(),
    arm7OverlayIds: z.array(uint32Schema).max(128).optional(),
    nitroFsFileIds: z.array(uint32Schema).max(256).optional(),
    nitroFsPaths: z.array(z.string().min(1).max(4096)).max(256).optional(),
  }),
]);
```

Add scalar schemas for exact defaults/maxes. Service-level validation still enforces combined selector totals and non-empty component scope.

- [ ] **Step 5: Register the exact handler and corrective actions**

Register:

```ts
server.tool(
  "nds_search_pattern",
  "Search one bounded exact/wildcard byte signature, typed integer, ASCII string, or UTF-16LE string in a validated Nintendo DS ROM without mutation or heuristic inference.",
  {
    rom: romSchema,
    pattern: patternSchema,
    scope: patternScopeSchema,
    offset: z.number().int().min(0).max(99999).default(0),
    limit: z.number().int().min(1).max(1000).default(100),
    maxScanBytes: z.number().int().min(1).max(512 * 1024 * 1024).default(64 * 1024 * 1024),
    contextBytes: z.number().int().min(0).max(64).default(0),
  },
  async ({ rom, pattern, scope, offset, limit, maxScanBytes, contextBytes }) => {
    const operation = "nds_search_pattern";
    try {
      const map = await readNdsRomMap(resolveRom(config, rom));
      const result = await searchNdsPattern(map, pattern, scope, {
        offset,
        limit,
        maxScanBytes,
        contextBytes,
      });
      return boundedTextResult(config, operation, {
        rom: relativeWorkspacePath(config, map.romPath),
        sha256: map.sha256,
        ...result,
      });
    } catch (error) {
      return ndsErrorResult(config, operation, error, "invalid-rom");
    }
  },
);
```

Extend `correctiveAction()` for the three new categories without changing existing actions.

- [ ] **Step 6: Update `server_capabilities`**

Insert `nds_search_pattern` exactly once in the tool array after `nds_find_xrefs`. Update `ndsStaticAnalysisPolicy` to allow bounded validated-NDS pattern search while still explicitly prohibiting generic binary pattern search. Do not change debugger/runtime policies.

- [ ] **Step 7: Run GREEN**

```bash
node --test --import tsx tests/nds-tools.test.ts
npm run typecheck
```

Expected: PASS with exactly twelve NDS registrations.

- [ ] **Step 8: Commit**

```bash
git add src/tools/nds.ts src/index.ts tests/nds-tools.test.ts
git commit -m "feat: expose bounded NDS pattern search tool"
```

---

### Task 7: Packaged production-artifact pattern-search smoke acceptance

**Files:**
- Modify: `scripts/check-install.mjs`
- Modify: `tests/package-capstone-install.test.ts`

- [ ] **Step 1: Write failing package-verifier assertions**

Add:

```ts
test("install verifier smoke-searches packaged NDS patterns", async () => {
  const source = await readFile(path.resolve("scripts/check-install.mjs"), "utf8");
  for (const required of [
    "dist/services/nds/pattern-search.js",
    "dist/services/nds/rom-map.js",
    "Packaged NDS pattern overlap smoke failed",
    "Packaged NDS pattern ownership smoke failed",
  ]) {
    assert.equal(source.includes(required), true, required);
  }
});
```

Keep all existing Capstone/WASM/reference checks unchanged.

- [ ] **Step 2: Run RED**

```bash
node --test --import tsx tests/package-capstone-install.test.ts
```

Expected: FAIL because pattern-search packaged checks are absent.

- [ ] **Step 3: Extend assembled required/imported files**

Add `dist/services/nds/pattern-search.js` and `dist/services/nds/rom-map.js` to `required`. Dynamically import `searchNdsPattern` and `readNdsRomMap` from assembled `dist` URLs.

- [ ] **Step 4: Create and remove a tiny valid NDS fixture inside `check-install.mjs`**

Import `mkdtemp`, `writeFile`, `rm` from `node:fs/promises` and `os` from `node:os`. Create `Buffer.alloc(0x1000)` and write:

```js
fixture.writeUInt32LE(0x200, 0x20);
fixture.writeUInt32LE(0x02000000, 0x24);
fixture.writeUInt32LE(0x02000000, 0x28);
fixture.writeUInt32LE(0x20, 0x2c);
fixture.writeUInt32LE(0x300, 0x30);
fixture.writeUInt32LE(0x03800000, 0x34);
fixture.writeUInt32LE(0x03800000, 0x38);
fixture.writeUInt32LE(0x20, 0x3c);
fixture.writeUInt32LE(0x400, 0x40);
fixture.writeUInt32LE(0x500, 0x48);
fixture.writeUInt32LE(0x600, 0x50);
fixture.writeUInt32LE(0x700, 0x58);
fixture.writeUInt32LE(0x800, 0x68);
fixture.set([0xaa, 0xaa, 0xaa], 0x200);
```

Write it under a temp directory, parse with packaged `readNdsRomMap`, and remove the directory in `finally`.

- [ ] **Step 5: Smoke the compiled search service**

Call:

```js
const result = await searchNdsPattern(
  patternMap,
  { kind: "byte-signature", signature: "AA ??" },
  { kind: "components", arm9Main: true },
  { offset: 0, limit: 10, maxScanBytes: 0x20, contextBytes: 0 },
);
```

Require exact offsets `[0x200,0x201]`, else throw `Packaged NDS pattern overlap smoke failed`. Require first-hit owner `arm9-main` with runtime address `0x02000000`, else throw `Packaged NDS pattern ownership smoke failed`.

The smoke must not import `src/` or `tests/helpers`.

- [ ] **Step 6: Run GREEN**

```bash
npm run build
node --test --import tsx tests/package-capstone-install.test.ts
node scripts/check-install.mjs .
```

Expected: PASS including existing Capstone/reference smoke checks.

- [ ] **Step 7: Commit**

```bash
git add scripts/check-install.mjs tests/package-capstone-install.test.ts
git commit -m "test: smoke packaged NDS pattern search"
```

---

### Task 8: User-facing documentation and security contract

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Document the twelfth NDS tool and exact pattern syntax**

Add `nds_search_pattern` to the tool list. Document `12 34 56 78`, `12 34 ?? 78`, typed integers, ASCII, UTF-16LE, and explicitly state no nibble wildcard, regex, case folding, normalization, alternate encoding, or implicit terminator.

- [ ] **Step 2: Document scope, ownership, and boundary semantics**

Explain canonical component combinations, explicit `whole-rom`, physical deduplication, full-span component containment, compressed-overlay stored-byte search, full-span runtime mapping, and no inferred banner extent.

- [ ] **Step 3: Document limits, pagination, truncation, context, and security**

Include `4096` pattern bytes, `100/1000` result limit, `0/99999` offset, `64 MiB/512 MiB` scan bytes, `0/64` context, 100000 discovered-match ceiling, exact truncation reasons, non-resumable scan-byte truncation, `nextOffset` semantics, and the generic-binary prohibition.

- [ ] **Step 4: Verify docs and repository checks**

```bash
grep -n "nds_search_pattern" README.md
grep -n "scan-byte-limit" README.md
grep -n "match-count-limit" README.md
grep -n "4096" README.md
grep -n "512 MiB" README.md
grep -n "generic binary" README.md
npm run check
```

Expected: every grep finds the contract and `npm run check` exits 0.

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: document NDS pattern discovery"
```

---

### Task 9: Final regression, package, and scope audit

**Files:**
- No planned production changes. Any final defect fix must start with a failing regression test and receive a separate commit.

- [ ] **Step 1: Run focused milestone tests**

```bash
node --test --import tsx tests/nds-patterns.test.ts tests/nds-pattern-scope.test.ts tests/nds-pattern-ownership.test.ts tests/nds-pattern-match.test.ts tests/nds-pattern-search.test.ts tests/nds-tools.test.ts tests/package-capstone-install.test.ts
```

Expected: PASS.

- [ ] **Step 2: Run complete verification**

```bash
npm run typecheck
npm test
npm run build
npm run check
node scripts/check-install.mjs .
```

Expected: all commands exit 0.

- [ ] **Step 3: Audit dependencies and milestone diff**

```bash
git diff -- package.json package-lock.json
git diff --name-only e3769d2756364dd2f2546536b3015e86c7b73473...HEAD
```

Expected: dependency diff empty. Changed production files are confined to new NDS pattern services, `errors.ts`, exported header constant, NDS tool/capability wiring, package smoke, README, design/plan docs, and tests. No DeSmuME, Capstone, disassembly, CFG, reference, or xref production implementation file changes.

- [ ] **Step 4: Mechanically inspect public tool surface**

```bash
grep -n 'nds_search_pattern' src/index.ts src/tools/nds.ts README.md
grep -n 'server.tool(' src/tools/nds.ts
```

Expected: capability and registration each contain the new tool exactly once; `tests/nds-tools.test.ts` proves twelve NDS registrations.

- [ ] **Step 5: Require final GitHub Actions evidence**

Push the final branch/PR head and require both workflows used by prior milestones:

- CI: success.
- Package: success, including `Assemble and smoke-test self-contained bundle`.

Do not claim post-merge `main` verification unless a separate post-merge run is actually visible.

- [ ] **Step 6: Review the milestone diff**

Request code review against baseline `e3769d2756364dd2f2546536b3015e86c7b73473`. Any accepted defect fix must add or adjust a failing regression test first, then rerun Steps 1-5.

- [ ] **Step 7: Prepare merge summary**

The summary must state:

- `nds_search_pattern` is the twelfth NDS static-analysis tool;
- exact supported pattern kinds and bounds;
- component vs whole-ROM boundary semantics;
- compressed overlays are searched only as stored bytes;
- pattern hits do not imply pointers, references, functions, or tables;
- final CI/package run numbers and statuses;
- physical Intel Catalina/DeSmuME acceptance remains separate.

---

## Execution Notes

- Use RED test → minimal GREEN implementation → focused verification → commit for every implementation task.
- Keep task-sized commits; do not collapse the milestone into one implementation commit.
- Refresh the GitHub branch head before every write after any message-stream interruption. Reconcile delayed landed commits before retrying a stale write.
- If a GitHub contents write returns stale-SHA/409, refetch the branch/file and reconcile before retrying.
- Do not broaden scope to regex, multi-pattern databases, decompression, arbitrary ranges, generic binaries, or runtime memory search.
- Native Intel Catalina/DeSmuME acceptance is not part of this plan and is not a blocker for this static-analysis milestone.
