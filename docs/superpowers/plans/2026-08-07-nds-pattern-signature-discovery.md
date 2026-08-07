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
- Pattern search verifies ROM SHA-256 before scanning and again before return, including failure paths where practical; never return mixed-revision bytes.
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
- `tests/nds-patterns.test.ts` — pattern compiler/range/encoding tests.
- `tests/nds-pattern-scope.test.ts` — canonical component and physical-union tests.
- `tests/nds-pattern-ownership.test.ts` — owner/runtime mapping tests.
- `tests/nds-pattern-match.test.ts` — chunking, overlap, alignment, component-boundary, scan-limit, pagination tests.
- `tests/nds-pattern-search.test.ts` — filesystem integration, context, source-integrity, whole-ROM/component search tests.

### Modify

- `src/services/nds/errors.ts` — pattern-search error union.
- `src/services/nds/header.ts` — export the already-used parsed-header byte extent constant so ownership code does not duplicate `0x6c`.
- `src/tools/nds.ts` — bounded schemas, handler, corrective actions for `nds_search_pattern`.
- `src/index.ts` — add the twelfth NDS tool and update the static-analysis capability policy.
- `tests/nds-tools.test.ts` — exact tool count, schemas/defaults/caps, handler integration, forbidden generic surface, output bound.
- `scripts/check-install.mjs` — packaged pattern-search smoke using a tiny synthetic NDS ROM.
- `tests/package-capstone-install.test.ts` — require packaged pattern-search files/smoke messages while retaining existing Capstone/reference checks.
- `README.md` — pattern syntax, scope, ownership, pagination/truncation/context/security documentation.

### Reuse unchanged unless a failing test demonstrates a narrow compatibility defect

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
- Consumes: existing `NdsError` and `AnyNdsErrorCategory`.
- Produces:

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

And in `errors.ts`:

```ts
export type NdsPatternSearchErrorCategory =
  | "invalid-pattern"
  | "invalid-pattern-scope"
  | "pattern-search-limit-exceeded";
```

`AnyNdsErrorCategory` must include `NdsPatternSearchErrorCategory`.

- [ ] **Step 1: Write compiler tests first**

Create `tests/nds-patterns.test.ts` with concrete RED cases:

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

test("rejects malformed, empty, nibble-wildcard, and all-wildcard signatures", () => {
  for (const signature of ["", "12 GG", "A? 12", "??", "?? ??"] as const) {
    assert.throws(
      () => compileNdsPattern({ kind: "byte-signature", signature }),
      (error) => error instanceof NdsError && error.category === "invalid-pattern",
    );
  }
});

test("encodes signed and unsigned integer widths and endianness exactly", () => {
  assert.equal(hex(compileNdsPattern({
    kind: "integer", value: 0x1234, width: 16, endian: "little", signed: false,
  }).bytes), "3412");
  assert.equal(hex(compileNdsPattern({
    kind: "integer", value: 0x1234, width: 16, endian: "big", signed: false,
  }).bytes), "1234");
  assert.equal(hex(compileNdsPattern({
    kind: "integer", value: -1, width: 32, endian: "little", signed: true,
  }).bytes), "ffffffff");
});

test("validates integer range and keeps alignment explicit", () => {
  assert.equal(compileNdsPattern({
    kind: "integer", value: 1, width: 32, endian: "little", signed: false,
  }).alignment, 1);
  assert.equal(compileNdsPattern({
    kind: "integer", value: 1, width: 32, endian: "little", signed: false,
    alignment: 4,
  }).alignment, 4);
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
```

Also add a generated 4097-byte signature/string case and prove it returns `invalid-pattern`.

- [ ] **Step 2: Prove RED**

```bash
node --test --import tsx tests/nds-patterns.test.ts
```

Expected: FAIL because `patterns.ts` and the pattern-specific error categories do not exist.

- [ ] **Step 3: Extend the NDS error union**

In `src/services/nds/errors.ts`, add exactly:

```ts
export type NdsPatternSearchErrorCategory =
  | "invalid-pattern"
  | "invalid-pattern-scope"
  | "pattern-search-limit-exceeded";

export type AnyNdsErrorCategory =
  | NdsErrorCategory
  | NdsReferenceErrorCategory
  | NdsPatternSearchErrorCategory;
```

Do not rename or remove any existing category.

- [ ] **Step 4: Implement exact byte-signature compilation**

In `patterns.ts`, tokenize only by whitespace and require every token to match:

```ts
const EXACT_BYTE = /^[0-9a-fA-F]{2}$/u;
const WILDCARD = "??";
```

For each wildcard append `0x00` byte and `0x00` mask. For each concrete token append parsed byte and `0xff` mask. Reject no tokens, malformed tokens, and `mask.every((value) => value === 0)`.

- [ ] **Step 5: Implement exact integer encoding**

Use `BigInt` for range validation so 32-bit signed/unsigned boundaries are exact even though the public value is a JavaScript number:

```ts
function integerBounds(width: 8 | 16 | 32, signed: boolean): readonly [bigint, bigint] {
  const bits = BigInt(width);
  if (signed) {
    return [-(1n << (bits - 1n)), (1n << (bits - 1n)) - 1n];
  }
  return [0n, (1n << bits) - 1n];
}
```

Require `Number.isSafeInteger(pattern.value)`. Convert negative signed values to two's complement with:

```ts
const modulus = 1n << BigInt(pattern.width);
const encoded = value < 0n ? modulus + value : value;
```

Emit bytes explicitly in requested endian order. Do not search alternate encodings.

- [ ] **Step 6: Implement exact ASCII/UTF-16LE compilation and shared length check**

ASCII requires every UTF-16 code unit `<= 0x7f` and then uses `Buffer.from(text, "ascii")` only after validation. UTF-16LE uses `Buffer.from(text, "utf16le")`. Reject encoded length `<1` or `>4096` for every pattern kind.

Return fresh `Uint8Array` values and never expose mutable shared buffers.

- [ ] **Step 7: Verify GREEN**

```bash
node --test --import tsx tests/nds-patterns.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 8: Commit**

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
- Consumes: `NdsRomMap`, `NdsOverlay`, canonical NitroFS/FAT mappings, `NdsError`.
- Produces:

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

export const NDS_PATTERN_MAX_OVERLAY_SELECTORS = 128;
export const NDS_PATTERN_MAX_NITROFS_SELECTORS = 256;
export const NDS_PATTERN_MAX_COMPONENTS = 256;

export function resolveNdsPatternScope(
  map: NdsRomMap,
  scope: NdsPatternSearchScope,
): ResolvedNdsPatternScope;

export function patternSpanIsEligible(
  scope: ResolvedNdsPatternScope,
  start: number,
  end: number,
): boolean;

export function selectPatternContextComponent(
  scope: ResolvedNdsPatternScope,
  start: number,
  end: number,
): NdsPatternComponent | null;
```

- [ ] **Step 1: Write scope tests first**

Create a fixture with ARM9/ARM7 main, two FAT files, one named NitroFS file, and one ARM9 overlay using existing fixture helpers. Add tests like:

```ts
test("resolves and deduplicates canonical component selectors", async () => {
  const fixture = await buildScopeFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const resolved = resolveNdsPatternScope(map, {
    kind: "components",
    arm9Main: true,
    arm9OverlayIds: [7, 7],
    nitroFsFileIds: [0],
    nitroFsPaths: ["asset.bin"],
  });
  assert.equal(resolved.components.filter((component) => component.kind === "arm9-main").length, 1);
  assert.equal(resolved.components.filter((component) => component.kind === "arm9-overlay").length, 1);
  assert.equal(resolved.components.filter((component) => component.kind === "nitrofs-file").length, 1);
});

test("normalizes overlapping physical selections without losing canonical components", async () => {
  const fixture = await buildOverlayBackedFileFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const resolved = resolveNdsPatternScope(map, {
    kind: "components",
    arm9OverlayIds: [7],
    nitroFsFileIds: [1],
  });
  assert.equal(resolved.components.length, 2);
  assert.deepEqual(resolved.physicalRanges, [{ start: 0x1300, end: 0x1380 }]);
});
```

Add full-span containment cases that prove:

```ts
assert.equal(patternSpanIsEligible(resolved, 0x1304, 0x1310), true);
assert.equal(patternSpanIsEligible(adjacentScope, 0x121f, 0x1221), false);
```

Add context selection tests: choose greatest containing component span, then stable component order for equal spans.

- [ ] **Step 2: Prove RED**

```bash
node --test --import tsx tests/nds-pattern-scope.test.ts
```

Expected: FAIL because the scope service does not exist.

- [ ] **Step 3: Implement canonical component construction**

Use main executable ROM ranges directly from `map.header.arm9/arm7`. Use overlay stored ranges exactly:

```ts
start = overlay.romOffset;
end = overlay.romOffset + overlay.romSize;
```

Use NitroFS/FAT files from `map.filesystem.files`, preserving `fileId` and parsed `path` (which may be `null`). Resolve exact path by equality, not prefix.

Unknown overlay IDs throw existing `unknown-overlay-id`. Unknown file ID/path throw existing `unknown-file-id`.

- [ ] **Step 4: Enforce selector and component caps**

Before deduplication, require:

```ts
(arm9OverlayIds.length + arm7OverlayIds.length) <= 128
(nitroFsFileIds.length + nitroFsPaths.length) <= 256
```

After canonical component deduplication by `key`, require `components.length <= 256`. Empty `components` scope throws `invalid-pattern-scope`. Bound violations throw `pattern-search-limit-exceeded`.

- [ ] **Step 5: Implement physical-union normalization**

Sort component `[start,end)` ranges by start/end and merge physically overlapping **or adjacent** ranges only for I/O efficiency:

```ts
if (next.start <= current.end) current.end = Math.max(current.end, next.end);
```

This merge must not authorize matches. `patternSpanIsEligible()` separately checks whether the full candidate span is contained in at least one original selected component. For `whole-rom`, return one range `{ start: 0, end: map.fileSize }` and eligibility is simply `start >= 0 && end <= map.fileSize`.

- [ ] **Step 6: Implement deterministic context component selection**

Filter selected components that fully contain the hit, then sort by:

1. descending `(end - start)`;
2. canonical kind order `arm9-main`, `arm7-main`, `arm9-overlay`, `arm7-overlay`, `nitrofs-file`;
3. overlay ID ascending;
4. file ID ascending;
5. key lexical.

Return the first component or `null` for whole-ROM.

- [ ] **Step 7: Verify GREEN**

```bash
node --test --import tsx tests/nds-pattern-scope.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 8: Commit**

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
- Consumes: `NdsRomMap`, validated header/FNT/FAT/overlay ranges.
- Produces:

```ts
export const NDS_PARSED_HEADER_BYTES = 0x6c; // exported from header.ts

export type NdsPatternOwner =
  | {
      readonly kind: "arm9-main" | "arm7-main";
      readonly processor: "arm9" | "arm7";
      readonly runtimeAddress: number;
    }
  | {
      readonly kind: "arm9-overlay" | "arm7-overlay";
      readonly processor: "arm9" | "arm7";
      readonly overlayId: number;
      readonly fileId: number;
      readonly compressed: boolean;
      readonly runtimeAddress: number | null;
    }
  | {
      readonly kind: "nitrofs-file";
      readonly fileId: number;
      readonly path: string | null;
    }
  | {
      readonly kind:
        | "header"
        | "fnt"
        | "fat"
        | "arm9-overlay-table"
        | "arm7-overlay-table";
    }
  | { readonly kind: "unmapped" };

export function ownersForNdsPatternHit(
  map: NdsRomMap,
  start: number,
  end: number,
): readonly NdsPatternOwner[];
```

Every owner uses full-hit-span containment, not mere start-byte overlap.

- [ ] **Step 1: Write ownership tests first**

Cover main, overlay, compressed overlay, NitroFS, structural regions, multiple ownership, and unmapped bytes:

```ts
test("maps full-span main and uncompressed overlay hits to runtime addresses", async () => {
  const fixture = await buildOwnershipFixture();
  const map = await readNdsRomMap(fixture.romPath);
  assert.deepEqual(ownersForNdsPatternHit(map, 0x204, 0x208), [{
    kind: "arm9-main",
    processor: "arm9",
    runtimeAddress: 0x02000004,
  }]);

  const overlayOwners = ownersForNdsPatternHit(map, 0x1304, 0x1308);
  const overlay = overlayOwners.find((owner) => owner.kind === "arm9-overlay");
  assert.equal(overlay?.runtimeAddress, 0x02200004);
});
```

Add a fixture where `overlay.ramSize < overlay.romSize` and prove bytes beyond `min(ramSize, romSize)` still receive an overlay owner but `runtimeAddress: null`.

Add compressed overlay proof that `runtimeAddress` is always `null`.

Add an overlay/NitroFS shared range proof that one hit gets both owner records.

Add structural owner tests for `[0,0x6c)`, FNT, FAT, and both overlay tables. Add a hit at `bannerOffset` that receives no fabricated banner owner.

- [ ] **Step 2: Prove RED**

```bash
node --test --import tsx tests/nds-pattern-ownership.test.ts
```

Expected: FAIL because ownership mapping and exported header extent do not exist.

- [ ] **Step 3: Export the existing parsed-header extent**

In `src/services/nds/header.ts`, change only the constant visibility:

```ts
export const NDS_PARSED_HEADER_BYTES = 0x6c;
```

Use this same constant in `parseNdsHeader()` where `FULL_HEADER_BYTES` was previously used; do not change parsing behavior.

- [ ] **Step 4: Implement full-span owner containment**

Use helper:

```ts
function contains(start: number, end: number, ownerStart: number, ownerEnd: number): boolean {
  return start >= ownerStart && end <= ownerEnd && end > start;
}
```

Add owners in deterministic order: main executables, overlays sorted by processor/ID, NitroFS files by file ID, structural regions, then `unmapped` only when no owner was added.

- [ ] **Step 5: Implement direct runtime mapping conservatively**

Main runtime mapping:

```ts
runtimeAddress = executable.ramAddress + (start - executable.romOffset);
```

only when the full hit is inside `[romOffset, romEnd)`.

Uncompressed overlay direct prefix:

```ts
const mappedBytes = Math.min(overlay.ramSize, overlay.romSize);
const mappedEnd = overlay.romOffset + mappedBytes;
```

Attach `overlay.ramAddress + (start - overlay.romOffset)` only when `!overlay.compressed && end <= mappedEnd`. Otherwise set `runtimeAddress: null`.

Never add banner ownership from offset alone.

- [ ] **Step 6: Verify GREEN plus header regression**

```bash
node --test --import tsx tests/nds-pattern-ownership.test.ts tests/nds-header.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 7: Commit**

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
- Consumes: `CompiledNdsPattern`, `ResolvedNdsPatternScope`, `patternSpanIsEligible()`.
- Produces:

```ts
export type NdsPatternTruncationReason =
  | "scan-byte-limit"
  | "match-count-limit";

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

export type NdsPatternReadAt = (
  romOffset: number,
  length: number,
) => Promise<Buffer>;

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

`internalChunkBytes` is an internal/test seam only; it is never exposed by MCP.

- [ ] **Step 1: Write pure matcher tests first**

Use an in-memory reader:

```ts
function reader(buffer: Buffer) {
  return async (offset: number, length: number) =>
    Buffer.from(buffer.subarray(offset, offset + length));
}
```

Add exact RED tests:

```ts
test("returns overlapping matches in ascending ROM order", async () => {
  const bytes = Buffer.from([0xaa, 0xaa, 0xaa]);
  const scope = wholeRomScope(bytes.length);
  const result = await scanNdsPatternMatches(
    scope,
    compileNdsPattern({ kind: "byte-signature", signature: "AA AA" }),
    reader(bytes),
    { offset: 0, limit: 10, maxScanBytes: 3 },
    2,
  );
  assert.deepEqual(result.matchOffsets, [0, 1]);
  assert.equal(result.scannedBytes, 3);
  assert.equal(result.status, "complete");
});
```

Add tests for:

- wildcard match across an internal 2/3-byte chunk boundary;
- no duplicate emitted from carry bytes;
- 2/4-byte absolute ROM alignment filtering;
- disconnected physical ranges scanned in ascending order;
- adjacent selected components physically coalesced for I/O but a spanning candidate rejected by `patternSpanIsEligible()`;
- overlapping selected components where a candidate crossing an internal provenance edge remains valid because one selected component contains the full span;
- whole-ROM candidate crossing the same structural edge remains valid.

- [ ] **Step 2: Add pagination/truncation RED tests**

Concrete assertions:

```ts
assert.deepEqual(page.matchOffsets, [2, 3]);
assert.equal(page.discoveredMatches, 5);
assert.equal(page.nextOffset, 4);
```

for `offset: 2, limit: 2` over five known matches.

For scan-byte truncation, use a range larger than `maxScanBytes` and assert:

```ts
assert.equal(result.status, "truncated");
assert.deepEqual(result.truncationReasons, ["scan-byte-limit"]);
assert.equal(result.nextOffset, null); // when no already-discovered later page hit exists
```

Prove a candidate whose final byte lies outside the physically examined prefix is not reported.

For match ceiling, construct a synthetic read source/range that produces at least 100001 single-byte exact hits and assert `discoveredMatches === 100000`, `status === "truncated"`, and `match-count-limit` is present.

- [ ] **Step 3: Prove RED**

```bash
node --test --import tsx tests/nds-pattern-match.test.ts
```

Expected: FAIL because the matcher does not exist.

- [ ] **Step 4: Validate matcher options**

Inside `scanNdsPatternMatches`, require safe integers and exact bounds:

```ts
1 <= limit <= 1000
0 <= offset <= 99999
1 <= maxScanBytes <= 512 * 1024 * 1024
1 <= internalChunkBytes
```

Invalid bounds throw `NdsError("pattern-search-limit-exceeded", ...)`.

- [ ] **Step 5: Implement chunked unique-byte scanning**

Iterate normalized `scope.physicalRanges` in ascending order. Read at most `min(chunkBytes, remainingRangeBytes, remainingScanBudget)` new physical bytes per iteration. Preserve up to `pattern.bytes.length - 1` carry bytes only when the previous read ended exactly at the current physical position.

Build each matching window as `carry + newBytes`, but increment:

```ts
scannedBytes += newBytes.length;
```

only once. Track the absolute start offset represented by the window so candidate offsets remain exact.

Do not carry across a physical gap.

- [ ] **Step 6: Implement exact/masked candidates and eligibility**

For each candidate start in the combined window that has all `pattern.bytes.length` bytes available:

1. reject if `candidateStart % pattern.alignment !== 0`;
2. reject unless `patternSpanIsEligible(scope, candidateStart, candidateEnd)`;
3. compare every byte using `(actual & mask) === (expected & mask)`;
4. guard against re-checking candidate starts already considered in the prior carry window;
5. on match increment `discoveredMatches` and append the start only when its match index lies in `[offset, offset + limit)`.

This preserves overlapping starts by advancing the candidate by exactly one byte.

- [ ] **Step 7: Implement truncation and `nextOffset` semantics**

If the scan budget is exhausted before the normalized physical union is fully read, add `scan-byte-limit` and stop. If `discoveredMatches === 100000`, add `match-count-limit` and stop immediately.

Set:

```ts
const returnedEndIndex = options.offset + matchOffsets.length;
const nextOffset = returnedEndIndex < discoveredMatches ? returnedEndIndex : null;
```

`status` is `truncated` iff at least one truncation reason exists. Do not infer undiscovered matches beyond the scan boundary.

- [ ] **Step 8: Verify GREEN**

```bash
node --test --import tsx tests/nds-pattern-match.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 9: Commit**

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
- Consumes: `compileNdsPattern`, `resolveNdsPatternScope`, `scanNdsPatternMatches`, `ownersForNdsPatternHit`, `hashFileSha256`, `readExact`.
- Produces:

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

The optional dependency object is an internal deterministic-test seam; MCP never exposes it.

- [ ] **Step 1: Write end-to-end service tests first**

Use real NDS fixtures/files. Add a component search:

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

Add separate tests for integer, ASCII, UTF-16LE, compressed overlay stored bytes, NitroFS exact path, and combined component scope.

- [ ] **Step 2: Add component-boundary and whole-ROM integration tests**

Construct two adjacent selected FAT/NitroFS components containing bytes `AA | BB` at the boundary and assert component scope does not return `AA BB`. Search the same ROM using `{ kind: "whole-rom" }` and assert the physical cross-boundary match is returned.

- [ ] **Step 3: Add context tests**

For component scope, request `contextBytes: 4` around a hit near the selected component start/end and assert `beforeHex`/`afterHex` are clipped to the deterministic containing component and `clippedAtStart`/`clippedAtEnd` accurately reflect clipping.

For whole-ROM, prove context can cross ordinary component/structure boundaries and is clipped only at offsets `0` and `map.fileSize`.

- [ ] **Step 4: Add source-integrity RED tests**

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

Post-scan verification is deterministic through the dependency seam:

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

Also prove the second hash is attempted when the matcher/read path throws by using a fixture that is truncated after map creation or a narrow injected hash sequence plus an invalidated read, and assert the original read error is returned only when the post-hash still matches.

- [ ] **Step 5: Prove RED**

```bash
node --test --import tsx tests/nds-pattern-search.test.ts
```

Expected: FAIL because the top-level service does not exist.

- [ ] **Step 6: Implement defaults and integrity envelope**

Defaults are exact:

```ts
const offset = options.offset ?? 0;
const limit = options.limit ?? 100;
const maxScanBytes = options.maxScanBytes ?? 64 * 1024 * 1024;
const contextBytes = options.contextBytes ?? 0;
```

Validate `contextBytes` as safe integer `0..64`, else `pattern-search-limit-exceeded`.

Before opening/reading, hash `map.romPath` and require equality with `map.sha256`. Open one file handle, run the scan and context reads, capture success/error, close the handle, then hash again before returning/rethrowing. If the final hash differs, throw `NdsError("invalid-rom", "Source ROM changed during pattern search")` even if the scan otherwise succeeded.

- [ ] **Step 7: Compose compiler, scope, and matcher**

Compile the public pattern, resolve the scope, and create `readAt` using `readExact(handle, offset, length, "NDS pattern search")`. Pass the exact matcher defaults/options. Keep the compiled pattern local; do not expose an arbitrary read primitive publicly.

- [ ] **Step 8: Build full hit records**

For each returned `matchOffset`:

```ts
const endOffset = matchOffset + compiled.bytes.length;
const matchedBytes = await readExact(handle, matchOffset, compiled.bytes.length, "NDS pattern hit");
```

Return lowercase `bytesHex`, `ownersForNdsPatternHit(map, matchOffset, endOffset)`, and context only when `contextBytes > 0`.

For component context use `selectPatternContextComponent()`. Compute requested context bounds, clamp to the chosen component. For whole-ROM clamp to `[0,map.fileSize)`. Set clip booleans by comparing unclamped and clamped bounds.

Context reads do not alter `scannedBytes`.

- [ ] **Step 9: Verify GREEN and related NDS regressions**

```bash
node --test --import tsx \
  tests/nds-patterns.test.ts \
  tests/nds-pattern-scope.test.ts \
  tests/nds-pattern-ownership.test.ts \
  tests/nds-pattern-match.test.ts \
  tests/nds-pattern-search.test.ts \
  tests/nds-resolver.test.ts \
  tests/nds-extraction.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 10: Commit**

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

**Interfaces:**
- Consumes: `NdsSearchPattern`, `NdsPatternSearchScope`, `searchNdsPattern()`, standard `boundedTextResult()`/`ndsErrorResult()` helpers.
- Produces: public MCP tool `nds_search_pattern` with exactly the approved fields/defaults.

- [ ] **Step 1: Extend tool-registration tests first**

Update `EXPECTED_TOOLS` in `tests/nds-tools.test.ts` to include:

```ts
"nds_search_pattern",
```

and rename the registration test to exactly twelve tools.

Add schema tests:

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

Prove schema maxes reject `limit: 1001`, `offset: 100000`, `maxScanBytes: 512*1024*1024 + 1`, and `contextBytes: 65`.

Prove nested integer alignment accepts only `1 | 2 | 4`.

For forbidden generic surface, assert the top-level schema has no:

```ts
for (const forbidden of [
  "binary", "bytes", "baseAddress", "runtimeAddress",
  "start", "end", "length", "output", "path",
]) {
  assert.equal(Object.hasOwn(server.schema("nds_search_pattern"), forbidden), false);
}
```

- [ ] **Step 2: Add handler RED tests**

Use a fixture with `AA AA AA` in ARM9 main. Invoke:

```ts
const body = resultBody(await server.invoke("nds_search_pattern", {
  rom,
  pattern: { kind: "byte-signature", signature: "AA AA" },
  scope: { kind: "components", arm9Main: true },
  limit: 10,
}));
assert.equal(body.status, "complete");
assert.deepEqual(
  (body.matches as Array<Record<string, unknown>>).map((hit) => hit.romOffset),
  [0x200, 0x201],
);
```

Add tool error tests for malformed pattern and empty scope, asserting `isError === true`, categories `invalid-pattern` / `invalid-pattern-scope`, and non-empty corrective actions.

Add a tiny `maxOutputBytes` test with context/many hits and assert existing `output-bound-exceeded` behavior.

- [ ] **Step 3: Prove RED**

```bash
node --test --import tsx tests/nds-tools.test.ts
```

Expected: FAIL because the twelfth tool/schema/handlers do not exist.

- [ ] **Step 4: Add bounded Zod schemas**

In `src/tools/nds.ts`, define nested discriminated unions:

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

Service-level validation still enforces combined selector totals and non-empty components.

Add scalar schemas with exact defaults/maxes.

- [ ] **Step 5: Register the handler and corrective actions**

Import `searchNdsPattern`. Register:

```ts
server.tool(
  "nds_search_pattern",
  "Search one bounded exact/wildcard byte signature, typed integer, ASCII string, or UTF-16LE string in a validated Nintendo DS ROM without mutation or heuristic inference.",
  { rom, pattern, scope, offset, limit, maxScanBytes, contextBytes },
  async (...) => { ... },
);
```

Handler flow:

```ts
const map = await readNdsRomMap(resolveRom(config, rom));
const result = await searchNdsPattern(map, pattern, scope, {
  offset, limit, maxScanBytes, contextBytes,
});
return boundedTextResult(config, operation, {
  rom: relativeWorkspacePath(config, map.romPath),
  sha256: map.sha256,
  ...result,
});
```

Extend `correctiveAction()` with the three exact new categories. Use `invalid-rom` as the fallback category only for unexpected non-`NdsError` failures in this handler.

- [ ] **Step 6: Update server capabilities**

In `src/index.ts`, insert `nds_search_pattern` after the existing NDS reference/xref tools. Update `ndsStaticAnalysisPolicy` to state that bounded deterministic raw pattern search is allowed only over validated NDS canonical components or explicit whole-ROM scope, while **generic binary** pattern search remains prohibited.

Do not change debugger/runtime policies.

- [ ] **Step 7: Verify GREEN**

```bash
node --test --import tsx tests/nds-tools.test.ts
npm run typecheck
```

Expected: PASS with exactly twelve NDS tool registrations.

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

**Interfaces:**
- Consumes: compiled `dist/services/nds/rom-map.js`, `dist/services/nds/pattern-search.js`; existing package verifier.
- Produces: assembled-bundle smoke proof of compiler + real file search + overlapping hits + canonical ownership.

- [ ] **Step 1: Extend package-verifier source tests first**

Add a test requiring:

```ts
for (const required of [
  "dist/services/nds/pattern-search.js",
  "dist/services/nds/rom-map.js",
  "Packaged NDS pattern overlap smoke failed",
  "Packaged NDS pattern ownership smoke failed",
]) {
  assert.equal(source.includes(required), true, required);
}
```

Keep all existing Capstone/WASM/reference smoke assertions unchanged.

- [ ] **Step 2: Prove RED**

```bash
node --test --import tsx tests/package-capstone-install.test.ts
```

Expected: FAIL because packaged pattern-search assets/smoke messages are not required yet.

- [ ] **Step 3: Require the compiled pattern-search asset**

In `scripts/check-install.mjs`, add:

```js
"dist/services/nds/pattern-search.js",
"dist/services/nds/rom-map.js",
```

to `required` and dynamically import `searchNdsPattern` / `readNdsRomMap` from those compiled paths.

- [ ] **Step 4: Create a tiny valid NDS fixture inside the assembled verifier**

Use only Node built-ins (`mkdtemp`, `writeFile`, `rm`, `os.tmpdir`, `path.join`). Allocate `Buffer.alloc(0x1000)` and write the minimum canonical header fields:

```js
fixture.writeUInt32LE(0x200, 0x20);      // ARM9 ROM
fixture.writeUInt32LE(0x02000000, 0x24); // ARM9 entry
fixture.writeUInt32LE(0x02000000, 0x28); // ARM9 RAM
fixture.writeUInt32LE(0x20, 0x2c);       // ARM9 size
fixture.writeUInt32LE(0x300, 0x30);      // ARM7 ROM
fixture.writeUInt32LE(0x03800000, 0x34); // ARM7 entry
fixture.writeUInt32LE(0x03800000, 0x38); // ARM7 RAM
fixture.writeUInt32LE(0x20, 0x3c);       // ARM7 size
fixture.writeUInt32LE(0x400, 0x40);      // FNT offset, size remains 0
fixture.writeUInt32LE(0x500, 0x48);      // FAT offset, size remains 0
fixture.writeUInt32LE(0x600, 0x50);      // ARM9 overlay table, size 0
fixture.writeUInt32LE(0x700, 0x58);      // ARM7 overlay table, size 0
fixture.writeUInt32LE(0x800, 0x68);      // banner offset only
fixture.set([0xaa, 0xaa, 0xaa], 0x200);
```

Write it to a temporary `.nds`, parse it with packaged `readNdsRomMap`, and remove the temporary directory in `finally`.

- [ ] **Step 5: Smoke-search the compiled service**

Call:

```js
const patternResult = await searchNdsPattern(
  patternMap,
  { kind: "byte-signature", signature: "AA ??" },
  { kind: "components", arm9Main: true },
  { offset: 0, limit: 10, maxScanBytes: 0x20, contextBytes: 0 },
);
```

Require exact overlapping starts `[0x200, 0x201]`; otherwise throw `Packaged NDS pattern overlap smoke failed`.

Require the first hit has an owner with `kind === "arm9-main"` and `runtimeAddress === 0x02000000`; otherwise throw `Packaged NDS pattern ownership smoke failed`.

This smoke must use assembled `dist` files only, never `src/` or test fixtures.

- [ ] **Step 6: Verify GREEN locally/source-side**

```bash
npm run build
node --test --import tsx tests/package-capstone-install.test.ts
node scripts/check-install.mjs .
```

Expected: PASS with existing Capstone/reference smoke behavior plus the new pattern-search smoke.

- [ ] **Step 7: Commit**

```bash
git add scripts/check-install.mjs tests/package-capstone-install.test.ts
git commit -m "test: smoke packaged NDS pattern search"
```

---

### Task 8: User-facing documentation and security contract

**Files:**
- Modify: `README.md`
- Test: source/document checks via `grep` plus full verification.

**Interfaces:**
- Consumes: final public tool/schema/result semantics from Tasks 1-7.
- Produces: documented twelfth NDS static tool and exact behavior/limits.

- [ ] **Step 1: Update the NDS tool list and capability narrative**

Document `nds_search_pattern` alongside the existing eleven NDS tools. State explicitly that it is NDS-aware and read-only, not a generic binary scanner.

- [ ] **Step 2: Document exact pattern syntax**

Include examples:

```text
12 34 56 78
12 34 ?? 78
```

and typed integer/ASCII/UTF-16LE request examples. State no nibble wildcards, regex, case folding, normalization, alternate encodings, or implicit terminators.

- [ ] **Step 3: Document scope and boundary semantics**

Explain canonical component combinations, explicit `whole-rom`, compressed-overlay stored-byte behavior, deduplication of overlapping physical selections, and the rule that component matches require full containment by at least one selected component.

- [ ] **Step 4: Document results, ownership, context, pagination, and limits**

Include exact defaults/maxes, both truncation reasons, `offset` as match index, non-resumable scan-byte truncation, `discoveredMatches` established-only meaning, `nextOffset` meaning, full-span runtime mapping rule, context clipping, and the fact that banner ownership is not inferred from offset alone.

- [ ] **Step 5: Verify documentation contains the required contract**

```bash
grep -n "nds_search_pattern" README.md
grep -n "scan-byte-limit" README.md
grep -n "match-count-limit" README.md
grep -n "4096" README.md
grep -n "512 MiB" README.md
grep -n "generic binary" README.md
npm run check
```

Expected: every grep finds the documented contract and `npm run check` passes.

- [ ] **Step 6: Commit**

```bash
git add README.md
git commit -m "docs: document NDS pattern discovery"
```

---

### Task 9: Final regression, package, and scope audit

**Files:**
- No planned production changes. Fix only defects proven by the final verification; any fix must receive its own RED test and commit.

**Interfaces:**
- Consumes: complete milestone.
- Produces: verified branch ready for code review/PR with no unsupported platform claim.

- [ ] **Step 1: Run focused milestone tests**

```bash
node --test --import tsx \
  tests/nds-patterns.test.ts \
  tests/nds-pattern-scope.test.ts \
  tests/nds-pattern-ownership.test.ts \
  tests/nds-pattern-match.test.ts \
  tests/nds-pattern-search.test.ts \
  tests/nds-tools.test.ts \
  tests/package-capstone-install.test.ts
```

Expected: PASS.

- [ ] **Step 2: Run complete repository verification**

```bash
npm run typecheck
npm test
npm run build
npm run check
node scripts/check-install.mjs .
```

Expected: every command exits 0.

- [ ] **Step 3: Audit dependency and forbidden-surface stability**

```bash
git diff -- package.json package-lock.json
git diff --name-only e3769d2756364dd2f2546536b3015e86c7b73473...HEAD
```

Expected:

- dependency diff is empty;
- changed production files are confined to NDS pattern services, `errors.ts`, exported header constant, NDS tool/capability wiring, package smoke, README/docs/tests;
- no DeSmuME GDB/controller/runtime implementation file changed;
- no Capstone/disassembly/CFG/reference/xref production file changed.

- [ ] **Step 4: Inspect public tool surface mechanically**

```bash
grep -n '"nds_' src/index.ts
grep -n 'server.tool(' src/tools/nds.ts
```

Expected: `nds_search_pattern` is present exactly once in capabilities and exactly once as a registration, and the NDS tool test proves exactly twelve registrations.

- [ ] **Step 5: Run GitHub Actions verification on the final branch head**

Push the final branch/PR head and require both repository workflows used by prior milestones:

- CI: success;
- Package: success, including `Assemble and smoke-test self-contained bundle`.

Do not claim post-merge `main` verification unless a separate run is actually visible after merge.

- [ ] **Step 6: Review only the milestone diff**

Request code review against baseline `e3769d2756364dd2f2546536b3015e86c7b73473`. Any accepted defect fix must add/adjust a failing regression test first, then rerun Steps 1-5.

- [ ] **Step 7: Prepare merge summary**

The final summary must state:

- `nds_search_pattern` is the twelfth NDS static-analysis tool;
- supported pattern kinds and exact limits;
- component/whole-ROM boundary semantics;
- compressed overlays are searched only as stored bytes;
- pattern hits do not imply pointers/references/functions/tables;
- all final CI/package evidence by run number/status;
- physical Intel Catalina/DeSmuME acceptance remains separate.

---

## Execution Notes

- Use TDD for every implementation task: RED test → minimal GREEN implementation → focused verification → commit.
- Use frequent task-sized commits; do not collapse all milestone work into one commit.
- Because repository execution/verification may be mediated through GitHub Actions, refresh the branch head before every write if a message stream interruption occurs. Never replay a stale write over a delayed landed commit.
- If a GitHub contents write returns a stale-SHA/409 conflict, refetch the branch/file and reconcile the already-landed content before retrying.
- Do not broaden scope to regex, multi-pattern databases, decompression, arbitrary ranges, generic binaries, or runtime search when implementing convenience behavior.
- Native Intel Catalina/DeSmuME acceptance is not part of this implementation plan and is not a blocker for this static-analysis milestone.
