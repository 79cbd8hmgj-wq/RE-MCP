# NDS Static Analysis Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a canonical, safe, native-independent Nintendo DS ROM model with structure inspection, address resolution, and controlled extraction while leaving Dynamic Debugging Patch 1 behavior unchanged pending Catalina acceptance.

**Architecture:** Parse each ROM into a canonical `NdsRomMap` built from strict header, FAT, FNT, and overlay services. Resolution and extraction consume only that validated model; MCP tools expose seven bounded operations and write derived artifacts only to the fixed workspace-level `analysis/generated/nds/<sha-prefix>/` tree. Existing `readArm9ExecutableRange()` becomes a compatibility adapter over the canonical parser.

**Tech Stack:** TypeScript 5.7, Node.js 20+, Node built-ins (`Buffer`, `node:fs/promises`, `node:fs`, `node:crypto`, `node:path`, `node:stream/promises`), MCP SDK, Zod, Node test runner via `node:test`/`tsx`. No new runtime dependency.

## Global Constraints

- Source `.nds` files are immutable.
- No arbitrary output path, raw offset/length extraction primitive, ROM rebuild, or ROM mutation.
- Generated artifacts live only under `RE_MCP_WORKSPACE_ROOT/analysis/generated/nds/<first-16-sha256-hex>/`.
- Full SHA-256 remains canonical; 16 hex characters are only a directory-name prefix.
- All file inputs resolve through `resolveInside(config.workspaceRoot, ...)`.
- All response serialization respects `config.maxOutputBytes`.
- FAT is authoritative for physical file ranges; FNT is authoritative for NitroFS names/hierarchy.
- Overlay tables are processor-specific, 32 bytes per record, with `compressedSize = packed & 0x00ffffff`, `flags = packed >>> 24`, and compression flag bit 0.
- Never fabricate ROM byte offsets for compressed runtime overlay bytes or BSS.
- Never fabricate runtime addresses for compressed overlay backing-file byte positions.
- Never choose among overlapping overlay candidates heuristically.
- `readArm9ExecutableRange()` result shape and debugger-facing validation remain compatible.
- Do not change breakpoint, continue, step, pause, GDB, stop-context, or process-lifecycle behavior.
- No new runtime dependency.
- TypeScript stays compatible with `strict`, `noUncheckedIndexedAccess`, and `exactOptionalPropertyTypes`.
- TDD: red test first, minimal green implementation, targeted verification, then commit.

## Branch / PR Sequence

Implement as three reviewable PRs rather than one oversized change:

1. **PR A — `feature/nds-static-structure`**: Tasks 1–5. Canonical parser and ROM map only.
2. **PR B — `feature/nds-address-extraction`**: Tasks 6–7. Resolver and controlled extraction, based on merged PR A.
3. **PR C — `feature/nds-static-mcp-tools`**: Tasks 8–10. Compatibility migration, MCP surface, docs/final regression, based on merged PR B.

At execution time, create an isolated worktree/branch using `superpowers:using-git-worktrees` when local git is available. If the execution environment cannot clone the repository, use isolated GitHub feature branches and GitHub Actions exactly as the previous Dynamic Debugging work did.

---

## File Structure

### New production files

- `src/services/nds/errors.ts` — stable NDS error categories and `NdsError`.
- `src/services/nds/io.ts` — bounded exact reads, regular-file validation, streaming SHA-256.
- `src/services/nds/header.ts` — strict NDS header parsing and ARM9/ARM7 metadata.
- `src/services/nds/fat.ts` — FAT record parsing and range validation.
- `src/services/nds/fnt.ts` — FNT directory-table/subtable traversal and file-path mapping.
- `src/services/nds/overlays.ts` — ARM9/ARM7 overlay-record parsing and FAT joins.
- `src/services/nds/rom-map.ts` — canonical `NdsRomMap` composition and executable/static ranges.
- `src/services/nds/resolver.ts` — runtime-address and ROM-offset resolution.
- `src/services/nds/extraction.ts` — deterministic generated paths, atomic range extraction, manifests/bundles.
- `src/tools/nds.ts` — seven MCP NDS tools, schemas, pagination, output-bound enforcement.

### Existing production files modified

- `src/services/nds-arm9.ts` — compatibility adapter over canonical map.
- `src/index.ts` — `registerNdsTools()` and capability list.
- `README.md` — static NDS tool documentation and safety boundary.

### New test files

- `tests/helpers/nds-fixture.ts` — deterministic synthetic NDS fixture builder.
- `tests/nds-header.test.ts`
- `tests/nds-fat.test.ts`
- `tests/nds-fnt.test.ts`
- `tests/nds-overlays.test.ts`
- `tests/nds-rom-map.test.ts`
- `tests/nds-resolver.test.ts`
- `tests/nds-extraction.test.ts`
- `tests/nds-tools.test.ts`

### Existing tests retained / extended

- `tests/nds-arm9.test.ts` — compatibility regression.
- Existing DeSmuME/debugger tests — must remain unchanged and green unless a fixture import path must be updated mechanically.

---

### Task 1: Build the test fixture, I/O primitives, ROM identity, and full header parser

**Files:**
- Create: `tests/helpers/nds-fixture.ts`
- Create: `src/services/nds/errors.ts`
- Create: `src/services/nds/io.ts`
- Create: `src/services/nds/header.ts`
- Create: `tests/nds-header.test.ts`

**Interfaces:**
- Produces: `NdsError`, `NdsErrorCategory`, `hashFileSha256(path)`, `readExact(handle, offset, length, label)`, `parseNdsHeader(romPath)`.
- Produces header types used by Tasks 2–10.

Define the shared error model:

```ts
export type NdsErrorCategory =
  | "invalid-rom"
  | "malformed-header"
  | "range-out-of-bounds"
  | "malformed-fat"
  | "malformed-fnt"
  | "malformed-overlay-table"
  | "unknown-file-id"
  | "unknown-overlay-id"
  | "output-bound-exceeded"
  | "generated-path-failure";

export class NdsError extends Error {
  constructor(
    readonly category: NdsErrorCategory,
    message: string,
  ) {
    super(message);
    this.name = "NdsError";
  }
}
```

Define header-facing types with explicit required properties so `exactOptionalPropertyTypes` does not leak `undefined` values:

```ts
export interface NdsExecutableHeader {
  readonly romOffset: number;
  readonly entryAddress: number;
  readonly ramAddress: number;
  readonly size: number;
  readonly romEnd: number;
  readonly ramEnd: number;
}

export interface NdsRegionHeader {
  readonly offset: number;
  readonly size: number;
  readonly end: number;
}

export interface NdsHeader {
  readonly gameTitle: string;
  readonly gameCode: string;
  readonly makerCode: string;
  readonly unitCode: number;
  readonly deviceCapacity: number;
  readonly romVersion: number;
  readonly bannerOffset: number;
  readonly arm9: NdsExecutableHeader;
  readonly arm7: NdsExecutableHeader;
  readonly fnt: NdsRegionHeader;
  readonly fat: NdsRegionHeader;
  readonly arm9OverlayTable: NdsRegionHeader;
  readonly arm7OverlayTable: NdsRegionHeader;
}

export interface ParsedNdsHeader {
  readonly romPath: string;
  readonly fileSize: number;
  readonly sha256: string;
  readonly sha256Prefix: string;
  readonly header: NdsHeader;
}
```

Use these NDS header offsets:

```ts
const HEADER_BYTES = 0x6c;
const OFFSETS = {
  title: 0x00,
  gameCode: 0x0c,
  makerCode: 0x10,
  unitCode: 0x12,
  deviceCapacity: 0x14,
  romVersion: 0x1e,
  arm9Rom: 0x20,
  arm9Entry: 0x24,
  arm9Ram: 0x28,
  arm9Size: 0x2c,
  arm7Rom: 0x30,
  arm7Entry: 0x34,
  arm7Ram: 0x38,
  arm7Size: 0x3c,
  fntOffset: 0x40,
  fntSize: 0x44,
  fatOffset: 0x48,
  fatSize: 0x4c,
  arm9OverlayOffset: 0x50,
  arm9OverlaySize: 0x54,
  arm7OverlayOffset: 0x58,
  arm7OverlaySize: 0x5c,
  bannerOffset: 0x68,
} as const;
```

- [ ] **Step 1: Add a deterministic synthetic NDS fixture builder**

Create `tests/helpers/nds-fixture.ts` with a builder that allocates a configurable ROM buffer, writes the header fields above, and exposes helpers to write arbitrary regions later without duplicating numeric offsets in every test.

Core API:

```ts
export interface NdsFixtureOptions {
  readonly fileSize?: number;
  readonly arm9RomOffset?: number;
  readonly arm9RamAddress?: number;
  readonly arm9EntryAddress?: number;
  readonly arm9Size?: number;
  readonly arm7RomOffset?: number;
  readonly arm7RamAddress?: number;
  readonly arm7EntryAddress?: number;
  readonly arm7Size?: number;
  readonly fntOffset?: number;
  readonly fntSize?: number;
  readonly fatOffset?: number;
  readonly fatSize?: number;
  readonly arm9OverlayOffset?: number;
  readonly arm9OverlaySize?: number;
  readonly arm7OverlayOffset?: number;
  readonly arm7OverlaySize?: number;
}

export interface NdsFixture {
  readonly directory: string;
  readonly romPath: string;
  readonly buffer: Buffer;
  write(): Promise<void>;
}

export async function createNdsFixture(
  options: NdsFixtureOptions = {},
): Promise<NdsFixture>;
```

Use safe defaults with non-overlapping regions, for example ARM9 at `0x200`, ARM7 at `0x600`, FNT `0x800`, FAT `0x900`, overlay tables at `0xa00`/`0xb00`, and a default ROM size large enough to hold them.

- [ ] **Step 2: Write failing header/identity tests**

Add tests similar to:

```ts
test("parses full NDS identity and executable metadata", async () => {
  const fixture = await createNdsFixture();
  const parsed = await parseNdsHeader(fixture.romPath);

  assert.equal(parsed.fileSize, fixture.buffer.length);
  assert.match(parsed.sha256, /^[a-f0-9]{64}$/);
  assert.equal(parsed.sha256Prefix, parsed.sha256.slice(0, 16));
  assert.equal(parsed.header.arm9.romOffset, 0x200);
  assert.equal(parsed.header.arm7.romOffset, 0x600);
});

test("rejects a referenced region beyond EOF", async () => {
  const fixture = await createNdsFixture({ arm9RomOffset: 0x1f00, arm9Size: 0x400 });
  await assert.rejects(
    parseNdsHeader(fixture.romPath),
    (error: unknown) => error instanceof NdsError && error.category === "range-out-of-bounds",
  );
});
```

Also cover: short header, directory instead of regular file, zero ARM9/ARM7 size, 32-bit RAM-range overflow, FNT/FAT/table range overflow, and stable full SHA-256.

- [ ] **Step 3: Run the header test and verify RED**

Run:

```bash
npm test -- tests/nds-header.test.ts
```

Expected: FAIL because `src/services/nds/header.ts` and exported interfaces do not exist yet.

- [ ] **Step 4: Implement minimal I/O and header parsing**

In `io.ts`, hash without loading an entire ROM into memory:

```ts
export async function hashFileSha256(filePath: string): Promise<string> {
  const hash = createHash("sha256");
  const stream = createReadStream(filePath);
  for await (const chunk of stream) hash.update(chunk);
  return hash.digest("hex");
}
```

Implement `readExact()` with `FileHandle.read()` and reject short reads with `NdsError("range-out-of-bounds", ...)`.

In `header.ts`, `stat()` the file, read exactly `0x6c`, decode fixed ASCII fields by trimming trailing NULs, decode `u32le` numeric fields, and validate each region with one helper:

```ts
function checkedRegion(
  offset: number,
  size: number,
  fileSize: number,
  label: string,
  allowEmpty: boolean,
): NdsRegionHeader {
  if ((!allowEmpty && size === 0) || offset > fileSize) {
    throw new NdsError("malformed-header", `${label} has an invalid offset/size`);
  }
  const end = offset + size;
  if (!Number.isSafeInteger(end) || end < offset || end > fileSize) {
    throw new NdsError("range-out-of-bounds", `${label} extends beyond the ROM file`);
  }
  return { offset, size, end };
}
```

For zero-size FNT/FAT/overlay tables, accept `{ offset: 0, size: 0, end: 0 }`; do not attempt to read them later.

- [ ] **Step 5: Run targeted tests and typecheck**

```bash
npm test -- tests/nds-header.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 6: Commit Task 1**

```bash
git add src/services/nds/errors.ts src/services/nds/io.ts src/services/nds/header.ts tests/helpers/nds-fixture.ts tests/nds-header.test.ts
git commit -m "feat: add canonical NDS header parser"
```

---

### Task 2: Parse and validate FAT physical file ranges

**Files:**
- Create: `src/services/nds/fat.ts`
- Create: `tests/nds-fat.test.ts`
- Modify: `tests/helpers/nds-fixture.ts`

**Interfaces:**
- Consumes: `ParsedNdsHeader`, `readExact()`, `NdsError`.
- Produces: `NdsFatEntry`, `parseNdsFat(parsedHeader)`.

```ts
export interface NdsFatEntry {
  readonly fileId: number;
  readonly startOffset: number;
  readonly endOffset: number;
  readonly size: number;
}

export async function parseNdsFat(
  parsed: ParsedNdsHeader,
): Promise<readonly NdsFatEntry[]>;
```

- [ ] **Step 1: Extend the fixture builder with FAT helpers**

Add:

```ts
export function writeFatEntry(
  buffer: Buffer,
  fatOffset: number,
  fileId: number,
  startOffset: number,
  endOffset: number,
): void {
  const base = fatOffset + fileId * 8;
  buffer.writeUInt32LE(startOffset, base);
  buffer.writeUInt32LE(endOffset, base + 4);
}
```

- [ ] **Step 2: Write failing FAT tests**

Cover valid entries, non-multiple-of-8 FAT size, `start > end`, end past EOF, and zero-length records:

```ts
test("parses FAT entries by file ID", async () => {
  const fixture = await createNdsFixture({ fatSize: 16 });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1000, 0x1020);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1100, 0x1100);
  await fixture.write();

  const parsed = await parseNdsHeader(fixture.romPath);
  assert.deepEqual(await parseNdsFat(parsed), [
    { fileId: 0, startOffset: 0x1000, endOffset: 0x1020, size: 0x20 },
    { fileId: 1, startOffset: 0x1100, endOffset: 0x1100, size: 0 },
  ]);
});
```

- [ ] **Step 3: Verify RED**

```bash
npm test -- tests/nds-fat.test.ts
```

Expected: FAIL because `parseNdsFat` does not exist.

- [ ] **Step 4: Implement FAT parsing**

Rules:

```ts
if (header.fat.size === 0) return [];
if (header.fat.size % 8 !== 0) {
  throw new NdsError("malformed-fat", "NDS FAT size must be divisible by 8");
}
```

Read exactly the FAT region, iterate `fileId = 0..count-1`, validate `start <= end <= fileSize`, and return frozen/plain records.

- [ ] **Step 5: Verify GREEN and regression**

```bash
npm test -- tests/nds-fat.test.ts tests/nds-header.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 6: Commit Task 2**

```bash
git add src/services/nds/fat.ts tests/helpers/nds-fixture.ts tests/nds-fat.test.ts
git commit -m "feat: parse NDS FAT ranges"
```

---

### Task 3: Reconstruct FNT/NitroFS hierarchy safely

**Files:**
- Create: `src/services/nds/fnt.ts`
- Create: `tests/nds-fnt.test.ts`
- Modify: `tests/helpers/nds-fixture.ts`

**Interfaces:**
- Consumes: `ParsedNdsHeader`, `NdsFatEntry[]`, `readExact()`, `NdsError`.
- Produces: `NdsDirectory`, `NdsNitroFile`, `NdsFilesystem`, `parseNdsFnt(parsed, fat)`.

```ts
export interface NdsDirectory {
  readonly directoryId: number;
  readonly parentDirectoryId: number | null;
  readonly path: string;
  readonly firstFileId: number;
}

export interface NdsNitroFile extends NdsFatEntry {
  readonly path: string | null;
}

export interface NdsFilesystem {
  readonly directories: readonly NdsDirectory[];
  readonly files: readonly NdsNitroFile[];
}
```

Use DS FNT rules explicitly:

- directory IDs start at `0xF000`;
- main-table entry index is `directoryId & 0x0fff`;
- each main-table record is 8 bytes: subtable offset `u32le`, first file ID `u16le`, parent/root metadata `u16le`;
- root record's final `u16` is directory count;
- each subtable entry starts with one byte; `0` terminates;
- low 7 bits are name length; high bit means directory;
- directory entries append a `u16le` child directory ID after name bytes;
- file entries consume the next implicit file ID.

- [ ] **Step 1: Add fixture helpers for valid root/nested FNTs**

Provide test helpers that write a root main-table entry and encoded file/directory subtable entries rather than hand-assembling bytes in each test.

- [ ] **Step 2: Write failing traversal tests**

Include:

```ts
test("reconstructs nested NitroFS paths and retains unnamed FAT entries", async () => {
  // Fixture maps file 0 -> root.bin and file 1 -> data/nested.bin;
  // file 2 exists in FAT but has no FNT name.
  const filesystem = await parseNdsFnt(parsed, fat);
  assert.equal(filesystem.files[0]?.path, "root.bin");
  assert.equal(filesystem.files[1]?.path, "data/nested.bin");
  assert.equal(filesystem.files[2]?.path, null);
});
```

Also test invalid child directory ID, cycle, main-table/subtable offset outside FNT, file ID beyond FAT, unterminated subtable, and unusual non-NUL filename bytes.

- [ ] **Step 3: Verify RED**

```bash
npm test -- tests/nds-fnt.test.ts
```

Expected: FAIL because FNT parser is missing.

- [ ] **Step 4: Implement bounded FNT traversal**

Read the FNT region once. Parse root directory count before traversal. Validate every main-table index and subtable cursor before reading.

Use a DFS helper with both `visiting` and `visited` sets:

```ts
function visitDirectory(directoryId: number, parentPath: string): void {
  if (visiting.has(directoryId)) {
    throw new NdsError("malformed-fnt", `FNT directory cycle at 0x${directoryId.toString(16)}`);
  }
  if (visited.has(directoryId)) return;
  visiting.add(directoryId);
  // Decode this directory's subtable with explicit bounds checks.
  visiting.delete(directoryId);
  visited.add(directoryId);
}
```

Decode names as Latin-1 for one-byte display preservation; never use decoded names to calculate file IDs. Reject `/`, `\\`, NUL, `.` and `..` as path-segment values so generated resolved paths cannot become traversal primitives.

After traversal, map every FAT entry to `{ ...entry, path: resolvedName ?? null }`.

- [ ] **Step 5: Verify GREEN and typecheck**

```bash
npm test -- tests/nds-fnt.test.ts tests/nds-fat.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 6: Commit Task 3**

```bash
git add src/services/nds/fnt.ts tests/helpers/nds-fixture.ts tests/nds-fnt.test.ts
git commit -m "feat: reconstruct NDS NitroFS paths"
```

---

### Task 4: Parse ARM9/ARM7 overlay tables with compression-safe metadata

**Files:**
- Create: `src/services/nds/overlays.ts`
- Create: `tests/nds-overlays.test.ts`
- Modify: `tests/helpers/nds-fixture.ts`

**Interfaces:**
- Consumes: `ParsedNdsHeader`, FAT/filesystem entries, `readExact()`, `NdsError`.
- Produces: `NdsOverlay`, `parseNdsOverlays(parsed, fat, processor)`.

```ts
export type NdsProcessor = "arm9" | "arm7";

export interface NdsOverlay {
  readonly processor: NdsProcessor;
  readonly overlayId: number;
  readonly ramAddress: number;
  readonly ramSize: number;
  readonly ramEnd: number;
  readonly bssSize: number;
  readonly bssEnd: number;
  readonly staticInitStart: number;
  readonly staticInitEnd: number;
  readonly fileId: number;
  readonly romOffset: number;
  readonly romSize: number;
  readonly compressedSize: number;
  readonly flags: number;
  readonly compressed: boolean;
}
```

- [ ] **Step 1: Add a 32-byte overlay fixture writer**

```ts
export function writeOverlayRecord(
  buffer: Buffer,
  tableOffset: number,
  index: number,
  values: {
    overlayId: number;
    ramAddress: number;
    ramSize: number;
    bssSize: number;
    staticInitStart: number;
    staticInitEnd: number;
    fileId: number;
    compressedSize: number;
    flags: number;
  },
): void {
  const base = tableOffset + index * 32;
  // write seven scalar u32 values, then:
  buffer.writeUInt32LE((values.compressedSize & 0x00ffffff) | ((values.flags & 0xff) << 24), base + 0x1c);
}
```

- [ ] **Step 2: Write failing overlay tests**

Cover ARM9 and ARM7 independently, table size not divisible by 32, invalid `fileId`, 32-bit overflow for `ramAddress + ramSize + bssSize`, compression bit decode, packed size decode, static-init range ordering, overlapping records being accepted as candidates, and physical size differing from runtime size.

Representative assertion:

```ts
assert.deepEqual(overlays[0], {
  processor: "arm9",
  overlayId: 37,
  ramAddress: 0x02210000,
  ramSize: 0x2000,
  ramEnd: 0x02212000,
  bssSize: 0x200,
  bssEnd: 0x02212200,
  staticInitStart: 0x02211f00,
  staticInitEnd: 0x02211f20,
  fileId: 3,
  romOffset: 0x1400,
  romSize: 0x1000,
  compressedSize: 0x0f00,
  flags: 1,
  compressed: true,
});
```

- [ ] **Step 3: Verify RED**

```bash
npm test -- tests/nds-overlays.test.ts
```

- [ ] **Step 4: Implement overlay parsing**

For zero-size table return `[]`. Otherwise require `size % 32 === 0`. Decode the final packed field exactly as specified. Resolve `fileId` through FAT; missing IDs throw `NdsError("malformed-overlay-table", ...)`.

Validate runtime additions with a helper:

```ts
function checkedAddressEnd(start: number, size: number, label: string): number {
  const end = start + size;
  if (!Number.isSafeInteger(end) || end > 0x1_0000_0000 || end < start) {
    throw new NdsError("malformed-overlay-table", `${label} overflows 32-bit address space`);
  }
  return end;
}
```

Allow `staticInitStart === staticInitEnd === 0`; otherwise require `start <= end` and both to lie inside the initialized `[ramAddress, ramEnd]` range.

Do not reject an overlay merely because `romSize !== ramSize` or because it overlaps another overlay.

- [ ] **Step 5: Verify GREEN**

```bash
npm test -- tests/nds-overlays.test.ts tests/nds-fat.test.ts
npm run typecheck
```

- [ ] **Step 6: Commit Task 4**

```bash
git add src/services/nds/overlays.ts tests/helpers/nds-fixture.ts tests/nds-overlays.test.ts
git commit -m "feat: parse NDS overlay tables"
```

---

### Task 5: Compose the canonical `NdsRomMap`

**Files:**
- Create: `src/services/nds/rom-map.ts`
- Create: `tests/nds-rom-map.test.ts`

**Interfaces:**
- Consumes: Tasks 1–4 parsers.
- Produces: `NdsRomMap`, `readNdsRomMap(romPath)`.

```ts
export interface NdsExecutableRange {
  readonly kind: "arm9-main" | "arm7-main" | "arm9-overlay" | "arm7-overlay";
  readonly processor: NdsProcessor;
  readonly start: number;
  readonly end: number;
  readonly initializedEnd: number;
  readonly sourceId: string;
  readonly overlayId: number | null;
  readonly compressed: boolean;
}

export interface NdsRomMap {
  readonly romPath: string;
  readonly fileSize: number;
  readonly sha256: string;
  readonly sha256Prefix: string;
  readonly header: NdsHeader;
  readonly fat: readonly NdsFatEntry[];
  readonly filesystem: NdsFilesystem;
  readonly overlays: Readonly<{
    arm9: readonly NdsOverlay[];
    arm7: readonly NdsOverlay[];
  }>;
  readonly executableRanges: readonly NdsExecutableRange[];
}

export async function readNdsRomMap(romPath: string): Promise<NdsRomMap>;
```

- [ ] **Step 1: Write failing composition tests**

Verify one parse returns the same SHA/header identity plus FAT/FNT/overlay joins. Verify executable ranges contain main ARM9/ARM7 and overlay initialized+BSS boundaries without claiming loaded state.

Use `overlayId: null` on main ranges to avoid optional-property ambiguity under `exactOptionalPropertyTypes`.

- [ ] **Step 2: Verify RED**

```bash
npm test -- tests/nds-rom-map.test.ts
```

- [ ] **Step 3: Implement `readNdsRomMap()`**

Sequence:

```ts
const parsed = await parseNdsHeader(romPath);
const fat = await parseNdsFat(parsed);
const filesystem = await parseNdsFnt(parsed, fat);
const arm9Overlays = await parseNdsOverlays(parsed, fat, "arm9");
const arm7Overlays = await parseNdsOverlays(parsed, fat, "arm7");
```

Build main ranges from header metadata and overlay ranges from validated overlay records. Do not infer loaded state or execution mode.

- [ ] **Step 4: Run all PR-A tests**

```bash
npm test -- tests/nds-header.test.ts tests/nds-fat.test.ts tests/nds-fnt.test.ts tests/nds-overlays.test.ts tests/nds-rom-map.test.ts
npm run typecheck
npm run build
```

Expected: PASS.

- [ ] **Step 5: Commit Task 5**

```bash
git add src/services/nds/rom-map.ts tests/nds-rom-map.test.ts
git commit -m "feat: compose canonical NDS ROM map"
```

- [ ] **Step 6: PR-A verification gate**

Run full repository verification:

```bash
npm run check
npm run build
```

Open PR **`Add canonical NDS static structure parser`** from `feature/nds-static-structure` to `main`. Require CI and Package success before integration.

---

### Task 6: Add runtime-address and ROM-offset resolvers

**Files:**
- Create: `src/services/nds/resolver.ts`
- Create: `tests/nds-resolver.test.ts`

**Interfaces:**
- Consumes: `NdsRomMap`, `NdsProcessor`.
- Produces: `resolveRuntimeAddress(map, address, processor)` and `resolveRomOffset(map, offset)`.

Define discriminated resolution types so normal ambiguity/BSS/compression outcomes are not exceptions:

```ts
export type RuntimeResolution =
  | { readonly status: "unmapped"; readonly address: number; readonly processor: NdsProcessor }
  | { readonly status: "resolved"; readonly candidate: RuntimeCandidate }
  | { readonly status: "ambiguous-runtime-address"; readonly candidates: readonly RuntimeCandidate[] }
  | { readonly status: "runtime-only-bss"; readonly candidate: RuntimeCandidate }
  | { readonly status: "compressed-no-direct-rom-mapping"; readonly candidate: RuntimeCandidate };

export interface RuntimeCandidate {
  readonly kind: "arm9-main" | "arm7-main" | "arm9-overlay" | "arm7-overlay" | "overlay-bss";
  readonly processor: NdsProcessor;
  readonly runtimeAddress: number;
  readonly relativeOffset: number;
  readonly overlayId: number | null;
  readonly fileId: number | null;
  readonly romOffset: number | null;
  readonly backingRomOffset: number | null;
  readonly backingRomSize: number | null;
  readonly compressed: boolean;
}

export interface RomOffsetResolution {
  readonly offset: number;
  readonly matches: readonly RomOffsetMatch[];
}
```

- [ ] **Step 1: Write failing runtime resolver tests**

Cover:

```ts
test("does not fabricate an exact ROM byte for compressed runtime overlay data", () => {
  const result = resolveRuntimeAddress(map, 0x02210040, "arm9");
  assert.equal(result.status, "compressed-no-direct-rom-mapping");
  if (result.status !== "compressed-no-direct-rom-mapping") assert.fail();
  assert.equal(result.candidate.romOffset, null);
  assert.equal(result.candidate.backingRomOffset, 0x1400);
});
```

Also main mapping, uncompressed overlay mapping, BSS, multiple overlapping overlays, processor isolation, unmapped address, and 32-bit input boundaries.

- [ ] **Step 2: Write failing ROM-offset classification tests**

Verify a byte may return both `nitrofs-file` and `arm9-overlay` classifications. Verify compressed overlay backing bytes get no runtime address. Verify header/FNT/FAT/overlay-table structural classifications.

- [ ] **Step 3: Verify RED**

```bash
npm test -- tests/nds-resolver.test.ts
```

- [ ] **Step 4: Implement resolver logic with no heuristics**

Runtime algorithm:

1. Collect main-range candidate for requested processor.
2. Collect every overlay initialized/BSS candidate for requested processor.
3. If no candidate: `unmapped`.
4. If more than one candidate: `ambiguous-runtime-address` with all candidates, even if one is main and one is overlay.
5. For a single BSS candidate: `runtime-only-bss`.
6. For a single compressed initialized overlay: `compressed-no-direct-rom-mapping`.
7. Otherwise: `resolved` with direct ROM mapping.

ROM-offset algorithm returns all matching classifications; do not deduplicate away meaningful file+overlay relationships.

- [ ] **Step 5: Verify GREEN**

```bash
npm test -- tests/nds-resolver.test.ts tests/nds-rom-map.test.ts
npm run typecheck
```

- [ ] **Step 6: Commit Task 6**

```bash
git add src/services/nds/resolver.ts tests/nds-resolver.test.ts
git commit -m "feat: resolve NDS runtime and ROM addresses"
```

---

### Task 7: Add controlled component extraction and transactional analysis bundles

**Files:**
- Create: `src/services/nds/extraction.ts`
- Create: `tests/nds-extraction.test.ts`

**Interfaces:**
- Consumes: `NdsRomMap`, validated component selectors, `resolveInside()`.
- Produces: `extractNdsComponent()` and `extractNdsAnalysisBundle()`.

```ts
export type NdsExtractionRequest =
  | { readonly component: "arm9" }
  | { readonly component: "arm7" }
  | { readonly component: "arm9-overlay"; readonly overlayId: number }
  | { readonly component: "arm7-overlay"; readonly overlayId: number }
  | { readonly component: "nitrofs-file"; readonly fileId: number }
  | { readonly component: "nitrofs-path"; readonly filePath: string };

export interface NdsExtractedArtifact {
  readonly output: string;
  readonly component: string;
  readonly sourceRomSha256: string;
  readonly outputSha256: string;
  readonly romOffset: number;
  readonly size: number;
  readonly ramAddress: number | null;
  readonly processor: NdsProcessor | null;
  readonly overlayId: number | null;
  readonly fileId: number | null;
  readonly compressed: boolean;
  readonly compressedSize: number | null;
}
```

Output root is fixed, not caller-supplied:

```ts
const relativeRoot = path.join("analysis", "generated", "nds", map.sha256Prefix);
const outputRoot = resolveInside(workspaceRoot, relativeRoot);
```

- [ ] **Step 1: Write failing extraction tests**

Test ARM9, ARM7, uncompressed/compressed overlay stored bytes, NitroFS by ID/path, unknown IDs, deterministic output names, source/artifact hashes, and source ROM hash before/after equality.

Also test that a `filePath` must exactly match a parsed FNT path; it is not resolved as a filesystem path.

- [ ] **Step 2: Write failing atomic-bundle tests**

Inject a narrow file-operation adapter into extraction for tests:

```ts
export interface NdsExtractionFs {
  mkdir: typeof mkdir;
  rename: typeof rename;
  rm: typeof rm;
}
```

Keep the default adapter internal/exported-for-test. Force a failure after some temporary bundle files are written and assert the final deterministic bundle directory is absent or the previous complete bundle is restored.

- [ ] **Step 3: Verify RED**

```bash
npm test -- tests/nds-extraction.test.ts
```

- [ ] **Step 4: Implement atomic range copy**

Use streaming copy so large ROM components are not loaded wholesale:

```ts
async function copyRangeAtomic(
  sourcePath: string,
  start: number,
  length: number,
  outputPath: string,
): Promise<string> {
  const temporary = `${outputPath}.tmp-${process.pid}-${Date.now()}`;
  await mkdir(path.dirname(outputPath), { recursive: true });
  if (length === 0) {
    await writeFile(temporary, Buffer.alloc(0), { flag: "wx" });
  } else {
    await pipeline(
      createReadStream(sourcePath, { start, end: start + length - 1 }),
      createWriteStream(temporary, { flags: "wx" }),
    );
  }
  const handle = await open(temporary, "r+");
  try { await handle.sync(); } finally { await handle.close(); }
  await rename(temporary, outputPath);
  return await hashFileSha256(outputPath);
}
```

On error, best-effort remove temporary files and throw `NdsError("generated-path-failure", ...)`.

Do not expose `copyRangeAtomic()` through MCP.

- [ ] **Step 5: Implement manifest and transactional bundle promotion**

Bundle metadata files:

```text
manifest.json
address-map.json
filesystem.json
overlays.json
arm9.bin
arm7.bin
overlays/arm9/overlay_<id>.bin
overlays/arm7/overlay_<id>.bin
```

Build under sibling `<shaPrefix>.tmp-<pid>-<timestamp>`. If final already exists, rename it to a backup sibling, rename completed temp to final, then remove backup. On promotion failure restore backup before rethrowing.

Manifests must explicitly mark compressed overlays as stored/compressed bytes.

- [ ] **Step 6: Verify GREEN and PR-B regression**

```bash
npm test -- tests/nds-resolver.test.ts tests/nds-extraction.test.ts
npm run check
npm run build
```

Expected: PASS.

- [ ] **Step 7: Commit Task 7**

```bash
git add src/services/nds/extraction.ts tests/nds-extraction.test.ts
git commit -m "feat: extract validated NDS analysis artifacts"
```

- [ ] **Step 8: PR-B verification gate**

Open PR **`Add NDS address resolution and controlled extraction`** from `feature/nds-address-extraction` to `main`. Require CI and Package success before integration.

---

### Task 8: Migrate `readArm9ExecutableRange()` to the canonical parser without debugger behavior changes

**Files:**
- Modify: `src/services/nds-arm9.ts`
- Modify: `tests/nds-arm9.test.ts`

**Interfaces:**
- Consumes: `readNdsRomMap()` or the canonical header parser.
- Preserves exactly:

```ts
export interface Arm9ExecutableRange {
  readonly start: number;
  readonly end: number;
  readonly size: number;
  readonly source: "arm9-header";
  readonly label: "ARM9 main";
}

export async function readArm9ExecutableRange(
  romPath: string,
): Promise<Arm9ExecutableRange>;
```

- [ ] **Step 1: Add compatibility regression tests before refactor**

Retain existing expected shape and add cases proving the old debugger-specific ARM9 main-RAM policy remains enforced:

```ts
test("compatibility adapter still rejects ARM9 outside DS main RAM", async () => {
  const fixture = await createNdsFixture({ arm9RamAddress: 0x01000000 });
  await assert.rejects(readArm9ExecutableRange(fixture.romPath), /outside DS main RAM/);
});
```

The canonical parser itself may parse broader 32-bit metadata; this adapter preserves the existing `0x02000000 <= ARM9 < 0x02400000` debugger constraint.

- [ ] **Step 2: Run existing compatibility tests before code change**

```bash
npm test -- tests/nds-arm9.test.ts
```

Expected: PASS on current implementation.

- [ ] **Step 3: Refactor to canonical source**

Replace independent header file reads with canonical metadata:

```ts
const map = await readNdsRomMap(romPath);
const { ramAddress: start, size, ramEnd: end } = map.header.arm9;
```

Then apply the existing DS main-RAM validation and return the exact old shape.

Do not modify `src/tools/desmume.ts` behavior in this task.

- [ ] **Step 4: Verify compatibility and debugger regression**

```bash
npm test -- tests/nds-arm9.test.ts tests/desmume-debug-tools.test.ts tests/desmume-start-race.test.ts tests/desmume-debug-lifecycle.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 5: Commit Task 8**

```bash
git add src/services/nds-arm9.ts tests/nds-arm9.test.ts
git commit -m "refactor: source ARM9 range from canonical NDS map"
```

---

### Task 9: Expose the seven bounded MCP NDS tools

**Files:**
- Create: `src/tools/nds.ts`
- Create: `tests/nds-tools.test.ts`
- Modify: `src/index.ts`

**Interfaces:**
- Consumes: `readNdsRomMap`, both resolvers, both extraction functions, `resolveInside`, `ServerConfig`.
- Produces: `registerNdsTools(server, config): void`.

Public tool names:

```text
nds_inspect_rom
nds_list_files
nds_list_overlays
nds_resolve_runtime_address
nds_resolve_rom_offset
nds_extract_component
nds_extract_analysis_bundle
```

Common schemas:

```ts
const uint32Schema = z.number().int().min(0).max(0xffffffff);
const romSchema = z.string().min(1);
const processorSchema = z.enum(["arm9", "arm7"]);
const listProcessorSchema = z.enum(["arm9", "arm7", "all"]);
const listLimitSchema = z.number().int().min(1).max(200).default(100);
const listOffsetSchema = z.number().int().min(0).default(0);
```

Use workspace-level generated output exactly as approved. No `project` or `output` field is added to extraction schemas.

- [ ] **Step 1: Create a fake MCP server test harness and write registration RED tests**

Follow the existing tool-test pattern by capturing `server.tool(name, description, schema, handler)` calls. Assert exactly the seven new names are registered by `registerNdsTools()`.

- [ ] **Step 2: Write schema/handler RED tests**

Cover:

- ROM path containment;
- list default/max limit and pagination offset;
- prefix filtering on parsed NitroFS paths while retaining stable `total`, `offset`, `limit`, and `nextOffset` fields;
- overlay processor filtering and pagination;
- uint32 bounds;
- normal runtime statuses are returned with `isError !== true`;
- parser/extraction errors return `isError: true` with `operation`, `category`, and `correctiveAction`;
- extraction selector validation rejects missing/wrong selector fields;
- no arbitrary output field exists;
- serialized response exceeding `maxOutputBytes` becomes `output-bound-exceeded`.

Define the extraction MCP schema as one object plus handler-level discriminant validation because `McpServer.tool()` currently receives a Zod raw shape:

```ts
{
  rom: romSchema,
  component: z.enum(["arm9", "arm7", "arm9-overlay", "arm7-overlay", "nitrofs-file"]),
  overlayId: z.number().int().min(0).optional(),
  fileId: z.number().int().min(0).optional(),
  filePath: z.string().min(1).optional(),
}
```

Normalize with an exhaustive helper that requires:

- no selector for `arm9`/`arm7`;
- `overlayId` only for overlay components;
- exactly one of `fileId` or `filePath` for `nitrofs-file`.

- [ ] **Step 3: Verify RED**

```bash
npm test -- tests/nds-tools.test.ts
```

Expected: FAIL because `registerNdsTools()` does not exist.

- [ ] **Step 4: Implement bounded result/error helpers**

```ts
function boundedTextResult(
  config: ServerConfig,
  operation: string,
  value: unknown,
  isError = false,
) {
  const text = JSON.stringify(value, null, 2);
  if (Buffer.byteLength(text, "utf8") > config.maxOutputBytes) {
    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          error: "Serialized NDS result exceeds RE_MCP_MAX_OUTPUT_BYTES",
          operation,
          category: "output-bound-exceeded",
          correctiveAction: "Narrow the request with prefix, processor, limit, or pagination offset.",
        }, null, 2),
      }],
      isError: true,
    };
  }
  return { content: [{ type: "text" as const, text }], isError };
}
```

Create `ndsErrorResult()` that maps `NdsError.category`; unknown errors use `invalid-rom` only when they arise during ROM open/stat, otherwise preserve a generic safe message without stack trace.

- [ ] **Step 5: Implement the seven handlers**

For every handler:

```ts
const romPath = resolveInside(config.workspaceRoot, rom);
const map = await readNdsRomMap(romPath);
```

`nds_inspect_rom` returns summary/counts and executable ranges.

`nds_list_files` filters named paths by `prefix`, sorts by `fileId`, slices `[offset, offset + limit)`, and returns pagination metadata.

`nds_list_overlays` filters processor first, sorts by `(processor, overlayId)`, then paginates.

Resolvers return their structured normal status without converting ambiguity/BSS/compression to an MCP error.

Extraction calls use `config.workspaceRoot` so service-computed destination remains fixed below `analysis/generated/nds`.

- [ ] **Step 6: Register tools in `src/index.ts` and capability list**

Add:

```ts
import { registerNdsTools } from "./tools/nds.js";
...
registerNdsTools(server, config);
```

Append all seven names to `server_capabilities.tools`. Do not alter `debuggerPolicy` except, if necessary, add a separate `ndsStaticAnalysisPolicy` field describing read-only ROM parsing plus controlled generated artifacts.

- [ ] **Step 7: Verify GREEN**

```bash
npm test -- tests/nds-tools.test.ts
npm run typecheck
npm run build
```

- [ ] **Step 8: Commit Task 9**

```bash
git add src/tools/nds.ts src/index.ts tests/nds-tools.test.ts
git commit -m "feat: expose NDS static analysis MCP tools"
```

---

### Task 10: Document the feature and run final cross-layer verification

**Files:**
- Modify: `README.md`
- Modify if necessary: `docs/superpowers/specs/2026-08-07-nds-static-analysis-foundation-design.md` only for factual implementation drift discovered during review; do not weaken approved constraints.

**Interfaces:**
- No new production interface.
- Produces user-facing documentation and final evidence that static tooling did not regress debugger behavior.

- [ ] **Step 1: Add README documentation**

Add an **NDS Static Analysis** section listing the seven tools and explaining:

```text
- ROM inputs stay read-only.
- Generated outputs go only to analysis/generated/nds/<sha-prefix>/.
- ARM9/ARM7, FAT/FNT, and overlays are parsed into one canonical map.
- Overlapping overlay candidates are reported, never guessed.
- BSS has no ROM bytes.
- Compressed overlay runtime bytes intentionally have no direct ROM-byte mapping until decompression support exists.
- The analysis bundle extracts stored overlay bytes; compressed overlays stay compressed.
```

Add a short workflow example:

```text
nds_inspect_rom
→ nds_list_overlays / nds_list_files
→ nds_resolve_runtime_address or nds_resolve_rom_offset
→ nds_extract_component or nds_extract_analysis_bundle
```

Do not document disassembly/Ghidra/watchpoints as implemented.

- [ ] **Step 2: Run focused NDS suite**

```bash
npm test -- tests/nds-header.test.ts tests/nds-fat.test.ts tests/nds-fnt.test.ts tests/nds-overlays.test.ts tests/nds-rom-map.test.ts tests/nds-resolver.test.ts tests/nds-extraction.test.ts tests/nds-tools.test.ts tests/nds-arm9.test.ts
```

Expected: PASS.

- [ ] **Step 3: Run debugger regression suite**

```bash
npm test -- tests/desmume-debug-tools.test.ts tests/desmume-debug-lifecycle.test.ts tests/desmume-start-race.test.ts tests/debug-controller-context.test.ts tests/arm9-registers.test.ts tests/stop-context.test.ts
```

Expected: PASS with no required behavior changes.

- [ ] **Step 4: Run full verification**

```bash
npm run check
npm run build
```

Expected: typecheck PASS, full tests PASS, build PASS.

- [ ] **Step 5: Review the diff for forbidden scope expansion**

Run:

```bash
git diff main...HEAD -- src/services src/tools src/index.ts README.md package.json package-lock.json
```

Confirm:

```text
package.json / package-lock.json have no new runtime dependency
no register write or memory write tool
no watchpoint tool
no arbitrary GDB packet tool
no new breakpoint/continue/step/pause behavior
no source-ROM write path
no caller-selected extraction output path
```

- [ ] **Step 6: Commit documentation**

```bash
git add README.md
git commit -m "docs: document NDS static analysis tools"
```

- [ ] **Step 7: PR-C verification gate**

Open PR **`Expose NDS static analysis foundation tools`** from `feature/nds-static-mcp-tools` to `main`.

PR body must summarize:

- seven tools;
- canonical parser/model;
- compressed/BSS mapping safety;
- deterministic controlled extraction;
- no new dependencies;
- no Dynamic Debugging behavior changes;
- exact CI evidence.

Require CI and Package success before integration.

---

## Final Acceptance Checklist

Before marking **NDS Static Analysis Foundation** complete, verify all of the following from the final PR head:

- [ ] `nds_inspect_rom` implemented and bounded.
- [ ] `nds_list_files` implemented with prefix + pagination.
- [ ] `nds_list_overlays` implemented with processor + pagination.
- [ ] `nds_resolve_runtime_address` reports main, overlay, BSS, compression, ambiguity, and unmapped states correctly.
- [ ] `nds_resolve_rom_offset` returns all valid classifications.
- [ ] `nds_extract_component` accepts only canonical selectors and no arbitrary output path.
- [ ] `nds_extract_analysis_bundle` produces deterministic complete bundles and does not dump all NitroFS assets.
- [ ] Source ROM SHA-256 is unchanged after extraction tests.
- [ ] Every artifact records source/output SHA-256.
- [ ] FAT/FNT/overlay malformed-fixture tests pass.
- [ ] Compressed overlay runtime bytes have `romOffset: null`.
- [ ] Compressed overlay backing bytes have no fabricated runtime address.
- [ ] BSS has no ROM offset.
- [ ] Overlapping overlays are never guessed.
- [ ] `readArm9ExecutableRange()` preserves existing public result shape and main-RAM policy.
- [ ] Existing DeSmuME debugger regression tests pass.
- [ ] `package.json` has no new runtime dependency.
- [ ] `npm run check` passes.
- [ ] `npm run build` passes.
- [ ] GitHub CI passes on the final head.
- [ ] GitHub Package workflow passes on the final head.
- [ ] Physical Catalina Dynamic Debugging acceptance remains a separate pending gate; do not falsely mark it complete because this static milestone passes.
