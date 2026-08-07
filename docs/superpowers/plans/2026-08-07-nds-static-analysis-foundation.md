# NDS Static Analysis Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a canonical, safe, native-independent Nintendo DS ROM model with structure inspection, address resolution, and controlled extraction while leaving Dynamic Debugging Patch 1 behavior unchanged pending Catalina acceptance.

**Architecture:** Parse each ROM into a canonical `NdsRomMap` built from strict header, FAT, FNT, and overlay services. Resolution and extraction consume only validated model data. Seven bounded MCP tools expose the model; extraction writes only to the fixed workspace-level `analysis/generated/nds/<sha-prefix>/` tree. The existing debugger ARM9 helper reuses canonical header-decoding code without inheriting stricter FAT/FNT/overlay validation.

**Tech Stack:** TypeScript 5.7, Node.js 20+, Node built-ins, MCP SDK, Zod, Node test runner through `tsx`. No new runtime dependency.

## Global Constraints

- Source `.nds` files are immutable.
- No arbitrary output path, raw offset/length extraction tool, ROM rebuild, or ROM mutation.
- Generated artifacts live only under `RE_MCP_WORKSPACE_ROOT/analysis/generated/nds/<first-16-sha256-hex>/`.
- Full SHA-256 is canonical; 16 hex characters are only the generated-directory prefix.
- All ROM inputs resolve with `resolveInside(config.workspaceRoot, rom)`.
- All serialized MCP responses respect `config.maxOutputBytes`.
- FAT is authoritative for physical file ranges; FNT is authoritative for names/hierarchy.
- Overlay table records are exactly 32 bytes.
- Overlay packed word: `compressedSize = packed & 0x00ffffff`, `flags = packed >>> 24`, `compressed = (flags & 1) !== 0`.
- Never fabricate ROM byte offsets for compressed runtime overlay bytes or BSS.
- Never fabricate runtime addresses for compressed overlay backing-file byte positions.
- Never choose among overlapping overlay candidates heuristically.
- `readArm9ExecutableRange()` keeps its existing result shape, ARM9 main-RAM policy, and narrow validation behavior.
- Do not change breakpoint, continue, step, pause, GDB, stop-context, or process-lifecycle behavior.
- No new runtime dependency.
- Code must satisfy `strict`, `noUncheckedIndexedAccess`, and `exactOptionalPropertyTypes`.
- Every task follows red test → minimal green → targeted verification → commit.

## Branch / PR Sequence

Use three reviewable PRs:

1. **PR A — `feature/nds-static-structure`**: Tasks 1–5. Create this branch from `design/nds-static-analysis-foundation` so the approved spec and this plan travel with the first implementation PR.
2. **PR B — `feature/nds-address-extraction`**: Tasks 6–7. Create from `main` after PR A merges.
3. **PR C — `feature/nds-static-mcp-tools`**: Tasks 8–10. Create from `main` after PR B merges.

At execution time, use `superpowers:using-git-worktrees` when local git is available. If local cloning remains blocked, use isolated GitHub branches and GitHub Actions as the verification environment.

---

## File Structure

### New production files

- `src/services/nds/errors.ts` — stable parser/operation error categories.
- `src/services/nds/io.ts` — exact bounded reads and streaming SHA-256.
- `src/services/nds/header.ts` — shared header decode, full validation, and ARM9 compatibility metadata reader.
- `src/services/nds/fat.ts` — FAT physical-range parser.
- `src/services/nds/fnt.ts` — FNT/NitroFS hierarchy parser.
- `src/services/nds/overlays.ts` — ARM9/ARM7 overlay parser and FAT joins.
- `src/services/nds/rom-map.ts` — canonical `NdsRomMap` composition.
- `src/services/nds/resolver.ts` — runtime-address and ROM-offset resolvers.
- `src/services/nds/extraction.ts` — deterministic atomic extraction and bundle promotion.
- `src/tools/nds.ts` — seven public MCP tools, schemas, pagination, output bounds.

### Existing production files modified

- `src/services/nds-arm9.ts` — compatibility adapter using `readArm9HeaderMetadata()`.
- `src/index.ts` — NDS tool registration and capabilities.
- `README.md` — NDS static-analysis documentation.

### New tests

- `tests/helpers/nds-fixture.ts`
- `tests/nds-header.test.ts`
- `tests/nds-fat.test.ts`
- `tests/nds-fnt.test.ts`
- `tests/nds-overlays.test.ts`
- `tests/nds-rom-map.test.ts`
- `tests/nds-resolver.test.ts`
- `tests/nds-extraction.test.ts`
- `tests/nds-tools.test.ts`

### Existing regression test

- `tests/nds-arm9.test.ts`
- existing debugger tests remain green without debugger behavior edits.

---

### Task 1: Add fixture infrastructure, I/O primitives, ROM identity, and header parsing

**Files:**
- Create: `tests/helpers/nds-fixture.ts`
- Create: `src/services/nds/errors.ts`
- Create: `src/services/nds/io.ts`
- Create: `src/services/nds/header.ts`
- Create: `tests/nds-header.test.ts`

**Interfaces:**

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
  constructor(readonly category: NdsErrorCategory, message: string) {
    super(message);
    this.name = "NdsError";
  }
}

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

export async function parseNdsHeader(romPath: string): Promise<ParsedNdsHeader>;
export async function readArm9HeaderMetadata(romPath: string): Promise<NdsExecutableHeader>;
```

`readArm9HeaderMetadata()` and `parseNdsHeader()` must share one private header-field decoder. The ARM9 compatibility reader validates only the file/header conditions and ARM9 ROM/runtime arithmetic required by the old helper; it does **not** validate ARM7, FNT, FAT, or overlay tables and does not hash the whole ROM.

Use these header offsets:

```ts
const HEADER_BYTES = 0x6c;
const OFFSETS = {
  title: 0x00, gameCode: 0x0c, makerCode: 0x10,
  unitCode: 0x12, deviceCapacity: 0x14, romVersion: 0x1e,
  arm9Rom: 0x20, arm9Entry: 0x24, arm9Ram: 0x28, arm9Size: 0x2c,
  arm7Rom: 0x30, arm7Entry: 0x34, arm7Ram: 0x38, arm7Size: 0x3c,
  fntOffset: 0x40, fntSize: 0x44,
  fatOffset: 0x48, fatSize: 0x4c,
  arm9OverlayOffset: 0x50, arm9OverlaySize: 0x54,
  arm7OverlayOffset: 0x58, arm7OverlaySize: 0x5c,
  bannerOffset: 0x68,
} as const;
```

- [ ] **Step 1: Create the deterministic NDS fixture builder**

`tests/helpers/nds-fixture.ts` must create a temp ROM with configurable header fields and a mutable `Buffer` plus `write()` method. Default non-overlapping regions: ARM9 `0x200`, ARM7 `0x600`, FNT `0x800`, FAT `0x900`, ARM9 overlay table `0xa00`, ARM7 overlay table `0xb00`, file size `0x4000`.

- [ ] **Step 2: Write failing header tests**

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

test("ARM9 compatibility metadata ignores malformed FAT", async () => {
  const fixture = await createNdsFixture({ fatOffset: 0x3ff0, fatSize: 0x100 });
  const arm9 = await readArm9HeaderMetadata(fixture.romPath);
  assert.equal(arm9.ramAddress, 0x02000000);
  await assert.rejects(parseNdsHeader(fixture.romPath), /FAT|beyond/i);
});
```

Also test short header, directory input, zero ARM9/ARM7 size for full parsing, ARM9/ARM7 runtime overflow, referenced region past EOF, empty table regions, and stable SHA-256.

- [ ] **Step 3: Verify RED**

```bash
npm test -- tests/nds-header.test.ts
```

Expected: module/export missing failures.

- [ ] **Step 4: Implement `NdsError`, exact reads, hashing, and shared header decode**

`hashFileSha256()` uses `createReadStream()` so ROM size does not become an in-memory hash buffer. `readExact()` uses `FileHandle.read()` and rejects short reads.

The full parser validates all header-referenced regions. For optional FNT/FAT/overlay tables, `size === 0` is allowed; preserve the decoded offset, set `end = offset`, and never read the table. Reject an offset greater than file size even when size is zero.

- [ ] **Step 5: Verify GREEN**

```bash
npm test -- tests/nds-header.test.ts
npm run typecheck
```

- [ ] **Step 6: Commit**

```bash
git add src/services/nds/errors.ts src/services/nds/io.ts src/services/nds/header.ts tests/helpers/nds-fixture.ts tests/nds-header.test.ts
git commit -m "feat: add canonical NDS header parser"
```

---

### Task 2: Parse FAT physical file ranges

**Files:**
- Create: `src/services/nds/fat.ts`
- Create: `tests/nds-fat.test.ts`
- Modify: `tests/helpers/nds-fixture.ts`

**Interfaces:**

```ts
export interface NdsFatEntry {
  readonly fileId: number;
  readonly startOffset: number;
  readonly endOffset: number;
  readonly size: number;
}

export async function parseNdsFat(parsed: ParsedNdsHeader): Promise<readonly NdsFatEntry[]>;
```

- [ ] **Step 1: Add `writeFatEntry()` fixture helper**

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

- [ ] **Step 2: Write RED tests**

Cover valid entries, `fat.size % 8 !== 0`, `start > end`, end past EOF, and zero-length files.

- [ ] **Step 3: Run RED**

```bash
npm test -- tests/nds-fat.test.ts
```

- [ ] **Step 4: Implement FAT parser**

```ts
if (parsed.header.fat.size === 0) return [];
if (parsed.header.fat.size % 8 !== 0) {
  throw new NdsError("malformed-fat", "NDS FAT size must be divisible by 8");
}
```

Read exactly the FAT region and validate every `[startOffset, endOffset)` against `parsed.fileSize`.

- [ ] **Step 5: Verify GREEN**

```bash
npm test -- tests/nds-fat.test.ts tests/nds-header.test.ts
npm run typecheck
```

- [ ] **Step 6: Commit**

```bash
git add src/services/nds/fat.ts tests/helpers/nds-fixture.ts tests/nds-fat.test.ts
git commit -m "feat: parse NDS FAT ranges"
```

---

### Task 3: Reconstruct FNT/NitroFS hierarchy

**Files:**
- Create: `src/services/nds/fnt.ts`
- Create: `tests/nds-fnt.test.ts`
- Modify: `tests/helpers/nds-fixture.ts`

**Interfaces:**

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

export async function parseNdsFnt(
  parsed: ParsedNdsHeader,
  fat: readonly NdsFatEntry[],
): Promise<NdsFilesystem>;
```

DS FNT rules used by implementation:

- directory IDs start at `0xF000`;
- main-table index is `directoryId & 0x0fff`;
- each main-table record is 8 bytes: subtable offset `u32le`, first file ID `u16le`, parent/root metadata `u16le`;
- root record final `u16` is directory count;
- subtable entry byte `0` terminates;
- low 7 bits are name length; high bit indicates directory;
- directory entries include a trailing child directory ID `u16le`;
- file IDs increment implicitly from the directory's first file ID.

- [ ] **Step 1: Add FNT fixture helpers**

Create helpers to write main-table records plus file/directory subtable entries. Tests must not hand-code the same FNT encoding repeatedly.

- [ ] **Step 2: Write RED tests**

```ts
test("reconstructs nested paths and preserves unnamed FAT entries", async () => {
  const filesystem = await parseNdsFnt(parsed, fat);
  assert.equal(filesystem.files[0]?.path, "root.bin");
  assert.equal(filesystem.files[1]?.path, "data/nested.bin");
  assert.equal(filesystem.files[2]?.path, null);
});
```

Also cover invalid directory ID, cycle, subtable past FNT end, file ID beyond FAT, unterminated subtable, and unusual one-byte filename values.

- [ ] **Step 3: Run RED**

```bash
npm test -- tests/nds-fnt.test.ts
```

- [ ] **Step 4: Implement bounded traversal**

Read only the FNT region. Validate root directory count before traversal. Use `visiting`/`visited` sets to detect cycles. Decode display names as Latin-1; reject path-segment values containing `/`, `\\`, NUL, or exactly `.`/`..`. File-ID arithmetic comes from FNT metadata, never from decoded names.

After traversal, return every FAT entry as a file, using `path: null` for unnamed entries.

- [ ] **Step 5: Verify GREEN**

```bash
npm test -- tests/nds-fnt.test.ts tests/nds-fat.test.ts
npm run typecheck
```

- [ ] **Step 6: Commit**

```bash
git add src/services/nds/fnt.ts tests/helpers/nds-fixture.ts tests/nds-fnt.test.ts
git commit -m "feat: reconstruct NDS NitroFS paths"
```

---

### Task 4: Parse ARM9/ARM7 overlay tables safely

**Files:**
- Create: `src/services/nds/overlays.ts`
- Create: `tests/nds-overlays.test.ts`
- Modify: `tests/helpers/nds-fixture.ts`

**Interfaces:**

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

export async function parseNdsOverlays(
  parsed: ParsedNdsHeader,
  fat: readonly NdsFatEntry[],
  processor: NdsProcessor,
): Promise<readonly NdsOverlay[]>;
```

- [ ] **Step 1: Add `writeOverlayRecord()` fixture helper**

Write eight little-endian `u32` values, packing the final word as:

```ts
const packed = (compressedSize & 0x00ffffff) | ((flags & 0xff) << 24);
```

- [ ] **Step 2: Write RED tests**

Cover ARM9/ARM7, table size not divisible by 32, invalid `fileId`, runtime overflow, compression flag/size decode, valid zero static-init range, invalid ordered/out-of-range static-init region, overlapping overlays accepted, and `romSize !== ramSize` accepted.

- [ ] **Step 3: Run RED**

```bash
npm test -- tests/nds-overlays.test.ts
```

- [ ] **Step 4: Implement parser**

Zero-size table returns `[]`. Nonzero table requires `size % 32 === 0`. Join `fileId` through FAT. Overflow-check `ramAddress + ramSize` and then `ramEnd + bssSize`. Preserve flags without interpreting bits other than compression bit 0.

- [ ] **Step 5: Verify GREEN**

```bash
npm test -- tests/nds-overlays.test.ts tests/nds-fat.test.ts
npm run typecheck
```

- [ ] **Step 6: Commit**

```bash
git add src/services/nds/overlays.ts tests/helpers/nds-fixture.ts tests/nds-overlays.test.ts
git commit -m "feat: parse NDS overlay tables"
```

---

### Task 5: Compose canonical `NdsRomMap`

**Files:**
- Create: `src/services/nds/rom-map.ts`
- Create: `tests/nds-rom-map.test.ts`

**Interfaces:**

```ts
export interface NdsExecutableRange {
  readonly kind: "arm9-main" | "arm7-main" | "arm9-overlay" | "arm7-overlay";
  readonly processor: NdsProcessor;
  readonly start: number;
  readonly initializedEnd: number;
  readonly end: number;
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
  readonly overlays: Readonly<{ arm9: readonly NdsOverlay[]; arm7: readonly NdsOverlay[] }>;
  readonly executableRanges: readonly NdsExecutableRange[];
}

export async function readNdsRomMap(romPath: string): Promise<NdsRomMap>;
```

For main binaries, `initializedEnd === end === ramEnd`. For overlays, `initializedEnd === ramEnd` and `end === bssEnd`.

- [ ] **Step 1: Write RED composition tests**

Assert the map preserves one ROM identity across header/FAT/FNT/overlay data and creates main+overlay ranges without loaded-state claims.

- [ ] **Step 2: Run RED**

```bash
npm test -- tests/nds-rom-map.test.ts
```

- [ ] **Step 3: Implement composition**

```ts
const parsed = await parseNdsHeader(romPath);
const fat = await parseNdsFat(parsed);
const filesystem = await parseNdsFnt(parsed, fat);
const arm9 = await parseNdsOverlays(parsed, fat, "arm9");
const arm7 = await parseNdsOverlays(parsed, fat, "arm7");
```

Build deterministic ranges sorted main ARM9, main ARM7, ARM9 overlays by ID, ARM7 overlays by ID.

- [ ] **Step 4: Verify PR-A scope**

```bash
npm test -- tests/nds-header.test.ts tests/nds-fat.test.ts tests/nds-fnt.test.ts tests/nds-overlays.test.ts tests/nds-rom-map.test.ts
npm run check
npm run build
```

- [ ] **Step 5: Commit**

```bash
git add src/services/nds/rom-map.ts tests/nds-rom-map.test.ts
git commit -m "feat: compose canonical NDS ROM map"
```

- [ ] **Step 6: Open PR A**

Open **`Add canonical NDS static structure parser`** from `feature/nds-static-structure` to `main`. The PR includes the approved design and implementation plan from the design branch. Require CI and Package success before integration.

---

### Task 6: Add runtime-address and ROM-offset resolvers

**Files:**
- Create: `src/services/nds/resolver.ts`
- Create: `tests/nds-resolver.test.ts`

**Interfaces:**

```ts
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

export type RuntimeResolution =
  | { readonly status: "unmapped"; readonly address: number; readonly processor: NdsProcessor }
  | { readonly status: "resolved"; readonly candidate: RuntimeCandidate }
  | { readonly status: "ambiguous-runtime-address"; readonly candidates: readonly RuntimeCandidate[] }
  | { readonly status: "runtime-only-bss"; readonly candidate: RuntimeCandidate }
  | { readonly status: "compressed-no-direct-rom-mapping"; readonly candidate: RuntimeCandidate };

export interface RomOffsetMatch {
  readonly kind: "header" | "fnt" | "fat" | "arm9-overlay-table" | "arm7-overlay-table" | "nitrofs-file" | "arm9-main" | "arm7-main" | "arm9-overlay" | "arm7-overlay";
  readonly fileId: number | null;
  readonly overlayId: number | null;
  readonly runtimeAddress: number | null;
}

export interface RomOffsetResolution {
  readonly offset: number;
  readonly matches: readonly RomOffsetMatch[];
}

export function resolveRuntimeAddress(map: NdsRomMap, address: number, processor: NdsProcessor): RuntimeResolution;
export function resolveRomOffset(map: NdsRomMap, offset: number): RomOffsetResolution;
```

- [ ] **Step 1: Write RED runtime tests**

Cover main binary, uncompressed overlay, compressed initialized overlay (`romOffset: null` with backing metadata), overlay BSS, multiple overlaps, main+overlay overlap, processor isolation, and unmapped address.

```ts
test("compressed runtime overlay bytes have no exact ROM offset", () => {
  const result = resolveRuntimeAddress(map, 0x02210040, "arm9");
  assert.equal(result.status, "compressed-no-direct-rom-mapping");
  if (result.status !== "compressed-no-direct-rom-mapping") assert.fail();
  assert.equal(result.candidate.romOffset, null);
  assert.equal(result.candidate.backingRomOffset, 0x1400);
});
```

- [ ] **Step 2: Write RED ROM-offset classification tests**

Verify multi-classification for overlay+NitroFS file, structural ranges, main binaries, and no fabricated runtime address for compressed overlay backing bytes. Offset `>= map.fileSize` throws `NdsError("range-out-of-bounds", ...)`.

- [ ] **Step 3: Run RED**

```bash
npm test -- tests/nds-resolver.test.ts
```

- [ ] **Step 4: Implement resolver without heuristics**

Runtime order:

1. collect every main/overlay candidate for requested processor;
2. zero candidates → `unmapped`;
3. more than one → `ambiguous-runtime-address` with all candidates;
4. one BSS candidate → `runtime-only-bss`;
5. one compressed initialized overlay → `compressed-no-direct-rom-mapping`;
6. otherwise → `resolved`.

ROM-offset resolver returns all valid matches and only includes runtime addresses when byte mapping is deterministic.

- [ ] **Step 5: Verify GREEN**

```bash
npm test -- tests/nds-resolver.test.ts tests/nds-rom-map.test.ts
npm run typecheck
```

- [ ] **Step 6: Commit**

```bash
git add src/services/nds/resolver.ts tests/nds-resolver.test.ts
git commit -m "feat: resolve NDS runtime and ROM addresses"
```

---

### Task 7: Add controlled extraction and transactional analysis bundles

**Files:**
- Create: `src/services/nds/extraction.ts`
- Create: `tests/nds-extraction.test.ts`

**Interfaces:**

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

export async function extractNdsComponent(
  map: NdsRomMap,
  workspaceRoot: string,
  request: NdsExtractionRequest,
): Promise<NdsExtractedArtifact>;

export async function extractNdsAnalysisBundle(
  map: NdsRomMap,
  workspaceRoot: string,
): Promise<{ readonly outputRoot: string; readonly manifestPath: string }>;
```

Fixed output root:

```ts
resolveInside(
  workspaceRoot,
  path.join("analysis", "generated", "nds", map.sha256Prefix),
);
```

- [ ] **Step 1: Write RED component tests**

Cover ARM9/ARM7, uncompressed/compressed overlay stored bytes, NitroFS by ID/path, unknown IDs, deterministic names, source/output hashes, and unchanged source hash before/after. `nitrofs-path` must match a parsed FNT path exactly; it is not a host-filesystem path.

- [ ] **Step 2: Write RED transaction tests**

Inject a narrow filesystem adapter for tests and force failure during a bundle build. Assert no new final directory appears, or an existing complete bundle is restored.

- [ ] **Step 3: Run RED**

```bash
npm test -- tests/nds-extraction.test.ts
```

- [ ] **Step 4: Implement streaming atomic range copy**

Use `createReadStream({ start, end })`, `createWriteStream({ flags: "wx" })`, `pipeline()`, then `FileHandle.sync()` and `rename()`. Zero-length files use an empty exclusive temp file. Best-effort remove temp files on error and throw `generated-path-failure`.

Hash the completed artifact with the streaming `hashFileSha256()` helper.

- [ ] **Step 5: Implement deterministic manifest/bundle promotion**

Bundle contents:

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

Build in sibling `<shaPrefix>.tmp-<pid>-<timestamp>`. If final exists, rename it to a backup sibling, promote the complete temp directory, then remove backup. On promotion failure, restore backup before throwing.

Compressed overlay artifacts remain stored/compressed and are marked as such in manifest metadata.

- [ ] **Step 6: Verify PR-B**

```bash
npm test -- tests/nds-resolver.test.ts tests/nds-extraction.test.ts
npm run check
npm run build
```

- [ ] **Step 7: Commit**

```bash
git add src/services/nds/extraction.ts tests/nds-extraction.test.ts
git commit -m "feat: extract validated NDS analysis artifacts"
```

- [ ] **Step 8: Open PR B**

Open **`Add NDS address resolution and controlled extraction`** from `feature/nds-address-extraction` to `main`. Require CI and Package success before integration.

---

### Task 8: Migrate debugger ARM9 range helper without broadening validation

**Files:**
- Modify: `src/services/nds-arm9.ts`
- Modify: `tests/nds-arm9.test.ts`

**Preserved interface:**

```ts
export interface Arm9ExecutableRange {
  readonly start: number;
  readonly end: number;
  readonly size: number;
  readonly source: "arm9-header";
  readonly label: "ARM9 main";
}

export async function readArm9ExecutableRange(romPath: string): Promise<Arm9ExecutableRange>;
```

- [ ] **Step 1: Add compatibility tests**

Keep all existing tests. Add a regression proving malformed unrelated static structures do not make `readArm9ExecutableRange()` fail when the ARM9 header/range is otherwise valid.

```ts
test("ARM9 compatibility helper does not validate unrelated FAT metadata", async () => {
  const fixture = await createNdsFixture({ fatOffset: 0x3ff0, fatSize: 0x100 });
  assert.deepEqual(await readArm9ExecutableRange(fixture.romPath), {
    start: 0x02000000,
    end: 0x02000200,
    size: 0x200,
    source: "arm9-header",
    label: "ARM9 main",
  });
});
```

Also preserve rejection outside `0x02000000..0x02400000`, zero size, 32-bit overflow, and ARM9 bytes beyond EOF.

- [ ] **Step 2: Verify pre-refactor behavior**

```bash
npm test -- tests/nds-arm9.test.ts
```

- [ ] **Step 3: Refactor to `readArm9HeaderMetadata()`**

```ts
const arm9 = await readArm9HeaderMetadata(romPath);
const start = arm9.ramAddress;
const end = arm9.ramEnd;
const size = arm9.size;
```

Apply the existing main-RAM check in `nds-arm9.ts` and return the exact old shape. Do **not** call `readNdsRomMap()` here because that would inherit FAT/FNT/overlay failures that the old debugger helper never enforced.

- [ ] **Step 4: Run compatibility/debugger regression**

```bash
npm test -- tests/nds-arm9.test.ts tests/desmume-debug-tools.test.ts tests/desmume-start-race.test.ts tests/desmume-debug-lifecycle.test.ts
npm run typecheck
```

- [ ] **Step 5: Commit**

```bash
git add src/services/nds-arm9.ts tests/nds-arm9.test.ts
git commit -m "refactor: share canonical ARM9 header decoding"
```

---

### Task 9: Expose exactly seven bounded MCP NDS tools

**Files:**
- Create: `src/tools/nds.ts`
- Create: `tests/nds-tools.test.ts`
- Modify: `src/index.ts`

**Interface:**

```ts
export function registerNdsTools(server: McpServer, config: ServerConfig): void;
```

Tool names:

```text
nds_inspect_rom
nds_list_files
nds_list_overlays
nds_resolve_runtime_address
nds_resolve_rom_offset
nds_extract_component
nds_extract_analysis_bundle
```

Schemas:

```ts
const uint32Schema = z.number().int().min(0).max(0xffffffff);
const romSchema = z.string().min(1);
const processorSchema = z.enum(["arm9", "arm7"]);
const listProcessorSchema = z.enum(["arm9", "arm7", "all"]);
const listLimitSchema = z.number().int().min(1).max(200).default(100);
const listOffsetSchema = z.number().int().min(0).default(0);
```

- [ ] **Step 1: Write RED registration/schema tests**

Capture `server.tool()` calls using the existing fake-server pattern. Assert these seven names and no extra NDS tool. Cover workspace containment, uint32 bounds, pagination defaults/max, processor filters, prefix filtering, and absence of any `output` extraction parameter.

Extraction schema:

```ts
{
  rom: romSchema,
  component: z.enum(["arm9", "arm7", "arm9-overlay", "arm7-overlay", "nitrofs-file"]),
  overlayId: z.number().int().min(0).optional(),
  fileId: z.number().int().min(0).optional(),
  filePath: z.string().min(1).optional(),
}
```

Handler normalization requires no selector for main binaries, `overlayId` only for overlay components, and exactly one of `fileId`/`filePath` for `nitrofs-file`.

- [ ] **Step 2: Write RED behavior/error tests**

Assert ambiguity/BSS/compression statuses are normal successful results. For a thrown `NdsError`, response has:

```json
{
  "error": "...",
  "operation": "nds_...",
  "category": "...",
  "correctiveAction": "..."
}
```

Map non-`NdsError` failures deterministically: ROM inspection/list/resolver handlers use category `invalid-rom`; extraction handlers use `generated-path-failure`. Never expose stack traces.

Test `maxOutputBytes` overflow returns category `output-bound-exceeded` and tells caller to narrow prefix/processor/limit/offset.

- [ ] **Step 3: Run RED**

```bash
npm test -- tests/nds-tools.test.ts
```

- [ ] **Step 4: Implement bounded result helper and seven handlers**

Every handler begins:

```ts
const romPath = resolveInside(config.workspaceRoot, rom);
const map = await readNdsRomMap(romPath);
```

`nds_list_files`: include unnamed entries when prefix is empty; when prefix is non-empty, only named paths that start with prefix match. Sort by file ID, then paginate. Return `{ total, offset, limit, nextOffset, files }`.

`nds_list_overlays`: filter processor first, sort processor then overlay ID, paginate, return matching metadata.

`nds_inspect_rom`: return identity/header/counts/executable ranges but not raw ROM bytes.

Resolvers return structured statuses unchanged.

Extraction passes only `config.workspaceRoot`; callers never choose generated destination.

- [ ] **Step 5: Register in `src/index.ts`**

```ts
import { registerNdsTools } from "./tools/nds.js";
...
registerNdsTools(server, config);
```

Append all seven names to `server_capabilities.tools`. Add `ndsStaticAnalysisPolicy` stating read-only ROM parsing plus controlled generated artifacts. Do not change the debugger policy semantics.

- [ ] **Step 6: Verify GREEN**

```bash
npm test -- tests/nds-tools.test.ts
npm run typecheck
npm run build
```

- [ ] **Step 7: Commit**

```bash
git add src/tools/nds.ts src/index.ts tests/nds-tools.test.ts
git commit -m "feat: expose NDS static analysis MCP tools"
```

---

### Task 10: Document and verify the completed milestone

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Document the seven tools and workflow**

Add an **NDS Static Analysis** section explaining:

```text
nds_inspect_rom
→ nds_list_files / nds_list_overlays
→ nds_resolve_runtime_address / nds_resolve_rom_offset
→ nds_extract_component / nds_extract_analysis_bundle
```

State explicitly:

- source ROM is read-only;
- output is fixed to `analysis/generated/nds/<sha-prefix>/`;
- overlapping overlays are reported, never guessed;
- BSS has no ROM bytes;
- compressed overlay runtime bytes intentionally have no exact ROM-byte mapping;
- compressed overlay extraction returns stored compressed bytes;
- disassembly, Ghidra, watchpoints, and ROM mutation are not part of this milestone.

- [ ] **Step 2: Run focused NDS suite**

```bash
npm test -- tests/nds-header.test.ts tests/nds-fat.test.ts tests/nds-fnt.test.ts tests/nds-overlays.test.ts tests/nds-rom-map.test.ts tests/nds-resolver.test.ts tests/nds-extraction.test.ts tests/nds-tools.test.ts tests/nds-arm9.test.ts
```

- [ ] **Step 3: Run debugger regression suite**

```bash
npm test -- tests/desmume-debug-tools.test.ts tests/desmume-debug-lifecycle.test.ts tests/desmume-start-race.test.ts tests/debug-controller-context.test.ts tests/arm9-registers.test.ts tests/stop-context.test.ts
```

- [ ] **Step 4: Run full verification**

```bash
npm run check
npm run build
```

- [ ] **Step 5: Inspect forbidden-scope diff**

```bash
git diff main...HEAD -- src/services src/tools src/index.ts README.md package.json package-lock.json
```

Confirm no new runtime dependency, watchpoint/register-write/memory-write/arbitrary-GDB tool, debugger execution behavior change, source-ROM write path, arbitrary extraction output path, or raw offset/length MCP extraction primitive.

- [ ] **Step 6: Commit docs**

```bash
git add README.md
git commit -m "docs: document NDS static analysis tools"
```

- [ ] **Step 7: Open PR C**

Open **`Expose NDS static analysis foundation tools`** from `feature/nds-static-mcp-tools` to `main`. Require CI and Package success before integration. PR body must enumerate the seven tools, compression/BSS ambiguity rules, controlled extraction, no new dependencies, no debugger behavior changes, and final workflow evidence.

---

## Final Acceptance Checklist

- [ ] All seven NDS tools are implemented and documented.
- [ ] Header, FAT, FNT, overlay, map, resolver, extraction, tool, and ARM9 compatibility tests pass.
- [ ] Source ROM SHA-256 is unchanged after extraction tests.
- [ ] Every extracted artifact records source and output SHA-256.
- [ ] Generated output is fixed below workspace `analysis/generated/nds/<sha-prefix>/`.
- [ ] No public arbitrary offset/length extraction primitive exists.
- [ ] Compressed runtime overlay bytes have no fabricated direct ROM offset.
- [ ] Compressed overlay backing bytes have no fabricated runtime address.
- [ ] BSS has no ROM offset.
- [ ] Overlapping overlay candidates are never guessed.
- [ ] `readArm9ExecutableRange()` preserves old result shape, main-RAM policy, and narrow validation behavior.
- [ ] Existing DeSmuME debugger regression tests pass.
- [ ] `package.json`/`package-lock.json` add no runtime dependency.
- [ ] `npm run check` passes.
- [ ] `npm run build` passes.
- [ ] GitHub CI passes on each final PR head.
- [ ] GitHub Package workflow passes on each final PR head.
- [ ] Physical Catalina Dynamic Debugging acceptance remains a separate pending gate and is not marked complete by this static milestone.
