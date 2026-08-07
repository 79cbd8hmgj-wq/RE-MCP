# NDS Pattern and Signature Discovery Design

Date: 2026-08-07
Status: Approved design, awaiting written-spec review
Baseline: `main` at `e3769d2756364dd2f2546536b3015e86c7b73473`

## Goal

Add one bounded, deterministic, read-only Nintendo DS static-analysis tool for locating raw byte signatures, typed integer constants, ASCII strings, and UTF-16LE strings inside validated `.nds` ROMs.

The milestone must preserve the repository's existing NDS-aware architecture. It must not expose a generic binary scanner, arbitrary byte buffers, arbitrary start/end ranges, mutation/rebuild behavior, heuristic pointer inference, decompression, or persistent indexing.

The public tool is:

- `nds_search_pattern`

This increases the NDS static-analysis tool count from eleven to twelve.

## Core invariant

Every reported match is an exact, reproducible byte-level fact from the validated NDS ROM.

A pattern hit is not automatically a code reference, pointer, table, function, string resource, or any other higher-level semantic claim. Existing disassembly, CFG, reference, and reverse-xref semantics remain unchanged.

## Architecture

Use one canonical pattern compiler and one bounded NDS-aware scanner.

```text
public typed pattern
    ↓
canonical byte+mask compiler
    ↓
canonical NDS scope resolver
    ↓
bounded streaming matcher
    ↓
canonical hit ownership mapper
    ↓
nds_search_pattern MCP adapter
```

All public pattern kinds compile into one internal representation:

```ts
interface CompiledPattern {
  readonly bytes: Uint8Array;
  readonly mask: Uint8Array; // 0xff = exact, 0x00 = wildcard
  readonly alignment: 1 | 2 | 4;
  readonly sourceKind:
    | "byte-signature"
    | "integer"
    | "ascii"
    | "utf16le";
}
```

This keeps matching, ordering, pagination, context, and truncation semantics identical for every pattern class.

## Public request model

Conceptually:

```ts
interface NdsSearchPatternRequest {
  readonly rom: string;
  readonly pattern: NdsSearchPattern;
  readonly scope: NdsPatternSearchScope;
  readonly offset?: number;
  readonly limit?: number;
  readonly maxScanBytes?: number;
  readonly contextBytes?: number;
}
```

Exactly one pattern is supplied per request.

### Pattern kinds

```ts
type NdsSearchPattern =
  | {
      kind: "byte-signature";
      signature: string;
    }
  | {
      kind: "integer";
      value: number;
      width: 8 | 16 | 32;
      endian: "little" | "big";
      signed: boolean;
      alignment?: 1 | 2 | 4;
    }
  | {
      kind: "ascii";
      text: string;
    }
  | {
      kind: "utf16le";
      text: string;
    };
```

### Byte signatures

Accepted examples:

```text
12 34 56 78
12 34 ?? 78
AA ?? ?? FF
```

Rules:

- concrete bytes are exactly two hexadecimal digits;
- `??` is the only wildcard token;
- tokens are whitespace-separated;
- nibble wildcards such as `A?` are rejected;
- regex, alternation, repetition, and fuzzy syntax are rejected;
- empty signatures are rejected;
- all-wildcard signatures are rejected;
- encoded pattern length must be within the public bound.

Example compilation:

```text
12 34 ?? 78
```

becomes conceptually:

```text
bytes = [0x12, 0x34, 0x00, 0x78]
mask  = [0xff, 0xff, 0x00, 0xff]
```

### Integer constants

Integer searches require explicit:

- width: 8, 16, or 32 bits;
- endianness: little or big;
- signedness.

The supplied value must fit the requested width and signedness exactly.

Examples:

```ts
{ kind: "integer", value: 4660, width: 16, endian: "little", signed: false }
```

compiles to `34 12`.

```ts
{ kind: "integer", value: -1, width: 16, endian: "little", signed: true }
```

compiles to `FF FF`.

No alternate signed/unsigned equivalent search occurs.

Integer alignment defaults to `1`. The caller may explicitly request `1`, `2`, or `4`. Alignment is evaluated against the canonical ROM offset of a candidate hit. Width never implies alignment automatically.

### ASCII strings

ASCII searches encode the supplied text to exact single-byte ASCII.

Rules:

- non-ASCII input is rejected;
- matching is case-sensitive;
- no null terminator is added;
- no normalization or alternate encoding is attempted;
- alignment is `1`.

### UTF-16LE strings

UTF-16LE searches encode the supplied JavaScript string deterministically as UTF-16 little-endian code units.

Rules:

- no null terminator is added;
- matching is exact and case-sensitive;
- no Unicode normalization is performed;
- no alternate encoding is attempted;
- alignment is `1`.

## Search scope

The tool supports either whole-ROM search or a bounded canonical component set.

```ts
type NdsPatternSearchScope =
  | { kind: "whole-rom" }
  | {
      kind: "components";
      arm9Main?: boolean;
      arm7Main?: boolean;
      arm9OverlayIds?: readonly number[];
      arm7OverlayIds?: readonly number[];
      nitroFsFileIds?: readonly number[];
      nitroFsPaths?: readonly string[];
    };
```

A `components` scope must select at least one component.

### Component validation

- overlay IDs must exist for the selected processor;
- NitroFS file IDs must exist;
- NitroFS paths must match an exact parsed path;
- duplicate selectors are canonicalized deterministically;
- no caller-defined arbitrary ROM start/end range is accepted.

### Physical normalization and component boundaries

Selected components may physically overlap because an overlay is FAT-backed and can also have a NitroFS file relationship.

The resolver therefore constructs physical search domains with provenance. Bytes covered by multiple selected relationships are scanned once, and one physical hit is returned once with all valid owners attached.

Adjacent but semantically distinct component ranges are not merged into one matching domain. A pattern may not begin in one component and finish in another merely because the physical ranges are adjacent.

`whole-rom` is the explicit exception: the ROM is one physical search domain, so a pattern may cross structural/component boundaries.

### Compressed overlays

Compressed overlays are valid raw-byte search sources.

The scanner searches their exact stored FAT-backed bytes. It does not decompress them. Hits are marked as belonging to a compressed overlay where applicable, and no runtime-address mapping is fabricated for compressed stored bytes.

This intentionally differs from disassembly/reference analysis, where compressed overlays are not decodable as runtime code.

## Matching semantics

### Exact candidate rule

A candidate start offset matches if, for every pattern byte:

```text
(candidateByte & maskByte) == (patternByte & maskByte)
```

With the current mask model, every byte is either fully exact (`0xff`) or fully wildcard (`0x00`).

### Overlapping matches

Overlapping matches are always returned.

Example:

```text
pattern: AA AA
bytes:   AA AA AA
```

returns starts at offsets `0` and `1` relative to that search domain.

### Alignment

Alignment is checked against the absolute ROM offset of each candidate start.

No component-relative or runtime-address-relative alignment rule is inferred.

### Boundary behavior

For component scopes, every candidate must fit entirely inside one canonical physical search domain. Internal I/O chunk boundaries do not count as semantic boundaries.

For whole-ROM scope, every candidate must fit entirely inside the ROM file.

## Streaming implementation

The scanner must be chunked/streaming and must not require buffering the full ROM.

When a pattern can cross an internal I/O chunk boundary, the matcher carries the final `patternLength - 1` bytes from the previous chunk into the next matching window.

Carry bytes are bookkeeping only:

- they are not double-counted in `scannedBytes`;
- duplicate candidate starts are not emitted;
- component-domain boundaries are still enforced.

## Result model

Each physical match is returned once in ascending ROM-offset order.

Conceptually:

```ts
interface NdsPatternHit {
  readonly romOffset: number;
  readonly endOffset: number;
  readonly length: number;
  readonly bytesHex: string;
  readonly owners: readonly NdsPatternOwner[];
  readonly context?: {
    readonly beforeHex: string;
    readonly afterHex: string;
    readonly clippedAtStart: boolean;
    readonly clippedAtEnd: boolean;
  };
}
```

### Ownership

`owners` records all deterministic canonical relationships available from the validated `NdsRomMap`, not only the selector that caused the bytes to be searched.

Owner kinds may include:

- ARM9 main;
- ARM7 main;
- ARM9 overlay stored bytes;
- ARM7 overlay stored bytes;
- NitroFS/FAT file;
- validated header-metadata bytes currently parsed by the NDS header parser;
- FNT region;
- FAT region;
- ARM9 overlay-table region;
- ARM7 overlay-table region;
- otherwise `unmapped`.

Where an owner has a deterministic direct ROM-to-runtime mapping, the owner includes the runtime address for the hit start.

For an uncompressed main executable or uncompressed overlay, runtime mapping is derived only from the already validated direct file-backed relationship.

Compressed-overlay stored bytes do not receive a fabricated runtime address.

### Banner ownership clarification

The current `NdsRomMap` validates only `bannerOffset`; it does not expose a validated banner size/range. The pattern milestone must therefore **not invent a banner extent** from that offset alone.

A hit near or after `bannerOffset` remains described by other proven owners or `unmapped` unless a future separately designed parser adds a validated banner range.

This tightens the approved design's original banner-owner idea to preserve the repository's no-guessing invariant.

### Ambiguous/overlapping ownership

Multiple owners are preserved rather than collapsed or guessed away.

For example, one FAT-backed physical range may be both:

- the stored bytes for an overlay; and
- a NitroFS/FAT file relationship.

The hit is still emitted once, with both owners.

## Pagination and status

`offset` is a **match index**, not a ROM byte offset.

Recommended public/default bounds:

```text
limit:          100 default / 1000 max
offset:         0 default / < 100000
contextBytes:   0 default / 64 max each side
maxScanBytes:   64 MiB default / 512 MiB max
patternLength:  1..4096 encoded bytes
```

Component-scope selector bounds:

- at most 128 overlay selectors total;
- at most 256 NitroFS selectors total;
- after resolution, at most 256 distinct canonical physical search domains.

A separate internal discovered-match ceiling is 100,000.

Conceptually:

```ts
interface NdsPatternSearchResult {
  readonly status: "complete" | "truncated";
  readonly truncationReasons: readonly (
    | "scan-byte-limit"
    | "match-count-limit"
  )[];
  readonly offset: number;
  readonly limit: number;
  readonly nextOffset: number | null;
  readonly scannedBytes: number;
  readonly discoveredMatches: number;
  readonly matches: readonly NdsPatternHit[];
}
```

### Complete result

`status === "complete"` means every byte in every selected search domain was examined for every candidate start that could fully contain the pattern.

A zero-hit result is definitive only when `status === "complete"`.

### Scan-byte truncation

If `maxScanBytes` prevents examination of the complete selected scope:

```text
status = "truncated"
truncationReasons includes "scan-byte-limit"
```

Only candidate starts whose entire pattern lies in the examined prefix are eligible. A partial candidate at the scan-budget boundary is not reported.

`offset` pagination does not act as a ROM-scan continuation cursor. If a scan is truncated by `maxScanBytes`, increasing `offset` alone cannot reveal bytes beyond the examined prefix. The caller must raise `maxScanBytes` or narrow/change the scope.

### Match-count truncation

If 100,000 discovered matches are reached, scanning stops and:

```text
status = "truncated"
truncationReasons includes "match-count-limit"
```

The scanner never silently drops an unbounded number of known hits.

### `nextOffset`

`nextOffset` is non-null only when the current scan has already discovered additional matches after the returned page.

It does not claim that undiscovered matches exist beyond a scan-byte or match-count truncation boundary.

Therefore a truncated result may legitimately have `nextOffset: null` while still having incomplete coverage.

## Context bytes

`contextBytes` defaults to `0` and is capped at 64 bytes before and after each returned hit.

Context is informational only:

- it does not change match identity;
- it does not affect `scannedBytes`;
- it counts toward the repository-wide serialized output ceiling;
- it is clipped to the component search-domain boundary for component-scoped searches;
- it is clipped only to ROM bounds for whole-ROM searches.

Component-scoped context never leaks into an adjacent component.

## Source integrity

Pattern search follows the static-analysis source-integrity model:

1. validate/parse the NDS ROM and obtain its SHA-256;
2. perform the bounded search against that path;
3. hash the ROM again before returning;
4. reject the result if the hash changed.

A result must never combine bytes from two source revisions.

The implementation should reuse the same hash helpers/integrity conventions already used by NDS extraction/static-analysis services rather than create an unrelated mechanism.

## Errors

Extend `src/services/nds/errors.ts` with a focused pattern-search union:

```ts
type NdsPatternSearchErrorCategory =
  | "invalid-pattern"
  | "invalid-pattern-scope"
  | "pattern-search-limit-exceeded";
```

Examples:

- malformed signature such as `12 GG ??` -> `invalid-pattern`;
- empty/all-wildcard signature -> `invalid-pattern`;
- integer outside requested width/signedness -> `invalid-pattern`;
- non-ASCII input for ASCII search -> `invalid-pattern`;
- structurally invalid component selector combination -> `invalid-pattern-scope`;
- invalid public bounds -> `pattern-search-limit-exceeded`;
- missing NitroFS file -> existing `unknown-file-id`;
- missing overlay -> existing `unknown-overlay-id`;
- malformed ROM metadata -> existing NDS structural error categories;
- repository-wide serialized output overflow -> existing `output-bound-exceeded`.

No scanner-specific replacement should be invented for an error already represented by the existing NDS error taxonomy.

## Security and capability boundary

The milestone remains read-only and NDS-specific.

It must not expose:

- arbitrary binary paths outside the validated NDS ROM flow;
- caller-supplied raw byte buffers;
- arbitrary caller-defined ROM offset ranges;
- caller-defined base/runtime addresses;
- arbitrary output paths;
- file mutation;
- ROM rebuilding;
- generic memory search;
- DeSmuME runtime search;
- decompression;
- regex/fuzzy search;
- pointer/reference inference from matched values;
- persistent signature storage/indexing.

The input ROM path remains subject to the existing workspace-root path policy.

## Proposed production boundaries

Conceptual files:

```text
src/services/nds/patterns.ts
src/services/nds/pattern-scope.ts
src/services/nds/pattern-search.ts
src/services/nds/errors.ts
src/tools/nds.ts
```

Responsibilities:

### `patterns.ts`

- validate/compile the four public pattern kinds;
- encode integer/string inputs;
- provide one canonical byte+mask model;
- contain no ROM traversal logic.

### `pattern-scope.ts`

- resolve canonical NDS selectors;
- construct bounded physical search domains with provenance;
- validate selector limits;
- preserve semantic boundaries while deduplicating physical overlap.

### `pattern-search.ts`

- stream bytes from validated search domains;
- perform exact/masked matching;
- enforce alignment;
- preserve overlapping matches;
- enforce scan/match limits;
- collect requested page/context;
- map deterministic ownership;
- verify source integrity before return.

### `errors.ts`

- add pattern-search error categories to the existing NDS error model.

### `tools/nds.ts`

- register `nds_search_pattern`;
- define bounded Zod schemas;
- normalize request shape;
- reuse standard NDS tool error/output handling;
- expose no generic binary/range/output-path fields.

## Non-regression boundaries

This milestone must not modify the semantics of:

- Capstone decoding;
- ARM/Thumb disassembly;
- control-flow analysis;
- proven-reference classification;
- reverse-xref traversal;
- extraction;
- DeSmuME GDB/controller/runtime support.

Physical Intel Catalina/DeSmuME acceptance remains separate and is not required for this native-independent milestone.

## Test-driven acceptance matrix

Implementation must be TDD-first and cover at minimum:

### Pattern compilation

- exact byte signatures;
- wildcard signatures;
- malformed tokens;
- empty signature rejection;
- all-wildcard rejection;
- encoded pattern-length bounds;
- 8/16/32-bit little-endian constants;
- 8/16/32-bit big-endian constants;
- signed minimum/maximum validation;
- unsigned minimum/maximum validation;
- explicit alignment 1/2/4;
- exact ASCII encoding;
- non-ASCII rejection;
- exact UTF-16LE encoding;
- no implicit string terminators;
- no case folding/normalization.

### Scope resolution

- ARM9 main;
- ARM7 main;
- multiple explicit ARM9 overlays;
- multiple explicit ARM7 overlays;
- compressed overlay stored bytes;
- NitroFS file ID;
- exact NitroFS path;
- combined component scopes;
- duplicate selector canonicalization;
- overlapping physical relationship deduplication;
- invalid/empty component scope;
- unknown file/overlay selectors;
- selector/domain caps.

### Matcher

- exact matches;
- wildcard matches;
- overlapping matches;
- alignment filtering;
- chunk-boundary matches;
- no duplicate chunk-boundary matches;
- no component-boundary crossing;
- allowed whole-ROM structural-boundary crossing;
- ascending ROM-offset ordering;
- scan-byte accounting without carry-byte double count.

### Pagination/truncation

- complete first page;
- complete later page;
- deterministic repeated requests;
- `nextOffset` only for already discovered later matches;
- scan-byte truncation;
- match-count truncation;
- truncated result with `nextOffset: null`;
- zero hits definitive only when complete;
- candidate excluded when pattern is incomplete at scan-budget boundary.

### Ownership/context

- main executable runtime mapping;
- uncompressed overlay runtime mapping;
- compressed overlay owner without fabricated runtime mapping;
- NitroFS/FAT owner;
- multiple owners on one physical hit;
- FNT/FAT/overlay-table/header-metadata ownership where validated;
- unmapped ownership fallback;
- context clipping at component start/end;
- context crossing ordinary internal I/O chunks;
- whole-ROM context clipping only at ROM bounds;
- context output-ceiling interaction.

### Integrity/tool surface

- ROM SHA change rejection;
- workspace-root path enforcement;
- repository-wide serialized output ceiling;
- exactly twelve NDS tool registrations after addition;
- tool description/capability declaration;
- forbidden arbitrary binary input fields absent;
- forbidden arbitrary start/end range fields absent;
- forbidden arbitrary output-path fields absent.

## Packaged acceptance

Extend the assembled-package smoke path so the compiled production artifact, not source-tree fixtures, proves that it can:

1. import the compiled pattern/search services;
2. compile at least one exact/wildcard pattern;
3. search a tiny synthetic valid NDS fixture;
4. return deterministic overlapping matches;
5. return deterministic canonical ownership metadata.

The package smoke must not depend on native Capstone behavior for this feature, although the existing disassembly/reference package smokes remain intact.

## Explicitly deferred

The following are intentionally outside this milestone:

- regex text search;
- fuzzy or case-insensitive search;
- automatic string discovery;
- nibble wildcards;
- multi-pattern batches;
- signature databases;
- persistent pattern/xref indexes;
- pointer inference from matched constants;
- literal-loaded value inference;
- decompressed-overlay searching;
- arbitrary include/exclude byte ranges;
- generic binary input;
- ROM mutation/rebuild;
- runtime memory scanning.

## Success criteria

The milestone is complete when:

1. `nds_search_pattern` is the twelfth registered NDS static tool;
2. all four approved pattern classes compile deterministically into one canonical matcher representation;
3. canonical components and explicit whole-ROM scope both work within bounds;
4. component scopes never allow cross-component matches;
5. whole-ROM scope can cross structural boundaries;
6. overlapping matches are preserved;
7. physical duplicate hits are emitted once with all proven owners;
8. compressed overlays are searched only as stored bytes;
9. pagination, scan limits, match limits, and context have explicit deterministic semantics;
10. source integrity is verified before return;
11. no generic binary/mutation/runtime-search surface is added;
12. unit/integration/tool/package acceptance tests pass;
13. physical Catalina/DeSmuME acceptance remains a separate concern.
