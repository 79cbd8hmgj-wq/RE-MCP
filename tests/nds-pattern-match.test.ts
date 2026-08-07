import assert from "node:assert/strict";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import {
  scanNdsPatternMatches,
  type NdsPatternReadAt,
} from "../src/services/nds/pattern-match.js";
import {
  type NdsPatternComponent,
  type ResolvedNdsPatternScope,
} from "../src/services/nds/pattern-scope.js";
import { compileNdsPattern } from "../src/services/nds/patterns.js";

function memoryReader(buffer: Buffer): NdsPatternReadAt {
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

function fileComponent(
  key: string,
  start: number,
  end: number,
  fileId: number,
): NdsPatternComponent {
  return {
    key,
    kind: "nitrofs-file",
    start,
    end,
    processor: null,
    overlayId: null,
    fileId,
    path: `${key}.bin`,
    compressed: false,
  };
}

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
  assert.equal(result.discoveredMatches, 2);
  assert.equal(result.scannedBytes, 3);
  assert.equal(result.status, "complete");
  assert.deepEqual(result.truncationReasons, []);
});

test("matches wildcard signatures across chunk boundaries without duplicates", async () => {
  const bytes = Buffer.from([0x00, 0xaa, 0x44, 0xbb, 0x00]);
  const result = await scanNdsPatternMatches(
    wholeRomScope(bytes.length),
    compileNdsPattern({ kind: "byte-signature", signature: "AA ?? BB" }),
    memoryReader(bytes),
    { offset: 0, limit: 10, maxScanBytes: bytes.length },
    2,
  );
  assert.deepEqual(result.matchOffsets, [1]);
  assert.equal(result.scannedBytes, bytes.length);
});

test("does not carry a candidate across disconnected physical ranges", async () => {
  const bytes = Buffer.from([0xaa, 0x00, 0xbb, 0x00, 0xaa, 0xbb]);
  const scope: ResolvedNdsPatternScope = {
    kind: "components",
    components: [
      fileComponent("left", 0, 1, 0),
      fileComponent("right", 2, 3, 1),
      fileComponent("pair", 4, 6, 2),
    ],
    physicalRanges: [
      { start: 0, end: 1 },
      { start: 2, end: 3 },
      { start: 4, end: 6 },
    ],
  };
  const result = await scanNdsPatternMatches(
    scope,
    compileNdsPattern({ kind: "byte-signature", signature: "AA BB" }),
    memoryReader(bytes),
    { offset: 0, limit: 10, maxScanBytes: 4 },
    1,
  );
  assert.deepEqual(result.matchOffsets, [4]);
  assert.equal(result.scannedBytes, 4);
});

test("rejects adjacent-component bridges but allows whole-ROM bridges", async () => {
  const bytes = Buffer.from([0x00, 0xbb, 0xcc, 0x00]);
  const adjacentScope: ResolvedNdsPatternScope = {
    kind: "components",
    components: [
      fileComponent("file:0", 0, 2, 0),
      fileComponent("file:1", 2, 4, 1),
    ],
    physicalRanges: [{ start: 0, end: 4 }],
  };
  const pattern = compileNdsPattern({ kind: "byte-signature", signature: "BB CC" });
  const componentResult = await scanNdsPatternMatches(
    adjacentScope,
    pattern,
    memoryReader(bytes),
    { offset: 0, limit: 10, maxScanBytes: 4 },
    2,
  );
  assert.deepEqual(componentResult.matchOffsets, []);

  const wholeResult = await scanNdsPatternMatches(
    wholeRomScope(4),
    pattern,
    memoryReader(bytes),
    { offset: 0, limit: 10, maxScanBytes: 4 },
    2,
  );
  assert.deepEqual(wholeResult.matchOffsets, [1]);
});

test("keeps matches valid across internal provenance edges when one component contains the span", async () => {
  const bytes = Buffer.from([0x00, 0xbb, 0xcc, 0x00, 0x00, 0x00]);
  const scope: ResolvedNdsPatternScope = {
    kind: "components",
    components: [
      fileComponent("wide", 0, 4, 0),
      fileComponent("overlap", 2, 6, 1),
    ],
    physicalRanges: [{ start: 0, end: 6 }],
  };
  const result = await scanNdsPatternMatches(
    scope,
    compileNdsPattern({ kind: "byte-signature", signature: "BB CC" }),
    memoryReader(bytes),
    { offset: 0, limit: 10, maxScanBytes: 6 },
    2,
  );
  assert.deepEqual(result.matchOffsets, [1]);
});

test("applies integer alignment to absolute ROM offsets", async () => {
  const bytes = Buffer.alloc(12);
  bytes.set([0x34, 0x12], 5);
  bytes.set([0x34, 0x12], 8);
  const componentScope: ResolvedNdsPatternScope = {
    kind: "components",
    components: [fileComponent("aligned", 5, 10, 0)],
    physicalRanges: [{ start: 5, end: 10 }],
  };
  const pattern = compileNdsPattern({
    kind: "integer",
    value: 0x1234,
    width: 16,
    endian: "little",
    signed: false,
    alignment: 2,
  });
  const result = await scanNdsPatternMatches(
    componentScope,
    pattern,
    memoryReader(bytes),
    { offset: 0, limit: 10, maxScanBytes: 5 },
    2,
  );
  assert.deepEqual(result.matchOffsets, [8]);
});

test("paginates discovered matches deterministically", async () => {
  const bytes = Buffer.alloc(5, 0xaa);
  const result = await scanNdsPatternMatches(
    wholeRomScope(bytes.length),
    compileNdsPattern({ kind: "byte-signature", signature: "AA" }),
    memoryReader(bytes),
    { offset: 2, limit: 2, maxScanBytes: 5 },
    2,
  );
  assert.deepEqual(result.matchOffsets, [2, 3]);
  assert.equal(result.discoveredMatches, 5);
  assert.equal(result.nextOffset, 4);
  assert.equal(result.status, "complete");
});

test("marks scan-byte truncation and excludes incomplete boundary candidates", async () => {
  const bytes = Buffer.from([0xaa, 0xbb, 0xaa, 0xbb, 0xaa]);
  const result = await scanNdsPatternMatches(
    wholeRomScope(bytes.length),
    compileNdsPattern({ kind: "byte-signature", signature: "AA BB" }),
    memoryReader(bytes),
    { offset: 0, limit: 10, maxScanBytes: 3 },
    2,
  );
  assert.deepEqual(result.matchOffsets, [0]);
  assert.equal(result.scannedBytes, 3);
  assert.equal(result.status, "truncated");
  assert.deepEqual(result.truncationReasons, ["scan-byte-limit"]);
  assert.equal(result.nextOffset, null);
});

test("stops at the 100000 discovered-match ceiling", async () => {
  const bytes = Buffer.alloc(100001, 0xaa);
  const result = await scanNdsPatternMatches(
    wholeRomScope(bytes.length),
    compileNdsPattern({ kind: "byte-signature", signature: "AA" }),
    memoryReader(bytes),
    { offset: 99998, limit: 2, maxScanBytes: bytes.length },
    4096,
  );
  assert.equal(result.discoveredMatches, 100000);
  assert.deepEqual(result.matchOffsets, [99998, 99999]);
  assert.equal(result.status, "truncated");
  assert.deepEqual(result.truncationReasons, ["match-count-limit"]);
  assert.equal(result.nextOffset, null);
});

test("rejects matcher options outside hard bounds", async () => {
  const pattern = compileNdsPattern({ kind: "byte-signature", signature: "AA" });
  for (const options of [
    { offset: -1, limit: 1, maxScanBytes: 1 },
    { offset: 100000, limit: 1, maxScanBytes: 1 },
    { offset: 0, limit: 0, maxScanBytes: 1 },
    { offset: 0, limit: 1001, maxScanBytes: 1 },
    { offset: 0, limit: 1, maxScanBytes: 0 },
    { offset: 0, limit: 1, maxScanBytes: 512 * 1024 * 1024 + 1 },
  ] as const) {
    await assert.rejects(
      scanNdsPatternMatches(wholeRomScope(1), pattern, memoryReader(Buffer.from([0xaa])), options),
      (error) => error instanceof NdsError && error.category === "pattern-search-limit-exceeded",
    );
  }
});
