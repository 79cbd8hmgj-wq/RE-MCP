import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import {
  MAX_NDS_REBUILD_GROWTH_BYTES,
  NDS_REBUILD_CONTRACT_VERSION,
  finalizeNdsRebuildLayout,
  planNdsPayloadLayout,
  type NdsPayloadLayoutInput,
} from "../src/services/nds/mutation/layout.js";

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function payload(
  kind: "relocated-file" | "new-file",
  fileId: number,
  size: number,
): NdsPayloadLayoutInput {
  const bytes = Buffer.alloc(size, fileId & 0xff);
  return {
    kind,
    ownerId: `${kind}:${fileId}`,
    fileId,
    bytes,
    sha256: sha256(bytes),
  };
}

function fakeBufferLength(length: number): Buffer {
  return { length } as Buffer;
}

function assertCategory(operation: () => unknown, expected: string): void {
  assert.throws(operation, (error: unknown) => {
    assert.ok(error instanceof NdsError);
    assert.equal(error.category, expected);
    return true;
  });
}

test("payload layout is deterministic, append-only, and ordered by class then file ID", () => {
  const sourceSize = 0x6101;
  const inputs = [
    payload("new-file", 12, 0x33),
    payload("relocated-file", 4, 0x21),
    payload("new-file", 10, 0x10),
    payload("relocated-file", 2, 0x18),
  ];

  const first = planNdsPayloadLayout(sourceSize, inputs);
  const second = planNdsPayloadLayout(sourceSize, [...inputs].reverse());

  assert.equal(NDS_REBUILD_CONTRACT_VERSION, 1);
  assert.deepEqual(
    Object.keys(first).sort(),
    ["nextOffset", "segments", "sourceSize", "tailStart"],
  );
  assert.equal(first.sourceSize, sourceSize);
  assert.equal(first.tailStart, 0x6200);
  assert.deepEqual(
    first.segments.map((segment) => [segment.kind, segment.ownerId]),
    [
      ["relocated-file", "relocated-file:2"],
      ["relocated-file", "relocated-file:4"],
      ["new-file", "new-file:10"],
      ["new-file", "new-file:12"],
    ],
  );
  assert.deepEqual(
    first.segments.map((segment) => [segment.kind, segment.ownerId, segment.start, segment.end]),
    second.segments.map((segment) => [segment.kind, segment.ownerId, segment.start, segment.end]),
  );
  for (const segment of first.segments) {
    assert.equal(segment.alignment, 0x200);
    assert.equal(segment.start % 0x200, 0);
    assert.equal(segment.end - segment.start, segment.size);
    assert.equal(segment.sha256, sha256(segment.bytes));
  }
});

test("metadata follows payloads in canonical order with four-byte alignment", () => {
  const payloadLayout = planNdsPayloadLayout(0x6000, [payload("relocated-file", 0, 0x31)]);
  const fnt = Buffer.from("fnt-table");
  const fat = Buffer.from("fat-table-contents");
  const arm9 = Buffer.alloc(64, 0x91);
  const arm7 = Buffer.alloc(32, 0x71);
  const layout = finalizeNdsRebuildLayout(payloadLayout, {
    fnt,
    fat,
    arm9OverlayTable: arm9,
    arm7OverlayTable: arm7,
  });

  assert.deepEqual(
    layout.segments.map((segment) => segment.kind),
    ["relocated-file", "fnt", "fat", "arm9-overlay-table", "arm7-overlay-table"],
  );
  for (const segment of layout.segments.slice(1)) {
    assert.equal(segment.alignment, 4);
    assert.equal(segment.start % 4, 0);
    assert.equal(segment.sha256, sha256(segment.bytes));
  }
  const meaningfulEnd = layout.segments.at(-1)!.end;
  assert.equal(layout.logicalUsedSize, meaningfulEnd);
  assert.ok(layout.finalSize >= meaningfulEnd);
  assert.equal(layout.finalSize, 128 * 1024);
  assert.equal(layout.deviceCapacity, 0);
});

test("metadata layout omits optional tables without creating phantom segments", () => {
  const payloadLayout = planNdsPayloadLayout(0x6000, []);
  const fat = Buffer.alloc(24, 0xf0);
  const layout = finalizeNdsRebuildLayout(payloadLayout, { fat });

  assert.deepEqual(layout.segments.map((segment) => segment.kind), ["fat"]);
  assert.equal(layout.segments[0]!.start % 4, 0);
});

test("layout rejects an artifact above 64 MiB without allocating it", () => {
  assertCategory(
    () => planNdsPayloadLayout(0x6000, [{
      kind: "relocated-file",
      ownerId: "relocated-file:0",
      fileId: 0,
      bytes: fakeBufferLength((64 * 1024 * 1024) + 1),
      sha256: "0".repeat(64),
    }]),
    "rebuild-layout-overflow",
  );
});

test("layout rejects aggregate new-file payload above 64 MiB without allocating it", () => {
  const half = 32 * 1024 * 1024;
  assertCategory(
    () => planNdsPayloadLayout(0x6000, [
      {
        kind: "new-file",
        ownerId: "new-file:10",
        fileId: 10,
        bytes: fakeBufferLength(half + 1),
        sha256: "1".repeat(64),
      },
      {
        kind: "new-file",
        ownerId: "new-file:11",
        fileId: 11,
        bytes: fakeBufferLength(half),
        sha256: "2".repeat(64),
      },
    ]),
    "rebuild-layout-overflow",
  );
});

test("layout rejects FNT and FAT above 4 MiB without allocating them", () => {
  const payloadLayout = planNdsPayloadLayout(0x6000, []);
  for (const key of ["fnt", "fat"] as const) {
    const metadata = {
      fat: Buffer.alloc(8),
      [key]: fakeBufferLength((4 * 1024 * 1024) + 1),
    };
    assertCategory(
      () => finalizeNdsRebuildLayout(payloadLayout, metadata),
      "rebuild-layout-overflow",
    );
  }
});

test("layout rejects unsafe source geometry, growth above 128 MiB, and capacity overflow", () => {
  assertCategory(
    () => planNdsPayloadLayout(Number.MAX_SAFE_INTEGER, []),
    "rebuild-layout-overflow",
  );

  const growthBytes = fakeBufferLength(MAX_NDS_REBUILD_GROWTH_BYTES + 1);
  assertCategory(
    () => planNdsPayloadLayout(128 * 1024, [{
      kind: "relocated-file",
      ownerId: "relocated-file:0",
      fileId: 0,
      bytes: growthBytes,
      sha256: "3".repeat(64),
    }]),
    "rebuild-layout-overflow",
  );

  const nearLimit = planNdsPayloadLayout((512 * 1024 * 1024) - 0x200, []);
  assertCategory(
    () => finalizeNdsRebuildLayout(nearLimit, { fat: Buffer.alloc(0x400) }),
    "rom-capacity-exceeded",
  );
});
