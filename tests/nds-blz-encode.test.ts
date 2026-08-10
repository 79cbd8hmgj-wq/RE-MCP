import assert from "node:assert/strict";
import test from "node:test";

import {
  decodeNdsBlz,
  encodeNdsBlz,
} from "../src/services/nds/blz.js";
import { NdsError } from "../src/services/nds/errors.js";
import {
  COMPRESSED_ARM_CODE_DECODED,
} from "./helpers/nds-compressed-code-fixture.js";

function assertCategory(
  operation: () => unknown,
  expected: "blz-output-limit" | "blz-recompression-failed",
): void {
  assert.throws(operation, (error: unknown) => {
    assert.ok(error instanceof NdsError);
    assert.equal(error.category, expected);
    return true;
  });
}

test("NDS BLZ recompression is deterministic and round-trips exact runtime bytes", () => {
  const first = encodeNdsBlz(COMPRESSED_ARM_CODE_DECODED);
  const second = encodeNdsBlz(COMPRESSED_ARM_CODE_DECODED);

  assert.deepEqual(first.bytes, second.bytes);
  assert.equal(first.decodedSize, COMPRESSED_ARM_CODE_DECODED.length);
  assert.equal(first.storedSize, first.bytes.length);
  assert.ok(first.storedSize < first.decodedSize);
  assert.ok(first.headerSize >= 8 && first.headerSize <= 11);
  assert.ok(first.encodedRegionSize > 0);
  assert.ok(first.passthroughSize >= 0);

  const decoded = decodeNdsBlz(first.bytes, COMPRESSED_ARM_CODE_DECODED.length);
  assert.deepEqual(decoded.bytes, COMPRESSED_ARM_CODE_DECODED);
});

test("NDS BLZ recompression emits self-consistent canonical footer geometry", () => {
  const result = encodeNdsBlz(COMPRESSED_ARM_CODE_DECODED);
  const footerOffset = result.bytes.length - 8;
  const compressedLengthAndHeader = result.bytes.readUInt32LE(footerOffset);
  const compressedLength = compressedLengthAndHeader & 0x00ff_ffff;
  const headerSize = compressedLengthAndHeader >>> 24;
  const extraSize = result.bytes.readUInt32LE(footerOffset + 4);

  assert.equal(headerSize, result.headerSize);
  assert.equal(compressedLength, result.encodedRegionSize + result.headerSize);
  assert.equal(result.passthroughSize, result.bytes.length - compressedLength);
  assert.equal(result.bytes.length + extraSize, result.decodedSize);
  assert.equal(result.bytes.length % 4, 0);

  const paddingStart = result.bytes.length - result.headerSize;
  for (let offset = paddingStart; offset < footerOffset; offset += 1) {
    assert.equal(result.bytes[offset], 0xff);
  }
});

test("NDS BLZ recompression rejects decoded input above the configured limit", () => {
  assertCategory(
    () => encodeNdsBlz(COMPRESSED_ARM_CODE_DECODED, {
      maxStoredBytes: 16 * 1024 * 1024,
      maxDecodedBytes: COMPRESSED_ARM_CODE_DECODED.length - 1,
    }),
    "blz-output-limit",
  );
});

test("NDS BLZ recompression rejects a compressed result above the configured stored limit", () => {
  const baseline = encodeNdsBlz(COMPRESSED_ARM_CODE_DECODED);

  assertCategory(
    () => encodeNdsBlz(COMPRESSED_ARM_CODE_DECODED, {
      maxStoredBytes: baseline.storedSize - 1,
      maxDecodedBytes: COMPRESSED_ARM_CODE_DECODED.length,
    }),
    "blz-output-limit",
  );
});

test("NDS BLZ recompression fails closed when canonical compressed form is not smaller", () => {
  const incompressible = Buffer.from(Array.from({ length: 64 }, (_, index) => index));

  assertCategory(
    () => encodeNdsBlz(incompressible),
    "blz-recompression-failed",
  );
});

test("NDS BLZ recompression uses overlapping matches for large repetitive images", () => {
  const decoded = Buffer.alloc(512 * 1024, 0xa5);
  const result = encodeNdsBlz(decoded);

  assert.ok(
    result.storedSize < decoded.length / 4,
    `expected repetitive image to compress below 25%, got ${result.storedSize}/${decoded.length}`,
  );
  assert.deepEqual(decodeNdsBlz(result.bytes, decoded.length).bytes, decoded);
});
