import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { decodeNdsBlz } from "../src/services/nds/blz.js";
import {
  NDS_BLZ_ENCODER_CONTRACT_VERSION,
  encodeNdsBlz,
} from "../src/services/nds/blz-encode.js";
import { NdsError } from "../src/services/nds/errors.js";
import {
  COMPRESSED_ARM_CODE_DECODED,
} from "./helpers/nds-compressed-code-fixture.js";

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function assertCategory(
  operation: () => unknown,
  expected: "blz-encode-failed" | "blz-output-limit",
): void {
  assert.throws(operation, (error: unknown) => {
    assert.ok(error instanceof NdsError);
    assert.equal(error.category, expected);
    return true;
  });
}

function assertDeterministicRoundTrip(runtime: Buffer): void {
  const first = encodeNdsBlz(runtime);
  const second = encodeNdsBlz(runtime);

  assert.equal(NDS_BLZ_ENCODER_CONTRACT_VERSION, 1);
  assert.equal(first.contractVersion, 1);
  assert.deepEqual(first.bytes, second.bytes);
  assert.equal(first.storedSize, first.bytes.length);
  assert.equal(first.runtimeSize, runtime.length);
  assert.equal(first.storedSha256, sha256(first.bytes));
  assert.equal(first.runtimeSha256, sha256(runtime));
  assert.ok(first.storedSize < first.runtimeSize);
  assert.deepEqual(decodeNdsBlz(first.bytes, runtime.length).bytes, runtime);
}

test("NDS BLZ encoder is deterministic for the current decoded overlay fixture", () => {
  assertDeterministicRoundTrip(COMPRESSED_ARM_CODE_DECODED);
});

test("NDS BLZ encoder is deterministic for repeated zero bytes", () => {
  assertDeterministicRoundTrip(Buffer.alloc(4096));
});

test("NDS BLZ encoder is deterministic for a repeated 16-byte pattern", () => {
  const pattern = Buffer.from("00112233445566778899aabbccddeeff", "hex");
  assertDeterministicRoundTrip(Buffer.concat(Array.from({ length: 256 }, () => pattern)));
});

test("NDS BLZ encoder uses the smallest displacement for equal longest matches", () => {
  const runtime = Buffer.from("ABC".repeat(16), "ascii");
  const result = encodeNdsBlz(runtime);

  assert.equal(
    result.bytes.toString("hex"),
    "006000f000f04142431cffff1400000a1c000000",
  );
  assert.deepEqual(decodeNdsBlz(result.bytes, runtime.length).bytes, runtime);
});

test("NDS BLZ encoder rejects empty runtime input", () => {
  assertCategory(() => encodeNdsBlz(Buffer.alloc(0)), "blz-encode-failed");
});

test("NDS BLZ encoder rejects runtime input above the configured decoded limit", () => {
  assertCategory(
    () => encodeNdsBlz(COMPRESSED_ARM_CODE_DECODED, {
      maxStoredBytes: 16 * 1024 * 1024,
      maxDecodedBytes: COMPRESSED_ARM_CODE_DECODED.length - 1,
    }),
    "blz-output-limit",
  );
});

test("NDS BLZ encoder rejects a valid compressed result above the configured stored limit", () => {
  const baseline = encodeNdsBlz(COMPRESSED_ARM_CODE_DECODED);

  assertCategory(
    () => encodeNdsBlz(COMPRESSED_ARM_CODE_DECODED, {
      maxStoredBytes: baseline.storedSize - 1,
      maxDecodedBytes: COMPRESSED_ARM_CODE_DECODED.length,
    }),
    "blz-output-limit",
  );
});

test("NDS BLZ encoder fails closed when no encoded suffix is smaller", () => {
  const literalHeavy = Buffer.from(Array.from({ length: 64 }, (_, index) => index));
  assertCategory(() => encodeNdsBlz(literalHeavy), "blz-encode-failed");
});

test("NDS BLZ encoder supports overlapping back-references", () => {
  const prefix = Buffer.from(Array.from({ length: 64 }, (_, index) => index));
  const repeatedSuffix = Buffer.alloc(32, 0xa5);
  const runtime = Buffer.concat([prefix, repeatedSuffix]);

  assertDeterministicRoundTrip(runtime);
});
