import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  DEFAULT_NDS_BLZ_LIMITS,
  decodeNdsBlz,
} from "../src/services/nds/blz.js";
import { NdsError } from "../src/services/nds/errors.js";

const FIXTURE_ROOT = fileURLToPath(new URL("./fixtures/nds-blz/", import.meta.url));

type ExpectedBlzCategory =
  | "malformed-blz"
  | "blz-output-size-mismatch"
  | "blz-output-limit";

async function fixture(name: string): Promise<Buffer> {
  return readFile(path.join(FIXTURE_ROOT, name));
}

function assertCategory(
  operation: () => unknown,
  expected: ExpectedBlzCategory,
): void {
  assert.throws(operation, (error: unknown) => {
    assert.ok(error instanceof NdsError);
    assert.equal(error.category, expected);
    return true;
  });
}

const GOLDEN_CASES = [
  "literal-only",
  "backreference",
  "mixed-groups",
  "uncompressed-prefix",
] as const;

for (const name of GOLDEN_CASES) {
  test(`NDS BLZ decodes independent ${name} golden vector exactly`, async () => {
    const [stored, expected] = await Promise.all([
      fixture(`${name}.bin`),
      fixture(`${name}.dec.bin`),
    ]);

    const result = decodeNdsBlz(stored, expected.length);

    assert.deepEqual(result.bytes, expected);
    assert.equal(result.storedSize, stored.length);
    assert.equal(result.decodedSize, expected.length);
    assert.ok(result.headerSize >= 8);
    assert.ok(result.encodedRegionSize > 0);
  });
}

test("NDS BLZ defaults cap stored and decoded images at 16 MiB", () => {
  assert.deepEqual(DEFAULT_NDS_BLZ_LIMITS, {
    maxStoredBytes: 16 * 1024 * 1024,
    maxDecodedBytes: 16 * 1024 * 1024,
  });
});

test("NDS BLZ rejects a truncated footer", () => {
  assertCategory(
    () => decodeNdsBlz(Buffer.alloc(7), 32),
    "malformed-blz",
  );
});

test("NDS BLZ rejects impossible header geometry", async () => {
  const [storedFixture, expected] = await Promise.all([
    fixture("backreference.bin"),
    fixture("backreference.dec.bin"),
  ]);
  const stored = Buffer.from(storedFixture);
  stored[stored.length - 5] = 7;

  assertCategory(
    () => decodeNdsBlz(stored, expected.length),
    "malformed-blz",
  );
});

test("NDS BLZ rejects non-FF header padding", async () => {
  const [storedFixture, expected] = await Promise.all([
    fixture("literal-only.bin"),
    fixture("literal-only.dec.bin"),
  ]);
  const stored = Buffer.from(storedFixture);
  const headerSize = stored[stored.length - 5]!;
  assert.ok(headerSize > 8);
  stored[stored.length - headerSize] = 0;

  assertCategory(
    () => decodeNdsBlz(stored, expected.length),
    "malformed-blz",
  );
});

test("NDS BLZ rejects a truncated compressed token", () => {
  const stored = Buffer.from([
    0x80,
    0x09, 0x00, 0x00, 0x08,
    0x03, 0x00, 0x00, 0x00,
  ]);

  assertCategory(
    () => decodeNdsBlz(stored, 12),
    "malformed-blz",
  );
});

test("NDS BLZ rejects a back-reference before decoded history", () => {
  const stored = Buffer.from([
    0x00, 0x00, 0x80, 0xff,
    0x0c, 0x00, 0x00, 0x09,
    0x04, 0x00, 0x00, 0x00,
  ]);

  assertCategory(
    () => decodeNdsBlz(stored, 16),
    "malformed-blz",
  );
});

test("NDS BLZ requires the canonical decoded size exactly", async () => {
  const [stored, expected] = await Promise.all([
    fixture("backreference.bin"),
    fixture("backreference.dec.bin"),
  ]);

  assertCategory(
    () => decodeNdsBlz(stored, expected.length + 1),
    "blz-output-size-mismatch",
  );
});

test("NDS BLZ enforces the stored-byte limit before decoding", async () => {
  const [stored, expected] = await Promise.all([
    fixture("backreference.bin"),
    fixture("backreference.dec.bin"),
  ]);

  assertCategory(
    () => decodeNdsBlz(stored, expected.length, {
      maxStoredBytes: stored.length - 1,
      maxDecodedBytes: expected.length,
    }),
    "blz-output-limit",
  );
});

test("NDS BLZ enforces the decoded-byte limit before allocation", async () => {
  const [stored, expected] = await Promise.all([
    fixture("backreference.bin"),
    fixture("backreference.dec.bin"),
  ]);

  assertCategory(
    () => decodeNdsBlz(stored, expected.length, {
      maxStoredBytes: stored.length,
      maxDecodedBytes: expected.length - 1,
    }),
    "blz-output-limit",
  );
});
