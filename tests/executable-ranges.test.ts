import assert from "node:assert/strict";
import test from "node:test";

import { ExecutableRangeRegistry } from "../src/services/executable-ranges.js";

function registry(): ExecutableRangeRegistry {
  return new ExecutableRangeRegistry({
    start: 0x02000000,
    end: 0x02010000,
    size: 0x10000,
    source: "arm9-header",
    label: "ARM9 main",
  });
}

test("lists the derived ARM9 range", () => {
  assert.deepEqual(registry().list(), [
    {
      id: "arm9-main",
      label: "ARM9 main",
      start: 0x02000000,
      end: 0x02010000,
      source: "arm9-header",
      symbolModes: {},
    },
  ]);
});

test("replaces additional executable ranges and rejects partial overlaps", () => {
  const ranges = registry();
  ranges.replaceAdditionalRanges([
    {
      id: "overlay-1",
      label: "Battle overlay",
      start: 0x02100000,
      end: 0x02110000,
      source: "overlay",
      overlayId: 1,
      defaultMode: "thumb",
    },
  ]);
  assert.equal(ranges.list().length, 2);

  assert.throws(
    () => ranges.replaceAdditionalRanges([
      {
        id: "bad",
        label: "Bad overlap",
        start: 0x0200f000,
        end: 0x02011000,
        source: "explicit",
      },
    ]),
    /overlap/,
  );
});

test("resolves explicit ARM and Thumb modes with alignment", () => {
  const ranges = registry();
  assert.equal(ranges.resolve({ address: 0x02000004, mode: "arm" }).kind, 4);
  assert.deepEqual(ranges.resolve({ address: 0x02000003, mode: "thumb" }), {
    address: 0x02000002,
    mode: "thumb",
    kind: 2,
    range: ranges.list()[0],
  });
  assert.throws(
    () => ranges.resolve({ address: 0x02000002, mode: "arm" }),
    /4-byte aligned/,
  );
});

test("auto mode follows metadata, history, and Thumb address evidence", () => {
  const ranges = registry();
  ranges.replaceAdditionalRanges([
    {
      id: "overlay-2",
      label: "Menu overlay",
      start: 0x02100000,
      end: 0x02110000,
      source: "overlay",
      defaultMode: "thumb",
      symbolModes: { ArmEntry: "arm" },
    },
  ]);

  assert.equal(
    ranges.resolve({ address: 0x02100000, mode: "auto", symbol: "ArmEntry" }).mode,
    "arm",
  );
  assert.equal(
    ranges.resolve({ address: 0x02100004, mode: "auto" }).mode,
    "thumb",
  );

  ranges.recordExecution(0x02000008, "arm");
  assert.equal(ranges.resolve({ address: 0x02000008, mode: "auto" }).mode, "arm");
  assert.equal(ranges.resolve({ address: 0x02000003, mode: "auto" }).mode, "thumb");
  assert.equal(ranges.resolve({ address: 0x02000006, mode: "auto" }).mode, "thumb");
});

test("auto mode rejects ambiguous 4-byte aligned addresses", () => {
  assert.throws(
    () => registry().resolve({ address: 0x02000004, mode: "auto" }),
    /ambiguous/,
  );
});

test("rejects addresses outside allowlisted executable ranges", () => {
  assert.throws(
    () => registry().resolve({ address: 0x02200000, mode: "arm" }),
    /outside all allowlisted/,
  );
});
