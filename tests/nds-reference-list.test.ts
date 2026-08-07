import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import test from "node:test";

import type {
  ArmDisassemblyBackend,
  ArmMode,
  DecodedArmInstruction,
} from "../src/services/disassembly/backend.js";
import { NdsError } from "../src/services/nds/errors.js";
import { listNdsReferences } from "../src/services/nds/reference-list.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import { createNdsFixture } from "./helpers/nds-fixture.js";

class FakeBackend implements ArmDisassemblyBackend {
  constructor(
    private readonly decoded: ReadonlyMap<number, DecodedArmInstruction | null>,
  ) {}

  decodeOne(
    _bytes: Uint8Array,
    address: number,
    _mode: ArmMode,
  ): DecodedArmInstruction | null {
    return this.decoded.get(address) ?? null;
  }

  close(): void {}
}

function decoded(
  address: number,
  overrides: Partial<DecodedArmInstruction> = {},
): DecodedArmInstruction {
  return {
    address,
    size: 4,
    bytes: [0x00, 0x00, 0xa0, 0xe1],
    mnemonic: "mov",
    operandsText: "r0, r0",
    operands: [],
    isJump: false,
    isCall: false,
    isReturn: false,
    isConditional: false,
    switchesMode: false,
    pcRelative: null,
    ...overrides,
  };
}

const LOCATION = {
  processor: "arm9" as const,
  runtimeAddress: 0x02000000,
  mode: "arm" as const,
};

test("lists proven references from a bounded sequential window without traversal", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, decoded(0x02000000, {
      mnemonic: "bl",
      operandsText: "#0x2000010",
      operands: [{ kind: "immediate", value: 0x02000010 }],
      isCall: true,
    })],
    [0x02000004, decoded(0x02000004)],
    [0x02000008, decoded(0x02000008, {
      mnemonic: "ldr",
      operandsText: "r0, [pc]",
      pcRelative: { kind: "literal-load", displacement: 0 },
    })],
  ]));

  const result = await listNdsReferences(
    map,
    LOCATION,
    { maxInstructions: 3, maxBytes: 12 },
    backend,
  );
  assert.equal(result.status, "complete");
  if (result.status !== "complete") {
    throw new Error(`Expected complete result, got ${result.status}`);
  }
  assert.equal(result.instructionsExamined, 3);
  assert.equal(result.decodedBytes, 12);
  assert.deepEqual(result.references.map((reference) => reference.kind), [
    "direct-call",
    "literal-pool",
  ]);
  assert.deepEqual(result.references.map((reference) => reference.target.runtimeAddress), [
    0x02000010,
    0x02000010,
  ]);
});

test("does not classify instructions beyond the configured window", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, decoded(0x02000000)],
    [0x02000004, decoded(0x02000004, {
      mnemonic: "bl",
      operands: [{ kind: "immediate", value: 0x02000010 }],
      isCall: true,
    })],
  ]));

  const result = await listNdsReferences(
    map,
    LOCATION,
    { maxInstructions: 1, maxBytes: 8 },
    backend,
  );
  assert.equal(result.status, "complete");
  if (result.status === "complete") {
    assert.equal(result.instructionsExamined, 1);
    assert.deepEqual(result.references, []);
  }
});

test("preserves disassembly source conditions instead of guessing a mode", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const result = await listNdsReferences(
    map,
    {
      processor: "arm9",
      runtimeAddress: 0x02000004,
      mode: "auto",
    },
    { maxInstructions: 1, maxBytes: 4 },
    new FakeBackend(new Map()),
  );
  assert.equal(result.status, "mode-ambiguous");
});

test("rejects a result when the ROM changes during reference listing", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  let mutated = false;
  const backend: ArmDisassemblyBackend = {
    decodeOne(_bytes, address) {
      if (!mutated) {
        mutated = true;
        const bytes = readFileSync(map.romPath);
        bytes[bytes.length - 1] = (bytes[bytes.length - 1]! ^ 0xff) & 0xff;
        writeFileSync(map.romPath, bytes);
      }
      return decoded(address);
    },
    close() {},
  };

  await assert.rejects(
    () => listNdsReferences(
      map,
      LOCATION,
      { maxInstructions: 1, maxBytes: 4 },
      backend,
    ),
    (error: unknown) => error instanceof NdsError && error.category === "invalid-rom",
  );
});
