import assert from "node:assert/strict";
import test from "node:test";

import type {
  ArmDisassemblyBackend,
  ArmMode,
  DecodedArmInstruction,
} from "../src/services/disassembly/backend.js";
import {
  decodeNdsInstructionDetailed,
  disassembleNdsRange,
  disassembleNdsRangeDetailed,
} from "../src/services/nds/disassembly.js";
import {
  resolveNdsCodeSource,
  type NdsCodeSource,
} from "../src/services/nds/disassembly-source.js";
import { readNdsRomMap, type NdsRomMap } from "../src/services/nds/rom-map.js";
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

function literal(address: number): DecodedArmInstruction {
  return {
    address,
    size: 4,
    bytes: [0x00, 0x00, 0x9f, 0xe5],
    mnemonic: "ldr",
    operandsText: "r0, [pc]",
    operands: [{
      kind: "memory",
      value: {
        baseRegister: "pc",
        indexRegister: null,
        displacement: 0,
      },
    }],
    isJump: false,
    isCall: false,
    isReturn: false,
    isConditional: false,
    switchesMode: false,
    pcRelative: { kind: "literal-load", displacement: 0 },
  };
}

async function mainSource(map: NdsRomMap): Promise<NdsCodeSource> {
  const resolution = resolveNdsCodeSource(map, {
    processor: "arm9",
    runtimeAddress: 0x02000000,
    mode: "arm",
  });
  assert.equal(resolution.status, "resolved");
  if (resolution.status !== "resolved") {
    throw new Error("Expected resolved ARM9 source");
  }
  return resolution.source;
}

test("detailed decode retains normalized backend semantics outside StaticInstruction", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const source = await mainSource(map);
  const backend = new FakeBackend(new Map([
    [0x02000000, literal(0x02000000)],
  ]));

  const detailed = decodeNdsInstructionDetailed(
    map,
    source,
    Uint8Array.from([0x00, 0x00, 0x9f, 0xe5]),
    backend,
  );
  assert.ok(detailed);
  assert.equal(detailed.instruction.mnemonic, "ldr");
  assert.deepEqual(detailed.decoded.pcRelative, {
    kind: "literal-load",
    displacement: 0,
  });
  assert.equal(Object.hasOwn(detailed.instruction, "decoded"), false);
  assert.equal(Object.hasOwn(detailed.instruction, "pcRelative"), false);
});

test("detailed range preserves metadata while public range strips it", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, literal(0x02000000)],
  ]));
  const location = {
    processor: "arm9" as const,
    runtimeAddress: 0x02000000,
    mode: "arm" as const,
  };
  const options = { maxInstructions: 1, maxBytes: 4 };

  const detailed = await disassembleNdsRangeDetailed(
    map,
    location,
    options,
    backend,
  );
  assert.equal(detailed.status, "complete");
  if (detailed.status !== "complete") {
    throw new Error(`Expected complete detailed result, got ${detailed.status}`);
  }
  assert.equal(detailed.instructions.length, 1);
  assert.equal(detailed.instructions[0]?.decoded.pcRelative?.kind, "literal-load");

  const publicResult = await disassembleNdsRange(map, location, options, backend);
  assert.equal(publicResult.status, "complete");
  if (publicResult.status !== "complete") {
    throw new Error(`Expected complete public result, got ${publicResult.status}`);
  }
  assert.equal(publicResult.instructions.length, 1);
  assert.equal(Object.hasOwn(publicResult.instructions[0]!, "decoded"), false);
  assert.equal(Object.hasOwn(publicResult.instructions[0]!, "pcRelative"), false);
});
