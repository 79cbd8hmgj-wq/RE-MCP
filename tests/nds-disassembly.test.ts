import assert from "node:assert/strict";
import test from "node:test";

import type {
  ArmDisassemblyBackend,
  ArmMode,
  DecodedArmInstruction,
} from "../src/services/disassembly/backend.js";
import { createCapstoneArmBackend } from "../src/services/disassembly/capstone.js";
import {
  decodeNdsInstruction,
  disassembleNdsRange,
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
    ...overrides,
  };
}

async function mainSource(
  map: NdsRomMap,
  address = 0x02000000,
  mode: ArmMode = "arm",
): Promise<NdsCodeSource> {
  const resolution = resolveNdsCodeSource(map, {
    processor: "arm9",
    runtimeAddress: address,
    mode,
  });
  assert.equal(resolution.status, "resolved");
  if (resolution.status !== "resolved") {
    throw new Error("Expected a resolved test source");
  }
  return resolution.source;
}

test("normalizes fallthrough and direct calls without traversing them", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const source = await mainSource(map);
  const backend = new FakeBackend(new Map([
    [0x02000000, decoded(0x02000000, {
      mnemonic: "bl",
      operandsText: "#0x2000008",
      operands: [{ kind: "immediate", value: 0x02000008 }],
      isCall: true,
    })],
  ]));

  const instruction = decodeNdsInstruction(
    map,
    source,
    Uint8Array.from([0x00, 0x00, 0x00, 0xeb]),
    backend,
  );
  assert.ok(instruction);
  assert.equal(instruction.flow.kind, "call");
  assert.equal(instruction.flow.directTarget, 0x02000008);
  assert.equal(instruction.flow.targetMode, "arm");
  assert.equal(instruction.flow.fallthrough, 0x02000004);
  assert.equal(instruction.targetResolution?.status, "resolved");
});

test("normalizes direct conditional and unconditional branches", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const conditionalSource = await mainSource(map, 0x02000000);
  const unconditionalSource = await mainSource(map, 0x02000004);
  const backend = new FakeBackend(new Map([
    [0x02000000, decoded(0x02000000, {
      mnemonic: "bne",
      operandsText: "#0x200000c",
      operands: [{ kind: "immediate", value: 0x0200000c }],
      isJump: true,
      isConditional: true,
    })],
    [0x02000004, decoded(0x02000004, {
      mnemonic: "b",
      operandsText: "#0x2000010",
      operands: [{ kind: "immediate", value: 0x02000010 }],
      isJump: true,
    })],
  ]));

  const conditional = decodeNdsInstruction(
    map,
    conditionalSource,
    Uint8Array.from([0, 0, 0, 0]),
    backend,
  );
  assert.ok(conditional);
  assert.deepEqual(conditional.flow, {
    kind: "conditional-branch",
    directTarget: 0x0200000c,
    targetMode: "arm",
    fallthrough: 0x02000004,
  });

  const unconditional = decodeNdsInstruction(
    map,
    unconditionalSource,
    Uint8Array.from([0, 0, 0, 0]),
    backend,
  );
  assert.ok(unconditional);
  assert.deepEqual(unconditional.flow, {
    kind: "unconditional-branch",
    directTarget: 0x02000010,
    targetMode: "arm",
    fallthrough: null,
  });
});

test("normalizes indirect calls, indirect branches, and BX LR returns", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, decoded(0x02000000, {
      mnemonic: "blx",
      operandsText: "r3",
      operands: [{ kind: "register", name: "r3" }],
      isCall: true,
      switchesMode: true,
    })],
    [0x02000004, decoded(0x02000004, {
      mnemonic: "bx",
      operandsText: "r3",
      operands: [{ kind: "register", name: "r3" }],
      isJump: true,
    })],
    [0x02000008, decoded(0x02000008, {
      mnemonic: "bx",
      operandsText: "lr",
      operands: [{ kind: "register", name: "lr" }],
      isJump: true,
    })],
  ]));

  const indirectCall = decodeNdsInstruction(
    map,
    await mainSource(map, 0x02000000),
    Uint8Array.from([0, 0, 0, 0]),
    backend,
  );
  assert.ok(indirectCall);
  assert.deepEqual(indirectCall.flow, {
    kind: "indirect-call",
    directTarget: null,
    targetMode: null,
    fallthrough: 0x02000004,
  });

  const indirectBranch = decodeNdsInstruction(
    map,
    await mainSource(map, 0x02000004),
    Uint8Array.from([0, 0, 0, 0]),
    backend,
  );
  assert.ok(indirectBranch);
  assert.deepEqual(indirectBranch.flow, {
    kind: "indirect-branch",
    directTarget: null,
    targetMode: null,
    fallthrough: null,
  });

  const returned = decodeNdsInstruction(
    map,
    await mainSource(map, 0x02000008),
    Uint8Array.from([0, 0, 0, 0]),
    backend,
  );
  assert.ok(returned);
  assert.equal(returned.flow.kind, "return");
  assert.equal(returned.flow.fallthrough, null);
});

test("propagates deterministic mode switches on immediate control flow", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, decoded(0x02000000, {
      mnemonic: "blx",
      operandsText: "#0x200000a",
      operands: [{ kind: "immediate", value: 0x0200000a }],
      isCall: true,
      switchesMode: true,
    })],
  ]));

  const instruction = decodeNdsInstruction(
    map,
    await mainSource(map),
    Uint8Array.from([0, 0, 0, 0]),
    backend,
  );
  assert.ok(instruction);
  assert.equal(instruction.flow.targetMode, "thumb");
  assert.equal(instruction.targetResolution?.status, "resolved");
  if (instruction.targetResolution?.status === "resolved") {
    assert.equal(instruction.targetResolution.source.mode, "thumb");
  }
});

test("canonical instructions retain exact bytes, ROM offset, mode, and source identity", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000004, decoded(0x02000004, {
      bytes: [0x1e, 0xff, 0x2f, 0xe1],
      mnemonic: "bx",
      operandsText: "lr",
      operands: [{ kind: "register", name: "lr" }],
      isJump: true,
    })],
  ]));

  const instruction = decodeNdsInstruction(
    map,
    await mainSource(map, 0x02000004),
    Uint8Array.from([0x1e, 0xff, 0x2f, 0xe1]),
    backend,
  );
  assert.ok(instruction);
  assert.equal(instruction.address, 0x02000004);
  assert.equal(instruction.romOffset, 0x204);
  assert.equal(instruction.bytesHex, "1eff2fe1");
  assert.equal(instruction.mode, "arm");
  assert.deepEqual(instruction.source, {
    processor: "arm9",
    component: "main",
    overlayId: null,
  });
});

test("bounded linear decoding stops at instruction limit without following branches", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, decoded(0x02000000, {
      mnemonic: "b",
      operandsText: "#0x2000040",
      operands: [{ kind: "immediate", value: 0x02000040 }],
      isJump: true,
    })],
    [0x02000004, decoded(0x02000004)],
  ]));

  const result = await disassembleNdsRange(
    map,
    { processor: "arm9", runtimeAddress: 0x02000000, mode: "arm" },
    { maxInstructions: 2, maxBytes: 32 },
    backend,
  );
  assert.equal(result.status, "complete");
  if (result.status !== "complete") return;
  assert.equal(result.instructions.length, 2);
  assert.equal(result.instructions[0]?.flow.kind, "unconditional-branch");
  assert.equal(result.instructions[1]?.address, 0x02000004);
  assert.equal(result.decodedBytes, 8);
  assert.equal(result.stopAddress, 0x02000008);
});

test("linear decoding returns the successfully decoded prefix on decode stop", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, decoded(0x02000000)],
    [0x02000004, null],
  ]));

  const result = await disassembleNdsRange(
    map,
    { processor: "arm9", runtimeAddress: 0x02000000, mode: "arm" },
    { maxInstructions: 8, maxBytes: 32 },
    backend,
  );
  assert.equal(result.status, "decode-stopped");
  if (result.status !== "decode-stopped") return;
  assert.equal(result.instructions.length, 1);
  assert.equal(result.decodedBytes, 4);
  assert.equal(result.stopAddress, 0x02000004);
});

test("linear decoding stops exactly at a validated component boundary", async () => {
  const fixture = await createNdsFixture({ arm9Size: 4 });
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, decoded(0x02000000)],
  ]));

  const result = await disassembleNdsRange(
    map,
    { processor: "arm9", runtimeAddress: 0x02000000, mode: "arm" },
    { maxInstructions: 8, maxBytes: 32 },
    backend,
  );
  assert.equal(result.status, "component-boundary");
  if (result.status !== "component-boundary") return;
  assert.equal(result.instructions.length, 1);
  assert.equal(result.decodedBytes, 4);
  assert.equal(result.stopAddress, 0x02000004);
});

test("real Capstone adapter decodes ARM BX LR from the canonical ARM9 source", async () => {
  const fixture = await createNdsFixture();
  fixture.buffer.set([0x1e, 0xff, 0x2f, 0xe1], 0x200);
  await fixture.write();
  const map = await readNdsRomMap(fixture.romPath);
  const backend = await createCapstoneArmBackend();
  try {
    const result = await disassembleNdsRange(
      map,
      { processor: "arm9", runtimeAddress: 0x02000000, mode: "arm" },
      { maxInstructions: 1, maxBytes: 4 },
      backend,
    );
    assert.equal(result.status, "complete");
    if (result.status !== "complete") return;
    const instruction = result.instructions[0];
    assert.ok(instruction);
    assert.equal(instruction.address, 0x02000000);
    assert.equal(instruction.romOffset, 0x200);
    assert.equal(instruction.bytesHex, "1eff2fe1");
    assert.equal(instruction.mnemonic, "bx");
    assert.equal(instruction.mode, "arm");
    assert.equal(instruction.flow.kind, "return");
  } finally {
    backend.close();
  }
});

test("real Capstone adapter decodes Thumb BX LR from an explicit Thumb source", async () => {
  const fixture = await createNdsFixture();
  fixture.buffer.set([0x70, 0x47], 0x202);
  await fixture.write();
  const map = await readNdsRomMap(fixture.romPath);
  const backend = await createCapstoneArmBackend();
  try {
    const result = await disassembleNdsRange(
      map,
      { processor: "arm9", runtimeAddress: 0x02000002, mode: "thumb" },
      { maxInstructions: 1, maxBytes: 2 },
      backend,
    );
    assert.equal(result.status, "complete");
    if (result.status !== "complete") return;
    const instruction = result.instructions[0];
    assert.ok(instruction);
    assert.equal(instruction.address, 0x02000002);
    assert.equal(instruction.romOffset, 0x202);
    assert.equal(instruction.bytesHex, "7047");
    assert.equal(instruction.mnemonic, "bx");
    assert.equal(instruction.mode, "thumb");
    assert.equal(instruction.flow.kind, "return");
  } finally {
    backend.close();
  }
});
