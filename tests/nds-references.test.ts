import assert from "node:assert/strict";
import test from "node:test";

import type {
  ArmMode,
  DecodedArmInstruction,
  DecodedArmPcRelativeSemantics,
} from "../src/services/disassembly/backend.js";
import type { DetailedStaticInstruction, StaticFlowKind } from "../src/services/nds/disassembly.js";
import type { NdsOverlay } from "../src/services/nds/overlays.js";
import {
  classifyNdsInstructionReferences,
  compareStaticReferences,
} from "../src/services/nds/references.js";
import { readNdsRomMap, type NdsRomMap } from "../src/services/nds/rom-map.js";
import { createNdsFixture } from "./helpers/nds-fixture.js";

function detailed(input: {
  address: number;
  mode?: ArmMode;
  flowKind?: StaticFlowKind;
  directTarget?: number | null;
  targetMode?: ArmMode | null;
  pcRelative?: DecodedArmPcRelativeSemantics;
  mnemonic?: string;
  operands?: DecodedArmInstruction["operands"];
}): DetailedStaticInstruction {
  const mode = input.mode ?? "arm";
  const flowKind = input.flowKind ?? "fallthrough";
  const directTarget = input.directTarget ?? null;
  const targetMode = input.targetMode ?? null;
  const size = mode === "arm" ? 4 : 2;
  return {
    instruction: {
      address: input.address,
      romOffset: 0x200 + (input.address - 0x02000000),
      size,
      bytesHex: mode === "arm" ? "0000a0e1" : "00bf",
      mode,
      mnemonic: input.mnemonic ?? "mov",
      operands: "",
      flow: {
        kind: flowKind,
        directTarget,
        targetMode,
        fallthrough: flowKind === "return" || flowKind === "indirect-branch"
          ? null
          : (input.address + size) >>> 0,
      },
      source: {
        processor: "arm9",
        component: "main",
        overlayId: null,
      },
      targetResolution: null,
    },
    decoded: {
      address: input.address,
      size,
      bytes: mode === "arm" ? [0x00, 0x00, 0xa0, 0xe1] : [0x00, 0xbf],
      mnemonic: input.mnemonic ?? "mov",
      operandsText: "",
      operands: input.operands ?? [],
      isJump: flowKind === "conditional-branch"
        || flowKind === "unconditional-branch"
        || flowKind === "indirect-branch",
      isCall: flowKind === "call" || flowKind === "indirect-call",
      isReturn: flowKind === "return",
      isConditional: flowKind === "conditional-branch",
      switchesMode: false,
      pcRelative: input.pcRelative ?? null,
    },
  };
}

function overlay(input: {
  overlayId: number;
  ramAddress: number;
  ramSize: number;
  bssSize?: number;
  romOffset: number;
  romSize: number;
  compressed?: boolean;
}): NdsOverlay {
  const bssSize = input.bssSize ?? 0;
  const compressed = input.compressed ?? false;
  return {
    processor: "arm9",
    overlayId: input.overlayId,
    ramAddress: input.ramAddress,
    ramSize: input.ramSize,
    ramEnd: input.ramAddress + input.ramSize,
    bssSize,
    bssEnd: input.ramAddress + input.ramSize + bssSize,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: input.overlayId,
    romOffset: input.romOffset,
    romSize: input.romSize,
    compressedSize: compressed ? input.romSize : 0,
    flags: compressed ? 1 : 0,
    compressed,
  };
}

function withArm9Overlays(
  map: NdsRomMap,
  overlays: readonly NdsOverlay[],
): NdsRomMap {
  return {
    ...map,
    overlays: {
      arm9: overlays,
      arm7: map.overlays.arm7,
    },
  };
}

test("classifies direct branches and calls but not indirect control flow", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);

  const branch = classifyNdsInstructionReferences(map, detailed({
    address: 0x02000000,
    flowKind: "conditional-branch",
    directTarget: 0x02000010,
    targetMode: "arm",
    mnemonic: "bne",
  }));
  assert.equal(branch.length, 1);
  assert.equal(branch[0]?.kind, "direct-branch");
  assert.equal(branch[0]?.target.runtimeAddress, 0x02000010);
  assert.equal(branch[0]?.target.resolution.status, "resolved");

  const call = classifyNdsInstructionReferences(map, detailed({
    address: 0x02000004,
    flowKind: "call",
    directTarget: 0x02000018,
    targetMode: "arm",
    mnemonic: "bl",
  }));
  assert.equal(call.length, 1);
  assert.equal(call[0]?.kind, "direct-call");
  assert.equal(call[0]?.evidence.mechanism, "direct-control-flow");

  assert.deepEqual(classifyNdsInstructionReferences(map, detailed({
    address: 0x02000008,
    flowKind: "indirect-call",
    mnemonic: "blx",
  })), []);
  assert.deepEqual(classifyNdsInstructionReferences(map, detailed({
    address: 0x0200000c,
    flowKind: "indirect-branch",
    mnemonic: "bx",
  })), []);
});

test("computes ARM and Thumb literal-pool slot addresses architecturally", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);

  const arm = classifyNdsInstructionReferences(map, detailed({
    address: 0x02000000,
    mode: "arm",
    mnemonic: "ldr",
    pcRelative: { kind: "literal-load", displacement: 0 },
  }));
  assert.equal(arm[0]?.kind, "literal-pool");
  assert.equal(arm[0]?.target.runtimeAddress, 0x02000008);

  const thumb = classifyNdsInstructionReferences(map, detailed({
    address: 0x02000002,
    mode: "thumb",
    mnemonic: "ldr",
    pcRelative: { kind: "literal-load", displacement: 0 },
  }));
  assert.equal(thumb[0]?.kind, "literal-pool");
  assert.equal(thumb[0]?.target.runtimeAddress, 0x02000004);

  const armNegative = classifyNdsInstructionReferences(map, detailed({
    address: 0x02000010,
    mode: "arm",
    mnemonic: "ldr",
    pcRelative: { kind: "literal-load", displacement: -4 },
  }));
  assert.equal(armNegative[0]?.target.runtimeAddress, 0x02000014);
});

test("classifies deterministic PC-relative address construction only", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);

  const add = classifyNdsInstructionReferences(map, detailed({
    address: 0x02000000,
    pcRelative: { kind: "address-add", immediate: 0x10 },
    mnemonic: "add",
  }));
  assert.equal(add[0]?.kind, "pc-relative-address");
  assert.equal(add[0]?.target.runtimeAddress, 0x02000018);

  const subtract = classifyNdsInstructionReferences(map, detailed({
    address: 0x02000020,
    pcRelative: { kind: "address-sub", immediate: 8 },
    mnemonic: "sub",
  }));
  assert.equal(subtract[0]?.target.runtimeAddress, 0x02000020);

  const thumb = classifyNdsInstructionReferences(map, detailed({
    address: 0x02000002,
    mode: "thumb",
    pcRelative: { kind: "address-add", immediate: 0 },
    mnemonic: "adr",
  }));
  assert.equal(thumb[0]?.target.runtimeAddress, 0x02000004);

  assert.deepEqual(classifyNdsInstructionReferences(map, detailed({
    address: 0x02000030,
    mnemonic: "add",
    operands: [
      { kind: "register", name: "r0" },
      { kind: "register", name: "pc" },
      { kind: "register", name: "r3" },
    ],
    pcRelative: null,
  })), []);
});

test("preserves ambiguous, BSS, and compressed runtime target resolution", async () => {
  const fixture = await createNdsFixture();
  const base = await readNdsRomMap(fixture.romPath);

  const ambiguousMap = withArm9Overlays(base, [
    overlay({
      overlayId: 1,
      ramAddress: 0x02200000,
      ramSize: 0x20,
      romOffset: 0x1000,
      romSize: 0x20,
    }),
    overlay({
      overlayId: 2,
      ramAddress: 0x02200000,
      ramSize: 0x20,
      romOffset: 0x1100,
      romSize: 0x20,
    }),
  ]);
  const ambiguous = classifyNdsInstructionReferences(ambiguousMap, detailed({
    address: 0x02000000,
    flowKind: "call",
    directTarget: 0x02200004,
    targetMode: "arm",
    mnemonic: "bl",
  }))[0]!;
  assert.equal(ambiguous.target.resolution.status, "ambiguous-runtime-address");
  assert.equal(ambiguous.target.romOffset, null);

  const bssMap = withArm9Overlays(base, [overlay({
    overlayId: 3,
    ramAddress: 0x02210000,
    ramSize: 0x20,
    bssSize: 0x20,
    romOffset: 0x1200,
    romSize: 0x20,
  })]);
  const bss = classifyNdsInstructionReferences(bssMap, detailed({
    address: 0x02000000,
    flowKind: "call",
    directTarget: 0x02210024,
    targetMode: "arm",
    mnemonic: "bl",
  }))[0]!;
  assert.equal(bss.target.resolution.status, "runtime-only-bss");

  const compressedMap = withArm9Overlays(base, [overlay({
    overlayId: 4,
    ramAddress: 0x02220000,
    ramSize: 0x20,
    romOffset: 0x1300,
    romSize: 0x18,
    compressed: true,
  })]);
  const compressed = classifyNdsInstructionReferences(compressedMap, detailed({
    address: 0x02000000,
    flowKind: "call",
    directTarget: 0x02220004,
    targetMode: "arm",
    mnemonic: "bl",
  }))[0]!;
  assert.equal(compressed.target.resolution.status, "compressed-no-direct-rom-mapping");
});

test("sorts references deterministically by source identity then kind and target", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const refs = [
    ...classifyNdsInstructionReferences(map, detailed({
      address: 0x02000004,
      flowKind: "call",
      directTarget: 0x02000020,
      targetMode: "arm",
      mnemonic: "bl",
    })),
    ...classifyNdsInstructionReferences(map, detailed({
      address: 0x02000000,
      flowKind: "unconditional-branch",
      directTarget: 0x02000010,
      targetMode: "arm",
      mnemonic: "b",
    })),
  ];
  refs.sort(compareStaticReferences);
  assert.deepEqual(refs.map((ref) => ref.source.instructionAddress), [
    0x02000000,
    0x02000004,
  ]);
});
