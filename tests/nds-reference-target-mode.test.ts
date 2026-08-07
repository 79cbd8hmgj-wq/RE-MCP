import assert from "node:assert/strict";
import test from "node:test";

import type { DetailedStaticInstruction } from "../src/services/nds/disassembly.js";
import { classifyNdsInstructionReferences } from "../src/services/nds/references.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import { createNdsFixture } from "./helpers/nds-fixture.js";

function detailed(input: {
  address: number;
  flowKind: "call" | "unconditional-branch" | "fallthrough";
  directTarget?: number | null;
  targetMode?: "arm" | "thumb" | null;
}): DetailedStaticInstruction {
  const directTarget = input.directTarget ?? null;
  const targetMode = input.targetMode ?? null;
  return {
    instruction: {
      address: input.address,
      romOffset: 0x200 + (input.address - 0x02000000),
      size: 4,
      bytesHex: "00000000",
      mode: "arm",
      mnemonic: input.flowKind === "call"
        ? "bl"
        : input.flowKind === "unconditional-branch"
          ? "b"
          : "ldr",
      operands: "",
      flow: {
        kind: input.flowKind,
        directTarget,
        targetMode,
        fallthrough: input.flowKind === "unconditional-branch"
          ? null
          : input.address + 4,
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
      size: 4,
      bytes: [0, 0, 0, 0],
      mnemonic: "nop",
      operandsText: "",
      operands: [],
      isJump: input.flowKind === "unconditional-branch",
      isCall: input.flowKind === "call",
      isReturn: false,
      isConditional: false,
      switchesMode: targetMode === "thumb",
      pcRelative: input.flowKind === "fallthrough"
        ? { kind: "literal-load", displacement: 0 }
        : null,
    },
  };
}

test("direct references preserve canonical target mode while data references have none", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);

  const directCall = classifyNdsInstructionReferences(map, detailed({
    address: 0x02000000,
    flowKind: "call",
    directTarget: 0x02000010,
    targetMode: "thumb",
  }))[0]!;
  assert.equal(directCall.kind, "direct-call");
  assert.equal(directCall.target.mode, "thumb");

  const directBranch = classifyNdsInstructionReferences(map, detailed({
    address: 0x02000004,
    flowKind: "unconditional-branch",
    directTarget: 0x02000020,
    targetMode: "arm",
  }))[0]!;
  assert.equal(directBranch.kind, "direct-branch");
  assert.equal(directBranch.target.mode, "arm");

  const literal = classifyNdsInstructionReferences(map, detailed({
    address: 0x02000008,
    flowKind: "fallthrough",
  }))[0]!;
  assert.equal(literal.kind, "literal-pool");
  assert.equal(literal.target.mode, null);
});
