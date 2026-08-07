import assert from "node:assert/strict";
import test from "node:test";

import { createCapstoneArmBackend } from "../src/services/disassembly/capstone.js";

test("decodes known ARM and Thumb instructions", async () => {
  const backend = await createCapstoneArmBackend();
  try {
    const arm = backend.decodeOne(
      Uint8Array.from([0x1e, 0xff, 0x2f, 0xe1]),
      0x02000000,
      "arm",
    );
    assert.ok(arm);
    assert.equal(arm.address, 0x02000000);
    assert.equal(arm.size, 4);
    assert.deepEqual(arm.bytes, [0x1e, 0xff, 0x2f, 0xe1]);
    assert.equal(arm.mnemonic, "bx");
    assert.equal(arm.operandsText, "lr");
    assert.equal(arm.isJump, true);
    assert.deepEqual(arm.operands[0], { kind: "register", name: "lr" });

    const thumb = backend.decodeOne(
      Uint8Array.from([0x70, 0x47]),
      0x02000010,
      "thumb",
    );
    assert.ok(thumb);
    assert.equal(thumb.address, 0x02000010);
    assert.equal(thumb.size, 2);
    assert.deepEqual(thumb.bytes, [0x70, 0x47]);
    assert.equal(thumb.mnemonic, "bx");
    assert.equal(thumb.operandsText, "lr");
  } finally {
    backend.close();
  }
});

test("normalizes ARM and Thumb PC-relative operands from structured detail", async () => {
  const backend = await createCapstoneArmBackend();
  try {
    const armLiteral = backend.decodeOne(
      Uint8Array.from([0x00, 0x00, 0x9f, 0xe5]),
      0x02000000,
      "arm",
    );
    assert.ok(armLiteral);
    assert.deepEqual(armLiteral.pcRelative, {
      kind: "literal-load",
      displacement: 0,
    });
    assert.equal(
      armLiteral.operands.some(
        (operand) => operand.kind === "memory"
          && operand.value.baseRegister === "pc"
          && operand.value.displacement === 0,
      ),
      true,
    );

    const thumbLiteral = backend.decodeOne(
      Uint8Array.from([0x00, 0x48]),
      0x02000002,
      "thumb",
    );
    assert.ok(thumbLiteral);
    assert.deepEqual(thumbLiteral.pcRelative, {
      kind: "literal-load",
      displacement: 0,
    });

    const armAdd = backend.decodeOne(
      Uint8Array.from([0x10, 0x00, 0x8f, 0xe2]),
      0x02000000,
      "arm",
    );
    assert.ok(armAdd);
    assert.deepEqual(armAdd.pcRelative, {
      kind: "address-add",
      immediate: 0x10,
    });

    const thumbAdr = backend.decodeOne(
      Uint8Array.from([0x00, 0xa0]),
      0x02000002,
      "thumb",
    );
    assert.ok(thumbAdr);
    assert.deepEqual(thumbAdr.pcRelative, {
      kind: "address-add",
      immediate: 0,
    });
  } finally {
    backend.close();
  }
});

test("returns null for an incomplete instruction", async () => {
  const backend = await createCapstoneArmBackend();
  try {
    assert.equal(
      backend.decodeOne(Uint8Array.from([0x00]), 0x02000000, "arm"),
      null,
    );
  } finally {
    backend.close();
  }
});
