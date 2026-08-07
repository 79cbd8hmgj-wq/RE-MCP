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
