import assert from "node:assert/strict";
import test from "node:test";

import { buildDesmumeArguments, validateGdbPort } from "../src/tools/desmume-policy.js";

test("Linux DeSmuME arguments match the verified GDB launcher contract", () => {
  assert.deepEqual(buildDesmumeArguments("linux-cli", 20000, "/workspace/game.nds"), [
    "--arm9gdb=20000",
    "/workspace/game.nds",
  ]);
});

test("Catalina Cocoa launcher receives ROM path and ARM9 port", () => {
  assert.deepEqual(buildDesmumeArguments("macos-cocoa", 20000, "/workspace/game.nds"), [
    "/workspace/game.nds",
    "20000",
  ]);
});

test("ARM9 GDB ports exclude privileged and invalid values", () => {
  assert.equal(validateGdbPort(20000), 20000);
  assert.throws(() => validateGdbPort(0), /1024 through 65535/);
  assert.throws(() => validateGdbPort(1023), /1024 through 65535/);
  assert.throws(() => validateGdbPort(65536), /1024 through 65535/);
  assert.throws(() => validateGdbPort(20000.5), /1024 through 65535/);
});
