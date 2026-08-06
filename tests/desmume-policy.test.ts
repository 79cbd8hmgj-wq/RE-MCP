import assert from "node:assert/strict";
import test from "node:test";

import { buildDesmumeArguments, validateGdbPort } from "../src/tools/desmume-policy.js";

test("DeSmuME arguments match the verified debug launcher contract", () => {
  assert.deepEqual(buildDesmumeArguments(20000, "/workspace/game.nds"), [
    "--arm9gdb=20000",
    "/workspace/game.nds",
  ]);
});

test("ARM9 GDB ports exclude privileged and invalid values", () => {
  assert.equal(validateGdbPort(20000), 20000);
  assert.throws(() => validateGdbPort(0), /1024 through 65535/);
  assert.throws(() => validateGdbPort(1023), /1024 through 65535/);
  assert.throws(() => validateGdbPort(65536), /1024 through 65535/);
  assert.throws(() => validateGdbPort(20000.5), /1024 through 65535/);
});
