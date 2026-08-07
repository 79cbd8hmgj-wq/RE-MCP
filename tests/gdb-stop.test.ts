import assert from "node:assert/strict";
import test from "node:test";

import { parseGdbStopReply } from "../src/services/gdb-stop.js";

test("parses signal stop replies", () => {
  assert.deepEqual(parseGdbStopReply("S05"), {
    kind: "signal",
    signal: 5,
    fields: {},
    raw: "S05",
  });
});

test("parses extended stop fields", () => {
  assert.deepEqual(parseGdbStopReply("T05thread:1;20:78563412;"), {
    kind: "signal",
    signal: 5,
    fields: { thread: "1", "20": "78563412" },
    raw: "T05thread:1;20:78563412;",
  });
});

test("parses normal and signal exits", () => {
  assert.deepEqual(parseGdbStopReply("W00"), {
    kind: "exited",
    status: 0,
    raw: "W00",
  });
  assert.deepEqual(parseGdbStopReply("X0b"), {
    kind: "terminated",
    signal: 11,
    raw: "X0b",
  });
});

test("rejects malformed and unsupported replies", () => {
  assert.throws(() => parseGdbStopReply("S0g"), /Malformed GDB stop byte/);
  assert.throws(() => parseGdbStopReply("T05thread;"), /Malformed GDB stop field/);
  assert.throws(() => parseGdbStopReply("OK"), /Unsupported GDB stop reply/);
  assert.throws(() => parseGdbStopReply("S0500"), /Unsupported GDB stop reply/);
});
