import assert from "node:assert/strict";
import test from "node:test";

import { OwnedProcessManager } from "../src/services/owned-process.js";

test("owned process manager starts, reports, and stops only its child", async () => {
  const manager = new OwnedProcessManager();
  const started = await manager.start({
    executable: process.execPath,
    args: ["-e", "console.log('ready'); setInterval(() => {}, 1000)"],
    cwd: process.cwd(),
    maxOutputBytes: 1024,
    metadata: { purpose: "test" },
  });

  assert.equal(started.running, true);
  assert.equal(typeof started.pid, "number");
  assert.equal(started.metadata.purpose, "test");
  await assert.rejects(
    manager.start({
      executable: process.execPath,
      args: ["-e", "setInterval(() => {}, 1000)"],
      cwd: process.cwd(),
      maxOutputBytes: 1024,
      metadata: {},
    }),
    /already running/,
  );

  const stopped = await manager.stop(2_000);
  assert.equal(stopped.running, false);
  assert.equal(stopped.pid, null);
  assert.equal(stopped.lastSignal, "SIGTERM");
});

test("owned process manager bounds captured output", async () => {
  const manager = new OwnedProcessManager();
  await manager.start({
    executable: process.execPath,
    args: ["-e", "process.stdout.write('x'.repeat(5000)); setTimeout(() => {}, 5000)"],
    cwd: process.cwd(),
    maxOutputBytes: 64,
    metadata: {},
  });

  await new Promise((resolve) => setTimeout(resolve, 100));
  const status = manager.status();
  assert.equal(status.stdout.length, 64);
  assert.equal(status.outputTruncated, true);
  await manager.stop(2_000);
});
