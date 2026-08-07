import assert from "node:assert/strict";
import test from "node:test";

import {
  OwnedProcessManager,
  type OwnedProcessExitEvent,
} from "../src/services/owned-process.js";

test("owned process exit listeners receive the exact process generation", async () => {
  const manager = new OwnedProcessManager();
  let resolveExit!: (event: OwnedProcessExitEvent) => void;
  const exited = new Promise<OwnedProcessExitEvent>((resolve) => {
    resolveExit = resolve;
  });
  const unsubscribe = manager.onExit(resolveExit);

  const started = await manager.start({
    executable: process.execPath,
    args: ["-e", "setTimeout(() => process.exit(0), 20)"],
    cwd: process.cwd(),
    maxOutputBytes: 4096,
    metadata: { emulator: "desmume", arm9GdbPort: 20000 },
  });
  assert.equal(started.running, true);
  assert.notEqual(started.pid, null);
  assert.notEqual(started.startedAt, null);

  const event = await Promise.race([
    exited,
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("Owned process exit event did not fire")), 2000),
    ),
  ]);
  unsubscribe();

  assert.equal(event.pid, started.pid);
  assert.equal(event.startedAt, started.startedAt);
  assert.deepEqual(event.metadata, started.metadata);
  assert.equal(event.exitCode, 0);
  assert.equal(event.signal, null);
  assert.equal(manager.status().running, false);
});

test("unsubscribed exit listeners are not called", async () => {
  const manager = new OwnedProcessManager();
  let calls = 0;
  const unsubscribe = manager.onExit(() => {
    calls += 1;
  });
  unsubscribe();

  await manager.start({
    executable: process.execPath,
    args: ["-e", "setTimeout(() => process.exit(0), 20)"],
    cwd: process.cwd(),
    maxOutputBytes: 4096,
    metadata: { emulator: "desmume" },
  });

  for (let attempt = 0; attempt < 100 && manager.status().running; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.equal(manager.status().running, false);
  assert.equal(calls, 0);
});
