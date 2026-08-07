import assert from "node:assert/strict";
import test from "node:test";

import { runProcess } from "../src/services/process-runner.js";

test("process runner terminates when the configured output limit is exceeded", async () => {
  const request = {
    executable: process.execPath,
    args: [
      "-e",
      "process.stdout.write('x'.repeat(1024)); setInterval(() => {}, 1000)",
    ],
    cwd: process.cwd(),
    timeoutMs: 500,
    maxOutputBytes: 64,
    terminateOnOutputLimit: true,
  } as Parameters<typeof runProcess>[0] & {
    readonly terminateOnOutputLimit: boolean;
  };

  const result = await runProcess(request) as Awaited<ReturnType<typeof runProcess>> & {
    readonly outputLimitExceeded?: boolean;
  };

  assert.equal(result.outputLimitExceeded, true);
  assert.equal(result.stdout.length, 64);
  assert.equal(result.timedOut, false);
});
