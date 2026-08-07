import assert from "node:assert/strict";
import test from "node:test";

import type { ServerConfig } from "../src/config.js";
import { NdsError } from "../src/services/nds/errors.js";
import {
  runGhidraInvocation,
  type GhidraInvocation,
} from "../src/services/nds/ghidra-runner.js";

function config(): ServerConfig {
  return {
    workspaceRoot: process.cwd(),
    commandTimeoutMs: 30_000,
    maxOutputBytes: 64 * 1024,
    ghidraHome: "/opt/ghidra_12.1.2_PUBLIC",
    ghidraTimeoutMs: 5_000,
  };
}

function invocation(source: string): GhidraInvocation {
  return {
    executable: process.execPath,
    args: ["-e", source],
    cwd: process.cwd(),
    stage: "arm9-import",
  };
}

test("nonzero Ghidra exits retain bounded stdout and stderr diagnostics", async () => {
  await assert.rejects(
    runGhidraInvocation(
      invocation("console.log('GHIDRA_STDOUT_DETAIL'); console.error('GHIDRA_STDERR_DETAIL'); process.exit(7)"),
      config(),
    ),
    (error: unknown) => {
      assert.equal(error instanceof NdsError, true);
      assert.equal((error as NdsError).category, "ghidra-import-failed");
      assert.match((error as Error).message, /GHIDRA_STDOUT_DETAIL/);
      assert.match((error as Error).message, /GHIDRA_STDERR_DETAIL/);
      assert.match((error as Error).message, /exit code 7/);
      return true;
    },
  );
});

test("Ghidra failure diagnostics are clipped independently of the process capture ceiling", async () => {
  await assert.rejects(
    runGhidraInvocation(
      invocation("console.error('PREFIX-' + 'x'.repeat(20000) + '-GHIDRA_TAIL'); process.exit(2)"),
      config(),
    ),
    (error: unknown) => {
      assert.equal(error instanceof NdsError, true);
      const message = (error as Error).message;
      assert.equal(Buffer.byteLength(message, "utf8") < 12 * 1024, true);
      assert.match(message, /GHIDRA_TAIL/);
      assert.match(message, /diagnostic clipped/i);
      return true;
    },
  );
});
