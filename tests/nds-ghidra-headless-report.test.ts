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
    ghidraHome: "/opt/ghidra",
    ghidraTimeoutMs: 30_000,
  };
}

function invocation(
  source: string,
  stage: GhidraInvocation["stage"] = "arm9-import",
): GhidraInvocation {
  return {
    executable: process.execPath,
    args: ["-e", source],
    cwd: process.cwd(),
    stage,
  };
}

test("Ghidra runner rejects a reported project save failure even when analyzeHeadless exits zero", async () => {
  const marker = "REPORT: Save failed for: RE-MCP_ARM9";
  await assert.rejects(
    runGhidraInvocation(
      invocation(`console.log(${JSON.stringify(marker)})`),
      config(),
    ),
    (error: unknown) =>
      error instanceof NdsError
      && error.category === "ghidra-import-failed"
      && error.message.includes(marker),
  );
});

test("Ghidra runner rejects RE-MCP script errors even when analyzeHeadless exits zero", async () => {
  const marker = "REPORT SCRIPT ERROR: ReMcpImportEvidence.java : IllegalArgumentException: Invalid opIndex specified: -2";
  await assert.rejects(
    runGhidraInvocation(
      invocation(`console.error(${JSON.stringify(marker)})`),
      config(),
    ),
    (error: unknown) =>
      error instanceof NdsError
      && error.category === "ghidra-import-failed"
      && error.message.includes(marker),
  );

  await assert.rejects(
    runGhidraInvocation(
      invocation(`console.error(${JSON.stringify(marker)})`, "arm9-process"),
      config(),
    ),
    (error: unknown) =>
      error instanceof NdsError
      && error.category === "ghidra-analysis-failed"
      && error.message.includes(marker),
  );
});

test("Ghidra runner does not reject a successful import report", async () => {
  const result = await runGhidraInvocation(
    invocation("console.log('REPORT: Import succeeded')"),
    config(),
  );
  assert.equal(result.exitCode, 0);
});
