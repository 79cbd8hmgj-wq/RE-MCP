import assert from "node:assert/strict";
import test from "node:test";

import { loadConfig } from "../src/config.js";

function environment(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    RE_MCP_WORKSPACE_ROOT: "/tmp/re-mcp-workspace",
    ...overrides,
  };
}

test("Ghidra config is optional and uses the bounded default timeout", () => {
  const config = loadConfig(environment());

  assert.equal(config.ghidraHome, null);
  assert.equal(config.ghidraTimeoutMs, 900_000);
});

test("Ghidra config resolves the configured home and accepts the maximum timeout", () => {
  const config = loadConfig(environment({
    RE_MCP_GHIDRA_HOME: "/opt/ghidra_12.1.2_PUBLIC",
    RE_MCP_GHIDRA_TIMEOUT_MS: "3600000",
  }));

  assert.equal(config.ghidraHome, "/opt/ghidra_12.1.2_PUBLIC");
  assert.equal(config.ghidraTimeoutMs, 3_600_000);
});

test("Ghidra config rejects timeouts above the supported maximum", () => {
  assert.throws(
    () => loadConfig(environment({ RE_MCP_GHIDRA_TIMEOUT_MS: "3600001" })),
    /RE_MCP_GHIDRA_TIMEOUT_MS must be between 1 and 3600000/,
  );
});

test("tool profile defaults to re-full", () => {
  assert.equal(loadConfig(environment()).toolProfile, "re-full");
});

test("tool profile accepts a known source-controlled profile", () => {
  assert.equal(
    loadConfig(environment({ RE_MCP_TOOL_PROFILE: "re-static-core" })).toolProfile,
    "re-static-core",
  );
});

test("tool profile rejects unknown values", () => {
  assert.throws(
    () => loadConfig(environment({ RE_MCP_TOOL_PROFILE: "everything-cheap" })),
    /RE_MCP_TOOL_PROFILE must be one of:/,
  );
});
