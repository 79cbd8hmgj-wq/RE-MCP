import assert from "node:assert/strict";
import test from "node:test";

import { loadConfig } from "../src/config.js";
import { assertSimpleProjectName, resolveInside } from "../src/security/paths.js";

test("loadConfig requires an explicit workspace root", () => {
  assert.throws(() => loadConfig({}), /RE_MCP_WORKSPACE_ROOT is required/);
});

test("loadConfig normalizes bounds", () => {
  const config = loadConfig({
    RE_MCP_WORKSPACE_ROOT: "/tmp/re-mcp",
    RE_MCP_COMMAND_TIMEOUT_MS: "5000",
    RE_MCP_MAX_OUTPUT_BYTES: "4096",
  });
  assert.equal(config.workspaceRoot, "/tmp/re-mcp");
  assert.equal(config.commandTimeoutMs, 5000);
  assert.equal(config.maxOutputBytes, 4096);
});

test("resolveInside accepts a contained path", () => {
  assert.equal(resolveInside("/workspace", "project/file"), "/workspace/project/file");
});

test("resolveInside rejects traversal", () => {
  assert.throws(() => resolveInside("/workspace", "../secret"), /escapes workspace root/);
  assert.throws(() => resolveInside("/workspace", "/etc/passwd"), /escapes workspace root/);
});

test("project names are deliberately narrow", () => {
  assert.equal(assertSimpleProjectName("Bakugan-DS-"), "Bakugan-DS-");
  assert.throws(() => assertSimpleProjectName("nested/project"), /Project name/);
  assert.throws(() => assertSimpleProjectName(".."), /Project name/);
});
