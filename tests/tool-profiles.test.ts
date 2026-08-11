import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import {
  FULL_TOOL_NAMES,
  TOOL_PROFILES,
  createProfiledToolRegistrar,
  resolveToolProfile,
} from "../src/tools/profiles.js";

async function listProfileTools(profile: string) {
  const workspace = await mkdtemp(path.join(os.tmpdir(), "re-mcp-profile-"));
  const client = new Client({ name: "tool-profile-test", version: "1.0.0" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["--import", "tsx", "src/index.ts"],
    env: {
      ...Object.fromEntries(
        Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] !== undefined),
      ),
      RE_MCP_WORKSPACE_ROOT: workspace,
      RE_MCP_TOOL_PROFILE: profile,
    },
    stderr: "pipe",
  });

  try {
    await client.connect(transport);
    const response = await client.listTools();
    return response.tools;
  } finally {
    await client.close().catch(() => undefined);
    await rm(workspace, { recursive: true, force: true });
  }
}

test("re-full retains every shipped tool including high-level orchestration", () => {
  assert.equal(FULL_TOOL_NAMES.length, 54);
  assert.deepEqual(TOOL_PROFILES["re-full"], FULL_TOOL_NAMES);
  assert.equal(FULL_TOOL_NAMES.includes("re_trace_function"), true);
  assert.equal(FULL_TOOL_NAMES.includes("re_investigate_data_usage"), true);
});

test("profiles are allowlists and invalid profile names fail closed", () => {
  assert.throws(() => resolveToolProfile("unknown"), /RE_MCP_TOOL_PROFILE must be one of:/);

  const registrations: string[] = [];
  const fakeServer = {
    tool(name: string) {
      registrations.push(name);
    },
  };
  const profiled = createProfiledToolRegistrar(fakeServer as never, "re-build");
  (profiled.tool as (...args: unknown[]) => unknown)("nds_mutation_validate");
  (profiled.tool as (...args: unknown[]) => unknown)("desmume_start");
  assert.deepEqual(registrations, ["nds_mutation_validate"]);
});

test("re-static-core advertises only its allowlist and cuts actual schema payload by at least 70%", async () => {
  const full = await listProfileTools("re-full");
  const compact = await listProfileTools("re-static-core");

  assert.deepEqual(
    compact.map((tool) => tool.name).sort(),
    [...TOOL_PROFILES["re-static-core"]].sort(),
  );
  assert.equal(full.length, FULL_TOOL_NAMES.length);

  const fullBytes = Buffer.byteLength(JSON.stringify(full), "utf8");
  const compactBytes = Buffer.byteLength(JSON.stringify(compact), "utf8");
  assert.ok(
    compactBytes <= Math.floor(fullBytes * 0.3),
    `expected re-static-core schema payload <=30% of re-full; full=${fullBytes}, compact=${compactBytes}`,
  );
});