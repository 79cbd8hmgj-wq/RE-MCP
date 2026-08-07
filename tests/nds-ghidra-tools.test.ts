import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../src/config.js";
import { NdsError } from "../src/services/nds/errors.js";
import {
  registerNdsGhidraTools,
  type NdsGhidraToolDependencies,
} from "../src/tools/nds-ghidra.js";

interface RegisteredTool {
  readonly schema: z.ZodRawShape;
  readonly handler: (input: Record<string, unknown>) => Promise<unknown>;
}

class FakeMcpServer {
  readonly tools = new Map<string, RegisteredTool>();

  tool(
    name: string,
    _description: string,
    schema: z.ZodRawShape,
    handler: (input: Record<string, unknown>) => Promise<unknown>,
  ): void {
    this.tools.set(name, { schema, handler });
  }

  parse(name: string, input: unknown): Record<string, unknown> {
    const tool = this.require(name);
    return z.object(tool.schema).parse(input);
  }

  async invoke(name: string, input: unknown): Promise<unknown> {
    const tool = this.require(name);
    return await tool.handler(this.parse(name, input));
  }

  private require(name: string): RegisteredTool {
    const tool = this.tools.get(name);
    if (tool === undefined) throw new Error(`Unknown test tool: ${name}`);
    return tool;
  }
}

interface TextToolResult {
  readonly content: Array<{ readonly type: string; readonly text: string }>;
  readonly isError?: boolean;
}

function body(result: unknown): Record<string, unknown> {
  const typed = result as TextToolResult;
  assert.equal(typed.content[0]?.type, "text");
  return JSON.parse(typed.content[0]!.text) as Record<string, unknown>;
}

function isError(result: unknown): boolean {
  return (result as TextToolResult).isError === true;
}

function config(maxOutputBytes = 64 * 1024): ServerConfig {
  return {
    workspaceRoot: "/workspace",
    commandTimeoutMs: 30_000,
    maxOutputBytes,
    ghidraHome: "/opt/ghidra_12.1.2_PUBLIC",
    ghidraTimeoutMs: 900_000,
  };
}

function successDependencies(diagnostic = ""): NdsGhidraToolDependencies {
  return {
    bootstrap: async (romPath) => ({
      sourceRomSha256: "a".repeat(64),
      projectPath: "analysis/ghidra/nds/" + "a".repeat(64) + "/project",
      ghidraVersion: "12.1.2",
      manifestSha256: "b".repeat(64),
      runKind: "initial",
      processors: [],
      diagnostic,
      resolvedRomForTest: romPath,
    }),
    status: async (romPath) => ({
      sourceRomSha256: "a".repeat(64),
      projectPath: "analysis/ghidra/nds/" + "a".repeat(64) + "/project",
      projectExists: true,
      bridgeExists: true,
      manifestSha256: "b".repeat(64),
      ghidraVersion: "12.1.2",
      processors: [],
      lastFailure: null,
      resolvedRomForTest: romPath,
    }),
  } as unknown as NdsGhidraToolDependencies;
}

function register(
  cfg: ServerConfig = config(),
  dependencies: NdsGhidraToolDependencies = successDependencies(),
): FakeMcpServer {
  const server = new FakeMcpServer();
  registerNdsGhidraTools(server as unknown as McpServer, cfg, dependencies);
  return server;
}

test("registers exactly the two bounded NDS Ghidra tools", () => {
  const server = register();
  assert.deepEqual([...server.tools.keys()].sort(), [
    "nds_ghidra_bootstrap",
    "nds_ghidra_status",
  ]);
});

test("Ghidra MCP schemas expose only one canonical ROM selector", () => {
  const server = register();
  for (const name of ["nds_ghidra_bootstrap", "nds_ghidra_status"]) {
    const tool = server.tools.get(name)!;
    assert.deepEqual(Object.keys(tool.schema), ["rom"]);
    assert.deepEqual(server.parse(name, { rom: "game.nds" }), { rom: "game.nds" });
    assert.throws(() => server.parse(name, { rom: "" }), /too_small|at least 1|String must contain/);
  }

  const forbidden = [
    "executable",
    "projectPath",
    "processor",
    "language",
    "loader",
    "args",
    "env",
    "scriptPath",
    "outputPath",
  ];
  for (const tool of server.tools.values()) {
    for (const key of forbidden) assert.equal(key in tool.schema, false, key);
  }
});

test("Ghidra MCP tools resolve ROM paths inside the configured workspace", async () => {
  const server = register();
  const bootstrap = body(await server.invoke("nds_ghidra_bootstrap", { rom: "roms/game.nds" }));
  const status = body(await server.invoke("nds_ghidra_status", { rom: "roms/game.nds" }));
  assert.equal(bootstrap.resolvedRomForTest, path.join("/workspace", "roms", "game.nds"));
  assert.equal(status.resolvedRomForTest, path.join("/workspace", "roms", "game.nds"));
});

test("Ghidra MCP success results use the shared serialized output bound", async () => {
  const server = register(config(128), successDependencies("x".repeat(1024)));
  const result = await server.invoke("nds_ghidra_bootstrap", { rom: "game.nds" });
  const parsed = body(result);
  assert.equal(isError(result), true);
  assert.equal(parsed.category, "output-bound-exceeded");
  assert.match(String(parsed.correctiveAction), /RE_MCP_MAX_OUTPUT_BYTES|serialized result/i);
});

test("Ghidra MCP errors preserve structured categories and corrective actions", async () => {
  const dependencies: NdsGhidraToolDependencies = {
    bootstrap: async () => {
      throw new NdsError("ghidra-not-configured", "RE_MCP_GHIDRA_HOME is not configured");
    },
    status: async () => {
      throw new NdsError("project-state-mismatch", "project ownership mismatch");
    },
  };
  const server = register(config(), dependencies);

  const bootstrapResult = await server.invoke("nds_ghidra_bootstrap", { rom: "game.nds" });
  const bootstrapError = body(bootstrapResult);
  assert.equal(isError(bootstrapResult), true);
  assert.equal(bootstrapError.category, "ghidra-not-configured");
  assert.match(String(bootstrapError.correctiveAction), /RE_MCP_GHIDRA_HOME/);

  const statusResult = await server.invoke("nds_ghidra_status", { rom: "game.nds" });
  const statusError = body(statusResult);
  assert.equal(isError(statusResult), true);
  assert.equal(statusError.category, "project-state-mismatch");
  assert.match(String(statusError.correctiveAction), /will not overwrite|ownership|state/i);
});

test("index registers both Ghidra tools and advertises their trust boundary", async () => {
  const indexPath = fileURLToPath(new URL("../src/index.ts", import.meta.url));
  const source = await readFile(indexPath, "utf8");
  assert.match(source, /registerNdsGhidraTools\(server, config\)/);
  assert.match(source, /"nds_ghidra_bootstrap"/);
  assert.match(source, /"nds_ghidra_status"/);
  assert.match(source, /Ghidra/i);
  assert.match(source, /SHA-scoped|SHA-256/);
  assert.match(source, /non-authoritative|not authoritative/i);
  assert.match(source, /analyst/i);
});
