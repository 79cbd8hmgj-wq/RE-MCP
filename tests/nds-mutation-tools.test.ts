import assert from "node:assert/strict";
import { access, rm } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../src/config.js";
import { registerNdsMutationTools } from "../src/tools/nds-mutation.js";
import { createMutationFixture } from "./helpers/nds-mutation-fixture.js";

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
    const tool = this.tools.get(name);
    if (tool === undefined) throw new Error(`Unknown test tool: ${name}`);
    return z.object(tool.schema).strict().parse(input);
  }

  async invoke(name: string, input: unknown): Promise<unknown> {
    const tool = this.tools.get(name);
    if (tool === undefined) throw new Error(`Unknown test tool: ${name}`);
    return await tool.handler(this.parse(name, input));
  }
}

function config(workspaceRoot = "/workspace"): ServerConfig {
  return {
    workspaceRoot,
    commandTimeoutMs: 30_000,
    maxOutputBytes: 64 * 1024,
  };
}

function register(workspaceRoot = "/workspace"): FakeMcpServer {
  const server = new FakeMcpServer();
  registerNdsMutationTools(
    server as unknown as McpServer,
    config(workspaceRoot),
  );
  return server;
}

function resultEnvelope(result: unknown): {
  readonly content: readonly { readonly type: string; readonly text: string }[];
  readonly isError?: boolean;
} {
  return result as {
    readonly content: readonly { readonly type: string; readonly text: string }[];
    readonly isError?: boolean;
  };
}

function resultBody(result: unknown): Record<string, unknown> {
  const envelope = resultEnvelope(result);
  assert.equal(envelope.content[0]?.type, "text");
  return JSON.parse(envelope.content[0]!.text) as Record<string, unknown>;
}

function resultError(result: unknown): boolean {
  return resultEnvelope(result).isError === true;
}

function workspaceRomPath(romPath: string): string {
  return path.basename(romPath);
}

test("registers exactly the three controlled NDS mutation tools", () => {
  const server = register();
  assert.deepEqual([...server.tools.keys()].sort(), [
    "nds_mutation_build",
    "nds_mutation_validate",
    "nds_mutation_verify",
  ]);
});

test("mutation tool schemas accept only ROM and manifest paths", () => {
  const server = register();

  for (const name of [
    "nds_mutation_validate",
    "nds_mutation_build",
    "nds_mutation_verify",
  ]) {
    assert.deepEqual(server.parse(name, {
      rom: "roms/game.nds",
      manifest: "plans/mod.json",
    }), {
      rom: "roms/game.nds",
      manifest: "plans/mod.json",
    });
    assert.throws(() => server.parse(name, {
      rom: "roms/game.nds",
      manifest: "plans/mod.json",
      output: "/tmp/game.nds",
    }));
  }
});

test("validate compiles a deterministic plan without creating an output tree", async () => {
  const fixture = await createMutationFixture();
  try {
    const manifest = await fixture.writeManifest({ outputFilename: "tool-build.nds" });
    const server = register(fixture.directory);
    const result = await server.invoke("nds_mutation_validate", {
      rom: workspaceRomPath(fixture.romPath),
      manifest,
    });

    assert.equal(resultError(result), false);
    const body = resultBody(result);
    const output = body.output as Record<string, unknown>;
    assert.equal(output.filename, "tool-build.nds");
    assert.match(String(output.buildId), /^[0-9a-f]{64}$/u);
    assert.equal(JSON.stringify(body).includes(fixture.directory), false);
    await assert.rejects(access(path.join(fixture.directory, "output", "nds")));
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("build publishes a verified ROM and verify freshly revalidates it", async () => {
  const fixture = await createMutationFixture();
  try {
    const manifest = await fixture.writeManifest({ outputFilename: "tool-build.nds" });
    const server = register(fixture.directory);
    const input = {
      rom: workspaceRomPath(fixture.romPath),
      manifest,
    };

    const built = await server.invoke("nds_mutation_build", input);
    assert.equal(resultError(built), false);
    const buildBody = resultBody(built);
    const verification = buildBody.verification as Record<string, unknown>;
    assert.equal(verification.status, "passed");
    assert.equal(verification.unexpectedChangedBytes, 0);
    assert.equal(buildBody.reused, false);
    assert.equal(path.isAbsolute(String(buildBody.outputRoot)), false);
    assert.equal(path.isAbsolute(String(buildBody.outputRomPath)), false);
    assert.equal(JSON.stringify(buildBody).includes(fixture.directory), false);

    const verified = await server.invoke("nds_mutation_verify", input);
    assert.equal(resultError(verified), false);
    const verifyBody = resultBody(verified);
    assert.equal(verifyBody.buildId, buildBody.buildId);
    assert.equal(verifyBody.outputSha256, buildBody.outputSha256);
    assert.equal(verifyBody.reused, true);
    assert.equal(
      (verifyBody.verification as Record<string, unknown>).unexpectedChangedBytes,
      0,
    );
    assert.equal(JSON.stringify(verifyBody).includes(fixture.directory), false);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("stale source identity returns a structured actionable mutation error", async () => {
  const fixture = await createMutationFixture();
  try {
    const manifest = await fixture.writeManifest({
      sourceSha256: "0".repeat(64),
      outputFilename: "stale.nds",
    });
    const server = register(fixture.directory);
    const result = await server.invoke("nds_mutation_validate", {
      rom: workspaceRomPath(fixture.romPath),
      manifest,
    });

    assert.equal(resultError(result), true);
    const body = resultBody(result);
    assert.equal(body.category, "source-rom-mismatch");
    assert.equal(body.operation, "nds_mutation_validate");
    assert.match(String(body.correctiveAction), /exact ROM|source|revision/iu);
    assert.equal(JSON.stringify(body).includes(fixture.directory), false);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});
