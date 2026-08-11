import assert from "node:assert/strict";
import { rm } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../src/config.js";
import { registerControllerCheckpointTools } from "../src/tools/controller-checkpoint.js";
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

function config(workspaceRoot: string): ServerConfig {
  return {
    workspaceRoot,
    commandTimeoutMs: 30_000,
    maxOutputBytes: 64 * 1024,
  };
}

function register(workspaceRoot: string): FakeMcpServer {
  const server = new FakeMcpServer();
  registerControllerCheckpointTools(server as unknown as McpServer, config(workspaceRoot));
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

function emptyState() {
  return {
    objective: "Continue exact-ROM reverse engineering",
    confirmedFacts: [],
    hypotheses: [],
    completedActions: [],
    nextActions: [],
  };
}

test("registers exactly the two controller checkpoint tools", () => {
  const server = register("/workspace");
  assert.deepEqual([...server.tools.keys()].sort(), [
    "controller_checkpoint_read",
    "controller_checkpoint_write",
  ]);
});

test("checkpoint tool schemas expose no caller-selected output path or arbitrary metadata", () => {
  const server = register("/workspace");
  assert.deepEqual(server.parse("controller_checkpoint_read", { rom: "roms/game.nds" }), {
    rom: "roms/game.nds",
  });
  assert.throws(() => server.parse("controller_checkpoint_read", {
    rom: "roms/game.nds",
    output: "/tmp/checkpoint.json",
  }));

  const parsed = server.parse("controller_checkpoint_write", {
    rom: "roms/game.nds",
    expectedRevision: 0,
    state: emptyState(),
  });
  assert.equal(parsed.rom, "roms/game.nds");
  assert.equal(parsed.expectedRevision, 0);
  assert.throws(() => server.parse("controller_checkpoint_write", {
    rom: "roms/game.nds",
    expectedRevision: 0,
    state: { ...emptyState(), metadata: { provider: "copilot" } },
  }));
  assert.throws(() => server.parse("controller_checkpoint_write", {
    rom: "roms/game.nds",
    expectedRevision: 0,
    state: emptyState(),
    output: "elsewhere/checkpoint.json",
  }));
});

test("checkpoint tools parse the exact ROM and round-trip state without leaking workspace paths", async () => {
  const fixture = await createMutationFixture();
  try {
    const server = register(fixture.directory);
    const rom = path.basename(fixture.romPath);

    const absent = await server.invoke("controller_checkpoint_read", { rom });
    assert.equal(resultError(absent), false);
    const absentBody = resultBody(absent);
    assert.equal(absentBody.exists, false);
    assert.equal(absentBody.expectedRevision, 0);
    assert.equal(JSON.stringify(absentBody).includes(fixture.directory), false);

    const written = await server.invoke("controller_checkpoint_write", {
      rom,
      expectedRevision: 0,
      state: {
        ...emptyState(),
        hypotheses: [{ id: "candidate", statement: "Needs revalidation", evidenceRefs: [] }],
      },
    });
    assert.equal(resultError(written), false);
    const writtenBody = resultBody(written);
    assert.equal(writtenBody.revision, 1);
    assert.equal(writtenBody.authority, "controller-state-only");
    assert.match(String(writtenBody.contentSha256), /^[0-9a-f]{64}$/);
    assert.equal(JSON.stringify(writtenBody).includes(fixture.directory), false);

    const read = await server.invoke("controller_checkpoint_read", { rom });
    assert.equal(resultError(read), false);
    const readBody = resultBody(read);
    assert.equal(readBody.exists, true);
    assert.equal(readBody.expectedRevision, 1);
    assert.equal((readBody.checkpoint as Record<string, unknown>).objective, emptyState().objective);
    assert.equal(JSON.stringify(readBody).includes(fixture.directory), false);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("stale checkpoint writes return structured corrective errors", async () => {
  const fixture = await createMutationFixture();
  try {
    const server = register(fixture.directory);
    const rom = path.basename(fixture.romPath);
    await server.invoke("controller_checkpoint_write", {
      rom,
      expectedRevision: 0,
      state: emptyState(),
    });

    const stale = await server.invoke("controller_checkpoint_write", {
      rom,
      expectedRevision: 0,
      state: emptyState(),
    });
    assert.equal(resultError(stale), true);
    const body = resultBody(stale);
    assert.equal(body.category, "checkpoint-revision-conflict");
    assert.equal(body.operation, "controller_checkpoint_write");
    assert.match(String(body.correctiveAction), /read.*checkpoint|revision/i);
    assert.equal(JSON.stringify(body).includes(fixture.directory), false);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("controller checkpoint registration and authority are surfaced by server capabilities", async () => {
  const source = await import("node:fs/promises").then(({ readFile }) => readFile("src/index.ts", "utf8"));
  assert.match(source, /registerControllerCheckpointTools\(exposedServer, config\)/);
  assert.match(source, /controller_checkpoint_read/);
  assert.match(source, /controller_checkpoint_write/);
  assert.match(source, /controller-state-only/);
  assert.match(source, /provider-neutral|controller checkpoint/i);
});
