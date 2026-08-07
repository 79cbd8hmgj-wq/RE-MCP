import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../src/config.js";
import { DebugController } from "../src/services/debug-controller.js";
import { GdbSession } from "../src/services/gdb-session.js";
import {
  OwnedProcessManager,
  type OwnedProcessExitEvent,
  type OwnedProcessExitListener,
  type OwnedProcessStart,
  type OwnedProcessStatus,
} from "../src/services/owned-process.js";
import { registerDesmumeTools } from "../src/tools/desmume.js";

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

  async invoke(name: string, input: unknown): Promise<unknown> {
    const tool = this.tools.get(name);
    if (tool === undefined) throw new Error(`Unknown test tool: ${name}`);
    return await tool.handler(z.object(tool.schema).parse(input));
  }
}

function stoppedStatus(exitCode: number | null = null): OwnedProcessStatus {
  return {
    running: false,
    pid: null,
    startedAt: null,
    executable: null,
    args: [],
    metadata: {},
    stdout: "",
    stderr: "",
    outputTruncated: false,
    lastExitCode: exitCode,
    lastSignal: null,
  };
}

class ExitDuringStartManager extends OwnedProcessManager {
  readonly #listeners = new Set<OwnedProcessExitListener>();
  #status: OwnedProcessStatus = stoppedStatus();

  override onExit(listener: OwnedProcessExitListener): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  override status(): OwnedProcessStatus {
    return this.#status;
  }

  override async start(request: OwnedProcessStart): Promise<OwnedProcessStatus> {
    const started: OwnedProcessStatus = {
      running: true,
      pid: 4321,
      startedAt: "2026-08-07T07:40:00.000Z",
      executable: request.executable,
      args: request.args,
      metadata: request.metadata,
      stdout: "",
      stderr: "",
      outputTruncated: false,
      lastExitCode: null,
      lastSignal: null,
    };
    this.#status = stoppedStatus(0);
    const event: OwnedProcessExitEvent = {
      pid: started.pid,
      startedAt: started.startedAt!,
      executable: started.executable!,
      args: started.args,
      metadata: started.metadata,
      exitCode: 0,
      signal: null,
    };
    for (const listener of this.#listeners) listener(event);
    return started;
  }
}

function createRom(): Buffer {
  const buffer = Buffer.alloc(0x400);
  buffer.writeUInt32LE(0x100, 0x20);
  buffer.writeUInt32LE(0x02000000, 0x28);
  buffer.writeUInt32LE(0x200, 0x2c);
  return buffer;
}

function config(workspaceRoot: string): ServerConfig {
  return {
    workspaceRoot,
    commandTimeoutMs: 30_000,
    maxOutputBytes: 64 * 1024,
  };
}

test("desmume_start does not initialize debugger state for a process that already exited", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "re-mcp-start-race-"));
  try {
    const launcher = path.join(directory, "desmume-launcher");
    const rom = path.join(directory, "game.nds");
    await writeFile(launcher, "#!/bin/sh\nexit 0\n");
    await chmod(launcher, 0o755);
    await writeFile(rom, createRom());

    const manager = new ExitDuringStartManager();
    const controller = new DebugController(() =>
      new GdbSession({
        host: "127.0.0.1",
        port: 20000,
        maxReplyBytes: 32_768,
        connectTimeoutMs: 1000,
      }),
    );
    const server = new FakeMcpServer();
    registerDesmumeTools(
      server as unknown as McpServer,
      config(directory),
      manager,
      controller,
    );

    const result = await server.invoke("desmume_start", {
      launcher: "desmume-launcher",
      rom: "game.nds",
      arm9GdbPort: 20000,
    });

    assert.equal(manager.status().running, false);
    assert.equal((result as { isError?: boolean }).isError, true);
    assert.deepEqual(controller.status(), {
      initialized: false,
      state: "unavailable",
      breakpoints: [],
      maximumBreakpoints: 32,
      executableRanges: [],
      hasStop: false,
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
