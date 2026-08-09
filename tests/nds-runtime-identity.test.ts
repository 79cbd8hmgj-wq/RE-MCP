import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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

function stoppedStatus(): OwnedProcessStatus {
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
    lastExitCode: null,
    lastSignal: null,
  };
}

function runningStatus(request: OwnedProcessStart): OwnedProcessStatus {
  return {
    running: true,
    pid: 4242,
    startedAt: "2026-08-09T13:30:00.000Z",
    executable: request.executable,
    args: request.args,
    metadata: request.metadata,
    stdout: "",
    stderr: "",
    outputTruncated: false,
    lastExitCode: null,
    lastSignal: null,
  };
}

class RecordingManager extends OwnedProcessManager {
  statusValue: OwnedProcessStatus = stoppedStatus();
  startRequest: OwnedProcessStart | null = null;
  stopCalled = false;

  override status(): OwnedProcessStatus {
    return this.statusValue;
  }

  override async start(request: OwnedProcessStart): Promise<OwnedProcessStatus> {
    this.startRequest = request;
    this.statusValue = runningStatus(request);
    return this.statusValue;
  }

  override async stop(): Promise<OwnedProcessStatus> {
    this.stopCalled = true;
    this.statusValue = stoppedStatus();
    return this.statusValue;
  }
}

class MutatingManager extends RecordingManager {
  constructor(private readonly romPath: string) {
    super();
  }

  override async start(request: OwnedProcessStart): Promise<OwnedProcessStatus> {
    const status = await super.start(request);
    const bytes = await readFile(this.romPath);
    bytes[0x100] = (bytes[0x100] ?? 0) ^ 0xff;
    await writeFile(this.romPath, bytes);
    return status;
  }
}

function createNarrowLaunchRom(): Buffer {
  const buffer = Buffer.alloc(0x400);
  buffer.writeUInt32LE(0x100, 0x20);
  buffer.writeUInt32LE(0x02000000, 0x24);
  buffer.writeUInt32LE(0x02000000, 0x28);
  buffer.writeUInt32LE(0x200, 0x2c);

  // Deliberately malformed full-parser metadata. desmume_start must continue to
  // use the narrow ARM9 header path and must not require a full NDS parse.
  buffer.writeUInt32LE(0xffffffff, 0x40);
  buffer.writeUInt32LE(0x100, 0x44);
  buffer.writeUInt32LE(0xffffffff, 0x48);
  buffer.writeUInt32LE(0x100, 0x4c);
  buffer.writeUInt32LE(0xffffffff, 0x50);
  buffer.writeUInt32LE(0x20, 0x54);
  return buffer;
}

function config(workspaceRoot: string): ServerConfig {
  return {
    workspaceRoot,
    commandTimeoutMs: 30_000,
    maxOutputBytes: 64 * 1024,
  };
}

function controller(): DebugController {
  return new DebugController(() =>
    new GdbSession({
      host: "127.0.0.1",
      port: 20000,
      maxReplyBytes: 32_768,
      connectTimeoutMs: 1000,
    }),
  );
}

async function createFixture(directory: string): Promise<void> {
  const launcher = path.join(directory, "desmume-launcher");
  await writeFile(launcher, "#!/bin/sh\nexit 0\n");
  await chmod(launcher, 0o755);
  await writeFile(path.join(directory, "game.nds"), createNarrowLaunchRom());
}

function resultText(result: unknown): string {
  const content = (result as { content?: readonly { text?: string }[] }).content;
  return content?.[0]?.text ?? "";
}

test("desmume_start binds a full ROM SHA-256 without requiring a full NDS parse", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "re-mcp-runtime-identity-"));
  try {
    await createFixture(directory);
    const manager = new RecordingManager();
    const debugController = controller();
    const server = new FakeMcpServer();
    registerDesmumeTools(
      server as unknown as McpServer,
      config(directory),
      manager,
      debugController,
    );

    const result = await server.invoke("desmume_start", {
      launcher: "desmume-launcher",
      rom: "game.nds",
      arm9GdbPort: 20000,
    });

    assert.equal((result as { isError?: boolean }).isError, undefined);
    assert.notEqual(manager.startRequest, null);
    assert.equal(manager.startRequest?.metadata.rom, path.join(directory, "game.nds"));
    assert.match(String(manager.startRequest?.metadata.romSha256), /^[0-9a-f]{64}$/u);
    assert.equal(debugController.status().initialized, true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("desmume_start fails closed when the ROM changes during process start", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "re-mcp-runtime-mutation-"));
  try {
    await createFixture(directory);
    const romPath = path.join(directory, "game.nds");
    const manager = new MutatingManager(romPath);
    const debugController = controller();
    const server = new FakeMcpServer();
    registerDesmumeTools(
      server as unknown as McpServer,
      config(directory),
      manager,
      debugController,
    );

    const result = await server.invoke("desmume_start", {
      launcher: "desmume-launcher",
      rom: "game.nds",
      arm9GdbPort: 20000,
    });

    assert.equal((result as { isError?: boolean }).isError, true);
    assert.match(resultText(result), /ROM changed during DeSmuME start/i);
    assert.equal(manager.stopCalled, true);
    assert.equal(manager.status().running, false);
    assert.deepEqual(debugController.status(), {
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
