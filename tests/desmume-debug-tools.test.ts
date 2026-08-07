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
  type OwnedProcessStart,
  type OwnedProcessStatus,
} from "../src/services/owned-process.js";
import type { Arm9ExecutableRange } from "../src/services/nds-arm9.js";
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

  parse(name: string, input: unknown): Record<string, unknown> {
    const tool = this.#require(name);
    return z.object(tool.schema).parse(input);
  }

  async invoke(name: string, input: unknown): Promise<unknown> {
    const tool = this.#require(name);
    return await tool.handler(this.parse(name, input));
  }

  #require(name: string): RegisteredTool {
    const tool = this.tools.get(name);
    if (tool === undefined) throw new Error(`Unknown test tool: ${name}`);
    return tool;
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

class FakeOwnedProcessManager extends OwnedProcessManager {
  readonly starts: OwnedProcessStart[] = [];
  #status: OwnedProcessStatus = stoppedStatus();

  override async start(request: OwnedProcessStart): Promise<OwnedProcessStatus> {
    this.starts.push(request);
    this.#status = {
      running: true,
      pid: 4321,
      startedAt: "2026-08-07T07:15:00.000Z",
      executable: request.executable,
      args: request.args,
      metadata: request.metadata,
      stdout: "",
      stderr: "",
      outputTruncated: false,
      lastExitCode: null,
      lastSignal: null,
    };
    return this.#status;
  }

  override status(): OwnedProcessStatus {
    return this.#status;
  }

  override async stop(_graceMs = 5_000): Promise<OwnedProcessStatus> {
    this.#status = stoppedStatus();
    return this.#status;
  }
}

class SpyDebugController extends DebugController {
  readonly initializations: Array<{
    readonly identity: string;
    readonly range: Arm9ExecutableRange;
  }> = [];

  constructor() {
    super(() =>
      new GdbSession({
        host: "127.0.0.1",
        port: 20000,
        maxReplyBytes: 32_768,
        connectTimeoutMs: 1000,
      }),
    );
  }

  override initialize(identity: string, range: Arm9ExecutableRange): void {
    this.initializations.push({ identity, range });
  }
}

function config(workspaceRoot: string): ServerConfig {
  return {
    workspaceRoot,
    commandTimeoutMs: 30_000,
    maxOutputBytes: 64 * 1024,
  };
}

function register(
  workspaceRoot: string,
  manager = new FakeOwnedProcessManager(),
  controller = new SpyDebugController(),
): {
  readonly server: FakeMcpServer;
  readonly manager: FakeOwnedProcessManager;
  readonly controller: SpyDebugController;
} {
  const server = new FakeMcpServer();
  registerDesmumeTools(
    server as unknown as McpServer,
    config(workspaceRoot),
    manager,
    controller,
  );
  return { server, manager, controller };
}

function createRom(): Buffer {
  const buffer = Buffer.alloc(0x400);
  buffer.writeUInt32LE(0x100, 0x20);
  buffer.writeUInt32LE(0x02000000, 0x28);
  buffer.writeUInt32LE(0x200, 0x2c);
  return buffer;
}

test("registers the nine controlled dynamic debugger tools", () => {
  const { server } = register("/workspace");
  const expected = [
    "desmume_breakpoint_add",
    "desmume_breakpoint_remove",
    "desmume_breakpoint_list",
    "desmume_continue",
    "desmume_step_instruction",
    "desmume_pause",
    "desmume_wait_for_stop",
    "desmume_capture_stop_context",
    "desmume_executable_ranges_replace",
  ];
  for (const name of expected) assert.equal(server.tools.has(name), true, name);
});

test("execution tool schemas enforce approved bounds and context defaults", () => {
  const { server } = register("/workspace");

  assert.deepEqual(server.parse("desmume_continue", {}), {
    timeoutMs: 10_000,
    captureContext: true,
  });
  assert.throws(
    () => server.parse("desmume_continue", { timeoutMs: 99 }),
    /greater than or equal to 100/,
  );
  assert.throws(
    () => server.parse("desmume_continue", { timeoutMs: 30_001 }),
    /less than or equal to 30000/,
  );

  assert.deepEqual(server.parse("desmume_step_instruction", { count: 1 }), {
    count: 1,
    perStepTimeoutMs: 1000,
    captureContext: true,
  });
  assert.throws(
    () => server.parse("desmume_step_instruction", { count: 0 }),
    /greater than or equal to 1/,
  );
  assert.throws(
    () => server.parse("desmume_step_instruction", { count: 101 }),
    /less than or equal to 100/,
  );
  assert.throws(
    () => server.parse("desmume_step_instruction", { count: 1, perStepTimeoutMs: 5001 }),
    /less than or equal to 5000/,
  );

  assert.deepEqual(server.parse("desmume_pause", {}), {
    timeoutMs: 1000,
    captureContext: true,
  });
  assert.throws(
    () => server.parse("desmume_pause", { timeoutMs: 99 }),
    /greater than or equal to 100/,
  );

  assert.deepEqual(server.parse("desmume_wait_for_stop", { timeoutMs: 30_000 }), {
    timeoutMs: 30_000,
    captureContext: true,
  });
  assert.throws(
    () => server.parse("desmume_wait_for_stop", { timeoutMs: 30_001 }),
    /less than or equal to 30000/,
  );
});

test("breakpoint and memory-region schemas enforce address and size limits", () => {
  const { server } = register("/workspace");

  assert.deepEqual(
    server.parse("desmume_breakpoint_add", {
      address: 0x02000000,
      mode: "arm",
    }),
    {
      address: 0x02000000,
      mode: "arm",
    },
  );
  assert.throws(
    () => server.parse("desmume_breakpoint_add", { address: 0x1_0000_0000, mode: "arm" }),
    /less than or equal to 4294967295/,
  );
  assert.throws(
    () => server.parse("desmume_breakpoint_add", { address: 0x02000000, mode: "mips" }),
    /Invalid enum value/,
  );

  const nineRegions = Array.from({ length: 9 }, (_, index) => ({
    label: `r${index}`,
    address: 0x02001000 + index * 0x100,
    length: 4,
  }));
  assert.throws(
    () => server.parse("desmume_capture_stop_context", { additionalRegions: nineRegions }),
    /less than or equal to 8/,
  );
  assert.throws(
    () => server.parse("desmume_capture_stop_context", {
      additionalRegions: [{ label: "large", address: 0x02001000, length: 4097 }],
    }),
    /less than or equal to 4096/,
  );
});

test("executable-range replacement is capped at 64 validated ranges", () => {
  const { server } = register("/workspace");
  const range = (index: number) => ({
    id: `range-${index}`,
    label: `Range ${index}`,
    start: 0x02010000 + index * 0x100,
    end: 0x02010080 + index * 0x100,
    source: "explicit" as const,
    defaultMode: "thumb" as const,
  });

  assert.equal(
    (server.parse("desmume_executable_ranges_replace", {
      ranges: Array.from({ length: 64 }, (_, index) => range(index)),
    }).ranges as readonly unknown[]).length,
    64,
  );
  assert.throws(
    () => server.parse("desmume_executable_ranges_replace", {
      ranges: Array.from({ length: 65 }, (_, index) => range(index)),
    }),
    /less than or equal to 64/,
  );
});

test("desmume_start derives ARM9 metadata before launch and initializes debugger identity", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "re-mcp-debug-tools-"));
  try {
    const launcher = path.join(directory, "desmume-launcher");
    const rom = path.join(directory, "game.nds");
    await writeFile(launcher, "#!/bin/sh\nexit 0\n");
    await chmod(launcher, 0o755);
    await writeFile(rom, createRom());

    const { server, manager, controller } = register(directory);
    const result = await server.invoke("desmume_start", {
      launcher: "desmume-launcher",
      rom: "game.nds",
      arm9GdbPort: 20000,
    });

    assert.equal(manager.starts.length, 1);
    assert.equal(controller.initializations.length, 1);
    assert.match(controller.initializations[0]!.identity, /^desmume:4321:2026-08-07T07:15:00\.000Z$/);
    assert.deepEqual(controller.initializations[0]!.range, {
      start: 0x02000000,
      end: 0x02000200,
      size: 0x200,
      source: "arm9-header",
      label: "ARM9 main",
    });
    assert.equal((result as { isError?: boolean }).isError, false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("desmume_start rejects malformed ROM metadata before launching", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "re-mcp-debug-tools-bad-rom-"));
  try {
    const launcher = path.join(directory, "desmume-launcher");
    const rom = path.join(directory, "bad.nds");
    await writeFile(launcher, "#!/bin/sh\nexit 0\n");
    await chmod(launcher, 0o755);
    await writeFile(rom, Buffer.alloc(0x20));

    const { server, manager, controller } = register(directory);
    const result = await server.invoke("desmume_start", {
      launcher: "desmume-launcher",
      rom: "bad.nds",
      arm9GdbPort: 20000,
    });

    assert.equal(manager.starts.length, 0);
    assert.equal(controller.initializations.length, 0);
    assert.equal((result as { isError?: boolean }).isError, true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
