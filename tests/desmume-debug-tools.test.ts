import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../src/config.js";
import type { DebugController } from "../src/services/debug-controller.js";
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

const MAIN_RANGE = {
  id: "arm9-main",
  label: "ARM9 main",
  start: 0x02000000,
  end: 0x02000200,
  source: "arm9-header",
  symbolModes: {},
} as const;

function breakpoint(enabled = true) {
  return {
    id: "bp-1",
    address: 0x02000000,
    requestedMode: "arm" as const,
    resolvedMode: "arm" as const,
    kind: 4 as const,
    rangeId: "arm9-main",
    source: "arm9-header" as const,
    createdAt: "2026-08-07T07:15:01.000Z",
    enabled,
    hitCount: 0,
  };
}

class SpyDebugController {
  readonly initializations: Array<{
    readonly identity: string;
    readonly range: Arm9ExecutableRange;
  }> = [];
  readonly calls: Array<{ readonly name: string; readonly input: unknown }> = [];
  debuggerState: "unavailable" | "stopped" | "running" | "waiting" = "stopped";
  failMethod: string | null = null;

  initialize(identity: string, range: Arm9ExecutableRange): void {
    this.initializations.push({ identity, range });
  }

  status() {
    return {
      initialized: this.initializations.length > 0 || this.debuggerState !== "unavailable",
      state: this.debuggerState,
      breakpoints: [breakpoint()],
      maximumBreakpoints: 32,
      executableRanges: [MAIN_RANGE],
      hasStop: true,
    };
  }

  replaceAdditionalRanges(input: unknown): void {
    this.#record("replaceAdditionalRanges", input);
  }

  async addBreakpoint(input: unknown): Promise<ReturnType<typeof breakpoint>> {
    this.#record("addBreakpoint", input);
    return breakpoint();
  }

  async removeBreakpoint(id: string, timeoutMs?: number): Promise<ReturnType<typeof breakpoint>> {
    this.#record("removeBreakpoint", { id, timeoutMs });
    return breakpoint(false);
  }

  async continueExecution(input: unknown): Promise<unknown> {
    this.#record("continueExecution", input);
    return { kind: "timeout", state: "running" };
  }

  async step(input: unknown): Promise<unknown> {
    this.#record("step", input);
    return {
      requested: 2,
      completed: 2,
      completedAll: true,
      result: { kind: "timeout", state: "running" },
    };
  }

  async pause(input: unknown): Promise<unknown> {
    this.#record("pause", input);
    return { kind: "timeout", state: "running" };
  }

  async waitForStop(input: unknown): Promise<unknown> {
    this.#record("waitForStop", input);
    return { kind: "timeout", state: "running" };
  }

  async captureCurrentStopContext(input: unknown): Promise<unknown> {
    this.#record("captureCurrentStopContext", input);
    return {
      capturedAt: "2026-08-07T07:15:02.000Z",
      stop: { kind: "signal", signal: 5, fields: {}, raw: "S05" },
      registers: { pc: 0x02000000, sp: 0x02000100, cpsr: 0x13, mode: "arm" },
      pcWindow: { address: 0x01ffffe0, length: 64, dataHex: "00".repeat(64) },
      stackWindow: { address: 0x02000100, length: 64, dataHex: "00".repeat(64) },
      additionalRegions: [],
    };
  }

  async reset(reason: string): Promise<void> {
    this.#record("reset", reason);
  }

  #record(name: string, input: unknown): void {
    if (this.failMethod === name) {
      throw new Error("GDB command requires stopped state; current state is running");
    }
    this.calls.push({ name, input });
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
    controller as unknown as DebugController,
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

function resultBody(result: unknown): Record<string, unknown> {
  const content = (result as { content: Array<{ type: string; text: string }> }).content;
  assert.equal(content[0]?.type, "text");
  return JSON.parse(content[0]!.text) as Record<string, unknown>;
}

async function markRunning(manager: FakeOwnedProcessManager): Promise<void> {
  await manager.start({
    executable: "/workspace/desmume",
    args: ["--arm9gdb=20000", "/workspace/game.nds"],
    cwd: "/workspace",
    maxOutputBytes: 64 * 1024,
    metadata: {
      emulator: "desmume",
      arm9GdbPort: 20000,
      rom: "/workspace/game.nds",
    },
  });
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

test("debugger MCP handlers delegate bounded requests and return controller results", async () => {
  const manager = new FakeOwnedProcessManager();
  const controller = new SpyDebugController();
  const { server } = register("/workspace", manager, controller);
  await markRunning(manager);

  const added = resultBody(await server.invoke("desmume_breakpoint_add", {
    address: 0x02000000,
    mode: "arm",
  }));
  assert.equal(added.id, "bp-1");

  const listed = resultBody(await server.invoke("desmume_breakpoint_list", {}));
  assert.equal(listed.maximumBreakpoints, 32);
  assert.equal(listed.state, "stopped");

  await server.invoke("desmume_executable_ranges_replace", {
    ranges: [{
      id: "overlay-1",
      label: "Overlay 1",
      start: 0x02010000,
      end: 0x02010100,
      source: "overlay",
      overlayId: 1,
      defaultMode: "thumb",
    }],
  });
  await server.invoke("desmume_continue", {});
  await server.invoke("desmume_step_instruction", { count: 2 });
  await server.invoke("desmume_pause", {});
  await server.invoke("desmume_wait_for_stop", { timeoutMs: 5000 });
  const context = resultBody(await server.invoke("desmume_capture_stop_context", {}));
  assert.equal((context.registers as { pc: number }).pc, 0x02000000);
  const removed = resultBody(await server.invoke("desmume_breakpoint_remove", { id: "bp-1" }));
  assert.equal(removed.enabled, false);

  assert.deepEqual(controller.calls, [
    {
      name: "addBreakpoint",
      input: { address: 0x02000000, mode: "arm", timeoutMs: 3000 },
    },
    {
      name: "replaceAdditionalRanges",
      input: [{
        id: "overlay-1",
        label: "Overlay 1",
        start: 0x02010000,
        end: 0x02010100,
        source: "overlay",
        overlayId: 1,
        defaultMode: "thumb",
      }],
    },
    {
      name: "continueExecution",
      input: { timeoutMs: 10_000, captureContext: true, maxOutputBytes: 64 * 1024 },
    },
    {
      name: "step",
      input: { count: 2, perStepTimeoutMs: 1000, captureContext: true, maxOutputBytes: 64 * 1024 },
    },
    {
      name: "pause",
      input: { timeoutMs: 1000, captureContext: true, maxOutputBytes: 64 * 1024 },
    },
    {
      name: "waitForStop",
      input: { timeoutMs: 5000, captureContext: true, maxOutputBytes: 64 * 1024 },
    },
    {
      name: "captureCurrentStopContext",
      input: { timeoutMs: 3000, maxOutputBytes: 64 * 1024 },
    },
    {
      name: "removeBreakpoint",
      input: { id: "bp-1", timeoutMs: 3000 },
    },
  ]);
});

test("debugger MCP errors include operation and recovery state", async () => {
  const manager = new FakeOwnedProcessManager();
  const controller = new SpyDebugController();
  controller.debuggerState = "running";
  controller.failMethod = "addBreakpoint";
  const { server } = register("/workspace", manager, controller);
  await markRunning(manager);

  const result = await server.invoke("desmume_breakpoint_add", {
    address: 0x02000000,
    mode: "arm",
  });
  assert.equal((result as { isError?: boolean }).isError, true);
  const body = resultBody(result);
  assert.equal(body.operation, "desmume_breakpoint_add");
  assert.equal(body.debuggerState, "running");
  assert.equal(body.emulatorRunning, true);
  assert.equal(body.connectionUsable, true);
  assert.match(String(body.correctiveAction), /pause|wait/i);
  assert.match(String(body.error), /requires stopped state/);
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
