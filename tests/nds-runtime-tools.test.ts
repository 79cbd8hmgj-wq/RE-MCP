import assert from "node:assert/strict";
import net from "node:net";
import { rm } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../src/config.js";
import { DebugController } from "../src/services/debug-controller.js";
import { encodeRspPacket, parseRspPacket } from "../src/services/gdb-rsp.js";
import { GdbSession } from "../src/services/gdb-session.js";
import { hashFileSha256 } from "../src/services/nds/io.js";
import type { Arm9ExecutableRange } from "../src/services/nds-arm9.js";
import {
  OwnedProcessManager,
  type OwnedProcessStart,
  type OwnedProcessStatus,
} from "../src/services/owned-process.js";
import type { StopContext } from "../src/services/stop-context.js";
import { registerNdsRuntimeTools } from "../src/tools/nds-runtime.js";
import { createNdsFixture } from "./helpers/nds-fixture.js";

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
    return z.object(tool.schema).parse(input);
  }

  async invoke(name: string, input: unknown): Promise<unknown> {
    const tool = this.tools.get(name);
    if (tool === undefined) throw new Error(`Unknown test tool: ${name}`);
    return await tool.handler(this.parse(name, input));
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
  #status: OwnedProcessStatus = stoppedStatus();

  override status(): OwnedProcessStatus {
    return this.#status;
  }

  setRunning(romPath: string, romSha256?: string): void {
    this.#status = {
      running: true,
      pid: 7777,
      startedAt: "2026-08-09T13:55:00.000Z",
      executable: "/workspace/desmume",
      args: ["--arm9gdb=20000", romPath],
      metadata: {
        emulator: "desmume",
        arm9GdbPort: 20000,
        rom: romPath,
        ...(romSha256 === undefined ? {} : { romSha256 }),
      },
      stdout: "",
      stderr: "",
      outputTruncated: false,
      lastExitCode: null,
      lastSignal: null,
    };
  }

  override async start(request: OwnedProcessStart): Promise<OwnedProcessStatus> {
    this.#status = {
      running: true,
      pid: 7777,
      startedAt: "2026-08-09T13:55:00.000Z",
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
}

function context(pc = 0x02000000): StopContext {
  return {
    capturedAt: "2026-08-09T13:56:00.000Z",
    stop: { kind: "signal", signal: 5, fields: {}, raw: "S05" },
    registers: {
      r0: 0,
      r1: 1,
      r2: 2,
      r3: 3,
      r4: 4,
      r5: 5,
      r6: 6,
      r7: 7,
      r8: 8,
      r9: 9,
      r10: 10,
      r11: 11,
      r12: 12,
      sp: 0x02000100,
      lr: 0x02000080,
      pc,
      cpsr: 0x60000013,
      mode: "arm",
      byteOrder: "little",
      raw: "00".repeat(168),
    },
    pcWindow: { address: 0x01ffffe0, length: 64, dataHex: "00".repeat(64) },
    stackWindow: { address: 0x02000100, length: 64, dataHex: "00".repeat(64) },
    additionalRegions: [],
  };
}

class SpyDebugController {
  debuggerState: "unavailable" | "stopped" | "running" | "waiting" = "stopped";
  readonly calls: string[] = [];
  capture = context();

  status() {
    return {
      initialized: this.debuggerState !== "unavailable",
      state: this.debuggerState,
      breakpoints: [],
      maximumBreakpoints: 32,
      executableRanges: [],
      hasStop: this.debuggerState === "stopped",
    };
  }

  async captureCurrentStopContext(input: unknown): Promise<StopContext> {
    this.calls.push(`capture:${JSON.stringify(input)}`);
    return this.capture;
  }
}

function config(workspaceRoot: string): ServerConfig {
  return {
    workspaceRoot,
    commandTimeoutMs: 30_000,
    maxOutputBytes: 64 * 1024,
  };
}

function resultBody(result: unknown): Record<string, unknown> {
  const wrapper = result as {
    readonly content: readonly { readonly type: string; readonly text: string }[];
    readonly isError?: boolean;
  };
  assert.equal(wrapper.content[0]?.type, "text");
  return JSON.parse(wrapper.content[0]!.text) as Record<string, unknown>;
}

function resultError(result: unknown): boolean {
  return (result as { readonly isError?: boolean }).isError === true;
}

function register(
  workspaceRoot: string,
  manager = new FakeOwnedProcessManager(),
  controller = new SpyDebugController(),
) {
  const server = new FakeMcpServer();
  registerNdsRuntimeTools(
    server as unknown as McpServer,
    config(workspaceRoot),
    manager,
    controller as unknown as DebugController,
  );
  return { server, manager, controller };
}

test("registers only bounded current-stop correlation inputs", () => {
  const { server } = register("/workspace");
  const tool = server.tools.get("nds_correlate_stop_context");
  assert.notEqual(tool, undefined);
  assert.deepEqual(Object.keys(tool!.schema).sort(), [
    "nearbyInstructions",
    "referenceLimit",
    "timeoutMs",
  ]);
  assert.deepEqual(server.parse("nds_correlate_stop_context", {}), {
    timeoutMs: 3000,
    nearbyInstructions: 8,
    referenceLimit: 16,
  });
  assert.throws(
    () => server.parse("nds_correlate_stop_context", { timeoutMs: 99 }),
    /greater than or equal to 100/,
  );
  assert.throws(
    () => server.parse("nds_correlate_stop_context", { nearbyInstructions: 33 }),
    /less than or equal to 32/,
  );
  assert.throws(
    () => server.parse("nds_correlate_stop_context", { referenceLimit: 65 }),
    /less than or equal to 64/,
  );
});

test("rejects correlation when there is no owned DeSmuME process", async () => {
  const { server } = register("/workspace");
  const result = await server.invoke("nds_correlate_stop_context", {});
  assert.equal(resultError(result), true);
  assert.equal(resultBody(result).category, "runtime-correlation-no-owned-process");
});

test("rejects correlation when the owned process lacks launch-time ROM identity", async () => {
  const fixture = await createNdsFixture();
  try {
    const { server, manager } = register(fixture.directory);
    manager.setRunning(fixture.romPath);
    const result = await server.invoke("nds_correlate_stop_context", {});
    assert.equal(resultError(result), true);
    assert.equal(resultBody(result).category, "runtime-correlation-rom-identity-missing");
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("rejects correlation while the shared debugger is running", async () => {
  const fixture = await createNdsFixture();
  try {
    const sha = await hashFileSha256(fixture.romPath);
    const controller = new SpyDebugController();
    controller.debuggerState = "running";
    const manager = new FakeOwnedProcessManager();
    manager.setRunning(fixture.romPath, sha);
    const { server } = register(fixture.directory, manager, controller);

    const result = await server.invoke("nds_correlate_stop_context", {});
    assert.equal(resultError(result), true);
    assert.equal(resultBody(result).category, "runtime-correlation-debugger-not-stopped");
    assert.deepEqual(controller.calls, []);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("correlates only the captured stopped PC and exposes only a workspace-relative ROM path", async () => {
  const fixture = await createNdsFixture();
  try {
    const sha = await hashFileSha256(fixture.romPath);
    const controller = new SpyDebugController();
    controller.capture = context(0x02000000);
    const manager = new FakeOwnedProcessManager();
    manager.setRunning(fixture.romPath, sha);
    const { server } = register(fixture.directory, manager, controller);

    const result = await server.invoke("nds_correlate_stop_context", {
      timeoutMs: 1500,
      nearbyInstructions: 1,
      referenceLimit: 0,
    });
    assert.equal(resultError(result), false);
    const body = resultBody(result);
    const runtime = body.runtimeObserved as Record<string, unknown>;
    const rom = body.rom as Record<string, unknown>;
    assert.equal(runtime.pc, 0x02000000);
    assert.equal(runtime.mode, "arm");
    assert.equal(rom.path, "fixture.nds");
    assert.equal(path.isAbsolute(String(rom.path)), false);
    assert.equal(String(rom.path).includes(fixture.directory), false);
    assert.equal(controller.calls.length, 1);
    assert.match(controller.calls[0] ?? "", /"timeoutMs":1500/);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

function littleEndianU32(value: number): string {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32LE(value >>> 0, 0);
  return buffer.toString("hex");
}

function registerPacket(pc: number): string {
  const registers = Array.from({ length: 16 }, (_, index) => 0x10000000 + index);
  registers[13] = 0x02000100;
  registers[15] = pc;
  return [
    ...registers.map(littleEndianU32),
    "0".repeat(8 * 24),
    "0".repeat(8),
    littleEndianU32(0x60000013),
  ].join("");
}

interface ScriptedReply {
  readonly command: string;
  readonly reply: string;
}

async function listen(server: net.Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("Expected TCP address");
  return address.port;
}

async function close(server: net.Server): Promise<void> {
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

function scriptedRspServer(script: readonly ScriptedReply[], received: string[]): net.Server {
  const remaining = [...script];
  return net.createServer((socket) => {
    let buffer = "";
    socket.on("data", (chunk) => {
      if (chunk.includes(0x03)) {
        received.push("INTERRUPT");
        return;
      }
      buffer += chunk.toString("ascii");
      for (;;) {
        const parsed = parseRspPacket(buffer);
        if (parsed === null) return;
        buffer = buffer.slice(parsed.consumed);
        received.push(parsed.payload);
        const expected = remaining.shift();
        if (expected === undefined) throw new Error(`Unexpected command ${parsed.payload}`);
        assert.equal(parsed.payload, expected.command);
        socket.write(`+${encodeRspPacket(expected.reply)}`, "ascii");
      }
    });
  });
}

const ARM9_RANGE: Arm9ExecutableRange = {
  start: 0x02000000,
  end: 0x02000200,
  size: 0x200,
  source: "arm9-header",
  label: "ARM9 main",
};

test("current-stop correlation uses only stopped-state RSP reads and never resumes execution", async () => {
  const fixture = await createNdsFixture();
  const received: string[] = [];
  const rsp = scriptedRspServer([
    { command: "?", reply: "S05" },
    { command: "g", reply: registerPacket(0x02000000) },
    { command: "m1ffffe0,40", reply: "00".repeat(64) },
    { command: "m2000100,40", reply: "00".repeat(64) },
    { command: "g", reply: registerPacket(0x02000000) },
    { command: "m1ffffe0,40", reply: "00".repeat(64) },
    { command: "m2000100,40", reply: "00".repeat(64) },
  ], received);
  const port = await listen(rsp);
  const controller = new DebugController(() =>
    new GdbSession({
      host: "127.0.0.1",
      port,
      maxReplyBytes: 32_768,
      connectTimeoutMs: 1000,
    }),
  );

  try {
    const sha = await hashFileSha256(fixture.romPath);
    const manager = new FakeOwnedProcessManager();
    manager.setRunning(fixture.romPath, sha);
    controller.initialize("runtime-tool-test", ARM9_RANGE);

    // Establish one real stopped GDB session; then isolate commands issued by
    // the runtime-correlation tool itself.
    await controller.captureCurrentStopContext({
      timeoutMs: 1000,
      maxOutputBytes: 64 * 1024,
    });
    received.length = 0;

    const server = new FakeMcpServer();
    registerNdsRuntimeTools(
      server as unknown as McpServer,
      config(fixture.directory),
      manager,
      controller,
    );
    const result = await server.invoke("nds_correlate_stop_context", {
      timeoutMs: 1000,
      nearbyInstructions: 1,
      referenceLimit: 0,
    });

    assert.equal(resultError(result), false);
    assert.deepEqual(received, [
      "g",
      "m1ffffe0,40",
      "m2000100,40",
    ]);
    assert.equal(received.includes("c"), false);
    assert.equal(received.includes("s"), false);
    assert.equal(received.includes("INTERRUPT"), false);
  } finally {
    await controller.reset("test cleanup");
    await close(rsp);
    await rm(fixture.directory, { recursive: true, force: true });
  }
});
