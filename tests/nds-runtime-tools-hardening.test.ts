import assert from "node:assert/strict";
import { rm } from "node:fs/promises";
import test from "node:test";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../src/config.js";
import type { DebugController } from "../src/services/debug-controller.js";
import { hashFileSha256 } from "../src/services/nds/io.js";
import {
  OwnedProcessManager,
  type OwnedProcessStatus,
} from "../src/services/owned-process.js";
import type { StopContext } from "../src/services/stop-context.js";
import { registerNdsRuntimeTools } from "../src/tools/nds-runtime.js";
import {
  createNdsFixture,
  writeFntMainRecord,
} from "./helpers/nds-fixture.js";

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

class MutableManager extends OwnedProcessManager {
  #status: OwnedProcessStatus = {
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

  override status(): OwnedProcessStatus {
    return this.#status;
  }

  setGeneration(
    romPath: string,
    sha256: string,
    pid: number,
    startedAt: string,
  ): void {
    this.#status = {
      running: true,
      pid,
      startedAt,
      executable: "/workspace/desmume",
      args: [romPath],
      metadata: {
        emulator: "desmume",
        arm9GdbPort: 20000,
        rom: romPath,
        romSha256: sha256,
      },
      stdout: "",
      stderr: "",
      outputTruncated: false,
      lastExitCode: null,
      lastSignal: null,
    };
  }
}

function stopContext(): StopContext {
  return {
    capturedAt: "2026-08-09T14:20:00.000Z",
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
      pc: 0x02000000,
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

class CaptureController {
  onCapture: (() => void) | null = null;

  status() {
    return {
      initialized: true,
      state: "stopped" as const,
      breakpoints: [],
      maximumBreakpoints: 32,
      executableRanges: [],
      hasStop: true,
    };
  }

  async captureCurrentStopContext(): Promise<StopContext> {
    this.onCapture?.();
    return stopContext();
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
  const content = (result as { content: readonly { text: string }[] }).content;
  return JSON.parse(content[0]!.text) as Record<string, unknown>;
}

function isError(result: unknown): boolean {
  return (result as { isError?: boolean }).isError === true;
}

function register(
  workspaceRoot: string,
  manager: MutableManager,
  controller: CaptureController,
): FakeMcpServer {
  const server = new FakeMcpServer();
  registerNdsRuntimeTools(
    server as unknown as McpServer,
    config(workspaceRoot),
    manager,
    controller as unknown as DebugController,
  );
  return server;
}

test("fails closed if the owned process generation changes while stop context is captured", async () => {
  const fixture = await createNdsFixture();
  try {
    const sha = await hashFileSha256(fixture.romPath);
    const manager = new MutableManager();
    const controller = new CaptureController();
    manager.setGeneration(fixture.romPath, sha, 1111, "2026-08-09T14:19:00.000Z");
    controller.onCapture = () => {
      manager.setGeneration(fixture.romPath, sha, 2222, "2026-08-09T14:19:30.000Z");
    };
    const server = register(fixture.directory, manager, controller);

    const result = await server.invoke("nds_correlate_stop_context", {
      nearbyInstructions: 1,
      referenceLimit: 0,
    });

    assert.equal(isError(result), true);
    assert.equal(resultBody(result).category, "runtime-correlation-context-failed");
    assert.match(String(resultBody(result).error), /process generation changed/i);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("preserves established NDS parser error categories from the static layer", async () => {
  const fixture = await createNdsFixture({ fntSize: 0x20 });
  try {
    writeFntMainRecord(fixture.buffer, 0x800, 0, 0x100, 0, 1);
    await fixture.write();
    const sha = await hashFileSha256(fixture.romPath);
    const manager = new MutableManager();
    const controller = new CaptureController();
    manager.setGeneration(fixture.romPath, sha, 3333, "2026-08-09T14:19:00.000Z");
    const server = register(fixture.directory, manager, controller);

    const result = await server.invoke("nds_correlate_stop_context", {
      nearbyInstructions: 1,
      referenceLimit: 0,
    });

    assert.equal(isError(result), true);
    assert.equal(resultBody(result).category, "malformed-fnt");
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});
