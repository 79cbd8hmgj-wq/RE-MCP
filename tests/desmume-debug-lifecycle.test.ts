import assert from "node:assert/strict";
import test from "node:test";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../src/config.js";
import type { DebugController } from "../src/services/debug-controller.js";
import {
  OwnedProcessManager,
  type OwnedProcessExitEvent,
  type OwnedProcessExitListener,
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
    const parsed = z.object(tool.schema).parse(input);
    return await tool.handler(parsed);
  }
}

function runningStatus(): OwnedProcessStatus {
  return {
    running: true,
    pid: 4321,
    startedAt: "2026-08-07T07:30:00.000Z",
    executable: "/workspace/desmume",
    args: ["--arm9gdb=20000", "/workspace/game.nds"],
    metadata: {
      emulator: "desmume",
      arm9GdbPort: 20000,
      rom: "/workspace/game.nds",
    },
    stdout: "",
    stderr: "",
    outputTruncated: false,
    lastExitCode: null,
    lastSignal: null,
  };
}

class FakeLifecycleManager extends OwnedProcessManager {
  #status = runningStatus();
  readonly #listeners = new Set<OwnedProcessExitListener>();

  override status(): OwnedProcessStatus {
    return this.#status;
  }

  override onExit(listener: OwnedProcessExitListener): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  override async stop(_graceMs = 5_000): Promise<OwnedProcessStatus> {
    if (this.#status.running) this.simulateExit();
    return this.#status;
  }

  simulateExit(): void {
    const previous = this.#status;
    this.#status = {
      running: false,
      pid: null,
      startedAt: null,
      executable: null,
      args: [],
      metadata: {},
      stdout: "",
      stderr: "",
      outputTruncated: false,
      lastExitCode: 0,
      lastSignal: null,
    };
    const event: OwnedProcessExitEvent = {
      pid: previous.pid,
      startedAt: previous.startedAt!,
      executable: previous.executable!,
      args: previous.args,
      metadata: previous.metadata,
      exitCode: 0,
      signal: null,
    };
    for (const listener of this.#listeners) listener(event);
  }
}

class ResetSpyController {
  readonly resetReasons: string[] = [];

  status() {
    return {
      initialized: true,
      state: "stopped" as const,
      breakpoints: [],
      maximumBreakpoints: 32,
      executableRanges: [],
      hasStop: false,
    };
  }

  async reset(reason: string): Promise<void> {
    this.resetReasons.push(reason);
  }
}

function config(): ServerConfig {
  return {
    workspaceRoot: "/workspace",
    commandTimeoutMs: 30_000,
    maxOutputBytes: 64 * 1024,
  };
}

function registerLifecycleHarness() {
  const manager = new FakeLifecycleManager();
  const controller = new ResetSpyController();
  const server = new FakeMcpServer();
  registerDesmumeTools(
    server as unknown as McpServer,
    config(),
    manager,
    controller as unknown as DebugController,
  );
  return { manager, controller, server };
}

test("spontaneous owned DeSmuME exit resets debugger session state", async () => {
  const { manager, controller } = registerLifecycleHarness();

  manager.simulateExit();
  await Promise.resolve();

  assert.deepEqual(controller.resetReasons, ["Owned DeSmuME process exited"]);
});

test("desmume_stop uses the owned-process exit reset exactly once", async () => {
  const { controller, server } = registerLifecycleHarness();

  await server.invoke("desmume_stop", {});
  await Promise.resolve();

  assert.deepEqual(controller.resetReasons, ["Owned DeSmuME process exited"]);
});
