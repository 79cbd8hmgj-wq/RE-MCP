import assert from "node:assert/strict";
import { rm } from "node:fs/promises";
import test from "node:test";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../src/config.js";
import type { ArmDisassemblyBackend } from "../src/services/disassembly/backend.js";
import type { DebugController } from "../src/services/debug-controller.js";
import { NdsError } from "../src/services/nds/errors.js";
import { hashFileSha256 } from "../src/services/nds/io.js";
import { correlateNdsStopContext } from "../src/services/nds/runtime-correlation.js";
import type { RuntimeGhidraEnricher } from "../src/services/nds/runtime-correlation-ghidra.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import {
  OwnedProcessManager,
  type OwnedProcessStatus,
} from "../src/services/owned-process.js";
import type { StopContext } from "../src/services/stop-context.js";
import { registerNdsRuntimeTools } from "../src/tools/nds-runtime.js";
import {
  createNdsFixture,
  writeFatEntry,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

const inertBackend: ArmDisassemblyBackend = {
  decodeOne: () => null,
  close: () => undefined,
};

function stopContext(pc: number): StopContext {
  return {
    capturedAt: "2026-08-09T14:45:00.000Z",
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
      sp: 0x023ff000,
      lr: 0x02000100,
      pc,
      cpsr: 0,
      mode: "arm",
      byteOrder: "little",
      raw: "00".repeat(168),
    },
    pcWindow: { address: pc, length: 4, dataHex: "00000000" },
    stackWindow: { address: 0x023ff000, length: 4, dataHex: "00000000" },
    additionalRegions: [],
  };
}

async function overlappingFixture() {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    fatSize: 16,
    arm9OverlaySize: 64,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1400, 0x1500);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1600, 0x1700);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 12,
    ramAddress: 0x02200000,
    ramSize: 0x100,
    bssSize: 0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 0,
    compressedSize: 0,
    flags: 0,
  });
  writeOverlayRecord(fixture.buffer, 0xa00, 1, {
    overlayId: 19,
    ramAddress: 0x02200080,
    ramSize: 0x80,
    bssSize: 0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 1,
    compressedSize: 0,
    flags: 0,
  });
  await fixture.write();
  return { fixture, map: await readNdsRomMap(fixture.romPath) };
}

function correlationInput(
  romPath: string,
  sha256: string,
  pc: number,
  includeGhidra: boolean,
  decompileGhidraFunction = false,
) {
  return {
    romPath,
    romDisplayPath: "fixture.nds",
    expectedRomSha256: sha256,
    stopContext: stopContext(pc),
    options: {
      nearbyInstructions: 1,
      referenceLimit: 0,
      maxOutputBytes: 64 * 1024,
      includeGhidra,
      decompileGhidraFunction,
    },
  } as const;
}

test("includeGhidra false performs no enrichment work", async () => {
  const fixture = await createNdsFixture();
  try {
    const map = await readNdsRomMap(fixture.romPath);
    let calls = 0;
    const enricher: RuntimeGhidraEnricher = async () => {
      calls += 1;
      return { status: "not-ready", reason: "unexpected call" };
    };

    const result = await correlateNdsStopContext(
      correlationInput(fixture.romPath, map.sha256, map.header.arm9.ramAddress, false),
      inertBackend,
      enricher,
    );

    assert.equal(calls, 0);
    assert.equal(result.candidates[0]?.ghidraDerived.status, "not-requested");
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("Ghidra enrichment runs once per ambiguous canonical overlay candidate", async () => {
  const { fixture, map } = await overlappingFixture();
  try {
    const calls: Array<number | null> = [];
    const enricher: RuntimeGhidraEnricher = async ({ candidate }) => {
      calls.push(candidate.overlayId);
      return { status: "not-ready", reason: `overlay ${candidate.overlayId}` };
    };

    const result = await correlateNdsStopContext(
      correlationInput(fixture.romPath, map.sha256, 0x02200090, true),
      inertBackend,
      enricher,
    );

    assert.equal(result.canonical.status, "ambiguous");
    assert.deepEqual(calls, [12, 19]);
    assert.deepEqual(
      result.candidates.map((candidate) => (candidate.ghidraDerived as { status: string }).status),
      ["not-ready", "not-ready"],
    );
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("decompileGhidraFunction cannot silently enable Ghidra", async () => {
  const fixture = await createNdsFixture();
  try {
    const map = await readNdsRomMap(fixture.romPath);
    await assert.rejects(
      correlateNdsStopContext(
        correlationInput(
          fixture.romPath,
          map.sha256,
          map.header.arm9.ramAddress,
          false,
          true,
        ),
        inertBackend,
      ),
      (error: unknown) =>
        error instanceof NdsError
        && error.category === "runtime-correlation-context-failed"
        && /requires includeGhidra/u.test(error.message),
    );
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

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
}

function config(workspaceRoot: string): ServerConfig {
  return {
    workspaceRoot,
    commandTimeoutMs: 30_000,
    maxOutputBytes: 64 * 1024,
  };
}

class IdleManager extends OwnedProcessManager {
  override status(): OwnedProcessStatus {
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
}

test("runtime tool exposes explicit opt-in Ghidra controls with false defaults", () => {
  const server = new FakeMcpServer();
  const manager = new IdleManager();
  const controller = {
    status: () => ({ state: "unavailable" }),
  } as unknown as DebugController;

  registerNdsRuntimeTools(
    server as unknown as McpServer,
    config("/workspace"),
    manager,
    controller,
  );

  const tool = server.tools.get("nds_correlate_stop_context");
  assert.notEqual(tool, undefined);
  assert.deepEqual(Object.keys(tool!.schema).sort(), [
    "decompileGhidraFunction",
    "includeGhidra",
    "nearbyInstructions",
    "referenceLimit",
    "timeoutMs",
  ]);
  assert.deepEqual(server.parse("nds_correlate_stop_context", {}), {
    timeoutMs: 3000,
    nearbyInstructions: 8,
    referenceLimit: 16,
    includeGhidra: false,
    decompileGhidraFunction: false,
  });
});
