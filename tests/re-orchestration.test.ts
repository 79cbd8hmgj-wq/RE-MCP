import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import type {
  ArmDisassemblyBackend,
  ArmMode,
  DecodedArmInstruction,
} from "../src/services/disassembly/backend.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import { investigateNdsDataUsage } from "../src/services/re-orchestration/data-usage.js";
import { traceNdsFunction } from "../src/services/re-orchestration/trace-function.js";
import { TOOL_PROFILES } from "../src/tools/profiles.js";
import {
  createNdsFixture,
  writeFatEntry,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

class FakeBackend implements ArmDisassemblyBackend {
  constructor(
    private readonly decoded: ReadonlyMap<number, DecodedArmInstruction | null>,
  ) {}

  decodeOne(
    _bytes: Uint8Array,
    address: number,
    _mode: ArmMode,
  ): DecodedArmInstruction | null {
    return this.decoded.get(address) ?? null;
  }

  close(): void {}
}

function instruction(
  address: number,
  overrides: Partial<DecodedArmInstruction> = {},
): DecodedArmInstruction {
  return {
    address,
    size: 4,
    bytes: [0, 0, 0, 0],
    mnemonic: "mov",
    operandsText: "r0, r0",
    operands: [],
    isJump: false,
    isCall: false,
    isReturn: false,
    isConditional: false,
    switchesMode: false,
    pcRelative: null,
    ...overrides,
  };
}

function call(address: number, target: number): DecodedArmInstruction {
  return instruction(address, {
    mnemonic: "bl",
    operandsText: `#0x${target.toString(16)}`,
    operands: [{ kind: "immediate", value: target }],
    isCall: true,
  });
}

function returned(address: number): DecodedArmInstruction {
  return instruction(address, {
    mnemonic: "bx",
    operandsText: "lr",
    operands: [{ kind: "register", name: "lr" }],
    isJump: true,
    isReturn: true,
  });
}

function addressReference(
  address: number,
  target: number,
): DecodedArmInstruction {
  const architecturalPc = address + 8;
  return instruction(address, {
    mnemonic: "add",
    operandsText: `r0, pc, #${target - architecturalPc}`,
    pcRelative: {
      kind: "address-add",
      immediate: target - architecturalPc,
    },
  });
}

const TRACE_LIMITS = {
  maxCandidates: 8,
  maxWindowInstructions: 2,
  maxWindowBytes: 8,
  proof: {
    maxComponents: 8,
    maxBlocks: 32,
    maxInstructions: 128,
    maxBytes: 512,
    maxEdges: 64,
    maxXrefs: 16,
  },
  cfg: {
    maxBlocks: 16,
    maxInstructions: 64,
    maxBytes: 256,
    maxEdges: 32,
  },
} as const;

const DATA_LIMITS = {
  maxCandidates: 8,
  maxWindowInstructions: 2,
  maxWindowBytes: 8,
  scan: {
    maxComponents: 8,
    maxBlocks: 32,
    maxInstructions: 128,
    maxBytes: 512,
    maxEdges: 64,
    maxXrefs: 8,
  },
} as const;

test("trace function returns bounded direct callers and deterministic proof context", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x80 });
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, call(0x02000000, 0x02000040)],
    [0x02000004, returned(0x02000004)],
    [0x02000020, call(0x02000020, 0x02000040)],
    [0x02000024, returned(0x02000024)],
    [0x02000040, returned(0x02000040)],
  ]));

  const result = await traceNdsFunction(
    map,
    {
      processor: "arm9",
      runtimeAddress: 0x02000040,
      mode: "arm",
      proofScope: { kind: "main" },
      seeds: [{ runtimeAddress: 0x02000020, mode: "arm" }],
    },
    TRACE_LIMITS,
    backend,
  );

  assert.equal(result.operation, "re_trace_function");
  assert.equal(result.sourceRomSha256, map.sha256);
  assert.equal(result.subject.runtimeAddress, 0x02000040);
  assert.deepEqual(
    result.candidates.map((candidate) => candidate.instructionAddress),
    [0x02000000, 0x02000020],
  );
  assert.equal(result.candidates.every((candidate) => candidate.callSiteWindow.length > 0), true);
  assert.equal(
    result.confirmedDeterministicEvidence.some((entry) => entry.kind === "function-proof"),
    true,
  );
});

test("trace function preserves bounded instructions before a call site", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x80 });
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, call(0x02000000, 0x02000018)],
    [0x02000004, returned(0x02000004)],
    [0x02000018, instruction(0x02000018, { mnemonic: "ldrb", operandsText: "r1, [r4, #0x12]" })],
    [0x0200001c, instruction(0x0200001c, { mnemonic: "cmp", operandsText: "r1, #7" })],
    [0x02000020, call(0x02000020, 0x02000040)],
    [0x02000024, returned(0x02000024)],
    [0x02000040, returned(0x02000040)],
  ]));

  const result = await traceNdsFunction(
    map,
    {
      processor: "arm9",
      runtimeAddress: 0x02000040,
      mode: "arm",
      proofScope: { kind: "main" },
      seeds: [],
    },
    {
      ...TRACE_LIMITS,
      maxWindowInstructions: 4,
      maxWindowBytes: 16,
    },
    backend,
  );

  const candidate = result.candidates.find(
    (entry) => entry.instructionAddress === 0x02000020,
  );
  assert.notEqual(candidate, undefined);
  assert.deepEqual(
    candidate?.callSiteWindow.map((entry) => entry.address),
    [0x02000018, 0x0200001c, 0x02000020, 0x02000024],
  );
  assert.deepEqual(
    candidate?.callSiteWindow.map((entry) => entry.mnemonic),
    ["ldrb", "cmp", "bl", "bx"],
  );
});

test("trace function obeys candidate bounds instead of silently widening work", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x80 });
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, call(0x02000000, 0x02000040)],
    [0x02000004, returned(0x02000004)],
    [0x02000020, call(0x02000020, 0x02000040)],
    [0x02000024, returned(0x02000024)],
    [0x02000040, returned(0x02000040)],
  ]));

  const result = await traceNdsFunction(
    map,
    {
      processor: "arm9",
      runtimeAddress: 0x02000040,
      mode: "arm",
      proofScope: { kind: "main" },
      seeds: [{ runtimeAddress: 0x02000020, mode: "arm" }],
    },
    { ...TRACE_LIMITS, maxCandidates: 1 },
    backend,
  );

  assert.equal(result.candidates.length, 1);
  assert.equal(result.ambiguities.some((entry) => entry.kind === "candidate-limit"), true);
});

test("data usage returns bounded direct references without semantic ranking", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x80 });
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, addressReference(0x02000000, 0x02000040)],
    [0x02000004, returned(0x02000004)],
    [0x02000020, addressReference(0x02000020, 0x02000040)],
    [0x02000024, returned(0x02000024)],
  ]));

  const result = await investigateNdsDataUsage(
    map,
    {
      processor: "arm9",
      runtimeAddress: 0x02000040,
      scope: { kind: "main" },
      seeds: [{ runtimeAddress: 0x02000020, mode: "arm" }],
    },
    DATA_LIMITS,
    backend,
  );

  assert.equal(result.operation, "re_investigate_data_usage");
  assert.deepEqual(
    result.candidates.map((candidate) => candidate.reference.source.instructionAddress),
    [0x02000000, 0x02000020],
  );
  assert.equal(
    result.candidates.every(
      (candidate) => candidate.reference.kind === "pc-relative-address",
    ),
    true,
  );
});

test("data usage preserves bounded instructions before a reference site", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x80 });
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, call(0x02000000, 0x02000018)],
    [0x02000004, returned(0x02000004)],
    [0x02000018, instruction(0x02000018, { mnemonic: "ldr", operandsText: "r2, [r4, #8]" })],
    [0x0200001c, instruction(0x0200001c, { mnemonic: "cmp", operandsText: "r2, #3" })],
    [0x02000020, addressReference(0x02000020, 0x02000040)],
    [0x02000024, returned(0x02000024)],
  ]));

  const result = await investigateNdsDataUsage(
    map,
    {
      processor: "arm9",
      runtimeAddress: 0x02000040,
      scope: { kind: "main" },
      seeds: [],
    },
    {
      ...DATA_LIMITS,
      maxWindowInstructions: 4,
      maxWindowBytes: 16,
    },
    backend,
  );

  const candidate = result.candidates.find(
    (entry) => entry.reference.source.instructionAddress === 0x02000020,
  );
  assert.notEqual(candidate, undefined);
  assert.deepEqual(
    candidate?.callSiteWindow.map((entry) => entry.address),
    [0x02000018, 0x0200001c, 0x02000020, 0x02000024],
  );
  assert.deepEqual(
    candidate?.callSiteWindow.map((entry) => entry.mnemonic),
    ["ldr", "cmp", "add", "bx"],
  );
});

test("data usage preserves overlapping overlay ownership as ambiguity", async () => {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    arm9Size: 0x80,
    fatSize: 16,
    arm9OverlaySize: 64,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1400, 0x1480);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1500, 0x1580);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 10,
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
    overlayId: 30,
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
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, returned(0x02000000)],
  ]));

  const result = await investigateNdsDataUsage(
    map,
    {
      processor: "arm9",
      runtimeAddress: 0x02200090,
      scope: { kind: "main" },
      seeds: [],
    },
    DATA_LIMITS,
    backend,
  );

  assert.equal(result.component.component, "unresolved");
  assert.equal(result.ambiguities.some((entry) => entry.kind === "runtime-ownership"), true);
  const ownership = result.ambiguities.find((entry) => entry.kind === "runtime-ownership");
  assert.equal(Array.isArray(ownership?.candidates), true);
});

test("static orchestration exposure is profile-scoped and production services import no mutation or debugger execution", async () => {
  assert.equal(TOOL_PROFILES["re-static-core"].includes("re_trace_function"), true);
  assert.equal(TOOL_PROFILES["re-static-core"].includes("re_investigate_data_usage"), true);
  assert.equal(TOOL_PROFILES["re-static-core"].includes("nds_mutation_build"), false);
  assert.equal(TOOL_PROFILES["re-static-core"].includes("desmume_continue"), false);

  const [traceSource, dataSource, contextSource, toolSource, indexSource] = await Promise.all([
    readFile("src/services/re-orchestration/trace-function.ts", "utf8"),
    readFile("src/services/re-orchestration/data-usage.ts", "utf8"),
    readFile("src/services/re-orchestration/context-window.ts", "utf8"),
    readFile("src/tools/re-orchestration.ts", "utf8"),
    readFile("src/index.ts", "utf8"),
  ]);
  const productionSource = `${traceSource}\n${dataSource}\n${contextSource}\n${toolSource}`;
  assert.doesNotMatch(productionSource, /nds-mutation|desmume|OwnedProcessManager/);
  assert.match(traceSource, /disassembleReContextWindow/);
  assert.match(dataSource, /disassembleReContextWindow/);
  assert.match(indexSource, /registerReOrchestrationTools\(server, config\)/);
  assert.match(indexSource, /"re_trace_function"/);
  assert.match(indexSource, /"re_investigate_data_usage"/);
});
