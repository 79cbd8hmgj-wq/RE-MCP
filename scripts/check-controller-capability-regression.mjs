#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

import { measureToolSchemas } from "./tool-schema-measurement.mjs";

const root = path.resolve(process.argv[2] ?? ".");
const ARM9_RAM = 0x02000000;
const TARGET_HELPER_ADDRESS = 0x02000080;
const TARGET_GENERIC_CALLER_A = 0x02000020;
const TARGET_IDENTITY_FUNCTION_ENTRY = 0x02000038;
const TARGET_IDENTITY_CALLER = 0x02000040;
const TARGET_GENERIC_CALLER_B = 0x02000060;

function moduleUrl(relativePath) {
  return pathToFileURL(path.join(root, relativePath)).href;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function armBl(fromAddress, targetAddress) {
  const delta = targetAddress - (fromAddress + 8);
  if (delta % 4 !== 0) throw new Error("Synthetic ARM BL target must be word aligned");
  const words = delta / 4;
  if (words < -0x800000 || words > 0x7fffff) {
    throw new Error("Synthetic ARM BL target is out of range");
  }
  return (0xeb000000 | (words & 0x00ffffff)) >>> 0;
}

function writeArmInstruction(fixture, runtimeAddress, word) {
  const offset = 0x200 + (runtimeAddress - ARM9_RAM);
  fixture.writeUInt32LE(word >>> 0, offset);
}

function writeSingleFileFnt(fixture, offset, fileName) {
  const name = Buffer.from(fileName, "latin1");
  const size = 8 + 1 + name.length + 1;
  fixture.writeUInt32LE(8, offset);
  fixture.writeUInt16LE(0, offset + 4);
  fixture.writeUInt16LE(1, offset + 6);
  fixture.writeUInt8(name.length, offset + 8);
  name.copy(fixture, offset + 9);
  fixture.writeUInt8(0, offset + 9 + name.length);
  return size;
}

function createPreCallCapabilityFixture(crc16NdsHeader) {
  const fixture = Buffer.alloc(0x1000);
  fixture.write("RE-MCP STRICT", 0x00, 12, "ascii");
  fixture.write("CAP1", 0x0c, 4, "ascii");
  fixture.write("01", 0x10, 2, "ascii");
  fixture.writeUInt8(0, 0x14);

  fixture.writeUInt32LE(0x200, 0x20);
  fixture.writeUInt32LE(ARM9_RAM, 0x24);
  fixture.writeUInt32LE(ARM9_RAM, 0x28);
  fixture.writeUInt32LE(0x100, 0x2c);

  for (let offset = 0x200; offset < 0x300; offset += 4) {
    fixture.writeUInt32LE(0xe1a00000, offset); // mov r0, r0
  }

  // Entry proves all three caller functions without controller-supplied seeds.
  writeArmInstruction(fixture, 0x02000000, armBl(0x02000000, TARGET_GENERIC_CALLER_A));
  writeArmInstruction(fixture, 0x02000004, armBl(0x02000004, TARGET_IDENTITY_FUNCTION_ENTRY));
  writeArmInstruction(fixture, 0x02000008, armBl(0x02000008, TARGET_GENERIC_CALLER_B));
  writeArmInstruction(fixture, 0x0200000c, 0xe12fff1e); // bx lr

  // Generic caller A: only a broad post-call bounds check.
  writeArmInstruction(fixture, TARGET_GENERIC_CALLER_A, armBl(TARGET_GENERIC_CALLER_A, TARGET_HELPER_ADDRESS));
  writeArmInstruction(fixture, TARGET_GENERIC_CALLER_A + 4, 0xe3500040); // cmp r0, #0x40
  writeArmInstruction(fixture, TARGET_GENERIC_CALLER_A + 8, 0x23a00000); // movcs r0, #0
  writeArmInstruction(fixture, TARGET_GENERIC_CALLER_A + 12, 0xe12fff1e); // bx lr

  // The distinguishing identity evidence is intentionally BEFORE the helper call.
  // A forward-only window beginning at the BL cannot pass this regression.
  writeArmInstruction(fixture, TARGET_IDENTITY_FUNCTION_ENTRY, 0xe5d41012); // ldrb r1, [r4, #0x12]
  writeArmInstruction(fixture, TARGET_IDENTITY_FUNCTION_ENTRY + 4, 0xe3510007); // cmp r1, #7
  writeArmInstruction(fixture, TARGET_IDENTITY_CALLER, armBl(TARGET_IDENTITY_CALLER, TARGET_HELPER_ADDRESS));
  writeArmInstruction(fixture, TARGET_IDENTITY_CALLER + 4, 0x13a00000); // movne r0, #0
  writeArmInstruction(fixture, TARGET_IDENTITY_CALLER + 8, 0xe12fff1e); // bx lr

  // Generic caller B: second broad bound distractor.
  writeArmInstruction(fixture, TARGET_GENERIC_CALLER_B, armBl(TARGET_GENERIC_CALLER_B, TARGET_HELPER_ADDRESS));
  writeArmInstruction(fixture, TARGET_GENERIC_CALLER_B + 4, 0xe3500020); // cmp r0, #0x20
  writeArmInstruction(fixture, TARGET_GENERIC_CALLER_B + 8, 0x23a00000); // movcs r0, #0
  writeArmInstruction(fixture, TARGET_GENERIC_CALLER_B + 12, 0xe12fff1e); // bx lr

  writeArmInstruction(fixture, TARGET_HELPER_ADDRESS, 0xe1a00000);
  writeArmInstruction(fixture, TARGET_HELPER_ADDRESS + 4, 0xe12fff1e);

  fixture.writeUInt32LE(0x300, 0x30);
  fixture.writeUInt32LE(0x03800000, 0x34);
  fixture.writeUInt32LE(0x03800000, 0x38);
  fixture.writeUInt32LE(0x20, 0x3c);
  fixture.fill(0xa7, 0x300, 0x320);

  const fntOffset = 0x400;
  const fntSize = writeSingleFileFnt(fixture, fntOffset, "base.bin");
  fixture.writeUInt32LE(fntOffset, 0x40);
  fixture.writeUInt32LE(fntSize, 0x44);

  const fatOffset = 0x500;
  const fileStart = 0x600;
  const fileBytes = Buffer.from("BASE", "ascii");
  fixture.writeUInt32LE(fatOffset, 0x48);
  fixture.writeUInt32LE(8, 0x4c);
  fixture.writeUInt32LE(fileStart, fatOffset);
  fixture.writeUInt32LE(fileStart + fileBytes.length, fatOffset + 4);
  fileBytes.copy(fixture, fileStart);

  fixture.writeUInt32LE(0x700, 0x50);
  fixture.writeUInt32LE(0, 0x54);
  fixture.writeUInt32LE(0x780, 0x58);
  fixture.writeUInt32LE(0, 0x5c);
  fixture.writeUInt32LE(fileStart + fileBytes.length, 0x80);
  fixture.writeUInt32LE(0x200, 0x84);
  fixture.writeUInt16LE(crc16NdsHeader(fixture.subarray(0, 0x15e)), 0x15e);
  return fixture;
}

function candidateAt(result, address) {
  return result.candidates.find((candidate) => candidate.instructionAddress === address) ?? null;
}

function requireInstruction(window, address, mnemonic) {
  const instruction = window.find((entry) => entry.address === address);
  if (instruction?.mnemonic !== mnemonic) {
    throw new Error(
      `Missing ${mnemonic} at 0x${address.toString(16)} in bounded pre-call evidence`,
    );
  }
}

const { crc16NdsHeader } = await import(moduleUrl("dist/services/nds/header-rebuild.js"));
const { readNdsRomMap } = await import(moduleUrl("dist/services/nds/rom-map.js"));
const { createCapstoneArmBackend } = await import(moduleUrl("dist/services/disassembly/capstone.js"));
const { traceNdsFunction } = await import(
  moduleUrl("dist/services/re-orchestration/trace-function.js")
);
const { persistInvestigationResumeArtifact } = await import(
  moduleUrl("dist/services/re-orchestration/resume-artifact.js")
);
const { persistInvestigationResult } = await import(
  moduleUrl("dist/services/re-orchestration/investigation-journal.js")
);
const { resumeInvestigation } = await import(
  moduleUrl("dist/services/re-orchestration/resume.js")
);

// Package-level profile/schema regression: focused exposure may shrink advertisement,
// but it must not silently drop phase-critical controls or the full legacy surface.
const [fullSchema, staticSchema, runtimeSchema] = await Promise.all([
  measureToolSchemas("re-full", { packageRoot: root }),
  measureToolSchemas("re-static-core", { packageRoot: root }),
  measureToolSchemas("re-runtime", { packageRoot: root }),
]);
if (fullSchema.toolCount !== 56) {
  throw new Error(`re-full capability count regressed: ${fullSchema.toolCount}`);
}
if (!staticSchema.toolNames.includes("server_capabilities")) {
  throw new Error("re-static-core lost server_capabilities discovery");
}
if (!runtimeSchema.toolNames.includes("desmume_executable_ranges_replace")) {
  throw new Error("re-runtime lost executable-range control");
}
if (!runtimeSchema.toolNames.includes("server_capabilities")) {
  throw new Error("re-runtime lost server_capabilities discovery");
}
if (staticSchema.serializedBytes > Math.floor(fullSchema.serializedBytes * 0.3)) {
  throw new Error(
    `re-static-core schema payload no longer meets 70% reduction: full=${fullSchema.serializedBytes}, static=${staticSchema.serializedBytes}`,
  );
}

const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), "re-mcp-capability-regression-"));
try {
  await mkdir(path.join(temporaryRoot, "roms"), { recursive: true });
  const fixture = createPreCallCapabilityFixture(crc16NdsHeader);
  const sourceHash = sha256(fixture);
  const romPath = path.join(temporaryRoot, "roms", "pre-call-context.nds");
  await writeFile(romPath, fixture, { flag: "wx" });
  const map = await readNdsRomMap(romPath);
  if (map.sha256 !== sourceHash) throw new Error("Strict fixture canonical SHA mismatch");

  const backend = await createCapstoneArmBackend();
  let trace;
  try {
    trace = await traceNdsFunction(
      map,
      {
        processor: "arm9",
        runtimeAddress: TARGET_HELPER_ADDRESS,
        mode: "arm",
        proofScope: { kind: "main" },
        seeds: [],
      },
      {
        maxCandidates: 8,
        maxWindowInstructions: 4,
        maxWindowBytes: 16,
        proof: {
          maxComponents: 4,
          maxBlocks: 64,
          maxInstructions: 128,
          maxBytes: 512,
          maxEdges: 128,
          maxXrefs: 16,
        },
        cfg: {
          maxBlocks: 16,
          maxInstructions: 32,
          maxBytes: 128,
          maxEdges: 32,
        },
      },
      backend,
    );
  } finally {
    backend.close();
  }

  const addresses = trace.candidates
    .map((candidate) => candidate.instructionAddress)
    .sort((left, right) => left - right);
  const expectedAddresses = [TARGET_GENERIC_CALLER_A, TARGET_IDENTITY_CALLER, TARGET_GENERIC_CALLER_B];
  if (JSON.stringify(addresses) !== JSON.stringify(expectedAddresses)) {
    throw new Error(`Strict trace caller set regressed: ${JSON.stringify(addresses)}`);
  }

  const identity = candidateAt(trace, TARGET_IDENTITY_CALLER);
  if (identity === null) throw new Error("Strict trace omitted identity-dependent caller");
  requireInstruction(identity.callSiteWindow, TARGET_IDENTITY_FUNCTION_ENTRY, "ldrb");
  requireInstruction(identity.callSiteWindow, TARGET_IDENTITY_FUNCTION_ENTRY + 4, "cmp");
  requireInstruction(identity.callSiteWindow, TARGET_IDENTITY_CALLER, "bl");
  requireInstruction(identity.callSiteWindow, TARGET_IDENTITY_CALLER + 4, "movne");

  for (const distractorAddress of [TARGET_GENERIC_CALLER_A, TARGET_GENERIC_CALLER_B]) {
    const distractor = candidateAt(trace, distractorAddress);
    if (distractor === null) throw new Error("Strict trace omitted a generic distractor");
    if (distractor.callSiteWindow.some((entry) => entry.mnemonic === "ldrb")) {
      throw new Error("Generic distractor unexpectedly contains the identity-load signature");
    }
  }

  const source = { sha256: map.sha256, sha256Prefix: map.sha256Prefix };
  const artifact = await persistInvestigationResumeArtifact(source, temporaryRoot, trace);
  await persistInvestigationResult(source, temporaryRoot, {
    operation: trace.operation,
    normalizedInputs: {
      rom: "roms/pre-call-context.nds",
      processor: "arm9",
      runtimeAddress: TARGET_HELPER_ADDRESS,
      mode: "arm",
      includeMain: true,
      overlayIds: [],
      seeds: [],
    },
    completedStages: trace.completedPrimitiveStages,
    artifacts: [artifact],
    result: { ...trace, artifacts: [artifact] },
    recommendedNextAction: trace.recommendedNextAction,
  });

  const resumed = await resumeInvestigation(romPath, {
    workspaceRoot: temporaryRoot,
    commandTimeoutMs: 30_000,
    maxOutputBytes: 1_000_000,
    ghidraHome: null,
    ghidraTimeoutMs: 30_000,
    toolProfile: "re-static-core",
  });
  if (resumed.replayRequired !== false) {
    throw new Error("Replay-free resume regressed despite a complete bounded resume artifact");
  }
  const resumedTrace = resumed.resumableResults.find(
    (entry) => entry.operation === "re_trace_function",
  );
  if (resumedTrace?.resumeEvidenceComplete !== true) {
    throw new Error("Resumed trace is not marked evidence-complete");
  }
  const resumedIdentity = resumedTrace.candidates.find(
    (candidate) => candidate?.instructionAddress === TARGET_IDENTITY_CALLER,
  );
  if (!Array.isArray(resumedIdentity?.callSiteWindow)) {
    throw new Error("Resume artifact lost bounded call-site evidence");
  }
  requireInstruction(resumedIdentity.callSiteWindow, TARGET_IDENTITY_FUNCTION_ENTRY, "ldrb");
  requireInstruction(resumedIdentity.callSiteWindow, TARGET_IDENTITY_FUNCTION_ENTRY + 4, "cmp");

  const finalBytes = await readFile(romPath);
  if (sha256(finalBytes) !== sourceHash) {
    throw new Error("Controller capability regression smoke modified the source ROM");
  }

  process.stdout.write("Controller capability regression smoke passed\n");
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
