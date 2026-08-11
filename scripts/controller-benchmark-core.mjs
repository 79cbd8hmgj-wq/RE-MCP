import { createHash } from "node:crypto";
import {
  lstat,
  mkdir,
  readdir,
  readFile,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

import { measureToolSchemas } from "./tool-schema-measurement.mjs";

const BENCHMARK_VERSION = 1;
const ROM_RELATIVE_PATH = "roms/controller-benchmark.nds";
const VALID_MANIFEST_RELATIVE_PATH = "plans/valid-mutation.json";
const INVALID_MANIFEST_RELATIVE_PATH = "plans/invalid-guard.json";
const SCENARIO_METADATA_RELATIVE_PATH = "benchmark/scenario.json";
const CONTROLLER_LABEL_MAX = 120;
const TARGET_HELPER_ADDRESS = 0x02000080;
const TARGET_GENERIC_CALLER_A = 0x02000020;
const TARGET_IDENTITY_CALLER = 0x02000040;
const TARGET_GENERIC_CALLER_B = 0x02000060;
const TARGET_EXPECTED_ACTION_ID = "identity-restriction-02000040";
const TARGET_REQUIRED_PROFILE = "re-static-core";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(scriptDirectory, "..");
const registryPath = path.join(packageRoot, "benchmarks", "controller", "scenarios.json");

function moduleUrl(relativePath) {
  return pathToFileURL(path.join(packageRoot, relativePath)).href;
}

function sha256Bytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function sha256File(filePath) {
  return sha256Bytes(await readFile(filePath));
}

function workspaceRelative(workspaceRoot, absolutePath) {
  return path.relative(path.resolve(workspaceRoot), path.resolve(absolutePath)).split(path.sep).join("/");
}

async function loadServices() {
  const { crc16NdsHeader } = await import(moduleUrl("dist/services/nds/header-rebuild.js"));
  const { readNdsRomMap } = await import(moduleUrl("dist/services/nds/rom-map.js"));
  const { NdsError } = await import(moduleUrl("dist/services/nds/errors.js"));
  const {
    readControllerCheckpoint,
    writeControllerCheckpoint,
  } = await import(moduleUrl("dist/services/controller-checkpoint.js"));
  const { loadNdsMutationManifest } = await import(
    moduleUrl("dist/services/nds/mutation/manifest.js")
  );
  const { compileNdsMutationPlan } = await import(
    moduleUrl("dist/services/nds/mutation/planner.js")
  );
  const { verifyPublishedNdsMutationBuild } = await import(
    moduleUrl("dist/services/nds/mutation/build.js")
  );
  const { readInvestigationJournal } = await import(
    moduleUrl("dist/services/re-orchestration/investigation-journal.js")
  );
  const { readInvestigationResumeArtifact } = await import(
    moduleUrl("dist/services/re-orchestration/resume-artifact.js")
  );
  return {
    crc16NdsHeader,
    readNdsRomMap,
    NdsError,
    readControllerCheckpoint,
    writeControllerCheckpoint,
    loadNdsMutationManifest,
    compileNdsMutationPlan,
    verifyPublishedNdsMutationBuild,
    readInvestigationJournal,
    readInvestigationResumeArtifact,
  };
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
  const offset = 0x200 + (runtimeAddress - 0x02000000);
  fixture.writeUInt32LE(word >>> 0, offset);
}

function writeTargetedFunctionFixture(fixture) {
  for (let offset = 0x200; offset < 0x300; offset += 4) {
    fixture.writeUInt32LE(0xe1a00000, offset); // ARM NOP (mov r0, r0)
  }

  // Program entry reaches all three callers so canonical xref traversal can prove them
  // without controller-supplied seeds.
  writeArmInstruction(fixture, 0x02000000, armBl(0x02000000, TARGET_GENERIC_CALLER_A));
  writeArmInstruction(fixture, 0x02000004, armBl(0x02000004, TARGET_IDENTITY_CALLER));
  writeArmInstruction(fixture, 0x02000008, armBl(0x02000008, TARGET_GENERIC_CALLER_B));
  writeArmInstruction(fixture, 0x0200000c, 0xe12fff1e); // bx lr

  // Generic caller A: broad bounds check after helper result.
  writeArmInstruction(fixture, TARGET_GENERIC_CALLER_A, armBl(TARGET_GENERIC_CALLER_A, TARGET_HELPER_ADDRESS));
  writeArmInstruction(fixture, TARGET_GENERIC_CALLER_A + 4, 0xe3500040); // cmp r0, #0x40
  writeArmInstruction(fixture, TARGET_GENERIC_CALLER_A + 8, 0x23a00000); // movcs r0, #0
  writeArmInstruction(fixture, TARGET_GENERIC_CALLER_A + 12, 0xe12fff1e); // bx lr

  // Identity-dependent caller: load identity byte from object state, compare to identity 7,
  // then reject on mismatch. The four-instruction window starts at the BL and exposes this
  // signature without any symbol/prose grading.
  writeArmInstruction(fixture, TARGET_IDENTITY_CALLER, armBl(TARGET_IDENTITY_CALLER, TARGET_HELPER_ADDRESS));
  writeArmInstruction(fixture, TARGET_IDENTITY_CALLER + 4, 0xe5d41012); // ldrb r1, [r4, #0x12]
  writeArmInstruction(fixture, TARGET_IDENTITY_CALLER + 8, 0xe3510007); // cmp r1, #7
  writeArmInstruction(fixture, TARGET_IDENTITY_CALLER + 12, 0x13a00000); // movne r0, #0
  writeArmInstruction(fixture, TARGET_IDENTITY_CALLER + 16, 0xe12fff1e); // bx lr

  // Generic caller B: a second broad bound, intentionally similar to A.
  writeArmInstruction(fixture, TARGET_GENERIC_CALLER_B, armBl(TARGET_GENERIC_CALLER_B, TARGET_HELPER_ADDRESS));
  writeArmInstruction(fixture, TARGET_GENERIC_CALLER_B + 4, 0xe3500020); // cmp r0, #0x20
  writeArmInstruction(fixture, TARGET_GENERIC_CALLER_B + 8, 0x23a00000); // movcs r0, #0
  writeArmInstruction(fixture, TARGET_GENERIC_CALLER_B + 12, 0xe12fff1e); // bx lr

  writeArmInstruction(fixture, TARGET_HELPER_ADDRESS, 0xe1a00000); // mov r0, r0
  writeArmInstruction(fixture, TARGET_HELPER_ADDRESS + 4, 0xe12fff1e); // bx lr
}

function createSyntheticRomBytes(crc16NdsHeader) {
  const fixture = Buffer.alloc(0x1000);
  fixture.write("RE-MCP BENCH", 0x00, 12, "ascii");
  fixture.write("BMK1", 0x0c, 4, "ascii");
  fixture.write("01", 0x10, 2, "ascii");
  fixture.writeUInt8(0, 0x14);

  fixture.writeUInt32LE(0x200, 0x20);
  fixture.writeUInt32LE(0x02000000, 0x24);
  fixture.writeUInt32LE(0x02000000, 0x28);
  fixture.writeUInt32LE(0x100, 0x2c);
  writeTargetedFunctionFixture(fixture);

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

async function loadRegistry() {
  const parsed = JSON.parse(await readFile(registryPath, "utf8"));
  if (
    parsed === null
    || typeof parsed !== "object"
    || parsed.benchmarkVersion !== BENCHMARK_VERSION
    || !Array.isArray(parsed.scenarios)
  ) {
    throw new Error("Controller benchmark scenario registry is invalid or unsupported");
  }
  const seen = new Set();
  for (const scenario of parsed.scenarios) {
    if (
      scenario === null
      || typeof scenario !== "object"
      || typeof scenario.id !== "string"
      || !/^[a-z0-9-]{1,64}$/.test(scenario.id)
      || typeof scenario.title !== "string"
      || scenario.title.length < 1
      || scenario.title.length > 120
      || typeof scenario.prompt !== "string"
      || scenario.prompt.length < 1
      || scenario.prompt.length > 4000
      || !Array.isArray(scenario.expectedTools)
      || scenario.expectedTools.length < 1
      || scenario.expectedTools.length > 12
      || scenario.expectedTools.some((tool) => typeof tool !== "string" || !/^[a-z0-9_]+$/.test(tool))
      || (scenario.requiredToolProfile !== undefined
        && (typeof scenario.requiredToolProfile !== "string"
          || !/^re-[a-z0-9-]+$/.test(scenario.requiredToolProfile)))
      || seen.has(scenario.id)
    ) {
      throw new Error("Controller benchmark scenario registry contains an invalid entry");
    }
    seen.add(scenario.id);
  }
  return parsed;
}

function selectScenario(registry, scenarioId) {
  const scenario = registry.scenarios.find((candidate) => candidate.id === scenarioId);
  if (scenario === undefined) throw new Error(`Unknown controller benchmark scenario: ${scenarioId}`);
  return scenario;
}

async function existingLstat(target) {
  try {
    return await lstat(target);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return null;
    throw error;
  }
}

async function requireEmptyPrepareWorkspace(workspaceRoot) {
  const info = await existingLstat(workspaceRoot);
  if (info === null) {
    await mkdir(workspaceRoot, { recursive: true });
    const created = await lstat(workspaceRoot);
    if (created.isSymbolicLink() || !created.isDirectory()) {
      throw new Error("Controller benchmark prepare workspace must be a real directory, not a symlink");
    }
    return;
  }
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new Error("Controller benchmark prepare workspace must be an empty real directory, not a symlink");
  }
  const entries = await readdir(workspaceRoot);
  if (entries.length !== 0) {
    throw new Error("Controller benchmark prepare workspace must be empty; non-empty targets are rejected");
  }
}

async function requireScoreWorkspace(workspaceRoot) {
  const info = await lstat(workspaceRoot);
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new Error("Controller benchmark score workspace must be a real directory, not a symlink");
  }
}

async function writeJsonExclusive(filePath, value) {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
  });
}

function mutationManifest(sourceSha256, validGuard) {
  return {
    format: "re-mcp-nds-mutation",
    formatVersion: 1,
    source: { sha256: sourceSha256 },
    output: { filename: "controller-benchmark-modded.nds" },
    operations: [
      {
        type: "replace-bytes",
        target: { component: "arm9", relativeOffset: 0xf0 },
        expected: validGuard ? "0000" : "ffff",
        replacement: validGuard ? "1234" : "5678",
      },
    ],
  };
}

async function prepareScenario(scenario, workspaceRoot, services) {
  await requireEmptyPrepareWorkspace(workspaceRoot);
  for (const relative of ["roms", "plans", "benchmark"]) {
    await mkdir(path.join(workspaceRoot, relative), { recursive: false });
  }

  const fixture = createSyntheticRomBytes(services.crc16NdsHeader);
  const romPath = path.join(workspaceRoot, ROM_RELATIVE_PATH);
  await writeFile(romPath, fixture, { flag: "wx" });
  const map = await services.readNdsRomMap(romPath);

  if (scenario.id === "verified-mutation") {
    await writeJsonExclusive(
      path.join(workspaceRoot, VALID_MANIFEST_RELATIVE_PATH),
      mutationManifest(map.sha256, true),
    );
  } else if (scenario.id === "guard-rejection") {
    await writeJsonExclusive(
      path.join(workspaceRoot, INVALID_MANIFEST_RELATIVE_PATH),
      mutationManifest(map.sha256, false),
    );
  }

  if (scenario.id === "checkpoint-resume") {
    await services.writeControllerCheckpoint(
      { sha256: map.sha256, sha256Prefix: map.sha256Prefix },
      workspaceRoot,
      0,
      {
        objective: "Resume this deterministic controller benchmark without trusting prior prose as ROM evidence.",
        confirmedFacts: [],
        hypotheses: [],
        completedActions: [],
        nextActions: [{
          id: "resume-analysis",
          description: "Revalidate the benchmark ROM and capture fresh controlled ARM9 evidence before advancing the checkpoint.",
        }],
      },
    );
  }

  const targeted = scenario.id === "targeted-function-investigation";
  const metadata = {
    benchmarkVersion: BENCHMARK_VERSION,
    scenarioId: scenario.id,
    sourceRomSha256: map.sha256,
    sourceRomSha256Prefix: map.sha256Prefix,
    rom: ROM_RELATIVE_PATH,
    ...(scenario.requiredToolProfile === undefined
      ? {}
      : { requiredToolProfile: scenario.requiredToolProfile }),
    ...(targeted ? { helperAddress: TARGET_HELPER_ADDRESS } : {}),
  };
  await writeJsonExclusive(path.join(workspaceRoot, SCENARIO_METADATA_RELATIVE_PATH), metadata);

  process.stdout.write(`${JSON.stringify({
    ...metadata,
    helperAddress: targeted ? `0x${TARGET_HELPER_ADDRESS.toString(16).padStart(8, "0")}` : undefined,
    prompt: scenario.prompt,
  }, null, 2)}\n`);
}

function check(id, passed) {
  return { id, passed: passed === true };
}

async function regularFileHash(workspaceRoot, relativePath) {
  const absolutePath = path.join(workspaceRoot, ...relativePath.split("/"));
  try {
    const info = await lstat(absolutePath);
    if (info.isSymbolicLink() || !info.isFile()) return null;
    return await sha256File(absolutePath);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return null;
    throw error;
  }
}

async function readJsonRegularFile(workspaceRoot, relativePath) {
  const absolutePath = path.join(workspaceRoot, ...relativePath.split("/"));
  try {
    const info = await lstat(absolutePath);
    if (info.isSymbolicLink() || !info.isFile()) return null;
    return JSON.parse(await readFile(absolutePath, "utf8"));
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return null;
    return null;
  }
}

async function safeReadCheckpoint(services, map, workspaceRoot) {
  try {
    return await services.readControllerCheckpoint(
      { sha256: map.sha256, sha256Prefix: map.sha256Prefix },
      workspaceRoot,
    );
  } catch {
    return null;
  }
}

async function safeReadInvestigation(services, map, workspaceRoot) {
  try {
    return await services.readInvestigationJournal(
      { sha256: map.sha256, sha256Prefix: map.sha256Prefix },
      workspaceRoot,
    );
  } catch {
    return null;
  }
}

function evidenceMatches(entries, relativePath, expectedSha256, requiredOutcome = null) {
  return entries.some((entry) => {
    if (requiredOutcome !== null && entry.outcome !== requiredOutcome) return false;
    return Array.isArray(entry.evidenceRefs) && entry.evidenceRefs.some(
      (ref) => ref.path === relativePath && ref.sha256 === expectedSha256,
    );
  });
}

async function scoreAnalysisHandoff(services, map, workspaceRoot, checks) {
  const manifestRelative = `analysis/generated/nds/${map.sha256Prefix}/manifest.json`;
  const manifest = await readJsonRegularFile(workspaceRoot, manifestRelative);
  const manifestHash = await regularFileHash(workspaceRoot, manifestRelative);
  checks.push(check(
    "analysis-bundle-manifest",
    manifest !== null
      && manifest.format === "re-mcp-nds-static-analysis"
      && manifest.formatVersion === 1
      && manifest.sourceRomSha256 === map.sha256
      && manifestHash !== null,
  ));

  const readResult = await safeReadCheckpoint(services, map, workspaceRoot);
  const checkpointValid = readResult !== null
    && readResult.exists === true
    && readResult.checkpoint.revision === 1
    && readResult.checkpoint.authority === "controller-state-only";
  checks.push(check("checkpoint-valid", checkpointValid));
  checks.push(check(
    "checkpoint-evidence-bound",
    checkpointValid
      && manifestHash !== null
      && evidenceMatches(readResult.checkpoint.confirmedFacts, manifestRelative, manifestHash),
  ));
}

async function scoreCheckpointResume(services, map, workspaceRoot, expectedFixture, checks) {
  const arm9Relative = `analysis/generated/nds/${map.sha256Prefix}/arm9.bin`;
  const arm9Absolute = path.join(workspaceRoot, ...arm9Relative.split("/"));
  let arm9Valid = false;
  let arm9Hash = null;
  try {
    const info = await lstat(arm9Absolute);
    if (!info.isSymbolicLink() && info.isFile()) {
      const actual = await readFile(arm9Absolute);
      const expected = expectedFixture.subarray(
        map.header.arm9.romOffset,
        map.header.arm9.romOffset + map.header.arm9.size,
      );
      arm9Valid = actual.equals(expected);
      arm9Hash = sha256Bytes(actual);
    }
  } catch {
    arm9Valid = false;
  }
  checks.push(check("resume-arm9-evidence", arm9Valid));

  const readResult = await safeReadCheckpoint(services, map, workspaceRoot);
  const checkpointValid = readResult !== null
    && readResult.exists === true
    && readResult.checkpoint.revision === 2
    && readResult.checkpoint.authority === "controller-state-only";
  checks.push(check("checkpoint-valid", checkpointValid));
  checks.push(check(
    "checkpoint-evidence-bound",
    checkpointValid
      && arm9Hash !== null
      && evidenceMatches(
        readResult.checkpoint.completedActions,
        arm9Relative,
        arm9Hash,
        "completed",
      ),
  ));
}

async function scoreVerifiedMutation(services, map, workspaceRoot, checks) {
  let verified = null;
  try {
    const loaded = await services.loadNdsMutationManifest(
      workspaceRoot,
      VALID_MANIFEST_RELATIVE_PATH,
    );
    verified = await services.verifyPublishedNdsMutationBuild(map, workspaceRoot, loaded);
  } catch {
    verified = null;
  }
  const buildPassed = verified !== null
    && verified.verification?.status === "passed"
    && verified.verification?.unexpectedChangedBytes === 0;
  checks.push(check("build-freshly-verified", buildPassed));

  const verificationRelative = buildPassed
    ? workspaceRelative(workspaceRoot, path.join(verified.outputRoot, "verification.json"))
    : null;
  const verificationHash = verificationRelative === null
    ? null
    : await regularFileHash(workspaceRoot, verificationRelative);
  const readResult = await safeReadCheckpoint(services, map, workspaceRoot);
  const checkpointValid = readResult !== null
    && readResult.exists === true
    && readResult.checkpoint.revision === 1
    && readResult.checkpoint.authority === "controller-state-only";
  checks.push(check("checkpoint-valid", checkpointValid));
  checks.push(check(
    "checkpoint-evidence-bound",
    checkpointValid
      && verificationRelative !== null
      && verificationHash !== null
      && evidenceMatches(
        readResult.checkpoint.completedActions,
        verificationRelative,
        verificationHash,
        "completed",
      ),
  ));
}

async function outputRootHasNoBuilds(workspaceRoot, sha256Prefix) {
  const outputRoot = path.join(workspaceRoot, "output", "nds", sha256Prefix);
  try {
    const info = await lstat(outputRoot);
    if (info.isSymbolicLink() || !info.isDirectory()) return false;
    return (await readdir(outputRoot)).length === 0;
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return true;
    throw error;
  }
}

async function scoreGuardRejection(services, map, workspaceRoot, checks) {
  let rejectedByCanonicalPlanner = false;
  try {
    const loaded = await services.loadNdsMutationManifest(
      workspaceRoot,
      INVALID_MANIFEST_RELATIVE_PATH,
    );
    await services.compileNdsMutationPlan(map, workspaceRoot, loaded);
  } catch (error) {
    rejectedByCanonicalPlanner = error instanceof services.NdsError
      && error.category === "original-byte-guard-failed";
  }
  checks.push(check("guard-canonically-rejected", rejectedByCanonicalPlanner));
  checks.push(check(
    "guard-rejected-no-output",
    await outputRootHasNoBuilds(workspaceRoot, map.sha256Prefix),
  ));

  const readResult = await safeReadCheckpoint(services, map, workspaceRoot);
  const checkpointValid = readResult !== null
    && readResult.exists === true
    && readResult.checkpoint.revision === 1
    && readResult.checkpoint.authority === "controller-state-only";
  checks.push(check("checkpoint-valid", checkpointValid));
  checks.push(check(
    "guard-failure-recorded",
    checkpointValid
      && readResult.checkpoint.completedActions.some((entry) => entry.outcome === "failed")
      && readResult.checkpoint.nextActions.length > 0,
  ));
}

function candidateInstructionAddresses(artifact) {
  if (!Array.isArray(artifact?.candidates)) return [];
  return artifact.candidates
    .map((candidate) => candidate?.instructionAddress)
    .filter((value) => Number.isSafeInteger(value))
    .sort((left, right) => left - right);
}

async function scoreTargetedFunctionInvestigation(
  services,
  map,
  workspaceRoot,
  activeToolProfile,
  checks,
) {
  checks.push(check("required-static-profile", activeToolProfile === TARGET_REQUIRED_PROFILE));

  const journal = await safeReadInvestigation(services, map, workspaceRoot);
  const journalValid = journal !== null
    && journal.metadata !== null
    && journal.projection !== null
    && journal.metadata.entryCount === journal.entries.length
    && journal.projection.latestSequence === journal.entries.length;
  checks.push(check("investigation-journal-integrity", journalValid));

  const traceEntries = journalValid
    ? journal.entries.filter((entry) => entry.operation === "re_trace_function")
    : [];
  const traceEntry = traceEntries.at(-1) ?? null;
  checks.push(check(
    "high-level-trace-persisted",
    traceEntry !== null
      && traceEntry.completionStatus === "completed"
      && traceEntry.sourceRomSha256 === map.sha256
      && traceEntry.completedStages.includes("direct-caller-xrefs"),
  ));

  const resumeRef = traceEntry?.artifactHashes.find(
    (artifact) => artifact.kind === "re-resume-state"
      && typeof artifact.path === "string"
      && typeof artifact.sha256 === "string",
  ) ?? null;
  let resumeArtifact = null;
  if (resumeRef !== null) {
    try {
      resumeArtifact = await services.readInvestigationResumeArtifact(
        workspaceRoot,
        { path: resumeRef.path, sha256: resumeRef.sha256 },
      );
    } catch {
      resumeArtifact = null;
    }
  }
  checks.push(check(
    "resume-artifact-integrity",
    resumeArtifact !== null
      && resumeArtifact.authority === "deterministic-resume-state"
      && resumeArtifact.sourceRomSha256 === map.sha256
      && resumeArtifact.operation === "re_trace_function"
      && resumeArtifact.subject?.runtimeAddress === TARGET_HELPER_ADDRESS,
  ));

  const candidateAddresses = candidateInstructionAddresses(resumeArtifact);
  checks.push(check(
    "target-caller-set",
    candidateAddresses.length === 3
      && candidateAddresses[0] === TARGET_GENERIC_CALLER_A
      && candidateAddresses[1] === TARGET_IDENTITY_CALLER
      && candidateAddresses[2] === TARGET_GENERIC_CALLER_B,
  ));

  const checkpointRead = await safeReadCheckpoint(services, map, workspaceRoot);
  const checkpointValid = checkpointRead !== null
    && checkpointRead.exists === true
    && checkpointRead.checkpoint.revision === 1
    && checkpointRead.checkpoint.authority === "controller-state-only";
  checks.push(check("checkpoint-valid", checkpointValid));
  checks.push(check(
    "identity-dependent-caller-selected",
    checkpointValid
      && checkpointRead.checkpoint.completedActions.some(
        (entry) => entry.id === TARGET_EXPECTED_ACTION_ID && entry.outcome === "completed",
      ),
  ));
}

function normalizeControllerLabel(raw) {
  if (raw === undefined) return null;
  if (
    raw.length < 1
    || raw.length > CONTROLLER_LABEL_MAX
    || raw.includes("\n")
    || raw.includes("\r")
  ) {
    throw new Error(`Controller label must be 1-${CONTROLLER_LABEL_MAX} characters on one line`);
  }
  return raw;
}

function optionalBooleanEnvironment(name) {
  const value = process.env[name];
  if (value === undefined || value.trim().length === 0) return null;
  if (value === "true" || value === "1" || value === "yes") return true;
  if (value === "false" || value === "0" || value === "no") return false;
  throw new Error(`${name} must be true/false, 1/0, or yes/no`);
}

function optionalCountEnvironment(name) {
  const value = process.env[name];
  if (value === undefined || value.trim().length === 0) return null;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${name} must be a non-negative safe integer`);
  }
  return parsed;
}

function liveControllerMetrics() {
  return {
    requestAccepted: optionalBooleanEnvironment("RE_MCP_BENCHMARK_REQUEST_ACCEPTED"),
    turns: optionalCountEnvironment("RE_MCP_BENCHMARK_TURNS"),
    toolCalls: optionalCountEnvironment("RE_MCP_BENCHMARK_TOOL_CALLS"),
  };
}

async function scoreScenario(scenario, workspaceRoot, controllerLabel, services) {
  await requireScoreWorkspace(workspaceRoot);
  const expectedFixture = createSyntheticRomBytes(services.crc16NdsHeader);
  const expectedSha256 = sha256Bytes(expectedFixture);
  const romPath = path.join(workspaceRoot, ROM_RELATIVE_PATH);
  const checks = [];
  const declaredProfile = process.env.RE_MCP_TOOL_PROFILE?.trim() || null;
  const activeToolProfile = declaredProfile ?? scenario.requiredToolProfile ?? "re-full";
  const schema = await measureToolSchemas(activeToolProfile, { packageRoot });

  let actualFixture = null;
  try {
    const info = await lstat(romPath);
    if (!info.isSymbolicLink() && info.isFile()) actualFixture = await readFile(romPath);
  } catch {
    actualFixture = null;
  }
  const sourceImmutable = actualFixture !== null && actualFixture.equals(expectedFixture);
  checks.push(check("source-immutable", sourceImmutable));

  if (!sourceImmutable) {
    const scorecard = {
      benchmarkVersion: BENCHMARK_VERSION,
      scenarioId: scenario.id,
      controllerLabel,
      activeToolProfile,
      advertisedToolCount: schema.toolCount,
      toolSchemaBytes: schema.serializedBytes,
      toolSchemaEstimatedTokens: schema.estimatedTokens,
      controllerRun: liveControllerMetrics(),
      passed: false,
      sourceRomSha256: expectedSha256,
      checks,
    };
    process.stdout.write(`${JSON.stringify(scorecard, null, 2)}\n`);
    process.exitCode = 1;
    return;
  }

  const map = await services.readNdsRomMap(romPath);
  checks.push(check("source-canonical-sha", map.sha256 === expectedSha256));

  const metadata = await readJsonRegularFile(workspaceRoot, SCENARIO_METADATA_RELATIVE_PATH);
  checks.push(check(
    "scenario-prepared",
    metadata !== null
      && metadata.benchmarkVersion === BENCHMARK_VERSION
      && metadata.scenarioId === scenario.id
      && metadata.sourceRomSha256 === map.sha256
      && metadata.rom === ROM_RELATIVE_PATH,
  ));
  if (scenario.requiredToolProfile !== undefined) {
    checks.push(check(
      "declared-required-profile",
      declaredProfile === scenario.requiredToolProfile,
    ));
  }

  if (scenario.id === "analysis-handoff") {
    await scoreAnalysisHandoff(services, map, workspaceRoot, checks);
  } else if (scenario.id === "checkpoint-resume") {
    await scoreCheckpointResume(services, map, workspaceRoot, expectedFixture, checks);
  } else if (scenario.id === "verified-mutation") {
    await scoreVerifiedMutation(services, map, workspaceRoot, checks);
  } else if (scenario.id === "guard-rejection") {
    await scoreGuardRejection(services, map, workspaceRoot, checks);
  } else if (scenario.id === "targeted-function-investigation") {
    await scoreTargetedFunctionInvestigation(
      services,
      map,
      workspaceRoot,
      activeToolProfile,
      checks,
    );
  } else {
    throw new Error(`Unsupported benchmark scenario: ${scenario.id}`);
  }

  const scorecard = {
    benchmarkVersion: BENCHMARK_VERSION,
    scenarioId: scenario.id,
    controllerLabel,
    activeToolProfile,
    advertisedToolCount: schema.toolCount,
    toolSchemaBytes: schema.serializedBytes,
    toolSchemaEstimatedTokens: schema.estimatedTokens,
    controllerRun: liveControllerMetrics(),
    passed: checks.every((entry) => entry.passed === true),
    sourceRomSha256: map.sha256,
    checks,
  };
  process.stdout.write(`${JSON.stringify(scorecard, null, 2)}\n`);
  if (!scorecard.passed) process.exitCode = 1;
}

export async function runControllerBenchmark(argv = process.argv.slice(2)) {
  const [mode, scenarioId, workspaceArg, controllerLabelArg, ...extra] = argv;
  if (
    extra.length !== 0
    || (mode !== "prepare" && mode !== "score")
    || scenarioId === undefined
    || workspaceArg === undefined
    || (mode === "prepare" && controllerLabelArg !== undefined)
  ) {
    throw new Error(
      "Usage: controller-benchmark.mjs prepare <scenario-id> <workspace> | score <scenario-id> <workspace> [controller-label]",
    );
  }

  const registry = await loadRegistry();
  const scenario = selectScenario(registry, scenarioId);
  const workspaceRoot = path.resolve(workspaceArg);
  const services = await loadServices();
  if (mode === "prepare") {
    await prepareScenario(scenario, workspaceRoot, services);
  } else {
    await scoreScenario(
      scenario,
      workspaceRoot,
      normalizeControllerLabel(controllerLabelArg),
      services,
    );
  }
}

export async function mainControllerBenchmark(argv = process.argv.slice(2)) {
  try {
    await runControllerBenchmark(argv);
  } catch (error) {
    const message = (error instanceof Error ? error.message : String(error)).slice(0, 1000);
    process.stderr.write(`Controller benchmark error: ${message}\n`);
    process.exitCode = 2;
  }
}
