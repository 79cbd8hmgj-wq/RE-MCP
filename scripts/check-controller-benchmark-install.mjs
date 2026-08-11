#!/usr/bin/env node

import { createHash } from "node:crypto";
import { execFile as execFileCallback } from "node:child_process";
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";

const execFile = promisify(execFileCallback);
const root = path.resolve(process.argv[2] ?? ".");
const benchmarkScript = path.join(root, "scripts", "controller-benchmark.mjs");
const TARGET_HELPER_ADDRESS = 0x02000080;
const TARGET_CORRECT_CALLER_ID = "identity-restriction-02000040";
const TARGET_WRONG_CALLER_ID = "identity-restriction-02000020";

const requiredFiles = [
  "benchmarks/controller/scenarios.json",
  "scripts/controller-benchmark.mjs",
  "scripts/controller-benchmark-core.mjs",
  "scripts/tool-schema-measurement.mjs",
  "docs/controller-benchmark.md",
  "docs/controller-efficiency-acceptance.md",
  "dist/services/nds/rom-map.js",
  "dist/services/nds/extraction.js",
  "dist/services/controller-checkpoint.js",
  "dist/services/nds/mutation/manifest.js",
  "dist/services/nds/mutation/build.js",
  "dist/services/disassembly/capstone.js",
  "dist/services/re-orchestration/trace-function.js",
  "dist/services/re-orchestration/investigation-journal.js",
  "dist/services/re-orchestration/resume-artifact.js",
];

for (const relativePath of requiredFiles) {
  const info = await stat(path.join(root, relativePath));
  if (!info.isFile()) throw new Error(`${relativePath} is not a regular packaged file`);
}

function moduleUrl(relativePath) {
  return pathToFileURL(path.join(root, relativePath)).href;
}

function relativeToWorkspace(workspaceRoot, absolutePath) {
  return path
    .relative(path.resolve(workspaceRoot), path.resolve(absolutePath))
    .split(path.sep)
    .join("/");
}

async function runBenchmark(args, expectedExit = 0, environment = {}) {
  try {
    const result = await execFile(process.execPath, [benchmarkScript, ...args], {
      cwd: root,
      maxBuffer: 4 * 1024 * 1024,
      encoding: "utf8",
      env: { ...process.env, ...environment },
    });
    if (expectedExit !== 0) {
      throw new Error(`benchmark unexpectedly succeeded for ${args.join(" ")}`);
    }
    return { stdout: result.stdout, stderr: result.stderr, exitCode: 0 };
  } catch (error) {
    if (
      error !== null
      && typeof error === "object"
      && "code" in error
      && typeof error.code === "number"
      && error.code === expectedExit
    ) {
      return {
        stdout: typeof error.stdout === "string" ? error.stdout : "",
        stderr: typeof error.stderr === "string" ? error.stderr : "",
        exitCode: error.code,
      };
    }
    throw error;
  }
}

function parseJsonOutput(stdout, label) {
  const parsed = JSON.parse(stdout);
  if (parsed === null || typeof parsed !== "object") {
    throw new Error(`${label} did not return a JSON object`);
  }
  return parsed;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

const { readNdsRomMap } = await import(moduleUrl("dist/services/nds/rom-map.js"));
const {
  extractNdsAnalysisBundle,
  extractNdsComponent,
} = await import(moduleUrl("dist/services/nds/extraction.js"));
const { writeControllerCheckpoint } = await import(
  moduleUrl("dist/services/controller-checkpoint.js")
);
const { loadNdsMutationManifest } = await import(
  moduleUrl("dist/services/nds/mutation/manifest.js")
);
const { buildNdsMutation } = await import(
  moduleUrl("dist/services/nds/mutation/build.js")
);
const { createCapstoneArmBackend } = await import(
  moduleUrl("dist/services/disassembly/capstone.js")
);
const { traceNdsFunction } = await import(
  moduleUrl("dist/services/re-orchestration/trace-function.js")
);
const { persistInvestigationResult } = await import(
  moduleUrl("dist/services/re-orchestration/investigation-journal.js")
);
const { persistInvestigationResumeArtifact } = await import(
  moduleUrl("dist/services/re-orchestration/resume-artifact.js")
);

const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), "re-mcp-controller-benchmark-"));

try {
  async function preparedWorkspace(scenarioId) {
    const workspace = path.join(temporaryRoot, `${scenarioId}-${Date.now()}-${Math.random().toString(16).slice(2)}`);
    const prepared = parseJsonOutput(
      (await runBenchmark(["prepare", scenarioId, workspace])).stdout,
      `${scenarioId} prepare`,
    );
    if (prepared.scenarioId !== scenarioId || typeof prepared.sourceRomSha256 !== "string") {
      throw new Error(`${scenarioId} prepare returned unexpected identity`);
    }
    const romPath = path.join(workspace, "roms", "controller-benchmark.nds");
    const map = await readNdsRomMap(romPath);
    if (map.sha256 !== prepared.sourceRomSha256) {
      throw new Error(`${scenarioId} prepared ROM SHA does not match canonical parse`);
    }
    return { workspace, romPath, map, prepared };
  }

  async function persistTargetedTrace(workspace, map) {
    const backend = await createCapstoneArmBackend();
    try {
      const result = await traceNdsFunction(
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
      const source = { sha256: map.sha256, sha256Prefix: map.sha256Prefix };
      const artifact = await persistInvestigationResumeArtifact(source, workspace, result);
      await persistInvestigationResult(source, workspace, {
        operation: result.operation,
        normalizedInputs: {
          rom: "roms/controller-benchmark.nds",
          processor: "arm9",
          runtimeAddress: TARGET_HELPER_ADDRESS,
          mode: "arm",
          includeMain: true,
          overlayIds: [],
          seeds: [],
        },
        completedStages: result.completedPrimitiveStages,
        artifacts: [artifact],
        result: { ...result, artifacts: [artifact] },
        recommendedNextAction: result.recommendedNextAction,
      });
      return result;
    } finally {
      backend.close();
    }
  }

  async function writeTargetSelection(workspace, map, actionId) {
    await writeControllerCheckpoint(
      { sha256: map.sha256, sha256Prefix: map.sha256Prefix },
      workspace,
      0,
      {
        objective: "Select the identity-dependent helper caller from deterministic trace evidence.",
        confirmedFacts: [],
        hypotheses: [],
        completedActions: [{
          id: actionId,
          description: "Selected one direct caller from the deterministic targeted-function trace.",
          outcome: "completed",
          evidenceRefs: [],
        }],
        nextActions: [],
      },
    );
  }

  // analysis-handoff
  {
    const { workspace, map } = await preparedWorkspace("analysis-handoff");
    const bundle = await extractNdsAnalysisBundle(map, workspace);
    const manifestRelative = relativeToWorkspace(workspace, bundle.manifestPath);
    await writeControllerCheckpoint(
      { sha256: map.sha256, sha256Prefix: map.sha256Prefix },
      workspace,
      0,
      {
        objective: "Complete deterministic analysis handoff acceptance.",
        confirmedFacts: [{
          id: "analysis-manifest-created",
          statement: "The benchmark analysis manifest was generated through RE-MCP.",
          evidenceRefs: [{ path: manifestRelative }],
        }],
        hypotheses: [],
        completedActions: [],
        nextActions: [],
      },
    );
    const score = parseJsonOutput(
      (await runBenchmark(["score", "analysis-handoff", workspace, "package-smoke"])).stdout,
      "analysis-handoff score",
    );
    if (score.passed !== true) throw new Error("analysis-handoff benchmark did not pass");
  }

  // checkpoint-resume
  {
    const { workspace, map } = await preparedWorkspace("checkpoint-resume");
    const artifact = await extractNdsComponent(map, workspace, { component: "arm9" });
    const artifactRelative = relativeToWorkspace(workspace, artifact.output);
    await writeControllerCheckpoint(
      { sha256: map.sha256, sha256Prefix: map.sha256Prefix },
      workspace,
      1,
      {
        objective: "Resume deterministic benchmark work from the existing checkpoint.",
        confirmedFacts: [],
        hypotheses: [],
        completedActions: [{
          id: "resume-arm9-extracted",
          description: "Fresh ARM9 evidence was extracted through RE-MCP after resume.",
          outcome: "completed",
          evidenceRefs: [{ path: artifactRelative }],
        }],
        nextActions: [],
      },
    );
    const score = parseJsonOutput(
      (await runBenchmark(["score", "checkpoint-resume", workspace, "package-smoke"])).stdout,
      "checkpoint-resume score",
    );
    if (score.passed !== true) throw new Error("checkpoint-resume benchmark did not pass");
  }

  // verified-mutation
  {
    const { workspace, map } = await preparedWorkspace("verified-mutation");
    const loaded = await loadNdsMutationManifest(workspace, "plans/valid-mutation.json");
    const built = await buildNdsMutation(map, workspace, loaded);
    const verificationPath = path.join(built.outputRoot, "verification.json");
    const verificationRelative = relativeToWorkspace(workspace, verificationPath);
    await writeControllerCheckpoint(
      { sha256: map.sha256, sha256Prefix: map.sha256Prefix },
      workspace,
      0,
      {
        objective: "Complete deterministic verified mutation acceptance.",
        confirmedFacts: [],
        hypotheses: [],
        completedActions: [{
          id: "mutation-built-verified",
          description: "The guarded benchmark mutation was built and verified through RE-MCP.",
          outcome: "completed",
          evidenceRefs: [{ path: verificationRelative }],
        }],
        nextActions: [],
      },
    );
    const score = parseJsonOutput(
      (await runBenchmark(["score", "verified-mutation", workspace, "package-smoke"])).stdout,
      "verified-mutation score",
    );
    if (score.passed !== true) throw new Error("verified-mutation benchmark did not pass");
  }

  // guard-rejection
  {
    const { workspace, map } = await preparedWorkspace("guard-rejection");
    await writeControllerCheckpoint(
      { sha256: map.sha256, sha256Prefix: map.sha256Prefix },
      workspace,
      0,
      {
        objective: "Record the expected fail-closed invalid guard without bypassing it.",
        confirmedFacts: [],
        hypotheses: [],
        completedActions: [{
          id: "invalid-guard-rejected",
          description: "The guarded mutation was rejected and no build was published.",
          outcome: "failed",
          evidenceRefs: [],
        }],
        nextActions: [{
          id: "refresh-original-guard",
          description: "Revalidate the exact original bytes before authoring a replacement manifest.",
        }],
      },
    );
    const score = parseJsonOutput(
      (await runBenchmark(["score", "guard-rejection", workspace, "package-smoke"])).stdout,
      "guard-rejection score",
    );
    if (score.passed !== true) throw new Error("guard-rejection benchmark did not pass");
  }

  // targeted-function-investigation: run the real high-level trace service, persist the same
  // compact deterministic resume artifact/journal state used by MCP, then select the correct
  // identity-dependent caller in structured checkpoint state.
  {
    const { workspace, map, prepared } = await preparedWorkspace("targeted-function-investigation");
    if (prepared.requiredToolProfile !== "re-static-core" || prepared.helperAddress !== "0x02000080") {
      throw new Error("targeted-function prepare did not emit the required profile/helper identity");
    }
    const trace = await persistTargetedTrace(workspace, map);
    const addresses = trace.candidates.map((candidate) => candidate.instructionAddress).sort((a, b) => a - b);
    if (JSON.stringify(addresses) !== JSON.stringify([0x02000020, 0x02000040, 0x02000060])) {
      throw new Error(`targeted trace returned unexpected direct callers: ${JSON.stringify(addresses)}`);
    }
    await writeTargetSelection(workspace, map, TARGET_CORRECT_CALLER_ID);
    const score = parseJsonOutput(
      (await runBenchmark(
        ["score", "targeted-function-investigation", workspace, "package-smoke-limited"],
        0,
        { RE_MCP_TOOL_PROFILE: "re-static-core" },
      )).stdout,
      "targeted-function-investigation score",
    );
    if (score.passed !== true) throw new Error("targeted-function-investigation benchmark did not pass");
    if (
      score.activeToolProfile !== "re-static-core"
      || !(score.advertisedToolCount > 0)
      || !(score.toolSchemaBytes > 0)
      || !(score.toolSchemaEstimatedTokens > 0)
    ) {
      throw new Error("targeted-function score omitted real profile/schema metrics");
    }
  }

  // wrong-caller selection must fail even when the real deterministic trace/journal exists.
  {
    const { workspace, map } = await preparedWorkspace("targeted-function-investigation");
    await persistTargetedTrace(workspace, map);
    await writeTargetSelection(workspace, map, TARGET_WRONG_CALLER_ID);
    const failed = parseJsonOutput(
      (await runBenchmark(
        ["score", "targeted-function-investigation", workspace, "package-smoke-wrong-caller"],
        1,
        { RE_MCP_TOOL_PROFILE: "re-static-core" },
      )).stdout,
      "targeted-function wrong-caller score",
    );
    if (failed.passed !== false) throw new Error("wrong-caller targeted benchmark unexpectedly passed");
    const selectionCheck = failed.checks.find((entry) => entry.id === "identity-dependent-caller-selected");
    if (selectionCheck?.passed !== false) {
      throw new Error("wrong-caller benchmark did not fail the deterministic selection check");
    }
  }

  // A freshly prepared but untouched scenario must fail deterministic scoring.
  {
    const workspace = path.join(temporaryRoot, "incomplete-analysis-handoff");
    await runBenchmark(["prepare", "analysis-handoff", workspace]);
    const failed = parseJsonOutput(
      (await runBenchmark(["score", "analysis-handoff", workspace], 1)).stdout,
      "incomplete analysis-handoff score",
    );
    if (failed.passed !== false) throw new Error("incomplete analysis-handoff unexpectedly passed");
  }

  // Prepare must reject a non-empty target without changing its existing sentinel.
  {
    const workspace = path.join(temporaryRoot, "non-empty-target");
    await mkdir(workspace);
    const sentinelPath = path.join(workspace, "sentinel.txt");
    const sentinelBytes = Buffer.from("do-not-touch", "utf8");
    await writeFile(sentinelPath, sentinelBytes, { flag: "wx" });
    await runBenchmark(["prepare", "analysis-handoff", workspace], 2);
    const after = await readFile(sentinelPath);
    if (sha256(after) !== sha256(sentinelBytes)) {
      throw new Error("non-empty prepare rejection modified existing contents");
    }
    const info = await lstat(sentinelPath);
    if (!info.isFile() || info.isSymbolicLink()) {
      throw new Error("non-empty prepare rejection changed sentinel type");
    }
  }

  console.log("Controller benchmark package smoke passed");
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
