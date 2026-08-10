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

const requiredFiles = [
  "benchmarks/controller/scenarios.json",
  "scripts/controller-benchmark.mjs",
  "docs/controller-benchmark.md",
  "dist/services/nds/rom-map.js",
  "dist/services/nds/extraction.js",
  "dist/services/controller-checkpoint.js",
  "dist/services/nds/mutation/manifest.js",
  "dist/services/nds/mutation/build.js",
];

for (const relativePath of requiredFiles) {
  const info = await stat(path.join(root, relativePath));
  if (!info.isFile()) {
    throw new Error(`${relativePath} is not a regular packaged file`);
  }
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

async function runBenchmark(args, expectedExit = 0) {
  try {
    const result = await execFile(process.execPath, [benchmarkScript, ...args], {
      cwd: root,
      maxBuffer: 2 * 1024 * 1024,
      encoding: "utf8",
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

const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), "re-mcp-controller-benchmark-"));

try {
  async function preparedWorkspace(scenarioId) {
    const workspace = path.join(temporaryRoot, scenarioId);
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

  // analysis-handoff: create the real canonical bundle, bind its manifest into revision 1,
  // then require the packaged scorer to accept the completed deterministic state.
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
        confirmedFacts: [
          {
            id: "analysis-manifest-created",
            statement: "The benchmark analysis manifest was generated through RE-MCP.",
            evidenceRefs: [{ path: manifestRelative }],
          },
        ],
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

  // checkpoint-resume: preparation seeds revision 1. Generate a controlled ARM9 artifact,
  // advance to revision 2, and prove the evidence hash survives checkpoint validation.
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
        completedActions: [
          {
            id: "resume-arm9-extracted",
            description: "Fresh ARM9 evidence was extracted through RE-MCP after resume.",
            outcome: "completed",
            evidenceRefs: [{ path: artifactRelative }],
          },
        ],
        nextActions: [],
      },
    );
    const score = parseJsonOutput(
      (await runBenchmark(["score", "checkpoint-resume", workspace, "package-smoke"])).stdout,
      "checkpoint-resume score",
    );
    if (score.passed !== true) throw new Error("checkpoint-resume benchmark did not pass");
  }

  // verified-mutation: build with the real transactional engine, bind verification.json,
  // then score through fresh published-build verification.
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
        completedActions: [
          {
            id: "mutation-built-verified",
            description: "The guarded benchmark mutation was built and verified through RE-MCP.",
            outcome: "completed",
            evidenceRefs: [{ path: verificationRelative }],
          },
        ],
        nextActions: [],
      },
    );
    const score = parseJsonOutput(
      (await runBenchmark(["score", "verified-mutation", workspace, "package-smoke"])).stdout,
      "verified-mutation score",
    );
    if (score.passed !== true) throw new Error("verified-mutation benchmark did not pass");
  }

  // guard-rejection: publish no output, record the failed guarded action, and require the
  // scorer itself to confirm canonical rejection plus the absence of a controlled build.
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
        completedActions: [
          {
            id: "invalid-guard-rejected",
            description: "The guarded mutation was rejected and no build was published.",
            outcome: "failed",
            evidenceRefs: [],
          },
        ],
        nextActions: [
          {
            id: "refresh-original-guard",
            description: "Revalidate the exact original bytes before authoring a replacement manifest.",
          },
        ],
      },
    );
    const score = parseJsonOutput(
      (await runBenchmark(["score", "guard-rejection", workspace, "package-smoke"])).stdout,
      "guard-rejection score",
    );
    if (score.passed !== true) throw new Error("guard-rejection benchmark did not pass");
  }

  // A freshly prepared but untouched scenario must fail deterministic scoring.
  {
    const workspace = path.join(temporaryRoot, "incomplete-analysis-handoff");
    await runBenchmark(["prepare", "analysis-handoff", workspace]);
    const failed = parseJsonOutput(
      (await runBenchmark(["score", "analysis-handoff", workspace], 1)).stdout,
      "incomplete analysis-handoff score",
    );
    if (failed.passed !== false) {
      throw new Error("incomplete analysis-handoff unexpectedly passed");
    }
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
