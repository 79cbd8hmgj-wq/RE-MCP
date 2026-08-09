import {
  lstat,
  open,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import path from "node:path";

import { NdsError } from "../errors.js";
import { hashFileSha256 } from "../io.js";
import type { NdsRomMap } from "../rom-map.js";
import { applyNdsMutationPlan } from "./apply.js";
import { assertNdsMutationSourceIdentity } from "./guards.js";
import type { LoadedNdsMutationManifest } from "./manifest.js";
import { compileNdsMutationPlan, type NdsResolvedMutationPlan } from "./planner.js";
import {
  NDS_MUTATION_EVIDENCE_FILENAMES,
  renderNdsMutationEvidence,
} from "./report.js";
import {
  cleanupNdsMutationStage,
  createNdsMutationStage,
  resolveNdsMutationOutputPaths,
  type NdsMutationStage,
} from "./staging.js";
import {
  verifyNdsMutationOutput,
  type NdsMutationVerificationResult,
} from "./verify.js";

export interface NdsMutationBuildResult {
  readonly buildId: string;
  readonly reused: boolean;
  readonly outputRoot: string;
  readonly outputRomPath: string;
  readonly outputSha256: string;
  readonly verification: NdsMutationVerificationResult;
}

export interface NdsMutationBuildHooks {
  readonly beforePublish?: (stage: NdsMutationStage) => Promise<void>;
}

async function pathExists(target: string): Promise<boolean> {
  try {
    await lstat(target);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

async function syncFileReadOnly(filePath: string): Promise<void> {
  const handle = await open(filePath, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function writeEvidence(
  stage: NdsMutationStage,
  loadedManifest: LoadedNdsMutationManifest,
  plan: NdsResolvedMutationPlan,
  verification: NdsMutationVerificationResult,
): Promise<void> {
  for (const evidence of renderNdsMutationEvidence(loadedManifest, plan, verification)) {
    const outputPath = path.join(stage.temporaryRoot, evidence.filename);
    await writeFile(outputPath, evidence.bytes, { flag: "wx" });
    await syncFileReadOnly(outputPath);
  }
}

function publishError(operation: string, error: unknown): NdsError<"publish-failed"> {
  return new NdsError(
    "publish-failed",
    `${operation} failed: ${error instanceof Error ? error.message : String(error)}`,
  );
}

function publishCollision(message: string, error?: unknown): NdsError<"publish-collision"> {
  const suffix = error === undefined
    ? ""
    : `: ${error instanceof Error ? error.message : String(error)}`;
  return new NdsError("publish-collision", `${message}${suffix}`);
}

async function requireExactPublishedEntries(
  finalRoot: string,
  outputFilename: string,
): Promise<void> {
  const rootInfo = await lstat(finalRoot);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) {
    throw new Error("deterministic build root is not a regular directory");
  }
  const expected = [outputFilename, ...NDS_MUTATION_EVIDENCE_FILENAMES].sort();
  const actual = (await readdir(finalRoot)).sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(
      `published build entries differ; expected ${expected.join(", ")}, found ${actual.join(", ")}`,
    );
  }
  for (const filename of expected) {
    const info = await lstat(path.join(finalRoot, filename));
    if (!info.isFile() || info.isSymbolicLink()) {
      throw new Error(`published entry ${filename} is not a regular non-symlink file`);
    }
  }
}

async function comparePublishedEvidence(
  finalRoot: string,
  loadedManifest: LoadedNdsMutationManifest,
  plan: NdsResolvedMutationPlan,
  verification: NdsMutationVerificationResult,
): Promise<void> {
  const expectedFiles = renderNdsMutationEvidence(loadedManifest, plan, verification);
  for (const expected of expectedFiles) {
    const actual = await readFile(path.join(finalRoot, expected.filename));
    if (!actual.equals(expected.bytes)) {
      throw new Error(`published evidence ${expected.filename} does not match fresh deterministic evidence`);
    }
  }
}

async function assertVerifiedOutputStillCurrent(
  map: NdsRomMap,
  plan: NdsResolvedMutationPlan,
  outputRomPath: string,
  expectedOutputSha256: string,
): Promise<void> {
  await assertNdsMutationSourceIdentity(map, plan.sourceSha256);
  const currentOutputSha256 = await hashFileSha256(outputRomPath);
  if (currentOutputSha256 !== expectedOutputSha256) {
    throw new NdsError(
      "output-verification-failed",
      `Verified output changed before publication; expected SHA-256 ${expectedOutputSha256}, found ${currentOutputSha256}`,
    );
  }
}

export async function verifyPublishedNdsMutationBuild(
  map: NdsRomMap,
  workspaceRoot: string,
  loadedManifest: LoadedNdsMutationManifest,
): Promise<NdsMutationBuildResult> {
  const plan = await compileNdsMutationPlan(map, workspaceRoot, loadedManifest);
  const outputPaths = resolveNdsMutationOutputPaths(plan, workspaceRoot);
  try {
    await requireExactPublishedEntries(outputPaths.finalRoot, plan.outputFilename);
    const verification = await verifyNdsMutationOutput(
      map,
      plan,
      outputPaths.finalRomPath,
    );
    await comparePublishedEvidence(
      outputPaths.finalRoot,
      loadedManifest,
      plan,
      verification,
    );
    await assertVerifiedOutputStillCurrent(
      map,
      plan,
      outputPaths.finalRomPath,
      verification.outputSha256,
    );
    return {
      buildId: plan.buildId,
      reused: true,
      outputRoot: outputPaths.finalRoot,
      outputRomPath: outputPaths.finalRomPath,
      outputSha256: verification.outputSha256,
      verification,
    };
  } catch (error) {
    if (error instanceof NdsError && error.category === "publish-collision") {
      throw error;
    }
    throw publishCollision(
      `Existing deterministic build ${plan.buildId} could not be freshly revalidated`,
      error,
    );
  }
}

export async function buildNdsMutation(
  map: NdsRomMap,
  workspaceRoot: string,
  loadedManifest: LoadedNdsMutationManifest,
  hooks: NdsMutationBuildHooks = {},
): Promise<NdsMutationBuildResult> {
  const plan = await compileNdsMutationPlan(map, workspaceRoot, loadedManifest);
  const outputPaths = resolveNdsMutationOutputPaths(plan, workspaceRoot);
  if (await pathExists(outputPaths.finalRoot)) {
    return await verifyPublishedNdsMutationBuild(map, workspaceRoot, loadedManifest);
  }

  const stage = await createNdsMutationStage(plan, workspaceRoot);
  let published = false;
  try {
    await applyNdsMutationPlan(plan, stage);
    const verification = await verifyNdsMutationOutput(map, plan, stage.stagedRomPath);
    await writeEvidence(stage, loadedManifest, plan, verification);
    await hooks.beforePublish?.(stage);
    await assertVerifiedOutputStillCurrent(
      map,
      plan,
      stage.stagedRomPath,
      verification.outputSha256,
    );

    try {
      await rename(stage.temporaryRoot, stage.finalRoot);
      published = true;
    } catch (error) {
      if (await pathExists(stage.finalRoot)) {
        throw publishCollision(
          `Deterministic build directory ${plan.buildId} appeared during publication`,
          error,
        );
      }
      throw publishError("Atomic NDS mutation build promotion", error);
    }

    return {
      buildId: plan.buildId,
      reused: false,
      outputRoot: stage.finalRoot,
      outputRomPath: stage.finalRomPath,
      outputSha256: verification.outputSha256,
      verification,
    };
  } catch (error) {
    if (error instanceof NdsError) {
      throw error;
    }
    throw publishError("NDS mutation build", error);
  } finally {
    if (!published) {
      await cleanupNdsMutationStage(stage);
    } else {
      try {
        await rm(stage.temporaryRoot, { recursive: true, force: true });
      } catch {
        // The atomic rename already moved the stage; best-effort only.
      }
    }
  }
}
