import {
  lstat,
  open,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import path from "node:path";

import { NdsError } from "../errors.js";
import type { NdsRomMap } from "../rom-map.js";
import { applyNdsMutationPlan } from "./apply.js";
import type { LoadedNdsMutationManifest } from "./manifest.js";
import { compileNdsMutationPlan } from "./planner.js";
import { renderNdsMutationEvidence } from "./report.js";
import {
  cleanupNdsMutationStage,
  createNdsMutationStage,
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
  plan: Awaited<ReturnType<typeof compileNdsMutationPlan>>,
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

export async function buildNdsMutation(
  map: NdsRomMap,
  workspaceRoot: string,
  loadedManifest: LoadedNdsMutationManifest,
): Promise<NdsMutationBuildResult> {
  const plan = await compileNdsMutationPlan(map, workspaceRoot, loadedManifest);
  const stage = await createNdsMutationStage(plan, workspaceRoot);
  let published = false;
  try {
    if (await pathExists(stage.finalRoot)) {
      throw publishError(
        "NDS mutation publication",
        new Error("deterministic final build directory already exists"),
      );
    }

    await applyNdsMutationPlan(plan, stage);
    const verification = await verifyNdsMutationOutput(map, plan, stage.stagedRomPath);
    await writeEvidence(stage, loadedManifest, plan, verification);

    try {
      await rename(stage.temporaryRoot, stage.finalRoot);
      published = true;
    } catch (error) {
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
