import {
  copyFile,
  mkdir,
  mkdtemp,
  open,
  rm,
  stat,
} from "node:fs/promises";
import path from "node:path";

import { resolveInside } from "../../../security/paths.js";
import { NdsError } from "../errors.js";
import { hashFileSha256 } from "../io.js";
import type { NdsResolvedMutationPlan } from "./planner.js";

export interface NdsMutationStage {
  readonly buildId: string;
  readonly temporaryRoot: string;
  readonly finalRoot: string;
  readonly stagedRomPath: string;
  readonly finalRomPath: string;
}

function stagingError(message: string): NdsError<"staging-failed"> {
  return new NdsError("staging-failed", message);
}

async function sameExistingFile(leftPath: string, rightPath: string): Promise<boolean> {
  if (path.resolve(leftPath) === path.resolve(rightPath)) {
    return true;
  }
  try {
    const [left, right] = await Promise.all([stat(leftPath), stat(rightPath)]);
    return left.dev === right.dev && left.ino === right.ino;
  } catch {
    return false;
  }
}

async function syncReadOnlyFile(filePath: string): Promise<void> {
  const handle = await open(filePath, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function assertArtifactsDoNotAliasStage(
  plan: NdsResolvedMutationPlan,
  stagedRomPath: string,
): Promise<void> {
  for (const operation of plan.operations) {
    if (
      operation.type === "replace-component"
      && await sameExistingFile(operation.replacement.absolutePath, stagedRomPath)
    ) {
      throw new NdsError(
        "unsupported-mutation-target",
        "Replacement artifact may not alias the staged ROM",
      );
    }
  }
}

export async function cleanupNdsMutationStage(stage: NdsMutationStage): Promise<void> {
  try {
    await rm(stage.temporaryRoot, { recursive: true, force: true });
  } catch {
    // Best-effort cleanup only.
  }
}

export async function createNdsMutationStage(
  plan: NdsResolvedMutationPlan,
  workspaceRoot: string,
): Promise<NdsMutationStage> {
  const finalParent = resolveInside(
    workspaceRoot,
    path.join("output", "nds", plan.sourceSha256Prefix),
  );
  const finalRoot = resolveInside(finalParent, plan.buildId);
  const finalRomPath = resolveInside(finalRoot, plan.outputFilename);
  let temporaryRoot: string | null = null;

  try {
    await mkdir(finalParent, { recursive: true });
    temporaryRoot = await mkdtemp(path.join(finalParent, `.${plan.buildId}.tmp-`));
    const stagedRomPath = resolveInside(temporaryRoot, plan.outputFilename);
    if (path.resolve(stagedRomPath) === path.resolve(plan.sourceRomPath)) {
      throw stagingError("Staged ROM path must differ from the immutable source ROM");
    }

    await copyFile(plan.sourceRomPath, stagedRomPath);
    await syncReadOnlyFile(stagedRomPath);
    const stagedSha256 = await hashFileSha256(stagedRomPath);
    if (stagedSha256 !== plan.sourceSha256) {
      throw stagingError(
        `Staged source copy SHA-256 is ${stagedSha256}, expected ${plan.sourceSha256}`,
      );
    }

    await assertArtifactsDoNotAliasStage(plan, stagedRomPath);
    return {
      buildId: plan.buildId,
      temporaryRoot,
      finalRoot,
      stagedRomPath,
      finalRomPath,
    };
  } catch (error) {
    if (temporaryRoot !== null) {
      try {
        await rm(temporaryRoot, { recursive: true, force: true });
      } catch {
        // Best-effort cleanup only.
      }
    }
    if (error instanceof NdsError) {
      throw error;
    }
    throw stagingError(
      `Unable to create controlled NDS mutation stage: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
