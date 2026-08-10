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
import {
  isNdsResolvedMutationPlanV2,
  resolvedNdsMutationArtifactPaths,
  type NdsResolvedMutationPlan,
} from "./planner.js";

export interface NdsMutationOutputPaths {
  readonly finalParent: string;
  readonly finalRoot: string;
  readonly finalRomPath: string;
}

export interface NdsMutationStage extends NdsMutationOutputPaths {
  readonly buildId: string;
  readonly temporaryRoot: string;
  readonly stagedRomPath: string;
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
  workspaceRoot: string,
  stagedRomPath: string,
  finalRomPath: string,
): Promise<void> {
  const manifestPath = resolveInside(workspaceRoot, plan.manifestWorkspacePath);
  const aliasCategory = isNdsResolvedMutationPlanV2(plan)
    ? "unsupported-rebuild-target" as const
    : "unsupported-mutation-target" as const;
  const protectedPaths = [
    { path: plan.sourceRomPath, label: "immutable source ROM" },
    { path: manifestPath, label: "mutation manifest" },
    { path: stagedRomPath, label: "staged ROM" },
    { path: finalRomPath, label: "deterministic final output ROM" },
  ] as const;

  for (const artifactPath of resolvedNdsMutationArtifactPaths(plan)) {
    for (const protectedPath of protectedPaths) {
      if (await sameExistingFile(artifactPath, protectedPath.path)) {
        throw new NdsError(
          aliasCategory,
          `Replacement artifact may not alias the ${protectedPath.label}`,
        );
      }
    }
  }
}

export function resolveNdsMutationOutputPaths(
  plan: NdsResolvedMutationPlan,
  workspaceRoot: string,
): NdsMutationOutputPaths {
  const finalParent = resolveInside(
    workspaceRoot,
    path.join("output", "nds", plan.sourceSha256Prefix),
  );
  const finalRoot = resolveInside(finalParent, plan.buildId);
  const finalRomPath = resolveInside(finalRoot, plan.outputFilename);
  return { finalParent, finalRoot, finalRomPath };
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
  const outputPaths = resolveNdsMutationOutputPaths(plan, workspaceRoot);
  let temporaryRoot: string | null = null;

  try {
    await mkdir(outputPaths.finalParent, { recursive: true });
    temporaryRoot = await mkdtemp(path.join(outputPaths.finalParent, `.${plan.buildId}.tmp-`));
    const stagedRomPath = resolveInside(temporaryRoot, plan.outputFilename);
    if (path.resolve(stagedRomPath) === path.resolve(plan.sourceRomPath)) {
      throw stagingError("Staged ROM path must differ from the immutable source ROM");
    }

    await assertArtifactsDoNotAliasStage(
      plan,
      workspaceRoot,
      stagedRomPath,
      outputPaths.finalRomPath,
    );
    await copyFile(plan.sourceRomPath, stagedRomPath);
    await syncReadOnlyFile(stagedRomPath);
    const stagedSha256 = await hashFileSha256(stagedRomPath);
    if (stagedSha256 !== plan.sourceSha256) {
      throw stagingError(
        `Staged source copy SHA-256 is ${stagedSha256}, expected ${plan.sourceSha256}`,
      );
    }

    await assertArtifactsDoNotAliasStage(
      plan,
      workspaceRoot,
      stagedRomPath,
      outputPaths.finalRomPath,
    );
    return {
      buildId: plan.buildId,
      temporaryRoot,
      stagedRomPath,
      ...outputPaths,
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
