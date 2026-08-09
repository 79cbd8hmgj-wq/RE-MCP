import { createHash } from "node:crypto";
import path from "node:path";

import { NdsError } from "../errors.js";
import type { NdsRomMap } from "../rom-map.js";
import { assertNoNdsMutationConflicts } from "./conflicts.js";
import {
  assertNdsMutationSourceIdentity,
  guardNdsMutationOperation,
  type GuardedNdsMutationOperation,
} from "./guards.js";
import type { LoadedNdsMutationManifest } from "./manifest.js";
import {
  ndsImmutableStructuralRanges,
  type NdsMutationPhysicalRange,
} from "./selectors.js";

export interface NdsResolvedMutationPlan {
  readonly sourceRomPath: string;
  readonly sourceWorkspacePath: string;
  readonly sourceSha256: string;
  readonly sourceSha256Prefix: string;
  readonly sourceSize: number;
  readonly manifestWorkspacePath: string;
  readonly manifestSha256: string;
  readonly outputFilename: string;
  readonly buildId: string;
  readonly operations: readonly GuardedNdsMutationOperation[];
  readonly applicationOperations: readonly GuardedNdsMutationOperation[];
  readonly immutableStructuralRanges: readonly NdsMutationPhysicalRange[];
}

function workspaceRelativePath(
  workspaceRoot: string,
  absolutePath: string,
): string {
  const resolvedRoot = path.resolve(workspaceRoot);
  const relative = path.relative(resolvedRoot, path.resolve(absolutePath));
  if (
    relative.length === 0
    || relative.startsWith("..")
    || path.isAbsolute(relative)
  ) {
    throw new NdsError(
      "source-rom-mismatch",
      "Source ROM must be a file beneath the configured workspace root",
    );
  }
  return relative.split(path.sep).join("/");
}

function sha256Text(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function buildIdentity(
  sourceSha256: string,
  manifestSha256: string,
  operations: readonly GuardedNdsMutationOperation[],
): string {
  const artifactShas = operations
    .filter((operation) => operation.type === "replace-component")
    .map((operation) => operation.replacement.sha256);
  return sha256Text([
    "re-mcp-nds-mutation-build-v1",
    sourceSha256,
    manifestSha256,
    ...artifactShas,
  ].join("\0"));
}

function serializeComponent(operation: GuardedNdsMutationOperation) {
  return {
    component: operation.component.component,
    processor: operation.component.processor,
    overlayId: operation.component.overlayId,
    fileId: operation.component.fileId,
    filePath: operation.component.filePath,
    romStart: operation.component.romStart,
    romEnd: operation.component.romEnd,
    size: operation.component.size,
    compressed: operation.component.compressed,
    overlayOwners: operation.component.overlayOwners,
  };
}

function serializeOperation(operation: GuardedNdsMutationOperation) {
  if (operation.type === "replace-bytes") {
    return {
      index: operation.index,
      type: operation.type,
      target: operation.target,
      component: serializeComponent(operation),
      romStart: operation.romStart,
      romEnd: operation.romEnd,
      size: operation.size,
      expected: operation.expected,
      replacement: operation.replacement,
    };
  }
  return {
    index: operation.index,
    type: operation.type,
    target: operation.target,
    component: serializeComponent(operation),
    romStart: operation.romStart,
    romEnd: operation.romEnd,
    size: operation.size,
    expectedOriginalSha256: operation.expectedOriginalSha256,
    originalSha256: operation.originalSha256,
    replacement: {
      artifact: operation.replacement.workspacePath,
      sha256: operation.replacement.sha256,
      size: operation.replacement.size,
    },
  };
}

export function serializeResolvedNdsMutationPlan(
  plan: NdsResolvedMutationPlan,
): unknown {
  return {
    source: {
      rom: plan.sourceWorkspacePath,
      sha256: plan.sourceSha256,
      sha256Prefix: plan.sourceSha256Prefix,
      size: plan.sourceSize,
    },
    manifest: {
      path: plan.manifestWorkspacePath,
      sha256: plan.manifestSha256,
    },
    output: {
      filename: plan.outputFilename,
      buildId: plan.buildId,
    },
    immutableStructuralRanges: plan.immutableStructuralRanges,
    operations: plan.operations.map((operation) => serializeOperation(operation)),
    applicationOrder: plan.applicationOperations.map((operation) => operation.index),
  };
}

export async function compileNdsMutationPlan(
  map: NdsRomMap,
  workspaceRoot: string,
  loadedManifest: LoadedNdsMutationManifest,
): Promise<NdsResolvedMutationPlan> {
  const expectedSourceSha256 = loadedManifest.manifest.source.sha256;
  if (map.sha256 !== expectedSourceSha256) {
    throw new NdsError(
      "source-rom-mismatch",
      `Mutation manifest requires source SHA-256 ${expectedSourceSha256}, but the canonical ROM map is ${map.sha256}`,
    );
  }

  await assertNdsMutationSourceIdentity(map, expectedSourceSha256);

  const operations: GuardedNdsMutationOperation[] = [];
  for (let index = 0; index < loadedManifest.manifest.operations.length; index += 1) {
    const operation = loadedManifest.manifest.operations[index];
    if (operation === undefined) {
      throw new NdsError(
        "mutation-manifest-invalid",
        `Normalized mutation operation ${index} is missing`,
      );
    }
    operations.push(await guardNdsMutationOperation(
      map,
      workspaceRoot,
      index,
      operation,
    ));
  }

  assertNoNdsMutationConflicts(operations);
  const immutableStructuralRanges = ndsImmutableStructuralRanges(map);
  await assertNdsMutationSourceIdentity(map, expectedSourceSha256);

  const applicationOperations = [...operations].sort(
    (left, right) => left.romStart - right.romStart
      || left.romEnd - right.romEnd
      || left.index - right.index,
  );
  const buildId = buildIdentity(
    expectedSourceSha256,
    loadedManifest.sha256,
    operations,
  );

  return {
    sourceRomPath: map.romPath,
    sourceWorkspacePath: workspaceRelativePath(workspaceRoot, map.romPath),
    sourceSha256: expectedSourceSha256,
    sourceSha256Prefix: map.sha256Prefix,
    sourceSize: map.fileSize,
    manifestWorkspacePath: loadedManifest.workspaceRelativePath,
    manifestSha256: loadedManifest.sha256,
    outputFilename: loadedManifest.manifest.output.filename,
    buildId,
    operations,
    applicationOperations,
    immutableStructuralRanges,
  };
}
