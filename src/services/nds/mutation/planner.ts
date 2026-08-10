import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";

import { resolveInside } from "../../../security/paths.js";
import { NDS_BLZ_ENCODER_CONTRACT_VERSION } from "../blz-encode.js";
import {
  serializeNdsFat,
  type NdsFinalFatEntry,
} from "../fat-serialize.js";
import { serializeExtendedNdsFnt } from "../fnt-serialize.js";
import { readNdsRebuildHeader } from "../header-rebuild.js";
import { NdsError } from "../errors.js";
import { createNdsOverlayRuntimeContext } from "../overlay-runtime.js";
import { serializeNdsOverlayTable } from "../overlays-serialize.js";
import type { NdsRomMap } from "../rom-map.js";
import {
  assertNoNdsMutationConflicts,
  assertNoNdsRebuildLogicalConflicts,
} from "./conflicts.js";
import {
  planNdsFilesystemExtensions,
  planNdsVariableFileReplacement,
  type NdsAddedFilePlan,
  type NdsFilesystemExtensionPlan,
  type NdsRelocatedFilePlan,
} from "./filesystem-plan.js";
import {
  assertNdsMutationSourceIdentity,
  guardNdsMutationOperation,
  type GuardedNdsComponentOperation,
  type GuardedNdsMutationOperation,
} from "./guards.js";
import {
  compileNdsHeaderRewritePlan,
  type NdsHeaderRewritePlan,
} from "./header-plan.js";
import {
  finalizeNdsRebuildLayout,
  NDS_REBUILD_CONTRACT_VERSION,
  planNdsPayloadLayout,
  type NdsPayloadLayoutInput,
  type NdsRebuildLayout,
} from "./layout.js";
import {
  serializeCanonicalJson,
  type LoadedNdsMutationManifest,
  type NdsMutationOperation,
  type NdsMutationOperationV2,
} from "./manifest.js";
import {
  planDecodedOverlayReplacement,
  type NdsDecodedOverlayReplacementPlan,
} from "./overlay-plan.js";
import {
  ndsImmutableStructuralRanges,
  type NdsMutationPhysicalRange,
} from "./selectors.js";

export interface NdsResolvedMutationPlanV1 {
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

export type NdsResolvedMutationOperationV2 =
  | {
    readonly kind: "fixed";
    readonly index: number;
    readonly operation: GuardedNdsMutationOperation;
  }
  | {
    readonly kind: "relocated-file";
    readonly index: number;
    readonly file: NdsRelocatedFilePlan;
  }
  | {
    readonly kind: "new-file";
    readonly index: number;
    readonly file: NdsAddedFilePlan;
  }
  | {
    readonly kind: "decoded-overlay";
    readonly index: number;
    readonly overlay: NdsDecodedOverlayReplacementPlan;
  };

export interface NdsResolvedMutationPlanV2 {
  readonly formatVersion: 2;
  readonly rebuildContractVersion: 1;
  readonly blzEncoderContractVersion: 1;
  readonly sourceRomPath: string;
  readonly sourceWorkspacePath: string;
  readonly sourceSha256: string;
  readonly sourceSha256Prefix: string;
  readonly sourceSize: number;
  readonly manifestWorkspacePath: string;
  readonly manifestSha256: string;
  readonly outputFilename: string;
  readonly buildId: string;
  readonly operations: readonly NdsResolvedMutationOperationV2[];
  readonly filesystemExtension: NdsFilesystemExtensionPlan;
  readonly finalFat: readonly NdsFinalFatEntry[];
  readonly layout: NdsRebuildLayout;
  readonly headerPlan: NdsHeaderRewritePlan;
}

export type NdsResolvedMutationPlan = NdsResolvedMutationPlanV1 | NdsResolvedMutationPlanV2;

export function isNdsResolvedMutationPlanV2(
  plan: NdsResolvedMutationPlan,
): plan is NdsResolvedMutationPlanV2 {
  return "formatVersion" in plan && plan.formatVersion === 2;
}

function workspaceRelativePath(
  workspaceRoot: string,
  absolutePath: string,
): string {
  const resolvedRoot = path.resolve(workspaceRoot);
  const relative = path.relative(resolvedRoot, path.resolve(absolutePath));
  if (
    relative.length === 0
    || relative === ".."
    || relative.startsWith(`..${path.sep}`)
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

function sha256Bytes(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function buildIdentityV1(
  sourceSha256: string,
  manifestSha256: string,
  operations: readonly GuardedNdsMutationOperation[],
): string {
  const replacementArtifactSha256 = operations
    .filter(
      (operation): operation is GuardedNdsComponentOperation => operation.type === "replace-component",
    )
    .sort((left, right) => left.index - right.index)
    .map((operation) => operation.replacement.sha256);
  const canonicalIdentity = serializeCanonicalJson({
    format: "re-mcp-nds-build-identity",
    formatVersion: 1,
    sourceSha256,
    manifestSha256,
    replacementArtifactSha256,
  });
  return sha256Text(canonicalIdentity);
}

function replacementArtifactHash(
  operation: NdsMutationOperationV2,
): string | null {
  return operation.type === "replace-bytes"
    ? null
    : operation.replacement.sha256;
}

function buildIdentityV2(
  sourceSha256: string,
  manifestSha256: string,
  operations: readonly NdsMutationOperationV2[],
): string {
  const replacementArtifactSha256 = operations
    .map((operation) => replacementArtifactHash(operation))
    .filter((value): value is string => value !== null);
  const canonicalIdentity = serializeCanonicalJson({
    format: "re-mcp-nds-build-identity",
    formatVersion: 2,
    sourceSha256,
    manifestSha256,
    replacementArtifactSha256,
    rebuildContractVersion: NDS_REBUILD_CONTRACT_VERSION,
    blzEncoderContractVersion: NDS_BLZ_ENCODER_CONTRACT_VERSION,
  });
  return sha256Text(canonicalIdentity);
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

function serializeFixedOperation(operation: GuardedNdsMutationOperation) {
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

function serializeFilesystemExtension(extension: NdsFilesystemExtensionPlan): unknown {
  return {
    addedDirectories: extension.addedDirectories,
    addedFiles: extension.addedFiles.map((file) => ({
      operationIndex: file.operationIndex,
      path: file.path,
      fileId: file.fileId,
      directoryId: file.directoryId,
      filename: file.filename,
      replacement: {
        artifact: file.replacementWorkspacePath,
        sha256: file.replacementSha256,
        size: file.replacementSize,
      },
    })),
    finalDirectoryCount: extension.finalDirectoryCount,
    finalFileCount: extension.finalFileCount,
  };
}

function serializeV2Operation(operation: NdsResolvedMutationOperationV2): unknown {
  if (operation.kind === "fixed") {
    return {
      kind: operation.kind,
      index: operation.index,
      operation: serializeFixedOperation(operation.operation),
    };
  }
  if (operation.kind === "relocated-file") {
    return {
      kind: operation.kind,
      index: operation.index,
      file: {
        operationIndex: operation.file.operationIndex,
        fileId: operation.file.fileId,
        filePath: operation.file.filePath,
        sourceStart: operation.file.sourceStart,
        sourceEnd: operation.file.sourceEnd,
        sourceSha256: operation.file.sourceSha256,
        replacement: {
          artifact: operation.file.replacementWorkspacePath,
          sha256: operation.file.replacementSha256,
          size: operation.file.replacementSize,
        },
      },
    };
  }
  if (operation.kind === "new-file") {
    return {
      kind: operation.kind,
      index: operation.index,
      file: {
        operationIndex: operation.file.operationIndex,
        path: operation.file.path,
        fileId: operation.file.fileId,
        directoryId: operation.file.directoryId,
        filename: operation.file.filename,
        replacement: {
          artifact: operation.file.replacementWorkspacePath,
          sha256: operation.file.replacementSha256,
          size: operation.file.replacementSize,
        },
      },
    };
  }
  return {
    kind: operation.kind,
    index: operation.index,
    overlay: {
      operationIndex: operation.overlay.operationIndex,
      processor: operation.overlay.processor,
      overlayId: operation.overlay.overlayId,
      fileId: operation.overlay.fileId,
      sourceStoredStart: operation.overlay.sourceStoredStart,
      sourceStoredEnd: operation.overlay.sourceStoredEnd,
      sourceStoredSha256: operation.overlay.sourceStoredSha256,
      sourceRuntimeSha256: operation.overlay.sourceRuntimeSha256,
      replacementRuntime: {
        artifact: operation.overlay.replacementRuntimeWorkspacePath,
        sha256: operation.overlay.replacementRuntimeSha256,
        size: operation.overlay.runtimeSize,
      },
      encodedSha256: operation.overlay.encodedSha256,
      encodedSize: operation.overlay.encodedSize,
    },
  };
}

export function serializeResolvedNdsMutationPlan(
  plan: NdsResolvedMutationPlan,
): unknown {
  if (!isNdsResolvedMutationPlanV2(plan)) {
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
      operations: plan.operations.map((operation) => serializeFixedOperation(operation)),
      applicationOrder: plan.applicationOperations.map((operation) => operation.index),
    };
  }

  return {
    formatVersion: 2,
    rebuildContractVersion: plan.rebuildContractVersion,
    blzEncoderContractVersion: plan.blzEncoderContractVersion,
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
    operations: plan.operations.map((operation) => serializeV2Operation(operation)),
    filesystemExtension: serializeFilesystemExtension(plan.filesystemExtension),
    finalFat: plan.finalFat,
    layout: {
      sourceSize: plan.layout.sourceSize,
      tailStart: plan.layout.tailStart,
      logicalUsedSize: plan.layout.logicalUsedSize,
      finalSize: plan.layout.finalSize,
      deviceCapacity: plan.layout.deviceCapacity,
      segments: plan.layout.segments.map((segment) => ({
        kind: segment.kind,
        ownerId: segment.ownerId,
        alignment: segment.alignment,
        start: segment.start,
        end: segment.end,
        size: segment.size,
        sha256: segment.sha256,
      })),
    },
    headerPlan: {
      sourceHeaderSha256: plan.headerPlan.sourceHeaderSha256,
      outputHeaderSha256: plan.headerPlan.outputHeaderSha256,
      rewrites: plan.headerPlan.rewrites,
    },
  };
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

function operationArtifactPath(operation: NdsMutationOperationV2): string | null {
  return operation.type === "replace-bytes"
    ? null
    : operation.replacement.artifact;
}

async function assertOperationArtifactNotManifest(
  workspaceRoot: string,
  loadedManifest: LoadedNdsMutationManifest,
  operation: NdsMutationOperationV2,
  aliasCategory: "unsupported-mutation-target" | "unsupported-rebuild-target",
): Promise<void> {
  const artifact = operationArtifactPath(operation);
  if (artifact === null) {
    return;
  }
  const artifactPath = resolveInside(workspaceRoot, artifact);
  if (await sameExistingFile(artifactPath, loadedManifest.manifestPath)) {
    throw new NdsError(
      aliasCategory,
      "Replacement artifact may not alias the mutation manifest",
    );
  }
}

export function resolvedNdsMutationArtifactPaths(
  plan: NdsResolvedMutationPlan,
): readonly string[] {
  if (!isNdsResolvedMutationPlanV2(plan)) {
    return plan.operations
      .filter(
        (operation): operation is GuardedNdsComponentOperation => operation.type === "replace-component",
      )
      .map((operation) => operation.replacement.absolutePath);
  }
  const paths: string[] = [];
  for (const operation of plan.operations) {
    if (operation.kind === "fixed") {
      if (operation.operation.type === "replace-component") {
        paths.push(operation.operation.replacement.absolutePath);
      }
    } else if (operation.kind === "relocated-file") {
      paths.push(operation.file.replacementAbsolutePath);
    } else if (operation.kind === "new-file") {
      paths.push(operation.file.replacementAbsolutePath);
    } else {
      paths.push(operation.overlay.replacementRuntimeAbsolutePath);
    }
  }
  return paths;
}

async function assertResolvedArtifactsNotFinalOutput(
  workspaceRoot: string,
  plan: NdsResolvedMutationPlan,
): Promise<void> {
  const finalOutputPath = resolveInside(
    workspaceRoot,
    path.join(
      "output",
      "nds",
      plan.sourceSha256Prefix,
      plan.buildId,
      plan.outputFilename,
    ),
  );
  for (const artifactPath of resolvedNdsMutationArtifactPaths(plan)) {
    if (await sameExistingFile(artifactPath, finalOutputPath)) {
      throw new NdsError(
        isNdsResolvedMutationPlanV2(plan)
          ? "unsupported-rebuild-target"
          : "unsupported-mutation-target",
        "Replacement artifact may not alias the deterministic final output ROM",
      );
    }
  }
}

async function readPlannedArtifactBytes(
  absolutePath: string,
  expectedSize: number,
  expectedSha256: string,
  label: string,
): Promise<Buffer> {
  let bytes: Buffer;
  try {
    bytes = await readFile(absolutePath);
  } catch (error) {
    throw new NdsError(
      "replacement-artifact-missing",
      `${label} became unavailable during rebuild planning: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (bytes.length !== expectedSize) {
    throw new NdsError(
      "replacement-artifact-missing",
      `${label} changed size from ${expectedSize} to ${bytes.length} bytes during rebuild planning`,
    );
  }
  const actualSha256 = sha256Bytes(bytes);
  if (actualSha256 !== expectedSha256) {
    throw new NdsError(
      "replacement-artifact-hash-mismatch",
      `${label} SHA-256 changed to ${actualSha256}, expected ${expectedSha256}`,
    );
  }
  return bytes;
}

function segmentByOwner(
  layout: Pick<NdsRebuildLayout, "segments">,
  ownerId: string,
) {
  const matches = layout.segments.filter((segment) => segment.ownerId === ownerId);
  if (matches.length !== 1 || matches[0] === undefined) {
    throw new NdsError(
      "rebuild-layout-overflow",
      `Rebuild payload owner ${ownerId} does not resolve to exactly one layout segment`,
    );
  }
  return matches[0];
}

function buildFinalFat(
  map: NdsRomMap,
  extension: NdsFilesystemExtensionPlan,
  layout: Pick<NdsRebuildLayout, "segments">,
  relocatedFiles: readonly NdsRelocatedFilePlan[],
  decodedOverlays: readonly NdsDecodedOverlayReplacementPlan[],
): readonly NdsFinalFatEntry[] {
  const entries: NdsFinalFatEntry[] = Array.from(
    { length: extension.finalFileCount },
    (_, fileId) => {
      const source = map.fat[fileId];
      return source === undefined
        ? { fileId, startOffset: 0, endOffset: 0 }
        : {
          fileId,
          startOffset: source.startOffset,
          endOffset: source.endOffset,
        };
    },
  );

  for (const file of relocatedFiles) {
    const segment = segmentByOwner(layout, `file:${file.fileId}`);
    entries[file.fileId] = {
      fileId: file.fileId,
      startOffset: segment.start,
      endOffset: segment.end,
    };
  }
  for (const overlay of decodedOverlays) {
    const segment = segmentByOwner(
      layout,
      `overlay:${overlay.processor}:${overlay.overlayId}`,
    );
    entries[overlay.fileId] = {
      fileId: overlay.fileId,
      startOffset: segment.start,
      endOffset: segment.end,
    };
  }
  for (const file of extension.addedFiles) {
    const segment = segmentByOwner(layout, `file:${file.fileId}`);
    entries[file.fileId] = {
      fileId: file.fileId,
      startOffset: segment.start,
      endOffset: segment.end,
    };
  }
  return entries;
}

async function compileV1Plan(
  map: NdsRomMap,
  workspaceRoot: string,
  loadedManifest: LoadedNdsMutationManifest,
): Promise<NdsResolvedMutationPlanV1> {
  const manifest = loadedManifest.manifest;
  if (manifest.formatVersion !== 1) {
    throw new NdsError("mutation-manifest-invalid", "Expected an NDS mutation v1 manifest");
  }
  const expectedSourceSha256 = manifest.source.sha256;
  if (map.sha256 !== expectedSourceSha256) {
    throw new NdsError(
      "source-rom-mismatch",
      `Mutation manifest requires source SHA-256 ${expectedSourceSha256}, but the canonical ROM map is ${map.sha256}`,
    );
  }

  await assertNdsMutationSourceIdentity(map, expectedSourceSha256);
  const operations: GuardedNdsMutationOperation[] = [];
  for (let index = 0; index < manifest.operations.length; index += 1) {
    const operation = manifest.operations[index];
    if (operation === undefined) {
      throw new NdsError(
        "mutation-manifest-invalid",
        `Normalized mutation operation ${index} is missing`,
      );
    }
    await assertOperationArtifactNotManifest(
      workspaceRoot,
      loadedManifest,
      operation,
      "unsupported-mutation-target",
    );
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
  const buildId = buildIdentityV1(
    expectedSourceSha256,
    loadedManifest.sha256,
    operations,
  );

  const plan: NdsResolvedMutationPlanV1 = {
    sourceRomPath: map.romPath,
    sourceWorkspacePath: workspaceRelativePath(workspaceRoot, map.romPath),
    sourceSha256: expectedSourceSha256,
    sourceSha256Prefix: map.sha256Prefix,
    sourceSize: map.fileSize,
    manifestWorkspacePath: loadedManifest.workspaceRelativePath,
    manifestSha256: loadedManifest.sha256,
    outputFilename: manifest.output.filename,
    buildId,
    operations,
    applicationOperations,
    immutableStructuralRanges,
  };
  await assertResolvedArtifactsNotFinalOutput(workspaceRoot, plan);
  return plan;
}

async function compileV2Plan(
  map: NdsRomMap,
  workspaceRoot: string,
  loadedManifest: LoadedNdsMutationManifest,
): Promise<NdsResolvedMutationPlanV2> {
  const manifest = loadedManifest.manifest;
  if (manifest.formatVersion !== 2) {
    throw new NdsError("mutation-manifest-invalid", "Expected an NDS mutation v2 manifest");
  }
  const expectedSourceSha256 = manifest.source.sha256;
  if (map.sha256 !== expectedSourceSha256) {
    throw new NdsError(
      "source-rom-mismatch",
      `Mutation manifest requires source SHA-256 ${expectedSourceSha256}, but the canonical ROM map is ${map.sha256}`,
    );
  }
  await assertNdsMutationSourceIdentity(map, expectedSourceSha256);

  const fixedOperations: GuardedNdsMutationOperation[] = [];
  const relocatedFiles: NdsRelocatedFilePlan[] = [];
  const newFileOperations: Array<{
    readonly index: number;
    readonly operation: Extract<NdsMutationOperationV2, { readonly type: "add-nitrofs-file" }>;
  }> = [];
  const decodedOverlayOperations: Array<{
    readonly index: number;
    readonly operation: Extract<NdsMutationOperationV2, { readonly type: "replace-decoded-overlay" }>;
  }> = [];

  for (let index = 0; index < manifest.operations.length; index += 1) {
    const operation = manifest.operations[index];
    if (operation === undefined) {
      throw new NdsError(
        "mutation-manifest-invalid",
        `Normalized mutation operation ${index} is missing`,
      );
    }
    await assertOperationArtifactNotManifest(
      workspaceRoot,
      loadedManifest,
      operation,
      "unsupported-rebuild-target",
    );

    if (operation.type === "replace-bytes" || operation.type === "replace-component") {
      fixedOperations.push(await guardNdsMutationOperation(
        map,
        workspaceRoot,
        index,
        operation,
      ));
    } else if (operation.type === "replace-nitrofs-file") {
      relocatedFiles.push(await planNdsVariableFileReplacement(
        map,
        workspaceRoot,
        index,
        operation,
      ));
    } else if (operation.type === "add-nitrofs-file") {
      newFileOperations.push({ index, operation });
    } else {
      decodedOverlayOperations.push({ index, operation });
    }
  }

  const filesystemExtension = await planNdsFilesystemExtensions(
    map,
    workspaceRoot,
    newFileOperations,
  );
  const runtimeContext = createNdsOverlayRuntimeContext(map);
  const decodedOverlays: NdsDecodedOverlayReplacementPlan[] = [];
  for (const { index, operation } of decodedOverlayOperations) {
    decodedOverlays.push(await planDecodedOverlayReplacement(
      map,
      workspaceRoot,
      index,
      operation,
      runtimeContext,
    ));
  }

  assertNoNdsRebuildLogicalConflicts(
    fixedOperations,
    relocatedFiles,
    decodedOverlays,
  );

  const payloadInputs: NdsPayloadLayoutInput[] = [];
  for (const file of relocatedFiles) {
    const bytes = await readPlannedArtifactBytes(
      file.replacementAbsolutePath,
      file.replacementSize,
      file.replacementSha256,
      `Mutation operation ${file.operationIndex} relocated NitroFS artifact`,
    );
    payloadInputs.push({
      kind: "relocated-file",
      ownerId: `file:${file.fileId}`,
      fileId: file.fileId,
      bytes,
      sha256: file.replacementSha256,
    });
  }
  for (const overlay of decodedOverlays) {
    payloadInputs.push({
      kind: "relocated-file",
      ownerId: `overlay:${overlay.processor}:${overlay.overlayId}`,
      fileId: overlay.fileId,
      bytes: overlay.encodedBytes,
      sha256: overlay.encodedSha256,
    });
  }
  for (const file of filesystemExtension.addedFiles) {
    const bytes = await readPlannedArtifactBytes(
      file.replacementAbsolutePath,
      file.replacementSize,
      file.replacementSha256,
      `Mutation operation ${file.operationIndex} new NitroFS artifact`,
    );
    payloadInputs.push({
      kind: "new-file",
      ownerId: `file:${file.fileId}`,
      fileId: file.fileId,
      bytes,
      sha256: file.replacementSha256,
    });
  }

  const payloadLayout = planNdsPayloadLayout(map.fileSize, payloadInputs);
  const finalFat = buildFinalFat(
    map,
    filesystemExtension,
    payloadLayout,
    relocatedFiles,
    decodedOverlays,
  );
  const fat = serializeNdsFat(finalFat);
  const fnt = filesystemExtension.addedDirectories.length > 0
    || filesystemExtension.addedFiles.length > 0
    ? serializeExtendedNdsFnt(map.filesystem, filesystemExtension)
    : undefined;

  const arm9Overrides = new Map<number, number>();
  const arm7Overrides = new Map<number, number>();
  for (const overlay of decodedOverlays) {
    (overlay.processor === "arm9" ? arm9Overrides : arm7Overrides)
      .set(overlay.overlayId, overlay.encodedSize);
  }
  const arm9OverlayTable = arm9Overrides.size > 0
    ? serializeNdsOverlayTable(map.overlays.arm9, arm9Overrides)
    : undefined;
  const arm7OverlayTable = arm7Overrides.size > 0
    ? serializeNdsOverlayTable(map.overlays.arm7, arm7Overrides)
    : undefined;

  const layout = finalizeNdsRebuildLayout(payloadLayout, {
    fat,
    ...(fnt === undefined ? {} : { fnt }),
    ...(arm9OverlayTable === undefined ? {} : { arm9OverlayTable }),
    ...(arm7OverlayTable === undefined ? {} : { arm7OverlayTable }),
  });
  const sourceHeader = await readNdsRebuildHeader(map.romPath);
  const headerPlan = compileNdsHeaderRewritePlan(sourceHeader, layout);
  await assertNdsMutationSourceIdentity(map, expectedSourceSha256);

  const fixedByIndex = new Map(fixedOperations.map((operation) => [operation.index, operation]));
  const relocatedByIndex = new Map(relocatedFiles.map((file) => [file.operationIndex, file]));
  const addedByIndex = new Map(filesystemExtension.addedFiles.map((file) => [file.operationIndex, file]));
  const overlayByIndex = new Map(decodedOverlays.map((overlay) => [overlay.operationIndex, overlay]));
  const operations: NdsResolvedMutationOperationV2[] = [];
  for (let index = 0; index < manifest.operations.length; index += 1) {
    const fixed = fixedByIndex.get(index);
    const relocated = relocatedByIndex.get(index);
    const added = addedByIndex.get(index);
    const overlay = overlayByIndex.get(index);
    const matches = [fixed, relocated, added, overlay].filter((value) => value !== undefined);
    if (matches.length !== 1) {
      throw new NdsError(
        "unsupported-rebuild-target",
        `Mutation operation ${index} did not resolve to exactly one rebuild plan operation`,
      );
    }
    if (fixed !== undefined) {
      operations.push({ kind: "fixed", index, operation: fixed });
    } else if (relocated !== undefined) {
      operations.push({ kind: "relocated-file", index, file: relocated });
    } else if (added !== undefined) {
      operations.push({ kind: "new-file", index, file: added });
    } else if (overlay !== undefined) {
      operations.push({ kind: "decoded-overlay", index, overlay });
    }
  }

  const buildId = buildIdentityV2(
    expectedSourceSha256,
    loadedManifest.sha256,
    manifest.operations,
  );
  const plan: NdsResolvedMutationPlanV2 = {
    formatVersion: 2,
    rebuildContractVersion: NDS_REBUILD_CONTRACT_VERSION,
    blzEncoderContractVersion: NDS_BLZ_ENCODER_CONTRACT_VERSION,
    sourceRomPath: map.romPath,
    sourceWorkspacePath: workspaceRelativePath(workspaceRoot, map.romPath),
    sourceSha256: expectedSourceSha256,
    sourceSha256Prefix: map.sha256Prefix,
    sourceSize: map.fileSize,
    manifestWorkspacePath: loadedManifest.workspaceRelativePath,
    manifestSha256: loadedManifest.sha256,
    outputFilename: manifest.output.filename,
    buildId,
    operations,
    filesystemExtension,
    finalFat,
    layout,
    headerPlan,
  };
  await assertResolvedArtifactsNotFinalOutput(workspaceRoot, plan);
  return plan;
}

export async function compileNdsMutationPlan(
  map: NdsRomMap,
  workspaceRoot: string,
  loadedManifest: LoadedNdsMutationManifest,
): Promise<NdsResolvedMutationPlan> {
  return loadedManifest.manifest.formatVersion === 1
    ? await compileV1Plan(map, workspaceRoot, loadedManifest)
    : await compileV2Plan(map, workspaceRoot, loadedManifest);
}
