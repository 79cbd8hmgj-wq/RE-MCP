import { createHash } from "node:crypto";
import { open, stat } from "node:fs/promises";

import { NdsError } from "../errors.js";
import { hashFileSha256, readExact } from "../io.js";
import { createNdsOverlayRuntimeContext } from "../overlay-runtime.js";
import type { NdsOverlay, NdsProcessor } from "../overlays.js";
import { readNdsRomMap, type NdsRomMap } from "../rom-map.js";
import type { GuardedNdsMutationOperation } from "./guards.js";
import { assertNdsMutationSourceIdentity } from "./guards.js";
import {
  isNdsResolvedMutationPlanV2,
  type NdsResolvedMutationPlan,
  type NdsResolvedMutationPlanV1,
  type NdsResolvedMutationPlanV2,
} from "./planner.js";

const DIFF_CHUNK_BYTES = 64 * 1024;
const RANGE_HASH_CHUNK_BYTES = 64 * 1024;

export interface NdsMutationOperationVerification {
  readonly index: number;
  readonly status: "passed";
  readonly romStart: number;
  readonly romEnd: number;
}

export interface NdsCompressedOverlayVerification {
  readonly processor: "arm9" | "arm7";
  readonly overlayId: number;
  readonly status: "passed";
  readonly runtimeSha256: string;
}

export interface NdsMutationVerificationResult {
  readonly status: "passed";
  readonly sourceSha256: string;
  readonly outputSha256: string;
  readonly sourceSize: number;
  readonly outputSize: number;
  readonly sourceUnchanged: true;
  readonly structuralMetadataUnchanged: boolean;
  readonly structuralMapUnchanged: boolean;
  readonly rebuildSemanticsVerified?: true;
  readonly changedByteCount: number;
  readonly unexpectedChangedBytes: 0;
  readonly operations: readonly NdsMutationOperationVerification[];
  readonly compressedOverlays: readonly NdsCompressedOverlayVerification[];
}

export interface NdsMutationVerifyHooks {
  readonly afterDiff?: () => Promise<void>;
}

function verificationError(message: string): NdsError<"output-verification-failed"> {
  return new NdsError("output-verification-failed", message);
}

async function hashFileRangeSha256(
  filePath: string,
  start: number,
  size: number,
): Promise<string> {
  const handle = await open(filePath, "r");
  const hash = createHash("sha256");
  try {
    let offset = 0;
    while (offset < size) {
      const length = Math.min(RANGE_HASH_CHUNK_BYTES, size - offset);
      const buffer = await readExact(handle, start + offset, length, "NDS verification range");
      hash.update(buffer);
      offset += length;
    }
  } finally {
    await handle.close();
  }
  return hash.digest("hex");
}

function structuralSnapshot(map: NdsRomMap): unknown {
  return {
    fileSize: map.fileSize,
    header: map.header,
    fat: map.fat,
    filesystem: {
      directories: map.filesystem.directories,
      files: map.filesystem.files,
    },
    overlays: map.overlays,
    executableRanges: map.executableRanges,
  };
}

async function assertStructuralBytesUnchanged(
  sourceMap: NdsRomMap,
  plan: NdsResolvedMutationPlanV1,
  outputRomPath: string,
): Promise<void> {
  const sourceHandle = await open(sourceMap.romPath, "r");
  const outputHandle = await open(outputRomPath, "r");
  try {
    for (const range of plan.immutableStructuralRanges) {
      const length = range.romEnd - range.romStart;
      const [source, output] = await Promise.all([
        readExact(sourceHandle, range.romStart, length, `source ${range.labels.join("/")}`),
        readExact(outputHandle, range.romStart, length, `output ${range.labels.join("/")}`),
      ]);
      if (!source.equals(output)) {
        throw new NdsError(
          "structural-map-changed",
          `Immutable NDS structure changed in ${range.labels.join(", ")} at ROM range 0x${range.romStart.toString(16)}..0x${range.romEnd.toString(16)}`,
        );
      }
    }
  } finally {
    await Promise.all([sourceHandle.close(), outputHandle.close()]);
  }
}

function assertStructuralGeometryUnchanged(sourceMap: NdsRomMap, outputMap: NdsRomMap): void {
  const source = JSON.stringify(structuralSnapshot(sourceMap));
  const output = JSON.stringify(structuralSnapshot(outputMap));
  if (source !== output) {
    throw new NdsError(
      "structural-map-changed",
      "Canonical NDS structural geometry changed after mutation",
    );
  }
}

async function verifyGuardedOperation(
  operation: GuardedNdsMutationOperation,
  outputRomPath: string,
): Promise<NdsMutationOperationVerification> {
  if (operation.type === "replace-bytes") {
    const outputHandle = await open(outputRomPath, "r");
    try {
      const actual = await readExact(
        outputHandle,
        operation.romStart,
        operation.size,
        `mutation operation ${operation.index}`,
      );
      const expected = Buffer.from(operation.replacement, "hex");
      if (!actual.equals(expected)) {
        throw verificationError(
          `Mutation operation ${operation.index} is missing or does not contain the requested replacement bytes`,
        );
      }
    } finally {
      await outputHandle.close();
    }
  } else {
    const actualSha256 = await hashFileRangeSha256(
      outputRomPath,
      operation.romStart,
      operation.size,
    );
    if (actualSha256 !== operation.replacement.sha256) {
      throw verificationError(
        `Mutation operation ${operation.index} output component SHA-256 is ${actualSha256}, expected ${operation.replacement.sha256}`,
      );
    }
  }
  return {
    index: operation.index,
    status: "passed",
    romStart: operation.romStart,
    romEnd: operation.romEnd,
  };
}

async function verifyOperations(
  plan: NdsResolvedMutationPlanV1,
  outputRomPath: string,
): Promise<readonly NdsMutationOperationVerification[]> {
  const results: NdsMutationOperationVerification[] = [];
  for (const operation of plan.operations) {
    results.push(await verifyGuardedOperation(operation, outputRomPath));
  }
  return results;
}

function overlayFor(
  map: NdsRomMap,
  processor: NdsProcessor,
  overlayId: number,
): NdsOverlay | undefined {
  return (processor === "arm9" ? map.overlays.arm9 : map.overlays.arm7)
    .find((overlay) => overlay.overlayId === overlayId);
}

async function verifyCompressedOverlays(
  sourceMap: NdsRomMap,
  outputMap: NdsRomMap,
  plan: NdsResolvedMutationPlanV1,
): Promise<readonly NdsCompressedOverlayVerification[]> {
  const owners = new Map<string, { readonly processor: NdsProcessor; readonly overlayId: number }>();
  for (const operation of plan.operations) {
    if (operation.type !== "replace-component") {
      continue;
    }
    for (const owner of operation.component.overlayOwners) {
      if (owner.compressed) {
        owners.set(`${owner.processor}:${owner.overlayId}`, {
          processor: owner.processor,
          overlayId: owner.overlayId,
        });
      }
    }
  }

  const ordered = [...owners.values()].sort(
    (left, right) => left.processor.localeCompare(right.processor)
      || left.overlayId - right.overlayId,
  );
  const context = createNdsOverlayRuntimeContext(outputMap);
  const results: NdsCompressedOverlayVerification[] = [];
  for (const owner of ordered) {
    const sourceOverlay = overlayFor(sourceMap, owner.processor, owner.overlayId);
    const outputOverlay = overlayFor(outputMap, owner.processor, owner.overlayId);
    if (sourceOverlay === undefined || outputOverlay === undefined) {
      throw new NdsError(
        "compressed-overlay-invalid",
        `${owner.processor.toUpperCase()} overlay ${owner.overlayId} is missing during output verification`,
      );
    }
    try {
      const runtime = await context.getCompressedOverlay(owner.processor, owner.overlayId);
      if (
        outputOverlay.romOffset !== sourceOverlay.romOffset
        || outputOverlay.romSize !== sourceOverlay.romSize
        || outputOverlay.ramAddress !== sourceOverlay.ramAddress
        || outputOverlay.ramSize !== sourceOverlay.ramSize
        || outputOverlay.bssSize !== sourceOverlay.bssSize
        || runtime.storedRomOffset !== outputOverlay.romOffset
        || runtime.storedSize !== outputOverlay.romSize
        || runtime.runtimeAddress !== outputOverlay.ramAddress
        || runtime.runtimeSize !== outputOverlay.ramSize
        || runtime.bssSize !== outputOverlay.bssSize
      ) {
        throw new Error("compressed overlay runtime geometry differs from the canonical source layout");
      }
      results.push({
        processor: owner.processor,
        overlayId: owner.overlayId,
        status: "passed",
        runtimeSha256: runtime.runtimeSha256,
      });
    } catch (error) {
      if (error instanceof NdsError && error.category === "compressed-overlay-invalid") {
        throw error;
      }
      throw new NdsError(
        "compressed-overlay-invalid",
        `${owner.processor.toUpperCase()} overlay ${owner.overlayId} failed post-build runtime validation: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
  return results;
}

async function countAndAttributeDiff(
  sourceMap: NdsRomMap,
  plan: NdsResolvedMutationPlanV1,
  outputRomPath: string,
): Promise<number> {
  const sourceHandle = await open(sourceMap.romPath, "r");
  const outputHandle = await open(outputRomPath, "r");
  const intervals = [...plan.applicationOperations];
  let intervalIndex = 0;
  let changedByteCount = 0;
  let unexpectedCount = 0;
  const firstUnexpected: number[] = [];
  try {
    for (let base = 0; base < plan.sourceSize; base += DIFF_CHUNK_BYTES) {
      const length = Math.min(DIFF_CHUNK_BYTES, plan.sourceSize - base);
      const [source, output] = await Promise.all([
        readExact(sourceHandle, base, length, "source ROM diff chunk"),
        readExact(outputHandle, base, length, "output ROM diff chunk"),
      ]);
      for (let index = 0; index < length; index += 1) {
        if (source[index] === output[index]) {
          continue;
        }
        changedByteCount += 1;
        const absoluteOffset = base + index;
        while (
          intervalIndex < intervals.length
          && (intervals[intervalIndex]?.romEnd ?? 0) <= absoluteOffset
        ) {
          intervalIndex += 1;
        }
        const interval = intervals[intervalIndex];
        if (
          interval === undefined
          || absoluteOffset < interval.romStart
          || absoluteOffset >= interval.romEnd
        ) {
          unexpectedCount += 1;
          if (firstUnexpected.length < 16) {
            firstUnexpected.push(absoluteOffset);
          }
        }
      }
    }
  } finally {
    await Promise.all([sourceHandle.close(), outputHandle.close()]);
  }
  if (unexpectedCount > 0) {
    throw new NdsError(
      "unexpected-rom-diff",
      `Output contains ${unexpectedCount} changed byte(s) outside approved mutation ranges; first offsets: ${firstUnexpected.map((offset) => `0x${offset.toString(16)}`).join(", ")}`,
    );
  }
  return changedByteCount;
}

function intervalContains(
  intervals: readonly { readonly start: number; readonly end: number }[],
  offset: number,
): boolean {
  return intervals.some((interval) => offset >= interval.start && offset < interval.end);
}

async function countAndAttributeV2PrefixDiff(
  sourceMap: NdsRomMap,
  plan: NdsResolvedMutationPlanV2,
  outputRomPath: string,
): Promise<number> {
  const allowed = [
    ...plan.operations
      .filter((operation) => operation.kind === "fixed")
      .map((operation) => ({
        start: operation.operation.romStart,
        end: operation.operation.romEnd,
      })),
    ...plan.headerPlan.rewrites.map((rewrite) => ({
      start: rewrite.offset,
      end: rewrite.offset + (rewrite.replacement.length / 2),
    })),
  ].sort((left, right) => left.start - right.start || left.end - right.end);

  const sourceHandle = await open(sourceMap.romPath, "r");
  const outputHandle = await open(outputRomPath, "r");
  let changedByteCount = 0;
  let unexpectedCount = 0;
  const firstUnexpected: number[] = [];
  try {
    for (let base = 0; base < plan.sourceSize; base += DIFF_CHUNK_BYTES) {
      const length = Math.min(DIFF_CHUNK_BYTES, plan.sourceSize - base);
      const [source, output] = await Promise.all([
        readExact(sourceHandle, base, length, "source v2 ROM diff chunk"),
        readExact(outputHandle, base, length, "output v2 ROM diff chunk"),
      ]);
      for (let index = 0; index < length; index += 1) {
        if (source[index] === output[index]) {
          continue;
        }
        changedByteCount += 1;
        const absoluteOffset = base + index;
        if (!intervalContains(allowed, absoluteOffset)) {
          unexpectedCount += 1;
          if (firstUnexpected.length < 16) {
            firstUnexpected.push(absoluteOffset);
          }
        }
      }
    }
  } finally {
    await Promise.all([sourceHandle.close(), outputHandle.close()]);
  }
  if (unexpectedCount > 0) {
    throw new NdsError(
      "unexpected-rom-diff",
      `Rebuilt output contains ${unexpectedCount} changed source-prefix byte(s) outside fixed/header rewrite ranges; first offsets: ${firstUnexpected.map((offset) => `0x${offset.toString(16)}`).join(", ")}`,
    );
  }
  return changedByteCount + (plan.layout.finalSize - plan.sourceSize);
}

async function assertExactV2Header(
  plan: NdsResolvedMutationPlanV2,
  outputRomPath: string,
): Promise<void> {
  const handle = await open(outputRomPath, "r");
  try {
    const actual = await readExact(handle, 0, 0x160, "rebuilt NDS header");
    if (!actual.equals(plan.headerPlan.outputHeaderBytes)) {
      throw verificationError("Rebuilt NDS header differs from the exact planned header bytes");
    }
  } finally {
    await handle.close();
  }
}

async function assertExactV2Segments(
  plan: NdsResolvedMutationPlanV2,
  outputRomPath: string,
): Promise<void> {
  const handle = await open(outputRomPath, "r");
  try {
    let cursor = plan.sourceSize;
    for (const segment of plan.layout.segments) {
      if (segment.start < cursor || segment.end > plan.layout.finalSize) {
        throw verificationError(`Rebuild segment ${segment.ownerId} has invalid planned geometry`);
      }
      if (segment.start > cursor) {
        const gap = await readExact(
          handle,
          cursor,
          segment.start - cursor,
          `rebuild zero gap before ${segment.ownerId}`,
        );
        if (gap.some((value) => value !== 0)) {
          throw new NdsError(
            "unexpected-rom-diff",
            `Rebuilt output contains non-zero unowned bytes before segment ${segment.ownerId}`,
          );
        }
      }
      const actual = await readExact(
        handle,
        segment.start,
        segment.size,
        `rebuild segment ${segment.ownerId}`,
      );
      if (!actual.equals(segment.bytes)) {
        throw verificationError(`Rebuild segment ${segment.ownerId} differs from planned bytes`);
      }
      cursor = segment.end;
    }
    if (cursor < plan.layout.finalSize) {
      const tail = await readExact(
        handle,
        cursor,
        plan.layout.finalSize - cursor,
        "rebuild capacity padding",
      );
      if (tail.some((value) => value !== 0)) {
        throw new NdsError(
          "unexpected-rom-diff",
          "Rebuilt output contains non-zero bytes in unowned capacity padding",
        );
      }
    }
  } finally {
    await handle.close();
  }
}

function assertV2FatAndFilesystem(
  sourceMap: NdsRomMap,
  outputMap: NdsRomMap,
  plan: NdsResolvedMutationPlanV2,
): void {
  if (outputMap.fat.length !== plan.finalFat.length) {
    throw verificationError(
      `Rebuilt FAT has ${outputMap.fat.length} entries, expected ${plan.finalFat.length}`,
    );
  }
  for (let fileId = 0; fileId < plan.finalFat.length; fileId += 1) {
    const expected = plan.finalFat[fileId]!;
    const actual = outputMap.fat[fileId]!;
    if (actual.startOffset !== expected.startOffset || actual.endOffset !== expected.endOffset) {
      throw verificationError(`Rebuilt FAT entry ${fileId} differs from planned byte range`);
    }
  }

  if (
    outputMap.filesystem.files.length !== plan.filesystemExtension.finalFileCount
    || outputMap.filesystem.directories.length !== plan.filesystemExtension.finalDirectoryCount
  ) {
    throw verificationError("Rebuilt NitroFS file/directory counts differ from the planned extension");
  }
  for (const sourceFile of sourceMap.filesystem.files) {
    const outputFile = outputMap.filesystem.files[sourceFile.fileId];
    if (outputFile === undefined || outputFile.fileId !== sourceFile.fileId || outputFile.path !== sourceFile.path) {
      throw verificationError(`Existing NitroFS file ${sourceFile.fileId} changed identity or path`);
    }
  }
  for (const addedFile of plan.filesystemExtension.addedFiles) {
    const outputFile = outputMap.filesystem.files[addedFile.fileId];
    if (outputFile === undefined || outputFile.path !== addedFile.path) {
      throw verificationError(
        `Added NitroFS file ${addedFile.fileId} is missing planned path ${addedFile.path}`,
      );
    }
  }
  for (const addedDirectory of plan.filesystemExtension.addedDirectories) {
    const outputDirectory = outputMap.filesystem.directories.find(
      (directory) => directory.directoryId === addedDirectory.directoryId,
    );
    if (
      outputDirectory === undefined
      || outputDirectory.path !== addedDirectory.path
      || outputDirectory.parentDirectoryId !== addedDirectory.parentDirectoryId
      || outputDirectory.firstFileId !== addedDirectory.firstFileId
    ) {
      throw verificationError(
        `Added NitroFS directory ${addedDirectory.path} differs from the planned directory record`,
      );
    }
  }
}

function overlaySemanticSnapshot(overlay: NdsOverlay): unknown {
  return {
    processor: overlay.processor,
    overlayId: overlay.overlayId,
    ramAddress: overlay.ramAddress,
    ramSize: overlay.ramSize,
    bssSize: overlay.bssSize,
    staticInitStart: overlay.staticInitStart,
    staticInitEnd: overlay.staticInitEnd,
    fileId: overlay.fileId,
    flags: overlay.flags,
    compressed: overlay.compressed,
  };
}

async function verifyV2OperationsAndOverlays(
  sourceMap: NdsRomMap,
  outputMap: NdsRomMap,
  plan: NdsResolvedMutationPlanV2,
  outputRomPath: string,
): Promise<{
  readonly operations: readonly NdsMutationOperationVerification[];
  readonly compressedOverlays: readonly NdsCompressedOverlayVerification[];
}> {
  const operationResults: NdsMutationOperationVerification[] = [];
  const compressedResults: NdsCompressedOverlayVerification[] = [];
  const runtimeContext = createNdsOverlayRuntimeContext(outputMap);

  for (const resolved of plan.operations) {
    if (resolved.kind === "fixed") {
      operationResults.push(await verifyGuardedOperation(resolved.operation, outputRomPath));
      continue;
    }

    const fileId = resolved.kind === "decoded-overlay"
      ? resolved.overlay.fileId
      : resolved.file.fileId;
    const finalRange = plan.finalFat[fileId];
    if (finalRange === undefined) {
      throw verificationError(`Rebuild operation ${resolved.index} has no final FAT range`);
    }

    const expectedSha256 = resolved.kind === "decoded-overlay"
      ? resolved.overlay.encodedSha256
      : resolved.file.replacementSha256;
    const actualSha256 = await hashFileRangeSha256(
      outputRomPath,
      finalRange.startOffset,
      finalRange.endOffset - finalRange.startOffset,
    );
    if (actualSha256 !== expectedSha256) {
      throw verificationError(
        `Rebuild operation ${resolved.index} final payload SHA-256 is ${actualSha256}, expected ${expectedSha256}`,
      );
    }
    operationResults.push({
      index: resolved.index,
      status: "passed",
      romStart: finalRange.startOffset,
      romEnd: finalRange.endOffset,
    });

    if (resolved.kind === "decoded-overlay") {
      const sourceOverlay = overlayFor(
        sourceMap,
        resolved.overlay.processor,
        resolved.overlay.overlayId,
      );
      const outputOverlay = overlayFor(
        outputMap,
        resolved.overlay.processor,
        resolved.overlay.overlayId,
      );
      if (sourceOverlay === undefined || outputOverlay === undefined) {
        throw new NdsError(
          "compressed-overlay-invalid",
          `Decoded-overlay operation ${resolved.index} target is missing after rebuild`,
        );
      }
      if (
        JSON.stringify(overlaySemanticSnapshot(outputOverlay))
          !== JSON.stringify(overlaySemanticSnapshot(sourceOverlay))
        || outputOverlay.romOffset !== finalRange.startOffset
        || outputOverlay.romSize !== finalRange.endOffset - finalRange.startOffset
        || outputOverlay.compressedSize !== resolved.overlay.encodedSize
      ) {
        throw new NdsError(
          "compressed-overlay-invalid",
          `Decoded-overlay operation ${resolved.index} canonical geometry differs from the rebuild plan`,
        );
      }
      try {
        const runtime = await runtimeContext.getCompressedOverlay(
          resolved.overlay.processor,
          resolved.overlay.overlayId,
        );
        if (
          runtime.storedSha256 !== resolved.overlay.encodedSha256
          || runtime.runtimeSha256 !== resolved.overlay.replacementRuntimeSha256
          || runtime.runtimeSize !== resolved.overlay.runtimeSize
        ) {
          throw new Error("stored/runtime identity differs from the planned decoded-overlay replacement");
        }
        compressedResults.push({
          processor: resolved.overlay.processor,
          overlayId: resolved.overlay.overlayId,
          status: "passed",
          runtimeSha256: runtime.runtimeSha256,
        });
      } catch (error) {
        if (error instanceof NdsError && error.category === "compressed-overlay-invalid") {
          throw error;
        }
        throw new NdsError(
          "compressed-overlay-invalid",
          `${resolved.overlay.processor.toUpperCase()} overlay ${resolved.overlay.overlayId} failed rebuilt runtime validation: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  }

  for (const processor of ["arm9", "arm7"] as const) {
    const sourceOverlays = sourceMap.overlays[processor];
    const outputOverlays = outputMap.overlays[processor];
    if (sourceOverlays.length !== outputOverlays.length) {
      throw verificationError(`${processor.toUpperCase()} overlay count changed unexpectedly`);
    }
    for (const sourceOverlay of sourceOverlays) {
      const outputOverlay = outputOverlays.find(
        (candidate) => candidate.overlayId === sourceOverlay.overlayId,
      );
      if (
        outputOverlay === undefined
        || JSON.stringify(overlaySemanticSnapshot(outputOverlay))
          !== JSON.stringify(overlaySemanticSnapshot(sourceOverlay))
      ) {
        throw verificationError(
          `${processor.toUpperCase()} overlay ${sourceOverlay.overlayId} changed non-owned semantics`,
        );
      }
    }
  }

  return { operations: operationResults, compressedOverlays: compressedResults };
}

async function verifyV1(
  sourceMap: NdsRomMap,
  plan: NdsResolvedMutationPlanV1,
  outputRomPath: string,
  hooks: NdsMutationVerifyHooks,
): Promise<NdsMutationVerificationResult> {
  const outputInfo = await stat(outputRomPath);
  if (!outputInfo.isFile() || outputInfo.size !== plan.sourceSize) {
    throw verificationError(
      `Output ROM must be a regular ${plan.sourceSize}-byte file; actual size is ${outputInfo.size}`,
    );
  }

  let outputMap: NdsRomMap;
  try {
    outputMap = await readNdsRomMap(outputRomPath);
  } catch (error) {
    throw new NdsError(
      "post-build-parse-failed",
      `Mutated ROM failed canonical NDS parsing: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  await assertStructuralBytesUnchanged(sourceMap, plan, outputRomPath);
  assertStructuralGeometryUnchanged(sourceMap, outputMap);
  const operations = await verifyOperations(plan, outputRomPath);
  const compressedOverlays = await verifyCompressedOverlays(sourceMap, outputMap, plan);
  const changedByteCount = await countAndAttributeDiff(sourceMap, plan, outputRomPath);
  await hooks.afterDiff?.();
  await assertNdsMutationSourceIdentity(sourceMap, plan.sourceSha256);

  const outputSha256 = await hashFileSha256(outputRomPath);
  if (outputSha256 !== outputMap.sha256) {
    throw verificationError(
      `Output ROM changed during verification; canonical parse SHA-256 was ${outputMap.sha256}, final SHA-256 is ${outputSha256}`,
    );
  }
  return {
    status: "passed",
    sourceSha256: plan.sourceSha256,
    outputSha256,
    sourceSize: plan.sourceSize,
    outputSize: outputInfo.size,
    sourceUnchanged: true,
    structuralMetadataUnchanged: true,
    structuralMapUnchanged: true,
    changedByteCount,
    unexpectedChangedBytes: 0,
    operations,
    compressedOverlays,
  };
}

async function verifyV2(
  sourceMap: NdsRomMap,
  plan: NdsResolvedMutationPlanV2,
  outputRomPath: string,
  hooks: NdsMutationVerifyHooks,
): Promise<NdsMutationVerificationResult> {
  const outputInfo = await stat(outputRomPath);
  if (!outputInfo.isFile() || outputInfo.size !== plan.layout.finalSize) {
    throw verificationError(
      `Rebuilt output ROM must be a regular ${plan.layout.finalSize}-byte file; actual size is ${outputInfo.size}`,
    );
  }

  let outputMap: NdsRomMap;
  try {
    outputMap = await readNdsRomMap(outputRomPath);
  } catch (error) {
    throw new NdsError(
      "post-build-parse-failed",
      `Rebuilt ROM failed canonical NDS parsing: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  await assertExactV2Header(plan, outputRomPath);
  await assertExactV2Segments(plan, outputRomPath);
  assertV2FatAndFilesystem(sourceMap, outputMap, plan);
  const postBuild = await verifyV2OperationsAndOverlays(
    sourceMap,
    outputMap,
    plan,
    outputRomPath,
  );
  const changedByteCount = await countAndAttributeV2PrefixDiff(
    sourceMap,
    plan,
    outputRomPath,
  );
  await hooks.afterDiff?.();
  await assertNdsMutationSourceIdentity(sourceMap, plan.sourceSha256);

  const outputSha256 = await hashFileSha256(outputRomPath);
  if (outputSha256 !== outputMap.sha256) {
    throw verificationError(
      `Rebuilt output changed during verification; canonical parse SHA-256 was ${outputMap.sha256}, final SHA-256 is ${outputSha256}`,
    );
  }
  return {
    status: "passed",
    sourceSha256: plan.sourceSha256,
    outputSha256,
    sourceSize: plan.sourceSize,
    outputSize: outputInfo.size,
    sourceUnchanged: true,
    structuralMetadataUnchanged: false,
    structuralMapUnchanged: false,
    rebuildSemanticsVerified: true,
    changedByteCount,
    unexpectedChangedBytes: 0,
    operations: postBuild.operations,
    compressedOverlays: postBuild.compressedOverlays,
  };
}

export async function verifyNdsMutationOutput(
  sourceMap: NdsRomMap,
  plan: NdsResolvedMutationPlan,
  outputRomPath: string,
  hooks: NdsMutationVerifyHooks = {},
): Promise<NdsMutationVerificationResult> {
  await assertNdsMutationSourceIdentity(sourceMap, plan.sourceSha256);
  return isNdsResolvedMutationPlanV2(plan)
    ? await verifyV2(sourceMap, plan, outputRomPath, hooks)
    : await verifyV1(sourceMap, plan, outputRomPath, hooks);
}
