import { createHash } from "node:crypto";
import { open, stat } from "node:fs/promises";

import { NdsError } from "../errors.js";
import { hashFileSha256, readExact } from "../io.js";
import { createNdsOverlayRuntimeContext } from "../overlay-runtime.js";
import type { NdsOverlay, NdsProcessor } from "../overlays.js";
import { readNdsRomMap, type NdsRomMap } from "../rom-map.js";
import { assertNdsMutationSourceIdentity } from "./guards.js";
import {
  isNdsResolvedMutationPlanV2,
  type NdsResolvedMutationPlan,
  type NdsResolvedMutationPlanV1,
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
  readonly structuralMetadataUnchanged: true;
  readonly structuralMapUnchanged: true;
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

async function verifyOperations(
  plan: NdsResolvedMutationPlanV1,
  outputRomPath: string,
): Promise<readonly NdsMutationOperationVerification[]> {
  const outputHandle = await open(outputRomPath, "r");
  const results: NdsMutationOperationVerification[] = [];
  try {
    for (const operation of plan.operations) {
      if (operation.type === "replace-bytes") {
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
      results.push({
        index: operation.index,
        status: "passed",
        romStart: operation.romStart,
        romEnd: operation.romEnd,
      });
    }
  } finally {
    await outputHandle.close();
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

export async function verifyNdsMutationOutput(
  sourceMap: NdsRomMap,
  plan: NdsResolvedMutationPlan,
  outputRomPath: string,
  hooks: NdsMutationVerifyHooks = {},
): Promise<NdsMutationVerificationResult> {
  if (isNdsResolvedMutationPlanV2(plan)) {
    throw new NdsError(
      "unsupported-rebuild-target",
      "NDS mutation v2 planning is available, but v2 semantic verification is not enabled until the rebuild verifier is implemented",
    );
  }
  await assertNdsMutationSourceIdentity(sourceMap, plan.sourceSha256);

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
