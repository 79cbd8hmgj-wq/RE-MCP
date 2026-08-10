import {
  lstat as nativeLstat,
  readFile as nativeReadFile,
} from "node:fs/promises";

import { encodeNdsBlz } from "../blz-encode.js";
import { NdsError } from "../errors.js";
import type {
  NdsOverlayRuntimeContext,
} from "../overlay-runtime.js";
import type { NdsOverlay, NdsProcessor } from "../overlays.js";
import type { NdsRomMap } from "../rom-map.js";
import {
  readVerifiedNdsArtifact,
  resolveNdsArtifactMetadata,
  type NdsArtifactIo,
} from "./artifacts.js";
import { assertNdsDecodedOverlaySourceGuards } from "./guards.js";
import type { NdsReplaceDecodedOverlayOperation } from "./manifest.js";

const MAX_PACKED_COMPRESSED_SIZE = 0x00ff_ffff;

export interface NdsDecodedOverlayReplacementPlan {
  readonly operationIndex: number;
  readonly processor: NdsProcessor;
  readonly overlayId: number;
  readonly fileId: number;
  readonly sourceStoredStart: number;
  readonly sourceStoredEnd: number;
  readonly sourceStoredSha256: string;
  readonly sourceRuntimeSha256: string;
  readonly replacementRuntimeWorkspacePath: string;
  readonly replacementRuntimeAbsolutePath: string;
  readonly replacementRuntimeSha256: string;
  readonly runtimeSize: number;
  readonly encodedBytes: Buffer;
  readonly encodedSha256: string;
  readonly encodedSize: number;
}

interface NdsOverlayPlanningIo extends NdsArtifactIo {
  readFile(filePath: string): Promise<Buffer>;
}

const defaultIo: NdsOverlayPlanningIo = {
  lstat: nativeLstat,
  readFile: nativeReadFile,
};

function guardFailed(message: string): never {
  throw new NdsError("decoded-overlay-guard-failed", message);
}

function selectOverlay(
  map: NdsRomMap,
  processor: NdsProcessor,
  overlayId: number,
): NdsOverlay {
  const overlays = processor === "arm9" ? map.overlays.arm9 : map.overlays.arm7;
  const overlay = overlays.find((candidate) => candidate.overlayId === overlayId);
  if (overlay === undefined) {
    guardFailed(
      `Mutation decoded-overlay target ${processor.toUpperCase()} overlay ${overlayId} does not exist`,
    );
  }
  if (!overlay.compressed) {
    guardFailed(
      `Mutation decoded-overlay target ${processor.toUpperCase()} overlay ${overlayId} is not compressed`,
    );
  }
  if (
    overlay.compressedSize < 8
    || overlay.compressedSize > overlay.romSize
    || overlay.ramSize < 1
  ) {
    guardFailed(
      `Mutation decoded-overlay target ${processor.toUpperCase()} overlay ${overlayId} has invalid canonical compression geometry`,
    );
  }
  return overlay;
}

export async function planDecodedOverlayReplacement(
  map: NdsRomMap,
  workspaceRoot: string,
  index: number,
  operation: NdsReplaceDecodedOverlayOperation,
  runtimeContext: NdsOverlayRuntimeContext,
  io: NdsOverlayPlanningIo = defaultIo,
): Promise<NdsDecodedOverlayReplacementPlan> {
  const overlay = selectOverlay(
    map,
    operation.target.processor,
    operation.target.overlayId,
  );

  let sourceRuntime;
  try {
    sourceRuntime = await runtimeContext.getCompressedOverlay(
      operation.target.processor,
      operation.target.overlayId,
    );
  } catch (error) {
    if (
      error instanceof NdsError
      && error.category === "compressed-overlay-runtime-unavailable"
    ) {
      guardFailed(
        `Mutation operation ${index} cannot derive the canonical decoded overlay runtime image: ${error.message}`,
      );
    }
    throw error;
  }

  if (
    sourceRuntime.fileId !== overlay.fileId
    || sourceRuntime.storedRomOffset !== overlay.romOffset
    || sourceRuntime.storedSize !== overlay.romSize
    || sourceRuntime.runtimeSize !== overlay.ramSize
  ) {
    guardFailed(
      `Mutation operation ${index} decoded-overlay runtime context does not match the canonical overlay geometry`,
    );
  }

  assertNdsDecodedOverlaySourceGuards(
    index,
    sourceRuntime.storedSha256,
    operation.expectedStoredSha256,
    sourceRuntime.runtimeSha256,
    operation.expectedRuntimeSha256,
  );

  const artifactOptions = {
    label: `Mutation operation ${index} decoded-overlay runtime artifact`,
    aliasCategory: "unsupported-rebuild-target" as const,
  };
  const metadata = await resolveNdsArtifactMetadata(
    map,
    workspaceRoot,
    operation.replacement.artifact,
    artifactOptions,
    io,
  );
  if (metadata.size !== overlay.ramSize) {
    guardFailed(
      `Mutation operation ${index} replacement runtime image is ${metadata.size} bytes, expected exact overlay RAM size ${overlay.ramSize}`,
    );
  }

  const { bytes: replacementRuntime, verified } = await readVerifiedNdsArtifact(
    metadata,
    operation.replacement.sha256,
    artifactOptions,
    io,
  );
  if (replacementRuntime.equals(sourceRuntime.bytes)) {
    throw new NdsError(
      "mutation-no-op",
      `Mutation operation ${index} decoded-overlay replacement is byte-identical to the source runtime image`,
    );
  }

  const encoded = encodeNdsBlz(replacementRuntime);
  if (encoded.storedSize > MAX_PACKED_COMPRESSED_SIZE) {
    throw new NdsError(
      "blz-packed-size-overflow",
      `Mutation operation ${index} encoded overlay size ${encoded.storedSize} exceeds the 24-bit overlay-table field`,
    );
  }

  return {
    operationIndex: index,
    processor: operation.target.processor,
    overlayId: operation.target.overlayId,
    fileId: overlay.fileId,
    sourceStoredStart: overlay.romOffset,
    sourceStoredEnd: overlay.romOffset + overlay.romSize,
    sourceStoredSha256: sourceRuntime.storedSha256,
    sourceRuntimeSha256: sourceRuntime.runtimeSha256,
    replacementRuntimeWorkspacePath: verified.workspacePath,
    replacementRuntimeAbsolutePath: verified.absolutePath,
    replacementRuntimeSha256: verified.sha256,
    runtimeSize: replacementRuntime.length,
    encodedBytes: encoded.bytes,
    encodedSha256: encoded.storedSha256,
    encodedSize: encoded.storedSize,
  };
}
