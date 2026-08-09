import { createHash } from "node:crypto";
import { lstat, open, stat } from "node:fs/promises";
import path from "node:path";

import { resolveInside } from "../../../security/paths.js";
import { decodeNdsBlz } from "../blz.js";
import { NdsError } from "../errors.js";
import { hashFileSha256, readExact } from "../io.js";
import type { NdsOverlay } from "../overlays.js";
import type { NdsRomMap } from "../rom-map.js";
import type {
  NdsMutationOperation,
  NdsReplaceBytesOperation,
  NdsReplaceComponentOperation,
} from "./manifest.js";
import {
  assertMutationRangeOutsideStructure,
  resolveNdsMutationByteTarget,
  resolveNdsMutationComponent,
  type NdsResolvedMutationComponent,
} from "./selectors.js";

const HASH_CHUNK_BYTES = 64 * 1024;

interface GuardedNdsMutationBase {
  readonly index: number;
  readonly component: NdsResolvedMutationComponent;
  readonly romStart: number;
  readonly romEnd: number;
  readonly size: number;
}

export interface GuardedNdsByteOperation extends GuardedNdsMutationBase {
  readonly type: "replace-bytes";
  readonly target: NdsReplaceBytesOperation["target"];
  readonly expected: string;
  readonly replacement: string;
}

export interface GuardedNdsComponentOperation extends GuardedNdsMutationBase {
  readonly type: "replace-component";
  readonly target: NdsReplaceComponentOperation["target"];
  readonly expectedOriginalSha256: string;
  readonly originalSha256: string;
  readonly replacement: Readonly<{
    readonly absolutePath: string;
    readonly workspacePath: string;
    readonly sha256: string;
    readonly size: number;
  }>;
}

export type GuardedNdsMutationOperation =
  | GuardedNdsByteOperation
  | GuardedNdsComponentOperation;

interface ResolvedReplacementArtifact {
  readonly absolutePath: string;
  readonly workspacePath: string;
  readonly size: number;
  readonly device: number;
  readonly inode: number;
}

function sourceMismatch(message: string): NdsError<"source-rom-mismatch"> {
  return new NdsError("source-rom-mismatch", message);
}

export async function assertNdsMutationSourceIdentity(
  map: NdsRomMap,
  expectedSha256: string,
): Promise<void> {
  if (map.sha256 !== expectedSha256) {
    throw sourceMismatch(
      "Canonical NDS map SHA-256 does not match the mutation manifest source identity",
    );
  }
  let actualSha256: string;
  try {
    actualSha256 = await hashFileSha256(map.romPath);
  } catch (error) {
    throw sourceMismatch(
      `Unable to revalidate source ROM identity: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (actualSha256 !== expectedSha256) {
    throw sourceMismatch(
      "Source ROM changed after canonical parsing; reparse the exact source before mutation planning",
    );
  }
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
      const length = Math.min(HASH_CHUNK_BYTES, size - offset);
      const buffer = Buffer.alloc(length);
      let filled = 0;
      while (filled < length) {
        const { bytesRead } = await handle.read(
          buffer,
          filled,
          length - filled,
          start + offset + filled,
        );
        if (bytesRead === 0) {
          throw new NdsError(
            "range-out-of-bounds",
            "Component hash range extends beyond the source ROM",
          );
        }
        filled += bytesRead;
      }
      hash.update(buffer);
      offset += length;
    }
  } finally {
    await handle.close();
  }
  return hash.digest("hex");
}

function workspaceRelativePath(workspaceRoot: string, absolutePath: string): string {
  return path
    .relative(path.resolve(workspaceRoot), absolutePath)
    .split(path.sep)
    .join("/");
}

function overlayForOwner(
  map: NdsRomMap,
  processor: "arm9" | "arm7",
  overlayId: number,
): NdsOverlay {
  const overlays = processor === "arm9" ? map.overlays.arm9 : map.overlays.arm7;
  const overlay = overlays.find((candidate) => candidate.overlayId === overlayId);
  if (overlay === undefined) {
    throw new NdsError(
      "compressed-overlay-invalid",
      `${processor.toUpperCase()} overlay ${overlayId} disappeared from the canonical map`,
    );
  }
  return overlay;
}

async function validateCompressedReplacement(
  map: NdsRomMap,
  component: NdsResolvedMutationComponent,
  artifactPath: string,
): Promise<void> {
  const compressedOwners = component.overlayOwners.filter((owner) => owner.compressed);
  if (compressedOwners.length === 0) {
    return;
  }

  const handle = await open(artifactPath, "r");
  try {
    for (const owner of compressedOwners) {
      const overlay = overlayForOwner(map, owner.processor, owner.overlayId);
      if (
        overlay.compressedSize < 8
        || overlay.compressedSize > overlay.romSize
        || overlay.romSize !== component.size
      ) {
        throw new NdsError(
          "compressed-overlay-invalid",
          `${owner.processor.toUpperCase()} overlay ${owner.overlayId} has incompatible stored compression geometry`,
        );
      }
      try {
        const payload = await readExact(
          handle,
          0,
          overlay.compressedSize,
          `${owner.processor.toUpperCase()} overlay ${owner.overlayId} replacement BLZ payload`,
        );
        const decoded = decodeNdsBlz(payload, overlay.ramSize);
        if (decoded.bytes.length !== overlay.ramSize) {
          throw new Error("decoded runtime size does not match canonical overlay RAM size");
        }
      } catch (error) {
        if (error instanceof NdsError && error.category === "compressed-overlay-invalid") {
          throw error;
        }
        throw new NdsError(
          "compressed-overlay-invalid",
          `${owner.processor.toUpperCase()} overlay ${owner.overlayId} replacement is not a valid canonical stored BLZ component: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  } finally {
    await handle.close();
  }
}

async function guardByteOperation(
  map: NdsRomMap,
  index: number,
  operation: NdsReplaceBytesOperation,
): Promise<GuardedNdsByteOperation> {
  const expected = Buffer.from(operation.expected, "hex");
  const range = resolveNdsMutationByteTarget(map, operation.target, expected.length);
  const handle = await open(map.romPath, "r");
  let actual: Buffer;
  try {
    actual = await readExact(
      handle,
      range.romStart,
      range.size,
      `Mutation operation ${index} expected bytes`,
    );
  } finally {
    await handle.close();
  }
  if (!actual.equals(expected)) {
    throw new NdsError(
      "original-byte-guard-failed",
      `Mutation operation ${index} expected original bytes ${operation.expected} but source contains ${actual.toString("hex")}`,
    );
  }
  return {
    type: "replace-bytes",
    index,
    target: operation.target,
    component: range.component,
    romStart: range.romStart,
    romEnd: range.romEnd,
    size: range.size,
    expected: operation.expected,
    replacement: operation.replacement,
  };
}

async function resolveReplacementArtifact(
  workspaceRoot: string,
  requestedPath: string,
): Promise<ResolvedReplacementArtifact> {
  try {
    const absolutePath = resolveInside(workspaceRoot, requestedPath);
    const info = await lstat(absolutePath);
    if (!info.isFile() || info.isSymbolicLink()) {
      throw new Error("replacement artifact must be a regular non-symlink file");
    }
    return {
      absolutePath,
      workspacePath: workspaceRelativePath(workspaceRoot, absolutePath),
      size: info.size,
      device: info.dev,
      inode: info.ino,
    };
  } catch (error) {
    throw new NdsError(
      "replacement-artifact-missing",
      `Replacement artifact ${JSON.stringify(requestedPath)} is unavailable inside the workspace: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

async function assertArtifactIsNotSource(
  map: NdsRomMap,
  artifact: ResolvedReplacementArtifact,
): Promise<void> {
  const sourceInfo = await stat(map.romPath);
  const samePath = path.resolve(artifact.absolutePath) === path.resolve(map.romPath);
  const sameFile = artifact.device === sourceInfo.dev && artifact.inode === sourceInfo.ino;
  if (samePath || sameFile) {
    throw new NdsError(
      "unsupported-mutation-target",
      "Replacement artifact may not alias the immutable source ROM",
    );
  }
}

async function guardComponentOperation(
  map: NdsRomMap,
  workspaceRoot: string,
  index: number,
  operation: NdsReplaceComponentOperation,
): Promise<GuardedNdsComponentOperation> {
  const component = resolveNdsMutationComponent(map, operation.target);
  assertMutationRangeOutsideStructure(map, component.romStart, component.romEnd);

  const originalSha256 = await hashFileRangeSha256(
    map.romPath,
    component.romStart,
    component.size,
  );
  if (originalSha256 !== operation.expectedOriginalSha256) {
    throw new NdsError(
      "original-component-guard-failed",
      `Mutation operation ${index} source component SHA-256 is ${originalSha256}, expected ${operation.expectedOriginalSha256}`,
    );
  }

  const artifact = await resolveReplacementArtifact(
    workspaceRoot,
    operation.replacement.artifact,
  );
  await assertArtifactIsNotSource(map, artifact);
  if (artifact.size !== component.size) {
    throw new NdsError(
      "replacement-size-mismatch",
      `Mutation operation ${index} replacement is ${artifact.size} bytes, expected exact stored size ${component.size}`,
    );
  }

  let artifactSha256: string;
  try {
    artifactSha256 = await hashFileSha256(artifact.absolutePath);
  } catch (error) {
    throw new NdsError(
      "replacement-artifact-missing",
      `Unable to hash replacement artifact: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (artifactSha256 !== operation.replacement.sha256) {
    throw new NdsError(
      "replacement-artifact-hash-mismatch",
      `Mutation operation ${index} replacement SHA-256 is ${artifactSha256}, expected ${operation.replacement.sha256}`,
    );
  }
  if (artifactSha256 === originalSha256) {
    throw new NdsError(
      "mutation-no-op",
      `Mutation operation ${index} replacement is byte-identical to the source component`,
    );
  }

  await validateCompressedReplacement(map, component, artifact.absolutePath);

  return {
    type: "replace-component",
    index,
    target: operation.target,
    component,
    romStart: component.romStart,
    romEnd: component.romEnd,
    size: component.size,
    expectedOriginalSha256: operation.expectedOriginalSha256,
    originalSha256,
    replacement: {
      absolutePath: artifact.absolutePath,
      workspacePath: artifact.workspacePath,
      sha256: artifactSha256,
      size: artifact.size,
    },
  };
}

export async function guardNdsMutationOperation(
  map: NdsRomMap,
  workspaceRoot: string,
  index: number,
  operation: NdsMutationOperation,
): Promise<GuardedNdsMutationOperation> {
  return operation.type === "replace-bytes"
    ? await guardByteOperation(map, index, operation)
    : await guardComponentOperation(map, workspaceRoot, index, operation);
}
