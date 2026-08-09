import { createHash } from "node:crypto";
import { lstat as nativeLstat, stat } from "node:fs/promises";
import path from "node:path";

import { resolveInside } from "../../../security/paths.js";
import { NdsError } from "../errors.js";
import { hashFileSha256 } from "../io.js";
import type { NdsRomMap } from "../rom-map.js";

export interface NdsArtifactStat {
  isFile(): boolean;
  isSymbolicLink(): boolean;
  readonly size: number;
  readonly dev?: number;
  readonly ino?: number;
}

export interface NdsArtifactIo {
  lstat(filePath: string): Promise<NdsArtifactStat>;
  readFile?(filePath: string): Promise<Buffer>;
  hashFileSha256?(filePath: string): Promise<string>;
}

export interface NdsResolvedArtifactMetadata {
  readonly absolutePath: string;
  readonly workspacePath: string;
  readonly size: number;
  readonly device: number | null;
  readonly inode: number | null;
}

export interface NdsVerifiedArtifact extends NdsResolvedArtifactMetadata {
  readonly sha256: string;
}

export interface NdsArtifactGuardOptions {
  readonly label: string;
  readonly aliasCategory: "unsupported-mutation-target" | "unsupported-rebuild-target";
}

const defaultIo: NdsArtifactIo = {
  lstat: nativeLstat,
  hashFileSha256,
};

function workspaceRelativePath(workspaceRoot: string, absolutePath: string): string {
  return path
    .relative(path.resolve(workspaceRoot), path.resolve(absolutePath))
    .split(path.sep)
    .join("/");
}

function missingArtifact(label: string, message: string): NdsError<"replacement-artifact-missing"> {
  return new NdsError("replacement-artifact-missing", `${label}: ${message}`);
}

async function assertNotSourceAlias(
  map: NdsRomMap,
  metadata: NdsResolvedArtifactMetadata,
  options: NdsArtifactGuardOptions,
): Promise<void> {
  if (path.resolve(metadata.absolutePath) === path.resolve(map.romPath)) {
    throw new NdsError(
      options.aliasCategory,
      `${options.label} may not alias the immutable source ROM`,
    );
  }
  if (metadata.device === null || metadata.inode === null) {
    return;
  }
  const sourceInfo = await stat(map.romPath);
  if (metadata.device === sourceInfo.dev && metadata.inode === sourceInfo.ino) {
    throw new NdsError(
      options.aliasCategory,
      `${options.label} may not hard-link to the immutable source ROM`,
    );
  }
}

export async function resolveNdsArtifactMetadata(
  map: NdsRomMap,
  workspaceRoot: string,
  requestedPath: string,
  options: NdsArtifactGuardOptions,
  io: NdsArtifactIo = defaultIo,
): Promise<NdsResolvedArtifactMetadata> {
  let absolutePath: string;
  try {
    absolutePath = resolveInside(workspaceRoot, requestedPath);
  } catch (error) {
    throw missingArtifact(
      options.label,
      `path ${JSON.stringify(requestedPath)} is outside the configured workspace: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  let info: NdsArtifactStat;
  try {
    info = await io.lstat(absolutePath);
  } catch (error) {
    throw missingArtifact(
      options.label,
      `path ${JSON.stringify(requestedPath)} is unavailable: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!info.isFile() || info.isSymbolicLink()) {
    throw missingArtifact(
      options.label,
      `path ${JSON.stringify(requestedPath)} must be a regular non-symlink file`,
    );
  }
  if (!Number.isSafeInteger(info.size) || info.size < 0) {
    throw missingArtifact(options.label, `path ${JSON.stringify(requestedPath)} has an invalid file size`);
  }

  const metadata: NdsResolvedArtifactMetadata = {
    absolutePath,
    workspacePath: workspaceRelativePath(workspaceRoot, absolutePath),
    size: info.size,
    device: info.dev ?? null,
    inode: info.ino ?? null,
  };
  await assertNotSourceAlias(map, metadata, options);
  return metadata;
}

async function calculateArtifactSha256(
  metadata: NdsResolvedArtifactMetadata,
  options: NdsArtifactGuardOptions,
  io: NdsArtifactIo,
): Promise<string> {
  if (io.hashFileSha256 !== undefined) {
    try {
      return await io.hashFileSha256(metadata.absolutePath);
    } catch (error) {
      throw missingArtifact(
        options.label,
        `unable to hash artifact: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
  if (io.readFile === undefined) {
    throw missingArtifact(options.label, "artifact IO cannot read or hash the resolved file");
  }
  let bytes: Buffer;
  try {
    bytes = await io.readFile(metadata.absolutePath);
  } catch (error) {
    throw missingArtifact(
      options.label,
      `unable to read artifact: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (bytes.length !== metadata.size) {
    throw missingArtifact(
      options.label,
      `artifact changed size from ${metadata.size} to ${bytes.length} bytes during validation`,
    );
  }
  return createHash("sha256").update(bytes).digest("hex");
}

export async function verifyNdsArtifactSha256(
  metadata: NdsResolvedArtifactMetadata,
  expectedSha256: string,
  options: NdsArtifactGuardOptions,
  io: NdsArtifactIo = defaultIo,
): Promise<NdsVerifiedArtifact> {
  const actualSha256 = await calculateArtifactSha256(metadata, options, io);
  if (actualSha256 !== expectedSha256) {
    throw new NdsError(
      "replacement-artifact-hash-mismatch",
      `${options.label} SHA-256 is ${actualSha256}, expected ${expectedSha256}`,
    );
  }
  return { ...metadata, sha256: actualSha256 };
}

export async function readVerifiedNdsArtifact(
  metadata: NdsResolvedArtifactMetadata,
  expectedSha256: string,
  options: NdsArtifactGuardOptions,
  io: NdsArtifactIo,
): Promise<{ readonly bytes: Buffer; readonly verified: NdsVerifiedArtifact }> {
  if (io.readFile === undefined) {
    throw missingArtifact(options.label, "artifact IO cannot read the resolved file");
  }
  let bytes: Buffer;
  try {
    bytes = await io.readFile(metadata.absolutePath);
  } catch (error) {
    throw missingArtifact(
      options.label,
      `unable to read artifact: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (bytes.length !== metadata.size) {
    throw missingArtifact(
      options.label,
      `artifact changed size from ${metadata.size} to ${bytes.length} bytes during validation`,
    );
  }
  const actualSha256 = createHash("sha256").update(bytes).digest("hex");
  if (actualSha256 !== expectedSha256) {
    throw new NdsError(
      "replacement-artifact-hash-mismatch",
      `${options.label} SHA-256 is ${actualSha256}, expected ${expectedSha256}`,
    );
  }
  return {
    bytes,
    verified: { ...metadata, sha256: actualSha256 },
  };
}
