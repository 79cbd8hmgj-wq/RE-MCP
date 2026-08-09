import { createHash } from "node:crypto";
import {
  lstat as nativeLstat,
  open,
  readFile as nativeReadFile,
  stat,
} from "node:fs/promises";
import path from "node:path";

import { resolveInside } from "../../../security/paths.js";
import { NdsError } from "../errors.js";
import type { NdsRomMap } from "../rom-map.js";
import type {
  NdsAddNitroFsFileOperation,
  NdsReplaceNitroFsFileOperation,
} from "./manifest.js";
import { resolveNdsMutationComponent } from "./selectors.js";

const ROOT_DIRECTORY_ID = 0xf000;
const MAX_DIRECTORY_COUNT = 0x1000;
const MAX_FINAL_FILE_COUNT = 0x10000;
const MAX_NEW_FILES = 256;
const MAX_ARTIFACT_BYTES = 64 * 1024 * 1024;
const MAX_AGGREGATE_NEW_FILE_BYTES = 64 * 1024 * 1024;
const HASH_CHUNK_BYTES = 64 * 1024;

export interface NdsAddedDirectoryPlan {
  readonly path: string;
  readonly directoryId: number;
  readonly parentDirectoryId: number;
  readonly firstFileId: number;
}

export interface NdsAddedFilePlan {
  readonly operationIndex: number;
  readonly path: string;
  readonly fileId: number;
  readonly directoryId: number;
  readonly filename: string;
  readonly replacementWorkspacePath: string;
  readonly replacementAbsolutePath: string;
  readonly replacementSha256: string;
  readonly replacementSize: number;
}

export interface NdsFilesystemExtensionPlan {
  readonly addedDirectories: readonly NdsAddedDirectoryPlan[];
  readonly addedFiles: readonly NdsAddedFilePlan[];
  readonly finalDirectoryCount: number;
  readonly finalFileCount: number;
}

export interface NdsRelocatedFilePlan {
  readonly operationIndex: number;
  readonly fileId: number;
  readonly filePath: string | null;
  readonly sourceStart: number;
  readonly sourceEnd: number;
  readonly sourceSha256: string;
  readonly replacementWorkspacePath: string;
  readonly replacementAbsolutePath: string;
  readonly replacementSha256: string;
  readonly replacementSize: number;
}

export interface NdsFilesystemPlanningIo {
  lstat(filePath: string): Promise<{
    isFile(): boolean;
    isSymbolicLink(): boolean;
    readonly size: number;
    readonly dev?: number;
    readonly ino?: number;
  }>;
  readFile(filePath: string): Promise<Buffer>;
}

export type NdsVariableFilePlanningIo = NdsFilesystemPlanningIo;

const defaultIo: NdsFilesystemPlanningIo = {
  lstat: nativeLstat,
  readFile: nativeReadFile,
};

interface PendingAddedFile {
  readonly index: number;
  readonly operation: NdsAddNitroFsFileOperation;
  readonly directoryPath: string;
  readonly filename: string;
  readonly absolutePath: string;
  readonly size: number;
}

function lexical(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function extensionError(message: string): NdsError<"filesystem-extension-invalid"> {
  return new NdsError("filesystem-extension-invalid", message);
}

function rebuildTargetError(message: string): NdsError<"unsupported-rebuild-target"> {
  return new NdsError("unsupported-rebuild-target", message);
}

function capacityError(message: string): NdsError<"filesystem-id-capacity-exceeded"> {
  return new NdsError("filesystem-id-capacity-exceeded", message);
}

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function workspaceRelativePath(workspaceRoot: string, absolutePath: string): string {
  return path
    .relative(path.resolve(workspaceRoot), path.resolve(absolutePath))
    .split(path.sep)
    .join("/");
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
        if (bytesRead < 1) {
          throw new NdsError(
            "range-out-of-bounds",
            "NitroFS source hash range extends beyond the immutable source ROM",
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

async function assertArtifactDoesNotAliasSource(
  map: NdsRomMap,
  absolutePath: string,
  artifactInfo: { readonly dev?: number; readonly ino?: number },
): Promise<void> {
  if (path.resolve(absolutePath) === path.resolve(map.romPath)) {
    throw rebuildTargetError("Replacement artifact may not alias the immutable source ROM");
  }
  if (artifactInfo.dev === undefined || artifactInfo.ino === undefined) {
    return;
  }
  const sourceInfo = await stat(map.romPath);
  if (artifactInfo.dev === sourceInfo.dev && artifactInfo.ino === sourceInfo.ino) {
    throw rebuildTargetError("Replacement artifact may not hard-link to the immutable source ROM");
  }
}

function sourceTopLevelNames(map: NdsRomMap): ReadonlySet<string> {
  const names = new Set<string>();
  for (const directory of map.filesystem.directories) {
    if (directory.path.length > 0) {
      names.add(directory.path.split("/")[0]!);
    }
  }
  for (const file of map.filesystem.files) {
    if (file.path !== null && !file.path.includes("/")) {
      names.add(file.path);
    }
  }
  return names;
}

function sourcePaths(map: NdsRomMap): {
  readonly files: ReadonlySet<string>;
  readonly directories: ReadonlySet<string>;
} {
  return {
    files: new Set(
      map.filesystem.files
        .map((file) => file.path)
        .filter((value): value is string => value !== null),
    ),
    directories: new Set(
      map.filesystem.directories
        .map((directory) => directory.path)
        .filter((value) => value.length > 0),
    ),
  };
}

function directoryPathsFor(filePath: string): readonly string[] {
  const segments = filePath.split("/");
  const directories: string[] = [];
  for (let length = 1; length < segments.length; length += 1) {
    directories.push(segments.slice(0, length).join("/"));
  }
  return directories;
}

async function inspectArtifacts(
  map: NdsRomMap,
  workspaceRoot: string,
  operations: readonly { index: number; operation: NdsAddNitroFsFileOperation }[],
  io: NdsFilesystemPlanningIo,
): Promise<readonly PendingAddedFile[]> {
  const pending: PendingAddedFile[] = [];
  let aggregateSize = 0;

  for (const { index, operation } of operations) {
    const segments = operation.path.split("/");
    if (segments.length < 2) {
      throw extensionError(
        `New NitroFS path ${operation.path} must be beneath a new top-level extension directory`,
      );
    }
    const filename = segments.at(-1)!;
    const directoryPath = segments.slice(0, -1).join("/");
    const absolutePath = resolveInside(workspaceRoot, operation.replacement.artifact);

    let info;
    try {
      info = await io.lstat(absolutePath);
    } catch (error) {
      throw new NdsError(
        "replacement-artifact-missing",
        `Unable to inspect new NitroFS artifact ${operation.replacement.artifact}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    if (!info.isFile() || info.isSymbolicLink()) {
      throw new NdsError(
        "replacement-artifact-missing",
        `New NitroFS artifact ${operation.replacement.artifact} must be a regular non-symlink file`,
      );
    }
    await assertArtifactDoesNotAliasSource(map, absolutePath, info);
    if (!Number.isSafeInteger(info.size) || info.size < 1 || info.size > MAX_ARTIFACT_BYTES) {
      throw extensionError(
        `New NitroFS artifact ${operation.replacement.artifact} size ${info.size} is outside the 1..${MAX_ARTIFACT_BYTES} byte limit`,
      );
    }
    aggregateSize += info.size;
    if (!Number.isSafeInteger(aggregateSize) || aggregateSize > MAX_AGGREGATE_NEW_FILE_BYTES) {
      throw extensionError(
        `New NitroFS artifacts total ${aggregateSize} bytes, above the ${MAX_AGGREGATE_NEW_FILE_BYTES}-byte aggregate limit`,
      );
    }
    pending.push({ index, operation, directoryPath, filename, absolutePath, size: info.size });
  }

  return pending;
}

function validatePathOwnership(
  map: NdsRomMap,
  pending: readonly PendingAddedFile[],
): readonly string[] {
  const topLevelSource = sourceTopLevelNames(map);
  const source = sourcePaths(map);
  const newFiles = new Set<string>();
  const newDirectories = new Set<string>();

  for (const item of pending) {
    const topLevel = item.operation.path.split("/")[0]!;
    if (topLevelSource.has(topLevel)) {
      throw extensionError(
        `New NitroFS path ${item.operation.path} uses source-owned top-level segment ${topLevel}`,
      );
    }
    if (source.files.has(item.operation.path) || source.directories.has(item.operation.path)) {
      throw new NdsError(
        "filesystem-path-collision",
        `New NitroFS path ${item.operation.path} collides with an existing source path`,
      );
    }
    if (newFiles.has(item.operation.path)) {
      throw new NdsError(
        "filesystem-path-collision",
        `New NitroFS path ${item.operation.path} is requested more than once`,
      );
    }
    newFiles.add(item.operation.path);
    for (const directoryPath of directoryPathsFor(item.operation.path)) {
      newDirectories.add(directoryPath);
    }
  }

  for (const filePath of newFiles) {
    if (newDirectories.has(filePath)) {
      throw new NdsError(
        "filesystem-path-collision",
        `New NitroFS path ${filePath} is both a file and a directory`,
      );
    }
  }

  return [...newDirectories].sort(lexical);
}

function assignDirectoryIds(
  map: NdsRomMap,
  directoryPaths: readonly string[],
): ReadonlyMap<string, number> {
  const sourceCount = map.filesystem.directories.length;
  if (
    sourceCount < 1
    || map.filesystem.directories[0]?.directoryId !== ROOT_DIRECTORY_ID
  ) {
    throw extensionError("NitroFS extension requires a canonical source FNT root directory");
  }
  const finalCount = sourceCount + directoryPaths.length;
  if (finalCount > MAX_DIRECTORY_COUNT) {
    throw capacityError(
      `NitroFS extension would create ${finalCount} directories, above the ${MAX_DIRECTORY_COUNT} directory limit`,
    );
  }
  const result = new Map<string, number>();
  for (let index = 0; index < directoryPaths.length; index += 1) {
    result.set(directoryPaths[index]!, ROOT_DIRECTORY_ID + sourceCount + index);
  }
  return result;
}

export async function planNdsFilesystemExtensions(
  map: NdsRomMap,
  workspaceRoot: string,
  operations: readonly { index: number; operation: NdsAddNitroFsFileOperation }[],
  io: NdsFilesystemPlanningIo = defaultIo,
): Promise<NdsFilesystemExtensionPlan> {
  if (operations.length > MAX_NEW_FILES) {
    throw capacityError(
      `Mutation manifest requests ${operations.length} new NitroFS files, above the ${MAX_NEW_FILES}-file limit`,
    );
  }
  if (map.fat.length + operations.length > MAX_FINAL_FILE_COUNT) {
    throw capacityError(
      `NitroFS extension would create ${map.fat.length + operations.length} FAT entries, above the ${MAX_FINAL_FILE_COUNT} file-ID limit`,
    );
  }
  if (operations.length === 0) {
    return {
      addedDirectories: [],
      addedFiles: [],
      finalDirectoryCount: map.filesystem.directories.length,
      finalFileCount: map.fat.length,
    };
  }

  const pending = await inspectArtifacts(map, workspaceRoot, operations, io);
  const directoryPaths = validatePathOwnership(map, pending);
  const directoryIds = assignDirectoryIds(map, directoryPaths);

  const pendingByDirectory = new Map<string, PendingAddedFile[]>();
  for (const item of pending) {
    const entries = pendingByDirectory.get(item.directoryPath) ?? [];
    entries.push(item);
    pendingByDirectory.set(item.directoryPath, entries);
  }
  for (const entries of pendingByDirectory.values()) {
    entries.sort((left, right) => lexical(left.filename, right.filename));
  }

  const firstFileIds = new Map<string, number>();
  const assigned = new Map<number, { fileId: number; directoryId: number }>();
  let nextFileId = map.fat.length;
  for (const directoryPath of directoryPaths) {
    const directoryId = directoryIds.get(directoryPath)!;
    firstFileIds.set(directoryPath, nextFileId);
    for (const item of pendingByDirectory.get(directoryPath) ?? []) {
      assigned.set(item.index, { fileId: nextFileId, directoryId });
      nextFileId += 1;
    }
  }
  if (nextFileId !== map.fat.length + operations.length) {
    throw extensionError("NitroFS extension file-ID assignment did not account for every new file");
  }

  const addedDirectories: NdsAddedDirectoryPlan[] = directoryPaths.map((directoryPath) => {
    const separator = directoryPath.lastIndexOf("/");
    const parentPath = separator < 0 ? "" : directoryPath.slice(0, separator);
    const parentDirectoryId = parentPath.length === 0
      ? ROOT_DIRECTORY_ID
      : directoryIds.get(parentPath);
    if (parentDirectoryId === undefined) {
      throw extensionError(`Missing planned parent directory for ${directoryPath}`);
    }
    return {
      path: directoryPath,
      directoryId: directoryIds.get(directoryPath)!,
      parentDirectoryId,
      firstFileId: firstFileIds.get(directoryPath)!,
    };
  });

  const addedFiles: NdsAddedFilePlan[] = [];
  for (const item of pending) {
    const identity = assigned.get(item.index);
    if (identity === undefined) {
      throw extensionError(`Missing planned file ID for ${item.operation.path}`);
    }
    const bytes = await io.readFile(item.absolutePath);
    if (bytes.length !== item.size) {
      throw extensionError(
        `New NitroFS artifact ${item.operation.replacement.artifact} changed size during planning`,
      );
    }
    const actualSha256 = sha256(bytes);
    if (actualSha256 !== item.operation.replacement.sha256) {
      throw new NdsError(
        "replacement-artifact-hash-mismatch",
        `New NitroFS artifact ${item.operation.replacement.artifact} SHA-256 is ${actualSha256}, expected ${item.operation.replacement.sha256}`,
      );
    }
    addedFiles.push({
      operationIndex: item.index,
      path: item.operation.path,
      fileId: identity.fileId,
      directoryId: identity.directoryId,
      filename: item.filename,
      replacementWorkspacePath: workspaceRelativePath(workspaceRoot, item.absolutePath),
      replacementAbsolutePath: item.absolutePath,
      replacementSha256: actualSha256,
      replacementSize: bytes.length,
    });
  }
  addedFiles.sort((left, right) => left.fileId - right.fileId);

  return {
    addedDirectories,
    addedFiles,
    finalDirectoryCount: map.filesystem.directories.length + addedDirectories.length,
    finalFileCount: nextFileId,
  };
}

function variableFileSelector(
  target: NdsReplaceNitroFsFileOperation["target"],
) {
  return "fileId" in target
    ? { component: "nitrofs-file" as const, fileId: target.fileId }
    : { component: "nitrofs-path" as const, filePath: target.filePath };
}

export async function planNdsVariableFileReplacement(
  map: NdsRomMap,
  workspaceRoot: string,
  index: number,
  operation: NdsReplaceNitroFsFileOperation,
  io: NdsVariableFilePlanningIo = defaultIo,
): Promise<NdsRelocatedFilePlan> {
  let component;
  try {
    component = resolveNdsMutationComponent(map, variableFileSelector(operation.target));
  } catch (error) {
    if (error instanceof NdsError && error.category === "unsupported-mutation-target") {
      throw rebuildTargetError(
        `NitroFS file selected by operation ${index} is overlay-backed and must use decoded-overlay rebuild semantics`,
      );
    }
    throw error;
  }
  if (component.fileId === null || component.processor !== null || component.overlayId !== null) {
    throw rebuildTargetError(`Mutation operation ${index} does not resolve to one ordinary NitroFS file`);
  }

  const sourceSha256 = await hashFileRangeSha256(
    map.romPath,
    component.romStart,
    component.size,
  );
  if (sourceSha256 !== operation.expectedOriginalSha256) {
    throw new NdsError(
      "original-component-guard-failed",
      `Mutation operation ${index} source NitroFS file SHA-256 is ${sourceSha256}, expected ${operation.expectedOriginalSha256}`,
    );
  }

  const absolutePath = resolveInside(workspaceRoot, operation.replacement.artifact);
  let info;
  try {
    info = await io.lstat(absolutePath);
  } catch (error) {
    throw new NdsError(
      "replacement-artifact-missing",
      `Replacement artifact ${operation.replacement.artifact} is unavailable inside the workspace: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new NdsError(
      "replacement-artifact-missing",
      `Replacement artifact ${operation.replacement.artifact} must be a regular non-symlink file`,
    );
  }
  await assertArtifactDoesNotAliasSource(map, absolutePath, info);
  if (!Number.isSafeInteger(info.size) || info.size < 1 || info.size > MAX_ARTIFACT_BYTES) {
    throw rebuildTargetError(
      `Mutation operation ${index} replacement size ${info.size} is outside the 1..${MAX_ARTIFACT_BYTES} byte limit`,
    );
  }

  const replacementBytes = await io.readFile(absolutePath);
  if (replacementBytes.length !== info.size) {
    throw rebuildTargetError(
      `Mutation operation ${index} replacement artifact changed size during planning`,
    );
  }
  const replacementSha256 = sha256(replacementBytes);
  if (replacementSha256 !== operation.replacement.sha256) {
    throw new NdsError(
      "replacement-artifact-hash-mismatch",
      `Mutation operation ${index} replacement SHA-256 is ${replacementSha256}, expected ${operation.replacement.sha256}`,
    );
  }
  if (replacementSha256 === sourceSha256) {
    throw new NdsError(
      "mutation-no-op",
      `Mutation operation ${index} replacement is byte-identical to the source NitroFS file`,
    );
  }

  return {
    operationIndex: index,
    fileId: component.fileId,
    filePath: component.filePath,
    sourceStart: component.romStart,
    sourceEnd: component.romEnd,
    sourceSha256,
    replacementWorkspacePath: workspaceRelativePath(workspaceRoot, absolutePath),
    replacementAbsolutePath: absolutePath,
    replacementSha256,
    replacementSize: replacementBytes.length,
  };
}
