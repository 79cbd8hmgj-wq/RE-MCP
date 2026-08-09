import { createHash } from "node:crypto";
import {
  lstat as nativeLstat,
  open,
  readFile as nativeReadFile,
} from "node:fs/promises";

import { NdsError } from "../errors.js";
import type { NdsRomMap } from "../rom-map.js";
import {
  readVerifiedNdsArtifact,
  resolveNdsArtifactMetadata,
  type NdsArtifactIo,
} from "./artifacts.js";
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

export interface NdsFilesystemPlanningIo extends NdsArtifactIo {
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
  readonly metadata: Awaited<ReturnType<typeof resolveNdsArtifactMetadata>>;
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
  const result: string[] = [];
  for (let length = 1; length < segments.length; length += 1) {
    result.push(segments.slice(0, length).join("/"));
  }
  return result;
}

function parentPath(directoryPath: string): string {
  const separator = directoryPath.lastIndexOf("/");
  return separator < 0 ? "" : directoryPath.slice(0, separator);
}

function lexicographicDirectoryPreorder(
  directoryPaths: ReadonlySet<string>,
): readonly string[] {
  const children = new Map<string, string[]>();
  for (const directoryPath of directoryPaths) {
    const parent = parentPath(directoryPath);
    const siblings = children.get(parent) ?? [];
    siblings.push(directoryPath);
    children.set(parent, siblings);
  }
  for (const siblings of children.values()) {
    siblings.sort((left, right) => lexical(left, right));
  }

  const ordered: string[] = [];
  function visit(parent: string): void {
    for (const child of children.get(parent) ?? []) {
      ordered.push(child);
      visit(child);
    }
  }
  visit("");
  if (ordered.length !== directoryPaths.size) {
    throw extensionError(
      "New NitroFS directory tree traversal did not account for every planned directory",
    );
  }
  return ordered;
}

async function inspectNewArtifacts(
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
    const metadata = await resolveNdsArtifactMetadata(
      map,
      workspaceRoot,
      operation.replacement.artifact,
      {
        label: `New NitroFS artifact ${operation.replacement.artifact}`,
        aliasCategory: "unsupported-rebuild-target",
      },
      io,
    );
    if (metadata.size < 1 || metadata.size > MAX_ARTIFACT_BYTES) {
      throw extensionError(
        `New NitroFS artifact ${operation.replacement.artifact} size ${metadata.size} is outside the 1..${MAX_ARTIFACT_BYTES} byte limit`,
      );
    }
    aggregateSize += metadata.size;
    if (!Number.isSafeInteger(aggregateSize) || aggregateSize > MAX_AGGREGATE_NEW_FILE_BYTES) {
      throw extensionError(
        `New NitroFS artifacts total ${aggregateSize} bytes, above the ${MAX_AGGREGATE_NEW_FILE_BYTES}-byte aggregate limit`,
      );
    }
    pending.push({
      index,
      operation,
      directoryPath: segments.slice(0, -1).join("/"),
      filename: segments.at(-1)!,
      metadata,
    });
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
  return lexicographicDirectoryPreorder(newDirectories);
}

function assignDirectoryIds(
  map: NdsRomMap,
  directoryPaths: readonly string[],
): ReadonlyMap<string, number> {
  const sourceCount = map.filesystem.directories.length;
  if (sourceCount < 1 || map.filesystem.directories[0]?.directoryId !== ROOT_DIRECTORY_ID) {
    throw extensionError("NitroFS extension requires a canonical source FNT root directory");
  }
  const finalCount = sourceCount + directoryPaths.length;
  if (finalCount > MAX_DIRECTORY_COUNT) {
    throw capacityError(
      `NitroFS extension would create ${finalCount} directories, above the ${MAX_DIRECTORY_COUNT} directory limit`,
    );
  }
  return new Map(
    directoryPaths.map((directoryPath, index) => [
      directoryPath,
      ROOT_DIRECTORY_ID + sourceCount + index,
    ]),
  );
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

  const pending = await inspectNewArtifacts(map, workspaceRoot, operations, io);
  const directoryPaths = validatePathOwnership(map, pending);
  const directoryIds = assignDirectoryIds(map, directoryPaths);
  const pendingByDirectory = new Map<string, PendingAddedFile[]>();
  for (const item of pending) {
    const files = pendingByDirectory.get(item.directoryPath) ?? [];
    files.push(item);
    pendingByDirectory.set(item.directoryPath, files);
  }
  for (const files of pendingByDirectory.values()) {
    files.sort((left, right) => lexical(left.filename, right.filename));
  }

  const firstFileIds = new Map<string, number>();
  const assigned = new Map<number, { readonly fileId: number; readonly directoryId: number }>();
  let nextFileId = map.fat.length;
  for (const directoryPath of directoryPaths) {
    firstFileIds.set(directoryPath, nextFileId);
    const directoryId = directoryIds.get(directoryPath)!;
    for (const item of pendingByDirectory.get(directoryPath) ?? []) {
      assigned.set(item.index, { fileId: nextFileId, directoryId });
      nextFileId += 1;
    }
  }
  if (nextFileId !== map.fat.length + operations.length) {
    throw extensionError("NitroFS extension file-ID assignment did not account for every new file");
  }

  const addedDirectories: NdsAddedDirectoryPlan[] = directoryPaths.map((directoryPath) => {
    const parent = parentPath(directoryPath);
    const parentDirectoryId = parent.length === 0
      ? ROOT_DIRECTORY_ID
      : directoryIds.get(parent);
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
    const { bytes, verified } = await readVerifiedNdsArtifact(
      item.metadata,
      item.operation.replacement.sha256,
      {
        label: `New NitroFS artifact ${item.operation.replacement.artifact}`,
        aliasCategory: "unsupported-rebuild-target",
      },
      io,
    );
    addedFiles.push({
      operationIndex: item.index,
      path: item.operation.path,
      fileId: identity.fileId,
      directoryId: identity.directoryId,
      filename: item.filename,
      replacementWorkspacePath: verified.workspacePath,
      replacementAbsolutePath: verified.absolutePath,
      replacementSha256: verified.sha256,
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

function variableFileSelector(target: NdsReplaceNitroFsFileOperation["target"]) {
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

  const metadata = await resolveNdsArtifactMetadata(
    map,
    workspaceRoot,
    operation.replacement.artifact,
    {
      label: `Mutation operation ${index} replacement artifact`,
      aliasCategory: "unsupported-rebuild-target",
    },
    io,
  );
  if (metadata.size < 1 || metadata.size > MAX_ARTIFACT_BYTES) {
    throw rebuildTargetError(
      `Mutation operation ${index} replacement size ${metadata.size} is outside the 1..${MAX_ARTIFACT_BYTES} byte limit`,
    );
  }
  const { bytes, verified } = await readVerifiedNdsArtifact(
    metadata,
    operation.replacement.sha256,
    {
      label: `Mutation operation ${index} replacement artifact`,
      aliasCategory: "unsupported-rebuild-target",
    },
    io,
  );
  if (verified.sha256 === sourceSha256) {
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
    replacementWorkspacePath: verified.workspacePath,
    replacementAbsolutePath: verified.absolutePath,
    replacementSha256: verified.sha256,
    replacementSize: bytes.length,
  };
}
