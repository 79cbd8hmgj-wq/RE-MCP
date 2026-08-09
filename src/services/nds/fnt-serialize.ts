import { NdsError } from "./errors.js";
import type { NdsDirectory, NdsFilesystem, NdsNitroFile } from "./fnt.js";
import type {
  NdsAddedDirectoryPlan,
  NdsAddedFilePlan,
  NdsFilesystemExtensionPlan,
} from "./mutation/filesystem-plan.js";

const ROOT_DIRECTORY_ID = 0xf000;
const MAX_FNT_BYTES = 4 * 1024 * 1024;
const MAX_NAME_BYTES = 0x7f;

interface SerializableDirectory {
  readonly directoryId: number;
  readonly parentDirectoryId: number | null;
  readonly path: string;
  readonly firstFileId: number;
  readonly source: boolean;
}

function fntError(message: string): NdsError<"fnt-rebuild-failed"> {
  return new NdsError("fnt-rebuild-failed", message);
}

function lexical(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function parentPath(filePath: string): string {
  const separator = filePath.lastIndexOf("/");
  return separator < 0 ? "" : filePath.slice(0, separator);
}

function baseName(itemPath: string): string {
  const separator = itemPath.lastIndexOf("/");
  return separator < 0 ? itemPath : itemPath.slice(separator + 1);
}

function encodedName(name: string, encoding: BufferEncoding): Buffer {
  const bytes = Buffer.from(name, encoding);
  if (bytes.length < 1 || bytes.length > MAX_NAME_BYTES) {
    throw fntError(`FNT name ${JSON.stringify(name)} must encode to 1..${MAX_NAME_BYTES} bytes`);
  }
  return bytes;
}

function fileEntry(name: string, encoding: BufferEncoding): Buffer {
  const bytes = encodedName(name, encoding);
  return Buffer.concat([Buffer.from([bytes.length]), bytes]);
}

function directoryEntry(
  name: string,
  directoryId: number,
  encoding: BufferEncoding,
): Buffer {
  const bytes = encodedName(name, encoding);
  const result = Buffer.alloc(1 + bytes.length + 2);
  result.writeUInt8(0x80 | bytes.length, 0);
  bytes.copy(result, 1);
  result.writeUInt16LE(directoryId, 1 + bytes.length);
  return result;
}

function sourceFilesFor(
  filesystem: NdsFilesystem,
  directory: NdsDirectory,
): readonly NdsNitroFile[] {
  const files = filesystem.files
    .filter(
      (file) => file.path !== null && parentPath(file.path) === directory.path,
    )
    .sort((left, right) => left.fileId - right.fileId);
  if (files.length === 0) {
    return files;
  }
  if (files[0]?.fileId !== directory.firstFileId) {
    throw fntError(
      `Source directory ${directory.path || "/"} first file ID does not match canonical FNT semantics`,
    );
  }
  for (let index = 0; index < files.length; index += 1) {
    if (files[index]?.fileId !== directory.firstFileId + index) {
      throw fntError(
        `Source directory ${directory.path || "/"} contains a non-contiguous FNT file-ID run`,
      );
    }
  }
  return files;
}

function serializableDirectories(
  source: NdsFilesystem,
  extension: NdsFilesystemExtensionPlan,
): readonly SerializableDirectory[] {
  const directories: SerializableDirectory[] = [
    ...source.directories.map((directory) => ({
      ...directory,
      source: true as const,
    })),
    ...extension.addedDirectories.map((directory) => ({
      ...directory,
      source: false as const,
    })),
  ].sort((left, right) => left.directoryId - right.directoryId);

  if (directories.length !== extension.finalDirectoryCount) {
    throw fntError(
      `Planned directory count ${extension.finalDirectoryCount} does not match ${directories.length} serialized directories`,
    );
  }
  for (let index = 0; index < directories.length; index += 1) {
    const expectedId = ROOT_DIRECTORY_ID + index;
    if (directories[index]?.directoryId !== expectedId) {
      throw fntError(
        `FNT directory IDs must remain contiguous; expected 0x${expectedId.toString(16)}`,
      );
    }
  }
  if (
    directories[0]?.directoryId !== ROOT_DIRECTORY_ID
    || directories[0]?.parentDirectoryId !== null
  ) {
    throw fntError("Serialized FNT requires the canonical root directory 0xF000");
  }
  return directories;
}

function addedFilesFor(
  extension: NdsFilesystemExtensionPlan,
  directoryId: number,
): readonly NdsAddedFilePlan[] {
  return extension.addedFiles
    .filter((file) => file.directoryId === directoryId)
    .sort((left, right) => left.fileId - right.fileId || lexical(left.filename, right.filename));
}

function buildSubtable(
  source: NdsFilesystem,
  extension: NdsFilesystemExtensionPlan,
  directory: SerializableDirectory,
  allDirectories: readonly SerializableDirectory[],
): Buffer {
  const entries: Buffer[] = [];

  if (directory.source) {
    const sourceDirectory = source.directories.find(
      (candidate) => candidate.directoryId === directory.directoryId,
    );
    if (sourceDirectory === undefined) {
      throw fntError(`Missing source directory 0x${directory.directoryId.toString(16)}`);
    }
    for (const file of sourceFilesFor(source, sourceDirectory)) {
      entries.push(fileEntry(baseName(file.path!), "latin1"));
    }
  } else {
    const files = addedFilesFor(extension, directory.directoryId);
    if (files.length > 0 && files[0]?.fileId !== directory.firstFileId) {
      throw fntError(`Added directory ${directory.path} has an inconsistent first file ID`);
    }
    for (let index = 0; index < files.length; index += 1) {
      const file = files[index]!;
      if (file.fileId !== directory.firstFileId + index) {
        throw fntError(`Added directory ${directory.path} contains a non-contiguous file-ID run`);
      }
      entries.push(fileEntry(file.filename, "ascii"));
    }
  }

  const children = allDirectories
    .filter((candidate) => candidate.parentDirectoryId === directory.directoryId)
    .sort((left, right) => left.directoryId - right.directoryId || lexical(left.path, right.path));
  for (const child of children) {
    entries.push(directoryEntry(
      baseName(child.path),
      child.directoryId,
      child.source ? "latin1" : "ascii",
    ));
  }

  entries.push(Buffer.from([0]));
  return Buffer.concat(entries);
}

export function serializeExtendedNdsFnt(
  source: NdsFilesystem,
  extension: NdsFilesystemExtensionPlan,
): Buffer {
  const directories = serializableDirectories(source, extension);
  const mainTableBytes = directories.length * 8;
  if (mainTableBytes > MAX_FNT_BYTES) {
    throw fntError(`FNT main table exceeds the ${MAX_FNT_BYTES}-byte limit`);
  }

  const subtables = directories.map((directory) =>
    buildSubtable(source, extension, directory, directories));
  const totalSize = mainTableBytes
    + subtables.reduce((total, subtable) => total + subtable.length, 0);
  if (totalSize > MAX_FNT_BYTES) {
    throw fntError(`Serialized FNT is ${totalSize} bytes, above the ${MAX_FNT_BYTES}-byte limit`);
  }

  const output = Buffer.alloc(totalSize);
  let subtableOffset = mainTableBytes;
  for (let index = 0; index < directories.length; index += 1) {
    const directory = directories[index]!;
    const subtable = subtables[index]!;
    const base = index * 8;
    output.writeUInt32LE(subtableOffset, base);
    output.writeUInt16LE(directory.firstFileId, base + 4);
    output.writeUInt16LE(
      directory.directoryId === ROOT_DIRECTORY_ID
        ? directories.length
        : directory.parentDirectoryId!,
      base + 6,
    );
    subtable.copy(output, subtableOffset);
    subtableOffset += subtable.length;
  }
  if (subtableOffset !== output.length) {
    throw fntError("Serialized FNT length does not match planned subtable geometry");
  }
  return output;
}
