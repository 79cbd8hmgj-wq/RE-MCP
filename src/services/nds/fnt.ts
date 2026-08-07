import { open } from "node:fs/promises";

import { NdsError } from "./errors.js";
import type { NdsFatEntry } from "./fat.js";
import type { ParsedNdsHeader } from "./header.js";
import { readExact } from "./io.js";

const ROOT_DIRECTORY_ID = 0xf000;
const DIRECTORY_ID_MASK = 0x0fff;

export interface NdsDirectory {
  readonly directoryId: number;
  readonly parentDirectoryId: number | null;
  readonly path: string;
  readonly firstFileId: number;
}

export interface NdsNitroFile extends NdsFatEntry {
  readonly path: string | null;
}

export interface NdsFilesystem {
  readonly directories: readonly NdsDirectory[];
  readonly files: readonly NdsNitroFile[];
}

interface FntMainRecord {
  readonly directoryId: number;
  readonly subtableOffset: number;
  readonly firstFileId: number;
  readonly parentOrDirectoryCount: number;
}

function validateDirectoryId(directoryId: number, directoryCount: number): number {
  if ((directoryId & 0xf000) !== ROOT_DIRECTORY_ID) {
    throw new NdsError("malformed-fnt", `Invalid FNT directory ID 0x${directoryId.toString(16)}`);
  }
  const index = directoryId & DIRECTORY_ID_MASK;
  if (index >= directoryCount) {
    throw new NdsError(
      "malformed-fnt",
      `FNT directory ID 0x${directoryId.toString(16)} exceeds the directory table`,
    );
  }
  return index;
}

function validatePathSegment(segment: string): void {
  if (
    segment.length === 0
    || segment === "."
    || segment === ".."
    || segment.includes("/")
    || segment.includes("\\")
    || segment.includes("\0")
  ) {
    throw new NdsError("malformed-fnt", `Invalid NitroFS path segment ${JSON.stringify(segment)}`);
  }
}

function joinNitroPath(parent: string, segment: string): string {
  return parent.length === 0 ? segment : `${parent}/${segment}`;
}

export async function parseNdsFnt(
  parsed: ParsedNdsHeader,
  fat: readonly NdsFatEntry[],
): Promise<NdsFilesystem> {
  const region = parsed.header.fnt;
  if (region.size === 0) {
    return {
      directories: [],
      files: fat.map((entry) => ({ ...entry, path: null })),
    };
  }
  if (region.size < 8) {
    throw new NdsError("malformed-fnt", "NDS FNT is too short for a root directory record");
  }

  const handle = await open(parsed.romPath, "r");
  let buffer: Buffer;
  try {
    buffer = await readExact(handle, region.offset, region.size, "NDS FNT");
  } finally {
    await handle.close();
  }

  const directoryCount = buffer.readUInt16LE(6);
  if (directoryCount < 1 || directoryCount > 0x1000) {
    throw new NdsError("malformed-fnt", `Invalid FNT directory count ${directoryCount}`);
  }
  const mainTableBytes = directoryCount * 8;
  if (mainTableBytes > buffer.length) {
    throw new NdsError("malformed-fnt", "FNT directory table extends beyond the FNT region");
  }

  const records: FntMainRecord[] = [];
  for (let index = 0; index < directoryCount; index += 1) {
    const base = index * 8;
    records.push({
      directoryId: ROOT_DIRECTORY_ID + index,
      subtableOffset: buffer.readUInt32LE(base),
      firstFileId: buffer.readUInt16LE(base + 4),
      parentOrDirectoryCount: buffer.readUInt16LE(base + 6),
    });
  }

  const root = records[0];
  if (root === undefined || root.parentOrDirectoryCount !== directoryCount) {
    throw new NdsError("malformed-fnt", "FNT root directory count does not match the main table");
  }
  for (let index = 1; index < records.length; index += 1) {
    const record = records[index];
    if (record === undefined) {
      throw new NdsError("malformed-fnt", `Missing FNT directory record ${index}`);
    }
    validateDirectoryId(record.parentOrDirectoryCount, directoryCount);
  }

  const visiting = new Set<number>();
  const visited = new Set<number>();
  const directories = new Map<number, NdsDirectory>();
  const filePaths = new Map<number, string>();

  function recordFor(directoryId: number): FntMainRecord {
    const index = validateDirectoryId(directoryId, directoryCount);
    const record = records[index];
    if (record === undefined) {
      throw new NdsError("malformed-fnt", `Missing FNT directory record ${index}`);
    }
    return record;
  }

  function visitDirectory(
    directoryId: number,
    directoryPath: string,
    parentDirectoryId: number | null,
  ): void {
    if (visiting.has(directoryId)) {
      throw new NdsError(
        "malformed-fnt",
        `FNT directory cycle detected at 0x${directoryId.toString(16)}`,
      );
    }
    const existing = directories.get(directoryId);
    if (visited.has(directoryId)) {
      if (
        existing === undefined
        || existing.path !== directoryPath
        || existing.parentDirectoryId !== parentDirectoryId
      ) {
        throw new NdsError(
          "malformed-fnt",
          `FNT directory 0x${directoryId.toString(16)} is referenced inconsistently`,
        );
      }
      return;
    }

    const record = recordFor(directoryId);
    if (directoryId !== ROOT_DIRECTORY_ID && record.parentOrDirectoryCount !== parentDirectoryId) {
      throw new NdsError(
        "malformed-fnt",
        `FNT directory 0x${directoryId.toString(16)} has an inconsistent parent`,
      );
    }
    if (record.subtableOffset < mainTableBytes || record.subtableOffset >= buffer.length) {
      throw new NdsError(
        "malformed-fnt",
        `FNT directory 0x${directoryId.toString(16)} has an invalid subtable offset`,
      );
    }

    visiting.add(directoryId);
    directories.set(directoryId, {
      directoryId,
      parentDirectoryId,
      path: directoryPath,
      firstFileId: record.firstFileId,
    });

    let cursor = record.subtableOffset;
    let fileId = record.firstFileId;
    for (;;) {
      if (cursor >= buffer.length) {
        throw new NdsError(
          "malformed-fnt",
          `FNT directory 0x${directoryId.toString(16)} is not terminated`,
        );
      }
      const descriptor = buffer[cursor];
      if (descriptor === undefined) {
        throw new NdsError("malformed-fnt", "Unexpected end of FNT subtable");
      }
      cursor += 1;
      if (descriptor === 0) {
        break;
      }

      const nameLength = descriptor & 0x7f;
      const isDirectory = (descriptor & 0x80) !== 0;
      if (nameLength === 0 || cursor + nameLength > buffer.length) {
        throw new NdsError("malformed-fnt", "Malformed FNT name entry");
      }
      const segment = buffer.subarray(cursor, cursor + nameLength).toString("latin1");
      cursor += nameLength;
      validatePathSegment(segment);

      if (isDirectory) {
        if (cursor + 2 > buffer.length) {
          throw new NdsError("malformed-fnt", "Truncated FNT child directory entry");
        }
        const childDirectoryId = buffer.readUInt16LE(cursor);
        cursor += 2;
        validateDirectoryId(childDirectoryId, directoryCount);
        visitDirectory(
          childDirectoryId,
          joinNitroPath(directoryPath, segment),
          directoryId,
        );
        continue;
      }

      if (fileId >= fat.length) {
        throw new NdsError(
          "malformed-fnt",
          `FNT file ID ${fileId} does not exist in the FAT`,
        );
      }
      if (filePaths.has(fileId)) {
        throw new NdsError("malformed-fnt", `FNT file ID ${fileId} is named more than once`);
      }
      filePaths.set(fileId, joinNitroPath(directoryPath, segment));
      fileId += 1;
    }

    visiting.delete(directoryId);
    visited.add(directoryId);
  }

  visitDirectory(ROOT_DIRECTORY_ID, "", null);
  if (visited.size !== directoryCount) {
    throw new NdsError("malformed-fnt", "FNT contains unreachable directory records");
  }

  return {
    directories: [...directories.values()].sort((left, right) => left.directoryId - right.directoryId),
    files: fat.map((entry) => ({
      ...entry,
      path: filePaths.get(entry.fileId) ?? null,
    })),
  };
}
