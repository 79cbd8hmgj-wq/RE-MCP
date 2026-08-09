import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import { hashFileSha256 } from "../../src/services/nds/io.js";
import { readNdsRomMap, type NdsRomMap } from "../../src/services/nds/rom-map.js";
import {
  COMPRESSED_ARM_CODE_DECODED,
  COMPRESSED_ARM_CODE_STORED,
} from "./nds-compressed-code-fixture.js";
import {
  createNdsFixture,
  encodeFntFileEntry,
  writeFatEntry,
  writeFntMainRecord,
  writeFntSubtable,
  writeOverlayRecord,
} from "./nds-fixture.js";

const ORDINARY_FILE_ID = 0;
const UNCOMPRESSED_FILE_ID = 1;
const COMPRESSED_FILE_ID = 2;
const ORDINARY_OFFSET = 0x1200;
const UNCOMPRESSED_OFFSET = 0x1300;
const COMPRESSED_OFFSET = 0x1400;
const ORDINARY_SIZE = 0x20;
const UNCOMPRESSED_SIZE = 0x40;
const COMPRESSED_BACKING_SIZE = 0x80;
const UNCOMPRESSED_OVERLAY_ID = 2;
const COMPRESSED_OVERLAY_ID = 7;

export interface MutationManifestOperationInput {
  readonly type: "replace-bytes" | "replace-component";
  readonly [key: string]: unknown;
}

export interface MutationManifestOverrides {
  readonly sourceSha256?: string;
  readonly outputFilename?: string;
  readonly expected?: string;
  readonly replacement?: string;
  readonly operations?: readonly MutationManifestOperationInput[];
  readonly extraRoot?: Readonly<Record<string, unknown>>;
}

export interface MutationFixture {
  readonly directory: string;
  readonly romPath: string;
  readonly sourceSha256: string;
  readonly map: NdsRomMap;
  readonly arm9Offset: number;
  readonly arm7Offset: number;
  readonly ordinaryFileId: number;
  readonly ordinaryRomOffset: number;
  readonly uncompressedFileId: number;
  readonly uncompressedOverlayId: number;
  readonly uncompressedRomOffset: number;
  readonly compressedFileId: number;
  readonly compressedOverlayId: number;
  readonly compressedRomOffset: number;
  readonly unrelatedRomOffset: number;
  writeManifest(
    overrides?: MutationManifestOverrides,
    relativePath?: string,
  ): Promise<string>;
  writeArtifact(relativePath: string, bytes: Buffer): Promise<{
    readonly relativePath: string;
    readonly absolutePath: string;
    readonly sha256: string;
  }>;
}

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export async function createMutationFixture(): Promise<MutationFixture> {
  const fixture = await createNdsFixture({
    fileSize: 0x6000,
    fntSize: 0x60,
    fatSize: 24,
    arm9OverlaySize: 64,
  });

  writeFatEntry(
    fixture.buffer,
    0x900,
    ORDINARY_FILE_ID,
    ORDINARY_OFFSET,
    ORDINARY_OFFSET + ORDINARY_SIZE,
  );
  writeFatEntry(
    fixture.buffer,
    0x900,
    UNCOMPRESSED_FILE_ID,
    UNCOMPRESSED_OFFSET,
    UNCOMPRESSED_OFFSET + UNCOMPRESSED_SIZE,
  );
  writeFatEntry(
    fixture.buffer,
    0x900,
    COMPRESSED_FILE_ID,
    COMPRESSED_OFFSET,
    COMPRESSED_OFFSET + COMPRESSED_BACKING_SIZE,
  );

  writeFntMainRecord(fixture.buffer, 0x800, 0, 8, 0, 1);
  writeFntSubtable(fixture.buffer, 0x800, 8, [
    encodeFntFileEntry("asset.bin"),
    encodeFntFileEntry("overlay.bin"),
    encodeFntFileEntry("compressed.bin"),
  ]);

  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: UNCOMPRESSED_OVERLAY_ID,
    ramAddress: 0x02210000,
    ramSize: UNCOMPRESSED_SIZE,
    bssSize: 0x20,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: UNCOMPRESSED_FILE_ID,
    compressedSize: 0,
    flags: 0,
  });
  writeOverlayRecord(fixture.buffer, 0xa00, 1, {
    overlayId: COMPRESSED_OVERLAY_ID,
    ramAddress: 0x02220000,
    ramSize: COMPRESSED_ARM_CODE_DECODED.length,
    bssSize: 0x20,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: COMPRESSED_FILE_ID,
    compressedSize: COMPRESSED_ARM_CODE_STORED.length,
    flags: 1,
  });

  fixture.buffer.fill(0xa9, 0x200, 0x400);
  fixture.buffer.fill(0xa7, 0x600, 0x700);
  fixture.buffer.fill(0xcc, ORDINARY_OFFSET, ORDINARY_OFFSET + ORDINARY_SIZE);
  fixture.buffer.fill(0x44, UNCOMPRESSED_OFFSET, UNCOMPRESSED_OFFSET + UNCOMPRESSED_SIZE);
  COMPRESSED_ARM_CODE_STORED.copy(fixture.buffer, COMPRESSED_OFFSET);
  fixture.buffer.fill(
    0x5a,
    COMPRESSED_OFFSET + COMPRESSED_ARM_CODE_STORED.length,
    COMPRESSED_OFFSET + COMPRESSED_BACKING_SIZE,
  );
  await fixture.write();

  const map = await readNdsRomMap(fixture.romPath);
  const sourceSha256 = await hashFileSha256(fixture.romPath);

  async function writeArtifact(relativePath: string, bytes: Buffer) {
    const absolutePath = path.join(fixture.directory, ...relativePath.split("/"));
    await mkdir(path.dirname(absolutePath), { recursive: true });
    await writeFile(absolutePath, bytes);
    return { relativePath, absolutePath, sha256: sha256(bytes) };
  }

  async function writeManifest(
    overrides: MutationManifestOverrides = {},
    relativePath = "plans/mutation.json",
  ): Promise<string> {
    const operations = overrides.operations ?? [
      {
        type: "replace-bytes" as const,
        target: { component: "arm9", relativeOffset: 4 },
        expected: overrides.expected ?? "a9a9",
        replacement: overrides.replacement ?? "1234",
      },
    ];
    const manifest = {
      format: "re-mcp-nds-mutation",
      formatVersion: 1,
      source: { sha256: overrides.sourceSha256 ?? sourceSha256 },
      output: { filename: overrides.outputFilename ?? "test-mod.nds" },
      operations,
      ...(overrides.extraRoot ?? {}),
    };
    const absolutePath = path.join(fixture.directory, ...relativePath.split("/"));
    await mkdir(path.dirname(absolutePath), { recursive: true });
    await writeFile(absolutePath, JSON.stringify(manifest, null, 2));
    return relativePath;
  }

  return {
    directory: fixture.directory,
    romPath: fixture.romPath,
    sourceSha256,
    map,
    arm9Offset: 0x200,
    arm7Offset: 0x600,
    ordinaryFileId: ORDINARY_FILE_ID,
    ordinaryRomOffset: ORDINARY_OFFSET,
    uncompressedFileId: UNCOMPRESSED_FILE_ID,
    uncompressedOverlayId: UNCOMPRESSED_OVERLAY_ID,
    uncompressedRomOffset: UNCOMPRESSED_OFFSET,
    compressedFileId: COMPRESSED_FILE_ID,
    compressedOverlayId: COMPRESSED_OVERLAY_ID,
    compressedRomOffset: COMPRESSED_OFFSET,
    unrelatedRomOffset: 0x1800,
    writeManifest,
    writeArtifact,
  };
}
