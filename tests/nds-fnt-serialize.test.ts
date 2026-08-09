import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import { parseNdsFat } from "../src/services/nds/fat.js";
import { parseNdsFnt } from "../src/services/nds/fnt.js";
import { serializeExtendedNdsFnt } from "../src/services/nds/fnt-serialize.js";
import { parseNdsHeader } from "../src/services/nds/header.js";
import {
  planNdsFilesystemExtensions,
  type NdsFilesystemPlanningIo,
} from "../src/services/nds/mutation/filesystem-plan.js";
import type { NdsAddNitroFsFileOperation } from "../src/services/nds/mutation/manifest.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import {
  createNdsFixture,
  encodeFntDirectoryEntry,
  encodeFntFileEntry,
  writeFatEntry,
  writeFntMainRecord,
  writeFntSubtable,
} from "./helpers/nds-fixture.js";

const ROOT_DIRECTORY_ID = 0xf000;
const DATA_DIRECTORY_ID = 0xf001;

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

async function createNestedSource() {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    fntSize: 0x100,
    fatSize: 16,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1200, 0x1210);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1300, 0x1310);
  fixture.buffer.fill(0x11, 0x1200, 0x1210);
  fixture.buffer.fill(0x22, 0x1300, 0x1310);

  writeFntMainRecord(fixture.buffer, 0x800, 0, 16, 0, 2);
  const dataSubtableOffset = writeFntSubtable(fixture.buffer, 0x800, 16, [
    encodeFntFileEntry("root.bin"),
    encodeFntDirectoryEntry("data", DATA_DIRECTORY_ID),
  ]);
  writeFntMainRecord(
    fixture.buffer,
    0x800,
    1,
    dataSubtableOffset,
    1,
    ROOT_DIRECTORY_ID,
  );
  writeFntSubtable(fixture.buffer, 0x800, dataSubtableOffset, [
    encodeFntFileEntry("existing.bin"),
  ]);
  await fixture.write();
  return { fixture, map: await readNdsRomMap(fixture.romPath) };
}

async function writeOperation(
  directory: string,
  index: number,
  nitroPath: string,
): Promise<{ index: number; operation: NdsAddNitroFsFileOperation }> {
  const bytes = Buffer.from(`artifact-${index}`, "utf8");
  const artifact = `patches/${index}.bin`;
  const absolute = path.join(directory, "patches", `${index}.bin`);
  await import("node:fs/promises").then(async ({ mkdir }) => {
    await mkdir(path.dirname(absolute), { recursive: true });
  });
  await writeFile(absolute, bytes);
  return {
    index,
    operation: {
      type: "add-nitrofs-file",
      path: nitroPath,
      replacement: { artifact, sha256: sha256(bytes) },
    },
  };
}

test("assigns new directory and file IDs independently of operation order", async () => {
  const { fixture, map } = await createNestedSource();
  const operations = await Promise.all([
    writeOperation(fixture.directory, 0, "re_mcp/economy/e2dt.bin"),
    writeOperation(fixture.directory, 1, "re_mcp/abilities/a2dt.bin"),
    writeOperation(fixture.directory, 2, "zzz_patch/state.bin"),
    writeOperation(fixture.directory, 3, "re_mcp/attributes/i2dt.bin"),
  ]);

  const plan = await planNdsFilesystemExtensions(
    map,
    fixture.directory,
    [operations[2]!, operations[0]!, operations[3]!, operations[1]!],
  );

  assert.deepEqual(
    plan.addedDirectories.map(({ path: directoryPath, directoryId }) => [directoryPath, directoryId]),
    [
      ["re_mcp", 0xf002],
      ["re_mcp/abilities", 0xf003],
      ["re_mcp/attributes", 0xf004],
      ["re_mcp/economy", 0xf005],
      ["zzz_patch", 0xf006],
    ],
  );
  assert.deepEqual(
    plan.addedFiles.map(({ path: filePath, fileId }) => [filePath, fileId]),
    [
      ["re_mcp/abilities/a2dt.bin", 2],
      ["re_mcp/attributes/i2dt.bin", 3],
      ["re_mcp/economy/e2dt.bin", 4],
      ["zzz_patch/state.bin", 5],
    ],
  );
  assert.equal(plan.finalDirectoryCount, 7);
  assert.equal(plan.finalFileCount, 6);
});

test("rejects existing top-level ownership, root insertion, and duplicate new paths", async () => {
  const { fixture, map } = await createNestedSource();
  const existing = await writeOperation(fixture.directory, 0, "data/new.bin");
  const root = await writeOperation(fixture.directory, 1, "new.bin");
  const duplicateA = await writeOperation(fixture.directory, 2, "re_mcp/a.bin");
  const duplicateB = await writeOperation(fixture.directory, 3, "re_mcp/a.bin");

  await assert.rejects(
    planNdsFilesystemExtensions(map, fixture.directory, [existing]),
    (error: unknown) => error instanceof NdsError
      && error.category === "filesystem-extension-invalid",
  );
  await assert.rejects(
    planNdsFilesystemExtensions(map, fixture.directory, [root]),
    (error: unknown) => error instanceof NdsError
      && error.category === "filesystem-extension-invalid",
  );
  await assert.rejects(
    planNdsFilesystemExtensions(map, fixture.directory, [duplicateA, duplicateB]),
    (error: unknown) => error instanceof NdsError
      && error.category === "filesystem-path-collision",
  );
});

test("enforces new-file count and aggregate payload limits before reading oversized artifacts", async () => {
  const { fixture, map } = await createNestedSource();
  const byte = Buffer.from([0x5a]);
  const hash = sha256(byte);
  const make = (index: number): { index: number; operation: NdsAddNitroFsFileOperation } => ({
    index,
    operation: {
      type: "add-nitrofs-file",
      path: `re_mcp/files/f${index}.bin`,
      replacement: { artifact: `virtual/f${index}.bin`, sha256: hash },
    },
  });
  const io: NdsFilesystemPlanningIo = {
    async lstat() {
      return { isFile: () => true, isSymbolicLink: () => false, size: 1 };
    },
    async readFile() {
      return byte;
    },
  };
  await assert.rejects(
    planNdsFilesystemExtensions(
      map,
      fixture.directory,
      Array.from({ length: 257 }, (_, index) => make(index)),
      io,
    ),
    (error: unknown) => error instanceof NdsError
      && error.category === "filesystem-id-capacity-exceeded",
  );

  let reads = 0;
  const oversizedIo: NdsFilesystemPlanningIo = {
    async lstat(filePath) {
      return {
        isFile: () => true,
        isSymbolicLink: () => false,
        size: filePath.endsWith("0.bin") ? 40 * 1024 * 1024 : 30 * 1024 * 1024,
      };
    },
    async readFile() {
      reads += 1;
      return byte;
    },
  };
  await assert.rejects(
    planNdsFilesystemExtensions(map, fixture.directory, [make(0), make(1)], oversizedIo),
    (error: unknown) => error instanceof NdsError
      && error.category === "filesystem-extension-invalid",
  );
  assert.equal(reads, 0, "aggregate-size rejection should occur before artifact reads");
});

test("serialized extended FNT reparses to exact source semantics plus additions", async () => {
  const { fixture, map } = await createNestedSource();
  const operations = await Promise.all([
    writeOperation(fixture.directory, 0, "re_mcp/attributes/i2dt.bin"),
    writeOperation(fixture.directory, 1, "re_mcp/abilities/a2dt.bin"),
  ]);
  const extension = await planNdsFilesystemExtensions(map, fixture.directory, operations);
  const fnt = serializeExtendedNdsFnt(map.filesystem, extension);
  assert.ok(fnt.length <= 4 * 1024 * 1024);

  const output = await createNdsFixture({
    fileSize: 0x6000,
    fntSize: fnt.length,
    fatSize: extension.finalFileCount * 8,
  });
  fnt.copy(output.buffer, 0x800);
  for (let fileId = 0; fileId < extension.finalFileCount; fileId += 1) {
    const start = 0x1200 + fileId * 0x20;
    writeFatEntry(output.buffer, 0x900, fileId, start, start + 0x10);
  }
  await output.write();
  const parsedHeader = await parseNdsHeader(output.romPath);
  const fat = await parseNdsFat(parsedHeader);
  const parsed = await parseNdsFnt(parsedHeader, fat);

  for (const sourceDirectory of map.filesystem.directories) {
    const finalDirectory = parsed.directories.find(
      (candidate) => candidate.directoryId === sourceDirectory.directoryId,
    );
    assert.deepEqual(finalDirectory, sourceDirectory);
  }
  for (const sourceFile of map.filesystem.files) {
    assert.equal(parsed.files[sourceFile.fileId]?.path, sourceFile.path);
  }
  for (const added of extension.addedFiles) {
    assert.equal(parsed.files[added.fileId]?.path, added.path);
  }
});
