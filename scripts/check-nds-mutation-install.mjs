import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

const root = path.resolve(process.argv[2] ?? process.cwd());

for (const relative of [
  "dist/services/nds/blz.js",
  "dist/services/nds/blz-encode.js",
  "dist/services/nds/header-rebuild.js",
  "dist/services/nds/mutation/manifest.js",
  "dist/services/nds/mutation/planner.js",
  "dist/services/nds/mutation/filesystem-plan.js",
  "dist/services/nds/mutation/layout.js",
  "dist/services/nds/mutation/header-plan.js",
  "dist/services/nds/mutation/build.js",
  "dist/tools/nds-mutation.js",
]) {
  await readFile(path.join(root, relative));
}

const builtIndex = await readFile(path.join(root, "dist/index.js"), "utf8");
if (!builtIndex.includes("registerNdsMutationTools(server, config)")) {
  throw new Error("Packaged server does not register controlled NDS mutation tools");
}

const moduleUrl = (relative) => pathToFileURL(path.join(root, relative)).href;
const { encodeNdsBlz } = await import(moduleUrl("dist/services/nds/blz-encode.js"));
const { decodeNdsBlz } = await import(moduleUrl("dist/services/nds/blz.js"));
const { crc16NdsHeader } = await import(moduleUrl("dist/services/nds/header-rebuild.js"));
const { readNdsRomMap } = await import(moduleUrl("dist/services/nds/rom-map.js"));
const { loadNdsMutationManifest } = await import(
  moduleUrl("dist/services/nds/mutation/manifest.js")
);
const { buildNdsMutation, verifyPublishedNdsMutationBuild } = await import(
  moduleUrl("dist/services/nds/mutation/build.js")
);

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function writeSingleFileFnt(fixture, offset, fileName) {
  const name = Buffer.from(fileName, "latin1");
  const size = 8 + 1 + name.length + 1;
  fixture.writeUInt32LE(8, offset);
  fixture.writeUInt16LE(0, offset + 4);
  fixture.writeUInt16LE(1, offset + 6);
  fixture.writeUInt8(name.length, offset + 8);
  name.copy(fixture, offset + 9);
  fixture.writeUInt8(0, offset + 9 + name.length);
  return size;
}

const runtime = Buffer.alloc(1024, 0x41);
const encodedOnce = encodeNdsBlz(runtime);
const encodedTwice = encodeNdsBlz(runtime);
if (
  encodedOnce.contractVersion !== 1
  || encodedOnce.storedSize >= runtime.length
  || !encodedOnce.bytes.equals(encodedTwice.bytes)
) {
  throw new Error("Packaged deterministic BLZ encoder contract smoke failed");
}
const decoded = decodeNdsBlz(encodedOnce.bytes, runtime.length);
if (!decoded.bytes.equals(runtime)) {
  throw new Error("Packaged BLZ encode/decode round-trip smoke failed");
}

const temp = await mkdtemp(path.join(os.tmpdir(), "re-mcp-rebuild-package-"));
try {
  const fixture = Buffer.alloc(0x1000);
  fixture.write("RE-MCP TEST", 0x00, 12, "ascii");
  fixture.write("TEST", 0x0c, 4, "ascii");
  fixture.write("01", 0x10, 2, "ascii");
  fixture.writeUInt8(0, 0x14);
  fixture.writeUInt32LE(0x200, 0x20);
  fixture.writeUInt32LE(0x02000000, 0x24);
  fixture.writeUInt32LE(0x02000000, 0x28);
  fixture.writeUInt32LE(0x20, 0x2c);
  fixture.writeUInt32LE(0x300, 0x30);
  fixture.writeUInt32LE(0x03800000, 0x34);
  fixture.writeUInt32LE(0x03800000, 0x38);
  fixture.writeUInt32LE(0x20, 0x3c);

  const fntOffset = 0x400;
  const fntSize = writeSingleFileFnt(fixture, fntOffset, "base.bin");
  fixture.writeUInt32LE(fntOffset, 0x40);
  fixture.writeUInt32LE(fntSize, 0x44);

  const fatOffset = 0x500;
  fixture.writeUInt32LE(fatOffset, 0x48);
  fixture.writeUInt32LE(8, 0x4c);
  const sourceFileStart = 0x600;
  const sourceFileBytes = Buffer.from("BASE", "ascii");
  fixture.writeUInt32LE(sourceFileStart, fatOffset);
  fixture.writeUInt32LE(sourceFileStart + sourceFileBytes.length, fatOffset + 4);
  sourceFileBytes.copy(fixture, sourceFileStart);

  fixture.writeUInt32LE(0x700, 0x50);
  fixture.writeUInt32LE(0, 0x54);
  fixture.writeUInt32LE(0x780, 0x58);
  fixture.writeUInt32LE(0, 0x5c);
  fixture.writeUInt32LE(sourceFileStart + sourceFileBytes.length, 0x80);
  fixture.writeUInt32LE(0x200, 0x84);
  fixture.writeUInt16LE(crc16NdsHeader(fixture.subarray(0, 0x15e)), 0x15e);

  const romPath = path.join(temp, "rebuild-source.nds");
  await writeFile(romPath, fixture);
  const map = await readNdsRomMap(romPath);
  const sourceBefore = await readFile(romPath);

  const replacementBytes = Buffer.from("VARIABLE-SIZE-REPLACEMENT", "ascii");
  const addedBytes = Buffer.from("NEW-NITROFS-FILE", "ascii");
  await writeFile(path.join(temp, "replacement.bin"), replacementBytes);
  await writeFile(path.join(temp, "added.bin"), addedBytes);

  const manifestPath = path.join(temp, "mutation.json");
  await writeFile(
    manifestPath,
    `${JSON.stringify({
      format: "re-mcp-nds-mutation",
      formatVersion: 2,
      source: { sha256: map.sha256 },
      output: { filename: "mutation-smoke-v2.nds" },
      operations: [
        {
          type: "replace-nitrofs-file",
          target: { filePath: "base.bin" },
          expectedOriginalSha256: sha256(sourceFileBytes),
          replacement: {
            artifact: "replacement.bin",
            sha256: sha256(replacementBytes),
          },
        },
        {
          type: "add-nitrofs-file",
          path: "re_mcp/package-added.bin",
          replacement: {
            artifact: "added.bin",
            sha256: sha256(addedBytes),
          },
        },
      ],
    }, null, 2)}\n`,
    "utf8",
  );

  const loaded = await loadNdsMutationManifest(temp, "mutation.json");
  const built = await buildNdsMutation(map, temp, loaded);
  if (
    built.reused !== false
    || built.verification.status !== "passed"
    || built.verification.rebuildSemanticsVerified !== true
    || built.verification.unexpectedChangedBytes !== 0
  ) {
    throw new Error("Packaged Rebuild Core 2 smoke did not produce a fresh semantically verified build");
  }

  const expectedRoot = path.join(
    temp,
    "output",
    "nds",
    map.sha256Prefix,
    built.buildId,
  );
  if (path.resolve(built.outputRoot) !== path.resolve(expectedRoot)) {
    throw new Error("Packaged NDS rebuild escaped its deterministic output root");
  }

  const expectedEntries = [
    "changed-components.json",
    "mutation-manifest.json",
    "mutation-smoke-v2.nds",
    "output.sha256",
    "resolved-plan.json",
    "verification.json",
  ].sort();
  const actualEntries = (await readdir(built.outputRoot)).sort();
  if (JSON.stringify(actualEntries) !== JSON.stringify(expectedEntries)) {
    throw new Error("Packaged NDS rebuild evidence set is incomplete or unexpected");
  }

  const outputMap = await readNdsRomMap(built.outputRomPath);
  const outputBytes = await readFile(built.outputRomPath);
  const replaced = outputMap.filesystem.files.find((file) => file.path === "base.bin");
  const added = outputMap.filesystem.files.find(
    (file) => file.path === "re_mcp/package-added.bin",
  );
  if (replaced === undefined || added === undefined) {
    throw new Error("Packaged v2 rebuild did not preserve and extend NitroFS paths");
  }
  if (
    !outputBytes.subarray(replaced.startOffset, replaced.endOffset).equals(replacementBytes)
    || !outputBytes.subarray(added.startOffset, added.endOffset).equals(addedBytes)
  ) {
    throw new Error("Packaged v2 rebuild payload bytes do not match requested NitroFS artifacts");
  }

  const evidence = JSON.parse(
    await readFile(path.join(built.outputRoot, "verification.json"), "utf8"),
  );
  if (
    evidence.rebuildSemanticsVerified !== true
    || evidence.rebuildContractVersion !== 1
    || evidence.blzEncoderContractVersion !== 1
  ) {
    throw new Error("Packaged v2 rebuild evidence is missing contract-version semantic proof");
  }

  const sourceAfterBuild = await readFile(romPath);
  if (!sourceAfterBuild.equals(sourceBefore)) {
    throw new Error("Packaged NDS rebuild modified its immutable source ROM");
  }

  const verified = await verifyPublishedNdsMutationBuild(map, temp, loaded);
  if (
    verified.reused !== true
    || verified.buildId !== built.buildId
    || verified.outputSha256 !== built.outputSha256
    || verified.verification.status !== "passed"
    || verified.verification.rebuildSemanticsVerified !== true
    || verified.verification.unexpectedChangedBytes !== 0
  ) {
    throw new Error("Packaged NDS rebuild verify did not freshly revalidate the deterministic build");
  }

  const sourceAfterVerify = await readFile(romPath);
  if (!sourceAfterVerify.equals(sourceBefore)) {
    throw new Error("Packaged NDS rebuild verify modified its immutable source ROM");
  }
} finally {
  await rm(temp, { recursive: true, force: true });
}

process.stdout.write("NDS Rebuild Core 2 package smoke passed\n");
