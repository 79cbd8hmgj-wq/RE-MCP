import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

const root = path.resolve(process.argv[2] ?? process.cwd());

for (const relative of [
  "dist/services/nds/mutation/manifest.js",
  "dist/services/nds/mutation/planner.js",
  "dist/services/nds/mutation/build.js",
  "dist/tools/nds-mutation.js",
]) {
  await readFile(path.join(root, relative));
}

const builtIndex = await readFile(path.join(root, "dist/index.js"), "utf8");
if (!builtIndex.includes("registerNdsMutationTools(server, config)")) {
  throw new Error("Packaged server does not register controlled NDS mutation tools");
}

const romMapUrl = pathToFileURL(
  path.join(root, "dist/services/nds/rom-map.js"),
).href;
const manifestUrl = pathToFileURL(
  path.join(root, "dist/services/nds/mutation/manifest.js"),
).href;
const buildUrl = pathToFileURL(
  path.join(root, "dist/services/nds/mutation/build.js"),
).href;
const { readNdsRomMap } = await import(romMapUrl);
const { loadNdsMutationManifest } = await import(manifestUrl);
const { buildNdsMutation, verifyPublishedNdsMutationBuild } = await import(buildUrl);

const temp = await mkdtemp(path.join(os.tmpdir(), "re-mcp-mutation-package-"));
try {
  const fixture = Buffer.alloc(0x1000);
  fixture.write("RE-MCP TEST", 0x00, 12, "ascii");
  fixture.write("TEST", 0x0c, 4, "ascii");
  fixture.write("01", 0x10, 2, "ascii");
  fixture.writeUInt8(8, 0x14);
  fixture.writeUInt32LE(0x200, 0x20);
  fixture.writeUInt32LE(0x02000000, 0x24);
  fixture.writeUInt32LE(0x02000000, 0x28);
  fixture.writeUInt32LE(0x20, 0x2c);
  fixture.writeUInt32LE(0x300, 0x30);
  fixture.writeUInt32LE(0x03800000, 0x34);
  fixture.writeUInt32LE(0x03800000, 0x38);
  fixture.writeUInt32LE(0x20, 0x3c);
  fixture.writeUInt32LE(0x400, 0x40);
  fixture.writeUInt32LE(0, 0x44);
  fixture.writeUInt32LE(0x500, 0x48);
  fixture.writeUInt32LE(0, 0x4c);
  fixture.writeUInt32LE(0x600, 0x50);
  fixture.writeUInt32LE(0, 0x54);
  fixture.writeUInt32LE(0x700, 0x58);
  fixture.writeUInt32LE(0, 0x5c);
  fixture.writeUInt32LE(0x800, 0x68);
  fixture.set([0xaa, 0xbb, 0xcc, 0xdd], 0x200);

  const romPath = path.join(temp, "mutation-source.nds");
  await writeFile(romPath, fixture);
  const map = await readNdsRomMap(romPath);
  const sourceBefore = await readFile(romPath);

  const manifestPath = path.join(temp, "mutation.json");
  await writeFile(
    manifestPath,
    `${JSON.stringify({
      format: "re-mcp-nds-mutation",
      formatVersion: 1,
      source: { sha256: map.sha256 },
      output: { filename: "mutation-smoke.nds" },
      operations: [{
        type: "replace-bytes",
        target: { component: "arm9", relativeOffset: 0 },
        expected: "aabb",
        replacement: "1234",
      }],
    }, null, 2)}\n`,
    "utf8",
  );

  const loaded = await loadNdsMutationManifest(temp, "mutation.json");
  const built = await buildNdsMutation(map, temp, loaded);
  if (
    built.reused !== false
    || built.verification.status !== "passed"
    || built.verification.unexpectedChangedBytes !== 0
  ) {
    throw new Error("Packaged NDS mutation build smoke did not produce a fresh verified build");
  }

  const expectedRoot = path.join(
    temp,
    "output",
    "nds",
    map.sha256Prefix,
    built.buildId,
  );
  if (path.resolve(built.outputRoot) !== path.resolve(expectedRoot)) {
    throw new Error("Packaged NDS mutation build escaped its deterministic output root");
  }

  const expectedEntries = [
    "changed-components.json",
    "mutation-manifest.json",
    "mutation-smoke.nds",
    "output.sha256",
    "resolved-plan.json",
    "verification.json",
  ].sort();
  const actualEntries = (await readdir(built.outputRoot)).sort();
  if (JSON.stringify(actualEntries) !== JSON.stringify(expectedEntries)) {
    throw new Error("Packaged NDS mutation evidence set is incomplete or unexpected");
  }

  const sourceAfterBuild = await readFile(romPath);
  if (!sourceAfterBuild.equals(sourceBefore)) {
    throw new Error("Packaged NDS mutation build modified its immutable source ROM");
  }

  const verified = await verifyPublishedNdsMutationBuild(map, temp, loaded);
  if (
    verified.reused !== true
    || verified.buildId !== built.buildId
    || verified.outputSha256 !== built.outputSha256
    || verified.verification.status !== "passed"
    || verified.verification.unexpectedChangedBytes !== 0
  ) {
    throw new Error("Packaged NDS mutation verify smoke did not freshly revalidate the deterministic build");
  }

  const sourceAfterVerify = await readFile(romPath);
  if (!sourceAfterVerify.equals(sourceBefore)) {
    throw new Error("Packaged NDS mutation verify modified its immutable source ROM");
  }
} finally {
  await rm(temp, { recursive: true, force: true });
}

process.stdout.write("NDS mutation package smoke passed\n");
