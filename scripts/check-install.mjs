import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

const root = path.resolve(process.argv[2] ?? process.cwd());
const required = [
  "dist/index.js",
  "dist/services/nds/disassembly.js",
  "dist/services/nds/references.js",
  "dist/services/nds/pattern-search.js",
  "dist/services/nds/rom-map.js",
  "package.json",
  "node_modules/@modelcontextprotocol/sdk/package.json",
  "node_modules/zod/package.json",
  "node_modules/@alexaltea/capstone-js/package.json",
  "node_modules/@alexaltea/capstone-js/dist/capstone.js",
  "node_modules/@alexaltea/capstone-js/dist/capstone.wasm",
];

for (const relative of required) {
  await access(path.join(root, relative));
}

const packageJson = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
const nodeMajor = Number.parseInt(process.versions.node.split(".")[0] ?? "0", 10);
if (nodeMajor < 20) {
  throw new Error(`Node.js 20 or newer is required; found ${process.versions.node}`);
}

const adapterUrl = pathToFileURL(
  path.join(root, "dist/services/disassembly/capstone.js"),
).href;
const disassemblyUrl = pathToFileURL(
  path.join(root, "dist/services/nds/disassembly.js"),
).href;
const referencesUrl = pathToFileURL(
  path.join(root, "dist/services/nds/references.js"),
).href;
const patternSearchUrl = pathToFileURL(
  path.join(root, "dist/services/nds/pattern-search.js"),
).href;
const romMapUrl = pathToFileURL(
  path.join(root, "dist/services/nds/rom-map.js"),
).href;
const { createCapstoneArmBackend } = await import(adapterUrl);
const { decodeNdsInstructionDetailed } = await import(disassemblyUrl);
const { classifyNdsInstructionReferences } = await import(referencesUrl);
const { searchNdsPattern } = await import(patternSearchUrl);
const { readNdsRomMap } = await import(romMapUrl);

const arm9 = {
  ramAddress: 0x02000000,
  ramEnd: 0x02000100,
  romOffset: 0x200,
  romEnd: 0x300,
  size: 0x100,
  entryAddress: 0x02000000,
};
const arm7 = {
  ramAddress: 0x03800000,
  ramEnd: 0x03800100,
  romOffset: 0x600,
  romEnd: 0x700,
  size: 0x100,
  entryAddress: 0x03800000,
};
const map = {
  header: { arm9, arm7 },
  overlays: { arm9: [], arm7: [] },
};
function sourceAt(runtimeAddress, mode) {
  return {
    processor: "arm9",
    component: "main",
    overlayId: null,
    runtimeAddress,
    romOffset: 0x200 + (runtimeAddress - 0x02000000),
    runtimeStart: 0x02000000,
    runtimeEnd: 0x02000100,
    romStart: 0x200,
    romEnd: 0x300,
    mode,
  };
}

const backend = await createCapstoneArmBackend();
try {
  const arm = backend.decodeOne(
    Uint8Array.from([0x1e, 0xff, 0x2f, 0xe1]),
    0x02000000,
    "arm",
  );
  const thumb = backend.decodeOne(
    Uint8Array.from([0x70, 0x47]),
    0x02000010,
    "thumb",
  );
  if (arm?.mnemonic !== "bx" || arm.size !== 4) {
    throw new Error("Packaged Capstone ARM smoke decode failed");
  }
  if (thumb?.mnemonic !== "bx" || thumb.size !== 2) {
    throw new Error("Packaged Capstone Thumb smoke decode failed");
  }

  const armDetailed = decodeNdsInstructionDetailed(
    map,
    sourceAt(0x02000000, "arm"),
    Uint8Array.from([0x00, 0x00, 0x00, 0xeb]),
    backend,
  );
  const armRefs = armDetailed === null
    ? []
    : classifyNdsInstructionReferences(map, armDetailed);
  if (
    armRefs.length !== 1
    || armRefs[0]?.kind !== "direct-call"
    || armRefs[0]?.target.runtimeAddress !== 0x02000008
  ) {
    throw new Error("Packaged ARM direct reference smoke failed");
  }

  const thumbDetailed = decodeNdsInstructionDetailed(
    map,
    sourceAt(0x02000002, "thumb"),
    Uint8Array.from([0x00, 0x48]),
    backend,
  );
  const thumbRefs = thumbDetailed === null
    ? []
    : classifyNdsInstructionReferences(map, thumbDetailed);
  if (
    thumbRefs.length !== 1
    || thumbRefs[0]?.kind !== "literal-pool"
    || thumbRefs[0]?.target.runtimeAddress !== 0x02000004
  ) {
    throw new Error("Packaged Thumb PC-relative reference smoke failed");
  }
} finally {
  backend.close();
}

const patternTemp = await mkdtemp(path.join(os.tmpdir(), "re-mcp-pattern-"));
try {
  const fixture = Buffer.alloc(0x1000);
  fixture.writeUInt32LE(0x200, 0x20);
  fixture.writeUInt32LE(0x02000000, 0x24);
  fixture.writeUInt32LE(0x02000000, 0x28);
  fixture.writeUInt32LE(0x20, 0x2c);
  fixture.writeUInt32LE(0x300, 0x30);
  fixture.writeUInt32LE(0x03800000, 0x34);
  fixture.writeUInt32LE(0x03800000, 0x38);
  fixture.writeUInt32LE(0x20, 0x3c);
  fixture.writeUInt32LE(0x400, 0x40);
  fixture.writeUInt32LE(0x500, 0x48);
  fixture.writeUInt32LE(0x600, 0x50);
  fixture.writeUInt32LE(0x700, 0x58);
  fixture.writeUInt32LE(0x800, 0x68);
  fixture.set([0xaa, 0xaa, 0xaa], 0x200);

  const patternRom = path.join(patternTemp, "pattern-smoke.nds");
  await writeFile(patternRom, fixture);
  const patternMap = await readNdsRomMap(patternRom);
  const patternResult = await searchNdsPattern(
    patternMap,
    { kind: "byte-signature", signature: "AA ??" },
    { kind: "components", arm9Main: true },
    { offset: 0, limit: 10, maxScanBytes: 0x20, contextBytes: 0 },
  );
  const patternOffsets = patternResult.matches.map((hit) => hit.romOffset);
  if (
    patternOffsets.length !== 2
    || patternOffsets[0] !== 0x200
    || patternOffsets[1] !== 0x201
  ) {
    throw new Error("Packaged NDS pattern overlap smoke failed");
  }
  const mainOwner = patternResult.matches[0]?.owners.find(
    (owner) => owner.kind === "arm9-main",
  );
  if (mainOwner?.runtimeAddress !== 0x02000000) {
    throw new Error("Packaged NDS pattern ownership smoke failed");
  }
} finally {
  await rm(patternTemp, { recursive: true, force: true });
}

process.stdout.write(
  JSON.stringify(
    {
      ok: true,
      package: packageJson.name,
      version: packageJson.version,
      node: process.versions.node,
      root,
    },
    null,
    2,
  ) + "\n",
);