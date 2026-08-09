import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

const root = path.resolve(process.argv[2] ?? process.cwd());
const required = [
  "dist/index.js",
  "dist/services/nds/blz.js",
  "dist/services/nds/disassembly.js",
  "dist/services/nds/extraction.js",
  "dist/services/nds/overlay-runtime.js",
  "dist/services/nds/references.js",
  "dist/services/nds/pattern-search.js",
  "dist/services/nds/function-discovery.js",
  "dist/services/nds/function-analysis.js",
  "dist/services/nds/ghidra-model.js",
  "dist/services/nds/ghidra-bridge.js",
  "dist/services/nds/ghidra-installation.js",
  "dist/services/nds/ghidra-runner.js",
  "dist/services/nds/ghidra-project.js",
  "dist/services/nds/rom-map.js",
  "dist/tools/nds-functions.js",
  "dist/tools/nds-ghidra.js",
  "resources/ghidra/ReMcpPrepareProgram.java",
  "resources/ghidra/ReMcpImportEvidence.java",
  "resources/ghidra/ReMcpRecordAnalysis.java",
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

const builtIndex = await readFile(path.join(root, "dist/index.js"), "utf8");
if (!builtIndex.includes("registerNdsFunctionTools(server, config)")) {
  throw new Error("Packaged server does not register NDS function tools");
}
if (!builtIndex.includes("registerNdsGhidraTools(server, config)")) {
  throw new Error("Packaged server does not register controlled NDS Ghidra tools");
}

for (const scriptName of [
  "ReMcpPrepareProgram.java",
  "ReMcpImportEvidence.java",
  "ReMcpRecordAnalysis.java",
]) {
  const source = await readFile(path.join(root, "resources", "ghidra", scriptName), "utf8");
  if (!source.includes("@category RE-MCP")) {
    throw new Error(`Packaged Ghidra resource lacks RE-MCP script identity: ${scriptName}`);
  }
}

const adapterUrl = pathToFileURL(
  path.join(root, "dist/services/disassembly/capstone.js"),
).href;
const disassemblyUrl = pathToFileURL(
  path.join(root, "dist/services/nds/disassembly.js"),
).href;
const extractionUrl = pathToFileURL(
  path.join(root, "dist/services/nds/extraction.js"),
).href;
const referencesUrl = pathToFileURL(
  path.join(root, "dist/services/nds/references.js"),
).href;
const patternSearchUrl = pathToFileURL(
  path.join(root, "dist/services/nds/pattern-search.js"),
).href;
const functionDiscoveryUrl = pathToFileURL(
  path.join(root, "dist/services/nds/function-discovery.js"),
).href;
const romMapUrl = pathToFileURL(
  path.join(root, "dist/services/nds/rom-map.js"),
).href;
const { createCapstoneArmBackend } = await import(adapterUrl);
const { decodeNdsInstructionDetailed } = await import(disassemblyUrl);
const { extractNdsAnalysisBundle } = await import(extractionUrl);
const { classifyNdsInstructionReferences } = await import(referencesUrl);
const { searchNdsPattern } = await import(patternSearchUrl);
const { discoverNdsFunctions } = await import(functionDiscoveryUrl);
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
    || armRefs[0]?.target.mode !== "arm"
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
    || thumbRefs[0]?.target.mode !== null
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
  fixture.set([0xaa, 0xaa, 0xbb], 0x200);

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

const functionTemp = await mkdtemp(path.join(os.tmpdir(), "re-mcp-function-"));
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

  fixture.set([0x00, 0x00, 0x00, 0xeb], 0x200);
  fixture.set([0x1e, 0xff, 0x2f, 0xe1], 0x204);
  fixture.set([0x1e, 0xff, 0x2f, 0xe1], 0x208);

  const functionRom = path.join(functionTemp, "function-smoke.nds");
  await writeFile(functionRom, fixture);
  const functionMap = await readNdsRomMap(functionRom);
  const functionBackend = await createCapstoneArmBackend();
  try {
    const functionResult = await discoverNdsFunctions(
      functionMap,
      { processor: "arm9", scope: { kind: "main" }, seeds: [] },
      {
        maxComponents: 4,
        maxFunctions: 8,
        maxCallSites: 16,
        maxTotalBlocks: 32,
        maxTotalInstructions: 64,
        maxTotalBytes: 256,
        maxTotalEdges: 64,
        perFunctionCfg: {
          maxBlocks: 16,
          maxInstructions: 32,
          maxBytes: 128,
          maxEdges: 32,
        },
      },
      functionBackend,
    );
    const ids = functionResult.functions.map((entry) => entry.id);
    if (
      functionResult.status !== "complete"
      || ids.length !== 2
      || ids[0] !== "arm9:main:02000000:arm"
      || ids[1] !== "arm9:main:02000008:arm"
      || functionResult.calls.length !== 1
      || functionResult.calls[0]?.instructionAddress !== 0x02000000
    ) {
      throw new Error("Packaged NDS proven-function discovery smoke failed");
    }
  } finally {
    functionBackend.close();
  }
} finally {
  await rm(functionTemp, { recursive: true, force: true });
}

const compressedTemp = await mkdtemp(path.join(os.tmpdir(), "re-mcp-compressed-"));
try {
  const compressedStored = Buffer.from(
    "060000eb0034009fe5000000ea0000000df0110021a010402d1ce91eff2f0d606000201002011001f001f001f001f001f001f0fe01f001f001f001f00000a0e10f49000008b7000000",
    "hex",
  );
  const compressedDecodedHead = Buffer.from(
    [
      "060000eb",
      "34009fe5",
      "000000ea",
      "0000a0e1",
      "1eff2fe1",
      "0000a0e1",
      "0000a0e1",
      "0000a0e1",
      "1eff2fe1",
      "0000a0e1",
      "0000a0e1",
      "0000a0e1",
      "10402de9",
      "1eff2fe1",
      "0000a0e1",
      "0000a0e1",
      "60002002",
    ].join(""),
    "hex",
  );
  const compressedDecoded = Buffer.concat([
    compressedDecodedHead,
    Buffer.from("0000a0e1".repeat(47), "hex"),
  ]);
  const trailingBackingBytes = 8;
  const backingSize = compressedStored.length + trailingBackingBytes;
  const fixture = Buffer.alloc(0x3000);

  fixture.write("RE-MCP TEST", 0x00, 12, "ascii");
  fixture.write("TEST", 0x0c, 4, "ascii");
  fixture.write("01", 0x10, 2, "ascii");
  fixture.writeUInt8(8, 0x14);
  fixture.writeUInt32LE(0x200, 0x20);
  fixture.writeUInt32LE(0x02000000, 0x24);
  fixture.writeUInt32LE(0x02000000, 0x28);
  fixture.writeUInt32LE(0x100, 0x2c);
  fixture.writeUInt32LE(0x600, 0x30);
  fixture.writeUInt32LE(0x03800000, 0x34);
  fixture.writeUInt32LE(0x03800000, 0x38);
  fixture.writeUInt32LE(0x100, 0x3c);
  fixture.writeUInt32LE(0x800, 0x40);
  fixture.writeUInt32LE(0, 0x44);
  fixture.writeUInt32LE(0x900, 0x48);
  fixture.writeUInt32LE(8, 0x4c);
  fixture.writeUInt32LE(0xa00, 0x50);
  fixture.writeUInt32LE(32, 0x54);
  fixture.writeUInt32LE(0xb00, 0x58);
  fixture.writeUInt32LE(0, 0x5c);
  fixture.writeUInt32LE(0xc00, 0x68);

  fixture.writeUInt32LE(0x1200, 0x900);
  fixture.writeUInt32LE(0x1200 + backingSize, 0x904);

  fixture.writeUInt32LE(7, 0xa00);
  fixture.writeUInt32LE(0x02200000, 0xa04);
  fixture.writeUInt32LE(compressedDecoded.length, 0xa08);
  fixture.writeUInt32LE(0x20, 0xa0c);
  fixture.writeUInt32LE(0, 0xa10);
  fixture.writeUInt32LE(0, 0xa14);
  fixture.writeUInt32LE(0, 0xa18);
  fixture.writeUInt32LE(
    ((compressedStored.length & 0x00ffffff) | (1 << 24)) >>> 0,
    0xa1c,
  );
  compressedStored.copy(fixture, 0x1200);
  Buffer.alloc(trailingBackingBytes, 0x5a).copy(
    fixture,
    0x1200 + compressedStored.length,
  );

  const compressedRom = path.join(compressedTemp, "compressed-smoke.nds");
  await writeFile(compressedRom, fixture);
  const sourceBefore = await readFile(compressedRom);
  const compressedMap = await readNdsRomMap(compressedRom);
  const bundle = await extractNdsAnalysisBundle(compressedMap, compressedTemp);
  const rawOverlay = await readFile(
    path.join(bundle.outputRoot, "overlays", "arm9", "overlay_7.bin"),
  );
  const runtimeOverlay = await readFile(
    path.join(bundle.outputRoot, "runtime", "overlays", "arm9", "overlay_7.bin"),
  );
  const manifest = JSON.parse(await readFile(bundle.manifestPath, "utf8"));
  const runtimeArtifact = manifest.runtimeArtifacts?.[0];

  if (
    rawOverlay.length !== backingSize
    || !rawOverlay.subarray(0, compressedStored.length).equals(compressedStored)
    || !runtimeOverlay.equals(compressedDecoded)
    || runtimeArtifact?.output !== "runtime/overlays/arm9/overlay_7.bin"
    || runtimeArtifact?.representation !== "derived-blz"
    || runtimeArtifact?.romOffset !== null
    || runtimeArtifact?.runtimeSize !== compressedDecoded.length
    || runtimeArtifact?.bssSize !== 0x20
    || runtimeArtifact?.runtimeSha256 !== runtimeArtifact?.outputSha256
  ) {
    throw new Error("Packaged compressed-overlay bundle smoke failed");
  }
  const sourceAfter = await readFile(compressedRom);
  if (!sourceAfter.equals(sourceBefore)) {
    throw new Error("Packaged compressed-overlay bundle smoke modified its source ROM");
  }
} finally {
  await rm(compressedTemp, { recursive: true, force: true });
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
