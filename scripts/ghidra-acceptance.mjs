import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

const workspaceRoot = path.resolve(process.argv[2] ?? "");
const romRelative = process.argv[3] ?? "";
if (!path.isAbsolute(workspaceRoot) || romRelative.length === 0 || path.isAbsolute(romRelative)) {
  throw new Error("Usage: node scripts/ghidra-acceptance.mjs <absolute-workspace-root> <relative-rom-path>");
}
const romPath = path.resolve(workspaceRoot, romRelative);
if (!romPath.startsWith(`${workspaceRoot}${path.sep}`)) {
  throw new Error("ROM path escapes the acceptance workspace");
}

function compiledRoot() {
  const sourceBuild = path.resolve("dist", "src");
  const packagedBuild = path.resolve("dist");
  if (existsSync(path.join(sourceBuild, "services", "nds", "ghidra-project.js"))) return sourceBuild;
  if (existsSync(path.join(packagedBuild, "services", "nds", "ghidra-project.js"))) return packagedBuild;
  throw new Error("Build RE-MCP before running the Ghidra acceptance harness");
}

const dist = compiledRoot();
async function importBuilt(relative) {
  return await import(pathToFileURL(path.join(dist, relative)).href);
}

const { bootstrapNdsGhidraProject, readNdsGhidraStatus } = await importBuilt("services/nds/ghidra-project.js");
const { readNdsRomMap } = await importBuilt("services/nds/rom-map.js");
const { ghidraProjectName, ghidraProjectRoot } = await importBuilt("services/nds/ghidra-model.js");
const { runProcess } = await importBuilt("services/process-runner.js");

const ghidraHome = path.resolve(process.env.RE_MCP_GHIDRA_HOME ?? "");
if (!process.env.RE_MCP_GHIDRA_HOME) {
  throw new Error("RE_MCP_GHIDRA_HOME is required for real Ghidra acceptance");
}
const ghidraTimeoutMs = Number.parseInt(process.env.RE_MCP_GHIDRA_TIMEOUT_MS ?? "900000", 10);
const maxOutputBytes = Number.parseInt(process.env.RE_MCP_MAX_OUTPUT_BYTES ?? "1000000", 10);
const config = {
  workspaceRoot,
  commandTimeoutMs: 120_000,
  maxOutputBytes,
  ghidraHome,
  ghidraTimeoutMs,
};

function writeAsciiFixed(buffer, offset, length, value) {
  buffer.fill(0, offset, offset + length);
  buffer.write(value.slice(0, length), offset, length, "ascii");
}

function writeFatEntry(buffer, fatOffset, fileId, startOffset, endOffset) {
  const base = fatOffset + fileId * 8;
  buffer.writeUInt32LE(startOffset, base);
  buffer.writeUInt32LE(endOffset, base + 4);
}

function writeOverlayRecord(buffer, tableOffset, index, values) {
  const base = tableOffset + index * 32;
  buffer.writeUInt32LE(values.overlayId, base);
  buffer.writeUInt32LE(values.ramAddress, base + 0x04);
  buffer.writeUInt32LE(values.ramSize, base + 0x08);
  buffer.writeUInt32LE(values.bssSize, base + 0x0c);
  buffer.writeUInt32LE(0, base + 0x10);
  buffer.writeUInt32LE(0, base + 0x14);
  buffer.writeUInt32LE(values.fileId, base + 0x18);
  const packed = (values.compressedSize & 0x00ffffff) | ((values.flags & 0xff) << 24);
  buffer.writeUInt32LE(packed >>> 0, base + 0x1c);
}

async function writeSyntheticRom() {
  await mkdir(path.dirname(romPath), { recursive: true });
  const buffer = Buffer.alloc(0x5000);
  writeAsciiFixed(buffer, 0x00, 12, "RE-MCP GHIDRA");
  writeAsciiFixed(buffer, 0x0c, 4, "GHDR");
  writeAsciiFixed(buffer, 0x10, 2, "01");
  buffer.writeUInt8(0, 0x12);
  buffer.writeUInt8(8, 0x14);
  buffer.writeUInt8(0, 0x1e);

  buffer.writeUInt32LE(0x200, 0x20);
  buffer.writeUInt32LE(0x02000000, 0x24);
  buffer.writeUInt32LE(0x02000000, 0x28);
  buffer.writeUInt32LE(0x40, 0x2c);
  buffer.writeUInt32LE(0x600, 0x30);
  buffer.writeUInt32LE(0x03800000, 0x34);
  buffer.writeUInt32LE(0x03800000, 0x38);
  buffer.writeUInt32LE(0x20, 0x3c);

  buffer.writeUInt32LE(0x800, 0x40);
  buffer.writeUInt32LE(0, 0x44);
  buffer.writeUInt32LE(0x900, 0x48);
  buffer.writeUInt32LE(24, 0x4c);
  buffer.writeUInt32LE(0xa00, 0x50);
  buffer.writeUInt32LE(96, 0x54);
  buffer.writeUInt32LE(0xb00, 0x58);
  buffer.writeUInt32LE(0, 0x5c);
  buffer.writeUInt32LE(0xc00, 0x68);

  // ARM BLX immediate: from 0x02000000 to 0x02000008, proving a Thumb entry.
  buffer.writeUInt32LE(0xfa000000, 0x200);
  buffer.writeUInt32LE(0xe12fff1e, 0x204); // ARM BX LR
  buffer.set([0x70, 0x47], 0x208); // Thumb BX LR
  buffer.writeUInt32LE(0xe12fff1e, 0x600); // ARM7 BX LR

  writeFatEntry(buffer, 0x900, 0, 0x1000, 0x1020);
  writeFatEntry(buffer, 0x900, 1, 0x1100, 0x1120);
  writeFatEntry(buffer, 0x900, 2, 0x1200, 0x1220);
  writeOverlayRecord(buffer, 0xa00, 0, {
    overlayId: 1,
    ramAddress: 0x02200000,
    ramSize: 0x20,
    bssSize: 0x10,
    fileId: 0,
    compressedSize: 0,
    flags: 0,
  });
  writeOverlayRecord(buffer, 0xa00, 1, {
    overlayId: 2,
    ramAddress: 0x02200000,
    ramSize: 0x20,
    bssSize: 0,
    fileId: 1,
    compressedSize: 0,
    flags: 0,
  });
  writeOverlayRecord(buffer, 0xa00, 2, {
    overlayId: 3,
    ramAddress: 0x02210000,
    ramSize: 0x20,
    bssSize: 0,
    fileId: 2,
    compressedSize: 0x18,
    flags: 1,
  });
  buffer.writeUInt32LE(0xe12fff1e, 0x1000);
  buffer.writeUInt32LE(0xe12fff1e, 0x1100);
  buffer.fill(0xcc, 0x1200, 0x1220);
  await writeFile(romPath, buffer);
}

const INSPECT_SCRIPT = `// @category RE-MCP Acceptance
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;

public class ReMcpAcceptanceInspect extends GhidraScript {
    private static final String ANALYST_MARKER = "REMCP_ACCEPTANCE_ANALYST_MARKER";
    private static final long ANALYST_MARKER_ADDRESS = 0x02000004L;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("expected output path and action");
        Path output = Paths.get(args[0]).toAbsolutePath().normalize();
        String action = args[1];
        Address markerAddress = currentProgram.getAddressFactory()
            .getDefaultAddressSpace()
            .getAddress(ANALYST_MARKER_ADDRESS);
        SymbolTable symbols = currentProgram.getSymbolTable();
        Symbol marker = symbols.getGlobalSymbol(ANALYST_MARKER, markerAddress);
        if ("mark".equals(action)) {
            if (marker == null) {
                marker = symbols.createLabel(markerAddress, ANALYST_MARKER, SourceType.USER_DEFINED);
            }
        }
        else if (!"inspect".equals(action)) {
            throw new IllegalArgumentException("action must be mark or inspect");
        }

        StringBuilder text = new StringBuilder();
        text.append("program\\t").append(currentProgram.getName()).append("\\n");
        text.append("language\\t").append(currentProgram.getLanguageID().getIdAsString()).append("\\n");
        text.append("marker\\t").append(marker == null ? "" : marker.getName()).append("\\n");
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            text.append("block\\t")
                .append(block.getName()).append("\\t")
                .append(block.isOverlay()).append("\\t")
                .append(block.getStart().getAddressSpace().getName()).append("\\t")
                .append(Long.toUnsignedString(block.getStart().getOffset(), 16)).append("\\t")
                .append(block.getSize()).append("\\n");
        }

        PropertyMapManager maps = currentProgram.getUsrPropertyManager();
        StringPropertyMap modes = maps.getStringPropertyMap("re-mcp.function-mode");
        StringPropertyMap calls = maps.getStringPropertyMap("re-mcp.call-evidence");
        ProgramContext context = currentProgram.getProgramContext();
        Register tMode = context.getRegister("TMode");
        long[] probes = new long[] { 0x02000000L, 0x02000008L };
        for (long probe : probes) {
            Address address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(probe);
            String mode = modes == null ? null : modes.getString(address);
            if (mode != null) text.append("mode\\t").append(Long.toUnsignedString(probe, 16)).append("\\t").append(mode).append("\\n");
            String call = calls == null ? null : calls.getString(address);
            if (call != null) text.append("call\\t").append(Long.toUnsignedString(probe, 16)).append("\\ttrue\\n");
            if (tMode != null) {
                BigInteger value = context.getValue(tMode, address, false);
                if (value != null) text.append("tmode\\t").append(Long.toUnsignedString(probe, 16)).append("\\t").append(value).append("\\n");
            }
        }
        Files.writeString(output, text.toString(), StandardCharsets.UTF_8);
    }
}
`;

function parseInspection(text) {
  const result = { blocks: [], modes: new Map(), tmodes: new Map(), calls: new Set() };
  for (const line of text.trim().split(/\r?\n/u)) {
    if (!line) continue;
    const parts = line.split("\t");
    switch (parts[0]) {
      case "program": result.program = parts[1]; break;
      case "language": result.language = parts[1]; break;
      case "marker": result.marker = parts[1]; break;
      case "block": result.blocks.push({ name: parts[1], overlay: parts[2] === "true", space: parts[3], start: parts[4], size: Number(parts[5]) }); break;
      case "mode": result.modes.set(parts[1], parts[2]); break;
      case "tmode": result.tmodes.set(parts[1], parts[2]); break;
      case "call": result.calls.add(parts[1]); break;
      default: throw new Error(`Unknown acceptance inspection record: ${line}`);
    }
  }
  return result;
}

async function inspect(map, programName, action, scriptDirectory) {
  const output = path.join(scriptDirectory, `${programName}-${action}.txt`);
  const analyzeHeadless = path.join(ghidraHome, "support", "analyzeHeadless");
  const args = [
    ghidraProjectRoot(map, workspaceRoot),
    ghidraProjectName(map),
    "-process",
    programName,
    "-noanalysis",
    "-scriptPath",
    scriptDirectory,
    "-postScript",
    "ReMcpAcceptanceInspect.java",
    output,
    action,
  ];
  const run = await runProcess({
    executable: analyzeHeadless,
    args,
    cwd: workspaceRoot,
    timeoutMs: ghidraTimeoutMs,
    maxOutputBytes,
    terminateOnOutputLimit: true,
  });
  assert.equal(run.timedOut, false, `acceptance inspection timed out: ${programName}`);
  assert.equal(run.outputLimitExceeded, false, `acceptance inspection exceeded output bound: ${programName}`);
  assert.equal(run.signal, null, `acceptance inspection was signaled: ${programName}`);
  assert.equal(run.exitCode, 0, `${programName} acceptance inspection failed:\n${run.stderr}\n${run.stdout}`);
  return parseInspection(await readFile(output, "utf8"));
}

await mkdir(workspaceRoot, { recursive: true });
await writeSyntheticRom();
const scriptDirectory = await mkdtemp(path.join(os.tmpdir(), "re-mcp-ghidra-acceptance-"));
try {
  await writeFile(path.join(scriptDirectory, "ReMcpAcceptanceInspect.java"), INSPECT_SCRIPT, "utf8");
  const map = await readNdsRomMap(romPath);
  const first = await bootstrapNdsGhidraProject(romPath, config);
  assert.equal(first.runKind, "initial");
  assert.equal(first.sourceRomSha256, map.sha256);
  assert.deepEqual(first.processors.map((entry) => entry.processor), ["arm9", "arm7"]);

  const status = await readNdsGhidraStatus(romPath, config);
  assert.equal(status.projectExists, true);
  assert.equal(status.bridgeExists, true);
  assert.equal(status.sourceRomSha256, map.sha256);
  const arm9Status = status.processors.find((entry) => entry.processor === "arm9");
  const arm7Status = status.processors.find((entry) => entry.processor === "arm7");
  assert.equal(arm9Status?.language, "ARM:LE:32:v5t");
  assert.equal(arm7Status?.language, "ARM:LE:32:v4t");
  assert.deepEqual(arm9Status?.compressedOverlayIds, [3]);

  const bridgeManifestPath = path.join(
    workspaceRoot,
    "analysis",
    "generated",
    "nds",
    map.sha256Prefix,
    "ghidra-bridge",
    "manifest.json",
  );
  const manifestText = await readFile(bridgeManifestPath, "utf8");
  const manifest = JSON.parse(manifestText);
  assert.equal(manifestText.includes("functionEnd"), false);
  assert.equal(manifestText.includes("bodyEnd"), false);
  assert.equal(manifestText.includes("bodySize"), false);
  const arm9Discovery = manifest.discovery.find((entry) => entry.processor === "arm9");
  assert.deepEqual(
    arm9Discovery.functions.map((entry) => [entry.entry.runtimeAddress, entry.entry.mode]),
    [[0x02000000, "arm"], [0x02000008, "thumb"]],
  );

  const arm9Before = await inspect(map, "RE-MCP_ARM9", "mark", scriptDirectory);
  const arm7Before = await inspect(map, "RE-MCP_ARM7", "inspect", scriptDirectory);
  assert.equal(arm9Before.program, "RE-MCP_ARM9");
  assert.equal(arm9Before.language, "ARM:LE:32:v5t");
  assert.equal(arm7Before.program, "RE-MCP_ARM7");
  assert.equal(arm7Before.language, "ARM:LE:32:v4t");
  assert.equal(arm9Before.marker, "REMCP_ACCEPTANCE_ANALYST_MARKER");

  const overlay1 = arm9Before.blocks.find((entry) => entry.name === "RE_MCP_ARM9_OVL_1");
  const overlay2 = arm9Before.blocks.find((entry) => entry.name === "RE_MCP_ARM9_OVL_2");
  assert.equal(overlay1?.overlay, true);
  assert.equal(overlay2?.overlay, true);
  assert.equal(overlay1?.start, "2200000");
  assert.equal(overlay2?.start, "2200000");
  assert.equal(overlay1?.space, "RE_MCP_ARM9_OVL_1");
  assert.equal(overlay2?.space, "RE_MCP_ARM9_OVL_2");
  assert.equal(arm9Before.blocks.some((entry) => entry.name.includes("OVL_3")), false);
  assert.equal(arm9Before.modes.get("2000000"), "arm");
  assert.equal(arm9Before.modes.get("2000008"), "thumb");
  assert.equal(arm9Before.tmodes.get("2000000"), "0");
  assert.equal(arm9Before.tmodes.get("2000008"), "1");
  assert.equal(arm9Before.calls.has("2000000"), true);

  const second = await bootstrapNdsGhidraProject(romPath, config);
  assert.equal(second.runKind, "already-current");
  const arm9After = await inspect(map, "RE-MCP_ARM9", "inspect", scriptDirectory);
  assert.equal(arm9After.marker, "REMCP_ACCEPTANCE_ANALYST_MARKER");
  assert.deepEqual(
    arm9After.blocks.filter((entry) => entry.name === "RE_MCP_ARM9_OVL_1" || entry.name === "RE_MCP_ARM9_OVL_2"),
    arm9Before.blocks.filter((entry) => entry.name === "RE_MCP_ARM9_OVL_1" || entry.name === "RE_MCP_ARM9_OVL_2"),
  );

  process.stdout.write(`${JSON.stringify({
    ok: true,
    ghidraVersion: first.ghidraVersion,
    sourceRomSha256: map.sha256,
    firstRun: first.runKind,
    secondRun: second.runKind,
    overlappingOverlaySpaces: [overlay1?.space, overlay2?.space],
    compressedOverlayIds: arm9Status?.compressedOverlayIds,
    provenModes: Object.fromEntries(arm9Before.modes),
    analystMarkerPreserved: arm9After.marker === "REMCP_ACCEPTANCE_ANALYST_MARKER",
  }, null, 2)}\n`);
} finally {
  await rm(scriptDirectory, { recursive: true, force: true });
}
