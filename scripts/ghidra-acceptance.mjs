import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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

const COMPRESSED_OVERLAY_ID = 3;
const COMPRESSED_RUNTIME_ADDRESS = 0x02210000;
const COMPRESSED_STORED_OFFSET = 0x1200;
const COMPRESSED_ARM_CODE_STORED = Buffer.from(
  "060000eb0034009fe5000000ea0000000df0110021a010402d1ce91eff2f0d606000201002011001f001f001f001f001f001f0fe01f001f001f001f00000a0e10f49000008b7000000",
  "hex",
);
const COMPRESSED_ARM_CODE_HEAD = Buffer.from(
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
const COMPRESSED_ARM_CODE_DECODED = Buffer.concat([
  COMPRESSED_ARM_CODE_HEAD,
  Buffer.from("0000a0e1".repeat(47), "hex"),
]);

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

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
  const buffer = Buffer.alloc(0x6000);
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

  // ARM9 entry: prove a compressed-overlay function, then a Thumb function.
  buffer.writeUInt32LE(0xeb083ffe, 0x200); // BL 0x02210000
  buffer.writeUInt32LE(0xfa000001, 0x204); // BLX 0x02000010
  buffer.writeUInt32LE(0xe12fff1e, 0x208); // ARM BX LR
  buffer.writeUInt32LE(0xe1a00000, 0x20c); // ARM NOP
  buffer.set([0x70, 0x47], 0x210); // Thumb BX LR
  buffer.writeUInt32LE(0xe12fff1e, 0x600); // ARM7 BX LR

  writeFatEntry(buffer, 0x900, 0, 0x1000, 0x1020);
  writeFatEntry(buffer, 0x900, 1, 0x1100, 0x1120);
  const compressedBackingSize = COMPRESSED_ARM_CODE_STORED.length + 8;
  writeFatEntry(
    buffer,
    0x900,
    2,
    COMPRESSED_STORED_OFFSET,
    COMPRESSED_STORED_OFFSET + compressedBackingSize,
  );
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
    overlayId: COMPRESSED_OVERLAY_ID,
    ramAddress: COMPRESSED_RUNTIME_ADDRESS,
    ramSize: COMPRESSED_ARM_CODE_DECODED.length,
    bssSize: 0x20,
    fileId: 2,
    compressedSize: COMPRESSED_ARM_CODE_STORED.length,
    flags: 1,
  });
  buffer.writeUInt32LE(0xe12fff1e, 0x1000);
  buffer.writeUInt32LE(0xe12fff1e, 0x1100);
  COMPRESSED_ARM_CODE_STORED.copy(buffer, COMPRESSED_STORED_OFFSET);
  buffer.fill(
    0x5a,
    COMPRESSED_STORED_OFFSET + COMPRESSED_ARM_CODE_STORED.length,
    COMPRESSED_STORED_OFFSET + compressedBackingSize,
  );
  await writeFile(romPath, buffer);
}

const INSPECT_SCRIPT = `// @category RE-MCP Acceptance
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;

public class ReMcpAcceptanceInspect extends GhidraScript {
    private static final String ANALYST_MARKER = "REMCP_ACCEPTANCE_ANALYST_MARKER";
    private static final long ANALYST_MARKER_ADDRESS = 0x0200000cL;
    private static final String DERIVED_SPACE = "RE_MCP_ARM9_OVL_3";
    private static final String DERIVED_BSS = "RE_MCP_ARM9_OVL_3_BSS";

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("expected output path and action");
        Path output = Paths.get(args[0]).toAbsolutePath().normalize();
        String action = args[1];
        Memory memory = currentProgram.getMemory();
        Options info = currentProgram.getOptions(Program.PROGRAM_INFO);
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
        else if ("downgrade-v1".equals(action)) {
            info.setString("re-mcp.bridge-format", "re-mcp-nds-ghidra:1");
            for (int overlayId : new int[] { 1, 2, 3 }) {
                info.removeOption("re-mcp.overlay." + overlayId + ".representation");
                info.removeOption("re-mcp.overlay." + overlayId + ".runtime-sha256");
            }
            MemoryBlock bss = memory.getBlock(DERIVED_BSS);
            if (bss != null) memory.removeBlock(bss, monitor);
            MemoryBlock derived = memory.getBlock(DERIVED_SPACE);
            if (derived != null) memory.removeBlock(derived, monitor);
        }
        else if ("tamper-derived".equals(action)) {
            MemoryBlock derived = requireDerived(memory);
            Address start = derived.getStart();
            memory.setByte(start, (byte)(memory.getByte(start) ^ 0xff));
        }
        else if ("restore-derived".equals(action)) {
            MemoryBlock derived = requireDerived(memory);
            memory.setByte(derived.getStart(), (byte)0x06);
        }
        else if (!"inspect".equals(action)) {
            throw new IllegalArgumentException("unknown acceptance action: " + action);
        }

        marker = symbols.getGlobalSymbol(ANALYST_MARKER, markerAddress);
        StringBuilder text = new StringBuilder();
        text.append("program\\t").append(currentProgram.getName()).append("\\n");
        text.append("language\\t").append(currentProgram.getLanguageID().getIdAsString()).append("\\n");
        text.append("marker\\t").append(marker == null ? "" : marker.getName()).append("\\n");
        text.append("owner\\tbridge-format\\t").append(info.getString("re-mcp.bridge-format", "")).append("\\n");
        text.append("owner\\toverlay3-representation\\t").append(info.getString("re-mcp.overlay.3.representation", "")).append("\\n");
        text.append("owner\\toverlay3-runtime-sha256\\t").append(info.getString("re-mcp.overlay.3.runtime-sha256", "")).append("\\n");

        for (MemoryBlock block : memory.getBlocks()) {
            text.append("block\\t")
                .append(block.getName()).append("\\t")
                .append(block.isOverlay()).append("\\t")
                .append(block.isInitialized()).append("\\t")
                .append(block.getStart().getAddressSpace().getName()).append("\\t")
                .append(Long.toUnsignedString(block.getStart().getOffset(), 16)).append("\\t")
                .append(block.getSize()).append("\\t")
                .append(block.isInitialized() ? sha256Block(memory, block) : "-").append("\\n");
        }

        PropertyMapManager maps = currentProgram.getUsrPropertyManager();
        StringPropertyMap modes = maps.getStringPropertyMap("re-mcp.function-mode");
        StringPropertyMap calls = maps.getStringPropertyMap("re-mcp.call-evidence");
        ProgramContext context = currentProgram.getProgramContext();
        Register tMode = context.getRegister("TMode");
        AddressFactory factory = currentProgram.getAddressFactory();
        probe(text, "main0", factory.getDefaultAddressSpace().getAddress(0x02000000L), modes, calls, context, tMode);
        probe(text, "main4", factory.getDefaultAddressSpace().getAddress(0x02000004L), modes, calls, context, tMode);
        probe(text, "main10", factory.getDefaultAddressSpace().getAddress(0x02000010L), modes, calls, context, tMode);
        AddressSpace overlaySpace = factory.getAddressSpace(DERIVED_SPACE);
        if (overlaySpace != null) {
            probe(text, "ovl3_0", overlaySpace.getAddress(0x02210000L), modes, calls, context, tMode);
            probe(text, "ovl3_20", overlaySpace.getAddress(0x02210020L), modes, calls, context, tMode);
        }
        Files.writeString(output, text.toString(), StandardCharsets.UTF_8);
    }

    private MemoryBlock requireDerived(Memory memory) {
        MemoryBlock block = memory.getBlock(DERIVED_SPACE);
        if (block == null) throw new IllegalStateException("derived overlay is absent");
        return block;
    }

    private void probe(
            StringBuilder text,
            String label,
            Address address,
            StringPropertyMap modes,
            StringPropertyMap calls,
            ProgramContext context,
            Register tMode) {
        String mode = modes == null ? null : modes.getString(address);
        if (mode != null) text.append("mode\\t").append(label).append("\\t").append(mode).append("\\n");
        String call = calls == null ? null : calls.getString(address);
        if (call != null) text.append("call\\t").append(label).append("\\ttrue\\n");
        if (tMode != null) {
            BigInteger value = context.getValue(tMode, address, false);
            if (value != null) text.append("tmode\\t").append(label).append("\\t").append(value).append("\\n");
        }
    }

    private String sha256Block(Memory memory, MemoryBlock block) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long remaining = block.getSize();
        Address cursor = block.getStart();
        byte[] buffer = new byte[8192];
        while (remaining > 0) {
            int requested = (int)Math.min((long)buffer.length, remaining);
            int count = memory.getBytes(cursor, buffer, 0, requested);
            if (count != requested) throw new IllegalStateException("short memory read");
            digest.update(buffer, 0, count);
            remaining -= count;
            if (remaining > 0) cursor = cursor.add(count);
        }
        StringBuilder result = new StringBuilder(64);
        for (byte value : digest.digest()) result.append(String.format("%02x", value & 0xff));
        return result.toString();
    }
}
`;

function parseInspection(text) {
  const result = {
    blocks: [],
    modes: new Map(),
    tmodes: new Map(),
    calls: new Set(),
    owners: new Map(),
  };
  for (const line of text.trim().split(/\r?\n/u)) {
    if (!line) continue;
    const parts = line.split("\t");
    switch (parts[0]) {
      case "program": result.program = parts[1]; break;
      case "language": result.language = parts[1]; break;
      case "marker": result.marker = parts[1]; break;
      case "owner": result.owners.set(parts[1], parts[2]); break;
      case "block": result.blocks.push({
        name: parts[1],
        overlay: parts[2] === "true",
        initialized: parts[3] === "true",
        space: parts[4],
        start: parts[5],
        size: Number(parts[6]),
        sha256: parts[7],
      }); break;
      case "mode": result.modes.set(parts[1], parts[2]); break;
      case "tmode": result.tmodes.set(parts[1], parts[2]); break;
      case "call": result.calls.add(parts[1]); break;
      default: throw new Error(`Unknown acceptance inspection record: ${line}`);
    }
  }
  return result;
}

async function inspect(map, programName, action, scriptDirectory) {
  const output = path.join(scriptDirectory, `${programName}-${action}-${Date.now()}.txt`);
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

function requireBlock(inspection, name) {
  const block = inspection.blocks.find((entry) => entry.name === name);
  assert.ok(block, `missing acceptance block ${name}`);
  return block;
}

async function makeStateStale(map) {
  const stateRoot = path.join(
    workspaceRoot,
    "analysis",
    "ghidra",
    "nds",
    map.sha256,
    "state",
  );
  for (const name of ["latest-run.json", "latest-success.json"]) {
    const file = path.join(stateRoot, name);
    const state = JSON.parse(await readFile(file, "utf8"));
    state.manifestSha256 = "0".repeat(64);
    state.stage = "acceptance-v1-project";
    for (const processor of state.processors ?? []) {
      processor.manifestSha256 = "0".repeat(64);
    }
    await writeFile(file, `${JSON.stringify(state, null, 2)}\n`, "utf8");
  }
}

const applicationLog = path.join(
  os.homedir(),
  ".config",
  "ghidra",
  "ghidra_12.1.2_PUBLIC",
  "application.log",
);

async function assertNoHiddenGhidraErrors(label) {
  if (!existsSync(applicationLog)) return;
  const text = await readFile(applicationLog, "utf8");
  assert.doesNotMatch(text, /REPORT SCRIPT ERROR|Exception/u, `${label}: hidden Ghidra error found`);
}

await mkdir(workspaceRoot, { recursive: true });
await writeSyntheticRom();
const sourceRomBefore = sha256(await readFile(romPath));
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
  assert.equal(arm9Status?.importedOverlays, 3);
  assert.deepEqual(arm9Status?.compressedOverlayIds, [COMPRESSED_OVERLAY_ID]);

  const generatedRoot = path.join(
    workspaceRoot,
    "analysis",
    "generated",
    "nds",
    map.sha256Prefix,
  );
  const bridgeManifestPath = path.join(generatedRoot, "ghidra-bridge", "manifest.json");
  const manifestText = await readFile(bridgeManifestPath, "utf8");
  const manifest = JSON.parse(manifestText);
  assert.equal(manifest.formatVersion, 2);
  assert.equal(manifestText.includes("functionEnd"), false);
  assert.equal(manifestText.includes("bodyEnd"), false);
  assert.equal(manifestText.includes("bodySize"), false);

  const arm9Manifest = manifest.processors.find((entry) => entry.processor === "arm9");
  const derivedManifest = arm9Manifest.overlays.find((entry) => entry.overlayId === COMPRESSED_OVERLAY_ID);
  assert.equal(derivedManifest.importStatus, "importable-derived");
  assert.equal(derivedManifest.representation, "derived-blz");
  assert.equal(derivedManifest.compressedSize, COMPRESSED_ARM_CODE_STORED.length);
  assert.equal(derivedManifest.initializedSize, COMPRESSED_ARM_CODE_DECODED.length);
  assert.equal(derivedManifest.ramSize, COMPRESSED_ARM_CODE_DECODED.length);
  assert.equal(derivedManifest.bssSize, 0x20);

  const rawStored = await readFile(path.join(generatedRoot, "overlays", "arm9", "overlay_3.bin"));
  const runtimeBytes = await readFile(path.join(generatedRoot, "runtime", "overlays", "arm9", "overlay_3.bin"));
  assert.equal(rawStored.length, COMPRESSED_ARM_CODE_STORED.length + 8);
  assert.equal(rawStored.subarray(0, COMPRESSED_ARM_CODE_STORED.length).equals(COMPRESSED_ARM_CODE_STORED), true);
  assert.equal(runtimeBytes.equals(COMPRESSED_ARM_CODE_DECODED), true);
  assert.equal(runtimeBytes.equals(rawStored), false);
  assert.equal(derivedManifest.storedSha256, sha256(rawStored));
  assert.equal(derivedManifest.runtimeSha256, sha256(runtimeBytes));

  const arm9Discovery = manifest.discovery.find((entry) => entry.processor === "arm9");
  assert.ok(arm9Discovery.functions.some((entry) =>
    entry.entry.component === "overlay"
    && entry.entry.overlayId === COMPRESSED_OVERLAY_ID
    && entry.entry.runtimeAddress === COMPRESSED_RUNTIME_ADDRESS));
  assert.ok(arm9Discovery.calls.some((entry) =>
    entry.instructionAddress === COMPRESSED_RUNTIME_ADDRESS
    && entry.instructionRomOffset === null));

  const arm9Before = await inspect(map, "RE-MCP_ARM9", "mark", scriptDirectory);
  const arm7Before = await inspect(map, "RE-MCP_ARM7", "inspect", scriptDirectory);
  assert.equal(arm9Before.program, "RE-MCP_ARM9");
  assert.equal(arm9Before.language, "ARM:LE:32:v5t");
  assert.equal(arm7Before.program, "RE-MCP_ARM7");
  assert.equal(arm7Before.language, "ARM:LE:32:v4t");
  assert.equal(arm9Before.marker, "REMCP_ACCEPTANCE_ANALYST_MARKER");
  assert.equal(arm9Before.owners.get("bridge-format"), "re-mcp-nds-ghidra:2");
  assert.equal(arm9Before.owners.get("overlay3-representation"), "derived-blz");
  assert.equal(arm9Before.owners.get("overlay3-runtime-sha256"), derivedManifest.runtimeSha256);

  const overlay1 = requireBlock(arm9Before, "RE_MCP_ARM9_OVL_1");
  const overlay2 = requireBlock(arm9Before, "RE_MCP_ARM9_OVL_2");
  const overlay3 = requireBlock(arm9Before, "RE_MCP_ARM9_OVL_3");
  const overlay3Bss = requireBlock(arm9Before, "RE_MCP_ARM9_OVL_3_BSS");
  assert.equal(overlay1.overlay, true);
  assert.equal(overlay2.overlay, true);
  assert.equal(overlay1.start, "2200000");
  assert.equal(overlay2.start, "2200000");
  assert.equal(overlay1.space, "RE_MCP_ARM9_OVL_1");
  assert.equal(overlay2.space, "RE_MCP_ARM9_OVL_2");
  assert.equal(overlay3.initialized, true);
  assert.equal(overlay3.size, COMPRESSED_ARM_CODE_DECODED.length);
  assert.equal(overlay3.sha256, derivedManifest.runtimeSha256);
  assert.equal(overlay3Bss.initialized, false);
  assert.equal(overlay3Bss.size, 0x20);
  assert.equal(arm9Before.modes.get("main0"), "arm");
  assert.equal(arm9Before.modes.get("main10"), "thumb");
  assert.equal(arm9Before.modes.get("ovl3_0"), "arm");
  assert.equal(arm9Before.modes.get("ovl3_20"), "arm");
  assert.equal(arm9Before.calls.has("main0"), true);
  assert.equal(arm9Before.calls.has("main4"), true);
  assert.equal(arm9Before.calls.has("ovl3_0"), true);

  // Simulate a trusted v1 project: retain v1 uncompressed overlay blocks and
  // analyst state, remove the formerly omitted compressed overlay, and clear
  // only the v2 per-overlay ownership keys.
  const downgraded = await inspect(map, "RE-MCP_ARM9", "downgrade-v1", scriptDirectory);
  assert.equal(downgraded.marker, "REMCP_ACCEPTANCE_ANALYST_MARKER");
  assert.equal(downgraded.owners.get("bridge-format"), "re-mcp-nds-ghidra:1");
  assert.equal(downgraded.blocks.some((entry) => entry.name === "RE_MCP_ARM9_OVL_3"), false);
  await makeStateStale(map);

  const migrated = await bootstrapNdsGhidraProject(romPath, config);
  assert.equal(migrated.runKind, "reconciled");
  const afterMigration = await inspect(map, "RE-MCP_ARM9", "inspect", scriptDirectory);
  assert.equal(afterMigration.marker, "REMCP_ACCEPTANCE_ANALYST_MARKER");
  assert.equal(afterMigration.owners.get("bridge-format"), "re-mcp-nds-ghidra:2");
  assert.equal(afterMigration.owners.get("overlay3-representation"), "derived-blz");
  assert.equal(requireBlock(afterMigration, "RE_MCP_ARM9_OVL_3").sha256, derivedManifest.runtimeSha256);
  assert.equal(requireBlock(afterMigration, "RE_MCP_ARM9_OVL_3_BSS").initialized, false);

  // A v2-owned block whose bytes changed must fail closed. The acceptance-only
  // helper restores the byte afterwards so the read-only inspection acceptance
  // can run against a healthy project.
  const tampered = await inspect(map, "RE-MCP_ARM9", "tamper-derived", scriptDirectory);
  const tamperedHash = requireBlock(tampered, "RE_MCP_ARM9_OVL_3").sha256;
  assert.notEqual(tamperedHash, derivedManifest.runtimeSha256);
  await assertNoHiddenGhidraErrors("before expected conflict test");
  await rm(applicationLog, { force: true });
  await assert.rejects(
    bootstrapNdsGhidraProject(romPath, config),
    (error) => error?.category === "ghidra-analysis-failed"
      && String(error.message).includes("runtime bytes do not match runtimeSha256"),
  );
  const afterRejectedConflict = await inspect(map, "RE-MCP_ARM9", "inspect", scriptDirectory);
  assert.equal(requireBlock(afterRejectedConflict, "RE_MCP_ARM9_OVL_3").sha256, tamperedHash,
    "failed reconciliation must not replace the conflicting owned block");
  assert.equal(afterRejectedConflict.marker, "REMCP_ACCEPTANCE_ANALYST_MARKER");
  const expectedFailureLog = existsSync(applicationLog) ? await readFile(applicationLog, "utf8") : "";
  assert.match(expectedFailureLog, /runtime bytes do not match runtimeSha256/,
    "expected Ghidra conflict diagnostic was not recorded");
  await rm(applicationLog, { force: true });

  await inspect(map, "RE-MCP_ARM9", "restore-derived", scriptDirectory);
  const finalRun = await bootstrapNdsGhidraProject(romPath, config);
  assert.equal(finalRun.runKind, "already-current");
  const arm9After = await inspect(map, "RE-MCP_ARM9", "inspect", scriptDirectory);
  assert.equal(arm9After.marker, "REMCP_ACCEPTANCE_ANALYST_MARKER");
  assert.equal(requireBlock(arm9After, "RE_MCP_ARM9_OVL_3").sha256, derivedManifest.runtimeSha256);
  assert.equal(sha256(await readFile(romPath)), sourceRomBefore, "Ghidra acceptance changed source ROM bytes");
  await assertNoHiddenGhidraErrors("after final recovery");

  process.stdout.write(`${JSON.stringify({
    ok: true,
    ghidraVersion: first.ghidraVersion,
    sourceRomSha256: map.sha256,
    initialRun: first.runKind,
    migrationRun: migrated.runKind,
    finalRun: finalRun.runKind,
    overlappingOverlaySpaces: [overlay1.space, overlay2.space],
    compressedOverlayIds: arm9Status?.compressedOverlayIds,
    compressedRuntimeSha256: derivedManifest.runtimeSha256,
    compressedStoredSha256: derivedManifest.storedSha256,
    compressedBssUninitialized: overlay3Bss.initialized === false,
    v1MigrationPreservedAnalystMarker: afterMigration.marker === "REMCP_ACCEPTANCE_ANALYST_MARKER",
    conflictingOwnedBlockRejectedWithoutReplacement: true,
    sourceRomPreserved: true,
  }, null, 2)}\n`);
} finally {
  await rm(scriptDirectory, { recursive: true, force: true });
}
