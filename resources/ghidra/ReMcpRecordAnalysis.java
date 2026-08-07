// @category RE-MCP

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

public class ReMcpRecordAnalysis extends GhidraScript {
    private static final String BRIDGE_FORMAT = "re-mcp-nds-ghidra";
    private static final int BRIDGE_FORMAT_VERSION = 1;

    private static final String KEY_BRIDGE_FORMAT = "re-mcp.bridge-format";
    private static final String KEY_ROM_SHA = "re-mcp.rom-sha256";
    private static final String KEY_MANIFEST_SHA = "re-mcp.manifest-sha256";
    private static final String KEY_PROCESSOR = "re-mcp.processor";
    private static final String KEY_LAST_IMPORT = "re-mcp.last-import";
    private static final String KEY_ANALYSIS_STATUS = "re-mcp.last-analysis-status";
    private static final String KEY_GHIDRA_VERSION = "re-mcp.ghidra-version";

    private final Gson gson = new GsonBuilder()
        .disableHtmlEscaping()
        .setPrettyPrinting()
        .create();

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException("expected manifest, processor, result path");
        }

        Path manifestPath = Paths.get(args[0]).toAbsolutePath().normalize();
        String processor = requireProcessor(args[1]);
        Path requestedResultPath = Paths.get(args[2]).toAbsolutePath().normalize();
        JsonObject manifest = readManifest(manifestPath);
        JsonObject processorManifest = processorManifest(manifest, processor);
        JsonObject discovery = discoveryFor(manifest, processor);
        String manifestSha256 = sha256(manifestPath);
        String sourceRomSha256 = requireString(manifest, "sourceRomSha256");
        String programName = requireString(processorManifest, "programName");
        String language = requireString(processorManifest, "language");
        String ghidraVersion = Application.getApplicationVersion();

        Path expectedResultPath = expectedResultPath(manifestPath, manifest, processor);
        if (!requestedResultPath.equals(expectedResultPath)) {
            throw new IllegalArgumentException(
                "result path does not match manifest generatedResultPaths for " + processor);
        }

        Options info = currentProgram.getOptions(Program.PROGRAM_INFO);
        requireOwnedValue(info, KEY_ROM_SHA, sourceRomSha256);
        requireOwnedValue(info, KEY_MANIFEST_SHA, manifestSha256);
        requireOwnedValue(info, KEY_PROCESSOR, processor);
        requireOwnedValue(info, KEY_BRIDGE_FORMAT, BRIDGE_FORMAT + ":" + BRIDGE_FORMAT_VERSION);
        if (!programName.equals(currentProgram.getName())) {
            throw new IllegalStateException(
                "program name mismatch: expected " + programName + ", found " + currentProgram.getName());
        }
        if (!language.equals(currentProgram.getLanguageID().getIdAsString())) {
            throw new IllegalStateException("program language no longer matches bridge manifest");
        }

        JsonArray compressedOverlayIds = new JsonArray();
        int importedOverlays = 0;
        for (JsonElement element : requireArray(processorManifest, "overlays")) {
            JsonObject overlay = element.getAsJsonObject();
            String importStatus = requireString(overlay, "importStatus");
            if ("importable".equals(importStatus)) {
                validateImportedOverlay(overlay);
                importedOverlays += 1;
            }
            else if ("not-imported-compressed".equals(importStatus)) {
                compressedOverlayIds.add(requireInt(overlay, "overlayId"));
            }
            else {
                throw new IllegalArgumentException("unknown overlay import status: " + importStatus);
            }
        }

        int provenEntries = requireArray(discovery, "functions").size();
        int directCalls = requireArray(discovery, "calls").size();

        JsonObject result = new JsonObject();
        result.addProperty("format", "re-mcp-nds-ghidra-processor-result");
        result.addProperty("formatVersion", 1);
        result.addProperty("sourceRomSha256", sourceRomSha256);
        result.addProperty("manifestSha256", manifestSha256);
        result.addProperty("processor", processor);
        result.addProperty("programName", programName);
        result.addProperty("language", language);
        result.addProperty("analysisStatus", "complete");
        result.addProperty("ghidraVersion", ghidraVersion);
        result.addProperty("importedOverlays", importedOverlays);
        result.add("compressedOverlayIds", compressedOverlayIds);
        result.addProperty("provenEntries", provenEntries);
        result.addProperty("directCalls", directCalls);

        info.setString(KEY_LAST_IMPORT, manifestSha256);
        info.setString(KEY_ANALYSIS_STATUS, "complete");
        info.setString(KEY_GHIDRA_VERSION, ghidraVersion);

        writeAtomically(requestedResultPath, gson.toJson(result) + "\n");
    }

    private JsonObject readManifest(Path manifestPath) throws Exception {
        if (!Files.isRegularFile(manifestPath)) {
            throw new IllegalArgumentException("manifest is not a regular file: " + manifestPath);
        }
        try (var reader = Files.newBufferedReader(manifestPath, StandardCharsets.UTF_8)) {
            JsonObject manifest = JsonParser.parseReader(reader).getAsJsonObject();
            if (!BRIDGE_FORMAT.equals(requireString(manifest, "format")) ||
                    requireInt(manifest, "formatVersion") != BRIDGE_FORMAT_VERSION) {
                throw new IllegalArgumentException("unsupported RE-MCP Ghidra bridge manifest");
            }
            return manifest;
        }
    }

    private String requireProcessor(String processor) {
        if (!processor.equals("arm9") && !processor.equals("arm7")) {
            throw new IllegalArgumentException("processor must be arm9 or arm7");
        }
        return processor;
    }

    private JsonObject processorManifest(JsonObject manifest, String processor) {
        for (JsonElement element : requireArray(manifest, "processors")) {
            JsonObject candidate = element.getAsJsonObject();
            if (processor.equals(requireString(candidate, "processor"))) {
                return candidate;
            }
        }
        throw new IllegalArgumentException("manifest has no processor record for " + processor);
    }

    private JsonObject discoveryFor(JsonObject manifest, String processor) {
        for (JsonElement element : requireArray(manifest, "discovery")) {
            JsonObject candidate = element.getAsJsonObject();
            if (processor.equals(requireString(candidate, "processor"))) {
                return candidate;
            }
        }
        throw new IllegalArgumentException("manifest has no discovery record for " + processor);
    }

    private void validateImportedOverlay(JsonObject overlay) {
        int overlayId = requireInt(overlay, "overlayId");
        String spaceName = requireString(overlay, "spaceName");
        long runtimeAddress = requireUint32(overlay, "runtimeAddress");
        long ramSize = requireNonNegativeLong(overlay, "ramSize");
        long fileBackedSize = requireNonNegativeLong(overlay, "fileBackedSize");
        long initializedSize = Math.min(ramSize, fileBackedSize);
        if (initializedSize <= 0) {
            throw new IllegalStateException(
                "importable overlay has no initialized runtime bytes: " + overlayId);
        }

        MemoryBlock block = currentProgram.getMemory().getBlock(spaceName);
        if (block == null ||
                !spaceName.equals(block.getName()) ||
                !block.isOverlay() ||
                !spaceName.equals(block.getStart().getAddressSpace().getName()) ||
                block.getStart().getOffset() != runtimeAddress ||
                block.getSize() != initializedSize) {
            throw new IllegalStateException(
                "importable overlay is missing or conflicts with canonical metadata: " + spaceName);
        }

        long bssSize = requireNonNegativeLong(overlay, "bssSize");
        if (bssSize > 0) {
            long bssOffset = addUint32(runtimeAddress, ramSize, "overlay BSS start");
            String bssName = spaceName + "_BSS";
            MemoryBlock bss = currentProgram.getMemory().getBlock(bssName);
            if (bss == null ||
                    !bssName.equals(bss.getName()) ||
                    !bss.isOverlay() ||
                    !spaceName.equals(bss.getStart().getAddressSpace().getName()) ||
                    bss.getStart().getOffset() != bssOffset ||
                    bss.getSize() != bssSize) {
                throw new IllegalStateException(
                    "overlay BSS is missing or conflicts with canonical metadata: " + bssName);
            }
        }
    }

    private Path expectedResultPath(
            Path manifestPath,
            JsonObject manifest,
            String processor) {
        JsonObject generatedResultPaths = requireObject(manifest, "generatedResultPaths");
        String relative = requireString(generatedResultPaths, processor);
        Path bridgeRoot = manifestPath.getParent();
        if (bridgeRoot == null) {
            throw new IllegalArgumentException("manifest has no bridge parent directory");
        }
        Path normalizedBridgeRoot = bridgeRoot.toAbsolutePath().normalize();
        Path expected = normalizedBridgeRoot.resolve(relative).toAbsolutePath().normalize();
        if (!expected.startsWith(normalizedBridgeRoot)) {
            throw new IllegalArgumentException("generatedResultPaths escapes the bridge root");
        }
        return expected;
    }

    private void requireOwnedValue(Options info, String key, String expected) {
        String actual = info.getString(key, null);
        if (!expected.equals(actual)) {
            throw new IllegalStateException(
                "RE-MCP program metadata mismatch for " + key + ": expected " + expected + ", found " + actual);
        }
    }

    private void writeAtomically(Path resultPath, String content) throws Exception {
        Path parent = resultPath.getParent();
        if (parent == null) {
            throw new IllegalArgumentException("result path has no parent");
        }
        Files.createDirectories(parent);
        Path temporary = Files.createTempFile(parent, resultPath.getFileName().toString() + ".", ".tmp");
        boolean promoted = false;
        try {
            Files.writeString(
                temporary,
                content,
                StandardCharsets.UTF_8,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE);
            try {
                Files.move(
                    temporary,
                    resultPath,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            }
            catch (AtomicMoveNotSupportedException unsupported) {
                Files.move(temporary, resultPath, StandardCopyOption.REPLACE_EXISTING);
            }
            promoted = true;
        }
        finally {
            if (!promoted) {
                Files.deleteIfExists(temporary);
            }
        }
    }

    private String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(path)) {
            byte[] buffer = new byte[8192];
            for (int count = input.read(buffer); count >= 0; count = input.read(buffer)) {
                if (count > 0) {
                    digest.update(buffer, 0, count);
                }
            }
        }
        StringBuilder result = new StringBuilder(64);
        for (byte value : digest.digest()) {
            result.append(String.format("%02x", value & 0xff));
        }
        return result.toString();
    }

    private long addUint32(long left, long right, String label) {
        long value = left + right;
        if (left < 0 || right < 0 || value < 0 || value > 0xffffffffL) {
            throw new IllegalArgumentException(label + " exceeds 32-bit address space");
        }
        return value;
    }

    private JsonArray requireArray(JsonObject object, String key) {
        JsonElement value = object.get(key);
        if (value == null || !value.isJsonArray()) {
            throw new IllegalArgumentException("manifest field is not an array: " + key);
        }
        return value.getAsJsonArray();
    }

    private JsonObject requireObject(JsonObject object, String key) {
        JsonElement value = object.get(key);
        if (value == null || !value.isJsonObject()) {
            throw new IllegalArgumentException("manifest field is not an object: " + key);
        }
        return value.getAsJsonObject();
    }

    private String requireString(JsonObject object, String key) {
        JsonElement value = object.get(key);
        if (value == null || value.isJsonNull() || !value.isJsonPrimitive()) {
            throw new IllegalArgumentException("manifest field is not a string: " + key);
        }
        return value.getAsString();
    }

    private int requireInt(JsonObject object, String key) {
        JsonElement value = object.get(key);
        if (value == null || value.isJsonNull()) {
            throw new IllegalArgumentException("manifest field is missing: " + key);
        }
        return value.getAsInt();
    }

    private long requireUint32(JsonObject object, String key) {
        long value = requireNonNegativeLong(object, key);
        if (value > 0xffffffffL) {
            throw new IllegalArgumentException("manifest field exceeds uint32: " + key);
        }
        return value;
    }

    private long requireNonNegativeLong(JsonObject object, String key) {
        JsonElement value = object.get(key);
        if (value == null || value.isJsonNull()) {
            throw new IllegalArgumentException("manifest field is missing: " + key);
        }
        long result = value.getAsLong();
        if (result < 0) {
            throw new IllegalArgumentException("manifest field must be non-negative: " + key);
        }
        return result;
    }
}
