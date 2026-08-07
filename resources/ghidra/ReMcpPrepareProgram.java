// @category RE-MCP

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;

public class ReMcpPrepareProgram extends GhidraScript {
    private static final String BRIDGE_FORMAT = "re-mcp-nds-ghidra";
    private static final int BRIDGE_FORMAT_VERSION = 1;
    private static final String OWNED_BRIDGE_FORMAT = BRIDGE_FORMAT + ":" + BRIDGE_FORMAT_VERSION;

    private static final String KEY_BRIDGE_FORMAT = "re-mcp.bridge-format";
    private static final String KEY_ROM_SHA = "re-mcp.rom-sha256";
    private static final String KEY_MANIFEST_SHA = "re-mcp.manifest-sha256";
    private static final String KEY_PROCESSOR = "re-mcp.processor";
    private static final String KEY_LAST_IMPORT = "re-mcp.last-import";
    private static final String KEY_ANALYSIS_STATUS = "re-mcp.last-analysis-status";
    private static final String KEY_GHIDRA_VERSION = "re-mcp.ghidra-version";
    private static final String MAP_OVERLAY_ID = "re-mcp.overlay-id";

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("expected manifest path and processor");
        }

        Path manifestPath = Paths.get(args[0]).toRealPath();
        String processor = requireProcessor(args[1]);
        JsonObject manifest = readManifest(manifestPath);
        JsonObject processorManifest = processorManifest(manifest, processor);
        String manifestSha256 = sha256(manifestPath);
        String sourceRomSha256 = requireString(manifest, "sourceRomSha256");
        String expectedLanguage = requireString(processorManifest, "language");
        String expectedProgramName = requireString(processorManifest, "programName");

        String actualLanguage = currentProgram.getLanguageID().getIdAsString();
        if (!expectedLanguage.equals(actualLanguage)) {
            throw new IllegalStateException(
                "program language mismatch: expected " + expectedLanguage + ", found " + actualLanguage);
        }

        Options info = currentProgram.getOptions(Program.PROGRAM_INFO);
        validateOwnedValue(info, KEY_BRIDGE_FORMAT, OWNED_BRIDGE_FORMAT);
        validateOwnedValue(info, KEY_ROM_SHA, sourceRomSha256);
        validateOwnedValue(info, KEY_PROCESSOR, processor);

        currentProgram.setName(expectedProgramName);
        info.setString(KEY_BRIDGE_FORMAT, OWNED_BRIDGE_FORMAT);
        info.setString(KEY_ROM_SHA, sourceRomSha256);
        info.setString(KEY_MANIFEST_SHA, manifestSha256);
        info.setString(KEY_PROCESSOR, processor);
        info.setString(KEY_LAST_IMPORT, manifestSha256);
        info.setString(KEY_ANALYSIS_STATUS, "pending");
        info.setString(KEY_GHIDRA_VERSION, Application.getApplicationVersion());

        validateMainMapping(processorManifest);
        Map<Integer, String> overlaySpaces = reconcileOverlays(manifestPath, processorManifest);
        applyProvenModeContext(manifest, processor, overlaySpaces);
    }

    private JsonObject readManifest(Path manifestPath) throws Exception {
        if (!Files.isRegularFile(manifestPath)) {
            throw new IllegalArgumentException("manifest is not a regular file: " + manifestPath);
        }
        try (var reader = Files.newBufferedReader(manifestPath, StandardCharsets.UTF_8)) {
            JsonObject manifest = JsonParser.parseReader(reader).getAsJsonObject();
            if (!BRIDGE_FORMAT.equals(requireString(manifest, "format"))) {
                throw new IllegalArgumentException("unsupported RE-MCP Ghidra bridge format");
            }
            if (requireInt(manifest, "formatVersion") != BRIDGE_FORMAT_VERSION) {
                throw new IllegalArgumentException("unsupported RE-MCP Ghidra bridge format version");
            }
            requireString(manifest, "sourceRomSha256");
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

    private void validateOwnedValue(Options info, String key, String expected) {
        String existing = info.getString(key, null);
        if (existing != null && !existing.equals(expected)) {
            throw new IllegalStateException(
                "existing RE-MCP ownership metadata conflicts for " + key + ": " + existing);
        }
    }

    private void validateMainMapping(JsonObject processorManifest) {
        JsonObject main = requireObject(processorManifest, "main");
        long runtimeAddress = requireUint32(main, "runtimeAddress");
        long fileBackedSize = requirePositiveLong(main, "fileBackedSize");
        Address start = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(runtimeAddress);
        MemoryBlock block = currentProgram.getMemory().getBlock(start);
        if (block == null || block.getStart().getOffset() > runtimeAddress || block.getEnd().getOffset() < runtimeAddress) {
            throw new IllegalStateException("main executable is not mapped at its canonical runtime address");
        }
        long available = block.getEnd().getOffset() - runtimeAddress + 1;
        if (available < fileBackedSize) {
            throw new IllegalStateException("main executable mapping is shorter than the canonical file-backed size");
        }
        block.setRead(true);
        block.setWrite(true);
        block.setExecute(true);
    }

    private Map<Integer, String> reconcileOverlays(
            Path manifestPath,
            JsonObject processorManifest) throws Exception {
        Map<Integer, String> overlaySpaces = new HashMap<>();
        Memory memory = currentProgram.getMemory();
        AddressFactory addressFactory = currentProgram.getAddressFactory();
        AddressSpace defaultSpace = addressFactory.getDefaultAddressSpace();
        StringPropertyMap overlayIds = stringMap(MAP_OVERLAY_ID);

        for (JsonElement element : requireArray(processorManifest, "overlays")) {
            JsonObject overlay = element.getAsJsonObject();
            int overlayId = requireInt(overlay, "overlayId");
            String spaceName = requireString(overlay, "spaceName");
            String importStatus = requireString(overlay, "importStatus");

            if ("not-imported-compressed".equals(importStatus)) {
                continue;
            }
            if (!"importable".equals(importStatus)) {
                throw new IllegalArgumentException("unknown overlay import status: " + importStatus);
            }
            overlaySpaces.put(overlayId, spaceName);

            long runtimeAddress = requireUint32(overlay, "runtimeAddress");
            long ramSize = requireNonNegativeLong(overlay, "ramSize");
            long fileBackedSize = requireNonNegativeLong(overlay, "fileBackedSize");
            long bssSize = requireNonNegativeLong(overlay, "bssSize");
            long initializedSize = Math.min(ramSize, fileBackedSize);
            if (initializedSize <= 0) {
                throw new IllegalStateException("importable overlay has no initialized runtime bytes: " + overlayId);
            }

            MemoryBlock initialized = memory.getBlock(spaceName);
            if (initialized == null) {
                Path artifact = resolveGeneratedArtifact(manifestPath, requireString(overlay, "artifactPath"));
                if (Files.size(artifact) < initializedSize) {
                    throw new IllegalStateException("overlay artifact is shorter than initialized runtime size: " + overlayId);
                }
                Address physicalStart = defaultSpace.getAddress(runtimeAddress);
                try (InputStream input = Files.newInputStream(artifact)) {
                    initialized = memory.createInitializedBlock(
                        spaceName,
                        physicalStart,
                        input,
                        initializedSize,
                        monitor,
                        true);
                }
            }

            validateOwnedOverlayBlock(initialized, spaceName, runtimeAddress, initializedSize);
            initialized.setRead(true);
            initialized.setWrite(true);
            initialized.setExecute(true);
            overlayIds.add(initialized.getStart(), Integer.toString(overlayId));

            if (bssSize > 0) {
                AddressSpace overlaySpace = initialized.getStart().getAddressSpace();
                long bssOffset = addUint32(runtimeAddress, ramSize, "overlay BSS start");
                Address bssStart = overlaySpace.getAddressInThisSpaceOnly(bssOffset);
                String bssName = spaceName + "_BSS";
                MemoryBlock bss = memory.getBlock(bssName);
                if (bss == null) {
                    bss = memory.createUninitializedBlock(bssName, bssStart, bssSize, false);
                }
                validateOwnedBssBlock(bss, bssName, overlaySpace, bssOffset, bssSize);
                bss.setRead(true);
                bss.setWrite(true);
                bss.setExecute(false);
            }
        }
        return overlaySpaces;
    }

    private void validateOwnedOverlayBlock(
            MemoryBlock block,
            String spaceName,
            long runtimeAddress,
            long expectedSize) {
        if (!spaceName.equals(block.getName())) {
            throw new IllegalStateException("overlay block name mismatch for " + spaceName);
        }
        if (!block.isOverlay()) {
            throw new IllegalStateException("owned overlay block is not an overlay: " + spaceName);
        }
        if (!spaceName.equals(block.getStart().getAddressSpace().getName())) {
            throw new IllegalStateException("overlay address-space mismatch for " + spaceName);
        }
        if (block.getStart().getOffset() != runtimeAddress || block.getSize() != expectedSize) {
            throw new IllegalStateException("overlay block geometry mismatch for " + spaceName);
        }
    }

    private void validateOwnedBssBlock(
            MemoryBlock block,
            String bssName,
            AddressSpace expectedSpace,
            long expectedOffset,
            long expectedSize) {
        if (!bssName.equals(block.getName()) ||
                !block.isOverlay() ||
                !expectedSpace.getName().equals(block.getStart().getAddressSpace().getName()) ||
                block.getStart().getOffset() != expectedOffset ||
                block.getSize() != expectedSize) {
            throw new IllegalStateException("overlay BSS block conflicts with canonical metadata: " + bssName);
        }
    }

    private void applyProvenModeContext(
            JsonObject manifest,
            String processor,
            Map<Integer, String> overlaySpaces) throws Exception {
        JsonObject discovery = discoveryFor(manifest, processor);
        ProgramContext context = currentProgram.getProgramContext();
        Register tMode = context.getRegister("TMode");
        if (tMode == null) {
            throw new IllegalStateException("Ghidra ARM language does not expose TMode context register");
        }
        for (JsonElement element : requireArray(discovery, "functions")) {
            JsonObject function = element.getAsJsonObject();
            JsonObject entry = requireObject(function, "entry");
            Address address = identityAddress(entry, overlaySpaces);
            String mode = requireString(entry, "mode");
            BigInteger desired;
            if ("thumb".equals(mode)) {
                desired = BigInteger.ONE;
            }
            else if ("arm".equals(mode)) {
                desired = BigInteger.ZERO;
            }
            else {
                throw new IllegalArgumentException("unknown proven function mode: " + mode);
            }
            BigInteger existing = context.getValue(tMode, address, false);
            if (!desired.equals(existing)) {
                context.setValue(tMode, address, address, desired);
            }
        }
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

    private Address identityAddress(JsonObject entry, Map<Integer, String> overlaySpaces) {
        long runtimeAddress = requireUint32(entry, "runtimeAddress");
        String component = requireString(entry, "component");
        AddressFactory factory = currentProgram.getAddressFactory();
        if ("main".equals(component)) {
            return factory.getDefaultAddressSpace().getAddress(runtimeAddress);
        }
        if (!"overlay".equals(component)) {
            throw new IllegalArgumentException("unknown function component: " + component);
        }
        JsonElement overlayElement = entry.get("overlayId");
        if (overlayElement == null || overlayElement.isJsonNull()) {
            throw new IllegalArgumentException("overlay function is missing overlayId");
        }
        int overlayId = overlayElement.getAsInt();
        String spaceName = overlaySpaces.get(overlayId);
        if (spaceName == null) {
            throw new IllegalStateException("function references unknown or compressed overlay " + overlayId);
        }
        AddressSpace space = factory.getAddressSpace(spaceName);
        if (space == null) {
            throw new IllegalStateException("Ghidra overlay address space is unavailable: " + spaceName);
        }
        return space.getAddress(runtimeAddress);
    }

    private Path resolveGeneratedArtifact(Path manifestPath, String relativePath) throws Exception {
        Path bridgeRoot = manifestPath.getParent().toRealPath();
        Path generatedRoot = bridgeRoot.getParent().toRealPath();
        Path candidate = bridgeRoot.resolve(relativePath).normalize().toAbsolutePath();
        if (!candidate.startsWith(generatedRoot) || !Files.isRegularFile(candidate)) {
            throw new IllegalArgumentException("manifest artifact escapes generated analysis root: " + relativePath);
        }
        Path real = candidate.toRealPath();
        if (!real.startsWith(generatedRoot)) {
            throw new IllegalArgumentException("manifest artifact resolves outside generated analysis root: " + relativePath);
        }
        return real;
    }

    private StringPropertyMap stringMap(String name) throws Exception {
        PropertyMapManager maps = currentProgram.getUsrPropertyManager();
        StringPropertyMap existing = maps.getStringPropertyMap(name);
        return existing != null ? existing : maps.createStringPropertyMap(name);
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

    private long requirePositiveLong(JsonObject object, String key) {
        long value = requireNonNegativeLong(object, key);
        if (value <= 0) {
            throw new IllegalArgumentException("manifest field must be positive: " + key);
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
