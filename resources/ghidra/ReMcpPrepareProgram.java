// @category RE-MCP

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
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
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;

public class ReMcpPrepareProgram extends GhidraScript {
    private static final String BRIDGE_FORMAT = "re-mcp-nds-ghidra";
    private static final int BRIDGE_FORMAT_VERSION = 2;
    private static final String OWNED_BRIDGE_FORMAT_V1 = "re-mcp-nds-ghidra:1";
    private static final String OWNED_BRIDGE_FORMAT_V2 = "re-mcp-nds-ghidra:2";

    private static final String KEY_BRIDGE_FORMAT = "re-mcp.bridge-format";
    private static final String KEY_ROM_SHA = "re-mcp.rom-sha256";
    private static final String KEY_MANIFEST_SHA = "re-mcp.manifest-sha256";
    private static final String KEY_PROCESSOR = "re-mcp.processor";
    private static final String KEY_LAST_IMPORT = "re-mcp.last-import";
    private static final String KEY_ANALYSIS_STATUS = "re-mcp.last-analysis-status";
    private static final String KEY_GHIDRA_VERSION = "re-mcp.ghidra-version";
    private static final String KEY_OVERLAY_PREFIX = "re-mcp.overlay.";
    private static final String KEY_OVERLAY_REPRESENTATION_SUFFIX = ".representation";
    private static final String KEY_OVERLAY_RUNTIME_SHA_SUFFIX = ".runtime-sha256";
    private static final String MAP_OVERLAY_ID = "re-mcp.overlay-id";

    private static final class OverlaySpec {
        final int overlayId;
        final String spaceName;
        final String importStatus;
        final String representation;
        final Path artifact;
        final long runtimeAddress;
        final long ramSize;
        final long bssSize;
        final long initializedSize;
        final long storedSize;
        final boolean compressed;
        final String runtimeSha256;

        OverlaySpec(
                int overlayId,
                String spaceName,
                String importStatus,
                String representation,
                Path artifact,
                long runtimeAddress,
                long ramSize,
                long bssSize,
                long initializedSize,
                long storedSize,
                boolean compressed,
                String runtimeSha256) {
            this.overlayId = overlayId;
            this.spaceName = spaceName;
            this.importStatus = importStatus;
            this.representation = representation;
            this.artifact = artifact;
            this.runtimeAddress = runtimeAddress;
            this.ramSize = ramSize;
            this.bssSize = bssSize;
            this.initializedSize = initializedSize;
            this.storedSize = storedSize;
            this.compressed = compressed;
            this.runtimeSha256 = runtimeSha256;
        }
    }

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
        String sourceRomSha256 = requireSha256(manifest, "sourceRomSha256");
        String expectedLanguage = requireString(processorManifest, "language");
        String expectedProgramName = requireString(processorManifest, "programName");

        String actualLanguage = currentProgram.getLanguageID().getIdAsString();
        if (!expectedLanguage.equals(actualLanguage)) {
            throw new IllegalStateException(
                "program language mismatch: expected " + expectedLanguage + ", found " + actualLanguage);
        }

        Options info = currentProgram.getOptions(Program.PROGRAM_INFO);
        String existingBridgeFormat = validateExistingBridgeOwnership(
            info,
            sourceRomSha256,
            processor);

        MemoryBlock main = validateMainMapping(processorManifest);
        List<OverlaySpec> specs = parseOverlaySpecs(manifestPath, processorManifest);
        Map<Integer, String> overlaySpaces = reconcileOverlays(
            info,
            existingBridgeFormat,
            specs);
        applyProvenModeContext(manifest, processor, overlaySpaces);

        main.setRead(true);
        main.setWrite(true);
        main.setExecute(true);
        currentProgram.setName(expectedProgramName);

        // Bridge-format ownership is promoted to v2 only after the complete v2
        // overlay reconciliation and proven-mode pass have succeeded.
        info.setString(KEY_BRIDGE_FORMAT, OWNED_BRIDGE_FORMAT_V2);
        info.setString(KEY_ROM_SHA, sourceRomSha256);
        info.setString(KEY_MANIFEST_SHA, manifestSha256);
        info.setString(KEY_PROCESSOR, processor);
        info.setString(KEY_LAST_IMPORT, manifestSha256);
        info.setString(KEY_ANALYSIS_STATUS, "pending");
        info.setString(KEY_GHIDRA_VERSION, Application.getApplicationVersion());
        for (OverlaySpec spec : specs) {
            info.setString(overlayRepresentationKey(spec.overlayId), spec.representation);
            info.setString(overlayRuntimeShaKey(spec.overlayId), spec.runtimeSha256);
        }
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
            requireSha256(manifest, "sourceRomSha256");
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

    private String validateExistingBridgeOwnership(
            Options info,
            String sourceRomSha256,
            String processor) {
        String existingBridgeFormat = info.getString(KEY_BRIDGE_FORMAT, null);
        if (existingBridgeFormat != null &&
                !OWNED_BRIDGE_FORMAT_V1.equals(existingBridgeFormat) &&
                !OWNED_BRIDGE_FORMAT_V2.equals(existingBridgeFormat)) {
            throw new IllegalStateException(
                "existing RE-MCP bridge-format ownership is unsupported: " + existingBridgeFormat);
        }

        String existingRomSha = info.getString(KEY_ROM_SHA, null);
        String existingProcessor = info.getString(KEY_PROCESSOR, null);
        if (existingBridgeFormat != null) {
            if (!sourceRomSha256.equals(existingRomSha)) {
                throw new IllegalStateException(
                    "existing RE-MCP ROM ownership does not match the incoming bridge");
            }
            if (!processor.equals(existingProcessor)) {
                throw new IllegalStateException(
                    "existing RE-MCP processor ownership does not match the incoming bridge");
            }
        }
        else {
            validateOptionalOwnedValue(info, KEY_ROM_SHA, sourceRomSha256);
            validateOptionalOwnedValue(info, KEY_PROCESSOR, processor);
        }
        return existingBridgeFormat;
    }

    private void validateOptionalOwnedValue(Options info, String key, String expected) {
        String existing = info.getString(key, null);
        if (existing != null && !existing.equals(expected)) {
            throw new IllegalStateException(
                "existing RE-MCP ownership metadata conflicts for " + key + ": " + existing);
        }
    }

    private MemoryBlock validateMainMapping(JsonObject processorManifest) {
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
        return block;
    }

    private List<OverlaySpec> parseOverlaySpecs(
            Path manifestPath,
            JsonObject processorManifest) throws Exception {
        List<OverlaySpec> result = new ArrayList<>();
        for (JsonElement element : requireArray(processorManifest, "overlays")) {
            JsonObject overlay = element.getAsJsonObject();
            int overlayId = requireNonNegativeInt(overlay, "overlayId");
            String spaceName = requireString(overlay, "spaceName");
            String importStatus = requireString(overlay, "importStatus");
            String representation = requireString(overlay, "representation");
            boolean compressed = requireBoolean(overlay, "compressed");
            long runtimeAddress = requireUint32(overlay, "runtimeAddress");
            long ramSize = requireNonNegativeLong(overlay, "ramSize");
            long bssSize = requireNonNegativeLong(overlay, "bssSize");
            long initializedSize = requirePositiveLong(overlay, "initializedSize");
            long storedSize = requireNonNegativeLong(overlay, "storedSize");
            String runtimeSha256 = requireSha256(overlay, "runtimeSha256");
            requireSha256(overlay, "storedSha256");

            if ("importable".equals(importStatus)) {
                if (!"rom-file-backed".equals(representation) || compressed) {
                    throw new IllegalArgumentException(
                        "importable overlay must be uncompressed rom-file-backed: " + overlayId);
                }
                if (initializedSize > ramSize || initializedSize > storedSize) {
                    throw new IllegalArgumentException(
                        "uncompressed overlay initializedSize exceeds canonical bounds: " + overlayId);
                }
            }
            else if ("importable-derived".equals(importStatus)) {
                if (!"derived-blz".equals(representation) || !compressed) {
                    throw new IllegalArgumentException(
                        "importable-derived overlay must be compressed derived-blz: " + overlayId);
                }
                if (initializedSize != ramSize) {
                    throw new IllegalArgumentException(
                        "derived overlay initializedSize must equal ramSize: " + overlayId);
                }
            }
            else {
                throw new IllegalArgumentException("unknown overlay import status: " + importStatus);
            }

            Path artifact = resolveGeneratedArtifact(
                manifestPath,
                requireString(overlay, "artifactPath"));
            long artifactSize = Files.size(artifact);
            if ("derived-blz".equals(representation)) {
                if (artifactSize != initializedSize) {
                    throw new IllegalStateException(
                        "derived overlay artifact size does not equal initializedSize: " + overlayId);
                }
            }
            else if (artifactSize != storedSize) {
                throw new IllegalStateException(
                    "stored overlay artifact size does not equal storedSize: " + overlayId);
            }
            if (!runtimeSha256.equals(sha256Prefix(artifact, initializedSize))) {
                throw new IllegalStateException(
                    "overlay artifact initialized bytes do not match runtimeSha256: " + overlayId);
            }

            result.add(new OverlaySpec(
                overlayId,
                spaceName,
                importStatus,
                representation,
                artifact,
                runtimeAddress,
                ramSize,
                bssSize,
                initializedSize,
                storedSize,
                compressed,
                runtimeSha256));
        }
        return result;
    }

    private Map<Integer, String> reconcileOverlays(
            Options info,
            String existingBridgeFormat,
            List<OverlaySpec> specs) throws Exception {
        Map<Integer, String> overlaySpaces = new HashMap<>();
        Memory memory = currentProgram.getMemory();
        AddressFactory addressFactory = currentProgram.getAddressFactory();
        AddressSpace defaultSpace = addressFactory.getDefaultAddressSpace();
        StringPropertyMap overlayIds = stringMap(MAP_OVERLAY_ID);

        // Preflight every existing block and every intended space before creating
        // a formerly absent overlay. A conflict therefore fails before RE-MCP
        // attempts to add any new derived overlay block.
        for (OverlaySpec spec : specs) {
            if (overlaySpaces.put(spec.overlayId, spec.spaceName) != null) {
                throw new IllegalStateException("duplicate overlay ID in processor manifest: " + spec.overlayId);
            }
            MemoryBlock initialized = memory.getBlock(spec.spaceName);
            if (initialized != null) {
                if (existingBridgeFormat == null) {
                    throw new IllegalStateException(
                        "pre-existing overlay block lacks RE-MCP bridge ownership: " + spec.spaceName);
                }
                validateOwnedOverlayBlock(
                    initialized,
                    spec.spaceName,
                    spec.runtimeAddress,
                    spec.initializedSize);
                validateRuntimeBytes(memory, initialized, spec);
                validateExistingOverlayMetadata(info, existingBridgeFormat, spec);
            }
            else {
                AddressSpace existingSpace = addressFactory.getAddressSpace(spec.spaceName);
                if (existingSpace != null) {
                    throw new IllegalStateException(
                        "overlay address-space already exists without the canonical block: " + spec.spaceName);
                }
            }

            String bssName = spec.spaceName + "_BSS";
            MemoryBlock bss = memory.getBlock(bssName);
            if (bss != null) {
                if (initialized == null) {
                    throw new IllegalStateException(
                        "overlay BSS exists without its canonical initialized block: " + bssName);
                }
                AddressSpace overlaySpace = initialized.getStart().getAddressSpace();
                long bssOffset = addUint32(spec.runtimeAddress, spec.ramSize, "overlay BSS start");
                validateOwnedBssBlock(bss, bssName, overlaySpace, bssOffset, spec.bssSize);
            }
        }

        for (OverlaySpec spec : specs) {
            MemoryBlock initialized = memory.getBlock(spec.spaceName);
            if (initialized == null) {
                Address physicalStart = defaultSpace.getAddress(spec.runtimeAddress);
                try (InputStream input = Files.newInputStream(spec.artifact)) {
                    initialized = memory.createInitializedBlock(
                        spec.spaceName,
                        physicalStart,
                        input,
                        spec.initializedSize,
                        monitor,
                        true);
                }
                validateOwnedOverlayBlock(
                    initialized,
                    spec.spaceName,
                    spec.runtimeAddress,
                    spec.initializedSize);
                validateRuntimeBytes(memory, initialized, spec);
            }

            initialized.setRead(true);
            initialized.setWrite(true);
            initialized.setExecute(true);
            overlayIds.add(initialized.getStart(), Integer.toString(spec.overlayId));

            if (spec.bssSize > 0) {
                AddressSpace overlaySpace = initialized.getStart().getAddressSpace();
                long bssOffset = addUint32(spec.runtimeAddress, spec.ramSize, "overlay BSS start");
                Address bssStart = overlaySpace.getAddressInThisSpaceOnly(bssOffset);
                String bssName = spec.spaceName + "_BSS";
                MemoryBlock bss = memory.getBlock(bssName);
                if (bss == null) {
                    bss = memory.createUninitializedBlock(bssName, bssStart, spec.bssSize, false);
                }
                validateOwnedBssBlock(
                    bss,
                    bssName,
                    overlaySpace,
                    bssOffset,
                    spec.bssSize);
                bss.setRead(true);
                bss.setWrite(true);
                bss.setExecute(false);
            }
        }
        return overlaySpaces;
    }

    private void validateExistingOverlayMetadata(
            Options info,
            String existingBridgeFormat,
            OverlaySpec spec) {
        String representationKey = overlayRepresentationKey(spec.overlayId);
        String runtimeShaKey = overlayRuntimeShaKey(spec.overlayId);
        String existingRepresentation = info.getString(representationKey, null);
        String existingRuntimeSha = info.getString(runtimeShaKey, null);

        if (OWNED_BRIDGE_FORMAT_V2.equals(existingBridgeFormat)) {
            if (!spec.representation.equals(existingRepresentation) ||
                    !spec.runtimeSha256.equals(existingRuntimeSha)) {
                throw new IllegalStateException(
                    "existing v2 overlay ownership metadata conflicts: " + spec.overlayId);
            }
            return;
        }

        // Safe v1 migration permits missing v2 overlay metadata only after the
        // actual block geometry and bytes have matched. Any pre-existing values
        // must already agree exactly.
        if (existingRepresentation != null &&
                !spec.representation.equals(existingRepresentation)) {
            throw new IllegalStateException(
                "existing overlay representation metadata conflicts: " + spec.overlayId);
        }
        if (existingRuntimeSha != null &&
                !spec.runtimeSha256.equals(existingRuntimeSha)) {
            throw new IllegalStateException(
                "existing overlay runtime hash metadata conflicts: " + spec.overlayId);
        }
    }

    private String overlayRepresentationKey(int overlayId) {
        return KEY_OVERLAY_PREFIX + overlayId + KEY_OVERLAY_REPRESENTATION_SUFFIX;
    }

    private String overlayRuntimeShaKey(int overlayId) {
        return KEY_OVERLAY_PREFIX + overlayId + KEY_OVERLAY_RUNTIME_SHA_SUFFIX;
    }

    private void validateRuntimeBytes(
            Memory memory,
            MemoryBlock block,
            OverlaySpec spec) throws Exception {
        if (!block.isInitialized()) {
            throw new IllegalStateException(
                "owned overlay initialized block is not initialized: " + spec.spaceName);
        }
        String actual = sha256Memory(memory, block, spec.initializedSize);
        if (!spec.runtimeSha256.equals(actual)) {
            throw new IllegalStateException(
                "owned overlay runtime bytes do not match runtimeSha256: " + spec.spaceName);
        }
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
                block.isInitialized() ||
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
        SymbolTable symbols = currentProgram.getSymbolTable();
        for (JsonElement element : requireArray(discovery, "functions")) {
            JsonObject function = element.getAsJsonObject();
            JsonObject entry = requireObject(function, "entry");
            Address address = identityAddress(entry, overlaySpaces);
            if (!symbols.isExternalEntryPoint(address)) {
                symbols.addExternalEntryPoint(address);
            }
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
            throw new IllegalStateException("function references unknown overlay " + overlayId);
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
        return digestHex(digest);
    }

    private String sha256Prefix(Path path, long length) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long remaining = length;
        try (InputStream input = Files.newInputStream(path)) {
            byte[] buffer = new byte[8192];
            while (remaining > 0) {
                int requested = (int)Math.min((long)buffer.length, remaining);
                int count = input.read(buffer, 0, requested);
                if (count < 0) {
                    throw new IllegalStateException(
                        "artifact ended before initializedSize while calculating runtime hash");
                }
                if (count > 0) {
                    digest.update(buffer, 0, count);
                    remaining -= count;
                }
            }
        }
        return digestHex(digest);
    }

    private String sha256Memory(
            Memory memory,
            MemoryBlock block,
            long length) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long remaining = length;
        Address cursor = block.getStart();
        byte[] buffer = new byte[8192];
        while (remaining > 0) {
            int requested = (int)Math.min((long)buffer.length, remaining);
            int count = memory.getBytes(cursor, buffer, 0, requested);
            if (count != requested) {
                throw new IllegalStateException(
                    "unable to read every initialized overlay byte for ownership hashing");
            }
            digest.update(buffer, 0, count);
            remaining -= count;
            if (remaining > 0) {
                cursor = cursor.add(count);
            }
        }
        return digestHex(digest);
    }

    private String digestHex(MessageDigest digest) {
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

    private String requireSha256(JsonObject object, String key) {
        String value = requireString(object, key);
        if (!value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException("manifest field is not lowercase SHA-256: " + key);
        }
        return value;
    }

    private boolean requireBoolean(JsonObject object, String key) {
        JsonElement value = object.get(key);
        if (value == null || value.isJsonNull() || !value.isJsonPrimitive()) {
            throw new IllegalArgumentException("manifest field is not a boolean: " + key);
        }
        return value.getAsBoolean();
    }

    private int requireInt(JsonObject object, String key) {
        JsonElement value = object.get(key);
        if (value == null || value.isJsonNull()) {
            throw new IllegalArgumentException("manifest field is missing: " + key);
        }
        return value.getAsInt();
    }

    private int requireNonNegativeInt(JsonObject object, String key) {
        int value = requireInt(object, key);
        if (value < 0) {
            throw new IllegalArgumentException("manifest field must be non-negative: " + key);
        }
        return value;
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
