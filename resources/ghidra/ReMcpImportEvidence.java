// @category RE-MCP

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;

public class ReMcpImportEvidence extends GhidraScript {
    private static final String BRIDGE_FORMAT = "re-mcp-nds-ghidra";
    private static final int BRIDGE_FORMAT_VERSION = 1;

    private static final String MAP_FUNCTION_ID = "re-mcp.function-id";
    private static final String MAP_FUNCTION_PROOF = "re-mcp.function-proof";
    private static final String MAP_FUNCTION_MODE = "re-mcp.function-mode";
    private static final String MAP_OVERLAY_ID = "re-mcp.overlay-id";
    private static final String MAP_CALL_EVIDENCE = "re-mcp.call-evidence";

    private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("expected manifest path and processor");
        }

        Path manifestPath = Paths.get(args[0]).toAbsolutePath().normalize();
        String processor = requireProcessor(args[1]);
        JsonObject manifest = readManifest(manifestPath);
        JsonObject processorManifest = processorManifest(manifest, processor);
        JsonObject discovery = discoveryFor(manifest, processor);
        Map<Integer, String> overlaySpaces = overlaySpaces(processorManifest);

        PropertyMapManager maps = currentProgram.getUsrPropertyManager();
        StringPropertyMap functionIds = stringMap(maps, MAP_FUNCTION_ID);
        StringPropertyMap functionProofs = stringMap(maps, MAP_FUNCTION_PROOF);
        StringPropertyMap functionModes = stringMap(maps, MAP_FUNCTION_MODE);
        StringPropertyMap overlayIds = stringMap(maps, MAP_OVERLAY_ID);
        StringPropertyMap callEvidence = stringMap(maps, MAP_CALL_EVIDENCE);

        Map<String, JsonObject> functionsById = new HashMap<>();
        for (JsonElement element : requireArray(discovery, "functions")) {
            JsonObject function = element.getAsJsonObject();
            String id = requireString(function, "id");
            JsonObject entry = requireObject(function, "entry");
            Address address = identityAddress(entry, overlaySpaces);

            functionIds.add(address, id);
            functionProofs.add(address, gson.toJson(requireArray(function, "evidence")));
            functionModes.add(address, requireString(entry, "mode"));
            JsonElement overlayId = entry.get("overlayId");
            if (overlayId != null && !overlayId.isJsonNull()) {
                overlayIds.add(address, Integer.toString(overlayId.getAsInt()));
            }
            functionsById.put(id, function);
        }

        importDirectCalls(discovery, functionsById, overlaySpaces, callEvidence);
    }

    private void importDirectCalls(
            JsonObject discovery,
            Map<String, JsonObject> functionsById,
            Map<Integer, String> overlaySpaces,
            StringPropertyMap callEvidence) {
        ReferenceManager references = currentProgram.getReferenceManager();
        for (JsonElement element : requireArray(discovery, "calls")) {
            JsonObject call = element.getAsJsonObject();
            String callerId = requireString(call, "callerFunctionId");
            String calleeId = requireString(call, "calleeFunctionId");
            JsonObject caller = functionsById.get(callerId);
            JsonObject callee = functionsById.get(calleeId);
            if (caller == null || callee == null) {
                throw new IllegalStateException("direct-call evidence references a function outside the manifest");
            }

            JsonObject callerEntry = requireObject(caller, "entry");
            JsonObject calleeEntry = requireObject(callee, "entry");
            long instructionAddress = requireUint32(call, "instructionAddress");
            Address from = componentAddress(callerEntry, instructionAddress, overlaySpaces);
            Address to = identityAddress(calleeEntry, overlaySpaces);
            callEvidence.add(from, gson.toJson(call));

            Reference[] existing = references.getReferencesFrom(from, ReferenceManager.MNEMONIC);
            boolean exact = false;
            for (Reference reference : existing) {
                if (reference.getToAddress().equals(to)) {
                    exact = true;
                    break;
                }
            }
            if (!exact && existing.length == 0) {
                references.addMemoryReference(
                    from,
                    to,
                    RefType.UNCONDITIONAL_CALL,
                    SourceType.IMPORTED,
                    ReferenceManager.MNEMONIC);
            }
        }
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

    private Map<Integer, String> overlaySpaces(JsonObject processorManifest) {
        Map<Integer, String> result = new HashMap<>();
        for (JsonElement element : requireArray(processorManifest, "overlays")) {
            JsonObject overlay = element.getAsJsonObject();
            if (!"not-imported-compressed".equals(requireString(overlay, "importStatus"))) {
                result.put(requireInt(overlay, "overlayId"), requireString(overlay, "spaceName"));
            }
        }
        return result;
    }

    private Address identityAddress(JsonObject entry, Map<Integer, String> overlaySpaces) {
        return componentAddress(entry, requireUint32(entry, "runtimeAddress"), overlaySpaces);
    }

    private Address componentAddress(
            JsonObject entry,
            long runtimeAddress,
            Map<Integer, String> overlaySpaces) {
        AddressFactory factory = currentProgram.getAddressFactory();
        String component = requireString(entry, "component");
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
            throw new IllegalStateException("function references an unavailable/compressed overlay: " + overlayId);
        }
        AddressSpace space = factory.getAddressSpace(spaceName);
        if (space == null) {
            throw new IllegalStateException("Ghidra overlay address space is unavailable: " + spaceName);
        }
        return space.getAddress(runtimeAddress);
    }

    private StringPropertyMap stringMap(PropertyMapManager maps, String name) throws Exception {
        StringPropertyMap existing = maps.getStringPropertyMap(name);
        return existing != null ? existing : maps.createStringPropertyMap(name);
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
        JsonElement value = object.get(key);
        if (value == null || value.isJsonNull()) {
            throw new IllegalArgumentException("manifest field is missing: " + key);
        }
        long result = value.getAsLong();
        if (result < 0 || result > 0xffffffffL) {
            throw new IllegalArgumentException("manifest field is not uint32: " + key);
        }
        return result;
    }
}
