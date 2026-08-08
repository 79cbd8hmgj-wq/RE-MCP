// @category RE-MCP

import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;

public class ReMcpInspectProgram extends GhidraScript {
    private static final String FORMAT = "re-mcp-nds-ghidra-inspection";
    private static final int FORMAT_VERSION = 1;
    private static final int MAX_BODY_RANGES = 256;
    private static final int MAX_DECOMPILE_CHARACTERS = 100000;
    private static final int MAX_PAGE_LIMIT = 1000;
    private static final int MAX_PAGE_OFFSET = 100000;
    private static final int MAX_SYMBOL_QUERY_CHARACTERS = 128;

    private static final String KEY_ROM_SHA = "re-mcp.rom-sha256";
    private static final String KEY_PROCESSOR = "re-mcp.processor";

    private static final String MAP_FUNCTION_ID = "re-mcp.function-id";
    private static final String MAP_FUNCTION_PROOF = "re-mcp.function-proof";
    private static final String MAP_FUNCTION_MODE = "re-mcp.function-mode";
    private static final String MAP_OVERLAY_ID = "re-mcp.overlay-id";
    private static final String MAP_CALL_EVIDENCE = "re-mcp.call-evidence";

    private final Gson gson = new GsonBuilder().serializeNulls().disableHtmlEscaping().create();

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("expected inspection request path and result path");
        }

        Path requestPath = Paths.get(args[0]).toRealPath();
        Path resultPath = Paths.get(args[1]).toAbsolutePath().normalize();
        JsonObject request = readRequest(requestPath);
        validateRequestEnvelope(request);
        validateProgramOwnership(request);

        String operation = requireString(request, "operation");
        JsonObject payload;
        if ("inspect-function".equals(operation)) {
            payload = inspectFunction(request);
        } else if ("decompile-function".equals(operation)) {
            payload = decompileFunction(request);
        } else if ("search-symbols".equals(operation)) {
            payload = searchSymbols(request);
        } else if ("list-references".equals(operation)) {
            payload = listReferences(request);
        } else if ("list-calls".equals(operation)) {
            payload = listCalls(request);
        } else {
            throw new IllegalArgumentException("unsupported Ghidra inspection operation: " + operation);
        }

        JsonObject envelope = new JsonObject();
        envelope.addProperty("format", FORMAT);
        envelope.addProperty("formatVersion", FORMAT_VERSION);
        envelope.addProperty("requestId", requireString(request, "requestId"));
        envelope.addProperty("sourceRomSha256", requireString(request, "sourceRomSha256"));
        envelope.addProperty("processor", requireString(request, "processor"));
        envelope.addProperty("programName", requireString(request, "programName"));
        envelope.addProperty("operation", operation);
        envelope.add("payload", payload);
        writeAtomically(resultPath, gson.toJson(envelope) + "\n");
    }

    private JsonObject readRequest(Path requestPath) throws Exception {
        if (!Files.isRegularFile(requestPath)) {
            throw new IllegalArgumentException("inspection request is not a regular file: " + requestPath);
        }
        try (var reader = Files.newBufferedReader(requestPath, StandardCharsets.UTF_8)) {
            JsonElement parsed = JsonParser.parseReader(reader);
            if (!parsed.isJsonObject()) {
                throw new IllegalArgumentException("inspection request must be a JSON object");
            }
            return parsed.getAsJsonObject();
        }
    }

    private void validateRequestEnvelope(JsonObject request) {
        if (!FORMAT.equals(requireString(request, "format"))) {
            throw new IllegalArgumentException("unsupported Ghidra inspection format");
        }
        if (requireInt(request, "formatVersion") != FORMAT_VERSION) {
            throw new IllegalArgumentException("unsupported Ghidra inspection formatVersion");
        }
        String requestId = requireString(request, "requestId");
        if (!requestId.matches("[a-f0-9]{16}")) {
            throw new IllegalArgumentException("invalid Ghidra inspection requestId");
        }
        String processor = requireString(request, "processor");
        if (!processor.equals("arm9") && !processor.equals("arm7")) {
            throw new IllegalArgumentException("processor must be arm9 or arm7");
        }
        requireString(request, "sourceRomSha256");
        requireString(request, "programName");
        requireString(request, "operation");
    }

    private void validateProgramOwnership(JsonObject request) {
        Options info = currentProgram.getOptions(Program.PROGRAM_INFO);
        requireOwnedValue(info, KEY_ROM_SHA, requireString(request, "sourceRomSha256"));
        requireOwnedValue(info, KEY_PROCESSOR, requireString(request, "processor"));
        String expectedProgramName = requireString(request, "programName");
        if (!expectedProgramName.equals(currentProgram.getName())) {
            throw new IllegalStateException("current Ghidra program does not match the canonical inspection programName");
        }
    }

    private void requireOwnedValue(Options info, String key, String expected) {
        String actual = info.getString(key, null);
        if (!expected.equals(actual)) {
            throw new IllegalStateException("current Ghidra program lacks matching RE-MCP ownership metadata: " + key);
        }
    }

    private Address selectedAddress(JsonObject request) {
        JsonObject selector = requireObject(request, "selector");
        long runtimeAddress = requireUint32(selector, "runtimeAddress");
        String component = requireString(selector, "component");
        AddressSpace space;

        if (component.equals("main")) {
            JsonElement addressSpace = selector.get("addressSpace");
            if (addressSpace != null && !addressSpace.isJsonNull()) {
                throw new IllegalArgumentException("main inspection selector must use the program default address space");
            }
            space = currentProgram.getAddressFactory().getDefaultAddressSpace();
            if (space == null || space.isOverlaySpace()) {
                throw new IllegalStateException("current Ghidra program has no usable non-overlay default address space");
            }
        } else if (component.equals("overlay")) {
            requireUint32(selector, "overlayId");
            String addressSpaceName = requireString(selector, "addressSpace");
            space = currentProgram.getAddressFactory().getAddressSpace(addressSpaceName);
            if (space == null || !space.isOverlaySpace()) {
                throw new IllegalStateException("requested canonical overlay address space is not present");
            }
        } else {
            throw new IllegalArgumentException("selector component must be main or overlay");
        }

        return space.getAddress(runtimeAddress);
    }

    private JsonObject inspectFunction(JsonObject request) {
        Address requested = selectedAddress(request);
        FunctionManager functions = currentProgram.getFunctionManager();
        Function function = functions.getFunctionContaining(requested);
        if (function == null) {
            JsonObject missing = new JsonObject();
            missing.addProperty("found", false);
            return missing;
        }
        return functionPayload(function);
    }

    private JsonObject functionPayload(Function function) {
        JsonObject payload = new JsonObject();
        payload.addProperty("found", true);
        payload.add("entry", addressObject(function.getEntryPoint()));
        payload.addProperty("name", function.getName());
        payload.addProperty(
            "namespace",
            function.getParentNamespace() == null ? "" : function.getParentNamespace().getName());
        payload.addProperty("signature", function.getPrototypeString(false, true));
        payload.addProperty("callingConvention", nullableString(function.getSignature().getCallingConventionName()));
        payload.addProperty("thunk", function.isThunk());
        payload.addProperty("external", function.isExternal());
        payload.addProperty("varArgs", function.hasVarArgs());

        JsonArray rangesJson = new JsonArray();
        AddressRangeIterator ranges = function.getBody().getAddressRanges();
        int count = 0;
        boolean truncated = false;
        while (ranges.hasNext()) {
            AddressRange range = ranges.next();
            if (count >= MAX_BODY_RANGES) {
                truncated = true;
                break;
            }
            JsonObject rangeJson = new JsonObject();
            rangeJson.addProperty("space", range.getMinAddress().getAddressSpace().getName());
            rangeJson.addProperty("start", range.getMinAddress().getOffset());
            rangeJson.addProperty("endExclusive", range.getMaxAddress().getOffset() + 1L);
            rangesJson.add(rangeJson);
            count += 1;
        }
        payload.add("bodyRanges", rangesJson);
        payload.addProperty("bodyRangesTruncated", truncated);

        Symbol entrySymbol = function.getSymbol();
        if (entrySymbol == null) {
            payload.add("entrySymbol", JsonNull.INSTANCE);
        } else {
            JsonObject symbolJson = new JsonObject();
            symbolJson.addProperty("name", entrySymbol.getName());
            symbolJson.addProperty("source", entrySymbol.getSource().toString());
            symbolJson.addProperty("primary", entrySymbol.isPrimary());
            symbolJson.addProperty("dynamic", entrySymbol.isDynamic());
            payload.add("entrySymbol", symbolJson);
        }

        payload.add("reMcpEvidence", reMcpEvidence(function.getEntryPoint()));
        return payload;
    }

    private JsonObject decompileFunction(JsonObject request) {
        Address requested = selectedAddress(request);
        Function function = currentProgram.getFunctionManager().getFunctionContaining(requested);
        if (function == null) {
            JsonObject missing = new JsonObject();
            missing.addProperty("found", false);
            missing.addProperty("completed", false);
            missing.addProperty("truncated", false);
            missing.addProperty("c", "");
            missing.addProperty("error", "no Ghidra function contains the requested address");
            return missing;
        }

        JsonObject parameters = requireObject(request, "parameters");
        int maxCharacters = requireBoundedInt(parameters, "maxCharacters", 1, MAX_DECOMPILE_CHARACTERS);
        DecompInterface decompiler = new DecompInterface();
        try {
            boolean opened = decompiler.openProgram(currentProgram);
            if (!opened) {
                throw new IllegalStateException("Ghidra decompiler could not open the current program");
            }
            DecompileResults results = decompiler.decompileFunction(function, 30, monitor);
            boolean completed = results.decompileCompleted();
            String c = "";
            if (completed && results.getDecompiledFunction() != null) {
                c = results.getDecompiledFunction().getC();
            }
            boolean truncated = c.length() > maxCharacters;
            if (truncated) {
                c = c.substring(0, maxCharacters);
            }

            JsonObject payload = functionPayload(function);
            payload.addProperty("completed", completed);
            payload.addProperty("truncated", truncated);
            payload.addProperty("c", c);
            payload.addProperty("error", nullableString(results.getErrorMessage()));
            return payload;
        } finally {
            decompiler.dispose();
        }
    }

    private JsonObject searchSymbols(JsonObject request) {
        JsonObject parameters = requireObject(request, "parameters");
        String query = requireString(parameters, "query");
        int queryCharacters = query.codePointCount(0, query.length());
        if (queryCharacters < 1 || queryCharacters > MAX_SYMBOL_QUERY_CHARACTERS) {
            throw new IllegalArgumentException("query must contain between 1 and 128 Unicode characters");
        }
        String match = requireString(parameters, "match");
        if (!match.equals("exact") && !match.equals("prefix") && !match.equals("contains")) {
            throw new IllegalArgumentException("match must be exact, prefix, or contains");
        }
        int limit = pageLimit(parameters);
        int offset = pageOffset(parameters);

        List<JsonObject> matches = new ArrayList<>();
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        SymbolIterator symbols = symbolTable.getAllSymbols(true);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            String name = symbol.getName();
            if (!symbolMatches(name, query, match)) {
                continue;
            }
            JsonObject record = new JsonObject();
            record.addProperty("name", name);
            record.addProperty(
                "namespace",
                symbol.getParentNamespace() == null ? "" : symbol.getParentNamespace().getName());
            record.addProperty("type", symbol.getSymbolType().toString());
            record.add("address", addressObject(symbol.getAddress()));
            record.addProperty("primary", symbol.isPrimary());
            record.addProperty("dynamic", symbol.isDynamic());
            record.addProperty("source", symbol.getSource().toString());
            record.add("reMcpEvidence", reMcpEvidence(symbol.getAddress()));
            matches.add(record);
        }

        matches.sort(this::compareSymbolRecords);
        return pagedResult(matches, offset, limit, "results");
    }

    private boolean symbolMatches(String name, String query, String match) {
        if (match.equals("exact")) {
            return name.equals(query);
        }
        if (match.equals("prefix")) {
            return name.startsWith(query);
        }
        return name.contains(query);
    }

    private int compareSymbolRecords(JsonObject left, JsonObject right) {
        int result = compareAddresses(requireObject(left, "address"), requireObject(right, "address"));
        if (result != 0) return result;
        result = stringField(left, "namespace").compareTo(stringField(right, "namespace"));
        if (result != 0) return result;
        result = stringField(left, "name").compareTo(stringField(right, "name"));
        if (result != 0) return result;
        return stringField(left, "type").compareTo(stringField(right, "type"));
    }

    private JsonObject listReferences(JsonObject request) {
        Address selected = selectedAddress(request);
        JsonObject parameters = requireObject(request, "parameters");
        String direction = requireString(parameters, "direction");
        if (!direction.equals("from") && !direction.equals("to") && !direction.equals("both")) {
            throw new IllegalArgumentException("direction must be from, to, or both");
        }
        int limit = pageLimit(parameters);
        int offset = pageOffset(parameters);
        ReferenceManager manager = currentProgram.getReferenceManager();
        List<JsonObject> records = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        if (direction.equals("from") || direction.equals("both")) {
            for (Reference reference : manager.getReferencesFrom(selected)) {
                addReferenceRecord(records, seen, reference);
            }
        }
        if (direction.equals("to") || direction.equals("both")) {
            ReferenceIterator incoming = manager.getReferencesTo(selected);
            while (incoming.hasNext()) {
                addReferenceRecord(records, seen, incoming.next());
            }
        }

        records.sort(this::compareReferenceRecords);
        return pagedResult(records, offset, limit, "results");
    }

    private void addReferenceRecord(
            List<JsonObject> records,
            Set<String> seen,
            Reference reference) {
        String key = referenceKey(reference);
        if (!seen.add(key)) {
            return;
        }
        records.add(referenceObject(reference));
    }

    private JsonObject referenceObject(Reference reference) {
        JsonObject record = new JsonObject();
        record.add("from", addressObject(reference.getFromAddress()));
        record.add("to", addressObject(reference.getToAddress()));
        record.addProperty("type", reference.getReferenceType().toString());
        record.addProperty("source", reference.getSource().toString());
        record.addProperty("operandIndex", reference.getOperandIndex());
        record.addProperty("primary", reference.isPrimary());
        return record;
    }

    private String referenceKey(Reference reference) {
        return addressKey(reference.getFromAddress())
            + "|" + addressKey(reference.getToAddress())
            + "|" + reference.getReferenceType()
            + "|" + reference.getSource()
            + "|" + reference.getOperandIndex()
            + "|" + reference.isPrimary();
    }

    private int compareReferenceRecords(JsonObject left, JsonObject right) {
        int result = compareAddresses(requireObject(left, "from"), requireObject(right, "from"));
        if (result != 0) return result;
        result = compareAddresses(requireObject(left, "to"), requireObject(right, "to"));
        if (result != 0) return result;
        result = stringField(left, "type").compareTo(stringField(right, "type"));
        if (result != 0) return result;
        result = stringField(left, "source").compareTo(stringField(right, "source"));
        if (result != 0) return result;
        return Integer.compare(intField(left, "operandIndex"), intField(right, "operandIndex"));
    }

    private JsonObject listCalls(JsonObject request) {
        Address selected = selectedAddress(request);
        FunctionManager functions = currentProgram.getFunctionManager();
        Function selectedFunction = functions.getFunctionContaining(selected);
        JsonObject parameters = requireObject(request, "parameters");
        String direction = requireString(parameters, "direction");
        if (!direction.equals("callers") && !direction.equals("callees") && !direction.equals("both")) {
            throw new IllegalArgumentException("direction must be callers, callees, or both");
        }
        int limit = pageLimit(parameters);
        int offset = pageOffset(parameters);

        if (selectedFunction == null) {
            JsonObject missing = pagedResult(new ArrayList<>(), offset, limit, "edges");
            missing.addProperty("found", false);
            return missing;
        }

        ReferenceManager references = currentProgram.getReferenceManager();
        List<JsonObject> edges = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        if (direction.equals("callees") || direction.equals("both")) {
            AddressIterator sources = references.getReferenceSourceIterator(selectedFunction.getBody(), true);
            while (sources.hasNext()) {
                Address callSite = sources.next();
                for (Reference reference : references.getReferencesFrom(callSite)) {
                    if (reference.getReferenceType().isCall()) {
                        addCallEdge(edges, seen, reference, functions);
                    }
                }
            }
        }

        if (direction.equals("callers") || direction.equals("both")) {
            ReferenceIterator incoming = references.getReferencesTo(selectedFunction.getEntryPoint());
            while (incoming.hasNext()) {
                Reference reference = incoming.next();
                if (reference.getReferenceType().isCall()) {
                    addCallEdge(edges, seen, reference, functions);
                }
            }
        }

        edges.sort(this::compareCallEdges);
        JsonObject payload = pagedResult(edges, offset, limit, "edges");
        payload.addProperty("found", true);
        payload.add("function", functionIdentity(selectedFunction));
        return payload;
    }

    private void addCallEdge(
            List<JsonObject> edges,
            Set<String> seen,
            Reference reference,
            FunctionManager functions) {
        String key = referenceKey(reference);
        if (!seen.add(key)) {
            return;
        }

        Function sourceFunction = functions.getFunctionContaining(reference.getFromAddress());
        Function targetFunction = functions.getFunctionAt(reference.getToAddress());
        if (targetFunction == null) {
            targetFunction = functions.getFunctionContaining(reference.getToAddress());
        }

        JsonObject edge = referenceObject(reference);
        edge.add("callSite", addressObject(reference.getFromAddress()));
        edge.add("sourceFunction", sourceFunction == null ? JsonNull.INSTANCE : functionIdentity(sourceFunction));
        edge.add("targetFunction", targetFunction == null ? JsonNull.INSTANCE : functionIdentity(targetFunction));
        addNullable(
            edge,
            "reMcpDirectCallEvidence",
            stringProperty(currentProgram.getUsrPropertyManager(), MAP_CALL_EVIDENCE, reference.getFromAddress()));
        edges.add(edge);
    }

    private JsonObject functionIdentity(Function function) {
        JsonObject result = new JsonObject();
        result.add("entry", addressObject(function.getEntryPoint()));
        result.addProperty("name", function.getName());
        result.addProperty(
            "namespace",
            function.getParentNamespace() == null ? "" : function.getParentNamespace().getName());
        return result;
    }

    private int compareCallEdges(JsonObject left, JsonObject right) {
        return compareReferenceRecords(left, right);
    }

    private JsonObject pagedResult(
            List<JsonObject> records,
            int offset,
            int limit,
            String arrayName) {
        int total = records.size();
        int start = Math.min(offset, total);
        int end = Math.min(total, start + limit);
        JsonArray returned = new JsonArray();
        for (int index = start; index < end; index += 1) {
            returned.add(records.get(index));
        }

        JsonObject payload = new JsonObject();
        payload.addProperty("totalMatches", total);
        payload.addProperty("returned", end - start);
        payload.addProperty("offset", offset);
        payload.addProperty("limit", limit);
        payload.addProperty("truncated", end < total);
        payload.add(arrayName, returned);
        return payload;
    }

    private int pageLimit(JsonObject parameters) {
        return requireBoundedInt(parameters, "limit", 1, MAX_PAGE_LIMIT);
    }

    private int pageOffset(JsonObject parameters) {
        return requireBoundedInt(parameters, "offset", 0, MAX_PAGE_OFFSET);
    }

    private int compareAddresses(JsonObject left, JsonObject right) {
        int result = stringField(left, "space").compareTo(stringField(right, "space"));
        if (result != 0) return result;
        return Long.compareUnsigned(longField(left, "offset"), longField(right, "offset"));
    }

    private String stringField(JsonObject object, String key) {
        return object.get(key).getAsString();
    }

    private int intField(JsonObject object, String key) {
        return object.get(key).getAsInt();
    }

    private long longField(JsonObject object, String key) {
        return object.get(key).getAsLong();
    }

    private String addressKey(Address address) {
        return address.getAddressSpace().getName() + ":" + Long.toUnsignedString(address.getOffset());
    }

    private JsonObject reMcpEvidence(Address address) {
        PropertyMapManager maps = currentProgram.getUsrPropertyManager();
        JsonObject evidence = new JsonObject();
        addNullable(evidence, "functionId", stringProperty(maps, MAP_FUNCTION_ID, address));
        addNullable(evidence, "functionProof", stringProperty(maps, MAP_FUNCTION_PROOF, address));
        addNullable(evidence, "functionMode", stringProperty(maps, MAP_FUNCTION_MODE, address));
        addNullable(evidence, "overlayId", stringProperty(maps, MAP_OVERLAY_ID, address));
        return evidence;
    }

    private String stringProperty(PropertyMapManager maps, String name, Address address) {
        StringPropertyMap property = maps.getStringPropertyMap(name);
        return property == null ? null : property.getString(address);
    }

    private JsonObject addressObject(Address address) {
        JsonObject result = new JsonObject();
        result.addProperty("space", address.getAddressSpace().getName());
        result.addProperty("offset", address.getOffset());
        return result;
    }

    private void addNullable(JsonObject object, String key, String value) {
        if (value == null) {
            object.add(key, JsonNull.INSTANCE);
        } else {
            object.addProperty(key, value);
        }
    }

    private String nullableString(String value) {
        return value == null ? "" : value;
    }

    private JsonObject requireObject(JsonObject object, String key) {
        JsonElement value = object.get(key);
        if (value == null || !value.isJsonObject()) {
            throw new IllegalArgumentException("missing object field: " + key);
        }
        return value.getAsJsonObject();
    }

    private String requireString(JsonObject object, String key) {
        JsonElement value = object.get(key);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException("missing string field: " + key);
        }
        String text = value.getAsString();
        if (text.isEmpty()) {
            throw new IllegalArgumentException("empty string field: " + key);
        }
        return text;
    }

    private int requireInt(JsonObject object, String key) {
        JsonElement value = object.get(key);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isNumber()) {
            throw new IllegalArgumentException("missing integer field: " + key);
        }
        return value.getAsInt();
    }

    private int requireBoundedInt(JsonObject object, String key, int minimum, int maximum) {
        int value = requireInt(object, key);
        if (value < minimum || value > maximum) {
            throw new IllegalArgumentException(
                key + " must be between " + minimum + " and " + maximum);
        }
        return value;
    }

    private long requireUint32(JsonObject object, String key) {
        JsonElement value = object.get(key);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isNumber()) {
            throw new IllegalArgumentException("missing uint32 field: " + key);
        }
        long number = value.getAsLong();
        if (number < 0L || number > 0xffffffffL) {
            throw new IllegalArgumentException(key + " must be an unsigned 32-bit integer");
        }
        return number;
    }

    private void writeAtomically(Path resultPath, String content) throws Exception {
        Path parent = resultPath.getParent();
        if (parent == null || !Files.isDirectory(parent)) {
            throw new IllegalArgumentException("inspection result parent directory does not exist");
        }
        Path temporary = resultPath.resolveSibling("." + resultPath.getFileName() + ".tmp");
        Files.writeString(temporary, content, StandardCharsets.UTF_8);
        try {
            Files.move(
                temporary,
                resultPath,
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException ignored) {
            Files.move(temporary, resultPath, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
