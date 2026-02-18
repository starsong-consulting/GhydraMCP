package eu.starsong.ghidra.endpoints;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.starsong.ghidra.api.ResponseBuilder;
import eu.starsong.ghidra.util.GhidraUtil;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.*;

/**
 * Endpoints for managing custom data types (structs, unions, enums).
 * Implements HATEOAS-compliant REST API for data type manipulation.
 */
public class DataTypeEndpoints extends AbstractEndpoint {

    private PluginTool tool;

    public DataTypeEndpoints(Program program, int port) {
        super(program, port);
    }

    public DataTypeEndpoints(Program program, int port, PluginTool tool) {
        super(program, port);
        this.tool = tool;
    }

    @Override
    protected PluginTool getTool() {
        return tool;
    }

    @Override
    public void registerEndpoints(HttpServer server) {
        server.createContext("/datatypes", this::handleDataTypes);
        server.createContext("/datatypes/struct", this::handleCreateStruct);
        server.createContext("/datatypes/enum", this::handleCreateEnum);
        server.createContext("/datatypes/union", this::handleCreateUnion);
    }

    /**
     * Handle GET /datatypes - List all data types
     */
    private void handleDataTypes(HttpExchange exchange) throws IOException {
        try {
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                return;
            }

            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                return;
            }

            Map<String, String> params = parseQueryParams(exchange);
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            String category = params.get("category");
            String kind = params.get("kind"); // struct, enum, union
            String name = params.get("name");

            DataTypeManager dtm = program.getDataTypeManager();
            List<Map<String, Object>> dataTypes = new ArrayList<>();

            // Iterate through all data types
            Iterator<DataType> iterator = dtm.getAllDataTypes();
            while (iterator.hasNext()) {
                DataType dt = iterator.next();

                // Apply filters
                if (category != null && !dt.getCategoryPath().getPath().contains(category)) {
                    continue;
                }

                if (name != null && !name.isEmpty()) {
                    String normalizedFilter = name.toLowerCase();
                    String dtName = dt.getName() != null ? dt.getName().toLowerCase() : "";
                    String dtDisplayName = dt.getDisplayName() != null ? dt.getDisplayName().toLowerCase() : "";
                    if (!dtName.contains(normalizedFilter) && !dtDisplayName.contains(normalizedFilter)) {
                        continue;
                    }
                }

                if (kind != null) {
                    boolean match = false;
                    if (kind.equals("struct") && dt instanceof Structure) match = true;
                    if (kind.equals("enum") && dt instanceof ghidra.program.model.data.Enum) match = true;
                    if (kind.equals("union") && dt instanceof Union) match = true;
                    if (!match) continue;
                }

                Map<String, Object> dtInfo = new HashMap<>();
                dtInfo.put("name", dt.getName());
                dtInfo.put("displayName", dt.getDisplayName());
                dtInfo.put("category", dt.getCategoryPath().getPath());
                dtInfo.put("length", dt.getLength());

                // Add type-specific information
                if (dt instanceof Structure) {
                    dtInfo.put("kind", "struct");
                    dtInfo.put("numComponents", ((Structure) dt).getNumComponents());
                } else if (dt instanceof ghidra.program.model.data.Enum) {
                    dtInfo.put("kind", "enum");
                    dtInfo.put("numValues", ((ghidra.program.model.data.Enum) dt).getCount());
                } else if (dt instanceof Union) {
                    dtInfo.put("kind", "union");
                    dtInfo.put("numComponents", ((Union) dt).getNumComponents());
                } else {
                    dtInfo.put("kind", "other");
                }

                dataTypes.add(dtInfo);
            }

            // Build response
            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true);

            // Apply pagination
            List<Map<String, Object>> paginated = applyPagination(
                    dataTypes, offset, limit, builder, "/datatypes",
                    buildQueryString(params));

            builder.result(paginated);
            builder.addLink("self", "/datatypes");
            builder.addLink("create_struct", "/datatypes/struct", "POST");
            builder.addLink("create_enum", "/datatypes/enum", "POST");
            builder.addLink("create_union", "/datatypes/union", "POST");

            sendJsonResponse(exchange, builder.build(), 200);

        } catch (Exception e) {
            Msg.error(this, "Error in /datatypes endpoint", e);
            sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
        }
    }

    /**
     * Handle POST /datatypes/struct - Create a new structure
     */
    private void handleCreateStruct(HttpExchange exchange) throws IOException {
        try {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                return;
            }

            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                return;
            }

            Map<String, String> params = parseJsonPostParams(exchange);
            String name = params.get("name");
            String fieldsJson = params.get("fields"); // JSON array of {name, type, size}
            String category = params.getOrDefault("category", "/");

            if (name == null || name.isEmpty()) {
                sendErrorResponse(exchange, 400, "Missing required parameter: name", "MISSING_PARAMETER");
                return;
            }

            try {
                Map<String, Object> result = TransactionHelper.executeInTransaction(
                        program, "Create struct " + name, () -> {
                            DataTypeManager dtm = program.getDataTypeManager();

                            // Create the structure
                            CategoryPath categoryPath = new CategoryPath(category);
                            Structure struct = new StructureDataType(categoryPath, name, 0, dtm);

                            // Parse and add fields if provided
                            List<Map<String, Object>> fieldsAdded = parseAndApplyFieldsToStructure(
                                program, struct, fieldsJson);

                            // Add to data type manager
                            Structure addedStruct = (Structure) dtm.addDataType(
                                struct, DataTypeConflictHandler.DEFAULT_HANDLER);

                            // Build result
                            Map<String, Object> resultMap = new HashMap<>();
                            resultMap.put("name", addedStruct.getName());
                            resultMap.put("category", addedStruct.getCategoryPath().getPath());
                            resultMap.put("length", addedStruct.getLength());
                            resultMap.put("kind", "struct");
                            resultMap.put("numComponents", addedStruct.getNumComponents());
                            if (!fieldsAdded.isEmpty()) {
                                resultMap.put("fieldsAdded", fieldsAdded);
                            }

                            return resultMap;
                        });

                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                        .success(true)
                        .result(result);

                builder.addLink("self", "/datatypes/struct");
                builder.addLink("datatypes", "/datatypes");

                sendJsonResponse(exchange, builder.build(), 201);

            } catch (Exception e) {
                Msg.error(this, "Error creating struct", e);
                sendErrorResponse(exchange, 500, "Failed to create struct: " + e.getMessage());
            }

        } catch (Exception e) {
            Msg.error(this, "Error in /datatypes/struct endpoint", e);
            sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
        }
    }

    /**
     * Handle POST /datatypes/enum - Create a new enumeration
     */
    private void handleCreateEnum(HttpExchange exchange) throws IOException {
        try {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                return;
            }

            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                return;
            }

            Map<String, String> params = parseJsonPostParams(exchange);
            String name = params.get("name");
            String valuesJson = params.get("values"); // JSON object of {name: value}
            String category = params.getOrDefault("category", "/");
            int size = parseIntOrDefault(params.get("size"), 4); // Default to 4 bytes

            if (name == null || name.isEmpty()) {
                sendErrorResponse(exchange, 400, "Missing required parameter: name", "MISSING_PARAMETER");
                return;
            }

            try {
                Map<String, Object> result = TransactionHelper.executeInTransaction(
                        program, "Create enum " + name, () -> {
                            DataTypeManager dtm = program.getDataTypeManager();

                            // Create the enum
                            CategoryPath categoryPath = new CategoryPath(category);
                            EnumDataType enumDt = new EnumDataType(categoryPath, name, size, dtm);

                            // Parse and add values if provided
                            List<Map<String, Object>> valuesAdded = parseAndApplyEnumValues(enumDt, valuesJson);

                            // Add to data type manager
                            DataType added = dtm.addDataType(enumDt, DataTypeConflictHandler.DEFAULT_HANDLER);
                            ghidra.program.model.data.Enum addedEnum = (ghidra.program.model.data.Enum) added;

                            // Build result
                            Map<String, Object> resultMap = new HashMap<>();
                            resultMap.put("name", added.getName());
                            resultMap.put("category", added.getCategoryPath().getPath());
                            resultMap.put("length", added.getLength());
                            resultMap.put("kind", "enum");
                            resultMap.put("numValues", addedEnum.getCount());
                            if (!valuesAdded.isEmpty()) {
                                resultMap.put("valuesAdded", valuesAdded);
                            }

                            return resultMap;
                        });

                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                        .success(true)
                        .result(result);

                builder.addLink("self", "/datatypes/enum");
                builder.addLink("datatypes", "/datatypes");

                sendJsonResponse(exchange, builder.build(), 201);

            } catch (Exception e) {
                Msg.error(this, "Error creating enum", e);
                sendErrorResponse(exchange, 500, "Failed to create enum: " + e.getMessage());
            }

        } catch (Exception e) {
            Msg.error(this, "Error in /datatypes/enum endpoint", e);
            sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
        }
    }

    /**
     * Handle POST /datatypes/union - Create a new union
     */
    private void handleCreateUnion(HttpExchange exchange) throws IOException {
        try {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                return;
            }

            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                return;
            }

            Map<String, String> params = parseJsonPostParams(exchange);
            String name = params.get("name");
            String fieldsJson = params.get("fields"); // JSON array of {name, type}
            String category = params.getOrDefault("category", "/");

            if (name == null || name.isEmpty()) {
                sendErrorResponse(exchange, 400, "Missing required parameter: name", "MISSING_PARAMETER");
                return;
            }

            try {
                Map<String, Object> result = TransactionHelper.executeInTransaction(
                        program, "Create union " + name, () -> {
                            DataTypeManager dtm = program.getDataTypeManager();

                            // Create the union
                            CategoryPath categoryPath = new CategoryPath(category);
                            UnionDataType union = new UnionDataType(categoryPath, name, dtm);

                            // Parse and add fields if provided
                            List<Map<String, Object>> fieldsAdded = parseAndApplyFieldsToUnion(
                                program, union, fieldsJson);

                            // Add to data type manager
                            DataType added = dtm.addDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);
                            Union addedUnion = (Union) added;

                            // Build result
                            Map<String, Object> resultMap = new HashMap<>();
                            resultMap.put("name", added.getName());
                            resultMap.put("category", added.getCategoryPath().getPath());
                            resultMap.put("length", added.getLength());
                            resultMap.put("kind", "union");
                            resultMap.put("numComponents", addedUnion.getNumComponents());
                            if (!fieldsAdded.isEmpty()) {
                                resultMap.put("fieldsAdded", fieldsAdded);
                            }

                            return resultMap;
                        });

                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                        .success(true)
                        .result(result);

                builder.addLink("self", "/datatypes/union");
                builder.addLink("datatypes", "/datatypes");

                sendJsonResponse(exchange, builder.build(), 201);

            } catch (Exception e) {
                Msg.error(this, "Error creating union", e);
                sendErrorResponse(exchange, 500, "Failed to create union: " + e.getMessage());
            }

        } catch (Exception e) {
            Msg.error(this, "Error in /datatypes/union endpoint", e);
            sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
        }
    }

    private List<Map<String, Object>> parseAndApplyFieldsToStructure(
            Program program,
            Structure structure,
            String fieldsJson) throws Exception {
        List<Map<String, Object>> fieldsAdded = new ArrayList<>();
        JsonArray fields = parseJsonArrayPayload(fieldsJson, "fields");
        if (fields == null) {
            return fieldsAdded;
        }

        for (int i = 0; i < fields.size(); i++) {
            JsonElement fieldElement = fields.get(i);
            if (!fieldElement.isJsonObject()) {
                throw new Exception("fields[" + i + "] must be a JSON object");
            }

            JsonObject field = fieldElement.getAsJsonObject();
            String fieldName = getStringOrDefault(field, "name", "field_" + i);
            String fieldTypeName = getRequiredString(field, "type", "fields[" + i + "].type");
            Integer requestedSize = getOptionalInteger(field, "size", "fields[" + i + "].size");
            Integer offset = getOptionalInteger(field, "offset", "fields[" + i + "].offset");
            String comment = getOptionalString(field, "comment");

            DataType fieldType = GhidraUtil.resolveDataType(program, fieldTypeName);
            if (fieldType == null) {
                throw new Exception("Unknown field type in fields[" + i + "]: " + fieldTypeName);
            }

            int length = resolveComponentLength(fieldType, requestedSize, "fields[" + i + "]");
            DataTypeComponent component;
            if (offset != null) {
                component = structure.insertAtOffset(offset, fieldType, length, fieldName, comment);
            } else {
                component = structure.add(fieldType, length, fieldName, comment);
            }

            if (component == null) {
                throw new Exception("Failed to add struct field '" + fieldName + "'");
            }

            Map<String, Object> added = new HashMap<>();
            added.put("name", component.getFieldName());
            added.put("type", component.getDataType().getName());
            added.put("offset", component.getOffset());
            added.put("length", component.getLength());
            fieldsAdded.add(added);
        }

        return fieldsAdded;
    }

    private List<Map<String, Object>> parseAndApplyFieldsToUnion(
            Program program,
            Union union,
            String fieldsJson) throws Exception {
        List<Map<String, Object>> fieldsAdded = new ArrayList<>();
        JsonArray fields = parseJsonArrayPayload(fieldsJson, "fields");
        if (fields == null) {
            return fieldsAdded;
        }

        for (int i = 0; i < fields.size(); i++) {
            JsonElement fieldElement = fields.get(i);
            if (!fieldElement.isJsonObject()) {
                throw new Exception("fields[" + i + "] must be a JSON object");
            }

            JsonObject field = fieldElement.getAsJsonObject();
            String fieldName = getStringOrDefault(field, "name", "field_" + i);
            String fieldTypeName = getRequiredString(field, "type", "fields[" + i + "].type");
            Integer requestedSize = getOptionalInteger(field, "size", "fields[" + i + "].size");
            String comment = getOptionalString(field, "comment");

            DataType fieldType = GhidraUtil.resolveDataType(program, fieldTypeName);
            if (fieldType == null) {
                throw new Exception("Unknown field type in fields[" + i + "]: " + fieldTypeName);
            }

            int length = resolveComponentLength(fieldType, requestedSize, "fields[" + i + "]");
            DataTypeComponent component = union.add(fieldType, length, fieldName, comment);
            if (component == null) {
                throw new Exception("Failed to add union field '" + fieldName + "'");
            }

            Map<String, Object> added = new HashMap<>();
            added.put("name", component.getFieldName());
            added.put("type", component.getDataType().getName());
            added.put("offset", component.getOffset());
            added.put("length", component.getLength());
            fieldsAdded.add(added);
        }

        return fieldsAdded;
    }

    private List<Map<String, Object>> parseAndApplyEnumValues(
            EnumDataType enumType,
            String valuesJson) throws Exception {
        List<Map<String, Object>> valuesAdded = new ArrayList<>();
        JsonElement valuesElement = parseJsonPayload(valuesJson, "values");
        if (valuesElement == null) {
            return valuesAdded;
        }

        if (valuesElement.isJsonObject()) {
            JsonObject valuesObject = valuesElement.getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : valuesObject.entrySet()) {
                long value = parseLongValue(entry.getValue(), "values." + entry.getKey());
                enumType.add(entry.getKey(), value);

                Map<String, Object> added = new HashMap<>();
                added.put("name", entry.getKey());
                added.put("value", value);
                valuesAdded.add(added);
            }
            return valuesAdded;
        }

        if (valuesElement.isJsonArray()) {
            JsonArray valuesArray = valuesElement.getAsJsonArray();
            for (int i = 0; i < valuesArray.size(); i++) {
                JsonElement element = valuesArray.get(i);
                if (!element.isJsonObject()) {
                    throw new Exception("values[" + i + "] must be a JSON object");
                }
                JsonObject valueObj = element.getAsJsonObject();
                String name = getRequiredString(valueObj, "name", "values[" + i + "].name");
                JsonElement rawValue = valueObj.get("value");
                if (rawValue == null || rawValue.isJsonNull()) {
                    throw new Exception("Missing required field: values[" + i + "].value");
                }
                long value = parseLongValue(rawValue, "values[" + i + "].value");
                enumType.add(name, value);

                Map<String, Object> added = new HashMap<>();
                added.put("name", name);
                added.put("value", value);
                valuesAdded.add(added);
            }
            return valuesAdded;
        }

        throw new Exception("values must be a JSON object or JSON array");
    }

    private JsonArray parseJsonArrayPayload(String raw, String fieldName) throws Exception {
        JsonElement parsed = parseJsonPayload(raw, fieldName);
        if (parsed == null) {
            return null;
        }
        if (!parsed.isJsonArray()) {
            throw new Exception(fieldName + " must be a JSON array");
        }
        return parsed.getAsJsonArray();
    }

    private JsonElement parseJsonPayload(String raw, String fieldName) throws Exception {
        if (raw == null || raw.isEmpty()) {
            return null;
        }

        JsonElement parsed;
        try {
            parsed = JsonParser.parseString(raw);
        } catch (Exception e) {
            throw new Exception("Invalid JSON in '" + fieldName + "': " + e.getMessage(), e);
        }

        // Handle doubly-encoded JSON payloads:
        // "{\"a\":1}" or "[{\"name\":\"x\"}]"
        if (parsed.isJsonPrimitive() && parsed.getAsJsonPrimitive().isString()) {
            String nested = parsed.getAsString();
            String trimmed = nested.trim();
            if ((trimmed.startsWith("{") && trimmed.endsWith("}")) ||
                (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
                try {
                    parsed = JsonParser.parseString(nested);
                } catch (Exception e) {
                    throw new Exception("Invalid nested JSON in '" + fieldName + "': " + e.getMessage(), e);
                }
            }
        }

        return parsed;
    }

    private int resolveComponentLength(DataType dataType, Integer requestedSize, String fieldPath) throws Exception {
        if (requestedSize != null) {
            if (requestedSize <= 0) {
                throw new Exception(fieldPath + ".size must be > 0");
            }
            return requestedSize;
        }

        int dataTypeLength = dataType.getLength();
        if (dataTypeLength <= 0) {
            throw new Exception(
                fieldPath + " has type '" + dataType.getName() + "' with non-positive length; specify size explicitly");
        }
        return dataTypeLength;
    }

    private String getRequiredString(JsonObject object, String key, String fieldPath) throws Exception {
        String value = getOptionalString(object, key);
        if (value == null || value.isEmpty()) {
            throw new Exception("Missing required field: " + fieldPath);
        }
        return value;
    }

    private String getStringOrDefault(JsonObject object, String key, String defaultValue) {
        String value = getOptionalString(object, key);
        return (value == null || value.isEmpty()) ? defaultValue : value;
    }

    private String getOptionalString(JsonObject object, String key) {
        JsonElement value = object.get(key);
        if (value == null || value.isJsonNull()) {
            return null;
        }
        if (value.isJsonPrimitive()) {
            return value.getAsString();
        }
        return value.toString();
    }

    private Integer getOptionalInteger(JsonObject object, String key, String fieldPath) throws Exception {
        JsonElement value = object.get(key);
        if (value == null || value.isJsonNull()) {
            return null;
        }
        try {
            if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber()) {
                return value.getAsInt();
            }
            if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()) {
                return Integer.decode(value.getAsString().trim());
            }
            throw new NumberFormatException("value is not a number");
        } catch (Exception e) {
            throw new Exception("Invalid integer value for " + fieldPath, e);
        }
    }

    private long parseLongValue(JsonElement value, String fieldPath) throws Exception {
        try {
            if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber()) {
                return value.getAsLong();
            }
            if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()) {
                return Long.decode(value.getAsString().trim());
            }
        } catch (Exception e) {
            throw new Exception("Invalid numeric value for " + fieldPath, e);
        }
        throw new Exception("Invalid numeric value for " + fieldPath);
    }

    /**
     * Build query string from parameters
     */
    private String buildQueryString(Map<String, String> params) {
        StringBuilder query = new StringBuilder();

        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (entry.getKey().equals("offset") || entry.getKey().equals("limit")) {
                continue; // Skip pagination params
            }
            if (query.length() > 0) {
                query.append("&");
            }
            query.append(entry.getKey()).append("=").append(entry.getValue());
        }

        return query.toString();
    }
}
